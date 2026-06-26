use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::db;
use crate::services::session::get_ssh_private_key;
use crate::services::ssh_key::userauth_pubkey_from_memory;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Default)]
struct WsMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/ssh/:machine_id", get(ws_ssh_handler))
        .with_state(state)
}

async fn ws_ssh_handler(
    ws: WebSocketUpgrade,
    State(_state): State<AppState>,
    Path(machine_id): Path<i64>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, machine_id))
}

async fn handle_socket(socket: WebSocket, machine_id: i64) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let pool = db::get_db();

    // Get machine info: server_id, ssh_port, status
    let machine_info: Option<(i64, i32, String)> = sqlx::query_as(
        "SELECT server_id, ssh_port, status FROM machines WHERE id = ?"
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (server_id, ssh_port, machine_status) = match machine_info {
        Some((sid, port, status)) => (sid, port, status),
        None => {
            let _ = send_ws_msg(&mut ws_tx, "error", None, Some("机器不存在".to_string())).await;
            return;
        }
    };

    // Check if machine is running
    if machine_status != "running" {
        let _ = send_ws_msg(&mut ws_tx, "error", None, Some("机器未运行".to_string())).await;
        return;
    }

    // Get server info
    let server_info: Option<(String, String)> = sqlx::query_as(
        "SELECT ip, agent_key FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (server_ip, agent_key) = match server_info {
        Some(info) => info,
        None => {
            let _ = send_ws_msg(&mut ws_tx, "error", None, Some("服务器不存在".to_string())).await;
            return;
        }
    };

    // Send ready message
    let _ = send_ws_msg(&mut ws_tx, "ready", None, None).await;

    // Get machine IP from agent
    let machine_name = format!("machine-{}", machine_id);
    let agent_url = format!("http://{}:19527/machine/{}", server_ip, machine_name);

    let machine_ip = match reqwest::Client::new()
        .get(&agent_url)
        .header("X-API-Key", &agent_key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(data) => data
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&server_ip)
                    .to_string(),
                Err(_) => server_ip.clone(),
            }
        }
        _ => server_ip.clone(),
    };

    // Create channels for communication
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(100);
    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(100);
    let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>(10);

    let machine_ip_clone = machine_ip.clone();
    let ssh_port = ssh_port;

    // Spawn SSH worker in a separate thread
    let ssh_handle = thread::spawn(move || {
        ssh_worker(machine_ip_clone, ssh_port, input_rx, output_tx, resize_rx)
    });

    let ws_write_task = tokio::spawn(async move {
        let mut rx = output_rx;
        while let Some(data) = rx.recv().await {
            let text = String::from_utf8_lossy(&data).to_string();
            if send_ws_msg(&mut ws_tx, "data", Some(text), None).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    let ws_read_task = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                        match ws_msg.msg_type.as_str() {
                            "auth" => {
                                // Auth message, send empty data to start
                                let _ = input_tx.send(b"".to_vec()).await;
                            }
                            "data" => {
                                if let Some(data) = ws_msg.data {
                                    let _ = input_tx.send(data.into_bytes()).await;
                                }
                            }
                            "resize" => {
                                // Handle PTY resize
                                if let (Some(cols), Some(rows)) = (ws_msg.cols, ws_msg.rows) {
                                    let _ = resize_tx.send((cols, rows)).await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        // Signal end of input
        drop(input_tx);
        drop(resize_tx);
    });

    let _ = tokio::join!(ws_read_task, ws_write_task);
    let _ = ssh_handle.join();
}

fn ssh_worker(
    machine_ip: String,
    ssh_port: i32,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: mpsc::Sender<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<(u16, u16)>,
) {
    let connect_addr = format!("{}:{}", machine_ip, ssh_port);

    // TCP connection with timeout using set_read_timeout
    let mut tcp = match TcpStream::connect(&connect_addr) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
            s
        }
        Err(e) => {
            let _ = output_tx.send(
                format!("\x1b[31m[错误] 无法连接到 {}: {}\x1b[0m\r\n", connect_addr, e).into_bytes()
            );
            return;
        }
    };

    let mut sess = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = output_tx.send(
                format!("\x1b[31m[错误] SSH会话创建失败: {}\x1b[0m\r\n", e).into_bytes()
            );
            return;
        }
    };

    sess.set_tcp_stream(tcp);

    if let Err(e) = sess.handshake() {
        let _ = output_tx.send(
            format!("\x1b[31m[错误] SSH握手失败: {}\x1b[0m\r\n", e).into_bytes()
        );
        return;
    }

    let private_key = get_ssh_private_key();
    if private_key.is_empty() || private_key == "NOT_YET_GENERATED" || private_key.contains("FALLBACK") {
        let _ = output_tx.send(
            "\x1b[31m[错误] 平台SSH密钥未配置，请联系管理员\x1b[0m\r\n".to_string().into_bytes()
        );
        return;
    }

    if let Err(e) = userauth_pubkey_from_memory(&sess, "root", &private_key) {
        let _ = output_tx.send(
            format!("\x1b[31m[错误] SSH密钥认证失败，请确认机器已注入平台公钥: {}\x1b[0m\r\n", e).into_bytes()
        );
        return;
    }

    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => {
            let _ = output_tx.send(
                format!("\x1b[31m[错误] SSH通道创建失败: {}\x1b[0m\r\n", e).into_bytes()
            );
            return;
        }
    };

    if let Err(e) = channel.request_pty("xterm-256color", None, Some((80, 24, 0, 0))) {
        let _ = output_tx.send(
            format!("\x1b[31m[错误] PTY请求失败: {}\x1b[0m\r\n", e).into_bytes()
        );
        return;
    }

    if let Err(e) = channel.shell() {
        let _ = output_tx.send(
            format!("\x1b[31m[错误] Shell启动失败: {}\x1b[0m\r\n", e).into_bytes()
        );
        return;
    }

    let _ = output_tx.send(
        format!("\x1b[32m[已连接到 {}]\x1b[0m\r\n", connect_addr).into_bytes()
    );

    let running = Arc::new(AtomicBool::new(true));
    let running_read = running.clone();
    let running_write = running.clone();

    // Use Arc<Mutex> to share channel between read thread and main loop
    let channel = Arc::new(std::sync::Mutex::new(channel));

    // Read thread for SSH output
    let output_tx_clone = output_tx.clone();
    let channel_read = channel.clone();
    let read_handle = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while running_read.load(Ordering::Relaxed) {
            let n = {
                let mut ch = channel_read.lock().unwrap();
                match ch.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                }
            };
            if output_tx_clone.blocking_send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    // Main loop: handle input and resize events
    loop {
        // Use recv_timeout or select-like pattern
        let input_data = {
            let timeout = Duration::from_millis(100);
            let start = std::time::Instant::now();
            loop {
                match input_rx.try_recv() {
                    Ok(data) => break Some(data),
                    Err(mpsc::error::TryRecvError::Empty) => {
                        if start.elapsed() >= timeout {
                            break None;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break None,
                }
            }
        };

        // Handle resize events (higher priority)
        if let Ok((cols, rows)) = resize_rx.try_recv() {
            let mut ch = channel.lock().unwrap();
            let _ = ch.request_pty_size(cols as u32, rows as u32, Some(0), Some(0));
        }

        match input_data {
            Some(data) => {
                let mut ch = channel.lock().unwrap();
                if ch.write_all(&data).is_err() {
                    break;
                }
                let _ = ch.flush();
            }
            None => {
                // Check if SSH session is still alive
                if !running_write.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = read_handle.join();
}

async fn send_ws_msg(
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg_type: &str,
    data: Option<String>,
    message: Option<String>,
) -> Result<(), ()> {
    let msg = WsMessage {
        msg_type: msg_type.to_string(),
        data,
        message,
        ..Default::default()
    };
    let text = serde_json::to_string(&msg).map_err(|_| ())?;
    ws_tx.send(Message::Text(text)).await.map_err(|_| ())?;
    Ok(())
}
