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
use std::sync::Arc;
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

    let machine_info: Option<(i64, i32)> = sqlx::query_as(
        "SELECT server_id, ssh_port FROM machines WHERE id = ?"
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if machine_info.is_none() {
        send_ws_msg(&mut ws_tx, "error", None, Some("机器不存在".to_string())).await;
        return;
    }

    let (server_id, ssh_port) = machine_info.unwrap();

    let server_info: Option<(String, String)> = sqlx::query_as(
        "SELECT ip, agent_key FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if server_info.is_none() {
        send_ws_msg(&mut ws_tx, "error", None, Some("服务器不存在".to_string())).await;
        return;
    }

    let (server_ip, agent_key) = server_info.unwrap();

    send_ws_msg(&mut ws_tx, "ready", None, None).await;

    let machine_name = format!("machine-{}", machine_id);
    let agent_url = format!("http://{}:19527/machine/{}", server_ip, machine_name);

    let machine_ip = match reqwest::Client::new()
        .get(&agent_url)
        .header("X-API-Key", &agent_key)
        .timeout(std::time::Duration::from_secs(10))
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

    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(100);
    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(100);

    let ssh_handle = tokio::task::spawn_blocking(move || {
        ssh_worker(machine_ip, ssh_port, input_rx, output_tx)
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
                                let _ = input_tx.send(b"".to_vec()).await;
                            }
                            "data" => {
                                if let Some(data) = ws_msg.data {
                                    let _ = input_tx.send(data.into_bytes()).await;
                                }
                            }
                            "resize" => {}
                            _ => {}
                        }
                    }
                }
                Ok(Message::Ping(_data)) => {}
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        drop(input_tx);
    });

    let _ = tokio::join!(ws_read_task, ws_write_task, ssh_handle);
}

fn ssh_worker(
    machine_ip: String,
    ssh_port: i32,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: mpsc::Sender<Vec<u8>>,
) {
    let rt = tokio::runtime::Handle::current();

    let connect_addr = format!("{}:{}", machine_ip, ssh_port);

    let tcp = match TcpStream::connect(&connect_addr) {
        Ok(s) => s,
        Err(e) => {
            let _ = rt.block_on(output_tx.send(
                format!("\x1b[31m[错误] 无法连接到机器: {}\x1b[0m\r\n", e).into_bytes()
            ));
            return;
        }
    };

    let mut sess = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = rt.block_on(output_tx.send(
                format!("\x1b[31m[错误] SSH会话创建失败: {}\x1b[0m\r\n", e).into_bytes()
            ));
            return;
        }
    };

    sess.set_tcp_stream(tcp);

    if let Err(e) = sess.handshake() {
        let _ = rt.block_on(output_tx.send(
            format!("\x1b[31m[错误] SSH握手失败: {}\x1b[0m\r\n", e).into_bytes()
        ));
        return;
    }

    let private_key = get_ssh_private_key();
    if private_key.is_empty() {
        let _ = rt.block_on(output_tx.send(
            "\x1b[31m[错误] 平台SSH密钥未配置\x1b[0m\r\n".to_string().into_bytes()
        ));
        return;
    }

    if let Err(e) = userauth_pubkey_from_memory(&sess, "root", &private_key) {
        let _ = rt.block_on(output_tx.send(
            format!("\x1b[31m[错误] SSH密钥认证失败: {}\x1b[0m\r\n", e).into_bytes()
        ));
        return;
    }

    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => {
            let _ = rt.block_on(output_tx.send(
                format!("\x1b[31m[错误] SSH通道创建失败: {}\x1b[0m\r\n", e).into_bytes()
            ));
            return;
        }
    };

    if let Err(e) = channel.request_pty("xterm-256color", None, Some((80, 24, 0, 0))) {
        let _ = rt.block_on(output_tx.send(
            format!("\x1b[31m[错误] PTY请求失败: {}\x1b[0m\r\n", e).into_bytes()
        ));
        return;
    }

    if let Err(e) = channel.shell() {
        let _ = rt.block_on(output_tx.send(
            format!("\x1b[31m[错误] Shell启动失败: {}\x1b[0m\r\n", e).into_bytes()
        ));
        return;
    }

    let _ = rt.block_on(output_tx.send(
        format!("\x1b[32m[已连接到 {}]\x1b[0m\r\n", connect_addr).into_bytes()
    ));

    let channel_arc = Arc::new(std::sync::Mutex::new(channel));
    let channel_read = channel_arc.clone();
    let channel_write = channel_arc.clone();
    let output_tx_clone = output_tx.clone();

    let read_handle = std::thread::spawn(move || {
        let rt2 = tokio::runtime::Handle::current();
        let mut buf = [0u8; 4096];
        loop {
            let n = {
                let mut ch = channel_read.lock().unwrap();
                match ch.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                }
            };
            if rt2.block_on(output_tx_clone.send(buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });

    loop {
        match rt.block_on(input_rx.recv()) {
            Some(data) => {
                let mut ch = channel_write.lock().unwrap();
                if ch.write_all(&data).is_err() {
                    break;
                }
                let _ = ch.flush();
            }
            None => break,
        }
    }

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
