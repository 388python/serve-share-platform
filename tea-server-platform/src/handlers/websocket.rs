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

use crate::db;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Default)]
struct WsMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
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
    let (mut sender, mut receiver) = socket.split();

    // Authenticate user
    let pool = db::get_db();
    let machine: Option<(i64, i64)> = sqlx::query_as(
        "SELECT user_id, server_id FROM machines WHERE id = ?"
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if machine.is_none() {
        let _ = sender
            .send(Message::Text(serde_json::to_string(&WsMessage {
                msg_type: "error".to_string(),
                message: Some("Machine not found".to_string()),
                ..Default::default()
            }).unwrap()))
            .await;
        return;
    }

    // Send ready message
    let _ = sender
        .send(Message::Text(serde_json::to_string(&WsMessage {
            msg_type: "ready".to_string(),
            ..Default::default()
        }).unwrap()))
        .await;

    // Handle WebSocket messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                    match ws_msg.msg_type.as_str() {
                        "auth" => {
                            let host = ws_msg.host.unwrap_or_default();
                            let port = ws_msg.port.unwrap_or(22);
                            
                            // Get server info
                            let server: Option<(String, String)> = sqlx::query_as(
                                "SELECT ip, agent_key FROM servers WHERE id = (SELECT server_id FROM machines WHERE id = ?)"
                            )
                            .bind(machine_id)
                            .fetch_optional(pool)
                            .await
                            .unwrap_or(None);

                            if let Some((server_ip, agent_key)) = server {
                                let machine_name = format!("machine-{}", machine_id);
                                let client = reqwest::Client::new();
                                let url = format!("http://{}:19527/machine/{}", server_ip, machine_name);
                                
                                match client
                                    .get(&url)
                                    .header("X-API-Key", &agent_key)
                                    .timeout(std::time::Duration::from_secs(10))
                                    .send()
                                    .await
                                {
                                    Ok(resp) if resp.status().is_success() => {
                                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                                            let machine_ip = data.get("ip")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or(&server_ip);
                                            
                                            let connect_addr = format!("{}:{}", machine_ip, port);
                                            
                                            // Try to connect
                                            match tokio::time::timeout(
                                                std::time::Duration::from_secs(10),
                                                tokio::net::TcpStream::connect(&connect_addr)
                                            ).await {
                                                Ok(Ok(_stream)) => {
                                                    let _ = sender.send(Message::Text(
                                                        serde_json::to_string(&WsMessage {
                                                            msg_type: "connected".to_string(),
                                                            data: Some(format!("已连接到 {}\r\n", connect_addr)),
                                                            ..Default::default()
                                                        }).unwrap()
                                                    )).await;
                                                },
                                                _ => {
                                                    let _ = sender.send(Message::Text(
                                                        serde_json::to_string(&WsMessage {
                                                            msg_type: "error".to_string(),
                                                            message: Some("无法连接到机器，请确保机器正在运行".to_string()),
                                                            ..Default::default()
                                                        }).unwrap()
                                                    )).await;
                                                }
                                            }
                                        }
                                    },
                                    _ => {
                                        let _ = sender.send(Message::Text(
                                            serde_json::to_string(&WsMessage {
                                                msg_type: "error".to_string(),
                                                message: Some("无法获取机器信息，请确保 Agent 正在运行".to_string()),
                                                ..Default::default()
                                            }).unwrap()
                                        )).await;
                                    }
                                }
                            }
                        }
                        "data" => {
                            if let Some(ref data) = ws_msg.data {
                                let _ = sender.send(Message::Text(
                                    serde_json::to_string(&WsMessage {
                                        msg_type: "data".to_string(),
                                        data: Some(data.clone()),
                                        ..Default::default()
                                    }).unwrap()
                                )).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = sender.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                break;
            }
            Err(e) => {
                tracing::error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
}
