use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::OnceLock;

use uuid::Uuid;

use crate::db;
use crate::models::*;
use crate::services;
use crate::AppState;

static STARTUP_TIME: OnceLock<chrono::DateTime<chrono::Utc>> = OnceLock::new();

pub fn set_startup_time(t: chrono::DateTime<chrono::Utc>) {
    let _ = STARTUP_TIME.set(t);
}

// Query parameters for OpenGFW stats
#[derive(Debug, Deserialize)]
struct StatsQuery {
    start_time: Option<String>,
    end_time: Option<String>,
    server_id: Option<i64>,
    hours: Option<i64>,
}

// Query parameters for OpenGFW logs
#[derive(Debug, Deserialize)]
struct LogsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    server_id: Option<i64>,
    protocol: Option<String>,
    username: Option<String>,
}

// ---- Helpers: Token extraction & auth ----

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    if let Some(rest) = auth.strip_prefix("Bearer ") {
        Some(rest.trim().to_string())
    } else {
        None
    }
}

// ---- Helper: Validate user API key -> user id ----

async fn authenticate_user(headers: &HeaderMap) -> Result<i64, (StatusCode, Json<ApiError>)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "missing_api_key".to_string(),
                message: "Missing Bearer token in Authorization header".to_string(),
            }),
        )
    })?;

    let pool = db::get_db();
    let user_id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE api_key = ?")
        .bind(&token)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let user_id = user_id.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "invalid_api_key".to_string(),
                message: "Invalid API key".to_string(),
            }),
        )
    })?;

    // Reject banned users
    let banned: Option<bool> = sqlx::query_scalar("SELECT is_banned FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    if banned.unwrap_or(false) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "account_banned".to_string(),
                message: "This account has been banned".to_string(),
            }),
        ));
    }

    Ok(user_id)
}

// ---- Helper: Validate admin API key ----

async fn authenticate_admin(headers: &HeaderMap) -> Result<i64, (StatusCode, Json<ApiError>)> {
    // First try the dedicated admin API key
    if let Some(token) = extract_bearer_token(headers) {
        let admin_key = db::get_config("admin_api_key")
            .await
            .unwrap_or_default();
        if !admin_key.is_empty() && token == admin_key {
            return Ok(-1);
        }
    }

    // Fall back to user API key with is_admin check
    let user_id = authenticate_user(headers).await?;
    let pool = db::get_db();
    let is_admin: Option<bool> = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if !is_admin.unwrap_or(false) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "not_admin".to_string(),
                message: "Admin access required".to_string(),
            }),
        ));
    }
    Ok(user_id)
}

// ---- Generic response types ----

#[derive(Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct ApiSuccess<T> {
    pub success: bool,
    pub data: T,
}

fn ok_response<T: Serialize>(data: T) -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "success": true, "data": data })))
}

// ==============================
// Health Handler
// ==============================

// GET /api/v1/health
async fn api_health() -> impl IntoResponse {
    let platform = db::get_config("site_name")
        .await
        .unwrap_or_else(|| "茶的服务器公益站".to_string());
    let started_at = STARTUP_TIME
        .get()
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    (StatusCode::OK, Json(json!({
        "platform": platform,
        "version": "0.1.0",
        "started_at": started_at,
    })))
        .into_response()
}

// ==============================
// Server Contribute API
// ==============================

#[derive(Deserialize)]
pub struct ContributeServerRequest {
    pub name: String,
    pub ip: String,
    pub ssh_port: Option<i32>,
    pub ssh_key: String,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub bandwidth_mbps: Option<f64>,
    pub disk_gb: f64,
    pub cpu_multiplier: Option<f64>,
    pub memory_multiplier: Option<f64>,
    pub bandwidth_multiplier: Option<f64>,
    pub disk_multiplier: Option<f64>,
    pub use_bonus: Option<bool>,
    pub virt_type: Option<String>,
    pub expires_days: Option<i32>,
    pub expose_ip: Option<bool>,
    pub nat_port_start: Option<i32>,
    pub nat_port_end: Option<i32>,
    pub nat_multiplier: Option<f64>,
    pub max_machine_hours: Option<f64>,
    pub free_nat_hours: Option<f64>, // 免费 NAT 额度（小时），由发布者配置
    pub linux_version: Option<String>,
    pub description: Option<String>,
    pub provider: Option<String>,
    pub agent_key: Option<String>,
}

// POST /api/v1/servers/contribute
async fn api_servers_contribute(
    headers: HeaderMap,
    Json(form): Json<ContributeServerRequest>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let now = chrono::Utc::now();
    let expires_days = form.expires_days.unwrap_or(30);
    let expires_at = now + chrono::Duration::days(expires_days as i64);

    let ssh_port = form.ssh_port.unwrap_or(22);
    let bandwidth_mbps = form.bandwidth_mbps.unwrap_or(0.0);
    let cpu_mult = form.cpu_multiplier.unwrap_or(1.0);
    let mem_mult = form.memory_multiplier.unwrap_or(1.0);
    let bw_mult = form.bandwidth_multiplier.unwrap_or(1.0);
    let disk_mult = form.disk_multiplier.unwrap_or(1.0);
    let use_bonus = form.use_bonus.unwrap_or(false);
    let virt_type = form.virt_type.unwrap_or_else(|| "lxd".to_string());
    let expose_ip = form.expose_ip.unwrap_or(false);
    let nat_port_start = form.nat_port_start.unwrap_or(0);
    let nat_port_end = form.nat_port_end.unwrap_or(0);
    let nat_mult = form.nat_multiplier.unwrap_or(1.0);
    let max_machine_hours = form.max_machine_hours.unwrap_or(0.0);
    let free_nat_hours = form.free_nat_hours.unwrap_or(0.0);
    let agent_key = form.agent_key.clone().unwrap_or_default();

    let proxy_port = services::ssh_proxy::allocate_port(0) as i32;

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, expires_at, is_active, proxy_port, agent_installed, agent_key, expose_ip, nat_port_start, nat_port_end, nat_multiplier, max_machine_hours, linux_version, description, provider) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&form.name)
    .bind(&form.ip)
    .bind(ssh_port)
    .bind(&form.ssh_key)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(bandwidth_mbps)
    .bind(form.disk_gb)
    .bind(cpu_mult)
    .bind(mem_mult)
    .bind(bw_mult)
    .bind(disk_mult)
    .bind(use_bonus)
    .bind(&virt_type)
    .bind(expires_at)
    .bind(proxy_port)
    .bind(&agent_key)
    .bind(expose_ip)
    .bind(nat_port_start)
    .bind(nat_port_end)
    .bind(nat_mult)
    .bind(max_machine_hours)
    .bind(free_nat_hours)
    .bind(form.linux_version.as_deref().unwrap_or(""))
    .bind(form.description.as_deref().unwrap_or(""))
    .bind(form.provider.as_deref().unwrap_or(""))
    .execute(pool)
    .await;

    match result {
        Ok(res) => {
            let server_id = res.last_insert_rowid();
            services::ssh_proxy::release_port(0);
            services::ssh_proxy::allocate_port_with_id(server_id, proxy_port as u16);

            let ip = form.ip.clone();
            let ssh_port_copy = ssh_port;
            let ssh_key = form.ssh_key.clone();
            tokio::spawn(async move {
                install_agent_ssh_api(server_id, &ip, ssh_port_copy, &ssh_key).await;
            });

            let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

            ok_response(server).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "insert_failed", "message": format!("{}", e) })),
        )
            .into_response(),
    }
}

async fn install_agent_ssh_api(_server_id: i64, _ip: &str, _port: i32, _ssh_key: &str) {
    let _ = tokio::task::spawn_blocking({
        let ip = _ip.to_string();
        let ssh_key = _ssh_key.to_string();
        let server_id = _server_id;
        move || {
            let tcp = match std::net::TcpStream::connect(format!("{}:{}", ip, _port)) {
                Ok(tcp) => tcp,
                Err(_) => return,
            };
            let mut session = match ssh2::Session::new() {
                Ok(s) => s,
                Err(_) => return,
            };
            session.set_tcp_stream(tcp);
            if session.handshake().is_err() {
                return;
            }
            if session
                .userauth_pubkey_memory("root", None, &ssh_key, None)
                .is_err()
            {
                return;
            }
            if let Ok(mut channel) = session.channel_session() {
                if channel
                    .exec("curl -sSL https://example.com/agent-install.sh | bash")
                    .is_ok()
                {
                    let _ = channel.wait_close();
                    if channel.exit_status().unwrap_or(1) == 0 {
                        let pool = db::get_db();
                        let _ = sqlx::query(
                            "UPDATE servers SET agent_installed = 1 WHERE id = ?",
                        )
                        .bind(server_id)
                        .execute(pool);
                    }
                }
            }
        }
    })
    .await;
}

// ==============================
// Machine Create API
// ==============================

#[derive(Deserialize)]
pub struct CreateMachineRequest {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub hours: Option<i32>,
    pub image: Option<String>,
    pub app_image: Option<String>,
    pub root_password: Option<String>,
    pub app_secrets: Option<String>,
}

// POST /api/v1/machines/create
async fn api_machines_create(
    headers: HeaderMap,
    Json(form): Json<CreateMachineRequest>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let now = chrono::Utc::now();

    // Get full user info including bonus
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "user_not_found" })),
            )
                .into_response()
        }
    };
    let core_hours = user.core_hours;
    let bonus_core_hours = user.bonus_core_hours;
    let total_available = core_hours + bonus_core_hours;

    let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
        .bind(form.server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let server = match server {
        Some(s) if s.is_active && s.expires_at > now => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_unavailable", "message": "Server not found or not active" })),
            )
                .into_response()
        }
    };

    // Validate user input against server limits
    if form.cpu_cores <= 0 || form.cpu_cores > server.cpu_cores {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_cpu", "message": format!("CPU must be between 1 and {}", server.cpu_cores) }))).into_response();
    }
    if form.memory_gb <= 0.0 || form.memory_gb > server.memory_gb {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_memory", "message": format!("Memory must be between 0.1 and {}", server.memory_gb) }))).into_response();
    }
    if form.disk_gb <= 0.0 || form.disk_gb > server.disk_gb {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_disk", "message": format!("Disk must be between 1 and {}", server.disk_gb) }))).into_response();
    }

    // Validate hours
    let mut hours = form.hours.unwrap_or(24) as i64;
    if hours <= 0 {
        hours = 24;
    }

    // Check max machine hours limit
    if server.max_machine_hours > 0.0 && hours as f64 > server.max_machine_hours {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "exceeds_max_hours", "message": "Max machine hours exceeded" })),
        )
            .into_response();
    }

    let mut expires_at = now + chrono::Duration::hours(hours);

    if expires_at > server.expires_at {
        let remaining_hours = (server.expires_at - now).num_hours().max(0);
        if remaining_hours == 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_expired", "message": "Server has expired" })),
            )
                .into_response();
        }
        hours = remaining_hours.min(hours);
        expires_at = now + chrono::Duration::hours(hours);
    }

    // Calculate cost including NAT if expose_ip is enabled
    // NAT ports count based on virt type and OS:
    // - LXD: 1 port (SSH)
    // - KVM Linux: 2 ports (SSH + VNC)
    // - KVM Windows: 3 ports (SSH + RDP + VNC)
    // Free NAT hours are provided by the server publisher
    let image = form.image.as_deref().unwrap_or("ubuntu:22.04");
    let is_windows = image.starts_with("windows:");
    let is_kvm = server.virt_type == "kvm";
    
    let nat_ports = if server.expose_ip && server.nat_port_start > 0 {
        if is_kvm {
            if is_windows { 3 } else { 2 }
        } else {
            1
        }
    } else {
        0
    };
    
    // Calculate NAT cost per hour
    let global_nat = db::get_config("global_nat_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let nat_cost_per_hour = nat_ports as f64 * server.nat_multiplier * global_nat;
    
    // Apply free NAT hours (subtract from total cost)
    let free_nat_hours = server.free_nat_hours;
    let free_nat_amount = if free_nat_hours > 0.0 && nat_cost_per_hour > 0.0 {
        (free_nat_hours.min(hours as f64) * nat_cost_per_hour).min(nat_cost_per_hour * hours as f64)
    } else {
        0.0
    };
    
    let ch_per_hour = services::core_hours::calculate_core_hours_per_hour(
        form.cpu_cores,
        form.memory_gb,
        0.0,
        form.disk_gb,
        server.cpu_multiplier,
        server.memory_multiplier,
        1.0,
        server.disk_multiplier,
        0, // NAT already accounted in free_nat_amount
        0.0,
    )
    .await;

    let nat_cost = (nat_cost_per_hour * hours as f64) - free_nat_amount;
    let total_cost = ch_per_hour * hours as f64 + nat_cost.max(0.0);

    if total_available < total_cost {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": "insufficient_balance", "message": "Not enough core hours" })),
        )
            .into_response();
    }

    // Deduct bonus first, then regular
    let bonus_used = if bonus_core_hours >= total_cost {
        total_cost
    } else {
        bonus_core_hours
    };
    let regular_used = total_cost - bonus_used;

    // Start transaction - all capacity checks happen here atomically
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!("failed to begin machine create transaction: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error", "message": "Failed to start transaction" })),
            )
                .into_response();
        }
    };

    // Check server resource capacity (CPU/Memory/Disk) within transaction
    let used_resources: Option<(Option<i64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT COALESCE(SUM(cpu_cores), 0), COALESCE(SUM(memory_gb), 0.0), COALESCE(SUM(disk_gb), 0.0) FROM machines WHERE server_id = ? AND status IN ('pending', 'running')"
    )
    .bind(server.id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let (used_cpu, used_mem, used_disk) = used_resources.unwrap_or((Some(0), Some(0.0), Some(0.0)));
    let used_cpu = used_cpu.unwrap_or(0) as i32;
    let used_mem = used_mem.unwrap_or(0.0);
    let used_disk = used_disk.unwrap_or(0.0);

    if used_cpu + form.cpu_cores > server.cpu_cores {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "insufficient_cpu", "message": "Server has insufficient CPU capacity" })),
        )
            .into_response();
    }
    if used_mem + form.memory_gb > server.memory_gb {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "insufficient_memory", "message": "Server has insufficient memory capacity" })),
        )
            .into_response();
    }
    if used_disk + form.disk_gb > server.disk_gb {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "insufficient_disk", "message": "Server has insufficient disk capacity" })),
        )
            .into_response();
    }

    // Check NAT port capacity within transaction
    if server.expose_ip && server.nat_port_start > 0 && nat_ports > 0 {
        // Calculate used ports: 1 per LXD machine, 2 per KVM Linux, 3 per KVM Windows
        let used_ports_query = r#"
            SELECT COALESCE(SUM(
                CASE 
                    WHEN virt_type = 'kvm' AND image LIKE 'windows:%' THEN 3
                    WHEN virt_type = 'kvm' THEN 2
                    ELSE 1
                END
            ), 0)
            FROM machines 
            WHERE server_id = ? AND status IN ('pending', 'running')
        "#;
        let used_ports: (i64,) = sqlx::query_as(used_ports_query)
            .bind(server.id)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or((0,));
        let total_available_nat = (server.nat_port_end - server.nat_port_start) as i64;
        if used_ports.0 + nat_ports as i64 > total_available_nat {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "no_nat_ports", "message": format!("Server has no available NAT ports (need {}, have {})", nat_ports, total_available_nat - used_ports.0) })),
            )
                .into_response();
        }
    }

    // Atomic debit with WHERE clause
    let debit_result = sqlx::query(
        "UPDATE users SET bonus_core_hours = bonus_core_hours - ?, core_hours = core_hours - ? WHERE id = ? AND bonus_core_hours >= ? AND core_hours >= ?",
    )
    .bind(bonus_used)
    .bind(regular_used)
    .bind(user_id)
    .bind(bonus_used)
    .bind(regular_used)
    .execute(&mut *tx)
    .await;

    match debit_result {
        Ok(result) if result.rows_affected() > 0 => {}
        Ok(_) => {
            let _ = tx.rollback().await;
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({ "error": "insufficient_balance", "message": "Balance changed, please try again" })),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!("failed to debit machine create cost: {}", err);
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error", "message": "Failed to debit balance" })),
            )
                .into_response();
        }
    };

    // Credit server owner (merchant)
    if bonus_used > 0.0 {
        if let Err(err) = sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours + ?, bonus_expires_at = COALESCE(bonus_expires_at, ?) WHERE id = ?"
        )
        .bind(bonus_used)
        .bind(user.bonus_expires_at)
        .bind(server.owner_id)
        .execute(&mut *tx)
        .await
        {
            tracing::error!("failed to credit merchant bonus balance: {}", err);
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error", "message": "Failed to credit merchant" })),
            )
                .into_response();
        }
    }
    if regular_used > 0.0 {
        if let Err(err) = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
            .bind(regular_used)
            .bind(server.owner_id)
            .execute(&mut *tx)
            .await
        {
            tracing::error!("failed to credit merchant balance: {}", err);
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error", "message": "Failed to credit merchant" })),
            )
                .into_response();
        }
    }

    let proxy_port = server.proxy_port;
    let used_hours = hours as f64;
    let image = form.image.clone().unwrap_or_else(|| "ubuntu:22.04".to_string());
    let app_image = form.app_image.clone().unwrap_or_default();
    let root_password = form.root_password.clone().unwrap_or_default();
    let app_secrets = form.app_secrets.clone().unwrap_or_else(|| "{}".to_string());

    let result = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port, used_hours, root_password, image, app_image, app_secrets, free_nat_hours, regular_core_hours_used, bonus_core_hours_used) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(form.server_id)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(form.disk_gb)
    .bind(&server.virt_type)
    .bind(ch_per_hour)
    .bind(expires_at)
    .bind(proxy_port)
    .bind(used_hours)
    .bind(&root_password)
    .bind(&image)
    .bind(&app_image)
    .bind(&app_secrets)
    .bind(free_nat_hours)
    .bind(regular_used)
    .bind(bonus_used)
    .execute(&mut *tx)
    .await;

    let result = match result {
        Ok(result) => result,
        Err(err) => {
            tracing::error!("failed to insert pending machine: {}", err);
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "insert_failed", "message": "Failed to create machine record" })),
            )
                .into_response();
        }
    };

    let machine_id = result.last_insert_rowid();

    // Log owner income for freeze period tracking
    if bonus_used > 0.0 || regular_used > 0.0 {
        let log_result = sqlx::query(
            "INSERT INTO owner_income_logs (user_id, regular_amount, bonus_amount, source_type, source_id) VALUES (?, ?, ?, 'machine_create', ?)"
        )
        .bind(server.owner_id)
        .bind(regular_used)
        .bind(bonus_used)
        .bind(machine_id)
        .execute(&mut *tx)
        .await;
        if let Err(e) = log_result {
            tracing::error!("failed to log owner income: {}", e);
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error", "message": "Failed to log owner income" })),
            )
                .into_response();
        }
    }

    if let Err(err) = tx.commit().await {
        tracing::error!("failed to commit machine create transaction: {}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db_error", "message": "Failed to commit machine creation" })),
        )
            .into_response();
    }

    // Trigger agent to create VM with retry
    let server_ip = server.ip.clone();
    let machine_name = format!("machine-{}", machine_id);
    let virt_type = server.virt_type.clone();
    let cpu = form.cpu_cores;
    let memory = form.memory_gb;
    let disk = form.disk_gb;

    let agent_key = server.agent_key.clone();
    if agent_key.is_empty() {
        tracing::warn!(server_id = server.id, machine_id = machine_id, "server has no agent_key configured");
    }
    services::machine_lifecycle::spawn_agent_create_job(
        services::machine_lifecycle::MachineProvisioningJob {
            machine_id,
            user_id,
            server_owner_id: server.owner_id,
            server_ip,
            machine_name,
            virt_type,
            cpu,
            memory_gb: memory,
            disk_gb: disk,
            agent_key,
            regular_used,
            bonus_used,
            used_hours,
            image: form.image.clone().unwrap_or_else(|| "ubuntu:22.04".to_string()),
            app_image: form.app_image.clone().unwrap_or_default(),
            root_password: form.root_password.clone().unwrap_or_default(),
            app_secrets: form.app_secrets.clone().unwrap_or_else(|| "{}".to_string()),
        },
    );

    let machine: Option<Machine> = sqlx::query_as("SELECT * FROM machines WHERE id = ?")
        .bind(machine_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    ok_response(machine).into_response()
}

// ==============================
// Redeem API
// ==============================

#[derive(Deserialize)]
pub struct RedeemRequest {
    pub code: String,
}

// POST /api/v1/redeem
async fn api_redeem(
    headers: HeaderMap,
    Json(form): Json<RedeemRequest>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let code: Option<RedeemCode> = sqlx::query_as(
        "SELECT * FROM redeem_codes WHERE code = ? AND is_used = 0",
    )
    .bind(&form.code)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let code = match code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_code", "message": "Invalid or already used redeem code" })),
            )
                .into_response()
        }
    };

    let now = chrono::Utc::now();
    let mut reward_info = json!({});

    match code.code_type.as_str() {
        "core_hours" => {
            let reward = code.core_hours.unwrap_or(0.0);
            let _ = sqlx::query(
                "UPDATE users SET core_hours = core_hours + ? WHERE id = ?",
            )
            .bind(reward)
            .bind(user_id)
            .execute(pool)
            .await;
            reward_info = json!({ "type": "core_hours", "core_hours": reward });
        }
        "subscription" => {
            let pkg_id = code.package_id;
            let _ = sqlx::query(
                "INSERT INTO user_packages (user_id, package_id, core_hours, is_active) VALUES (?, ?, 0, 1)",
            )
            .bind(user_id)
            .bind(pkg_id)
            .execute(pool)
            .await;
            reward_info = json!({ "type": "subscription", "package_id": pkg_id });
        }
        _ => {}
    }

    let _ = sqlx::query(
        "UPDATE redeem_codes SET is_used = 1, used_by = ?, used_at = ? WHERE id = ?",
    )
    .bind(user_id)
    .bind(now)
    .bind(code.id)
    .execute(pool)
    .await;

    ok_response(json!({
        "redeemed": true,
        "reward": reward_info,
    }))
    .into_response()
}

// ==============================
// Packages Buy API
// ==============================

#[derive(Deserialize)]
pub struct BuyPackageRequest {
    pub package_id: i64,
}

// POST /api/v1/packages/buy
async fn api_packages_buy(
    headers: HeaderMap,
    Json(form): Json<BuyPackageRequest>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let pkg: Option<RechargePackage> = sqlx::query_as(
        "SELECT * FROM recharge_packages WHERE id = ? AND is_active = 1",
    )
    .bind(form.package_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let pkg = match pkg {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "package_not_found", "message": "Package not found or inactive" })),
            )
                .into_response()
        }
    };

    let cfg = crate::config::AppConfig::get();
    let out_trade_no = Uuid::new_v4().to_string().replace('-', "");

    let _ = sqlx::query(
        "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, status) VALUES (?, ?, ?, ?, ?, 'pending')",
    )
    .bind(user_id)
    .bind(&out_trade_no)
    .bind(pkg.price_ldc)
    .bind(pkg.core_hours)
    .bind(&pkg.name)
    .execute(pool)
    .await;

    match services::ldc_payment::create_payment(cfg, &out_trade_no, pkg.price_ldc, &pkg.name).await {
        Ok(url) => ok_response(json!({ "payment_url": url, "order_id": out_trade_no })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "payment_failed", "message": format!("{}", e) })),
        )
            .into_response(),
    }
}

// ==============================
// User API v1 Handlers
// ==============================

// GET /api/v1/me
async fn api_me(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    match user {
        Some(mut u) => {
            // Don't leak api_key back in response
            u.api_key = None;
            ok_response(u).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "user_not_found", "message": "User not found" })),
        )
            .into_response(),
    }
}

// POST /api/v1/me/api-key  (regenerate)
async fn api_me_regenerate_key(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let new_key = format!("usr_{}", Uuid::new_v4().to_string().replace('-', ""));
    let pool = db::get_db();
    let _ = sqlx::query("UPDATE users SET api_key = ? WHERE id = ?")
        .bind(&new_key)
        .bind(user_id)
        .execute(pool)
        .await;

    ok_response(json!({ "api_key": new_key })).into_response()
}

// GET /api/v1/servers
async fn api_my_servers(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE owner_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    ok_response(servers).into_response()
}

// GET /api/v1/machines
async fn api_my_machines(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    ok_response(machines).into_response()
}

// GET /api/v1/market
async fn api_market(_headers: HeaderMap) -> impl IntoResponse {
    let pool = db::get_db();
    let now = chrono::Utc::now();
    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE is_active = 1 AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(now)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    ok_response(servers).into_response()
}

// GET /api/v1/orders
async fn api_my_orders(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let orders: Vec<Order> = sqlx::query_as(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    ok_response(orders).into_response()
}

// GET /api/v1/packages
async fn api_packages(_headers: HeaderMap) -> impl IntoResponse {
    let pool = db::get_db();
    let packages: Vec<RechargePackage> = sqlx::query_as(
        "SELECT * FROM recharge_packages WHERE is_active = 1 ORDER BY price_ldc ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    ok_response(packages).into_response()
}

// ==============================
// Admin API Handlers
// ==============================

#[derive(Deserialize)]
pub struct AdminUpdateUser {
    pub is_banned: Option<bool>,
    pub core_hours: Option<f64>,
    pub bonus_core_hours: Option<f64>,
    pub is_admin: Option<bool>,
}

// GET /api/v1/admin/users
async fn api_admin_users(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    // Strip api_keys from list
    let cleaned: Vec<serde_json::Value> = users
        .into_iter()
        .map(|mut u| {
            u.api_key = None;
            serde_json::to_value(u).unwrap_or(json!({}))
        })
        .collect();

    ok_response(cleaned).into_response()
}

// GET /api/v1/admin/users/:id
async fn api_admin_user_detail(headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    match user {
        Some(mut u) => {
            u.api_key = None;
            ok_response(u).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "user_not_found", "message": "User not found" })),
        )
            .into_response(),
    }
}

// PUT /api/v1/admin/users/:id
async fn api_admin_user_update(
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(form): Json<AdminUpdateUser>,
) -> impl IntoResponse {
    let admin_user_id = match authenticate_admin(&headers).await {
        Ok(aid) => aid,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();

    if let Some(banned) = form.is_banned {
        let _ = sqlx::query("UPDATE users SET is_banned = ? WHERE id = ?")
            .bind(banned)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(ch) = form.core_hours {
        let _ = sqlx::query("UPDATE users SET core_hours = ? WHERE id = ?")
            .bind(ch)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(bonus) = form.bonus_core_hours {
        let _ = sqlx::query("UPDATE users SET bonus_core_hours = ? WHERE id = ?")
            .bind(bonus)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(is_admin_val) = form.is_admin {
        // Protect current admin self-revoke via admin api key (id -1)
        // also protect users with id -1 (admin user record itself is rare)
        if is_admin_val || (admin_user_id != id) {
            let _ = sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
                .bind(is_admin_val)
                .bind(id)
                .execute(pool)
                .await;
        }
    }

    // Read back
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    match user {
        Some(mut u) => {
            u.api_key = None;
            ok_response(u).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "user_not_found", "message": "User not found" })),
        )
            .into_response(),
    }
}

// GET /api/v1/admin/servers
async fn api_admin_servers(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let servers: Vec<Server> =
        sqlx::query_as("SELECT * FROM servers ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    ok_response(servers).into_response()
}

// POST /api/v1/admin/servers/:id/toggle
async fn api_admin_server_toggle(headers: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let current: Option<bool> = sqlx::query_scalar("SELECT is_active FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    match current {
        Some(cur) => {
            let new_val = !cur;
            let _ = sqlx::query("UPDATE servers SET is_active = ? WHERE id = ?")
                .bind(new_val)
                .bind(id)
                .execute(pool)
                .await;
            ok_response(json!({ "id": id, "is_active": new_val })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "server_not_found", "message": "Server not found" })),
        )
            .into_response(),
    }
}

// POST /api/v1/admin/servers/batch
async fn api_admin_servers_batch(
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let ids = match body.get("ids").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_i64()).collect::<Vec<i64>>(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_ids"}))).into_response(),
    };
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");

    if ids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "empty_ids"}))).into_response();
    }

    let pool = db::get_db();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

    let mut success = 0;
    let mut failed: Vec<i64> = Vec::new();

    match action {
        "enable" => {
            let query = format!("UPDATE servers SET is_active = 1 WHERE id IN ({})", placeholders);
            let mut q = sqlx::query(&query);
            for id in &ids { q = q.bind(id); }
            match q.execute(pool).await {
                Ok(res) => success = res.rows_affected() as usize,
                Err(_) => failed = ids.clone(),
            }
        }
        "disable" => {
            let query = format!("UPDATE servers SET is_active = 0 WHERE id IN ({})", placeholders);
            let mut q = sqlx::query(&query);
            for id in &ids { q = q.bind(id); }
            match q.execute(pool).await {
                Ok(res) => success = res.rows_affected() as usize,
                Err(_) => failed = ids.clone(),
            }
        }
        "delete" => {
            let query = format!("DELETE FROM servers WHERE id IN ({})", placeholders);
            let mut q = sqlx::query(&query);
            for id in &ids { q = q.bind(id); }
            match q.execute(pool).await {
                Ok(res) => success = res.rows_affected() as usize,
                Err(_) => failed = ids.clone(),
            }
        }
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_action"}))).into_response(),
    }

    ok_response(json!({
        "success": success,
        "failed": failed.len(),
        "failed_ids": failed,
        "action": action,
    })).into_response()
}

// GET /api/v1/admin/machines
async fn api_admin_machines(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machines: Vec<Machine> =
        sqlx::query_as("SELECT * FROM machines ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    ok_response(machines).into_response()
}

// POST /api/v1/admin/machines/batch
async fn api_admin_machines_batch(
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let ids = match body.get("ids").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_i64()).collect::<Vec<i64>>(),
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_ids"}))).into_response(),
    };
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");

    if ids.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "empty_ids"}))).into_response();
    }

    let pool = db::get_db();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

    let mut success_count = 0;
    let mut failed: Vec<i64> = Vec::new();

    match action {
        "stop" => {
            let query = format!("UPDATE machines SET status = 'stopped' WHERE id IN ({}) AND status = 'running'", placeholders);
            let mut q = sqlx::query(&query);
            for id in &ids { q = q.bind(id); }
            match q.execute(pool).await {
                Ok(res) => success_count = res.rows_affected() as usize,
                Err(_) => failed = ids.clone(),
            }
        }
        "start" => {
            let query = format!("UPDATE machines SET status = 'running' WHERE id IN ({}) AND status = 'stopped'", placeholders);
            let mut q = sqlx::query(&query);
            for id in &ids { q = q.bind(id); }
            match q.execute(pool).await {
                Ok(res) => success_count = res.rows_affected() as usize,
                Err(_) => failed = ids.clone(),
            }
        }
        "delete" => {
            for id in &ids {
                match crate::services::machine_lifecycle::refund_machine_remaining(*id).await {
                    Ok(_) => {
                        success_count += 1;
                    }
                    Err(e) => {
                        tracing::error!(machine_id = id, error = %e, "admin batch delete machine failed");
                        failed.push(*id);
                    }
                }
            }
        }
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_action"}))).into_response(),
    }

    ok_response(json!({
        "success": success_count,
        "failed": failed.len(),
        "failed_ids": failed,
        "action": action,
    })).into_response()
}

// GET /api/v1/admin/config
async fn api_admin_config(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let configs: Vec<SiteConfig> = sqlx::query_as("SELECT * FROM site_config ORDER BY key")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    ok_response(configs).into_response()
}

// OpenGFW Config Types
#[derive(Serialize)]
struct OpenGFWConfigResponse {
    enabled: bool,
    block_vpn: bool,
    block_shadowsocks: bool,
    block_wireguard: bool,
    block_openvpn: bool,
    block_trojan: bool,
    block_vmess: bool,
    block_vless: bool,
    block_xray: bool,
    block_clash: bool,
    servers_with_opengfw: Vec<(i64, String, String)>,
}

#[derive(Deserialize)]
struct OpenGFWConfigPatch {
    enabled: bool,
    block_vpn: bool,
    block_shadowsocks: bool,
    block_wireguard: bool,
    block_openvpn: bool,
    block_trojan: bool,
    block_vmess: bool,
    block_vless: bool,
    block_xray: bool,
    block_clash: bool,
}

// GET /api/v1/admin/opengfw/config
async fn api_admin_opengfw_config(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();

    let enabled = db::get_config("opengfw_enabled").await.unwrap_or("false".to_string()) == "true";
    let block_vpn = db::get_config("opengfw_block_vpn").await.unwrap_or("true".to_string()) == "true";
    let block_shadowsocks = db::get_config("opengfw_block_shadowsocks").await.unwrap_or("true".to_string()) == "true";
    let block_wireguard = db::get_config("opengfw_block_wireguard").await.unwrap_or("true".to_string()) == "true";
    let block_openvpn = db::get_config("opengfw_block_openvpn").await.unwrap_or("true".to_string()) == "true";
    let block_trojan = db::get_config("opengfw_block_trojan").await.unwrap_or("true".to_string()) == "true";
    let block_vmess = db::get_config("opengfw_block_vmess").await.unwrap_or("true".to_string()) == "true";
    let block_vless = db::get_config("opengfw_block_vless").await.unwrap_or("true".to_string()) == "true";
    let block_xray = db::get_config("opengfw_block_xray").await.unwrap_or("true".to_string()) == "true";
    let block_clash = db::get_config("opengfw_block_clash").await.unwrap_or("true".to_string()) == "true";

    let servers_with_opengfw: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, name, ip FROM servers WHERE opengfw_enabled = 1 AND is_active = 1"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let config = OpenGFWConfigResponse {
        enabled,
        block_vpn,
        block_shadowsocks,
        block_wireguard,
        block_openvpn,
        block_trojan,
        block_vmess,
        block_vless,
        block_xray,
        block_clash,
        servers_with_opengfw,
    };

    ok_response(config).into_response()
}

// PUT /api/v1/admin/opengfw/config
async fn api_admin_opengfw_config_save(
    headers: HeaderMap,
    Json(form): Json<OpenGFWConfigPatch>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_enabled")
        .bind(form.enabled.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_vpn")
        .bind(form.block_vpn.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_shadowsocks")
        .bind(form.block_shadowsocks.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_wireguard")
        .bind(form.block_wireguard.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_openvpn")
        .bind(form.block_openvpn.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_trojan")
        .bind(form.block_trojan.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_vmess")
        .bind(form.block_vmess.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_vless")
        .bind(form.block_vless.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_xray")
        .bind(form.block_xray.to_string())
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind("opengfw_block_clash")
        .bind(form.block_clash.to_string())
        .execute(pool)
        .await;

    ok_response(json!({ "message": "配置已保存" })).into_response()
}

// GET /api/v1/admin/opengfw/stats
async fn api_admin_opengfw_stats(headers: HeaderMap, Query(params): Query<StatsQuery>) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let (total_blocked, by_protocol, by_server) = services::opengfw::get_block_stats(
        params.start_time.clone(),
        params.end_time.clone(),
        params.server_id,
    ).await;

    let hourly_stats = services::opengfw::get_hourly_stats(params.hours.unwrap_or(24)).await;
    let top_users = services::opengfw::get_top_users(10).await;

    ok_response(json!({
        "total_blocked": total_blocked,
        "by_protocol": by_protocol,
        "by_server": by_server,
        "hourly_stats": hourly_stats,
        "top_users": top_users,
    })).into_response()
}

// GET /api/v1/admin/opengfw/logs
async fn api_admin_opengfw_logs(headers: HeaderMap, Query(params): Query<LogsQuery>) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let logs = services::opengfw::get_recent_logs(
        params.limit.unwrap_or(100),
        params.offset.unwrap_or(0),
        params.server_id,
        params.protocol,
        params.username,
    ).await;

    ok_response(logs).into_response()
}

// POST /api/v1/admin/opengfw/refresh-rules
async fn api_admin_opengfw_refresh(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let servers: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, ip, agent_key FROM servers WHERE is_active = 1 AND opengfw_enabled = 1 AND agent_installed = 1"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut refreshed_servers = 0;
    let mut results = Vec::new();

    for (server_id, server_ip, agent_key) in servers {
        let config = services::opengfw::get_server_opengfw_config(server_id).await;
        if let Some(config) = config {
            let rules = serde_json::to_string(&config.rules).unwrap_or_default();
            let agent_url = format!("http://{}:19527/opengfw/config", server_ip);

            let response = reqwest::Client::new()
                .post(&agent_url)
                .header("X-API-Key", &agent_key)
                .header("Content-Type", "application/json")
                .json(&json!({
                    "enabled": config.enabled,
                    "rules": rules,
                }))
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    refreshed_servers += 1;
                    results.push(json!({
                        "server_ip": server_ip,
                        "status": "ok",
                    }));
                }
                Ok(resp) => {
                    results.push(json!({
                        "server_ip": server_ip,
                        "status": "error",
                        "message": format!("HTTP {}", resp.status()),
                    }));
                }
                Err(err) => {
                    results.push(json!({
                        "server_ip": server_ip,
                        "status": "error",
                        "message": err.to_string(),
                    }));
                }
            }
        }
    }

    ok_response(json!({
        "refreshed_servers": refreshed_servers,
        "results": results,
    })).into_response()
}

// GET /api/v1/admin/opengfw/rules - Get all rules
async fn api_admin_opengfw_rules_list(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let rules = services::opengfw::get_all_rules().await;
    ok_response(rules).into_response()
}

// GET /api/v1/admin/opengfw/rules/templates - Get rule templates
async fn api_admin_opengfw_rules_templates(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let templates = services::opengfw::get_rule_templates();
    ok_response(templates).into_response()
}

// POST /api/v1/admin/opengfw/rules - Create new rule
async fn api_admin_opengfw_rules_create(
    headers: HeaderMap,
    Json(rule): Json<OpenGFWRuleRequest>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    match services::opengfw::add_rule(
        rule.name,
        rule.description,
        rule.protocol,
        rule.match_signature,
        rule.action,
    ).await {
        Ok(id) => (StatusCode::OK, Json(json!({ "id": id, "message": "规则已创建" }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiError { error: "create_failed".to_string(), message: e })).into_response(),
    }
}

// PUT /api/v1/admin/opengfw/rules/:id - Update rule
async fn api_admin_opengfw_rules_update(
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
    Json(rule): Json<OpenGFWRuleRequest>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    match services::opengfw::update_rule(
        rule_id,
        rule.name,
        rule.description,
        rule.protocol,
        rule.match_signature,
        rule.action,
        rule.is_active,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "规则已更新" }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiError { error: "update_failed".to_string(), message: e })).into_response(),
    }
}

// DELETE /api/v1/admin/opengfw/rules/:id - Delete rule
async fn api_admin_opengfw_rules_delete(
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    match services::opengfw::delete_rule(rule_id).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "规则已删除" }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiError { error: "delete_failed".to_string(), message: e })).into_response(),
    }
}

// POST /api/v1/admin/opengfw/rules/:id/toggle - Toggle rule active status
async fn api_admin_opengfw_rules_toggle(
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(false);

    match services::opengfw::toggle_rule(rule_id, active).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": if active { "规则已启用" } else { "规则已禁用" } }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiError { error: "toggle_failed".to_string(), message: e })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ConfigPatch {
    pub key: String,
    pub value: String,
}

// PUT /api/v1/admin/config
async fn api_admin_config_save(
    headers: HeaderMap,
    Json(form): Json<ConfigPatch>,
) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind(&form.key)
        .bind(&form.value)
        .execute(pool)
        .await;

    ok_response(json!({ "key": form.key, "value": form.value })).into_response()
}

// GET /api/v1/admin/orders
async fn api_admin_orders(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let orders: Vec<Order> = sqlx::query_as("SELECT * FROM orders ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    ok_response(orders).into_response()
}

// GET /api/v1/admin/packages
async fn api_admin_packages(headers: HeaderMap) -> impl IntoResponse {
    match authenticate_admin(&headers).await {
        Ok(_) => {}
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let packages: Vec<RechargePackage> =
        sqlx::query_as("SELECT * FROM recharge_packages ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    ok_response(packages).into_response()
}

// ==============================
// Balance to Code API
// ==============================

#[derive(Deserialize)]
struct BalanceToCodeApiRequest {
    amount: f64,
    use_bonus: Option<bool>,
}

async fn api_balance_to_code(
    headers: HeaderMap,
    Json(req): Json<BalanceToCodeApiRequest>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let daily_limit: i64 = db::get_config("balance_to_code_daily_limit").await
        .unwrap_or_else(|| "5".to_string()).parse().unwrap_or(5);
    let fee_pct: f64 = db::get_config("balance_to_code_fee").await
        .unwrap_or_else(|| "0.05".to_string()).parse().unwrap_or(0.05);

    let today_start = chrono::Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM balance_to_code_logs WHERE user_id = ? AND created_at >= ?"
    ).bind(user_id).bind(today_start).fetch_one(pool).await.unwrap_or((0,));

    if today_count.0 >= daily_limit {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":"daily_limit","message":"每日兑换次数已达上限"}))).into_response();
    }

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id).fetch_optional(pool).await.unwrap_or(None);
    let user = match user {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error":"user_not_found"}))).into_response(),
    };

    let fee = req.amount * fee_pct;
    let total_deduct = req.amount + fee;
    let is_bonus = req.use_bonus.unwrap_or(false);

    // Check 14-day freeze period for owner earnings
    let freeze_days: i64 = db::get_config("owner_income_freeze_days").await
        .unwrap_or_else(|| "14".to_string()).parse().unwrap_or(14);

    let total_owner_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ?"
    ).bind(user_id).fetch_optional(pool).await.unwrap_or(None);
    let (total_regular_income, total_bonus_income) = total_owner_income.unwrap_or((0.0, 0.0));

    let freeze_threshold = chrono::Utc::now() - chrono::Duration::days(freeze_days);
    let withdrawable_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ? AND created_at <= ?"
    ).bind(user_id).bind(freeze_threshold).fetch_optional(pool).await.unwrap_or(None);
    let (withdrawable_regular, withdrawable_bonus) = withdrawable_income.unwrap_or((0.0, 0.0));

    let frozen_regular = (total_regular_income - withdrawable_regular).max(0.0);
    let frozen_bonus = (total_bonus_income - withdrawable_bonus).max(0.0);

    if is_bonus {
        let available = (user.bonus_core_hours - frozen_bonus).max(0.0);
        if total_deduct > available {
            return (StatusCode::BAD_REQUEST, Json(json!({
                "error": "frozen_balance",
                "message": format!("赠额核时中有 {:.4} 处于{}天冻结期内，暂不可提现。可用额度: {:.4}", frozen_bonus, freeze_days, available),
                "frozen": frozen_bonus,
                "available": available
            }))).into_response();
        }
        let _ = sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ?")
            .bind(total_deduct).bind(user_id).execute(pool).await;
    } else {
        let available = (user.core_hours - frozen_regular).max(0.0);
        if total_deduct > available {
            return (StatusCode::BAD_REQUEST, Json(json!({
                "error": "frozen_balance",
                "message": format!("普通核时中有 {:.4} 处于{}天冻结期内，暂不可提现。可用额度: {:.4}", frozen_regular, freeze_days, available),
                "frozen": frozen_regular,
                "available": available
            }))).into_response();
        }
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ?")
            .bind(total_deduct).bind(user_id).execute(pool).await;
    }

    let code = format!("balance_{}", Uuid::new_v4().to_string().replace('-', ""));
    let _ = sqlx::query("INSERT INTO redeem_codes (code, code_type, core_hours) VALUES (?, 'core_hours', ?)")
        .bind(&code).bind(req.amount).execute(pool).await;
    let _ = sqlx::query("INSERT INTO balance_to_code_logs (user_id, amount, fee, is_bonus, code) VALUES (?, ?, ?, ?, ?)")
        .bind(user_id).bind(req.amount).bind(fee).bind(is_bonus).bind(&code).execute(pool).await;

    ok_response(json!({"code": code, "amount": req.amount, "fee": fee})).into_response()
}

// ==============================
// Buy Premium API
// ==============================

// POST /api/v1/servers/:id/buy-premium
async fn api_buy_premium(
    headers: HeaderMap,
    Path(server_id): Path<i64>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();

    let premium_enabled = db::get_config("premium_enabled").await.unwrap_or_else(|| "false".to_string());
    if premium_enabled != "true" {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"premium_disabled","message":"优选功能未开放"}))).into_response();
    }

    let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ? AND owner_id = ?")
        .bind(server_id).bind(user_id).fetch_optional(pool).await.unwrap_or(None);

    let server = match server {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error":"server_not_found"}))).into_response(),
    };

    if server.is_premium {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"already_premium"}))).into_response();
    }

    let cost: f64 = db::get_config("premium_ldc_cost").await
        .unwrap_or_else(|| "100".to_string()).parse().unwrap_or(100.0);

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id).fetch_optional(pool).await.unwrap_or(None);
    let user = match user {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error":"user_not_found"}))).into_response(),
    };

    if user.core_hours < cost {
        return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error":"insufficient_balance","message":"核时余额不足"}))).into_response();
    }

    let _ = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ?")
        .bind(cost).bind(user_id).execute(pool).await;
    let _ = sqlx::query("UPDATE servers SET is_premium = 1 WHERE id = ?")
        .bind(server_id).execute(pool).await;

    ok_response(json!({"server_id": server_id, "is_premium": true, "cost": cost})).into_response()
}

// ==============================
// Machine Operations API
// ==============================

// GET /api/v1/images - Get available system images
async fn api_images_list() -> impl IntoResponse {
    let images = vec![
        // Linux 镜像
        json!({"id": "ubuntu:22.04", "name": "Ubuntu 22.04 LTS", "type": "linux", "virt": ["lxd", "kvm"]}),
        json!({"id": "ubuntu:24.04", "name": "Ubuntu 24.04 LTS", "type": "linux", "virt": ["lxd", "kvm"]}),
        json!({"id": "debian:12", "name": "Debian 12 (Bookworm)", "type": "linux", "virt": ["lxd", "kvm"]}),
        json!({"id": "debian:11", "name": "Debian 11 (Bullseye)", "type": "linux", "virt": ["lxd", "kvm"]}),
        json!({"id": "centos:9", "name": "CentOS Stream 9", "type": "linux", "virt": ["lxd", "kvm"]}),
        json!({"id": "alpine:3.19", "name": "Alpine Linux 3.19", "type": "linux", "virt": ["lxd", "kvm"]}),
        // Windows 镜像（仅 KVM）
        json!({"id": "windows:2022", "name": "Windows Server 2022", "type": "windows", "virt": ["kvm"], "note": "需要 KVM 虚拟化"}),
        json!({"id": "windows:2019", "name": "Windows Server 2019", "type": "windows", "virt": ["kvm"], "note": "需要 KVM 虚拟化"}),
        json!({"id": "windows:2025", "name": "Windows Server 2025", "type": "windows", "virt": ["kvm"], "note": "需要 KVM 虚拟化"}),
        json!({"id": "windows:10", "name": "Windows 10", "type": "windows", "virt": ["kvm"], "note": "需要 KVM 虚拟化"}),
        json!({"id": "windows:11", "name": "Windows 11", "type": "windows", "virt": ["kvm"], "note": "需要 KVM 虚拟化"}),
    ];
    ok_response(json!({"images": images}))
}

// GET /api/v1/app-images - Get available application images
async fn api_app_images_list() -> impl IntoResponse {
    let apps = vec![
        json!({"id": "mc", "name": "Minecraft Server", "docker_image": "itzg/minecraft-server", "ports": [25565]}),
        json!({"id": "sub2api", "name": "Subscription Converter", "docker_image": "tindy2013/subconverter", "ports": [25500]}),
        json!({"id": "newapi", "name": "New API", "docker_image": "calciumion/new-api", "ports": [3000]}),
        json!({"id": "cliproxyapi", "name": "CLI Proxy API", "docker_image": "ghcr.io/metacubx/cliproxyapi", "ports": [8080]}),
        json!({"id": "nginx", "name": "Nginx", "docker_image": "nginx:alpine", "ports": [80, 443]}),
        json!({"id": "mysql", "name": "MySQL", "docker_image": "mysql:8.0", "ports": [3306]}),
        json!({"id": "redis", "name": "Redis", "docker_image": "redis:alpine", "ports": [6379]}),
    ];
    ok_response(json!({"app_images": apps}))
}

// GET /api/v1/machines/:id - Get machine detail
async fn api_machine_detail(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machine: Option<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some(m) => {
            let server: Option<Server> = sqlx::query_as(
                "SELECT * FROM servers WHERE id = ?"
            )
            .bind(m.server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            (StatusCode::OK, Json(json!({
                "machine": m,
                "server": server,
            }))).into_response()
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// GET /api/v1/machines/:id/console - Get web console access
async fn api_machine_console(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machine: Option<(i64, i64, String, String)> = sqlx::query_as(
        "SELECT id, server_id, virt_type, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some((id, server_id, _virt_type, status)) => {
            if status != "running" {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "machine not running"}))).into_response();
            }

            // Get server IP and agent key
            let server: Option<(String, String)> = sqlx::query_as(
                "SELECT ip, agent_key FROM servers WHERE id = ?"
            )
            .bind(server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match server {
                Some((ip, agent_key)) => {
                    let machine_name = format!("machine-{}", id);
                    let client = reqwest::Client::new();
                    let url = format!("http://{}:19527/console/{}", ip, machine_name);
                    
                    let resp = client
                        .get(&url)
                        .header("X-API-Key", &agent_key)
                        .timeout(std::time::Duration::from_secs(10))
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            let data: Value = r.json().await.unwrap_or(json!({"error": "parse error"}));
                            (StatusCode::OK, Json(data)).into_response()
                        },
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "agent unreachable"}))).into_response(),
                    }
                },
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// POST /api/v1/machines/:id/exec - Execute command in machine
async fn api_machine_exec(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let command = body.get("command").and_then(|v| v.as_str()).unwrap_or("");

    if command.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "command required"}))).into_response();
    }

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some((id, server_id, status)) => {
            if status != "running" {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "machine not running"}))).into_response();
            }

            let server: Option<(String, String)> = sqlx::query_as(
                "SELECT ip, agent_key FROM servers WHERE id = ?"
            )
            .bind(server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match server {
                Some((ip, agent_key)) => {
                    let machine_name = format!("machine-{}", id);
                    let client = reqwest::Client::new();
                    let url = format!("http://{}:19527/exec/{}", ip, machine_name);
                    
                    let resp = client
                        .post(&url)
                        .header("X-API-Key", &agent_key)
                        .json(&json!({"command": command}))
                        .timeout(std::time::Duration::from_secs(60))
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            let data: Value = r.json().await.unwrap_or(json!({"error": "parse error"}));
                            (StatusCode::OK, Json(data)).into_response()
                        },
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "agent unreachable"}))).into_response(),
                    }
                },
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// POST /api/v1/machines/:id/reinstall - Reinstall machine
async fn api_machine_reinstall(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let image = body.get("image").and_then(|v| v.as_str()).unwrap_or("ubuntu:22.04");
    let app_image = body.get("app_image").and_then(|v| v.as_str()).unwrap_or("");

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some((id, server_id, _status)) => {
            let server: Option<(String, String)> = sqlx::query_as(
                "SELECT ip, agent_key FROM servers WHERE id = ?"
            )
            .bind(server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match server {
                Some((ip, agent_key)) => {
                    let machine_name = format!("machine-{}", id);
                    let client = reqwest::Client::new();
                    let url = format!("http://{}:19527/reinstall/{}", ip, machine_name);
                    
                    let resp = client
                        .post(&url)
                        .header("X-API-Key", &agent_key)
                        .json(&json!({"image": image, "app_image": app_image}))
                        .timeout(std::time::Duration::from_secs(120))
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            // Update image in database
                            sqlx::query("UPDATE machines SET image = ?, app_image = ? WHERE id = ?")
                                .bind(image)
                                .bind(app_image)
                                .bind(id)
                                .execute(pool)
                                .await
                                .ok();
                            
                            let data: Value = r.json().await.unwrap_or(json!({"error": "parse error"}));
                            (StatusCode::OK, Json(data)).into_response()
                        },
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "reinstall failed"}))).into_response(),
                    }
                },
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// POST /api/v1/machines/:id/app-install - Install app in machine
async fn api_machine_app_install(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let app_image = body.get("app_image").and_then(|v| v.as_str()).unwrap_or("");
    let secrets = body.get("secrets").cloned().unwrap_or(json!({}));

    if app_image.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "app_image required"}))).into_response();
    }

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some((id, server_id, status)) => {
            if status != "running" {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "machine not running"}))).into_response();
            }

            let server: Option<(String, String)> = sqlx::query_as(
                "SELECT ip, agent_key FROM servers WHERE id = ?"
            )
            .bind(server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match server {
                Some((ip, agent_key)) => {
                    let machine_name = format!("machine-{}", id);
                    let client = reqwest::Client::new();
                    let url = format!("http://{}:19527/app-install/{}", ip, machine_name);
                    
                    let resp = client
                        .post(&url)
                        .header("X-API-Key", &agent_key)
                        .json(&json!({"app_image": app_image, "secrets": secrets}))
                        .timeout(std::time::Duration::from_secs(120))
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            // Update app_image and app_secrets in database
                            let secrets_str = secrets.to_string();
                            sqlx::query("UPDATE machines SET app_image = ?, app_secrets = ? WHERE id = ?")
                                .bind(app_image)
                                .bind(secrets_str)
                                .bind(id)
                                .execute(pool)
                                .await
                                .ok();
                            
                            let data: Value = r.json().await.unwrap_or(json!({"error": "parse error"}));
                            (StatusCode::OK, Json(data)).into_response()
                        },
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "app install failed"}))).into_response(),
                    }
                },
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// POST /api/v1/machines/:id/app-uninstall - Uninstall app from machine
async fn api_machine_app_uninstall(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let app_image = body.get("app_image").and_then(|v| v.as_str()).unwrap_or("");

    if app_image.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "app_image required"}))).into_response();
    }

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match machine {
        Some((id, server_id, status)) => {
            if status != "running" {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "machine not running"}))).into_response();
            }

            let server: Option<(String, String)> = sqlx::query_as(
                "SELECT ip, agent_key FROM servers WHERE id = ?"
            )
            .bind(server_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match server {
                Some((ip, agent_key)) => {
                    let machine_name = format!("machine-{}", id);
                    let client = reqwest::Client::new();
                    let url = format!("http://{}:19527/app-uninstall/{}", ip, machine_name);
                    
                    let resp = client
                        .post(&url)
                        .header("X-API-Key", &agent_key)
                        .json(&json!({"app_image": app_image}))
                        .timeout(std::time::Duration::from_secs(30))
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            // Clear app_image in database
                            sqlx::query("UPDATE machines SET app_image = '' WHERE id = ?")
                                .bind(id)
                                .execute(pool)
                                .await
                                .ok();
                            
                            let data: Value = r.json().await.unwrap_or(json!({"error": "parse error"}));
                            (StatusCode::OK, Json(data)).into_response()
                        },
                        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "app uninstall failed"}))).into_response(),
                    }
                },
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
            }
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    }
}

// GET /api/v1/machines/:id/port-forwards - List port forwards
async fn api_machine_port_forwards_list(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (id, server_id, _status) = match machine {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    };

    // Get server info
    let server: Option<(String, String)> = sqlx::query_as(
        "SELECT ip, agent_key FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (ip, agent_key) = match server {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
    };

    let machine_name = format!("machine-{}", id);
    let client = reqwest::Client::new();
    let url = format!("http://{}:19527/port-forwards/{}", ip, machine_name);

    let resp = client
        .get(&url)
        .header("X-API-Key", &agent_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let data: Value = r.json().await.unwrap_or(json!({"forwards": []}));
            (StatusCode::OK, Json(data)).into_response()
        },
        Ok(r) => {
            let msg = r.text().await.unwrap_or_default();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "failed to list", "detail": msg}))).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// POST /api/v1/machines/:id/port-forwards - Add port forward
async fn api_machine_port_forward_add(
    headers: HeaderMap,
    Path(machine_id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let vm_port = body.get("vm_port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let protocol = body.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
    let host_port = body.get("host_port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if vm_port <= 0 || vm_port > 65535 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid vm_port"}))).into_response();
    }
    if protocol != "tcp" && protocol != "udp" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid protocol"}))).into_response();
    }

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (id, server_id, status) = match machine {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    };

    if status != "running" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "machine not running"}))).into_response();
    }

    let server: Option<(String, String)> = sqlx::query_as(
        "SELECT ip, agent_key FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (ip, agent_key) = match server {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
    };

    let machine_name = format!("machine-{}", id);
    let client = reqwest::Client::new();
    let url = format!("http://{}:19527/port-forward/add/{}", ip, machine_name);

    let req_body = json!({
        "vm_port": vm_port,
        "protocol": protocol,
        "host_port": if host_port > 0 { host_port } else { 0 },
    });

    let resp = client
        .post(&url)
        .header("X-API-Key", &agent_key)
        .json(&req_body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let data: Value = r.json().await.unwrap_or(json!({"status": "ok"}));
            let hp = data.get("host_port").and_then(|v| v.as_i64()).unwrap_or(host_port as i64) as i32;
            let vip = data.get("vm_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
            
            sqlx::query(
                "INSERT INTO port_forwards (machine_id, server_id, user_id, name, protocol, host_port, vm_port, vm_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(id)
            .bind(server_id)
            .bind(user_id)
            .bind(&name)
            .bind(&protocol)
            .bind(hp)
            .bind(vm_port)
            .bind(&vip)
            .execute(pool)
            .await
            .ok();

            match crate::services::machine_lifecycle::charge_nat_port_add(id, 1).await {
                Ok((regular, bonus)) => {
                    let mut result = data.clone();
                    result["regular_charged"] = json!(regular);
                    result["bonus_charged"] = json!(bonus);
                    result["total_charged"] = json!(regular + bonus);
                    (StatusCode::OK, Json(result)).into_response()
                }
                Err(e) => {
                    tracing::warn!(machine_id = id, error = %e, "failed to charge for NAT port, rolling back db record");
                    let _ = sqlx::query("DELETE FROM port_forwards WHERE machine_id = ? AND host_port = ? AND user_id = ?")
                        .bind(id)
                        .bind(hp)
                        .bind(user_id)
                        .execute(pool)
                        .await;
                    (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": "insufficient balance", "detail": e.to_string()}))).into_response()
                }
            }
        },
        Ok(r) => {
            let msg = r.text().await.unwrap_or_default();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "add failed", "detail": msg}))).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// DELETE /api/v1/machines/:id/port-forwards/:host_port - Delete port forward
async fn api_machine_port_forward_delete(
    headers: HeaderMap,
    Path((machine_id, host_port)): Path<(i64, i32)>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, server_id, status FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (id, server_id, _status) = match machine {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "machine not found"}))).into_response(),
    };

    let server: Option<(String, String)> = sqlx::query_as(
        "SELECT ip, agent_key FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (ip, agent_key) = match server {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "server not found"}))).into_response(),
    };

    let machine_name = format!("machine-{}", id);
    let client = reqwest::Client::new();
    let url = format!("http://{}:19527/port-forward/{}/{}", ip, machine_name, host_port);

    let resp = client
        .delete(&url)
        .header("X-API-Key", &agent_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            sqlx::query("DELETE FROM port_forwards WHERE machine_id = ? AND host_port = ? AND user_id = ?")
                .bind(id)
                .bind(host_port)
                .bind(user_id)
                .execute(pool)
                .await
                .ok();
            
            let refund_result = crate::services::machine_lifecycle::refund_nat_port_remove(id, 1).await;
            let data: Value = r.json().await.unwrap_or(json!({"status": "ok"}));
            let mut result = data.clone();
            
            match refund_result {
                Ok((regular, bonus)) => {
                    result["regular_refunded"] = json!(regular);
                    result["bonus_refunded"] = json!(bonus);
                    result["total_refunded"] = json!(regular + bonus);
                }
                Err(e) => {
                    tracing::warn!(machine_id = id, error = %e, "failed to refund for NAT port removal");
                    result["refund_warning"] = json!(e.to_string());
                }
            }
            
            (StatusCode::OK, Json(result)).into_response()
        },
        Ok(r) => {
            let msg = r.text().await.unwrap_or_default();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "delete failed", "detail": msg}))).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ==============================
// Router builder
// ==============================

pub fn router(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/health", get(api_health))
        .route("/v1/me", get(api_me).post(api_me_regenerate_key))
        .route("/v1/me/api-key", post(api_me_regenerate_key))
        .route("/v1/servers", get(api_my_servers))
        .route("/v1/servers/contribute", post(api_servers_contribute))
        .route("/v1/servers/:id/buy-premium", post(api_buy_premium))
        .route("/v1/machines", get(api_my_machines))
        .route("/v1/machines/create", post(api_machines_create))
        .route("/v1/market", get(api_market))
        .route("/v1/orders", get(api_my_orders))
        .route("/v1/packages", get(api_packages))
        .route("/v1/packages/buy", post(api_packages_buy))
        .route("/v1/redeem", post(api_redeem))
        .route("/v1/balance-to-code", post(api_balance_to_code))
        .route("/v1/admin/users", get(api_admin_users))
        .route(
            "/v1/admin/users/:id",
            get(api_admin_user_detail).put(api_admin_user_update),
        )
        .route("/v1/admin/servers", get(api_admin_servers))
        .route(
            "/v1/admin/servers/:id/toggle",
            post(api_admin_server_toggle),
        )
        .route("/v1/admin/servers/batch", post(api_admin_servers_batch))
        .route("/v1/admin/machines", get(api_admin_machines))
        .route("/v1/admin/machines/batch", post(api_admin_machines_batch))
        .route(
            "/v1/admin/config",
            get(api_admin_config).put(api_admin_config_save),
        )
        .route(
            "/v1/admin/opengfw/config",
            get(api_admin_opengfw_config).put(api_admin_opengfw_config_save),
        )
        .route("/v1/admin/opengfw/stats", get(api_admin_opengfw_stats))
        .route("/v1/admin/opengfw/logs", get(api_admin_opengfw_logs))
        .route("/v1/admin/opengfw/refresh-rules", post(api_admin_opengfw_refresh))
        // Rule management endpoints
        .route("/v1/admin/opengfw/rules", get(api_admin_opengfw_rules_list))
        .route("/v1/admin/opengfw/rules/templates", get(api_admin_opengfw_rules_templates))
        .route("/v1/admin/opengfw/rules", post(api_admin_opengfw_rules_create))
        .route("/v1/admin/opengfw/rules/:id", put(api_admin_opengfw_rules_update))
        .route("/v1/admin/opengfw/rules/:id", delete(api_admin_opengfw_rules_delete))
        .route("/v1/admin/opengfw/rules/:id/toggle", post(api_admin_opengfw_rules_toggle))
        .route("/v1/admin/orders", get(api_admin_orders))
        .route("/v1/admin/packages", get(api_admin_packages))
        // Machine operations
        .route("/v1/images", get(api_images_list))
        .route("/v1/app-images", get(api_app_images_list))
        .route("/v1/machines/:id", get(api_machine_detail))
        .route("/v1/machines/:id/console", get(api_machine_console))
        .route("/v1/machines/:id/exec", post(api_machine_exec))
        .route("/v1/machines/:id/reinstall", post(api_machine_reinstall))
        .route("/v1/machines/:id/app-install", post(api_machine_app_install))
        .route("/v1/machines/:id/app-uninstall", post(api_machine_app_uninstall))
        .route("/v1/machines/:id/port-forwards", get(api_machine_port_forwards_list))
        .route("/v1/machines/:id/port-forwards", post(api_machine_port_forward_add))
        .route("/v1/machines/:id/port-forwards/:host_port", delete(api_machine_port_forward_delete))
}
