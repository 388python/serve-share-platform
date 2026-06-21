use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    pub linux_version: Option<String>,
    pub description: Option<String>,
    pub provider: Option<String>,
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

    let proxy_port = services::ssh_proxy::allocate_port(0) as i32;

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, expires_at, is_active, proxy_port, agent_installed, expose_ip, nat_port_start, nat_port_end, nat_multiplier, max_machine_hours, linux_version, description, provider) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(expose_ip)
    .bind(nat_port_start)
    .bind(nat_port_end)
    .bind(nat_mult)
    .bind(max_machine_hours)
    .bind(form.linux_version.as_deref().unwrap_or(""))
    .bind(form.description.as_deref().unwrap_or(""))
    .bind(form.provider.as_deref().unwrap_or(""))
    .execute(pool)
    .await;

    match result {
        Ok(res) => {
            let server_id = res.last_insert_rowid();
            services::ssh_proxy::release_port(0);
            services::ssh_proxy::allocate_port(server_id);

            let _ = sqlx::query("UPDATE servers SET proxy_port = ? WHERE id = ?")
                .bind(proxy_port)
                .bind(server_id)
                .execute(pool)
                .await;

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

    let ch_per_hour = services::core_hours::calculate_core_hours_per_hour(
        form.cpu_cores,
        form.memory_gb,
        0.0,
        form.disk_gb,
        server.cpu_multiplier,
        server.memory_multiplier,
        1.0,
        server.disk_multiplier,
        0,
        0.0,
    )
    .await;

    let total_cost = ch_per_hour * hours as f64;

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
    if server.expose_ip && server.nat_port_start > 0 {
        let used_ports: (i64,) = sqlx::query_as(
            "SELECT COALESCE(COUNT(*), 0) FROM machines WHERE server_id = ? AND status IN ('pending', 'running')"
        )
        .bind(server.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or((0,));
        let total_available_nat = (server.nat_port_end - server.nat_port_start) as i64;
        if used_ports.0 + 1 > total_available_nat {
            let _ = tx.rollback().await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "no_nat_ports", "message": "Server has no available NAT ports" })),
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

    let result = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port, used_hours) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
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

    let agent_key = "tea-platform-agent-key".to_string();
    services::machine_lifecycle::spawn_agent_create_job(
        services::machine_lifecycle::MachineProvisioningJob {
            machine_id,
            user_id,
            owner_id: server.owner_id,
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
    pub ldc_balance: Option<f64>,
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
    if let Some(ldc) = form.ldc_balance {
        let _ = sqlx::query("UPDATE users SET ldc_balance = ? WHERE id = ?")
            .bind(ldc)
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

    if is_bonus {
        if user.bonus_core_hours < total_deduct {
            return (StatusCode::BAD_REQUEST, Json(json!({"error":"insufficient_bonus"}))).into_response();
        }
        let _ = sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ?")
            .bind(total_deduct).bind(user_id).execute(pool).await;
    } else {
        if user.core_hours < total_deduct {
            return (StatusCode::BAD_REQUEST, Json(json!({"error":"insufficient_balance"}))).into_response();
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

    if user.ldc_balance < cost {
        return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error":"insufficient_ldc","message":"LDC 余额不足"}))).into_response();
    }

    let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ?")
        .bind(cost).bind(user_id).execute(pool).await;
    let _ = sqlx::query("UPDATE servers SET is_premium = 1 WHERE id = ?")
        .bind(server_id).execute(pool).await;

    ok_response(json!({"server_id": server_id, "is_premium": true, "cost_ldc": cost})).into_response()
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
        .route("/v1/admin/machines", get(api_admin_machines))
        .route(
            "/v1/admin/config",
            get(api_admin_config).put(api_admin_config_save),
        )
        .route("/v1/admin/orders", get(api_admin_orders))
        .route("/v1/admin/packages", get(api_admin_packages))
}
