use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db;
use crate::models::*;
use crate::services;
use crate::AppState;

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
        "SELECT * FROM servers WHERE is_active = 1 AND expires_at > ? ORDER BY (cpu_cores - COALESCE((SELECT SUM(cpu_cores) FROM machines WHERE server_id = servers.id AND status = 'running'), 0)) DESC, created_at DESC",
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

// POST /api/v1/servers/contribute
#[derive(Deserialize)]
pub struct ApiContributeServer {
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
}

async fn api_contribute_server(
    headers: HeaderMap,
    Json(form): Json<ApiContributeServer>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let now = Utc::now();
    let expires_days = form.expires_days.unwrap_or(30);
    let expires_at = now + chrono::Duration::days(expires_days as i64);

    let virt_type = form.virt_type.unwrap_or_else(|| "lxd".to_string());
    let ssh_port = form.ssh_port.unwrap_or(22);
    let bandwidth_mbps = form.bandwidth_mbps.unwrap_or(0.0);
    let cpu_mult = form.cpu_multiplier.unwrap_or(1.0);
    let mem_mult = form.memory_multiplier.unwrap_or(1.0);
    let bw_mult = form.bandwidth_multiplier.unwrap_or(1.0);
    let disk_mult = form.disk_multiplier.unwrap_or(1.0);
    let use_bonus = form.use_bonus.unwrap_or(false);

    let proxy_port = services::ssh_proxy::allocate_port(0) as i32;

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, expires_at, is_active, proxy_port, agent_installed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0)",
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

            let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

            match server {
                Some(s) => ok_response(s).into_response(),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "server_not_found", "message": "Server created but not found" })),
                ).into_response(),
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "insert_failed", "message": format!("{}", e) })),
        ).into_response(),
    }
}

// POST /api/v1/machines/create
#[derive(Deserialize)]
pub struct ApiCreateMachine {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub hours: Option<i32>,
}

async fn api_create_machine(
    headers: HeaderMap,
    Json(form): Json<ApiCreateMachine>,
) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let pool = db::get_db();
    let now = Utc::now();

    let user: Option<(f64,)> =
        sqlx::query_as("SELECT core_hours FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let core_hours = user.unwrap_or((0.0,)).0;

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
                Json(json!({ "error": "invalid_server", "message": "Server not available" })),
            ).into_response();
        }
    };

    let mut hours = form.hours.unwrap_or(24) as i64;
    let mut expires_at = now + chrono::Duration::hours(hours);

    if expires_at > server.expires_at {
        let remaining_hours = (server.expires_at - now).num_hours().max(0);
        if remaining_hours == 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_expired", "message": "Server has expired" })),
            ).into_response();
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
    )
    .await;

    let total_cost = ch_per_hour * hours as f64;

    if core_hours < total_cost {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": "insufficient_balance", "message": "Not enough core hours" })),
        ).into_response();
    }

    let new_core_hours = core_hours - total_cost;
    let _ = sqlx::query("UPDATE users SET core_hours = ? WHERE id = ?")
        .bind(new_core_hours)
        .bind(user_id)
        .execute(pool)
        .await;

    let proxy_port = server.proxy_port;

    let result = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)",
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
    .execute(pool)
    .await;

    match result {
        Ok(res) => {
            let machine_id = res.last_insert_rowid();

            let _ = sqlx::query(
                "UPDATE users SET total_usage_hours = total_usage_hours + ? WHERE id = ?",
            )
            .bind(hours as f64)
            .bind(user_id)
            .execute(pool)
            .await;

            let machine: Option<Machine> = sqlx::query_as("SELECT * FROM machines WHERE id = ?")
                .bind(machine_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

            match machine {
                Some(m) => ok_response(m).into_response(),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "machine_not_found", "message": "Machine created but not found" })),
                ).into_response(),
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "insert_failed", "message": format!("{}", e) })),
        ).into_response(),
    }
}

// POST /api/v1/redeem
#[derive(Deserialize)]
pub struct ApiRedeem {
    pub code: String,
}

async fn api_redeem(
    headers: HeaderMap,
    Json(form): Json<ApiRedeem>,
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
                Json(json!({ "error": "invalid_code", "message": "Invalid or used redeem code" })),
            ).into_response();
        }
    };

    let now = Utc::now();

    match code.code_type.as_str() {
        "core_hours" => {
            let reward = code.core_hours.unwrap_or(0.0);
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(reward)
                .bind(user_id)
                .execute(pool)
                .await;
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

    ok_response(json!({ "code": form.code, "redeemed": true })).into_response()
}

// POST /api/v1/packages/buy
#[derive(Deserialize)]
pub struct ApiBuyPackage {
    pub package_id: i64,
}

async fn api_buy_package(
    headers: HeaderMap,
    Json(form): Json<ApiBuyPackage>,
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
                Json(json!({ "error": "package_not_found", "message": "Package not found" })),
            ).into_response();
        }
    };

    let cfg = AppConfig::get();
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
        Ok(url) => ok_response(json!({ "payment_url": url })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "payment_failed", "message": "Failed to create payment" })),
        ).into_response(),
    }
}

// POST /api/v1/checkin
async fn api_checkin(headers: HeaderMap) -> impl IntoResponse {
    let user_id = match authenticate_user(&headers).await {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };

    let checkin_enabled = db::get_config("checkin_enabled")
        .await
        .unwrap_or_else(|| "true".to_string());
    if checkin_enabled != "true" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "checkin_disabled", "message": "Checkin is currently disabled" })),
        ).into_response();
    }

    let pool = db::get_db();
    let now = Utc::now();
    let today = now.date_naive();

    let last_checkin: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT last_checkin FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .flatten();

    if let Some(last) = last_checkin {
        if last.date_naive() == today {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "already_checked_in", "message": "Already checked in today" })),
            ).into_response();
        }
    }

    let reward: f64 = db::get_config("checkin_reward")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);

    let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ?, last_checkin = ? WHERE id = ?")
        .bind(reward)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await;

    let _ = sqlx::query(
        "INSERT INTO checkins (user_id, reward_core_hours) VALUES (?, ?)",
    )
    .bind(user_id)
    .bind(reward)
    .execute(pool)
    .await;

    ok_response(json!({ "reward": reward, "checked_in": true })).into_response()
}

// POST /api/v1/agent/violations
#[derive(Deserialize)]
pub struct AgentViolation {
    pub server_id: Option<i64>,
    pub machine_id: Option<i64>,
    pub violation_type: String,
    pub detail: Option<String>,
}

async fn api_agent_violations(
    headers: HeaderMap,
    Json(form): Json<AgentViolation>,
) -> impl IntoResponse {
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if api_key != "tea-platform-agent-key" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": "Invalid agent key" })),
        ).into_response();
    }

    let pool = db::get_db();
    let _ = sqlx::query(
        "INSERT INTO violations (server_id, machine_id, violation_type, detail) VALUES (?, ?, ?, ?)",
    )
    .bind(form.server_id)
    .bind(form.machine_id)
    .bind(&form.violation_type)
    .bind(form.detail.unwrap_or_default())
    .execute(pool)
    .await;

    ok_response(json!({ "recorded": true })).into_response()
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
// Router builder
// ==============================

pub fn router(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/me", get(api_me).post(api_me_regenerate_key))
        .route("/v1/me/api-key", post(api_me_regenerate_key))
        .route("/v1/servers", get(api_my_servers))
        .route("/v1/servers/contribute", post(api_contribute_server))
        .route("/v1/machines", get(api_my_machines))
        .route("/v1/machines/create", post(api_create_machine))
        .route("/v1/market", get(api_market))
        .route("/v1/orders", get(api_my_orders))
        .route("/v1/packages", get(api_packages))
        .route("/v1/packages/buy", post(api_buy_package))
        .route("/v1/redeem", post(api_redeem))
        .route("/v1/checkin", post(api_checkin))
        .route("/v1/agent/violations", post(api_agent_violations))
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
