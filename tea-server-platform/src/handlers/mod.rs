use axum::{
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tera::Context;
use tower_cookies::{cookie::SameSite, cookie::time::Duration, Cookie, Cookies};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub mod api;

use crate::config::AppConfig;
use crate::db;
use crate::models::*;
use crate::services;
use crate::AppState;

// ---- Session Cookie Signing ----

pub const SESSION_TTL_SECS: i64 = 86400; // 24 小时

fn session_key_bytes() -> Vec<u8> {
    AppConfig::get().session_secret.as_bytes().to_vec()
}

/// HMAC-SHA256 对给定 payload 签名，返回 64 位 hex 字符串
fn sign_bytes(payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(&session_key_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"default-signing-key").expect("HMAC init"));
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    let mut out = String::with_capacity(result.len() * 2);
    use std::fmt::Write;
    for b in &result[..] {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Constant-time 验证 HMAC-SHA256 签名
fn verify_sig(payload: &[u8], expected_hex: &str) -> bool {
    let expected = match hex::decode(expected_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if expected.is_empty() {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(&session_key_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"default-signing-key").expect("HMAC init"));
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionPayload {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    pub core_hours: f64,
    pub ldc_balance: f64,
    pub iat: i64,   // issued at (unix timestamp)
    pub exp: i64,   // expires
}

impl SessionPayload {
    pub fn new(user_id: i64, username: &str, is_admin: bool, core_hours: f64, ldc_balance: f64) -> Self {
        let now = Utc::now().timestamp();
        Self {
            user_id,
            username: username.to_string(),
            is_admin,
            core_hours,
            ldc_balance,
            iat: now,
            exp: now + SESSION_TTL_SECS,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.exp < Utc::now().timestamp()
    }
}

/// 将 SessionPayload 编码为 `base64(json).signature` 格式的 cookie 值
pub fn encode_session(session: &SessionPayload) -> String {
    let json = serde_json::to_string(session).expect("session JSON serialization");
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        json.as_bytes(),
    );
    let sig = sign_bytes(b64.as_bytes());
    format!("{}.{}", b64, sig)
}

/// 解码 `base64(json).signature`，验证签名和过期
pub fn decode_session(cookie_value: &str) -> Option<SessionPayload> {
    let dot = cookie_value.rfind('.')?;
    let (b64, sig) = cookie_value.split_at(dot);
    let sig = &sig[1..]; // skip '.'

    if !verify_sig(b64.as_bytes(), sig) {
        tracing::warn!("session: invalid signature rejected");
        return None;
    }

    let json_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        b64.as_bytes(),
    ).ok()?;

    let session: SessionPayload = serde_json::from_slice(&json_bytes).ok()?;
    if session.is_expired() {
        tracing::warn!("session: expired session rejected (user_id={})", session.user_id);
        return None;
    }
    Some(session)
}

// ---- Session Helpers ----

fn get_session_user(cookies: &Cookies) -> Option<(i64, String, bool)> {
    let session_cookie = cookies.get("session")?;
    let session = decode_session(session_cookie.value())?;
    Some((session.user_id, session.username, session.is_admin))
}

fn require_auth(cookies: &Cookies) -> Result<(i64, String, bool), Redirect> {
    get_session_user(cookies).ok_or_else(|| Redirect::to("/login"))
}

fn require_admin(cookies: &Cookies) -> Result<(i64, String), Redirect> {
    let (user_id, username, is_admin) = require_auth(cookies)?;
    if !is_admin {
        return Err(Redirect::to("/"));
    }
    Ok((user_id, username))
}

fn build_base_context(cookies: &Cookies, ctx: &mut Context) {
    let site_name = db::get_config_sync("site_name")
        .unwrap_or_else(|| "茶的服务器公益站".to_string());
    ctx.insert("site_name", &site_name);

    if let Some(session_cookie) = cookies.get("session") {
        if let Some(session) = decode_session(session_cookie.value()) {
            ctx.insert("user_name", &session.username);
            ctx.insert("user_balance", &format!("{:.2}", session.core_hours));
            ctx.insert("user_ldc", &format!("{:.2}", session.ldc_balance));
            ctx.insert("is_admin", &session.is_admin.to_string());
        }
    }
}

fn set_session_cookie(
    cookies: &Cookies,
    user_id: i64,
    username: &str,
    is_admin: bool,
    core_hours: f64,
    ldc_balance: f64,
) {
    let payload = SessionPayload::new(user_id, username, is_admin, core_hours, ldc_balance);
    let cookie_value = encode_session(&payload);

    let mut cookie = Cookie::new("session", cookie_value);
    cookie.set_path("/");
    cookie.set_max_age(Duration::seconds(SESSION_TTL_SECS));
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookies.add(cookie);
}

/// 公开包装：解析签名 session cookie（供 main.rs/index_page 使用）
pub fn parse_signed_session_wrapper(
    cookie_value: &str,
) -> Option<HashMap<String, String>> {
    let session = decode_session(cookie_value)?;
    let mut map = HashMap::new();
    map.insert("username".to_string(), session.username);
    map.insert("user_id".to_string(), session.user_id.to_string());
    map.insert("core_hours".to_string(), format!("{:.2}", session.core_hours));
    map.insert("ldc_balance".to_string(), format!("{:.2}", session.ldc_balance));
    map.insert("is_admin".to_string(), session.is_admin.to_string());
    Some(map)
}

/// 公开包装：写入签名 session cookie（供 main.rs/auth_callback 使用）
pub fn set_session_cookie_wrapper(
    cookies: &Cookies,
    user_id: i64,
    username: &str,
    is_admin: bool,
    core_hours: f64,
    ldc_balance: f64,
) {
    set_session_cookie(cookies, user_id, username, is_admin, core_hours, ldc_balance)
}

// ---- Password Comparison (Constant-Time) ----

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- Health Check ----

pub async fn health_check() -> &'static str {
    "OK"
}

// ---- Auth Handlers ----

#[derive(Deserialize)]
pub struct AdminLoginForm {
    pub username: String,
    pub password: String,
}

pub async fn admin_login(
    cookies: Cookies,
    Form(params): Form<AdminLoginForm>,
) -> impl IntoResponse {
    let cfg = AppConfig::get();

    // Constant-time 用户名与密码比较，抗时序攻击
    let username_ok = ct_eq(&params.username, &cfg.admin_username);
    let password_ok = ct_eq(&params.password, &cfg.admin_password);
    if !username_ok || !password_ok {
        tracing::warn!("Failed admin login attempt for username='{}'", params.username);
        return Redirect::to("/admin-login/ui").into_response();
    }

    let pool = db::get_db();
    let user: Option<(i64, f64, f64)> = sqlx::query_as(
        "SELECT id, core_hours, ldc_balance FROM users WHERE username = ?",
    )
    .bind(&params.username)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (user_id, core_hours, ldc_balance) = match user {
        Some((uid, ch, ldc)) => {
            let _ = sqlx::query("UPDATE users SET is_admin = 1 WHERE id = ?")
                .bind(uid)
                .execute(pool)
                .await;
            (uid, ch, ldc)
        }
        None => {
            let _ = sqlx::query(
                "INSERT INTO users (linuxdo_id, username, email, ldc_balance, core_hours, is_admin) VALUES (-1, ?, ?, 0, 0, 1)",
            )
            .bind(&params.username)
            .bind(format!("{}@admin.local", params.username))
            .execute(pool)
            .await;

            sqlx::query_as::<_, (i64, f64, f64)>(
                "SELECT id, core_hours, ldc_balance FROM users WHERE username = ?",
            )
            .bind(&params.username)
            .fetch_one(pool)
            .await
            .unwrap_or((0, 0.0, 0.0))
        }
    };

    set_session_cookie(&cookies, user_id, &params.username, true, core_hours, ldc_balance);
    Redirect::to("/admin").into_response()
}

pub async fn admin_login_ui(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let cfg = AppConfig::get();
    let site_name = db::get_config_sync("site_name")
        .unwrap_or_else(|| cfg.platform_domain.clone());

    let mut ctx = Context::new();
    ctx.insert("site_name", &site_name);
    let rendered = state
        .templates
        .render("admin/login.html", &ctx)
        .unwrap_or_else(|_| String::from("<html><body>管理员登录模板未找到</body></html>"));
    Html(rendered)
}

pub async fn logout(cookies: Cookies) -> impl IntoResponse {
    let mut cookie = Cookie::new("session", "");
    cookie.set_path("/");
    cookie.set_max_age(Duration::seconds(0));
    cookies.add(cookie);
    Redirect::to("/").into_response()
}

// ---- User Page Handlers ----

pub async fn user_dashboard(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();

    let user: (f64, f64) = sqlx::query_as(
        "SELECT core_hours, ldc_balance FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .unwrap_or((0.0, 0.0));

    let api_key: Option<String> = sqlx::query_scalar("SELECT api_key FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let packages: Vec<UserPackage> = sqlx::query_as(
        "SELECT * FROM user_packages WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("user_hours", &format!("{:.2}", user.0));
    ctx.insert("user_ldc", &format!("{:.2}", user.1));
    ctx.insert("api_key", &api_key.unwrap_or_default());
    ctx.insert("machines", &machines);
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("user/dashboard.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn regenerate_api_key(cookies: Cookies) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };
    let new_key = format!("usr_{}", Uuid::new_v4().to_string().replace('-', ""));
    let pool = db::get_db();
    let _ = sqlx::query("UPDATE users SET api_key = ? WHERE id = ?")
        .bind(&new_key)
        .bind(user_id)
        .execute(pool)
        .await;
    Redirect::to("/dashboard").into_response()
}

pub async fn contribute_server_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    if let Ok(servers) = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE owner_id = ? AND is_active = 1 ORDER BY created_at DESC")
        .bind(0i64)
        .fetch_all(pool)
        .await {
        ctx.insert("servers", &servers);
    }

    let rendered = state
        .templates
        .render("user/servers/contribute.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct ContributeServerForm {
    pub name: String,
    pub ip: String,
    pub ssh_port: Option<i32>,
    pub ssh_key: String,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub bandwidth_mbps: Option<f64>,
    pub disk_gb: f64,
    pub virt_type: Option<String>,
}

pub async fn contribute_server_submit(
    cookies: Cookies,
    Form(form): Form<ContributeServerForm>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    // 基本输入验证
    let ssh_port = form.ssh_port.unwrap_or(22);
    if ssh_port < 1 || ssh_port > 65535 {
        return Redirect::to("/servers/contribute").into_response();
    }
    if form.cpu_cores < 1 || form.memory_gb < 0.5 || form.disk_gb < 1.0 {
        return Redirect::to("/servers/contribute").into_response();
    }
    if form.ip.is_empty() || form.name.is_empty() || form.ssh_key.is_empty() {
        return Redirect::to("/servers/contribute").into_response();
    }

    let pool = db::get_db();
    let virt_type = form.virt_type.unwrap_or_else(|| "lxd".to_string());
    let bandwidth = form.bandwidth_mbps.unwrap_or(0.0);

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, virt_type, is_active, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, DATETIME('now','+30 days'), CURRENT_TIMESTAMP)",
    )
    .bind(user_id)
    .bind(&form.name)
    .bind(&form.ip)
    .bind(ssh_port)
    .bind(&form.ssh_key)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(bandwidth)
    .bind(form.disk_gb)
    .bind(&virt_type)
    .execute(pool)
    .await;

    match result {
        Ok(_) => Redirect::to("/servers/contribute").into_response(),
        Err(e) => {
            tracing::error!("Failed to add server: {}", e);
            Redirect::to("/servers/contribute?error=db").into_response()
        }
    }
}

pub async fn delete_server(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    // 只允许用户删除自己的服务器
    let owner: Option<i64> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if owner != Some(user_id) {
        return Redirect::to("/servers/contribute").into_response();
    }

    let _ = sqlx::query("UPDATE servers SET is_active = 0 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Redirect::to("/servers/contribute").into_response()
}

pub async fn buy_premium(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let owner: Option<i64> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if owner != Some(user_id) {
        return Redirect::to("/servers/contribute").into_response();
    }

    let ldc_cost = 10.0;
    let current_ldc: f64 = sqlx::query_scalar("SELECT ldc_balance FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0.0);

    if current_ldc < ldc_cost {
        return Redirect::to("/servers/contribute?error=insufficient_ldc").into_response();
    }

    let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ?")
        .bind(ldc_cost)
        .bind(user_id)
        .execute(pool)
        .await;

    let _ = sqlx::query(
        "UPDATE servers SET is_premium = 1, expires_at = DATETIME(expires_at, '+30 days') WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await;

    Redirect::to("/servers/contribute").into_response()
}

pub async fn machine_market(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE status = 'running' ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("machines", &machines);

    let rendered = state
        .templates
        .render("user/market.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn auto_select_machine(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE is_active = 1 AND expires_at > CURRENT_TIMESTAMP ORDER BY is_premium DESC, created_at DESC LIMIT 20",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("servers", &servers);

    let rendered = state
        .templates
        .render("user/machines/auto.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct CreateMachineForm {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub virt_type: Option<String>,
    pub duration_days: Option<i32>,
}

pub async fn create_machine(
    cookies: Cookies,
    Form(form): Form<CreateMachineForm>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    if form.cpu_cores < 1 || form.memory_gb < 0.5 || form.disk_gb < 1.0 {
        return Redirect::to("/machines?error=invalid_spec").into_response();
    }

    let pool = db::get_db();
    let duration_days = form.duration_days.unwrap_or(1).max(1);
    let virt_type = form.virt_type.unwrap_or_else(|| "lxd".to_string());

    // 检查服务器是否存在且活跃，包括资源总量
    let server: Option<(i64, String, f64, f64, f64, i32, f64, f64, String, String)> = sqlx::query_as(
        "SELECT id, ip, cpu_multiplier, memory_multiplier, disk_multiplier, cpu_cores, memory_gb, disk_gb, virt_type, agent_key FROM servers WHERE id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(form.server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (sid, ip, cpu_mul, mem_mul, disk_mul, total_cpu, total_mem, total_disk, _server_virt, agent_key) = match server {
        Some(s) => s,
        None => return Redirect::to("/machines?error=server_unavailable").into_response(),
    };

    // 简化计费：小时 * (cpu * cpu_mul + memory * mem_mul + disk * disk_mul) * 0.01
    let hours = (duration_days * 24) as f64;
    let cost = hours * (form.cpu_cores as f64 * cpu_mul + form.memory_gb * mem_mul + form.disk_gb * disk_mul) * 0.01;

    // 查询用户余额
    let current_hours: f64 = sqlx::query_scalar("SELECT core_hours FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0.0);

    if current_hours < cost {
        return Redirect::to("/machines?error=insufficient_funds").into_response();
    }

    // 在事务中检查服务器剩余资源并创建机器
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to begin transaction: {}", e);
            return Redirect::to("/machines?error=db").into_response();
        }
    };

    // 原子查询当前已使用资源
    let used: (Option<i64>, Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(cpu_cores), 0), COALESCE(SUM(memory_gb), 0.0), COALESCE(SUM(disk_gb), 0.0) FROM machines WHERE server_id = ? AND status IN ('pending', 'running')"
    )
    .bind(sid)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or((Some(0), Some(0.0), Some(0.0)));

    let used_cpu = used.0.unwrap_or(0) as i32;
    let used_mem = used.1.unwrap_or(0.0);
    let used_disk = used.2.unwrap_or(0.0);

    // 检查是否有足够的剩余资源
    if used_cpu + form.cpu_cores > total_cpu {
        let _ = tx.rollback().await;
        return Redirect::to("/machines?error=insufficient_cpu").into_response();
    }
    if used_mem + form.memory_gb > total_mem {
        let _ = tx.rollback().await;
        return Redirect::to("/machines?error=insufficient_memory").into_response();
    }
    if used_disk + form.disk_gb > total_disk {
        let _ = tx.rollback().await;
        return Redirect::to("/machines?error=insufficient_disk").into_response();
    }

    // 扣费
    let debit = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?")
        .bind(cost)
        .bind(user_id)
        .bind(cost)
        .execute(&mut *tx)
        .await;

    match debit {
        Ok(res) if res.rows_affected() > 0 => {}
        Ok(_) => {
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=insufficient_funds").into_response();
        }
        Err(e) => {
            tracing::error!("Failed to debit: {}", e);
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    }

    let insert = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, DATETIME('now', format('+{} days', ?)), NULL, CURRENT_TIMESTAMP)",
    )
    .bind(user_id)
    .bind(form.server_id)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(form.disk_gb)
    .bind(&virt_type)
    .bind(0.01)
    .bind(duration_days)
    .execute(&mut *tx)
    .await;

    let machine_id = match insert {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            tracing::error!("Failed to insert machine: {}", e);
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit transaction: {}", e);
        return Redirect::to("/machines?error=db").into_response();
    }

    // 调用 Agent 创建 VM（使用 machine_lifecycle 服务，含重试和退款）
    let machine_name = format!("machine-{}", machine_id);
    services::machine_lifecycle::spawn_agent_create_job(
        services::machine_lifecycle::MachineProvisioningJob {
            machine_id,
            user_id,
            server_ip: ip,
            machine_name,
            virt_type,
            cpu: form.cpu_cores,
            memory_gb: form.memory_gb,
            disk_gb: form.disk_gb,
            agent_key: agent_key.clone(),
            regular_used: cost,
            bonus_used: 0.0,
            used_hours: hours,
        },
    );

    Redirect::to("/machines").into_response()
}

pub async fn my_machines(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("machines", &machines);

    let rendered = state
        .templates
        .render("user/machines/list.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn stop_machine(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM machines WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if owner != Some(user_id) {
        return Redirect::to("/machines").into_response();
    }

    let _ = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Redirect::to("/machines").into_response()
}

pub async fn delete_machine(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM machines WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if owner != Some(user_id) {
        return Redirect::to("/machines").into_response();
    }

    let _ = sqlx::query("UPDATE machines SET status = 'deleted' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Redirect::to("/machines").into_response()
}

pub async fn machine_connect(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM machines WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if owner != Some(user_id) {
        return Err(Redirect::to("/machines"));
    }

    let machine: Option<Machine> = sqlx::query_as("SELECT * FROM machines WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    if let Some(m) = machine {
        ctx.insert("machine", &m);
    }

    let rendered = state
        .templates
        .render("user/machines/connect.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Free Plan / Checkin ----

pub async fn free_plan(
    cookies: Cookies,
    Form(_form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    // 新用户赠送 10 小时（简单检查）
    let existing_checkin: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM checkins WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if existing_checkin.is_none() {
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours + 10 WHERE id = ?")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("INSERT INTO checkins (user_id, reward_core_hours) VALUES (?, 10)")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    Redirect::to("/dashboard").into_response()
}

pub async fn checkin(
    cookies: Cookies,
    Form(_form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let reward = 10.0;

    let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
        .bind(reward)
        .bind(user_id)
        .execute(pool)
        .await;

    let _ = sqlx::query("INSERT INTO checkins (user_id, reward_core_hours) VALUES (?, ?)")
        .bind(user_id)
        .bind(reward)
        .execute(pool)
        .await;

    Redirect::to("/dashboard").into_response()
}

// ---- Recharge / Withdraw ----

pub async fn recharge_callback(
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let amount: f64 = params
        .get("amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    if amount > 0.0 {
        let pool = db::get_db();
        let out_trade_no = format!("recharge_{}", Uuid::new_v4());
        let _ = sqlx::query(
            "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, status) VALUES (?, ?, ?, ?, 'recharge', 'completed')",
        )
        .bind(user_id)
        .bind(&out_trade_no)
        .bind(amount)
        .bind(amount)
        .execute(pool)
        .await;

        let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance + ? WHERE id = ?")
            .bind(amount)
            .bind(user_id)
            .execute(pool)
            .await;
    }

    Redirect::to("/dashboard").into_response()
}

pub async fn withdraw_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let pool = db::get_db();
    let user: (f64, f64) = sqlx::query_as(
        "SELECT core_hours, ldc_balance FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0.0, 0.0));

    ctx.insert("user_hours", &format!("{:.2}", user.0));
    ctx.insert("user_ldc", &format!("{:.2}", user.1));

    let rendered = state
        .templates
        .render("user/withdraw.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn withdraw_submit(
    cookies: Cookies,
    Form(_form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (_user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };
    // 占位：实际提现流程需接入支付系统
    Redirect::to("/dashboard?msg=withdraw_submitted").into_response()
}

// ---- Stats Page ----

pub async fn stats_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let total_users: Option<i64> = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    ctx.insert("total_users", &total_users.unwrap_or(0));

    let total_machines: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM machines WHERE status = 'running'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    ctx.insert("total_machines", &total_machines.unwrap_or(0));

    let total_servers: Option<i64> =
        sqlx::query_scalar("SELECT COUNT(*) FROM servers WHERE is_active = 1")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    ctx.insert("total_servers", &total_servers.unwrap_or(0));

    let rendered = state
        .templates
        .render("user/stats.html", &ctx)
        .unwrap_or_default();
    Html(rendered)
}

// ---- Admin Dashboard ----

pub async fn admin_dashboard(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    ctx.insert("total_users", &total_users);

    let total_machines: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM machines WHERE status = 'running'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("total_machines", &total_machines);

    let total_servers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM servers WHERE is_active = 1")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    ctx.insert("total_servers", &total_servers);

    let rendered = state
        .templates
        .render("admin/dashboard.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_config_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    // 收集所有站点配置
    for key in [
        "site_name", "checkin_enabled", "free_plan_enabled", "registration_enabled",
        "require_invite", "checkin_reward", "payment_mode", "ldc_client_id", "ldc_client_secret",
        "admin_api_key", "traffic_monitor_enabled", "traffic_bandwidth_threshold_mbps",
        "premium_enabled", "premium_ldc_cost",
    ] {
        let value: Option<String> = sqlx::query_scalar::<_, String>(
            "SELECT value FROM site_config WHERE key = ?",
        )
        .bind(key)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        ctx.insert(key, &value.unwrap_or_default());
    }

    let rendered = state
        .templates
        .render("admin/config.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_config_save(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    match require_admin(&cookies) {
        Ok(_) => {}
        Err(redirect) => return redirect.into_response(),
    }

    let pool = db::get_db();

    for (key, value) in &form {
        // 只允许写入已知的配置键，避免 SQL 注入
        let allowed = [
            "site_name", "checkin_enabled", "free_plan_enabled", "registration_enabled",
            "require_invite", "checkin_reward", "payment_mode", "ldc_client_id", "ldc_client_secret",
            "admin_api_key", "traffic_monitor_enabled", "traffic_bandwidth_threshold_mbps",
            "premium_enabled", "premium_ldc_cost", "virt_type", "select_mode", "lock_bonus",
            "global_cpu_multiplier", "global_memory_multiplier", "global_bandwidth_multiplier",
            "global_disk_multiplier", "recharge_multiplier", "recharge_fee", "withdraw_fee",
            "settlement_threshold_pct", "balance_to_code_fee", "balance_to_code_daily_limit",
            "balance_to_code_enabled", "ldc_ed25519_private_key", "ldc_ed25519_public_key",
        ];
        if allowed.iter().any(|k| k == key) {
            let _ = sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await;
        }
    }

    Redirect::to("/admin/config").into_response()
}

pub async fn admin_users(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC LIMIT 100")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    ctx.insert("users", &users);

    let rendered = state
        .templates
        .render("admin/users.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_user_edit(
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    match require_admin(&cookies) {
        Ok(_) => {}
        Err(redirect) => return redirect.into_response(),
    }

    let pool = db::get_db();

    if let Some(ldc) = form.get("ldc_balance").and_then(|v| v.parse::<f64>().ok()) {
        let _ = sqlx::query("UPDATE users SET ldc_balance = ? WHERE id = ?")
            .bind(ldc)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(hours) = form.get("core_hours").and_then(|v| v.parse::<f64>().ok()) {
        let _ = sqlx::query("UPDATE users SET core_hours = ? WHERE id = ?")
            .bind(hours)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(ban) = form.get("is_banned") {
        let banned = if ban == "1" { 1 } else { 0 };
        let _ = sqlx::query("UPDATE users SET is_banned = ? WHERE id = ?")
            .bind(banned)
            .bind(id)
            .execute(pool)
            .await;
    }

    Redirect::to("/admin/users").into_response()
}

pub async fn admin_servers(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let servers: Vec<Server> = sqlx::query_as("SELECT * FROM servers ORDER BY created_at DESC LIMIT 100")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    ctx.insert("servers", &servers);

    let rendered = state
        .templates
        .render("admin/servers.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_servers_toggle(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match require_admin(&cookies) {
        Ok(_) => {}
        Err(redirect) => return redirect.into_response(),
    }

    let pool = db::get_db();
    let _ = sqlx::query("UPDATE servers SET is_active = 1 - is_active WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Redirect::to("/admin/servers").into_response()
}

pub async fn admin_oauth_apps(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let apps: Vec<OAuthApp> = sqlx::query_as("SELECT * FROM oauth_apps ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    ctx.insert("apps", &apps);

    let rendered = state
        .templates
        .render("admin/oauth-apps.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_oauth_apps_create(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    match require_admin(&cookies) {
        Ok(_) => {}
        Err(redirect) => return redirect.into_response(),
    }

    let pool = db::get_db();
    let name = form.get("name").cloned().unwrap_or_default();
    let redirect_uri = form.get("redirect_uri").cloned().unwrap_or_default();
    if name.is_empty() || redirect_uri.is_empty() {
        return Redirect::to("/admin/oauth-apps").into_response();
    }

    let client_id = format!("cli_{}", Uuid::new_v4().to_string().replace('-', ""));
    let client_secret = format!("sec_{}", Uuid::new_v4().to_string().replace('-', ""));
    let created_by = match get_session_user(&cookies) {
        Some((uid, _, _)) => uid,
        None => 0,
    };

    let _ = sqlx::query(
        "INSERT INTO oauth_apps (name, client_id, client_secret, redirect_uri, created_by, is_active) VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(&name)
    .bind(&client_id)
    .bind(&client_secret)
    .bind(&redirect_uri)
    .bind(created_by)
    .execute(pool)
    .await;

    Redirect::to("/admin/oauth-apps").into_response()
}

// ---- Balance to Code ----

pub async fn balance_to_code(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let amount: f64 = form
        .get("amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    if amount <= 0.0 {
        return Redirect::to("/dashboard?error=invalid_amount").into_response();
    }

    let pool = db::get_db();
    let current_ldc: f64 = sqlx::query_scalar("SELECT ldc_balance FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or(0.0);

    if current_ldc < amount {
        return Redirect::to("/dashboard?error=insufficient_funds").into_response();
    }

    // 扣除余额
    let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ?")
        .bind(amount)
        .bind(user_id)
        .execute(pool)
        .await;

    // 生成兑换码
    let code = format!("LDC{}", Uuid::new_v4().to_string().replace('-', "").to_uppercase());
    let _ = sqlx::query(
        "INSERT INTO balance_to_code_logs (user_id, amount, fee, is_bonus, code) VALUES (?, ?, 0, 0, ?)",
    )
    .bind(user_id)
    .bind(amount)
    .bind(&code)
    .execute(pool)
    .await;

    Redirect::to(&format!("/dashboard?code={}", code)).into_response()
}
