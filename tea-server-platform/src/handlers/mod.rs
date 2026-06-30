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
pub mod websocket;

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
    pub iat: i64,   // issued at (unix timestamp)
    pub exp: i64,   // expires
}

impl SessionPayload {
    pub fn new(user_id: i64, username: &str, is_admin: bool, core_hours: f64) -> Self {
        let now = Utc::now().timestamp();
        Self {
            user_id,
            username: username.to_string(),
            is_admin,
            core_hours,
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
) {
    let payload = SessionPayload::new(user_id, username, is_admin, core_hours);
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
) {
    set_session_cookie(cookies, user_id, username, is_admin, core_hours)
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
    State(state): State<AppState>,
    cookies: Cookies,
    Form(params): Form<AdminLoginForm>,
) -> impl IntoResponse {
    let cfg = AppConfig::get();

    // Rate limit: 5 admin login attempts per 15 minutes per session
    let limiter_key = format!("admin_login:{}", cookies.get("session").map(|c| c.value().to_string()).unwrap_or_default());
    if !state.api_limiter.check(&limiter_key).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(r#"<p>登录尝试过于频繁，请15分钟后再试。</p><a href="/admin-login/ui">返回</a>"#),
        ).into_response();
    }

    // Constant-time 用户名与密码比较，抗时序攻击
    let username_ok = ct_eq(&params.username, &cfg.admin_username);
    let password_ok = ct_eq(&params.password, &cfg.admin_password);
    if !username_ok || !password_ok {
        tracing::warn!("Failed admin login attempt for username='{}'", params.username);
        return Redirect::to("/admin-login/ui").into_response();
    }

    let pool = db::get_db();
    let user: Option<(i64, f64)> = sqlx::query_as(
        "SELECT id, core_hours FROM users WHERE username = ?",
    )
    .bind(&params.username)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (user_id, core_hours) = match user {
        Some((uid, ch)) => {
            let _ = sqlx::query("UPDATE users SET is_admin = 1 WHERE id = ?")
                .bind(uid)
                .execute(pool)
                .await;
            (uid, ch)
        }
        None => {
            let _ = sqlx::query(
                "INSERT INTO users (linuxdo_id, username, email, core_hours, is_admin) VALUES (-1, ?, ?, 0, 1)",
            )
            .bind(&params.username)
            .bind(format!("{}@admin.local", params.username))
            .execute(pool)
            .await;

            sqlx::query_as::<_, (i64, f64)>(
                "SELECT id, core_hours FROM users WHERE username = ?",
            )
            .bind(&params.username)
            .fetch_one(pool)
            .await
            .unwrap_or((0, 0.0))
        }
    };

    set_session_cookie(&cookies, user_id, &params.username, true, core_hours);
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

pub async fn redeem_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let rendered = state
        .templates
        .render("user/redeem.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn redeem_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let code = form.get("code").cloned().unwrap_or_default();
    if code.is_empty() {
        return Redirect::to("/redeem?error=empty_code").into_response();
    }

    let pool = db::get_db();
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return Redirect::to("/redeem?error=system_error").into_response(),
    };

    // 查询兑换码（加锁）
    let code_info: Option<(i64, String, f64)> = sqlx::query_as(
        "SELECT id, code_type, COALESCE(core_hours, 0) FROM redeem_codes WHERE code = ? AND is_used = 0",
    )
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await
    .unwrap_or(None);

    let (code_id, code_type, core_hours_val) = match code_info {
        Some(c) => c,
        None => {
            let _ = tx.rollback().await;
            return Redirect::to("/redeem?error=invalid_code").into_response();
        }
    };

    // 标记为已使用
    let _ = sqlx::query(
        "UPDATE redeem_codes SET is_used = 1, used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
    .bind(user_id)
    .bind(code_id)
    .execute(&mut *tx)
    .await;

    // 根据类型发放奖励
    if code_type == "core_hours" {
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
            .bind(core_hours_val)
            .bind(user_id)
            .execute(&mut *tx)
            .await;
    }

    let commit_result = tx.commit().await;
    if commit_result.is_err() {
        // 提交失败时不需要回滚，因为事务已经回滚
        tracing::error!("Failed to commit redeem transaction: {:?}", commit_result.err());
        return Redirect::to("/redeem?error=system_error").into_response();
    }

    Redirect::to("/redeem?success=1").into_response()
}

pub async fn user_dashboard(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();

    let user: (f64, f64) = sqlx::query_as(
        "SELECT core_hours, bonus_core_hours FROM users WHERE id = ?",
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

    // Calculate frozen owner earnings for display
    let freeze_days: i64 = db::get_config("owner_income_freeze_days")
        .await
        .unwrap_or_else(|| "14".to_string())
        .parse()
        .unwrap_or(14);
    let total_owner_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (total_regular_income, total_bonus_income) = total_owner_income.unwrap_or((0.0, 0.0));

    let freeze_threshold = chrono::Utc::now() - chrono::Duration::days(freeze_days);
    let withdrawable_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ? AND created_at <= ?"
    )
    .bind(user_id)
    .bind(freeze_threshold)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (withdrawable_regular, withdrawable_bonus) = withdrawable_income.unwrap_or((0.0, 0.0));

    let frozen_regular = (total_regular_income - withdrawable_regular).max(0.0);
    let frozen_bonus = (total_bonus_income - withdrawable_bonus).max(0.0);
    let available_regular = (user.0 - frozen_regular).max(0.0);
    let available_bonus = (user.1 - frozen_bonus).max(0.0);

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("user_hours", &format!("{:.2}", user.0));
    ctx.insert("bonus_hours", &format!("{:.2}", user.1));
    ctx.insert("api_key", &api_key.unwrap_or_default());
    ctx.insert("machines", &machines);
    ctx.insert("packages", &packages);
    ctx.insert("frozen_regular", &frozen_regular);
    ctx.insert("frozen_bonus", &frozen_bonus);
    ctx.insert("available_regular", &available_regular);
    ctx.insert("available_bonus", &available_bonus);
    ctx.insert("freeze_days", &freeze_days);
    ctx.insert("is_owner", &(total_regular_income > 0.0 || total_bonus_income > 0.0));

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
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    if let Ok(servers) = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE owner_id = ? AND is_active = 1 ORDER BY created_at DESC")
        .bind(user_id)
        .fetch_all(pool)
        .await {
        ctx.insert("servers", &servers);
    }

    let global_cpu_mult: f64 = db::get_config("global_cpu_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_mem_mult: f64 = db::get_config("global_memory_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_bw_mult: f64 = db::get_config("global_bandwidth_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_disk_mult: f64 = db::get_config("global_disk_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);

    ctx.insert("global_cpu_multiplier", &global_cpu_mult);
    ctx.insert("global_memory_multiplier", &global_mem_mult);
    ctx.insert("global_bandwidth_multiplier", &global_bw_mult);
    ctx.insert("global_disk_multiplier", &global_disk_mult);

    let rendered = state
        .templates
        .render("user/contribute.html", &ctx)
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
    pub description: Option<String>,
    pub provider: Option<String>,
    pub cpu_multiplier: Option<f64>,
    pub memory_multiplier: Option<f64>,
    pub bandwidth_multiplier: Option<f64>,
    pub disk_multiplier: Option<f64>,
    pub use_bonus: Option<String>,
    pub linux_version: Option<String>,
    pub expires_days: Option<i32>,
    pub nat_port_start: Option<i32>,
    pub nat_port_end: Option<i32>,
    pub nat_multiplier: Option<f64>,
    pub free_nat_hours: Option<f64>,
    pub max_machine_hours: Option<f64>,
    pub premium_days: Option<i32>,
}

pub async fn contribute_server_submit(
    State(_state): State<AppState>,
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
    let cpu_mult = form.cpu_multiplier.unwrap_or(1.0);
    let mem_mult = form.memory_multiplier.unwrap_or(1.0);
    let bw_mult = form.bandwidth_multiplier.unwrap_or(1.0);
    let disk_mult = form.disk_multiplier.unwrap_or(1.0);
    let nat_port_start = form.nat_port_start.unwrap_or(0);
    let nat_port_end = form.nat_port_end.unwrap_or(0);
    let nat_mult = form.nat_multiplier.unwrap_or(1.0);
    let free_nat_hours = form.free_nat_hours.unwrap_or(0.0);
    let max_machine_hours = form.max_machine_hours.unwrap_or(0.0);
    let expires_days = form.expires_days.unwrap_or(30);
    let use_bonus = form.use_bonus.as_ref().map(|v| v == "on").unwrap_or(false);

    // 优选套餐处理
    let premium_days = form.premium_days.unwrap_or(0).max(0);
    let premium_enabled = db::get_config("premium_enabled")
        .await
        .unwrap_or_else(|| "false".to_string())
        == "true";
    let premium_daily_cost: f64 = db::get_config("premium_ldc_cost")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);
    let premium_total_cost = if premium_enabled && premium_days > 0 {
        premium_daily_cost * premium_days as f64
    } else {
        0.0
    };

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, is_active, expires_at, created_at, expose_ip, nat_port_start, nat_port_end, nat_multiplier, max_machine_hours, free_nat_hours, linux_version, description, provider) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, DATETIME('now', '+' || ? || ' days'), CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(cpu_mult)
    .bind(mem_mult)
    .bind(bw_mult)
    .bind(disk_mult)
    .bind(use_bonus)
    .bind(&virt_type)
    .bind(expires_days)
    .bind(nat_port_start > 0)
    .bind(nat_port_start)
    .bind(nat_port_end)
    .bind(nat_mult)
    .bind(max_machine_hours)
    .bind(free_nat_hours)
    .bind(form.linux_version.as_deref().unwrap_or(""))
    .bind(form.description.as_deref().unwrap_or(""))
    .bind(form.provider.as_deref().unwrap_or(""));

    let result = result.execute(pool).await;

    let server_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            tracing::error!("Failed to add server: {}", e);
            return Redirect::to("/servers/contribute?error=db").into_response();
        }
    };

    // 如果用户选择了优选套餐，创建订单并跳转到支付
    if premium_total_cost > 0.0 && server_id > 0 {
        let cfg = crate::config::AppConfig::get();
        let out_trade_no = format!("premium_{}_{}", server_id, chrono::Utc::now().timestamp_millis());
        let metadata = serde_json::json!({
            "server_id": server_id,
            "days": premium_days,
        }).to_string();

        let _ = sqlx::query(
            "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, order_type, metadata, status) VALUES (?, ?, ?, ?, ?, 'premium', ?, 'pending')",
        )
        .bind(user_id)
        .bind(&out_trade_no)
        .bind(premium_total_cost)
        .bind(premium_total_cost)
        .bind(format!("优选套餐 {} 天", premium_days))
        .bind(&metadata)
        .execute(pool)
        .await;

        match crate::services::ldc_payment::create_payment(cfg, &out_trade_no, premium_total_cost, &format!("优选套餐 {} 天", premium_days)).await {
            Ok(pay_url) => return Redirect::to(&pay_url).into_response(),
            Err(_) => return Redirect::to("/servers/contribute?error=pay_failed").into_response(),
        }
    }

    Redirect::to("/servers/contribute").into_response()
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
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
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
        return Redirect::to("/dashboard").into_response();
    }

    let days: i32 = form
        .get("days")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
        .max(1);

    let premium_daily_cost: f64 = db::get_config("premium_ldc_cost")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);
    let total_cost = premium_daily_cost * days as f64;

    let cfg = crate::config::AppConfig::get();
    let out_trade_no = format!("premium_{}_{}", id, chrono::Utc::now().timestamp_millis());

    let metadata = serde_json::json!({
        "server_id": id,
        "days": days,
    }).to_string();

    let _ = sqlx::query(
        "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, order_type, metadata, status) VALUES (?, ?, ?, ?, ?, 'premium', ?, 'pending')",
    )
    .bind(user_id)
    .bind(&out_trade_no)
    .bind(total_cost)
    .bind(total_cost)
    .bind(format!("优选套餐 {} 天", days))
    .bind(&metadata)
    .execute(pool)
    .await;

    match crate::services::ldc_payment::create_payment(cfg, &out_trade_no, total_cost, &format!("优选套餐 {} 天", days)).await {
        Ok(pay_url) => Redirect::to(&pay_url).into_response(),
        Err(_) => Redirect::to("/dashboard?error=pay_failed").into_response(),
    }
}

pub async fn servers_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE is_active = 1 ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("servers", &servers);

    let rendered = state
        .templates
        .render("servers.html", &ctx)
        .unwrap_or_default();
    Html(rendered)
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

    let global_cpu_mult: f64 = db::get_config("global_cpu_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_mem_mult: f64 = db::get_config("global_memory_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_bw_mult: f64 = db::get_config("global_bandwidth_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let global_disk_mult: f64 = db::get_config("global_disk_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);

    ctx.insert("global_cpu_multiplier", &global_cpu_mult);
    ctx.insert("global_memory_multiplier", &global_mem_mult);
    ctx.insert("global_bandwidth_multiplier", &global_bw_mult);
    ctx.insert("global_disk_multiplier", &global_disk_mult);

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
    pub image: Option<String>,      // 系统镜像
    pub app_image: Option<String>,  // 应用镜像
    pub root_password: Option<String>, // 用户设置的 root 密码
    pub app_secrets: Option<String>,   // 应用密钥（JSON 字符串）
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
    let server: Option<(i64, String, f64, f64, f64, i32, f64, f64, String, String, i64, bool, i32, i32, f64, f64)> = sqlx::query_as(
        "SELECT id, ip, cpu_multiplier, memory_multiplier, disk_multiplier, cpu_cores, memory_gb, disk_gb, virt_type, agent_key, owner_id, expose_ip, nat_port_start, nat_port_end, nat_multiplier, free_nat_hours FROM servers WHERE id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind(form.server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (sid, ip, cpu_mul, mem_mul, disk_mul, total_cpu, total_mem, total_disk, _server_virt, agent_key, server_owner_id, expose_ip, nat_port_start, nat_port_end, nat_multiplier, free_nat_hours_server) = match server {
        Some(s) => s,
        None => return Redirect::to("/machines?error=server_unavailable").into_response(),
    };

    let hours = (duration_days * 24) as f64;
    let image = form.image.as_deref().unwrap_or("ubuntu:22.04");
    let is_windows = image.starts_with("windows:");
    let is_kvm = virt_type == "kvm";

    // 计算 NAT 端口数量
    let nat_ports = if expose_ip && nat_port_start > 0 {
        if is_kvm {
            if is_windows { 3 } else { 2 }
        } else {
            1
        }
    } else {
        0
    };

    // 计算 NAT 费用
    let global_nat = db::get_config("global_nat_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let nat_cost_per_hour = nat_ports as f64 * nat_multiplier * global_nat;

    // 应用免费 NAT 额度
    let free_nat_amount = if free_nat_hours_server > 0.0 && nat_cost_per_hour > 0.0 {
        (free_nat_hours_server.min(hours) * nat_cost_per_hour).min(nat_cost_per_hour * hours)
    } else {
        0.0
    };

    // 计算基础费用
    let ch_per_hour = services::core_hours::calculate_core_hours_per_hour(
        form.cpu_cores,
        form.memory_gb,
        0.0,
        form.disk_gb,
        cpu_mul,
        mem_mul,
        1.0,
        disk_mul,
        0,
        0.0,
    )
    .await;

    let nat_cost = (nat_cost_per_hour * hours) - free_nat_amount;
    let cost = ch_per_hour * hours + nat_cost.max(0.0);

    // 查询用户余额（regular + bonus）
    let user_balance: (f64, f64) = sqlx::query_as(
        "SELECT core_hours, bonus_core_hours FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0.0, 0.0));

    let total_balance = user_balance.0 + user_balance.1;
    if total_balance < cost {
        return Redirect::to("/machines?error=insufficient_funds").into_response();
    }

    // 计算bonus和regular各扣多少（优先扣bonus）
    let bonus_deduct = user_balance.1.min(cost);
    let regular_deduct = cost - bonus_deduct;

    // 在事务中检查服务器剩余资源并创建机器
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to begin transaction: {}", e);
            return Redirect::to("/machines?error=db").into_response();
        }
    };

    // 原子查询当前已使用资源
    let used: (i64, f64, f64) = match sqlx::query_as(
        "SELECT COALESCE(SUM(cpu_cores), 0), COALESCE(SUM(memory_gb), 0.0), COALESCE(SUM(disk_gb), 0.0) FROM machines WHERE server_id = ? AND status IN ('pending', 'running')"
    )
    .bind(sid)
    .fetch_one(&mut *tx)
    .await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("Failed to query used resources: {}", e);
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    };

    let used_cpu = used.0 as i32;
    let used_mem = used.1;
    let used_disk = used.2;

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

    // 检查 NAT 端口容量
    if expose_ip && nat_port_start > 0 && nat_ports > 0 {
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
        let used_ports: (i64,) = match sqlx::query_as(used_ports_query)
            .bind(sid)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to query used NAT ports: {}", e);
                let _ = tx.rollback().await;
                return Redirect::to("/machines?error=db").into_response();
            }
        };
        let total_available_nat = (nat_port_end - nat_port_start) as i64;
        if used_ports.0 + nat_ports as i64 > total_available_nat {
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=no_nat_ports").into_response();
        }
    }

    // 扣费（优先扣bonus，再扣regular）
    let mut debit_ok = true;

    if bonus_deduct > 0.0 {
        let res = sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ? AND bonus_core_hours >= ?"
        )
        .bind(bonus_deduct)
        .bind(user_id)
        .bind(bonus_deduct)
        .execute(&mut *tx)
        .await;
        if res.is_err() || res.unwrap().rows_affected() == 0 {
            debit_ok = false;
        }
    }

    if debit_ok && regular_deduct > 0.0 {
        let res = sqlx::query(
            "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?"
        )
        .bind(regular_deduct)
        .bind(user_id)
        .bind(regular_deduct)
        .execute(&mut *tx)
        .await;
        if res.is_err() || res.unwrap().rows_affected() == 0 {
            debit_ok = false;
        }
    }

    if !debit_ok {
        let _ = tx.rollback().await;
        return Redirect::to("/machines?error=insufficient_funds").into_response();
    }

    // 给机主加钱（bonus部分加bonus，regular部分加regular）
    if bonus_deduct > 0.0 {
        let res = sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours + ? WHERE id = ?")
            .bind(bonus_deduct)
            .bind(server_owner_id)
            .execute(&mut *tx)
            .await;
        if res.is_err() {
            tracing::error!("Failed to add bonus to server owner: {:?}", res.err());
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    }
    if regular_deduct > 0.0 {
        let res = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
            .bind(regular_deduct)
            .bind(server_owner_id)
            .execute(&mut *tx)
            .await;
        if res.is_err() {
            tracing::error!("Failed to add regular to server owner: {:?}", res.err());
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    }

    let image = form.image.unwrap_or_else(|| "ubuntu:22.04".to_string());
    let app_image = form.app_image.unwrap_or_default();
    let root_password_val = form.root_password.as_deref().unwrap_or("");
    let encrypted_root_password = crate::services::crypto::Crypto::encrypt(root_password_val);
    let insert = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, used_hours, root_password, image, app_image, free_nat_hours, regular_core_hours_used, bonus_core_hours_used, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, DATETIME('now', format('+{} days', ?)), ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    )
    .bind(user_id)
    .bind(form.server_id)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(form.disk_gb)
    .bind(&virt_type)
    .bind(ch_per_hour)
    .bind(duration_days)
    .bind(hours)
    .bind(&encrypted_root_password)
    .bind(&image)
    .bind(&app_image)
    .bind(free_nat_hours_server)
    .bind(regular_deduct)
    .bind(bonus_deduct)
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

    // Log owner income for freeze period tracking
    if bonus_deduct > 0.0 || regular_deduct > 0.0 {
        let log_result = sqlx::query(
            "INSERT INTO owner_income_logs (user_id, regular_amount, bonus_amount, source_type, source_id) VALUES (?, ?, ?, 'machine_create', ?)"
        )
        .bind(server_owner_id)
        .bind(regular_deduct)
        .bind(bonus_deduct)
        .bind(machine_id)
        .execute(&mut *tx)
        .await;
        if let Err(e) = log_result {
            tracing::error!("Failed to log owner income: {}", e);
            let _ = tx.rollback().await;
            return Redirect::to("/machines?error=db").into_response();
        }
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit transaction: {}", e);
        return Redirect::to("/machines?error=db").into_response();
    }

    // 调用 Agent 创建 VM（使用 machine_lifecycle 服务，含重试和退款）
    let machine_name = format!("machine-{}", machine_id);
    let root_password = crate::services::crypto::Crypto::encrypt(&form.root_password.unwrap_or_default());
    let app_secrets = form.app_secrets.unwrap_or_else(|| "{}".to_string());
    
    services::machine_lifecycle::spawn_agent_create_job(
        services::machine_lifecycle::MachineProvisioningJob {
            machine_id,
            user_id,
            server_owner_id,
            server_ip: ip,
            machine_name,
            virt_type,
            cpu: form.cpu_cores,
            memory_gb: form.memory_gb,
            disk_gb: form.disk_gb,
            agent_key: agent_key.clone(),
            regular_used: regular_deduct,
            bonus_used: bonus_deduct,
            used_hours: hours,
            image,
            app_image,
            root_password,
            app_secrets,
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

pub async fn suspend_machine(
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

    let _ = sqlx::query("UPDATE machines SET status = 'suspended' WHERE id = ? AND status IN ('running', 'stopped')")
        .bind(id)
        .execute(pool)
        .await;

    Redirect::to("/machines").into_response()
}

pub async fn unsuspend_machine(
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

    let _ = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ? AND status = 'suspended'")
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

    // 删除机器并按剩余时间退款
    match services::machine_lifecycle::refund_machine_remaining(id).await {
        Ok((regular_refund, bonus_refund)) => {
            if regular_refund > 0.0 || bonus_refund > 0.0 {
                tracing::info!(
                    machine_id = id,
                    regular_refund = regular_refund,
                    bonus_refund = bonus_refund,
                    "machine deleted, refund processed"
                );
            }
        }
        Err(e) => {
            tracing::error!(machine_id = id, error = %e, "failed to process refund on machine deletion");
        }
    }

    Redirect::to("/machines").into_response()
}

pub async fn machine_detail(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    
    // Get machine owned by this user
    let machine: Option<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if machine.is_none() {
        return Err(Redirect::to("/machines?error=not_found"));
    }

    let m = machine.unwrap();
    
    // Decrypt root_password for display
    let mut m = m;
    m.root_password = m.root_password.and_then(|rp| crate::services::crypto::Crypto::decrypt(&rp));
    // Get server info
    let server: Option<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE id = ?"
    )
    .bind(m.server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machine", &m);
    ctx.insert("server", &server);

    let rendered = state
        .templates
        .render("user/machine_detail.html", &ctx)
        .unwrap_or_else(|_| "Template error".to_string());

    Ok(Html(rendered))
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
    State(state): State<AppState>,
    cookies: Cookies,
    Form(_form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    // Rate limit: 1 checkin per hour per user_id
    let limiter_key = format!("checkin:{}", user_id);
    if !state.checkin_limiter.check(&limiter_key).await {
        return Redirect::to("/dashboard?error=rate_limited").into_response();
    }

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
    State(_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let pool = db::get_db();

    tracing::info!(?params, "recharge callback received");

    // 1. 验证签名
    if !crate::services::ldc_payment::verify_callback(&params).await {
        tracing::warn!("recharge callback signature verification failed");
        return "fail";
    }

    // 2. 获取订单号和金额
    let out_trade_no = match params.get("out_trade_no") {
        Some(v) => v.clone(),
        None => {
            tracing::warn!("recharge callback missing out_trade_no");
            return "fail";
        }
    };
    let trade_status = params
        .get("trade_status")
        .or_else(|| params.get("status"))
        .cloned()
        .unwrap_or_default();
    let total_fee: f64 = params
        .get("total_fee")
        .or_else(|| params.get("money"))
        .or_else(|| params.get("amount"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    // 3. 只处理成功的支付
    let success_statuses = ["TRADE_SUCCESS", "success", "1", "paid"];
    if !success_statuses.iter().any(|s| s.eq_ignore_ascii_case(&trade_status)) {
        tracing::info!(%out_trade_no, %trade_status, "recharge callback: not success status, ignoring");
        return "success";
    }

    if total_fee <= 0.0 {
        tracing::warn!(%out_trade_no, %total_fee, "recharge callback: invalid amount");
        return "fail";
    }

    // 4. 查询订单，检查是否已处理（幂等性）
    let order: Option<(i64, i64, f64, String, String, String)> = sqlx::query_as(
        "SELECT id, user_id, ldc_amount, status, order_type, metadata FROM orders WHERE out_trade_no = ?",
    )
    .bind(&out_trade_no)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (order_id, user_id, package_core_hours, status, order_type, metadata) = match order {
        Some(o) => o,
        None => {
            tracing::warn!(%out_trade_no, "payment callback: order not found");
            return "fail";
        }
    };

    // 已处理过的订单直接返回成功
    if status == "completed" {
        tracing::info!(%out_trade_no, %order_type, "payment callback: order already completed");
        return "success";
    }

    // 5. 原子更新订单状态 + 业务处理（使用事务保证一致性）
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(%e, "failed to begin transaction for payment callback");
            return "fail";
        }
    };

    // 标记订单为已完成
    let update_result = sqlx::query(
        "UPDATE orders SET status = 'completed', trade_no = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'",
    )
    .bind(params.get("trade_no").unwrap_or(&String::new()))
    .bind(order_id)
    .execute(&mut *tx)
    .await;

    if update_result.is_err() || update_result.unwrap().rows_affected() == 0 {
        let _ = tx.rollback().await;
        tracing::warn!(%out_trade_no, %order_type, "payment callback: order already processed or update failed");
        return "success";
    }

    // 根据订单类型处理
    match order_type.as_str() {
        "premium" => {
            // 优选套餐：给服务器加优选天数
            let meta: serde_json::Value = serde_json::from_str(&metadata).unwrap_or(serde_json::json!({}));
            let server_id = meta["server_id"].as_i64().unwrap_or(0);
            let days = meta["days"].as_i64().unwrap_or(0) as i32;

            if server_id > 0 && days > 0 {
                let _ = sqlx::query(
                    "UPDATE servers SET is_premium = 1, premium_expires_at = CASE WHEN premium_expires_at IS NULL OR premium_expires_at < CURRENT_TIMESTAMP THEN DATETIME('now', '+' || ? || ' days') ELSE DATETIME(premium_expires_at, '+' || ? || ' days') END WHERE id = ?",
                )
                .bind(days)
                .bind(days)
                .bind(server_id)
                .execute(&mut *tx)
                .await;
            }
            tracing::info!(%out_trade_no, %user_id, %server_id, %days, "premium callback: success");
        }
        _ => {
            // 默认 recharge：增加用户核时余额
            let multiplier: f64 = db::get_config("recharge_multiplier")
                .await
                .and_then(|v| v.parse().ok())
                .unwrap_or(1.0);
            let fee: f64 = db::get_config("recharge_fee")
                .await
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let actual_core_hours = package_core_hours * multiplier * (1.0 - fee);

            let add_result = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(actual_core_hours)
                .bind(user_id)
                .execute(&mut *tx)
                .await;

            if add_result.is_err() {
                let _ = tx.rollback().await;
                tracing::error!("recharge callback: failed to add user core_hours");
                return "fail";
            }
            tracing::info!(%out_trade_no, %user_id, %total_fee, %actual_core_hours, "recharge callback: success");
        }
    }

    if tx.commit().await.is_err() {
        tracing::error!("payment callback: failed to commit transaction");
        return "fail";
    }

    "success"
}

pub async fn withdraw_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let pool = db::get_db();
    let user: (f64,) = sqlx::query_as(
        "SELECT core_hours FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0.0,));

    let fee_rate: f64 = db::get_config("withdraw_fee")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    ctx.insert("user_hours", &format!("{:.2}", user.0));
    ctx.insert("withdraw_fee", &fee_rate);

    let rendered = state
        .templates
        .render("user/withdraw.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn withdraw_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, username, _is_admin) = match require_auth(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let amount: f64 = form
        .get("amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    if amount <= 0.0 {
        return Redirect::to("/withdraw?error=invalid_amount").into_response();
    }

    let pool = db::get_db();

    // 最小提现额
    if amount < 1.0 {
        return Redirect::to("/withdraw?error=min_withdraw").into_response();
    }

    // 计算手续费
    let fee_rate: f64 = db::get_config("withdraw_fee")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let fee = amount * fee_rate;
    let total_deduct = amount + fee;

    // 事务：冻结余额 + 创建提现订单
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return Redirect::to("/withdraw?error=system_error").into_response(),
    };

    // 原子扣减余额（用 WHERE 条件确保不会扣成负数）
    let deduct_result = sqlx::query(
        "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?",
    )
    .bind(total_deduct)
    .bind(user_id)
    .bind(total_deduct)
    .execute(&mut *tx)
    .await;

    if deduct_result.is_err() || deduct_result.unwrap().rows_affected() == 0 {
        let _ = tx.rollback().await;
        return Redirect::to("/withdraw?error=insufficient_balance").into_response();
    }

    // 创建提现订单
    let out_trade_no = format!("withdraw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let insert_result = sqlx::query(
        "INSERT INTO withdraw_orders (user_id, out_trade_no, amount, fee, actual_amount, status) VALUES (?, ?, ?, ?, ?, 'pending')",
    )
    .bind(user_id)
    .bind(&out_trade_no)
    .bind(amount)
    .bind(fee)
    .bind(amount)
    .execute(&mut *tx)
    .await;

    if insert_result.is_err() {
        let _ = tx.rollback().await;
        return Redirect::to("/withdraw?error=system_error").into_response();
    }

    if tx.commit().await.is_err() {
        return Redirect::to("/withdraw?error=system_error").into_response();
    }

    // 异步调用 LDC 分发接口（后台处理）
    tokio::spawn(async move {
        let cfg = crate::config::AppConfig::get();
        match crate::services::ldc_payment::distribute_ldc(cfg, user_id, &username, amount, &out_trade_no).await {
            Ok(true) => {
                let _ = sqlx::query(
                    "UPDATE withdraw_orders SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE out_trade_no = ?",
                )
                .bind(&out_trade_no)
                .execute(db::get_db())
                .await;
                tracing::info!(%out_trade_no, %user_id, %amount, "withdraw completed");
            }
            Ok(false) => {
                let _ = sqlx::query(
                    "UPDATE withdraw_orders SET status = 'failed', fail_reason = 'distribute failed', updated_at = CURRENT_TIMESTAMP WHERE out_trade_no = ?",
                )
                .bind(&out_trade_no)
                .execute(db::get_db())
                .await;
                // 退款
                let _ = sqlx::query(
                    "UPDATE users SET core_hours = core_hours + ? WHERE id = ?",
                )
                .bind(amount + fee)
                .bind(user_id)
                .execute(db::get_db())
                .await;
                tracing::warn!(%out_trade_no, %user_id, "withdraw distribute failed, refunded");
            }
            Err(e) => {
                let _ = sqlx::query(
                    "UPDATE withdraw_orders SET status = 'failed', fail_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE out_trade_no = ?",
                )
                .bind(format!("{}", e))
                .bind(&out_trade_no)
                .execute(db::get_db())
                .await;
                // 退款
                let _ = sqlx::query(
                    "UPDATE users SET core_hours = core_hours + ? WHERE id = ?",
                )
                .bind(amount + fee)
                .bind(user_id)
                .execute(db::get_db())
                .await;
                tracing::error!(%e, %out_trade_no, %user_id, "withdraw distribute error, refunded");
            }
        }
    });

    Redirect::to("/dashboard?msg=withdraw_submitted").into_response()
}

// ---- User Center Page ----

pub async fn user_center_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    if let Some(user) = sqlx::query_as::<_, (String, String, String, f64, f64, f64, String)>(
        "SELECT username, email, api_key, core_hours, bonus_core_hours, total_usage_hours, created_at FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    {
        let profile = serde_json::json!({
            "username": user.0,
            "email": user.1,
            "api_key": user.2,
            "core_hours": user.3,
            "bonus_core_hours": user.4,
            "total_usage_hours": user.5,
            "created_at": user.6
        });
        ctx.insert("profile", &profile);
        if !user.2.is_empty() {
            ctx.insert("api_key", &user.2);
        }
    }

    let active_machines: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM machines WHERE user_id = ? AND status = 'running'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("active_machines", &(active_machines as i32));

    let total_machines: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM machines WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("total_machines", &(total_machines as i32));

    let total_servers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM servers WHERE owner_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("total_servers", &(total_servers as i32));

    let total_orders: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM orders WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("total_orders", &(total_orders as i32));

    let unread_warnings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM warning_letters WHERE user_id = ? AND is_read = 0"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("unread_warnings", &(unread_warnings as i32));

    let total_warnings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM warning_letters WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("total_warnings", &(total_warnings as i32));

    let rendered = state
        .templates
        .render("user/index.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn user_email_update(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, _username) = match require_auth(&cookies) {
        Ok(v) => (v.0, v.1),
        Err(redirect) => return redirect.into_response(),
    };

    let email = form.get("email").cloned().unwrap_or_default();

    // 简单验证邮箱格式
    if !email.is_empty() && (!email.contains('@') || !email.contains('.')) {
        return Redirect::to("/user?error=invalid_email").into_response();
    }

    let pool = db::get_db();
    let _ = sqlx::query("UPDATE users SET email = ? WHERE id = ?")
        .bind(&email)
        .bind(user_id)
        .execute(pool)
        .await;

    Redirect::to("/user").into_response()
}

// ---- Packages Page ----

pub async fn packages_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> impl IntoResponse {
    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let packages: Vec<RechargePackage> = sqlx::query_as(
        "SELECT id, name, duration_days, core_hours, price_ldc, is_cumulative, cumulative_hours, is_active, created_at FROM recharge_packages WHERE is_active = 1 ORDER BY is_cumulative DESC, price_ldc ASC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("user/packages.html", &ctx)
        .unwrap_or_default();
    Html(rendered)
}

// ---- Recharge Page ----

pub async fn recharge_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let recharge_multiplier = db::get_config("recharge_multiplier")
        .await
        .unwrap_or_else(|| "1.0".to_string())
        .parse::<f64>()
        .unwrap_or(1.0);
    ctx.insert("recharge_multiplier", &recharge_multiplier);

    let recharge_fee = db::get_config("recharge_fee")
        .await
        .unwrap_or_else(|| "0.0".to_string())
        .parse::<f64>()
        .unwrap_or(0.0);
    ctx.insert("recharge_fee", &recharge_fee);

    let rendered = state
        .templates
        .render("user/recharge.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn recharge_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let money: f64 = form
        .get("money")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0)
        .max(0.01);

    let pool = db::get_db();
    let cfg = crate::config::AppConfig::get();
    let out_trade_no = format!("recharge_{}_{}", user_id, chrono::Utc::now().timestamp_millis());

    let _ = sqlx::query(
        "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, order_type, status) VALUES (?, ?, ?, ?, ?, 'recharge', 'pending')",
    )
    .bind(user_id)
    .bind(&out_trade_no)
    .bind(money)
    .bind(money)
    .bind(format!("账户充值 {:.2} 元", money))
    .execute(pool)
    .await;

    match crate::services::ldc_payment::create_payment(cfg, &out_trade_no, money, &format!("账户充值 {:.2} 元", money)).await {
        Ok(pay_url) => Ok(Redirect::to(&pay_url).into_response()),
        Err(_) => Ok(Redirect::to("/recharge?error=pay_failed").into_response()),
    }
}

// ---- Balance to Code Page ----

pub async fn balance_to_code_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let user: Option<(f64, f64)> = sqlx::query_as(
        "SELECT core_hours, bonus_core_hours FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    if let Some((ch, bch)) = user {
        ctx.insert("core_hours", &ch);
        ctx.insert("bonus_core_hours", &bch);
    }

    let fee_pct = db::get_config("balance_to_code_fee")
        .await
        .unwrap_or_else(|| "0.05".to_string())
        .parse::<f64>()
        .unwrap_or(0.05)
        * 100.0;
    ctx.insert("fee_pct", &fee_pct);

    let daily_limit = db::get_config("balance_to_code_daily_limit")
        .await
        .unwrap_or_else(|| "5".to_string())
        .parse::<i64>()
        .unwrap_or(5);
    ctx.insert("daily_limit", &daily_limit);

    let today_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM balance_to_code_logs WHERE user_id = ? AND DATE(created_at) = DATE('now')"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("today_count", &today_count);
    ctx.insert("can_convert", &(today_count < daily_limit));

    let logs: Vec<BalanceToCodeLog> = sqlx::query_as(
        "SELECT id, user_id, amount, fee, is_bonus, code, created_at FROM balance_to_code_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 20"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("logs", &logs);

    let rendered = state
        .templates
        .render("user/balance_to_code.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Warning Letters Page ----

pub async fn warning_letters_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let letters: Vec<WarningLetter> = sqlx::query_as(
        "SELECT id, user_id, subject, content, warning_type, severity, is_read, requires_action, action_taken, action_note, action_at, sent_by, created_at, expires_at FROM warning_letters WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("letters", &letters);

    let unread_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM warning_letters WHERE user_id = ? AND is_read = 0"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    ctx.insert("unread_count", &(unread_count as i32));

    let rendered = state
        .templates
        .render("warning_letters.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Warning Letter Detail Page ----

pub async fn warning_letter_detail(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    if let Some(letter) = sqlx::query_as::<_, WarningLetter>(
        "SELECT id, user_id, subject, content, warning_type, severity, is_read, requires_action, action_taken, action_note, action_at, sent_by, created_at, expires_at FROM warning_letters WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    {
        ctx.insert("letter", &letter);

        let _ = sqlx::query("UPDATE warning_letters SET is_read = 1 WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(pool)
            .await;
    }

    let rendered = state
        .templates
        .render("warning_letter_detail.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Dispute Page ----

pub async fn dispute_page(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let machine_id = params.get("machine_id").cloned().unwrap_or_default();
    ctx.insert("machine_id", &machine_id);

    let machine_exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id.parse::<i64>().unwrap_or(0))
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    if machine_exists.is_none() {
        return Err(Redirect::to("/machines"));
    }

    let rendered = state
        .templates
        .render("user/dispute.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn dispute_create(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (user_id, username) = match require_auth(&cookies) {
        Ok(v) => (v.0, v.1),
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let machine_id: i64 = form
        .get("machine_id")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let reason = form.get("reason").cloned().unwrap_or_default();

    if machine_id == 0 || reason.is_empty() {
        return Redirect::to("/machines").into_response();
    }

    // 检查机器是否属于用户
    let machine: Option<(i64, f64)> = sqlx::query_as(
        "SELECT server_id, core_hours_per_hour FROM machines WHERE id = ? AND user_id = ?"
    )
    .bind(machine_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (server_id, ch_per_hour) = match machine {
        Some(v) => v,
        None => return Redirect::to("/machines").into_response(),
    };

    // 冻结24小时费用
    let freeze_amount = ch_per_hour * 24.0;
    let auto_resolve_hours = db::get_config("dispute_auto_resolve_hours")
        .await
        .unwrap_or_else(|| "72".to_string())
        .parse::<i64>()
        .unwrap_or(72);

    let result = sqlx::query(
        "INSERT INTO disputes (machine_id, user_id, server_id, reason, amount_frozen, regular_amount_frozen, bonus_amount_frozen, status, auto_resolve_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now', '+' || ? || ' hours'), CURRENT_TIMESTAMP)"
    )
    .bind(machine_id)
    .bind(user_id)
    .bind(server_id)
    .bind(&reason)
    .bind(freeze_amount)
    .bind(freeze_amount)
    .bind(0.0)
    .bind(auto_resolve_hours)
    .execute(pool)
    .await;

    if result.is_ok() {
        // 通知管理员
        let notify = db::get_config("mail_notify_dispute")
            .await
            .unwrap_or_else(|| "1".to_string())
            == "1";
        if notify {
            let site_name = db::get_config("site_name").await.unwrap_or_default();
            // 找到管理员邮箱
            let admins: Vec<(String, String)> = sqlx::query_as(
                "SELECT username, email FROM users WHERE is_admin = 1 AND email != ''"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();
            for (admin_name, admin_email) in admins {
                let notification = crate::services::mail_templates::dispute_created_notice(
                    &site_name, &admin_name, machine_id, &username, &reason,
                );
                crate::services::mail::send_mail_async(
                    admin_email,
                    notification.subject,
                    notification.html_body,
                    notification.text_body,
                );
            }
        }
    }

    Redirect::to(&format!("/machines/{}", machine_id)).into_response()
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
            "admin_api_key", "agent_api_key", "traffic_monitor_enabled", "traffic_bandwidth_threshold_mbps",
            "premium_enabled", "premium_ldc_cost", "virt_type", "select_mode", "lock_bonus",
            "global_cpu_multiplier", "global_memory_multiplier", "global_bandwidth_multiplier",
            "global_disk_multiplier", "recharge_multiplier", "recharge_fee", "withdraw_fee",
            "settlement_threshold_pct", "balance_to_code_fee", "balance_to_code_daily_limit",
            "balance_to_code_enabled", "ldc_ed25519_private_key", "ldc_ed25519_public_key",
            "mail_enabled", "mail_smtp_host", "mail_smtp_port", "mail_username", "mail_password",
            "mail_from_name", "mail_from_email", "mail_plain_domains",
            "mail_notify_warning_letter", "mail_notify_ban", "mail_notify_machine_status", "mail_notify_dispute",
            "new_user_core_hours", "owner_income_freeze_days", "global_nat_multiplier",
            "dispute_auto_resolve_hours", "checkin_bonus_expiry_days",
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

    if let Some(hours) = form.get("core_hours").and_then(|v| v.parse::<f64>().ok()) {
        let _ = sqlx::query("UPDATE users SET core_hours = ? WHERE id = ?")
            .bind(hours)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(bonus) = form.get("bonus_core_hours").and_then(|v| v.parse::<f64>().ok()) {
        let _ = sqlx::query("UPDATE users SET bonus_core_hours = ? WHERE id = ?")
            .bind(bonus)
            .bind(id)
            .execute(pool)
            .await;
    }
    if let Some(ban) = form.get("is_banned") {
        let banned = if ban == "1" { 1 } else { 0 };
        let was_banned: Option<i64> = sqlx::query_scalar("SELECT is_banned FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
        let was_banned = was_banned.unwrap_or(0) != 0;
        let now_banned = banned != 0;

        let _ = sqlx::query("UPDATE users SET is_banned = ? WHERE id = ?")
            .bind(banned)
            .bind(id)
            .execute(pool)
            .await;

        if was_banned != now_banned {
            let user: Option<(String, String)> = sqlx::query_as(
                "SELECT username, email FROM users WHERE id = ?"
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
            if let Some((username, email)) = user {
                if !email.is_empty() {
                    let site_name = db::get_config("site_name").await.unwrap_or_default();
                    let notify_ban = db::get_config("mail_notify_ban")
                        .await
                        .unwrap_or_else(|| "1".to_string())
                        == "1";
                    if notify_ban {
                        let notification = if now_banned {
                            crate::services::mail_templates::account_banned_notice(
                                &site_name, &username, "违反平台规则",
                            )
                        } else {
                            crate::services::mail_templates::account_unbanned_notice(&site_name, &username)
                        };
                        crate::services::mail::send_mail_async(
                            email,
                            notification.subject,
                            notification.html_body,
                            notification.text_body,
                        );
                    }
                }
            }
        }
    }

    if let Some(email_new) = form.get("email") {
        let _ = sqlx::query("UPDATE users SET email = ? WHERE id = ?")
            .bind(email_new)
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

// ---- Admin Packages Page ----

pub async fn admin_packages_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let packages: Vec<RechargePackage> = sqlx::query_as(
        "SELECT id, name, duration_days, core_hours, price_ldc, is_cumulative, cumulative_hours, is_active, created_at FROM recharge_packages ORDER BY is_cumulative DESC, price_ldc ASC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("admin/packages.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Codes Page ----

pub async fn admin_codes_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let codes: Vec<RedeemCode> = sqlx::query_as(
        "SELECT id, code, code_type, package_id, core_hours, is_used, used_by, created_at, used_at FROM redeem_codes ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("codes", &codes);

    let packages: Vec<(i64, String, f64)> = sqlx::query_as(
        "SELECT id, name, price_ldc FROM recharge_packages WHERE is_active = 1"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("admin/codes.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Invites Page ----

pub async fn admin_invites_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let invites: Vec<Invite> = sqlx::query_as(
        "SELECT id, code, is_used, used_by, created_at, used_at, private_note, public_note FROM invites ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("invites", &invites);

    let rendered = state
        .templates
        .render("admin/invites.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Orders Page ----

pub async fn admin_orders_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let orders: Vec<Order> = sqlx::query_as(
        "SELECT id, user_id, out_trade_no, money, ldc_amount, order_name, status, trade_no, created_at FROM orders ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("orders", &orders);

    let rendered = state
        .templates
        .render("admin/orders.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Machines Page ----

pub async fn admin_machines_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT id, user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, regular_core_hours_used, bonus_core_hours_used, expires_at, ssh_port, created_at, settled, used_hours, image, app_image, web_port, vnc_port, root_password, ip_address, app_secrets, free_nat_hours FROM machines ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("machines", &machines);

    let rendered = state
        .templates
        .render("admin/machines.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Machines Stats Page ----

pub async fn admin_machines_stats_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let machine_stats: Vec<MachineStats> = sqlx::query_as(
        "SELECT id, machine_id, cpu_usage_percent, memory_used_mb, memory_total_mb, disk_used_gb, disk_total_gb, bandwidth_rx_mbps, bandwidth_tx_mbps, uptime_seconds, process_count, last_updated FROM machine_stats ORDER BY last_updated DESC LIMIT 50"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("machine_stats", &machine_stats);

    let rendered = state
        .templates
        .render("admin/machines_stats.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Traffic Alerts Page ----

pub async fn admin_traffic_alerts_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let traffic_alerts: Vec<TrafficAlert> = sqlx::query_as(
        "SELECT id, machine_id, server_id, alert_type, message, resolved, created_at FROM traffic_alerts ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("traffic_alerts", &traffic_alerts);

    let rendered = state
        .templates
        .render("admin/traffic_alerts.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin OpenGFW Page ----

pub async fn admin_opengfw_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let rules: Vec<OpenGFWRule> = sqlx::query_as(
        "SELECT id, name, description, protocol, match_signature, action, is_active, created_at FROM opengfw_rules ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("rules", &rules);

    let logs: Vec<OpenGFWLog> = sqlx::query_as(
        "SELECT id, machine_id, server_id, protocol, src_ip, dst_ip, dst_port, blocked_at FROM opengfw_logs ORDER BY blocked_at DESC LIMIT 50"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("logs", &logs);

    let rendered = state
        .templates
        .render("admin/opengfw.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

// ---- Admin Disputes Page ----

pub async fn admin_disputes_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let disputes: Vec<Dispute> = sqlx::query_as(
        "SELECT id, machine_id, user_id, server_id, reason, status, resolution, reply, amount_frozen, regular_amount_frozen, bonus_amount_frozen, created_at, resolved_at, auto_resolve_at FROM disputes ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("disputes", &disputes);

    let rendered = state
        .templates
        .render("admin/disputes.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_dispute_resolve(
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let _ = match require_admin(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let resolution = form.get("resolution").cloned().unwrap_or_default();
    let reply = form.get("reply").cloned().unwrap_or_default();

    let dispute: Option<(i64, i64, f64, f64, f64)> = sqlx::query_as(
        "SELECT user_id, machine_id, amount_frozen, regular_amount_frozen, bonus_amount_frozen FROM disputes WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (user_id, machine_id, _amount, regular_frozen, bonus_frozen) = match dispute {
        Some(d) => (d.0, d.1, d.2, d.3, d.4),
        None => return Redirect::to("/admin/disputes").into_response(),
    };

    let result = resolution.clone();
    let is_upheld = resolution == "refund";
    let reply_text = if is_upheld { "争议成立，已退款" } else { "争议不成立，驳回申诉" };

    if is_upheld {
        // 退款给用户
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ?, bonus_core_hours = bonus_core_hours + ? WHERE id = ?")
            .bind(regular_frozen)
            .bind(bonus_frozen)
            .bind(user_id)
            .execute(pool)
            .await;
    }

    let _ = sqlx::query(
        "UPDATE disputes SET status = 'resolved', resolution = ?, reply = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?"
    )
    .bind(&result)
    .bind(&reply)
    .bind(id)
    .execute(pool)
    .await;

    // 发送通知邮件
    let notify = db::get_config("mail_notify_dispute")
        .await
        .unwrap_or_else(|| "1".to_string())
        == "1";
    if notify {
        let user: Option<(String, String)> = sqlx::query_as(
            "SELECT username, email FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        if let Some((username, email)) = user {
            if !email.is_empty() {
                let site_name = db::get_config("site_name").await.unwrap_or_default();
                let resolution_str = if is_upheld { "upheld" } else { "rejected" };
                let notification = crate::services::mail_templates::dispute_resolved_notice(
                    &site_name, &username, machine_id, resolution_str, reply_text,
                );
                crate::services::mail::send_mail_async(
                    email,
                    notification.subject,
                    notification.html_body,
                    notification.text_body,
                );
            }
        }
    }

    Redirect::to("/admin/disputes").into_response()
}

pub async fn admin_dispute_intervene(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let _ = match require_admin(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();

    let dispute: Option<(i64, i64)> = sqlx::query_as(
        "SELECT user_id, machine_id FROM disputes WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (user_id, machine_id) = match dispute {
        Some(d) => d,
        None => return Redirect::to("/admin/disputes").into_response(),
    };

    let _ = sqlx::query("UPDATE disputes SET status = 'platform' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    // 发送通知邮件
    let notify = db::get_config("mail_notify_dispute")
        .await
        .unwrap_or_else(|| "1".to_string())
        == "1";
    if notify {
        let user: Option<(String, String)> = sqlx::query_as(
            "SELECT username, email FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        if let Some((username, email)) = user {
            if !email.is_empty() {
                let site_name = db::get_config("site_name").await.unwrap_or_default();
                let notification = crate::services::mail_templates::dispute_intervened_notice(
                    &site_name, &username, machine_id,
                );
                crate::services::mail::send_mail_async(
                    email,
                    notification.subject,
                    notification.html_body,
                    notification.text_body,
                );
            }
        }
    }

    Redirect::to("/admin/disputes").into_response()
}

// ---- Admin Warning Letters Page ----

pub async fn admin_warning_letters_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let pool = db::get_db();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let letters: Vec<WarningLetter> = sqlx::query_as(
        "SELECT id, user_id, subject, content, warning_type, severity, is_read, requires_action, action_taken, action_note, action_at, sent_by, created_at, expires_at FROM warning_letters ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("letters", &letters);

    let users: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, username FROM users ORDER BY username ASC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    ctx.insert("users", &users);

    let rendered = state
        .templates
        .render("admin/warning_letters.html", &ctx)
        .unwrap_or_default();
    Ok(Html(rendered))
}

pub async fn admin_warning_letter_send(
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let (admin_id, _admin_name) = match require_admin(&cookies) {
        Ok(v) => v,
        Err(redirect) => return redirect.into_response(),
    };

    let pool = db::get_db();
    let user_id: i64 = form
        .get("user_id")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let subject = form.get("subject").cloned().unwrap_or_default();
    let content = form.get("content").cloned().unwrap_or_default();
    let warning_type = form.get("warning_type").cloned().unwrap_or_else(|| "general".to_string());
    let severity = form.get("severity").cloned().unwrap_or_else(|| "warning".to_string());
    let expiry_days: i64 = form
        .get("expiry_days")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let requires_action = if form.get("requires_action").is_some() { 1 } else { 0 };

    if user_id == 0 || subject.is_empty() || content.is_empty() {
        return Redirect::to("/admin/warning-letters?error=invalid_input").into_response();
    }

    let expires_at = if expiry_days > 0 {
        Some(format!("datetime('now', '+{} days')", expiry_days))
    } else {
        None
    };

    let query = if let Some(exp) = expires_at {
        format!(
            "INSERT INTO warning_letters (user_id, subject, content, warning_type, severity, requires_action, sent_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, {})",
            exp
        )
    } else {
        "INSERT INTO warning_letters (user_id, subject, content, warning_type, severity, requires_action, sent_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)".to_string()
    };

    let result = sqlx::query(&query)
        .bind(user_id)
        .bind(&subject)
        .bind(&content)
        .bind(&warning_type)
        .bind(&severity)
        .bind(requires_action)
        .bind(admin_id)
        .execute(pool)
        .await;

    if let Ok(res) = result {
        let letter_id = res.last_insert_rowid();
        // 发送邮件通知
        let user: Option<(String, String)> = sqlx::query_as(
            "SELECT username, email FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        if let Some((username, email)) = user {
            if !email.is_empty() {
                let site_name = db::get_config("site_name").await.unwrap_or_default();
                let notify = db::get_config("mail_notify_warning_letter")
                    .await
                    .unwrap_or_else(|| "1".to_string())
                    == "1";
                if notify {
                    let notification = crate::services::mail_templates::warning_letter_notice(
                        &site_name, &username, &subject, &content, letter_id,
                    );
                    crate::services::mail::send_mail_async(
                        email,
                        notification.subject,
                        notification.html_body,
                        notification.text_body,
                    );
                }
            }
        }
    }

    Redirect::to("/admin/warning-letters").into_response()
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

    // 1. 检查功能是否启用
    let enabled: String = db::get_config("balance_to_code_enabled")
        .await
        .unwrap_or_else(|| "false".to_string());
    if enabled != "true" {
        return Redirect::to("/dashboard?error=feature_disabled").into_response();
    }

    // 2. 最小金额
    if amount < 1.0 {
        return Redirect::to("/dashboard?error=min_amount").into_response();
    }

    // 3. 计算手续费
    let fee_rate: f64 = db::get_config("balance_to_code_fee")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.05);
    let fee = amount * fee_rate;
    let total_deduct = amount + fee;

    // 4. 检查每日限额
    let daily_limit: f64 = db::get_config("balance_to_code_daily_limit")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(5.0);

    let used_today: Option<f64> = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0) FROM balance_to_code_logs WHERE user_id = ? AND DATE(created_at) = DATE('now')",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let used_today = used_today.unwrap_or(0.0);

    if used_today + amount > daily_limit {
        return Redirect::to("/dashboard?error=daily_limit").into_response();
    }

    // 5. 检查14天冻结期（机主收入到账后14天才能提现）
    let freeze_days: i64 = db::get_config("owner_income_freeze_days")
        .await
        .unwrap_or_else(|| "14".to_string())
        .parse()
        .unwrap_or(14);

    let total_owner_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (total_regular_income, _total_bonus_income) = total_owner_income.unwrap_or((0.0, 0.0));

    let freeze_threshold = chrono::Utc::now() - chrono::Duration::days(freeze_days);
    let withdrawable_income: Option<(f64, f64)> = sqlx::query_as(
        "SELECT COALESCE(SUM(regular_amount), 0), COALESCE(SUM(bonus_amount), 0) FROM owner_income_logs WHERE user_id = ? AND created_at <= ?"
    )
    .bind(user_id)
    .bind(freeze_threshold)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (withdrawable_regular, _withdrawable_bonus) = withdrawable_income.unwrap_or((0.0, 0.0));

    let frozen_regular = (total_regular_income - withdrawable_regular).max(0.0);

    let user_balance: Option<(f64,)> = sqlx::query_as("SELECT core_hours FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    let user_core_hours = user_balance.map(|b| b.0).unwrap_or(0.0);
    let available = (user_core_hours - frozen_regular).max(0.0);

    if total_deduct > available {
        return Redirect::to(&format!("/dashboard?error=frozen_balance&frozen={:.2}&available={:.2}&days={}", frozen_regular, available, freeze_days)).into_response();
    }

    // 6. 事务：原子扣减余额 + 生成兑换码
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return Redirect::to("/dashboard?error=system_error").into_response(),
    };

    // 原子扣减（WHERE条件确保不会负数）
    let deduct_result = sqlx::query(
        "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?",
    )
    .bind(total_deduct)
    .bind(user_id)
    .bind(total_deduct)
    .execute(&mut *tx)
    .await;

    if deduct_result.is_err() || deduct_result.unwrap().rows_affected() == 0 {
        let _ = tx.rollback().await;
        return Redirect::to("/dashboard?error=insufficient_funds").into_response();
    }

    // 生成兑换码
    let code = format!("LDC{}", Uuid::new_v4().simple().to_string().to_uppercase());

    // 写入 balance_to_code_logs 记录
    let insert_result = sqlx::query(
        "INSERT INTO balance_to_code_logs (user_id, amount, fee, is_bonus, code, status) VALUES (?, ?, ?, 0, ?, 'active')",
    )
    .bind(user_id)
    .bind(amount)
    .bind(fee)
    .bind(&code)
    .execute(&mut *tx)
    .await;

    if insert_result.is_err() {
        let _ = tx.rollback().await;
        return Redirect::to("/dashboard?error=system_error").into_response();
    }

    // 同时写入 redeem_codes 表，使其可以被核销
    let redeem_result = sqlx::query(
        "INSERT INTO redeem_codes (code, code_type, core_hours) VALUES (?, 'core_hours', ?)",
    )
    .bind(&code)
    .bind(amount)
    .execute(&mut *tx)
    .await;

    if redeem_result.is_err() {
        let _ = tx.rollback().await;
        return Redirect::to("/dashboard?error=system_error").into_response();
    }

    if tx.commit().await.is_err() {
        return Redirect::to("/dashboard?error=system_error").into_response();
    }

    Redirect::to(&format!("/dashboard?code={}", code)).into_response()
}
