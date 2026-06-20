use axum::{
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Redirect},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tera::Context;
use tower_cookies::{cookie::time::Duration, Cookie, Cookies};
use uuid::Uuid;

pub mod api;

use crate::config::AppConfig;
use crate::db;
use crate::models::*;
use crate::services;
use crate::AppState;

// ---- Session Helpers (using signed cookies — SESSION_SECRET) ----

fn get_session_user(cookies: &Cookies) -> Option<(i64, String, bool)> {
    let session = services::session::get_session_checked(cookies)?;
    Some((session.user_id, session.username, session.is_admin))
}

/// 统一的 Agent API Key 获取函数 — 任何与 Agent 通信都应使用此函数
fn agent_api_key() -> String {
    db::get_config_sync("agent_api_key")
        .filter(|k| !k.is_empty() && k != "tea-platform-agent-key")
        .unwrap_or_else(|| {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            const CHARS: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(64);
            for b in bytes.iter() {
                out.push(CHARS[(b & 0xf) as usize] as char);
                out.push(CHARS[((b >> 4) & 0xf) as usize] as char);
            }
            out
        })
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
    let site_name = db::get_config_sync("site_name").unwrap_or_else(|| "茶的服务器公益站".to_string());
    ctx.insert("site_name", &site_name);

    if let Some(session) = services::session::get_session(cookies) {
        ctx.insert("user_name", &session.username);
        ctx.insert(
            "user_balance",
            &format!("{:.2}", session.core_hours),
        );
        ctx.insert("user_ldc", &format!("{:.2}", session.ldc_balance));
        ctx.insert("is_admin", &session.is_admin.to_string());
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
    let session = services::session::UserSession {
        user_id,
        username: username.to_string(),
        is_admin,
        core_hours,
        ldc_balance,
    };
    services::session::set_session_cookie(cookies, &session);
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

    // 避免时序攻击：使用 constant-time 比较
    let username_ok = constant_time_eq(params.username.as_bytes(), cfg.admin_username.as_bytes());
    let password_ok = constant_time_eq(params.password.as_bytes(), cfg.admin_password.as_bytes());

    if !username_ok || !password_ok {
        tracing::warn!("Failed admin login attempt for username='{}'", params.username);
        return Redirect::to("/").into_response();
    }

    // Find or create the admin user in DB
    let pool = db::get_db();
    let user: Option<(i64, String, bool, f64, f64)> = sqlx::query_as(
        "SELECT id, username, is_admin, core_hours, ldc_balance FROM users WHERE username = ?",
    )
    .bind(&params.username)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (user_id, username, core_hours, ldc_balance) =
        if let Some((uid, uname, _admin, ch, ldc)) = user {
            // Ensure admin flag is set
            let _ = sqlx::query("UPDATE users SET is_admin = 1 WHERE id = ?")
                .bind(uid)
                .execute(pool)
                .await;
            (uid, uname, ch, ldc)
        } else {
            // Create admin user with special linuxdo_id = -1
            let _ = sqlx::query(
                "INSERT INTO users (linuxdo_id, username, email, ldc_balance, core_hours, is_admin) VALUES (-1, ?, ?, 0, 0, 1)",
            )
            .bind(&params.username)
            .bind(format!("{}@admin.local", params.username))
            .execute(pool)
            .await;

            let new_user: (i64, String, f64, f64) = sqlx::query_as(
                "SELECT id, username, core_hours, ldc_balance FROM users WHERE username = ?",
            )
            .bind(&params.username)
            .fetch_one(pool)
            .await
            .unwrap_or((0, params.username.clone(), 0.0, 0.0));
            (new_user.0, new_user.1, new_user.2, new_user.3)
        };

    set_session_cookie(&cookies, user_id, &username, true, core_hours, ldc_balance);
    Redirect::to("/admin").into_response()
}

/// 简单的 constant-time 字节比较实现，用于避免时序侧信道攻击。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn logout(cookies: Cookies) -> impl IntoResponse {
    services::session::clear_session_cookie(&cookies);
    Redirect::to("/")
}

// ---- User Page Handlers ----

pub async fn user_dashboard(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();

    // Get user info
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
        .unwrap_or(None)
        .flatten();

    // Get user's machines
    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Get user's packages
    let packages: Vec<UserPackage> = sqlx::query_as(
        "SELECT * FROM user_packages WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Get user's contributed servers
    let my_servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE owner_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let premium_enabled = db::get_config_sync("premium_enabled").unwrap_or_else(|| "false".to_string()) == "true";
    let premium_ldc_cost = db::get_config_sync("premium_ldc_cost").unwrap_or_else(|| "100".to_string());

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("core_hours", &user.0);
    ctx.insert("ldc_balance", &user.1);
    ctx.insert("api_key", &api_key);
    ctx.insert("machines", &machines);
    ctx.insert("packages", &packages);
    ctx.insert("my_servers", &my_servers);
    ctx.insert("premium_enabled", &premium_enabled);
    ctx.insert("premium_ldc_cost", &premium_ldc_cost);

    let rendered = state
        .templates
        .render("user/dashboard.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn regenerate_api_key(
    cookies: Cookies,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, username, is_admin) = require_auth(&cookies)?;
    let new_key = format!("usr_{}", Uuid::new_v4().to_string().replace('-', ""));
    let pool = db::get_db();
    let _ = sqlx::query("UPDATE users SET api_key = ? WHERE id = ?")
        .bind(&new_key)
        .bind(user_id)
        .execute(pool)
        .await;
    // Refresh session
    let user: (f64, f64) = sqlx::query_as("SELECT core_hours, ldc_balance FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
        .unwrap_or((0.0, 0.0));
    set_session_cookie(&cookies, user_id, &username, is_admin, user.0, user.1);
    Ok(Redirect::to("/dashboard"))
}

pub async fn contribute_server_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, is_admin) = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    // If admin, pass available virt types based on config
    if is_admin {
        let virt_type =
            db::get_config_sync("virt_type").unwrap_or_else(|| "lxd".to_string());
        let types: Vec<&str> = virt_type.split(',').collect();
        ctx.insert("available_virt_types", &types);
    }

    let select_mode =
        db::get_config_sync("select_mode").unwrap_or_else(|| "market".to_string());
    ctx.insert("select_mode", &select_mode);

    let lock_bonus = db::get_config("lock_bonus").await.unwrap_or_else(|| "unlocked".to_string());
    ctx.insert("lock_bonus", &lock_bonus);

    let premium_enabled = db::get_config("premium_enabled").await.unwrap_or_else(|| "false".to_string());
    let premium_ldc_cost: f64 = db::get_config("premium_ldc_cost").await
        .and_then(|v| v.parse().ok())
        .unwrap_or(100.0);
    ctx.insert("premium_enabled", &premium_enabled);
    ctx.insert("premium_ldc_cost", &premium_ldc_cost);

    // Pass user's ldc balance to the template
    let pool2 = db::get_db();
    let user_ldc: Option<f64> = sqlx::query_scalar("SELECT ldc_balance FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool2)
        .await
        .unwrap_or(None)
        .flatten();
    ctx.insert("user_ldc", &user_ldc.unwrap_or(0.0));

    let rendered = state
        .templates
        .render("user/contribute.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
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
    pub premium_days: Option<i32>,
}

pub async fn contribute_server_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<ContributeServerForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let now = Utc::now();
    let expires_days = form.expires_days.unwrap_or(30);
    let expires_at = now + chrono::Duration::days(expires_days as i64);

    let virt_type = if is_admin {
        form.virt_type.unwrap_or_else(|| "lxd".to_string())
    } else {
        db::get_config_sync("virt_type").unwrap_or_else(|| "lxd".to_string())
    };

    let ssh_port = form.ssh_port.unwrap_or(22);
    let bandwidth_mbps = form.bandwidth_mbps.unwrap_or(0.0);
    let cpu_mult = form.cpu_multiplier.unwrap_or(1.0);
    let mem_mult = form.memory_multiplier.unwrap_or(1.0);
    let bw_mult = form.bandwidth_multiplier.unwrap_or(1.0);
    let disk_mult = form.disk_multiplier.unwrap_or(1.0);
    let use_bonus = form.use_bonus.unwrap_or(false);
    let expose_ip = form.expose_ip.unwrap_or(false);
    let nat_port_start = form.nat_port_start.unwrap_or(0);
    let nat_port_end = form.nat_port_end.unwrap_or(0);
    let nat_mult = form.nat_multiplier.unwrap_or(1.0);
    let max_machine_hours = form.max_machine_hours.unwrap_or(0.0);
    let linux_version = form.linux_version.unwrap_or_default();

    // ---- Premium logic ----
    let premium_days = form.premium_days.unwrap_or(0).max(0);
    let premium_enabled_cfg = db::get_config("premium_enabled").await
        .unwrap_or_else(|| "false".to_string());
    let premium_daily_cost: f64 = db::get_config("premium_ldc_cost").await
        .and_then(|v| v.parse().ok())
        .unwrap_or(100.0);

    let (is_premium, premium_expires_at, premium_cost) = if premium_days > 0 && premium_enabled_cfg == "true" {
        let total_cost = premium_daily_cost * premium_days as f64;
        // Check user balance
        let balance: Option<f64> = sqlx::query_scalar("SELECT ldc_balance FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
            .flatten();
        if balance.unwrap_or(0.0) >= total_cost {
            // Deduct from user's ldc_balance
            let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ?")
                .bind(total_cost)
                .bind(user_id)
                .execute(pool)
                .await;
            let expires = now + chrono::Duration::days(premium_days as i64);
            (true, Some(expires), total_cost)
        } else {
            (false, None, 0.0)
        }
    } else {
        (false, None, 0.0)
    };
    let _ = premium_cost; // suppress unused warning

    // Allocate proxy port
    let temp_proxy_port = services::ssh_proxy::allocate_port(0) as i32; // temporary

    let result = sqlx::query(
        "INSERT INTO servers (owner_id, name, ip, ssh_port, ssh_key, cpu_cores, memory_gb, bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier, disk_multiplier, use_bonus, virt_type, expires_at, is_active, proxy_port, agent_installed, expose_ip, nat_port_start, nat_port_end, nat_multiplier, max_machine_hours, linux_version, description, provider, is_premium, premium_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(temp_proxy_port)
    .bind(expose_ip)
    .bind(nat_port_start)
    .bind(nat_port_end)
    .bind(nat_mult)
    .bind(max_machine_hours)
    .bind(&linux_version)
    .bind(form.description.as_deref().unwrap_or(""))
    .bind(form.provider.as_deref().unwrap_or(""))
    .bind(is_premium)
    .bind(premium_expires_at)
    .execute(pool)
    .await;

    match result {
        Ok(res) => {
            let server_id = res.last_insert_rowid();
            // Release temp port and allocate with real server_id
            services::ssh_proxy::release_port(0);
            let final_proxy_port = services::ssh_proxy::allocate_port(server_id) as i32;

            // Update proxy_port in DB if different
            if final_proxy_port != temp_proxy_port {
                let _ = sqlx::query("UPDATE servers SET proxy_port = ? WHERE id = ?")
                    .bind(final_proxy_port)
                    .bind(server_id)
                    .execute(pool)
                    .await;
            }

            // Spawn background task to install agent via ssh2
            let ip = form.ip.clone();
            let ssh_port_copy = ssh_port;
            let ssh_key = form.ssh_key.clone();
            tokio::spawn(async move {
                install_agent_ssh(server_id, &ip, ssh_port_copy, &ssh_key).await;
            });

            Ok(Redirect::to("/dashboard"))
        }
        Err(e) => {
            // Release temp port on failure
            services::ssh_proxy::release_port(0);
            tracing::error!("Failed to insert server: {}", e);
            Ok(Redirect::to("/servers/contribute"))
        }
    }
}

async fn install_agent_ssh(_server_id: i64, _ip: &str, _port: i32, _ssh_key: &str) {
    // Attempt to connect via SSH and run agent installation
    // This runs in the background
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
            // Run agent install command
            if let Ok(mut channel) = session.channel_session() {
                if channel
                    .exec("curl -sSL https://example.com/agent-install.sh | bash")
                    .is_ok()
                {
                    let _ = channel.wait_close();
                    if channel.exit_status().unwrap_or(1) == 0 {
                        // Detect Linux version via uname -r
                        let mut detected_linux_version = String::new();
                        if let Ok(mut ver_channel) = session.channel_session() {
                            if ver_channel.exec("uname -r").is_ok() {
                                use std::io::Read;
                                let _ = ver_channel.read_to_string(&mut detected_linux_version);
                                detected_linux_version = detected_linux_version.trim().to_string();
                                let _ = ver_channel.wait_close();
                            }
                        }

                        // Mark agent as installed, backfill linux_version if empty
                        let pool = db::get_db();
                        let _ = sqlx::query(
                            "UPDATE servers SET agent_installed = 1, linux_version = CASE WHEN linux_version = '' OR linux_version IS NULL THEN ? ELSE linux_version END WHERE id = ?",
                        )
                        .bind(&detected_linux_version)
                        .bind(server_id)
                        .execute(pool);
                    }
                }
            }
        }
    })
    .await;
}

pub async fn machine_market(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE is_active = 1 AND expires_at > ?",
    )
    .bind(Utc::now())
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Get used capacity for each server
    let mut server_capacities: Vec<(Server, bool)> = Vec::new();
    for s in servers {
        let used: Option<(f64, f64, f64)> = sqlx::query_as(
            "SELECT COALESCE(SUM(cpu_cores), 0), COALESCE(SUM(memory_gb), 0), COALESCE(SUM(disk_gb), 0) FROM machines WHERE server_id = ? AND status = 'running'"
        )
        .bind(s.id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        
        let has_capacity = if let Some((used_cpu, used_mem, used_disk)) = used {
            (s.cpu_cores as f64) > used_cpu && s.memory_gb > used_mem && s.disk_gb > used_disk
        } else {
            true
        };
        server_capacities.push((s, has_capacity));
    }

    // Sort: premium first (if enabled), then has capacity, then by created_at DESC
    let premium_enabled = db::get_config_sync("premium_enabled").unwrap_or_else(|| "false".to_string()) == "true";
    server_capacities.sort_by(|a, b| {
        let a_premium = premium_enabled && a.0.is_premium;
        let b_premium = premium_enabled && b.0.is_premium;
        b_premium.cmp(&a_premium)  // premium first
            .then_with(|| b.1.cmp(&a.1))  // true (has capacity) comes first
            .then_with(|| b.0.created_at.cmp(&a.0.created_at))
    });

    let sorted_servers: Vec<Server> = server_capacities.into_iter().map(|(s, _)| s).collect();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("servers", &sorted_servers);
    ctx.insert("premium_enabled", &premium_enabled);

    let rendered = state
        .templates
        .render("user/market.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn auto_select_machine(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let rendered = state
        .templates
        .render("user/auto_select.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct CreateMachineForm {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub hours: Option<i32>,
}

pub async fn create_machine(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreateMachineForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, username, is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let now = Utc::now();

    // Get user info (including bonus)
    let user: Option<User> =
        sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let user = user.ok_or_else(|| Redirect::to("/login"))?;
    let core_hours = user.core_hours;
    let bonus_core_hours = user.bonus_core_hours;
    let total_available = core_hours + bonus_core_hours;
    let ldc_balance = user.ldc_balance;

    // Get server info
    let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
        .bind(form.server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let server = match server {
        Some(s) if s.is_active && s.expires_at > now => s,
        _ => return Ok(Redirect::to("/market")),
    };

    // Validate user input against server limits
    if form.cpu_cores <= 0 || form.cpu_cores > server.cpu_cores as i32 {
        return Ok(Redirect::to("/market?error=invalid_cpu"));
    }
    if form.memory_gb <= 0.0 || form.memory_gb > server.memory_gb {
        return Ok(Redirect::to("/market?error=invalid_memory"));
    }
    if form.disk_gb <= 0.0 || form.disk_gb > server.disk_gb {
        return Ok(Redirect::to("/market?error=invalid_disk"));
    }

    let mut hours = form.hours.unwrap_or(24) as i64;
    let mut expires_at = now + chrono::Duration::hours(hours);

    // Task 6.2: Check max machine hours
    if server.max_machine_hours > 0.0 && hours as f64 > server.max_machine_hours {
        return Ok(Redirect::to("/machines"));
    }

    // Check machine expiry does not exceed server expiry
    if expires_at > server.expires_at {
        let remaining_hours = (server.expires_at - now).num_hours().max(0);
        if remaining_hours == 0 {
            return Ok(Redirect::to("/market?error=server_expired"));
        }
        hours = remaining_hours.min(hours);
        expires_at = now + chrono::Duration::hours(hours);
    }

    // NAT port allocation: each running machine uses 1 NAT port
    let nat_ports = if server.expose_ip && server.nat_port_start > 0 {
        let used_ports: (i64,) = sqlx::query_as(
            "SELECT COALESCE(COUNT(*), 0) FROM machines WHERE server_id = ? AND status = 'running'"
        )
        .bind(server.id)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
        let total_available = (server.nat_port_end - server.nat_port_start) as i64;
        // Each machine uses 1 NAT port, check if there's capacity for this new machine
        if used_ports.0 < total_available {
            1 // This new machine uses 1 NAT port
        } else {
            0 // No ports available, won't charge for NAT
        }
    } else {
        0
    };

    // Calculate core hours per hour
    let ch_per_hour = services::core_hours::calculate_core_hours_per_hour(
        form.cpu_cores,
        form.memory_gb,
        0.0,
        form.disk_gb,
        server.cpu_multiplier,
        server.memory_multiplier,
        1.0,
        server.disk_multiplier,
        nat_ports,
        server.nat_multiplier,
    )
    .await;

    let total_cost = ch_per_hour * hours as f64;

    // Check if user has enough core hours (bonus + regular)
    if total_available < total_cost {
        return Ok(Redirect::to("/recharge"));
    }

    // Task 5.3: Deduct bonus first, then regular
    let bonus_used = if bonus_core_hours >= total_cost {
        total_cost
    } else {
        bonus_core_hours
    };
    let regular_used = total_cost - bonus_used;

    let _ = sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours - ?, core_hours = core_hours - ? WHERE id = ?")
        .bind(bonus_used)
        .bind(regular_used)
        .bind(user_id)
        .execute(pool)
        .await;

    let new_core_hours = core_hours - regular_used;

    // Update session cookie
    set_session_cookie(&cookies, user_id, &username, is_admin, new_core_hours, ldc_balance);

    // Task 5.3: Credit merchant - bonus used goes to merchant's bonus_core_hours with expiry
    if bonus_used > 0.0 {
        let _ = sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours + ?, bonus_expires_at = COALESCE(bonus_expires_at, ?) WHERE id = ?"
        )
        .bind(bonus_used)
        .bind(user.bonus_expires_at)
        .bind(server.owner_id)
        .execute(pool)
        .await;
    }
    if regular_used > 0.0 {
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
            .bind(regular_used)
            .bind(server.owner_id)
            .execute(pool)
            .await;
    }

    // Get proxy port from server
    let proxy_port = server.proxy_port;

    // Task 1.1: Include used_hours in machine insert
    let used_hours = hours as f64;
    let result = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port, used_hours) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)",
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
    .execute(pool)
    .await
    .unwrap();

    let machine_id = result.last_insert_rowid();

    // Update total_usage_hours
    let _ = sqlx::query(
        "UPDATE users SET total_usage_hours = total_usage_hours + ? WHERE id = ?",
    )
    .bind(hours as f64)
    .bind(user_id)
    .execute(pool)
    .await;

    // Check cumulative packages for auto-grant
    let total_usage: Option<f64> = sqlx::query_scalar(
        "SELECT total_usage_hours FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if let Some(total_hours) = total_usage {
        let cumulative_packages: Vec<RechargePackage> = sqlx::query_as(
            "SELECT * FROM recharge_packages WHERE is_cumulative = 1 AND is_active = 1 AND cumulative_hours IS NOT NULL",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for pkg in cumulative_packages {
            if let Some(threshold) = pkg.cumulative_hours {
                if total_hours >= threshold {
                    // Check if already granted
                    let already_granted: Option<i64> = sqlx::query_scalar(
                        "SELECT id FROM user_packages WHERE user_id = ? AND package_id = ?",
                    )
                    .bind(user_id)
                    .bind(pkg.id)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or(None);

                    if already_granted.is_none() {
                        let _ = sqlx::query(
                            "INSERT INTO user_packages (user_id, package_id, core_hours, is_active) VALUES (?, ?, ?, 1)",
                        )
                        .bind(user_id)
                        .bind(pkg.id)
                        .bind(pkg.core_hours)
                        .execute(pool)
                        .await;

                        // Grant core hours
                        let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                            .bind(pkg.core_hours)
                            .bind(user_id)
                            .execute(pool)
                            .await;
                    }
                }
            }
        }
    }

    // Trigger agent to create VM on the server
    let server_ip = server.ip.clone();
    let server_ssh_port = server.ssh_port;
    let server_ssh_key = server.ssh_key.clone();
    let machine_name = format!("machine-{}", machine_id);
    let virt_type = server.virt_type.clone();
    let cpu = form.cpu_cores;
    let memory = form.memory_gb;
    let disk = form.disk_gb;

    // Get configured agent API key (never use hardcoded default)
    let agent_key = agent_api_key();

    tokio::spawn(async move {
        let agent_url = format!("http://{}:19527", server_ip);
        let client = reqwest::Client::new();
        let _ = client
            .post(&format!("{}/create", agent_url))
            .header("X-API-Key", agent_key)
            .json(&serde_json::json!({
                "name": machine_name,
                "cpu": cpu,
                "memory": (memory * 1024.0) as i64,
                "disk": disk,
                "virt_type": virt_type,
            }))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;
    });

    Ok(Redirect::to("/machines"))
}

pub async fn my_machines(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let machines: Vec<Machine> = sqlx::query_as(
        "SELECT * FROM machines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machines", &machines);

    let rendered = state
        .templates
        .render("user/machines.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct MachineIdPath {
    pub id: i64,
}

pub async fn stop_machine(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<MachineIdPath>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let machine: Option<(i64, i64, String)> =
        sqlx::query_as("SELECT user_id, server_id, virt_type FROM machines WHERE id = ?")
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    match machine {
        Some((owner_id, server_id, virt_type)) if owner_id == user_id => {
            // Check if machine is already stopped
            let current_status: Option<(String,)> = sqlx::query_as(
                "SELECT status FROM machines WHERE id = ?"
            )
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            if let Some((status,)) = current_status {
                if status == "stopped" || status == "deleted" {
                    // Already stopped, no need to stop again
                    return Ok(Redirect::to("/machines"));
                }
            }

            let _ = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
                .bind(path.id)
                .execute(pool)
                .await;

            // Call agent to stop VM
            let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

            if let Some(s) = server {
                let machine_name = format!("machine-{}", path.id);
                // Use configured agent API key (never hardcoded)
                let agent_key = agent_api_key();
                tokio::spawn(async move {
                    let agent_url = format!("http://{}:19527", s.ip);
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&format!("{}/stop/{}", agent_url, machine_name))
                        .header("X-API-Key", agent_key)
                        .timeout(std::time::Duration::from_secs(15))
                        .send()
                        .await;
                });
            }
        }
        _ => {}
    }

    Ok(Redirect::to("/machines"))
}

pub async fn delete_machine(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<MachineIdPath>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let machine: Option<(i64, i64)> =
        sqlx::query_as("SELECT user_id, server_id FROM machines WHERE id = ?")
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    match machine {
        Some((owner_id, server_id)) if owner_id == user_id => {
            // Check if machine already deleted
            let current_status: Option<(String,)> = sqlx::query_as(
                "SELECT status FROM machines WHERE id = ?"
            )
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            if let Some((status,)) = current_status {
                if status == "deleted" {
                    // Already deleted
                    return Ok(Redirect::to("/machines"));
                }
            }

            // Get server info before deletion for agent call
            let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

            let machine_name = format!("machine-{}", path.id);

            // Mark as deleted and call agent (do in this order for consistency)
            let _ = sqlx::query("UPDATE machines SET status = 'deleted' WHERE id = ?")
                .bind(path.id)
                .execute(pool)
                .await;

            if let Some(s) = server {
                let agent_key = agent_api_key();
                tokio::spawn(async move {
                    let agent_url = format!("http://{}:19527", s.ip);
                    let client = reqwest::Client::new();
                    let _ = client
                        .delete(&format!("{}/{}", agent_url, machine_name))
                        .header("X-API-Key", agent_key)
                        .timeout(std::time::Duration::from_secs(15))
                        .send()
                        .await;
                });
            }
        }
        _ => {}
    }

    Ok(Redirect::to("/machines"))
}

pub async fn machine_connect(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<MachineIdPath>,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let machine: Option<Machine> = sqlx::query_as("SELECT * FROM machines WHERE id = ? AND user_id = ?")
        .bind(path.id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let machine = match machine {
        Some(m) => m,
        None => return Err(Redirect::to("/machines")),
    };

    // Get server for proxy info
    let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ?")
        .bind(machine.server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machine", &machine);

    if let Some(ref srv) = server {
        ctx.insert("server_ip", &srv.ip);
        if srv.expose_ip {
            // Direct connection: expose server IP with SSH port
            ctx.insert("proxy_port", &srv.ssh_port);
            ctx.insert("direct_connect", &true);
        } else {
            // Proxy connection: use proxy port
            ctx.insert("proxy_port", &machine.ssh_port.unwrap_or(0));
            ctx.insert("direct_connect", &false);
        }
    }

    let rendered = state
        .templates
        .render("user/connect.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct ServerIdPath {
    pub id: i64,
}

pub async fn delete_server(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<ServerIdPath>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let server: Option<(i64,)> =
        sqlx::query_as("SELECT owner_id FROM servers WHERE id = ?")
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    match server {
        Some((owner_id,)) if owner_id == user_id => {
            // Delete associated machines first
            let _ = sqlx::query("DELETE FROM machines WHERE server_id = ?")
                .bind(path.id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM servers WHERE id = ?")
                .bind(path.id)
                .execute(pool)
                .await;
            services::ssh_proxy::release_port(path.id);
        }
        _ => {}
    }

    Ok(Redirect::to("/dashboard"))
}

// ---- Recharge Handlers ----

pub async fn recharge_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let multiplier = db::get_config_sync("recharge_multiplier")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    ctx.insert("recharge_multiplier", &multiplier);

    let rendered = state
        .templates
        .render("user/recharge.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct RechargeForm {
    pub money: f64,
}

pub async fn create_recharge_order(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<RechargeForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    if form.money <= 0.0 {
        return Ok(Redirect::to("/recharge"));
    }

    let cfg = AppConfig::get();
    let pool = db::get_db();

    let out_trade_no = Uuid::new_v4().to_string().replace('-', "");
    let multiplier = db::get_config_sync("recharge_multiplier")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let fee_rate = db::get_config_sync("recharge_fee")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let ldc_amount = (form.money * multiplier * (1.0 - fee_rate)).max(0.0);

    // Create order in DB
    let _ = sqlx::query(
        "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, status) VALUES (?, ?, ?, ?, '充值订单', 'pending')",
    )
    .bind(user_id)
    .bind(&out_trade_no)
    .bind(form.money)
    .bind(ldc_amount)
    .execute(pool)
    .await;

    // Create payment via LDC
    match services::ldc_payment::create_payment(cfg, &out_trade_no, form.money, "充值订单").await {
        Ok(url) => Ok(Redirect::to(&url)),
        Err(_) => Ok(Redirect::to("/recharge")),
    }
}

#[derive(Deserialize)]
pub struct RechargeCallbackParams {
    pub out_trade_no: Option<String>,
    pub trade_no: Option<String>,
    pub money: Option<String>,
    pub status: Option<String>,
    pub sign: Option<String>,
    pub sign_type: Option<String>,
    pub pid: Option<String>,
    pub r#type: Option<String>,
    pub name: Option<String>,
}

pub async fn recharge_callback(
    State(_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let out_trade_no = match params.get("out_trade_no") {
        Some(v) => v.clone(),
        None => return "fail".to_string(),
    };
    let trade_no = params.get("trade_no").cloned().unwrap_or_default();
    let status = params.get("status").cloned().unwrap_or_default();
    let sign = params.get("sign").cloned().unwrap_or_default();
    let sign_type = params.get("sign_type").cloned().unwrap_or_else(|| "MD5".to_string());
    
    // Get amount from callback for verification (optional but recommended)
    let callback_money: f64 = params.get("money")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    let client_secret = db::get_config_sync("ldc_client_secret").unwrap_or_default();

    // Verify sign
    if sign_type == "MD5" {
        let mut sign_params: Vec<(&str, &str)> = params
            .iter()
            .filter(|(k, _)| *k != "sign" && *k != "sign_type")
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        sign_params.sort_by(|a, b| a.0.cmp(b.0));
        let payload: String = sign_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        let sign_str = format!("{}{}", payload, client_secret);
        let expected = format!("{:x}", md5::compute(sign_str.as_bytes()));
        if sign != expected {
            tracing::warn!("Payment callback sign verification failed for order: {}", out_trade_no);
            return "sign error".to_string();
        }
    }

    let pool = db::get_db();

    // Check if order exists and is still pending
    let order: Option<(i64, String, f64, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT user_id, status, ldc_amount, created_at FROM orders WHERE out_trade_no = ?",
    )
    .bind(&out_trade_no)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (order_user_id, order_status, order_ldc_amount, order_created_at) = match order {
        Some(o) => o,
        None => {
            tracing::warn!("Payment callback: order not found: {}", out_trade_no);
            return "order not found".to_string();
        }
    };

    // Check order status - prevent double processing
    if order_status != "pending" {
        tracing::debug!("Payment callback: order already processed: {}", out_trade_no);
        return "success".to_string();
    }

    // Verify payment status
    if status == "TRADE_SUCCESS" || status == "1" {
        // CRITICAL: Verify amount matches to prevent fraud
        // If callback includes money, verify it matches the order
        if callback_money > 0.0 && (callback_money - order_ldc_amount).abs() > 0.01 {
            tracing::warn!("Payment callback: amount mismatch for order {}: expected={}, got={}", 
                out_trade_no, order_ldc_amount, callback_money);
            return "amount mismatch".to_string();
        }

        // Update order status atomically with balance update
        // Use a single transaction to prevent race conditions
        let update_result = sqlx::query(
            "UPDATE orders SET status = 'paid', trade_no = ?, updated_at = CURRENT_TIMESTAMP WHERE out_trade_no = ? AND status = 'pending'"
        )
        .bind(&trade_no)
        .bind(&out_trade_no)
        .execute(pool)
        .await;

        match update_result {
            Ok(res) if res.rows_affected() > 0 => {
                // Update user balance
                let _ = sqlx::query(
                    "UPDATE users SET ldc_balance = ldc_balance + ? WHERE id = ?"
                )
                .bind(order_ldc_amount)
                .bind(order_user_id)
                .execute(pool)
                .await;
                tracing::info!("Payment successful: order={}, user={}, amount={}", 
                    out_trade_no, order_user_id, order_ldc_amount);
            }
            _ => {
                tracing::warn!("Payment callback: failed to update order status (possibly already processed): {}", out_trade_no);
            }
        }
    } else {
        // Payment failed - log it
        tracing::info!("Payment failed: order={}, status={}", out_trade_no, status);
    }

    "success".to_string()
}

// ---- Withdraw Handlers ----

pub async fn withdraw_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let rendered = state
        .templates
        .render("user/withdraw.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct WithdrawForm {
    pub amount: f64,
}

pub async fn withdraw_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<WithdrawForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, username, is_admin) = require_auth(&cookies)?;

    if form.amount <= 0.0 {
        return Ok(Redirect::to("/withdraw"));
    }

    let pool = db::get_db();
    let cfg = AppConfig::get();

    // Get user balance
    let user: Option<(f64, f64)> =
        sqlx::query_as("SELECT core_hours, ldc_balance FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let (core_hours, ldc_balance) = user.unwrap_or((0.0, 0.0));

    let fee_rate = db::get_config_sync("withdraw_fee")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let fee = form.amount * fee_rate;
    let actual_amount = form.amount - fee;

    if actual_amount <= 0.0 || ldc_balance < form.amount {
        return Ok(Redirect::to("/withdraw"));
    }

    let out_trade_no = format!("WD{}", Uuid::new_v4().to_string().replace('-', ""));

    // Call LDC distribute API FIRST to verify it succeeds
    let ldc_success = match services::ldc_payment::distribute_ldc(
        cfg,
        user_id,
        &username,
        actual_amount,
        &out_trade_no,
    )
    .await {
        Ok(true) => true,
        Ok(false) => {
            tracing::warn!("LDC distribute returned false for user {}", user_id);
            false
        }
        Err(e) => {
            tracing::error!("LDC distribute failed for user {}: {}", user_id, e);
            false
        }
    };

    if !ldc_success {
        return Ok(Redirect::to("/withdraw"));
    }

    // Only deduct after LDC API success
    let deduct_result = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ? AND ldc_balance >= ?")
        .bind(form.amount)
        .bind(user_id)
        .bind(form.amount)
        .execute(pool)
        .await;

    match deduct_result {
        Ok(res) if res.rows_affected() > 0 => {
            // Success - update session
            let new_balance = ldc_balance - form.amount;
            set_session_cookie(&cookies, user_id, &username, is_admin, core_hours, new_balance);

            // Create withdraw order record
            let _ = sqlx::query(
                "INSERT INTO orders (user_id, out_trade_no, money, ldc_amount, order_name, status) VALUES (?, ?, ?, ?, '提现', 'paid')",
            )
            .bind(user_id)
            .bind(&out_trade_no)
            .bind(form.amount)
            .bind(actual_amount)
            .execute(pool)
            .await;

            tracing::info!("Withdraw successful: user={}, amount={}, actual={}", user_id, form.amount, actual_amount);
            Ok(Redirect::to("/dashboard"))
        }
        _ => {
            // Failed to deduct (possible race condition or insufficient balance)
            // Note: LDC was already sent, so we need to log this for manual reconciliation
            tracing::error!("Withdraw failed to deduct balance but LDC was sent: user={}, amount={}, out_trade_no={}", 
                user_id, form.amount, out_trade_no);
            Ok(Redirect::to("/withdraw"))
        }
    }
}

// ---- Checkin Handler ----

pub async fn checkin(
    cookies: Cookies,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, username, is_admin) = require_auth(&cookies)?;

    let checkin_enabled = db::get_config_sync("checkin_enabled")
        .unwrap_or_else(|| "true".to_string());
    if checkin_enabled != "true" {
        return Ok(Redirect::to("/dashboard"));
    }

    let pool = db::get_db();
    let now = Utc::now();
    let today = now.date_naive();

    // Check if already checked in today
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
            return Ok(Redirect::to("/dashboard"));
        }
    }

    let reward: f64 = db::get_config_sync("checkin_reward")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);

    let expiry_days: f64 = db::get_config("checkin_bonus_expiry_days").await
        .unwrap_or_else(|| "30".to_string())
        .parse()
        .unwrap_or(30.0);
    
    // Get existing bonus expiry, extend from existing or current time
    let existing_expiry: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT bonus_expires_at FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .flatten();
    
    let now = chrono::Utc::now();
    let base_time = existing_expiry.filter(|e| e > &now).unwrap_or(now);
    let bonus_expires_at = base_time + chrono::Duration::days(expiry_days as i64);

    let _ = sqlx::query(
        "UPDATE users SET bonus_core_hours = bonus_core_hours + ?, bonus_expires_at = ?, last_checkin = ? WHERE id = ?"
    )
    .bind(reward)
    .bind(bonus_expires_at)
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await;

    let user_row: (f64, f64) = sqlx::query_as(
        "SELECT core_hours, ldc_balance FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .unwrap_or((reward, 0.0));

    // Record checkin
    let _ = sqlx::query(
        "INSERT INTO checkins (user_id, reward_core_hours) VALUES (?, ?)",
    )
    .bind(user_id)
    .bind(reward)
    .execute(pool)
    .await;

    set_session_cookie(&cookies, user_id, &username, is_admin, user_row.0, user_row.1);
    Ok(Redirect::to("/dashboard"))
}

// ---- Free Plan Handler ----

pub async fn free_plan(
    cookies: Cookies,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

    let free_enabled = db::get_config_sync("free_plan_enabled")
        .unwrap_or_else(|| "true".to_string());
    if free_enabled != "true" {
        return Ok(Redirect::to("/dashboard"));
    }

    let pool = db::get_db();
    let now = Utc::now();

    // Check if user already has an active free machine
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM machines WHERE user_id = ? AND status = 'running'",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(Some(0));

    if existing.unwrap_or(0) > 0 {
        return Ok(Redirect::to("/machines"));
    }

    // Find any available active server
    let server: Option<Server> = sqlx::query_as(
        "SELECT * FROM servers WHERE is_active = 1 AND expires_at > ? ORDER BY RANDOM() LIMIT 1",
    )
    .bind(now)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let server = match server {
        Some(s) => s,
        None => return Ok(Redirect::to("/dashboard")),
    };

    let cpu_cores = 1i32;
    let memory_gb = 1.0f64;
    let disk_gb = 10.0f64;

    let ch = services::core_hours::calculate_core_hours_per_hour(
        cpu_cores,
        memory_gb,
        0.0,
        disk_gb,
        server.cpu_multiplier,
        server.memory_multiplier,
        1.0,
        server.disk_multiplier,
        0,
        0.0,
    )
    .await;

    let expires_at = now + chrono::Duration::hours(24);

    let _ = sqlx::query(
        "INSERT INTO machines (user_id, server_id, cpu_cores, memory_gb, disk_gb, virt_type, status, core_hours_per_hour, expires_at, ssh_port) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)",
    )
    .bind(user_id)
    .bind(server.id)
    .bind(cpu_cores)
    .bind(memory_gb)
    .bind(disk_gb)
    .bind(&server.virt_type)
    .bind(ch)
    .bind(expires_at)
    .bind(server.proxy_port)
    .execute(pool)
    .await
    .unwrap();

    Ok(Redirect::to("/machines"))
}

// ---- Redeem Handlers ----

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
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct RedeemForm {
    pub code: String,
}

pub async fn redeem_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<RedeemForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, username, is_admin) = require_auth(&cookies)?;

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
        None => return Ok(Redirect::to("/redeem")),
    };

    let now = Utc::now();

    match code.code_type.as_str() {
        "core_hours" => {
            let reward = code.core_hours.unwrap_or(0.0);
            let user_row: (f64, f64) = sqlx::query_as(
                "UPDATE users SET core_hours = core_hours + ? WHERE id = ? RETURNING core_hours, ldc_balance",
            )
            .bind(reward)
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
            .unwrap_or((reward, 0.0));

            set_session_cookie(&cookies, user_id, &username, is_admin, user_row.0, user_row.1);
        }
        "subscription" => {
            let pkg_id = code.package_id;
            // Create user package
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

    // Mark code as used
    let _ = sqlx::query(
        "UPDATE redeem_codes SET is_used = 1, used_by = ?, used_at = ? WHERE id = ?",
    )
    .bind(user_id)
    .bind(now)
    .bind(code.id)
    .execute(pool)
    .await;

    Ok(Redirect::to("/dashboard"))
}

// ---- Package Handlers ----

pub async fn packages_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;

    let pool = db::get_db();
    let packages: Vec<RechargePackage> = sqlx::query_as(
        "SELECT * FROM recharge_packages WHERE is_active = 1 ORDER BY price_ldc ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("user/packages.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct BuyPackageForm {
    pub package_id: i64,
}

pub async fn buy_package(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<BuyPackageForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;

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
        None => return Ok(Redirect::to("/packages")),
    };

    let cfg = AppConfig::get();
    let out_trade_no = Uuid::new_v4().to_string().replace('-', "");

    // Create order
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

    // Create payment
    match services::ldc_payment::create_payment(cfg, &out_trade_no, pkg.price_ldc, &pkg.name).await {
        Ok(url) => Ok(Redirect::to(&url)),
        Err(_) => Ok(Redirect::to("/packages")),
    }
}

// ---- Admin Handlers ----

pub async fn admin_dashboard(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let server_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM servers")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let machine_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM machines")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let total_revenue: (Option<f64>,) =
        sqlx::query_as("SELECT SUM(money) FROM orders WHERE status = 'paid'")
            .fetch_one(pool)
            .await
            .unwrap_or((Some(0.0),));

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("user_count", &user_count.0);
    ctx.insert("server_count", &server_count.0);
    ctx.insert("machine_count", &machine_count.0);
    ctx.insert("total_revenue", &total_revenue.0.unwrap_or(0.0));

    let rendered = state
        .templates
        .render("admin/dashboard.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_config_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let configs: Vec<SiteConfig> = sqlx::query_as("SELECT * FROM site_config ORDER BY key")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("configs", &configs);

    let rendered = state
        .templates
        .render("admin/config.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_config_save(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<HashMap<String, String>>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    for (key, value) in &form {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await;
    }

    Ok(Redirect::to("/admin/config"))
}

pub async fn admin_users(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("users", &users);

    let rendered = state
        .templates
        .render("admin/users.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct AdminUserEditForm {
    pub is_banned: Option<bool>,
    pub core_hours: Option<f64>,
    pub ldc_balance: Option<f64>,
    pub is_admin: Option<String>,
}

pub async fn admin_user_edit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<MachineIdPath>,
    Form(form): Form<AdminUserEditForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (admin_user_id, _admin_username) = require_admin(&cookies)?;

    let pool = db::get_db();

    if let Some(banned) = form.is_banned {
        let _ = sqlx::query("UPDATE users SET is_banned = ? WHERE id = ?")
            .bind(banned)
            .bind(path.id)
            .execute(pool)
            .await;
    }
    if let Some(ch) = form.core_hours {
        let _ = sqlx::query("UPDATE users SET core_hours = ? WHERE id = ?")
            .bind(ch)
            .bind(path.id)
            .execute(pool)
            .await;
    }
    if let Some(ldc) = form.ldc_balance {
        let _ = sqlx::query("UPDATE users SET ldc_balance = ? WHERE id = ?")
            .bind(ldc)
            .bind(path.id)
            .execute(pool)
            .await;
    }

    // Handle is_admin: checkbox value is "on" when checked, absent when unchecked
    if let Some(is_admin_val) = &form.is_admin {
        if is_admin_val == "on" {
            let _ = sqlx::query("UPDATE users SET is_admin = 1 WHERE id = ?")
                .bind(path.id)
                .execute(pool)
                .await;
        }
    } else {
        // Checkbox not checked = revoke admin, but protect current admin
        if path.id != admin_user_id {
            let _ = sqlx::query("UPDATE users SET is_admin = 0 WHERE id = ?")
                .bind(path.id)
                .execute(pool)
                .await;
        }
    }

    Ok(Redirect::to("/admin/users"))
}

pub async fn admin_servers(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let servers: Vec<Server> = sqlx::query_as("SELECT * FROM servers ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("servers", &servers);

    let rendered = state
        .templates
        .render("admin/servers.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_servers_toggle(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<ServerIdPath>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    // Toggle is_active
    let server: Option<(bool,)> =
        sqlx::query_as("SELECT is_active FROM servers WHERE id = ?")
            .bind(path.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    if let Some((current,)) = server {
        let _ = sqlx::query("UPDATE servers SET is_active = ? WHERE id = ?")
            .bind(!current)
            .bind(path.id)
            .execute(pool)
            .await;
    }

    Ok(Redirect::to("/admin/servers"))
}

pub async fn admin_machines(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let machines: Vec<Machine> =
        sqlx::query_as("SELECT * FROM machines ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machines", &machines);

    let rendered = state
        .templates
        .render("admin/machines.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

// Machine overview with stats for admin
pub async fn admin_machines_stats(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    
    // Get all machines with their server info
    #[derive(Debug, sqlx::FromRow)]
    struct MachineWithServer {
        id: i64,
        user_id: i64,
        server_id: i64,
        cpu_cores: i32,
        memory_gb: f64,
        disk_gb: f64,
        status: String,
        virt_type: String,
        expires_at: chrono::DateTime<Utc>,
        created_at: chrono::DateTime<Utc>,
        server_name: String,
        server_ip: String,
    }
    
    let machines: Vec<MachineWithServer> = sqlx::query_as(
        r#"
        SELECT 
            m.id, m.user_id, m.server_id, m.cpu_cores, m.memory_gb, m.disk_gb,
            m.status, m.virt_type, m.expires_at, m.created_at,
            s.name as server_name, s.ip as server_ip
        FROM machines m
        JOIN servers s ON m.server_id = s.id
        ORDER BY m.created_at DESC
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    
    // Get stats and usernames for each machine
    #[derive(Debug, Serialize, Deserialize)]
    struct MachineStatsView {
        id: i64,
        user_id: i64,
        username: String,
        server_id: i64,
        server_name: String,
        server_ip: String,
        cpu_cores: i32,
        memory_gb: f64,
        disk_gb: f64,
        status: String,
        virt_type: String,
        expires_at: String,
        created_at: String,
        cpu_usage: f64,
        memory_used_mb: f64,
        memory_total_mb: f64,
        disk_used_gb: f64,
        disk_total_gb: f64,
        bandwidth_rx: f64,
        bandwidth_tx: f64,
        last_updated: String,
    }
    
    let mut machines_with_stats = Vec::new();
    for m in &machines {
        let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = ?")
            .bind(m.user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
            .unwrap_or_else(|| "Unknown".to_string());
        
        let stats: Option<(f64, f64, f64, f64, f64, f64, String)> = sqlx::query_as(
            r#"
            SELECT cpu_usage_percent, memory_used_mb, memory_total_mb, 
                   disk_used_gb, disk_total_gb, bandwidth_rx_mbps, 
                   strftime('%Y-%m-%d %H:%M', last_updated) as updated
            FROM machine_stats WHERE machine_id = ?
            "#
        )
        .bind(m.id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        
        let (cpu_usage, memory_used, memory_total, disk_used, disk_total, bw_rx, last_updated) = 
            stats.unwrap_or((0.0, 0.0, 0.0, 0.0, 0.0, 0.0, "N/A".to_string()));
        
        machines_with_stats.push(MachineStatsView {
            id: m.id,
            user_id: m.user_id,
            username,
            server_id: m.server_id,
            server_name: m.server_name.clone(),
            server_ip: m.server_ip.clone(),
            cpu_cores: m.cpu_cores,
            memory_gb: m.memory_gb,
            disk_gb: m.disk_gb,
            status: m.status.clone(),
            virt_type: m.virt_type.clone(),
            expires_at: m.expires_at.format("%Y-%m-%d %H:%M").to_string(),
            created_at: m.created_at.format("%Y-%m-%d %H:%M").to_string(),
            cpu_usage,
            memory_used_mb: memory_used,
            memory_total_mb: memory_total,
            disk_used_gb: disk_used,
            disk_total_gb: disk_total,
            bandwidth_rx: bw_rx,
            bandwidth_tx: 0.0,
            last_updated,
        });
    }

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machines", &machines_with_stats);

    let rendered = state
        .templates
        .render("admin/machines_stats.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_packages(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let packages: Vec<RechargePackage> =
        sqlx::query_as("SELECT * FROM recharge_packages ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("admin/packages.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct CreatePackageForm {
    pub name: String,
    pub duration_days: Option<i32>,
    pub core_hours: f64,
    pub price_ldc: f64,
    pub is_cumulative: Option<bool>,
    pub cumulative_hours: Option<f64>,
}

pub async fn admin_package_create(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreatePackageForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let _ = sqlx::query(
        "INSERT INTO recharge_packages (name, duration_days, core_hours, price_ldc, is_cumulative, cumulative_hours, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)",
    )
    .bind(&form.name)
    .bind(form.duration_days)
    .bind(form.core_hours)
    .bind(form.price_ldc)
    .bind(form.is_cumulative.unwrap_or(false))
    .bind(form.cumulative_hours)
    .execute(pool)
    .await;

    Ok(Redirect::to("/admin/packages"))
}

pub async fn admin_package_delete(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(path): Path<MachineIdPath>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let _ = sqlx::query("DELETE FROM recharge_packages WHERE id = ?")
        .bind(path.id)
        .execute(pool)
        .await;

    Ok(Redirect::to("/admin/packages"))
}

pub async fn admin_generate_codes(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let packages: Vec<RechargePackage> =
        sqlx::query_as("SELECT * FROM recharge_packages WHERE is_active = 1")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("packages", &packages);

    let rendered = state
        .templates
        .render("admin/codes.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct GenerateCodesForm {
    pub code_type: String,
    pub count: i32,
    pub package_id: Option<i64>,
    pub core_hours: Option<f64>,
}

pub async fn admin_generate_codes_submit(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<GenerateCodesForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let count = form.count.min(1000).max(1);

    for _ in 0..count {
        let code = format!(
            "{}-{}",
            Uuid::new_v4().to_string().replace('-', ""),
            Uuid::new_v4().to_string().replace('-', "")
        );
        let _ = sqlx::query(
            "INSERT INTO redeem_codes (code, code_type, package_id, core_hours, is_used) VALUES (?, ?, ?, ?, 0)",
        )
        .bind(&code)
        .bind(&form.code_type)
        .bind(form.package_id)
        .bind(form.core_hours)
        .execute(pool)
        .await;
    }

    Ok(Redirect::to("/admin/codes"))
}

pub async fn admin_invites(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let invites: Vec<Invite> = sqlx::query_as("SELECT * FROM invites ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("invites", &invites);

    let rendered = state
        .templates
        .render("admin/invites.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct GenerateInvitesForm {
    pub count: i32,
    pub private_note: Option<String>,
    pub public_note: Option<String>,
}

pub async fn admin_generate_invites(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<GenerateInvitesForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let count = form.count.min(1000).max(1);

    for _ in 0..count {
        let code = Uuid::new_v4().to_string().replace('-', "");
        let _ = sqlx::query(
            "INSERT INTO invites (code, is_used, private_note, public_note) VALUES (?, 0, ?, ?)",
        )
        .bind(&code)
        .bind(form.private_note.as_deref().unwrap_or(""))
        .bind(form.public_note.as_deref().unwrap_or(""))
        .execute(pool)
        .await;
    }

    Ok(Redirect::to("/admin/invites"))
}

pub async fn admin_orders(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let orders: Vec<Order> = sqlx::query_as("SELECT * FROM orders ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("orders", &orders);

    let rendered = state
        .templates
        .render("admin/orders.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn stats_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Html<String> {
    let pool = db::get_db();
    
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool).await.unwrap_or((0,));
    let server_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM servers")
        .fetch_one(pool).await.unwrap_or((0,));
    let running_machines: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM machines WHERE status = 'running'")
        .fetch_one(pool).await.unwrap_or((0,));
    let total_core_hours: (Option<f64>,) = sqlx::query_as("SELECT SUM(total_usage_hours) FROM users")
        .fetch_one(pool).await.unwrap_or((Some(0.0),));
    
    let recent_users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC LIMIT 10")
        .fetch_all(pool).await.unwrap_or_default();
    let recent_servers: Vec<Server> = sqlx::query_as("SELECT * FROM servers WHERE is_active = 1 ORDER BY created_at DESC LIMIT 10")
        .fetch_all(pool).await.unwrap_or_default();
    
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("user_count", &user_count.0);
    ctx.insert("server_count", &server_count.0);
    ctx.insert("running_machines", &running_machines.0);
    ctx.insert("total_core_hours", &total_core_hours.0.unwrap_or(0.0));
    ctx.insert("recent_users", &recent_users);
    ctx.insert("recent_servers", &recent_servers);
    
    let rendered = state.templates.render("user/stats.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Html(rendered)
}

pub async fn admin_traffic_alerts(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;

    let pool = db::get_db();
    let alerts: Vec<TrafficAlert> = sqlx::query_as(
        "SELECT * FROM traffic_alerts ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("alerts", &alerts);

    let rendered = state
        .templates
        .render("admin/traffic_alerts.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

// ---- Dispute handlers ----

#[derive(Deserialize)]
pub struct NewDisputeForm {
    pub machine_id: i64,
}

#[derive(Deserialize)]
pub struct CreateDisputeForm {
    pub machine_id: i64,
    pub reason: String,
}

pub async fn dispute_new_page(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(form): Query<NewDisputeForm>,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username, _is_admin) = require_auth(&cookies)?;
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("machine_id", &form.machine_id);
    let rendered = state.templates.render("user/dispute.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn dispute_create(
    State(_state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreateDisputeForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    // Get machine info
    let machine: Option<Machine> = sqlx::query_as("SELECT * FROM machines WHERE id = ? AND user_id = ?")
        .bind(form.machine_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let machine = machine.ok_or_else(|| Redirect::to("/machines"))?;

    // Calculate amount to freeze (core hours)
    let amount_frozen = machine.core_hours_per_hour * machine.used_hours;

    // Freeze the core hours (deduct from contributor)
    let _ = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = (SELECT owner_id FROM servers WHERE id = ?)")
        .bind(amount_frozen)
        .bind(machine.server_id)
        .execute(pool)
        .await;

    let auto_hours: f64 = db::get_config("dispute_auto_resolve_hours").await
        .unwrap_or_else(|| "72".to_string())
        .parse()
        .unwrap_or(72.0);
    let auto_resolve_at = chrono::Utc::now() + chrono::Duration::hours(auto_hours as i64);

    let _ = sqlx::query(
        "INSERT INTO disputes (machine_id, user_id, server_id, reason, amount_frozen, auto_resolve_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(form.machine_id)
    .bind(user_id)
    .bind(machine.server_id)
    .bind(&form.reason)
    .bind(amount_frozen)
    .bind(auto_resolve_at)
    .execute(pool)
    .await;

    Ok(Redirect::to("/machines"))
}

pub async fn admin_disputes(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();
    let disputes: Vec<Dispute> = sqlx::query_as("SELECT * FROM disputes ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("disputes", &disputes);
    let rendered = state.templates.render("admin/disputes.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct ResolveDisputeForm {
    pub resolution: String,
}

pub async fn admin_dispute_resolve(
    State(_state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<ResolveDisputeForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();

    let dispute: Option<Dispute> = sqlx::query_as("SELECT * FROM disputes WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    if let Some(d) = dispute {
        if form.resolution == "refund" {
            // Refund to user
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(d.amount_frozen)
                .bind(d.user_id)
                .execute(pool)
                .await;
        } else {
            // Reject: restore to server owner
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = (SELECT owner_id FROM servers WHERE id = ?)")
                .bind(d.amount_frozen)
                .bind(d.server_id)
                .execute(pool)
                .await;
        }
        let _ = sqlx::query("UPDATE disputes SET status = 'resolved', resolution = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(&form.resolution)
            .bind(id)
            .execute(pool)
            .await;
    }

    Ok(Redirect::to("/admin/disputes"))
}

// Merchant reply to dispute
#[derive(Deserialize)]
pub struct MerchantDisputeReplyForm {
    pub reply: String,
    pub action: String, // "refund" or "reject"
}

pub async fn merchant_dispute_reply(
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<MerchantDisputeReplyForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let dispute: Option<Dispute> = sqlx::query_as(
        "SELECT d.* FROM disputes d JOIN servers s ON d.server_id = s.id WHERE d.id = ? AND s.owner_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if let Some(d) = dispute {
        let _ = sqlx::query("UPDATE disputes SET reply = ? WHERE id = ?")
            .bind(&form.reply)
            .bind(id)
            .execute(pool)
            .await;

        if form.action == "refund" {
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(d.amount_frozen)
                .bind(d.user_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("UPDATE disputes SET status = 'resolved', resolution = 'refund', resolved_at = CURRENT_TIMESTAMP WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await;
        } else if form.action == "reject" {
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(d.amount_frozen)
                .bind(user_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("UPDATE disputes SET status = 'resolved', resolution = 'reject', resolved_at = CURRENT_TIMESTAMP WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await;
        }
    }

    Ok(Redirect::to("/dashboard"))
}

// ---- OAuth App handlers ----

#[derive(Deserialize)]
pub struct CreateOAuthAppForm {
    pub name: String,
    pub redirect_uri: String,
}

pub async fn admin_oauth_apps(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (_user_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();
    let apps: Vec<OAuthApp> = sqlx::query_as("SELECT * FROM oauth_apps ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("apps", &apps);
    let rendered = state.templates.render("admin/oauth_apps.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_oauth_apps_create(
    cookies: Cookies,
    Form(form): Form<CreateOAuthAppForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();
    let client_id = format!("app_{}", Uuid::new_v4().to_string().replace('-', ""));
    let client_secret = format!("secret_{}", Uuid::new_v4().to_string().replace('-', ""));
    let _ = sqlx::query(
        "INSERT INTO oauth_apps (name, client_id, client_secret, redirect_uri, created_by) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&form.name)
    .bind(&client_id)
    .bind(&client_secret)
    .bind(&form.redirect_uri)
    .bind(user_id)
    .execute(pool)
    .await;
    Ok(Redirect::to("/admin/oauth-apps"))
}

// ---- Balance to Code handlers ----

pub async fn balance_to_code_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let user = user.ok_or_else(|| Redirect::to("/login"))?;

    let daily_limit: i64 = db::get_config("balance_to_code_daily_limit").await
        .unwrap_or_else(|| "5".to_string()).parse().unwrap_or(5);
    let fee_pct: f64 = db::get_config("balance_to_code_fee").await
        .unwrap_or_else(|| "0.05".to_string()).parse().unwrap_or(0.05);
    let enabled = db::get_config("balance_to_code_enabled").await
        .unwrap_or_else(|| "true".to_string());

    let today_start = chrono::Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM balance_to_code_logs WHERE user_id = ? AND created_at >= ?"
    )
    .bind(user_id)
    .bind(today_start)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let logs: Vec<BalanceToCodeLog> = sqlx::query_as(
        "SELECT * FROM balance_to_code_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 20"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let can_convert = enabled == "true" && today_count.0 < daily_limit;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("core_hours", &user.core_hours);
    ctx.insert("bonus_core_hours", &user.bonus_core_hours);
    ctx.insert("bonus_expires_at", &user.bonus_expires_at);
    ctx.insert("today_count", &today_count.0);
    ctx.insert("daily_limit", &daily_limit);
    ctx.insert("fee_pct", &(fee_pct * 100.0));
    ctx.insert("can_convert", &can_convert);
    ctx.insert("logs", &logs);

    let rendered = state.templates.render("user/balance_to_code.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

#[derive(Deserialize)]
pub struct BalanceToCodeForm {
    pub amount: f64,
    pub use_bonus: Option<String>,
}

pub async fn balance_to_code_submit(
    cookies: Cookies,
    Form(form): Form<BalanceToCodeForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let daily_limit: i64 = db::get_config("balance_to_code_daily_limit").await
        .unwrap_or_else(|| "5".to_string()).parse().unwrap_or(5);
    let fee_pct: f64 = db::get_config("balance_to_code_fee").await
        .unwrap_or_else(|| "0.05".to_string()).parse().unwrap_or(0.05);

    let today_start = chrono::Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM balance_to_code_logs WHERE user_id = ? AND created_at >= ?"
    )
    .bind(user_id)
    .bind(today_start)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if today_count.0 >= daily_limit {
        return Ok(Redirect::to("/balance-to-code"));
    }

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    let user = user.ok_or_else(|| Redirect::to("/login"))?;

    let fee = form.amount * fee_pct;
    let total_deduct = form.amount + fee;
    let is_bonus = form.use_bonus.as_deref() == Some("on");

    if is_bonus {
        if user.bonus_core_hours < total_deduct {
            return Ok(Redirect::to("/balance-to-code"));
        }
        let _ = sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ?")
            .bind(total_deduct)
            .bind(user_id)
            .execute(pool)
            .await;
    } else {
        if user.core_hours < total_deduct {
            return Ok(Redirect::to("/balance-to-code"));
        }
        let _ = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ?")
            .bind(total_deduct)
            .bind(user_id)
            .execute(pool)
            .await;
    }

    let code = format!("balance_{}", Uuid::new_v4().to_string().replace('-', ""));

    // Create redeem code
    let _ = sqlx::query(
        "INSERT INTO redeem_codes (code, code_type, core_hours) VALUES (?, 'core_hours', ?)"
    )
    .bind(&code)
    .bind(form.amount)
    .execute(pool)
    .await;

    // Log
    let _ = sqlx::query(
        "INSERT INTO balance_to_code_logs (user_id, amount, fee, is_bonus, code) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(user_id)
    .bind(form.amount)
    .bind(fee)
    .bind(is_bonus)
    .bind(&code)
    .execute(pool)
    .await;

    Ok(Redirect::to("/balance-to-code"))
}

// ---- Buy Premium Handler ----

#[derive(Deserialize)]
pub struct BuyPremiumForm {
    pub premium_days: i32,
}

pub async fn buy_premium(
    cookies: Cookies,
    Path(server_id): Path<i64>,
    Form(form): Form<BuyPremiumForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();
    let days = form.premium_days.max(0);

    // Check if premium is enabled
    let premium_enabled = db::get_config_sync("premium_enabled").unwrap_or_else(|| "false".to_string());
    if premium_enabled != "true" || days <= 0 {
        return Ok(Redirect::to("/dashboard"));
    }

    // Check server ownership
    let server: Option<Server> = sqlx::query_as("SELECT * FROM servers WHERE id = ? AND owner_id = ?")
        .bind(server_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let server = match server {
        Some(s) => s,
        None => return Ok(Redirect::to("/dashboard")),
    };

    // Calculate cost
    let daily_cost: f64 = db::get_config_sync("premium_ldc_cost")
        .unwrap_or_else(|| "100".to_string())
        .parse()
        .unwrap_or(100.0);
    let total_cost = daily_cost * days as f64;

    // Check LDC balance
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => return Ok(Redirect::to("/login")),
    };

    if user.ldc_balance < total_cost {
        return Ok(Redirect::to("/dashboard"));
    }

    // Deduct LDC
    let _ = sqlx::query("UPDATE users SET ldc_balance = ldc_balance - ? WHERE id = ?")
        .bind(total_cost)
        .bind(user_id)
        .execute(pool)
        .await;

    // Calculate new premium expiry (extend from now or existing expiry)
    let now = Utc::now();
    let existing_expiry: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT premium_expires_at FROM servers WHERE id = ?"
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .flatten();
    let base = existing_expiry.filter(|e| e > &now).unwrap_or(now);
    let new_expiry = base + chrono::Duration::days(days as i64);

    // Update server
    let _ = sqlx::query("UPDATE servers SET is_premium = 1, premium_expires_at = ? WHERE id = ?")
        .bind(new_expiry)
        .bind(server_id)
        .execute(pool)
        .await;

    Ok(Redirect::to("/dashboard"))
}

// ==================== Warning Letters ====================

#[derive(Debug, Deserialize)]
pub struct SendWarningForm {
    pub user_id: i64,
    pub subject: String,
    pub content: String,
    pub warning_type: String,
    pub severity: String,
    pub requires_action: Option<String>,
    pub expiry_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct WarningActionForm {
    pub note: String,
}

pub async fn admin_warning_letters(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (admin_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();

    let raw_letters: Vec<(i64, i64, String, String, String, String, String, bool, bool, bool, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT w.id, w.user_id, u.username, w.subject, w.content, w.warning_type,
               w.severity, w.is_read, w.requires_action, w.action_taken,
               w.created_at, w.expires_at
        FROM warning_letters w
        JOIN users u ON w.user_id = u.id
        ORDER BY w.created_at DESC
        LIMIT 100
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let letters: Vec<WarningLetterView> = raw_letters
        .into_iter()
        .map(|(id, user_id, username, subject, content, warning_type, severity, is_read, requires_action, action_taken, created_at, expires_at)| {
            WarningLetterView {
                id,
                user_id,
                username,
                subject,
                content,
                warning_type,
                severity,
                is_read,
                requires_action,
                action_taken,
                action_note: None,
                created_at: created_at.format("%Y-%m-%d %H:%M").to_string(),
                expires_at: expires_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()),
            }
        })
        .collect();

    let users: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, username FROM users WHERE is_banned = 0 ORDER BY id"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("letters", &letters);
    ctx.insert("users", &users);

    let rendered = state.templates.render("admin/warning_letters.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn admin_warning_letters_send(
    cookies: Cookies,
    Form(form): Form<SendWarningForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (admin_id, _username) = require_admin(&cookies)?;
    let pool = db::get_db();

    let requires_action = form.requires_action.as_deref() == Some("on");

    let expires_at = form.expiry_days
        .filter(|&d| d > 0)
        .map(|d| Utc::now() + chrono::Duration::days(d as i64));

    let _ = sqlx::query(
        "INSERT INTO warning_letters (user_id, subject, content, warning_type, severity, requires_action, expires_at, sent_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(form.user_id)
    .bind(&form.subject)
    .bind(&form.content)
    .bind(&form.warning_type)
    .bind(&form.severity)
    .bind(requires_action)
    .bind(&expires_at)
    .bind(admin_id)
    .execute(pool)
    .await;

    Ok(Redirect::to("/admin/warning-letters"))
}

pub async fn admin_warning_letter_delete(
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, Redirect> {
    let _ = require_admin(&cookies)?;
    let pool = db::get_db();

    let _ = sqlx::query("DELETE FROM warning_letters WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Ok(Redirect::to("/admin/warning-letters"))
}

pub async fn user_warning_letters(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let raw_letters: Vec<(i64, String, String, String, String, bool, bool, bool, Option<String>, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT id, subject, content, warning_type, severity, is_read, requires_action,
               action_taken, action_note, created_at, expires_at
        FROM warning_letters
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let letters: Vec<WarningLetterView> = raw_letters
        .into_iter()
        .map(|(id, subject, content, warning_type, severity, is_read, requires_action, action_taken, action_note, created_at, expires_at)| {
            WarningLetterView {
                id,
                user_id,
                username: String::new(),
                subject,
                content,
                warning_type,
                severity,
                is_read,
                requires_action,
                action_taken,
                action_note,
                created_at: created_at.format("%Y-%m-%d %H:%M").to_string(),
                expires_at: expires_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()),
            }
        })
        .collect();

    let unread_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM warning_letters WHERE user_id = ? AND is_read = 0"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("letters", &letters);
    ctx.insert("unread_count", &unread_count.0);

    let rendered = state.templates.render("warning_letters.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn user_warning_letter_detail(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> Result<Html<String>, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let letter: Option<(i64, String, String, String, String, bool, bool, bool, Option<String>, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT id, subject, content, warning_type, severity, is_read, requires_action,
               action_taken, action_note, created_at, expires_at
        FROM warning_letters
        WHERE id = ? AND user_id = ?
        "#
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let letter = match letter {
        Some(l) => l,
        None => return Err(Redirect::to("/warnings")),
    };

    let _ = sqlx::query("UPDATE warning_letters SET is_read = 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    let letter_view = WarningLetterView {
        id: letter.0,
        user_id,
        username: String::new(),
        subject: letter.1,
        content: letter.2,
        warning_type: letter.3,
        severity: letter.4,
        is_read: true,
        requires_action: letter.5,
        action_taken: letter.6,
        action_note: letter.8,
        created_at: letter.9.format("%Y-%m-%d %H:%M").to_string(),
        expires_at: letter.10.map(|d| d.format("%Y-%m-%d %H:%M").to_string()),
    };

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);
    ctx.insert("letter", &letter_view);

    let rendered = state.templates.render("warning_letter_detail.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}

pub async fn user_warning_letter_action(
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(form): Form<WarningActionForm>,
) -> Result<impl IntoResponse, Redirect> {
    let (user_id, _username, _is_admin) = require_auth(&cookies)?;
    let pool = db::get_db();

    let now = Utc::now();
    let _ = sqlx::query(
        "UPDATE warning_letters SET action_taken = 1, action_note = ?, action_at = ? WHERE id = ? AND user_id = ? AND requires_action = 1"
    )
    .bind(&form.note)
    .bind(now)
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await;

    Ok(Redirect::to(&format!("/warnings/{}", id)))
}

// ==================== OpenGFW Admin Page ====================

pub async fn admin_opengfw_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Html<String>, Redirect> {
    let _ = require_admin(&cookies)?;

    let mut ctx = Context::new();
    build_base_context(&cookies, &mut ctx);

    let rendered = state
        .templates
        .render("admin/opengfw.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Ok(Html(rendered))
}