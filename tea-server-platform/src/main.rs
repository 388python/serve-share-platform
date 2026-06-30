use axum::{
    extract::{Form, Path, Query, State},
    http::{header::HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tera::{Context, Tera};
use tower_cookies::{cookie::SameSite, Cookie, CookieManagerLayer, Cookies};
use tower_http::services::ServeDir;
use tracing_subscriber;

mod config;
mod db;
mod handlers;
mod models;
mod services;

#[derive(Clone)]
pub struct AppState {
    pub templates: Arc<Tera>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout();

    // Set panic hook to ensure panics are visible in Docker logs
    std::panic::set_hook(Box::new(|info| {
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "[PANIC] {}", info);
        let _ = stderr.flush();
        eprintln!("[PANIC] {}", info);
    }));

    let _ = writeln!(stdout, "[tea-server-platform] starting...");
    let _ = stdout.flush();

    // Print environment info for debugging
    let _ = writeln!(stdout, "[DEBUG] Current directory: {:?}", std::env::current_dir());
    let _ = writeln!(stdout, "[DEBUG] templates dir exists: {}", std::path::Path::new("templates").exists());
    let _ = writeln!(stdout, "[DEBUG] static dir exists: {}", std::path::Path::new("static").exists());
    let _ = stdout.flush();

    // 初始化 tracing（带 ansicolor 关闭，避免 Docker 日志乱码）
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .init();

    tracing::info!("tracing subscriber initialized");

    // Load config
    match config::AppConfig::from_env() {
        Ok(_) => tracing::info!("config loaded successfully"),
        Err(e) => {
            tracing::error!("failed to load config: {}", e);
            let _ = writeln!(stdout, "[FATAL] failed to load config: {}", e);
            let _ = stdout.flush();
            return Err(e);
        }
    }
    let cfg = config::AppConfig::get();
    tracing::info!("database_url: {}", cfg.database_url);
    tracing::info!("bind_addr: {}", cfg.bind_addr);

    // Record startup time for health endpoint
    handlers::api::set_startup_time(chrono::Utc::now());

    // Init database
    tracing::info!("initializing database...");
    match db::init_db(&cfg.database_url).await {
        Ok(_) => tracing::info!("database initialized"),
        Err(e) => {
            tracing::error!("failed to initialize database: {}", e);
            return Err(e);
        }
    }

    // Init Tera templates
    tracing::info!("initializing templates...");
    let mut tera = match Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("failed to load templates: {}", e);
            let _ = writeln!(stdout, "[FATAL] failed to load templates: {}", e);
            let _ = stdout.flush();
            return Err(e.into());
        }
    };
    tera.autoescape_on(vec!["html", ".tera"]);
    let app_state = AppState {
        templates: Arc::new(tera),
    };
    tracing::info!("templates initialized");

    // Background task: stop expired machines every 60 seconds
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();

            // Get expired machines
            let expired: Vec<(i64, i64)> = match sqlx::query_as(
                "SELECT id, server_id FROM machines WHERE status = 'running' AND expires_at < ?",
            )
            .bind(now)
            .fetch_all(pool)
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Failed to query expired machines: {}", e);
                    continue;
                }
            };

            for (machine_id, server_id) in &expired {
                if let Err(e) = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
                    .bind(machine_id)
                    .execute(pool)
                    .await
                {
                    tracing::error!("Failed to stop expired machine {}: {}", machine_id, e);
                    continue;
                }

                // Call agent to stop VM
                let server: Option<(String,)> = match sqlx::query_as(
                    "SELECT ip FROM servers WHERE id = ?",
                )
                .bind(server_id)
                .fetch_optional(pool)
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Failed to query server {}: {}", server_id, e);
                        continue;
                    }
                };

                if let Some((ip,)) = server {
                    let machine_name = format!("machine-{}", machine_id);
                    let agent_url = format!("http://{}:19527", ip);
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&format!("{}/stop/{}", agent_url, machine_name))
                        .header("X-API-Key", "tea-platform-agent-key")
                        .timeout(std::time::Duration::from_secs(15))
                        .send()
                        .await;
                }
            }
            tracing::debug!("Expired machine cleanup: {} machines stopped", expired.len());
        }
    });

    // Background task: SSH proxy listener (start on port range)
    tokio::spawn(async move {
        let cfg = config::AppConfig::get();
        let start_port = cfg.ssh_proxy_port_start;
        // Start SSH proxy listeners on the port range
        for port_offset in 0..cfg.ssh_proxy_port_count {
            let port = start_port + port_offset;
            let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(l) => l,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((incoming, _addr)) => {
                            // Forward to the corresponding server
                            let pool = db::get_db();
                            let server: Option<(i32, String)> = sqlx::query_as(
                                "SELECT ssh_port, ip FROM servers WHERE proxy_port = ? AND is_active = 1",
                            )
                            .bind(port as i32)
                            .fetch_optional(pool)
                            .await
                            .unwrap_or(None);

                            if let Some((ssh_port, ip)) = server {
                                let target = format!("{}:{}", ip, ssh_port);
                                if let Ok(outgoing) = tokio::net::TcpStream::connect(&target).await {
                                    let (mut ri, mut wi) = tokio::io::split(incoming);
                                    let (mut ro, mut wo) = tokio::io::split(outgoing);
                                    let _ = tokio::join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    );
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    // Background task: Traffic monitoring
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let enabled = db::get_config("traffic_monitor_enabled").await
                .unwrap_or_else(|| "true".to_string());
            if enabled != "true" {
                continue;
            }
            let pool = db::get_db();
            let machines: Vec<(i64, String)> = match sqlx::query_as(
                "SELECT m.id, s.ip FROM machines m JOIN servers s ON m.server_id = s.id WHERE m.status = 'running'"
            )
            .fetch_all(pool)
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Failed to query running machines for traffic monitor: {}", e);
                    continue;
                }
            };
            
            for (machine_id, server_ip) in &machines {
                let alerts = services::traffic_monitor::scan_machine_traffic(*machine_id, server_ip).await;
                for alert_msg in &alerts {
                    tracing::warn!("Traffic alert for machine {}: {}", machine_id, alert_msg);
                    if let Err(e) = sqlx::query(
                        "INSERT INTO traffic_alerts (machine_id, alert_type, message) VALUES (?, 'traffic_violation', ?)"
                    )
                    .bind(machine_id)
                    .bind(alert_msg)
                    .execute(pool)
                    .await
                    {
                        tracing::error!("Failed to insert traffic alert for machine {}: {}", machine_id, e);
                    }
                    // Stop the machine
                    if let Err(e) = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
                        .bind(machine_id)
                        .execute(pool)
                        .await
                    {
                        tracing::error!("Failed to stop machine {} due to traffic alert: {}", machine_id, e);
                    }
                }
            }
        }
    });

    // Background task: Delayed settlement
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            let pool = db::get_db();
            let threshold_pct: f64 = db::get_config("settlement_threshold_pct").await
                .unwrap_or_else(|| "80".to_string())
                .parse()
                .unwrap_or(80.0);
            let threshold = threshold_pct / 100.0;

            // Find stopped/deleted machines that haven't been settled
            let machines: Vec<(i64, i64, f64, f64)> = match sqlx::query_as(
                "SELECT m.id, m.server_id, m.core_hours_per_hour, m.used_hours FROM machines m WHERE m.status IN ('stopped','deleted') AND m.settled = 0"
            )
            .fetch_all(pool)
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Failed to query unsettled machines: {}", e);
                    continue;
                }
            };

            for (machine_id, server_id, ch_per_hour, used_hours) in &machines {
                // Get server expiry
                let server_expiry: Option<(String,)> = match sqlx::query_as(
                    "SELECT expires_at FROM servers WHERE id = ?"
                )
                .bind(server_id)
                .fetch_optional(pool)
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Failed to query server expiry for settlement: {}", e);
                        continue;
                    }
                };

                if let Some((expires_at_str,)) = server_expiry {
                    if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(&expires_at_str) {
                        let max_hours = (expires_at.naive_utc() - chrono::Utc::now().naive_utc()).num_hours() as f64;
                        if max_hours > 0.0 && used_hours / max_hours >= threshold {
                            // Settle: credit core hours to server owner
                            let total_ch = ch_per_hour * used_hours;
                            if let Err(e) = sqlx::query(
                                "UPDATE users SET core_hours = core_hours + ? WHERE id = (SELECT owner_id FROM servers WHERE id = ?)"
                            )
                            .bind(total_ch)
                            .bind(server_id)
                            .execute(pool)
                            .await
                            {
                                tracing::error!("Failed to credit settlement for machine {}: {}", machine_id, e);
                                continue;
                            }
                            if let Err(e) = sqlx::query("UPDATE machines SET settled = 1 WHERE id = ?")
                                .bind(machine_id)
                                .execute(pool)
                                .await
                            {
                                tracing::error!("Failed to mark machine {} as settled: {}", machine_id, e);
                            }
                        }
                    }
                }
            }
        }
    });

    // Background task: Dispute auto-resolve
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();
            match sqlx::query(
                "UPDATE disputes SET status = 'platform' WHERE status = 'pending' AND auto_resolve_at <= ?"
            )
            .bind(now)
            .execute(pool)
            .await
            {
                Ok(_) => {}
                Err(e) => tracing::error!("Failed to auto-resolve disputes: {}", e),
            }
        }
    });

    // Background task: Clean expired bonus
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();
            match sqlx::query(
                "UPDATE users SET bonus_core_hours = 0, bonus_expires_at = NULL WHERE bonus_expires_at IS NOT NULL AND bonus_expires_at <= ?"
            )
            .bind(now)
            .execute(pool)
            .await
            {
                Ok(_) => {}
                Err(e) => tracing::error!("Failed to clean expired bonus: {}", e),
            }
        }
    });

    // Build router
    let app = Router::new()
        // Public routes
        .route("/", get(index_page))
        .route("/health", get(handlers::health_check))
        .route("/stats", get(handlers::stats_page))
        .route("/login", get(login_page))
        .route("/invite", post(invite_submit))
        .route("/auth/callback", get(auth_callback))
        .route("/admin-login", post(handlers::admin_login))
        .route("/admin-login/ui", get(handlers::admin_login_ui))
        .route("/logout", get(handlers::logout))
        // User center
        .route("/user", get(handlers::user_center_page))
        // User dashboard
        .route("/dashboard", get(handlers::user_dashboard))
        .route("/dashboard/api-key", post(handlers::regenerate_api_key))
        // Server contribution
        .route("/servers", get(handlers::servers_page))
        .route("/servers/contribute", get(handlers::contribute_server_page))
        .route("/servers/contribute", post(handlers::contribute_server_submit))
        .route("/servers/:id/delete", post(handlers::delete_server))
        .route("/servers/:id/buy-premium", post(handlers::buy_premium))
        // Machine market / auto select
        .route("/market", get(handlers::machine_market))
        .route("/machines/auto", get(handlers::auto_select_machine))
        .route("/machines/create", post(handlers::create_machine))
        .route("/machines", get(handlers::my_machines))
        .route("/machines/:id", get(handlers::machine_detail))
        .route("/machines/:id/stop", post(handlers::stop_machine))
        .route("/machines/:id/suspend", post(handlers::suspend_machine))
        .route("/machines/:id/unsuspend", post(handlers::unsuspend_machine))
        .route("/machines/:id/delete", post(handlers::delete_machine))
        .route("/machines/:id/connect", get(handlers::machine_connect))
        // WebSocket SSH
        .nest("/ws", handlers::websocket::router(app_state.clone()))
        // Disputes
        .route("/disputes/new", get(handlers::dispute_page))
        .route("/disputes/create", post(handlers::dispute_create))
        // Recharge
        .route("/recharge", get(handlers::recharge_page))
        .route("/recharge", post(handlers::recharge_submit))
        .route("/recharge/callback", get(handlers::recharge_callback))
        // Withdraw
        .route("/withdraw", get(handlers::withdraw_page))
        .route("/withdraw", post(handlers::withdraw_submit))
        // Checkin
        .route("/checkin", post(handlers::checkin))
        // Free plan
        .route("/free-plan", post(handlers::free_plan))
        // Balance to code
        .route("/balance-to-code", get(handlers::balance_to_code_page))
        .route("/balance-to-code", post(handlers::balance_to_code))
        // Packages
        .route("/packages", get(handlers::packages_page))
        // Redeem code
        .route("/redeem", get(handlers::redeem_page))
        .route("/redeem", post(handlers::redeem_submit))
        // Warning letters
        .route("/warnings", get(handlers::warning_letters_page))
        .route("/warnings/:id", get(handlers::warning_letter_detail))
        // User profile / email
        .route("/user/email", post(handlers::user_email_update))
        // OAuth authorize
        .route("/oauth/authorize", get(services::auth::oauth_authorize))
        // Admin routes
        .route("/admin", get(handlers::admin_dashboard))
        .route("/admin/config", get(handlers::admin_config_page))
        .route("/admin/config", post(handlers::admin_config_save))
        .route("/admin/users", get(handlers::admin_users))
        .route("/admin/users/:id", post(handlers::admin_user_edit))
        .route("/admin/servers", get(handlers::admin_servers))
        .route("/admin/servers/:id/toggle", post(handlers::admin_servers_toggle))
        .route("/admin/packages", get(handlers::admin_packages_page))
        .route("/admin/codes", get(handlers::admin_codes_page))
        .route("/admin/invites", get(handlers::admin_invites_page))
        .route("/admin/orders", get(handlers::admin_orders_page))
        .route("/admin/machines", get(handlers::admin_machines_page))
        .route("/admin/machines-stats", get(handlers::admin_machines_stats_page))
        .route("/admin/traffic-alerts", get(handlers::admin_traffic_alerts_page))
        .route("/admin/opengfw", get(handlers::admin_opengfw_page))
        .route("/admin/disputes", get(handlers::admin_disputes_page))
        .route("/admin/disputes/:id/resolve", post(handlers::admin_dispute_resolve))
        .route("/admin/disputes/:id/intervene", post(handlers::admin_dispute_intervene))
        .route("/admin/warning-letters", get(handlers::admin_warning_letters_page))
        .route("/admin/warning-letters/send", post(handlers::admin_warning_letter_send))
        .route("/admin/oauth-apps", get(handlers::admin_oauth_apps))
        .route("/admin/oauth-apps", post(handlers::admin_oauth_apps_create))
        // API routes (RESTful JSON) - mounted under /api prefix
        .nest("/api", handlers::api::router(app_state.clone()))
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(CookieManagerLayer::new())
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("Server listening on {}", cfg.bind_addr);
    println!("[DEBUG] Server started, listening on {}", cfg.bind_addr);
    let _ = std::io::Write::flush(&mut std::io::stdout());

    axum::serve(listener, app).await?;

    tracing::info!("Server shut down normally");
    println!("[DEBUG] Server shut down normally");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    Ok(())
}

// ---- Route Handlers ----

async fn index_page(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let cfg = config::AppConfig::get();
    let site_name = db::get_config("site_name")
        .await
        .unwrap_or_else(|| cfg.platform_domain.clone());

    let mut ctx = Context::new();
    ctx.insert("site_name", &site_name);
    ctx.insert("bonus_hours", &"0");

    if let Some(session_cookie) = cookies.get("session") {
        if let Some(session) = handlers::parse_signed_session_wrapper(session_cookie.value()) {
            let user_name = session.get("username").cloned().unwrap_or_default();
            let user_id_str = session.get("user_id").cloned().unwrap_or_default();
            let is_admin = session.get("is_admin").cloned().unwrap_or_else(|| "false".to_string());
            let core_hours = session.get("core_hours").cloned().unwrap_or_else(|| "0".to_string());
            let bonus_hours = session.get("bonus_core_hours").cloned().unwrap_or_else(|| "0".to_string());

            ctx.insert("user_name", &user_name);
            ctx.insert("user_balance", &core_hours);
            ctx.insert("is_admin", &is_admin);
            ctx.insert("bonus_hours", &bonus_hours);

            // Fetch user profile from database
            if let Ok(user_id) = user_id_str.parse::<i64>() {
                let pool = db::get_db();
                
                // Get user details
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

                // Count user's machines
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

                // Count user's servers
                let total_servers: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM servers WHERE owner_id = ?"
                )
                .bind(user_id)
                .fetch_one(pool)
                .await
                .unwrap_or(0);
                ctx.insert("total_servers", &(total_servers as i32));

                // Count user's orders
                let total_orders: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM orders WHERE user_id = ?"
                )
                .bind(user_id)
                .fetch_one(pool)
                .await
                .unwrap_or(0);
                ctx.insert("total_orders", &(total_orders as i32));

                // Count warning letters
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
            }
        }
    }

    let rendered = state
        .templates
        .render("user/index.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Html(rendered)
}

async fn login_page(
    State(_state): State<AppState>,
    cookies: Cookies,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let cfg = config::AppConfig::get();

    // OAuth 配置缺失时给出明确错误，避免跳转到无效 URL
    if cfg.linuxdo_oauth.client_id.is_empty() {
        tracing::error!("LINUXDO_CLIENT_ID is not configured — OAuth login unavailable");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "服务器未配置 LinuxDo OAuth Client ID，请在 .env 中设置 LINUXDO_CLIENT_ID",
        )
            .into_response();
    }
    if cfg.linuxdo_oauth.redirect_uri.is_empty() {
        tracing::error!("redirect_uri is empty — check PLATFORM_DOMAIN or LINUXDO_REDIRECT_URI");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "服务器未配置 OAuth redirect_uri，请在 .env 中设置 PLATFORM_DOMAIN 或 LINUXDO_REDIRECT_URI",
        )
            .into_response();
    }

    // 检查是否需要邀请码：如果 require_invite=true 且 URL 和 cookie 都没有邀请码，显示邀请码输入页面
    let require_invite = db::get_config("require_invite")
        .await
        .unwrap_or_default()
        .parse::<bool>()
        .unwrap_or(false);

    let has_invite_from_url = params
        .get("invite_code")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let has_invite_from_cookie = cookies
        .get("invite_code")
        .map(|c| !c.value().trim().is_empty())
        .unwrap_or(false);

    if require_invite && !has_invite_from_url && !has_invite_from_cookie {
        let error_msg = params.get("error").cloned().unwrap_or_default();
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>输入邀请码</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body {{ background: #f8f9fa; }}
        .invite-card {{ max-width: 420px; margin: 80px auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card shadow invite-card">
            <div class="card-body p-5">
                <h3 class="card-title text-center mb-4">需要邀请码</h3>
                <p class="text-muted text-center mb-4">请输入邀请码后继续登录</p>
                {}
                <form method="post" action="/invite">
                    <div class="mb-3">
                        <label for="invite_code" class="form-label">邀请码</label>
                        <input type="text" class="form-control form-control-lg" id="invite_code" name="invite_code" placeholder="请输入邀请码" required autocomplete="off">
                    </div>
                    <button type="submit" class="btn btn-primary w-100 btn-lg">继续登录</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"#,
            if !error_msg.is_empty() {
                format!(
                    r#"<div class="alert alert-danger" role="alert">{}</div>"#,
                    match error_msg.as_str() {
                        "invalid_invite" => "邀请码无效或已被使用",
                        _ => "请输入有效的邀请码",
                    }
                )
            } else {
                String::new()
            }
        );
        return axum::response::Html(html).into_response();
    }

    let (oauth_url, state_value) = services::auth::create_oauth_url(cfg);

    // state cookie: 用于 CSRF 校验，包含 HMAC-SHA256 签名
    let mut state_cookie = Cookie::new("oauth_state", state_value);
    state_cookie.set_path("/");
    state_cookie.set_max_age(cookie::time::Duration::minutes(10));
    state_cookie.set_http_only(true);
    state_cookie.set_same_site(SameSite::Lax);
    cookies.add(state_cookie);

    // invite_code cookie: 如果用户通过 /login?invite_code=xxx 访问，
    // 保存邀请码到 cookie 以便在 OAuth 回调时使用（LinuxDo 不会回传 invite_code）
    if let Some(invite_code) = params.get("invite_code") {
        if !invite_code.is_empty() {
            let mut invite_cookie = Cookie::new("invite_code", invite_code.clone());
            invite_cookie.set_path("/");
            invite_cookie.set_max_age(cookie::time::Duration::minutes(10));
            invite_cookie.set_http_only(true);
            invite_cookie.set_same_site(SameSite::Lax);
            cookies.add(invite_cookie);
        }
    }

    Redirect::to(&oauth_url).into_response()
}

async fn invite_submit(
    cookies: Cookies,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let invite_code = form
        .get("invite_code")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    if invite_code.is_empty() {
        return Redirect::to("/login?error=invalid_invite").into_response();
    }

    // 快速校验：检查邀请码是否存在且未被使用
    let invite_exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM invites WHERE code = ? AND is_used = 0",
    )
    .bind(&invite_code)
    .fetch_optional(db::get_db())
    .await
    .unwrap_or(None);

    if invite_exists.is_none() {
        return Redirect::to("/login?error=invalid_invite").into_response();
    }

    // 保存邀请码到 cookie
    let mut invite_cookie = Cookie::new("invite_code", invite_code);
    invite_cookie.set_path("/");
    invite_cookie.set_max_age(cookie::time::Duration::minutes(10));
    invite_cookie.set_http_only(true);
    invite_cookie.set_same_site(SameSite::Lax);
    cookies.add(invite_cookie);

    Redirect::to("/login").into_response()
}

async fn auth_callback(
    State(_state): State<AppState>,
    cookies: Cookies,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let cfg = config::AppConfig::get();

    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => return Redirect::to("/").into_response(),
    };

    // 双重校验：
    // 1) 验证 cookie 中的 state 与回调参数中的 state 一致（防 CSRF）
    // 2) 使用 HMAC-SHA256 签名验证 state 的完整性和有效期（防篡改/重放）
    let cookie_state = cookies.get("oauth_state").map(|c| c.value().to_string());
    if let Some(expected_state) = cookie_state {
        if let Some(incoming_state) = params.get("state") {
            if incoming_state != &expected_state {
                tracing::warn!("OAuth state mismatch — possible CSRF");
                return Redirect::to("/").into_response();
            }
            if !services::auth::verify_state(incoming_state) {
                tracing::warn!("OAuth state signature invalid or expired — possible tampering");
                return Redirect::to("/").into_response();
            }
        } else {
            tracing::warn!("OAuth callback missing state parameter");
            return Redirect::to("/").into_response();
        }
    } else {
        // 没有 cookie state，仍然尝试自验证签名（允许非严格模式）
        if let Some(incoming_state) = params.get("state") {
            if !services::auth::verify_state(incoming_state) {
                tracing::warn!("OAuth state signature invalid or expired");
                return Redirect::to("/").into_response();
            }
        }
    }

    // Exchange code for token
    let token_response = match services::auth::exchange_code_for_token(cfg, &code).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Token exchange failed: {}", e);
            return Redirect::to("/").into_response();
        }
    };

    // Get user info
    let user_info = match services::auth::get_user_info(cfg, &token_response.access_token).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Get user info failed: {}", e);
            return Redirect::to("/").into_response();
        }
    };

    // Upsert user in database
    let pool = db::get_db();
    let existing: Option<(i64, bool, f64)> = sqlx::query_as(
        "SELECT id, is_admin, core_hours FROM users WHERE linuxdo_id = ?",
    )
    .bind(user_info.id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let user_id: i64;
    let is_admin: bool;
    let core_hours: f64;

    if let Some((uid, admin, ch)) = existing {
        user_id = uid;
        is_admin = admin;
        core_hours = ch;
    } else {
        // Check registration enabled
        let reg_enabled = db::get_config("registration_enabled").await
            .map(|v| v == "true")
            .unwrap_or(true);
        if !reg_enabled {
            return Redirect::to("/?error=registration_closed").into_response();
        }

        // Check invite requirement
        let require_invite = db::get_config("require_invite").await
            .map(|v| v == "true")
            .unwrap_or(false);

        let new_user_core_hours: f64 = db::get_config("new_user_core_hours").await
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0);

        // 需要邀请码时：先验证，保存 invite_id，用户创建后再标记使用人
        let mut pending_invite_id: Option<i64> = None;
        if require_invite {
            // 从 cookie 读取 invite_code（在 /login?invite_code=xxx 时保存）
            // 注意：LinuxDo OAuth 回调只会带 code 和 state，不会回传 invite_code
            let invite_code = cookies
                .get("invite_code")
                .map(|c| c.value().to_string())
                .unwrap_or_default();
            if invite_code.is_empty() {
                return Redirect::to("/?error=invite_required").into_response();
            }
            // 验证邀请码是否存在且未使用
            let invite_valid: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM invites WHERE code = ? AND is_used = 0",
            )
            .bind(&invite_code)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match invite_valid {
                Some(invite_id) => {
                    // 先标记为已使用（防止并发重复使用），used_by 稍后在用户创建后回填
                    let _ = sqlx::query(
                        "UPDATE invites SET is_used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?",
                    )
                    .bind(invite_id)
                    .execute(pool)
                    .await;
                    pending_invite_id = Some(invite_id);
                }
                None => {
                    let public_note: Option<String> = sqlx::query_scalar(
                        "SELECT public_note FROM invites WHERE code = ?",
                    )
                    .bind(&invite_code)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or(None)
                    .flatten();
                    if let Some(note) = public_note {
                        if !note.is_empty() {
                            return Redirect::to(&format!(
                                "/?error=invalid_invite&note={}",
                                urlencoding::encode(&note)
                            ))
                            .into_response();
                        }
                    }
                    return Redirect::to("/?error=invalid_invite").into_response();
                }
            }
        }

        sqlx::query(
            "INSERT INTO users (linuxdo_id, username, email, core_hours, is_admin) VALUES (?, ?, ?, ?, 0)",
        )
        .bind(user_info.id)
        .bind(user_info.effective_name())
        .bind(user_info.effective_email())
        .bind(new_user_core_hours)
        .execute(pool)
        .await
        .map_err(|e| tracing::error!("Failed to create user: {}", e))
        .ok();

        let new_user: (i64, bool, f64) = sqlx::query_as(
            "SELECT id, is_admin, core_hours FROM users WHERE linuxdo_id = ?",
        )
        .bind(user_info.id)
        .fetch_one(pool)
        .await
        .unwrap_or((0, false, 0.0));

        // 如果有待处理的邀请码，现在回填使用人
        if let Some(invite_id) = pending_invite_id {
            let _ = sqlx::query("UPDATE invites SET used_by = ? WHERE id = ?")
                .bind(new_user.0)
                .bind(invite_id)
                .execute(pool)
                .await;
        }

        user_id = new_user.0;
        is_admin = new_user.1;
        core_hours = new_user.2;
    }

    handlers::set_session_cookie_wrapper(
        &cookies,
        user_id,
        &user_info.effective_name(),
        is_admin,
        core_hours,
    );

    // 清除 state 和 invite_code cookie
    let mut state_cookie = Cookie::new("oauth_state", "");
    state_cookie.set_path("/");
    state_cookie.set_max_age(cookie::time::Duration::seconds(0));
    cookies.add(state_cookie);

    let mut invite_cookie = Cookie::new("invite_code", "");
    invite_cookie.set_path("/");
    invite_cookie.set_max_age(cookie::time::Duration::seconds(0));
    cookies.add(invite_cookie);

    Redirect::to("/").into_response()
}