use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tera::{Context, Tera};
use tower_cookies::{cookie::time::Duration, Cookie, CookieManagerLayer, Cookies};
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
    tracing_subscriber::fmt::init();

    // Load config
    config::AppConfig::from_env()?;
    let cfg = config::AppConfig::get();

    // Record startup time for health endpoint
    handlers::api::set_startup_time(chrono::Utc::now());

    // Init database
    db::init_db(&cfg.database_url).await?;

    // Init Tera templates
    let mut tera = Tera::new("templates/**/*")?;
    tera.autoescape_on(vec!["html", ".tera"]);
    let app_state = AppState {
        templates: Arc::new(tera),
    };

    // Background task: stop expired machines every 60 seconds
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();

            // Get expired machines
            let expired: Vec<(i64, i64)> = sqlx::query_as(
                "SELECT id, server_id FROM machines WHERE status = 'running' AND expires_at < ?",
            )
            .bind(now)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            for (machine_id, server_id) in &expired {
                let _ = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
                    .bind(machine_id)
                    .execute(pool)
                    .await;

                // Call agent to stop VM
                let server: Option<(String,)> = sqlx::query_as(
                    "SELECT ip FROM servers WHERE id = ?",
                )
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

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
                        Ok((mut incoming, _addr)) => {
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
                                if let Ok(mut outgoing) = tokio::net::TcpStream::connect(&target).await {
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
            let machines: Vec<(i64, String)> = sqlx::query_as(
                "SELECT m.id, s.ip FROM machines m JOIN servers s ON m.server_id = s.id WHERE m.status = 'running'"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();
            
            for (machine_id, server_ip) in &machines {
                let alerts = services::traffic_monitor::scan_machine_traffic(*machine_id, server_ip).await;
                for alert_msg in &alerts {
                    tracing::warn!("Traffic alert for machine {}: {}", machine_id, alert_msg);
                    let _ = sqlx::query(
                        "INSERT INTO traffic_alerts (machine_id, alert_type, message) VALUES (?, 'traffic_violation', ?)"
                    )
                    .bind(machine_id)
                    .bind(alert_msg)
                    .execute(pool)
                    .await;
                    // Stop the machine
                    let _ = sqlx::query("UPDATE machines SET status = 'stopped' WHERE id = ?")
                        .bind(machine_id)
                        .execute(pool)
                        .await;
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
            let machines: Vec<(i64, i64, f64, f64)> = sqlx::query_as(
                "SELECT m.id, m.server_id, m.core_hours_per_hour, m.used_hours FROM machines m WHERE m.status IN ('stopped','deleted') AND m.settled = 0"
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            for (machine_id, server_id, ch_per_hour, used_hours) in &machines {
                // Get server expiry
                let server_expiry: Option<(String,)> = sqlx::query_as(
                    "SELECT expires_at FROM servers WHERE id = ?"
                )
                .bind(server_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);

                if let Some((expires_at_str,)) = server_expiry {
                    if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(&expires_at_str) {
                        let max_hours = (expires_at.naive_utc() - chrono::Utc::now().naive_utc()).num_hours() as f64;
                        if max_hours > 0.0 && used_hours / max_hours >= threshold {
                            // Settle: credit core hours to server owner
                            let total_ch = ch_per_hour * used_hours;
                            let _ = sqlx::query(
                                "UPDATE users SET core_hours = core_hours + ? WHERE id = (SELECT owner_id FROM servers WHERE id = ?)"
                            )
                            .bind(total_ch)
                            .bind(server_id)
                            .execute(pool)
                            .await;
                            let _ = sqlx::query("UPDATE machines SET settled = 1 WHERE id = ?")
                                .bind(machine_id)
                                .execute(pool)
                                .await;
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
            let _ = sqlx::query(
                "UPDATE disputes SET status = 'platform' WHERE status = 'pending' AND auto_resolve_at <= ?"
            )
            .bind(now)
            .execute(pool)
            .await;
        }
    });

    // Background task: Clean expired bonus
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();
            let _ = sqlx::query(
                "UPDATE users SET bonus_core_hours = 0, bonus_expires_at = NULL WHERE bonus_expires_at IS NOT NULL AND bonus_expires_at <= ?"
            )
            .bind(now)
            .execute(pool)
            .await;
        }
    });

    // Background task: Expire premium on servers
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let pool = db::get_db();
            let now = chrono::Utc::now();
            let _ = sqlx::query(
                "UPDATE servers SET is_premium = 0, premium_expires_at = NULL WHERE is_premium = 1 AND premium_expires_at IS NOT NULL AND premium_expires_at <= ?"
            )
            .bind(now)
            .execute(pool)
            .await;
        }
    });

    // Build router
    let app = Router::new()
        // Public routes
        .route("/", get(index_page))
        .route("/health", get(handlers::health_check))
        .route("/stats", get(handlers::stats_page))
        .route("/login", get(login_page))
        .route("/auth/callback", get(auth_callback))
        .route("/admin-login", get(handlers::admin_login))
        .route("/logout", get(handlers::logout))
        // User dashboard
        .route("/dashboard", get(handlers::user_dashboard))
        .route("/dashboard/api-key", post(handlers::regenerate_api_key))
        // Server contribution
        .route("/servers/contribute", get(handlers::contribute_server_page))
        .route("/servers/contribute", post(handlers::contribute_server_submit))
        .route("/servers/:id/delete", post(handlers::delete_server))
        .route("/servers/:id/buy-premium", post(handlers::buy_premium))
        // Machine market / auto select
        .route("/market", get(handlers::machine_market))
        .route("/machines/auto", get(handlers::auto_select_machine))
        .route("/machines/create", post(handlers::create_machine))
        .route("/machines", get(handlers::my_machines))
        .route("/machines/:id/stop", post(handlers::stop_machine))
        .route("/machines/:id/delete", post(handlers::delete_machine))
        .route("/machines/:id/connect", get(handlers::machine_connect))
        // Disputes
        .route("/disputes/new", get(handlers::dispute_new_page))
        .route("/disputes/create", post(handlers::dispute_create))
        .route("/disputes/:id/reply", post(handlers::merchant_dispute_reply))
        // Recharge
        .route("/recharge", get(handlers::recharge_page))
        .route("/recharge", post(handlers::create_recharge_order))
        .route("/recharge/callback", get(handlers::recharge_callback))
        // Withdraw
        .route("/withdraw", get(handlers::withdraw_page))
        .route("/withdraw", post(handlers::withdraw_submit))
        // Checkin
        .route("/checkin", post(handlers::checkin))
        // Free plan
        .route("/free-plan", post(handlers::free_plan))
        // Redeem
        .route("/redeem", get(handlers::redeem_page))
        .route("/redeem", post(handlers::redeem_submit))
        // Packages
        .route("/packages", get(handlers::packages_page))
        .route("/packages/buy", post(handlers::buy_package))
        // Balance to code
        .route("/balance-to-code", get(handlers::balance_to_code_page))
        .route("/balance-to-code", post(handlers::balance_to_code_submit))
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
        .route("/admin/machines", get(handlers::admin_machines))
        .route("/admin/packages", get(handlers::admin_packages))
        .route("/admin/packages/create", post(handlers::admin_package_create))
        .route("/admin/packages/:id/delete", post(handlers::admin_package_delete))
        .route("/admin/codes", get(handlers::admin_generate_codes))
        .route("/admin/codes/generate", post(handlers::admin_generate_codes_submit))
        .route("/admin/invites", get(handlers::admin_invites))
        .route("/admin/invites/generate", post(handlers::admin_generate_invites))
        .route("/admin/orders", get(handlers::admin_orders))
        .route("/admin/traffic-alerts", get(handlers::admin_traffic_alerts))
        .route("/admin/disputes", get(handlers::admin_disputes))
        .route("/admin/disputes/:id/resolve", post(handlers::admin_dispute_resolve))
        .route("/admin/oauth-apps", get(handlers::admin_oauth_apps))
        .route("/admin/oauth-apps", post(handlers::admin_oauth_apps_create))
        // API routes (RESTful JSON) - mounted under /api prefix
        .nest("/api", handlers::api::router(app_state.clone()))
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        .layer(CookieManagerLayer::new())
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("Server listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;

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

    // Try to read user session from cookie
    if let Some(session_cookie) = cookies.get("session") {
        let session_value = session_cookie.value().to_string();
        if let Ok(session) = handlers::parse_session(&session_value) {
            ctx.insert(
                "user_name",
                &session.get("username").unwrap_or(&String::new()),
            );
            ctx.insert(
                "user_balance",
                &session.get("core_hours").unwrap_or(&"0".to_string()),
            );
            ctx.insert(
                "user_ldc",
                &session.get("ldc_balance").unwrap_or(&"0".to_string()),
            );
            ctx.insert(
                "is_admin",
                &session.get("is_admin").unwrap_or(&"false".to_string()),
            );
        }
    }

    let rendered = state
        .templates
        .render("user/index.html", &ctx)
        .unwrap_or_else(|e| e.to_string());
    Html(rendered)
}

async fn login_page(State(_state): State<AppState>) -> impl IntoResponse {
    let cfg = config::AppConfig::get();
    let oauth_url = services::auth::create_oauth_url(cfg);
    Redirect::to(&oauth_url)
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
    let existing: Option<(i64, bool, f64, f64)> = sqlx::query_as(
        "SELECT id, is_admin, core_hours, ldc_balance FROM users WHERE linuxdo_id = ?",
    )
    .bind(user_info.id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let user_id: i64;
    let is_admin: bool;
    let core_hours: f64;
    let ldc_balance: f64;

    if let Some((uid, admin, ch, ldc)) = existing {
        user_id = uid;
        is_admin = admin;
        core_hours = ch;
        ldc_balance = ldc;
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

        if require_invite {
            let invite_code = params.get("invite_code").cloned().unwrap_or_default();
            if invite_code.is_empty() {
                return Redirect::to("/?error=invite_required").into_response();
            }
            // Verify and consume invite code
            let invite_valid: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM invites WHERE code = ? AND is_used = 0",
            )
            .bind(&invite_code)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            match invite_valid {
                Some(invite_id) => {
                    sqlx::query("UPDATE invites SET is_used = 1, used_by = (SELECT id FROM users WHERE linuxdo_id = ? LIMIT 1), used_at = CURRENT_TIMESTAMP WHERE id = ?")
                        .bind(user_info.id)
                        .bind(invite_id)
                        .execute(pool)
                        .await
                        .ok();
                }
                None => {
                    let public_note: Option<String> = sqlx::query_scalar(
                        "SELECT public_note FROM invites WHERE code = ?"
                    )
                    .bind(&invite_code)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or(None)
                    .flatten();
                    if let Some(note) = public_note {
                        if !note.is_empty() {
                            return Redirect::to(&format!("/?error=invalid_invite&note={}", urlencoding::encode(&note))).into_response();
                        }
                    }
                    return Redirect::to("/?error=invalid_invite").into_response();
                }
            }
        }

        sqlx::query(
            "INSERT INTO users (linuxdo_id, username, email, ldc_balance, core_hours, is_admin) VALUES (?, ?, ?, 0, ?, 0)",
        )
        .bind(user_info.id)
        .bind(user_info.effective_name())
        .bind(user_info.effective_email())
        .bind(new_user_core_hours)
        .execute(pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to create user: {}", e);
            panic!("User creation failed");
        });

        let new_user: (i64, bool, f64, f64) = sqlx::query_as(
            "SELECT id, is_admin, core_hours, ldc_balance FROM users WHERE linuxdo_id = ?",
        )
        .bind(user_info.id)
        .fetch_one(pool)
        .await
        .unwrap_or((0, false, 0.0, 0.0));

        user_id = new_user.0;
        is_admin = new_user.1;
        core_hours = new_user.2;
        ldc_balance = new_user.3;
    }

    // Create session cookie
    let session_data = format!(
        "user_id={}|username={}|is_admin={}|core_hours={}|ldc_balance={}",
        user_id,
        user_info.effective_name(),
        is_admin,
        core_hours,
        ldc_balance,
    );

    let mut cookie = Cookie::new("session", session_data);
    cookie.set_path("/");
    cookie.set_max_age(Duration::hours(24));
    cookie.set_http_only(true);
    cookies.add(cookie);

    Redirect::to("/").into_response()
}