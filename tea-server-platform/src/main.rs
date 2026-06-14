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
            let _ = sqlx::query(
                "UPDATE machines SET status = 'stopped' WHERE status = 'running' AND expires_at < ?",
            )
            .bind(now)
            .execute(pool)
            .await;
            tracing::debug!("Expired machine cleanup completed");
        }
    });

    // Build router
    let app = Router::new()
        // Public routes
        .route("/", get(index_page))
        .route("/health", get(handlers::health_check))
        .route("/login", get(login_page))
        .route("/auth/callback", get(auth_callback))
        .route("/admin-login", get(handlers::admin_login))
        .route("/logout", get(handlers::logout))
        // User dashboard
        .route("/dashboard", get(handlers::user_dashboard))
        // Server contribution
        .route("/servers/contribute", get(handlers::contribute_server_page))
        .route("/servers/contribute", post(handlers::contribute_server_submit))
        .route("/servers/:id/delete", post(handlers::delete_server))
        // Machine market / auto select
        .route("/market", get(handlers::machine_market))
        .route("/machines/auto", get(handlers::auto_select_machine))
        .route("/machines/create", post(handlers::create_machine))
        .route("/machines", get(handlers::my_machines))
        .route("/machines/:id/stop", post(handlers::stop_machine))
        .route("/machines/:id/delete", post(handlers::delete_machine))
        .route("/machines/:id/connect", get(handlers::machine_connect))
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
        sqlx::query(
            "INSERT INTO users (linuxdo_id, username, email, ldc_balance, core_hours, is_admin) VALUES (?, ?, ?, 0, 0, 0)",
        )
        .bind(user_info.id)
        .bind(user_info.effective_name())
        .bind(user_info.effective_email())
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