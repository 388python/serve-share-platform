use axum::{Router, routing::get};
use dotenv::dotenv;
use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use tera::Tera;
use tower_http::services::ServeDir;
use tower_sessions::SessionManagerLayer;
use tower_sessions_sqlx_store::SqliteStore;

mod config;
mod db;
mod models;
mod routes;
mod services;

use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let config = Config::from_env();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    db::create_tables(&pool).await?;

    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("警告: 无法加载模板: {}", e);
            Tera::default()
        }
    };

    let session_store = SqliteStore::new(pool.clone());
    session_store.migrate().await?;
    let session_layer = SessionManagerLayer::new(session_store);

    let app_state = AppState {
        db: pool.clone(),
        tera,
        config: config.clone(),
    };

    let admin_router = Router::new()
        .route("/dashboard", get(routes::admin::dashboard))
        .route("/settings", get(routes::admin::settings_page).post(routes::admin::settings_update))
        .route("/invite-codes", get(routes::admin::invite_codes_page))
        .route("/invite-codes/generate", get(routes::admin::invite_codes_page).post(routes::admin::invite_codes_generate))
        .route("/invite-codes/delete/{id}", get(routes::admin::invite_codes_page).post(routes::admin::invite_codes_delete))
        .route("/codes", get(routes::admin::codes_page))
        .route("/codes/generate", get(routes::admin::codes_page).post(routes::admin::codes_generate))
        .route("/packages", get(routes::admin::packages_page))
        .route("/packages/create", get(routes::admin::packages_page).post(routes::admin::packages_create))
        .route("/packages/edit/{id}", get(routes::admin::packages_page).post(routes::admin::packages_edit))
        .route("/packages/delete/{id}", get(routes::admin::packages_page).post(routes::admin::packages_delete))
        .route("/users", get(routes::admin::users_page))
        .route("/users/ban/{id}", get(routes::admin::users_page).post(routes::admin::users_ban))
        .route("/users/set-admin/{id}", get(routes::admin::users_page).post(routes::admin::users_set_admin))
        .route("/users/adjust-hours", get(routes::admin::users_page).post(routes::admin::users_adjust_hours))
        .route("/servers", get(routes::admin::servers_page))
        .route("/servers/approve/{id}", get(routes::admin::servers_page).post(routes::admin::servers_approve))
        .route("/servers/offline/{id}", get(routes::admin::servers_page).post(routes::admin::servers_offline))
        .route("/vms", get(routes::admin::vms_page))
        .route("/vms/stop/{id}", get(routes::admin::vms_page).post(routes::admin::vms_stop));

    let app = Router::new()
        .route("/", get(routes::index))
        .route("/login", get(routes::auth::login_page))
        .route("/auth/login", get(routes::auth::login))
        .route("/auth/callback", get(routes::auth::callback))
        .route("/auth/logout", get(routes::auth::logout))
        .route("/admin-login", get(routes::admin::admin_login))
        .route("/payment/callback", get(routes::user::handle_payment_callback))
        .nest("/admin", admin_router)
        .nest_service("/static", ServeDir::new("static"))
        .layer(session_layer)
        .with_state(app_state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    println!("🌐 {} 运行在 http://{}", config.site_name, addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub tera: Tera,
    pub config: Config,
}