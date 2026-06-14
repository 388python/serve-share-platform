use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::db;
use crate::models::*;
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
// Router builder
// ==============================

pub fn router(_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/me", get(api_me).post(api_me_regenerate_key))
        .route("/v1/me/api-key", post(api_me_regenerate_key))
        .route("/v1/servers", get(api_my_servers))
        .route("/v1/machines", get(api_my_machines))
        .route("/v1/market", get(api_market))
        .route("/v1/orders", get(api_my_orders))
        .route("/v1/packages", get(api_packages))
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
