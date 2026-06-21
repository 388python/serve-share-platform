use crate::config::AppConfig;
use axum::{
    extract::{Form, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_cookies::Cookies;

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxDoTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxDoUserInfo {
    pub id: i64,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub trust_level: Option<i32>,
    pub admin: Option<bool>,
}

impl LinuxDoUserInfo {
    pub fn effective_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.username)
    }

    pub fn effective_email(&self) -> String {
        self.email
            .clone()
            .unwrap_or_else(|| format!("{}@linux.do", self.username))
    }
}

pub fn create_oauth_url(config: &AppConfig) -> String {
    format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope=read",
        config.linuxdo_oauth.auth_url,
        config.linuxdo_oauth.client_id,
        config.linuxdo_oauth.redirect_uri,
    )
}

pub async fn exchange_code_for_token(
    config: &AppConfig,
    code: &str,
) -> anyhow::Result<LinuxDoTokenResponse> {
    let client = Client::new();
    let resp = client
        .post(&config.linuxdo_oauth.token_url)
        .form(&[
            ("client_id", config.linuxdo_oauth.client_id.as_str()),
            ("client_secret", config.linuxdo_oauth.client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", config.linuxdo_oauth.redirect_uri.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<LinuxDoTokenResponse>()
        .await?;
    Ok(resp)
}

pub async fn get_user_info(
    config: &AppConfig,
    access_token: &str,
) -> anyhow::Result<LinuxDoUserInfo> {
    let client = Client::new();
    let resp = client
        .get(&config.linuxdo_oauth.user_info_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json::<LinuxDoUserInfo>()
        .await?;
    Ok(resp)
}

#[derive(Deserialize)]
pub struct OAuthAuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub response_type: Option<String>,
}

#[derive(Deserialize)]
pub struct OAuthTokenForm {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: String,
}

/// OAuth authorization endpoint - requires user confirmation
/// User must be logged in to authorize
pub async fn oauth_authorize(cookies: Cookies, Query(q): Query<OAuthAuthorizeQuery>) -> Response {
    if q.response_type.as_deref().unwrap_or("code") != "code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_response_type"})),
        )
            .into_response();
    }

    let session = match crate::services::session::get_session_checked(&cookies) {
        Some(session) => session,
        None => return Redirect::to("/login").into_response(),
    };

    let pool = crate::db::get_db();

    // Verify the app exists and is active
    let app: Option<(String, String)> = sqlx::query_as(
        "SELECT client_id, redirect_uri FROM oauth_apps WHERE client_id = ? AND is_active = 1",
    )
    .bind(&q.client_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (client_id, registered_uri) = match app {
        Some(app) => app,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_client"})),
            )
                .into_response();
        }
    };

    // CRITICAL: Verify redirect_uri matches exactly to prevent redirect attacks
    if !url_matches(&q.redirect_uri, &registered_uri) {
        tracing::warn!(
            "OAuth redirect_uri mismatch: expected={}, got={}",
            registered_uri,
            q.redirect_uri
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "redirect_uri_mismatch"})),
        )
            .into_response();
    }

    let mut redirect_url = match url::Url::parse(&q.redirect_uri) {
        Ok(url) => url,
        Err(err) => {
            tracing::warn!("OAuth redirect_uri parse failed: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_redirect_uri"})),
            )
                .into_response();
        }
    };

    // Generate auth code with expiration (5 minutes)
    let code = format!("auth_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    // Store auth code for later token exchange verification
    if let Err(err) = sqlx::query(
        "INSERT INTO oauth_codes (code, client_id, redirect_uri, user_id, expires_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&code)
    .bind(&client_id)
    .bind(&q.redirect_uri)
    .bind(session.user_id)
    .bind(expires_at)
    .execute(pool)
    .await
    {
        tracing::error!("OAuth authorize: failed to store auth code: {}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "server_error"})),
        )
            .into_response();
    }

    redirect_url.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = &q.state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }
    Redirect::to(redirect_url.as_str()).into_response()
}

/// OAuth token endpoint - exchanges a one-time authorization code for a Bearer API key.
pub async fn oauth_token(Form(form): Form<OAuthTokenForm>) -> Response {
    if form.grant_type != "authorization_code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type"})),
        )
            .into_response();
    }

    let pool = crate::db::get_db();
    let app_redirect_uri: Option<String> = sqlx::query_scalar(
        "SELECT redirect_uri FROM oauth_apps WHERE client_id = ? AND client_secret = ? AND is_active = 1",
    )
    .bind(&form.client_id)
    .bind(&form.client_secret)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let Some(app_redirect_uri) = app_redirect_uri else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    };

    if !url_matches(&form.redirect_uri, &app_redirect_uri) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "redirect_uri_mismatch"})),
        )
            .into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!("OAuth token: failed to begin transaction: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response();
        }
    };

    let code_row: Option<(i64, Option<i64>, String, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, user_id, redirect_uri, expires_at FROM oauth_codes WHERE code = ? AND client_id = ?",
        )
        .bind(&form.code)
        .bind(&form.client_id)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or(None);

    let (code_id, user_id, code_redirect_uri, expires_at) = match code_row {
        Some((code_id, Some(user_id), redirect_uri, expires_at)) => {
            (code_id, user_id, redirect_uri, expires_at)
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
    };

    if code_redirect_uri != form.redirect_uri || expires_at <= chrono::Utc::now() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }

    let deleted = match sqlx::query("DELETE FROM oauth_codes WHERE id = ?")
        .bind(code_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => true,
        Ok(_) => false,
        Err(err) => {
            tracing::error!("OAuth token: failed to delete auth code: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response();
        }
    };

    if !deleted {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }

    let access_token: Option<String> = sqlx::query_scalar("SELECT api_key FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or(None)
        .filter(|key: &String| !key.is_empty());

    let access_token = match access_token {
        Some(key) => key,
        None => {
            let new_key = format!("usr_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
            if let Err(err) = sqlx::query("UPDATE users SET api_key = ? WHERE id = ?")
                .bind(&new_key)
                .bind(user_id)
                .execute(&mut *tx)
                .await
            {
                tracing::error!("OAuth token: failed to persist user API key: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "server_error"})),
                )
                    .into_response();
            }
            new_key
        }
    };

    if let Err(err) = tx.commit().await {
        tracing::error!("OAuth token: failed to commit transaction: {}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "server_error"})),
        )
            .into_response();
    }

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": "read"
    }))
    .into_response()
}

/// Check if URLs match for security (prevents redirect_uri manipulation)
fn url_matches(redirect: &str, registered: &str) -> bool {
    redirect == registered
}
