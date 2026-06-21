use crate::config::AppConfig;
use axum::{
    extract::{Form, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use tower_cookies::Cookies;

type HmacSha256 = Hmac<Sha256>;

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

// ---- OAuth State (Signed) ----
// state 格式：timestamp.nonce.hmac_sha256_signature
// 自包含、可验证，防 CSRF 和重放攻击

pub const STATE_TTL_SECS: i64 = 600; // 10 分钟

fn state_secret_bytes() -> Vec<u8> {
    AppConfig::get().session_secret.as_bytes().to_vec()
}

/// HMAC-SHA256 签名并返回 hex 字符串
fn hmac_hex(payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(&state_secret_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"default").expect("HMAC init"));
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(result.len() * 2);
    use std::fmt::Write;
    for byte in &result[..] {
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// 验证 HMAC-SHA256 签名
fn hmac_verify(payload: &[u8], expected_hex: &str) -> bool {
    let expected = match hex::decode(expected_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if expected.is_empty() {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(&state_secret_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"default").expect("HMAC init"));
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

/// 生成带签名的 OAuth state
pub fn generate_state() -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = uuid::Uuid::new_v4().to_string().replace('-', "");
    let payload = format!("{}.{}", timestamp, nonce);
    let sig = hmac_hex(payload.as_bytes());
    format!("{}.{}", payload, sig)
}

/// 验证 OAuth state：签名必须有效 + 未过期
pub fn verify_state(state: &str) -> bool {
    let parts: Vec<&str> = state.splitn(3, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (ts_str, _nonce, expected_sig) = (parts[0], parts[1], parts[2]);
    let timestamp: i64 = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = chrono::Utc::now().timestamp();
    if now - timestamp > STATE_TTL_SECS || timestamp - now > 30 {
        return false;
    }
    let signed_payload = format!("{}.{}", ts_str, parts[1]);
    hmac_verify(signed_payload.as_bytes(), expected_sig)
}

/// 生成 LinuxDo OAuth 授权 URL
/// 返回 (oauth_url, signed_state_value)
/// 所有参数值都经过 URL 编码，顺序：client_id → redirect_uri → response_type → scope → state
pub fn create_oauth_url(config: &AppConfig) -> (String, String) {
    let state = generate_state();

    // 对每个参数值单独 URL 编码
    let client_id_enc = urlencoding::encode(&config.linuxdo_oauth.client_id).to_string();
    let redirect_uri_enc =
        urlencoding::encode(&config.linuxdo_oauth.redirect_uri).to_string();
    let state_enc = urlencoding::encode(&state).to_string();
    let scope_enc = urlencoding::encode("read").to_string();

    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.linuxdo_oauth.auth_url,
        client_id_enc,
        redirect_uri_enc,
        scope_enc,
        state_enc
    );
    (url, state)
}

pub async fn exchange_code_for_token(
    config: &AppConfig,
    code: &str,
) -> anyhow::Result<LinuxDoTokenResponse> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

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
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("LinuxDo token exchange request failed: {}", e);
            return Err(anyhow::anyhow!("token exchange request failed: {}", e));
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            "LinuxDo token exchange failed: status={}, body={}",
            status,
            body
        );
        return Err(anyhow::anyhow!(
            "token exchange failed (status={}): {}",
            status,
            body
        ));
    }

    let token = resp.json::<LinuxDoTokenResponse>().await.map_err(|e| {
        tracing::error!("LinuxDo token response parse failed: {}", e);
        anyhow::anyhow!("token response parse failed: {}", e)
    })?;
    Ok(token)
}

pub async fn get_user_info(
    config: &AppConfig,
    access_token: &str,
) -> anyhow::Result<LinuxDoUserInfo> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .get(&config.linuxdo_oauth.user_info_url)
        .bearer_auth(access_token)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("LinuxDo user info request failed: {}", e);
            return Err(anyhow::anyhow!("user info request failed: {}", e));
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            "LinuxDo user info failed: status={}, body={}",
            status,
            body
        );
        return Err(anyhow::anyhow!(
            "user info failed (status={}): {}",
            status,
            body
        ));
    }

    let user = resp.json::<LinuxDoUserInfo>().await.map_err(|e| {
        tracing::error!("LinuxDo user info response parse failed: {}", e);
        anyhow::anyhow!("user info response parse failed: {}", e)
    })?;
    Ok(user)
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
