use crate::config::AppConfig;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

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

pub const STATE_TTL_SECS: i64 = 600; // 10 分钟

fn hmac_key() -> Vec<u8> {
    AppConfig::get().session_secret.as_bytes().to_vec()
}

/// HMAC-SHA256 签名，返回 hex 字符串
fn hmac_hex(payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(&hmac_key())
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
    let mut mac = HmacSha256::new_from_slice(&hmac_key())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"default").expect("HMAC init"));
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

/// 生成并签名一个 OAuth state: `timestamp.nonce.sig`
/// 返回一个自包含的、可验证的字符串，无需服务器端存储。
pub fn generate_state() -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = uuid::Uuid::new_v4().to_string().replace('-', "");
    let payload = format!("{}.{}", timestamp, nonce);
    let sig = hmac_hex(payload.as_bytes());
    format!("{}.{}", payload, sig)
}

/// 验证 OAuth state: 必须签名正确且未过期
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
        return false; // 过期或超过 30 秒的未来时间
    }
    let signed_payload = format!("{}.{}", ts_str, parts[1]);
    hmac_verify(signed_payload.as_bytes(), expected_sig)
}

// ---- OAuth URL & Token Exchange ----

/// 生成 OAuth 授权 URL（包含签名 state、URL 编码参数）
/// 返回 (oauth_url, signed_state_value)，签名 state 包含时间戳和 HMAC-SHA256 签名，
/// 可在回调时自验证，避免 CSRF 和 state 篡改。
pub fn create_oauth_url(config: &AppConfig) -> (String, String) {
    let state = generate_state();

    let client_id_enc = urlencoding::encode(&config.linuxdo_oauth.client_id);
    let redirect_uri_enc = urlencoding::encode(&config.linuxdo_oauth.redirect_uri);
    let state_enc = urlencoding::encode(&state);

    let url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&state={}&scope=read",
        config.linuxdo_oauth.auth_url, client_id_enc, redirect_uri_enc, state_enc
    );
    (url, state)
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

use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
};

#[derive(Deserialize)]
pub struct OAuthAuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub response_type: Option<String>,
}

/// 平台作为 OAuth 提供商的静默授权端点
pub async fn oauth_authorize(
    Query(q): Query<OAuthAuthorizeQuery>,
) -> impl IntoResponse {
    let pool = crate::db::get_db();

    let app: Option<(String, String)> = sqlx::query_as(
        "SELECT client_id, redirect_uri FROM oauth_apps WHERE client_id = ? AND is_active = 1",
    )
    .bind(&q.client_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if app.is_none() {
        let encoded = q.state.as_deref().unwrap_or("");
        return Redirect::to(&format!(
            "{}?error=invalid_client&state={}",
            q.redirect_uri, encoded
        ));
    }

    let code = format!("auth_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let encoded_state = q.state.as_deref().unwrap_or("");
    let redirect_url = format!("{}?code={}&state={}", q.redirect_uri, code, encoded_state);
    Redirect::to(&redirect_url)
}
