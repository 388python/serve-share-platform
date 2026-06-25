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
    let key = hmac_key();
    if key.is_empty() || key.len() < 16 {
        tracing::warn!("session_secret is too short or empty — using fallback key (NOT SECURE FOR PRODUCTION)");
    }
    let mut mac = HmacSha256::new_from_slice(&key)
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback-key-not-for-production").expect("HMAC init"));
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
    let key = hmac_key();
    if key.is_empty() || key.len() < 16 {
        tracing::warn!("session_secret is too short or empty — using fallback key (NOT SECURE FOR PRODUCTION)");
    }
    let mut mac = HmacSha256::new_from_slice(&key)
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback-key-not-for-production").expect("HMAC init"));
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

/// 生成 LinuxDo OAuth 授权 URL（包含签名 state、URL 编码参数）
/// 参考标准 OAuth 2.0 顺序：client_id → redirect_uri → response_type → scope → state
/// 返回 (oauth_url, signed_state_value)，签名 state 包含时间戳和 HMAC-SHA256 签名
pub fn create_oauth_url(config: &AppConfig) -> (String, String) {
    let state = generate_state();

    // 校验关键配置
    if config.linuxdo_oauth.client_id.is_empty() {
        tracing::warn!("LINUXDO_CLIENT_ID is empty — OAuth will fail");
    }
    if config.linuxdo_oauth.redirect_uri.is_empty() {
        tracing::warn!("LINUXDO_REDIRECT_URI / PLATFORM_DOMAIN produced empty redirect_uri");
    }

    // URL 编码所有参数值（特别是 redirect_uri 中的 :// 和 / 必须编码）
    let client_id_enc = urlencoding::encode(&config.linuxdo_oauth.client_id).to_string();
    let redirect_uri_enc =
        urlencoding::encode(&config.linuxdo_oauth.redirect_uri).to_string();
    let state_enc = urlencoding::encode(&state).to_string();
    let scope_enc = urlencoding::encode("read").to_string();

    // 按标准 OAuth 顺序组装（与 LinuxDo / Discourse 规范一致）
    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.linuxdo_oauth.auth_url,
        client_id_enc,
        redirect_uri_enc,
        scope_enc,
        state_enc
    );

    tracing::debug!(
        "Generated OAuth URL: {} (redirect_uri raw={})",
        config.linuxdo_oauth.auth_url,
        config.linuxdo_oauth.redirect_uri
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

use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
};

#[derive(Debug, Deserialize)]
pub struct OAuthAuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    #[allow(dead_code)]
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
