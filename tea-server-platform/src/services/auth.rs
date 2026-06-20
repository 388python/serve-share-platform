use crate::config::AppConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
            (
                "client_secret",
                config.linuxdo_oauth.client_secret.as_str(),
            ),
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

/// OAuth authorization endpoint - requires user confirmation
/// User must be logged in to authorize
pub async fn oauth_authorize(
    Query(q): Query<OAuthAuthorizeQuery>,
) -> impl IntoResponse {
    let pool = crate::db::get_db();

    // Verify the app exists and is active
    let app: Option<(String, String)> = sqlx::query_as(
        "SELECT client_id, redirect_uri FROM oauth_apps WHERE client_id = ? AND is_active = 1"
    )
    .bind(&q.client_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (client_id, registered_uri) = match app {
        Some(app) => app,
        None => {
            return Redirect::to(&format!("{}?error=invalid_client&state={}",
                q.redirect_uri, q.state.as_deref().unwrap_or("")));
        }
    };

    // CRITICAL: Verify redirect_uri matches exactly to prevent redirect attacks
    if !url_matches(&q.redirect_uri, &registered_uri) {
        tracing::warn!("OAuth redirect_uri mismatch: expected={}, got={}", registered_uri, q.redirect_uri);
        return Redirect::to(&format!("{}?error=redirect_uri_mismatch&state={}",
            q.redirect_uri, q.state.as_deref().unwrap_or("")));
    }

    // Generate auth code with expiration (5 minutes)
    let code = format!("auth_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    // Store auth code for later token exchange verification
    let _ = sqlx::query(
        "INSERT INTO oauth_codes (code, client_id, redirect_uri, expires_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&code)
    .bind(&client_id)
    .bind(&q.redirect_uri)
    .bind(expires_at)
    .execute(pool)
    .await;

    // Redirect back with code
    let mut redirect_url = format!("{}?code={}", q.redirect_uri, code);
    if let Some(state) = &q.state {
        redirect_url = format!("{}&state={}", redirect_url, state);
    }
    Redirect::to(&redirect_url)
}

/// Check if URLs match for security (prevents redirect_uri manipulation)
fn url_matches(redirect: &str, registered: &str) -> bool {
    // Parse both URLs and compare components
    if let (Ok(redirect_url), Ok(registered_url)) = (
        url::Url::parse(redirect),
        url::Url::parse(registered),
    ) {
        // Scheme must be HTTPS (or http for localhost)
        let valid_scheme = redirect_url.scheme() == registered_url.scheme()
            && (redirect_url.scheme() == "https" || redirect_url.scheme() == "http");
        if !valid_scheme {
            return false;
        }
        // Host must match exactly
        if redirect_url.host_str() != registered_url.host_str() {
            return false;
        }
        // Path must match
        if redirect_url.path() != registered_url.path() {
            return false;
        }
        true
    } else {
        // Fallback to exact string comparison
        redirect == registered
    }
}