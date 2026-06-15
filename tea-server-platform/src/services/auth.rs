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

/// Silent authorization endpoint - no user confirmation
pub async fn oauth_authorize(
    Query(q): Query<OAuthAuthorizeQuery>,
) -> impl IntoResponse {
    let pool = crate::db::get_db();

    // Verify the app
    let app: Option<(String, String)> = sqlx::query_as(
        "SELECT client_id, redirect_uri FROM oauth_apps WHERE client_id = ? AND is_active = 1"
    )
    .bind(&q.client_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if app.is_none() {
        return Redirect::to(&format!("{}?error=invalid_client&state={}",
            q.redirect_uri, q.state.as_deref().unwrap_or("")));
    }

    // Generate a code (in production, this would be a real auth code)
    let code = format!("auth_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    // Redirect back with code
    let mut redirect_url = format!("{}?code={}", q.redirect_uri, code);
    if let Some(state) = &q.state {
        redirect_url = format!("{}&state={}", redirect_url, state);
    }
    Redirect::to(&redirect_url)
}