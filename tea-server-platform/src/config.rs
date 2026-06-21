use serde::Deserialize;
use std::sync::OnceLock;

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub bind_addr: String,
    pub session_secret: String,
    pub linuxdo_oauth: LinuxDoOAuthConfig,
    pub admin_username: String,
    pub admin_password: String,
    pub platform_domain: String,
    pub ssh_proxy_port_start: u16,
    pub ssh_proxy_port_count: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LinuxDoOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub redirect_uri: String,
}

impl Default for LinuxDoOAuthConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_url: String::from("https://connect.linux.do/oauth2/authorize"),
            token_url: String::from("https://connect.linux.do/oauth2/token"),
            user_info_url: String::from("https://connect.linux.do/api/user"),
            redirect_uri: String::new(), // 由 AppConfig 从 platform_domain 派生
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: String::from("sqlite:tea_platform.db?mode=rwc"),
            bind_addr: String::from("0.0.0.0:3000"),
            session_secret: String::from("change-me-in-production-super-secret-key"),
            linuxdo_oauth: LinuxDoOAuthConfig::default(),
            admin_username: String::from("admin"),
            admin_password: String::from("admin"),
            platform_domain: String::from("http://localhost:3000"),
            ssh_proxy_port_start: 22000,
            ssh_proxy_port_count: 100,
        }
    }
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<&'static AppConfig> {
        dotenvy::dotenv().ok();

        // 先读 platform_domain — redirect_uri 需要基于它
        let platform_domain = std::env::var("PLATFORM_DOMAIN")
            .unwrap_or_else(|_| AppConfig::default().platform_domain);

        // redirect_uri: 优先从 LINUXDO_REDIRECT_URI 环境变量，
        // 否则从 platform_domain 派生: {platform_domain}/auth/callback
        let redirect_uri = std::env::var("LINUXDO_REDIRECT_URI")
            .unwrap_or_else(|_| format!("{}/auth/callback", platform_domain.trim_end_matches('/')));

        let cfg = AppConfig {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| AppConfig::default().database_url),
            bind_addr: std::env::var("BIND_ADDR")
                .unwrap_or_else(|_| AppConfig::default().bind_addr),
            session_secret: std::env::var("SESSION_SECRET")
                .unwrap_or_else(|_| AppConfig::default().session_secret),
            linuxdo_oauth: LinuxDoOAuthConfig {
                client_id: std::env::var("LINUXDO_CLIENT_ID")
                    .unwrap_or_default(),
                client_secret: std::env::var("LINUXDO_CLIENT_SECRET")
                    .unwrap_or_default(),
                auth_url: std::env::var("LINUXDO_AUTH_URL")
                    .unwrap_or_else(|_| LinuxDoOAuthConfig::default().auth_url),
                token_url: std::env::var("LINUXDO_TOKEN_URL")
                    .unwrap_or_else(|_| LinuxDoOAuthConfig::default().token_url),
                user_info_url: std::env::var("LINUXDO_USER_INFO_URL")
                    .unwrap_or_else(|_| LinuxDoOAuthConfig::default().user_info_url),
                redirect_uri,
            },
            admin_username: std::env::var("ADMIN_USERNAME")
                .unwrap_or_else(|_| AppConfig::default().admin_username),
            admin_password: std::env::var("ADMIN_PASSWORD")
                .unwrap_or_else(|_| AppConfig::default().admin_password),
            platform_domain,
            ssh_proxy_port_start: std::env::var("SSH_PROXY_PORT_START")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(AppConfig::default().ssh_proxy_port_start),
            ssh_proxy_port_count: std::env::var("SSH_PROXY_PORT_COUNT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
        };

        CONFIG
            .set(cfg)
            .map_err(|_| anyhow::anyhow!("CONFIG already initialized"))?;
        Ok(CONFIG.get().unwrap())
    }

    pub fn get() -> &'static AppConfig {
        CONFIG.get().expect("AppConfig not initialized. Call from_env() first.")
    }
}
