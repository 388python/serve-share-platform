use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub linuxdo_client_id: String,
    pub linuxdo_client_secret: String,
    pub linuxdo_redirect_uri: String,
    pub admin_username: String,
    pub admin_password_hash: String,
    pub secret_key: String,
    pub site_name: String,
    pub host: String,
    pub port: u16,
    pub ldc_api_base: String,
    pub ldc_pid: String,
    pub ldc_key: String,
    pub ldc_client_id: String,
    pub ldc_client_secret: String,
    pub ldc_ed25519_private_key: String,
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:data.db".to_string()),
            linuxdo_client_id: env::var("LINUXDO_CLIENT_ID")
                .unwrap_or_default(),
            linuxdo_client_secret: env::var("LINUXDO_CLIENT_SECRET")
                .unwrap_or_default(),
            linuxdo_redirect_uri: env::var("LINUXDO_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/callback".to_string()),
            admin_username: env::var("ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            admin_password_hash: env::var("ADMIN_PASSWORD_HASH")
                .unwrap_or_default(),
            secret_key: env::var("SECRET_KEY")
                .unwrap_or_else(|_| "change_me_to_random_string".to_string()),
            site_name: env::var("SITE_NAME")
                .unwrap_or_else(|_| "茶的服务器公益站".to_string()),
            host: env::var("HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            ldc_api_base: env::var("LDC_API_BASE")
                .unwrap_or_else(|_| "https://credit.linux.do".to_string()),
            ldc_pid: env::var("LDC_PID").unwrap_or_default(),
            ldc_key: env::var("LDC_KEY").unwrap_or_default(),
            ldc_client_id: env::var("LDC_CLIENT_ID").unwrap_or_default(),
            ldc_client_secret: env::var("LDC_CLIENT_SECRET").unwrap_or_default(),
            ldc_ed25519_private_key: env::var("LDC_ED25519_PRIVATE_KEY")
                .unwrap_or_default(),
        }
    }
}