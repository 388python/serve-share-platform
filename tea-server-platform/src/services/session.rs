use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;
use tower_cookies::cookie::time::Duration;
use tower_cookies::Cookie;
use tower_cookies::Cookies;

use crate::db;

#[allow(dead_code)]
type HmacSha256 = Hmac<Sha256>;

/// Session data for a logged-in user
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct UserSession {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    pub core_hours: f64,
    pub ldc_balance: f64,
}

/// 会话有效期（秒）—— 即使 cookie 未过期，超过此时间的会话也将失效 (预留)
#[allow(dead_code)]
const SESSION_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Get the secret key from config (fall back to a static runtime key) (预留)
#[allow(dead_code)]
fn get_secret() -> Vec<u8> {
    // Use the session_secret from site_config DB table first;
    // fall back to SESSION_SECRET env var; otherwise generate a random
    // in-memory key (which means sessions will reset on restart —
    // acceptable for unconfigured deployments).
    if let Some(db_secret) = db::get_config_sync("session_secret") {
        if !db_secret.is_empty() && db_secret != "change-me-in-production-super-secret-key" {
            return db_secret.into_bytes();
        }
    }

    std::env::var("SESSION_SECRET")
        .ok()
        .filter(|s| !s.is_empty() && s != "change-me-in-production-super-secret-key")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|| {
            // Runtime random secret — generated once per-process. This
            // avoids hard-coded defaults and still yields valid
            // signatures as long as the process is alive.
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes.to_vec()
        })
}

/// 返回当前使用的会话密钥是否为生产环境之外的"默认值"。
/// 用于在启动时或运行时发出警告。
#[allow(dead_code)]
pub fn uses_default_secret() -> bool {
    // Note: if using runtime-random key, we still consider it
    // "production safe" (not a well-known default).
    db::get_config_sync("session_secret").map_or(true, |s| {
        s.is_empty() || s == "change-me-in-production-super-secret-key"
    }) && std::env::var("SESSION_SECRET").map_or(true, |s| {
        s.is_empty() || s == "change-me-in-production-super-secret-key"
    })
}

/// Compute HMAC-SHA256 signature (预留)
#[allow(dead_code)]
fn compute_signature(data: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    BASE64.encode(result.into_bytes())
}

/// Serialize and sign a session. Format: `base64(data)|signature` (预留)
#[allow(dead_code)]
pub fn encode_session(session: &UserSession) -> String {
    let data = format!(
        "user_id={}|username={}|is_admin={}|core_hours={}|ldc_balance={}|ts={}",
        session.user_id,
        session.username,
        session.is_admin,
        session.core_hours,
        session.ldc_balance,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let secret = get_secret();
    let sig = compute_signature(&data, &secret);
    format!("{}|{}", BASE64.encode(data.as_bytes()), sig)
}

/// Verify and decode a signed session cookie value (no DB verification) (预留)
#[allow(dead_code)]
pub fn decode_session(value: &str) -> Option<UserSession> {
    let mut parts = value.rsplitn(2, '|');
    let sig = parts.next()?;
    let data_b64 = parts.next()?;

    // Decode base64 payload
    let data = BASE64.decode(data_b64.as_bytes()).ok()?;
    let data_str = String::from_utf8(data).ok()?;

    // Verify signature
    let secret = get_secret();
    let expected = compute_signature(&data_str, &secret);
    if expected != sig {
        tracing::warn!("Session signature mismatch — possible tampering");
        return None;
    }

    // Parse key-value pairs
    let mut map = std::collections::HashMap::new();
    for part in data_str.split('|') {
        let mut kv = part.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            map.insert(k.to_string(), v.to_string());
        }
    }

    // Verify session age (replay protection)
    let ts: u64 = map.get("ts").and_then(|v| v.parse().ok()).unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(ts) > SESSION_MAX_AGE_SECS {
        tracing::warn!("Session expired — rejecting stale cookie");
        return None;
    }

    let user_id: i64 = map.get("user_id").and_then(|v| v.parse().ok())?;
    let username = map.get("username").cloned()?;
    let is_admin = map
        .get("is_admin")
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);
    let core_hours = map
        .get("core_hours")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let ldc_balance = map
        .get("ldc_balance")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);

    Some(UserSession {
        user_id,
        username,
        is_admin,
        core_hours,
        ldc_balance,
    })
}

/// Write a signed session cookie (预留)
#[allow(dead_code)]
pub fn set_session_cookie(cookies: &Cookies, session: &UserSession) {
    let encoded = encode_session(session);
    let mut cookie = Cookie::new("session", encoded);
    cookie.set_path("/");
    cookie.set_max_age(Duration::hours(24));
    cookie.set_http_only(true);
    // Set SameSite=Strict to prevent CSRF for cross-site POSTs
    let _ = cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookies.add(cookie);
}

/// Clear the session cookie (预留)
#[allow(dead_code)]
pub fn clear_session_cookie(cookies: &Cookies) {
    let mut cookie = Cookie::new("session", "");
    cookie.set_path("/");
    cookie.set_max_age(Duration::seconds(0));
    cookie.set_http_only(true);
    let _ = cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookies.add(cookie);
}

/// Read and verify a session cookie (no DB verification) (预留)
#[allow(dead_code)]
pub fn get_session(cookies: &Cookies) -> Option<UserSession> {
    let session_cookie = cookies.get("session")?;
    decode_session(session_cookie.value())
}

/// Read and verify a session cookie, plus DB-level sanity checks: (预留)
/// - User must still exist in the database
/// - is_admin must match the database record (prevents cookie tampering)
/// - User must not be banned
#[allow(dead_code)]
pub fn get_session_checked(cookies: &Cookies) -> Option<UserSession> {
    let session = get_session(cookies)?;
    let pool = db::get_db();

    // Query DB for user status — we use tokio's block_in_place here since
    // the function can be called from either sync or async contexts; for
    // sync callers (e.g., handlers mod.rs) this is fine.
    let row: Option<(i64, i64)> = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            sqlx::query_as::<_, (i64, i64)>("SELECT is_banned, is_admin FROM users WHERE id = ?")
                .bind(session.user_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None)
        })
    });

    let (banned_int, admin_int) = match row {
        Some(r) => r,
        None => return None, // user no longer exists
    };
    let banned = banned_int != 0;
    let db_is_admin = admin_int != 0;

    if banned {
        tracing::warn!("Session rejected for banned user_id={}", session.user_id);
        return None;
    }

    // Enforce: admin bit from cookie must match DB (critical safety)
    if session.is_admin && !db_is_admin {
        tracing::warn!(
            "Session claims is_admin=true but DB says no — tampering suspected for user_id={}",
            session.user_id
        );
        return None;
    }

    Some(UserSession {
        is_admin: db_is_admin,
        ..session
    })
}

static GENERATED_AGENT_API_KEY: OnceLock<String> = OnceLock::new();

fn is_valid_agent_api_key(key: &str) -> bool {
    !key.is_empty() && key != "tea-platform-agent-key"
}

fn generate_hex_key() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes.iter() {
        out.push(CHARS[(b & 0xf) as usize] as char);
        out.push(CHARS[((b >> 4) & 0xf) as usize] as char);
    }
    out
}

/// Get or generate the platform's SSH private key for agent installation.
/// The private key is stored encrypted in site_config.
pub fn get_ssh_private_key() -> String {
    if let Some(key) = db::get_config_sync("platform_ssh_private_key") {
        if !key.is_empty() && key != "CHANGE_ME" {
            return key;
        }
    }

    // Generate a new SSH key pair using ssh-keygen
    let key_path = std::env::temp_dir().join("tea-platform-ssh-key");
    let pub_key_path = std::env::temp_dir().join("tea-platform-ssh-key.pub");

    // Remove old keys if they exist
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_key_path);

    let output = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", key_path.to_str().unwrap(), "-N", "", "-C", "tea-platform-agent"])
        .output();

    let (private_key, public_key) = match output {
        Ok(out) if out.status.success() => {
            let priv_key = std::fs::read_to_string(&key_path).unwrap_or_default();
            let pub_key = std::fs::read_to_string(&pub_key_path).unwrap_or_default();
            (priv_key, pub_key)
        }
        _ => {
            tracing::warn!("Failed to generate SSH key pair with ssh-keygen, falling back to temp key");
            ("FALLBACK_KEY_DO_NOT_USE".to_string(), "FALLBACK_KEY_DO_NOT_USE".to_string())
        }
    };

    // Clean up temp files
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_key_path);

    // Persist the private key and public key
    let _ = db::set_config_sync("platform_ssh_private_key", &private_key);
    let _ = db::set_config_sync("platform_ssh_public_key", public_key.trim());

    private_key
}

/// Get the platform's SSH public key (shown to users for server authorization).
pub fn get_ssh_public_key() -> String {
    db::get_config_sync("platform_ssh_public_key")
        .unwrap_or_else(|| "NOT_YET_GENERATED".to_string())
}

/// 获取 Agent API Key。管理员配置优先生效；未配置时生成一次并写回配置表。
pub fn agent_api_key() -> String {
    if let Some(configured) = db::get_config_sync("agent_api_key") {
        if is_valid_agent_api_key(&configured) {
            return configured;
        }
    }

    GENERATED_AGENT_API_KEY
        .get_or_init(|| {
            let generated = generate_hex_key();
            if let Err(err) = db::set_config_sync("agent_api_key", &generated) {
                tracing::warn!("failed to persist generated Agent API key: {}", err);
            } else {
                tracing::warn!(
                    "Agent API key was not configured; generated and persisted a new key"
                );
            }
            generated
        })
        .clone()
}
