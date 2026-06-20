use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// Table: users
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub linuxdo_id: i64,
    pub username: String,
    pub email: String,
    pub ldc_balance: f64,
    pub core_hours: f64,
    pub bonus_core_hours: f64,
    pub bonus_expires_at: Option<DateTime<Utc>>,
    pub total_usage_hours: f64,
    pub is_admin: bool,
    pub is_banned: bool,
    pub created_at: DateTime<Utc>,
    pub last_checkin: Option<DateTime<Utc>>,
    pub api_key: Option<String>,
}

// Table: servers
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Server {
    pub id: i64,
    pub owner_id: i64,
    pub name: String,
    pub ip: String,
    pub ssh_port: i32,
    pub ssh_key: String,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub bandwidth_mbps: f64,
    pub disk_gb: f64,
    pub cpu_multiplier: f64,
    pub memory_multiplier: f64,
    pub bandwidth_multiplier: f64,
    pub disk_multiplier: f64,
    pub use_bonus: bool,
    pub virt_type: String,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
    pub proxy_port: Option<i32>,
    pub agent_installed: bool,
    pub created_at: DateTime<Utc>,
    pub expose_ip: bool,
    pub nat_port_start: i32,
    pub nat_port_end: i32,
    pub nat_multiplier: f64,
    pub max_machine_hours: f64,
    pub is_premium: bool,
    pub premium_expires_at: Option<DateTime<Utc>>,
    pub linux_version: String,
    pub description: String,
    pub provider: String,
}

// Table: machines
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Machine {
    pub id: i64,
    pub user_id: i64,
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub virt_type: String,
    pub status: String,
    pub core_hours_per_hour: f64,
    pub expires_at: DateTime<Utc>,
    pub ssh_port: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub settled: bool,
    pub used_hours: f64,
}

// Table: orders
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Order {
    pub id: i64,
    pub user_id: i64,
    pub out_trade_no: String,
    pub money: f64,
    pub ldc_amount: f64,
    pub order_name: String,
    pub status: String,
    pub trade_no: Option<String>,
    pub created_at: DateTime<Utc>,
}

// Table: recharge_packages
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RechargePackage {
    pub id: i64,
    pub name: String,
    pub duration_days: Option<i32>,
    pub core_hours: f64,
    pub price_ldc: f64,
    pub is_cumulative: bool,
    pub cumulative_hours: Option<f64>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// Table: redeem_codes
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RedeemCode {
    pub id: i64,
    pub code: String,
    pub code_type: String,
    pub package_id: Option<i64>,
    pub core_hours: Option<f64>,
    pub is_used: bool,
    pub used_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

// Table: invites
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Invite {
    pub id: i64,
    pub code: String,
    pub is_used: bool,
    pub used_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub private_note: String,
    pub public_note: String,
}

// Table: checkins
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Checkin {
    pub id: i64,
    pub user_id: i64,
    pub reward_core_hours: f64,
    pub created_at: DateTime<Utc>,
}

// Table: site_config
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiteConfig {
    pub id: i64,
    pub key: String,
    pub value: String,
}

// Table: user_packages
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserPackage {
    pub id: i64,
    pub user_id: i64,
    pub package_id: Option<i64>,
    pub core_hours: f64,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// Table: traffic_alerts
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TrafficAlert {
    pub id: i64,
    pub machine_id: Option<i64>,
    pub server_id: Option<i64>,
    pub alert_type: String,
    pub message: String,
    pub resolved: bool,
    pub created_at: DateTime<Utc>,
}

// Table: disputes
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Dispute {
    pub id: i64,
    pub machine_id: i64,
    pub user_id: i64,
    pub server_id: i64,
    pub reason: String,
    pub status: String,
    pub resolution: Option<String>,
    pub reply: Option<String>,
    pub amount_frozen: f64,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub auto_resolve_at: DateTime<Utc>,
}

// Table: oauth_apps
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OAuthApp {
    pub id: i64,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub created_by: i64,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// Table: balance_to_code_logs
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BalanceToCodeLog {
    pub id: i64,
    pub user_id: i64,
    pub amount: f64,
    pub fee: f64,
    pub is_bonus: bool,
    pub code: String,
    pub created_at: DateTime<Utc>,
}

// Table: machine_stats
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MachineStats {
    pub id: i64,
    pub machine_id: i64,
    pub cpu_usage_percent: f64,
    pub memory_used_mb: f64,
    pub memory_total_mb: f64,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
    pub bandwidth_rx_mbps: f64,
    pub bandwidth_tx_mbps: f64,
    pub uptime_seconds: i64,
    pub process_count: i64,
    pub last_updated: DateTime<Utc>,
}

// Table: warning_letters
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WarningLetter {
    pub id: i64,
    pub user_id: i64,
    pub subject: String,
    pub content: String,
    pub warning_type: String,
    pub severity: String,
    pub is_read: bool,
    pub requires_action: bool,
    pub action_taken: bool,
    pub action_note: Option<String>,
    pub action_at: Option<DateTime<Utc>>,
    pub sent_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// Warning letter view model with username
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningLetterView {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub subject: String,
    pub content: String,
    pub warning_type: String,
    pub severity: String,
    pub is_read: bool,
    pub requires_action: bool,
    pub action_taken: bool,
    pub action_note: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// Combined machine info with stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineWithStats {
    #[serde(flatten)]
    pub machine: Machine,
    pub stats: Option<MachineStats>,
    pub server_name: String,
    pub server_ip: String,
}

// Request/response types for API and template rendering
#[derive(Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    pub ldc_balance: f64,
    pub core_hours: f64,
}

// Table: opengfw_rules
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OpenGFWRule {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub protocol: String,
    pub action: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// Table: opengfw_logs
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OpenGFWLog {
    pub id: i64,
    pub machine_id: i64,
    pub server_id: i64,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub blocked_at: DateTime<Utc>,
}

// OpenGFW log with additional info for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenGFWLogView {
    pub id: i64,
    pub machine_id: i64,
    pub server_id: i64,
    pub server_name: String,
    pub server_ip: String,
    pub username: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub blocked_at: String,
}

// OpenGFW configuration for agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenGFWConfig {
    pub enabled: bool,
    pub rules: Vec<OpenGFWRuleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenGFWRuleItem {
    pub name: String,
    pub protocol: String,
    pub action: String,
}