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
    pub total_usage_hours: f64,
    pub is_admin: bool,
    pub is_banned: bool,
    pub created_at: DateTime<Utc>,
    pub last_checkin: Option<DateTime<Utc>>,
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

// Request/response types for API and template rendering
#[derive(Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    pub ldc_balance: f64,
    pub core_hours: f64,
}