use serde::{Deserialize, Serialize};

// ========== User ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub linuxdo_id: i64,
    pub username: String,
    pub email: Option<String>,
    pub core_hours: f64,
    pub is_admin: bool,
    pub is_banned: bool,
    pub invite_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub core_hours: f64,
    pub is_admin: bool,
    pub created_at: String,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            core_hours: u.core_hours,
            is_admin: u.is_admin,
            created_at: u.created_at,
        }
    }
}

// ========== Server ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Server {
    pub id: i64,
    pub user_id: i64,
    pub ip: String,
    pub ssh_port: i64,
    pub ssh_key_encrypted: String,
    pub cpu_cores: i64,
    pub memory_gb: f64,
    pub bandwidth_mbps: f64,
    pub disk_gb: f64,
    pub cpu_multiplier: f64,
    pub memory_multiplier: f64,
    pub bandwidth_multiplier: f64,
    pub disk_multiplier: f64,
    pub use_bonus: bool,
    pub virtualization_type: String,
    pub status: String,
    pub core_hours_per_hour: f64,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub agent_token: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerContributeForm {
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
    pub virtualization_type: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServerWithUser {
    pub id: i64,
    pub user_id: i64,
    pub ip: String,
    pub ssh_port: i64,
    pub ssh_key_encrypted: String,
    pub cpu_cores: i64,
    pub memory_gb: f64,
    pub bandwidth_mbps: f64,
    pub disk_gb: f64,
    pub cpu_multiplier: f64,
    pub memory_multiplier: f64,
    pub bandwidth_multiplier: f64,
    pub disk_multiplier: f64,
    pub use_bonus: bool,
    pub virtualization_type: String,
    pub status: String,
    pub core_hours_per_hour: f64,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub agent_token: Option<String>,
    pub last_seen: Option<String>,
    pub username: Option<String>,
}

// ========== VM Instance ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VmInstance {
    pub id: i64,
    pub user_id: i64,
    pub server_id: i64,
    pub cpu_cores: i64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub forwarded_port: Option<i64>,
    pub vm_id: Option<String>,
    pub status: String,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVmForm {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub duration_hours: i32,
}

// ========== Settings ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingForm {
    pub key: String,
    pub value: String,
}

// ========== Invite Code ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InviteCode {
    pub id: i64,
    pub code: String,
    pub is_used: bool,
    pub used_by: Option<i64>,
    pub created_at: String,
}

// ========== Core Hour Codes ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CoreHourCode {
    pub id: i64,
    pub code: String,
    pub amount: f64,
    pub daily_amount: f64,
    pub code_type: String,
    pub expires_at: Option<String>,
    pub valid_days: Option<i64>,
    pub is_used: bool,
    pub used_by: Option<i64>,
    pub used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateCodeForm {
    pub amount: f64,
    pub code_type: String,
    pub valid_days: Option<i32>,
    pub daily_amount: Option<f64>,
    pub count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemCodeForm {
    pub code: String,
}

// ========== Core Hour Packages ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CoreHourPackage {
    pub id: i64,
    pub name: String,
    pub package_type: String,
    pub duration_days: Option<i64>,
    pub accumulated_hours: Option<f64>,
    pub core_hours: f64,
    pub price_ldc: f64,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageForm {
    pub name: String,
    pub package_type: String,
    pub duration_days: Option<i32>,
    pub accumulated_hours: Option<f64>,
    pub core_hours: f64,
    pub price_ldc: f64,
}

// ========== Recharge Orders ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RechargeOrder {
    pub id: i64,
    pub user_id: i64,
    pub out_trade_no: String,
    pub trade_no: Option<String>,
    pub amount_ldc: f64,
    pub core_hours: f64,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RechargeForm {
    pub amount_ldc: f64,
}

// ========== Sign-In ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SignInRecord {
    pub id: i64,
    pub user_id: i64,
    pub date: String,
    pub core_hours_awarded: f64,
    pub created_at: String,
}

// ========== User Subscription ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSubscription {
    pub id: i64,
    pub user_id: i64,
    pub code_id: i64,
    pub daily_amount: f64,
    pub starts_at: String,
    pub expires_at: String,
    pub last_awarded_at: Option<String>,
    pub is_active: bool,
    pub created_at: String,
}

// ========== User Package ==========

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserPackage {
    pub id: i64,
    pub user_id: i64,
    pub package_id: i64,
    pub core_hours: f64,
    pub accumulated_hours_used: f64,
    pub expires_at: Option<String>,
    pub is_active: bool,
    pub created_at: String,
}

// ========== API Response ==========

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(message: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

// ========== Dashboard Stats ==========

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_users: i64,
    pub total_servers: i64,
    pub active_vms: i64,
    pub total_core_hours_awarded: f64,
}

// ========== Pagination ==========

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
}