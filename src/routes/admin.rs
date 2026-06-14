use axum::{
    extract::{Form, Path, Query, State},
    response::{IntoResponse, Redirect},
    http::StatusCode,
};
use rand::Rng;
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;
use tower_sessions::Session;

use crate::models::{
    CoreHourCode, CoreHourPackage, InviteCode, User, VmInstance, Server,
};
use crate::AppState;

// ========== Helpers ==========

async fn check_admin_auth(session: &Session) -> bool {
    matches!(session.get::<String>("is_admin").await, Ok(Some(val)) if val == "1")
}

async fn get_setting_value(db: &SqlitePool, key: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
        .unwrap_or(None)
        .unwrap_or_default()
}

async fn set_setting_value(db: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')",
    )
    .bind(key)
    .bind(value)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

fn generate_random_code(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn render_admin(
    tera: &tera::Tera,
    template: &str,
    context: &Context,
) -> axum::response::Response {
    match tera.render(template, context) {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => {
            eprintln!("模板渲染错误: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("模板错误: {}", e)).into_response()
        }
    }
}

fn redirect_with_msg(path: &str, msg: &str) -> axum::response::Response {
    let url = format!("{}?msg={}", path, urlencoding(msg));
    Redirect::to(&url).into_response()
}

fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

// ========== Form structs ==========

#[derive(Deserialize)]
pub struct AdminLoginParams {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SettingsUpdateForm {
    pub site_name: String,
    pub registration_open: String,
    pub invite_code_required: String,
    pub sign_in_enabled: String,
    pub free_package_enabled: String,
    pub global_cpu_multiplier: String,
    pub global_memory_multiplier: String,
    pub global_bandwidth_multiplier: String,
    pub global_disk_multiplier: String,
    pub recharge_multiplier: String,
    pub recharge_fee_percent: String,
    pub withdraw_fee_percent: String,
    pub virtualization_lxd: Option<String>,
    pub virtualization_kvm: Option<String>,
    pub machine_select_mode: String,
    pub new_user_core_hours: String,
    pub sign_in_core_hours: String,
}

#[derive(Deserialize)]
pub struct InviteCodeGenerateForm {
    pub count: Option<i32>,
}

#[derive(Deserialize)]
pub struct CodeGenerateForm {
    pub code_type: String,
    pub amount: f64,
    pub valid_days: Option<i32>,
    pub daily_amount: Option<f64>,
    pub count: Option<i32>,
}

#[derive(Deserialize)]
pub struct PackageCreateForm {
    pub name: String,
    pub package_type: String,
    pub duration_days: Option<String>,
    pub accumulated_hours: Option<String>,
    pub core_hours: String,
    pub price_ldc: String,
}

#[derive(Deserialize)]
pub struct PackageEditForm {
    pub name: String,
    pub package_type: String,
    pub duration_days: Option<String>,
    pub accumulated_hours: Option<String>,
    pub core_hours: String,
    pub price_ldc: String,
    pub is_active: Option<String>,
}

#[derive(Deserialize)]
pub struct UserAdjustHoursForm {
    pub user_id: i64,
    pub amount: f64,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct PageParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

// ========== Admin Login ==========

pub async fn admin_login(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<AdminLoginParams>,
) -> impl IntoResponse {
    if params.username != state.config.admin_username {
        return (StatusCode::UNAUTHORIZED, "用户名或密码错误").into_response();
    }

    match bcrypt::verify(&params.password, &state.config.admin_password_hash) {
        Ok(true) => {
            let _ = session.insert("is_admin", "1").await;
            let _ = session.insert("user_id", 0i64).await;
            Redirect::to("/admin/dashboard").into_response()
        }
        Ok(false) => {
            (StatusCode::UNAUTHORIZED, "用户名或密码错误").into_response()
        }
        Err(e) => {
            eprintln!("bcrypt 验证错误: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response()
        }
    }
}

// ========== Dashboard ==========

pub async fn dashboard(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_servers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM servers")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let active_vms: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vm_instances WHERE status = 'running'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let pending_servers: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM servers WHERE status = 'pending'")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("total_users", &total_users);
    context.insert("total_servers", &total_servers);
    context.insert("active_vms", &active_vms);
    context.insert("pending_servers", &pending_servers);

    render_admin(&state.tera, "admin/dashboard.html.tera", &context)
}

// ========== Settings ==========

pub async fn settings_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let settings = load_all_settings(&state.db).await;

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    for (key, value) in &settings {
        context.insert(key, value);
    }

    // Parse virtualization_types for checkbox states
    let virt_types = settings.iter()
        .find(|(k, _)| k == "virtualization_types")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let lxd_enabled = virt_types.contains("lxd");
    let kvm_enabled = virt_types.contains("kvm");
    context.insert("virtualization_lxd", &lxd_enabled);
    context.insert("virtualization_kvm", &kvm_enabled);

    render_admin(&state.tera, "admin/settings.html.tera", &context)
}

pub async fn settings_update(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<SettingsUpdateForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    // Build virtualization_types from checkboxes
    let mut virt_types = Vec::new();
    if form.virtualization_lxd.as_deref() == Some("1") {
        virt_types.push("lxd");
    }
    if form.virtualization_kvm.as_deref() == Some("1") {
        virt_types.push("kvm");
    }
    let virtualization_types = if virt_types.is_empty() {
        "lxd".to_string()
    } else {
        virt_types.join(",")
    };

    let pairs: Vec<(&str, String)>= vec![
        ("site_name", form.site_name),
        ("registration_open", form.registration_open),
        ("invite_code_required", form.invite_code_required),
        ("sign_in_enabled", form.sign_in_enabled),
        ("free_package_enabled", form.free_package_enabled),
        ("global_cpu_multiplier", form.global_cpu_multiplier),
        ("global_memory_multiplier", form.global_memory_multiplier),
        ("global_bandwidth_multiplier", form.global_bandwidth_multiplier),
        ("global_disk_multiplier", form.global_disk_multiplier),
        ("recharge_multiplier", form.recharge_multiplier),
        ("recharge_fee_percent", form.recharge_fee_percent),
        ("withdraw_fee_percent", form.withdraw_fee_percent),
        ("virtualization_types", virtualization_types),
        ("machine_select_mode", form.machine_select_mode),
        ("new_user_core_hours", form.new_user_core_hours),
        ("sign_in_core_hours", form.sign_in_core_hours),
    ];

    for (key, value) in &pairs {
        if let Err(e) = set_setting_value(&state.db, key, value).await {
            eprintln!("保存设置 {} 失败: {}", key, e);
        }
    }

    redirect_with_msg("/admin/settings", "设置已保存")
}

async fn load_all_settings(db: &SqlitePool) -> Vec<(String, String)> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM settings ORDER BY key")
            .fetch_all(db)
            .await
            .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for (k, v) in rows {
        map.insert(k, v);
    }

    let keys = [
        "site_name",
        "registration_open",
        "invite_code_required",
        "sign_in_enabled",
        "free_package_enabled",
        "global_cpu_multiplier",
        "global_memory_multiplier",
        "global_bandwidth_multiplier",
        "global_disk_multiplier",
        "recharge_multiplier",
        "recharge_fee_percent",
        "withdraw_fee_percent",
        "virtualization_types",
        "machine_select_mode",
        "new_user_core_hours",
        "sign_in_core_hours",
    ];

    keys.iter()
        .map(|k| {
            let v = map.get(*k).cloned().unwrap_or_default();
            (k.to_string(), v)
        })
        .collect()
}

// ========== Invite Codes ==========

pub async fn invite_codes_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let codes: Vec<InviteCode> = sqlx::query_as(
        "SELECT id, code, is_used, used_by, created_at FROM invite_codes ORDER BY id DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("codes", &codes);

    render_admin(&state.tera, "admin/invite_codes.html.tera", &context)
}

pub async fn invite_codes_generate(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<InviteCodeGenerateForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let count = form.count.unwrap_or(1).max(1).min(100);
    let mut generated: Vec<String> = Vec::new();

    for _ in 0..count {
        let code = generate_random_code(8);
        if let Err(e) = sqlx::query("INSERT INTO invite_codes (code) VALUES (?)")
            .bind(&code)
            .execute(&state.db)
            .await
        {
            eprintln!("生成邀请码失败: {}", e);
        } else {
            generated.push(code);
        }
    }

    let msg = format!("成功生成 {} 个邀请码", generated.len());
    redirect_with_msg("/admin/invite-codes", &msg)
}

pub async fn invite_codes_delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query("DELETE FROM invite_codes WHERE id = ? AND is_used = 0")
        .bind(id)
        .execute(&state.db)
        .await;

    redirect_with_msg("/admin/invite-codes", "邀请码已删除")
}

// ========== Core Hour Codes ==========

pub async fn codes_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let codes: Vec<CoreHourCode> = sqlx::query_as(
        "SELECT id, code, amount, daily_amount, code_type, expires_at, valid_days, is_used, used_by, used_at, created_at FROM core_hour_codes ORDER BY id DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("codes", &codes);

    render_admin(&state.tera, "admin/codes.html.tera", &context)
}

pub async fn codes_generate(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<CodeGenerateForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let count = form.count.unwrap_or(1).max(1).min(100);
    let daily = form.daily_amount.unwrap_or(0.0);

    for _ in 0..count {
        let code = generate_random_code(12);
        if let Err(e) = sqlx::query(
            "INSERT INTO core_hour_codes (code, amount, daily_amount, code_type, valid_days) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&code)
        .bind(form.amount)
        .bind(daily)
        .bind(&form.code_type)
        .bind(form.valid_days)
        .execute(&state.db)
        .await
        {
            eprintln!("生成核时码失败: {}", e);
        }
    }

    let msg = format!("成功生成 {} 个核时码", count);
    redirect_with_msg("/admin/codes", &msg)
}

// ========== Packages ==========

pub async fn packages_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let packages: Vec<CoreHourPackage> = sqlx::query_as(
        "SELECT id, name, package_type, duration_days, accumulated_hours, core_hours, price_ldc, is_active, created_at, updated_at FROM core_hour_packages ORDER BY id DESC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("packages", &packages);

    render_admin(&state.tera, "admin/packages.html.tera", &context)
}

pub async fn packages_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<PackageCreateForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let duration_days: Option<i64> = form.duration_days
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() });
    let accumulated_hours: Option<f64> = form.accumulated_hours
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() });
    let core_hours: f64 = form.core_hours.parse().unwrap_or(0.0);
    let price_ldc: f64 = form.price_ldc.parse().unwrap_or(0.0);

    let _ = sqlx::query(
        "INSERT INTO core_hour_packages (name, package_type, duration_days, accumulated_hours, core_hours, price_ldc) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&form.name)
    .bind(&form.package_type)
    .bind(duration_days)
    .bind(accumulated_hours)
    .bind(core_hours)
    .bind(price_ldc)
    .execute(&state.db)
    .await;

    redirect_with_msg("/admin/packages", "套餐已创建")
}

pub async fn packages_edit(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Form(form): Form<PackageEditForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let duration_days: Option<i64> = form.duration_days
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() });
    let accumulated_hours: Option<f64> = form.accumulated_hours
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() });
    let core_hours: f64 = form.core_hours.parse().unwrap_or(0.0);
    let price_ldc: f64 = form.price_ldc.parse().unwrap_or(0.0);
    let is_active: bool = form.is_active.as_deref() == Some("1");

    let _ = sqlx::query(
        "UPDATE core_hour_packages SET name = ?, package_type = ?, duration_days = ?, accumulated_hours = ?, core_hours = ?, price_ldc = ?, is_active = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&form.name)
    .bind(&form.package_type)
    .bind(duration_days)
    .bind(accumulated_hours)
    .bind(core_hours)
    .bind(price_ldc)
    .bind(is_active)
    .bind(id)
    .execute(&state.db)
    .await;

    redirect_with_msg("/admin/packages", "套餐已更新")
}

pub async fn packages_delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE core_hour_packages SET is_active = 0, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    redirect_with_msg("/admin/packages", "套餐已停用")
}

// ========== Users ==========

pub async fn users_page(
    State(state): State<AppState>,
    session: Session,
    Query(page_params): Query<PageParams>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let page = page_params.page.unwrap_or(1).max(1);
    let per_page = page_params.per_page.unwrap_or(20).max(1).min(100);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let users: Vec<User> = sqlx::query_as(
        "SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("users", &users);
    context.insert("page", &page);
    context.insert("per_page", &per_page);
    context.insert("total", &total);
    context.insert("total_pages", &total_pages);

    render_admin(&state.tera, "admin/users.html.tera", &context)
}

pub async fn users_ban(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE users SET is_banned = CASE WHEN is_banned = 1 THEN 0 ELSE 1 END, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    Redirect::to("/admin/users").into_response()
}

pub async fn users_set_admin(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE users SET is_admin = CASE WHEN is_admin = 1 THEN 0 ELSE 1 END, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    Redirect::to("/admin/users").into_response()
}

pub async fn users_adjust_hours(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<UserAdjustHoursForm>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE users SET core_hours = MAX(0, core_hours + ?), updated_at = datetime('now') WHERE id = ?",
    )
    .bind(form.amount)
    .bind(form.user_id)
    .execute(&state.db)
    .await;

    let msg = format!(
        "用户 {} 核时已调整 {}（原因: {}）",
        form.user_id, form.amount, form.reason
    );
    redirect_with_msg("/admin/users", &msg)
}

// ========== Servers ==========

pub async fn servers_page(
    State(state): State<AppState>,
    session: Session,
    Query(page_params): Query<PageParams>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let page = page_params.page.unwrap_or(1).max(1);
    let per_page = page_params.per_page.unwrap_or(20).max(1).min(100);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM servers")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let servers: Vec<Server> = sqlx::query_as(
        "SELECT * FROM servers ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("servers", &servers);
    context.insert("page", &page);
    context.insert("per_page", &per_page);
    context.insert("total", &total);
    context.insert("total_pages", &total_pages);

    render_admin(&state.tera, "admin/servers.html.tera", &context)
}

pub async fn servers_approve(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE servers SET status = 'active', updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    Redirect::to("/admin/servers").into_response()
}

pub async fn servers_offline(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE servers SET status = 'offline', updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    Redirect::to("/admin/servers").into_response()
}

// ========== VMs ==========

pub async fn vms_page(
    State(state): State<AppState>,
    session: Session,
    Query(page_params): Query<PageParams>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let page = page_params.page.unwrap_or(1).max(1);
    let per_page = page_params.per_page.unwrap_or(20).max(1).min(100);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vm_instances")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let vms: Vec<VmInstance> = sqlx::query_as(
        "SELECT * FROM vm_instances ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);
    context.insert("vms", &vms);
    context.insert("page", &page);
    context.insert("per_page", &per_page);
    context.insert("total", &total);
    context.insert("total_pages", &total_pages);

    render_admin(&state.tera, "admin/vms.html.tera", &context)
}

pub async fn vms_stop(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !check_admin_auth(&session).await {
        return (StatusCode::UNAUTHORIZED, "请先登录管理后台").into_response();
    }

    let _ = sqlx::query(
        "UPDATE vm_instances SET status = 'stopped', updated_at = datetime('now') WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await;

    Redirect::to("/admin/vms").into_response()
}