use axum::{
    extract::{State, Form, Query, Path},
    response::{IntoResponse, Redirect},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tera::Context;
use tower_sessions::Session;

use crate::models::{
    Server, VmInstance, CoreHourPackage, SignInRecord,
};
use crate::routes::auth::get_current_user;
use crate::services::agent;
use crate::AppState;

// ========== 辅助结构 ==========

#[derive(Debug, Clone, Serialize)]
struct VmDisplayInfo {
    pub id: i64,
    pub server_id: i64,
    pub cpu_cores: i64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub forwarded_port: Option<i64>,
    pub status: String,
    pub expires_at: String,
    pub server_ip: String,
    pub server_ssh_port: i64,
}

// ========== 表单结构 ==========

#[derive(Debug, Deserialize)]
pub struct ContributeFormData {
    pub ip: String,
    #[serde(default = "default_ssh_port")]
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
    #[serde(default)]
    pub use_bonus: bool,
    pub virtualization_type: String,
    pub expires_at: String,
}

fn default_ssh_port() -> i32 { 22 }

#[derive(Debug, Deserialize)]
pub struct VmFormData {
    pub server_id: i64,
    pub cpu_cores: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub duration_hours: i32,
}

#[derive(Debug, Deserialize)]
pub struct RechargeFormData {
    pub amount_ldc: f64,
}

#[derive(Debug, Deserialize)]
pub struct RedeemFormData {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct VmQueryParams {
    pub server_id: Option<i64>,
}

// ========== 辅助函数 ==========

/// 渲染模板或返回错误
fn render_template(tera: &tera::Tera, template: &str, context: &Context) -> axum::response::Response {
    match tera.render(template, context) {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => {
            eprintln!("模板渲染错误 [{}]: {}", template, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("模板错误: {}", e)).into_response()
        }
    }
}

/// 需要登录的路由辅助: 未登录则重定向到 /login
async fn require_login(
    state: &AppState,
    session: &Session,
    context: &mut Context,
) -> Result<crate::models::User, axum::response::Response> {
    match get_current_user(&state.db, session).await {
        Ok(Some(user)) => {
            context.insert("user", &user);
            Ok(user)
        }
        Ok(None) => Err(Redirect::to("/login").into_response()),
        Err(e) => {
            eprintln!("获取用户错误: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response())
        }
    }
}

// ========== 路由处理器 ==========

/// GET /servers/contribute - 贡献服务器页面
pub async fn contribute_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    // 需要登录
    let _user = match get_current_user(&state.db, &session).await {
        Ok(Some(u)) => { context.insert("user", &u); u }
        Ok(None) => return Redirect::to("/login").into_response(),
        Err(e) => {
            eprintln!("获取用户错误: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
        }
    };

    // 获取启用的虚拟化方式
    let virt_types = crate::routes::auth::get_setting(&state.db, "virtualization_types")
        .await
        .unwrap_or_else(|| "lxd".to_string());
    let lxd_enabled = virt_types.contains("lxd");
    let kvm_enabled = virt_types.contains("kvm");
    context.insert("virtualization_lxd", &lxd_enabled);
    context.insert("virtualization_kvm", &kvm_enabled);
    context.insert("virtualization_default", if lxd_enabled { "lxd" } else { "kvm" });

    render_template(&state.tera, "contribute.html.tera", &context)
}

/// POST /servers/contribute - 处理贡献提交
pub async fn contribute_submit(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<ContributeFormData>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // 验证输入
    if form.ip.is_empty() || form.ssh_key.is_empty() {
        context.insert("error", "IP 地址和 SSH 私钥不能为空");
        return render_template(&state.tera, "contribute.html.tera", &context);
    }

    if form.cpu_cores <= 0 {
        context.insert("error", "CPU 核心数必须大于 0");
        return render_template(&state.tera, "contribute.html.tera", &context);
    }

    // TODO: 加密 SSH 私钥，目前存储为占位加密
    let encrypted_key = &form.ssh_key;

    // 计算每小时核时收益
    let core_hours_per_hour = crate::services::calculate_core_hours_per_hour(
        &state.db,
        form.cpu_cores,
        form.cpu_multiplier,
        form.memory_gb,
        form.memory_multiplier,
        form.bandwidth_mbps,
        form.bandwidth_multiplier,
        form.disk_gb,
        form.disk_multiplier,
    ).await.unwrap_or(0.0);

    let result = sqlx::query(
        r#"INSERT INTO servers (user_id, ip, ssh_port, ssh_key_encrypted, cpu_cores, memory_gb,
           bandwidth_mbps, disk_gb, cpu_multiplier, memory_multiplier, bandwidth_multiplier,
           disk_multiplier, use_bonus, virtualization_type, status, core_hours_per_hour, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)"#,
    )
    .bind(user.id)
    .bind(&form.ip)
    .bind(form.ssh_port)
    .bind(encrypted_key)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(form.bandwidth_mbps)
    .bind(form.disk_gb)
    .bind(form.cpu_multiplier)
    .bind(form.memory_multiplier)
    .bind(form.bandwidth_multiplier)
    .bind(form.disk_multiplier)
    .bind(form.use_bonus)
    .bind(&form.virtualization_type)
    .bind(core_hours_per_hour)
    .bind(&form.expires_at)
    .execute(&state.db)
    .await;

    match result {
        Ok(query_result) => {
            let server_id = query_result.last_insert_rowid();
            // Attempt to install agent on the target server
            let agent_result = agent::install_agent(
                &state.db,
                server_id,
                &form.ip,
                form.ssh_port as u16,
                &form.ssh_key,
                &form.virtualization_type,
            )
            .await;

            match agent_result {
                Ok(()) => {
                    println!("[Contribute] 服务器 {} agent 安装成功", server_id);
                    context.insert("success", "服务器贡献成功！Agent 已自动安装，服务器状态为 active。");
                }
                Err(e) => {
                    eprintln!("[Contribute] 服务器 {} agent 安装失败: {}", server_id, e);
                    context.insert("success", "服务器贡献成功，但 Agent 安装失败，请稍后重试。服务器状态为 pending。");
                }
            }
        }
        Err(e) => {
            eprintln!("贡献服务器错误: {}", e);
            context.insert("error", "保存失败，请稍后重试。");
        }
    }

    render_template(&state.tera, "contribute.html.tera", &context)
}

/// GET /marketplace - 机器广场
pub async fn marketplace(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = get_current_user(&state.db, &session).await.ok().flatten();
    if let Some(ref u) = user {
        context.insert("user", u);
    }

    // 查询可用服务器 (status = 'approved')
    let servers = match sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE status = 'approved' AND expires_at > datetime('now') ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("查询服务器列表错误: {}", e);
            Vec::new()
        }
    };

    context.insert("servers", &servers);

    render_template(&state.tera, "marketplace.html.tera", &context)
}

/// GET /vms/create?server_id=X - 创建 VM 页面
pub async fn create_vm_page(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<VmQueryParams>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let _user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let server_id = match params.server_id {
        Some(id) => id,
        None => return Redirect::to("/marketplace").into_response(),
    };

    let server = match sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            context.insert("error", "服务器不存在");
            return render_template(&state.tera, "create_vm.html.tera", &context);
        }
        Err(e) => {
            eprintln!("查询服务器错误: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
        }
    };

    context.insert("server", &server);

    render_template(&state.tera, "create_vm.html.tera", &context)
}

/// POST /vms/create - 创建 VM
pub async fn create_vm(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<VmFormData>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // 获取服务器信息
    let server = match sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE id = ?",
    )
    .bind(form.server_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            context.insert("error", "服务器不存在");
            return render_template(&state.tera, "create_vm.html.tera", &context);
        }
        Err(e) => {
            eprintln!("查询服务器错误: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
        }
    };

    context.insert("server", &server);

    // 验证资源不超过服务器上限
    if form.cpu_cores <= 0 || form.cpu_cores as i64 > server.cpu_cores {
        context.insert("error", &format!("CPU 核心数需在 1 - {} 之间", server.cpu_cores));
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }
    if form.memory_gb <= 0.0 || form.memory_gb > server.memory_gb {
        context.insert("error", &format!("内存需在 0.1 - {} GB 之间", server.memory_gb));
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }
    if form.disk_gb <= 0.0 || form.disk_gb > server.disk_gb {
        context.insert("error", &format!("磁盘需在 0.1 - {} GB 之间", server.disk_gb));
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }
    if form.duration_hours <= 0 {
        context.insert("error", "时长必须大于 0 小时");
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }

    // 计算核心小时消耗
    let core_hours_cost = crate::services::calculate_vm_cost(
        &state.db,
        &server,
        form.cpu_cores,
        form.memory_gb,
        form.disk_gb,
        form.duration_hours,
    ).await.unwrap_or(0.0);

    // 检查余额
    if user.core_hours < core_hours_cost {
        context.insert("error", &format!(
            "核时不足！需要 {:.1} 核时，当前余额 {:.1} 核时",
            core_hours_cost, user.core_hours
        ));
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }

    // 计算过期时间
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(form.duration_hours as i64);
    let expires_at_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

    // TODO: 分配端口，这里简化处理
    let forwarded_port: i64 = 22000 + server.id * 100 + 1;

    // 扣除核时
    let deduct_result = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ?")
        .bind(core_hours_cost)
        .bind(user.id)
        .execute(&state.db)
        .await;

    if let Err(e) = deduct_result {
        eprintln!("扣除核时错误: {}", e);
        context.insert("error", "操作失败，请稍后重试");
        return render_template(&state.tera, "create_vm.html.tera", &context);
    }

    // 创建 VM 实例 - 使用 VmInstance 结构体字段匹配
    let result = sqlx::query(
        r#"INSERT INTO vm_instances (user_id, server_id, cpu_cores, memory_gb, disk_gb,
           forwarded_port, status, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)"#,
    )
    .bind(user.id)
    .bind(form.server_id)
    .bind(form.cpu_cores)
    .bind(form.memory_gb)
    .bind(form.disk_gb)
    .bind(forwarded_port)
    .bind(&expires_at_str)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            return Redirect::to("/my/vms?created=1").into_response();
        }
        Err(e) => {
            eprintln!("创建 VM 错误: {}", e);
            // 退还核时
            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(core_hours_cost)
                .bind(user.id)
                .execute(&state.db)
                .await;
            context.insert("error", "创建虚拟机失败，请稍后重试");
            return render_template(&state.tera, "create_vm.html.tera", &context);
        }
    }
}

/// GET /my/vms - 我的虚拟机
pub async fn my_vms(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let vms = match sqlx::query_as::<_, VmInstance>(
        "SELECT * FROM vm_instances WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("查询 VM 列表错误: {}", e);
            Vec::new()
        }
    };

    // 获取 VM 对应的服务器信息
    let mut vm_infos: Vec<VmDisplayInfo> = Vec::new();
    for vm in &vms {
        let server = sqlx::query_as::<_, Server>(
            "SELECT * FROM servers WHERE id = ?",
        )
        .bind(vm.server_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let (server_ip, server_ssh_port) = if let Some(ref s) = server {
            (s.ip.clone(), s.ssh_port)
        } else {
            ("未知".to_string(), 0i64)
        };

        vm_infos.push(VmDisplayInfo {
            id: vm.id,
            server_id: vm.server_id,
            cpu_cores: vm.cpu_cores,
            memory_gb: vm.memory_gb,
            disk_gb: vm.disk_gb,
            forwarded_port: vm.forwarded_port,
            status: vm.status.clone(),
            expires_at: vm.expires_at.clone(),
            server_ip,
            server_ssh_port,
        });
    }

    context.insert("vms", &vm_infos);

    render_template(&state.tera, "my_vms.html.tera", &context)
}

/// GET /my/servers - 我贡献的服务器
pub async fn my_servers(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let servers = match sqlx::query_as::<_, Server>(
        "SELECT * FROM servers WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("查询服务器列表错误: {}", e);
            Vec::new()
        }
    };

    context.insert("servers", &servers);

    render_template(&state.tera, "my_servers.html.tera", &context)
}

/// GET /recharge - 充值页面
pub async fn recharge_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let _user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // 获取充值和费率信息
    let multiplier: f64 = super::auth::get_setting(&state.db, "recharge_multiplier")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);

    let fee_percent: f64 = super::auth::get_setting(&state.db, "recharge_fee_percent")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    context.insert("recharge_multiplier", &multiplier);
    context.insert("recharge_fee_percent", &fee_percent);

    render_template(&state.tera, "recharge.html.tera", &context)
}

/// POST /recharge/create - 创建充值订单
pub async fn recharge_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<RechargeFormData>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    if form.amount_ldc <= 0.0 {
        context.insert("error", "请输入有效的 LDC 金额");
        let multiplier: f64 = super::auth::get_setting(&state.db, "recharge_multiplier")
            .await.and_then(|v| v.parse().ok()).unwrap_or(1.0);
        let fee_percent: f64 = super::auth::get_setting(&state.db, "recharge_fee_percent")
            .await.and_then(|v| v.parse().ok()).unwrap_or(0.0);
        context.insert("recharge_multiplier", &multiplier);
        context.insert("recharge_fee_percent", &fee_percent);
        return render_template(&state.tera, "recharge.html.tera", &context);
    }

    // 生成订单号
    let out_trade_no = format!("RECHARGE_{}_{}", user.id, chrono::Utc::now().timestamp());

    // 计算核心小时
    let multiplier: f64 = super::auth::get_setting(&state.db, "recharge_multiplier")
        .await.and_then(|v| v.parse().ok()).unwrap_or(1.0);
    let fee_percent: f64 = super::auth::get_setting(&state.db, "recharge_fee_percent")
        .await.and_then(|v| v.parse().ok()).unwrap_or(0.0);

    let after_fee = form.amount_ldc * (1.0 - fee_percent / 100.0);
    let core_hours = after_fee * multiplier;

    // 创建订单
    let result = sqlx::query(
        r#"INSERT INTO recharge_orders (user_id, out_trade_no, amount_ldc, core_hours, status)
           VALUES (?, ?, ?, ?, 'pending')"#,
    )
    .bind(user.id)
    .bind(&out_trade_no)
    .bind(form.amount_ldc)
    .bind(core_hours)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            context.insert("success", &format!(
                "充值订单已创建！订单号: {}，预计获得 {:.1} 核时。请完成支付。",
                out_trade_no, core_hours
            ));
        }
        Err(e) => {
            eprintln!("创建充值订单错误: {}", e);
            context.insert("error", "创建订单失败，请稍后重试");
        }
    }

    context.insert("recharge_multiplier", &multiplier);
    context.insert("recharge_fee_percent", &fee_percent);
    render_template(&state.tera, "recharge.html.tera", &context)
}

/// GET /redeem - 兑换码页面
pub async fn redeem_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let _user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    render_template(&state.tera, "redeem.html.tera", &context)
}

/// POST /codes/redeem - 兑换码兑换
pub async fn redeem_code(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<RedeemFormData>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    if form.code.is_empty() {
        context.insert("error", "请输入兑换码");
        return render_template(&state.tera, "redeem.html.tera", &context);
    }

    // 查询兑换码
    let code_record = match sqlx::query_as::<_, crate::models::CoreHourCode>(
        "SELECT * FROM core_hour_codes WHERE code = ?",
    )
    .bind(&form.code)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            context.insert("error", "兑换码无效");
            return render_template(&state.tera, "redeem.html.tera", &context);
        }
        Err(e) => {
            eprintln!("查询兑换码错误: {}", e);
            context.insert("error", "查询失败，请稍后重试");
            return render_template(&state.tera, "redeem.html.tera", &context);
        }
    };

    if code_record.is_used {
        context.insert("error", "该兑换码已被使用");
        return render_template(&state.tera, "redeem.html.tera", &context);
    }

    // 检查过期
    if let Some(ref exp) = code_record.expires_at {
        if exp.as_str() < chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string().as_str() {
            context.insert("error", "该兑换码已过期");
            return render_template(&state.tera, "redeem.html.tera", &context);
        }
    }

    match code_record.code_type.as_str() {
        "one_time" => {
            // 一次性兑换码 => 直接增加核时
            let _ = sqlx::query("UPDATE core_hour_codes SET is_used = 1, used_by = ?, used_at = datetime('now') WHERE id = ?")
                .bind(user.id)
                .bind(code_record.id)
                .execute(&state.db)
                .await;

            let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                .bind(code_record.amount)
                .bind(user.id)
                .execute(&state.db)
                .await;

            context.insert("success", &format!("兑换成功！获得 {:.1} 核时", code_record.amount));
        }
        "subscription" => {
            // 订阅码 => 创建订阅记录
            let valid_days = code_record.valid_days.unwrap_or(30);
            let starts_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let expires_at = (chrono::Utc::now() + chrono::Duration::days(valid_days))
                .format("%Y-%m-%d %H:%M:%S").to_string();

            let _ = sqlx::query("UPDATE core_hour_codes SET is_used = 1, used_by = ?, used_at = datetime('now') WHERE id = ?")
                .bind(user.id)
                .bind(code_record.id)
                .execute(&state.db)
                .await;

            let _ = sqlx::query(
                r#"INSERT INTO user_subscriptions (user_id, code_id, daily_amount, starts_at, expires_at, is_active)
                   VALUES (?, ?, ?, ?, ?, 1)"#,
            )
            .bind(user.id)
            .bind(code_record.id)
            .bind(code_record.daily_amount)
            .bind(&starts_at)
            .bind(&expires_at)
            .execute(&state.db)
            .await;

            context.insert("success", &format!(
                "订阅兑换成功！每日自动获得 {:.1} 核时，有效期 {} 天",
                code_record.daily_amount, valid_days
            ));
        }
        _ => {
            context.insert("error", "不支持的兑换码类型");
        }
    }

    render_template(&state.tera, "redeem.html.tera", &context)
}

/// GET /packages - 核时套餐页面
pub async fn packages_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = get_current_user(&state.db, &session).await.ok().flatten();
    if let Some(ref u) = user {
        context.insert("user", u);
    }

    let packages = match sqlx::query_as::<_, CoreHourPackage>(
        "SELECT * FROM core_hour_packages WHERE is_active = 1 ORDER BY price_ldc ASC",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("查询套餐列表错误: {}", e);
            Vec::new()
        }
    };

    context.insert("packages", &packages);

    render_template(&state.tera, "packages.html.tera", &context)
}

/// POST /packages/buy/{id} - 购买套餐
pub async fn buy_package(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let _user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // 查询套餐
    let package = match sqlx::query_as::<_, CoreHourPackage>(
        "SELECT * FROM core_hour_packages WHERE id = ? AND is_active = 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            context.insert("error", "套餐不存在或已下架");
            let packages = sqlx::query_as::<_, CoreHourPackage>(
                "SELECT * FROM core_hour_packages WHERE is_active = 1 ORDER BY price_ldc ASC",
            )
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            context.insert("packages", &packages);
            return render_template(&state.tera, "packages.html.tera", &context);
        }
        Err(e) => {
            eprintln!("查询套餐错误: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
        }
    };

    // 检查余额
    let user = match get_current_user(&state.db, &session).await {
        Ok(Some(u)) => u,
        _ => {
            context.insert("error", "获取用户信息失败");
            return render_template(&state.tera, "packages.html.tera", &context);
        }
    };

    if (user.core_hours as f64) < package.price_ldc {
        context.insert("error", &format!(
            "核时不足！需要 {:.1} 核时，当前余额 {:.1} 核时",
            package.price_ldc, user.core_hours
        ));
        let packages = sqlx::query_as::<_, CoreHourPackage>(
            "SELECT * FROM core_hour_packages WHERE is_active = 1 ORDER BY price_ldc ASC",
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        context.insert("packages", &packages);
        return render_template(&state.tera, "packages.html.tera", &context);
    }

    // 扣除核时
    let _ = sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ?")
        .bind(package.price_ldc)
        .bind(user.id)
        .execute(&state.db)
        .await;

    // 创建用户套餐记录
    let expires_at = match &package.package_type {
        typ if typ == "duration" => {
            let days = package.duration_days.unwrap_or(30);
            let exp = chrono::Utc::now() + chrono::Duration::days(days);
            Some(exp.format("%Y-%m-%d %H:%M:%S").to_string())
        }
        _ => None,
    };

    let _ = sqlx::query(
        r#"INSERT INTO user_packages (user_id, package_id, core_hours, expires_at, is_active)
           VALUES (?, ?, ?, ?, 1)"#,
    )
    .bind(user.id)
    .bind(package.id)
    .bind(package.core_hours)
    .bind(&expires_at)
    .execute(&state.db)
    .await;

    return Redirect::to("/packages?bought=1").into_response();
}

/// GET /sign-in - 签到页面
pub async fn sign_in_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // 查询今天是否已签到
    let signed_in_today = sqlx::query_as::<_, SignInRecord>(
        "SELECT * FROM sign_in_records WHERE user_id = ? AND date = ?",
    )
    .bind(user.id)
    .bind(&today)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .is_some();

    context.insert("signed_in_today", &signed_in_today);

    // 签到奖励核时
    let sign_in_hours: f64 = super::auth::get_setting(&state.db, "sign_in_core_hours")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(2.0);
    context.insert("sign_in_hours", &sign_in_hours);

    // 签到是否开启
    let sign_in_enabled: bool = super::auth::get_setting(&state.db, "sign_in_enabled")
        .await
        .map(|v| v == "1")
        .unwrap_or(true);
    context.insert("sign_in_enabled", &sign_in_enabled);

    render_template(&state.tera, "sign_in.html.tera", &context)
}

/// POST /sign-in - 执行签到
pub async fn sign_in(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    let user = match require_login(&state, &session, &mut context).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // 检查是否已签到
    let already = sqlx::query_as::<_, SignInRecord>(
        "SELECT * FROM sign_in_records WHERE user_id = ? AND date = ?",
    )
    .bind(user.id)
    .bind(&today)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .is_some();

    if already {
        context.insert("error", "今天已经签到过了！");
        context.insert("signed_in_today", &true);
        let sign_in_hours: f64 = super::auth::get_setting(&state.db, "sign_in_core_hours")
            .await.and_then(|v| v.parse().ok()).unwrap_or(2.0);
        context.insert("sign_in_hours", &sign_in_hours);
        context.insert("sign_in_enabled", &true);
        return render_template(&state.tera, "sign_in.html.tera", &context);
    }

    // 获取签到奖励
    let sign_in_hours: f64 = super::auth::get_setting(&state.db, "sign_in_core_hours")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(2.0);

    // 增加核时
    let _ = sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
        .bind(sign_in_hours)
        .bind(user.id)
        .execute(&state.db)
        .await;

    // 插入签到记录
    let _ = sqlx::query(
        "INSERT INTO sign_in_records (user_id, date, core_hours_awarded) VALUES (?, ?, ?)",
    )
    .bind(user.id)
    .bind(&today)
    .bind(sign_in_hours)
    .execute(&state.db)
    .await;

    context.insert("success", &format!("签到成功！获得 {:.1} 核时", sign_in_hours));
    context.insert("signed_in_today", &true);
    context.insert("sign_in_hours", &sign_in_hours);
    context.insert("sign_in_enabled", &true);

    render_template(&state.tera, "sign_in.html.tera", &context)
}

/// GET /payment/callback - 支付异步通知回调
pub async fn handle_payment_callback(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match crate::services::payment::process_payment_callback(
        &state.db,
        &params,
        &state.config,
    )
    .await
    {
        Ok(()) => "success".into_response(),
        Err(e) => {
            eprintln!("Payment callback error: {}", e);
            "fail".into_response()
        }
    }
}