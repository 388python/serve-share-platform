use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    http::StatusCode,
};
use reqwest::Client;
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;
use tower_sessions::Session;

use crate::models::User;
use crate::AppState;

// ========== LinuxDo OAuth 相关结构 ==========

#[derive(Debug, Deserialize)]
struct LdcTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LdcUserInfo {
    id: i64,
    username: String,
    name: Option<String>,
    email: Option<String>,
}

// ========== 请求参数 ==========

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

// ========== 辅助函数 ==========

/// 获取当前登录用户
pub async fn get_current_user(
    db: &SqlitePool,
    session: &Session,
) -> Result<Option<User>, sqlx::Error> {
    let user_id: Option<i64> = session.get("user_id").await.unwrap_or(None);
    match user_id {
        Some(id) => {
            let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
                .bind(id)
                .fetch_optional(db)
                .await?;
            Ok(user)
        }
        None => Ok(None),
    }
}

/// 获取设置值
pub async fn get_setting(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
}

/// 检查注册是否开放
pub async fn is_registration_open(pool: &SqlitePool) -> bool {
    get_setting(pool, "registration_open")
        .await
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// 验证邀请码
pub async fn verify_invite_code(pool: &SqlitePool, code: &str) -> Result<bool, sqlx::Error> {
    let code = sqlx::query_as::<_, (i64, i64)>(
        "SELECT id, is_used FROM invite_codes WHERE code = ?",
    )
    .bind(code)
    .fetch_optional(pool)
    .await?;

    match code {
        Some((_, 0)) => Ok(true),
        _ => Ok(false),
    }
}

/// 使用邀请码（标记为已使用）
pub async fn consume_invite_code(pool: &SqlitePool, code: &str, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE invite_codes SET is_used = 1, used_by = ? WHERE code = ?")
        .bind(user_id)
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

/// 奖励算力时间
pub async fn award_core_hours(pool: &SqlitePool, user_id: i64, hours: f64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
        .bind(hours)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ========== 路由处理器 ==========

/// 登录页面 - 显示 LinuxDo Connect 登录按钮
pub async fn login_page(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    // 如果已登录则跳转首页
    if let Ok(Some(_)) = get_current_user(&state.db, &session).await {
        return Redirect::to("/").into_response();
    }

    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    match state.tera.render("login.html.tera", &context) {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => {
            eprintln!("模板渲染错误: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("模板错误: {}", e),
            )
                .into_response()
        }
    }
}

/// GET /auth/login - 重定向到 LinuxDo OAuth 授权页
pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Query(invite): Query<InviteQuery>,
) -> impl IntoResponse {
    // 检查是否需要邀请码，如果需要则存入 session
    let invite_required = get_setting(&state.db, "invite_code_required")
        .await
        .map(|v| v == "1")
        .unwrap_or(false);

    if invite_required {
        if let Some(code) = &invite.invite_code {
            match verify_invite_code(&state.db, code).await {
                Ok(true) => {
                    let _ = session.insert("pending_invite_code", code.as_str()).await;
                }
                Ok(false) => {
                    return Redirect::to("/login?error=invalid_invite").into_response();
                }
                Err(e) => {
                    eprintln!("验证邀请码错误: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
                }
            }
        } else {
            return Redirect::to("/login?error=invite_required").into_response();
        }
    }

    // 生成 state 参数防 CSRF
    let oauth_state = uuid::Uuid::new_v4().to_string();
    let _ = session.insert("oauth_state", &oauth_state).await;

    let auth_url = format!(
        "https://connect.linux.do/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&state={}",
        state.config.linuxdo_client_id,
        urlencoding(&state.config.linuxdo_redirect_uri),
        oauth_state
    );

    Redirect::to(&auth_url).into_response()
}

#[derive(Debug, Deserialize)]
pub struct InviteQuery {
    pub invite_code: Option<String>,
}

/// GET /auth/callback - OAuth 回调处理
pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // 检查是否有错误
    if let Some(error) = &params.error {
        eprintln!("OAuth 错误: {} - {:?}", error, params.error_description);
        return Redirect::to("/login?error=oauth_denied").into_response();
    }

    let code = match &params.code {
        Some(c) => c.clone(),
        None => return Redirect::to("/login?error=no_code").into_response(),
    };

    // 验证 state
    let stored_state: Option<String> = session.get("oauth_state").await.unwrap_or(None);
    if let Some(expected_state) = stored_state {
        if params.state.as_deref() != Some(&expected_state) {
            return Redirect::to("/login?error=state_mismatch").into_response();
        }
    }

    // 清除 state
    let _ = session.remove::<String>("oauth_state").await;

    // 1. 用 code 换取 access_token
    let client = Client::new();
    let token_result = client
        .post("https://connect.linux.do/oauth2/token")
        .form(&[
            ("client_id", state.config.linuxdo_client_id.as_str()),
            ("client_secret", state.config.linuxdo_client_secret.as_str()),
            ("code", &code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", state.config.linuxdo_redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_resp = match token_result {
        Ok(resp) => match resp.json::<LdcTokenResponse>().await {
            Ok(data) => data,
            Err(e) => {
                eprintln!("解析 token 响应错误: {}", e);
                return Redirect::to("/login?error=token_parse").into_response();
            }
        },
        Err(e) => {
            eprintln!("获取 token 错误: {}", e);
            return Redirect::to("/login?error=token_request").into_response();
        }
    };

    // 2. 用 access_token 获取用户信息
    let user_result = client
        .get("https://connect.linux.do/api/user")
        .header("Authorization", format!("Bearer {}", token_resp.access_token))
        .send()
        .await;

    let ldc_user = match user_result {
        Ok(resp) => match resp.json::<LdcUserInfo>().await {
            Ok(data) => data,
            Err(e) => {
                eprintln!("解析用户信息错误: {}", e);
                return Redirect::to("/login?error=user_info").into_response();
            }
        },
        Err(e) => {
            eprintln!("获取用户信息错误: {}", e);
            return Redirect::to("/login?error=user_info_request").into_response();
        }
    };

    // 3. 查找或创建用户
    let existing_user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE linuxdo_id = ?",
    )
    .bind(ldc_user.id)
    .fetch_optional(&state.db)
    .await;

    let user = match existing_user {
        Ok(Some(user)) => {
            // 用户已存在
            if user.is_banned {
                return Redirect::to("/login?error=banned").into_response();
            }

            // 更新用户名和邮箱（可能已变更）
            let username = ldc_user.name.as_deref().unwrap_or(&ldc_user.username);
            let _ = sqlx::query(
                "UPDATE users SET username = ?, email = ?, updated_at = datetime('now') WHERE id = ?",
            )
            .bind(username)
            .bind(&ldc_user.email)
            .bind(user.id)
            .execute(&state.db)
            .await;

            user
        }
        Ok(None) => {
            // 新用户 - 检查注册是否开放
            if !is_registration_open(&state.db).await {
                return Redirect::to("/login?error=registration_closed").into_response();
            }

            // 检查邀请码
            let invite_required = get_setting(&state.db, "invite_code_required")
                .await
                .map(|v| v == "1")
                .unwrap_or(false);

            let pending_invite: Option<String> = session
                .get("pending_invite_code")
                .await
                .unwrap_or(None);

            if invite_required {
                match pending_invite {
                    Some(ref code) => {
                        match verify_invite_code(&state.db, code).await {
                            Ok(true) => {}
                            Ok(false) => {
                                return Redirect::to("/login?error=invalid_invite").into_response();
                            }
                            Err(_) => {
                                return Redirect::to("/login?error=invite_error").into_response();
                            }
                        }
                    }
                    None => {
                        return Redirect::to("/login?error=invite_required").into_response();
                    }
                }
            }

            let username = ldc_user.name.as_deref().unwrap_or(&ldc_user.username);
            let email = ldc_user.email.as_deref().unwrap_or("");

            let result = sqlx::query(
                r#"INSERT INTO users (linuxdo_id, username, email)
                   VALUES (?, ?, ?)"#,
            )
            .bind(ldc_user.id)
            .bind(username)
            .bind(email)
            .execute(&state.db)
            .await;

            let user_id = match result {
                Ok(r) => r.last_insert_rowid(),
                Err(e) => {
                    eprintln!("创建用户错误: {}", e);
                    return Redirect::to("/login?error=create_user").into_response();
                }
            };

            // 领取邀请码
            if let Some(ref code) = pending_invite {
                let _ = consume_invite_code(&state.db, code, user_id).await;
                let _ = session.remove::<String>("pending_invite_code").await;
            }

            // 奖励新用户算力时间
            let new_user_hours: f64 = get_setting(&state.db, "new_user_core_hours")
                .await
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);

            if new_user_hours > 0.0 {
                let _ = award_core_hours(&state.db, user_id, new_user_hours).await;
            }

            // 重新获取完整用户信息
            match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(&state.db)
                .await
            {
                Ok(Some(u)) => u,
                _ => return Redirect::to("/login?error=user_not_found").into_response(),
            }
        }
        Err(e) => {
            eprintln!("查询用户错误: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误").into_response();
        }
    };

    // 4. 设置 Session
    let _ = session.insert("user_id", user.id).await;

    // 如果是管理员则设置标记
    if user.is_admin {
        let _ = session.insert("is_admin", "1").await;
    }

    Redirect::to("/").into_response()
}

/// GET /auth/logout - 清除 session 并跳转到首页
pub async fn logout(session: Session) -> impl IntoResponse {
    let _ = session.clear().await;
    Redirect::to("/").into_response()
}

/// URL 编码辅助函数
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