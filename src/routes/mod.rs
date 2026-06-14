pub mod admin;
pub mod api;
pub mod auth;
pub mod user;

use axum::{extract::State, response::IntoResponse};
use tera::Context;
use tower_sessions::Session;

use crate::AppState;

pub async fn index(
    State(state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("site_name", &state.config.site_name);

    // 加载当前用户信息
    if let Ok(Some(user)) = auth::get_current_user(&state.db, &session).await {
        context.insert("user", &user);
    }

    match state.tera.render("index.html.tera", &context) {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => {
            eprintln!("模板渲染错误: {}", e);
            axum::response::Html(format!(
                "<h1>{} - 模板错误</h1><pre>{}</pre>",
                state.config.site_name, e
            ))
            .into_response()
        }
    }
}