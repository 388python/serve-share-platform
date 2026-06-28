use crate::services::mail::build_html_template;

pub struct MailNotification {
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

pub fn warning_letter_notice(site_name: &str, username: &str, subject: &str, content: &str, letter_id: i64) -> MailNotification {
    let subject_line = format!("[{}] 新警告信：{}", site_name, subject);
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        您收到了一封新的警告信。\n\n\
        标题：{subject}\n\
        内容：{content}\n\n\
        请登录 {site_name} 查看详情并及时处理。\n\n\
        —— {site_name} 系统",
        username = username,
        subject = subject,
        content = content,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <p>您收到了一封新的警告信，请及时处理。</p>
            <div class="alert-warning">
                <strong>{subject}</strong>
            </div>
            <p style="white-space: pre-wrap;">{content}</p>
            <p>
                <a href="/warnings/{letter_id}" class="btn">查看详情</a>
            </p>"#,
        username = username,
        subject = subject,
        content = html_escape(content),
        letter_id = letter_id
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn account_banned_notice(site_name: &str, username: &str, reason: &str) -> MailNotification {
    let subject_line = format!("[{}] 账户被封禁通知", site_name);
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        很遗憾地通知您，您的账户已被封禁。\n\n\
        封禁原因：{reason}\n\n\
        如有疑问，请联系管理员。\n\n\
        —— {site_name} 系统",
        username = username,
        reason = reason,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <div class="alert-danger">
                <strong>您的账户已被封禁</strong>
            </div>
            <p><strong>封禁原因：</strong>{reason}</p>
            <p>如有疑问，请联系管理员进行申诉。</p>"#,
        username = username,
        reason = html_escape(reason)
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn account_unbanned_notice(site_name: &str, username: &str) -> MailNotification {
    let subject_line = format!("[{}] 账户已解封通知", site_name);
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        您的账户已被解封，现在可以正常使用了。\n\n\
        请遵守平台规则，合理使用资源。\n\n\
        —— {site_name} 系统",
        username = username,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <div class="alert-info">
                <strong>您的账户已解封</strong>
            </div>
            <p>您的账户现已恢复正常使用，请遵守平台规则，合理使用资源。</p>"#,
        username = username
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn machine_status_changed_notice(
    site_name: &str,
    username: &str,
    machine_id: i64,
    old_status: &str,
    new_status: &str,
    reason: &str,
) -> MailNotification {
    let new_status_cn = status_cn(new_status);
    let subject_line = format!("[{}] 机器 #{} 状态变更：{}", site_name, machine_id, new_status_cn);
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        您的机器 #{machine_id} 状态已由管理员变更。\n\n\
        原状态：{old_status}\n\
        新状态：{new_status_cn}\n\
        变更原因：{reason}\n\n\
        请登录 {site_name} 查看详情。\n\n\
        —— {site_name} 系统",
        username = username,
        machine_id = machine_id,
        old_status = status_cn(old_status),
        new_status_cn = new_status_cn,
        reason = reason,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <p>您的机器 <strong>#{machine_id}</strong> 状态已由管理员变更。</p>
            <div class="alert-info">
                <table>
                    <tr><td>原状态：</td><td>{old_status_cn}</td></tr>
                    <tr><td>新状态：</td><td><strong>{new_status_cn}</strong></td></tr>
                    <tr><td>变更原因：</td><td>{reason}</td></tr>
                </table>
            </div>
            <p>
                <a href="/machines/{machine_id}" class="btn">查看机器详情</a>
            </p>"#,
        username = username,
        machine_id = machine_id,
        old_status_cn = status_cn(old_status),
        new_status_cn = new_status_cn,
        reason = html_escape(reason),
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn dispute_created_notice(
    site_name: &str,
    admin_username: &str,
    machine_id: i64,
    username: &str,
    reason: &str,
) -> MailNotification {
    let subject_line = format!("[{}] 新争议：机器 #{}", site_name, machine_id);
    let text_body = format!(
        "管理员 {admin_username}：\n\n\
        用户 {username} 对机器 #{machine_id} 发起了新的争议。\n\n\
        争议原因：{reason}\n\n\
        请登录 {site_name} 后台查看并处理。\n\n\
        —— {site_name} 系统",
        admin_username = admin_username,
        username = username,
        machine_id = machine_id,
        reason = reason,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>管理员 <strong>{admin_username}</strong>：</p>
            <div class="alert-warning">
                <strong>新争议提交</strong>
            </div>
            <table>
                <tr><td>机器：</td><td>#{machine_id}</td></tr>
                <tr><td>用户：</td><td>{username}</td></tr>
                <tr><td>原因：</td><td>{reason}</td></tr>
            </table>
            <p>
                <a href="/admin/disputes" class="btn">前往处理</a>
            </p>"#,
        admin_username = admin_username,
        username = username,
        machine_id = machine_id,
        reason = html_escape(reason),
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn dispute_resolved_notice(
    site_name: &str,
    username: &str,
    machine_id: i64,
    result: &str,
    resolution: &str,
) -> MailNotification {
    let subject_line = format!("[{}] 争议已处理：机器 #{}", site_name, machine_id);
    let result_cn = if result == "upheld" { "成立" } else { "不成立" };
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        您针对机器 #{machine_id} 发起的争议已处理完成。\n\n\
        处理结果：{result_cn}\n\
        处理说明：{resolution}\n\n\
        请登录 {site_name} 查看详情。\n\n\
        —— {site_name} 系统",
        username = username,
        machine_id = machine_id,
        result_cn = result_cn,
        resolution = resolution,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <div class="alert-info">
                <strong>争议处理完成</strong>
            </div>
            <table>
                <tr><td>机器：</td><td>#{machine_id}</td></tr>
                <tr><td>处理结果：</td><td><strong>{result_cn}</strong></td></tr>
                <tr><td>处理说明：</td><td>{resolution}</td></tr>
            </table>
            <p>
                <a href="/machines/{machine_id}" class="btn">查看机器</a>
            </p>"#,
        username = username,
        machine_id = machine_id,
        result_cn = result_cn,
        resolution = html_escape(resolution),
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

pub fn dispute_intervened_notice(
    site_name: &str,
    username: &str,
    machine_id: i64,
) -> MailNotification {
    let subject_line = format!("[{}] 争议平台介入：机器 #{}", site_name, machine_id);
    let text_body = format!(
        "亲爱的 {username}：\n\n\
        您针对机器 #{machine_id} 发起的争议已由平台介入处理。\n\n\
        我们正在核实情况，请耐心等待处理结果。\n\n\
        —— {site_name} 系统",
        username = username,
        machine_id = machine_id,
        site_name = site_name
    );
    let html_content = format!(
        r#"            <p>亲爱的 <strong>{username}</strong>：</p>
            <div class="alert-warning">
                <strong>平台已介入处理</strong>
            </div>
            <p>您针对机器 <strong>#{machine_id}</strong> 发起的争议已由平台介入，我们正在核实情况，请耐心等待处理结果。</p>"#,
        username = username,
        machine_id = machine_id,
    );
    let html_body = build_html_template(&subject_line, &html_content, site_name);
    MailNotification {
        subject: subject_line,
        html_body,
        text_body,
    }
}

fn status_cn(status: &str) -> String {
    match status {
        "running" => "运行中".to_string(),
        "stopped" => "已停止".to_string(),
        "pending" => "创建中".to_string(),
        "failed" => "创建失败".to_string(),
        "suspended" => "已暂停".to_string(),
        "deleted" => "已删除".to_string(),
        _ => status.to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
