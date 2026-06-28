use crate::db;
use anyhow::{Context, Result};
use lettre::{
    message::{Message, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_name: String,
    pub from_email: String,
    pub plain_domains: Vec<String>,
}

impl MailConfig {
    pub async fn load() -> Self {
        let enabled = db::get_config("mail_enabled")
            .await
            .unwrap_or_else(|| "0".to_string())
            == "1";
        let host = db::get_config("mail_smtp_host")
            .await
            .unwrap_or_default();
        let port = db::get_config("mail_smtp_port")
            .await
            .unwrap_or_else(|| "465".to_string())
            .parse::<u16>()
            .unwrap_or(465);
        let username = db::get_config("mail_username")
            .await
            .unwrap_or_default();
        let password = db::get_config("mail_password")
            .await
            .unwrap_or_default();
        let from_name = db::get_config("mail_from_name")
            .await
            .unwrap_or_else(|| "通知".to_string());
        let from_email = db::get_config("mail_from_email")
            .await
            .unwrap_or_default();
        let plain_domains_str = db::get_config("mail_plain_domains")
            .await
            .unwrap_or_default();
        let plain_domains = plain_domains_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            enabled,
            host,
            port,
            username,
            password,
            from_name,
            from_email,
            plain_domains,
        }
    }

    pub fn is_plain_domain(&self, email: &str) -> bool {
        let domain = email
            .split('@')
            .last()
            .unwrap_or("")
            .to_lowercase();
        self.plain_domains
            .iter()
            .any(|d| domain.ends_with(&d.to_lowercase()))
    }
}

pub async fn send_mail(to: &str, subject: &str, html_body: &str, text_body: &str) -> Result<()> {
    let config = MailConfig::load().await;
    if !config.enabled {
        tracing::debug!("Mail disabled, skipping send to {}", to);
        return Ok(());
    }
    if config.host.is_empty() || config.username.is_empty() {
        tracing::warn!("Mail config incomplete, skipping send");
        return Ok(());
    }

    let from_addr = if config.from_email.is_empty() {
        &config.username
    } else {
        &config.from_email
    };

    let email = Message::builder()
        .from(
            format!("{} <{}>", config.from_name, from_addr)
                .parse()
                .with_context(|| format!("invalid from address: {}", from_addr))?,
        )
        .to(to.parse().with_context(|| format!("invalid to address: {}", to))?)
        .subject(subject);

    let email = if config.is_plain_domain(to) {
        email
            .singlepart(SinglePart::plain(text_body.to_string()))
            .context("failed to build plain text email")?
    } else {
        email
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text_body.to_string()))
                    .singlepart(SinglePart::html(html_body.to_string())),
            )
            .context("failed to build multipart email")?
    };

    let creds = Credentials::new(config.username.clone(), config.password.clone());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        .with_context(|| format!("invalid SMTP host: {}", config.host))?
        .port(config.port)
        .credentials(creds)
        .build();

    mailer.send(email).await.context("failed to send email")?;

    tracing::info!(to = to, subject = subject, "email sent");
    Ok(())
}

pub fn send_mail_async(to: String, subject: String, html_body: String, text_body: String) {
    tokio::spawn(async move {
        match send_mail(&to, &subject, &html_body, &text_body).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(to = to, error = %e, "failed to send email");
            }
        }
    });
}

pub fn build_html_template(title: &str, content: &str, site_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header {{ background: #4f46e5; color: #fff; padding: 24px 32px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 20px; font-weight: 600; }}
        .content {{ padding: 32px; line-height: 1.7; color: #333; }}
        .content p {{ margin: 0 0 16px; }}
        .footer {{ padding: 20px 32px; background: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 8px 8px; color: #6b7280; font-size: 14px; text-align: center; }}
        .btn {{ display: inline-block; padding: 10px 24px; background: #4f46e5; color: #fff !important; text-decoration: none; border-radius: 6px; font-weight: 500; }}
        .alert-info {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px 16px; margin: 16px 0; color: #1e40af; }}
        .alert-warning {{ background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; margin: 16px 0; color: #92400e; }}
        .alert-danger {{ background: #fee2e2; border-left: 4px solid #ef4444; padding: 12px 16px; margin: 16px 0; color: #991b1b; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
        </div>
        <div class="content">
{content}
        </div>
        <div class="footer">
            此邮件由 {site_name} 自动发送，请勿直接回复。
        </div>
    </div>
</body>
</html>"#,
        title = title,
        content = content,
        site_name = site_name
    )
}
