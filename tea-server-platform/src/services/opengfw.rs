use crate::db;
use crate::models::{OpenGFWConfig, OpenGFWRule, OpenGFWRuleItem, OpenGFWLog, OpenGFWLogView};

/// Get OpenGFW enabled status for a server
pub async fn is_server_opengfw_enabled(server_id: i64) -> bool {
    let pool = db::get_db();
    let enabled: Option<bool> = sqlx::query_scalar("SELECT opengfw_enabled FROM servers WHERE id = ?")
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    enabled.unwrap_or(false)
}

/// Get all active OpenGFW rules from config
pub async fn get_active_rules() -> Vec<OpenGFWRuleItem> {
    let mut rules = Vec::new();

    // Check each protocol config
    let protocols = [
        ("shadowsocks", "opengfw_block_shadowsocks"),
        ("wireguard", "opengfw_block_wireguard"),
        ("openvpn", "opengfw_block_openvpn"),
        ("trojan", "opengfw_block_trojan"),
        ("vmess", "opengfw_block_vmess"),
        ("vless", "opengfw_block_vless"),
        ("xray", "opengfw_block_xray"),
        ("clash", "opengfw_block_clash"),
    ];

    for (protocol, config_key) in protocols {
        let enabled = db::get_config(config_key)
            .await
            .unwrap_or_else(|| "false".to_string());
        if enabled == "true" {
            rules.push(OpenGFWRuleItem {
                name: protocol.to_string(),
                protocol: protocol.to_string(),
                action: "block".to_string(),
            });
        }
    }

    rules
}

/// Get OpenGFW config for a specific server
pub async fn get_server_opengfw_config(server_id: i64) -> Option<OpenGFWConfig> {
    let pool = db::get_db();

    // Check if server has OpenGFW enabled
    let enabled = is_server_opengfw_enabled(server_id).await;
    if !enabled {
        return Some(OpenGFWConfig {
            enabled: false,
            rules: vec![],
        });
    }

    // Check global enabled flag
    let global_enabled = db::get_config("opengfw_enabled")
        .await
        .unwrap_or_else(|| "false".to_string());
    if global_enabled != "true" {
        return Some(OpenGFWConfig {
            enabled: false,
            rules: vec![],
        });
    }

    let rules = get_active_rules().await;

    Some(OpenGFWConfig {
        enabled: true,
        rules,
    })
}

/// Log a blocked connection
pub async fn log_blocked_connection(
    machine_id: i64,
    server_id: i64,
    protocol: &str,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    dst_port: Option<i32>,
) {
    let pool = db::get_db();
    let _ = sqlx::query(
        "INSERT INTO opengfw_logs (machine_id, server_id, protocol, src_ip, dst_ip, dst_port) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(machine_id)
    .bind(server_id)
    .bind(protocol)
    .bind(&src_ip)
    .bind(&dst_ip)
    .bind(dst_port)
    .execute(pool)
    .await;
}

/// Get recent blocked logs
pub async fn get_recent_logs(limit: i64) -> Vec<OpenGFWLogView> {
    let pool = db::get_db();

    let raw_logs: Vec<(i64, i64, i64, String, Option<String>, Option<String>, Option<i32>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
        SELECT id, machine_id, server_id, protocol, src_ip, dst_ip, dst_port, blocked_at
        FROM opengfw_logs
        ORDER BY blocked_at DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut logs = Vec::new();
    for (id, machine_id, server_id, protocol, src_ip, dst_ip, dst_port, blocked_at) in raw_logs {
        // Get server info
        let server_info: Option<(String, String)> = sqlx::query_as(
            "SELECT name, ip FROM servers WHERE id = ?"
        )
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

        // Get user info
        let machine_user_id: Option<(i64,)> = sqlx::query_as(
            "SELECT user_id FROM machines WHERE id = ?"
        )
        .bind(machine_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

        let username = if let Some((user_id,)) = machine_user_id {
            sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None)
                .unwrap_or_else(|| "Unknown".to_string())
        } else {
            "Unknown".to_string()
        };

        let (server_name, server_ip) = server_info.unwrap_or_else(|| ("Unknown".to_string(), "Unknown".to_string()));

        logs.push(OpenGFWLogView {
            id,
            machine_id,
            server_id,
            server_name,
            server_ip,
            username,
            protocol,
            src_ip,
            dst_ip,
            dst_port,
            blocked_at: blocked_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        });
    }

    logs
}

/// Get block statistics
pub async fn get_block_stats() -> (i64, Vec<(String, i64)>) {
    let pool = db::get_db();

    // Total blocked count
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM opengfw_logs")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    // Count by protocol
    let by_protocol: Vec<(String, i64)> = sqlx::query_as(
        "SELECT protocol, COUNT(*) FROM opengfw_logs GROUP BY protocol ORDER BY COUNT(*) DESC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    (total.0, by_protocol)
}

/// Initialize default OpenGFW rules
pub async fn init_default_rules() {
    let pool = db::get_db();

    let default_rules = vec![
        ("Shadowsocks", "Shadowsocks/SOCKS 代理协议", "shadowsocks"),
        ("WireGuard", "WireGuard VPN 协议", "wireguard"),
        ("OpenVPN", "OpenVPN 协议", "openvpn"),
        ("Trojan", "Trojan 代理协议", "trojan"),
        ("VMess", "VMess 代理协议", "vmess"),
        ("VLess", "VLess 代理协议", "vless"),
        ("Xray", "Xray 代理协议", "xray"),
        ("Clash", "Clash 代理协议", "clash"),
    ];

    for (name, description, protocol) in default_rules {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM opengfw_rules WHERE protocol = ?"
        )
        .bind(protocol)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

        if exists.is_none() {
            let _ = sqlx::query(
                "INSERT INTO opengfw_rules (name, description, protocol, action, is_active) VALUES (?, ?, ?, 'block', 1)"
            )
            .bind(name)
            .bind(description)
            .bind(protocol)
            .execute(pool)
            .await;
        }
    }
}
