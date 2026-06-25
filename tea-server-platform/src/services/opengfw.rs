use crate::db;
use crate::models::{OpenGFWConfig, OpenGFWRule, OpenGFWRuleItem, OpenGFWLogView, OpenGFWRuleTemplate};

/// Protocol templates with their signatures
const PROTOCOL_TEMPLATES: &[(&str, &str, &str)] = &[
    ("shadowsocks", "Shadowsocks", "shadowsocks"),
    ("wireguard", "WireGuard VPN", "wireguard"),
    ("openvpn", "OpenVPN", "openvpn"),
    ("trojan", "Trojan Proxy", "trojan"),
    ("vmess", "VMess Protocol", "vmess"),
    ("vless", "VLess Protocol", "vless"),
    ("xray", "Xray Protocol", "xray"),
    ("clash", "Clash Proxy", "clash"),
    ("l2tp", "L2TP/IPSec", "l2tp"),
    ("ipsec", "IPSec VPN", "ipsec"),
    ("sstp", "SSTP VPN", "sstp"),
    ("wireguard-udp", "WireGuard (UDP)", "wireguard-udp"),
];

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

/// Get all active OpenGFW rules from database
pub async fn get_active_rules() -> Vec<OpenGFWRuleItem> {
    let pool = db::get_db();
    
    let rules: Vec<OpenGFWRule> = sqlx::query_as(
        "SELECT id, name, description, protocol, match_signature, action, is_active, created_at FROM opengfw_rules WHERE is_active = 1"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rules.into_iter().map(|rule| {
        OpenGFWRuleItem {
            id: Some(rule.id),
            name: rule.name,
            protocol: rule.protocol,
            match_signature: rule.match_signature,
            action: rule.action,
        }
    }).collect()
}

/// Get all rules (active and inactive)
pub async fn get_all_rules() -> Vec<OpenGFWRule> {
    let pool = db::get_db();
    
    sqlx::query_as(
        "SELECT id, name, description, protocol, match_signature, action, is_active, created_at FROM opengfw_rules ORDER BY id ASC"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Add a new custom rule
pub async fn add_rule(
    name: String,
    description: String,
    protocol: String,
    match_signature: String,
    action: String,
) -> Result<i64, String> {
    let pool = db::get_db();
    
    let result = sqlx::query(
        "INSERT INTO opengfw_rules (name, description, protocol, match_signature, action, is_active) VALUES (?, ?, ?, ?, ?, 1)"
    )
    .bind(&name)
    .bind(&description)
    .bind(&protocol)
    .bind(&match_signature)
    .bind(&action)
    .execute(pool)
    .await;

    match result {
        Ok(r) => Ok(r.last_insert_rowid()),
        Err(e) => Err(e.to_string())
    }
}

/// Update an existing rule
pub async fn update_rule(
    rule_id: i64,
    name: String,
    description: String,
    protocol: String,
    match_signature: String,
    action: String,
    is_active: bool,
) -> Result<(), String> {
    let pool = db::get_db();
    
    let result = sqlx::query(
        "UPDATE opengfw_rules SET name = ?, description = ?, protocol = ?, match_signature = ?, action = ?, is_active = ? WHERE id = ?"
    )
    .bind(&name)
    .bind(&description)
    .bind(&protocol)
    .bind(&match_signature)
    .bind(&action)
    .bind(is_active)
    .bind(rule_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string())
    }
}

/// Delete a rule
pub async fn delete_rule(rule_id: i64) -> Result<(), String> {
    let pool = db::get_db();
    
    let result = sqlx::query("DELETE FROM opengfw_rules WHERE id = ?")
    .bind(rule_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string())
    }
}

/// Toggle rule active status
pub async fn toggle_rule(rule_id: i64, active: bool) -> Result<(), String> {
    let pool = db::get_db();
    
    let result = sqlx::query("UPDATE opengfw_rules SET is_active = ? WHERE id = ?")
    .bind(active)
    .bind(rule_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string())
    }
}

/// Get rule templates for quick setup
pub fn get_rule_templates() -> Vec<OpenGFWRuleTemplate> {
    PROTOCOL_TEMPLATES.iter().map(|(protocol, name, desc)| {
        let signature = get_protocol_signature(protocol);
        OpenGFWRuleTemplate {
            protocol: protocol.to_string(),
            name: name.to_string(),
            description: desc.to_string(),
            default_signature: signature,
        }
    }).collect()
}

/// Get protocol signature for OpenGFW matching
fn get_protocol_signature(protocol: &str) -> String {
    match protocol {
        "shadowsocks" => "payload,56,0,0,0,0,0,0,0,0,6,0xff,0x17".to_string(),
        "wireguard" => "payload,0,0,0,0,0,0,0,0,0,17,0,51820".to_string(),
        "openvpn" => "payload,0,0,0,0,0,0,0,0,0,6,0,1194".to_string(),
        "trojan" => "payload,0,0,0,0,0,0,0,0,0,6,0,443".to_string(),
        "vmess" => "payload,0,0,0,0,0,0,0,0,0,6,0,80".to_string(),
        "vless" => "payload,0,0,0,0,0,0,0,0,0,6,0,80".to_string(),
        "xray" => "payload,0,0,0,0,0,0,0,0,0,6,0,80".to_string(),
        "clash" => "payload,0,0,0,0,0,0,0,0,0,6,0,7890".to_string(),
        "l2tp" => "payload,0,0,0,0,0,0,0,0,0,6,0,1701".to_string(),
        "ipsec" => "payload,0,0,0,0,0,0,0,0,0,6,0,500".to_string(),
        "sstp" => "payload,0,0,0,0,0,0,0,0,0,6,0,443".to_string(),
        "wireguard-udp" => "payload,0,0,0,0,0,0,0,0,0,17,0,51820".to_string(),
        _ => String::new(),
    }
}

/// Get OpenGFW config for a specific server
pub async fn get_server_opengfw_config(server_id: i64) -> Option<OpenGFWConfig> {
    let enabled = is_server_opengfw_enabled(server_id).await;
    if !enabled {
        return Some(OpenGFWConfig {
            enabled: false,
            rules: vec![],
        });
    }

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

/// Log a blocked connection (预留)
#[allow(dead_code)]
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

/// Get recent blocked logs with pagination and filters
pub async fn get_recent_logs(
    limit: i64,
    offset: i64,
    server_id: Option<i64>,
    protocol: Option<String>,
    username: Option<String>,
) -> Vec<OpenGFWLogView> {
    let pool = db::get_db();

    let mut query = String::from(
        r#"
        SELECT l.id, l.machine_id, l.server_id, l.protocol, l.src_ip, l.dst_ip, l.dst_port, l.blocked_at
        FROM opengfw_logs l
        WHERE 1=1
        "#
    );

    if server_id.is_some() {
        query.push_str(" AND l.server_id = ? ");
    }
    if protocol.is_some() {
        query.push_str(" AND l.protocol = ? ");
    }
    if username.is_some() {
        query.push_str(" AND EXISTS (SELECT 1 FROM machines m JOIN users u ON m.user_id = u.id WHERE m.id = l.machine_id AND u.username LIKE ?) ");
    }

    query.push_str(" ORDER BY l.blocked_at DESC LIMIT ? OFFSET ? ");

    let mut query_builder = sqlx::query_as::<_, (i64, i64, i64, String, Option<String>, Option<String>, Option<i32>, chrono::DateTime<chrono::Utc>)>(&query);

    if let Some(sid) = server_id {
        query_builder = query_builder.bind(sid);
    }
    if let Some(ref p) = protocol {
        query_builder = query_builder.bind(p);
    }
    if let Some(ref u) = username {
        query_builder = query_builder.bind(format!("%{}%", u));
    }

    query_builder = query_builder.bind(limit).bind(offset);

    let raw_logs = query_builder
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let mut logs = Vec::new();
    for (id, machine_id, server_id, protocol, src_ip, dst_ip, dst_port, blocked_at) in raw_logs {
        let server_info: Option<(String, String)> = sqlx::query_as(
            "SELECT name, ip FROM servers WHERE id = ?"
        )
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

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

/// Get block statistics with more details
pub async fn get_block_stats(
    start_time: Option<String>,
    end_time: Option<String>,
    server_id: Option<i64>,
) -> (i64, Vec<(String, i64)>, Vec<(String, i64)>) {
    let pool = db::get_db();

    let mut where_clause = String::from("1=1");
    
    if let Some(ref start) = start_time {
        where_clause.push_str(&format!(" AND blocked_at >= '{}'", start));
    }
    if let Some(ref end) = end_time {
        where_clause.push_str(&format!(" AND blocked_at <= '{}'", end));
    }
    if let Some(sid) = server_id {
        where_clause.push_str(&format!(" AND server_id = {}", sid));
    }

    let total: i64 = sqlx::query_scalar::<_, i64>(
        &format!("SELECT COUNT(*) FROM opengfw_logs WHERE {}", where_clause)
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let by_protocol: Vec<(String, i64)> = sqlx::query_as(
        &format!(
            "SELECT protocol, COUNT(*) FROM opengfw_logs WHERE {} GROUP BY protocol ORDER BY COUNT(*) DESC",
            where_clause
        )
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let by_server: Vec<(String, i64)> = sqlx::query_as(
        &format!(
            r#"
            SELECT COALESCE(s.name, 'Unknown'), COUNT(*) 
            FROM opengfw_logs l 
            LEFT JOIN servers s ON l.server_id = s.id 
            WHERE {} 
            GROUP BY l.server_id 
            ORDER BY COUNT(*) DESC"#,
            where_clause
        )
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    (total, by_protocol, by_server)
}

/// Get hourly statistics for charts
pub async fn get_hourly_stats(hours: i64) -> Vec<(String, i64)> {
    let pool = db::get_db();
    
    let stats: Vec<(String, i64)> = sqlx::query_as(
        &format!(
            r#"
            SELECT strftime('%Y-%m-%d %H:00', blocked_at) as hour, COUNT(*)
            FROM opengfw_logs
            WHERE blocked_at >= datetime('now', '-{} hours')
            GROUP BY hour
            ORDER BY hour ASC
            "#,
            hours
        )
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    stats
}

/// Get top users by blocked connections
pub async fn get_top_users(limit: i64) -> Vec<(String, i64)> {
    let pool = db::get_db();

    sqlx::query_as(
        r#"
        SELECT COALESCE(u.username, 'Unknown'), COUNT(*) as cnt
        FROM opengfw_logs l
        JOIN machines m ON l.machine_id = m.id
        JOIN users u ON m.user_id = u.id
        GROUP BY u.id
        ORDER BY cnt DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Initialize default OpenGFW rules (预留)
#[allow(dead_code)]
pub async fn init_default_rules() {
    let pool = db::get_db();

    let existing_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM opengfw_rules")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    if existing_count.0 > 0 {
        return;
    }

    for (name, description, protocol) in PROTOCOL_TEMPLATES {
        let signature = get_protocol_signature(protocol);
        let _ = sqlx::query(
            "INSERT INTO opengfw_rules (name, description, protocol, match_signature, action, is_active) VALUES (?, ?, ?, ?, 'block', 1)"
        )
        .bind(*name)
        .bind(format!("{} 协议", description))
        .bind(*protocol)
        .bind(&signature)
        .execute(pool)
        .await;
    }
}
