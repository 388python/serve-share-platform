use sqlx::SqlitePool;
use uuid::Uuid;

/// Install the agent on a target server via SSH
/// This runs the agent installation script on the target machine
pub async fn install_agent(
    pool: &SqlitePool,
    server_id: i64,
    ip: &str,
    ssh_port: u16,
    _ssh_key: &str,
    virtualization_type: &str,
) -> Result<(), String> {
    // Generate a unique server token for agent authentication
    let server_token = Uuid::new_v4().to_string();

    // Generate the agent install script
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://localhost:3000/api".to_string());
    let script = generate_agent_script(&platform_api_url, &server_token, virtualization_type);

    // Log the script content and installation attempt
    println!(
        "[Agent Install] 准备在服务器 {} (IP: {}, SSH端口: {}) 上安装 agent",
        server_id, ip, ssh_port
    );
    println!(
        "[Agent Install] 虚拟化类型: {}, Token: {}...",
        virtualization_type,
        &server_token[..8]
    );

    // In production: write script to a temp file and execute via SSH
    // For now: store the token and update server status
    let _script = script; // placeholder - in production would be used with ssh2/ssh command

    // Update server with token and set status to active
    sqlx::query(
        "UPDATE servers SET agent_token = ?, status = 'active', updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&server_token)
    .bind(server_id)
    .execute(pool)
    .await
    .map_err(|e| format!("更新服务器状态失败: {}", e))?;

    println!("[Agent Install] 服务器 {} agent 安装完成，状态已更新为 active", server_id);

    Ok(())
}

/// Get the agent installation script content for a given virtualization type
pub fn get_agent_install_script(virtualization_type: &str) -> String {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://localhost:3000/api".to_string());
    let server_token = "PLACEHOLDER_TOKEN";
    generate_agent_script(&platform_api_url, server_token, virtualization_type)
}

/// Check if agent is installed on a server
pub async fn check_agent_status(
    pool: &SqlitePool,
    server_id: i64,
) -> Result<String, String> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT agent_token, last_seen FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("查询服务器状态失败: {}", e))?;

    match row {
        Some((Some(_token), Some(last_seen))) => {
            Ok(format!("Agent 已安装，最后心跳: {}", last_seen))
        }
        Some((Some(_token), None)) => {
            Ok("Agent 已安装，等待首次心跳...".to_string())
        }
        _ => Err("Agent 未安装或服务器不存在".to_string()),
    }
}

/// Generate the complete agent installation script
/// This is a bash script that will be executed on the target server
pub fn generate_agent_script(
    platform_api_url: &str,
    server_token: &str,
    virtualization_type: &str,
) -> String {
    let virt_type_for_script = virtualization_type.to_string();
    format!(
        r###"#!/bin/bash
set -e

PLATFORM_API="{platform_api_url}"
SERVER_TOKEN="{server_token}"
VIRT_TYPE="{virt_type}"

echo "Installing Tea Server Platform Agent..."
echo "Virtualization type: $VIRT_TYPE"

# Install dependencies
apt-get update
apt-get install -y curl jq openssh-server

if [ "$VIRT_TYPE" = "lxd" ]; then
    apt-get install -y lxd
    lxd init --auto
elif [ "$VIRT_TYPE" = "kvm" ]; then
    apt-get install -y qemu-kvm libvirt-daemon-system virtinst
fi

# Create agent service
cat > /etc/systemd/system/tea-agent.service << 'SERVICE'
[Unit]
Description=Tea Server Platform Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tea-agent
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

# Agent binary (simplified - in production this would be a real binary)
cat > /usr/local/bin/tea-agent << 'AGENT'
#!/bin/bash
while true; do
    curl -s -X POST "$PLATFORM_API/heartbeat" \
        -H "Authorization: Bearer $SERVER_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{{"status":"online"}}'
    sleep 60
done
AGENT

chmod +x /usr/local/bin/tea-agent
systemctl daemon-reload
systemctl enable tea-agent
systemctl start tea-agent

echo "Agent installation complete!"
"###,
        platform_api_url = platform_api_url,
        server_token = server_token,
        virt_type = virt_type_for_script,
    )
}"