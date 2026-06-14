use crate::db;
use tracing;

/// Known VPN protocol ports and signatures to detect
const VPN_PORTS: &[u16] = &[
    1080,  // SOCKS
    8388,  // Shadowsocks
    51820, // WireGuard
    1194,  // OpenVPN
    500, 4500, // IPsec/IKE
    1701, // L2TP
    1723, // PPTP
];

/// Known VPN process names / signatures
const VPN_PROCESS_SIGNATURES: &[&str] = &[
    "shadowsocks", "ss-server", "ss-local",
    "v2ray", "xray", "vmess", "vless",
    "trojan", "trojan-go",
    "hysteria", "tuic",
    "wireguard", "wg-quick",
    "openvpn",
    "clash", "mihomo",
    "sing-box",
    "naiveproxy",
    "brook",
    "gost",
    "iperf3", "iperf",  // bandwidth testing tools often abused
    "speedtest",
];

/// Check if a machine is running VPN-like traffic by querying the agent API.
pub async fn detect_vpn_traffic(_machine_id: i64, server_ip: &str) -> Vec<String> {
    // Query the agent for listening ports and processes
    let agent_url = format!("http://{}:19527", server_ip);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut alerts = Vec::new();

    // Check listening ports
    if let Ok(resp) = client
        .get(&format!("{}/ports", agent_url))
        .header("X-API-Key", "tea-platform-agent-key")
        .send()
        .await
    {
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            if let Some(ports) = body.get("listening_ports").and_then(|v| v.as_array()) {
                for port_info in ports {
                    if let Some(port) = port_info.get("port").and_then(|v| v.as_u64()) {
                        let port_u16 = port as u16;
                        if port_u16 != 22 && port_u16 != 19527 {
                            // Check against known VPN ports
                            if VPN_PORTS.contains(&port_u16) {
                                alerts.push(format!(
                                    "检测到疑似 VPN 监听端口: {} (协议特征: 匹配已知 VPN 端口)",
                                    port_u16
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check running processes for VPN signatures
    if let Ok(resp) = client
        .get(&format!("{}/processes", agent_url))
        .header("X-API-Key", "tea-platform-agent-key")
        .send()
        .await
    {
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            if let Some(procs) = body.get("processes").and_then(|v| v.as_array()) {
                for proc_info in procs {
                    if let Some(name) = proc_info.get("name").and_then(|v| v.as_str()) {
                        let name_lower = name.to_lowercase();
                        for sig in VPN_PROCESS_SIGNATURES {
                            if name_lower.contains(sig) {
                                alerts.push(format!(
                                    "检测到疑似 VPN 进程: {} (匹配签名: {})",
                                    name, sig
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    alerts
}

/// Check if a machine exceeds bandwidth threshold by querying the agent
pub async fn check_bandwidth_abuse(machine_id: i64, server_ip: &str) -> Option<f64> {
    let threshold_str = db::get_config("traffic_bandwidth_threshold_mbps")
        .await
        .unwrap_or_else(|| "100".to_string());
    let threshold: f64 = threshold_str.parse().unwrap_or(100.0);

    let agent_url = format!("http://{}:19527", server_ip);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Query agent for current bandwidth usage
    if let Ok(resp) = client
        .get(&format!("{}/traffic/{}", agent_url, machine_id))
        .header("X-API-Key", "tea-platform-agent-key")
        .send()
        .await
    {
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            let current_mbps = body
                .get("bandwidth_mbps")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            if current_mbps > threshold {
                return Some(current_mbps);
            }
        }
    }

    None
}

/// Run a full traffic scan for a machine
pub async fn scan_machine_traffic(machine_id: i64, server_ip: &str) -> Vec<String> {
    let mut alerts = Vec::new();

    // Check VPN traffic
    let vpn_alerts = detect_vpn_traffic(machine_id, server_ip).await;
    alerts.extend(vpn_alerts);

    // Check bandwidth abuse
    if let Some(bw) = check_bandwidth_abuse(machine_id, server_ip).await {
        alerts.push(format!("带宽超标: {:.1} Mbps (阈值: 可配置)", bw));
    }

    alerts
}