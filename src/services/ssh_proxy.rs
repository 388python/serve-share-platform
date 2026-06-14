use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Port forwarder manager - manages port allocation and SSH tunnels
pub struct PortForwarder {
    pub pool: SqlitePool,
    /// Next available port for forwarding
    pub next_port: Arc<Mutex<u16>>,
    /// Base port range for forwarding
    pub port_range_start: u16,
    pub port_range_end: u16,
}

impl PortForwarder {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            next_port: Arc::new(Mutex::new(22000)),
            port_range_start: 22000,
            port_range_end: 22999,
        }
    }

    /// Allocate the next available port
    pub async fn allocate_port(&self) -> Result<u16, String> {
        // Query vm_instances for the highest used forwarded_port
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT MAX(forwarded_port) FROM vm_instances WHERE forwarded_port IS NOT NULL",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("查询端口失败: {}", e))?;

        let next_port = match row {
            Some((Some(max_port),)) => {
                let next = (max_port as u16) + 1;
                if next > self.port_range_end {
                    return Err("端口池已耗尽，没有可用端口".to_string());
                }
                next
            }
            _ => self.port_range_start,
        };

        // Update the cached next_port
        let mut current = self.next_port.lock().await;
        *current = next_port + 1;

        Ok(next_port)
    }

    /// Release a port back to the pool
    pub async fn release_port(&self, port: u16) -> Result<(), String> {
        sqlx::query("UPDATE vm_instances SET forwarded_port = NULL WHERE forwarded_port = ?")
            .bind(port as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("释放端口失败: {}", e))?;

        // Optionally adjust next_port downward
        let mut current = self.next_port.lock().await;
        if port < *current {
            *current = port;
        }

        Ok(())
    }

    /// Get the platform host address for SSH connection display
    /// Returns the platform's public IP/hostname that users connect to
    pub fn get_platform_host(&self) -> &str {
        "platform-host"
    }
}