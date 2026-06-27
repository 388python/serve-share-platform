use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::db;

pub struct MachineProvisioningJob {
    pub machine_id: i64,
    pub user_id: i64,
    pub server_owner_id: i64,
    pub server_ip: String,
    pub machine_name: String,
    pub virt_type: String,
    pub cpu: i32,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub agent_key: String,
    pub regular_used: f64,
    pub bonus_used: f64,
    pub used_hours: f64,
    pub image: String,        // 系统镜像
    pub app_image: String,    // 应用镜像
    pub root_password: String, // 用户设置的 root 密码
    pub app_secrets: String,   // 应用密钥（JSON 字符串）
}

pub fn spawn_agent_create_job(job: MachineProvisioningJob) {
    tokio::spawn(async move {
        let result = call_agent_create(&job).await;
        if let Some(create_data) = result {
            if let Err(err) =
                mark_machine_running(job.machine_id, job.user_id, job.used_hours, &create_data).await
            {
                tracing::error!(
                    machine_id = job.machine_id,
                    error = %err,
                    "failed to mark provisioned machine as running"
                );
            }
        } else if let Err(err) = fail_machine_and_refund(&job).await {
            tracing::error!(
                machine_id = job.machine_id,
                error = %err,
                "failed to refund failed machine provisioning"
            );
        }
    });
}

async fn call_agent_create(job: &MachineProvisioningJob) -> Option<Value> {
    let agent_url = format!("http://{}:19527", job.server_ip);
    let client = reqwest::Client::new();

    // Parse app_secrets from JSON string
    let app_secrets_val: Value = serde_json::from_str(&job.app_secrets).unwrap_or(json!({}));

    let request_body = json!({
        "name": job.machine_name,
        "cpu": job.cpu,
        "memory": (job.memory_gb * 1024.0) as i64,
        "disk": job.disk_gb,
        "virt_type": job.virt_type,
        "image": job.image,
        "app_image": job.app_image,
        "ssh_public_key": crate::services::session::get_ssh_public_key(),
        "root_password": job.root_password,
        "app_secrets": app_secrets_val,
    });

    let max_retries = 3;
    for attempt in 0..max_retries {
        if attempt > 0 {
            let backoff = std::time::Duration::from_secs(1 << (attempt - 1));
            tracing::warn!(
                machine_id = job.machine_id,
                attempt = attempt + 1,
                max = max_retries,
                backoff_ms = backoff.as_millis(),
                "retrying agent create after backoff",
            );
            tokio::time::sleep(backoff).await;
        }

        tracing::info!(
            machine_id = job.machine_id,
            attempt = attempt + 1,
            agent_url = %agent_url,
            request_body = %request_body,
            "sending create request to agent",
        );

        let response = client
            .post(&format!("{}/create", agent_url))
            .header("X-API-Key", &job.agent_key)
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(
                    machine_id = job.machine_id,
                    attempt = attempt + 1,
                    error = %err,
                    "agent create request failed",
                );
                continue;
            }
        };

        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            tracing::warn!(
                machine_id = job.machine_id,
                attempt = attempt + 1,
                status = %status,
                response_body = %body_text,
                "agent create returned non-success status",
            );
            continue;
        }

        match response.json::<Value>().await {
            Ok(body) if body.get("status").and_then(Value::as_str) == Some("created") => {
                tracing::info!(
                    machine_id = job.machine_id,
                    attempt = attempt + 1,
                    response = %body,
                    "agent create succeeded",
                );
                return Some(body);
            }
            Ok(body) => {
                tracing::warn!(
                    machine_id = job.machine_id,
                    attempt = attempt + 1,
                    response = %body,
                    "agent create did not confirm creation",
                );
                continue;
            }
            Err(err) => {
                tracing::warn!(
                    machine_id = job.machine_id,
                    attempt = attempt + 1,
                    error = %err,
                    "agent create returned invalid json",
                );
                continue;
            }
        }
    }

    tracing::error!(
        machine_id = job.machine_id,
        "agent create failed after all {} retries",
        max_retries,
    );
    None
}

async fn mark_machine_running(
    machine_id: i64,
    user_id: i64,
    used_hours: f64,
    create_data: &Value,
) -> anyhow::Result<()> {
    let pool = db::get_db();
    let mut tx = pool.begin().await?;

    let root_password = create_data
        .get("root_password")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ip = create_data.get("ip").and_then(Value::as_str).unwrap_or_default();
    let app_secrets = create_data
        .get("app_secrets")
        .map(|v| v.to_string())
        .unwrap_or_default();

    // 提取端口信息
    let ssh_port = create_data.get("ssh_port").and_then(|v| v.as_i64()).map(|v| v as i32);
    let vnc_port = create_data.get("vnc_port").and_then(|v| v.as_i64()).map(|v| v as i32);
    let web_port = create_data.get("novnc_port").and_then(|v| v.as_i64()).map(|v| v as i32);

    let updated = sqlx::query(
        "UPDATE machines SET status = 'running', root_password = ?, ip_address = ?, app_secrets = ?, ssh_port = ?, vnc_port = ?, web_port = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(root_password)
    .bind(ip)
    .bind(app_secrets)
    .bind(ssh_port)
    .bind(vnc_port)
    .bind(web_port)
    .bind(machine_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() > 0 {
        sqlx::query("UPDATE users SET total_usage_hours = total_usage_hours + ? WHERE id = ?")
            .bind(used_hours)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        grant_cumulative_packages(&mut tx, user_id).await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn grant_cumulative_packages(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: i64,
) -> anyhow::Result<()> {
    let total_usage: Option<f64> =
        sqlx::query_scalar("SELECT total_usage_hours FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?;

    let Some(total_hours) = total_usage else {
        return Ok(());
    };

    let packages: Vec<(i64, f64, Option<f64>)> = sqlx::query_as(
        "SELECT id, core_hours, cumulative_hours FROM recharge_packages WHERE is_cumulative = 1 AND is_active = 1 AND cumulative_hours IS NOT NULL",
    )
    .fetch_all(&mut **tx)
    .await?;

    for (package_id, core_hours, threshold) in packages {
        if threshold.is_some_and(|value| total_hours >= value) {
            let already_granted: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM user_packages WHERE user_id = ? AND package_id = ?",
            )
            .bind(user_id)
            .bind(package_id)
            .fetch_optional(&mut **tx)
            .await?;

            if already_granted.is_none() {
                sqlx::query(
                    "INSERT INTO user_packages (user_id, package_id, core_hours, is_active) VALUES (?, ?, ?, 1)",
                )
                .bind(user_id)
                .bind(package_id)
                .bind(core_hours)
                .execute(&mut **tx)
                .await?;

                sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
                    .bind(core_hours)
                    .bind(user_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
    }

    Ok(())
}

async fn fail_machine_and_refund(job: &MachineProvisioningJob) -> anyhow::Result<()> {
    let pool = db::get_db();
    let mut tx = pool.begin().await?;

    let updated =
        sqlx::query("UPDATE machines SET status = 'failed' WHERE id = ? AND status = 'pending'")
            .bind(job.machine_id)
            .execute(&mut *tx)
            .await?;

    if updated.rows_affected() > 0 {
        // 退还给用户
        sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours + ?, core_hours = core_hours + ? WHERE id = ?")
            .bind(job.bonus_used)
            .bind(job.regular_used)
            .bind(job.user_id)
            .execute(&mut *tx)
            .await?;

        // 从机主扣回（bonus扣bonus，regular扣regular）
        if job.bonus_used > 0.0 {
            sqlx::query(
                "UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ? AND bonus_core_hours >= ?"
            )
            .bind(job.bonus_used)
            .bind(job.server_owner_id)
            .bind(job.bonus_used)
            .execute(&mut *tx)
            .await?;
        }
        if job.regular_used > 0.0 {
            sqlx::query(
                "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?"
            )
            .bind(job.regular_used)
            .bind(job.server_owner_id)
            .bind(job.regular_used)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(())
}

/// 机器删除/到期时按剩余时间比例退款
pub async fn refund_machine_remaining(machine_id: i64) -> anyhow::Result<(f64, f64)> {
    let pool = db::get_db();
    let mut tx = pool.begin().await?;

    // 查询机器信息
    let machine: Option<(i64, i64, f64, f64, DateTime<Utc>, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT user_id, server_id, regular_core_hours_used, bonus_core_hours_used, created_at, expires_at, status FROM machines WHERE id = ?",
    )
    .bind(machine_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (user_id, server_id, regular_used, bonus_used, created_at, expires_at, status) = match machine {
        Some(m) => m,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    // 只对running/stopped状态的机器退款（pending/failed/deleted/expired不处理）
    if status != "running" && status != "stopped" {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    // 查询机主ID
    let server_owner_id: Option<i64> = sqlx::query_scalar(
        "SELECT owner_id FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?;

    let server_owner_id = match server_owner_id {
        Some(id) => id,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    // 计算剩余时间比例
    let now = Utc::now();
    let total_duration = expires_at.signed_duration_since(created_at).num_seconds() as f64;
    let elapsed = now.signed_duration_since(created_at).num_seconds() as f64;

    if total_duration <= 0.0 || elapsed >= total_duration {
        // 已经过期或时间异常，不退款
        return Ok((0.0, 0.0));
    }

    let remaining_ratio = 1.0 - (elapsed / total_duration);
    if remaining_ratio <= 0.0 {
        return Ok((0.0, 0.0));
    }

    let regular_refund = regular_used * remaining_ratio;
    let bonus_refund = bonus_used * remaining_ratio;

    // 更新机器状态为deleted
    let updated = sqlx::query(
        "UPDATE machines SET status = 'deleted' WHERE id = ? AND status IN ('running', 'stopped')",
    )
    .bind(machine_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        return Ok((0.0, 0.0));
    }

    // 退给用户（bonus退bonus，regular退regular）
    if bonus_refund > 0.0 {
        sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours + ? WHERE id = ?"
        )
        .bind(bonus_refund)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    if regular_refund > 0.0 {
        sqlx::query(
            "UPDATE users SET core_hours = core_hours + ? WHERE id = ?"
        )
        .bind(regular_refund)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }

    // 从机主扣回（bonus扣bonus，regular扣regular）
    if bonus_refund > 0.0 {
        let _ = sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ? AND bonus_core_hours >= ?"
        )
        .bind(bonus_refund)
        .bind(server_owner_id)
        .bind(bonus_refund)
        .execute(&mut *tx)
        .await;
    }
    if regular_refund > 0.0 {
        let _ = sqlx::query(
            "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?"
        )
        .bind(regular_refund)
        .bind(server_owner_id)
        .bind(regular_refund)
        .execute(&mut *tx)
        .await;
    }

    tx.commit().await?;
    Ok((regular_refund, bonus_refund))
}

/// 添加NAT端口映射时实时扣费
pub async fn charge_nat_port_add(machine_id: i64, port_count: i32) -> anyhow::Result<(f64, f64)> {
    let pool = crate::db::get_db();
    let mut tx = pool.begin().await?;

    let machine: Option<(i64, i64, f64, f64, f64, DateTime<Utc>, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT user_id, server_id, core_hours_per_hour, regular_core_hours_used, bonus_core_hours_used, created_at, expires_at, status FROM machines WHERE id = ?",
    )
    .bind(machine_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (user_id, server_id, old_per_hour, regular_used, bonus_used, _created_at, expires_at, status) = match machine {
        Some(m) => m,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    if status != "running" && status != "stopped" {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let now = Utc::now();
    if now >= expires_at {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let remaining_hours = (expires_at - now).num_seconds() as f64 / 3600.0;
    if remaining_hours <= 0.0 {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let server: Option<(i64, f64)> = sqlx::query_as(
        "SELECT owner_id, nat_multiplier FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (server_owner_id, nat_multiplier) = match server {
        Some(s) => s,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    let nat_cost_per_port = crate::services::core_hours::calculate_nat_cost_per_port_per_hour(nat_multiplier).await;
    let total_additional_per_hour = port_count as f64 * nat_cost_per_port;
    let total_cost = total_additional_per_hour * remaining_hours;

    if total_cost <= 0.0 {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let user_balance: Option<(f64, f64)> = sqlx::query_as(
        "SELECT bonus_core_hours, core_hours FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (user_bonus, user_regular) = user_balance.unwrap_or((0.0, 0.0));

    let bonus_to_charge = total_cost.min(user_bonus);
    let regular_to_charge = total_cost - bonus_to_charge;

    if regular_to_charge > user_regular {
        let _ = tx.rollback().await;
        anyhow::bail!("insufficient balance");
    }

    if bonus_to_charge > 0.0 {
        sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ? AND bonus_core_hours >= ?"
        )
        .bind(bonus_to_charge)
        .bind(user_id)
        .bind(bonus_to_charge)
        .execute(&mut *tx)
        .await?;
    }
    if regular_to_charge > 0.0 {
        sqlx::query(
            "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?"
        )
        .bind(regular_to_charge)
        .bind(user_id)
        .bind(regular_to_charge)
        .execute(&mut *tx)
        .await?;
    }

    if bonus_to_charge > 0.0 {
        sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours + ? WHERE id = ?"
        )
        .bind(bonus_to_charge)
        .bind(server_owner_id)
        .execute(&mut *tx)
        .await?;
    }
    if regular_to_charge > 0.0 {
        sqlx::query(
            "UPDATE users SET core_hours = core_hours + ? WHERE id = ?"
        )
        .bind(regular_to_charge)
        .bind(server_owner_id)
        .execute(&mut *tx)
        .await?;
    }

    let new_per_hour = old_per_hour + total_additional_per_hour;
    let new_regular_used = regular_used + regular_to_charge;
    let new_bonus_used = bonus_used + bonus_to_charge;

    sqlx::query(
        "UPDATE machines SET core_hours_per_hour = ?, regular_core_hours_used = ?, bonus_core_hours_used = ? WHERE id = ?"
    )
    .bind(new_per_hour)
    .bind(new_regular_used)
    .bind(new_bonus_used)
    .bind(machine_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((regular_to_charge, bonus_to_charge))
}

/// 删除NAT端口映射时实时退款
pub async fn refund_nat_port_remove(machine_id: i64, port_count: i32) -> anyhow::Result<(f64, f64)> {
    let pool = crate::db::get_db();
    let mut tx = pool.begin().await?;

    let machine: Option<(i64, i64, f64, f64, f64, DateTime<Utc>, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT user_id, server_id, core_hours_per_hour, regular_core_hours_used, bonus_core_hours_used, created_at, expires_at, status FROM machines WHERE id = ?",
    )
    .bind(machine_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (user_id, server_id, old_per_hour, regular_used, bonus_used, _created_at, expires_at, status) = match machine {
        Some(m) => m,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    if status != "running" && status != "stopped" {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let now = Utc::now();
    if now >= expires_at {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let remaining_hours = (expires_at - now).num_seconds() as f64 / 3600.0;
    if remaining_hours <= 0.0 {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let total_used = regular_used + bonus_used;
    if total_used <= 0.0 {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let server: Option<(i64, f64)> = sqlx::query_as(
        "SELECT owner_id, nat_multiplier FROM servers WHERE id = ?",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?;

    let (server_owner_id, nat_multiplier) = match server {
        Some(s) => s,
        None => {
            let _ = tx.rollback().await;
            return Ok((0.0, 0.0));
        }
    };

    let nat_cost_per_port = crate::services::core_hours::calculate_nat_cost_per_port_per_hour(nat_multiplier).await;
    let remove_per_hour = port_count as f64 * nat_cost_per_port;
    let total_refund = remove_per_hour * remaining_hours;

    if total_refund <= 0.0 {
        let _ = tx.rollback().await;
        return Ok((0.0, 0.0));
    }

    let bonus_ratio = if total_used > 0.0 { bonus_used / total_used } else { 0.0 };
    let bonus_refund = total_refund * bonus_ratio;
    let regular_refund = total_refund - bonus_refund;

    let actual_bonus_refund = bonus_refund.min(bonus_used);
    let actual_regular_refund = regular_refund.min(regular_used);

    if actual_bonus_refund > 0.0 {
        sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours + ? WHERE id = ?"
        )
        .bind(actual_bonus_refund)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
    if actual_regular_refund > 0.0 {
        sqlx::query(
            "UPDATE users SET core_hours = core_hours + ? WHERE id = ?"
        )
        .bind(actual_regular_refund)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }

    if actual_bonus_refund > 0.0 {
        let _ = sqlx::query(
            "UPDATE users SET bonus_core_hours = bonus_core_hours - ? WHERE id = ? AND bonus_core_hours >= ?"
        )
        .bind(actual_bonus_refund)
        .bind(server_owner_id)
        .bind(actual_bonus_refund)
        .execute(&mut *tx)
        .await;
    }
    if actual_regular_refund > 0.0 {
        let _ = sqlx::query(
            "UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?"
        )
        .bind(actual_regular_refund)
        .bind(server_owner_id)
        .bind(actual_regular_refund)
        .execute(&mut *tx)
        .await;
    }

    let new_per_hour = (old_per_hour - remove_per_hour).max(0.0);
    let new_regular_used = (regular_used - actual_regular_refund).max(0.0);
    let new_bonus_used = (bonus_used - actual_bonus_refund).max(0.0);

    sqlx::query(
        "UPDATE machines SET core_hours_per_hour = ?, regular_core_hours_used = ?, bonus_core_hours_used = ? WHERE id = ?"
    )
    .bind(new_per_hour)
    .bind(new_regular_used)
    .bind(new_bonus_used)
    .bind(machine_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((actual_regular_refund, actual_bonus_refund))
}