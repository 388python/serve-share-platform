use serde_json::{json, Value};

use crate::db;

pub struct MachineProvisioningJob {
    pub machine_id: i64,
    pub user_id: i64,
    pub owner_id: i64,
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
}

pub fn spawn_agent_create_job(job: MachineProvisioningJob) {
    tokio::spawn(async move {
        let success = call_agent_create(&job).await;
        if success {
            if let Err(err) =
                mark_machine_running(job.machine_id, job.user_id, job.used_hours).await
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

async fn call_agent_create(job: &MachineProvisioningJob) -> bool {
    let agent_url = format!("http://{}:19527", job.server_ip);
    let response = reqwest::Client::new()
        .post(format!("{}/create", agent_url))
        .header("X-API-Key", &job.agent_key)
        .json(&json!({
            "name": job.machine_name,
            "cpu": job.cpu,
            "memory": (job.memory_gb * 1024.0) as i64,
            "disk": job.disk_gb,
            "virt_type": job.virt_type,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(err) => {
            tracing::warn!(
                machine_id = job.machine_id,
                error = %err,
                "agent create request failed"
            );
            return false;
        }
    };

    if !response.status().is_success() {
        tracing::warn!(
            machine_id = job.machine_id,
            status = %response.status(),
            "agent create returned non-success status"
        );
        return false;
    }

    match response.json::<Value>().await {
        Ok(body) if body.get("status").and_then(Value::as_str) == Some("created") => true,
        Ok(body) => {
            tracing::warn!(
                machine_id = job.machine_id,
                response = %body,
                "agent create did not confirm creation"
            );
            false
        }
        Err(err) => {
            tracing::warn!(
                machine_id = job.machine_id,
                error = %err,
                "agent create returned invalid json"
            );
            false
        }
    }
}

async fn mark_machine_running(
    machine_id: i64,
    user_id: i64,
    used_hours: f64,
) -> anyhow::Result<()> {
    let pool = db::get_db();
    let mut tx = pool.begin().await?;

    let updated =
        sqlx::query("UPDATE machines SET status = 'running' WHERE id = ? AND status = 'pending'")
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
        sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours + ?, core_hours = core_hours + ? WHERE id = ?")
            .bind(job.bonus_used)
            .bind(job.regular_used)
            .bind(job.user_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("UPDATE users SET bonus_core_hours = bonus_core_hours - ?, core_hours = core_hours - ? WHERE id = ?")
            .bind(job.bonus_used)
            .bind(job.regular_used)
            .bind(job.owner_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}
