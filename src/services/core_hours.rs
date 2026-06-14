use sqlx::SqlitePool;

use crate::models::Server;

/// Calculate core hours per hour using the full formula
/// cpu_cores * cpu_multiplier * global_cpu_multiplier + 
/// memory_gb * memory_multiplier * global_memory_multiplier + 
/// bandwidth_mbps * bandwidth_multiplier * global_bandwidth_multiplier + 
/// disk_gb * disk_multiplier * global_disk_multiplier
pub async fn calculate_core_hours_per_hour(
    pool: &SqlitePool,
    cpu_cores: i32,
    cpu_multiplier: f64,
    memory_gb: f64,
    memory_multiplier: f64,
    bandwidth_mbps: f64,
    bandwidth_multiplier: f64,
    disk_gb: f64,
    disk_multiplier: f64,
) -> Result<f64, sqlx::Error> {
    let global_cpu_multiplier: f64 = get_setting(pool, "global_cpu_multiplier")
        .await?
        .parse()
        .unwrap_or(1.0);
    let global_memory_multiplier: f64 = get_setting(pool, "global_memory_multiplier")
        .await?
        .parse()
        .unwrap_or(1.0);
    let global_bandwidth_multiplier: f64 = get_setting(pool, "global_bandwidth_multiplier")
        .await?
        .parse()
        .unwrap_or(1.0);
    let global_disk_multiplier: f64 = get_setting(pool, "global_disk_multiplier")
        .await?
        .parse()
        .unwrap_or(1.0);

    let result = cpu_cores as f64 * cpu_multiplier * global_cpu_multiplier
        + memory_gb * memory_multiplier * global_memory_multiplier
        + bandwidth_mbps * bandwidth_multiplier * global_bandwidth_multiplier
        + disk_gb * disk_multiplier * global_disk_multiplier;

    Ok(result)
}

/// Get a setting value from the settings table
pub async fn get_setting(pool: &SqlitePool, key: &str) -> Result<String, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_one(pool)
        .await
}

/// Set a setting value in the settings table
pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Calculate VM core hours cost based on specs and duration
pub async fn calculate_vm_cost(
    pool: &SqlitePool,
    server: &Server,
    cpu_cores: i32,
    memory_gb: f64,
    disk_gb: f64,
    duration_hours: i32,
) -> Result<f64, sqlx::Error> {
    let cpu_ratio = cpu_cores as f64 / server.cpu_cores as f64;
    let memory_ratio = memory_gb / server.memory_gb;
    let disk_ratio = disk_gb / server.disk_gb;

    let max_ratio = cpu_ratio.max(memory_ratio).max(disk_ratio);

    let cost = max_ratio * server.core_hours_per_hour * duration_hours as f64;

    Ok(cost)
}

/// Award core hours to a user
pub async fn award_core_hours(pool: &SqlitePool, user_id: i64, amount: f64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
        .bind(amount)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Deduct core hours from a user (returns error if insufficient)
pub async fn deduct_core_hours(pool: &SqlitePool, user_id: i64, amount: f64) -> Result<(), String> {
    let current: (f64,) = sqlx::query_as("SELECT core_hours FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("查询用户余额失败: {}", e))?;

    if current.0 < amount {
        return Err(format!(
            "核时不足！当前余额 {:.1}，需要 {:.1}",
            current.0, amount
        ));
    }

    sqlx::query("UPDATE users SET core_hours = core_hours - ? WHERE id = ? AND core_hours >= ?")
        .bind(amount)
        .bind(user_id)
        .bind(amount)
        .execute(pool)
        .await
        .map_err(|e| format!("扣除核时失败: {}", e))?;

    Ok(())
}