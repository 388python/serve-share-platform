use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::sync::OnceLock;

static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

pub async fn init_db(database_url: &str) -> anyhow::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    run_migrations(&pool).await?;
    DB_POOL
        .set(pool)
        .map_err(|_| anyhow::anyhow!("DB_POOL already initialized"))
}

pub fn get_db() -> &'static SqlitePool {
    DB_POOL.get().expect("Database not initialized")
}

async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            linuxdo_id INTEGER NOT NULL UNIQUE,
            username TEXT NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            ldc_balance REAL NOT NULL DEFAULT 0,
            core_hours REAL NOT NULL DEFAULT 0,
            total_usage_hours REAL NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_checkin DATETIME
        );

        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            ssh_port INTEGER NOT NULL DEFAULT 22,
            ssh_key TEXT NOT NULL,
            cpu_cores INTEGER NOT NULL,
            memory_gb REAL NOT NULL,
            bandwidth_mbps REAL NOT NULL DEFAULT 0,
            disk_gb REAL NOT NULL,
            cpu_multiplier REAL NOT NULL DEFAULT 1.0,
            memory_multiplier REAL NOT NULL DEFAULT 1.0,
            bandwidth_multiplier REAL NOT NULL DEFAULT 1.0,
            disk_multiplier REAL NOT NULL DEFAULT 1.0,
            use_bonus INTEGER NOT NULL DEFAULT 0,
            virt_type TEXT NOT NULL DEFAULT 'lxd',
            expires_at DATETIME NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            proxy_port INTEGER,
            agent_installed INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            cpu_cores INTEGER NOT NULL,
            memory_gb REAL NOT NULL,
            disk_gb REAL NOT NULL,
            virt_type TEXT NOT NULL DEFAULT 'lxd',
            status TEXT NOT NULL DEFAULT 'running',
            core_hours_per_hour REAL NOT NULL DEFAULT 0,
            expires_at DATETIME NOT NULL,
            ssh_port INTEGER,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            out_trade_no TEXT NOT NULL UNIQUE,
            money REAL NOT NULL,
            ldc_amount REAL NOT NULL,
            order_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            trade_no TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS recharge_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            duration_days INTEGER,
            core_hours REAL NOT NULL DEFAULT 0,
            price_ldc REAL NOT NULL DEFAULT 0,
            is_cumulative INTEGER NOT NULL DEFAULT 0,
            cumulative_hours REAL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS redeem_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            code_type TEXT NOT NULL DEFAULT 'core_hours',
            package_id INTEGER,
            core_hours REAL,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by INTEGER,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            used_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by INTEGER,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            used_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reward_core_hours REAL NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS site_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            value TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS user_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            package_id INTEGER,
            core_hours REAL NOT NULL DEFAULT 0,
            expires_at DATETIME,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Add api_key column to users (ignore error if already exists)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN api_key TEXT")
        .execute(pool)
        .await;

    let defaults = vec![
        ("site_name", "茶的服务器公益站"),
        ("checkin_enabled", "true"),
        ("free_plan_enabled", "true"),
        ("registration_enabled", "true"),
        ("require_invite", "false"),
        ("recharge_multiplier", "1.0"),
        ("recharge_fee", "0.0"),
        ("withdraw_fee", "0.0"),
        ("virt_type", "lxd"),
        ("select_mode", "market"),
        ("lock_bonus", "unlocked"),
        ("global_cpu_multiplier", "1.0"),
        ("global_memory_multiplier", "1.0"),
        ("global_bandwidth_multiplier", "1.0"),
        ("global_disk_multiplier", "1.0"),
        ("new_user_core_hours", "0"),
        ("checkin_reward", "10"),
        ("payment_mode", "epay"),
        ("ldc_client_id", ""),
        ("ldc_client_secret", ""),
        ("ldc_ed25519_private_key", ""),
        ("ldc_ed25519_public_key", ""),
        ("admin_api_key", ""),
    ];
    for (key, value) in defaults {
        sqlx::query("INSERT OR IGNORE INTO site_config (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?;
    }

    Ok(())
}

pub async fn get_config(key: &str) -> Option<String> {
    let pool = get_db();
    sqlx::query_scalar::<_, String>("SELECT value FROM site_config WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
}

pub async fn set_config(key: &str, value: &str) -> anyhow::Result<()> {
    let pool = get_db();
    sqlx::query("INSERT OR REPLACE INTO site_config (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// Synchronous version of get_config for use in non-async contexts.
/// Uses block_in_place to safely block within the tokio runtime.
pub fn get_config_sync(key: &str) -> Option<String> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(get_config(key))
    })
}