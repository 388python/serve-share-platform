use sqlx::SqlitePool;

pub async fn create_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            linuxdo_id INTEGER UNIQUE NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            core_hours REAL NOT NULL DEFAULT 0.0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            invite_code TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Servers table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            ssh_port INTEGER NOT NULL DEFAULT 22,
            ssh_key_encrypted TEXT NOT NULL,
            cpu_cores INTEGER NOT NULL DEFAULT 1,
            memory_gb REAL NOT NULL DEFAULT 1.0,
            bandwidth_mbps REAL NOT NULL DEFAULT 10.0,
            disk_gb REAL NOT NULL DEFAULT 10.0,
            cpu_multiplier REAL NOT NULL DEFAULT 1.0,
            memory_multiplier REAL NOT NULL DEFAULT 1.0,
            bandwidth_multiplier REAL NOT NULL DEFAULT 1.0,
            disk_multiplier REAL NOT NULL DEFAULT 1.0,
            use_bonus INTEGER NOT NULL DEFAULT 0,
            virtualization_type TEXT NOT NULL DEFAULT 'lxd',
            status TEXT NOT NULL DEFAULT 'pending',
            core_hours_per_hour REAL NOT NULL DEFAULT 0.0,
            expires_at TEXT NOT NULL,
            agent_token TEXT,
            last_seen TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Add agent_token column if not exists (for existing databases)
    let _ = sqlx::query(
        "ALTER TABLE servers ADD COLUMN agent_token TEXT",
    )
    .execute(pool)
    .await;

    // Add last_seen column if not exists (for existing databases)
    let _ = sqlx::query(
        "ALTER TABLE servers ADD COLUMN last_seen TEXT",
    )
    .execute(pool)
    .await;

    // VM instances table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vm_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            cpu_cores INTEGER NOT NULL DEFAULT 1,
            memory_gb REAL NOT NULL DEFAULT 1.0,
            disk_gb REAL NOT NULL DEFAULT 10.0,
            forwarded_port INTEGER,
            vm_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Settings table (key-value store)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Invite codes table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS invite_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (used_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Core hour codes table (核时码 & 订阅码)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS core_hour_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            amount REAL NOT NULL DEFAULT 0.0,
            daily_amount REAL NOT NULL DEFAULT 0.0,
            code_type TEXT NOT NULL DEFAULT 'one_time',
            expires_at TEXT,
            valid_days INTEGER,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by INTEGER,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (used_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Core hour packages table (核时套餐)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS core_hour_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            package_type TEXT NOT NULL DEFAULT 'duration',
            duration_days INTEGER,
            accumulated_hours REAL,
            core_hours REAL NOT NULL DEFAULT 0.0,
            price_ldc REAL NOT NULL DEFAULT 0.0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Recharge orders table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS recharge_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            out_trade_no TEXT NOT NULL UNIQUE,
            trade_no TEXT,
            amount_ldc REAL NOT NULL DEFAULT 0.0,
            core_hours REAL NOT NULL DEFAULT 0.0,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Sign-in records table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sign_in_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            core_hours_awarded REAL NOT NULL DEFAULT 0.0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, date)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User subscriptions (订阅码激活记录)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_id INTEGER NOT NULL,
            daily_amount REAL NOT NULL DEFAULT 0.0,
            starts_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_awarded_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (code_id) REFERENCES core_hour_codes(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User package purchases
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            package_id INTEGER NOT NULL,
            core_hours REAL NOT NULL DEFAULT 0.0,
            accumulated_hours_used REAL NOT NULL DEFAULT 0.0,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (package_id) REFERENCES core_hour_packages(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Initialize default settings
    init_default_settings(pool).await?;

    Ok(())
}

async fn init_default_settings(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let defaults = vec![
        ("site_name", "茶的服务器公益站"),
        ("registration_open", "1"),
        ("invite_code_required", "0"),
        ("sign_in_enabled", "1"),
        ("free_package_enabled", "1"),
        ("global_cpu_multiplier", "1.0"),
        ("global_memory_multiplier", "1.0"),
        ("global_bandwidth_multiplier", "1.0"),
        ("global_disk_multiplier", "1.0"),
        ("recharge_multiplier", "1.0"),
        ("recharge_fee_percent", "0.0"),
        ("withdraw_fee_percent", "5.0"),
        ("virtualization_types", "lxd,kvm"),
        ("machine_select_mode", "marketplace"),
        ("new_user_core_hours", "10.0"),
        ("sign_in_core_hours", "2.0"),
    ];

    for (key, value) in defaults {
        sqlx::query(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    }

    Ok(())
}