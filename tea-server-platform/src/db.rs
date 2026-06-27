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
            regular_core_hours_used REAL NOT NULL DEFAULT 0,
            bonus_core_hours_used REAL NOT NULL DEFAULT 0,
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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

    // Create traffic_alerts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS traffic_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER,
            server_id INTEGER,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Create disputes table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            resolution TEXT,
            reply TEXT,
            amount_frozen REAL NOT NULL DEFAULT 0,
            regular_amount_frozen REAL NOT NULL DEFAULT 0,
            bonus_amount_frozen REAL NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME,
            auto_resolve_at DATETIME NOT NULL
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Create oauth_apps table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            client_id TEXT NOT NULL UNIQUE,
            client_secret TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Create oauth_codes table for authorization codes with expiration
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            user_id INTEGER,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Add missing fields to servers table (contribute flow)
    let new_columns = [
        "expose_ip INTEGER NOT NULL DEFAULT 0",
        "nat_port_start INTEGER NOT NULL DEFAULT 0",
        "nat_port_end INTEGER NOT NULL DEFAULT 0",
        "nat_multiplier REAL NOT NULL DEFAULT 1.0",
        "max_machine_hours REAL NOT NULL DEFAULT 0",
        "free_nat_hours REAL NOT NULL DEFAULT 0",
        "linux_version TEXT NOT NULL DEFAULT ''",
        "description TEXT NOT NULL DEFAULT ''",
        "provider TEXT NOT NULL DEFAULT ''",
        "is_premium INTEGER NOT NULL DEFAULT 0",
        "premium_expires_at DATETIME",
    ];
    for col in &new_columns {
        let _ = sqlx::query(&format!("ALTER TABLE servers ADD COLUMN {}", col))
            .execute(pool)
            .await;
    }

    // Add missing fields to machines table
    let machine_cols = [
        "description TEXT NOT NULL DEFAULT ''",
        "provider TEXT NOT NULL DEFAULT ''",
        "settled INTEGER NOT NULL DEFAULT 0",
        "core_hours_per_hour REAL NOT NULL DEFAULT 0",
        "used_hours REAL NOT NULL DEFAULT 0",
        "regular_core_hours_used REAL NOT NULL DEFAULT 0",
        "bonus_core_hours_used REAL NOT NULL DEFAULT 0",
        "max_hours REAL NOT NULL DEFAULT 0",
        "is_premium INTEGER NOT NULL DEFAULT 0",
        "premium_expires_at DATETIME",
        "linux_version TEXT NOT NULL DEFAULT ''",
        "image TEXT DEFAULT 'ubuntu:22.04'",
        "app_image TEXT DEFAULT ''",
        "web_port INTEGER DEFAULT 0",
        "vnc_port INTEGER DEFAULT 0",
        "root_password TEXT DEFAULT ''",
        "ip_address TEXT DEFAULT ''",
        "app_secrets TEXT DEFAULT ''",
        "free_nat_hours REAL DEFAULT 0",
    ];
    for col in &machine_cols {
        let _ = sqlx::query(&format!("ALTER TABLE machines ADD COLUMN {}", col))
            .execute(pool)
            .await;
    }

    // Create warning_letters table (proper schema)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS warning_letters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            content TEXT NOT NULL,
            warning_type TEXT NOT NULL DEFAULT 'general',
            severity TEXT NOT NULL DEFAULT 'warning',
            is_read INTEGER NOT NULL DEFAULT 0,
            requires_action INTEGER NOT NULL DEFAULT 0,
            action_taken INTEGER NOT NULL DEFAULT 0,
            action_note TEXT,
            action_at DATETIME,
            sent_by INTEGER,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Migrate warning_letters: add missing columns in case table was created with old schema
    let warning_cols = [
        "subject TEXT NOT NULL DEFAULT 'Warning'",
        "warning_type TEXT NOT NULL DEFAULT 'general'",
        "severity TEXT NOT NULL DEFAULT 'warning'",
        "requires_action INTEGER NOT NULL DEFAULT 0",
        "action_taken INTEGER NOT NULL DEFAULT 0",
        "action_note TEXT",
        "action_at DATETIME",
        "sent_by INTEGER",
        "expires_at DATETIME",
    ];
    for col in &warning_cols {
        let _ = sqlx::query(&format!("ALTER TABLE warning_letters ADD COLUMN {}", col))
            .execute(pool)
            .await;
    }

    // Create opengfw tables
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS opengfw_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL,
            match_signature TEXT DEFAULT '',
            action TEXT NOT NULL DEFAULT 'block',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS opengfw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER,
            server_id INTEGER,
            rule_id INTEGER,
            source_ip TEXT,
            target_ip TEXT,
            action TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Add match_signature column if not exists (migration)
    sqlx::query("ALTER TABLE opengfw_rules ADD COLUMN match_signature TEXT DEFAULT ''")
        .execute(pool)
        .await
        .ok();

    // Create balance_to_code_logs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS balance_to_code_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0,
            is_bonus INTEGER NOT NULL DEFAULT 0,
            code TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active',
            redeemed_by INTEGER,
            redeemed_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Create withdraw_orders table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS withdraw_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            out_trade_no TEXT NOT NULL UNIQUE,
            amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0,
            actual_amount REAL NOT NULL,
            withdraw_address TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            trade_no TEXT,
            fail_reason TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Create machine_stats table for storing real-time machine stats
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS machine_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER NOT NULL UNIQUE,
            cpu_usage_percent REAL NOT NULL DEFAULT 0,
            memory_used_mb REAL NOT NULL DEFAULT 0,
            memory_total_mb REAL NOT NULL DEFAULT 0,
            disk_used_gb REAL NOT NULL DEFAULT 0,
            disk_total_gb REAL NOT NULL DEFAULT 0,
            bandwidth_rx_mbps REAL NOT NULL DEFAULT 0,
            bandwidth_tx_mbps REAL NOT NULL DEFAULT 0,
            uptime_seconds INTEGER NOT NULL DEFAULT 0,
            process_count INTEGER NOT NULL DEFAULT 0,
            last_updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Create OpenGFW rules table for VPN/protocol blocking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS opengfw_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL,
            match_signature TEXT DEFAULT '',
            action TEXT NOT NULL DEFAULT 'block',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Add match_signature column if not exists (migration)
    sqlx::query("ALTER TABLE opengfw_rules ADD COLUMN match_signature TEXT DEFAULT ''")
        .execute(pool)
        .await
        .ok();

    // Add missing columns to opengfw_logs (migration)
    sqlx::query("ALTER TABLE opengfw_logs ADD COLUMN protocol TEXT DEFAULT ''")
        .execute(pool)
        .await
        .ok();
    sqlx::query("ALTER TABLE opengfw_logs ADD COLUMN src_ip TEXT DEFAULT ''")
        .execute(pool)
        .await
        .ok();
    sqlx::query("ALTER TABLE opengfw_logs ADD COLUMN dst_ip TEXT DEFAULT ''")
        .execute(pool)
        .await
        .ok();
    sqlx::query("ALTER TABLE opengfw_logs ADD COLUMN dst_port INTEGER DEFAULT 0")
        .execute(pool)
        .await
        .ok();
    sqlx::query("ALTER TABLE opengfw_logs ADD COLUMN blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        .execute(pool)
        .await
        .ok();

    // Create OpenGFW blocked logs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS opengfw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );
    "#,
    )
    .execute(pool)
    .await?;

    // Add OpenGFW enabled column to servers table
    let _ =
        sqlx::query("ALTER TABLE servers ADD COLUMN opengfw_enabled INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await;

    // Add columns to invites
    let _ = sqlx::query("ALTER TABLE invites ADD COLUMN private_note TEXT DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE invites ADD COLUMN public_note TEXT DEFAULT ''")
        .execute(pool)
        .await;

    // Settlement: machines table
    let _ = sqlx::query("ALTER TABLE machines ADD COLUMN settled INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE machines ADD COLUMN used_hours REAL NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE machines ADD COLUMN regular_core_hours_used REAL NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "ALTER TABLE machines ADD COLUMN bonus_core_hours_used REAL NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // Dispute frozen balance split: preserves regular/bonus accounting during settlement.
    let _ = sqlx::query(
        "ALTER TABLE disputes ADD COLUMN regular_amount_frozen REAL NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;
    let _ =
        sqlx::query("ALTER TABLE disputes ADD COLUMN bonus_amount_frozen REAL NOT NULL DEFAULT 0")
            .execute(pool)
            .await;

    // Expose IP & NAT: servers table
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN expose_ip INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN agent_key TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN nat_port_start INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN nat_port_end INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN nat_multiplier REAL NOT NULL DEFAULT 1.0")
        .execute(pool)
        .await;

    // Max machine hours: servers table
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN max_machine_hours REAL NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    // Bonus expiry: users table
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN bonus_core_hours REAL NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN bonus_expires_at DATETIME")
        .execute(pool)
        .await;

    sqlx::query(
        r#"
        UPDATE users
        SET core_hours = core_hours + (
                SELECT COALESCE(SUM(
                    CASE
                        WHEN d.regular_amount_frozen > 0 OR d.bonus_amount_frozen > 0
                            THEN d.regular_amount_frozen
                        ELSE d.amount_frozen
                    END
                ), 0)
                FROM disputes d
                JOIN servers s ON d.server_id = s.id
                WHERE s.owner_id = users.id
                  AND d.status IN ('pending', 'platform')
                  AND d.id NOT IN (
                      SELECT MIN(id)
                      FROM disputes
                      WHERE status IN ('pending', 'platform')
                      GROUP BY machine_id
                  )
            ),
            bonus_core_hours = bonus_core_hours + (
                SELECT COALESCE(SUM(
                    CASE
                        WHEN d.regular_amount_frozen > 0 OR d.bonus_amount_frozen > 0
                            THEN d.bonus_amount_frozen
                        ELSE 0
                    END
                ), 0)
                FROM disputes d
                JOIN servers s ON d.server_id = s.id
                WHERE s.owner_id = users.id
                  AND d.status IN ('pending', 'platform')
                  AND d.id NOT IN (
                      SELECT MIN(id)
                      FROM disputes
                      WHERE status IN ('pending', 'platform')
                      GROUP BY machine_id
                  )
            )
        WHERE id IN (
            SELECT s.owner_id
            FROM disputes d
            JOIN servers s ON d.server_id = s.id
            WHERE d.status IN ('pending', 'platform')
              AND d.id NOT IN (
                  SELECT MIN(id)
                  FROM disputes
                  WHERE status IN ('pending', 'platform')
                  GROUP BY machine_id
              )
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        UPDATE disputes
        SET status = 'resolved',
            resolution = COALESCE(resolution, 'duplicate'),
            resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP)
        WHERE status IN ('pending', 'platform')
          AND id NOT IN (
              SELECT MIN(id)
              FROM disputes
              WHERE status IN ('pending', 'platform')
              GROUP BY machine_id
          )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_disputes_one_active_per_machine ON disputes(machine_id) WHERE status = 'pending' OR status = 'platform'",
    )
    .execute(pool)
    .await?;

    // Premium and Linux version: servers table
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN is_premium INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN linux_version TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN premium_expires_at DATETIME")
        .execute(pool)
        .await;

    // Description and provider: servers table
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN description TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN provider TEXT NOT NULL DEFAULT ''")
        .execute(pool)
        .await;

    // Orders update timestamp for payment callbacks
    let _ = sqlx::query(
        "ALTER TABLE orders ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
    )
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
        ("agent_api_key", ""),
        ("traffic_monitor_enabled", "true"),
        ("traffic_bandwidth_threshold_mbps", "100"),
        ("settlement_threshold_pct", "80"),
        ("global_nat_multiplier", "1.0"),
        ("dispute_auto_resolve_hours", "72"),
        ("checkin_bonus_expiry_days", "30"),
        ("balance_to_code_fee", "0.05"),
        ("balance_to_code_daily_limit", "5"),
        ("balance_to_code_enabled", "true"),
        ("premium_enabled", "false"),
        ("premium_ldc_cost", "100"),
        ("opengfw_enabled", "false"),
        ("opengfw_block_vpn", "true"),
        ("opengfw_block_shadowsocks", "true"),
        ("opengfw_block_wireguard", "true"),
        ("opengfw_block_openvpn", "true"),
        ("opengfw_block_trojan", "true"),
        ("opengfw_block_vmess", "true"),
        ("opengfw_block_vless", "true"),
        ("opengfw_block_xray", "true"),
        ("opengfw_block_clash", "true"),
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
    match sqlx::query_scalar::<_, String>("SELECT value FROM site_config WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
    {
        Ok(val) => val,
        Err(e) => {
            tracing::error!("get_config failed for key '{}': {}", key, e);
            None
        }
    }
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
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(get_config(key)))
}

/// Synchronous version of set_config for use in non-async contexts.
pub fn set_config_sync(key: &str, value: &str) -> anyhow::Result<()> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(set_config(key, value))
    })
}
