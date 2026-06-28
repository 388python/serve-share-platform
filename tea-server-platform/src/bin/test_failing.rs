use tera::{Context, Tera};
use std::path::Path;
use serde_json::json;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let base = Path::new(&manifest_dir).join("templates");

    let all_glob = format!("{}/**/*.html", base.display());
    let tera = Tera::new(&all_glob).expect("Failed to load all templates");

    println!("=== 语法验证: 所有模板语法正确 ✅ ===");
    println!();
    println!("现在用完整上下文验证渲染...");
    println!();

    let all_paths = [
        "components/base.html",
        "user/index.html",
        "user/dashboard.html",
        "user/packages.html",
        "user/machines.html",
        "user/market.html",
        "user/recharge.html",
        "user/withdraw.html",
        "user/stats.html",
        "user/connect.html",
        "user/auto_select.html",
        "user/balance_to_code.html",
        "user/redeem.html",
        "user/contribute.html",
        "user/dispute.html",
        "user/error.html",
        "servers.html",
        "warning_letters.html",
        "warning_letter_detail.html",
        "admin/dashboard.html",
        "admin/users.html",
        "admin/servers.html",
        "admin/packages.html",
        "admin/machines.html",
        "admin/machines_stats.html",
        "admin/orders.html",
        "admin/codes.html",
        "admin/invites.html",
        "admin/oauth_apps.html",
        "admin/config.html",
        "admin/disputes.html",
        "admin/traffic_alerts.html",
        "admin/warning_letters.html",
        "admin/opengfw.html",
    ];

    // Super rich context
    let mut ctx = Context::new();
    ctx.insert("site_name", "Test");
    ctx.insert("current_url", "");
    ctx.insert("user_name", "Test User");
    ctx.insert("user_ldc", &100);
    ctx.insert("user_balance", &50);
    ctx.insert("is_admin", &true);
    ctx.insert("is_logged_in", &true);
    ctx.insert("warning_count", &0);

    // Collections
    ctx.insert("packages", &json!([
        {"id": 1, "name": "套餐1", "price": 100, "duration_days": 30, "description": "test", "core_hours": 100, "is_premium": false},
        {"id": 2, "name": "套餐2", "price": 200, "duration_days": 60, "description": "test", "core_hours": 200, "is_premium": false},
    ]));
    ctx.insert("machines", &json!([]));
    ctx.insert("codes", &json!([]));
    ctx.insert("invites", &json!([]));
    ctx.insert("users", &json!([
        {"id": 1, "username": "user1", "ldc_balance": 100, "core_hours": 50, "is_active": true, "is_admin": false, "email": "test@test.com", "created_at": "2025-01-01"},
        {"id": 2, "username": "user2", "ldc_balance": 0, "core_hours": 0, "is_active": true, "is_admin": false, "email": "test2@test.com", "created_at": "2025-01-01"},
    ]));
    ctx.insert("user", &json!({"id": 1, "username": "testuser", "ldc_balance": 100, "core_hours": 50}));
    ctx.insert("servers", &json!([]));
    ctx.insert("orders", &json!([]));
    ctx.insert("disputes", &json!([]));
    ctx.insert("letters", &json!([]));
    ctx.insert("unread_count", &0);
    ctx.insert("letters_count", &0);
    ctx.insert("stats", &json!([]));
    ctx.insert("machine_stats", &json!([]));

    // Machine details
    ctx.insert("machine", &json!({
        "id": 1,
        "status": "running",
        "cpu_cores": 2,
        "memory_mb": 2048,
        "disk_gb": 50,
        "created_at": "2025-01-01",
        "expires_at": "2025-12-31",
        "user_id": 1,
        "ip": "127.0.0.1"
    }));
    ctx.insert("machine_id", &1);
    ctx.insert("proxy_port", &2222);
    ctx.insert("ssh_port", &2222);

    // Warning letter details
    ctx.insert("letter", &json!({
        "id": 1,
        "subject": "Test Warning",
        "content": "Test content",
        "severity": "info",
        "warning_type": "general",
        "is_read": false,
        "requires_action": false,
        "action_taken": false,
        "created_at": "2025-01-01",
        "expires_at": "2025-12-31"
    }));

    // Configs
    ctx.insert("configs", &json!([
        {"key": "site_name", "value": "Test"},
        {"key": "opengfw_enabled", "value": "false"},
        {"key": "premium_enabled", "value": "false"},
        {"key": "premium_ldc_cost", "value": "100"},
    ]));

    // Contribute/loc bonus
    ctx.insert("lock_bonus", &json!({"lock_period": 30, "rate": 0.05, "is_premium": false}));
    ctx.insert("premium_ldc_cost", &100);
    ctx.insert("premium_enabled", &false);

    // Dashboard counters
    ctx.insert("total_revenue", &0);
    ctx.insert("user_count", &2);
    ctx.insert("server_count", &1);
    ctx.insert("machine_count", &1);
    ctx.insert("running_machines", &1);
    ctx.insert("total_core_hours", &100);
    ctx.insert("total_usage_hours", &10);
    ctx.insert("active_machines", &1);
    ctx.insert("total_machines", &1);
    ctx.insert("total_servers", &0);
    ctx.insert("total_orders", &0);
    ctx.insert("unread_warnings", &0);
    ctx.insert("total_warnings", &0);
    ctx.insert("profile", &json!({
        "username": "testuser",
        "email": "test@test.com",
        "created_at": "2025-01-01",
        "core_hours": 100,
        "bonus_core_hours": 10,
        "total_usage_hours": 10
    }));

    // Recharge/withdraw
    ctx.insert("recharge_multiplier", &1.0);
    ctx.insert("bonus_core_hours", &10);
    ctx.insert("bonus_expires_at", &"2025-12-31");
    ctx.insert("core_hours", &100);
    ctx.insert("today_count", &0);
    ctx.insert("daily_limit", &5);
    ctx.insert("fee_pct", &5);
    ctx.insert("balance_to_code_rate", &0.5);

    // Logs
    ctx.insert("logs", &json!([]));
    ctx.insert("api_key", &"test-key");
    ctx.insert("invite_code", &"");
    ctx.insert("invite_codes", &json!([]));
    ctx.insert("private_note", &"");

    // Traffic alerts
    ctx.insert("traffic_alerts", &json!([]));
    ctx.insert("traffic_stats", &json!([]));

    // Premium
    ctx.insert("is_premium", &false);
    ctx.insert("premium_servers", &json!([]));
    ctx.insert("current_user_ldc", &100);

    // Flash message
    ctx.insert("flash_message", &"");

    // Market
    ctx.insert("market_machines", &json!([]));
    ctx.insert("public_machines", &json!([]));

    // Test render all
    let mut failures = 0;
    for p in &all_paths {
        match tera.render(p, &ctx) {
            Ok(_) => println!("✅ {}", p),
            Err(e) => {
                println!("❌ {}", p);
                let msg = format!("{:?}", e);
                for line in msg.lines().take(3) {
                    println!("   {}", line);
                }
                failures += 1;
            }
        }
    }

    println!();
    if failures == 0 {
        println!("✅ 全部 33 个模板语法正确，可正常渲染");
    } else {
        println!("❌ {} 个模板仍有问题（可能仍缺少特定上下文变量）", failures);
    }
}
