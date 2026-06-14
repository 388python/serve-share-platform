use std::collections::HashMap;

use md_5::{Digest, Md5};
use reqwest::Client;
use sqlx::SqlitePool;

use crate::config::Config;

/// Create a payment order using EasyPay compatible interface (MD5 signature)
/// Returns the payment URL to redirect user to
pub async fn create_epay_order(
    config: &Config,
    _pool: &SqlitePool,
    _user_id: i64,
    amount_ldc: f64,
    order_name: &str,
    out_trade_no: &str,
) -> Result<String, String> {
    let mut params = HashMap::new();
    params.insert("pid".to_string(), config.ldc_pid.clone());
    params.insert("type".to_string(), "epay".to_string());
    params.insert("out_trade_no".to_string(), out_trade_no.to_string());
    params.insert("name".to_string(), order_name.to_string());
    params.insert("money".to_string(), format!("{:.2}", amount_ldc));

    let sign = generate_epay_sign(&params, &config.ldc_key);
    params.insert("sign".to_string(), sign);
    params.insert("sign_type".to_string(), "MD5".to_string());

    let url = format!("{}/epay/pay/submit.php", config.ldc_api_base);

    let client = Client::new();
    let response = client
        .post(&url)
        .form(&params)
        .header("User-Agent", "TeaServerPlatform/1.0")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    // Check for redirect (Location header)
    if let Some(location) = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok())
    {
        if !location.is_empty() {
            return Ok(location.to_string());
        }
    }

    // Check for JSON error response
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        return Err(format!("Payment API error ({}): {}", status.as_u16(), body));
    }

    // Try to parse as JSON for error
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(code) = json.get("code").and_then(|v| v.as_i64()) {
            if code != 1 {
                let msg = json
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                return Err(format!("Payment API error: {}", msg));
            }
        }
    }

    Ok(body)
}

/// Verify the MD5 signature from async payment notification
pub fn verify_epay_sign(params: &HashMap<String, String>, key: &str) -> bool {
    let provided_sign = match params.get("sign") {
        Some(s) => s.clone(),
        None => return false,
    };

    let computed_sign = generate_epay_sign(params, key);
    computed_sign == provided_sign
}

/// Generate MD5 sign for EasyPay payment
pub fn generate_epay_sign(params: &HashMap<String, String>, key: &str) -> String {
    // Filter out empty values and "sign", "sign_type" fields
    let mut filtered: Vec<(&String, &String)> = params
        .iter()
        .filter(|(k, v)| {
            k.as_str() != "sign" && k.as_str() != "sign_type" && !v.is_empty()
        })
        .collect();

    // Sort keys alphabetically (ASCII order)
    filtered.sort_by(|a, b| a.0.cmp(b.0));

    // Build string: k1=v1&k2=v2...
    let mut sign_str = String::new();
    for (i, (k, v)) in filtered.iter().enumerate() {
        if i > 0 {
            sign_str.push('&');
        }
        sign_str.push_str(k);
        sign_str.push('=');
        sign_str.push_str(v);
    }

    // Append key
    sign_str.push_str(key);

    // MD5 hash, return lowercase hex
    let digest = Md5::digest(sign_str.as_bytes());
    format!("{:x}", digest)
}

/// Process payment callback - verify sign, update order status, award core hours
pub async fn process_payment_callback(
    pool: &SqlitePool,
    params: &HashMap<String, String>,
    config: &Config,
) -> Result<(), String> {
    // Verify signature
    if !verify_epay_sign(params, &config.ldc_key) {
        return Err("Invalid signature".to_string());
    }

    let out_trade_no = params
        .get("out_trade_no")
        .ok_or_else(|| "Missing out_trade_no".to_string())?;
    let trade_no = params
        .get("trade_no")
        .ok_or_else(|| "Missing trade_no".to_string())?;
    let trade_status = params
        .get("trade_status")
        .ok_or_else(|| "Missing trade_status".to_string())?;

    if trade_status != "TRADE_SUCCESS" {
        return Err(format!("Trade status not success: {}", trade_status));
    }

    // Update recharge_orders: set status='paid', trade_no
    let result = sqlx::query(
        "UPDATE recharge_orders SET status = 'paid', trade_no = ?, updated_at = datetime('now') WHERE out_trade_no = ? AND status = 'pending'",
    )
    .bind(trade_no)
    .bind(out_trade_no)
    .execute(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    if result.rows_affected() == 0 {
        return Err("Order not found or already processed".to_string());
    }

    // Look up the order to get user_id and core_hours
    let order = sqlx::query_as::<_, crate::models::RechargeOrder>(
        "SELECT * FROM recharge_orders WHERE out_trade_no = ?",
    )
    .bind(out_trade_no)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    if let Some(order) = order {
        // Award core_hours to user
        sqlx::query("UPDATE users SET core_hours = core_hours + ? WHERE id = ?")
            .bind(order.core_hours)
            .bind(order.user_id)
            .execute(pool)
            .await
            .map_err(|e| format!("Failed to award core hours: {}", e))?;
    }

    Ok(())
}

/// Query order status from LinuxDo
pub async fn query_order(
    config: &Config,
    out_trade_no: &str,
) -> Result<String, String> {
    let url = format!(
        "{}/epay/api.php?act=order&pid={}&key={}&out_trade_no={}",
        config.ldc_api_base, config.ldc_pid, config.ldc_key, out_trade_no
    );

    let client = Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", "TeaServerPlatform/1.0")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Try to parse JSON and extract status
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(status) = json.get("status").and_then(|v| v.as_i64()) {
            return Ok(status.to_string());
        }
        if let Some(status) = json.get("trade_status").and_then(|v| v.as_str()) {
            return Ok(status.to_string());
        }
    }

    Ok(body)
}

/// Refund an order
pub async fn refund_order(
    config: &Config,
    trade_no: &str,
    money: f64,
) -> Result<bool, String> {
    let url = format!("{}/epay/api.php", config.ldc_api_base);

    let mut params = HashMap::new();
    params.insert("act".to_string(), "refund".to_string());
    params.insert("pid".to_string(), config.ldc_pid.clone());
    params.insert("key".to_string(), config.ldc_key.clone());
    params.insert("trade_no".to_string(), trade_no.to_string());
    params.insert("money".to_string(), format!("{:.2}", money));

    let client = Client::new();
    let response = client
        .post(&url)
        .form(&params)
        .header("User-Agent", "TeaServerPlatform/1.0")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(code) = json.get("code").and_then(|v| v.as_i64()) {
            return Ok(code == 1);
        }
    }

    Ok(false)
}

/// Distribute LDC to a user (admin function, uses Basic Auth)
pub async fn distribute_ldc(
    config: &Config,
    linuxdo_user_id: i64,
    linuxdo_username: &str,
    amount: f64,
    remark: &str,
) -> Result<String, String> {
    let url = format!("{}/lpay/distribute", config.ldc_api_base);

    let out_trade_no = format!(
        "DIST_{}_{}",
        linuxdo_user_id,
        chrono::Utc::now().timestamp()
    );

    let body = serde_json::json!({
        "user_id": linuxdo_user_id,
        "username": linuxdo_username,
        "amount": amount,
        "out_trade_no": out_trade_no,
        "remark": remark,
    });

    let auth = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", config.ldc_client_id, config.ldc_client_secret)
        )
    );

    let client = Client::new();
    let response = client
        .post(&url)
        .json(&body)
        .header("Authorization", &auth)
        .header("User-Agent", "TeaServerPlatform/1.0")
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let resp_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_body) {
        if let Some(trade_no) = json.get("trade_no").and_then(|v| v.as_str()) {
            return Ok(trade_no.to_string());
        }
        if let Some(trade_no) = json.get("data").and_then(|v| v.get("trade_no")).and_then(|v| v.as_str()) {
            return Ok(trade_no.to_string());
        }
    }

    Err(format!("Distribute failed: {}", resp_body))
}