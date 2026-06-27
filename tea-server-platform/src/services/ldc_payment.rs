use crate::config::AppConfig;
use crate::db;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct LdcPaymentRequest {
    pub amount: f64,
    pub order_id: String,
    pub description: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct LdcPaymentResponse {
    pub success: bool,
    pub transaction_id: Option<String>,
    pub message: String,
}

// Generate Ed25519 keypair
#[allow(dead_code)]
pub fn generate_ed25519_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let private_key = BASE64.encode(signing_key.to_bytes());
    let public_key = BASE64.encode(verifying_key.to_bytes());
    (private_key, public_key)
}

// Sign with Ed25519 for official LDC API
pub fn sign_ed25519(data: &str, private_key_b64: &str) -> anyhow::Result<String> {
    let key_bytes = BASE64.decode(private_key_b64)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(data.as_bytes());
    Ok(BASE64.encode(signature.to_bytes()))
}

// MD5 sign for EPay compatible API
pub fn sign_md5(params: &[(&str, &str)], secret: &str) -> String {
    let mut sorted: Vec<_> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let payload: String = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    let sign_str = format!("{}{}", payload, secret);
    format!("{:x}", md5::compute(sign_str.as_bytes()))
}

// Create a payment order via LDC API
pub async fn create_payment(
    cfg: &AppConfig,
    out_trade_no: &str,
    money: f64,
    order_name: &str,
) -> anyhow::Result<String> {
    // returns payment URL
    let payment_mode = db::get_config("payment_mode")
        .await
        .unwrap_or_else(|| "epay".to_string());
    let client_id = db::get_config("ldc_client_id").await.unwrap_or_default();
    let client_secret = db::get_config("ldc_client_secret").await.unwrap_or_default();

    let money_str = format!("{:.2}", money);

    // Pre-compute URLs to avoid temporary value lifetime issues
    let notify_url = format!("{}/recharge/callback", cfg.platform_domain);
    let return_url = format!("{}/dashboard", cfg.platform_domain);

    if payment_mode == "ldcpay" {
        // Official Ed25519 mode
        let private_key = db::get_config("ldc_ed25519_private_key")
            .await
            .unwrap_or_default();
        let params = vec![
            ("client_id", client_id.as_str()),
            ("type", "ldcpay"),
            ("out_trade_no", out_trade_no),
            ("money", &money_str),
            ("order_name", order_name),
            ("notify_url", notify_url.as_str()),
            ("return_url", return_url.as_str()),
        ];
        let mut sorted: Vec<_> = params.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let payload: String = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        let sign_data = format!("{}{}", payload, client_secret);
        let sign = sign_ed25519(&sign_data, &private_key)?;

        let client = reqwest::Client::new();
        let _resp = client
            .post("https://credit.linux.do/epay/pay/submit.php")
            .json(&serde_json::json!({
                "client_id": client_id,
                "type": "ldcpay",
                "out_trade_no": out_trade_no,
                "money": money_str,
                "order_name": order_name,
                "notify_url": notify_url,
                "return_url": return_url,
                "sign": sign,
            }))
            .send()
            .await?;

        Ok(format!(
            "https://credit.linux.do/paying?order_no={}",
            out_trade_no
        ))
    } else {
        // EPay compatible MD5 mode
        let params = vec![
            ("pid", client_id.as_str()),
            ("type", "epay"),
            ("out_trade_no", out_trade_no),
            ("name", order_name),
            ("money", &money_str),
            ("notify_url", notify_url.as_str()),
            ("return_url", return_url.as_str()),
        ];
        let sign = sign_md5(&params, &client_secret);

        let mut form_params: Vec<(&str, &str)> = params.clone();
        form_params.push(("sign", &sign));
        form_params.push(("sign_type", "MD5"));

        let client = reqwest::Client::new();
        let resp = client
            .post("https://credit.linux.do/epay/pay/submit.php")
            .form(&form_params)
            .send()
            .await?;

        // This returns a redirect to the payment page
        let final_url = resp.url().to_string();
        if final_url.contains("paying") {
            Ok(final_url)
        } else {
            Ok(format!(
                "https://credit.linux.do/paying?order_no={}",
                out_trade_no
            ))
        }
    }
}

// Query order status
#[allow(dead_code)]
pub async fn query_order(out_trade_no: &str) -> anyhow::Result<Option<String>> {
    // returns status
    let client_id = db::get_config("ldc_client_id").await.unwrap_or_default();
    let client_secret = db::get_config("ldc_client_secret").await.unwrap_or_default();

    let client = reqwest::Client::new();
    let resp = client
        .get("https://credit.linux.do/epay/api.php")
        .query(&[
            ("act", "order"),
            ("pid", &client_id),
            ("key", &client_secret),
            ("out_trade_no", out_trade_no),
        ])
        .send()
        .await?;

    let body = resp.text().await?;
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if json["code"] == 1 {
            Ok(Some(json["status"].to_string()))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

// Distribute LDC to user (withdraw)
#[allow(dead_code)]
pub async fn distribute_ldc(
    _cfg: &AppConfig,
    user_id: i64,
    username: &str,
    amount: f64,
    out_trade_no: &str,
) -> anyhow::Result<bool> {
    let client_id = db::get_config("ldc_client_id").await.unwrap_or_default();
    let client_secret = db::get_config("ldc_client_secret").await.unwrap_or_default();
    let auth = BASE64.encode(format!("{}:{}", client_id, client_secret));

    let client = reqwest::Client::new();
    let resp = client
        .post("https://credit.linux.do/lpay/distribute")
        .header("Authorization", format!("Basic {}", auth))
        .json(&serde_json::json!({
            "user_id": user_id,
            "username": username,
            "amount": format!("{:.2}", amount),
            "out_trade_no": out_trade_no,
            "remark": "Server platform withdrawal",
        }))
        .send()
        .await?;

    let body = resp.text().await?;
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        Ok(json["code"] == 1)
    } else {
        Ok(false)
    }
}

// Verify callback signature (MD5 mode - EPay compatible)
pub fn verify_callback_md5(params: &HashMap<String, String>, secret: &str) -> bool {
    let sign = match params.get("sign") {
        Some(s) => s.clone(),
        None => return false,
    };

    let mut sorted_keys: Vec<&String> = params.keys().filter(|k| *k != "sign" && *k != "sign_type").collect();
    sorted_keys.sort();

    let payload: String = sorted_keys
        .iter()
        .map(|k| format!("{}={}", k, params.get(*k).unwrap_or(&String::new())))
        .collect::<Vec<_>>()
        .join("&");

    let sign_str = format!("{}{}", payload, secret);
    let computed = format!("{:x}", md5::compute(sign_str.as_bytes()));

    computed.to_lowercase() == sign.to_lowercase()
}

// Verify callback signature (Ed25519 mode - official LDC)
pub fn verify_callback_ed25519(params: &HashMap<String, String>, public_key_b64: &str) -> bool {
    let sign = match params.get("sign") {
        Some(s) => s.clone(),
        None => return false,
    };

    let mut sorted_keys: Vec<&String> = params.keys().filter(|k| *k != "sign").collect();
    sorted_keys.sort();

    let payload: String = sorted_keys
        .iter()
        .map(|k| format!("{}={}", k, params.get(*k).unwrap_or(&String::new())))
        .collect::<Vec<_>>()
        .join("&");

    let key_bytes = match BASE64.decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_array) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_bytes = match BASE64.decode(&sign) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}

// Verify callback with auto-detection of sign mode
pub async fn verify_callback(params: &HashMap<String, String>) -> bool {
    let payment_mode = db::get_config("payment_mode")
        .await
        .unwrap_or_else(|| "epay".to_string());

    if payment_mode == "ldcpay" {
        let public_key = db::get_config("ldc_ed25519_public_key")
            .await
            .unwrap_or_default();
        if public_key.is_empty() {
            return false;
        }
        verify_callback_ed25519(params, &public_key)
    } else {
        let secret = db::get_config("ldc_client_secret")
            .await
            .unwrap_or_default();
        if secret.is_empty() {
            return false;
        }
        verify_callback_md5(params, &secret)
    }
}