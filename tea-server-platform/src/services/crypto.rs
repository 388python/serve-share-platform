use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};

pub struct Crypto;

const NONCE_PREFIX_LEN: usize = 12; // 96-bit nonce for AES-256-GCM

impl Crypto {
    /// Get encryption key from environment or generate a stable one
    fn get_key() -> Vec<u8> {
        // Try environment variable first
        if let Ok(key) = std::env::var("ENCRYPTION_KEY") {
            if key.len() >= 32 {
                return key.as_bytes()[..32].to_vec();
            }
        }
        // Fall back to session_secret (first 32 bytes)
        let secret = crate::config::AppConfig::get().session_secret.as_bytes();
        if secret.len() >= 32 {
            secret[..32].to_vec()
        } else {
            // Pad with zeros if too short (should not happen with proper config)
            let mut key = secret.to_vec();
            key.resize(32, 0);
            key
        }
    }

    /// Encrypt plaintext, returns `nonce_base64.ciphertext_base64`
    pub fn encrypt(plaintext: &str) -> String {
        if plaintext.is_empty() {
            return String::new();
        }
        let key = Self::get_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .expect("AES-256-GCM key must be 32 bytes");

        let nonce_bytes = Nonce::from_slice(&Self::generate_nonce());
        let ciphertext = cipher
            .encrypt(nonce_bytes, plaintext.as_bytes())
            .expect("encryption failure");

        let mut result = Self::generate_nonce();
        result.extend_from_slice(&ciphertext);
        // Store as hex for safety
        hex::encode(&result)
    }

    /// Decrypt ciphertext from `nonce_base64.ciphertext_base64` format
    pub fn decrypt(hex_encoded: &str) -> Option<String> {
        if hex_encoded.is_empty() {
            return Some(String::new());
        }
        let data = hex::decode(hex_encoded).ok()?;
        if data.len() < NONCE_PREFIX_LEN {
            return None;
        }

        let key = Self::get_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .expect("AES-256-GCM key must be 32 bytes");

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_PREFIX_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }

    fn generate_nonce() -> Vec<u8> {
        use rand::RngCore;
        let mut nonce = vec![0u8; NONCE_PREFIX_LEN];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}
