use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::collections::VecDeque;

/// Simple in-memory rate limiter keyed by string (e.g., IP address or user_id).
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if the key should be allowed. Returns true if under limit, false if rate limited.
    pub async fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(key.to_string()).or_insert_with(VecDeque::new);

        // Remove expired entries
        while bucket.front().map_or(false, |t| *t < cutoff) {
            bucket.pop_front();
        }

        if bucket.len() >= self.max_requests {
            return false;
        }

        bucket.push_back(now);
        true
    }

    /// Periodic cleanup task to prevent memory leaks from stale entries.
    /// Call this in a background tokio task.
    pub async fn cleanup_task(self: Arc<Self>, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            let mut buckets = self.buckets.lock().await;
            let now = Instant::now();
            let max_age = Duration::from_secs(interval_secs * 2);
            buckets.retain(|_, entries| {
                if let Some(oldest) = entries.front() {
                    now.duration_since(*oldest) < max_age
                } else {
                    false
                }
            });
        }
    }
}
