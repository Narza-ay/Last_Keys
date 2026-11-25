//! In-memory fixed-window rate limiter for unauthenticated endpoints.
//!
//! Keys combine the endpoint group with the client IP and, where relevant, a
//! hash of the e-mail address. Limits apply per server instance.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_TRACKED_KEYS: usize = 100_000;

pub(crate) struct RateLimiter {
    limit: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub(crate) fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Records one request for `key`; returns `false` when the limit is
    /// exceeded for the current window.
    pub(crate) fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let Ok(mut buckets) = self.buckets.lock() else {
            // A poisoned lock means a panic elsewhere; fail closed.
            return false;
        };
        if buckets.len() >= MAX_TRACKED_KEYS {
            let window = self.window;
            buckets.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key_and_resets() {
        let rl = RateLimiter::new(2, Duration::from_millis(50));
        assert!(rl.allow("a"));
        assert!(rl.allow("a"));
        assert!(!rl.allow("a"));
        assert!(rl.allow("b"), "keys are independent");
        std::thread::sleep(Duration::from_millis(60));
        assert!(rl.allow("a"), "window resets");
    }
}
