use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Cache<String, Arc<Mutex<(u32, Instant)>>>,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_keys: u64, window_secs: u64) -> Self {
        let window = Duration::from_secs(window_secs.max(1));
        let buckets = Cache::builder()
            .max_capacity(max_keys)
            .time_to_live(window * 2)
            .build();
        Self { buckets, window }
    }

    /// Returns `Ok(())` if request is allowed, or `Err(retry_after_secs)` if limit exceeded.
    pub fn check_and_increment(&self, key: &str, max_requests: u32) -> Result<(), u64> {
        if max_requests == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let entry = self
            .buckets
            .get_with(key.to_string(), || Arc::new(Mutex::new((0, now))));
        let mut guard = entry.lock().unwrap_or_else(|e| e.into_inner());
        let (count, window_start) = &mut *guard;

        if now.duration_since(*window_start) >= self.window {
            *count = 1;
            *window_start = now;
            return Ok(());
        }

        if *count >= max_requests {
            let elapsed = now.duration_since(*window_start);
            let remaining = self.window.saturating_sub(elapsed).as_secs().max(1);
            return Err(remaining);
        }

        *count += 1;
        Ok(())
    }
}
