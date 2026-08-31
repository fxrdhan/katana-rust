use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_BACKOFF_CACHE_SIZE: usize = 10000;
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct HostBackoff {
    consecutive: AtomicI32,
}

impl HostBackoff {
    pub fn new() -> Self {
        Self {
            consecutive: AtomicI32::new(0),
        }
    }

    pub fn load(&self) -> i32 {
        self.consecutive.load(Ordering::Relaxed)
    }

    pub fn add(&self, val: i32) {
        self.consecutive.fetch_add(val, Ordering::Relaxed);
    }
}

/// Adaptive per-host throttle memory with exponential backoff calculation.
pub struct HostBackoffManager {
    cache: Mutex<LruCache<String, std::sync::Arc<HostBackoff>>>,
}

impl Default for HostBackoffManager {
    fn default() -> Self {
        Self::new(DEFAULT_BACKOFF_CACHE_SIZE)
    }
}

impl HostBackoffManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
        }
    }

    pub fn backoff_for(&self, host: &str) -> std::sync::Arc<HostBackoff> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get(host) {
            return std::sync::Arc::clone(entry);
        }
        let entry = std::sync::Arc::new(HostBackoff::new());
        cache.put(host.to_string(), std::sync::Arc::clone(&entry));
        entry
    }

    /// Calculate the delay duration for a host if it has accumulated throttle signals.
    pub fn get_backoff_delay(&self, host: &str) -> Option<Duration> {
        let b = self.backoff_for(host);
        let n = b.load();
        if n <= 0 {
            return None;
        }

        let multiplier = 2f64.powi(n - 1);
        let base_millis = (BACKOFF_BASE.as_millis() as f64 * multiplier)
            .min(BACKOFF_MAX.as_millis() as f64) as u64;

        // Add up to 50% pseudo-jitter based on current millis
        let jitter = if base_millis > 2 {
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64)
                % (base_millis / 2)
        } else {
            0
        };

        Some(Duration::from_millis(base_millis + jitter))
    }

    /// Records a throttle event (HTTP 429 or 503).
    pub fn record_throttle(&self, host: &str) {
        let b = self.backoff_for(host);
        b.add(1);
    }

    /// Records a successful HTTP request, decrementing the consecutive count.
    pub fn record_success(&self, host: &str) {
        let b = self.backoff_for(host);
        let current = b.load();
        if current > 0 {
            b.add(-1);
        }
    }

    /// Returns true if status code indicates rate limiting or temporary unavailability.
    pub fn is_throttled(status_code: u16) -> bool {
        status_code == 429 || status_code == 503
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_lifecycle() {
        let manager = HostBackoffManager::new(100);
        let host = "example.com";

        // Initial state -> no delay
        assert_eq!(manager.get_backoff_delay(host), None);

        // Record throttle
        manager.record_throttle(host);
        let delay1 = manager.get_backoff_delay(host).unwrap();
        assert!(delay1 >= Duration::from_millis(1000));
        assert!(delay1 <= Duration::from_millis(1500));

        // Record second throttle -> exponential increase
        manager.record_throttle(host);
        let delay2 = manager.get_backoff_delay(host).unwrap();
        assert!(delay2 >= Duration::from_millis(2000));

        // Record success -> decrements
        manager.record_success(host);
        let delay_after_success = manager.get_backoff_delay(host).unwrap();
        assert!(delay_after_success <= delay2);

        // Another success -> back to 0
        manager.record_success(host);
        assert_eq!(manager.get_backoff_delay(host), None);
    }

    #[test]
    fn test_is_throttled() {
        assert!(HostBackoffManager::is_throttled(429));
        assert!(HostBackoffManager::is_throttled(503));
        assert!(!HostBackoffManager::is_throttled(200));
        assert!(!HostBackoffManager::is_throttled(404));
        assert!(!HostBackoffManager::is_throttled(500));
    }
}
