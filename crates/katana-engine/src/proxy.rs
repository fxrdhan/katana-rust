use reqwest::Proxy;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Thread-safe multi-protocol proxy rotator supporting HTTP, HTTPS, and SOCKS5 proxies.
pub struct ProxyRotator {
    proxies: Vec<String>,
    counter: AtomicUsize,
}

impl ProxyRotator {
    /// Creates a new ProxyRotator from a list of proxy target URLs.
    pub fn new(proxies: Vec<String>) -> Self {
        let cleaned: Vec<String> = proxies
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        Self {
            proxies: cleaned,
            counter: AtomicUsize::new(0),
        }
    }

    /// Parses a single URL or comma-separated list of proxy URLs.
    pub fn from_comma_separated(proxy_str: &str) -> Self {
        let list: Vec<String> = proxy_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self::new(list)
    }
}

impl std::str::FromStr for ProxyRotator {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_comma_separated(s))
    }
}

impl ProxyRotator {
    /// Returns the total number of configured proxies.
    pub fn total_proxies(&self) -> usize {
        self.proxies.len()
    }

    /// Checks if no proxies are configured.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Returns the next proxy URL in round-robin sequence.
    pub fn next_proxy(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        Some(self.proxies[idx].clone())
    }

    /// Builds a reqwest::Proxy instance for the next rotated proxy.
    pub fn next_reqwest_proxy(&self) -> Option<Proxy> {
        let proxy_url = self.next_proxy()?;
        Proxy::all(&proxy_url).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_rotator_round_robin() {
        let rotator = ProxyRotator::from_comma_separated(
            "http://127.0.0.1:8080, socks5://127.0.0.1:1080, http://127.0.0.1:8081",
        );
        assert_eq!(rotator.total_proxies(), 3);

        assert_eq!(rotator.next_proxy().unwrap(), "http://127.0.0.1:8080");
        assert_eq!(rotator.next_proxy().unwrap(), "socks5://127.0.0.1:1080");
        assert_eq!(rotator.next_proxy().unwrap(), "http://127.0.0.1:8081");
        assert_eq!(rotator.next_proxy().unwrap(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_proxy_rotator_empty() {
        let rotator = ProxyRotator::new(vec![]);
        assert!(rotator.is_empty());
        assert_eq!(rotator.next_proxy(), None);
    }
}
