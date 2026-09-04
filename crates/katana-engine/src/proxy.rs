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

    /// Parses a single URL, comma-separated list of proxy URLs, or reads from a proxy list file.
    pub fn from_file_or_comma_separated(proxy_str: &str) -> Self {
        let trimmed = proxy_str.trim();
        if std::path::Path::new(trimmed).is_file() {
            if let Ok(content) = std::fs::read_to_string(trimmed) {
                let proxies: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                return Self::new(proxies);
            }
        }
        Self::from_comma_separated(trimmed)
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
        Ok(Self::from_file_or_comma_separated(s))
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

    /// Returns the next proxy parsed as a reqwest::Url.
    pub fn next_url(&self) -> Option<reqwest::Url> {
        let p = self.next_proxy()?;
        reqwest::Url::parse(&p).ok()
    }

    /// Builds a reqwest::Proxy instance for the next rotated proxy.
    pub fn next_reqwest_proxy(&self) -> Option<Proxy> {
        let proxy_url = self.next_proxy()?;
        Proxy::all(&proxy_url).ok()
    }

    /// Builds a rotating reqwest::Proxy that rotates across proxies dynamically on every request.
    pub fn build_rotating_proxy(rotator: std::sync::Arc<Self>) -> Option<Proxy> {
        if rotator.is_empty() {
            return None;
        }
        if rotator.total_proxies() == 1 {
            return rotator.next_reqwest_proxy();
        }
        Some(Proxy::custom(move |_url| rotator.next_url()))
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

    #[test]
    fn test_proxy_rotator_file_parsing() {
        let tmp_file = std::env::temp_dir().join("katana_test_proxies.txt");
        let content = "# Comment\nhttp://127.0.0.1:8001\nsocks5://127.0.0.1:1080\n\n";
        std::fs::write(&tmp_file, content).unwrap();

        let rotator = ProxyRotator::from_file_or_comma_separated(tmp_file.to_str().unwrap());
        assert_eq!(rotator.total_proxies(), 2);
        assert_eq!(rotator.next_proxy().unwrap(), "http://127.0.0.1:8001");
        assert_eq!(rotator.next_proxy().unwrap(), "socks5://127.0.0.1:1080");

        let _ = std::fs::remove_file(tmp_file);
    }

    #[test]
    fn test_build_rotating_proxy() {
        let rotator = std::sync::Arc::new(ProxyRotator::from_comma_separated(
            "http://127.0.0.1:8080, http://127.0.0.1:8081",
        ));
        let proxy = ProxyRotator::build_rotating_proxy(rotator);
        assert!(proxy.is_some());
        let client = reqwest::Client::builder().proxy(proxy.unwrap()).build();
        assert!(client.is_ok());
    }
}
