use regex::Regex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Checks whether an IPv4 address belongs to loopback, private, link-local,
/// broadcast, or cloud metadata ranges.
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Loopback: 127.0.0.0/8
    if ip.is_loopback() {
        return true;
    }
    // Unspecified / Broadcast: 0.0.0.0/8, 255.255.255.255
    if ip.is_unspecified() || ip.is_broadcast() {
        return true;
    }
    // Reserved / Class E: 240.0.0.0/4
    if octets[0] >= 240 {
        return true;
    }
    // RFC 1918 Private ranges:
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local / Cloud Metadata: 169.254.0.0/16 (e.g. 169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Carrier-Grade NAT (RFC 6598): 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }

    false
}

/// Checks whether an IPv6 address belongs to loopback, unique-local, link-local,
/// or IPv4-mapped private ranges.
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }
    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }
    // IPv4-mapped IPv6: ::ffff:a.b.c.d
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }
    let seg = ip.segments();
    // Unique Local Address (RFC 4193): fc00::/7 (0xfc00 - 0xfdff)
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-Local Unicast (RFC 4291): fe80::/10 (0xfe80 - 0xfebf)
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    false
}

/// Checks whether an IP address belongs to private, loopback, link-local, or metadata ranges.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

/// Network egress policy for restricting targets and crawler traversal (e.g. SSRF protection).
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    pub exclude_private_ips: bool,
    pub deny_hosts: HashSet<String>,
    pub deny_patterns: Vec<Regex>,
}

impl NetworkPolicy {
    /// Creates a new `NetworkPolicy` from options and deny filters.
    pub fn new(exclude_private_ips: bool, deny_list: &[String]) -> Result<Self, regex::Error> {
        let mut policy = Self {
            exclude_private_ips,
            deny_hosts: HashSet::new(),
            deny_patterns: Vec::new(),
        };

        for item in deny_list {
            let item_trimmed = item.trim();
            if item_trimmed.is_empty() {
                continue;
            }
            if item_trimmed.eq_ignore_ascii_case("private-ips") {
                policy.exclude_private_ips = true;
            } else if let Ok(re) = Regex::new(item_trimmed) {
                let clean = item_trimmed.to_lowercase();
                policy.deny_hosts.insert(clean);
                policy.deny_patterns.push(re);
            } else {
                policy.deny_hosts.insert(item_trimmed.to_lowercase());
            }
        }

        Ok(policy)
    }

    /// Validates an IP address against the network policy.
    pub fn validate_ip(&self, ip: &IpAddr) -> bool {
        if self.exclude_private_ips && is_private_ip(ip) {
            return false;
        }
        let ip_str = ip.to_string();
        if self.deny_hosts.contains(&ip_str) {
            return false;
        }
        for pat in &self.deny_patterns {
            if pat.is_match(&ip_str) {
                return false;
            }
        }
        true
    }

    /// Validates a hostname or IP string against the network policy.
    pub fn validate_host(&self, host: &str) -> bool {
        let clean_host = host.trim_matches(|c| c == '[' || c == ']').to_lowercase();

        if self.exclude_private_ips
            && (clean_host == "localhost" || clean_host == "127.0.0.1" || clean_host == "::1")
        {
            return false;
        }

        if let Ok(ip) = clean_host.parse::<IpAddr>() {
            return self.validate_ip(&ip);
        }

        if self.deny_hosts.contains(&clean_host) {
            return false;
        }

        for pat in &self.deny_patterns {
            if pat.is_match(&clean_host) {
                return false;
            }
        }

        true
    }

    /// Validates a candidate URL against the network policy.
    pub fn validate_url(&self, url_str: &str) -> bool {
        if let Ok(parsed) = Url::parse(url_str) {
            if let Some(host) = parsed.host_str() {
                return self.validate_host(host);
            }
        }
        self.validate_host(url_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ipv4_detection() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.5".parse().unwrap()));
        assert!(is_private_ip(&"172.31.255.254".parse().unwrap()));
        assert!(!is_private_ip(&"172.32.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.169.254".parse().unwrap())); // AWS metadata
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap())); // Public DNS
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap())); // Public Cloudflare
    }

    #[test]
    fn test_is_private_ipv6_detection() {
        assert!(is_private_ip(&"::1".parse().unwrap())); // Loopback
        assert!(is_private_ip(&"::".parse().unwrap())); // Unspecified
        assert!(is_private_ip(&"fc00::1".parse().unwrap())); // Unique local
        assert!(is_private_ip(&"fe80::1".parse().unwrap())); // Link-local
        assert!(is_private_ip(&"::ffff:192.168.1.1".parse().unwrap())); // IPv4-mapped private
        assert!(!is_private_ip(&"2606:4700:4700::1111".parse().unwrap())); // Cloudflare IPv6
    }

    #[test]
    fn test_network_policy_url_validation() {
        let policy = NetworkPolicy::new(true, &["internal\\.corp".to_string()]).unwrap();

        // Private IPs blocked
        assert!(!policy.validate_url("http://127.0.0.1:8080/admin"));
        assert!(!policy.validate_url("http://localhost:3000/"));
        assert!(!policy.validate_url("http://169.254.169.254/latest/meta-data/"));
        assert!(!policy.validate_url("http://192.168.1.50/login"));
        assert!(!policy.validate_url("http://[::1]:8080/status"));

        // Deny pattern blocked
        assert!(!policy.validate_url("https://service.internal.corp/api"));

        // Public IPs and domains allowed
        assert!(policy.validate_url("https://example.com/"));
        assert!(policy.validate_url("http://93.184.216.34/index.html"));
    }

    #[test]
    fn test_network_policy_exclude_flag_private_ips() {
        let policy = NetworkPolicy::new(false, &["private-ips".to_string()]).unwrap();
        assert!(policy.exclude_private_ips);
        assert!(!policy.validate_url("http://10.0.0.1/dashboard"));
        assert!(policy.validate_url("https://example.com/"));
    }
}
