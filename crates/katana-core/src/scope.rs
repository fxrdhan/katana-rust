use regex::Regex;
use url::Url;

#[derive(Debug, Clone, Default)]
pub enum FieldScope {
    Dn,
    #[default]
    Rdn,
    Fqdn,
    Custom(Regex),
}

/// ScopeManager validates if a given URL is within allowed crawling boundaries.
#[derive(Debug, Clone, Default)]
pub struct ScopeManager {
    in_scope: Vec<Regex>,
    out_of_scope: Vec<Regex>,
    field_scope: FieldScope,
    no_scope: bool,
}

impl ScopeManager {
    pub fn new(
        in_scope_patterns: &[String],
        out_of_scope_patterns: &[String],
        field_scope_str: &str,
        no_scope: bool,
    ) -> Result<Self, regex::Error> {
        let mut in_scope = Vec::new();
        for pat in in_scope_patterns {
            in_scope.push(Regex::new(pat)?);
        }

        let mut out_of_scope = Vec::new();
        for pat in out_of_scope_patterns {
            out_of_scope.push(Regex::new(pat)?);
        }

        let field_scope = match field_scope_str.to_lowercase().as_str() {
            "dn" => FieldScope::Dn,
            "rdn" => FieldScope::Rdn,
            "fqdn" => FieldScope::Fqdn,
            "" => FieldScope::Rdn,
            custom => FieldScope::Custom(Regex::new(custom)?),
        };

        Ok(Self {
            in_scope,
            out_of_scope,
            field_scope,
            no_scope,
        })
    }

    /// Validates whether a target URL is in scope relative to root hostname.
    pub fn validate(&self, target_url: &str, root_hostname: &str) -> bool {
        let parsed = match Url::parse(target_url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // 1. DNS-based scope validation (unless no_scope is enabled)
        if !self.no_scope {
            let hostname = parsed.host_str().unwrap_or("");
            if !self.validate_dns(hostname, root_hostname) {
                return false;
            }
        }

        // 2. URL regex pattern validation
        if !self.in_scope.is_empty() || !self.out_of_scope.is_empty() {
            return self.validate_url(target_url);
        }

        true
    }

    fn validate_url(&self, url: &str) -> bool {
        // Out-of-scope rules have absolute priority
        for out_regex in &self.out_of_scope {
            if out_regex.is_match(url) {
                return false;
            }
        }

        if self.in_scope.is_empty() {
            return true;
        }

        self.in_scope.iter().any(|r| r.is_match(url))
    }

    fn validate_dns(&self, hostname: &str, root_hostname: &str) -> bool {
        let host_lower = hostname.to_lowercase();
        let root_lower = root_hostname.to_lowercase();

        if let FieldScope::Custom(re) = &self.field_scope {
            return re.is_match(hostname);
        }

        let host_ip = hostname
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<std::net::IpAddr>()
            .ok();
        let root_ip = root_hostname
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<std::net::IpAddr>()
            .ok();

        // If either host or root is an IP address, or scope is FQDN, perform exact host matching
        if matches!(self.field_scope, FieldScope::Fqdn) || host_ip.is_some() || root_ip.is_some() {
            if let (Some(h_ip), Some(r_ip)) = (host_ip, root_ip) {
                return h_ip == r_ip;
            }
            return host_lower == root_lower;
        }

        let (rdn, dn) = get_domain_rdn_and_dn(&root_lower);

        match self.field_scope {
            FieldScope::Dn => {
                // dn is keyword matching: any host whose name contains keyword is in scope
                host_lower.contains(&dn.to_lowercase())
            }
            FieldScope::Rdn => {
                // rdn matches root domain itself or any subdomains with dot boundary
                matches_domain_or_subdomain(&host_lower, &rdn)
            }
            _ => false,
        }
    }
}

/// Matches host == domain or host is subdomain ending with .domain (boundary enforcement)
pub fn matches_domain_or_subdomain(host: &str, domain: &str) -> bool {
    let h = host.to_lowercase();
    let d = domain.to_lowercase();
    h == d || h.ends_with(&format!(".{}", d))
}

/// Extract root domain name (RDN) and domain keyword (DN) from hostname
pub fn get_domain_rdn_and_dn(domain: &str) -> (String, String) {
    let clean = domain.trim_matches('.');
    if clean.is_empty() {
        return (String::new(), String::new());
    }

    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() <= 1 {
        return (clean.to_string(), clean.to_string());
    }

    // Common multi-part TLD suffixes like .co.uk, .com.au, .ac.id
    let last_two = if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        String::new()
    };

    let is_cctld = last_two == "co.uk"
        || last_two == "com.au"
        || last_two == "ac.id"
        || last_two == "co.id"
        || last_two == "gov.uk"
        || last_two == "org.uk";

    if is_cctld && parts.len() >= 3 {
        let rdn = format!("{}.{}", parts[parts.len() - 3], last_two);
        let dn = parts[parts.len() - 3].to_string();
        (rdn, dn)
    } else {
        let rdn = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        let dn = parts[parts.len() - 2].to_string();
        (rdn, dn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_manager_url_golden_vectors() {
        let in_scope = vec!["example".to_string()];
        let out_scope = vec![r"logout\.php".to_string()];
        let manager = ScopeManager::new(&in_scope, &out_scope, "dn", false).unwrap();

        assert!(manager.validate("https://test.com/index.php/example", "test.com"));
        assert!(!manager.validate("https://test.com/logout.php", "another.com"));
    }

    #[test]
    fn test_scope_manager_dn_golden_vectors() {
        let manager = ScopeManager::new(&[], &[], "dn", false).unwrap();

        assert!(manager.validate("https://testanother.com/index.php", "test.com"));
        assert!(
            manager.validate("https://TESTANOTHER.com/index.php", "test.com"),
            "dn keyword match must be case-insensitive"
        );
    }

    #[test]
    fn test_scope_manager_rdn_golden_vectors() {
        let manager = ScopeManager::new(&[], &[], "rdn", false).unwrap();

        // Subdomain is in scope
        assert!(manager.validate("https://subdomain.example.com/logout.php", "example.com"));

        // Root domain itself is in scope
        assert!(manager.validate("https://example.com/index.php", "example.com"));

        // Look-alike domains (boundary check) MUST be out of scope
        assert!(!manager.validate("https://evilexample.com/index.php", "example.com"));
        assert!(!manager.validate("https://notexample.com/index.php", "example.com"));

        // Mixed-case DNS must be in scope
        assert!(manager.validate("https://EXAMPLE.com/index.php", "example.com"));
        assert!(manager.validate("https://Sub.Example.COM/index.php", "example.com"));

        // Localhost in scope
        assert!(manager.validate("http://localhost:8082/logout.php", "localhost"));
    }

    #[test]
    fn test_scope_manager_fqdn_golden_vectors() {
        let manager = ScopeManager::new(&[], &[], "fqdn", false).unwrap();

        assert!(manager.validate("https://test.com/index.php", "test.com"));
        assert!(!manager.validate("https://subdomain.example.com/logout.php", "example.com"));
        assert!(!manager.validate("https://example.com/logout.php", "another.com"));
    }

    #[test]
    fn test_scope_get_domain_rdn_and_dn() {
        let (rdn, dn) = get_domain_rdn_and_dn("test.projectdiscovery.io");
        assert_eq!(rdn, "projectdiscovery.io");
        assert_eq!(dn, "projectdiscovery");
    }

    #[test]
    fn test_scope_no_scope_with_out_of_scope_golden_vectors() {
        let out_of_scope = vec![
            r"logout\.php".to_string(),
            r"/admin/".to_string(),
            r"\.js$".to_string(),
            r"^https?://[^/]+/\?lang=[a-z]{2}".to_string(),
        ];
        let manager = ScopeManager::new(&[], &out_of_scope, "rdn", true).unwrap();

        // Cross-domain allowed with no_scope
        assert!(manager.validate("https://completely-different.com/index.php", "original.com"));

        // Out-of-scope rule rejected
        assert!(!manager.validate(
            "https://completely-different.com/logout.php",
            "original.com"
        ));

        // Normal URLs allowed
        assert!(manager.validate("https://any-site.com/products/item123", "original.com"));
    }

    #[test]
    fn test_scope_no_scope_with_both_in_and_out_of_scope() {
        let in_scope = vec![r"/api/".to_string(), r"/products/".to_string()];
        let out_scope = vec![r"/api/internal/".to_string(), r"\.css$".to_string()];
        let manager = ScopeManager::new(&in_scope, &out_scope, "fqdn", true).unwrap();

        // Allowed: matches in_scope, not out_of_scope
        assert!(manager.validate("https://external.com/api/users", "original.com"));

        // Rejected: matches both (out_of_scope wins)
        assert!(!manager.validate("https://external.com/api/internal/secrets", "original.com"));

        // Rejected: not in in_scope
        assert!(!manager.validate("https://external.com/about/company", "original.com"));

        // Rejected: matches out_of_scope
        assert!(!manager.validate("https://external.com/styles/main.css", "original.com"));
    }

    #[test]
    fn test_scope_ip_address_exact_matching() {
        // Even with rdn or dn, IP addresses must only match exactly and not treat octets as domain parts
        let manager_rdn = ScopeManager::new(&[], &[], "rdn", false).unwrap();
        let manager_dn = ScopeManager::new(&[], &[], "dn", false).unwrap();

        // IPv4 exact match
        assert!(manager_rdn.validate("http://192.168.1.1/index.html", "192.168.1.1"));
        assert!(manager_dn.validate("http://192.168.1.1/index.html", "192.168.1.1"));

        // IPv4 mismatch
        assert!(!manager_rdn.validate("http://192.168.1.2/index.html", "192.168.1.1"));
        assert!(!manager_dn.validate("http://192.168.1.2/index.html", "192.168.1.1"));

        // Subdomain of IP or prefix lookalike must fail
        assert!(!manager_rdn.validate("http://192.168.1.100/index.html", "192.168.1.1"));
        assert!(!manager_dn.validate("http://192.168.1.100/index.html", "192.168.1.1"));

        // Domain vs IP mismatch
        assert!(!manager_rdn.validate("http://example.com/index.html", "192.168.1.1"));
        assert!(!manager_rdn.validate("http://192.168.1.1/index.html", "example.com"));

        // IPv6 exact match (including bracketed format in URL)
        assert!(manager_rdn.validate("http://[::1]/index.html", "::1"));
        assert!(manager_rdn.validate("http://[::1]/index.html", "[::1]"));
        assert!(!manager_rdn.validate("http://[::2]/index.html", "::1"));
    }
}
