use regex::Regex;
use url::Url;

/// ScopeManager validates if a given URL is within allowed crawling boundaries.
#[derive(Debug, Clone, Default)]
pub struct ScopeManager {
    scope_regexes: Vec<Regex>,
    out_of_scope_regexes: Vec<Regex>,
}

impl ScopeManager {
    pub fn new(
        scope_patterns: &[String],
        out_of_scope_patterns: &[String],
    ) -> Result<Self, regex::Error> {
        let mut scope_regexes = Vec::new();
        for pat in scope_patterns {
            scope_regexes.push(Regex::new(pat)?);
        }

        let mut out_of_scope_regexes = Vec::new();
        for pat in out_of_scope_patterns {
            out_of_scope_regexes.push(Regex::new(pat)?);
        }

        Ok(Self {
            scope_regexes,
            out_of_scope_regexes,
        })
    }

    /// Validates whether a target URL is in scope relative to the root hostname.
    pub fn validate(&self, target_url: &str, root_hostname: &str) -> bool {
        let parsed = match Url::parse(target_url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let host = match parsed.host_str() {
            Some(h) => h,
            None => return false,
        };

        // Out-of-scope rules have highest precedence
        for out_regex in &self.out_of_scope_regexes {
            if out_regex.is_match(target_url) {
                return false;
            }
        }

        // If explicit scope patterns are configured, check against them
        if !self.scope_regexes.is_empty() {
            return self.scope_regexes.iter().any(|r| r.is_match(target_url));
        }

        // Default: match same host or subdomain
        if !root_hostname.is_empty() {
            return host == root_hostname || host.ends_with(&format!(".{}", root_hostname));
        }

        true
    }
}
