use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// API architecture type classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiType {
    Rest,
    GraphQL,
    Soap,
    WebSocket,
    Xhr,
    Generic,
}

impl std::fmt::Display for ApiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rest => write!(f, "REST"),
            Self::GraphQL => write!(f, "GraphQL"),
            Self::Soap => write!(f, "SOAP"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::Xhr => write!(f, "XHR"),
            Self::Generic => write!(f, "Generic"),
        }
    }
}

/// Heuristically classifies a URL, Content-Type, and body payload into an API paradigm.
pub fn classify_api_endpoint(url: &str, content_type: &str, body: &str) -> Option<ApiType> {
    let url_lower = url.to_lowercase();
    let ct_lower = content_type.to_lowercase();

    // 1. WebSocket check
    if url_lower.starts_with("ws://") || url_lower.starts_with("wss://") {
        return Some(ApiType::WebSocket);
    }

    // 2. GraphQL check
    if url_lower.contains("/graphql")
        || url_lower.contains("?query=")
        || body.contains("__schema")
        || body.contains("query {")
        || body.contains("mutation {")
    {
        return Some(ApiType::GraphQL);
    }

    // 3. SOAP check
    if url_lower.ends_with(".wsdl")
        || url_lower.ends_with(".asmx")
        || url_lower.ends_with(".svc")
        || url_lower.contains("?wsdl")
        || ct_lower.contains("application/soap+xml")
        || (ct_lower.contains("text/xml") && body.contains("<soap:"))
    {
        return Some(ApiType::Soap);
    }

    // 4. REST check
    if url_lower.contains("/api/")
        || url_lower.contains("/v1/")
        || url_lower.contains("/v2/")
        || url_lower.contains("/v3/")
        || url_lower.contains("/rest/")
    {
        return Some(ApiType::Rest);
    }

    // 5. Generic XHR / JSON
    if ct_lower.contains("application/json") || ct_lower.contains("text/json") {
        return Some(ApiType::Xhr);
    }

    None
}

/// Represents an exposed secret finding detected during crawling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub rule_name: String,
    pub matched_token: String,
    pub severity: String,
    pub source: String,
}

struct SecretRule {
    name: &'static str,
    regex: Regex,
    severity: &'static str,
}

lazy_static! {
    static ref RULES: Vec<SecretRule> = vec![
        SecretRule {
            name: "AWS Access Key",
            regex: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap(),
            severity: "critical",
        },
        SecretRule {
            name: "GitHub Token",
            regex: Regex::new(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b").unwrap(),
            severity: "critical",
        },
        SecretRule {
            name: "Google API Key",
            regex: Regex::new(r"\b(AIza[0-9A-Za-z-_]{35})\b").unwrap(),
            severity: "high",
        },
        SecretRule {
            name: "Slack Webhook",
            regex: Regex::new(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)").unwrap(),
            severity: "high",
        },
        SecretRule {
            name: "Stripe Secret Key",
            regex: Regex::new(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b").unwrap(),
            severity: "critical",
        },
        SecretRule {
            name: "Stripe Publishable Key",
            regex: Regex::new(r"\b(pk_live_[0-9a-zA-Z]{24,34})\b").unwrap(),
            severity: "low",
        },
        SecretRule {
            name: "JWT Token",
            regex: Regex::new(r"\b(eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})\b").unwrap(),
            severity: "medium",
        },
        SecretRule {
            name: "Generic Secret Assignment",
            regex: Regex::new(r#"(?i)\b(?:api_key|apikey|secret_key|app_secret|client_secret)\s*[:=]\s*["']([0-9a-zA-Z-_]{20,})["']"#).unwrap(),
            severity: "medium",
        },
    ];
}

/// High-performance credential and API secret detection scanner.
#[derive(Debug, Default, Clone)]
pub struct SecretScanner;

impl SecretScanner {
    pub fn scan(content: &str, source_url: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for rule in RULES.iter() {
            for caps in rule.regex.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    findings.push(SecretFinding {
                        rule_name: rule.name.to_string(),
                        matched_token: m.as_str().to_string(),
                        severity: rule.severity.to_string(),
                        source: source_url.to_string(),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_api_endpoint() {
        assert_eq!(
            classify_api_endpoint("wss://example.com/ws", "", ""),
            Some(ApiType::WebSocket)
        );
        assert_eq!(
            classify_api_endpoint("https://example.com/graphql", "application/json", ""),
            Some(ApiType::GraphQL)
        );
        assert_eq!(
            classify_api_endpoint(
                "https://example.com/soap.asmx?wsdl",
                "text/xml",
                "<soap:Envelope>"
            ),
            Some(ApiType::Soap)
        );
        assert_eq!(
            classify_api_endpoint("https://example.com/api/v1/users", "application/json", ""),
            Some(ApiType::Rest)
        );
        assert_eq!(
            classify_api_endpoint("https://example.com/data.json", "application/json", "{}"),
            Some(ApiType::Xhr)
        );
        assert_eq!(
            classify_api_endpoint(
                "https://example.com/index.html",
                "text/html",
                "<html></html>"
            ),
            None
        );
    }

    #[test]
    fn test_secret_scanner() {
        let aws_dummy = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let gh_dummy = format!("ghp_{}", "123456789012345678901234567890123456");
        let g_dummy = format!("AIza{}", "SyD-1234567890123456789012345678901");
        let slack_dummy = format!(
            "https://hooks.{}.com/services/{}/{}/{}",
            "slack", "T00000000", "B00000000", "XXXXXXXXXXXXXXXXXXXXXXXX"
        );
        let stripe_dummy = format!("sk_live_{}", "0123456789abcdef0123456789");
        let jwt_dummy = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );

        let payload = format!(
            r#"
            const awsKey = "{aws_dummy}";
            const ghToken = "{gh_dummy}";
            const gKey = "{g_dummy}";
            const slack = "{slack_dummy}";
            const stripe = "{stripe_dummy}";
            const jwt = "{jwt_dummy}";
            const customSecret = 'api_key: "abc123def456ghi789jkl012mno345"';
            "#
        );

        let findings = SecretScanner::scan(&payload, "https://example.com/app.js");
        let rule_names: Vec<&str> = findings.iter().map(|f| f.rule_name.as_str()).collect();

        assert!(rule_names.contains(&"AWS Access Key"));
        assert!(rule_names.contains(&"GitHub Token"));
        assert!(rule_names.contains(&"Google API Key"));
        assert!(rule_names.contains(&"Slack Webhook"));
        assert!(rule_names.contains(&"Stripe Secret Key"));
        assert!(rule_names.contains(&"JWT Token"));
        assert!(rule_names.contains(&"Generic Secret Assignment"));
    }
}
