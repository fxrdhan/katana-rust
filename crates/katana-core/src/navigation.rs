use crate::knowledge::SecretFinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Form extracted from an HTML page.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub enctype: String,
    pub parameters: Vec<String>,
}

/// Navigation Request representing a target endpoint to visit or discovered.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Request {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub method: String,

    #[serde(rename = "endpoint")]
    pub url: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub body: String,

    #[serde(skip)]
    pub depth: usize,

    #[serde(skip)]
    pub skip_validation: bool,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub headers: HashMap<String, String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub tag: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub attribute: String,

    #[serde(skip)]
    pub root_hostname: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub custom_fields: HashMap<String, Vec<String>>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub raw: String,
}

impl Request {
    /// Compute unique deduplication key for this request.
    /// GET uses URL; POST/others include body.
    pub fn request_url(&self) -> String {
        if self.method.is_empty() || self.method.eq_ignore_ascii_case("GET") {
            self.url.clone()
        } else {
            format!("{}:{}", self.url, self.body)
        }
    }
}

/// Navigation Response received from a visited endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Response {
    #[serde(skip)]
    pub depth: usize,

    #[serde(skip_serializing_if = "is_zero_status", default)]
    pub status_code: u16,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub headers: HashMap<String, String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub body: String,

    #[serde(skip_serializing_if = "is_zero_len", default)]
    pub content_length: usize,

    #[serde(skip)]
    pub root_hostname: String,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub technologies: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub raw: String,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub forms: Vec<Form>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub xhr_requests: Vec<Request>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub stored_response_path: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_type: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secrets: Vec<SecretFinding>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_data: Option<TlsData>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub knowledgebase: HashMap<String, serde_json::Value>,
}

/// Extracted TLS/SSL certificate metadata and client fingerprints matching upstream schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TlsData {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subject_dn: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subject_cn: String,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subject_an: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub issuer_dn: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub issuer_cn: String,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub issuer_org: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub not_before: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub not_after: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub cipher: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub tls_version: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub fingerprint_sha256: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ja3: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ja4: String,
}

fn is_zero_status(code: &u16) -> bool {
    *code == 0
}

fn is_zero_len(len: &usize) -> bool {
    *len == 0
}

impl Response {
    /// Resolves a relative or absolute path against the current response URL.
    pub fn absolute_url(&self, current_url: &str, target_path: &str) -> Option<String> {
        let base = Url::parse(current_url).ok()?;
        let joined = base.join(target_path).ok()?;
        Some(joined.to_string())
    }
}

/// Final crawl result emitted to consumers / output writers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Result {
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_data: Option<TlsData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub technologies: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secrets: Vec<SecretFinding>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_data_serialization_parity() {
        let tls = TlsData {
            subject_dn: "CN=example.com,O=Example Corp,C=US".to_string(),
            subject_cn: "example.com".to_string(),
            subject_an: vec!["example.com".to_string(), "www.example.com".to_string()],
            issuer_dn: "CN=DigiCert Global G2,O=DigiCert Inc,C=US".to_string(),
            issuer_cn: "DigiCert Global G2".to_string(),
            issuer_org: vec!["DigiCert Inc".to_string()],
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
            cipher: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "tls13".to_string(),
            fingerprint_sha256: "ab:cd:ef:12:34:56".to_string(),
            ja3: "b32309a26951912be7dba376398abc3b".to_string(),
            ja4: "t13d1516h2_8daaf6152771_e56270d43700".to_string(),
        };

        let res = Result {
            timestamp: Utc::now(),
            request: Some(Request {
                url: "https://example.com".to_string(),
                method: "GET".to_string(),
                ..Default::default()
            }),
            tls_data: Some(tls.clone()),
            response: Some(Response {
                status_code: 200,
                tls_data: Some(tls),
                ..Default::default()
            }),
            ..Default::default()
        };

        let json_str = serde_json::to_string(&res).expect("serialization failed");
        assert!(json_str.contains("\"tls_data\""));
        assert!(json_str.contains("\"subject_cn\":\"example.com\""));
        assert!(json_str.contains("\"tls_version\":\"tls13\""));
        assert!(json_str.contains("\"ja4\":\"t13d1516h2_8daaf6152771_e56270d43700\""));

        let deserialized: Result = serde_json::from_str(&json_str).expect("deserialization failed");
        assert_eq!(
            deserialized.tls_data.as_ref().unwrap().subject_cn,
            "example.com"
        );
    }
}
