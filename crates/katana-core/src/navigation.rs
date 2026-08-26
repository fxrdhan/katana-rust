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

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub knowledgebase: HashMap<String, serde_json::Value>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}
