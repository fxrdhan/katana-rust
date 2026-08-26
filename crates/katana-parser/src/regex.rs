use katana_core::navigation::Request;
use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

lazy_static! {
    static ref RE_RELATIVE_ENDPOINTS: Regex = Regex::new(
        r#"(?i)(?:https?://[A-Za-z0-9_\-.]+(?::\d{1,5})?)?(?:/[a-zA-Z0-9_\-\.\%]+)+(?:\?[^"'\s\)]+)?|\b[a-zA-Z0-9_\-\.]+\.(?:aspx?|js(?:on|p)?|html|php\d?|action|do)\b"#
    ).unwrap();
}

/// Extract candidate endpoints from raw JavaScript or body text using regex.
pub fn extract_endpoints_from_regex(base_url: &str, content: &str, current_depth: usize) -> Vec<Request> {
    let mut results = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    for mat in RE_RELATIVE_ENDPOINTS.find_iter(content) {
        let match_str = mat.as_str().trim();
        if let Ok(resolved) = base.join(match_str) {
            results.push(Request {
                method: "GET".to_string(),
                url: resolved.to_string(),
                depth: current_depth + 1,
                tag: "regex".to_string(),
                attribute: "js".to_string(),
                root_hostname: root_hostname.clone(),
                source: base_url.to_string(),
                ..Default::default()
            });
        }
    }

    results
}
