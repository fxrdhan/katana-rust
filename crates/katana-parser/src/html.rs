use katana_core::navigation::Request;
use scraper::{Html, Selector};
use url::Url;

/// Parses HTML content and extracts potential navigation endpoints.
pub fn parse_html_endpoints(
    base_url: &str,
    html_content: &str,
    current_depth: usize,
) -> Vec<Request> {
    let mut results = Vec::new();
    let document = Html::parse_document(html_content);
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    let tag_selectors = [
        ("a", "href"),
        ("a", "ping"),
        ("link[href]", "href"),
        ("script[src]", "src"),
        ("iframe", "src"),
        ("embed", "src"),
        ("img", "src"),
        ("video", "src"),
        ("audio", "src"),
        ("source", "src"),
        ("form[action]", "action"),
        ("button[formaction]", "formaction"),
    ];

    for (selector_str, attr_name) in tag_selectors {
        if let Ok(selector) = Selector::parse(selector_str) {
            for element in document.select(&selector) {
                if let Some(attr_val) = element.value().attr(attr_name) {
                    let trimmed = attr_val.trim();
                    if trimmed.is_empty()
                        || trimmed.starts_with("data:")
                        || trimmed.starts_with("javascript:")
                        || trimmed.starts_with("mailto:")
                        || trimmed.starts_with("vbscript:")
                    {
                        continue;
                    }

                    if let Ok(resolved) = base.join(trimmed) {
                        results.push(Request {
                            method: "GET".to_string(),
                            url: resolved.to_string(),
                            depth: current_depth + 1,
                            tag: selector_str.to_string(),
                            attribute: attr_name.to_string(),
                            root_hostname: root_hostname.clone(),
                            source: base_url.to_string(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    results
}
