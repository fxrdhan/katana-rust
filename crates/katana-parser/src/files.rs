use katana_core::navigation::Request;
use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

lazy_static! {
    static ref RE_LOC: Regex = Regex::new(r"(?i)<loc>\s*([^<]+)\s*</loc>").unwrap();
}

/// Parses a robots.txt body text and extracts allowed/disallowed URL endpoints.
pub fn parse_robots_txt(base_url: &str, content: &str) -> Vec<Request> {
    let mut results = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        let directive = parts[0].trim().to_lowercase();
        if directive.starts_with("allow") || directive == "disallow" {
            let path_val = parts[1].trim();
            if path_val.is_empty() {
                continue;
            }

            if let Ok(resolved) = base.join(path_val) {
                results.push(Request {
                    method: "GET".to_string(),
                    url: resolved.to_string(),
                    depth: 2,
                    tag: "file".to_string(),
                    attribute: "robotstxt".to_string(),
                    root_hostname: root_hostname.clone(),
                    source: base_url.to_string(),
                    ..Default::default()
                });
            }
        }
    }

    results
}

/// Parses a sitemap.xml body content and extracts all <loc> endpoint URLs.
pub fn parse_sitemap_xml(base_url: &str, content: &str) -> Vec<Request> {
    let mut results = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    for caps in RE_LOC.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let loc_val = m.as_str().trim();
            if loc_val.is_empty() {
                continue;
            }

            if let Ok(resolved) = base.join(loc_val) {
                results.push(Request {
                    method: "GET".to_string(),
                    url: resolved.to_string(),
                    depth: 2,
                    tag: "file".to_string(),
                    attribute: "sitemapxml".to_string(),
                    root_hostname: root_hostname.clone(),
                    source: base_url.to_string(),
                    ..Default::default()
                });
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_robots_txt() {
        let base = "https://example.com/robots.txt";
        let content = r#"
        User-agent: *
        Disallow: /admin/
        Allow: /public/api
        Disallow: /private/secret.php
        # Comment
        "#;

        let res = parse_robots_txt(base, content);
        let urls: Vec<&str> = res.iter().map(|r| r.url.as_str()).collect();

        assert_eq!(res.len(), 3);
        assert!(urls.contains(&"https://example.com/admin/"));
        assert!(urls.contains(&"https://example.com/public/api"));
        assert!(urls.contains(&"https://example.com/private/secret.php"));

        for r in &res {
            assert_eq!(r.depth, 2);
            assert_eq!(r.tag, "file");
            assert_eq!(r.attribute, "robotstxt");
        }
    }

    #[test]
    fn test_parse_sitemap_xml() {
        let base = "https://example.com/sitemap.xml";
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://example.com/page1</loc>
          </url>
          <url>
            <loc>/page2</loc>
          </url>
        </urlset>"#;

        let res = parse_sitemap_xml(base, content);
        let urls: Vec<&str> = res.iter().map(|r| r.url.as_str()).collect();

        assert_eq!(res.len(), 2);
        assert!(urls.contains(&"https://example.com/page1"));
        assert!(urls.contains(&"https://example.com/page2"));

        for r in &res {
            assert_eq!(r.depth, 2);
            assert_eq!(r.tag, "file");
            assert_eq!(r.attribute, "sitemapxml");
        }
    }
}
