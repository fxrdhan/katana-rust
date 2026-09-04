use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref SPA_ROOT_REGEX: Regex = Regex::new(
        r#"(?i)<(?:div|section|main)\s+id=["'](?:root|app|__next|__nuxt|main-content)["']\s*>\s*</(?:div|section|main)>|<app-root(?:\s+[^>]*)?>\s*</app-root>"#
    ).unwrap();

    static ref SPA_NOSCRIPT_REGEX: Regex = Regex::new(
        r#"(?i)need to enable JavaScript|requires JavaScript|enable JavaScript to continue|JavaScript is disabled"#
    ).unwrap();

    static ref SPA_BUNDLE_REGEX: Regex = Regex::new(
        r#"(?i)<script[^>]+src=["'][^"']*(?:react|vue|angular|svelte|next|nuxt|umi|chunk-vendors|runtime~main|main\.[0-9a-f]{8,}\.js)[^"']*["']"#
    ).unwrap();
}

/// Evaluates whether a given HTML page represents a client-rendered Dynamic Single Page Application (SPA).
pub fn is_dynamic_spa(html: &str, content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    if !ct.is_empty() && !ct.contains("text/html") && !ct.contains("application/xhtml") {
        return false;
    }

    // 1. Direct match on empty SPA root mount elements
    if SPA_ROOT_REGEX.is_match(html) {
        return true;
    }

    // 2. Noscript tag indicating JavaScript client runtime requirement
    if html.contains("<noscript") && SPA_NOSCRIPT_REGEX.is_match(html) {
        return true;
    }

    // 3. SPA script bundle presence coupled with sparse static content
    if SPA_BUNDLE_REGEX.is_match(html) {
        // Compute non-tag character count
        let stripped = strip_html_tags(html);
        if stripped.trim().len() < 300 {
            return true;
        }
    }

    false
}

/// Quick helper to strip HTML tags and measure text density
fn strip_html_tags(html: &str) -> String {
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut out = String::with_capacity(html.len());

    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if !in_tag && chars[i] == '<' {
            in_tag = true;
            if i + 7 < len && &lower[i..i + 7] == "<script" {
                in_script = true;
            } else if i + 6 < len && &lower[i..i + 6] == "<style" {
                in_style = true;
            } else if in_script && i + 9 <= len && &lower[i..i + 9] == "</script>" {
                in_script = false;
                i += 8;
            } else if in_style && i + 8 <= len && &lower[i..i + 8] == "</style>" {
                in_style = false;
                i += 7;
            }
        } else if in_tag && chars[i] == '>' {
            in_tag = false;
        } else if !in_tag && !in_script && !in_style {
            out.push(chars[i]);
        }
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_react_spa_root_detection() {
        let react_html = r#"
            <!DOCTYPE html>
            <html>
            <head><title>React App</title></head>
            <body>
                <noscript>You need to enable JavaScript to run this app.</noscript>
                <div id="root"></div>
                <script src="/static/js/bundle.js"></script>
            </body>
            </html>
        "#;
        assert!(is_dynamic_spa(react_html, "text/html; charset=utf-8"));
    }

    #[test]
    fn test_vue_spa_app_detection() {
        let vue_html = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Vue App</title></head>
            <body>
                <div id="app"></div>
                <script src="/js/chunk-vendors.js"></script>
            </body>
            </html>
        "#;
        assert!(is_dynamic_spa(vue_html, "text/html"));
    }

    #[test]
    fn test_angular_app_root_detection() {
        let angular_html = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Angular SPA</title></head>
            <body>
                <app-root></app-root>
                <script src="/runtime.js"></script>
            </body>
            </html>
        "#;
        assert!(is_dynamic_spa(angular_html, "text/html"));
    }

    #[test]
    fn test_static_html_not_spa() {
        let static_html = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Static Blog</title></head>
            <body>
                <h1>Welcome to our blog</h1>
                <p>This is a completely static website with lots of paragraph text content rendered server-side.</p>
                <p>More detailed content about security tools, crawling, and HTTP pipelines that goes well beyond three hundred characters of pure text to avoid false positives.</p>
                <a href="/about">About Us</a>
                <a href="/contact">Contact Us</a>
            </body>
            </html>
        "#;
        assert!(!is_dynamic_spa(static_html, "text/html"));
    }
}
