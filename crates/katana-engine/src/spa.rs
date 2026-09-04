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
    static ref SCRIPT_STYLE_REGEX: Regex =
        Regex::new(r#"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>"#).unwrap();
    static ref HTML_TAG_REGEX: Regex = Regex::new(r#"(?is)<[^>]+>"#).unwrap();
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

/// Safely strips script, style, and HTML tags to measure raw visible text density without Unicode panics.
fn strip_html_tags(html: &str) -> String {
    let without_scripts = SCRIPT_STYLE_REGEX.replace_all(html, " ");
    HTML_TAG_REGEX
        .replace_all(&without_scripts, " ")
        .to_string()
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

    #[test]
    fn test_spa_detection_with_unicode_and_emojis() {
        let unicode_spa = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Unicode 🚀 日本語</title></head>
            <body>
                <noscript>JavaScriptが必要です need to enable JavaScript</noscript>
                <div id="root"></div>
                <script src="/static/js/bundle.js"></script>
            </body>
            </html>
        "#;
        assert!(is_dynamic_spa(unicode_spa, "text/html"));
    }

    #[test]
    fn test_strip_html_tags_with_unicode() {
        let html = "A😀<script src=\"app.js\">var x = 1;</script><p>Text</p>";
        let stripped = strip_html_tags(html);
        assert!(stripped.contains("Text"));
    }
}
