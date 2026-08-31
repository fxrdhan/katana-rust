use katana_core::navigation::Request;
use scraper::{Html, Selector};
use url::Url;

struct ParserContext<'a> {
    base_url: &'a str,
    base: &'a Url,
    root_hostname: &'a str,
    current_depth: usize,
}

/// Extracts the inner text of all `<script>` tags from an HTML document.
pub fn extract_inline_scripts(html_content: &str) -> Vec<String> {
    let mut scripts = Vec::new();
    let document = Html::parse_document(html_content);
    if let Ok(selector) = Selector::parse("script") {
        for element in document.select(&selector) {
            let text: String = element.text().collect();
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                scripts.push(trimmed.to_string());
            }
        }
    }
    scripts
}

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

    let ctx = ParserContext {
        base_url,
        base: &base,
        root_hostname: &root_hostname,
        current_depth,
    };

    let tag_selectors = [
        ("a", "href"),
        ("a", "ping"),
        ("link[href]", "href"),
        ("script[src]", "src"),
        ("iframe", "src"),
        ("frame", "src"),
        ("embed", "src"),
        ("img", "src"),
        ("img", "dynsrc"),
        ("img", "longdesc"),
        ("img", "lowsrc"),
        ("video", "src"),
        ("video", "poster"),
        ("track", "src"),
        ("audio", "src"),
        ("source", "src"),
        ("body", "background"),
        ("table", "background"),
        ("td", "background"),
        ("blockquote", "cite"),
        ("area", "ping"),
        ("button", "formaction"),
        ("object", "data"),
        ("object", "codebase"),
        ("applet", "archive"),
        ("applet", "codebase"),
        ("html", "manifest"),
        ("image", "href"),
        ("[hx-get]", "hx-get"),
        ("[hx-post]", "hx-post"),
        ("[hx-put]", "hx-put"),
        ("[hx-patch]", "hx-patch"),
    ];

    for (selector_str, attr_name) in tag_selectors {
        if let Ok(selector) = Selector::parse(selector_str) {
            for element in document.select(&selector) {
                if let Some(attr_val) = element.value().attr(attr_name) {
                    process_candidate_url(&ctx, attr_val, selector_str, attr_name, &mut results);
                }

                // Handle srcset attribute for multi-URL parsing
                if let Some(srcset_val) = element.value().attr("srcset") {
                    for entry in srcset_val.split(',') {
                        let parts: Vec<&str> = entry.split_whitespace().collect();
                        if let Some(src_candidate) = parts.first() {
                            process_candidate_url(
                                &ctx,
                                src_candidate,
                                selector_str,
                                "srcset",
                                &mut results,
                            );
                        }
                    }
                }
            }
        }
    }

    results
}

fn process_candidate_url(
    ctx: &ParserContext,
    raw_val: &str,
    tag: &str,
    attribute: &str,
    results: &mut Vec<Request>,
) {
    let trimmed = raw_val.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("data:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("vbscript:")
    {
        return;
    }

    if let Ok(resolved) = ctx.base.join(trimmed) {
        let method = match attribute {
            "hx-post" => "POST",
            "hx-put" => "PUT",
            "hx-patch" => "PATCH",
            _ => "GET",
        };

        results.push(Request {
            method: method.to_string(),
            url: resolved.to_string(),
            depth: ctx.current_depth + 1,
            tag: tag.to_string(),
            attribute: attribute.to_string(),
            root_hostname: ctx.root_hostname.to_string(),
            source: ctx.base_url.to_string(),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_parser_golden_vectors() {
        let base = "https://security-crawl-maze.app/html/body/xyz/";

        // a[href] and a[ping]
        let html_a = r#"<a href="/test/html/body/a/href.found">Link</a><a ping="/test/html/body/a/ping.found">Ping</a>"#;
        let res_a = parse_html_endpoints(base, html_a, 0);
        let urls_a: Vec<&str> = res_a.iter().map(|r| r.url.as_str()).collect();
        assert!(urls_a.contains(&"https://security-crawl-maze.app/test/html/body/a/href.found"));
        assert!(urls_a.contains(&"https://security-crawl-maze.app/test/html/body/a/ping.found"));

        // body[background]
        let html_bg = r#"<body background="/test/html/body/background.found"></body>"#;
        let res_bg = parse_html_endpoints(base, html_bg, 0);
        assert_eq!(
            res_bg[0].url,
            "https://security-crawl-maze.app/test/html/body/background.found"
        );

        // blockquote[cite]
        let html_cite = r#"<blockquote cite="/test/html/body/blockquote/cite.found"></blockquote>"#;
        let res_cite = parse_html_endpoints(base, html_cite, 0);
        assert_eq!(
            res_cite[0].url,
            "https://security-crawl-maze.app/test/html/body/blockquote/cite.found"
        );

        // area[ping]
        let html_area = r##"<map name="map"><area ping="/test/html/body/map/area/ping.found" shape="rect" href="#"></map>"##;
        let res_area = parse_html_endpoints(base, html_area, 0);
        assert_eq!(
            res_area[0].url,
            "https://security-crawl-maze.app/test/html/body/map/area/ping.found"
        );

        // audio & source srcset
        let html_audio = r#"<audio controls><source src="/test/audio.mp3"><source srcset="/test/audio1x.mp3 1x, /test/audio2x.mp3 2x"></audio>"#;
        let res_audio = parse_html_endpoints(base, html_audio, 0);
        let urls_audio: Vec<&str> = res_audio.iter().map(|r| r.url.as_str()).collect();
        assert!(urls_audio.contains(&"https://security-crawl-maze.app/test/audio.mp3"));
        assert!(urls_audio.contains(&"https://security-crawl-maze.app/test/audio1x.mp3"));
        assert!(urls_audio.contains(&"https://security-crawl-maze.app/test/audio2x.mp3"));

        // img variants
        let html_img = r#"<img dynsrc="/dyn.png" longdesc="/long.html" lowsrc="/low.png" src="/src.png" srcset="/img1x.png 1x, /img2x.png 2x">"#;
        let res_img = parse_html_endpoints(base, html_img, 0);
        let urls_img: Vec<&str> = res_img.iter().map(|r| r.url.as_str()).collect();
        assert!(urls_img.contains(&"https://security-crawl-maze.app/dyn.png"));
        assert!(urls_img.contains(&"https://security-crawl-maze.app/long.html"));
        assert!(urls_img.contains(&"https://security-crawl-maze.app/low.png"));
        assert!(urls_img.contains(&"https://security-crawl-maze.app/src.png"));
        assert!(urls_img.contains(&"https://security-crawl-maze.app/img1x.png"));
        assert!(urls_img.contains(&"https://security-crawl-maze.app/img2x.png"));

        // HTMX verbs
        let html_htmx = r#"<div hx-get="/api/items" hx-post="/api/create" hx-put="/api/update" hx-patch="/api/patch"></div>"#;
        let res_htmx = parse_html_endpoints(base, html_htmx, 0);
        let methods_htmx: Vec<(&str, &str)> = res_htmx
            .iter()
            .map(|r| (r.method.as_str(), r.url.as_str()))
            .collect();
        assert!(methods_htmx.contains(&("GET", "https://security-crawl-maze.app/api/items")));
        assert!(methods_htmx.contains(&("POST", "https://security-crawl-maze.app/api/create")));
        assert!(methods_htmx.contains(&("PUT", "https://security-crawl-maze.app/api/update")));
        assert!(methods_htmx.contains(&("PATCH", "https://security-crawl-maze.app/api/patch")));

        // Blacklist schemes rejected
        let html_blacklist = r#"<a href="javascript:void(0)">JS</a><a href="mailto:test@example.com">Mail</a><img src="data:image/png;base64,123">"#;
        let res_bl = parse_html_endpoints(base, html_blacklist, 0);
        assert!(res_bl.is_empty(), "Blacklisted schemes must be rejected");
    }
}
