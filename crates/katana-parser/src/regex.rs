use katana_core::navigation::Request;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use url::Url;

lazy_static! {
    static ref PAGE_BODY_REGEX: Regex = Regex::new(
        r"(?i)(?:((?:[\.]{1,2}/[A-Za-z0-9\-_/\\?&@\.?=%]+)|(https?://[A-Za-z0-9_\-\.]+(?:[\.]{0,2})?/[A-Za-z0-9\-_/\\?&@\.?=%]+)|(/[A-Za-z0-9\-_/\\?&@\.%]+\.(?:aspx?|action|cfm|cgi|do|pl|css|x?html?|js(?:p|on)?|pdf|php5?|py|rss))|([A-Za-z0-9\-_?&@\.%]+/[A-Za-z0-9/\\\-_?&@\.%]+\.(?:aspx?|action|cfm|cgi|do|pl|css|x?html?|js(?:p|on)?|pdf|php5?|py|rss))))"
    ).unwrap();

    static ref RELATIVE_ENDPOINTS_REGEX: Regex = Regex::new(
        &r#"(?i)(?:"|'|\s)((?:(https?://[A-Za-z0-9_\-.]+(?:\:\d{1,5})?)+([\.]{1,2})?/[A-Za-z0-9/\-_\\.%]+(?:[\?|#][^"']+)?)凡((\.{1,2}/)?[a-zA-Z0-9\-_/\\%]+\.(?:aspx?|js(?:on|p)?|html|php5?|action|do)(?:[\?|#][^"']+)?)凡((\.{0,2}/)[a-zA-Z0-9\-_/\\%]+(?:/|\\)[a-zA-Z0-9\-_]{3,}(?:[\?|#][^"']+)?)凡((\.{0,2})[a-zA-Z0-9\-_/\\%]{3,}/))(?:"|'|\s)"#
            .replace('凡', "|"),
    )
    .unwrap();
}

/// Extract raw matched endpoint strings from page body text.
pub fn extract_body_endpoints(data: &str) -> Vec<String> {
    let mut matches = Vec::new();
    let mut unique = HashSet::new();

    for caps in PAGE_BODY_REGEX.captures_iter(data) {
        if let Some(m) = caps.get(1) {
            let s = m.as_str();
            if unique.insert(s.to_string()) {
                matches.push(s.to_string());
            }
        }
    }

    matches
}

/// Extract raw matched relative endpoint strings from JavaScript data.
pub fn extract_relative_endpoints(data: &str) -> Vec<String> {
    let mut matches = Vec::new();
    let mut unique = HashSet::new();

    // Pad with space so start/end boundary matches
    let padded = format!(" {} ", data);

    for caps in RELATIVE_ENDPOINTS_REGEX.captures_iter(&padded) {
        if let Some(m) = caps.get(1) {
            let s = m.as_str();
            if unique.insert(s.to_string()) {
                matches.push(s.to_string());
            }
        }
    }

    matches
}

/// Extract candidate endpoints from raw JavaScript or body text using regex.
pub fn extract_endpoints_from_regex(
    base_url: &str,
    content: &str,
    current_depth: usize,
) -> Vec<Request> {
    let mut results = Vec::new();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    let extracted = extract_relative_endpoints(content);
    for match_str in extracted {
        if let Ok(resolved) = base.join(&match_str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_body_regex_golden_vectors() {
        let test_cases = [
            (
                "Mix of patterns",
                r#"Some text <a href="./rel/file.txt">link1</a> and <img src="../rel2/file.php"/> also http://a.com/b.html and https://c.com/d.aspx?p=1 finally /abs/path.js and rel/path/script.py end"#,
                vec![
                    "./rel/file.txt",
                    "../rel2/file.php",
                    "http://a.com/b.html",
                    "https://c.com/d.aspx?p=1",
                    "/abs/path.js",
                    "rel/path/script.py",
                ],
            ),
            (
                "No matches",
                "Just some plain text without any URLs or paths.",
                vec![],
            ),
            (
                "Only BodyC0",
                r#""./path1" '../path2'"#,
                vec!["./path1", "../path2"],
            ),
            (
                "Only BodyC1",
                "http://example.com/page1 https://secure.com/page2",
                vec!["http://example.com/page1", "https://secure.com/page2"],
            ),
            (
                "Only BodyC2",
                r#""/path/to/file.css" '/another/script.js'"#,
                vec!["/path/to/file.css", "/another/script.js"],
            ),
            (
                "Only BodyC3",
                r#""relative/path/file.php" 'another/relative/page.html'"#,
                vec!["relative/path/file.php", "another/relative/page.html"],
            ),
        ];

        for (name, input, expected) in test_cases {
            let actual = extract_body_endpoints(input);
            let mut sorted_actual = actual;
            let mut sorted_expected = expected.into_iter().map(String::from).collect::<Vec<_>>();
            sorted_actual.sort();
            sorted_expected.sort();
            assert_eq!(
                sorted_actual, sorted_expected,
                "Test case [{name}] failed for input: {input}"
            );
        }
    }

    #[test]
    fn test_relative_endpoints_regex_golden_vectors() {
        let test_cases = [
            (
                "Mix of patterns in JS-like context",
                r#"var u1 = "https://d.com/e.php?q=1"; let u2 = './f/g.js'; const u3 = '../h/i.html'; func('/j/k/lll'); load('m/nnn/'); action("o/p.action");"#,
                vec![
                    "https://d.com/e.php?q=1",
                    "./f/g.js",
                    "../h/i.html",
                    "/j/k/lll",
                    "m/nnn/",
                    "o/p.action",
                ],
            ),
            (
                "No matches",
                "var x = 1; let y = 'hello'; const z = true;",
                vec![],
            ),
            (
                "Only JsC0",
                r#""https://example.com/api/v1?key=123" 'http://localhost:8080/test#section'"#,
                vec![
                    "https://example.com/api/v1?key=123",
                    "http://localhost:8080/test#section",
                ],
            ),
            (
                "Only JsC1",
                r#""./script.js" 'page.php?id=5'"#,
                vec!["./script.js", "page.php?id=5"],
            ),
            (
                "Only JsC2",
                r#""/api/v2/users" '/data/items/fetch'"#,
                vec!["/api/v2/users", "/data/items/fetch"],
            ),
            (
                "Only JsC3",
                r#""./images/" '../assets/' "static/""#,
                vec!["./images/", "../assets/", "static/"],
            ),
        ];

        for (name, input, expected) in test_cases {
            let actual = extract_relative_endpoints(input);
            let mut sorted_actual = actual;
            let mut sorted_expected = expected.into_iter().map(String::from).collect::<Vec<_>>();
            sorted_actual.sort();
            sorted_expected.sort();
            assert_eq!(
                sorted_actual, sorted_expected,
                "Test case [{name}] failed for input: {input}"
            );
        }
    }
}
