use dashmap::DashSet;
use katana_similarity::simhash::{hamming_distance, simhash64};
use lazy_static::lazy_static;
use regex::Regex;
use std::sync::Arc;

lazy_static! {
    static ref RE_SCRIPT_TAG: Regex = Regex::new(r"(?is)<script\b[^>]*>.*?</script>").unwrap();
    static ref RE_STYLE_TAG: Regex = Regex::new(r"(?is)<style\b[^>]*>.*?</style>").unwrap();
    static ref RE_COMMENTS: Regex = Regex::new(r"(?s)<!--.*?-->").unwrap();
    static ref RE_DYNAMIC_ATTRS: Regex = Regex::new(
        r#"(?i)\b(?:csrf|nonce|token|timestamp|_t|_ts|auth|session|sig)\s*=\s*["'][^"']*["']"#
    )
    .unwrap();
    static ref RE_WHITESPACE: Regex = Regex::new(r"\s+").unwrap();
}

/// Strips dynamic tokens, scripts, styles, and comments from rendered HTML.
pub fn strip_dom(raw_html: &str) -> String {
    let no_scripts = RE_SCRIPT_TAG.replace_all(raw_html, "");
    let no_styles = RE_STYLE_TAG.replace_all(&no_scripts, "");
    let no_comments = RE_COMMENTS.replace_all(&no_styles, "");
    let no_dyn_attrs = RE_DYNAMIC_ATTRS.replace_all(&no_comments, "");
    let clean = RE_WHITESPACE.replace_all(&no_dyn_attrs, " ");
    clean.trim().to_string()
}

/// Represents a distinct browser page state in headless/hybrid crawling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageState {
    pub url: String,
    pub depth: usize,
    pub simhash: u64,
}

impl PageState {
    pub fn from_html(url: &str, depth: usize, raw_html: &str) -> Self {
        let stripped = strip_dom(raw_html);
        let hash = simhash64(stripped.split_whitespace());
        Self {
            url: url.to_string(),
            depth,
            simhash: hash,
        }
    }

    /// Checks if two page states are structurally identical within Hamming distance tolerance.
    pub fn is_similar(&self, other: &PageState, tolerance: u32) -> bool {
        hamming_distance(self.simhash, other.simhash) <= tolerance
    }
}

/// Thread-safe State Graph for tracking browser DOM states and avoiding duplicate page loops.
#[derive(Debug, Clone, Default)]
pub struct StateGraph {
    states: Arc<DashSet<u64>>,
    tolerance: u32,
}

impl StateGraph {
    pub fn new(tolerance: u32) -> Self {
        Self {
            states: Arc::new(DashSet::new()),
            tolerance,
        }
    }

    /// Returns true if the page state has already been seen (or is within tolerance distance).
    pub fn contains_or_insert(&self, state: &PageState) -> bool {
        if self.states.contains(&state.simhash) {
            return true;
        }

        // Check distance against existing hashes if tolerance > 0
        if self.tolerance > 0 {
            for existing in self.states.iter() {
                if hamming_distance(*existing, state.simhash) <= self.tolerance {
                    return true;
                }
            }
        }

        self.states.insert(state.simhash);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_dom() {
        let html = r#"
            <html>
                <head>
                    <script>var x = 123; let token = "random_xyz";</script>
                    <style>body { color: red; }</style>
                </head>
                <body>
                    <!-- A comment -->
                    <div id="content" csrf="secret_123" nonce="abc">
                        <h1>Welcome</h1>
                        <p>User Dashboard</p>
                    </div>
                </body>
            </html>
        "#;

        let stripped = strip_dom(html);
        assert!(!stripped.contains("var x = 123"));
        assert!(!stripped.contains("body { color: red; }"));
        assert!(!stripped.contains("A comment"));
        assert!(!stripped.contains("secret_123"));
        assert!(stripped.contains("Welcome"));
        assert!(stripped.contains("User Dashboard"));
    }

    #[test]
    fn test_page_state_similarity() {
        let html1 = "<div><h1>Hello World</h1><p>Welcome to our platform</p></div>";
        let html2 =
            "<div><h1>Hello World</h1><p>Welcome to our platform</p><!-- tiny comment --></div>";

        let state1 = PageState::from_html("https://example.com/page1", 1, html1);
        let state2 = PageState::from_html("https://example.com/page2", 1, html2);

        assert!(state1.is_similar(&state2, 2));

        let graph = StateGraph::new(2);
        assert!(!graph.contains_or_insert(&state1)); // first time -> false
        assert!(graph.contains_or_insert(&state2)); // similar -> true
    }
}
