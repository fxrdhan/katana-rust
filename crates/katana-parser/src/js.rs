use katana_core::navigation::Request;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use url::Url;

lazy_static! {
    static ref COMMON_JS_LIB_REGEX: Regex = Regex::new(
        r"(?i)(?:amplify|quantserve|slideshow|jquery|modernizr|polyfill|vendor|modules|gtm|underscore?|tween|retina|selectivizr|cufon|angular|swf|sha1|freestyle|bootstrap|d3|backbone|videojs|google[-_]analytics|material|redux|knockout|datepicker|datetimepicker|ember|react|ng|fusion|analytics|libs?|vendors?|node[-_]modules|lodash|moment|chart|highcharts|raphael|prototype|mootools|dojo|ext|yui|web[-_]?components|polymer|vue|svelte|next|nuxt|gatsby|express|koa|hapi|socket[-_.]?io|axios|superagent|request|bluebird|rxjs|ramda|immutable|flux|redux[-_]saga|mobx|relay|apollo|graphql|three|phaser|pixi|babylon|cannon|hammer|howler|gsap|velocity|mo[-_.]?js|popper|shepherd|prism|highlight|markdown[-_]?it|codemirror|ace[-_]?editor|tinymce|ckeditor|quill|simplemde|monaco[-_]?editor|pdf[-_.]?js|jspdf|fabric|paper|konva|p5|processing|matter[-_.]?js|box2d|planck|chart[-_.]?js|plotly|echarts|d3[-_.]?force|sigma|c3|nvd3|amcharts|vis[-_.]?js|dagre[-_.]?d3|cytoscape|leaflet|openlayers|ol3|mapbox|cesium|turf|moment[-_.]?timezone|luxon|dayjs|date[-_.]?fns|date[-_.]?io|flatpickr|pikaday|fullcalendar|draggable|interact|sortable|dragula|dropzone|filepond|uppy|fine[-_.]?uploader|plyr|mediaelement|flowplayer|jwplayer|video[-_.]?js|mediaelement[-_.]?js|dash[-_.]?js|hls[-_.]?js|videojs|wavesurfer|soundmanager|amplitude|pizzicato|tone|adroll|doubleclick|facebook-pixel|ga-audiences|googlesyndication|adsbygoogle|gpt|amazon-adsystem|criteo|taboola|outbrain|bidswitch|bidswitch\.net|spotxchange|yahoo|media\.net|contextweb|openx|pubmatic|rubiconproject|indexexchange|appnexus|liveintent|triplelift|verizonmedia|synacor|sonobi|yieldmo|gumgum|smartadserver|mopub|pubnative|inmobi|chartboost|tapjoy|admob|unityads|vungle|flurry|matomy|altitude|dataxu|thetradedesk|exponential|zypmedia|quantcast|mediamath|bidswitch|mgid|revcontent|powerlinks|rhythmone|airpush|smaato|adcolony|mopub|leadbolt|mobfox|nativo|revjet|smartyads|avocarrot|epom|imobile|supersonicads|loopme|applovin|pandora|mytarget|bidvertiser|chitika|popads|propellerads|buysellads|adhit|hilltopads|plugrush|popcash|popunder|revenuehits|trafficjunky|trafficfactory|zero-|smartoasis)(?:[-._][\w\d]*)*\.js$"
    ).unwrap();

    // Call expressions: fetch("..."), axios.get("..."), $.get("..."), $.post("..."), etc.
    static ref RE_CALL_EXPR: Regex = Regex::new(
        r#"(?i)(?:fetch|\$\.(?:get|post|ajax)|axios(?:\.(?:get|post|put|delete|patch))?|open|WebSocket|EventSource)\s*\(\s*["'`]([^"'`]+)["'`]"#
    ).unwrap();

    // Object properties: url: "...", endpoint: "...", path: "...", route: "...", action: "..."
    static ref RE_OBJECT_PROP: Regex = Regex::new(
        r#"(?i)(?:url|endpoint|path|route|action|uri|src|href)\s*:\s*["'`]([^"'`]+)["'`]"#
    ).unwrap();

    // Template literals with placeholders: `/api/${version}/users` -> sanitized to `/api/users`
    static ref RE_TEMPLATE_LITERAL: Regex = Regex::new(
        r#"`(/[^`]+)`"#
    ).unwrap();
    static ref RE_TEMPLATE_CLEANER: Regex = Regex::new(
        r#"\$\{[^}]+\}"#
    ).unwrap();
}

/// Checks if a file path belongs to a common third-party JS vendor library.
pub fn is_common_js_library(path: &str) -> bool {
    COMMON_JS_LIB_REGEX.is_match(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedJSEndpoint {
    pub endpoint: String,
    pub endpoint_type: String,
}

/// Analyzes JavaScript text and extracts endpoint candidates using semantic AST/token patterns.
pub fn extract_js_ast_endpoints(
    base_url: &str,
    content: &str,
    depth: usize,
    tag: &str,
) -> Vec<Request> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    // 1. Call expressions (fetch, axios, ajax, open, etc.)
    for caps in RE_CALL_EXPR.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let candidate = m.as_str().trim();
            if is_valid_js_candidate(candidate) && seen.insert(candidate.to_string()) {
                if let Ok(resolved) = base.join(candidate) {
                    results.push(Request {
                        method: "GET".to_string(),
                        url: resolved.to_string(),
                        depth: depth + 1,
                        tag: tag.to_string(),
                        attribute: "jsluice-call".to_string(),
                        root_hostname: root_hostname.clone(),
                        source: base_url.to_string(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // 2. Object properties (url: "...", endpoint: "...", path: "...")
    for caps in RE_OBJECT_PROP.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let candidate = m.as_str().trim();
            if is_valid_js_candidate(candidate) && seen.insert(candidate.to_string()) {
                if let Ok(resolved) = base.join(candidate) {
                    results.push(Request {
                        method: "GET".to_string(),
                        url: resolved.to_string(),
                        depth: depth + 1,
                        tag: tag.to_string(),
                        attribute: "jsluice-property".to_string(),
                        root_hostname: root_hostname.clone(),
                        source: base_url.to_string(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // 3. Template literals
    for caps in RE_TEMPLATE_LITERAL.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let raw_template = m.as_str();
            let cleaned = RE_TEMPLATE_CLEANER.replace_all(raw_template, "");
            let candidate = cleaned.trim();
            if is_valid_js_candidate(candidate) && seen.insert(candidate.to_string()) {
                if let Ok(resolved) = base.join(candidate) {
                    results.push(Request {
                        method: "GET".to_string(),
                        url: resolved.to_string(),
                        depth: depth + 1,
                        tag: tag.to_string(),
                        attribute: "jsluice-template".to_string(),
                        root_hostname: root_hostname.clone(),
                        source: base_url.to_string(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    results
}

fn is_valid_js_candidate(s: &str) -> bool {
    if s.is_empty()
        || s.len() > 1024
        || s.starts_with('#')
        || s.starts_with("data:")
        || s.starts_with("javascript:")
        || s.starts_with("mailto:")
        || s.starts_with("vbscript:")
    {
        return false;
    }

    // Must start with /, http://, https://, or ./ or ../
    s.starts_with('/')
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("./")
        || s.starts_with("../")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_common_js_library() {
        assert!(is_common_js_library("https://example.com/js/jquery.min.js"));
        assert!(is_common_js_library("/assets/vendor.bundle.js"));
        assert!(is_common_js_library("/static/react-dom.production.min.js"));
        assert!(is_common_js_library("https://cdn.example.com/lodash.js"));
        assert!(is_common_js_library("/node_modules/bootstrap.js"));

        assert!(!is_common_js_library("/app/main.js"));
        assert!(!is_common_js_library("/custom/dashboard_controller.js"));
        assert!(!is_common_js_library("https://example.com/api/routes.js"));
    }

    #[test]
    fn test_extract_js_ast_endpoints() {
        let base = "https://example.com/app/index.html";
        let script_code = r#"
            // API client calls
            fetch("/api/v1/users");
            axios.post('/api/v1/login', { user: 'admin' });
            $.get("/api/v1/stats");
            window.open("https://auth.example.com/oauth/authorize");

            // Object properties
            const config = {
                endpoint: "/api/v2/items",
                url: "https://api.example.com/v2/data",
                route: "/dashboard/settings"
            };

            // Template literal
            const userId = 42;
            const userUrl = `/api/v3/profile/${userId}/details`;
        "#;

        let requests = extract_js_ast_endpoints(base, script_code, 0, "script");
        let urls: Vec<&str> = requests.iter().map(|r| r.url.as_str()).collect();

        assert!(urls.contains(&"https://example.com/api/v1/users"));
        assert!(urls.contains(&"https://example.com/api/v1/login"));
        assert!(urls.contains(&"https://example.com/api/v1/stats"));
        assert!(urls.contains(&"https://auth.example.com/oauth/authorize"));
        assert!(urls.contains(&"https://example.com/api/v2/items"));
        assert!(urls.contains(&"https://api.example.com/v2/data"));
        assert!(urls.contains(&"https://example.com/dashboard/settings"));
        assert!(urls.contains(&"https://example.com/api/v3/profile//details"));
    }
}
