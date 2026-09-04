use crate::regex::extract_relative_endpoints;
use katana_core::navigation::Request;
use lazy_static::lazy_static;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use url::Url;

lazy_static! {
    static ref COMMON_JS_LIB_REGEX: Regex = Regex::new(
        r"(?i)(?:amplify|quantserve|slideshow|jquery|modernizr|polyfill|vendor|modules|gtm|underscore?|tween|retina|selectivizr|cufon|angular|swf|sha1|freestyle|bootstrap|d3|backbone|videojs|google[-_]analytics|material|redux|knockout|datepicker|datetimepicker|ember|react|ng|fusion|analytics|libs?|vendors?|node[-_]modules|lodash|moment|chart|highcharts|raphael|prototype|mootools|dojo|ext|yui|web[-_]?components|polymer|vue|svelte|next|nuxt|gatsby|express|koa|hapi|socket[-_.]?io|axios|superagent|request|bluebird|rxjs|ramda|immutable|flux|redux[-_]saga|mobx|relay|apollo|graphql|three|phaser|pixi|babylon|cannon|hammer|howler|gsap|velocity|mo[-_.]?js|popper|shepherd|prism|highlight|markdown[-_]?it|codemirror|ace[-_]?editor|tinymce|ckeditor|quill|simplemde|monaco[-_]?editor|pdf[-_.]?js|jspdf|fabric|paper|konva|p5|processing|matter[-_.]?js|box2d|planck|chart[-_.]?js|plotly|echarts|d3[-_.]?force|sigma|c3|nvd3|amcharts|vis[-_.]?js|dagre[-_.]?d3|cytoscape|leaflet|openlayers|ol3|mapbox|cesium|turf|moment[-_.]?timezone|luxon|dayjs|date[-_.]?fns|date[-_.]?io|flatpickr|pikaday|fullcalendar|draggable|interact|sortable|dragula|dropzone|filepond|uppy|fine[-_.]?uploader|plyr|mediaelement|flowplayer|jwplayer|video[-_.]?js|mediaelement[-_.]?js|dash[-_.]?js|hls[-_.]?js|videojs|wavesurfer|soundmanager|amplitude|pizzicato|tone|adroll|doubleclick|facebook-pixel|ga-audiences|googlesyndication|adsbygoogle|gpt|amazon-adsystem|criteo|taboola|outbrain|bidswitch|bidswitch\.net|spotxchange|yahoo|media\.net|contextweb|openx|pubmatic|rubiconproject|indexexchange|appnexus|liveintent|triplelift|verizonmedia|synacor|sonobi|yieldmo|gumgum|smartadserver|mopub|pubnative|inmobi|chartboost|tapjoy|admob|unityads|vungle|flurry|matomy|altitude|dataxu|thetradedesk|exponential|zypmedia|quantcast|mediamath|bidswitch|mgid|revcontent|powerlinks|rhythmone|airpush|smaato|adcolony|mopub|leadbolt|mobfox|nativo|revjet|smartyads|avocarrot|epom|imobile|supersonicads|loopme|applovin|pandora|mytarget|bidvertiser|chitika|popads|propellerads|buysellads|adhit|hilltopads|plugrush|popcash|popunder|revenuehits|trafficjunky|trafficfactory|zero-|smartoasis)(?:[-._][\w\d]*)*\.js$"
    ).unwrap();

    // Regex fallback patterns
    static ref RE_CALL_EXPR: Regex = Regex::new(
        r#"(?i)(?:fetch|\$\.(?:get|post|ajax)|axios(?:\.(?:get|post|put|delete|patch))?|open|WebSocket|EventSource)\s*\(\s*["'`]([^"'`]+)["'`]"#
    ).unwrap();

    static ref RE_OBJECT_PROP: Regex = Regex::new(
        r#"(?i)(?:url|endpoint|path|route|action|uri|src|href)\s*:\s*["'`]([^"'`]+)["'`]"#
    ).unwrap();

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

fn normalize_endpoint_slashes(s: &str) -> String {
    if let Some((scheme, rest)) = s.split_once("://") {
        let clean_rest = normalize_path_slashes(rest);
        format!("{}://{}", scheme, clean_rest)
    } else if let Some(stripped) = s.strip_prefix("//") {
        let clean_rest = normalize_path_slashes(stripped);
        format!("//{}", clean_rest)
    } else {
        normalize_path_slashes(s)
    }
}

fn normalize_path_slashes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_slash = false;
    for c in s.chars() {
        if c == '/' {
            if !prev_slash {
                result.push(c);
                prev_slash = true;
            }
        } else {
            result.push(c);
            prev_slash = false;
        }
    }
    result
}

/// Evaluates an AST expression to a static string if it is composed of string literals,
/// numeric/boolean literals, tracked variable identifiers, template literals, parenthesized expressions,
/// or binary additions (+).
fn resolve_expression_to_string(
    expr: &Expression,
    variables: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => Some(s.value.as_str().to_string()),
        Expression::NumericLiteral(n) => Some(n.value.to_string()),
        Expression::BooleanLiteral(b) => Some(b.value.to_string()),
        Expression::Identifier(id) => variables.get(id.name.as_str()).cloned(),
        Expression::ParenthesizedExpression(p) => {
            resolve_expression_to_string(&p.expression, variables)
        }
        Expression::BinaryExpression(bin) => {
            if bin.operator == BinaryOperator::Addition {
                let left = resolve_expression_to_string(&bin.left, variables)?;
                let right = resolve_expression_to_string(&bin.right, variables)?;
                Some(format!("{}{}", left, right))
            } else {
                None
            }
        }
        Expression::TemplateLiteral(tpl) => {
            let mut resolved = String::new();
            for (i, quasi) in tpl.quasis.iter().enumerate() {
                resolved.push_str(quasi.value.raw.as_str());
                if i < tpl.expressions.len() {
                    if let Some(val) = resolve_expression_to_string(&tpl.expressions[i], variables)
                    {
                        resolved.push_str(&val);
                    }
                }
            }
            if !resolved.is_empty() {
                Some(normalize_endpoint_slashes(&resolved))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Checks if a property key matches common endpoint property names.
fn is_url_property_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "url"
            | "uri"
            | "endpoint"
            | "path"
            | "route"
            | "action"
            | "src"
            | "href"
            | "api"
            | "target"
            | "link"
            | "download"
            | "baseurl"
            | "hostname"
            | "host"
    )
}

/// Checks if callee identifier/member matches common network and navigation calls.
fn is_network_callee(callee_str: &str) -> bool {
    let lower = callee_str.to_ascii_lowercase();
    lower == "fetch"
        || lower == "open"
        || lower == "websocket"
        || lower == "eventsource"
        || lower == "request"
        || lower.starts_with("axios")
        || lower.starts_with("$.")
        || lower.starts_with("jquery.")
        || lower.ends_with(".open")
        || lower.ends_with(".get")
        || lower.ends_with(".post")
        || lower.ends_with(".put")
        || lower.ends_with(".delete")
        || lower.ends_with(".patch")
        || lower.ends_with(".ajax")
        || lower.ends_with(".sendbeacon")
        || lower.ends_with(".navigate")
        || lower.ends_with(".push")
}

fn get_callee_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        _ => {
            if let Some(mem) = expr.as_member_expression() {
                match mem {
                    MemberExpression::StaticMemberExpression(s) => {
                        let obj_name = get_callee_name(&s.object);
                        let prop = s.property.name.as_str();
                        if let Some(obj) = obj_name {
                            Some(format!("{}.{}", obj, prop))
                        } else {
                            Some(prop.to_string())
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
    }
}

fn attribute_priority(attr: &str) -> u8 {
    match attr {
        "jsluice-call" => 4,
        "jsluice-property" => 3,
        "jsluice-template" | "jsluice-variable" | "jsluice-assignment" => 2,
        _ => 1,
    }
}

/// AST endpoint extractor with variable tracking and semantic context labeling.
struct AstEndpointExtractor {
    variables: HashMap<String, String>,
    candidates: HashMap<String, (String, u8)>,
    order: Vec<String>,
}

impl AstEndpointExtractor {
    fn new() -> Self {
        Self {
            variables: HashMap::new(),
            candidates: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn add_candidate(&mut self, candidate: String, attribute: &str) {
        let trimmed = candidate.trim();
        if is_valid_js_candidate(trimmed) {
            let p = attribute_priority(attribute);
            let key = trimmed.to_string();
            match self.candidates.get_mut(&key) {
                Some((existing_attr, existing_p)) => {
                    if p > *existing_p {
                        *existing_attr = attribute.to_string();
                        *existing_p = p;
                    }
                }
                None => {
                    self.candidates
                        .insert(key.clone(), (attribute.to_string(), p));
                    self.order.push(key);
                }
            }
        }
    }

    fn visit_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                for d in &decl.declarations {
                    let var_name = if let BindingPattern::BindingIdentifier(id) = &d.id {
                        Some(id.name.as_str().to_string())
                    } else {
                        None
                    };

                    if let Some(init) = &d.init {
                        self.visit_expression(init);
                        if let Some(val) = resolve_expression_to_string(init, &self.variables) {
                            if let Some(name) = var_name {
                                self.variables.insert(name, val.clone());
                            }
                            if is_valid_js_candidate(&val) {
                                self.add_candidate(val, "jsluice-variable");
                            }
                        }
                    }
                }
            }
            Statement::BlockStatement(b) => {
                for s in &b.body {
                    self.visit_statement(s);
                }
            }
            Statement::ExpressionStatement(e) => {
                self.visit_expression(&e.expression);
            }
            Statement::IfStatement(s) => {
                self.visit_expression(&s.test);
                self.visit_statement(&s.consequent);
                if let Some(alt) = &s.alternate {
                    self.visit_statement(alt);
                }
            }
            Statement::WhileStatement(s) => {
                self.visit_expression(&s.test);
                self.visit_statement(&s.body);
            }
            Statement::DoWhileStatement(s) => {
                self.visit_statement(&s.body);
                self.visit_expression(&s.test);
            }
            Statement::ForStatement(s) => {
                self.visit_statement(&s.body);
            }
            Statement::ForInStatement(s) => {
                self.visit_statement(&s.body);
            }
            Statement::ForOfStatement(s) => {
                self.visit_statement(&s.body);
            }
            Statement::ReturnStatement(s) => {
                if let Some(arg) = &s.argument {
                    self.visit_expression(arg);
                }
            }
            Statement::ThrowStatement(s) => {
                self.visit_expression(&s.argument);
            }
            Statement::TryStatement(s) => {
                for st in &s.block.body {
                    self.visit_statement(st);
                }
                if let Some(h) = &s.handler {
                    for st in &h.body.body {
                        self.visit_statement(st);
                    }
                }
                if let Some(f) = &s.finalizer {
                    for st in &f.body {
                        self.visit_statement(st);
                    }
                }
            }
            Statement::SwitchStatement(s) => {
                self.visit_expression(&s.discriminant);
                for case in &s.cases {
                    for st in &case.consequent {
                        self.visit_statement(st);
                    }
                }
            }
            Statement::FunctionDeclaration(f) => {
                if let Some(body) = &f.body {
                    for st in &body.statements {
                        self.visit_statement(st);
                    }
                }
            }
            Statement::ExportDefaultDeclaration(export_default) => {
                if let ExportDefaultDeclarationKind::FunctionDeclaration(f) =
                    &export_default.declaration
                {
                    if let Some(body) = &f.body {
                        for st in &body.statements {
                            self.visit_statement(st);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn visit_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::StringLiteral(s) => {
                let val = s.value.as_str();
                if is_valid_js_candidate(val) {
                    self.add_candidate(val.to_string(), "jsluice-literal");
                }
            }
            Expression::TemplateLiteral(tpl) => {
                for e in &tpl.expressions {
                    self.visit_expression(e);
                }
                // Static prefix extraction (before any dynamic placeholders)
                if let Some(first_quasi) = tpl.quasis.first() {
                    let prefix = first_quasi.value.raw.as_str();
                    if is_valid_js_candidate(prefix) {
                        self.add_candidate(prefix.to_string(), "jsluice-template");
                    }
                }
                // Resolved / sanitized template literal
                if let Some(resolved) = resolve_expression_to_string(expr, &self.variables) {
                    if is_valid_js_candidate(&resolved) {
                        self.add_candidate(resolved, "jsluice-template");
                    }
                }
            }
            Expression::CallExpression(call) => {
                self.visit_expression(&call.callee);
                let callee_name = get_callee_name(&call.callee);
                let is_net = callee_name
                    .as_deref()
                    .map(is_network_callee)
                    .unwrap_or(false);

                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.visit_expression(e);
                        if let Some(val) = resolve_expression_to_string(e, &self.variables) {
                            if is_valid_js_candidate(&val) {
                                let attr = if is_net {
                                    "jsluice-call"
                                } else {
                                    "jsluice-literal"
                                };
                                self.add_candidate(val, attr);
                            }
                        }
                    }
                }
            }
            Expression::NewExpression(call) => {
                self.visit_expression(&call.callee);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.visit_expression(e);
                        if let Some(val) = resolve_expression_to_string(e, &self.variables) {
                            if is_valid_js_candidate(&val) {
                                self.add_candidate(val, "jsluice-call");
                            }
                        }
                    }
                }
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    if let ObjectPropertyKind::ObjectProperty(p) = prop {
                        self.visit_expression(&p.value);
                        let key_name = match &p.key {
                            PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
                            PropertyKey::StringLiteral(s) => Some(s.value.to_string()),
                            _ => None,
                        };
                        let is_url_prop = key_name
                            .as_deref()
                            .map(is_url_property_key)
                            .unwrap_or(false);
                        if let Some(val) = resolve_expression_to_string(&p.value, &self.variables) {
                            if is_valid_js_candidate(&val) {
                                let attr = if is_url_prop {
                                    "jsluice-property"
                                } else {
                                    "jsluice-literal"
                                };
                                self.add_candidate(val, attr);
                            }
                        }
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for elem in &arr.elements {
                    if let Some(e) = elem.as_expression() {
                        self.visit_expression(e);
                    }
                }
            }
            Expression::AssignmentExpression(assign) => {
                self.visit_expression(&assign.right);
                if let Some(val) = resolve_expression_to_string(&assign.right, &self.variables) {
                    if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left {
                        self.variables.insert(id.name.to_string(), val.clone());
                    }
                    if is_valid_js_candidate(&val) {
                        self.add_candidate(val, "jsluice-assignment");
                    }
                }
            }
            Expression::BinaryExpression(bin) => {
                self.visit_expression(&bin.left);
                self.visit_expression(&bin.right);
                if bin.operator == BinaryOperator::Addition {
                    if let Some(val) = resolve_expression_to_string(expr, &self.variables) {
                        if is_valid_js_candidate(&val) {
                            self.add_candidate(val, "jsluice-variable");
                        }
                    }
                }
            }
            Expression::LogicalExpression(log) => {
                self.visit_expression(&log.left);
                self.visit_expression(&log.right);
            }
            Expression::ConditionalExpression(cond) => {
                self.visit_expression(&cond.test);
                self.visit_expression(&cond.consequent);
                self.visit_expression(&cond.alternate);
            }
            Expression::ParenthesizedExpression(p) => {
                self.visit_expression(&p.expression);
            }
            Expression::SequenceExpression(seq) => {
                for e in &seq.expressions {
                    self.visit_expression(e);
                }
            }
            Expression::AwaitExpression(a) => {
                self.visit_expression(&a.argument);
            }
            Expression::UnaryExpression(u) => {
                self.visit_expression(&u.argument);
            }
            _ => {
                if let Some(mem) = expr.as_member_expression() {
                    match mem {
                        MemberExpression::StaticMemberExpression(s) => {
                            self.visit_expression(&s.object);
                        }
                        MemberExpression::ComputedMemberExpression(c) => {
                            self.visit_expression(&c.object);
                            self.visit_expression(&c.expression);
                        }
                        MemberExpression::PrivateFieldExpression(p) => {
                            self.visit_expression(&p.object);
                        }
                    }
                }
            }
        }
    }
}

/// Fallback regex extractor invoked when AST parser fails or on partial scripts.
pub fn extract_js_regex_fallback(
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

    // 1. Call expressions regex
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

    // 2. Object properties regex
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

    // 3. Template literals regex
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

    // 4. Relative endpoints regex
    for candidate in extract_relative_endpoints(content) {
        let trimmed = candidate.trim();
        if is_valid_js_candidate(trimmed) && seen.insert(trimmed.to_string()) {
            if let Ok(resolved) = base.join(trimmed) {
                results.push(Request {
                    method: "GET".to_string(),
                    url: resolved.to_string(),
                    depth: depth + 1,
                    tag: tag.to_string(),
                    attribute: "jsluice-regex".to_string(),
                    root_hostname: root_hostname.clone(),
                    source: base_url.to_string(),
                    ..Default::default()
                });
            }
        }
    }

    results
}

/// Analyzes JavaScript text and extracts endpoint candidates using semantic AST
/// with variable tracking and regex fallback.
pub fn extract_js_ast_endpoints(
    base_url: &str,
    content: &str,
    depth: usize,
    tag: &str,
) -> Vec<Request> {
    let mut results = Vec::new();
    let mut seen_urls = HashSet::new();

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return results,
    };
    let root_hostname = base.host_str().unwrap_or("").to_string();

    let allocator = Allocator::default();
    let source_type = SourceType::default()
        .with_module(true)
        .with_jsx(true)
        .with_typescript(true);

    let parser = Parser::new(&allocator, content, source_type);
    let ret = parser.parse();

    let mut used_ast = false;

    if !ret.panicked {
        let mut extractor = AstEndpointExtractor::new();
        for stmt in &ret.program.body {
            extractor.visit_statement(stmt);
        }

        for candidate in &extractor.order {
            if let Some((attribute, _)) = extractor.candidates.get(candidate) {
                if let Ok(resolved) = base.join(candidate) {
                    let resolved_str = resolved.to_string();
                    if seen_urls.insert(resolved_str.clone()) {
                        results.push(Request {
                            method: "GET".to_string(),
                            url: resolved_str,
                            depth: depth + 1,
                            tag: tag.to_string(),
                            attribute: attribute.clone(),
                            root_hostname: root_hostname.clone(),
                            source: base_url.to_string(),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        used_ast = !results.is_empty();
    }

    // Fallback or complementary regex extraction if AST panicked, has parse errors, or yielded nothing
    if !used_ast || !ret.diagnostics.is_empty() {
        let fallback_results = extract_js_regex_fallback(base_url, content, depth, tag);
        for req in fallback_results {
            if seen_urls.insert(req.url.clone()) {
                results.push(req);
            }
        }
    }

    results
}

fn is_valid_js_candidate(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 1024
        || s.starts_with('#')
        || s.starts_with("data:")
        || s.starts_with("javascript:")
        || s.starts_with("mailto:")
        || s.starts_with("vbscript:")
        || s.starts_with("tel:")
    {
        return false;
    }

    // Disallow characters that are invalid in URLs/endpoints
    if s.contains('\n')
        || s.contains('\r')
        || s.contains('\t')
        || s.contains('<')
        || s.contains('>')
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
        assert!(urls.contains(&"https://example.com/api/v3/profile/42/details"));

        let attr_map: HashMap<_, _> = requests
            .iter()
            .map(|r| (r.url.as_str(), r.attribute.as_str()))
            .collect();
        assert_eq!(
            attr_map.get("https://example.com/api/v1/users"),
            Some(&"jsluice-call")
        );
        assert_eq!(
            attr_map.get("https://example.com/api/v1/login"),
            Some(&"jsluice-call")
        );
        assert_eq!(
            attr_map.get("https://example.com/api/v1/stats"),
            Some(&"jsluice-call")
        );
        assert_eq!(
            attr_map.get("https://auth.example.com/oauth/authorize"),
            Some(&"jsluice-call")
        );
        assert_eq!(
            attr_map.get("https://example.com/api/v2/items"),
            Some(&"jsluice-property")
        );
        assert_eq!(
            attr_map.get("https://api.example.com/v2/data"),
            Some(&"jsluice-property")
        );
        assert_eq!(
            attr_map.get("https://example.com/dashboard/settings"),
            Some(&"jsluice-property")
        );
        assert_eq!(
            attr_map.get("https://example.com/api/v3/profile/42/details"),
            Some(&"jsluice-template")
        );
    }

    #[test]
    fn test_ast_variable_tracking_and_concatenation() {
        let base = "https://example.com/app/index.html";
        let script_code = r#"
            const API_BASE = "https://api.example.com";
            const VERSION = "/v1";
            const USERS_PATH = "/users";
            const FULL_URL = API_BASE + VERSION + USERS_PATH;

            let dynamicEndpoint;
            dynamicEndpoint = "/dynamic/resource";

            fetch(FULL_URL);
            fetch(dynamicEndpoint);

            const tmpl = `${API_BASE}/graphql`;
            fetch(tmpl);
        "#;

        let requests = extract_js_ast_endpoints(base, script_code, 0, "script");
        let urls: Vec<&str> = requests.iter().map(|r| r.url.as_str()).collect();

        assert!(urls.contains(&"https://api.example.com/v1/users"));
        assert!(urls.contains(&"https://example.com/dynamic/resource"));
        assert!(urls.contains(&"https://api.example.com/graphql"));
    }

    #[test]
    fn test_regex_fallback_on_malformed_syntax() {
        let base = "https://example.com/app/index.html";
        // Malformed JS syntax that would fail strict AST parsing
        let malformed_script = r#"
            function broken() {{{
                fetch("/api/fallback/users");
                const obj = { endpoint: "/api/fallback/endpoint" };
            }}}}
        "#;

        let requests = extract_js_ast_endpoints(base, malformed_script, 0, "script");
        let urls: Vec<&str> = requests.iter().map(|r| r.url.as_str()).collect();

        assert!(urls.contains(&"https://example.com/api/fallback/users"));
        assert!(urls.contains(&"https://example.com/api/fallback/endpoint"));
    }
}
