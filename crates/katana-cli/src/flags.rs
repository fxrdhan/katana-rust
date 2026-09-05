use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "katana",
    author = "fxrdhan <fxrdhan@github>",
    version,
    about = "A fast, memory-safe, asynchronous web crawler for offensive-security automation (Rust port)"
)]
pub struct CliArgs {
    /// Target URL to crawl
    #[arg(short = 'u', long = "url")]
    pub url: Option<String>,

    /// List of target URLs (file path)
    #[arg(short = 'l', long = "list")]
    pub list: Option<String>,

    /// Raw HTTP request file path (-r, -request)
    #[arg(short = 'r', long = "raw-request", alias = "request")]
    pub raw_request: Option<String>,

    /// Resume scan from state stored in checkpoint file (-resume)
    #[arg(long = "resume")]
    pub resume: Option<String>,

    /// Maximum crawl depth
    #[arg(short = 'd', long = "depth", default_value_t = 3)]
    pub depth: usize,

    /// Number of concurrent workers
    #[arg(short = 'c', long = "concurrency", default_value_t = 10)]
    pub concurrency: usize,

    /// Request timeout in seconds
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    pub timeout: u64,

    /// Number of concurrent inputs to process (-p, --parallelism)
    #[arg(short = 'p', long = "parallelism", default_value_t = 10)]
    pub parallelism: usize,

    /// Request delay between requests in seconds (-rd, --delay)
    #[arg(long = "delay", alias = "rd", default_value_t = 0)]
    pub delay: u64,

    /// Custom header/cookie to include in all HTTP requests in header:value format (-H)
    #[arg(short = 'H', long = "headers")]
    pub headers: Vec<String>,

    /// Maximum duration to crawl target in seconds or duration format like 10s, 5m (-ct)
    #[arg(long = "crawl-duration", alias = "ct")]
    pub crawl_duration: Option<String>,

    /// Maximum requests to send per second (-rl)
    #[arg(long = "rate-limit", alias = "rl", default_value_t = 150)]
    pub rate_limit: usize,

    /// Maximum requests to send per minute (-rlm)
    #[arg(long = "rate-limit-minute", alias = "rlm", default_value_t = 0)]
    pub rate_limit_minute: usize,

    /// In-scope URL regex to be followed by crawler (-cs)
    #[arg(long = "crawl-scope", alias = "cs", value_delimiter = ',')]
    pub crawl_scope: Vec<String>,

    /// Out-of-scope URL regex to be excluded by crawler (-cos)
    #[arg(long = "crawl-out-scope", alias = "cos", value_delimiter = ',')]
    pub crawl_out_scope: Vec<String>,

    /// Exclude host matching specified filter ('private-ips', ip, regex) (-e, --exclude)
    #[arg(short = 'e', long = "exclude", value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Exclude private/intranet IPs and loopback from crawling (--exclude-private-ips)
    #[arg(long = "exclude-private-ips")]
    pub exclude_private_ips: bool,

    /// Pre-defined scope field (dn, rdn, fqdn) or custom regex (-fs)
    #[arg(long = "field-scope", alias = "fs", default_value = "rdn")]
    pub field_scope: String,

    /// Disables host-based default scope (-ns, --no-scope)
    #[arg(long = "no-scope", alias = "ns")]
    pub no_scope: bool,

    /// Enable headless browser crawling (-hl)
    #[arg(long = "headless", alias = "hl")]
    pub headless: bool,

    /// Enable headless hybrid crawling (-hb, --hybrid)
    #[arg(long = "headless-hybrid", alias = "hb", visible_alias = "hybrid")]
    pub headless_hybrid: bool,

    /// Use system installed chrome browser
    #[arg(long = "system-chrome")]
    pub system_chrome: bool,

    /// Chrome DevTools Protocol websocket URL
    #[arg(long = "chrome-ws-url")]
    pub chrome_ws_url: Option<String>,

    /// Chrome data directory for browser profile storage
    #[arg(long = "chrome-data-dir")]
    pub chrome_data_dir: Option<String>,

    /// Automatically fill and submit HTML forms (-aff)
    #[arg(long = "automatic-form-fill", alias = "aff")]
    pub automatic_form_fill: bool,

    /// Scan response bodies for exposed credentials and secrets (-secrets)
    #[arg(long = "scan-secrets", alias = "secrets")]
    pub scan_secrets: bool,

    /// Scrape JavaScript endpoints using regular expressions
    #[arg(short = 'j', long = "js-crawl")]
    pub js_crawl: bool,

    /// Scrape JavaScript endpoints using JSLuice AST analysis (-jsl)
    #[arg(long = "jsluice", alias = "jsl")]
    pub jsluice: bool,

    /// Extract HTML forms
    #[arg(short = 'f', long = "form-extraction")]
    pub form_extraction: bool,

    /// Ignore query parameter values (-iqp)
    #[arg(long = "ignore-query-params", alias = "iqp")]
    pub ignore_query_params: bool,

    /// Deduplicate similar URLs via structural fingerprinting
    #[arg(long = "filter-similar")]
    pub filter_similar: bool,

    /// Crawl parent directory paths (-pc)
    #[arg(long = "path-climb", alias = "pc")]
    pub path_climb: bool,

    /// Enable crawling of known files (all, robotstxt, sitemapxml) (-kf, --known-files)
    #[arg(long = "known-files", alias = "kf")]
    pub known_files: Option<String>,

    /// Maximum pages to crawl per domain (-mdp)
    #[arg(long = "max-domain-pages", alias = "mdp", default_value_t = 0)]
    pub max_domain_pages: usize,

    /// Display out-of-scope endpoints in output (-do)
    #[arg(long = "display-out-scope", alias = "do")]
    pub display_out_scope: bool,

    /// Match only specific file extensions (-em, --extension-match)
    #[arg(long = "extension-match", alias = "em", value_delimiter = ',')]
    pub extension_match: Vec<String>,

    /// Filter/deny specific file extensions (-ef, --extension-filter)
    #[arg(long = "extension-filter", alias = "ef", value_delimiter = ',')]
    pub extension_filter: Vec<String>,

    /// Disable default file extension filter (-nef, --no-extension-filter)
    #[arg(long = "no-extension-filter", alias = "nef")]
    pub no_extension_filter: bool,

    /// HTTP/HTTPS/SOCKS5 Proxy URL or comma-separated list of proxies for rotation
    #[arg(long = "proxy")]
    pub proxy: Option<String>,

    /// Enable TLS ClientHello browser impersonation (-tlsi, --tls-impersonate)
    #[arg(long = "tls-impersonate", alias = "tlsi")]
    pub tls_impersonate: bool,

    /// TLS impersonation preset profile (chrome, firefox, safari, random)
    #[arg(long = "tls-preset")]
    pub tls_preset: Option<String>,

    /// Output file path (-o)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Store response headers and body to directory (-sr)
    #[arg(long = "store-response", alias = "sr")]
    pub store_response: bool,

    /// Directory to store response files (-srd)
    #[arg(long = "store-response-dir", alias = "srd")]
    pub store_response_dir: Option<String>,

    /// Custom fields YAML configuration file path (-config)
    #[arg(long = "config", alias = "custom-fields-config")]
    pub config: Option<String>,

    /// Custom field names to display (-fields, -fld)
    #[arg(long = "fields", alias = "fld")]
    pub fields: Option<String>,

    /// Output format as JSONL
    #[arg(long = "jsonl")]
    pub jsonl: bool,

    /// Omit raw requests/responses from jsonl output (-or)
    #[arg(long = "omit-raw", alias = "or")]
    pub omit_raw: bool,

    /// Omit response body from jsonl output (-ob)
    #[arg(long = "omit-body", alias = "ob")]
    pub omit_body: bool,

    /// Regex or list of regexes to match on output url (-mr)
    #[arg(long = "match-regex", alias = "mr")]
    pub match_regex: Vec<String>,

    /// Regex or list of regexes to filter on output url (-fr)
    #[arg(long = "filter-regex", alias = "fr")]
    pub filter_regex: Vec<String>,

    /// Extract TLS/SSL certificate metadata and client fingerprints (-tls, --tls-data)
    #[arg(long = "tls-data", alias = "tls")]
    pub tls_data: bool,

    /// Automated CAPTCHA solver provider, e.g. capsolver (-csp)
    #[arg(long = "captcha-solver-provider", alias = "csp")]
    pub captcha_solver_provider: Option<String>,

    /// Automated CAPTCHA solver API key (-csk, --capsolver-key)
    #[arg(
        long = "captcha-solver-api-key",
        alias = "csk",
        visible_alias = "capsolver-key"
    )]
    pub captcha_solver_api_key: Option<String>,

    /// Visit strategy: depth-first (DFS/LIFO) or breadth-first (BFS/FIFO) (-s, --strategy)
    #[arg(short = 's', long = "strategy", default_value = "depth-first")]
    pub strategy: String,

    /// Silent mode - output only discovered endpoints, suppressing logs and progress (-silent)
    #[arg(long = "silent")]
    pub silent: bool,

    /// Show real-time crawl progress bar and telemetry metrics
    #[arg(long = "show-progress", alias = "progress")]
    pub show_progress: bool,

    /// Enable verbose debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Splits comma-separated regex patterns while preserving commas inside quantifiers `{n,m}` and sets `[a,b]`.
pub fn split_regex_patterns(input: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut brace_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => {
                current.push(ch);
                escaped = true;
            }
            '{' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                current.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if brace_depth == 0 && bracket_depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    results.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        results.push(trimmed.to_string());
    }

    results
}

/// Normalizes CLI arguments so single-hyphen multi-character flags (e.g. -cs, -rl, -ct, -iqp)
/// are cleanly mapped to double-hyphen long flags (--cs, --rl, --ct, --iqp) matching Katana Go CLI UX,
/// and decomposes comma-separated regex flags (-mr, -fr) without corrupting quantifier syntax.
pub fn normalize_cli_args<I, T>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let raw: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut normalized = Vec::new();
    let mut i = 0;

    while i < raw.len() {
        let arg = &raw[i];
        if (arg == "-mr"
            || arg == "--mr"
            || arg == "--match-regex"
            || arg == "-fr"
            || arg == "--fr"
            || arg == "--filter-regex")
            && i + 1 < raw.len()
        {
            let flag = if arg.starts_with("--") {
                arg.clone()
            } else {
                format!("-{}", arg)
            };
            let val = &raw[i + 1];
            let parts = split_regex_patterns(val);
            for part in parts {
                normalized.push(flag.clone());
                normalized.push(part);
            }
            i += 2;
            continue;
        }

        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 2 {
            normalized.push(format!("-{}", arg));
        } else {
            normalized.push(arg.clone());
        }
        i += 1;
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_flags_scope_and_runtime() {
        let input = [
            "katana",
            "-u",
            "https://example.com",
            "-c",
            "20",
            "-p",
            "5",
            "-H",
            "Authorization: Bearer token123",
            "-H",
            "X-Key: val",
            "-cs",
            ".*example\\.com.*",
            "-cos",
            ".*logout.*",
            "-fs",
            "fqdn",
            "--no-scope",
            "-rl",
            "300",
            "-rlm",
            "5000",
            "-ct",
            "30s",
        ];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();

        assert_eq!(args.url.as_deref(), Some("https://example.com"));
        assert_eq!(args.concurrency, 20);
        assert_eq!(args.parallelism, 5);
        assert_eq!(
            args.headers,
            vec!["Authorization: Bearer token123", "X-Key: val"]
        );
        assert_eq!(args.crawl_scope, vec![".*example\\.com.*"]);
        assert_eq!(args.crawl_out_scope, vec![".*logout.*"]);
        assert_eq!(args.field_scope, "fqdn");
        assert!(args.no_scope);
        assert_eq!(args.rate_limit, 300);
        assert_eq!(args.rate_limit_minute, 5000);
        assert_eq!(args.crawl_duration.as_deref(), Some("30s"));
    }

    #[test]
    fn test_cli_flags_custom_headers_with_commas() {
        let input = [
            "katana",
            "-u",
            "https://example.com",
            "-H",
            "Accept: text/html,application/xhtml+xml;q=0.9",
            "-H",
            "Cookie: session=abc, user=def",
        ];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();
        assert_eq!(
            args.headers,
            vec![
                "Accept: text/html,application/xhtml+xml;q=0.9",
                "Cookie: session=abc, user=def"
            ]
        );
    }

    #[test]
    fn test_cli_flags_extended_filtering_and_upstream_parity() {
        let input = [
            "katana",
            "-u",
            "https://example.com",
            "-or",
            "-ob",
            "-mr",
            ".*admin.*,.*api.*",
            "-fr",
            ".*logout.*",
            "-tls",
            "-csp",
            "capsolver",
            "-csk",
            "CAP-1234567890",
            "--jsonl",
        ];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();

        assert!(args.omit_raw);
        assert!(args.omit_body);
        assert_eq!(args.match_regex, vec![".*admin.*", ".*api.*"]);
        assert_eq!(args.filter_regex, vec![".*logout.*"]);
        assert!(args.tls_data);
        assert_eq!(args.captcha_solver_provider.as_deref(), Some("capsolver"));
        assert_eq!(
            args.captcha_solver_api_key.as_deref(),
            Some("CAP-1234567890")
        );
        assert!(args.jsonl);
    }

    #[test]
    fn test_cli_flags_extension_matching_and_filtering() {
        let input = [
            "katana",
            "-u",
            "https://example.com",
            "-em",
            "php,html,js",
            "-ef",
            "bak,old",
            "-nef",
        ];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();

        assert_eq!(args.extension_match, vec!["php", "html", "js"]);
        assert_eq!(args.extension_filter, vec!["bak", "old"]);
        assert!(args.no_extension_filter);
    }

    #[test]
    fn test_cli_flags_exclude_and_private_ips() {
        let input = [
            "katana",
            "-u",
            "https://example.com",
            "-e",
            "private-ips,10.0.0.1",
            "--exclude-private-ips",
        ];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();

        assert_eq!(args.exclude, vec!["private-ips", "10.0.0.1"]);
        assert!(args.exclude_private_ips);
    }

    #[test]
    fn test_cli_flags_known_files() {
        let input = ["katana", "-u", "https://example.com", "-kf", "all"];
        let normalized = normalize_cli_args(input);
        let args = CliArgs::try_parse_from(normalized).unwrap();

        assert_eq!(args.known_files.as_deref(), Some("all"));
    }

    #[test]
    fn test_cli_flags_strategy() {
        let input_default = ["katana", "-u", "https://example.com"];
        let args_default = CliArgs::try_parse_from(normalize_cli_args(input_default)).unwrap();
        assert_eq!(args_default.strategy, "depth-first");

        let input_bfs = ["katana", "-u", "https://example.com", "-s", "breadth-first"];
        let args_bfs = CliArgs::try_parse_from(normalize_cli_args(input_bfs)).unwrap();
        assert_eq!(args_bfs.strategy, "breadth-first");
    }
}
