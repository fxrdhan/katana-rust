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

    /// Maximum pages to crawl per domain (-mdp)
    #[arg(long = "max-domain-pages", alias = "mdp", default_value_t = 0)]
    pub max_domain_pages: usize,

    /// Display out-of-scope endpoints in output (-do)
    #[arg(long = "display-out-scope", alias = "do")]
    pub display_out_scope: bool,

    /// HTTP Proxy URL
    #[arg(long = "proxy")]
    pub proxy: Option<String>,

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

    /// Enable verbose debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Normalizes CLI arguments so single-hyphen multi-character flags (e.g. -cs, -rl, -ct, -iqp)
/// are cleanly mapped to double-hyphen long flags (--cs, --rl, --ct, --iqp) matching Katana Go CLI UX.
pub fn normalize_cli_args<I, T>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    args.into_iter()
        .map(|arg| {
            let s = arg.as_ref();
            if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 {
                format!("-{}", s)
            } else {
                s.to_string()
            }
        })
        .collect()
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
}
