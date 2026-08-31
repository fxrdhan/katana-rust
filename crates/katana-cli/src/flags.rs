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

    /// Maximum crawl depth
    #[arg(short = 'd', long = "depth", default_value_t = 3)]
    pub depth: usize,

    /// Number of concurrent workers
    #[arg(short = 'c', long = "concurrency", default_value_t = 10)]
    pub concurrency: usize,

    /// Request timeout in seconds
    #[arg(short = 't', long = "timeout", default_value_t = 10)]
    pub timeout: u64,

    /// Request delay between requests in seconds
    #[arg(short = 'p', long = "delay", default_value_t = 0)]
    pub delay: u64,

    /// Enable headless browser crawling (-hl)
    #[arg(short = 'H', long = "headless", alias = "hl")]
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
