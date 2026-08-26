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

    /// Scrape JavaScript endpoints using regular expressions
    #[arg(short = 'j', long = "js-crawl")]
    pub js_crawl: bool,

    /// Extract HTML forms
    #[arg(short = 'f', long = "form-extraction")]
    pub form_extraction: bool,

    /// Deduplicate similar URLs via structural fingerprinting
    #[arg(long = "filter-similar")]
    pub filter_similar: bool,

    /// Output format as JSONL
    #[arg(long = "jsonl")]
    pub jsonl: bool,

    /// Enable verbose debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}
