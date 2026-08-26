use colored::*;
use katana_core::navigation::Result as CrawlResult;

pub struct OutputWriter {
    pub jsonl: bool,
}

impl OutputWriter {
    pub fn new(jsonl: bool) -> Self {
        Self { jsonl }
    }

    pub fn write_result(&self, res: &CrawlResult) {
        if self.jsonl {
            if let Ok(json_str) = serde_json::to_string(res) {
                println!("{}", json_str);
            }
        } else if let Some(req) = &res.request {
            let method = if req.method.is_empty() {
                "GET".to_string()
            } else {
                req.method.clone()
            };

            let tag = if req.tag.is_empty() {
                "url".to_string()
            } else {
                req.tag.clone()
            };

            let status_str = if let Some(resp) = &res.response {
                format!("[{}]", resp.status_code).green()
            } else if !res.error.is_empty() {
                format!("[ERR: {}]", res.error).red()
            } else {
                "[DISCOVERED]".cyan()
            };

            println!(
                "{} [{}] [{}] {} [depth:{}]",
                status_str,
                tag.magenta(),
                method.yellow(),
                req.url,
                req.depth
            );
        }
    }
}
