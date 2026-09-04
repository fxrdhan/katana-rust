use colored::*;
use katana_core::navigation::Result as CrawlResult;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

pub struct OutputWriter {
    pub jsonl: bool,
    file_handle: Option<Mutex<File>>,
}

impl OutputWriter {
    pub fn new(jsonl: bool, output_file: Option<&str>) -> Self {
        let file_handle = output_file.and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        });

        Self { jsonl, file_handle }
    }

    pub fn write_result(&self, res: &CrawlResult) {
        if self.jsonl {
            if let Ok(json_str) = serde_json::to_string(res) {
                println!("{}", json_str);
                if let Some(file_mutex) = &self.file_handle {
                    if let Ok(mut f) = file_mutex.lock() {
                        let _ = writeln!(f, "{}", json_str);
                    }
                }
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

            let api_str = if let Some(api) = &res.api_type {
                format!(" [{}]", api.blue())
            } else {
                String::new()
            };

            let tech_str = if !res.technologies.is_empty() {
                format!(" [{}]", res.technologies.join(", ").bright_blue())
            } else {
                String::new()
            };

            let line = format!(
                "{} [{}] [{}] {}{}{}",
                status_str,
                tag.magenta(),
                method.yellow(),
                req.url,
                api_str,
                tech_str
            );

            println!("{}", line);

            // Write raw line to file
            if let Some(file_mutex) = &self.file_handle {
                if let Ok(mut f) = file_mutex.lock() {
                    let _ = writeln!(f, "{}", req.url);
                }
            }

            // Print custom fields if any
            for (name, vals) in &req.custom_fields {
                for val in vals {
                    println!("  {} {}: {}", "[CUSTOM FIELD]".cyan(), name.bold(), val);
                }
            }

            // Highlight detected secrets in interactive mode
            for secret in &res.secrets {
                println!(
                    "  {} [{}] {} in {}",
                    "[SECRET DETECTED]".bold().red(),
                    secret.severity.to_uppercase().yellow(),
                    format!("{}: {}", secret.rule_name, secret.matched_token).bright_white(),
                    secret.source.dimmed()
                );
            }
        }
    }
}
