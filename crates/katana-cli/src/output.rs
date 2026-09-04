use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use katana_core::navigation::Result as CrawlResult;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct OutputWriter {
    pub jsonl: bool,
    pub silent: bool,
    file_handle: Option<Mutex<File>>,
    progress_bar: Option<ProgressBar>,
    discovered_count: Arc<AtomicU64>,
}

impl OutputWriter {
    pub fn new(jsonl: bool, silent: bool, show_progress: bool, output_file: Option<&str>) -> Self {
        let file_handle = output_file.and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        });

        let progress_bar = if show_progress && !silent && !jsonl {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
                    .template("{spinner:.green} [{elapsed_precise}] {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            pb.set_message("Discovered: 0 endpoints");
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };

        Self {
            jsonl,
            silent,
            file_handle,
            progress_bar,
            discovered_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn print_line(&self, line: &str) {
        if let Some(pb) = &self.progress_bar {
            pb.println(line);
        } else {
            println!("{}", line);
        }
    }

    pub fn write_result(&self, res: &CrawlResult) {
        let count = self.discovered_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(pb) = &self.progress_bar {
            pb.set_message(format!("Discovered: {} endpoints", count));
        }

        if self.jsonl {
            if let Ok(json_str) = serde_json::to_string(res) {
                if let Some(pb) = &self.progress_bar {
                    pb.println(&json_str);
                } else {
                    println!("{}", json_str);
                }
                if let Some(file_mutex) = &self.file_handle {
                    if let Ok(mut f) = file_mutex.lock() {
                        let _ = writeln!(f, "{}", json_str);
                    }
                }
            }
        } else if let Some(req) = &res.request {
            if self.silent {
                // In silent mode without JSONL, print only URL to stdout
                println!("{}", req.url);
                if let Some(file_mutex) = &self.file_handle {
                    if let Ok(mut f) = file_mutex.lock() {
                        let _ = writeln!(f, "{}", req.url);
                    }
                }
                return;
            }

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

            self.print_line(&line);

            // Write raw line to file
            if let Some(file_mutex) = &self.file_handle {
                if let Ok(mut f) = file_mutex.lock() {
                    let _ = writeln!(f, "{}", req.url);
                }
            }

            // Print custom fields if any
            for (name, vals) in &req.custom_fields {
                for val in vals {
                    self.print_line(&format!(
                        "  {} {}: {}",
                        "[CUSTOM FIELD]".cyan(),
                        name.bold(),
                        val
                    ));
                }
            }

            // Highlight detected secrets in interactive mode
            for secret in &res.secrets {
                self.print_line(&format!(
                    "  {} [{}] {} in {}",
                    "[SECRET DETECTED]".bold().red(),
                    secret.severity.to_uppercase().yellow(),
                    format!("{}: {}", secret.rule_name, secret.matched_token).bright_white(),
                    secret.source.dimmed()
                ));
            }
        }
    }

    pub fn finish(&self) {
        if let Some(pb) = &self.progress_bar {
            pb.finish_and_clear();
        }
    }
}

impl Drop for OutputWriter {
    fn drop(&mut self) {
        self.finish();
    }
}
