use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use katana_core::navigation::Result as CrawlResult;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct OutputWriter {
    pub jsonl: bool,
    pub silent: bool,
    pub omit_raw: bool,
    pub omit_body: bool,
    pub match_regex: Vec<Regex>,
    pub filter_regex: Vec<Regex>,
    file_handle: Option<Mutex<File>>,
    progress_bar: Option<ProgressBar>,
    discovered_count: Arc<AtomicU64>,
}

impl OutputWriter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jsonl: bool,
        silent: bool,
        show_progress: bool,
        output_file: Option<&str>,
        omit_raw: bool,
        omit_body: bool,
        match_patterns: &[String],
        filter_patterns: &[String],
    ) -> anyhow::Result<Self> {
        let file_handle = output_file.and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        });

        let mut match_regex = Vec::new();
        for pat in match_patterns {
            let p = Path::new(pat);
            if p.is_file() {
                let file = File::open(p)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line_str = line?.trim().to_string();
                    if !line_str.is_empty() {
                        let re = Regex::new(&line_str)?;
                        match_regex.push(re);
                    }
                }
            } else {
                let re = Regex::new(pat)?;
                match_regex.push(re);
            }
        }

        let mut filter_regex = Vec::new();
        for pat in filter_patterns {
            let p = Path::new(pat);
            if p.is_file() {
                let file = File::open(p)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line_str = line?.trim().to_string();
                    if !line_str.is_empty() {
                        let re = Regex::new(&line_str)?;
                        filter_regex.push(re);
                    }
                }
            } else {
                let re = Regex::new(pat)?;
                filter_regex.push(re);
            }
        }

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

        Ok(Self {
            jsonl,
            silent,
            omit_raw,
            omit_body,
            match_regex,
            filter_regex,
            file_handle,
            progress_bar,
            discovered_count: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn print_line(&self, line: &str) {
        if let Some(pb) = &self.progress_bar {
            pb.println(line);
        } else {
            println!("{}", line);
        }
    }

    pub fn write_result(&self, res: &CrawlResult) {
        let target_url = res.request.as_ref().map(|r| r.url.as_str()).unwrap_or("");

        // URL filtering via match-regex (-mr) and filter-regex (-fr)
        if !self.match_regex.is_empty()
            && !self.match_regex.iter().any(|re| re.is_match(target_url))
        {
            return;
        }
        if self.filter_regex.iter().any(|re| re.is_match(target_url)) {
            return;
        }

        let count = self.discovered_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(pb) = &self.progress_bar {
            pb.set_message(format!("Discovered: {} endpoints", count));
        }

        if self.jsonl {
            let mut output_res = res.clone();
            if self.omit_raw {
                if let Some(req) = &mut output_res.request {
                    req.raw.clear();
                }
                if let Some(resp) = &mut output_res.response {
                    resp.raw.clear();
                }
            }
            if self.omit_body {
                if let Some(resp) = &mut output_res.response {
                    resp.body.clear();
                }
            }

            if let Ok(json_str) = serde_json::to_string(&output_res) {
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

            let tls_str = if let Some(tls) = &res.tls_data {
                let ver = if !tls.tls_version.is_empty() {
                    &tls.tls_version
                } else {
                    "tls"
                };
                let cn = if !tls.subject_cn.is_empty() {
                    &tls.subject_cn
                } else {
                    ""
                };
                if !cn.is_empty() {
                    format!(" [{} | {}]", ver.cyan(), cn.bold())
                } else {
                    format!(" [{}]", ver.cyan())
                }
            } else {
                String::new()
            };

            let line = format!(
                "{} [{}] [{}] {}{}{}{}",
                status_str,
                tag.magenta(),
                method.yellow(),
                req.url,
                api_str,
                tech_str,
                tls_str
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

#[cfg(test)]
mod tests {
    use super::*;
    use katana_core::navigation::{Request, Response};

    #[test]
    fn test_output_writer_regex_and_omission_parity() {
        let writer = OutputWriter::new(
            true, // jsonl
            true, // silent
            false,
            None,
            true, // omit_raw
            true, // omit_body
            &[".*api.*".to_string()],
            &[".*logout.*".to_string()],
        )
        .unwrap();

        // Should be filtered out by filter_regex
        let logout_res = CrawlResult {
            request: Some(Request {
                url: "https://example.com/api/logout".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let target_url = logout_res.request.as_ref().unwrap().url.as_str();
        assert!(writer.filter_regex.iter().any(|re| re.is_match(target_url)));

        // Should not match match_regex
        let non_api_res = CrawlResult {
            request: Some(Request {
                url: "https://example.com/about".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let target_url2 = non_api_res.request.as_ref().unwrap().url.as_str();
        assert!(!writer.match_regex.iter().any(|re| re.is_match(target_url2)));

        // Should match and omit raw and body
        let valid_res = CrawlResult {
            request: Some(Request {
                url: "https://example.com/api/v1/users".to_string(),
                raw: "GET /api/v1/users HTTP/1.1\r\n...".to_string(),
                ..Default::default()
            }),
            response: Some(Response {
                status_code: 200,
                raw: "HTTP/1.1 200 OK\r\n...".to_string(),
                body: "{\"users\":[]}".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let target_url3 = valid_res.request.as_ref().unwrap().url.as_str();
        assert!(writer.match_regex.iter().any(|re| re.is_match(target_url3)));
        assert!(!writer
            .filter_regex
            .iter()
            .any(|re| re.is_match(target_url3)));

        let mut output_res = valid_res.clone();
        if writer.omit_raw {
            if let Some(req) = &mut output_res.request {
                req.raw.clear();
            }
            if let Some(resp) = &mut output_res.response {
                resp.raw.clear();
            }
        }
        if writer.omit_body {
            if let Some(resp) = &mut output_res.response {
                resp.body.clear();
            }
        }

        assert!(output_res.request.as_ref().unwrap().raw.is_empty());
        assert!(output_res.response.as_ref().unwrap().raw.is_empty());
        assert!(output_res.response.as_ref().unwrap().body.is_empty());
    }

    #[test]
    fn test_output_writer_regex_with_commas_and_file_patterns() {
        let temp_dir = std::env::temp_dir();
        let pattern_file = temp_dir.join("test_patterns.txt");
        std::fs::write(&pattern_file, ".*logout.*\n.*admin/v[0-9]{1,2}.*\n").unwrap();

        let writer = OutputWriter::new(
            false,
            false,
            false,
            None,
            false,
            false,
            &["^https://example\\.com/api/[a-z]{2,5}$".to_string()],
            &[pattern_file.to_string_lossy().to_string()],
        )
        .expect("should initialize with comma regexes and file patterns");

        assert_eq!(writer.match_regex.len(), 1);
        assert_eq!(writer.filter_regex.len(), 2);

        assert!(writer.match_regex[0].is_match("https://example.com/api/users"));
        assert!(!writer.match_regex[0].is_match("https://example.com/api/toolongpath"));

        assert!(writer.filter_regex[0].is_match("https://example.com/logout"));
        assert!(writer.filter_regex[1].is_match("https://example.com/admin/v12/dashboard"));

        let _ = std::fs::remove_file(pattern_file);
    }
}
