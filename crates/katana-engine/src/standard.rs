use crate::traits::Engine;
use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashSet;
use katana_core::navigation::{Request, Response, Result as CrawlResult};
use katana_core::options::Options;
use katana_core::scope::ScopeManager;
use katana_parser::{extract_endpoints_from_regex, parse_forms, parse_html_endpoints};
use katana_similarity::fingerprint_url;
use reqwest::Client;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use url::Url;

pub struct StandardEngine {
    options: Arc<Options>,
    client: Client,
    scope: Arc<ScopeManager>,
    visited_urls: Arc<DashSet<String>>,
}

impl StandardEngine {
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(options.timeout))
            .danger_accept_invalid_certs(true);

        if options.disable_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = client_builder.build()?;
        let scope = Arc::new(ScopeManager::new(
            &options.scope,
            &options.out_of_scope,
            "rdn",
            false,
        )?);

        Ok(Self {
            options: Arc::new(options),
            client,
            scope,
            visited_urls: Arc::new(DashSet::new()),
        })
    }
}

#[async_trait]
impl Engine for StandardEngine {
    async fn crawl(
        &self,
        root_url: &str,
        sender: mpsc::UnboundedSender<CrawlResult>,
    ) -> anyhow::Result<()> {
        let parsed_root = Url::parse(root_url)?;
        let root_hostname = parsed_root.host_str().unwrap_or("").to_string();

        let mut queue = VecDeque::new();
        let initial_req = Request {
            method: "GET".to_string(),
            url: root_url.to_string(),
            depth: 0,
            root_hostname: root_hostname.clone(),
            ..Default::default()
        };

        queue.push_back(initial_req);
        self.visited_urls.insert(root_url.to_string());

        info!("Starting Standard crawl for root: {}", root_url);

        while let Some(current_req) = queue.pop_front() {
            if current_req.depth > self.options.max_depth {
                debug!("Skipping {} - max depth exceeded", current_req.url);
                continue;
            }

            debug!("Fetching [{}] depth={}", current_req.url, current_req.depth);

            let fetch_res = self.client.get(&current_req.url).send().await;

            match fetch_res {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let headers_map = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    let body_text = resp.text().await.unwrap_or_default();
                    let forms = if self.options.form_extraction {
                        parse_forms(&body_text)
                    } else {
                        Vec::new()
                    };

                    let nav_resp = Response {
                        depth: current_req.depth,
                        status_code: status,
                        headers: headers_map,
                        content_length: body_text.len(),
                        root_hostname: root_hostname.clone(),
                        forms,
                        body: body_text.clone(),
                        ..Default::default()
                    };

                    let crawl_result = CrawlResult {
                        timestamp: Utc::now(),
                        request: Some(current_req.clone()),
                        response: Some(nav_resp),
                        error: String::new(),
                    };

                    let _ = sender.send(crawl_result);

                    // Discover new links
                    let mut discovered =
                        parse_html_endpoints(&current_req.url, &body_text, current_req.depth);

                    if self.options.scrape_js {
                        let regex_discovered = extract_endpoints_from_regex(
                            &current_req.url,
                            &body_text,
                            current_req.depth,
                        );
                        discovered.extend(regex_discovered);
                    }

                    for mut next_req in discovered {
                        let dedup_key = if self.options.filter_similar {
                            fingerprint_url(&next_req.url, None)
                        } else {
                            next_req.request_url()
                        };

                        if !self.visited_urls.contains(&dedup_key) {
                            self.visited_urls.insert(dedup_key);

                            if self.scope.validate(&next_req.url, &root_hostname) {
                                next_req.root_hostname = root_hostname.clone();
                                queue.push_back(next_req);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("Error fetching {}: {}", current_req.url, err);
                    let err_result = CrawlResult {
                        timestamp: Utc::now(),
                        request: Some(current_req),
                        response: None,
                        error: err.to_string(),
                    };
                    let _ = sender.send(err_result);
                }
            }
        }

        Ok(())
    }
}
