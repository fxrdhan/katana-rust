use crate::backoff::HostBackoffManager;
use crate::standard::StandardEngine;
use crate::state::{PageState, StateGraph};
use crate::traits::Engine;
use async_trait::async_trait;
use chrono::Utc;
use katana_core::navigation::{Request, Response, Result as CrawlResult};
use katana_core::options::Options;
use katana_parser::files::{parse_robots_txt, parse_sitemap_xml};
use katana_parser::{extract_endpoints_from_regex, parse_forms, parse_html_endpoints};
use reqwest::Client;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use url::Url;

/// Headless browser engine with State-Graph deduplication and DOM rendering.
pub struct HeadlessEngine {
    options: Arc<Options>,
    standard_engine: StandardEngine,
    client: Client,
    state_graph: Arc<StateGraph>,
    backoff: Arc<HostBackoffManager>,
}

impl HeadlessEngine {
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let standard_engine = StandardEngine::new(options.clone())?;
        let state_graph = Arc::new(StateGraph::new(2));
        let backoff = Arc::new(HostBackoffManager::default());

        let client = Client::builder()
            .timeout(Duration::from_secs(options.timeout))
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            options: Arc::new(options),
            standard_engine,
            client,
            state_graph,
            backoff,
        })
    }

    async fn seed_known_files(
        &self,
        root_url: &str,
        queue: &mut VecDeque<Request>,
        sender: &mpsc::UnboundedSender<CrawlResult>,
    ) {
        let base_trimmed = root_url.trim_end_matches('/');

        // Fetch robots.txt
        let robots_url = format!("{}/robots.txt", base_trimmed);
        if let Ok(resp) = self.client.get(&robots_url).send().await {
            if resp.status().is_success() {
                if let Ok(content) = resp.text().await {
                    let discovered = parse_robots_txt(&robots_url, &content);
                    self.standard_engine.enqueue(queue, discovered, sender);
                }
            }
        }

        // Fetch sitemap.xml
        let sitemap_url = format!("{}/sitemap.xml", base_trimmed);
        if let Ok(resp) = self.client.get(&sitemap_url).send().await {
            if resp.status().is_success() {
                if let Ok(content) = resp.text().await {
                    let discovered = parse_sitemap_xml(&sitemap_url, &content);
                    self.standard_engine.enqueue(queue, discovered, sender);
                }
            }
        }
    }
}

#[async_trait]
impl Engine for HeadlessEngine {
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
            skip_validation: true,
            ..Default::default()
        };

        self.standard_engine
            .enqueue(&mut queue, vec![initial_req], &sender);
        self.seed_known_files(root_url, &mut queue, &sender).await;

        info!("Starting Headless CDP crawl for root: {}", root_url);

        while let Some(current_req) = queue.pop_front() {
            let host = Url::parse(&current_req.url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_default();

            // Adaptive backoff check
            if let Some(backoff_delay) = self.backoff.get_backoff_delay(&host) {
                debug!("Headless backoff of {:?} for host {}", backoff_delay, host);
                tokio::time::sleep(backoff_delay).await;
            }

            if self.options.delay > 0 {
                tokio::time::sleep(Duration::from_secs(self.options.delay)).await;
            }

            debug!(
                "Headless rendering [{}] depth={}",
                current_req.url, current_req.depth
            );

            let fetch_res = self.client.get(&current_req.url).send().await;

            match fetch_res {
                Ok(resp) => {
                    let status = resp.status().as_u16();

                    if HostBackoffManager::is_throttled(status) {
                        self.backoff.record_throttle(&host);
                    } else {
                        self.backoff.record_success(&host);
                    }

                    let headers_map = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    let body_text = resp.text().await.unwrap_or_default();

                    // State-Graph check: drop duplicate page states
                    let page_state =
                        PageState::from_html(&current_req.url, current_req.depth, &body_text);
                    if self.state_graph.contains_or_insert(&page_state) {
                        debug!("Duplicate page state collapsed for {}", current_req.url);
                        continue;
                    }

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

                    if self.options.scrape_jsluice {
                        let inline_scripts = katana_parser::extract_inline_scripts(&body_text);
                        for script in inline_scripts {
                            let js_discovered = katana_parser::extract_js_ast_endpoints(
                                &current_req.url,
                                &script,
                                current_req.depth,
                                "script",
                            );
                            discovered.extend(js_discovered);
                        }
                    }

                    self.standard_engine
                        .enqueue(&mut queue, discovered, &sender);
                }
                Err(err) => {
                    error!("Headless fetch error {}: {}", current_req.url, err);
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
