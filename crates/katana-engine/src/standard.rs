use crate::backoff::HostBackoffManager;
use crate::traits::Engine;
use async_trait::async_trait;
use chrono::Utc;
use dashmap::{DashMap, DashSet};
use katana_core::error::KatanaError;
use katana_core::filters::{
    extract_parent_paths, is_cycle, is_logout_url, replace_all_query_param,
};
use katana_core::navigation::{Request, Response, Result as CrawlResult};
use katana_core::options::Options;
use katana_core::scope::ScopeManager;
use katana_parser::files::{parse_robots_txt, parse_sitemap_xml};
use katana_parser::{extract_endpoints_from_regex, parse_forms, parse_html_endpoints};
use katana_similarity::{fingerprint_url, PathTrie};
use reqwest::Client;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info};
use url::Url;

pub struct StandardEngine {
    options: Arc<Options>,
    client: Client,
    scope: Arc<ScopeManager>,
    visited_urls: Arc<DashSet<String>>,
    domain_counters: Arc<DashMap<String, AtomicUsize>>,
    path_trie: Arc<PathTrie>,
    backoff: Arc<HostBackoffManager>,
}

impl StandardEngine {
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(options.timeout))
            .danger_accept_invalid_certs(true);

        if options.disable_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(proxy_url) = &options.proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy_url)?);
        }

        if let Some(ua) = &options.user_agent {
            client_builder = client_builder.user_agent(ua);
        }

        let client = client_builder.build()?;
        let scope = Arc::new(ScopeManager::new(
            &options.scope,
            &options.out_of_scope,
            "rdn",
            false,
        )?);

        let path_trie = Arc::new(PathTrie::new(options.filter_similar_threshold));
        let backoff = Arc::new(HostBackoffManager::default());

        Ok(Self {
            options: Arc::new(options),
            client,
            scope,
            visited_urls: Arc::new(DashSet::new()),
            domain_counters: Arc::new(DashMap::new()),
            path_trie,
            backoff,
        })
    }

    /// Complete 10-step enqueue validation funnel matching Katana Go architecture.
    pub fn enqueue(
        &self,
        queue: &mut VecDeque<Request>,
        requests: Vec<Request>,
        sender: &mpsc::UnboundedSender<CrawlResult>,
    ) {
        for nr in requests {
            // 1. URL Sanity
            if nr.url.is_empty() {
                continue;
            }
            if Url::parse(&nr.url).is_err() {
                continue;
            }

            // 2. Query parameter handling (-iqp)
            let mut req_url = nr.request_url();
            if self.options.ignore_query_params {
                req_url = replace_all_query_param(&req_url, "");
            }

            // 3. Structural fingerprinting (-filter-similar)
            if self.options.filter_similar {
                req_url = fingerprint_url(&req_url, Some(&self.path_trie));
            }

            // 4. Logout guard
            if self.options.auth_credentials.is_some() && is_logout_url(&nr.url) {
                debug!("Skipping logout URL: {}", nr.url);
                continue;
            }

            // 5. Depth ceiling (emit without consuming uniqueness)
            if nr.depth > self.options.max_depth {
                let depth_err = CrawlResult {
                    timestamp: Utc::now(),
                    request: Some(nr.clone()),
                    response: None,
                    error: KatanaError::MaxDepthReached.to_string(),
                };
                let _ = sender.send(depth_err);
                continue;
            }

            // 6. Per-domain page quota (-mdp)
            if self.options.max_domain_pages > 0 && !nr.root_hostname.is_empty() {
                if let Some(counter) = self.domain_counters.get(&nr.root_hostname) {
                    if counter.load(Ordering::Relaxed) >= self.options.max_domain_pages {
                        continue;
                    }
                }
            }

            // 7. Uniqueness check
            if !self.visited_urls.insert(req_url.clone()) && nr.custom_fields.is_empty() {
                continue;
            }

            // 8. Cycle detection
            if is_cycle(&nr.url) {
                debug!("Cycle detected, dropping: {}", nr.url);
                continue;
            }

            // 9. Scope validation
            let in_scope = self.scope.validate(&nr.url, &nr.root_hostname);
            if !in_scope && !nr.skip_validation {
                if self.options.display_out_scope {
                    let out_scope_res = CrawlResult {
                        timestamp: Utc::now(),
                        request: Some(nr.clone()),
                        response: None,
                        error: KatanaError::OutOfScope.to_string(),
                    };
                    let _ = sender.send(out_scope_res);
                }
                continue;
            }

            // 10. Push & Path-climbing (-pc)
            queue.push_back(nr.clone());

            if self.options.path_climb {
                let parent_urls = extract_parent_paths(&nr.url);
                for parent_url in parent_urls {
                    let mut check_url = parent_url.clone();
                    if self.options.filter_similar {
                        check_url = fingerprint_url(&check_url, Some(&self.path_trie));
                    }
                    if !self.visited_urls.insert(check_url) {
                        continue;
                    }
                    if !self.scope.validate(&parent_url, &nr.root_hostname) {
                        continue;
                    }

                    let parent_depth = nr.depth.saturating_sub(1);
                    queue.push_back(Request {
                        method: nr.method.clone(),
                        url: parent_url,
                        depth: parent_depth,
                        root_hostname: nr.root_hostname.clone(),
                        source: nr.source.clone(),
                        tag: "path-climb".to_string(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Seed known files (robots.txt and sitemap.xml) if configured.
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
                    self.enqueue(queue, discovered, sender);
                }
            }
        }

        // Fetch sitemap.xml
        let sitemap_url = format!("{}/sitemap.xml", base_trimmed);
        if let Ok(resp) = self.client.get(&sitemap_url).send().await {
            if resp.status().is_success() {
                if let Ok(content) = resp.text().await {
                    let discovered = parse_sitemap_xml(&sitemap_url, &content);
                    self.enqueue(queue, discovered, sender);
                }
            }
        }
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
            skip_validation: true,
            ..Default::default()
        };

        self.enqueue(&mut queue, vec![initial_req], &sender);
        self.seed_known_files(root_url, &mut queue, &sender).await;

        info!("Starting Standard crawl for root: {}", root_url);

        let concurrency = self.options.concurrency.max(1);
        let _semaphore = Arc::new(Semaphore::new(concurrency));

        while let Some(current_req) = queue.pop_front() {
            let host = Url::parse(&current_req.url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_default();

            // Apply adaptive backoff if host is throttled
            if let Some(backoff_delay) = self.backoff.get_backoff_delay(&host) {
                debug!("Applying backoff of {:?} to host {}", backoff_delay, host);
                tokio::time::sleep(backoff_delay).await;
            }

            // Fixed delay if requested
            if self.options.delay > 0 {
                tokio::time::sleep(Duration::from_secs(self.options.delay)).await;
            }

            debug!("Fetching [{}] depth={}", current_req.url, current_req.depth);

            let fetch_res = self.client.get(&current_req.url).send().await;

            match fetch_res {
                Ok(resp) => {
                    let status = resp.status().as_u16();

                    // Record throttle or success state
                    if HostBackoffManager::is_throttled(status) {
                        self.backoff.record_throttle(&host);
                    } else {
                        self.backoff.record_success(&host);
                    }

                    // Increment domain page counter
                    if !current_req.root_hostname.is_empty() {
                        let counter = self
                            .domain_counters
                            .entry(current_req.root_hostname.clone())
                            .or_insert_with(|| AtomicUsize::new(0));
                        counter.fetch_add(1, Ordering::Relaxed);
                    }

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

                    // Funnel discovered requests through the 10-step enqueue pipeline
                    self.enqueue(&mut queue, discovered, &sender);
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
