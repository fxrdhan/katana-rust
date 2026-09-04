use crate::backoff::HostBackoffManager;
use crate::traits::Engine;
use async_trait::async_trait;
use chrono::Utc;
use dashmap::{DashMap, DashSet};
use governor::{
    clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};
use katana_core::error::KatanaError;
use katana_core::filters::{
    extract_parent_paths, is_cycle, is_logout_url, replace_all_query_param, CompactUrlFilter,
};
use katana_core::navigation::{Request, Response, Result as CrawlResult};
use katana_core::options::Options;
use katana_core::scope::ScopeManager;
use katana_parser::files::{parse_robots_txt, parse_sitemap_xml};
use katana_parser::{extract_endpoints_from_regex, parse_forms, parse_html_endpoints};
use katana_similarity::{fingerprint_url, PathTrie};
use reqwest::Client;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info};
use url::Url;

pub type TokenBucketRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
pub struct StandardEngine {
    options: Arc<Options>,
    client: Client,
    scope: Arc<ScopeManager>,
    visited_filter: Arc<CompactUrlFilter>,
    visited_urls: Arc<DashSet<String>>,
    domain_counters: Arc<DashMap<String, AtomicUsize>>,
    path_trie: Arc<PathTrie>,
    backoff: Arc<HostBackoffManager>,
    custom_fields: Arc<katana_core::CustomFieldManager>,
    rate_limiter_second: Option<Arc<TokenBucketRateLimiter>>,
    rate_limiter_minute: Option<Arc<TokenBucketRateLimiter>>,
    active_queue: Arc<tokio::sync::Mutex<VecDeque<Request>>>,
    in_flight_requests: Arc<DashSet<String>>,
}

fn store_response_to_disk(
    dir: &str,
    url: &str,
    status: u16,
    headers: &HashMap<String, String>,
    body: &str,
) -> Option<String> {
    use sha2::Digest;
    std::fs::create_dir_all(dir).ok()?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(url.as_bytes());
    hasher.update(Utc::now().to_rfc3339().as_bytes());
    let file_hash = format!("{:x}", hasher.finalize());
    let filename = format!("{}.txt", &file_hash[..16]);
    let file_path = format!("{}/{}", dir.trim_end_matches('/'), filename);

    let mut content = format!("HTTP/1.1 {}\r\n", status);
    for (k, v) in headers {
        content.push_str(&format!("{}: {}\r\n", k, v));
    }
    content.push_str("\r\n");
    content.push_str(body);

    std::fs::write(&file_path, content).ok()?;
    Some(file_path)
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
            &options.field_scope,
            options.no_scope,
        )?);

        let path_trie = Arc::new(PathTrie::new(options.filter_similar_threshold));
        let backoff = Arc::new(HostBackoffManager::default());
        let custom_fields = if let Some(cfg_path) = &options.custom_fields_config {
            Arc::new(katana_core::CustomFieldManager::from_file(cfg_path).unwrap_or_default())
        } else {
            Arc::new(katana_core::CustomFieldManager::new())
        };

        let rate_limiter_second = if options.rate_limit > 0 {
            NonZeroU32::new(options.rate_limit as u32)
                .map(|limit| Arc::new(RateLimiter::direct(Quota::per_second(limit))))
        } else {
            None
        };

        let rate_limiter_minute = if options.rate_limit_minute > 0 {
            NonZeroU32::new(options.rate_limit_minute as u32)
                .map(|limit| Arc::new(RateLimiter::direct(Quota::per_minute(limit))))
        } else {
            None
        };

        let visited_filter = Arc::new(CompactUrlFilter::new());
        let visited_urls = Arc::new(DashSet::new());

        // Pre-populate if resuming from checkpoint file
        if let Some(resume_path) = &options.resume_file {
            if let Ok(cp) = katana_core::CrawlCheckpoint::load(resume_path) {
                info!(
                    "Resuming from checkpoint file: {} ({} visited URLs)",
                    resume_path,
                    cp.visited_urls.len()
                );
                for u in cp.visited_urls {
                    visited_filter.insert(&u);
                    visited_urls.insert(u);
                }
            }
        }

        Ok(Self {
            options: Arc::new(options),
            client,
            scope,
            visited_filter,
            visited_urls,
            domain_counters: Arc::new(DashMap::new()),
            path_trie,
            backoff,
            custom_fields,
            rate_limiter_second,
            rate_limiter_minute,
            active_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            in_flight_requests: Arc::new(DashSet::new()),
        })
    }

    /// Builds a configured reqwest HTTP request honoring HTTP method, global custom headers,
    /// request-specific headers, and request body payload.
    pub fn build_http_request(&self, req: &Request) -> Result<reqwest::Request, KatanaError> {
        let method = match req.method.to_uppercase().as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "PATCH" => reqwest::Method::PATCH,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };
        let mut builder = self.client.request(method, &req.url);

        // Global custom headers from options (-H)
        for (k, v) in &self.options.custom_headers {
            if let (Ok(hname), Ok(hval)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                builder = builder.header(hname, hval);
            }
        }

        // Request-specific headers
        for (k, v) in &req.headers {
            if let (Ok(hname), Ok(hval)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                builder = builder.header(hname, hval);
            }
        }

        // Request body payload
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        builder
            .build()
            .map_err(|e| KatanaError::HttpError(e.to_string()))
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
                    error: KatanaError::MaxDepthReached.to_string(),
                    ..Default::default()
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

            // 7. Uniqueness check via 64-bit compact fingerprint filter
            if !self.visited_filter.insert(&req_url) && nr.custom_fields.is_empty() {
                continue;
            }
            self.visited_urls.insert(req_url.clone());

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
                        error: KatanaError::OutOfScope.to_string(),
                        ..Default::default()
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
                    if !self.visited_filter.insert(&check_url) {
                        continue;
                    }
                    self.visited_urls.insert(check_url);
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

    /// Dumps the current crawl state to a checkpoint file.
    pub fn dump_checkpoint_file(&self, path: &str, in_flight: Vec<String>) -> anyhow::Result<()> {
        let visited: Vec<String> = self.visited_urls.iter().map(|item| item.clone()).collect();
        let mut all_in_flight = std::collections::HashSet::new();
        for u in in_flight {
            all_in_flight.insert(u);
        }
        for u in self.in_flight_requests.iter() {
            all_in_flight.insert(u.clone());
        }
        if let Ok(q) = self.active_queue.try_lock() {
            for req in q.iter() {
                all_in_flight.insert(req.url.clone());
            }
        }
        let checkpoint =
            katana_core::CrawlCheckpoint::new(visited, all_in_flight.into_iter().collect());
        checkpoint.save(path)
    }

    /// Returns the currently visited URLs.
    pub fn visited_urls(&self) -> Vec<String> {
        self.visited_urls.iter().map(|item| item.clone()).collect()
    }

    async fn process_request(
        &self,
        current_req: Request,
        queue: Arc<tokio::sync::Mutex<VecDeque<Request>>>,
        sender: mpsc::UnboundedSender<CrawlResult>,
        notify: Arc<tokio::sync::Notify>,
    ) {
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

        // Apply token-bucket rate limiters (governor)
        if let Some(limiter) = &self.rate_limiter_second {
            limiter.until_ready().await;
        }
        if let Some(limiter) = &self.rate_limiter_minute {
            limiter.until_ready().await;
        }

        debug!(
            "Fetching [{}] {} depth={}",
            current_req.method, current_req.url, current_req.depth
        );

        let current_url = current_req.url.clone();
        self.in_flight_requests.insert(current_url.clone());

        let req_obj = match self.build_http_request(&current_req) {
            Ok(r) => r,
            Err(err) => {
                self.in_flight_requests.remove(&current_url);
                error!("Error building request for {}: {}", current_req.url, err);
                let err_result = CrawlResult {
                    timestamp: Utc::now(),
                    request: Some(current_req),
                    error: err.to_string(),
                    ..Default::default()
                };
                let _ = sender.send(err_result);
                return;
            }
        };

        let fetch_res = self.client.execute(req_obj).await;

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

                let location_header = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                let content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let headers_map: HashMap<String, String> = resp
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

                let api_type = katana_core::knowledge::classify_api_endpoint(
                    &current_req.url,
                    &content_type,
                    &body_text,
                )
                .map(|t| t.to_string());

                let secrets = if self.options.scan_secrets {
                    katana_core::knowledge::SecretScanner::scan(&body_text, &current_req.url)
                } else {
                    Vec::new()
                };

                let custom_fields = self.custom_fields.extract(&headers_map, &body_text);

                let stored_path = if self.options.store_response {
                    let dir = self
                        .options
                        .store_response_dir
                        .as_deref()
                        .unwrap_or("katana_response");
                    store_response_to_disk(dir, &current_req.url, status, &headers_map, &body_text)
                } else {
                    None
                };

                let nav_resp = Response {
                    depth: current_req.depth,
                    status_code: status,
                    headers: headers_map,
                    content_length: body_text.len(),
                    root_hostname: current_req.root_hostname.clone(),
                    forms,
                    body: body_text.clone(),
                    stored_response_path: stored_path.unwrap_or_default(),
                    api_type: api_type.clone(),
                    secrets: secrets.clone(),
                    ..Default::default()
                };

                let mut final_req = current_req.clone();
                final_req.custom_fields = custom_fields;

                let crawl_result = CrawlResult {
                    timestamp: Utc::now(),
                    request: Some(final_req),
                    response: Some(nav_resp),
                    api_type,
                    secrets,
                    error: String::new(),
                };

                let _ = sender.send(crawl_result);

                // Discover new links
                let mut discovered =
                    parse_html_endpoints(&current_req.url, &body_text, current_req.depth);

                // Location response header extraction
                if let Some(loc_str) = &location_header {
                    if let Ok(base_parsed) = Url::parse(&current_req.url) {
                        if let Ok(resolved) = base_parsed.join(loc_str) {
                            discovered.push(Request {
                                method: "GET".to_string(),
                                url: resolved.to_string(),
                                depth: current_req.depth + 1,
                                tag: "header".to_string(),
                                attribute: "location".to_string(),
                                root_hostname: current_req.root_hostname.clone(),
                                source: current_req.url.clone(),
                                ..Default::default()
                            });
                        }
                    }
                }

                if self.options.scrape_js {
                    let regex_discovered = extract_endpoints_from_regex(
                        &current_req.url,
                        &body_text,
                        current_req.depth,
                    );
                    discovered.extend(regex_discovered);
                }

                if self.options.scrape_jsluice {
                    let is_js_file = current_req.url.ends_with(".js")
                        || current_req.url.ends_with(".css")
                        || content_type.contains("/javascript");

                    if is_js_file {
                        if !katana_parser::is_common_js_library(&current_req.url) {
                            let js_discovered = katana_parser::extract_js_ast_endpoints(
                                &current_req.url,
                                &body_text,
                                current_req.depth,
                                "js",
                            );
                            discovered.extend(js_discovered);
                        }
                    } else {
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
                }

                // Funnel discovered requests through the 10-step enqueue pipeline
                if !discovered.is_empty() {
                    let mut q = queue.lock().await;
                    self.enqueue(&mut q, discovered, &sender);
                    notify.notify_waiters();
                }
            }
            Err(err) => {
                error!("Error fetching {}: {}", current_req.url, err);
                let err_result = CrawlResult {
                    timestamp: Utc::now(),
                    request: Some(current_req),
                    error: err.to_string(),
                    ..Default::default()
                };
                let _ = sender.send(err_result);
            }
        }
        self.in_flight_requests.remove(&current_url);
    }
}

#[async_trait]
impl Engine for StandardEngine {
    fn dump_checkpoint(&self, path: &str, in_flight: Vec<String>) -> anyhow::Result<()> {
        self.dump_checkpoint_file(path, in_flight)
    }

    async fn crawl(
        &self,
        root_url: &str,
        sender: mpsc::UnboundedSender<CrawlResult>,
    ) -> anyhow::Result<()> {
        let parsed_root = Url::parse(root_url)?;
        let root_hostname = parsed_root.host_str().unwrap_or("").to_string();

        let mut initial_queue = VecDeque::new();
        let initial_req = Request {
            method: "GET".to_string(),
            url: root_url.to_string(),
            depth: 0,
            root_hostname: root_hostname.clone(),
            skip_validation: true,
            ..Default::default()
        };

        self.enqueue(&mut initial_queue, vec![initial_req], &sender);
        self.seed_known_files(root_url, &mut initial_queue, &sender)
            .await;

        // Seed in-flight URLs from checkpoint file if resuming
        if let Some(resume_path) = &self.options.resume_file {
            if let Ok(cp) = katana_core::CrawlCheckpoint::load(resume_path) {
                let resume_reqs: Vec<Request> = cp
                    .in_flight_urls
                    .into_iter()
                    .map(|u| Request {
                        method: "GET".to_string(),
                        url: u,
                        depth: 1,
                        root_hostname: root_hostname.clone(),
                        ..Default::default()
                    })
                    .collect();
                self.enqueue(&mut initial_queue, resume_reqs, &sender);
            }
        }

        info!("Starting Standard crawl for root: {}", root_url);

        let concurrency = self.options.concurrency.max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        {
            let mut q = self.active_queue.lock().await;
            q.clear();
            q.extend(initial_queue);
        }
        let queue = self.active_queue.clone();
        let notify = Arc::new(tokio::sync::Notify::new());
        let active_workers = Arc::new(AtomicUsize::new(0));

        let engine = self.clone();
        let queue_clone = queue.clone();
        let notify_clone = notify.clone();
        let sender_clone = sender.clone();
        let active_clone = active_workers.clone();
        let sem_clone = semaphore.clone();

        let crawl_loop = async move {
            loop {
                let maybe_req = {
                    let mut q = queue_clone.lock().await;
                    q.pop_front()
                };

                if let Some(current_req) = maybe_req {
                    let permit = sem_clone.clone().acquire_owned().await.unwrap();
                    active_clone.fetch_add(1, Ordering::SeqCst);

                    let eng = engine.clone();
                    let q_ref = queue_clone.clone();
                    let notif = notify_clone.clone();
                    let snd = sender_clone.clone();
                    let act = active_clone.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        eng.process_request(current_req, q_ref, snd, notif.clone())
                            .await;
                        act.fetch_sub(1, Ordering::SeqCst);
                        notif.notify_waiters();
                    });
                } else {
                    if active_clone.load(Ordering::SeqCst) == 0 {
                        break;
                    }
                    tokio::select! {
                        _ = notify_clone.notified() => {},
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                    }
                }
            }

            // Wait for all in-flight workers to finish
            let _ = sem_clone.acquire_many(concurrency as u32).await;
        };

        if let Some(dur_secs) = self.options.crawl_duration {
            if dur_secs > 0 {
                tokio::select! {
                    _ = crawl_loop => {},
                    _ = tokio::time::sleep(Duration::from_secs(dur_secs)) => {
                        info!(
                            "Crawl duration reached ({}s), terminating crawl for {}",
                            dur_secs, root_url
                        );
                    }
                }
                return Ok(());
            }
        }

        crawl_loop.await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use katana_core::options::Options;

    #[test]
    fn test_build_http_request_methods_and_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom-Global".to_string(), "GlobalValue".to_string());

        let options = Options {
            custom_headers: headers,
            ..Default::default()
        };

        let engine = StandardEngine::new(options).unwrap();

        let mut req_headers = HashMap::new();
        req_headers.insert("X-Request-Specific".to_string(), "ReqVal".to_string());

        let req = Request {
            method: "POST".to_string(),
            url: "https://example.com/api/test".to_string(),
            headers: req_headers,
            body: r#"{"foo":"bar"}"#.to_string(),
            ..Default::default()
        };

        let http_req = engine.build_http_request(&req).unwrap();
        assert_eq!(http_req.method(), reqwest::Method::POST);
        assert_eq!(http_req.url().as_str(), "https://example.com/api/test");
        assert_eq!(
            http_req
                .headers()
                .get("X-Custom-Global")
                .unwrap()
                .to_str()
                .unwrap(),
            "GlobalValue"
        );
        assert_eq!(
            http_req
                .headers()
                .get("X-Request-Specific")
                .unwrap()
                .to_str()
                .unwrap(),
            "ReqVal"
        );
    }

    #[test]
    fn test_build_http_request_different_methods() {
        let options = Options::default();
        let engine = StandardEngine::new(options).unwrap();

        for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"] {
            let req = Request {
                method: method.to_string(),
                url: "https://example.com/".to_string(),
                ..Default::default()
            };
            let http_req = engine.build_http_request(&req).unwrap();
            assert_eq!(http_req.method().as_str(), *method);
        }
    }

    #[test]
    fn test_checkpoint_dump_and_resume_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("cp_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cp_file = temp_dir.join("test.resume");
        let cp_path = cp_file.to_str().unwrap();

        let options = Options::default();
        let engine = StandardEngine::new(options).unwrap();
        engine
            .visited_urls
            .insert("https://example.com/crawled1".to_string());
        engine
            .visited_urls
            .insert("https://example.com/crawled2".to_string());

        let in_flight = vec!["https://example.com/pending1".to_string()];
        engine.dump_checkpoint_file(cp_path, in_flight).unwrap();

        assert!(cp_file.exists());
        let loaded = katana_core::CrawlCheckpoint::load(cp_path).unwrap();
        assert_eq!(loaded.visited_urls.len(), 2);
        assert_eq!(loaded.in_flight_urls.len(), 1);
        assert_eq!(loaded.in_flight_urls[0], "https://example.com/pending1");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_token_bucket_rate_limiter_creation() {
        let options = Options {
            rate_limit: 10,
            rate_limit_minute: 60,
            ..Default::default()
        };
        let engine = StandardEngine::new(options).unwrap();
        assert!(engine.rate_limiter_second.is_some());
        assert!(engine.rate_limiter_minute.is_some());

        let limiter = engine.rate_limiter_second.as_ref().unwrap();
        limiter.until_ready().await;
    }
}
