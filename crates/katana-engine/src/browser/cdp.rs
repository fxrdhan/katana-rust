use crate::browser::actions::{generate_click_actions_script, generate_form_fill_script};
use crate::browser::launcher::{build_chrome_args, find_system_chrome, ChromeLaunchOptions};
use crate::browser::stealth::get_stealth_script;
use futures::{SinkExt, StreamExt};
use katana_core::navigation::Form;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

/// Intercepted network subresource discovered during live browser navigation.
#[derive(Debug, Clone)]
pub struct DiscoveredSubresource {
    pub url: String,
    pub method: String,
    pub resource_type: String,
}

/// Chrome DevTools Protocol (CDP) WebSocket client for automating a browser page.
pub struct CdpSession {
    next_id: AtomicU64,
    cmd_tx: mpsc::Sender<Message>,
    pending_responses: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    subresources: Arc<Mutex<Vec<DiscoveredSubresource>>>,
    page_loaded: Arc<tokio::sync::Notify>,
}

impl CdpSession {
    /// Connects to a Chrome tab DevTools WebSocket URL.
    pub async fn connect(ws_url: &str) -> anyhow::Result<Self> {
        let (ws_stream, _) = connect_async(ws_url).await?;
        let (mut ws_write, mut ws_read) = ws_stream.split();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Message>(128);
        let pending_responses: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let subresources = Arc::new(Mutex::new(Vec::new()));
        let page_loaded = Arc::new(tokio::sync::Notify::new());

        // Writer task
        tokio::spawn(async move {
            while let Some(msg) = cmd_rx.recv().await {
                if ws_write.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Reader & Event dispatcher task
        let pending_resp_clone = Arc::clone(&pending_responses);
        let subresources_clone = Arc::clone(&subresources);
        let page_loaded_clone = Arc::clone(&page_loaded);
        let cmd_tx_clone = cmd_tx.clone();

        tokio::spawn(async move {
            while let Some(msg_result) = ws_read.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => break,
                };

                if let Message::Text(text) = msg {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        // Check if it's a response to a command with "id"
                        if let Some(id) = val.get("id").and_then(|v| v.as_u64()) {
                            let mut pending = pending_resp_clone.lock().await;
                            if let Some(tx) = pending.remove(&id) {
                                let _ = tx.send(val);
                            }
                            continue;
                        }

                        // Check if it's an event
                        if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
                            match method {
                                "Network.requestWillBeSent" => {
                                    if let Some(req) = val.pointer("/params/request") {
                                        let url = req
                                            .get("url")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let method = req
                                            .get("method")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("GET")
                                            .to_string();
                                        let resource_type = val
                                            .pointer("/params/type")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Other")
                                            .to_string();

                                        if !url.is_empty() && !url.starts_with("data:") {
                                            let mut sub = subresources_clone.lock().await;
                                            sub.push(DiscoveredSubresource {
                                                url,
                                                method,
                                                resource_type,
                                            });
                                        }
                                    }
                                }
                                "Fetch.requestPaused" => {
                                    if let Some(request_id) =
                                        val.pointer("/params/requestId").and_then(|v| v.as_str())
                                    {
                                        let continue_cmd = json!({
                                            "id": 9999999,
                                            "method": "Fetch.continueRequest",
                                            "params": {
                                                "requestId": request_id
                                            }
                                        });
                                        let _ = cmd_tx_clone
                                            .send(Message::Text(continue_cmd.to_string()))
                                            .await;
                                    }
                                }
                                "Page.loadEventFired" | "Page.domContentEventFired" => {
                                    page_loaded_clone.notify_waiters();
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            // Clear pending responses to fail fast on disconnect
            let mut pending = pending_resp_clone.lock().await;
            pending.clear();
        });

        Ok(Self {
            next_id: AtomicU64::new(1),
            cmd_tx,
            pending_responses,
            subresources,
            page_loaded,
        })
    }

    /// Sends a CDP command and awaits its response.
    pub async fn send_command(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = json!({
            "id": id,
            "method": method,
            "params": params
        });

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = self.pending_responses.lock().await;
            pending.insert(id, resp_tx);
        }

        self.cmd_tx
            .send(Message::Text(req.to_string()))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send CDP command: {}", e))?;

        let resp = tokio::time::timeout(Duration::from_secs(10), resp_rx)
            .await
            .map_err(|_| anyhow::anyhow!("CDP command timed out: {}", method))??;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("CDP error on {}: {}", method, err);
        }

        Ok(resp)
    }

    /// Enables Page, Network, Runtime, and Fetch domains.
    pub async fn init_page(&self, stealth: bool) -> anyhow::Result<()> {
        self.send_command("Page.enable", json!({})).await?;
        self.send_command("Network.enable", json!({})).await?;
        self.send_command("Runtime.enable", json!({})).await?;
        let _ = self.send_command("Fetch.enable", json!({})).await;

        if stealth {
            let stealth_code = get_stealth_script();
            let _ = self
                .send_command(
                    "Page.addScriptToEvaluateOnNewDocument",
                    json!({ "source": stealth_code }),
                )
                .await;
        }

        Ok(())
    }

    /// Navigates the page to the target URL and waits for page load or timeout.
    pub async fn navigate(&self, url: &str, wait_duration: Duration) -> anyhow::Result<()> {
        self.send_command("Page.navigate", json!({ "url": url }))
            .await?;

        // Wait for page load event or timeout
        let _ = tokio::time::timeout(wait_duration, self.page_loaded.notified()).await;
        // Small settling grace period for client JS hydration
        tokio::time::sleep(Duration::from_millis(300)).await;

        Ok(())
    }

    /// Evaluates a JavaScript expression and returns the result value.
    pub async fn evaluate(&self, expression: &str) -> anyhow::Result<Value> {
        let resp = self
            .send_command(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true
                }),
            )
            .await?;

        Ok(resp
            .pointer("/result/result/value")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// Extracts the full outer HTML of the document after JS execution.
    pub async fn get_html(&self) -> anyhow::Result<String> {
        let val = self.evaluate("document.documentElement.outerHTML").await?;
        Ok(val.as_str().unwrap_or("").to_string())
    }

    /// Simulates clicking interactive elements (buttons, links with onclick).
    pub async fn click_interactive_elements(&self) -> anyhow::Result<()> {
        let script = generate_click_actions_script();
        let _ = self.evaluate(script).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok(())
    }

    /// Automatically populates and submits forms on the page.
    pub async fn fill_forms(&self, forms: &[Form]) -> anyhow::Result<()> {
        for form in forms {
            let script = generate_form_fill_script(form);
            let _ = self.evaluate(&script).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// Drains all intercepted subresource URLs discovered during page execution.
    pub async fn drain_subresources(&self) -> Vec<DiscoveredSubresource> {
        let mut sub = self.subresources.lock().await;
        std::mem::take(&mut *sub)
    }
}

/// Lifecycle manager for Chrome instances and tab recycling.
pub struct BrowserLifecycleManager {
    child_process: Option<Child>,
    http_endpoint: String,
    browser_ws_url: String,
    active_tab_id: Option<String>,
    tab_request_count: usize,
    max_requests_per_tab: usize,
    stealth: bool,
}

impl BrowserLifecycleManager {
    pub fn browser_ws_url(&self) -> &str {
        &self.browser_ws_url
    }

    pub fn http_endpoint(&self) -> &str {
        &self.http_endpoint
    }

    /// Launches a system Chrome browser or attaches to an existing CDP WebSocket/HTTP endpoint.
    pub fn new(options: &ChromeLaunchOptions, max_requests_per_tab: usize) -> anyhow::Result<Self> {
        if let Some(ws_url) = &options.chrome_ws_url {
            let http_endpoint = if ws_url.starts_with("http://") || ws_url.starts_with("https://") {
                ws_url.clone()
            } else {
                let is_secure = ws_url.starts_with("wss://");
                let stripped = ws_url
                    .strip_prefix("wss://")
                    .or_else(|| ws_url.strip_prefix("ws://"))
                    .unwrap_or(ws_url);
                let host_port = stripped.split('/').next().unwrap_or("127.0.0.1:9222");
                format!(
                    "{}://{}",
                    if is_secure { "https" } else { "http" },
                    host_port
                )
            };

            return Ok(Self {
                child_process: None,
                http_endpoint,
                browser_ws_url: ws_url.clone(),
                active_tab_id: None,
                tab_request_count: 0,
                max_requests_per_tab,
                stealth: true,
            });
        }

        let chrome_bin = find_system_chrome().ok_or_else(|| {
            anyhow::anyhow!("Chrome or Chromium executable not found on host system")
        })?;

        let mut cmd = Command::new(chrome_bin);
        let chrome_opts = options.clone();
        // Force remote debugging port to 0 for OS to pick dynamic free port
        let mut args = build_chrome_args(&chrome_opts);
        args.push("--remote-debugging-port=0".to_string());
        cmd.args(args);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot capture Chrome stderr"))?;

        let mut reader = BufReader::new(stderr);
        let mut browser_ws_url = String::new();
        let mut http_endpoint = String::new();

        // Read stderr until "DevTools listening on ws://..."
        let mut line = String::new();
        for _ in 0..50 {
            line.clear();
            if reader.read_line(&mut line).is_ok() && line.contains("DevTools listening on") {
                if let Some(ws_idx) = line.find("ws://") {
                    let ws_str = line[ws_idx..].trim().to_string();
                    browser_ws_url = ws_str.clone();

                    if let Some(host_port) = ws_str
                        .strip_prefix("ws://")
                        .and_then(|s| s.split('/').next())
                    {
                        http_endpoint = format!("http://{}", host_port);
                    }
                    break;
                }
            }
        }

        if browser_ws_url.is_empty() {
            let _ = child.kill();
            anyhow::bail!("Failed to obtain DevTools listening WebSocket URL from Chrome process");
        }

        info!("Spawned Chrome headless process on CDP: {}", http_endpoint);

        Ok(Self {
            child_process: Some(child),
            http_endpoint,
            browser_ws_url,
            active_tab_id: None,
            tab_request_count: 0,
            max_requests_per_tab,
            stealth: true,
        })
    }

    /// Acquires a clean or recycled CDP tab session.
    pub async fn acquire_tab_session(&mut self) -> anyhow::Result<CdpSession> {
        // If a direct page WebSocket URL was provided (e.g. ws://.../devtools/page/<id>), connect directly
        if self.browser_ws_url.contains("/devtools/page/") {
            let session = CdpSession::connect(&self.browser_ws_url).await?;
            session.init_page(self.stealth).await?;
            return Ok(session);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        // Check if existing tab needs recycling
        if self.tab_request_count >= self.max_requests_per_tab {
            if let Some(tab_id) = self.active_tab_id.take() {
                debug!(
                    "Recycling browser tab {} after {} requests",
                    tab_id, self.tab_request_count
                );
                let close_url = format!("{}/json/close/{}", self.http_endpoint, tab_id);
                let _ = client.get(&close_url).send().await;
            }
            self.tab_request_count = 0;
        }

        // Create new tab if none active
        let tab_ws_url = if let Some(tab_id) = &self.active_tab_id {
            self.tab_request_count += 1;
            let stripped_endpoint = self
                .http_endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            format!("ws://{}/devtools/page/{}", stripped_endpoint, tab_id)
        } else {
            let new_url = format!("{}/json/new?about:blank", self.http_endpoint);
            let resp = client.put(&new_url).send().await?.json::<Value>().await?;

            let tab_id = resp
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ws_url = resp
                .get("webSocketDebuggerUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if ws_url.is_empty() {
                anyhow::bail!("Failed to create new CDP page target");
            }

            self.active_tab_id = Some(tab_id);
            self.tab_request_count = 1;
            ws_url
        };

        let session = CdpSession::connect(&tab_ws_url).await?;
        session.init_page(self.stealth).await?;

        Ok(session)
    }

    /// Explicitly recycles the active tab (e.g. after a navigation crash).
    pub async fn recycle_active_tab(&mut self) {
        if let Some(tab_id) = self.active_tab_id.take() {
            let client = reqwest::Client::default();
            let close_url = format!("{}/json/close/{}", self.http_endpoint, tab_id);
            let _ = client.get(&close_url).send().await;
        }
        self.tab_request_count = 0;
    }
}

impl Drop for BrowserLifecycleManager {
    fn drop(&mut self) {
        if let Some(mut child) = self.child_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_subresource_representation() {
        let sub = DiscoveredSubresource {
            url: "https://example.com/assets/app.js".to_string(),
            method: "GET".to_string(),
            resource_type: "Script".to_string(),
        };

        assert_eq!(sub.url, "https://example.com/assets/app.js");
        assert_eq!(sub.method, "GET");
        assert_eq!(sub.resource_type, "Script");
    }

    #[test]
    fn test_browser_lifecycle_manager_ws_url_accessor() {
        let opts = ChromeLaunchOptions {
            chrome_ws_url: Some("ws://127.0.0.1:9222/devtools/browser/test-id".to_string()),
            ..Default::default()
        };

        let mgr = BrowserLifecycleManager::new(&opts, 25).unwrap();
        assert_eq!(
            mgr.browser_ws_url(),
            "ws://127.0.0.1:9222/devtools/browser/test-id"
        );
        assert_eq!(mgr.http_endpoint(), "http://127.0.0.1:9222");
    }
}
