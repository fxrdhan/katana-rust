use crate::headless::HeadlessEngine;
use crate::spa::is_dynamic_spa;
use crate::standard::StandardEngine;
use crate::traits::Engine;
use async_trait::async_trait;
use katana_core::navigation::Result as CrawlResult;
use katana_core::options::Options;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

/// Hybrid crawler combining high-throughput StandardEngine HTTP fetching with Headless dynamic rendering
/// and intelligent Single Page Application (SPA) escalation.
pub struct HybridEngine {
    options: Arc<Options>,
    standard_engine: StandardEngine,
    headless_engine: HeadlessEngine,
}

impl HybridEngine {
    pub fn new(options: Options) -> anyhow::Result<Self> {
        let standard_engine = StandardEngine::new(options.clone())?;
        let headless_engine = HeadlessEngine::new(options.clone())?;

        Ok(Self {
            options: Arc::new(options),
            standard_engine,
            headless_engine,
        })
    }

    pub fn options(&self) -> &Options {
        &self.options
    }
}

#[async_trait]
impl Engine for HybridEngine {
    fn dump_checkpoint(&self, path: &str, in_flight: Vec<String>) -> anyhow::Result<()> {
        self.standard_engine.dump_checkpoint(path, in_flight)
    }

    async fn crawl(
        &self,
        root_url: &str,
        sender: mpsc::UnboundedSender<CrawlResult>,
    ) -> anyhow::Result<()> {
        info!(
            "Starting Hybrid crawl with dynamic SPA escalation for root: {}",
            root_url
        );

        // Fast static pass via StandardEngine
        let (std_tx, mut std_rx): (
            mpsc::UnboundedSender<CrawlResult>,
            mpsc::UnboundedReceiver<CrawlResult>,
        ) = mpsc::unbounded_channel();
        let forward_sender = sender.clone();
        let escalated_spas: Arc<tokio::sync::Mutex<Vec<String>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let escalated_spas_clone = Arc::clone(&escalated_spas);

        let forward_handle = tokio::spawn(async move {
            while let Some(res) = std_rx.recv().await {
                // Inspect response body for client-rendered SPA markers
                if let (Some(req), Some(resp)) = (&res.request, &res.response) {
                    let content_type = resp
                        .headers
                        .get("content-type")
                        .cloned()
                        .unwrap_or_default();

                    if is_dynamic_spa(&resp.body, &content_type) {
                        info!(
                            "Intelligent hybrid escalation: dynamic SPA detected on {}; scheduling headless CDP rendering",
                            req.url
                        );
                        let mut spas = escalated_spas_clone.lock().await;
                        spas.push(req.url.clone());
                    }
                }
                let _ = forward_sender.send(res);
            }
        });

        self.standard_engine.crawl(root_url, std_tx).await?;
        let _ = forward_handle.await;

        let detected_spas: Vec<String> = {
            let mut s = escalated_spas.lock().await;
            std::mem::take(&mut *s)
        };

        if !detected_spas.is_empty() {
            info!(
                "Escalating {} dynamic SPA targets to Headless CDP engine",
                detected_spas.len()
            );
            for spa_url in &detected_spas {
                let _ = self.headless_engine.crawl(spa_url, sender.clone()).await;
            }
        } else {
            // If no individual SPA was detected, perform dynamic rendering pass on root URL
            let _ = self.headless_engine.crawl(root_url, sender).await;
        }

        Ok(())
    }
}
