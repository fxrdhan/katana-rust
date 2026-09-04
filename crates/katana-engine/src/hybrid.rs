use crate::headless::HeadlessEngine;
use crate::standard::StandardEngine;
use crate::traits::Engine;
use async_trait::async_trait;
use katana_core::navigation::Result as CrawlResult;
use katana_core::options::Options;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

/// Hybrid crawler combining high-throughput StandardEngine HTTP fetching with Headless dynamic rendering.
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
        info!("Starting Hybrid crawl for root: {}", root_url);

        // Fast static pass via StandardEngine
        let (std_tx, mut std_rx) = mpsc::unbounded_channel();
        let forward_sender = sender.clone();

        let forward_handle = tokio::spawn(async move {
            while let Some(res) = std_rx.recv().await {
                let _ = forward_sender.send(res);
            }
        });

        self.standard_engine.crawl(root_url, std_tx).await?;
        let _ = forward_handle.await;

        // Dynamic rendering pass via HeadlessEngine
        self.headless_engine.crawl(root_url, sender).await?;

        Ok(())
    }
}
