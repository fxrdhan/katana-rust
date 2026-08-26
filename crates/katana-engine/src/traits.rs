use async_trait::async_trait;
use katana_core::navigation::Result as CrawlResult;
use tokio::sync::mpsc;

#[async_trait]
pub trait Engine: Send + Sync {
    /// Execute crawl starting from root URL and stream results through a channel.
    async fn crawl(&self, root_url: &str, sender: mpsc::UnboundedSender<CrawlResult>) -> anyhow::Result<()>;
}
