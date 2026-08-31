use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

/// Persistent checkpoint state for saving and resuming crawling operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlCheckpoint {
    pub visited_urls: Vec<String>,
    pub in_flight_urls: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

impl CrawlCheckpoint {
    pub fn new(visited_urls: Vec<String>, in_flight_urls: Vec<String>) -> Self {
        Self {
            visited_urls,
            in_flight_urls,
            timestamp: Utc::now(),
        }
    }

    /// Saves the current checkpoint state to a JSON file.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json_str = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json_str.as_bytes())?;
        Ok(())
    }

    /// Loads a crawl checkpoint from a JSON file.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let checkpoint: Self = serde_json::from_str(&content)?;
        Ok(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_serialization() {
        let temp_file =
            std::env::temp_dir().join(format!("checkpoint_test_{}.json", std::process::id()));
        let path_str = temp_file.to_str().unwrap();

        let cp = CrawlCheckpoint::new(
            vec!["https://example.com/page1".to_string()],
            vec!["https://example.com/page2".to_string()],
        );

        cp.save(path_str).unwrap();

        let loaded = CrawlCheckpoint::load(path_str).unwrap();
        assert_eq!(
            loaded.visited_urls,
            vec!["https://example.com/page1".to_string()]
        );
        assert_eq!(
            loaded.in_flight_urls,
            vec!["https://example.com/page2".to_string()]
        );

        let _ = std::fs::remove_file(temp_file);
    }
}
