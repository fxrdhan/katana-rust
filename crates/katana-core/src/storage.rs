use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref INDEX_LOCK: Mutex<()> = Mutex::new(());
}

/// Thread-safe disk persistence for raw HTTP responses with synchronized index mapping (index.txt).
pub struct ResponseStorageManager;

impl ResponseStorageManager {
    /// Stores an HTTP response to disk and appends an entry to the index.txt catalogue.
    pub fn store_response(
        dir: &str,
        url: &str,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> anyhow::Result<String> {
        let dir_path = Path::new(dir);
        fs::create_dir_all(dir_path)?;

        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        let file_hash = format!("{:x}", hasher.finalize());
        let filename = format!("{}.txt", &file_hash[..16]);
        let file_path: PathBuf = dir_path.join(&filename);

        // Serialize standard HTTP/1.1 wire payload
        let mut content = format!("HTTP/1.1 {}\r\n", status);
        for (k, v) in headers {
            content.push_str(&format!("{}: {}\r\n", k, v));
        }
        content.push_str("\r\n");
        content.push_str(body);

        fs::write(&file_path, content)?;

        // Synchronize index.txt mapping: <hash> <status> <url> <filename>
        let index_path = dir_path.join("index.txt");
        let _lock = INDEX_LOCK.lock().unwrap();
        let mut index_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)?;

        writeln!(
            index_file,
            "{} {} {} {}",
            &file_hash[..16],
            status,
            url,
            filename
        )?;

        Ok(file_path.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_response_and_index() {
        let temp_dir = std::env::temp_dir().join(format!(
            "katana_test_storage_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let dir_str = temp_dir.to_str().unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        headers.insert("server".to_string(), "nginx".to_string());

        let file_path = ResponseStorageManager::store_response(
            dir_str,
            "https://example.com/login",
            200,
            &headers,
            "<html><body>Login</body></html>",
        )
        .expect("failed to store response");

        assert!(Path::new(&file_path).exists());

        // Check index.txt
        let index_file = temp_dir.join("index.txt");
        assert!(index_file.exists());

        let index_content = fs::read_to_string(&index_file).unwrap();
        assert!(index_content.contains("https://example.com/login"));
        assert!(index_content.contains("200"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_deterministic_hashing() {
        let temp_dir = std::env::temp_dir().join(format!(
            "katana_test_deterministic_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let dir_str = temp_dir.to_str().unwrap();
        let headers = HashMap::new();

        let path1 = ResponseStorageManager::store_response(
            dir_str,
            "https://example.com/test",
            200,
            &headers,
            "body1",
        )
        .unwrap();
        let path2 = ResponseStorageManager::store_response(
            dir_str,
            "https://example.com/test",
            200,
            &headers,
            "body2",
        )
        .unwrap();

        assert_eq!(path1, path2);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
