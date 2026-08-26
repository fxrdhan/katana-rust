use crate::pathtrie::PathTrie;
use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

lazy_static! {
    static ref RE_UUID: Regex = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap();
    static ref RE_SHA256: Regex = Regex::new(r"^[0-9a-fA-F]{64}$").unwrap();
    static ref RE_SHA1: Regex = Regex::new(r"^[0-9a-fA-F]{40}$").unwrap();
    static ref RE_MD5: Regex = Regex::new(r"^[0-9a-fA-F]{32}$").unwrap();
    static ref RE_OBJECT_ID: Regex = Regex::new(r"^[0-9a-fA-F]{24}$").unwrap();
    static ref RE_HEX: Regex = Regex::new(r"^(?:[0-9a-fA-F]{8,}|[0-9]*[a-fA-F]+[0-9a-fA-F]*)$").unwrap();
    static ref RE_DATE: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
    static ref RE_TIMESTAMP: Regex = Regex::new(r"^\d{10}(?:\d{3})?$").unwrap();
    static ref RE_NUMERIC: Regex = Regex::new(r"^\d+$").unwrap();
}

/// Transform a path segment into its canonical placeholder token.
pub fn fingerprint_segment(segment: &str) -> String {
    if segment.is_empty() {
        return String::new();
    }

    if RE_UUID.is_match(segment) {
        return "{uuid}".to_string();
    }
    if RE_SHA256.is_match(segment) {
        return "{sha256}".to_string();
    }
    if RE_SHA1.is_match(segment) {
        return "{sha1}".to_string();
    }
    if RE_MD5.is_match(segment) {
        return "{md5}".to_string();
    }
    if RE_OBJECT_ID.is_match(segment) {
        return "{oid}".to_string();
    }
    if RE_DATE.is_match(segment) {
        return "{date}".to_string();
    }
    if RE_TIMESTAMP.is_match(segment) {
        return "{ts}".to_string();
    }
    if RE_NUMERIC.is_match(segment) {
        return "{num}".to_string();
    }
    if segment.len() >= 8 && RE_HEX.is_match(segment) {
        return "{hex}".to_string();
    }

    segment.to_string()
}

/// Compute structural URL fingerprint across path segments and query parameter keys.
pub fn fingerprint_url(raw_url: &str, path_trie: Option<&mut PathTrie>) -> String {
    let mut parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return raw_url.to_string(),
    };

    let segments: Vec<String> = parsed
        .path_segments()
        .map(|s| s.map(fingerprint_segment).collect())
        .unwrap_or_default();

    let host = parsed.host_str().unwrap_or("").to_string();

    let final_segments = if let Some(trie) = path_trie {
        trie.insert_and_collapse(&host, &segments)
    } else {
        segments
    };

    let new_path = format!("/{}", final_segments.join("/"));
    parsed.set_path(&new_path);

    // Keep only sorted query keys, strip values
    let mut query_keys: Vec<String> = parsed.query_pairs().map(|(k, _)| k.to_string()).collect();
    query_keys.sort();
    query_keys.dedup();

    if query_keys.is_empty() {
        parsed.set_query(None);
    } else {
        let query_str = query_keys.join("&");
        parsed.set_query(Some(&query_str));
    }

    let res = parsed.to_string();
    res.replace("%7B", "{").replace("%7D", "}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_tokens() {
        assert_eq!(fingerprint_segment("12345"), "{num}");
        assert_eq!(fingerprint_segment("2026-08-26"), "{date}");
        assert_eq!(fingerprint_segment("1724673849"), "{ts}");
        assert_eq!(
            fingerprint_segment("550e8400-e29b-41d4-a716-446655440000"),
            "{uuid}"
        );
        assert_eq!(
            fingerprint_segment("5d41402abc4b2a76b9719d911017c592"),
            "{md5}"
        );
        assert_eq!(fingerprint_segment("dashboard"), "dashboard");
    }

    #[test]
    fn test_fingerprint_url_query_normalization() {
        let url1 = "https://example.com/users/123?page=1&sort=desc";
        let url2 = "https://example.com/users/456?sort=asc&page=2";

        let fp1 = fingerprint_url(url1, None);
        let fp2 = fingerprint_url(url2, None);

        assert_eq!(fp1, "https://example.com/users/{num}?page&sort");
        assert_eq!(fp1, fp2, "Different parameter values and IDs should produce identical structural fingerprint");
    }
}
