use crate::pathtrie::PathTrie;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::BTreeSet;
use url::Url;

lazy_static! {
    static ref RE_UUID: Regex = Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    .unwrap();
    static ref RE_SHA256: Regex = Regex::new(r"^[0-9a-fA-F]{64}$").unwrap();
    static ref RE_SHA1: Regex = Regex::new(r"^[0-9a-fA-F]{40}$").unwrap();
    static ref RE_MD5: Regex = Regex::new(r"^[0-9a-fA-F]{32}$").unwrap();
    static ref RE_OID: Regex = Regex::new(r"^[0-9a-fA-F]{24}$").unwrap();
    static ref RE_HEX: Regex = Regex::new(r"^[0-9a-fA-F]{8,}$").unwrap();
    static ref RE_DATE: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
    static ref RE_TS: Regex = Regex::new(r"^\d{10}(\d{3})?$").unwrap();
    static ref RE_NUM: Regex = Regex::new(r"^\d+$").unwrap();
}

/// Check if string has at least one a-f or A-F hex character.
#[inline]
pub fn contains_hex_letter(s: &str) -> bool {
    s.chars()
        .any(|c| ('a'..='f').contains(&c) || ('A'..='F').contains(&c))
}

/// Normalize a single path segment against heuristic patterns.
pub fn normalize_segment(segment: &str) -> (String, bool) {
    if segment.is_empty() {
        return (String::new(), false);
    }

    // If segment is already a normalized placeholder
    let clean = segment.replace("%7B", "{").replace("%7D", "}");
    if clean.starts_with('{') && clean.ends_with('}') {
        return (clean, true);
    }

    if RE_UUID.is_match(&clean) {
        return ("{uuid}".to_string(), true);
    }
    if RE_SHA256.is_match(&clean) && contains_hex_letter(&clean) {
        return ("{sha256}".to_string(), true);
    }
    if RE_SHA1.is_match(&clean) && contains_hex_letter(&clean) {
        return ("{sha1}".to_string(), true);
    }
    if RE_MD5.is_match(&clean) && contains_hex_letter(&clean) {
        return ("{md5}".to_string(), true);
    }
    if RE_OID.is_match(&clean) && contains_hex_letter(&clean) {
        return ("{oid}".to_string(), true);
    }
    if RE_HEX.is_match(&clean) && contains_hex_letter(&clean) {
        return ("{hex}".to_string(), true);
    }
    if RE_DATE.is_match(&clean) {
        return ("{date}".to_string(), true);
    }
    if RE_TS.is_match(&clean) {
        return ("{ts}".to_string(), true);
    }
    if RE_NUM.is_match(&clean) {
        return ("{num}".to_string(), true);
    }

    (clean, false)
}

/// Produces a structural fingerprint of the given URL.
pub fn fingerprint_url(raw_url: &str, trie: Option<&PathTrie>) -> String {
    if raw_url.is_empty() {
        return raw_url.to_string();
    }

    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return raw_url.to_string(),
    };

    // Extract path and query from raw_url to preserve empty-path vs root-slash vs trailing-slash
    let without_scheme = if let Some(idx) = raw_url.find("://") {
        &raw_url[idx + 3..]
    } else {
        raw_url
    };

    let path_and_query = if let Some(slash_idx) = without_scheme.find('/') {
        &without_scheme[slash_idx..]
    } else if let Some(q_idx) = without_scheme.find('?') {
        &without_scheme[q_idx..]
    } else if let Some(hash_idx) = without_scheme.find('#') {
        &without_scheme[hash_idx..]
    } else {
        ""
    };

    let raw_path = if let Some(q_idx) = path_and_query.find('?') {
        &path_and_query[..q_idx]
    } else if let Some(hash_idx) = path_and_query.find('#') {
        &path_and_query[..hash_idx]
    } else {
        path_and_query
    };

    if raw_path.is_empty() || raw_path == "/" {
        let mut res = build_fingerprint_base(&parsed, raw_path);
        append_sorted_query(&parsed, &mut res);
        return res;
    }

    let has_trailing_slash = raw_path.ends_with('/') && raw_path != "/";
    let trimmed = raw_path.trim_matches('/');
    let mut segments: Vec<String> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('/').map(|s| s.to_string()).collect()
    };

    // Layer 1: heuristic regex normalization
    for seg in &mut segments {
        let (placeholder, matched) = normalize_segment(seg);
        if matched {
            *seg = placeholder;
        }
    }

    // Layer 2: adaptive trie normalization
    if let Some(trie) = trie {
        let host = parsed.host_str().unwrap_or("");
        segments = trie.fingerprint(host, &segments);
    }

    let mut fingerprinted_path = format!("/{}", segments.join("/"));
    if has_trailing_slash {
        fingerprinted_path.push('/');
    }

    let mut res = build_fingerprint_base(&parsed, &fingerprinted_path);
    append_sorted_query(&parsed, &mut res);
    res
}

fn build_fingerprint_base(parsed: &Url, path: &str) -> String {
    let mut result = String::new();
    if !parsed.scheme().is_empty() {
        result.push_str(parsed.scheme());
        result.push_str("://");
    }

    if let Some(host) = parsed.host_str() {
        result.push_str(host);
        if let Some(port) = parsed.port() {
            result.push(':');
            result.push_str(&port.to_string());
        }
    }

    result.push_str(path);
    result
}

fn append_sorted_query(parsed: &Url, result: &mut String) {
    if parsed.query().is_some() {
        let mut keys = BTreeSet::new();
        for (k, _) in parsed.query_pairs() {
            keys.insert(k.to_string());
        }
        if !keys.is_empty() {
            result.push('?');
            let query_str = keys.into_iter().collect::<Vec<_>>().join("&");
            result.push_str(&query_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathtrie::DEFAULT_PROMOTION_THRESHOLD;

    #[test]
    fn test_contains_hex_letter() {
        let tests = [
            ("abcdef01", true),
            ("ABCDEF01", true),
            ("1234abcd", true),
            ("12345678", false),
            ("00000000", false),
            ("0000000a", true),
            ("", false),
            ("g", false),
        ];

        for (input, want) in tests {
            assert_eq!(
                contains_hex_letter(input),
                want,
                "contains_hex_letter({input}) failed"
            );
        }
    }

    #[test]
    fn test_normalize_segment() {
        let tests = [
            // UUID
            ("550e8400-e29b-41d4-a716-446655440000", "{uuid}", true),
            ("550E8400-E29B-41D4-A716-446655440000", "{uuid}", true),
            ("12345678-1234-1234-1234-123456789012", "{uuid}", true),
            // SHA256
            (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "{sha256}",
                true,
            ),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                "{num}",
                true,
            ),
            // SHA1
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "{sha1}", true),
            ("1234567890123456789012345678901234567890", "{num}", true),
            // MD5
            ("d41d8cd98f00b204e9800998ecf8427e", "{md5}", true),
            ("12345678901234567890123456789012", "{num}", true),
            // ObjectId
            ("507f1f77bcf86cd799439011", "{oid}", true),
            ("123456789012345678901234", "{num}", true),
            // Long hex
            ("abcdef01", "{hex}", true),
            ("1234abcd5678", "{hex}", true),
            ("DEADBEEF", "{hex}", true),
            ("12345678", "{num}", true),
            ("123456789", "{num}", true),
            // ISO date
            ("2024-01-15", "{date}", true),
            ("2023-12-31", "{date}", true),
            ("1999-01-01", "{date}", true),
            ("20240115", "{num}", true),
            // Timestamp
            ("1704067200", "{ts}", true),
            ("1704067200000", "{ts}", true),
            ("17040672001", "{num}", true),
            ("17040672000001", "{num}", true),
            // Numeric
            ("123", "{num}", true),
            ("0", "{num}", true),
            ("999999", "{num}", true),
            ("1", "{num}", true),
            // Non-matching
            ("users", "users", false),
            ("api", "api", false),
            ("v1", "v1", false),
            ("v2", "v2", false),
            ("my-awesome-post", "my-awesome-post", false),
            ("image123.jpg", "image123.jpg", false),
            ("style.css", "style.css", false),
            ("index.html", "index.html", false),
            ("abcdef", "abcdef", false),
            ("feedback", "feedback", false),
            ("deadbeef-cafe", "deadbeef-cafe", false),
            ("", "", false),
        ];

        for (segment, want, matched) in tests {
            let (got_val, got_match) = normalize_segment(segment);
            assert_eq!(got_val, want, "normalize_segment({segment}) value mismatch");
            assert_eq!(
                got_match, matched,
                "normalize_segment({segment}) match flag mismatch"
            );
        }
    }

    #[test]
    fn test_fingerprint_url_golden_vectors() {
        let tests = [
            (
                "numeric path segments",
                "https://example.com/api/v1/users/123/posts/456",
                "https://example.com/api/v1/users/{num}/posts/{num}",
            ),
            (
                "uuid in path",
                "https://example.com/product/550e8400-e29b-41d4-a716-446655440000",
                "https://example.com/product/{uuid}",
            ),
            (
                "date in path",
                "https://example.com/archive/2024-01-15/article",
                "https://example.com/archive/{date}/article",
            ),
            (
                "query params sorted and values dropped",
                "https://example.com/search?z=1&a=2&m=3",
                "https://example.com/search?a&m&z",
            ),
            (
                "no variable segments unchanged",
                "https://example.com/about/team",
                "https://example.com/about/team",
            ),
            ("root path", "https://example.com/", "https://example.com/"),
            ("empty path", "https://example.com", "https://example.com"),
            (
                "mixed pattern types in one path",
                "https://example.com/users/42/posts/da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "https://example.com/users/{num}/posts/{sha1}",
            ),
            (
                "trailing slash preserved",
                "https://example.com/api/v1/users/123/",
                "https://example.com/api/v1/users/{num}/",
            ),
            (
                "timestamp in path",
                "https://example.com/events/1704067200",
                "https://example.com/events/{ts}",
            ),
            (
                "http scheme",
                "http://example.com/items/99",
                "http://example.com/items/{num}",
            ),
            (
                "url with port",
                "https://example.com:8443/api/users/42",
                "https://example.com:8443/api/users/{num}",
            ),
            (
                "fragment stripped",
                "https://example.com/page/123#section",
                "https://example.com/page/{num}",
            ),
            (
                "variable path with query params",
                "https://example.com/users/42/posts?sort=date&page=1",
                "https://example.com/users/{num}/posts?page&sort",
            ),
            (
                "uuid then numeric then date",
                "https://example.com/obj/550e8400-e29b-41d4-a716-446655440000/rev/5/date/2024-01-15",
                "https://example.com/obj/{uuid}/rev/{num}/date/{date}",
            ),
            (
                "md5 hash in path",
                "https://cdn.example.com/assets/d41d8cd98f00b204e9800998ecf8427e/image.png",
                "https://cdn.example.com/assets/{md5}/image.png",
            ),
            (
                "sha256 hash in path",
                "https://example.com/blobs/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "https://example.com/blobs/{sha256}",
            ),
            (
                "mongodb objectid in path",
                "https://example.com/docs/507f1f77bcf86cd799439011",
                "https://example.com/docs/{oid}",
            ),
            (
                "long hex token in path",
                "https://example.com/verify/abcdef0123456789",
                "https://example.com/verify/{hex}",
            ),
            (
                "13-digit timestamp",
                "https://example.com/snapshot/1704067200000",
                "https://example.com/snapshot/{ts}",
            ),
            (
                "single segment numeric",
                "https://example.com/42",
                "https://example.com/{num}",
            ),
            (
                "query with no path segments",
                "https://example.com/?q=test",
                "https://example.com/?q",
            ),
            (
                "single query param",
                "https://example.com/search?q=hello",
                "https://example.com/search?q",
            ),
            (
                "file extension not affected",
                "https://example.com/assets/image123.jpg",
                "https://example.com/assets/image123.jpg",
            ),
            (
                "deeply nested numeric ids",
                "https://example.com/a/1/b/2/c/3/d/4",
                "https://example.com/a/{num}/b/{num}/c/{num}/d/{num}",
            ),
        ];

        for (name, url_str, want) in tests {
            let got = fingerprint_url(url_str, None);
            assert_eq!(got, want, "Test case [{name}] failed for URL {url_str}");
        }
    }

    #[test]
    fn test_fingerprint_url_idempotency() {
        let urls = [
            "https://example.com/users/123/posts/456",
            "https://example.com/product/550e8400-e29b-41d4-a716-446655440000",
            "https://example.com/search?z=1&a=2",
            "https://example.com/about/team",
        ];
        for raw in urls {
            let first = fingerprint_url(raw, None);
            let second = fingerprint_url(&first, None);
            assert_eq!(first, second, "Fingerprint must be idempotent for {raw}");
        }
    }

    #[test]
    fn test_fingerprint_url_with_trie_promotion_lifecycle() {
        let trie = PathTrie::new(0);
        let host = "https://example.com";

        // Before promotion: each slug is kept as-is
        for i in 0..DEFAULT_PROMOTION_THRESHOLD {
            let u = format!("{host}/blog/post-{i}");
            let expected = format!("{host}/blog/post-{i}");
            let fp = fingerprint_url(&u, Some(&trie));
            assert_eq!(fp, expected, "Before promotion failed for {u}");
        }

        // Trigger promotion with one more distinct slug
        fingerprint_url(&format!("{host}/blog/the-trigger"), Some(&trie));

        // After promotion: all new slugs should collapse
        let got = fingerprint_url(&format!("{host}/blog/never-seen-before"), Some(&trie));
        let want = format!("{host}/blog/{{param}}");
        assert_eq!(got, want, "After promotion new slug did not collapse");

        // Previously seen slugs also collapse after promotion
        let got_prev = fingerprint_url(&format!("{host}/blog/post-0"), Some(&trie));
        assert_eq!(got_prev, want, "Previously seen slug did not collapse");
    }

    #[test]
    fn test_fingerprint_url_with_trie_multiple_hosts() {
        let trie = PathTrie::new(0);

        // Promote /users/* on host A
        for i in 0..=DEFAULT_PROMOTION_THRESHOLD {
            fingerprint_url(&format!("https://a.com/users/user-{i}"), Some(&trie));
        }

        // Host B should be unaffected
        let got_b = fingerprint_url("https://b.com/users/alice", Some(&trie));
        assert_eq!(got_b, "https://b.com/users/alice", "Host B was affected");

        // Host A should collapse
        let got_a = fingerprint_url("https://a.com/users/new-user", Some(&trie));
        assert_eq!(
            got_a, "https://a.com/users/{param}",
            "Host A did not collapse"
        );
    }
}
