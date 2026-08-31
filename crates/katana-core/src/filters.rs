use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

pub const MAX_URL_LENGTH: usize = 2_097_152; // 2MB Chrome Limit
pub const MIN_CYCLE_SEQUENCE_LEN: usize = 10;
pub const MAX_CYCLE_SEQUENCE_COUNT: usize = 10;

lazy_static! {
    static ref LOGOUT_URL_PATTERN: Regex = Regex::new(
        r"(?i)(log[\s_-]?out|sign[\s_-]?out|signout|deconnexion|cerrar[\s_-]?sesion|sair|abmelden|uitloggen|ausloggen|disconnect|terminate|end[\s_-]?session|salir|desconectar|afmelden|wyloguj|sign[\s_-]?off)"
    ).unwrap();
}

/// Detects whether a URL is a logout / session termination endpoint.
#[inline]
pub fn is_logout_url(url: &str) -> bool {
    LOGOUT_URL_PATTERN.is_match(url)
}

/// Detects whether a URL is trapped in an infinite cycle or redirect loop.
pub fn is_cycle(url: &str) -> bool {
    if url.len() > MAX_URL_LENGTH {
        return true;
    }

    // Check for repeating substring sequences (>= 10 chars repeating >= 10 times)
    let bytes = url.as_bytes();
    let n = bytes.len();
    if n < MIN_CYCLE_SEQUENCE_LEN * MAX_CYCLE_SEQUENCE_COUNT {
        return false;
    }

    for seq_len in MIN_CYCLE_SEQUENCE_LEN..=(n / MAX_CYCLE_SEQUENCE_COUNT) {
        for start in 0..=(n - seq_len * MAX_CYCLE_SEQUENCE_COUNT) {
            let seq = &bytes[start..start + seq_len];
            let mut count = 1;
            let mut next = start + seq_len;

            while next + seq_len <= n && &bytes[next..next + seq_len] == seq {
                count += 1;
                if count >= MAX_CYCLE_SEQUENCE_COUNT {
                    return true;
                }
                next += seq_len;
            }
        }
    }

    false
}

/// Replaces all query parameter values with a replacement value (e.g. empty string for -iqp).
pub fn replace_all_query_param(raw_url: &str, replacement: &str) -> String {
    let mut parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return raw_url.to_string(),
    };

    if parsed.query().is_none() {
        return raw_url.to_string();
    }

    let keys: Vec<String> = parsed.query_pairs().map(|(k, _)| k.to_string()).collect();
    let mut pairs = Vec::with_capacity(keys.len());
    for k in keys {
        pairs.push((k, replacement.to_string()));
    }

    parsed.query_pairs_mut().clear().extend_pairs(pairs);
    parsed.to_string()
}

/// Extracts parent directory paths for path-climbing (-pc).
pub fn extract_parent_paths(raw_url: &str) -> Vec<String> {
    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };

    let path = parsed.path().trim_matches('/');
    if path.is_empty() {
        return Vec::new();
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 1 {
        return Vec::new();
    }

    let scheme = parsed.scheme();
    let host = match parsed.host_str() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let port_part = if let Some(p) = parsed.port() {
        format!(":{}", p)
    } else {
        String::new()
    };

    let mut urls = Vec::new();
    for i in (1..parts.len()).rev() {
        let parent_path = parts[..i].join("/");
        if !parent_path.is_empty() {
            urls.push(format!(
                "{}://{}{}/{}",
                scheme, host, port_part, parent_path
            ));
        }
    }

    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_logout_url() {
        assert!(is_logout_url("https://example.com/auth/logout"));
        assert!(is_logout_url("https://example.com/sign-out?token=123"));
        assert!(is_logout_url("https://example.com/api/v1/deconnexion"));
        assert!(is_logout_url("https://example.com/abmelden.php"));
        assert!(!is_logout_url("https://example.com/login"));
        assert!(!is_logout_url("https://example.com/dashboard/users"));
    }

    #[test]
    fn test_is_cycle() {
        // Normal URL
        assert!(!is_cycle("https://example.com/api/v1/users/profile"));

        // Repeating sequence of length 10 repeated 10 times
        let loop_part = "abcdefghij".repeat(10);
        let cycle_url = format!("https://example.com/dir/{}/test", loop_part);
        assert!(is_cycle(&cycle_url));

        // Excessively long URL > 2MB
        let long_url = "https://example.com/".to_string() + &"a".repeat(MAX_URL_LENGTH + 10);
        assert!(is_cycle(&long_url));
    }

    #[test]
    fn test_replace_all_query_param() {
        let url = "https://example.com/search?q=katana&page=5&sort=desc";
        let stripped = replace_all_query_param(url, "");
        assert_eq!(stripped, "https://example.com/search?q=&page=&sort=");
    }

    #[test]
    fn test_extract_parent_paths() {
        let url = "https://example.com/a/b/c/d";
        let parents = extract_parent_paths(url);
        assert_eq!(
            parents,
            vec![
                "https://example.com/a/b/c",
                "https://example.com/a/b",
                "https://example.com/a",
            ]
        );
    }
}
