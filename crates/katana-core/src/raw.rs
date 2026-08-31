use crate::navigation::Request;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

/// Parses a raw HTTP request string conforming to RFC 7230 / RFC 9112 into a `Request`.
pub fn parse_raw_request_str(raw: &str, https: bool) -> anyhow::Result<Request> {
    let raw_normalized = raw.replace("\r\n", "\n");
    let mut parts = raw_normalized.splitn(2, "\n\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();

    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty raw request"))?;

    let req_parts: Vec<&str> = request_line.split_whitespace().collect();
    if req_parts.len() < 2 {
        anyhow::bail!("Invalid HTTP request line: {}", request_line);
    }

    let method = req_parts[0].to_uppercase();
    let path = req_parts[1];

    let mut headers = HashMap::new();
    let mut host = String::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("host") {
                host = val.clone();
            }
            headers.insert(key, val);
        }
    }

    if host.is_empty() {
        anyhow::bail!("Missing 'Host' header in raw HTTP request");
    }

    let scheme = if https { "https" } else { "http" };
    let full_url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("{}://{}{}", scheme, host, path)
    };

    Ok(Request {
        method,
        url: full_url,
        body,
        headers,
        depth: 0,
        tag: "raw-request".to_string(),
        root_hostname: host,
        ..Default::default()
    })
}

/// Reads a raw HTTP request file and parses it into a `Request`.
pub fn parse_raw_request_file(path: &str, https: bool) -> anyhow::Result<Request> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    parse_raw_request_str(&content, https)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_raw_request_str_get() {
        let raw = "GET /index.html?lang=en HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Katana/1.0\r\n\r\n";
        let req = parse_raw_request_str(raw, true).unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://example.com/index.html?lang=en");
        assert_eq!(req.root_hostname, "example.com");
        assert_eq!(req.headers.get("User-Agent").unwrap(), "Katana/1.0");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_raw_request_str_post_with_body() {
        let raw = "POST /api/v1/auth HTTP/1.1\nHost: api.target.local:8080\nContent-Type: application/json\n\n{\"username\":\"admin\",\"password\":\"secret\"}";
        let req = parse_raw_request_str(raw, false).unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "http://api.target.local:8080/api/v1/auth");
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/json");
        assert_eq!(req.body, "{\"username\":\"admin\",\"password\":\"secret\"}");
    }
}
