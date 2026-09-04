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

/// Serializes a Request into RFC 7230 wire format.
pub fn serialize_raw_request(req: &Request, extra_headers: &HashMap<String, String>) -> String {
    let method = if req.method.is_empty() {
        "GET"
    } else {
        req.method.as_str()
    };
    let (host_str, path_and_query) = if let Ok(u) = url::Url::parse(&req.url) {
        let h = if let Some(port) = u.port() {
            format!("{}:{}", u.host_str().unwrap_or(""), port)
        } else {
            u.host_str().unwrap_or("").to_string()
        };
        let pq = match u.query() {
            Some(q) => format!("{}?{}", u.path(), q),
            None => u.path().to_string(),
        };
        (h, if pq.is_empty() { "/".to_string() } else { pq })
    } else {
        ("".to_string(), "/".to_string())
    };

    let mut out = format!("{} {} HTTP/1.1\r\n", method, path_and_query);
    if !host_str.is_empty() {
        out.push_str(&format!("Host: {}\r\n", host_str));
    }
    for (k, v) in extra_headers {
        if !k.eq_ignore_ascii_case("host") {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    for (k, v) in &req.headers {
        if !k.eq_ignore_ascii_case("host") && !extra_headers.contains_key(k) {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    out.push_str("\r\n");
    if !req.body.is_empty() {
        out.push_str(&req.body);
    }
    out
}

/// Serializes an HTTP response status, headers, and body into RFC 7230 wire format.
pub fn serialize_raw_response(
    status: u16,
    headers: &HashMap<String, String>,
    body: &str,
) -> String {
    let mut out = format!("HTTP/1.1 {}\r\n", status);
    for (k, v) in headers {
        out.push_str(&format!("{}: {}\r\n", k, v));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
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

    #[test]
    fn test_serialize_raw_request_and_response() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let req = Request {
            method: "POST".to_string(),
            url: "https://example.com/api/test?v=1".to_string(),
            body: "{\"ping\":true}".to_string(),
            headers,
            ..Default::default()
        };

        let mut custom = HashMap::new();
        custom.insert("X-Custom-Auth".to_string(), "token".to_string());

        let raw_req = serialize_raw_request(&req, &custom);
        assert!(raw_req.starts_with("POST /api/test?v=1 HTTP/1.1\r\n"));
        assert!(raw_req.contains("Host: example.com\r\n"));
        assert!(raw_req.contains("X-Custom-Auth: token\r\n"));
        assert!(raw_req.contains("Content-Type: application/json\r\n"));
        assert!(raw_req.ends_with("\r\n{\"ping\":true}"));

        let mut resp_headers = HashMap::new();
        resp_headers.insert("Server".to_string(), "nginx".to_string());
        let raw_resp = serialize_raw_response(200, &resp_headers, "{\"pong\":true}");
        assert!(raw_resp.starts_with("HTTP/1.1 200\r\n"));
        assert!(raw_resp.contains("Server: nginx\r\n"));
        assert!(raw_resp.ends_with("\r\n{\"pong\":true}"));
    }
}
