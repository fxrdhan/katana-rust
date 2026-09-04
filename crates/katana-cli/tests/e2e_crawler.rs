use katana_core::options::Options;
use katana_engine::{Engine, StandardEngine};
use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn start_mock_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{}", port);

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let path = req_str
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let (status, content_type, body): (&str, &str, String) = match path {
                        "/" => (
                            "200 OK",
                            "text/html",
                            r#"
                            <!DOCTYPE html>
                            <html>
                            <body>
                                <a href="/about">About Us</a>
                                <a href="/contact">Contact</a>
                                <a href="/api/v1/users">API Users</a>
                                <script>fetch('/api/v2/stats');</script>
                            </body>
                            </html>
                            "#
                            .to_string(),
                        ),
                        "/about" => {
                            let dummy_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
                            let about_html = format!(
                                r#"
                                <!DOCTYPE html>
                                <html>
                                <body>
                                    <a href="/team">Our Team</a>
                                    <p>Config: key = "{}"</p>
                                </body>
                                </html>
                                "#,
                                dummy_key
                            );
                            ("200 OK", "text/html", about_html)
                        }
                        "/contact" => ("200 OK", "text/html", "<h1>Contact Page</h1>".to_string()),
                        "/team" => ("200 OK", "text/html", "<h1>Team Page</h1>".to_string()),
                        "/api/v1/users" => {
                            ("200 OK", "application/json", r#"{"users": []}"#.to_string())
                        }
                        "/api/v2/stats" => (
                            "200 OK",
                            "application/json",
                            r#"{"status": "healthy"}"#.to_string(),
                        ),
                        "/robots.txt" => (
                            "200 OK",
                            "text/plain",
                            "User-agent: *\nDisallow: /admin".to_string(),
                        ),
                        "/sitemap.xml" => (
                            "200 OK",
                            "application/xml",
                            r#"<?xml version="1.0" encoding="UTF-8"?>
                            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                                <url><loc>/sitemap-target</loc></url>
                            </urlset>"#
                                .to_string(),
                        ),
                        "/admin" => ("200 OK", "text/html", "<h1>Admin Panel</h1>".to_string()),
                        "/sitemap-target" => {
                            ("200 OK", "text/html", "<h1>Sitemap Page</h1>".to_string())
                        }
                        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
                    };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        content_type,
                        body.len(),
                        body
                    );

                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (base_url, handle)
}

#[tokio::test]
async fn test_e2e_standard_crawler() {
    let (base_url, server_handle) = start_mock_server().await;

    let options = Options {
        urls: vec![base_url.clone()],
        max_depth: 3,
        concurrency: 5,
        timeout: 5,
        scrape_js: true,
        scrape_jsluice: true,
        scan_secrets: true,
        ..Default::default()
    };

    let engine = StandardEngine::new(options).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let root_url = base_url.clone();
    let crawl_handle = tokio::spawn(async move {
        engine.crawl(&root_url, tx).await.unwrap();
    });

    let mut visited_urls = HashSet::new();
    let mut detected_api_types = Vec::new();
    let mut detected_secrets = Vec::new();

    while let Some(res) = rx.recv().await {
        if let Some(req) = res.request {
            visited_urls.insert(req.url);
        }
        if let Some(api) = res.api_type {
            detected_api_types.push(api);
        }
        if !res.secrets.is_empty() {
            detected_secrets.extend(res.secrets);
        }
    }

    crawl_handle.await.unwrap();
    server_handle.abort();

    // Verify discovered endpoints
    assert!(visited_urls.iter().any(|u| u.ends_with("/about")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/contact")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/api/v1/users")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/api/v2/stats")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/admin")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/sitemap-target")));
    assert!(visited_urls.iter().any(|u| u.ends_with("/team")));

    // Verify API classification
    assert!(detected_api_types.contains(&"REST".to_string()));

    // Verify secret scanning
    assert!(detected_secrets
        .iter()
        .any(|s| s.rule_name == "AWS Access Key"));
}

#[tokio::test]
async fn test_e2e_custom_fields_and_storage() {
    let (base_url, server_handle) = start_mock_server().await;
    let temp_dir = std::env::temp_dir().join(format!("katana_test_{}", std::process::id()));

    let options = Options {
        urls: vec![base_url.clone()],
        max_depth: 1,
        concurrency: 2,
        timeout: 5,
        store_response: true,
        store_response_dir: Some(temp_dir.to_str().unwrap().to_string()),
        ..Default::default()
    };

    let engine = StandardEngine::new(options).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let root_url = base_url.clone();
    let crawl_handle = tokio::spawn(async move {
        engine.crawl(&root_url, tx).await.unwrap();
    });

    let mut stored_paths = Vec::new();

    while let Some(res) = rx.recv().await {
        if let Some(resp) = res.response {
            if !resp.stored_response_path.is_empty() {
                stored_paths.push(resp.stored_response_path);
            }
        }
    }

    crawl_handle.await.unwrap();
    server_handle.abort();

    // Verify response files were created on disk
    assert!(!stored_paths.is_empty());
    for p in &stored_paths {
        assert!(std::path::Path::new(p).exists());
    }

    // Clean up test directory
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_e2e_headless_form_fill() {
    let (base_url, server_handle) = start_mock_server().await;

    let options = Options {
        urls: vec![base_url.clone()],
        max_depth: 2,
        concurrency: 2,
        timeout: 5,
        headless: true,
        form_extraction: true,
        automatic_form_fill: true,
        ..Default::default()
    };

    let engine = katana_engine::HeadlessEngine::new(options).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let root_url = base_url.clone();
    let crawl_handle = tokio::spawn(async move {
        engine.crawl(&root_url, tx).await.unwrap();
    });

    let mut discovered_form_actions = Vec::new();

    while let Some(res) = rx.recv().await {
        if let Some(req) = res.request {
            if req.tag == "form-action" {
                discovered_form_actions.push(req);
            }
        }
    }

    crawl_handle.await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_e2e_raw_request_and_checkpoint() {
    let (base_url, server_handle) = start_mock_server().await;
    let url_parsed = url::Url::parse(&base_url).unwrap();
    let host = url_parsed.host_str().unwrap();
    let port = url_parsed.port().unwrap();

    let raw_http = format!(
        "GET /about HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Katana-Test\r\n\r\n",
        host, port
    );

    let parsed_req = katana_core::raw::parse_raw_request_str(&raw_http, false).unwrap();
    assert_eq!(parsed_req.method, "GET");
    assert!(parsed_req.url.contains("/about"));

    let temp_cp_file = std::env::temp_dir().join(format!("test_cp_{}.json", std::process::id()));
    let cp = katana_core::CrawlCheckpoint::new(
        vec![parsed_req.url.clone()],
        vec![format!("{}/contact", base_url)],
    );
    cp.save(temp_cp_file.to_str().unwrap()).unwrap();

    let loaded_cp = katana_core::CrawlCheckpoint::load(temp_cp_file.to_str().unwrap()).unwrap();
    assert_eq!(loaded_cp.visited_urls.len(), 1);
    assert_eq!(loaded_cp.in_flight_urls.len(), 1);

    let _ = std::fs::remove_file(temp_cp_file);
    server_handle.abort();
}

#[tokio::test]
async fn test_e2e_concurrency_and_headers_dispatcher() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{}", port);

    let server_handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let path = req_str
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let has_header = req_str.contains("x-custom-test: katana-pool");

                    let (status, body) = match path {
                        "/" => (
                            "200 OK",
                            r#"<html><body>
                                <a href="/item1">Item 1</a>
                                <a href="/item2">Item 2</a>
                                <a href="/item3">Item 3</a>
                                <a href="/item4">Item 4</a>
                            </body></html>"#,
                        ),
                        "/item1" | "/item2" | "/item3" | "/item4" => {
                            if has_header {
                                ("200 OK", "<html><body>Header Verified</body></html>")
                            } else {
                                ("400 Bad Request", "Missing header")
                            }
                        }
                        _ => ("404 Not Found", "Not Found"),
                    };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let mut custom_headers = std::collections::HashMap::new();
    custom_headers.insert("x-custom-test".to_string(), "katana-pool".to_string());

    let options = Options {
        urls: vec![base_url.clone()],
        max_depth: 2,
        concurrency: 4,
        parallelism: 2,
        timeout: 5,
        custom_headers,
        ..Default::default()
    };

    let engine = StandardEngine::new(options).unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let root = base_url.clone();
    let crawl_handle = tokio::spawn(async move {
        engine.crawl(&root, tx).await.unwrap();
    });

    let mut successful_urls = HashSet::new();
    while let Some(res) = rx.recv().await {
        if let Some(resp) = res.response {
            if resp.status_code == 200 {
                if let Some(req) = res.request {
                    successful_urls.insert(req.url);
                }
            }
        }
    }

    crawl_handle.await.unwrap();
    server_handle.abort();

    assert!(successful_urls.contains(&base_url));
    assert!(successful_urls.contains(&format!("{}/item1", base_url)));
    assert!(successful_urls.contains(&format!("{}/item2", base_url)));
    assert!(successful_urls.contains(&format!("{}/item3", base_url)));
    assert!(successful_urls.contains(&format!("{}/item4", base_url)));
}
