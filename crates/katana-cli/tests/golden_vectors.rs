use katana_core::storage::ResponseStorageManager;
use katana_core::technology::detect_technologies;
use katana_engine::proxy::ProxyRotator;
use katana_engine::spa::is_dynamic_spa;
use katana_engine::tls::TlsClientProfile;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[test]
fn test_golden_vectors_web_technology_fingerprinting() {
    // Vector 1: Modern Cloud-hosted Node.js / Express / Cloudflare stack
    let mut headers1 = HashMap::new();
    headers1.insert("server".to_string(), "cloudflare".to_string());
    headers1.insert("x-powered-by".to_string(), "Express".to_string());
    headers1.insert("cf-ray".to_string(), "8e71234abcd-SIN".to_string());
    headers1.insert(
        "set-cookie".to_string(),
        "connect.sid=s%3A123; Path=/; HttpOnly".to_string(),
    );

    let techs1 = detect_technologies(&headers1, "");
    assert!(techs1.contains(&"Cloudflare".to_string()));
    assert!(techs1.contains(&"Express".to_string()));
    assert!(techs1.contains(&"Node.js".to_string()));

    // Vector 2: Full WordPress CMS with PHP, Apache, Elementor, and jQuery
    let mut headers2 = HashMap::new();
    headers2.insert("server".to_string(), "Apache/2.4.52 (Ubuntu)".to_string());
    headers2.insert("x-powered-by".to_string(), "PHP/8.2.14".to_string());
    headers2.insert("x-generator".to_string(), "WordPress 6.4".to_string());

    let wp_body = r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta name="generator" content="WordPress 6.4.3" />
            <link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css" />
            <script src="/wp-includes/js/jquery/jquery.min.js"></script>
        </head>
        <body class="elementor-page">
            <div class="elementor-inner">WordPress Elementor Page</div>
        </body>
        </html>
    "#;

    let techs2 = detect_technologies(&headers2, wp_body);
    assert!(techs2.contains(&"WordPress".to_string()));
    assert!(techs2.contains(&"PHP".to_string()));
    assert!(techs2.contains(&"Apache".to_string()));
    assert!(techs2.contains(&"Elementor".to_string()));
    assert!(techs2.contains(&"jQuery".to_string()));

    // Vector 3: Next.js Client-Hydrated React Application on Vercel/AWS
    let mut headers3 = HashMap::new();
    headers3.insert("x-amz-cf-id".to_string(), "ABCD1234==".to_string());
    headers3.insert("x-powered-by".to_string(), "Next.js".to_string());

    let next_body = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Next.js Dashboard</title></head>
        <body>
            <div id="__next" data-reactroot="">
                <div class="dashboard-root">
                    <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}}}</script>
                </div>
            </div>
            <script src="/_next/static/chunks/main.js"></script>
        </body>
        </html>
    "#;

    let techs3 = detect_technologies(&headers3, next_body);
    assert!(techs3.contains(&"Next.js".to_string()));
    assert!(techs3.contains(&"React".to_string()));
    assert!(techs3.contains(&"Amazon CloudFront".to_string()));
}

#[test]
fn test_golden_vectors_spa_detection_and_escalation() {
    // 1. React create-react-app template
    let react_spa = r#"
        <!DOCTYPE html>
        <html>
        <head><title>React App</title></head>
        <body>
            <noscript>You need to enable JavaScript to run this app.</noscript>
            <div id="root"></div>
            <script src="/static/js/bundle.js"></script>
        </body>
        </html>
    "#;
    assert!(is_dynamic_spa(react_spa, "text/html"));

    // 2. Vue CLI template
    let vue_spa = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Vue SPA</title></head>
        <body>
            <div id="app"></div>
            <script src="/js/chunk-vendors.12345678.js"></script>
            <script src="/js/app.87654321.js"></script>
        </body>
        </html>
    "#;
    assert!(is_dynamic_spa(vue_spa, "text/html"));

    // 3. Angular standard app-root
    let angular_spa = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Angular SPA</title></head>
        <body>
            <app-root></app-root>
            <script src="/runtime.js"></script>
            <script src="/main.js"></script>
        </body>
        </html>
    "#;
    assert!(is_dynamic_spa(angular_spa, "text/html"));

    // 4. Server-rendered heavy static HTML (NOT an SPA)
    let static_page = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Documentation Page</title></head>
        <body>
            <h1>Project Documentation</h1>
            <p>This is a comprehensive documentation page describing Katana architecture and offensive recon crawling pipelines.</p>
            <p>It contains multiple paragraphs explaining deduplication, SimHash, adaptive PathTrie promotion, and rate limiting algorithms.</p>
            <p>Because it contains abundant server-rendered static textual content and no empty SPA root containers, it should never be misclassified as a dynamic SPA.</p>
            <a href="/section1">Section 1</a>
            <a href="/section2">Section 2</a>
        </body>
        </html>
    "#;
    assert!(!is_dynamic_spa(static_page, "text/html"));
}

#[test]
fn test_golden_vectors_response_storage_with_index() {
    let test_dir = std::env::temp_dir().join(format!(
        "katana_golden_vector_storage_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let dir_str = test_dir.to_str().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("server".to_string(), "nginx/1.22.0".to_string());

    let target_url = "https://api.target.internal/v1/health";
    let body = r#"{"status":"pass","uptime":3600}"#;

    let file_path =
        ResponseStorageManager::store_response(dir_str, target_url, 200, &headers, body)
            .expect("store_response failed");

    // Verify stored response file
    assert!(Path::new(&file_path).exists());
    let saved_raw = fs::read_to_string(&file_path).expect("failed to read response file");
    assert!(saved_raw.starts_with("HTTP/1.1 200\r\n"));
    assert!(saved_raw.contains("content-type: application/json\r\n"));
    assert!(saved_raw.contains("server: nginx/1.22.0\r\n"));
    assert!(saved_raw.ends_with(body));

    // Verify index.txt catalogue format
    let index_file = test_dir.join("index.txt");
    assert!(index_file.exists());
    let index_text = fs::read_to_string(&index_file).expect("failed to read index.txt");
    let lines: Vec<&str> = index_text.lines().collect();
    assert_eq!(lines.len(), 1);

    // Expected format: <hash> <status> <url> <filename>
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[1], "200");
    assert_eq!(parts[2], target_url);
    assert!(parts[3].ends_with(".txt"));

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_golden_vectors_proxy_rotator_and_tls_profile() {
    let proxy_csv = "http://10.0.0.1:8080, socks5://10.0.0.2:1080, http://10.0.0.3:3128";
    let rotator = ProxyRotator::from_comma_separated(proxy_csv);

    assert_eq!(rotator.total_proxies(), 3);
    assert_eq!(
        rotator.next_proxy(),
        Some("http://10.0.0.1:8080".to_string())
    );
    assert_eq!(
        rotator.next_proxy(),
        Some("socks5://10.0.0.2:1080".to_string())
    );
    assert_eq!(
        rotator.next_proxy(),
        Some("http://10.0.0.3:3128".to_string())
    );
    // Wraps around round-robin
    assert_eq!(
        rotator.next_proxy(),
        Some("http://10.0.0.1:8080".to_string())
    );

    // TLS Profiles
    assert_eq!(
        "chrome".parse::<TlsClientProfile>().unwrap(),
        TlsClientProfile::Chrome
    );
    assert_eq!(
        "firefox".parse::<TlsClientProfile>().unwrap(),
        TlsClientProfile::Firefox
    );
    assert_eq!(
        "safari".parse::<TlsClientProfile>().unwrap(),
        TlsClientProfile::Safari
    );
    assert_eq!(
        "random".parse::<TlsClientProfile>().unwrap(),
        TlsClientProfile::Random
    );
}
