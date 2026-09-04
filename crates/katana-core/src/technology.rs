use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};

lazy_static! {
    static ref META_GENERATOR_REGEX: Regex =
        Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).unwrap();
    static ref SCRIPT_SRC_REGEX: Regex =
        Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
    static ref LINK_HREF_REGEX: Regex =
        Regex::new(r#"(?i)<link[^>]+href=["']([^"']+)["']"#).unwrap();
}

/// Detects web technologies and frameworks (Wappalyzer parity) from response headers and body content.
pub fn detect_technologies(headers: &HashMap<String, String>, body: &str) -> Vec<String> {
    let mut detected = BTreeSet::new();

    // 1. Analyze Headers
    for (name, val) in headers {
        let name_lower = name.to_lowercase();
        let val_lower = val.to_lowercase();

        match name_lower.as_str() {
            "server" => {
                if val_lower.contains("nginx") {
                    detected.insert("Nginx".to_string());
                }
                if val_lower.contains("apache") {
                    detected.insert("Apache".to_string());
                }
                if val_lower.contains("cloudflare") {
                    detected.insert("Cloudflare".to_string());
                }
                if val_lower.contains("caddy") {
                    detected.insert("Caddy".to_string());
                }
                if val_lower.contains("litespeed") {
                    detected.insert("LiteSpeed".to_string());
                }
                if val_lower.contains("microsoft-iis") {
                    detected.insert("Microsoft-IIS".to_string());
                }
                if val_lower.contains("openresty") {
                    detected.insert("OpenResty".to_string());
                }
                if val_lower.contains("gunicorn") {
                    detected.insert("Gunicorn".to_string());
                }
                if val_lower.contains("uvicorn") {
                    detected.insert("Uvicorn".to_string());
                }
                if val_lower.contains("envoy") {
                    detected.insert("Envoy".to_string());
                }
            }
            "x-powered-by" => {
                if val_lower.contains("php") {
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("express") {
                    detected.insert("Express".to_string());
                    detected.insert("Node.js".to_string());
                }
                if val_lower.contains("asp.net") {
                    detected.insert("ASP.NET".to_string());
                }
                if val_lower.contains("next.js") {
                    detected.insert("Next.js".to_string());
                    detected.insert("React".to_string());
                }
                if val_lower.contains("nuxt") {
                    detected.insert("Nuxt.js".to_string());
                    detected.insert("Vue.js".to_string());
                }
                if val_lower.contains("django") {
                    detected.insert("Django".to_string());
                    detected.insert("Python".to_string());
                }
                if val_lower.contains("rails") {
                    detected.insert("Ruby on Rails".to_string());
                    detected.insert("Ruby".to_string());
                }
                if val_lower.contains("spring") {
                    detected.insert("Spring Boot".to_string());
                    detected.insert("Java".to_string());
                }
            }
            "x-generator" => {
                if val_lower.contains("wordpress") {
                    detected.insert("WordPress".to_string());
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("drupal") {
                    detected.insert("Drupal".to_string());
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("joomla") {
                    detected.insert("Joomla".to_string());
                    detected.insert("PHP".to_string());
                }
            }
            "set-cookie" => {
                if val_lower.contains("phpsessid") {
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("jsessionid") {
                    detected.insert("Java".to_string());
                }
                if val_lower.contains("laravel_session") || val_lower.contains("xsrf-token") {
                    detected.insert("Laravel".to_string());
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("csrftoken") {
                    detected.insert("Django".to_string());
                    detected.insert("Python".to_string());
                }
                if val_lower.contains("connect.sid") {
                    detected.insert("Express".to_string());
                    detected.insert("Node.js".to_string());
                }
                if val_lower.contains("wp-settings-") || val_lower.contains("wordpress_") {
                    detected.insert("WordPress".to_string());
                    detected.insert("PHP".to_string());
                }
                if val_lower.contains("__cf_bm") || val_lower.contains("cf_clearance") {
                    detected.insert("Cloudflare".to_string());
                }
            }
            "cf-ray" | "cf-cache-status" => {
                detected.insert("Cloudflare".to_string());
            }
            "x-amz-cf-id" => {
                detected.insert("Amazon CloudFront".to_string());
                detected.insert("AWS".to_string());
            }
            "x-drupal-cache" | "x-drupal-dynamic-cache" => {
                detected.insert("Drupal".to_string());
                detected.insert("PHP".to_string());
            }
            "x-shopify-stage" => {
                detected.insert("Shopify".to_string());
            }
            _ => {}
        }
    }

    if body.is_empty() {
        return detected.into_iter().collect();
    }

    let body_lower = body.to_lowercase();

    // 2. Analyze Meta Generator tags
    for cap in META_GENERATOR_REGEX.captures_iter(body) {
        if let Some(content) = cap.get(1) {
            let gen = content.as_str().to_lowercase();
            if gen.contains("wordpress") {
                detected.insert("WordPress".to_string());
                detected.insert("PHP".to_string());
            } else if gen.contains("joomla") {
                detected.insert("Joomla".to_string());
                detected.insert("PHP".to_string());
            } else if gen.contains("drupal") {
                detected.insert("Drupal".to_string());
                detected.insert("PHP".to_string());
            } else if gen.contains("gatsby") {
                detected.insert("Gatsby".to_string());
                detected.insert("React".to_string());
            } else if gen.contains("hugo") {
                detected.insert("Hugo".to_string());
            } else if gen.contains("shopify") {
                detected.insert("Shopify".to_string());
            }
        }
    }

    // 3. Analyze Script and Link tags
    for cap in SCRIPT_SRC_REGEX.captures_iter(body) {
        if let Some(src) = cap.get(1) {
            let s = src.as_str().to_lowercase();
            if s.contains("jquery") {
                detected.insert("jQuery".to_string());
            }
            if s.contains("react") || s.contains("react-dom") {
                detected.insert("React".to_string());
            }
            if s.contains("vue") {
                detected.insert("Vue.js".to_string());
            }
            if s.contains("angular") {
                detected.insert("Angular".to_string());
            }
            if s.contains("bootstrap") {
                detected.insert("Bootstrap".to_string());
            }
            if s.contains("google-analytics.com") || s.contains("googletagmanager.com") {
                detected.insert("Google Analytics".to_string());
            }
            if s.contains("cdn.shopify.com") {
                detected.insert("Shopify".to_string());
            }
            if s.contains("wp-content") || s.contains("wp-includes") {
                detected.insert("WordPress".to_string());
                detected.insert("PHP".to_string());
            }
        }
    }

    for cap in LINK_HREF_REGEX.captures_iter(body) {
        if let Some(href) = cap.get(1) {
            let h = href.as_str().to_lowercase();
            if h.contains("bootstrap") {
                detected.insert("Bootstrap".to_string());
            }
            if h.contains("tailwind") {
                detected.insert("Tailwind CSS".to_string());
            }
            if h.contains("font-awesome") || h.contains("fontawesome") {
                detected.insert("Font Awesome".to_string());
            }
            if h.contains("wp-content") || h.contains("wp-includes") {
                detected.insert("WordPress".to_string());
            }
        }
    }

    // 4. Analyze In-body DOM patterns
    if body_lower.contains("__next_data__") {
        detected.insert("Next.js".to_string());
        detected.insert("React".to_string());
    }
    if body_lower.contains("__nuxt__") {
        detected.insert("Nuxt.js".to_string());
        detected.insert("Vue.js".to_string());
    }
    if body_lower.contains("data-reactroot") {
        detected.insert("React".to_string());
    }
    if body_lower.contains("ng-version") || body_lower.contains("ng-app") {
        detected.insert("Angular".to_string());
    }
    if body_lower.contains("elementor") {
        detected.insert("Elementor".to_string());
        detected.insert("WordPress".to_string());
    }
    if body_lower.contains("woocommerce") {
        detected.insert("WooCommerce".to_string());
        detected.insert("WordPress".to_string());
    }

    detected.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_technologies_from_headers() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.24.0 (Ubuntu)".to_string());
        headers.insert("x-powered-by".to_string(), "Express".to_string());
        headers.insert("cf-ray".to_string(), "8bd7321098a123-SIN".to_string());

        let techs = detect_technologies(&headers, "");
        assert!(techs.contains(&"Nginx".to_string()));
        assert!(techs.contains(&"Express".to_string()));
        assert!(techs.contains(&"Node.js".to_string()));
        assert!(techs.contains(&"Cloudflare".to_string()));
    }

    #[test]
    fn test_detect_wordpress_and_jquery_from_html() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.52".to_string());
        headers.insert(
            "set-cookie".to_string(),
            "wp-settings-1=library; path=/".to_string(),
        );

        let html = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta name="generator" content="WordPress 6.4.2" />
                <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
                <script src="/wp-includes/js/jquery/jquery.min.js"></script>
            </head>
            <body>
                <div class="elementor elementor-10">Hello WordPress</div>
            </body>
            </html>
        "#;

        let techs = detect_technologies(&headers, html);
        assert!(techs.contains(&"Apache".to_string()));
        assert!(techs.contains(&"WordPress".to_string()));
        assert!(techs.contains(&"PHP".to_string()));
        assert!(techs.contains(&"jQuery".to_string()));
        assert!(techs.contains(&"Elementor".to_string()));
    }

    #[test]
    fn test_detect_nextjs_and_react() {
        let headers = HashMap::new();
        let html = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Next.js App</title></head>
            <body>
                <div id="__next" data-reactroot=""><script id="__NEXT_DATA__" type="application/json">{}</script></div>
            </body>
            </html>
        "#;

        let techs = detect_technologies(&headers, html);
        assert!(techs.contains(&"Next.js".to_string()));
        assert!(techs.contains(&"React".to_string()));
    }
}
