use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptchaProvider {
    RecaptchaV2,
    RecaptchaV3,
    RecaptchaV2Enterprise,
    RecaptchaV3Enterprise,
    Turnstile,
    HCaptcha,
}

impl std::fmt::Display for CaptchaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecaptchaV2 => write!(f, "recaptchav2"),
            Self::RecaptchaV3 => write!(f, "recaptchav3"),
            Self::RecaptchaV2Enterprise => write!(f, "recaptchav2enterprise"),
            Self::RecaptchaV3Enterprise => write!(f, "recaptchav3enterprise"),
            Self::Turnstile => write!(f, "turnstile"),
            Self::HCaptcha => write!(f, "hcaptcha"),
        }
    }
}

/// Metadata describing a detected CAPTCHA challenge on a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptchaInfo {
    pub provider: CaptchaProvider,
    pub sitekey: String,
    pub page_url: String,
    pub action: String,
}

lazy_static::lazy_static! {
    static ref RE_HCAPTCHA_SITEKEY: Regex = Regex::new(
        r#"(?i)<[^>]*class=["'][^"']*h-captcha[^"']*["'][^>]*data-sitekey=["']([^"']+)["']"#
    ).unwrap();
    static ref RE_TURNSTILE_SITEKEY: Regex = Regex::new(
        r#"(?i)<[^>]*class=["'][^"']*cf-turnstile[^"']*["'][^>]*data-sitekey=["']([^"']+)["']"#
    ).unwrap();
    static ref RE_RECAPTCHA_SITEKEY: Regex = Regex::new(
        r#"(?i)<[^>]*class=["'][^"']*g-recaptcha[^"']*["'][^>]*data-sitekey=["']([^"']+)["']"#
    ).unwrap();
    static ref RE_RECAPTCHA_V3_SCRIPT: Regex = Regex::new(
        r#"(?i)https://www\.google\.com/recaptcha/(api|enterprise)\.js\?render=([a-zA-Z0-9_-]+)"#
    ).unwrap();
    static ref RE_GENERIC_DATA_SITEKEY: Regex = Regex::new(
        r#"(?i)data-sitekey=["']([a-zA-Z0-9_-]{20,})["']"#
    ).unwrap();
}

/// Detects and identifies CAPTCHA provider and sitekey from static HTML markup.
pub fn detect_captcha_in_html(html: &str, page_url: &str) -> Option<CaptchaInfo> {
    // 1. hCaptcha check
    if let Some(caps) = RE_HCAPTCHA_SITEKEY.captures(html) {
        if let Some(sitekey) = caps.get(1) {
            return Some(CaptchaInfo {
                provider: CaptchaProvider::HCaptcha,
                sitekey: sitekey.as_str().to_string(),
                page_url: page_url.to_string(),
                action: String::new(),
            });
        }
    }

    // 2. Cloudflare Turnstile check
    if let Some(caps) = RE_TURNSTILE_SITEKEY.captures(html) {
        if let Some(sitekey) = caps.get(1) {
            return Some(CaptchaInfo {
                provider: CaptchaProvider::Turnstile,
                sitekey: sitekey.as_str().to_string(),
                page_url: page_url.to_string(),
                action: String::new(),
            });
        }
    }

    // 3. reCAPTCHA v3 script render param check
    if let Some(caps) = RE_RECAPTCHA_V3_SCRIPT.captures(html) {
        let is_enterprise = caps.get(1).is_some_and(|m| m.as_str() == "enterprise");
        if let Some(sitekey) = caps.get(2) {
            let key_str = sitekey.as_str();
            if key_str != "explicit" {
                return Some(CaptchaInfo {
                    provider: if is_enterprise {
                        CaptchaProvider::RecaptchaV3Enterprise
                    } else {
                        CaptchaProvider::RecaptchaV3
                    },
                    sitekey: key_str.to_string(),
                    page_url: page_url.to_string(),
                    action: String::new(),
                });
            }
        }
    }

    // 4. reCAPTCHA v2 / Enterprise badge check
    let is_enterprise = html.contains("recaptcha/enterprise.js");
    if let Some(caps) = RE_RECAPTCHA_SITEKEY.captures(html) {
        if let Some(sitekey) = caps.get(1) {
            return Some(CaptchaInfo {
                provider: if is_enterprise {
                    CaptchaProvider::RecaptchaV2Enterprise
                } else {
                    CaptchaProvider::RecaptchaV2
                },
                sitekey: sitekey.as_str().to_string(),
                page_url: page_url.to_string(),
                action: String::new(),
            });
        }
    }

    // 5. Generic data-sitekey fallback
    if let Some(caps) = RE_GENERIC_DATA_SITEKEY.captures(html) {
        if let Some(sitekey) = caps.get(1) {
            return Some(CaptchaInfo {
                provider: if is_enterprise {
                    CaptchaProvider::RecaptchaV2Enterprise
                } else {
                    CaptchaProvider::RecaptchaV2
                },
                sitekey: sitekey.as_str().to_string(),
                page_url: page_url.to_string(),
                action: String::new(),
            });
        }
    }

    None
}

/// Returns client JavaScript snippet for identifying CAPTCHAs in live DOM.
pub fn get_identify_js() -> &'static str {
    r#"
    (() => {
        const hcap = document.querySelector('.h-captcha[data-sitekey]');
        if (hcap) return { provider: "hcaptcha", sitekey: hcap.getAttribute("data-sitekey"), action: "" };

        const cf = document.querySelector('.cf-turnstile[data-sitekey]');
        if (cf) return { provider: "turnstile", sitekey: cf.getAttribute("data-sitekey"), action: "" };

        const recap = document.querySelector('.g-recaptcha[data-sitekey]');
        if (recap) return { provider: "recaptchav2", sitekey: recap.getAttribute("data-sitekey"), action: "" };

        const generic = document.querySelector('[data-sitekey]');
        if (generic) return { provider: "recaptchav2", sitekey: generic.getAttribute("data-sitekey"), action: "" };

        return null;
    })()
    "#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_captcha_in_html() {
        let html_hcaptcha = r#"<html><body><div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div></body></html>"#;
        let info = detect_captcha_in_html(html_hcaptcha, "https://example.com").unwrap();
        assert_eq!(info.provider, CaptchaProvider::HCaptcha);
        assert_eq!(info.sitekey, "10000000-ffff-ffff-ffff-000000000001");

        let html_turnstile = r#"<html><body><div class="cf-turnstile" data-sitekey="0x4AAAAAAABcdef123456789"></div></body></html>"#;
        let info = detect_captcha_in_html(html_turnstile, "https://example.com").unwrap();
        assert_eq!(info.provider, CaptchaProvider::Turnstile);
        assert_eq!(info.sitekey, "0x4AAAAAAABcdef123456789");

        let html_recaptcha_v3 = r#"<html><head><script src="https://www.google.com/recaptcha/api.js?render=6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"></script></head><body></body></html>"#;
        let info = detect_captcha_in_html(html_recaptcha_v3, "https://example.com").unwrap();
        assert_eq!(info.provider, CaptchaProvider::RecaptchaV3);
        assert_eq!(info.sitekey, "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-");
    }
}
