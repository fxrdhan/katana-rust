use super::identify::CaptchaProvider;

/// Returns JavaScript payload for injecting a solved CAPTCHA token and triggering callback/form submission.
pub fn get_inject_script(provider: &CaptchaProvider, token: &str) -> String {
    match provider {
        CaptchaProvider::RecaptchaV2
        | CaptchaProvider::RecaptchaV3
        | CaptchaProvider::RecaptchaV2Enterprise
        | CaptchaProvider::RecaptchaV3Enterprise => {
            format!(
                r#"
                (() => {{
                    const token = "{}";
                    document.querySelectorAll('[id="g-recaptcha-response"], [name="g-recaptcha-response"]').forEach(el => {{
                        el.value = token;
                        el.style.display = 'block';
                    }});

                    let called = false;
                    const el = document.querySelector('.g-recaptcha[data-callback]');
                    if (el) {{
                        const name = el.getAttribute('data-callback');
                        if (name && typeof window[name] === 'function') {{
                            window[name](token);
                            called = true;
                        }}
                    }}

                    if (!called && typeof ___grecaptcha_cfg !== 'undefined' && ___grecaptcha_cfg.clients) {{
                        try {{
                            for (const key in ___grecaptcha_cfg.clients) {{
                                const client = ___grecaptcha_cfg.clients[key];
                                if (client && typeof client.callback === 'function') {{
                                    client.callback(token);
                                    called = true;
                                    break;
                                }}
                            }}
                        }} catch (e) {{}}
                    }}

                    const form = document.querySelector('form:has(#g-recaptcha-response)') ||
                                 document.querySelector('form:has(.g-recaptcha)');
                    if (form) form.submit();
                }})();
                "#,
                token
            )
        }
        CaptchaProvider::Turnstile => {
            format!(
                r#"
                (() => {{
                    const token = "{}";
                    document.querySelectorAll('[name="cf-turnstile-response"]').forEach(el => {{
                        el.value = token;
                    }});

                    const el = document.querySelector('.cf-turnstile[data-callback]');
                    if (el) {{
                        const name = el.getAttribute('data-callback');
                        if (name && typeof window[name] === 'function') {{
                            window[name](token);
                        }}
                    }}

                    const form = document.querySelector('form:has([name="cf-turnstile-response"])');
                    if (form) form.submit();
                }})();
                "#,
                token
            )
        }
        CaptchaProvider::HCaptcha => {
            format!(
                r#"
                (() => {{
                    const token = "{}";
                    document.querySelectorAll('[name="h-captcha-response"], [name="g-recaptcha-response"]').forEach(el => {{
                        el.value = token;
                    }});

                    const el = document.querySelector('.h-captcha[data-callback]');
                    if (el) {{
                        const name = el.getAttribute('data-callback');
                        if (name && typeof window[name] === 'function') {{
                            window[name](token);
                        }}
                    }}

                    const form = document.querySelector('form:has([name="h-captcha-response"])');
                    if (form) form.submit();
                }})();
                "#,
                token
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_inject_script() {
        let script_recap = get_inject_script(&CaptchaProvider::RecaptchaV2, "mock_token_123");
        assert!(script_recap.contains("mock_token_123"));
        assert!(script_recap.contains("g-recaptcha-response"));

        let script_turnstile = get_inject_script(&CaptchaProvider::Turnstile, "mock_turnstile_456");
        assert!(script_turnstile.contains("mock_turnstile_456"));
        assert!(script_turnstile.contains("cf-turnstile-response"));

        let script_hcaptcha = get_inject_script(&CaptchaProvider::HCaptcha, "mock_hcap_789");
        assert!(script_hcaptcha.contains("mock_hcap_789"));
        assert!(script_hcaptcha.contains("h-captcha-response"));
    }
}
