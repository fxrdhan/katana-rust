/// Returns JavaScript payload to inject into new browser pages to evade bot detection.
pub fn get_stealth_script() -> &'static str {
    r#"
    (() => {
        // 1. Overwrite navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });

        // 2. Mock window.chrome runtime
        if (!window.chrome) {
            window.chrome = {
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {}
            };
        }

        // 3. Mock languages and plugins
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });

        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });

        // 4. Overwrite Permissions query
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
    })();
    "#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_script_payload() {
        let script = get_stealth_script();
        assert!(script.contains("navigator.webdriver"));
        assert!(script.contains("window.chrome"));
        assert!(script.contains("languages"));
    }
}
