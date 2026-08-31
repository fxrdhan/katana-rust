use std::path::PathBuf;

/// Options for launching a Chrome/Chromium browser process or connecting to CDP.
#[derive(Debug, Clone)]
pub struct ChromeLaunchOptions {
    pub show_browser: bool,
    pub no_sandbox: bool,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
    pub user_data_dir: Option<PathBuf>,
    pub chrome_ws_url: Option<String>,
    pub window_width: u32,
    pub window_height: u32,
}

impl Default for ChromeLaunchOptions {
    fn default() -> Self {
        Self {
            show_browser: false,
            no_sandbox: true,
            proxy: None,
            user_agent: None,
            user_data_dir: None,
            chrome_ws_url: None,
            window_width: 1920,
            window_height: 1080,
        }
    }
}

/// Locates the system Chrome or Chromium executable across different operating systems.
pub fn find_system_chrome() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(env_path) = std::env::var("CHROME_PATH") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mac_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ];
        for p in &mac_paths {
            let path = PathBuf::from(p);
            if path.exists() {
                return Some(path);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let win_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        for p in &win_paths {
            let path = PathBuf::from(p);
            if path.exists() {
                return Some(path);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let linux_binaries = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
        ];
        for bin in &linux_binaries {
            if let Ok(p) = which::which(bin) {
                return Some(p);
            }
        }
    }

    None
}

/// Builds the complete list of CLI arguments for spawning Chrome.
pub fn build_chrome_args(opts: &ChromeLaunchOptions) -> Vec<String> {
    let mut args = vec![
        "--disable-gpu".to_string(),
        "--disable-dev-shm-usage".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-extensions".to_string(),
        "--disable-sync".to_string(),
        "--disable-translate".to_string(),
        "--metrics-recording-only".to_string(),
        "--no-first-run".to_string(),
        "--safebrowsing-disable-auto-update".to_string(),
        "--ignore-certificate-errors".to_string(),
        "--ignore-ssl-errors".to_string(),
        format!("--window-size={},{}", opts.window_width, opts.window_height),
    ];

    if !opts.show_browser {
        args.push("--headless=new".to_string());
    }

    if opts.no_sandbox {
        args.push("--no-sandbox".to_string());
        args.push("--disable-setuid-sandbox".to_string());
    }

    if let Some(proxy) = &opts.proxy {
        args.push(format!("--proxy-server={}", proxy));
    }

    if let Some(ua) = &opts.user_agent {
        args.push(format!("--user-agent={}", ua));
    }

    if let Some(data_dir) = &opts.user_data_dir {
        args.push(format!("--user-data-dir={}", data_dir.display()));
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_chrome_args() {
        let opts = ChromeLaunchOptions {
            show_browser: false,
            no_sandbox: true,
            proxy: Some("http://127.0.0.1:8080".to_string()),
            user_agent: Some("Custom-Agent/1.0".to_string()),
            user_data_dir: Some(PathBuf::from("/tmp/katana_chrome")),
            ..Default::default()
        };

        let args = build_chrome_args(&opts);

        assert!(args.contains(&"--headless=new".to_string()));
        assert!(args.contains(&"--no-sandbox".to_string()));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:8080".to_string()));
        assert!(args.contains(&"--user-agent=Custom-Agent/1.0".to_string()));
        assert!(args.contains(&"--user-data-dir=/tmp/katana_chrome".to_string()));
    }
}
