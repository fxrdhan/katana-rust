use std::collections::HashSet;
use url::Url;

/// Default list of static binary, media, and archive extensions to be filtered from crawling.
pub const DEFAULT_EXT_FILTER: &[&str] = &[
    ".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".csv", ".deb", ".dll",
    ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264", ".ico", ".iso",
    ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4",
    ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt",
    ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tar.gz", ".tar", ".tif", ".tiff",
    ".ttf", ".txt", ".vob", ".wav", ".webm", ".webp", ".wmv", ".woff", ".woff2", ".xcf",
    ".xls", ".xlsx", ".zip",
];

/// Normalizes an extension string to lower-case with a leading dot.
pub fn normalize_extension(ext: &str) -> String {
    let trimmed = ext.trim().to_lowercase();
    if trimmed.is_empty() {
        return String::new();
    }
    if !trimmed.starts_with('.') {
        format!(".{}", trimmed)
    } else {
        trimmed
    }
}

/// Validator for filtering or allowing URLs based on file extensions.
#[derive(Debug, Clone)]
pub struct ExtensionValidator {
    extensions_match: HashSet<String>,
    extensions_filter: HashSet<String>,
}

impl Default for ExtensionValidator {
    fn default() -> Self {
        Self::new(&[], &[], false)
    }
}

impl ExtensionValidator {
    pub fn new(
        extensions_match: &[String],
        extensions_filter: &[String],
        no_default_ext_filter: bool,
    ) -> Self {
        let mut match_set = HashSet::new();
        let mut filter_set = HashSet::new();

        for ext in extensions_match {
            match_set.insert(normalize_extension(ext));
        }

        if !no_default_ext_filter {
            for ext in DEFAULT_EXT_FILTER {
                filter_set.insert(normalize_extension(ext));
            }
        }

        for ext in extensions_filter {
            filter_set.insert(normalize_extension(ext));
        }

        Self {
            extensions_match: match_set,
            extensions_filter: filter_set,
        }
    }

    /// Validates whether an item/URL path is permitted for crawling based on its extension.
    pub fn validate_path(&self, item: &str) -> bool {
        let path = if let Ok(u) = Url::parse(item) {
            u.path().to_string()
        } else {
            // Strip query string and fragment if present in raw string
            let without_query = item.split('?').next().unwrap_or(item);
            let without_hash = without_query.split('#').next().unwrap_or(without_query);
            without_hash.to_string()
        };

        let filename = path.rsplit('/').next().unwrap_or(&path);
        let filename_lower = filename.to_lowercase();

        // Check compound extensions like .tar.gz first
        let extension = if filename_lower.ends_with(".tar.gz") {
            ".tar.gz".to_string()
        } else if let Some(dot_idx) = filename_lower.rfind('.') {
            filename_lower[dot_idx..].to_string()
        } else {
            String::new()
        };

        if extension.is_empty() && !self.extensions_match.is_empty() {
            return self.extensions_match.contains("");
        }

        if !self.extensions_match.is_empty() {
            return self.extensions_match.contains(&extension);
        }

        if !extension.is_empty() && self.extensions_filter.contains(&extension) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_denylist_filtering() {
        let validator = ExtensionValidator::default();

        // Allowed targets
        assert!(validator.validate_path("https://example.com/index.html"));
        assert!(validator.validate_path("https://example.com/api/v1/users"));
        assert!(validator.validate_path("https://example.com/"));
        assert!(validator.validate_path("https://example.com/script.js"));
        assert!(validator.validate_path("https://example.com/page.php?id=1"));

        // Denied default extensions
        assert!(!validator.validate_path("https://example.com/assets/logo.png"));
        assert!(!validator.validate_path("https://example.com/downloads/archive.zip"));
        assert!(!validator.validate_path("https://example.com/docs/manual.pdf"));
        assert!(!validator.validate_path("https://example.com/video.mp4"));
        assert!(!validator.validate_path("https://example.com/font.woff2"));
        assert!(!validator.validate_path("https://example.com/source.tar.gz"));
    }

    #[test]
    fn test_custom_extension_match_override() {
        let match_rules = vec!["php".to_string(), "html".to_string()];
        let validator = ExtensionValidator::new(&match_rules, &[], false);

        assert!(validator.validate_path("https://example.com/page.php"));
        assert!(validator.validate_path("https://example.com/index.html"));
        assert!(!validator.validate_path("https://example.com/app.js"));
        assert!(!validator.validate_path("https://example.com/logo.png"));
    }

    #[test]
    fn test_no_default_filter_with_custom_filter() {
        let filter_rules = vec!["custom".to_string()];
        let validator = ExtensionValidator::new(&[], &filter_rules, true);

        // png is allowed because default filter is disabled
        assert!(validator.validate_path("https://example.com/logo.png"));
        // custom extension is denied
        assert!(!validator.validate_path("https://example.com/file.custom"));
    }
}
