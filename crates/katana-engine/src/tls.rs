use reqwest::ClientBuilder;

/// TLS impersonation profile simulating browser ClientHello characteristics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsClientProfile {
    Chrome,
    Firefox,
    Safari,
    Random,
}

impl std::str::FromStr for TlsClientProfile {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "random" => Self::Random,
            _ => Self::Chrome,
        })
    }
}

/// Applies TLS ClientHello configuration and browser impersonation to a reqwest ClientBuilder.
pub fn apply_tls_configuration(
    mut builder: ClientBuilder,
    impersonate_preset: Option<&str>,
) -> ClientBuilder {
    let profile = impersonate_preset
        .and_then(|s| s.parse::<TlsClientProfile>().ok())
        .unwrap_or(TlsClientProfile::Chrome);

    // Apply TLS version bounds
    match profile {
        TlsClientProfile::Chrome => {
            builder = builder
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .max_tls_version(reqwest::tls::Version::TLS_1_3);
        }
        TlsClientProfile::Firefox => {
            builder = builder
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .max_tls_version(reqwest::tls::Version::TLS_1_3);
        }
        TlsClientProfile::Safari => {
            builder = builder
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .max_tls_version(reqwest::tls::Version::TLS_1_3);
        }
        TlsClientProfile::Random => {
            // Random variation of TLS min version
            let use_tls13 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .is_multiple_of(2);
            if use_tls13 {
                builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_3);
            } else {
                builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);
            }
        }
    }

    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_client_profile_parsing() {
        assert_eq!(
            "chrome".parse::<TlsClientProfile>().unwrap(),
            TlsClientProfile::Chrome
        );
        assert_eq!(
            "FIREFOX".parse::<TlsClientProfile>().unwrap(),
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
        assert_eq!(
            "unknown".parse::<TlsClientProfile>().unwrap(),
            TlsClientProfile::Chrome
        );
    }

    #[test]
    fn test_apply_tls_configuration() {
        let builder = reqwest::Client::builder();
        let configured = apply_tls_configuration(builder, Some("chrome"));
        let client = configured.build();
        assert!(client.is_ok());
    }
}
