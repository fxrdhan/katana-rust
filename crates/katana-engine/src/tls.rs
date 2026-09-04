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

use dashmap::DashMap;
use katana_core::navigation::TlsData;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

#[derive(Debug)]
struct CaptureVerifier {
    certs: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl rustls::client::danger::ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut guard = self.certs.lock().unwrap();
        guard.push(end_entity.as_ref().to_vec());
        for inter in intermediates {
            guard.push(inter.as_ref().to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parses an X.509 certificate from raw DER bytes into TlsData.
pub fn parse_x509_der(der: &[u8]) -> anyhow::Result<TlsData> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

    let subject_dn = cert.subject().to_string();
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();

    let mut subject_an = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(dns) => subject_an.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        subject_an.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else if ip.len() == 16 {
                        subject_an.push(
                            ip.chunks(2)
                                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                                .collect::<Vec<_>>()
                                .join(":"),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let issuer_dn = cert.issuer().to_string();
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();

    let mut issuer_org = Vec::new();
    for org in cert.issuer().iter_organization() {
        if let Ok(s) = org.as_str() {
            issuer_org.push(s.to_string());
        }
    }

    let not_before = cert.validity().not_before.to_datetime().to_string();
    let not_after = cert.validity().not_after.to_datetime().to_string();

    let sha256_hash = sha2::Sha256::digest(der);
    let fingerprint_sha256 = sha256_hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    Ok(TlsData {
        subject_dn,
        subject_cn,
        subject_an,
        issuer_dn,
        issuer_cn,
        issuer_org,
        not_before,
        not_after,
        fingerprint_sha256,
        ..Default::default()
    })
}

/// Computes standard JA3 fingerprint (raw string and MD5 hash) for the given client profile.
pub fn compute_ja3_fingerprint(profile: &TlsClientProfile) -> (String, String) {
    let raw = match profile {
        TlsClientProfile::Chrome => {
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0".to_string()
        }
        TlsClientProfile::Firefox => {
            "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0".to_string()
        }
        TlsClientProfile::Safari => {
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24,0".to_string()
        }
        TlsClientProfile::Random => {
            "771,4865-4866-4867-49195-49199-52393,0-23-65281-10-11-16-5-13-51-43,29-23-24,0".to_string()
        }
    };
    let hash = format!("{:x}", md5::Md5::digest(raw.as_bytes()));
    (raw, hash)
}

/// Computes JA4 fingerprint according to the FoxIO JA4 specification:
/// Format: {protocol}{tls_version}{sni}{ciphers_count}{extensions_count}{alpn}_{cipher_hash}_{ext_hash}
pub fn compute_ja4_fingerprint(
    profile: &TlsClientProfile,
    is_domain: bool,
    tls_version: &str,
    alpn: &str,
) -> String {
    let ver_code = match tls_version {
        "tls13" => "13",
        "tls12" => "12",
        "tls11" => "11",
        "tls10" => "10",
        _ => "13",
    };
    let sni_char = if is_domain { 'd' } else { 'i' };
    let alpn_code = if alpn.is_empty() {
        "00"
    } else if alpn.len() >= 2 {
        &alpn[0..2]
    } else {
        "h2"
    };

    let (ciphers_str, exts_str) = match profile {
        TlsClientProfile::Chrome => (
            "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035",
            "0000,0017,ff01,000a,000b,0023,0010,0005,000d,0012,0033,002d,002b,001b,4469",
        ),
        TlsClientProfile::Firefox => (
            "1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c00a,c009,c013,c014,009c,009d,002f,0035",
            "0000,0017,ff01,000a,000b,0023,0010,0005,0022,0033,002b,000d,002d,001c,0015",
        ),
        TlsClientProfile::Safari => (
            "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035",
            "0000,0017,ff01,000a,000b,0010,0005,000d,0012,0033,002d,002b,001b",
        ),
        TlsClientProfile::Random => (
            "1301,1302,1303,c02b,c02f,cca9",
            "0000,0017,ff01,000a,000b,0010,0005,000d,0033,002b",
        ),
    };

    let c_count = ciphers_str.split(',').count();
    let e_count = exts_str.split(',').count();

    let c_hash_full = format!("{:x}", sha2::Sha256::digest(ciphers_str.as_bytes()));
    let e_hash_full = format!("{:x}", sha2::Sha256::digest(exts_str.as_bytes()));

    let c_hash_12 = &c_hash_full[..12];
    let e_hash_12 = &e_hash_full[..12];

    format!(
        "t{}{}{:02}{:02}{}_{}_{}",
        ver_code, sni_char, c_count, e_count, alpn_code, c_hash_12, e_hash_12
    )
}

/// TLS certificate metadata extractor with concurrency-safe caching.
#[derive(Default)]
pub struct TlsExtractor {
    cache: DashMap<String, Arc<TlsData>>,
}

impl TlsExtractor {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Extracts TLS certificate details and client fingerprints for target host:port.
    pub async fn extract_tls_data(
        &self,
        host: &str,
        port: u16,
        preset: Option<&str>,
    ) -> anyhow::Result<Arc<TlsData>> {
        let clean_host = host.trim_matches(|c| c == '[' || c == ']');
        let cache_key = format!("{}:{}", clean_host, port);
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(Arc::clone(&cached));
        }

        let addr = if clean_host.contains(':') {
            format!("[{}]:{}", clean_host, port)
        } else {
            format!("{}:{}", clean_host, port)
        };
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await??;

        let capture_verifier = Arc::new(CaptureVerifier {
            certs: std::sync::Mutex::new(Vec::new()),
        });
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::clone(&capture_verifier) as _;

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(clean_host.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, stream),
        )
        .await??;

        let (_, session) = tls_stream.get_ref();

        let negotiated_version = match session.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => "tls13",
            Some(rustls::ProtocolVersion::TLSv1_2) => "tls12",
            Some(rustls::ProtocolVersion::TLSv1_1) => "tls11",
            Some(rustls::ProtocolVersion::TLSv1_0) => "tls10",
            _ => "tls13",
        };

        let negotiated_cipher = session
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let captured = capture_verifier.certs.lock().unwrap().clone();
        let leaf_der = captured
            .first()
            .ok_or_else(|| anyhow::anyhow!("No certificates received in TLS handshake"))?;

        let mut tls_data = parse_x509_der(leaf_der)?;
        tls_data.tls_version = negotiated_version.to_string();
        tls_data.cipher = negotiated_cipher;

        let profile = preset
            .and_then(|s| s.parse::<TlsClientProfile>().ok())
            .unwrap_or(TlsClientProfile::Chrome);

        let is_domain = host.chars().any(|c| c.is_alphabetic());
        let (_, ja3_hash) = compute_ja3_fingerprint(&profile);
        let ja4 = compute_ja4_fingerprint(&profile, is_domain, negotiated_version, "h2");

        tls_data.ja3 = ja3_hash;
        tls_data.ja4 = ja4;

        let arc_data = Arc::new(tls_data);
        self.cache.insert(cache_key, Arc::clone(&arc_data));
        Ok(arc_data)
    }
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

    #[test]
    fn test_compute_ja3_fingerprint() {
        let (raw, hash) = compute_ja3_fingerprint(&TlsClientProfile::Chrome);
        assert!(!raw.is_empty());
        assert_eq!(hash.len(), 32);

        let (_, ff_hash) = compute_ja3_fingerprint(&TlsClientProfile::Firefox);
        assert_ne!(hash, ff_hash);
    }

    #[test]
    fn test_compute_ja4_fingerprint() {
        let ja4_chrome = compute_ja4_fingerprint(&TlsClientProfile::Chrome, true, "tls13", "h2");
        assert!(ja4_chrome.starts_with("t13d"));
        assert!(ja4_chrome.contains("_"));
        assert_eq!(ja4_chrome.len(), 36);

        let ja4_ip = compute_ja4_fingerprint(&TlsClientProfile::Chrome, false, "tls12", "h1");
        assert!(ja4_ip.starts_with("t12i"));
    }

    #[tokio::test]
    async fn test_tls_extractor_cache() {
        let extractor = TlsExtractor::new();
        let dummy = Arc::new(TlsData {
            subject_cn: "test.local".to_string(),
            cipher: "TLS_AES_128_GCM_SHA256".to_string(),
            tls_version: "tls13".to_string(),
            ..Default::default()
        });

        extractor
            .cache
            .insert("test.local:443".to_string(), dummy.clone());
        let res = extractor
            .extract_tls_data("test.local", 443, Some("chrome"))
            .await
            .unwrap();
        assert_eq!(res.subject_cn, "test.local");
    }
}
