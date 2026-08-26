use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum KatanaError {
    #[error("maximum crawl depth exceeded")]
    MaxDepthReached,

    #[error("endpoint is out of scope")]
    OutOfScope,

    #[error("url cycle detected")]
    CycleDetected,

    #[error("invalid url: {0}")]
    InvalidUrl(String),

    #[error("network policy rejected url: {0}")]
    NetworkPolicyRejected(String),

    #[error("http request failed: {0}")]
    HttpError(String),

    #[error("crawl timeout reached")]
    Timeout,

    #[error("other error: {0}")]
    Custom(String),
}
