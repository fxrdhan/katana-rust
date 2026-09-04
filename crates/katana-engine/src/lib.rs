pub mod backoff;
pub mod browser;
pub mod captcha;
pub mod headless;
pub mod hybrid;
pub mod spa;
pub mod standard;
pub mod state;
pub mod traits;

pub use backoff::HostBackoffManager;
pub use headless::HeadlessEngine;
pub use hybrid::HybridEngine;
pub use spa::is_dynamic_spa;
pub use standard::StandardEngine;
pub use state::{strip_dom, PageState, StateGraph};
pub use traits::Engine;
