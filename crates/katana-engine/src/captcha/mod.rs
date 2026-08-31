pub mod identify;
pub mod injection;
pub mod solver;

pub use identify::{detect_captcha_in_html, get_identify_js, CaptchaInfo, CaptchaProvider};
pub use injection::get_inject_script;
pub use solver::{CapsolverProvider, CaptchaSolver};
