pub mod identify;
pub mod injection;
pub mod solver;

pub use identify::{
    detect_captcha_in_html, get_identify_js, parse_captcha_info_from_value, CaptchaInfo,
    CaptchaProvider,
};
pub use injection::get_inject_script;
pub use solver::{CapsolverProvider, CaptchaSolver};
