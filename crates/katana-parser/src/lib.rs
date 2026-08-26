pub mod forms;
pub mod html;
pub mod regex;

pub use forms::parse_forms;
pub use html::parse_html_endpoints;
pub use regex::extract_endpoints_from_regex;
