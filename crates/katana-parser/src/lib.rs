pub mod files;
pub mod forms;
pub mod html;
pub mod js;
pub mod regex;

pub use files::{parse_robots_txt, parse_sitemap_xml};
pub use forms::parse_forms;
pub use html::{extract_inline_scripts, parse_html_endpoints};
pub use js::{extract_js_ast_endpoints, is_common_js_library};
pub use regex::{extract_body_endpoints, extract_endpoints_from_regex, extract_relative_endpoints};
