pub mod files;
pub mod forms;
pub mod html;
pub mod regex;

pub use files::{parse_robots_txt, parse_sitemap_xml};
pub use forms::parse_forms;
pub use html::parse_html_endpoints;
pub use regex::{extract_body_endpoints, extract_endpoints_from_regex, extract_relative_endpoints};
