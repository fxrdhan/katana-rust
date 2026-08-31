pub mod actions;
pub mod launcher;
pub mod stealth;

pub use actions::{
    generate_click_actions_script, generate_form_fill_script, get_field_synthetic_value,
};
pub use launcher::{build_chrome_args, find_system_chrome, ChromeLaunchOptions};
pub use stealth::get_stealth_script;
