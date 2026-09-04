use katana_core::navigation::Form;

/// Returns realistic synthetic input data for a given form field name/type.
pub fn get_field_synthetic_value(field_name: &str, field_type: &str) -> &'static str {
    let name_lower = field_name.to_lowercase();
    let type_lower = field_type.to_lowercase();

    if type_lower == "password" || name_lower.contains("pass") || name_lower.contains("pwd") {
        "Password123!"
    } else if type_lower == "email" || name_lower.contains("email") || name_lower.contains("mail") {
        "test@example.com"
    } else if name_lower.contains("user")
        || name_lower.contains("login")
        || name_lower.contains("name")
    {
        "admin"
    } else if type_lower == "tel" || name_lower.contains("phone") || name_lower.contains("mobile") {
        "+15550199"
    } else if type_lower == "number" || name_lower.contains("age") || name_lower.contains("count") {
        "1"
    } else if type_lower == "search" || name_lower.contains("search") || name_lower.contains("q") {
        "katana"
    } else {
        "katana_test"
    }
}

/// Generates a JavaScript snippet to populate and automatically submit an HTML form.
pub fn generate_form_fill_script(form: &Form) -> String {
    let mut script = String::from("(() => {\n");
    let form_selector = if !form.action.is_empty() {
        format!("form[action*=\"{}\"]", form.action.replace('"', "\\\""))
    } else {
        "form".to_string()
    };
    script.push_str(&format!(
        "    const form = document.querySelector('{}') || document.querySelector('form');\n",
        form_selector
    ));
    script.push_str("    if (!form) return;\n");

    for (idx, param) in form.parameters.iter().enumerate() {
        let val = get_field_synthetic_value(param, "text");
        let safe_name = param.replace('"', "\\\"");
        script.push_str(&format!(
            "    const input_{idx} = form.querySelector('[name=\"{safe_name}\"]');\n",
            idx = idx,
            safe_name = safe_name
        ));
        script.push_str(&format!(
            "    if (input_{idx}) {{ input_{idx}.value = \"{val}\"; }}\n",
            idx = idx,
            val = val
        ));
    }

    script.push_str("    try { form.submit(); } catch(e) {}\n");
    script.push_str("})();\n");
    script
}

/// Returns a JavaScript snippet to simulate clicking on dynamic links and buttons on a page.
pub fn generate_click_actions_script() -> &'static str {
    r#"
    (() => {
        // Find all clickable buttons and action anchors
        const actionElements = document.querySelectorAll('button, a[onclick], input[type="submit"], input[type="button"]');
        for (const el of actionElements) {
            try {
                el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
            } catch (e) {}
        }
    })();
    "#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_field_synthetic_value() {
        assert_eq!(
            get_field_synthetic_value("user_email", "text"),
            "test@example.com"
        );
        assert_eq!(
            get_field_synthetic_value("password", "password"),
            "Password123!"
        );
        assert_eq!(get_field_synthetic_value("username", "text"), "admin");
        assert_eq!(get_field_synthetic_value("phone_num", "tel"), "+15550199");
        assert_eq!(
            get_field_synthetic_value("search_query", "search"),
            "katana"
        );
    }

    #[test]
    fn test_generate_form_fill_script() {
        let form = Form {
            action: "/login".to_string(),
            method: "POST".to_string(),
            enctype: "".to_string(),
            parameters: vec!["username".to_string(), "password".to_string()],
        };

        let script = generate_form_fill_script(&form);
        assert!(script.contains("name=\"username\""));
        assert!(script.contains("name=\"password\""));
        assert!(script.contains("admin"));
        assert!(script.contains("Password123!"));
        assert!(script.contains("form.submit()"));
    }

    #[test]
    fn test_generate_form_fill_script_with_special_characters() {
        let form = Form {
            action: "/update-profile".to_string(),
            method: "POST".to_string(),
            enctype: "".to_string(),
            parameters: vec![
                "csrf-token".to_string(),
                "user[email]".to_string(),
                "phone.number".to_string(),
            ],
        };

        let script = generate_form_fill_script(&form);
        assert!(script.contains("name=\"csrf-token\""));
        assert!(script.contains("name=\"user[email]\""));
        assert!(script.contains("name=\"phone.number\""));
        assert!(script.contains("input_0"));
        assert!(script.contains("input_1"));
        assert!(script.contains("input_2"));
        // Confirm no invalid JS identifier names like "input_csrf-token"
        assert!(!script.contains("input_csrf-token"));
        assert!(!script.contains("input_user[email]"));
    }
}
