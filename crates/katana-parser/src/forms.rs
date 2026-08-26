use katana_core::navigation::Form;
use scraper::{Html, Selector};

/// Parse form definitions and input parameters from HTML.
pub fn parse_forms(html_content: &str) -> Vec<Form> {
    let mut forms = Vec::new();
    let document = Html::parse_document(html_content);

    let form_selector = match Selector::parse("form") {
        Ok(s) => s,
        Err(_) => return forms,
    };
    let input_selector = match Selector::parse("input[name], select[name], textarea[name]") {
        Ok(s) => s,
        Err(_) => return forms,
    };

    for form_el in document.select(&form_selector) {
        let action = form_el.value().attr("action").unwrap_or("").to_string();
        let method = form_el.value().attr("method").unwrap_or("GET").to_uppercase();
        let enctype = form_el
            .value()
            .attr("enctype")
            .unwrap_or("application/x-www-form-urlencoded")
            .to_string();

        let mut parameters = Vec::new();
        for input in form_el.select(&input_selector) {
            if let Some(name) = input.value().attr("name") {
                if !name.trim().is_empty() {
                    parameters.push(name.to_string());
                }
            }
        }

        forms.push(Form {
            action,
            method,
            enctype,
            parameters,
        });
    }

    forms
}
