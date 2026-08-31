use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomFieldPart {
    Header,
    Body,
    Response,
}

impl From<&str> for CustomFieldPart {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "header" | "headers" => Self::Header,
            "body" => Self::Body,
            _ => Self::Response,
        }
    }
}

/// Custom field extraction configuration definition (YAML schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFieldConfig {
    pub name: String,
    #[serde(rename = "type", default = "default_type")]
    pub field_type: String,
    #[serde(default = "default_part")]
    pub part: String,
    #[serde(default)]
    pub group: usize,
    #[serde(default)]
    pub regex: Vec<String>,
}

fn default_type() -> String {
    "regex".to_string()
}

fn default_part() -> String {
    "response".to_string()
}

#[derive(Debug, Clone)]
struct CompiledCustomField {
    name: String,
    part: CustomFieldPart,
    group: usize,
    regexes: Vec<Regex>,
}

/// Manager for registering and executing custom field extractors across responses.
#[derive(Debug, Clone, Default)]
pub struct CustomFieldManager {
    fields: Vec<CompiledCustomField>,
}

impl CustomFieldManager {
    pub fn new() -> Self {
        let mut mgr = Self { fields: Vec::new() };
        // Default built-in extractors
        mgr.register(CustomFieldConfig {
            name: "email".to_string(),
            field_type: "regex".to_string(),
            part: "response".to_string(),
            group: 0,
            regex: vec![r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string()],
        });
        mgr
    }

    pub fn register(&mut self, cfg: CustomFieldConfig) {
        let mut compiled = Vec::new();
        for r_str in &cfg.regex {
            if let Ok(re) = Regex::new(r_str) {
                compiled.push(re);
            }
        }

        if !compiled.is_empty() {
            self.fields.push(CompiledCustomField {
                name: cfg.name,
                part: CustomFieldPart::from(cfg.part.as_str()),
                group: cfg.group,
                regexes: compiled,
            });
        }
    }

    pub fn from_yaml(yaml_str: &str) -> anyhow::Result<Self> {
        let mut mgr = Self::default();
        let configs: Vec<CustomFieldConfig> = serde_yaml::from_str(yaml_str)?;
        for cfg in configs {
            mgr.register(cfg);
        }
        Ok(mgr)
    }

    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Self::from_yaml(&content)
    }

    pub fn extract(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> HashMap<String, Vec<String>> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        let header_str = headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        for field in &self.fields {
            let target_text = match field.part {
                CustomFieldPart::Header => &header_str,
                CustomFieldPart::Body => body,
                CustomFieldPart::Response => body, // or combined
            };

            for re in &field.regexes {
                for caps in re.captures_iter(target_text) {
                    let val = if field.group < caps.len() {
                        caps.get(field.group).map(|m| m.as_str().to_string())
                    } else {
                        caps.get(0).map(|m| m.as_str().to_string())
                    };

                    if let Some(v) = val {
                        result.entry(field.name.clone()).or_default().push(v);
                    }
                }
            }

            // Deduplicate extracted values
            if let Some(vals) = result.get_mut(&field.name) {
                vals.sort();
                vals.dedup();
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_field_manager() {
        let yaml_content = r#"
        - name: phone
          type: regex
          part: body
          group: 0
          regex:
            - '\+?[0-9]{1,3}-[0-9]{3}-[0-9]{3}-[0-9]{4}'
        - name: server_banner
          type: regex
          part: header
          group: 1
          regex:
            - 'server:\s*([^\r\n]+)'
        "#;

        let mgr = CustomFieldManager::from_yaml(yaml_content).unwrap();

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.21.6".to_string());

        let body = "Please call customer support at +1-800-555-0199 or contact us.";

        let extracted = mgr.extract(&headers, body);

        assert_eq!(
            extracted.get("server_banner").unwrap(),
            &vec!["nginx/1.21.6".to_string()]
        );
        assert_eq!(
            extracted.get("phone").unwrap(),
            &vec!["+1-800-555-0199".to_string()]
        );
    }
}
