use super::identify::CaptchaInfo;
use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;

/// Trait for solving automated CAPTCHA challenges via third-party solver APIs.
#[async_trait]
pub trait CaptchaSolver: Send + Sync {
    async fn solve(&self, info: &CaptchaInfo) -> anyhow::Result<String>;
}

/// Solver implementation for Capsolver API (capsolver.com).
pub struct CapsolverProvider {
    pub api_key: String,
    pub client: reqwest::Client,
}

impl CapsolverProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl CaptchaSolver for CapsolverProvider {
    async fn solve(&self, info: &CaptchaInfo) -> anyhow::Result<String> {
        let task_type = match info.provider {
            super::identify::CaptchaProvider::RecaptchaV2 => "ReCaptchaV2TaskProxyLess",
            super::identify::CaptchaProvider::RecaptchaV3 => "ReCaptchaV3TaskProxyLess",
            super::identify::CaptchaProvider::RecaptchaV2Enterprise => {
                "ReCaptchaV2EnterpriseTaskProxyLess"
            }
            super::identify::CaptchaProvider::RecaptchaV3Enterprise => {
                "ReCaptchaV3EnterpriseTaskProxyLess"
            }
            super::identify::CaptchaProvider::Turnstile => "AntiTurnstileTaskProxyLess",
            super::identify::CaptchaProvider::HCaptcha => "HCaptchaTaskProxyLess",
        };

        let create_task_payload = json!({
            "clientKey": self.api_key,
            "task": {
                "type": task_type,
                "websiteURL": info.page_url,
                "websiteKey": info.sitekey,
            }
        });

        let resp = self
            .client
            .post("https://api.capsolver.com/createTask")
            .json(&create_task_payload)
            .send()
            .await?;

        let resp_json: serde_json::Value = resp.json().await?;
        if let Some(error_id) = resp_json.get("errorId").and_then(|v| v.as_i64()) {
            if error_id != 0 {
                let err_desc = resp_json
                    .get("errorDescription")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown capsolver error");
                anyhow::bail!("Capsolver error: {}", err_desc);
            }
        }

        let task_id = resp_json
            .get("taskId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing taskId in response"))?;

        // Poll for task result
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let result_payload = json!({
                "clientKey": self.api_key,
                "taskId": task_id
            });

            let res = self
                .client
                .post("https://api.capsolver.com/getTaskResult")
                .json(&result_payload)
                .send()
                .await?;

            let res_json: serde_json::Value = res.json().await?;
            let status = res_json
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if status == "ready" {
                if let Some(solution) = res_json.get("solution") {
                    if let Some(token) = solution
                        .get("gRecaptchaResponse")
                        .or_else(|| solution.get("token"))
                        .and_then(|v| v.as_str())
                    {
                        return Ok(token.to_string());
                    }
                }
            } else if status == "failed" {
                anyhow::bail!("Capsolver task processing failed");
            }
        }

        anyhow::bail!("Capsolver task timed out");
    }
}
