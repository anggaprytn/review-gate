use crate::{
    error::{Result, ReviewGateError},
    llm::types::{OllamaGenerateRequest, OllamaGenerateResponse},
};

#[derive(Debug, Clone)]
pub struct OllamaClient {
    base_url: String,
    model: String,
    http: reqwest::Client,
}

impl OllamaClient {
    pub fn new(base_url: String, model: String, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model,
            http,
        }
    }

    pub async fn review(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.base_url);
        let body = OllamaGenerateRequest {
            model: &self.model,
            prompt,
            stream: false,
        };

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|err| map_ollama_request_error(err, &self.base_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ReviewGateError::OllamaApi(format!(
                "request failed with status {status}: {body}"
            )));
        }

        let output = response.json::<OllamaGenerateResponse>().await?;
        Ok(output.response)
    }
}

fn map_ollama_request_error(err: reqwest::Error, base_url: &str) -> ReviewGateError {
    if err.is_connect() || err.is_timeout() {
        ReviewGateError::OllamaUnreachable(base_url.to_string())
    } else {
        ReviewGateError::Reqwest(err)
    }
}
