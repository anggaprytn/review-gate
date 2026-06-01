use crate::{
    config::LlmConfig,
    error::{Result, ReviewGateError},
    llm::types::{
        LlmReviewResponse, LlmRunMetadata, OllamaGenerateOptions, OllamaGenerateRequest,
        OllamaGenerateResponse,
    },
};
use reqwest::StatusCode;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OllamaClient {
    base_url: String,
    model: String,
    timeout_seconds: u64,
    max_context_tokens: u32,
    temperature: f64,
    http: reqwest::Client,
}

impl OllamaClient {
    pub fn from_config(config: &LlmConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent(format!("reviewgate/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self::with_options(
            config.ollama_base_url.clone(),
            config.model.clone(),
            config.timeout_seconds,
            config.max_context_tokens,
            config.temperature,
            http,
        ))
    }

    pub fn new(base_url: String, model: String, http: reqwest::Client) -> Self {
        Self::with_options(base_url, model, 180, 12_000, 0.1, http)
    }

    pub fn with_options(
        base_url: String,
        model: String,
        timeout_seconds: u64,
        max_context_tokens: u32,
        temperature: f64,
        http: reqwest::Client,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model,
            timeout_seconds,
            max_context_tokens,
            temperature,
            http,
        }
    }

    pub async fn review(&self, prompt: &str) -> Result<LlmReviewResponse> {
        let url = format!("{}/api/generate", self.base_url);
        let body = build_ollama_generate_request(
            &self.model,
            prompt,
            self.temperature,
            self.max_context_tokens,
        );

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|err| map_ollama_request_error(err, &self.base_url, self.timeout_seconds))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if status == StatusCode::NOT_FOUND || body.to_lowercase().contains("not found") {
                return Err(ReviewGateError::OllamaModelNotFound(self.model.clone()));
            }
            return Err(ReviewGateError::OllamaApi(format!(
                "request failed with status {status}: {}",
                clean_error_body(&body)
            )));
        }

        let output = response
            .json::<OllamaGenerateResponse>()
            .await
            .map_err(|err| ReviewGateError::InvalidOllamaResponse(err.to_string()))?;
        parse_ollama_generate_response(output)
    }
}

pub fn build_ollama_generate_request(
    model: &str,
    prompt: &str,
    temperature: f64,
    max_context_tokens: u32,
) -> OllamaGenerateRequest {
    OllamaGenerateRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
        response_format: "json".to_string(),
        options: OllamaGenerateOptions {
            temperature,
            num_ctx: max_context_tokens,
        },
    }
}

pub fn parse_ollama_generate_response(output: OllamaGenerateResponse) -> Result<LlmReviewResponse> {
    if output.done == Some(false) {
        return Err(ReviewGateError::InvalidOllamaResponse(
            "non-streaming response was not marked done".to_string(),
        ));
    }

    let response = output.response.ok_or_else(|| {
        ReviewGateError::InvalidOllamaResponse("missing response field".to_string())
    })?;
    let text = response.trim().to_string();
    if text.is_empty() {
        return Err(ReviewGateError::EmptyModelResponse);
    }

    Ok(LlmReviewResponse {
        text,
        metadata: LlmRunMetadata {
            total_duration: output.total_duration,
            load_duration: output.load_duration,
            prompt_eval_count: output.prompt_eval_count,
            eval_count: output.eval_count,
        },
    })
}

fn map_ollama_request_error(
    err: reqwest::Error,
    base_url: &str,
    timeout_seconds: u64,
) -> ReviewGateError {
    if err.is_timeout() {
        ReviewGateError::OllamaTimeout {
            seconds: timeout_seconds,
        }
    } else if err.is_connect() {
        ReviewGateError::OllamaUnreachable(base_url.to_string())
    } else {
        ReviewGateError::Reqwest(err)
    }
}

fn clean_error_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "empty response body".to_string()
    } else {
        trimmed.chars().take(500).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{build_ollama_generate_request, parse_ollama_generate_response};
    use crate::{error::ReviewGateError, llm::types::OllamaGenerateResponse};
    use serde_json::json;

    #[test]
    fn builds_ollama_request_body_for_json_non_streaming() {
        let request = build_ollama_generate_request("qwen2.5-coder:7b", "review this", 0.1, 12000);
        let body = serde_json::to_value(request).unwrap();

        assert_eq!(
            body,
            json!({
                "model": "qwen2.5-coder:7b",
                "prompt": "review this",
                "stream": false,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                    "num_ctx": 12000
                }
            })
        );
    }

    #[test]
    fn parses_ollama_response_and_metadata() {
        let parsed = parse_ollama_generate_response(OllamaGenerateResponse {
            response: Some(r#"{"summary":"ok"}"#.to_string()),
            done: Some(true),
            total_duration: Some(10),
            load_duration: Some(2),
            prompt_eval_count: Some(42),
            eval_count: Some(7),
        })
        .unwrap();

        assert_eq!(parsed.text, r#"{"summary":"ok"}"#);
        assert_eq!(parsed.metadata.prompt_eval_count, Some(42));
        assert_eq!(parsed.metadata.eval_count, Some(7));
    }

    #[test]
    fn empty_ollama_response_returns_clear_error() {
        let err = parse_ollama_generate_response(OllamaGenerateResponse {
            response: Some("   ".to_string()),
            done: Some(true),
            total_duration: None,
            load_duration: None,
            prompt_eval_count: None,
            eval_count: None,
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::EmptyModelResponse));
    }
}
