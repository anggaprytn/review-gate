use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct OllamaGenerateRequest {
    pub model: String,
    pub prompt: String,
    pub stream: bool,
    #[serde(rename = "format")]
    pub response_format: String,
    pub options: OllamaGenerateOptions,
}

#[derive(Debug, Clone, Serialize)]
pub struct OllamaGenerateOptions {
    pub temperature: f64,
    pub num_ctx: u32,
}

#[derive(Debug, Deserialize)]
pub struct OllamaGenerateResponse {
    pub response: Option<String>,
    pub done: Option<bool>,
    pub total_duration: Option<u64>,
    pub load_duration: Option<u64>,
    pub prompt_eval_count: Option<u64>,
    pub eval_count: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlmRunMetadata {
    pub total_duration: Option<u64>,
    pub load_duration: Option<u64>,
    pub prompt_eval_count: Option<u64>,
    pub eval_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmReviewResponse {
    pub text: String,
    pub metadata: LlmRunMetadata,
}
