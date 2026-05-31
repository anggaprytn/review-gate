use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct OllamaGenerateRequest<'a> {
    pub model: &'a str,
    pub prompt: &'a str,
    pub stream: bool,
}

#[derive(Debug, Deserialize)]
pub struct OllamaGenerateResponse {
    pub response: String,
}
