use crate::error::{Result, ReviewGateError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmProvider {
    Ollama,
    CodexCli,
    GeminiCli,
}

impl LlmProvider {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama),
            "codex_cli" | "codex-cli" | "codex" => Ok(Self::CodexCli),
            "gemini_cli" | "gemini-cli" | "gemini" => Ok(Self::GeminiCli),
            _ => Err(ReviewGateError::UnsupportedLlmProvider(
                value.trim().to_string(),
            )),
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::CodexCli => "codex_cli",
            Self::GeminiCli => "gemini_cli",
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::LlmProvider;
    use crate::error::ReviewGateError;

    #[test]
    fn parses_supported_providers() {
        assert_eq!(LlmProvider::parse("ollama").unwrap(), LlmProvider::Ollama);
        assert_eq!(
            LlmProvider::parse("codex_cli").unwrap(),
            LlmProvider::CodexCli
        );
        assert_eq!(
            LlmProvider::parse("CODEX-CLI").unwrap(),
            LlmProvider::CodexCli
        );
        assert_eq!(
            LlmProvider::parse("gemini_cli").unwrap(),
            LlmProvider::GeminiCli
        );
    }

    #[test]
    fn unsupported_provider_returns_guard_error() {
        let err = LlmProvider::parse("openai").unwrap_err();

        assert!(matches!(err, ReviewGateError::UnsupportedLlmProvider(_)));
    }
}
