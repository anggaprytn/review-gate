pub mod codex_cli;
pub mod gemini_cli;
pub mod ollama;
pub mod types;

use crate::{
    config::LlmConfig,
    error::Result,
    llm::{
        codex_cli::CodexCliClient,
        gemini_cli::GeminiCliClient,
        ollama::OllamaClient,
        types::{LlmProvider, LlmReviewResponse},
    },
};

pub async fn review_with_config(config: &LlmConfig, prompt: &str) -> Result<LlmReviewResponse> {
    match LlmProvider::parse(&config.provider)? {
        LlmProvider::Ollama => OllamaClient::from_config(config)?.review(prompt).await,
        LlmProvider::CodexCli => CodexCliClient::from_config(config)?.review(prompt),
        LlmProvider::GeminiCli => GeminiCliClient::from_config(config)?.review(prompt),
    }
}

pub fn provider_local_only(config: &LlmConfig) -> bool {
    matches!(
        LlmProvider::parse(&config.provider),
        Ok(LlmProvider::Ollama)
    )
}

pub fn external_model_call_label(config: &LlmConfig) -> &'static str {
    match LlmProvider::parse(&config.provider) {
        Ok(LlmProvider::Ollama) => "disabled",
        Ok(LlmProvider::CodexCli) => "enabled through Codex CLI",
        Ok(LlmProvider::GeminiCli) => "enabled through Gemini CLI",
        Err(_) => "unknown",
    }
}

pub fn auth_label(config: &LlmConfig) -> Option<&'static str> {
    match LlmProvider::parse(&config.provider) {
        Ok(LlmProvider::CodexCli) => Some("local Codex login"),
        Ok(LlmProvider::GeminiCli) => Some("Gemini CLI local authentication"),
        Ok(LlmProvider::Ollama) | Err(_) => None,
    }
}

pub fn payload_label(_config: &LlmConfig) -> &'static str {
    "sanitized diff only"
}

#[cfg(test)]
mod tests {
    use super::{auth_label, external_model_call_label, payload_label, provider_local_only};
    use crate::config::LlmConfig;

    #[test]
    fn metadata_labels_ollama_as_local_only() {
        let config = config("ollama");

        assert!(provider_local_only(&config));
        assert_eq!(external_model_call_label(&config), "disabled");
        assert_eq!(auth_label(&config), None);
        assert_eq!(payload_label(&config), "sanitized diff only");
    }

    #[test]
    fn metadata_labels_gemini_as_external_cli_call() {
        let config = config("gemini_cli");

        assert!(!provider_local_only(&config));
        assert_eq!(
            external_model_call_label(&config),
            "enabled through Gemini CLI"
        );
        assert_eq!(auth_label(&config), Some("Gemini CLI local authentication"));
    }

    #[test]
    fn metadata_labels_codex_as_external_cli_call() {
        let config = config("codex_cli");

        assert!(!provider_local_only(&config));
        assert_eq!(
            external_model_call_label(&config),
            "enabled through Codex CLI"
        );
        assert_eq!(auth_label(&config), Some("local Codex login"));
    }

    fn config(provider: &str) -> LlmConfig {
        LlmConfig {
            provider: provider.to_string(),
            ollama_base_url: "http://localhost:11434".to_string(),
            model: "model".to_string(),
            timeout_seconds: 180,
            max_context_tokens: 12000,
            temperature: 0.1,
            codex_timeout_seconds: 240,
            codex_bin: "codex".to_string(),
            codex_full_auto: false,
            gemini_timeout_seconds: 240,
            gemini_bin: "gemini".to_string(),
            gemini_output_format: "json".to_string(),
        }
    }
}
