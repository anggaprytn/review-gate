use crate::error::{Result, ReviewGateError};
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub gitlab_token: Option<String>,
    pub gitlab_base_url: Option<String>,
    pub llm: LlmConfig,
    pub privacy: PrivacyConfig,
    pub review: ReviewConfig,
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: String,
    pub ollama_base_url: String,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    pub local_only: bool,
    pub redact_secrets: bool,
}

#[derive(Debug, Clone)]
pub struct ReviewConfig {
    pub max_inline_comments: u32,
    pub severity_threshold: String,
    pub max_diff_bytes: usize,
    pub max_files: usize,
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    providers: Option<ProvidersConfig>,
    llm: Option<FileLlmConfig>,
    privacy: Option<FilePrivacyConfig>,
    review: Option<FileReviewConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct ProvidersConfig {
    gitlab: Option<FileGitLabConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct FileGitLabConfig {
    base_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FileLlmConfig {
    provider: Option<String>,
    ollama_base_url: Option<String>,
    model: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FilePrivacyConfig {
    local_only: Option<bool>,
    redact_secrets: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct FileReviewConfig {
    max_inline_comments: Option<u32>,
    severity_threshold: Option<String>,
    max_diff_bytes: Option<usize>,
    max_files: Option<usize>,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let file_config = load_file_config(".reviewgate.toml")?;

        let gitlab_base_url = env::var("GITLAB_BASE_URL").ok().or_else(|| {
            file_config
                .providers
                .as_ref()
                .and_then(|providers| providers.gitlab.as_ref())
                .and_then(|gitlab| gitlab.base_url.clone())
        });

        let file_llm = file_config.llm.as_ref();
        let provider = env::var("REVIEWGATE_LLM_PROVIDER")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.provider.clone()))
            .unwrap_or_else(|| "ollama".to_string());
        let ollama_base_url = env::var("OLLAMA_BASE_URL")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.ollama_base_url.clone()))
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        let model = env::var("REVIEWGATE_MODEL")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.model.clone()))
            .unwrap_or_else(|| "qwen2.5-coder:7b".to_string());

        let file_privacy = file_config.privacy.as_ref();
        let privacy = PrivacyConfig {
            local_only: env_bool("REVIEWGATE_LOCAL_ONLY")
                .or_else(|| file_privacy.and_then(|privacy| privacy.local_only))
                .unwrap_or(true),
            redact_secrets: env_bool("REVIEWGATE_REDACT_SECRETS")
                .or_else(|| file_privacy.and_then(|privacy| privacy.redact_secrets))
                .unwrap_or(true),
        };

        let file_review = file_config.review.as_ref();
        let review = ReviewConfig {
            max_inline_comments: env::var("REVIEWGATE_MAX_INLINE_COMMENTS")
                .ok()
                .and_then(|value| value.parse().ok())
                .or_else(|| file_review.and_then(|review| review.max_inline_comments))
                .unwrap_or(8),
            severity_threshold: env::var("REVIEWGATE_SEVERITY_THRESHOLD")
                .ok()
                .or_else(|| file_review.and_then(|review| review.severity_threshold.clone()))
                .unwrap_or_else(|| "medium".to_string()),
            max_diff_bytes: env::var("REVIEWGATE_MAX_DIFF_BYTES")
                .ok()
                .and_then(|value| value.parse().ok())
                .or_else(|| file_review.and_then(|review| review.max_diff_bytes))
                .unwrap_or(200_000),
            max_files: env::var("REVIEWGATE_MAX_FILES")
                .ok()
                .and_then(|value| value.parse().ok())
                .or_else(|| file_review.and_then(|review| review.max_files))
                .unwrap_or(50),
        };

        Ok(Self {
            gitlab_token: env::var("GITLAB_TOKEN")
                .ok()
                .filter(|value| !value.is_empty()),
            gitlab_base_url,
            llm: LlmConfig {
                provider,
                ollama_base_url,
                model,
            },
            privacy,
            review,
        })
    }

    pub fn validate_for_preview(&self) -> Result<()> {
        if self.llm.provider != "ollama" {
            return Err(ReviewGateError::UnsupportedLlmProvider(
                self.llm.provider.clone(),
            ));
        }
        if self.llm.ollama_base_url.trim().is_empty() {
            return Err(ReviewGateError::Config(
                "OLLAMA_BASE_URL must not be empty".to_string(),
            ));
        }
        if self.llm.model.trim().is_empty() {
            return Err(ReviewGateError::Config(
                "REVIEWGATE_MODEL must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

fn load_file_config(path: &str) -> Result<FileConfig> {
    if !Path::new(path).exists() {
        return Ok(FileConfig::default());
    }

    let contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&contents)?)
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .and_then(|value| match value.to_lowercase().as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        })
}
