use crate::error::{Result, ReviewGateError};
use crate::llm::types::LlmProvider;
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub gitlab_token: Option<String>,
    pub gitlab_base_url: Option<String>,
    pub llm: LlmConfig,
    pub privacy: PrivacyConfig,
    pub review: ReviewConfig,
    pub inline: InlineConfig,
    pub publish: PublishConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: String,
    pub ollama_base_url: String,
    pub model: String,
    pub timeout_seconds: u64,
    pub max_context_tokens: u32,
    pub temperature: f64,
    pub codex_timeout_seconds: u64,
    pub codex_bin: String,
    pub codex_full_auto: bool,
    pub gemini_timeout_seconds: u64,
    pub gemini_bin: String,
    pub gemini_output_format: String,
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

#[derive(Debug, Clone)]
pub struct InlineConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub dedupe: bool,
    pub max_inline_total: usize,
    pub max_high_inline: usize,
    pub max_medium_inline: usize,
}

#[derive(Debug, Clone)]
pub struct PublishConfig {
    pub max_note_chars: usize,
    pub internal_note: bool,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub enabled: bool,
    pub db_path: PathBuf,
    pub store_raw_diff: bool,
    pub store_raw_llm: bool,
    pub verify_max_previous_findings: usize,
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
    timeout_seconds: Option<u64>,
    max_context_tokens: Option<u32>,
    temperature: Option<f64>,
    codex_timeout_seconds: Option<u64>,
    codex_bin: Option<String>,
    codex_full_auto: Option<bool>,
    gemini_timeout_seconds: Option<u64>,
    gemini_bin: Option<String>,
    gemini_output_format: Option<String>,
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
            .unwrap_or_else(|| "gemini_cli".to_string());
        let ollama_base_url = env::var("OLLAMA_BASE_URL")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.ollama_base_url.clone()))
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        let model = env::var("REVIEWGATE_MODEL")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.model.clone()))
            .unwrap_or_else(|| default_model_for_provider(&provider).to_string());
        let timeout_seconds = env::var("REVIEWGATE_LLM_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| file_llm.and_then(|llm| llm.timeout_seconds))
            .unwrap_or(180);
        let max_context_tokens = env::var("REVIEWGATE_MAX_CONTEXT_TOKENS")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| file_llm.and_then(|llm| llm.max_context_tokens))
            .unwrap_or(12_000);
        let temperature = env::var("REVIEWGATE_TEMPERATURE")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| file_llm.and_then(|llm| llm.temperature))
            .unwrap_or(0.1);
        let codex_timeout_seconds = env::var("REVIEWGATE_CODEX_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| file_llm.and_then(|llm| llm.codex_timeout_seconds))
            .unwrap_or(240);
        let codex_bin = env::var("REVIEWGATE_CODEX_BIN")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.codex_bin.clone()))
            .unwrap_or_else(|| "codex".to_string());
        let codex_full_auto = env_bool("REVIEWGATE_CODEX_FULL_AUTO")
            .or_else(|| file_llm.and_then(|llm| llm.codex_full_auto))
            .unwrap_or(false);
        let gemini_timeout_seconds = env::var("REVIEWGATE_GEMINI_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| file_llm.and_then(|llm| llm.gemini_timeout_seconds))
            .unwrap_or(240);
        let gemini_bin = env::var("REVIEWGATE_GEMINI_BIN")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.gemini_bin.clone()))
            .unwrap_or_else(|| "gemini".to_string());
        let gemini_output_format = env::var("REVIEWGATE_GEMINI_OUTPUT_FORMAT")
            .ok()
            .or_else(|| file_llm.and_then(|llm| llm.gemini_output_format.clone()))
            .unwrap_or_else(|| "json".to_string());

        let file_privacy = file_config.privacy.as_ref();
        let privacy = PrivacyConfig {
            local_only: env_bool("REVIEWGATE_LOCAL_ONLY")
                .or_else(|| file_privacy.and_then(|privacy| privacy.local_only))
                .unwrap_or_else(|| default_local_only_for_provider(&provider)),
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
        let inline = InlineConfig {
            enabled: env_bool("REVIEWGATE_INLINE_ENABLED").unwrap_or(false),
            dry_run: env_bool("REVIEWGATE_INLINE_DRY_RUN").unwrap_or(true),
            dedupe: env_bool("REVIEWGATE_INLINE_DEDUPE").unwrap_or(true),
            max_inline_total: env::var("REVIEWGATE_MAX_INLINE_TOTAL")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(10),
            max_high_inline: env::var("REVIEWGATE_MAX_HIGH_INLINE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8),
            max_medium_inline: env::var("REVIEWGATE_MAX_MEDIUM_INLINE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5),
        };
        let publish = PublishConfig {
            max_note_chars: env::var("REVIEWGATE_PUBLISH_MAX_NOTE_CHARS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(60_000),
            internal_note: env_bool("REVIEWGATE_GITLAB_INTERNAL_NOTE").unwrap_or(false),
        };
        let storage = StorageConfig {
            enabled: env_bool("REVIEWGATE_STORAGE_ENABLED").unwrap_or(true),
            db_path: env::var("REVIEWGATE_DB_PATH")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".reviewgate/reviewgate.sqlite")),
            store_raw_diff: env_bool("REVIEWGATE_STORE_RAW_DIFF").unwrap_or(false),
            store_raw_llm: env_bool("REVIEWGATE_STORE_RAW_LLM").unwrap_or(false),
            verify_max_previous_findings: env::var("REVIEWGATE_VERIFY_MAX_PREVIOUS_FINDINGS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
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
                timeout_seconds,
                max_context_tokens,
                temperature,
                codex_timeout_seconds,
                codex_bin,
                codex_full_auto,
                gemini_timeout_seconds,
                gemini_bin,
                gemini_output_format,
            },
            privacy,
            review,
            inline,
            publish,
            storage,
        })
    }

    pub fn validate_for_preview(&self) -> Result<()> {
        match LlmProvider::parse(&self.llm.provider)? {
            LlmProvider::Ollama => {
                if self.llm.ollama_base_url.trim().is_empty() {
                    return Err(ReviewGateError::Config(
                        "OLLAMA_BASE_URL must not be empty".to_string(),
                    ));
                }
            }
            LlmProvider::CodexCli => {
                if self.llm.codex_bin.trim().is_empty() {
                    return Err(ReviewGateError::Config(
                        "REVIEWGATE_CODEX_BIN must not be empty".to_string(),
                    ));
                }
                if self.llm.codex_full_auto {
                    return Err(ReviewGateError::Config(
                        "REVIEWGATE_CODEX_FULL_AUTO=true is not supported for ReviewGate codex_cli because this provider must stay read-only".to_string(),
                    ));
                }
            }
            LlmProvider::GeminiCli => {
                if self.llm.gemini_bin.trim().is_empty() {
                    return Err(ReviewGateError::Config(
                        "REVIEWGATE_GEMINI_BIN must not be empty".to_string(),
                    ));
                }
                let output_format = self.llm.gemini_output_format.trim();
                if output_format.is_empty() {
                    return Err(ReviewGateError::Config(
                        "REVIEWGATE_GEMINI_OUTPUT_FORMAT must not be empty".to_string(),
                    ));
                }
            }
        }
        if self.llm.model.trim().is_empty() {
            return Err(ReviewGateError::Config(
                "REVIEWGATE_MODEL must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

fn default_model_for_provider(provider: &str) -> &'static str {
    match LlmProvider::parse(provider) {
        Ok(LlmProvider::Ollama) => "qwen2.5-coder:7b",
        Ok(LlmProvider::CodexCli) => "gpt-5.2-codex",
        Ok(LlmProvider::GeminiCli) | Err(_) => "gemini-2.5-pro",
    }
}

fn default_local_only_for_provider(provider: &str) -> bool {
    matches!(LlmProvider::parse(provider), Ok(LlmProvider::Ollama))
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

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, InlineConfig, LlmConfig, PrivacyConfig, PublishConfig, ReviewConfig,
        StorageConfig,
    };
    use crate::error::ReviewGateError;

    #[test]
    fn unsupported_provider_returns_guard_error() {
        let config = config_with_provider("openai");

        let err = config.validate_for_preview().unwrap_err();

        assert!(matches!(err, ReviewGateError::UnsupportedLlmProvider(_)));
        assert!(err.to_string().contains("unsupported LLM provider"));
    }

    #[test]
    fn codex_cli_provider_is_supported_by_config_validation() {
        let config = config_with_provider("codex_cli");

        config.validate_for_preview().unwrap();
    }

    #[test]
    fn gemini_cli_provider_is_supported_by_config_validation() {
        let config = config_with_provider("gemini_cli");

        config.validate_for_preview().unwrap();
    }

    #[test]
    fn empty_provider_returns_guard_error() {
        let config = config_with_provider("");

        let err = config.validate_for_preview().unwrap_err();

        assert!(matches!(err, ReviewGateError::UnsupportedLlmProvider(_)));
    }

    #[test]
    fn codex_full_auto_fails_closed() {
        let mut config = config_with_provider("codex_cli");
        config.llm.codex_full_auto = true;

        let err = config.validate_for_preview().unwrap_err();

        assert!(err.to_string().contains("read-only"));
    }

    fn config_with_provider(provider: &str) -> AppConfig {
        AppConfig {
            gitlab_token: Some("token".to_string()),
            gitlab_base_url: None,
            llm: LlmConfig {
                provider: provider.to_string(),
                ollama_base_url: "http://localhost:11434".to_string(),
                model: "qwen2.5-coder:7b".to_string(),
                timeout_seconds: 180,
                max_context_tokens: 12000,
                temperature: 0.1,
                codex_timeout_seconds: 240,
                codex_bin: "codex".to_string(),
                codex_full_auto: false,
                gemini_timeout_seconds: 240,
                gemini_bin: "gemini".to_string(),
                gemini_output_format: "json".to_string(),
            },
            privacy: PrivacyConfig {
                local_only: true,
                redact_secrets: true,
            },
            review: ReviewConfig {
                max_inline_comments: 8,
                severity_threshold: "medium".to_string(),
                max_diff_bytes: 200_000,
                max_files: 50,
            },
            inline: InlineConfig {
                enabled: false,
                dry_run: true,
                dedupe: true,
                max_inline_total: 10,
                max_high_inline: 8,
                max_medium_inline: 5,
            },
            publish: PublishConfig {
                max_note_chars: 60_000,
                internal_note: false,
            },
            storage: StorageConfig {
                enabled: true,
                db_path: ".reviewgate/reviewgate.sqlite".into(),
                store_raw_diff: false,
                store_raw_llm: false,
                verify_max_previous_findings: 30,
            },
        }
    }
}
