use crate::error::{Result, ReviewGateError};
use crate::llm::types::LlmProvider;
use serde::Deserialize;
use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct AppConfig {
    pub gitlab_token: Option<String>,
    pub gitlab_token_source: Option<GitLabTokenSource>,
    pub gitlab_base_url: Option<String>,
    pub llm: LlmConfig,
    pub privacy: PrivacyConfig,
    pub review: ReviewConfig,
    pub current_file_validation: CurrentFileValidationConfig,
    pub inline: InlineConfig,
    pub publish: PublishConfig,
    pub storage: StorageConfig,
    pub ci: CiConfig,
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
pub struct CurrentFileValidationConfig {
    pub enabled: bool,
    pub validate_priority_with_model: bool,
    pub max_file_bytes: usize,
    pub context_lines: usize,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitLabTokenSource {
    GitLabToken,
    ReviewGateGitLabToken,
    CiJobToken,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GitLabTokenSelection {
    pub token: String,
    pub source: GitLabTokenSource,
}

impl fmt::Debug for GitLabTokenSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabTokenSelection")
            .field("token", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct CiConfig {
    pub allow_ci_job_token: bool,
    pub history_required: bool,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field(
                "gitlab_token",
                &self.gitlab_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("gitlab_token_source", &self.gitlab_token_source)
            .field("gitlab_base_url", &self.gitlab_base_url)
            .field("llm", &self.llm)
            .field("privacy", &self.privacy)
            .field("review", &self.review)
            .field("current_file_validation", &self.current_file_validation)
            .field("inline", &self.inline)
            .field("publish", &self.publish)
            .field("storage", &self.storage)
            .field("ci", &self.ci)
            .finish()
    }
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
        let current_file_validation = CurrentFileValidationConfig {
            enabled: env_bool("REVIEWGATE_CURRENT_FILE_VALIDATION").unwrap_or(true),
            validate_priority_with_model: env_bool("REVIEWGATE_VALIDATE_PRIORITY_WITH_MODEL")
                .unwrap_or(true),
            max_file_bytes: env::var("REVIEWGATE_MAX_VALIDATION_FILE_BYTES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(80_000),
            context_lines: env::var("REVIEWGATE_VALIDATION_CONTEXT_LINES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(40),
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
        let ci = CiConfig {
            allow_ci_job_token: env_bool("REVIEWGATE_ALLOW_CI_JOB_TOKEN").unwrap_or(false),
            history_required: env_bool("REVIEWGATE_CI_HISTORY_REQUIRED").unwrap_or(false),
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
        let gitlab_token = select_gitlab_token_from_env(ci.allow_ci_job_token)?;

        Ok(Self {
            gitlab_token: gitlab_token
                .as_ref()
                .map(|selection| selection.token.clone()),
            gitlab_token_source: gitlab_token.map(|selection| selection.source),
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
            current_file_validation,
            inline,
            publish,
            storage,
            ci,
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

fn select_gitlab_token_from_env(allow_ci_job_token: bool) -> Result<Option<GitLabTokenSelection>> {
    select_gitlab_token_from_values(
        env::var("GITLAB_TOKEN").ok(),
        env::var("REVIEWGATE_GITLAB_TOKEN").ok(),
        env::var("CI_JOB_TOKEN").ok(),
        allow_ci_job_token,
    )
}

pub fn select_gitlab_token_from_values(
    gitlab_token: Option<String>,
    reviewgate_gitlab_token: Option<String>,
    ci_job_token: Option<String>,
    allow_ci_job_token: bool,
) -> Result<Option<GitLabTokenSelection>> {
    if let Some(token) = non_empty(gitlab_token) {
        return Ok(Some(GitLabTokenSelection {
            token,
            source: GitLabTokenSource::GitLabToken,
        }));
    }

    if let Some(token) = non_empty(reviewgate_gitlab_token) {
        return Ok(Some(GitLabTokenSelection {
            token,
            source: GitLabTokenSource::ReviewGateGitLabToken,
        }));
    }

    if let Some(token) = non_empty(ci_job_token) {
        if allow_ci_job_token {
            return Ok(Some(GitLabTokenSelection {
                token,
                source: GitLabTokenSource::CiJobToken,
            }));
        }
        return Err(ReviewGateError::CiJobTokenNotAllowed);
    }

    Ok(None)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        select_gitlab_token_from_values, AppConfig, CiConfig, CurrentFileValidationConfig,
        GitLabTokenSource, InlineConfig, LlmConfig, PrivacyConfig, PublishConfig, ReviewConfig,
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

    #[test]
    fn token_selection_prefers_gitlab_token() {
        let selected = select_gitlab_token_from_values(
            Some("gitlab".to_string()),
            Some("reviewgate".to_string()),
            Some("job".to_string()),
            true,
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected.token, "gitlab");
        assert_eq!(selected.source, GitLabTokenSource::GitLabToken);
    }

    #[test]
    fn token_selection_uses_reviewgate_token_second() {
        let selected = select_gitlab_token_from_values(
            None,
            Some("reviewgate".to_string()),
            Some("job".to_string()),
            true,
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected.token, "reviewgate");
        assert_eq!(selected.source, GitLabTokenSource::ReviewGateGitLabToken);
    }

    #[test]
    fn ci_job_token_is_rejected_by_default() {
        let err = select_gitlab_token_from_values(None, None, Some("job".to_string()), false)
            .unwrap_err();

        assert!(matches!(err, ReviewGateError::CiJobTokenNotAllowed));
        assert_eq!(
            err.to_string(),
            "CI_JOB_TOKEN detected but not allowed by ReviewGate. Set REVIEWGATE_ALLOW_CI_JOB_TOKEN=true if your GitLab instance permits MR note publishing with CI job tokens, or provide GITLAB_TOKEN."
        );
    }

    #[test]
    fn ci_job_token_is_allowed_when_enabled() {
        let selected = select_gitlab_token_from_values(None, None, Some("job".to_string()), true)
            .unwrap()
            .unwrap();

        assert_eq!(selected.token, "job");
        assert_eq!(selected.source, GitLabTokenSource::CiJobToken);
    }

    #[test]
    fn app_config_debug_redacts_gitlab_token() {
        let mut config = config_with_provider("gemini_cli");
        config.gitlab_token = Some("secret-token".to_string());

        let debug = format!("{config:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
    }

    fn config_with_provider(provider: &str) -> AppConfig {
        AppConfig {
            gitlab_token: Some("token".to_string()),
            gitlab_token_source: Some(GitLabTokenSource::GitLabToken),
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
            current_file_validation: CurrentFileValidationConfig {
                enabled: true,
                validate_priority_with_model: true,
                max_file_bytes: 80_000,
                context_lines: 40,
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
            ci: CiConfig {
                allow_ci_job_token: false,
                history_required: false,
            },
        }
    }
}
