use thiserror::Error;

pub type Result<T> = std::result::Result<T, ReviewGateError>;

#[derive(Debug, Error)]
pub enum ReviewGateError {
    #[error("invalid GitLab merge request URL: {0}")]
    InvalidMrUrl(String),

    #[error("GITLAB_TOKEN is required for GitLab API access")]
    MissingGitLabToken,

    #[error("GitLab token is invalid or missing required scope")]
    InvalidGitLabToken,

    #[error("cannot reach GitLab base URL. Check VPN connection or GitLab base URL")]
    GitLabUnreachable,

    #[error("GitLab API error: {0}")]
    GitLabApi(String),

    #[error("cannot reach Ollama at {0}. Start Ollama or configure another model provider")]
    OllamaUnreachable(String),

    #[error("Ollama API error: {0}")]
    OllamaApi(String),

    #[error("unsupported LLM provider '{0}'. v0.1 supports ollama only")]
    UnsupportedLlmProvider(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
