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

    #[error(
        "GitLab token does not have permission to access or write to this project or merge request"
    )]
    GitLabForbidden,

    #[error("GitLab project or merge request was not found")]
    GitLabNotFound,

    #[error("GitLab rate limit exceeded. Retry later")]
    GitLabRateLimited,

    #[error("cannot reach GitLab base URL. Check VPN connection or GitLab base URL")]
    GitLabUnreachable,

    #[error("GitLab request timed out. Check VPN connection or GitLab responsiveness")]
    GitLabTimeout,

    #[error("GitLab response was malformed: {0}")]
    MalformedGitLabResponse(String),

    #[error("GitLab merge request diff refs are required for inline publishing")]
    MissingGitLabDiffRefs,

    #[error("GitLab does not support the requested API parameter: {0}")]
    UnsupportedGitLabParameter(String),

    #[error("GitLab API error: {0}")]
    GitLabApi(String),

    #[error("GitLab validation error: {0}")]
    GitLabValidation(String),

    #[error("publish attempted with empty ReviewGate markdown")]
    PublishEmptyMarkdown,

    #[error("GitLab note body is too large after truncation. Increase REVIEWGATE_PUBLISH_MAX_NOTE_CHARS")]
    PublishNoteBodyTooLarge,

    #[error("model output could not be parsed into structured ReviewGate markdown, so publishing was skipped")]
    PublishRequiresParsedReview,

    #[error("--publish-inline requires --publish")]
    PublishInlineRequiresPublish,

    #[error("inline comment body is empty")]
    EmptyInlineCommentBody,

    #[error("cannot reach Ollama at {0}. Start Ollama or configure another model provider")]
    OllamaUnreachable(String),

    #[error("Ollama request timed out after {seconds} seconds. Check model load time or increase REVIEWGATE_LLM_TIMEOUT_SECONDS")]
    OllamaTimeout { seconds: u64 },

    #[error("Ollama model '{0}' was not found. Pull it with: ollama pull {0}")]
    OllamaModelNotFound(String),

    #[error("Ollama response was malformed: {0}")]
    InvalidOllamaResponse(String),

    #[error("Ollama returned an empty model response")]
    EmptyModelResponse,

    #[error("Ollama API error: {0}")]
    OllamaApi(String),

    #[error("Only Ollama provider is implemented in this version.")]
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
