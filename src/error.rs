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

    #[error("Codex CLI binary was not found. Install Codex CLI or set REVIEWGATE_CODEX_BIN")]
    CodexBinaryNotFound,

    #[error("Codex CLI is not authenticated. Run `codex login` first, then retry.")]
    CodexNotAuthenticated,

    #[error("Codex CLI command failed: {0}")]
    CodexCommandFailed(String),

    #[error("Codex CLI request timed out after {seconds} seconds. Check model load time or increase REVIEWGATE_CODEX_TIMEOUT_SECONDS")]
    CodexTimeout { seconds: u64 },

    #[error("Codex CLI returned an empty model response")]
    CodexEmptyResponse,

    #[error("Gemini CLI binary was not found. Install Gemini CLI or set REVIEWGATE_GEMINI_BIN")]
    GeminiBinaryNotFound,

    #[error("Gemini CLI is not authenticated. Run `gemini` once and choose Login with Google, or configure Gemini CLI auth, then retry.")]
    GeminiNotAuthenticated,

    #[error("Gemini CLI command failed: {0}")]
    GeminiCommandFailed(String),

    #[error("Gemini CLI request timed out after {seconds} seconds. Check model load time or increase REVIEWGATE_GEMINI_TIMEOUT_SECONDS")]
    GeminiTimeout { seconds: u64 },

    #[error("Gemini CLI returned an empty model response")]
    GeminiEmptyResponse,

    #[error(
        "unsupported LLM provider. Use REVIEWGATE_LLM_PROVIDER=gemini_cli, codex_cli, or ollama"
    )]
    UnsupportedLlmProvider(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
