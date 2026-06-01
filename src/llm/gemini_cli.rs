use crate::{
    config::LlmConfig,
    error::{Result, ReviewGateError},
    llm::types::{LlmReviewResponse, LlmRunMetadata},
};
use serde::Deserialize;
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct GeminiCliClient {
    gemini_bin: String,
    model: String,
    timeout_seconds: u64,
    output_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiCommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiProcessOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Deserialize)]
struct GeminiWrapper {
    response: Option<String>,
    text: Option<String>,
    #[serde(default)]
    stats: Option<GeminiStats>,
    #[serde(default)]
    usage_metadata: Option<GeminiStats>,
}

#[derive(Debug, Deserialize)]
struct GeminiStats {
    #[serde(alias = "promptTokenCount", alias = "prompt_tokens")]
    prompt_token_count: Option<u64>,
    #[serde(
        alias = "candidatesTokenCount",
        alias = "candidateTokenCount",
        alias = "response_tokens",
        alias = "completion_tokens"
    )]
    candidates_token_count: Option<u64>,
    #[serde(alias = "totalTokenCount", alias = "total_tokens")]
    total_token_count: Option<u64>,
}

#[derive(Debug)]
struct TempRunDir {
    path: PathBuf,
}

impl GeminiCliClient {
    pub fn from_config(config: &LlmConfig) -> Result<Self> {
        Ok(Self {
            gemini_bin: config.gemini_bin.clone(),
            model: config.model.clone(),
            timeout_seconds: config.gemini_timeout_seconds,
            output_format: config.gemini_output_format.clone(),
        })
    }

    pub fn review(&self, prompt: &str) -> Result<LlmReviewResponse> {
        let supports_output_format = preflight_gemini_cli(&self.gemini_bin)?;
        let temp_dir = TempRunDir::create()?;
        let prompt_file = temp_dir.path.join("reviewgate_prompt.txt");
        fs::write(&prompt_file, prompt)?;

        let output_format = if supports_output_format {
            self.output_format.as_str()
        } else {
            "text"
        };
        let spec =
            build_gemini_command(&self.gemini_bin, &self.model, output_format, &temp_dir.path);
        let gemini_prompt = gemini_review_prompt(prompt);
        let output = run_gemini_command(
            &spec,
            &gemini_prompt,
            Duration::from_secs(self.timeout_seconds),
        )?;
        parse_gemini_process_output(output)
    }
}

pub fn preflight_gemini_cli(gemini_bin: &str) -> Result<bool> {
    match run_preflight_command(gemini_bin, &["--version"]) {
        Ok(_) => {}
        Err(ReviewGateError::GeminiCommandFailed(_)) => {
            run_preflight_command(gemini_bin, &["--help"])?;
        }
        Err(err) => return Err(err),
    }
    let help = run_preflight_command(gemini_bin, &["--help"])?;
    Ok(help.contains("--output-format"))
}

pub fn build_gemini_command(
    gemini_bin: &str,
    model: &str,
    output_format: &str,
    current_dir: &Path,
) -> GeminiCommandSpec {
    let mut args = vec![
        "--model".to_string(),
        model.to_string(),
        "--prompt".to_string(),
        "Return the ReviewGate JSON review for the provided sanitized diff. Output JSON only."
            .to_string(),
        "--approval-mode".to_string(),
        "plan".to_string(),
        "--sandbox".to_string(),
        "--skip-trust".to_string(),
    ];
    if !output_format.trim().is_empty() {
        args.push("--output-format".to_string());
        args.push(output_format.trim().to_string());
    }

    GeminiCommandSpec {
        program: gemini_bin.to_string(),
        args,
        current_dir: current_dir.to_path_buf(),
    }
}

pub fn gemini_review_prompt(reviewgate_prompt: &str) -> String {
    format!(
        r#"You are being invoked by ReviewGate as a read-only model backend.

Hard constraints:
- Do not modify files.
- Do not run commands.
- Do not inspect the repository.
- Review only the sanitized diff and metadata inside the ReviewGate prompt below.
- Return JSON only, with no markdown and no prose outside JSON.
- Include anchor_id and risk_code when available.
- Do not invent anchors.

ReviewGate prompt:
{reviewgate_prompt}
"#
    )
}

pub fn parse_gemini_process_output(output: GeminiProcessOutput) -> Result<LlmReviewResponse> {
    if !output.success {
        if looks_like_auth_error(&output.stderr) || looks_like_auth_error(&output.stdout) {
            return Err(ReviewGateError::GeminiNotAuthenticated);
        }
        return Err(ReviewGateError::GeminiCommandFailed(sanitize_process_text(
            &output.stderr,
        )));
    }

    let stdout = output.stdout.trim();
    if stdout.is_empty() {
        return Err(ReviewGateError::GeminiEmptyResponse);
    }

    if let Ok(wrapper) = serde_json::from_str::<GeminiWrapper>(stdout) {
        if let Some(response) = wrapper.response.or(wrapper.text) {
            if !response.trim().is_empty() {
                return Ok(LlmReviewResponse {
                    text: response.trim().to_string(),
                    metadata: metadata_from_stats(wrapper.stats.or(wrapper.usage_metadata)),
                });
            }
        }
    }

    Ok(LlmReviewResponse {
        text: stdout.to_string(),
        metadata: LlmRunMetadata::default(),
    })
}

fn metadata_from_stats(stats: Option<GeminiStats>) -> LlmRunMetadata {
    let Some(stats) = stats else {
        return LlmRunMetadata::default();
    };
    LlmRunMetadata {
        prompt_eval_count: stats.prompt_token_count,
        eval_count: stats.candidates_token_count.or_else(|| {
            stats
                .total_token_count
                .zip(stats.prompt_token_count)
                .map(|(total, prompt)| total.saturating_sub(prompt))
        }),
        ..LlmRunMetadata::default()
    }
}

fn run_preflight_command(gemini_bin: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(gemini_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(map_gemini_spawn_error)?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(ReviewGateError::GeminiCommandFailed(sanitize_process_text(
            &stderr,
        )));
    }

    Ok(if stdout.trim().is_empty() {
        stderr
    } else {
        stdout
    })
}

fn run_gemini_command(
    spec: &GeminiCommandSpec,
    prompt: &str,
    timeout: Duration,
) -> Result<GeminiProcessOutput> {
    let mut child = Command::new(&spec.program)
        .args(&spec.args)
        .current_dir(&spec.current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_gemini_spawn_error)?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes())?;
    }

    let stdout = child.stdout.take().map(read_pipe_async);
    let stderr = child.stderr.take().map(read_pipe_async);
    let start = Instant::now();

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ReviewGateError::GeminiTimeout {
                seconds: timeout.as_secs(),
            });
        }
        thread::sleep(Duration::from_millis(50));
    };

    Ok(GeminiProcessOutput {
        success: status.success(),
        stdout: stdout
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: stderr
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default(),
    })
}

fn read_pipe_async<R>(mut pipe: R) -> thread::JoinHandle<String>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut text = String::new();
        let _ = pipe.read_to_string(&mut text);
        text
    })
}

fn map_gemini_spawn_error(err: std::io::Error) -> ReviewGateError {
    if err.kind() == std::io::ErrorKind::NotFound {
        ReviewGateError::GeminiBinaryNotFound
    } else {
        ReviewGateError::Io(err)
    }
}

fn looks_like_auth_error(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("not authenticated")
        || lower.contains("not logged in")
        || lower.contains("please log in")
        || lower.contains("login required")
        || lower.contains("authentication required")
        || lower.contains("no credentials")
        || lower.contains("api key required")
}

fn sanitize_process_text(value: &str) -> String {
    let mut output = value.trim().chars().take(800).collect::<String>();
    if output.is_empty() {
        output = "empty stderr".to_string();
    }
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            output = output.replace(&home, "~");
        }
    }
    output = output
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("token")
                && !lower.contains("credential")
                && !lower.contains("api_key")
                && !lower.contains("apikey")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if output.trim().is_empty() {
        "Gemini CLI failed; stderr was redacted".to_string()
    } else {
        output
    }
}

impl TempRunDir {
    fn create() -> Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("reviewgate-gemini-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_gemini_command, gemini_review_prompt, parse_gemini_process_output,
        GeminiProcessOutput,
    };
    use crate::error::ReviewGateError;
    use std::path::Path;

    #[test]
    fn builds_safe_headless_gemini_command() {
        let spec = build_gemini_command("gemini", "gemini-2.5-pro", "json", Path::new("/tmp/rg"));

        assert_eq!(spec.program, "gemini");
        assert!(spec.args.contains(&"--model".to_string()));
        assert!(spec.args.contains(&"gemini-2.5-pro".to_string()));
        assert!(spec.args.contains(&"--prompt".to_string()));
        assert!(spec.args.contains(&"--approval-mode".to_string()));
        assert!(spec.args.contains(&"plan".to_string()));
        assert!(spec.args.contains(&"--sandbox".to_string()));
        assert!(spec.args.contains(&"--skip-trust".to_string()));
        assert!(spec.args.contains(&"--output-format".to_string()));
        assert!(spec.args.contains(&"json".to_string()));
        assert!(!spec.args.contains(&"--yolo".to_string()));
        assert!(!spec.args.contains(&"--all-files".to_string()));
    }

    #[test]
    fn prompt_tells_gemini_not_to_modify_or_run_commands() {
        let prompt = gemini_review_prompt("ReviewGate prompt body");

        assert!(prompt.contains("Do not modify files"));
        assert!(prompt.contains("Do not run commands"));
        assert!(prompt.contains("Return JSON only"));
        assert!(prompt.contains("ReviewGate prompt body"));
    }

    #[test]
    fn parses_wrapper_response_json_and_stats() {
        let parsed = parse_gemini_process_output(GeminiProcessOutput {
            success: true,
            stdout: r#"{
              "response":"{\"summary\":\"ok\"}",
              "stats":{"promptTokenCount": 10, "candidatesTokenCount": 4}
            }"#
            .to_string(),
            stderr: String::new(),
        })
        .unwrap();

        assert_eq!(parsed.text, r#"{"summary":"ok"}"#);
        assert_eq!(parsed.metadata.prompt_eval_count, Some(10));
        assert_eq!(parsed.metadata.eval_count, Some(4));
    }

    #[test]
    fn keeps_full_review_analysis_stdout() {
        let parsed = parse_gemini_process_output(GeminiProcessOutput {
            success: true,
            stdout: r#"{"summary":"ok","findings":[]}"#.to_string(),
            stderr: String::new(),
        })
        .unwrap();

        assert!(parsed.text.contains(r#""summary":"ok""#));
    }

    #[test]
    fn keeps_extra_text_for_tolerant_review_parser() {
        let parsed = parse_gemini_process_output(GeminiProcessOutput {
            success: true,
            stdout: "text before\n{\"summary\":\"ok\"}\ntext after".to_string(),
            stderr: String::new(),
        })
        .unwrap();

        assert!(parsed.text.contains("text before"));
        assert!(parsed.text.contains(r#""summary":"ok""#));
    }

    #[test]
    fn empty_stdout_returns_clear_error() {
        let err = parse_gemini_process_output(GeminiProcessOutput {
            success: true,
            stdout: " ".to_string(),
            stderr: String::new(),
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::GeminiEmptyResponse));
    }

    #[test]
    fn non_zero_exit_status_returns_command_failed() {
        let err = parse_gemini_process_output(GeminiProcessOutput {
            success: false,
            stdout: String::new(),
            stderr: "boom".to_string(),
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::GeminiCommandFailed(_)));
    }

    #[test]
    fn auth_failure_maps_to_login_message() {
        let err = parse_gemini_process_output(GeminiProcessOutput {
            success: false,
            stdout: String::new(),
            stderr: "not authenticated".to_string(),
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::GeminiNotAuthenticated));
    }
}
