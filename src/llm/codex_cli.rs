use crate::{
    config::LlmConfig,
    error::{Result, ReviewGateError},
    llm::types::{LlmReviewResponse, LlmRunMetadata},
};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct CodexCliClient {
    codex_bin: String,
    model: String,
    timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexCommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexProcessOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub last_message: Option<String>,
}

#[derive(Debug)]
struct TempRunDir {
    path: PathBuf,
}

impl CodexCliClient {
    pub fn from_config(config: &LlmConfig) -> Result<Self> {
        Ok(Self {
            codex_bin: config.codex_bin.clone(),
            model: config.model.clone(),
            timeout_seconds: config.codex_timeout_seconds,
        })
    }

    pub fn review(&self, prompt: &str) -> Result<LlmReviewResponse> {
        preflight_codex_cli(&self.codex_bin)?;

        let temp_dir = TempRunDir::create()?;
        let prompt_file = temp_dir.path.join("reviewgate_prompt.txt");
        let output_file = temp_dir.path.join("reviewgate_codex_output.txt");
        fs::write(&prompt_file, prompt)?;

        let model_prompt = codex_review_prompt(prompt);
        let spec =
            build_codex_exec_command(&self.codex_bin, &self.model, &temp_dir.path, &output_file);
        let output = run_codex_command(
            &spec,
            &model_prompt,
            Duration::from_secs(self.timeout_seconds),
        )?;
        let text = parse_codex_process_output(output)?;

        Ok(LlmReviewResponse {
            text,
            metadata: LlmRunMetadata::default(),
        })
    }
}

pub fn preflight_codex_cli(codex_bin: &str) -> Result<()> {
    run_preflight_command(codex_bin, &["--version"])?;
    let status = run_preflight_command(codex_bin, &["login", "status"])?;
    if !status.to_ascii_lowercase().contains("logged in") {
        return Err(ReviewGateError::CodexNotAuthenticated);
    }
    Ok(())
}

pub fn build_codex_exec_command(
    codex_bin: &str,
    model: &str,
    work_dir: &Path,
    output_file: &Path,
) -> CodexCommandSpec {
    CodexCommandSpec {
        program: codex_bin.to_string(),
        args: vec![
            "exec".to_string(),
            "--model".to_string(),
            model.to_string(),
            "--sandbox".to_string(),
            "read-only".to_string(),
            "--cd".to_string(),
            work_dir.display().to_string(),
            "--skip-git-repo-check".to_string(),
            "--ephemeral".to_string(),
            "--ignore-rules".to_string(),
            "--color".to_string(),
            "never".to_string(),
            "--output-last-message".to_string(),
            output_file.display().to_string(),
            "-".to_string(),
        ],
    }
}

pub fn codex_review_prompt(reviewgate_prompt: &str) -> String {
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

pub fn parse_codex_process_output(output: CodexProcessOutput) -> Result<String> {
    if !output.success {
        if looks_like_auth_error(&output.stderr) || looks_like_auth_error(&output.stdout) {
            return Err(ReviewGateError::CodexNotAuthenticated);
        }
        return Err(ReviewGateError::CodexCommandFailed(sanitize_process_text(
            &output.stderr,
        )));
    }

    let text = output
        .last_message
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&output.stdout)
        .trim()
        .to_string();

    if text.is_empty() {
        return Err(ReviewGateError::CodexEmptyResponse);
    }

    Ok(text)
}

fn run_preflight_command(codex_bin: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(codex_bin)
        .args(args)
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(map_codex_spawn_error)?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if looks_like_auth_error(&stdout) || looks_like_auth_error(&stderr) {
            return Err(ReviewGateError::CodexNotAuthenticated);
        }
        return Err(ReviewGateError::CodexCommandFailed(sanitize_process_text(
            &stderr,
        )));
    }

    Ok(if stdout.trim().is_empty() {
        stderr
    } else {
        stdout
    })
}

fn run_codex_command(
    spec: &CodexCommandSpec,
    prompt: &str,
    timeout: Duration,
) -> Result<CodexProcessOutput> {
    let mut child = Command::new(&spec.program)
        .args(&spec.args)
        .env_remove("OPENAI_API_KEY")
        .env_remove("CODEX_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_codex_spawn_error)?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes())?;
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(read_pipe_async);
    let stderr_reader = stderr.map(read_pipe_async);
    let start = Instant::now();

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ReviewGateError::CodexTimeout {
                seconds: timeout.as_secs(),
            });
        }
        thread::sleep(Duration::from_millis(50));
    };

    let stdout = stdout_reader
        .map(|reader| reader.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_reader
        .map(|reader| reader.join().unwrap_or_default())
        .unwrap_or_default();
    let last_message = output_last_message(&spec.args);

    Ok(CodexProcessOutput {
        success: status.success(),
        stdout,
        stderr,
        last_message,
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

fn output_last_message(args: &[String]) -> Option<String> {
    let path = args
        .windows(2)
        .find(|window| window[0] == "--output-last-message")
        .map(|window| PathBuf::from(&window[1]))?;
    fs::read_to_string(path).ok()
}

fn map_codex_spawn_error(err: std::io::Error) -> ReviewGateError {
    if err.kind() == std::io::ErrorKind::NotFound {
        ReviewGateError::CodexBinaryNotFound
    } else {
        ReviewGateError::Io(err)
    }
}

fn looks_like_auth_error(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("not authenticated")
        || lower.contains("not logged in")
        || lower.contains("please log in")
        || lower.contains("run codex login")
        || lower.contains("run `codex login`")
        || lower.contains("login required")
        || lower.contains("authentication required")
        || lower.contains("no credentials")
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
            !lower.contains("token") && !lower.contains("credential")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if output.trim().is_empty() {
        "Codex CLI failed; stderr was redacted".to_string()
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
            env::temp_dir().join(format!("reviewgate-codex-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[allow(dead_code)]
fn _status_success(status: ExitStatus) -> bool {
    status.success()
}

#[cfg(test)]
mod tests {
    use super::{
        build_codex_exec_command, codex_review_prompt, parse_codex_process_output,
        CodexProcessOutput,
    };
    use crate::error::ReviewGateError;
    use std::path::Path;

    #[test]
    fn builds_read_only_codex_exec_command() {
        let spec = build_codex_exec_command(
            "codex",
            "gpt-5.2-codex",
            Path::new("/tmp/rg"),
            Path::new("/tmp/rg/out.txt"),
        );

        assert_eq!(spec.program, "codex");
        assert!(spec.args.contains(&"exec".to_string()));
        assert!(spec.args.contains(&"--model".to_string()));
        assert!(spec.args.contains(&"gpt-5.2-codex".to_string()));
        assert!(spec.args.contains(&"--sandbox".to_string()));
        assert!(spec.args.contains(&"read-only".to_string()));
        assert!(spec.args.contains(&"--ephemeral".to_string()));
        assert!(spec.args.contains(&"--ignore-rules".to_string()));
        assert!(spec.args.contains(&"-".to_string()));
        assert!(!spec
            .args
            .contains(&"--dangerously-bypass-approvals-and-sandbox".to_string()));
    }

    #[test]
    fn prompt_tells_codex_not_to_modify_or_run_commands() {
        let prompt = codex_review_prompt("ReviewGate prompt body");

        assert!(prompt.contains("Do not modify files"));
        assert!(prompt.contains("Do not run commands"));
        assert!(prompt.contains("Return JSON only"));
        assert!(prompt.contains("ReviewGate prompt body"));
    }

    #[test]
    fn parses_stdout_json() {
        let parsed = parse_codex_process_output(CodexProcessOutput {
            success: true,
            stdout: r#"{"summary":"ok"}"#.to_string(),
            stderr: String::new(),
            last_message: None,
        })
        .unwrap();

        assert_eq!(parsed, r#"{"summary":"ok"}"#);
    }

    #[test]
    fn prefers_output_last_message_over_stdout_events() {
        let parsed = parse_codex_process_output(CodexProcessOutput {
            success: true,
            stdout: "event logs".to_string(),
            stderr: String::new(),
            last_message: Some(r#"{"summary":"ok"}"#.to_string()),
        })
        .unwrap();

        assert_eq!(parsed, r#"{"summary":"ok"}"#);
    }

    #[test]
    fn empty_stdout_returns_clear_error() {
        let err = parse_codex_process_output(CodexProcessOutput {
            success: true,
            stdout: "  ".to_string(),
            stderr: String::new(),
            last_message: None,
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::CodexEmptyResponse));
    }

    #[test]
    fn non_zero_exit_status_returns_command_failed() {
        let err = parse_codex_process_output(CodexProcessOutput {
            success: false,
            stdout: String::new(),
            stderr: "boom".to_string(),
            last_message: None,
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::CodexCommandFailed(_)));
    }

    #[test]
    fn auth_failure_maps_to_login_message() {
        let err = parse_codex_process_output(CodexProcessOutput {
            success: false,
            stdout: String::new(),
            stderr: "not authenticated".to_string(),
            last_message: None,
        })
        .unwrap_err();

        assert!(matches!(err, ReviewGateError::CodexNotAuthenticated));
    }
}
