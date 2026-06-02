use crate::{
    config::{AppConfig, GitLabTokenSource},
    error::Result,
    llm::{external_model_call_label, provider_local_only, types::LlmProvider},
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct DoctorOptions {
    pub network: bool,
}

pub async fn run_doctor(options: DoctorOptions) -> Result<String> {
    let config = AppConfig::load()?;
    Ok(build_doctor_output(&config, options).await)
}

pub async fn build_doctor_output(config: &AppConfig, options: DoctorOptions) -> String {
    let mut output = String::new();
    output.push_str("ReviewGate Doctor\n\n");
    output.push_str("✅ Config loaded\n");
    output.push_str(&format!("✅ Provider: {}\n", config.llm.provider));
    output.push_str(&token_source_line(config));
    output.push_str(&sqlite_line(&config.storage.db_path));
    output.push_str(&reviewgate_dir_line(&config.storage.db_path));
    output.push_str(&ci_line());

    match LlmProvider::parse(&config.llm.provider) {
        Ok(LlmProvider::GeminiCli) => {
            output.push_str(&format!(
                "⚠️ External model call: {}\n",
                external_model_call_label(&config.llm)
            ));
            output.push_str(&binary_line("Gemini CLI", &config.llm.gemini_bin));
            if options.network {
                output.push_str(&cli_preflight_line("Gemini CLI", &config.llm.gemini_bin));
            }
        }
        Ok(LlmProvider::CodexCli) => {
            output.push_str(&format!(
                "⚠️ External model call: {}\n",
                external_model_call_label(&config.llm)
            ));
            output.push_str(&binary_line("Codex CLI", &config.llm.codex_bin));
            if options.network {
                output.push_str(&cli_preflight_line("Codex CLI", &config.llm.codex_bin));
            }
        }
        Ok(LlmProvider::Ollama) => {
            output.push_str(&format!(
                "✅ Local-only model mode: {}\n",
                provider_local_only(&config.llm)
            ));
            output.push_str(&ollama_provider_line(config));
            if options.network {
                output.push_str(&ollama_reachability_line(&config.llm.ollama_base_url).await);
            }
        }
        Err(err) => {
            output.push_str(&format!("❌ Provider validation: {err}\n"));
        }
    }

    if options.network {
        output.push_str(&gitlab_reachability_line(config).await);
    } else {
        output.push_str("ℹ️ Network checks: skipped (use --network)\n");
    }

    output
}

fn token_source_line(config: &AppConfig) -> String {
    match config.gitlab_token_source {
        Some(source) => format!(
            "✅ GitLab token source: {}\n",
            gitlab_token_source_label(source)
        ),
        None => "⚠️ GitLab token source: missing (set GITLAB_TOKEN or REVIEWGATE_GITLAB_TOKEN)\n"
            .to_string(),
    }
}

pub fn gitlab_token_source_label(source: GitLabTokenSource) -> &'static str {
    match source {
        GitLabTokenSource::GitLabToken => "GITLAB_TOKEN",
        GitLabTokenSource::ReviewGateGitLabToken => "REVIEWGATE_GITLAB_TOKEN",
        GitLabTokenSource::CiJobToken => "CI_JOB_TOKEN",
    }
}

fn sqlite_line(db_path: &Path) -> String {
    if path_writable_for_db(db_path) {
        format!("✅ SQLite path writable: {}\n", db_path.display())
    } else {
        format!(
            "⚠️ SQLite path may not be writable: {}\n",
            db_path.display()
        )
    }
}

fn reviewgate_dir_line(db_path: &Path) -> String {
    let dir = db_path.parent().unwrap_or_else(|| Path::new("."));
    if dir.exists() {
        if dir.is_dir() {
            format!("✅ {} status: present\n", dir.display())
        } else {
            format!(
                "⚠️ {} status: exists but is not a directory\n",
                dir.display()
            )
        }
    } else {
        format!(
            "⚠️ {} status: missing, will be created when storage opens\n",
            dir.display()
        )
    }
}

fn ci_line() -> String {
    if env::var("GITLAB_CI").ok().as_deref() == Some("true") {
        let source = env::var("CI_PIPELINE_SOURCE").unwrap_or_else(|_| "unknown".to_string());
        format!("✅ GitLab CI detected: {source}\n")
    } else {
        "ℹ️ GitLab CI detected: no\n".to_string()
    }
}

fn binary_line(label: &str, binary: &str) -> String {
    if command_exists(binary) {
        format!("✅ {label} found: {binary}\n")
    } else {
        format!("⚠️ {label} not found on PATH: {binary}\n")
    }
}

fn ollama_provider_line(config: &AppConfig) -> String {
    if command_exists("ollama") {
        "✅ Ollama CLI found: ollama\n".to_string()
    } else if !config.llm.ollama_base_url.trim().is_empty() {
        format!("✅ Ollama URL configured: {}\n", config.llm.ollama_base_url)
    } else {
        "⚠️ Ollama CLI not found and OLLAMA_BASE_URL is empty\n".to_string()
    }
}

fn cli_preflight_line(label: &str, binary: &str) -> String {
    if !command_exists(binary) {
        return format!("⚠️ {label} preflight skipped: binary not found\n");
    }

    match Command::new(binary).arg("--version").output() {
        Ok(output) if output.status.success() => format!("✅ {label} preflight passed\n"),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr
                .lines()
                .next()
                .unwrap_or("command returned a non-zero status");
            format!("⚠️ {label} preflight warning: {message}\n")
        }
        Err(err) => format!("⚠️ {label} preflight warning: {err}\n"),
    }
}

async fn gitlab_reachability_line(config: &AppConfig) -> String {
    let Some(base_url) = config
        .gitlab_base_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return "⚠️ GitLab reachability: skipped, base URL not configured\n".to_string();
    };

    match http_get_reachable(base_url).await {
        Ok(()) => format!("✅ GitLab base URL reachable: {base_url}\n"),
        Err(err) => format!("⚠️ GitLab base URL not reachable: {base_url} ({err})\n"),
    }
}

async fn ollama_reachability_line(base_url: &str) -> String {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    match http_get_reachable(&url).await {
        Ok(()) => format!("✅ Ollama reachable: {base_url}\n"),
        Err(err) => format!("⚠️ Ollama not reachable: {base_url} ({err})\n"),
    }
}

async fn http_get_reachable(url: &str) -> std::result::Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent(format!("reviewgate/{} doctor", env!("CARGO_PKG_VERSION")))
        .build()?;
    client.get(url).send().await?.error_for_status()?;
    Ok(())
}

fn path_writable_for_db(db_path: &Path) -> bool {
    let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
    if parent.exists() {
        return probe_writable_dir(parent);
    }

    nearest_existing_ancestor(parent)
        .as_deref()
        .is_some_and(probe_writable_dir)
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path;
    loop {
        if current.exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn probe_writable_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".reviewgate-doctor-{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

fn command_exists(binary: &str) -> bool {
    let binary = binary.trim();
    if binary.is_empty() {
        return false;
    }
    let path = Path::new(binary);
    if path.components().count() > 1 {
        return path.is_file();
    }
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| dir.join(binary).is_file())
}

#[cfg(test)]
mod tests {
    use super::{build_doctor_output, gitlab_token_source_label, DoctorOptions};
    use crate::config::{
        AppConfig, CiConfig, GitLabTokenSource, InlineConfig, LlmConfig, PrivacyConfig,
        PublishConfig, ReviewConfig, StorageConfig,
    };

    #[test]
    fn token_source_labels_do_not_include_token_values() {
        assert_eq!(
            gitlab_token_source_label(GitLabTokenSource::GitLabToken),
            "GITLAB_TOKEN"
        );
        assert_eq!(
            gitlab_token_source_label(GitLabTokenSource::ReviewGateGitLabToken),
            "REVIEWGATE_GITLAB_TOKEN"
        );
    }

    #[tokio::test]
    async fn default_doctor_skips_network_and_redacts_token_value() {
        let mut config = config_with_provider("gemini_cli");
        config.gitlab_token = Some("super-secret-token".to_string());

        let output = build_doctor_output(&config, DoctorOptions { network: false }).await;

        assert!(output.contains("ReviewGate Doctor"));
        assert!(output.contains("Config loaded"));
        assert!(output.contains("Provider: gemini_cli"));
        assert!(output.contains("GitLab token source: GITLAB_TOKEN"));
        assert!(output.contains("Network checks: skipped"));
        assert!(!output.contains("super-secret-token"));
    }

    fn config_with_provider(provider: &str) -> AppConfig {
        AppConfig {
            gitlab_token: Some("token".to_string()),
            gitlab_token_source: Some(GitLabTokenSource::GitLabToken),
            gitlab_base_url: Some("https://gitlab.example.com".to_string()),
            llm: LlmConfig {
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
            },
            privacy: PrivacyConfig {
                local_only: false,
                redact_secrets: true,
            },
            review: ReviewConfig {
                max_inline_comments: 8,
                severity_threshold: "medium".to_string(),
                max_diff_bytes: 200_000,
                max_files: 50,
            },
            current_file_validation: crate::config::CurrentFileValidationConfig {
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
