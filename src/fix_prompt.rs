use crate::{
    counters::{
        count_stored_findings, emoji_enabled, format_finding_counters_terminal,
        format_verification_counters_terminal, FindingCounters, VerificationCounters,
    },
    error::{Result, ReviewGateError},
    gitlab::url::GitLabMrUrl,
    review::comparison::{
        compare_current_run_with_previous, format_comparison_terminal,
        format_comparison_terminal_default, ReviewComparison,
    },
    storage::{LatestReviewRun, Storage, StoredReviewFinding},
};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixPromptFormat {
    Markdown,
    Codex,
    Gemini,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FixPromptSeverity {
    Critical,
    High,
    Medium,
    Low,
    Note,
}

#[derive(Debug, Clone)]
pub struct FixPromptOptions {
    pub run_id: Option<String>,
    pub min_severity: FixPromptSeverity,
    pub include_notes: bool,
    pub format: FixPromptFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFixPrompt {
    pub run: LatestReviewRun,
    pub findings: Vec<StoredReviewFinding>,
    pub comparison: ReviewComparison,
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsSummary {
    pub run: LatestReviewRun,
    pub findings: Vec<StoredReviewFinding>,
    pub comparison: ReviewComparison,
    pub latest_verification: Option<VerificationCounters>,
}

impl FixPromptFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "markdown" => Ok(Self::Markdown),
            "codex" => Ok(Self::Codex),
            "gemini" => Ok(Self::Gemini),
            _ => Err(ReviewGateError::InvalidFixPromptFormat(value.to_string())),
        }
    }
}

impl FixPromptSeverity {
    pub fn parse_min(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Ok(Self::Critical),
            "HIGH" => Ok(Self::High),
            "MEDIUM" => Ok(Self::Medium),
            "LOW" => Ok(Self::Low),
            _ => Err(ReviewGateError::InvalidSeverity(value.to_string())),
        }
    }

    fn parse_stored(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Self::Critical),
            "HIGH" => Some(Self::High),
            "MEDIUM" => Some(Self::Medium),
            "LOW" => Some(Self::Low),
            "NOTE" => Some(Self::Note),
            _ => None,
        }
    }
}

pub fn effective_min_severity(
    min_severity: Option<&str>,
    include_low: bool,
) -> Result<FixPromptSeverity> {
    match min_severity {
        Some(value) => FixPromptSeverity::parse_min(value),
        None if include_low => Ok(FixPromptSeverity::Low),
        None => Ok(FixPromptSeverity::Medium),
    }
}

pub fn build_fix_prompt(
    storage: &Storage,
    mr: &GitLabMrUrl,
    options: FixPromptOptions,
) -> Result<GeneratedFixPrompt> {
    let run = select_run(storage, mr, options.run_id.as_deref())?;
    let findings = filtered_actionable_findings(
        storage.review_findings_for_run(&run.id)?,
        options.min_severity,
        options.include_notes,
    );
    if findings.is_empty() {
        return Err(ReviewGateError::NoActionableFindings);
    }
    let comparison =
        compare_current_run_with_previous(storage, &run.project_path, run.mr_iid, &run.id)?;

    let prompt = render_fix_prompt(
        &findings,
        options.format,
        comparison.previous_run_id.as_ref().map(|_| &comparison),
    );
    Ok(GeneratedFixPrompt {
        run,
        findings,
        comparison,
        prompt,
    })
}

pub fn latest_findings_summary(storage: &Storage, mr: &GitLabMrUrl) -> Result<FindingsSummary> {
    let run = select_run(storage, mr, None)?;
    let findings = storage.review_findings_for_run(&run.id)?;
    let comparison =
        compare_current_run_with_previous(storage, &run.project_path, run.mr_iid, &run.id)?;
    let latest_verification = storage.latest_verification_counters(&mr.project_path, mr.mr_iid)?;
    Ok(FindingsSummary {
        run,
        findings,
        comparison,
        latest_verification,
    })
}

pub fn write_prompt_output(path: &Path, prompt: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(ReviewGateError::OutputFileExists(
            path.display().to_string(),
        ));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, prompt)?;
    Ok(())
}

pub fn copy_to_clipboard(prompt: &str) -> Result<()> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["pbcopy"]
    } else if cfg!(target_os = "windows") {
        &["clip"]
    } else {
        &["wl-copy", "xclip", "xsel"]
    };

    for candidate in candidates {
        match copy_with_command(candidate, prompt) {
            Ok(()) => return Ok(()),
            Err(ClipboardCommandError::NotFound) => continue,
            Err(ClipboardCommandError::Failed(message)) => {
                return Err(ReviewGateError::ClipboardUnavailable(message));
            }
        }
    }

    Err(ReviewGateError::ClipboardUnavailable(format!(
        "no supported clipboard command found ({})",
        candidates.join(", ")
    )))
}

pub fn format_findings_summary(summary: &FindingsSummary) -> String {
    let mut output = String::new();
    output.push_str("ReviewGate latest findings summary\n");
    output.push_str(&format!("Run ID: {}\n", summary.run.id));
    output.push_str(&format!("MR URL: {}\n", summary.run.mr_url));
    output.push_str("Latest review:\n");
    output.push_str(&format_finding_counter_lines(
        &count_stored_findings(&summary.findings),
        emoji_enabled(),
    ));
    output.push_str(&format_comparison_terminal_default(&summary.comparison));
    output.push_str("Latest verification:\n");
    if let Some(counters) = summary.latest_verification.as_ref() {
        output.push_str(&format_verification_counter_lines(
            counters,
            emoji_enabled(),
        ));
    } else {
        output.push_str("- none\n");
    }
    output.push_str("Findings:\n");
    if summary.findings.is_empty() {
        output.push_str("- none\n");
    } else {
        for finding in &summary.findings {
            output.push_str(&format!(
                "- [{}] {} - {}\n",
                finding.severity,
                file_line_label(finding),
                finding.title
            ));
        }
    }
    output
}

fn select_run(
    storage: &Storage,
    mr: &GitLabMrUrl,
    run_id: Option<&str>,
) -> Result<LatestReviewRun> {
    if let Some(run_id) = run_id {
        return storage
            .completed_review_run_by_id_for_mr(run_id, &mr.project_path, mr.mr_iid)?
            .ok_or_else(|| ReviewGateError::ReviewRunNotFound(run_id.to_string()));
    }

    storage
        .latest_completed_review_run(&mr.project_path, mr.mr_iid)?
        .ok_or(ReviewGateError::NoPreviousReviewRun)
}

fn filtered_actionable_findings(
    findings: Vec<StoredReviewFinding>,
    min_severity: FixPromptSeverity,
    include_notes: bool,
) -> Vec<StoredReviewFinding> {
    findings
        .into_iter()
        .filter(|finding| finding.actionable)
        .filter(|finding| {
            let Some(severity) = FixPromptSeverity::parse_stored(&finding.severity) else {
                return false;
            };
            severity <= min_severity || (include_notes && severity == FixPromptSeverity::Note)
        })
        .collect()
}

fn render_fix_prompt(
    findings: &[StoredReviewFinding],
    format: FixPromptFormat,
    comparison: Option<&ReviewComparison>,
) -> String {
    let mut prompt = String::new();
    prompt.push_str(&render_fix_prompt_header(
        &count_stored_findings(findings),
        emoji_enabled(),
        comparison,
    ));
    prompt.push_str("You are an AI coding agent.\n\n");
    prompt.push_str("Fix only the ReviewGate findings listed below.\n\n");
    prompt.push_str("Rules:\n");
    prompt.push_str("- Keep changes minimal.\n");
    prompt
        .push_str("- Preserve existing behavior unless the finding requires a behavior change.\n");
    prompt.push_str("- Do not address unrelated refactors.\n");
    prompt.push_str("- Do not rename files unless necessary.\n");
    prompt.push_str(
        "- Add or update focused tests when the finding asks for tests or when behavior changes.\n",
    );
    prompt.push_str("- Do not introduce new dependencies unless necessary.\n");
    prompt.push_str("- After changes, run the relevant tests.\n");
    prompt.push_str(
        "- If a finding is unclear or cannot be fixed safely, leave a short note explaining why.\n",
    );

    match format {
        FixPromptFormat::Markdown => {}
        FixPromptFormat::Codex => {
            prompt.push_str("\nCodex-specific instructions:\n");
            prompt.push_str("- Do not run destructive commands.\n");
            prompt.push_str("- Inspect files first.\n");
            prompt.push_str("- Make a minimal patch.\n");
            prompt.push_str("- Run tests.\n");
            prompt.push_str("- Report changed files.\n");
        }
        FixPromptFormat::Gemini => {
            prompt.push_str("\nGemini-specific instructions:\n");
            prompt.push_str("- Do not use broad repo-wide edits.\n");
            prompt.push_str("- Do not use YOLO mode.\n");
            prompt.push_str("- Make a minimal patch.\n");
            prompt.push_str("- Run tests.\n");
            prompt.push_str("- Report changed files.\n");
        }
    }

    prompt.push_str("\nReviewGate findings from latest SQLite run:\n\n");
    for finding in findings {
        prompt.push_str(&format!("- [{}] {}\n", finding.severity, finding.title));
        prompt.push_str(&format!("  File: {}\n", file_line_label(finding)));
        prompt.push_str(&format!("  Category: {}\n", finding.category));
        prompt.push_str(&format!(
            "  Risk code: {}\n",
            finding.risk_code.as_deref().unwrap_or("none")
        ));
        prompt.push_str(&format!("  Effort: {}\n", finding.effort));
        prompt.push_str(&format!(
            "  Problem: {}\n",
            indent_continuation(&finding.body)
        ));
        prompt.push_str(&format!(
            "  Suggested fix: {}\n\n",
            indent_continuation(finding.suggested_fix.as_deref().unwrap_or("none"))
        ));
    }

    prompt
}

fn render_fix_prompt_header(
    counters: &FindingCounters,
    emoji: bool,
    comparison: Option<&ReviewComparison>,
) -> String {
    let mut header = String::new();
    header.push_str("ReviewGate fix prompt\n\n");
    header.push_str(&format!("Findings included: {}\n", counters.total));
    header.push_str(&format!(
        "{}: {}\n",
        severity_label("Critical", "🔴", emoji),
        counters.critical
    ));
    header.push_str(&format!(
        "{}: {}\n",
        severity_label("High", "🟠", emoji),
        counters.high
    ));
    header.push_str(&format!(
        "{}: {}\n",
        severity_label("Medium", "🟡", emoji),
        counters.medium
    ));
    if counters.low > 0 {
        header.push_str(&format!(
            "{}: {}\n",
            severity_label("Low", "🟢", emoji),
            counters.low
        ));
    }
    if counters.note > 0 {
        header.push_str(&format!(
            "{}: {}\n",
            severity_label("Notes", "🔵", emoji),
            counters.note
        ));
    }
    if let Some(comparison) = comparison {
        header.push('\n');
        header.push_str(&format_comparison_terminal(comparison, emoji));
    }
    header.push_str("\n---\n\n");
    header
}

fn format_verification_counter_lines(counters: &VerificationCounters, emoji: bool) -> String {
    format_verification_counters_terminal(counters, emoji)
        .lines()
        .skip(1)
        .map(|line| format!("{line}\n"))
        .collect()
}

fn format_finding_counter_lines(counters: &FindingCounters, emoji: bool) -> String {
    format_finding_counters_terminal(counters, emoji)
        .lines()
        .skip(1)
        .map(|line| format!("{line}\n"))
        .collect()
}

fn severity_label(label: &str, icon: &str, emoji: bool) -> String {
    if emoji {
        format!("{icon} {label}")
    } else {
        label.to_string()
    }
}

fn file_line_label(finding: &StoredReviewFinding) -> String {
    let file_path = finding.file_path.as_deref().unwrap_or("<unknown>");
    let line = finding.new_line.or(finding.old_line);
    match line {
        Some(line) => format!("{file_path}:{line}"),
        None => format!("{file_path}:unknown"),
    }
}

fn indent_continuation(value: &str) -> String {
    value.replace('\n', "\n  ")
}

enum ClipboardCommandError {
    NotFound,
    Failed(String),
}

fn copy_with_command(
    command: &str,
    prompt: &str,
) -> std::result::Result<(), ClipboardCommandError> {
    let mut child = Command::new(command)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ClipboardCommandError::NotFound
            } else {
                ClipboardCommandError::Failed(error.to_string())
            }
        })?;

    let Some(mut stdin) = child.stdin.take() else {
        return Err(ClipboardCommandError::Failed(format!(
            "{command} stdin unavailable"
        )));
    };
    stdin
        .write_all(prompt.as_bytes())
        .map_err(|error| ClipboardCommandError::Failed(error.to_string()))?;
    drop(stdin);

    let status = child
        .wait()
        .map_err(|error| ClipboardCommandError::Failed(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(ClipboardCommandError::Failed(format!(
            "{command} exited with {status}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_fix_prompt, effective_min_severity, format_findings_summary, latest_findings_summary,
        write_prompt_output, FixPromptFormat, FixPromptOptions, FixPromptSeverity,
    };
    use crate::{gitlab::url::GitLabMrUrl, storage::Storage};
    use rusqlite::{params, Connection};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn latest_findings_query_uses_latest_completed_run() {
        let (storage, mr) = storage_with_runs(&[
            RunFixture {
                id: "run-old",
                completed_at: "001",
                findings: vec![finding("HIGH", "Old high", true)],
            },
            RunFixture {
                id: "run-new",
                completed_at: "002",
                findings: vec![finding("HIGH", "New high", true)],
            },
        ]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert_eq!(generated.run.id, "run-new");
        assert_eq!(generated.findings[0].title, "New high");
    }

    #[test]
    fn run_id_findings_query_uses_selected_run() {
        let (storage, mr) = storage_with_runs(&[
            RunFixture {
                id: "run-old",
                completed_at: "001",
                findings: vec![finding("HIGH", "Old high", true)],
            },
            RunFixture {
                id: "run-new",
                completed_at: "002",
                findings: vec![finding("HIGH", "New high", true)],
            },
        ]);
        let options = FixPromptOptions {
            run_id: Some("run-old".to_string()),
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert_eq!(generated.run.id, "run-old");
        assert_eq!(generated.findings[0].title, "Old high");
    }

    #[test]
    fn run_id_not_found_error() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);
        let options = FixPromptOptions {
            run_id: Some("missing-run".to_string()),
            ..default_options()
        };

        let err = build_fix_prompt(&storage, &mr, options).unwrap_err();

        assert!(matches!(
            err,
            crate::error::ReviewGateError::ReviewRunNotFound(id) if id == "missing-run"
        ));
    }

    #[test]
    fn severity_filtering_respects_min_severity() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("CRITICAL", "Critical", true),
            finding("HIGH", "High", true),
            finding("MEDIUM", "Medium", true),
        ]);
        let options = FixPromptOptions {
            min_severity: FixPromptSeverity::High,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert_eq!(titles(&generated), vec!["Critical", "High"]);
    }

    #[test]
    fn actionable_filtering_excludes_non_actionable_findings() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("HIGH", "Actionable", true),
            finding("HIGH", "Non-actionable", false),
        ]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert_eq!(titles(&generated), vec!["Actionable"]);
    }

    #[test]
    fn fix_prompt_excludes_non_actionable_positive_notes() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("HIGH", "Actionable", true),
            finding("NOTE", "Credentials removed from persisted state", false),
        ]);
        let options = FixPromptOptions {
            include_notes: true,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert_eq!(titles(&generated), vec!["Actionable"]);
        assert!(!generated.prompt.contains("Credentials removed"));
    }

    #[test]
    fn low_and_note_are_excluded_by_default() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("HIGH", "High", true),
            finding("LOW", "Low", true),
            finding("NOTE", "Note", true),
        ]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert_eq!(titles(&generated), vec!["High"]);
    }

    #[test]
    fn include_low_adds_low_findings() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("MEDIUM", "Medium", true),
            finding("LOW", "Low", true),
        ]);
        let options = FixPromptOptions {
            min_severity: FixPromptSeverity::Low,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert_eq!(titles(&generated), vec!["Medium", "Low"]);
    }

    #[test]
    fn include_notes_adds_note_findings() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("MEDIUM", "Medium", true),
            finding("NOTE", "Note", true),
        ]);
        let options = FixPromptOptions {
            include_notes: true,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert_eq!(titles(&generated), vec!["Medium", "Note"]);
    }

    #[test]
    fn sorting_uses_severity_then_source_order() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("MEDIUM", "Medium first", true),
            finding("HIGH", "High first", true),
            finding("HIGH", "High second", true),
            finding("CRITICAL", "Critical", true),
        ]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert_eq!(
            titles(&generated),
            vec!["Critical", "High first", "High second", "Medium first"]
        );
    }

    #[test]
    fn markdown_prompt_formatting() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert!(generated.prompt.starts_with("ReviewGate fix prompt"));
        assert!(generated.prompt.contains("Findings included: 1"));
        assert!(generated.prompt.contains("🟠 High: 1"));
        assert!(generated
            .prompt
            .contains("---\n\nYou are an AI coding agent."));
        assert!(generated.prompt.contains("- [HIGH] Timeout missing"));
        assert!(generated.prompt.contains("  File: src/example.rs:42"));
        assert!(generated.prompt.contains("  Category: correctness"));
        assert!(generated.prompt.contains("  Risk code: missing_timeout"));
        assert!(!generated.prompt.contains("Codex-specific instructions"));
        assert!(!generated.prompt.contains("Gemini-specific instructions"));
    }

    #[test]
    fn codex_prompt_formatting() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);
        let options = FixPromptOptions {
            format: FixPromptFormat::Codex,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert!(generated.prompt.contains("Codex-specific instructions"));
        assert!(generated
            .prompt
            .contains("- Do not run destructive commands."));
        assert!(generated.prompt.contains("- Inspect files first."));
        assert!(generated.prompt.contains("- Report changed files."));
    }

    #[test]
    fn gemini_prompt_formatting() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);
        let options = FixPromptOptions {
            format: FixPromptFormat::Gemini,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert!(generated.prompt.contains("Gemini-specific instructions"));
        assert!(generated
            .prompt
            .contains("- Do not use broad repo-wide edits."));
        assert!(generated.prompt.contains("- Do not use YOLO mode."));
        assert!(generated.prompt.contains("- Report changed files."));
    }

    #[test]
    fn no_previous_run_error() {
        let path = temp_db_path("no_previous_run_error");
        let storage = Storage::open_path(path).unwrap();
        let mr = mr();

        let err = build_fix_prompt(&storage, &mr, default_options()).unwrap_err();

        assert!(matches!(
            err,
            crate::error::ReviewGateError::NoPreviousReviewRun
        ));
    }

    #[test]
    fn no_actionable_findings_message() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Not actionable", false)]);

        let err = build_fix_prompt(&storage, &mr, default_options()).unwrap_err();

        assert_eq!(
            err.to_string(),
            "no actionable ReviewGate findings matched the requested filters"
        );
    }

    #[test]
    fn output_file_overwrite_requires_force() {
        let dir = temp_dir("output_file_overwrite_requires_force");
        let path = dir.join(".reviewgate/fix-prompt.md");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "existing").unwrap();

        let err = write_prompt_output(&path, "new", false).unwrap_err();
        assert!(matches!(
            err,
            crate::error::ReviewGateError::OutputFileExists(_)
        ));

        write_prompt_output(&path, "new", true).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "new");
    }

    #[test]
    fn fix_prompt_test_dbs_do_not_share_state() {
        let first = temp_db_path("fix_prompt");
        let second = temp_db_path("fix_prompt");

        assert_ne!(first, second);
        assert!(!first.ends_with(".reviewgate/reviewgate.sqlite"));
        assert!(!second.ends_with(".reviewgate/reviewgate.sqlite"));
    }

    #[test]
    fn generated_prompt_does_not_include_raw_diff() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert!(!generated.prompt.contains("@@ -1,1 +1,1 @@"));
        assert!(!generated.prompt.contains("RAW_DIFF_SENTINEL"));
    }

    #[test]
    fn generated_prompt_does_not_include_raw_llm_payload() {
        let (storage, mr) = storage_with_single_run(vec![finding("HIGH", "Timeout missing", true)]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert!(!generated.prompt.contains("RAW_LLM_SENTINEL"));
        assert!(!generated.prompt.contains("\"overall_risk\""));
    }

    #[test]
    fn include_low_changes_default_min_severity() {
        assert_eq!(
            effective_min_severity(None, true).unwrap(),
            FixPromptSeverity::Low
        );
        assert_eq!(
            effective_min_severity(Some("HIGH"), true).unwrap(),
            FixPromptSeverity::High
        );
    }

    #[test]
    fn findings_summary_output_includes_counters() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("CRITICAL", "Critical", true),
            finding("HIGH", "High", true),
            finding("MEDIUM", "Medium", true),
            finding("LOW", "Low", false),
            finding("NOTE", "Note", false),
        ]);

        let summary = latest_findings_summary(&storage, &mr).unwrap();
        let output = format_findings_summary(&summary);

        assert!(output.contains("Latest review:"));
        assert!(output.contains("Open priority findings: 3"));
        assert!(output.contains("🔴 Critical: 1"));
        assert!(output.contains("🟠 High: 1"));
        assert!(output.contains("🟡 Medium: 1"));
        assert!(output.contains("🟢 Low-priority findings: 1"));
        assert!(output.contains("🔵 Notes: 1"));
        assert!(output.contains("Latest verification:"));
    }

    #[test]
    fn findings_summary_output_includes_comparison() {
        let (storage, mr) = storage_with_runs(&[
            RunFixture {
                id: "run-old",
                completed_at: "001",
                findings: vec![finding("HIGH", "Old high", true)],
            },
            RunFixture {
                id: "run-new",
                completed_at: "002",
                findings: vec![finding("HIGH", "New high", true)],
            },
        ]);

        let summary = latest_findings_summary(&storage, &mr).unwrap();
        let output = format_findings_summary(&summary);

        assert!(output.contains("Change since previous published review:"));
        assert!(output.contains("Compared with: run-old"));
        assert!(output.contains("⚠️ Previously detected priority findings still present: 1"));
    }

    #[test]
    fn fix_prompt_header_includes_comparison_when_previous_run_exists() {
        let (storage, mr) = storage_with_runs(&[
            RunFixture {
                id: "run-old",
                completed_at: "001",
                findings: vec![finding("HIGH", "Old high", true)],
            },
            RunFixture {
                id: "run-new",
                completed_at: "002",
                findings: vec![finding("HIGH", "New high", true)],
            },
        ]);

        let generated = build_fix_prompt(&storage, &mr, default_options()).unwrap();

        assert!(generated
            .prompt
            .contains("Change since previous published review:"));
        assert!(generated.prompt.contains("🆕 New priority findings: 0"));
        assert!(generated
            .prompt
            .contains("⚠️ Previously detected priority findings still present: 1"));
        assert!(generated
            .prompt
            .contains("ReviewGate findings from latest SQLite run:"));
    }

    #[test]
    fn fix_prompt_header_counters_respect_severity_filters() {
        let (storage, mr) = storage_with_single_run(vec![
            finding("CRITICAL", "Critical", true),
            finding("HIGH", "High", true),
            finding("MEDIUM", "Medium", true),
            finding("LOW", "Low", true),
            finding("NOTE", "Note", true),
        ]);
        let options = FixPromptOptions {
            min_severity: FixPromptSeverity::High,
            include_notes: false,
            ..default_options()
        };

        let generated = build_fix_prompt(&storage, &mr, options).unwrap();

        assert!(generated.prompt.contains("Findings included: 2"));
        assert!(generated.prompt.contains("🔴 Critical: 1"));
        assert!(generated.prompt.contains("🟠 High: 1"));
        assert!(generated.prompt.contains("🟡 Medium: 0"));
        assert!(!generated.prompt.contains("🟢 Low:"));
        assert!(!generated.prompt.contains("🔵 Notes:"));
        assert_eq!(titles(&generated), vec!["Critical", "High"]);
    }

    fn default_options() -> FixPromptOptions {
        FixPromptOptions {
            run_id: None,
            min_severity: FixPromptSeverity::Medium,
            include_notes: false,
            format: FixPromptFormat::Markdown,
        }
    }

    fn titles(generated: &super::GeneratedFixPrompt) -> Vec<&str> {
        generated
            .findings
            .iter()
            .map(|finding| finding.title.as_str())
            .collect()
    }

    fn storage_with_single_run(findings: Vec<FindingFixture>) -> (Storage, GitLabMrUrl) {
        storage_with_runs(&[RunFixture {
            id: "run-1",
            completed_at: "001",
            findings,
        }])
    }

    fn storage_with_runs(runs: &[RunFixture]) -> (Storage, GitLabMrUrl) {
        let path = temp_db_path("fix_prompt");
        drop(Storage::open_path(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        for run in runs {
            insert_run(&conn, run);
            for (index, finding) in run.findings.iter().enumerate() {
                insert_finding(&conn, run.id, index, finding);
            }
        }
        drop(conn);
        (Storage::open_path(path).unwrap(), mr())
    }

    fn insert_run(conn: &Connection, run: &RunFixture) {
        conn.execute(
            "INSERT INTO review_runs (
                id, provider, project_path, mr_iid, mr_url, mr_title, source_branch,
                target_branch, head_sha, model_provider, model_name, local_only, status,
                started_at, completed_at, summary_note_id, summary_publish_action,
                raw_diff_stored, raw_llm_stored
            ) VALUES (?1, 'gitlab', 'group/repo', 59, ?2, 'RAW_DIFF_SENTINEL', 'source',
                'target', 'head', 'gemini_cli', 'gemini-2.5-pro', 0, 'completed',
                ?3, ?3, ?4, 'created', 0, 0)",
            params![
                run.id,
                "https://gitlab.company.local/group/repo/-/merge_requests/59",
                run.completed_at,
                10_000 + run.completed_at.parse::<i64>().unwrap_or_default()
            ],
        )
        .unwrap();
    }

    fn insert_finding(conn: &Connection, run_id: &str, index: usize, finding: &FindingFixture) {
        conn.execute(
            "INSERT INTO review_findings (
                id, run_id, project_path, mr_iid, head_sha, severity, effort, category,
                risk_code, file_path, old_line, new_line, title, body, suggested_fix,
                actionable, created_at
            ) VALUES (?1, ?2, 'group/repo', 59, 'head', ?3, 'quick', 'correctness',
                'missing_timeout', 'src/example.rs', NULL, 42, ?4, ?5, 'Use a timeout.',
                ?6, '001')",
            params![
                format!("{run_id}-finding-{index}"),
                run_id,
                finding.severity,
                finding.title,
                finding.body,
                if finding.actionable { 1 } else { 0 }
            ],
        )
        .unwrap();
    }

    fn finding(severity: &'static str, title: &'static str, actionable: bool) -> FindingFixture {
        FindingFixture {
            severity,
            title,
            body: "Problem body.",
            actionable,
        }
    }

    fn mr() -> GitLabMrUrl {
        GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59").unwrap()
    }

    struct RunFixture {
        id: &'static str,
        completed_at: &'static str,
        findings: Vec<FindingFixture>,
    }

    struct FindingFixture {
        severity: &'static str,
        title: &'static str,
        body: &'static str,
        actionable: bool,
    }

    fn temp_db_path(name: &str) -> PathBuf {
        temp_dir(name).join("reviewgate.sqlite")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let sequence = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "reviewgate-fix-prompt-{name}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
