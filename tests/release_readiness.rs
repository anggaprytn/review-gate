use reviewgate::{
    branding::REVIEWGATE_ATTRIBUTION,
    gitlab::{
        inline::format_inline_comment_body_with_emoji,
        publish::{build_summary_note_body, build_verification_note_body},
        url::GitLabMrUrl,
    },
    review::types::{Effort, ReviewCategory, ReviewFinding, RiskCode, Severity},
    storage::StoredPreviousFinding,
    verify::{
        format_verification_markdown, VerificationOutcome, VerificationResult, VerificationStatus,
    },
};
use std::{fs, path::Path, process::Command};

#[test]
fn readme_does_not_require_private_prd() {
    let readme = fs::read_to_string("README.md").unwrap();

    assert!(!readme.contains("docs/PRD.md"));
    assert!(!readme.contains("PRD.md"));
}

#[test]
fn gitignore_keeps_local_only_paths_ignored() {
    let gitignore = fs::read_to_string(".gitignore").unwrap();

    assert!(gitignore.lines().any(|line| line.trim() == "/docs/PRD.md"));
    assert!(gitignore.lines().any(|line| line.trim() == ".reviewgate/"));
    assert!(gitignore.lines().any(|line| line.trim() == ".env"));
}

#[test]
fn summary_output_keeps_attribution_and_hidden_marker() {
    let body = build_summary_note_body(
        "# ReviewGate AI Code Review\n\nBody\n",
        "group/repo",
        59,
        "gemini_cli/gemini-2.5-pro",
        false,
        "enabled through Gemini CLI",
        "abc123",
        "disabled",
        20_000,
    )
    .unwrap();

    assert!(body.contains(REVIEWGATE_ATTRIBUTION));
    assert!(body.contains("reviewgate:summary"));
}

#[test]
fn inline_output_keeps_attribution_and_hidden_marker() {
    let mr =
        GitLabMrUrl::parse("https://gitlab.example.com/group/repo/-/merge_requests/59").unwrap();
    let body = format_inline_comment_body_with_emoji(&mr, &finding(), "fp", "head", false).unwrap();

    assert!(body.contains(REVIEWGATE_ATTRIBUTION));
    assert!(body.contains("reviewgate:inline"));
}

#[test]
fn verification_output_keeps_attribution_and_hidden_marker() {
    let markdown = format_verification_markdown(
        &VerificationOutcome {
            summary: "1 fixed.".to_string(),
            results: vec![VerificationResult {
                previous_finding: previous_finding(),
                status: VerificationStatus::Fixed,
                reason: "Fixed by the current diff.".to_string(),
                evidence: Some("Timeout added.".to_string()),
            }],
            parsed: true,
            parse_warning: None,
        },
        "run-1",
        "head",
        "ollama/qwen2.5-coder:7b",
        "verification summary note",
    );
    let body = build_verification_note_body(&markdown, "group/repo", 59, 20_000).unwrap();

    assert!(body.contains(REVIEWGATE_ATTRIBUTION));
    assert!(body.contains("reviewgate:verification"));
}

#[test]
fn no_public_watermark_disable_flag_or_env_exists() {
    let forbidden = [
        ["--no-", "watermark"].concat(),
        ["REVIEWGATE_HIDE_", "WATERMARK"].concat(),
        ["REVIEWGATE_DISABLE_", "BRANDING"].concat(),
    ];
    let mut offenders = Vec::new();
    collect_matching_files(Path::new("."), &forbidden, &mut offenders);

    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn config_example_is_valid_toml() {
    let value: toml::Value = toml::from_str(include_str!("../examples/.reviewgate.toml")).unwrap();

    assert_eq!(value["llm"]["provider"].as_str(), Some("gemini_cli"));
}

#[test]
fn doctor_default_skips_network_and_redacts_token() {
    let output = Command::new(env!("CARGO_BIN_EXE_reviewgate"))
        .arg("doctor")
        .env("GITLAB_TOKEN", "test-token-secret")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ReviewGate Doctor"));
    assert!(stdout.contains("Network checks: skipped"));
    assert!(stdout.contains("GitLab token source: GITLAB_TOKEN"));
    assert!(!stdout.contains("test-token-secret"));
}

#[test]
fn ci_example_targets_merge_request_events() {
    let example = fs::read_to_string("examples/gitlab-ci-reviewgate.yml").unwrap();

    assert!(example.contains("merge_request_event"));
    assert!(example.contains("reviewgate review --ci --publish"));
}

#[test]
fn install_script_exists_and_is_executable() {
    let metadata = fs::metadata("scripts/install.sh").unwrap();
    assert!(metadata.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(metadata.permissions().mode() & 0o111, 0);
    }
}

fn collect_matching_files(path: &Path, forbidden: &[String], offenders: &mut Vec<String>) {
    if should_skip(path) {
        return;
    }

    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            collect_matching_files(&entry.unwrap().path(), forbidden, offenders);
        }
        return;
    }

    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for value in forbidden {
        if contents.contains(value) {
            offenders.push(format!("{} contains {value}", path.display()));
        }
    }
}

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "target" | ".reviewgate"))
}

fn finding() -> ReviewFinding {
    ReviewFinding {
        severity: Severity::High,
        category: ReviewCategory::Reliability,
        risk_code: Some(RiskCode::MissingTimeout),
        anchor_id: None,
        file_path: Some("src/client.rs".to_string()),
        line: Some(42),
        title: "Request has no timeout".to_string(),
        body: "The request can hang indefinitely.".to_string(),
        suggested_fix: Some("Add a request timeout.".to_string()),
        effort: Effort::Quick,
        actionable: true,
    }
}

fn previous_finding() -> StoredPreviousFinding {
    StoredPreviousFinding {
        id: "finding-1".to_string(),
        severity: "HIGH".to_string(),
        effort: "quick".to_string(),
        category: "reliability".to_string(),
        risk_code: Some("missing_timeout".to_string()),
        anchor_id: None,
        file_path: Some("src/client.rs".to_string()),
        old_line: None,
        new_line: Some(42),
        title: "Request has no timeout".to_string(),
        body: "The request can hang indefinitely.".to_string(),
        suggested_fix: Some("Add a request timeout.".to_string()),
        actionable: true,
        fingerprint_v2: Some("fp".to_string()),
    }
}
