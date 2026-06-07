use reviewgate::{
    branding::REVIEWGATE_ATTRIBUTION,
    gitlab::{
        inline::format_inline_comment_body_with_emoji,
        publish::{build_summary_note_body, build_verification_note_body},
        url::GitLabMrUrl,
    },
    review::{
        comparison::{insert_comparison_section_with_emoji, ReviewComparison},
        formatter::{
            format_review_markdown_for_mode_with_risk_gate, format_review_markdown_with_emoji,
            MarkdownRenderMode,
        },
        risk::{
            BlastRadius, MergeDecision, MergeRiskAssessment, RiskEvidence, RiskEvidenceSource,
            RiskFactor, RiskGateItem,
        },
        types::{
            Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode, Severity,
        },
    },
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
    assert!(!body.contains("## Finding Summary"));
    assert!(!body.contains("## Change Since Previous Published Review"));
    assert!(!body.contains("## Merge Risk Gate"));
    assert!(!body.contains("| Severity | Count |"));
    assert!(!body.contains("| Status | Count |"));
}

#[test]
fn summary_markdown_can_include_merge_risk_gate_near_top() {
    let sync_evidence = vec![RiskEvidence {
        source: RiskEvidenceSource::ChangedFile,
        file_path: Some("src/features/sync/offlineQueue.ts".to_string()),
        finding_id: None,
        risk_code: None,
        rule_id: "changed_file.offline_sync_missing_recovery_test".to_string(),
        description: "Changed file path matches offline sync evidence.".to_string(),
    }];
    let assessment = MergeRiskAssessment {
        score: 78,
        decision: MergeDecision::Blocked,
        blocking_issues: vec![RiskGateItem {
            label: "Modified offline sync layer without adding recovery test".to_string(),
            evidence: sync_evidence.clone(),
        }],
        required_before_merge: vec![RiskGateItem {
            label: "Add sync recovery test".to_string(),
            evidence: sync_evidence.clone(),
        }],
        risk_factors: vec![RiskFactor {
            rule_id: "changed_file.offline_sync_missing_recovery_test".to_string(),
            label: "Offline sync layer changed without recovery test".to_string(),
            score: 25,
            evidence: sync_evidence,
            points: 25,
        }],
        blast_radius: BlastRadius::default(),
    };

    let markdown = format_review_markdown_for_mode_with_risk_gate(
        &analysis(),
        MarkdownRenderMode::Publish,
        false,
        Some(&assessment),
    );

    let gate_index = markdown.find("## Merge Risk Gate").unwrap();
    let summary_index = markdown.find("## Summary").unwrap();
    let findings_index = markdown.find("## Critical").unwrap();
    assert!(gate_index < summary_index);
    assert!(gate_index < findings_index);
    assert!(markdown.contains("Risk Score: 78/100"));
    assert!(markdown.contains("Decision: BLOCKED"));
}

#[test]
fn final_markdown_sanitizes_medium_only_bad_risk_gate() {
    let analysis = ReviewAnalysis {
        summary: "Main risks found:\n- Modified offline sync layer without adding recovery test\n- Hardcoded Google Maps API key in AndroidManifest.xml".to_string(),
        findings: vec![
            finding_with(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::SecretLeak),
                "AndroidManifest.xml",
                "Hardcoded Google Maps API key in android manifest",
            ),
            finding_with(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "MainActivity.kt",
                "Untrusted application warning is easily missed",
            ),
            finding_with(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AntiInstrumentationModule.kt",
                "Security check fails silently",
            ),
            finding_with(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AppSignatureVerifier.kt",
                "Overly broad exception handling in signature verification",
            ),
            finding_with(
                Severity::Medium,
                ReviewCategory::Reliability,
                Some(RiskCode::PerformanceRegression),
                "Profile/index.tsx",
                "Logout relies on fixed timeout for WebView cleanup",
            ),
        ],
        test_coverage_note: Some("Test coverage is insufficient.".to_string()),
        privacy_note: Some("Temporary files were moved to cache-backed storage.".to_string()),
        overall_risk: OverallRisk::Medium,
    };
    let assessment = MergeRiskAssessment {
        score: 100,
        decision: MergeDecision::Blocked,
        blocking_issues: vec![RiskGateItem {
            label: "Modified offline sync layer without adding recovery test".to_string(),
            evidence: vec![RiskEvidence {
                source: RiskEvidenceSource::ChangedFile,
                file_path: Some("Profile/index.tsx".to_string()),
                finding_id: None,
                risk_code: None,
                rule_id: "changed_file.offline_sync_missing_recovery_test".to_string(),
                description: "bad fallback".to_string(),
            }],
        }],
        required_before_merge: vec![RiskGateItem {
            label: "Add sync recovery test".to_string(),
            evidence: vec![RiskEvidence {
                source: RiskEvidenceSource::ChangedFile,
                file_path: Some("Profile/index.tsx".to_string()),
                finding_id: None,
                risk_code: None,
                rule_id: "changed_file.offline_sync_missing_recovery_test".to_string(),
                description: "bad fallback".to_string(),
            }],
        }],
        risk_factors: vec![RiskFactor {
            rule_id: "verification.large_review.failed_chunks".to_string(),
            label: "Large MR review was partial or high-risk files were prioritized.".to_string(),
            score: 16,
            evidence: vec![RiskEvidence {
                source: RiskEvidenceSource::Verification,
                file_path: None,
                finding_id: None,
                risk_code: None,
                rule_id: "verification.large_review.failed_chunks".to_string(),
                description: "1 review chunk failed.".to_string(),
            }],
            points: 16,
        }],
        blast_radius: BlastRadius {
            failed_chunks: 1,
            ..BlastRadius::default()
        },
    };

    let markdown = format_review_markdown_for_mode_with_risk_gate(
        &analysis,
        MarkdownRenderMode::Publish,
        false,
        Some(&assessment),
    );

    assert!(markdown.contains("Risk Score: 56/100"));
    assert!(markdown.contains("Decision: NEEDS HUMAN"));
    assert!(!markdown.contains("Risk Score: 100/100"));
    assert!(!markdown.contains("Modified offline sync layer"));
    assert!(!markdown.contains("Add sync recovery test"));
    assert!(!markdown.contains("Blocking Issues:"));
    assert!(markdown.contains("Confirm the Google Maps API key is package/SHA restricted"));
    assert!(markdown.contains("Replace transient Toast-only untrusted-build warning"));
    assert!(markdown.contains("Surface or log native security check failures"));
    assert!(markdown.contains("Log expected signature-verification exceptions"));
    assert!(markdown.contains("Add monitoring or fallback behavior for WebView cleanup timeout"));
    assert!(markdown.contains(REVIEWGATE_ATTRIBUTION));
    assert!(!markdown.contains("reviewgate:inline"));
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
    assert!(body.contains("## Verification Summary"));
}

#[test]
fn review_markdown_uses_pipe_table_for_counters_and_compact_comparison() {
    let markdown = format_review_markdown_with_emoji(&analysis(), true);
    let markdown = insert_comparison_section_with_emoji(&markdown, &comparison(), true);

    assert!(markdown.contains("## Finding Summary"));
    assert!(markdown.contains("| Severity | Count |\n|---|---:|"));
    assert!(markdown.contains("## Change Since Previous Published Review"));
    assert!(markdown.contains("Compared with: `previous-run`"));
    assert!(markdown.contains("Current review:"));
    assert!(!markdown.contains("| Status | Count |\n|---|---:|"));
    assert!(!markdown.contains('━'));
    assert!(!markdown.contains('─'));
}

#[test]
fn verification_markdown_uses_pipe_table_for_summary() {
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
        "preview",
    );

    assert!(markdown.contains("## Verification Summary"));
    assert!(markdown.contains("| Status | Count |\n|---|---:|"));
    assert!(!markdown.contains('━'));
    assert!(!markdown.contains('─'));
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
fn docker_packaging_files_are_release_ready() {
    for path in [
        "Dockerfile",
        ".dockerignore",
        "docs/docker.md",
        "examples/gitlab-ci-docker-reviewgate.yml",
        ".github/workflows/docker.yml",
    ] {
        assert!(Path::new(path).is_file(), "{path} should exist");
    }

    let dockerignore = fs::read_to_string(".dockerignore").unwrap();
    assert!(
        dockerignore.lines().any(|line| line.trim() == ".git"),
        ".dockerignore should exclude .git"
    );
    assert!(
        dockerignore.lines().any(|line| line.trim() == "target"),
        ".dockerignore should exclude target"
    );
    assert!(
        dockerignore.lines().any(|line| line.trim() == ".env"),
        ".dockerignore should exclude .env"
    );
    assert!(
        dockerignore
            .lines()
            .any(|line| line.trim() == ".reviewgate"),
        ".dockerignore should exclude .reviewgate"
    );
    assert!(
        dockerignore
            .lines()
            .any(|line| line.trim() == "docs/PRD.md"),
        ".dockerignore should exclude docs/PRD.md"
    );

    let dockerfile = fs::read_to_string("Dockerfile").unwrap();
    assert!(dockerfile.contains("FROM rust:"));
    assert!(dockerfile.contains("FROM debian:bookworm-slim"));
    assert!(dockerfile.contains("/usr/local/bin/reviewgate"));
    assert!(dockerfile.contains("ca-certificates"));
    assert!(dockerfile.contains("USER reviewgate"));
    assert!(dockerfile.contains("CMD [\"--help\"]"));
    assert!(!dockerfile.contains("COPY ."));

    let docs = fs::read_to_string("docs/docker.md").unwrap();
    assert!(docs.contains("docker build -t reviewgate:local ."));
    assert!(docs.contains("docker run --rm reviewgate:local --version"));
    assert!(docs.contains("docker run --rm reviewgate:local doctor"));
    assert!(docs.contains("ollama"));
    assert!(docs.contains("Privacy"));

    let example = fs::read_to_string("examples/gitlab-ci-docker-reviewgate.yml").unwrap();
    assert!(example.contains("ghcr.io/anggaprytn/review-gate:v0.1.0-alpha.3"));
    assert!(example.contains("REVIEWGATE_LLM_PROVIDER: \"ollama\""));
    assert!(example.contains("OLLAMA_BASE_URL: \"http://ollama:11434\""));
    assert!(example.contains("reviewgate doctor"));
    assert!(example.contains("reviewgate review --ci --publish"));
    assert!(example.contains("reviewgate review --ci --publish --soft-fail"));
    assert!(example.contains("merge_request_event"));

    let workflow = fs::read_to_string(".github/workflows/docker.yml").unwrap();
    assert!(workflow.contains("tags:"));
    assert!(workflow.contains("- \"v*\""));
    assert!(workflow.contains("ghcr.io/anggaprytn/review-gate"));
    assert!(workflow.contains("docker/build-push-action"));
    assert!(workflow.contains("docker/metadata-action"));
    assert!(workflow.contains("latest"));
    assert!(workflow.contains("alpha"));
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

#[test]
fn install_script_supports_release_overrides_and_dry_run() {
    let script = fs::read_to_string("scripts/install.sh").unwrap();

    assert!(script.contains("REVIEWGATE_REPO"));
    assert!(script.contains("REVIEWGATE_VERSION"));
    assert!(script.contains("REVIEWGATE_INSTALL_DRY_RUN"));
    assert!(script.contains("anggaprytn/review-gate"));
    assert!(script.contains("reviewgate-${version}-${target}.tar.gz"));
    assert!(script.contains("No prebuilt ReviewGate binary is available"));
}

#[test]
fn install_script_handles_explicit_alpha_prerelease_version() {
    let output = Command::new("sh")
        .arg("scripts/install.sh")
        .env("REVIEWGATE_INSTALL_DRY_RUN", "true")
        .env("REVIEWGATE_VERSION", "v0.1.0-alpha.1")
        .env("INSTALL_DIR", "/tmp/reviewgate-install-test/bin")
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("repo: anggaprytn/review-gate"));
    assert!(stdout.contains("release version/latest: v0.1.0-alpha.1"));
    assert!(stdout.contains("/releases/download/v0.1.0-alpha.1/reviewgate-v0.1.0-alpha.1-"));
    assert!(!stdout.contains("reviewgate-<version>"));
}

#[test]
fn release_workflow_artifact_names_match_install_script_expectations() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").unwrap();
    let script = fs::read_to_string("scripts/install.sh").unwrap();

    assert!(workflow.contains("tags:"));
    assert!(workflow.contains("- \"v*\""));
    assert!(workflow.contains("reviewgate-${GITHUB_REF_NAME}-${{ matrix.target }}.tar.gz"));
    assert!(workflow.contains("checksums.txt"));
    assert!(workflow.contains("softprops/action-gh-release"));
    assert!(script.contains("reviewgate-${version}-${target}.tar.gz"));
    assert!(script.contains("/releases/download/${version}/${archive}"));
    assert!(script.contains("/releases/download/${version}/checksums.txt"));
}

#[test]
fn release_smoke_docs_and_templates_exist() {
    for path in [
        "docs/release-smoke-test.md",
        "docs/release-checklist.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/provider_issue.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/pull_request_template.md",
    ] {
        assert!(Path::new(path).is_file(), "{path} should exist");
    }

    let smoke = fs::read_to_string("docs/release-smoke-test.md").unwrap();
    assert!(smoke.contains("reviewgate --version"));
    assert!(smoke.contains("reviewgate doctor"));
    assert!(smoke.contains("reviewgate review \"$MR_URL\" --dry-run"));
    assert!(smoke.contains("reviewgate review \"$MR_URL\" --preview"));
    assert!(smoke.contains("reviewgate review \"$MR_URL\" --publish"));
    assert!(smoke.contains("reviewgate verify \"$MR_URL\" --preview"));
    assert!(smoke.contains("--publish-inline"));

    let checklist = fs::read_to_string("docs/release-checklist.md").unwrap();
    assert!(checklist.contains("cargo fmt --all -- --check"));
    assert!(checklist.contains("cargo clippy --all-targets --all-features -- -D warnings"));
    assert!(checklist.contains("git diff --check"));

    let pr_template = fs::read_to_string(".github/pull_request_template.md").unwrap();
    assert!(pr_template.contains("Plain `review --publish` remains summary-only"));
    assert!(pr_template.contains("Inline publishing remains explicit"));
}

#[test]
fn issue_templates_warn_not_to_paste_secrets() {
    for path in [
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/provider_issue.yml",
    ] {
        let template = fs::read_to_string(path).unwrap();
        assert!(template.contains("Do not paste tokens"), "{path}");
        assert!(template.contains("private merge request URLs"), "{path}");
        assert!(template.contains("raw diffs"), "{path}");
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
        evidence_status: None,
        evidence_reason: None,
    }
}

fn finding_with(
    severity: Severity,
    category: ReviewCategory,
    risk_code: Option<RiskCode>,
    file_path: &str,
    title: &str,
) -> ReviewFinding {
    ReviewFinding {
        severity,
        category,
        risk_code,
        anchor_id: None,
        file_path: Some(file_path.to_string()),
        line: Some(1),
        title: title.to_string(),
        body: title.to_string(),
        suggested_fix: None,
        effort: Effort::Moderate,
        actionable: true,
        evidence_status: Some(reviewgate::review::types::EvidenceValidationStatus::Validated),
        evidence_reason: None,
    }
}

fn analysis() -> ReviewAnalysis {
    ReviewAnalysis {
        summary: "summary".to_string(),
        findings: vec![finding()],
        test_coverage_note: None,
        privacy_note: None,
        overall_risk: OverallRisk::High,
    }
}

fn comparison() -> ReviewComparison {
    ReviewComparison {
        previous_run_id: Some("previous-run".to_string()),
        current_run_id: "current-run".to_string(),
        new_findings: 1,
        still_detected: 5,
        not_detected: 0,
        verified_fixed: 0,
        needs_verification: 0,
        previous_total_actionable: 5,
        current_total_actionable: 6,
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
