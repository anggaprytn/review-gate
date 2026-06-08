use reviewgate::{
    config::{ReviewConfig, RiskGateConfig},
    gitlab::{
        context::DiffStats,
        types::{DiffRefs, MergeRequestDiff},
    },
    review::{
        anchors::{AnchorLineKind, AnchoredDiffContext, ReviewLineAnchor},
        formatter::{format_review_markdown_for_mode_with_risk_gate, MarkdownRenderMode},
        inline::{resolve_inline_candidates, InlineEligibilityReason},
        pipeline::{run_review_quality_pipeline, ReviewQualityPipelineInput},
        risk::MergeDecision,
        types::{
            Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory,
            ReviewFinding, RiskCode, Severity,
        },
    },
};
use std::{collections::HashMap, fs, path::Path};

macro_rules! finding {
    (
        $severity:expr,
        $category:expr,
        $risk_code:expr,
        $file_path:expr,
        $line:expr,
        $title:expr,
        $body:expr,
        $suggested_fix:expr $(,)?
    ) => {
        finding(FindingSpec {
            severity: $severity,
            category: $category,
            risk_code: $risk_code,
            file_path: $file_path,
            line: $line,
            title: $title,
            body: $body,
            suggested_fix: $suggested_fix,
        })
    };
}

#[test]
fn golden_fixture_files_are_present() {
    for name in [
        "sql_injection_secret_logging.md",
        "medium_only_security_hardening.md",
        "large_mr_failed_chunks.md",
        "false_missing_await.md",
        "false_variable_scope.md",
        "false_toctou.md",
        "positive_note_spam.md",
        "privacy_contradiction.md",
        "hardcoded_policy_blocker_regression.md",
        "offline_sync_true_positive_policy.md",
    ] {
        let path = Path::new("tests/fixtures/review_outputs").join(name);
        assert!(path.exists(), "missing fixture {}", path.display());
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("Expected decision"),
            "fixture {} should document expected decision",
            path.display()
        );
    }
}

#[test]
fn sql_injection_and_secret_logging_publish_blocked_with_evidence() {
    let output = run_case(vec![
        finding!(
            Severity::Critical,
            ReviewCategory::Security,
            Some(RiskCode::SqlInjection),
            "src/db.ts",
            10,
            "SQL injection in payment lookup",
            "User input is interpolated into a SQL query.",
            "Use parameterized queries for the customer lookup.",
        ),
        finding!(
            Severity::High,
            ReviewCategory::Privacy,
            Some(RiskCode::PiiOrSecretLogging),
            "src/logger.ts",
            20,
            "Authorization token logging",
            "The Authorization header token is written to logger.info.",
            "Remove the Authorization header from logs or redact it before logging.",
        ),
    ]);
    let markdown = render_markdown(&output);

    assert_eq!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert!(markdown.contains("Decision: BLOCKED"));
    assert!(markdown.contains("SQL injection"));
    assert!(markdown.contains("Authorization token logging"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn medium_only_security_hardening_cannot_publish_blocked() {
    let output = run_case(vec![finding!(
        Severity::Medium,
        ReviewCategory::Security,
        Some(RiskCode::WeakErrorHandling),
        "src/auth.ts",
        12,
        "Untrusted build warning is easy to miss",
        "The warning is transient and can be missed during startup.",
        "Show a persistent warning state until the user acknowledges the risk.",
    )]);
    let markdown = render_markdown(&output);

    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert!(output.risk_assessment.score <= 74);
    assert!(!markdown.contains("Blocking Issues:"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn security_fail_closed_weakening_fix_is_rewritten_before_markdown_and_risk_gate() {
    let output = run_review_quality_pipeline(security_input(vec![finding!(
        Severity::High,
        ReviewCategory::Security,
        Some(RiskCode::AuthBypass),
        "src/security.ts",
        10,
        "Runtime integrity check blocks on uncertainty",
        "The runtime guard fails closed and blocks when integrity is unknown.",
        "Return false when the runtime check fails so the app can continue.",
    )]))
    .unwrap();
    let markdown = render_markdown(&output);

    let finding = &output.analysis.findings[0];
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(
        finding.evidence_status,
        Some(EvidenceValidationStatus::NeedsManualConfirmation)
    );
    assert!(finding
        .suggested_fix
        .as_deref()
        .unwrap()
        .contains("Confirm the intended security posture"));
    assert!(!markdown.contains("Return false when the runtime check fails"));
    assert!(!markdown.contains("so the app can continue"));
    assert!(!markdown.contains("Return false"));
    assert!(!markdown.contains("Blocking Issues:"));
    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn fail_closed_security_observability_gap_is_medium_max_and_not_blocking() {
    let output = run_review_quality_pipeline(security_input(vec![finding!(
        Severity::High,
        ReviewCategory::Security,
        Some(RiskCode::WeakErrorHandling),
        "src/security.ts",
        10,
        "Broad exception handling hides integrity failures",
        "The integrity check catches every exception and fails closed, but false positives can block legitimate users with no diagnostic reason.",
        "Add explicit logging for each failure path.",
    )]))
    .unwrap();
    let markdown = render_markdown(&output);

    let finding = &output.analysis.findings[0];
    assert_eq!(
        finding.title,
        "Security failure reason is not observable enough"
    );
    assert_eq!(finding.category, ReviewCategory::Observability);
    assert_eq!(finding.risk_code, Some(RiskCode::ObservabilityGap));
    assert_eq!(finding.severity, Severity::Medium);
    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert!(!markdown.contains("Blocking Issues:"));
    assert!(markdown.contains("Keep the fail-closed behavior"));
    assert!(!markdown.contains("return false"));
    assert!(!markdown.contains("Allow the app to continue"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn security_tradeoff_medium_only_cannot_publish_blocked_or_inline() {
    let output = run_review_quality_pipeline(security_input(vec![finding!(
        Severity::High,
        ReviewCategory::Security,
        Some(RiskCode::AuthBypass),
        "src/security.ts",
        10,
        "Root policy blocks uncertain devices",
        "The root runtime guard uses default deny and blocks untrusted devices.",
        "Allow users to continue when root detection is uncertain.",
    )]))
    .unwrap();
    let markdown = render_markdown(&output);

    assert_eq!(output.analysis.findings[0].severity, Severity::Medium);
    assert_eq!(
        output.analysis.findings[0].evidence_status,
        Some(EvidenceValidationStatus::NeedsManualConfirmation)
    );
    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert!(output.risk_assessment.score <= 74);
    assert!(!markdown.contains("Blocking Issues:"));
    assert!(!markdown.contains("Allow users to continue"));

    let candidates = resolve_inline_candidates(
        &output.analysis,
        &[diff(
            "src/security.ts",
            "@@ -10 +10 @@\n+if (rootUnknown) { block(); return true; }",
        )],
        Some(&diff_refs()),
        &reviewgate::config::InlineConfig {
            enabled: true,
            dry_run: true,
            dedupe: true,
            max_inline_total: 8,
            max_high_inline: 8,
            max_medium_inline: 5,
        },
    );
    assert_eq!(
        candidates[0].reason,
        InlineEligibilityReason::NeedsManualConfirmation
    );
}

#[test]
fn destructive_security_action_keeps_policy_framing_without_no_wipe_fix() {
    let output = run_review_quality_pipeline(security_input(vec![finding!(
        Severity::High,
        ReviewCategory::Security,
        Some(RiskCode::DataIntegrityRisk),
        "src/security.ts",
        10,
        "Automatic token wipe can affect legitimate users",
        "A false positive in the tamper detector can clear tokens and wipe local data.",
        "Do not wipe data; allow the user to continue.",
    )]))
    .unwrap();
    let markdown = render_markdown(&output);

    let finding = &output.analysis.findings[0];
    assert_eq!(finding.severity, Severity::Medium);
    let fix = finding.suggested_fix.as_deref().unwrap();
    assert!(fix.contains("destructive security-response policy"));
    assert!(!fix.to_ascii_lowercase().contains("do not wipe"));
    assert!(!markdown.contains("Do not wipe data"));
    assert!(!markdown.contains("allow the user to continue"));
    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
}

#[test]
fn false_missing_await_and_false_scope_claims_do_not_survive() {
    let output = run_case(vec![
        finding!(
            Severity::High,
            ReviewCategory::Correctness,
            Some(RiskCode::MissingAuthorizationCheck),
            "src/auth.ts",
            10,
            "Missing await on getToken",
            "getToken is called without await.",
            "Await getToken before building headers.",
        ),
        finding!(
            Severity::High,
            ReviewCategory::Correctness,
            Some(RiskCode::NilOrNullRisk),
            "src/upload.ts",
            30,
            "tempFile is out of scope in finally",
            "The finally block cannot access `tempFile`.",
            "Declare tempFile outside try.",
        ),
    ]);
    let markdown = render_markdown(&output);

    assert_eq!(output.quality_report.final_priority_findings, 0);
    assert!(!markdown.contains("Missing await"));
    assert!(!markdown.contains("out of scope"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn false_toctou_claim_is_low_hardening_not_blocker() {
    let output = run_case(vec![finding!(
        Severity::High,
        ReviewCategory::Security,
        Some(RiskCode::DataIntegrityRisk),
        "src/cache.ts",
        40,
        "TOCTOU symlink deletion can wipe data",
        "Cache cleanup can follow a symlink and delete user data.",
        "Use non-following deletion APIs.",
    )]);
    let markdown = render_markdown(&output);

    assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
    assert_eq!(output.quality_report.final_priority_findings, 0);
    assert!(!markdown.contains("Blocking Issues:"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn hardcoded_api_key_drops_without_actual_key_but_secret_logging_remains_with_exact_evidence() {
    let output = run_case(vec![
        finding!(
            Severity::High,
            ReviewCategory::Security,
            Some(RiskCode::SecretLeak),
            "android/AndroidManifest.xml",
            50,
            "Hardcoded Google Maps API key",
            "The manifest hardcodes a Google Maps API key.",
            "Move the API key to build-time configuration.",
        ),
        finding!(
            Severity::High,
            ReviewCategory::Privacy,
            Some(RiskCode::PiiOrSecretLogging),
            "src/logger.ts",
            20,
            "Authorization token logging",
            "The Authorization header token is written to logger.info.",
            "Redact the Authorization token before logging.",
        ),
    ]);
    let markdown = render_markdown(&output);

    assert!(!markdown.contains("Hardcoded Google Maps API key"));
    assert!(markdown.contains("Authorization token logging"));
    assert_eq!(output.quality_report.final_priority_findings, 1);
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn positive_note_spam_and_privacy_contradictions_are_sanitized() {
    let output = run_case(vec![
        finding!(
            Severity::High,
            ReviewCategory::Other("positive_note".to_string()),
            Some(RiskCode::PositiveNote),
            "src/auth.ts",
            11,
            "Positive: security improved",
            "This change improves security. No action needed.",
            "No action needed",
        ),
        finding!(
            Severity::High,
            ReviewCategory::Privacy,
            Some(RiskCode::PiiOrSecretLogging),
            "src/logger.ts",
            20,
            "Authorization token logging",
            "The Authorization header token is written to logger.info.",
            "Redact the Authorization token before logging.",
        ),
    ]);
    let markdown = render_markdown(&output);

    assert!(!markdown.contains("Positive: security improved"));
    assert!(markdown.contains("Potential privacy risks"));
    assert!(!markdown.contains("No obvious new PII or secret exposure detected"));
    assert_final_markdown_invariants(&markdown);
}

#[test]
fn medium_data_integrity_finding_does_not_block_or_force_path_policy() {
    let mut input = input(vec![finding!(
        Severity::Medium,
        ReviewCategory::DataIntegrity,
        Some(RiskCode::DataIntegrityRisk),
        "src/offline/syncQueue.ts",
        60,
        "Offline sync failure can drop queued writes",
        "The retry failure path clears the queue without persisting failed writes.",
        "Persist failed writes and add a recovery test for retry exhaustion.",
    )]);
    input.diffs = vec![diff(
        "src/offline/syncQueue.ts",
        "@@ -1 +1 @@\n+queue.clear();\n",
    )];
    input.changed_files = vec!["src/offline/syncQueue.ts".to_string()];
    input.diff_stats = Some(DiffStats {
        changed_file_count: 1,
        total_diff_bytes: 120,
        ..DiffStats::default()
    });
    let output = run_review_quality_pipeline(input).unwrap();
    let markdown = render_markdown(&output);

    assert_eq!(output.risk_assessment.decision, MergeDecision::NeedsHuman);
    assert!(!markdown.contains("Modified offline sync layer without adding recovery test"));
    assert!(!markdown.contains("Add sync recovery test"));
    assert_final_markdown_invariants(&markdown);
}

fn assert_final_markdown_invariants(markdown: &str) {
    assert!(markdown
        .contains("[AI generated by ReviewGate](https://github.com/anggaprytn/review-gate)"));
    assert!(!markdown.contains("raw AI"));
    assert!(!markdown.contains("As an AI"));
    assert!(!markdown.contains("Touched protected module"));
    assert!(!markdown.contains("|---\n|---"));
}

fn render_markdown(output: &reviewgate::review::pipeline::ReviewQualityPipelineOutput) -> String {
    format_review_markdown_for_mode_with_risk_gate(
        &output.analysis,
        MarkdownRenderMode::Publish,
        false,
        Some(&output.risk_assessment),
    )
}

fn run_case(
    findings: Vec<ReviewFinding>,
) -> reviewgate::review::pipeline::ReviewQualityPipelineOutput {
    run_review_quality_pipeline(input(findings)).unwrap()
}

fn input(findings: Vec<ReviewFinding>) -> ReviewQualityPipelineInput {
    ReviewQualityPipelineInput {
        analysis: ReviewAnalysis {
            summary: "- Unrelated hardcoded blocker should not survive.\n- Authorization token logging in src/logger.ts.".to_string(),
            findings,
            test_coverage_note: Some("- malformed coverage bullet\n- Add sync recovery test".to_string()),
            privacy_note: Some(
                "No obvious new PII or secret exposure detected. Authorization token may be logged."
                    .to_string(),
            ),
            overall_risk: OverallRisk::High,
        },
        changed_files: vec![
            "src/db.ts".to_string(),
            "src/logger.ts".to_string(),
            "src/auth.ts".to_string(),
            "src/upload.ts".to_string(),
            "src/cache.ts".to_string(),
            "android/AndroidManifest.xml".to_string(),
        ],
        diff_context: Some(anchors()),
        current_file_provider: None,
        comparison: None,
        large_review_stats: None,
        config: ReviewConfig {
            max_inline_comments: 8,
            severity_threshold: "medium".to_string(),
            max_diff_bytes: 200_000,
            max_files: 50,
        },
        risk_gate_config: Some(RiskGateConfig {
            enabled: true,
            publish: true,
            block_threshold: 90,
            needs_human_threshold: 50,
            protected_paths: Vec::new(),
            owner_reviews: HashMap::new(),
            required_tests: HashMap::new(),
            contract_paths: Vec::new(),
            migration_paths: Vec::new(),
        }),
        diffs: vec![
            diff("src/db.ts", "@@ -1 +1 @@\n+db.query(`select * from payments where customer = ${customerId}`);\n"),
            diff("src/logger.ts", "@@ -1 +1 @@\n+logger.info('Authorization', authorizationToken);\n"),
            diff("src/auth.ts", "@@ -1 +1 @@\n+const token = await getToken();\n"),
            diff("src/upload.ts", "@@ -1 +1 @@\n+let tempFile = null; try { tempFile = createTempFile(); } finally { cleanup(tempFile); }\n"),
            diff("src/cache.ts", "@@ -1 +1 @@\n+const ok = file.canonicalPath.startsWith(cacheDir.canonicalPath);\n"),
            diff("android/AndroidManifest.xml", "@@ -1 +1 @@\n+<meta-data android:value=\"${MAPS_API_KEY}\" />\n"),
        ],
        diff_stats: Some(DiffStats {
            changed_file_count: 6,
            total_diff_bytes: 600,
            ..DiffStats::default()
        }),
    }
}

fn security_input(findings: Vec<ReviewFinding>) -> ReviewQualityPipelineInput {
    let mut input = input(findings);
    input.changed_files = vec!["src/security.ts".to_string()];
    input.diff_context = Some(anchors_for(&[(
        "src/security.ts",
        10,
        "if (integrityUnknown || rootUnknown) { block(); return true; } clearTokens(); wipeLocalData();",
    )]));
    input.diffs = vec![diff(
        "src/security.ts",
        "@@ -10 +10 @@\n+if (integrityUnknown || rootUnknown) { block(); return true; } clearTokens(); wipeLocalData();",
    )];
    input.diff_stats = Some(DiffStats {
        changed_file_count: 1,
        total_diff_bytes: 180,
        ..DiffStats::default()
    });
    input
}

struct FindingSpec<'a> {
    severity: Severity,
    category: ReviewCategory,
    risk_code: Option<RiskCode>,
    file_path: &'a str,
    line: u32,
    title: &'a str,
    body: &'a str,
    suggested_fix: &'a str,
}

fn finding(spec: FindingSpec<'_>) -> ReviewFinding {
    ReviewFinding {
        severity: spec.severity,
        category: spec.category,
        risk_code: spec.risk_code,
        anchor_id: Some(format!("{}:{}", spec.file_path, spec.line)),
        file_path: Some(spec.file_path.to_string()),
        line: Some(spec.line),
        title: spec.title.to_string(),
        body: spec.body.to_string(),
        suggested_fix: Some(spec.suggested_fix.to_string()),
        effort: Effort::Moderate,
        actionable: true,
        evidence_status: None,
        evidence_reason: None,
    }
}

fn anchors() -> AnchoredDiffContext {
    let entries = [
        ("src/db.ts", 10, "db.query(`select * from payments where customer = ${customerId}`);"),
        ("src/logger.ts", 20, "logger.info('Authorization', authorizationToken);"),
        ("src/auth.ts", 10, "const token = await getToken();"),
        (
            "src/upload.ts",
            30,
            "let tempFile = null; try { tempFile = createTempFile(); } finally { cleanup(tempFile); }",
        ),
        (
            "src/cache.ts",
            40,
            "const ok = file.canonicalPath.startsWith(cacheDir.canonicalPath);",
        ),
        (
            "android/AndroidManifest.xml",
            50,
            "<meta-data android:value=\"${MAPS_API_KEY}\" />",
        ),
        (
            "src/offline/syncQueue.ts",
            60,
            "queue.clear(); // retry failure path",
        ),
    ];
    let anchors = entries
        .iter()
        .map(|(path, line, content)| ReviewLineAnchor {
            anchor_id: format!("{path}:{line}"),
            file_path: (*path).to_string(),
            old_path: (*path).to_string(),
            new_path: (*path).to_string(),
            old_line: None,
            new_line: Some(*line),
            kind: AnchorLineKind::Added,
            content_preview: (*content).to_string(),
        })
        .collect::<Vec<_>>();
    AnchoredDiffContext {
        prompt_text: entries
            .iter()
            .map(|(_, _, content)| *content)
            .collect::<Vec<_>>()
            .join("\n"),
        total_anchors: anchors.len(),
        anchors,
        truncated: false,
    }
}

fn anchors_for(entries: &[(&str, u32, &str)]) -> AnchoredDiffContext {
    let anchors = entries
        .iter()
        .map(|(path, line, content)| ReviewLineAnchor {
            anchor_id: format!("{path}:{line}"),
            file_path: (*path).to_string(),
            old_path: (*path).to_string(),
            new_path: (*path).to_string(),
            old_line: None,
            new_line: Some(*line),
            kind: AnchorLineKind::Added,
            content_preview: (*content).to_string(),
        })
        .collect::<Vec<_>>();
    AnchoredDiffContext {
        prompt_text: entries
            .iter()
            .map(|(_, _, content)| *content)
            .collect::<Vec<_>>()
            .join("\n"),
        total_anchors: anchors.len(),
        anchors,
        truncated: false,
    }
}

fn diff_refs() -> DiffRefs {
    DiffRefs {
        base_sha: Some("base".to_string()),
        start_sha: Some("start".to_string()),
        head_sha: Some("head".to_string()),
    }
}

fn diff(path: &str, diff: &str) -> MergeRequestDiff {
    MergeRequestDiff {
        old_path: path.to_string(),
        new_path: path.to_string(),
        diff: diff.to_string(),
        new_file: false,
        renamed_file: false,
        deleted_file: false,
        generated_file: None,
        collapsed: None,
        too_large: None,
    }
}
