use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
    review::types::{ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode},
};
use std::collections::{BTreeSet, HashMap};

const MAX_PRIORITY_CHECKS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum QaCheckKind {
    SecuritySession,
    MobileRuntime,
    UploadCleanup,
    ApiNetwork,
    NavigationRouting,
    TestCoverage,
}

#[derive(Debug, Clone)]
struct QaCheck {
    kind: QaCheckKind,
    files: BTreeSet<String>,
    findings: BTreeSet<String>,
}

impl QaCheck {
    fn new(kind: QaCheckKind) -> Self {
        Self {
            kind,
            files: BTreeSet::new(),
            findings: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AreaCounts {
    security: usize,
    mobile: usize,
    cleanup: usize,
    api: usize,
    navigation: usize,
}

pub fn format_qa_checklist(analysis: &ReviewAnalysis, changed_files: &[String]) -> String {
    let mut checks = collect_checks(analysis, changed_files);
    checks.sort_by_key(|check| check.kind);
    checks.truncate(MAX_PRIORITY_CHECKS);

    let counts = area_counts(&checks);
    let mut output = String::new();
    output.push_str("# ReviewGate Human QA Checklist\n\n");
    output.push_str("Generated from ReviewGate findings and changed files.\n\n");
    output.push_str("## QA Summary\n\n");
    output.push_str(&format!("Manual checks recommended: {}\n\n", checks.len()));
    output.push_str("| Area | Count |\n");
    output.push_str("|---|---:|\n");
    output.push_str(&format!(
        "| 🔐 Security-sensitive flows | {} |\n",
        counts.security
    ));
    output.push_str(&format!(
        "| 📱 Mobile runtime behavior | {} |\n",
        counts.mobile
    ));
    output.push_str(&format!(
        "| 🧹 Cleanup/session behavior | {} |\n",
        counts.cleanup
    ));
    output.push_str(&format!("| 🌐 API/network behavior | {} |\n", counts.api));
    output.push_str(&format!(
        "| 🧭 Navigation/routing behavior | {} |\n",
        counts.navigation
    ));
    output.push_str("\n## Priority Manual Checks\n\n");

    if checks.is_empty() {
        output.push_str("No targeted manual QA checks were triggered from the reviewed findings or changed file paths.\n\n");
    } else {
        for (index, check) in checks.iter().enumerate() {
            if index > 0 {
                output.push('\n');
            }
            push_check(&mut output, check);
        }
    }

    output.push_str("## Regression Checks\n\n");
    for item in regression_checks(analysis, changed_files) {
        output.push_str("- ");
        output.push_str(&item);
        output.push('\n');
    }

    output.push_str("\n## Notes\n\n");
    output.push_str("This checklist is generated from changed files and ReviewGate findings. It is not a substitute for product acceptance criteria.\n");
    if has_test_coverage_signal(analysis) {
        output.push_str("\nReviewGate flagged test coverage as needing manual attention.\n");
    }
    if has_privacy_signal(analysis) {
        output.push_str("\nReviewGate included privacy-related context; include privacy-sensitive assertions where relevant.\n");
    }
    output.push('\n');
    output.push_str(REVIEWGATE_ATTRIBUTION);
    output.push('\n');

    output
}

fn collect_checks(analysis: &ReviewAnalysis, changed_files: &[String]) -> Vec<QaCheck> {
    let mut checks: HashMap<QaCheckKind, QaCheck> = HashMap::new();

    for path in changed_files
        .iter()
        .filter(|path| is_publishable_path(path))
    {
        for kind in check_kinds_for_path(path) {
            checks
                .entry(kind)
                .or_insert_with(|| QaCheck::new(kind))
                .files
                .insert(path.trim().to_string());
        }
    }

    for finding in &analysis.findings {
        for kind in check_kinds_for_finding(finding) {
            let check = checks.entry(kind).or_insert_with(|| QaCheck::new(kind));
            if let Some(path) = finding
                .file_path
                .as_deref()
                .filter(|path| is_publishable_path(path))
            {
                check.files.insert(path.trim().to_string());
            }
            check.findings.insert(finding_label(finding));
        }
    }

    if has_test_coverage_signal(analysis) || changed_files_have_no_matching_tests(changed_files) {
        let check = checks
            .entry(QaCheckKind::TestCoverage)
            .or_insert_with(|| QaCheck::new(QaCheckKind::TestCoverage));
        for path in changed_files
            .iter()
            .filter(|path| is_publishable_path(path) && !is_test_path(path))
            .take(5)
        {
            check.files.insert(path.trim().to_string());
        }
        for finding in analysis.findings.iter().filter(|finding| {
            finding.risk_code == Some(RiskCode::MissingTestCoverage)
                || finding.category == ReviewCategory::TestCoverage
        }) {
            check.findings.insert(finding_label(finding));
        }
    }

    checks.into_values().collect()
}

fn check_kinds_for_finding(finding: &ReviewFinding) -> Vec<QaCheckKind> {
    let mut kinds = Vec::new();
    if matches!(
        finding.category,
        ReviewCategory::Security | ReviewCategory::Privacy | ReviewCategory::DataIntegrity
    ) || matches!(
        finding.risk_code,
        Some(
            RiskCode::AuthBypass
                | RiskCode::MissingAuthorizationCheck
                | RiskCode::SecretLeak
                | RiskCode::PiiOrSecretLogging
                | RiskCode::DataIntegrityRisk
        )
    ) {
        kinds.push(QaCheckKind::SecuritySession);
    }
    if matches!(
        finding.risk_code,
        Some(RiskCode::MissingTimeout | RiskCode::UnboundedRetry | RiskCode::ApiContractBreak)
    ) || finding.category == ReviewCategory::ApiContract
    {
        kinds.push(QaCheckKind::ApiNetwork);
    }
    if matches!(finding.risk_code, Some(RiskCode::MissingTestCoverage))
        || finding.category == ReviewCategory::TestCoverage
    {
        kinds.push(QaCheckKind::TestCoverage);
    }
    if let Some(path) = finding.file_path.as_deref() {
        kinds.extend(check_kinds_for_path(path));
    }
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

fn check_kinds_for_path(path: &str) -> Vec<QaCheckKind> {
    let normalized = path.to_ascii_lowercase();
    let mut kinds = Vec::new();

    if contains_any(
        &normalized,
        &[
            "auth",
            "login",
            "logout",
            "token",
            "session",
            "security",
            "root",
            "jailbreak",
            "integrity",
            "permission",
            "middleware",
        ],
    ) {
        kinds.push(QaCheckKind::SecuritySession);
    }
    if is_mobile_runtime_path(path, &normalized) {
        kinds.push(QaCheckKind::MobileRuntime);
    }
    if contains_any(
        &normalized,
        &[
            "upload",
            "photo",
            "image",
            "signature",
            "rnfs",
            "temp",
            "cache",
            "cleanup",
        ],
    ) {
        kinds.push(QaCheckKind::UploadCleanup);
    }
    if contains_any(
        &normalized,
        &[
            "api", "fetch", "axios", "client", "webhook", "request", "timeout", "retry",
        ],
    ) {
        kinds.push(QaCheckKind::ApiNetwork);
    }
    if contains_any(
        &normalized,
        &["navigation", "route", "redirect", "accessdenied", "blocked"],
    ) {
        kinds.push(QaCheckKind::NavigationRouting);
    }

    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

fn is_mobile_runtime_path(original_path: &str, normalized: &str) -> bool {
    original_path.ends_with(".kt")
        || original_path.ends_with(".java")
        || original_path.ends_with(".gradle")
        || normalized.contains("/android/")
        || contains_any(
            normalized,
            &[
                "mainactivity",
                "mainapplication",
                "nativemodule",
                "androidmanifest",
                "network_security_config",
                "webview",
                "device integrity",
            ],
        )
}

fn area_counts(checks: &[QaCheck]) -> AreaCounts {
    let mut counts = AreaCounts::default();
    for check in checks {
        match check.kind {
            QaCheckKind::SecuritySession => counts.security += 1,
            QaCheckKind::MobileRuntime => counts.mobile += 1,
            QaCheckKind::UploadCleanup => counts.cleanup += 1,
            QaCheckKind::ApiNetwork => counts.api += 1,
            QaCheckKind::NavigationRouting => counts.navigation += 1,
            QaCheckKind::TestCoverage => {}
        }
    }
    counts
}

fn push_check(output: &mut String, check: &QaCheck) {
    output.push_str("### ");
    output.push_str(check_title(check.kind));
    output.push_str("\n\nCheck:\n");
    for item in check_steps(check.kind) {
        output.push_str("- ");
        output.push_str(item);
        output.push('\n');
    }
    output.push_str("\nRelated files:\n");
    push_limited_values(
        output,
        &check.files,
        "No directly related changed file was identified.",
    );
    output.push_str("\nRelated ReviewGate findings:\n");
    push_limited_values(
        output,
        &check.findings,
        "No directly related ReviewGate finding was identified.",
    );
    output.push('\n');
}

fn check_title(kind: QaCheckKind) -> &'static str {
    match kind {
        QaCheckKind::SecuritySession => "🔐 Compromised device/session handling",
        QaCheckKind::MobileRuntime => "📱 Mobile runtime startup behavior",
        QaCheckKind::UploadCleanup => "🧹 Upload temp-file cleanup",
        QaCheckKind::ApiNetwork => "🌐 API/network failure handling",
        QaCheckKind::NavigationRouting => "🧭 Navigation and blocked-route handling",
        QaCheckKind::TestCoverage => "🧪 Targeted regression coverage gap",
    }
}

fn check_steps(kind: QaCheckKind) -> &'static [&'static str] {
    match kind {
        QaCheckKind::SecuritySession => &[
            "Trigger an unauthorized, expired-session, or compromised-device condition; expect protected flows to be blocked.",
            "Confirm the active session is cleared when access is denied; expect no authenticated request to continue.",
            "Confirm blocked or access-denied UI appears; expect the user to be redirected away from sensitive screens.",
        ],
        QaCheckKind::MobileRuntime => &[
            "Start the app on a clean Android install; expect startup to complete without a native crash.",
            "Start the app after an upgrade install; expect native modules, manifest permissions, and WebView-dependent screens to load.",
            "Exercise device-integrity or network-security checks when present; expect failures to show a controlled blocked state.",
        ],
        QaCheckKind::UploadCleanup => &[
            "Complete a successful upload; expect temporary files and loading state to be cleared afterward.",
            "Force an upload or API failure; expect temporary files to be cleaned and retry controls to remain usable.",
            "Retry after failure; expect the retry to create fresh upload input and not reuse stale files.",
        ],
        QaCheckKind::ApiNetwork => &[
            "Force a slow or timed-out API response; expect timeout handling to stop loading and show recoverable feedback.",
            "Force a retryable server or webhook failure; expect retries to stay bounded and not duplicate user actions.",
            "Confirm successful responses still update the visible state; expect no stale data after completion.",
        ],
        QaCheckKind::NavigationRouting => &[
            "Open protected routes while unauthorized; expect redirect or access-denied behavior before sensitive content renders.",
            "Navigate back after a blocked route; expect the user to land on an allowed screen.",
            "Repeat the flow after login/logout; expect route guards to follow the current session state.",
        ],
        QaCheckKind::TestCoverage => &[
            "Run the nearest automated tests for the changed area; expect critical user paths to be covered or manually verified.",
            "Exercise the changed behavior manually when no matching test changed; expect the documented acceptance behavior to hold.",
            "Check one adjacent regression path; expect unchanged flows around the modified code to still pass.",
        ],
    }
}

fn regression_checks(analysis: &ReviewAnalysis, changed_files: &[String]) -> Vec<String> {
    let mut checks = vec![
        "Login works and lands on the expected authenticated screen.".to_string(),
        "Logout clears session state and redirects correctly.".to_string(),
        "Sensitive screens still render only for authorized users.".to_string(),
        "Upload, incident, or task flows touched by this MR still complete successfully."
            .to_string(),
        "App startup and first navigation do not crash.".to_string(),
    ];

    if changed_files
        .iter()
        .any(|path| check_kinds_for_path(path).contains(&QaCheckKind::ApiNetwork))
    {
        checks.push("Network failure recovery resets loading and error state.".to_string());
    }
    if has_test_coverage_signal(analysis) {
        checks.push(
            "Manual regression evidence is captured for behavior without automated coverage."
                .to_string(),
        );
    }
    checks
}

fn push_limited_values(output: &mut String, values: &BTreeSet<String>, empty: &str) {
    if values.is_empty() {
        output.push_str("- ");
        output.push_str(empty);
        output.push('\n');
        return;
    }

    for value in values.iter().take(5) {
        output.push_str("- `");
        output.push_str(&escape_backticks(value));
        output.push_str("`\n");
    }
}

fn finding_label(finding: &ReviewFinding) -> String {
    let mut label = format!(
        "{}: {}",
        finding.severity.display_upper(),
        blank_fallback(&finding.title, "Untitled finding")
    );
    if let Some(risk_code) = finding.risk_code {
        label.push_str(" (");
        label.push_str(risk_code.display_lower());
        label.push(')');
    }
    label
}

fn has_test_coverage_signal(analysis: &ReviewAnalysis) -> bool {
    analysis.findings.iter().any(|finding| {
        finding.risk_code == Some(RiskCode::MissingTestCoverage)
            || finding.category == ReviewCategory::TestCoverage
    }) || analysis
        .test_coverage_note
        .as_deref()
        .is_some_and(has_non_empty_signal)
}

fn has_privacy_signal(analysis: &ReviewAnalysis) -> bool {
    analysis
        .privacy_note
        .as_deref()
        .is_some_and(has_non_empty_signal)
        || analysis
            .findings
            .iter()
            .any(|finding| finding.category == ReviewCategory::Privacy)
}

fn has_non_empty_signal(note: &str) -> bool {
    let normalized = note.trim().to_ascii_lowercase();
    !normalized.is_empty()
        && !matches!(
            normalized.as_str(),
            "none" | "n/a" | "no issues" | "no obvious exposure detected"
        )
}

fn changed_files_have_no_matching_tests(changed_files: &[String]) -> bool {
    let has_source = changed_files
        .iter()
        .any(|path| is_publishable_path(path) && !is_test_path(path) && is_source_like_path(path));
    let has_test = changed_files
        .iter()
        .any(|path| is_publishable_path(path) && is_test_path(path));
    has_source && !has_test
}

fn is_publishable_path(path: &str) -> bool {
    let trimmed = path.trim();
    !trimmed.is_empty()
        && !trimmed.contains('\n')
        && !trimmed.starts_with("diff --git ")
        && !trimmed.starts_with("@@")
}

fn is_source_like_path(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    !normalized.ends_with(".md")
        && !normalized.ends_with(".png")
        && !normalized.ends_with(".jpg")
        && !normalized.ends_with(".jpeg")
        && !normalized.ends_with(".gif")
        && !normalized.ends_with(".lock")
}

fn is_test_path(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    normalized.contains("/test/")
        || normalized.contains("/tests/")
        || normalized.contains("__tests__")
        || normalized.contains(".test.")
        || normalized.contains(".spec.")
        || normalized.ends_with("_test.go")
        || normalized.ends_with("test.kt")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn blank_fallback<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value.trim()
    }
}

fn escape_backticks(value: &str) -> String {
    value.replace('`', "'")
}

#[cfg(test)]
mod tests {
    use super::format_qa_checklist;
    use crate::review::types::{
        Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode, Severity,
    };

    #[test]
    fn qa_checklist_generated_from_security_finding() {
        let analysis = analysis_with_findings(vec![finding(
            Severity::High,
            ReviewCategory::Security,
            Some(RiskCode::AuthBypass),
            Some("src/auth/session.ts"),
            "Session can continue after auth failure",
            "RAW_LLM_OUTPUT_BODY",
        )]);

        let checklist = format_qa_checklist(&analysis, &["src/auth/session.ts".to_string()]);

        assert!(checklist.contains("# ReviewGate Human QA Checklist"));
        assert!(checklist.contains("Compromised device/session handling"));
        assert!(checklist.contains("expect protected flows to be blocked"));
        assert!(checklist.contains("`src/auth/session.ts`"));
        assert!(checklist.contains("HIGH: Session can continue after auth failure"));
        assert!(!checklist.contains("RAW_LLM_OUTPUT_BODY"));
    }

    #[test]
    fn qa_checklist_generated_from_upload_temp_file_finding() {
        let analysis = analysis_with_findings(vec![finding(
            Severity::Medium,
            ReviewCategory::Reliability,
            Some(RiskCode::UnclosedResource),
            Some("src/upload/tempCleanup.ts"),
            "Temp files remain after failed upload",
            "details",
        )]);

        let checklist = format_qa_checklist(&analysis, &["src/upload/tempCleanup.ts".to_string()]);

        assert!(checklist.contains("Upload temp-file cleanup"));
        assert!(checklist.contains("Force an upload or API failure"));
        assert!(checklist.contains("Temp files remain after failed upload"));
    }

    #[test]
    fn qa_checklist_generated_from_navigation_finding() {
        let analysis = analysis_with_findings(vec![finding(
            Severity::Medium,
            ReviewCategory::Correctness,
            None,
            Some("src/navigation/AccessDenied.tsx"),
            "Blocked route can show sensitive content",
            "details",
        )]);

        let checklist =
            format_qa_checklist(&analysis, &["src/navigation/AccessDenied.tsx".to_string()]);

        assert!(checklist.contains("Navigation and blocked-route handling"));
        assert!(checklist.contains("expect redirect or access-denied behavior"));
    }

    #[test]
    fn qa_checklist_generated_from_android_native_file_changes() {
        let checklist = format_qa_checklist(
            &analysis_with_findings(vec![]),
            &["android/app/src/main/AndroidManifest.xml".to_string()],
        );

        assert!(checklist.contains("Mobile runtime startup behavior"));
        assert!(checklist.contains("expect startup to complete without a native crash"));
    }

    #[test]
    fn duplicate_qa_areas_are_merged() {
        let analysis = analysis_with_findings(vec![finding(
            Severity::High,
            ReviewCategory::Security,
            Some(RiskCode::MissingAuthorizationCheck),
            Some("src/auth/middleware.ts"),
            "Authorization guard is missing",
            "details",
        )]);

        let checklist = format_qa_checklist(
            &analysis,
            &[
                "src/auth/middleware.ts".to_string(),
                "src/security/session.ts".to_string(),
            ],
        );

        assert_eq!(
            checklist
                .matches("Compromised device/session handling")
                .count(),
            1
        );
        assert!(checklist.contains("Manual checks recommended: 2"));
    }

    #[test]
    fn priority_checks_are_limited_to_max_8() {
        let analysis = ReviewAnalysis {
            test_coverage_note: Some("No matching tests changed.".to_string()),
            privacy_note: Some("PII behavior changed.".to_string()),
            ..analysis_with_findings(vec![
                finding(
                    Severity::High,
                    ReviewCategory::Security,
                    Some(RiskCode::AuthBypass),
                    Some("src/auth/login.ts"),
                    "Auth issue",
                    "details",
                ),
                finding(
                    Severity::Medium,
                    ReviewCategory::ApiContract,
                    Some(RiskCode::MissingTimeout),
                    Some("src/api/client.ts"),
                    "Timeout issue",
                    "details",
                ),
                finding(
                    Severity::Medium,
                    ReviewCategory::Correctness,
                    None,
                    Some("android/app/src/main/java/MainActivity.kt"),
                    "Android issue",
                    "details",
                ),
                finding(
                    Severity::Medium,
                    ReviewCategory::Reliability,
                    None,
                    Some("src/upload/photoCache.ts"),
                    "Upload issue",
                    "details",
                ),
                finding(
                    Severity::Medium,
                    ReviewCategory::Correctness,
                    None,
                    Some("src/routes/blocked.tsx"),
                    "Route issue",
                    "details",
                ),
            ])
        };

        let checklist = format_qa_checklist(
            &analysis,
            &[
                "src/auth/login.ts".to_string(),
                "src/api/client.ts".to_string(),
                "android/app/src/main/java/MainActivity.kt".to_string(),
                "src/upload/photoCache.ts".to_string(),
                "src/routes/blocked.tsx".to_string(),
            ],
        );
        let count = priority_section_count(&checklist);

        assert!(count <= 8, "priority count was {count}");
    }

    #[test]
    fn qa_checklist_includes_attribution() {
        let checklist = format_qa_checklist(&analysis_with_findings(vec![]), &[]);

        assert!(checklist.contains("[AI generated by ReviewGate]"));
    }

    #[test]
    fn qa_checklist_does_not_include_raw_diff_or_raw_llm_output() {
        let analysis = analysis_with_findings(vec![finding(
            Severity::High,
            ReviewCategory::Security,
            Some(RiskCode::SecretLeak),
            Some("src/auth/token.ts"),
            "Secret exposure risk",
            "diff --git a/src/auth/token.ts b/src/auth/token.ts\nRAW_LLM_OUTPUT",
        )]);

        let checklist = format_qa_checklist(
            &analysis,
            &[
                "src/auth/token.ts".to_string(),
                "diff --git a/raw b/raw".to_string(),
            ],
        );

        assert!(!checklist.contains("RAW_LLM_OUTPUT"));
        assert!(!checklist.contains("diff --git"));
    }

    fn priority_section_count(checklist: &str) -> usize {
        checklist
            .lines()
            .filter(|line| line.starts_with("### "))
            .count()
    }

    fn analysis_with_findings(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "Summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Medium,
        }
    }

    fn finding(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        file_path: Option<&str>,
        title: &str,
        body: &str,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category,
            risk_code,
            anchor_id: None,
            file_path: file_path.map(str::to_string),
            line: Some(42),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: None,
            effort: Effort::Moderate,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }
}
