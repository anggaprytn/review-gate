use crate::review::{
    risk::{MergeDecision, MergeRiskAssessment, RiskEvidence, RiskGateItem},
    types::{EvidenceValidationStatus, ReviewAnalysis, ReviewFinding, RiskCode, Severity},
};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReport {
    pub analysis: ReviewAnalysis,
    pub risk_assessment: Option<MergeRiskAssessment>,
}

pub fn sanitize_review_report(mut report: ReviewReport) -> ReviewReport {
    report.analysis = sanitize_review_analysis(report.analysis);
    if let Some(assessment) = report.risk_assessment.take() {
        report.risk_assessment = Some(sanitize_merge_risk_assessment(&report.analysis, assessment));
    }
    report
}

pub fn sanitize_merge_risk_assessment(
    analysis: &ReviewAnalysis,
    mut assessment: MergeRiskAssessment,
) -> MergeRiskAssessment {
    assessment.blocking_issues.retain(|item| {
        evidence_backed_gate_item(item) && hardcoded_item_has_matching_evidence(item)
    });
    assessment.required_before_merge.retain(|item| {
        evidence_backed_gate_item(item) && hardcoded_item_has_matching_evidence(item)
    });

    replace_generic_required_actions(analysis, &mut assessment.required_before_merge);
    add_missing_finding_actions(analysis, &mut assessment.required_before_merge);
    dedupe_gate_items(&mut assessment.blocking_issues);
    dedupe_gate_items(&mut assessment.required_before_merge);

    let has_critical = analysis.findings.iter().any(|finding| {
        validated_actionable_finding(finding) && finding.severity == Severity::Critical
    });
    let has_high = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable_finding(finding) && finding.severity == Severity::High);
    let has_policy_hard_blocker = assessment
        .blocking_issues
        .iter()
        .any(true_policy_hard_blocker);

    if !has_critical && !has_high && !has_policy_hard_blocker {
        assessment.score = assessment
            .score
            .min(medium_only_score_cap(analysis, &assessment));
        if assessment.decision == MergeDecision::Blocked {
            assessment.decision = if should_need_human(analysis, &assessment) {
                MergeDecision::NeedsHuman
            } else {
                MergeDecision::Pass
            };
        }
    }

    if assessment.decision == MergeDecision::Pass && should_need_human(analysis, &assessment) {
        assessment.decision = MergeDecision::NeedsHuman;
    }

    assessment
}

fn sanitize_review_analysis(mut analysis: ReviewAnalysis) -> ReviewAnalysis {
    analysis.summary = sanitize_summary(&analysis.summary, &analysis.findings);
    analysis.test_coverage_note = sanitize_optional_note(analysis.test_coverage_note);
    analysis.privacy_note = sanitize_optional_note(analysis.privacy_note);
    analysis.findings.retain(renderable_final_finding);
    analysis
}

fn sanitize_summary(summary: &str, findings: &[ReviewFinding]) -> String {
    let mut output = Vec::new();
    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            output.push(String::new());
            continue;
        }
        if is_bullet(trimmed) {
            let item = bullet_text(trimmed);
            if has_item_evidence(item, findings) {
                output.push(trimmed.to_string());
            }
            continue;
        }
        if !contains_forbidden_hardcoded_text(trimmed) {
            output.push(trimmed.to_string());
        }
    }
    let sanitized = output.join("\n").trim().to_string();
    if sanitized.is_empty() {
        "ReviewGate found no evidence-backed summary bullets to publish.".to_string()
    } else {
        sanitized
    }
}

fn sanitize_optional_note(note: Option<String>) -> Option<String> {
    note.map(|note| {
        note.lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !contains_forbidden_hardcoded_text(trimmed)
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
    .filter(|note| !note.trim().is_empty())
}

fn renderable_final_finding(finding: &ReviewFinding) -> bool {
    if finding.risk_code == Some(RiskCode::PositiveNote) {
        return validated_positive_note(finding)
            && positive_note_safe_topic(finding)
            && !negative_positive_note_text(finding);
    }
    true
}

fn evidence_backed_gate_item(item: &RiskGateItem) -> bool {
    !item.label.trim().is_empty()
        && !item.evidence.is_empty()
        && item.evidence.iter().any(evidence_has_signal)
}

fn evidence_has_signal(evidence: &RiskEvidence) -> bool {
    evidence
        .file_path
        .as_deref()
        .is_some_and(|path| !path.trim().is_empty())
        || evidence
            .finding_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty())
        || evidence
            .risk_code
            .as_deref()
            .is_some_and(|risk_code| !risk_code.trim().is_empty())
        || evidence.rule_id.starts_with("verification.")
        || evidence.rule_id.starts_with("comparison.")
}

fn hardcoded_item_has_matching_evidence(item: &RiskGateItem) -> bool {
    let label = item.label.as_str();
    if label.contains("Modified offline sync") || label.contains("Add sync recovery test") {
        return item.evidence.iter().any(|evidence| {
            evidence.rule_id.contains("offline_sync")
                && evidence
                    .file_path
                    .as_deref()
                    .is_some_and(offline_sync_path_signal)
        });
    }
    if label.contains("Changed API response contract") {
        return item
            .evidence
            .iter()
            .any(|evidence| evidence.rule_id.contains("api_contract"));
    }
    if label.contains("Added DB migration") {
        return item
            .evidence
            .iter()
            .any(|evidence| evidence.rule_id.contains("migration"));
    }
    if label.contains("Touched protected module") {
        return item
            .evidence
            .iter()
            .any(|evidence| evidence.rule_id.contains("protected_path"));
    }
    !contains_forbidden_hardcoded_text(label)
}

fn replace_generic_required_actions(analysis: &ReviewAnalysis, items: &mut Vec<RiskGateItem>) {
    for item in items.iter_mut() {
        if !is_generic_required_action(&item.label) {
            continue;
        }
        if let Some(finding) = matching_finding_for_item(analysis, item) {
            item.label = finding_required_action(finding);
        }
    }
    items.retain(|item| !is_generic_required_action(&item.label));
}

fn add_missing_finding_actions(analysis: &ReviewAnalysis, items: &mut Vec<RiskGateItem>) {
    let mut existing = items
        .iter()
        .map(|item| normalize_key(&item.label))
        .collect::<HashSet<_>>();
    for finding in analysis
        .findings
        .iter()
        .filter(|finding| validated_actionable_finding(finding))
        .filter(|finding| {
            matches!(
                finding.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        })
    {
        let action = finding_required_action(finding);
        let key = normalize_key(&action);
        if key.is_empty() || existing.contains(&key) {
            continue;
        }
        let evidence = finding_evidence(finding);
        if evidence.is_empty() {
            continue;
        }
        items.push(RiskGateItem {
            label: action,
            evidence,
        });
        existing.insert(key);
    }
}

fn matching_finding_for_item<'a>(
    analysis: &'a ReviewAnalysis,
    item: &RiskGateItem,
) -> Option<&'a ReviewFinding> {
    analysis.findings.iter().find(|finding| {
        item.evidence.iter().any(|evidence| {
            evidence
                .file_path
                .as_deref()
                .zip(finding.file_path.as_deref())
                .is_some_and(|(left, right)| left == right)
                || evidence.risk_code.as_deref().is_some_and(|risk_code| {
                    finding
                        .risk_code
                        .is_some_and(|finding_code| finding_code.display_lower() == risk_code)
                })
        })
    })
}

fn finding_evidence(finding: &ReviewFinding) -> Vec<RiskEvidence> {
    if finding
        .file_path
        .as_deref()
        .is_none_or(|path| path.trim().is_empty())
        && finding
            .anchor_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty())
        && finding.risk_code.is_none()
    {
        return Vec::new();
    }
    vec![RiskEvidence {
        source: crate::review::risk::RiskEvidenceSource::Finding,
        file_path: finding.file_path.clone(),
        finding_id: finding.anchor_id.clone(),
        risk_code: finding
            .risk_code
            .map(|risk_code| risk_code.display_lower().to_string()),
        rule_id: "publisher_sanitizer.finding_action".to_string(),
        description: "Final validated finding used for publisher-required action.".to_string(),
    }]
}

fn finding_required_action(finding: &ReviewFinding) -> String {
    let text = format!(
        "{} {} {}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding.title,
        finding.body
    )
    .to_ascii_lowercase();

    if finding.risk_code == Some(RiskCode::SecretLeak)
        && contains_any(
            &text,
            &["google maps", "maps api key", "androidmanifest.xml"],
        )
    {
        return "Confirm the Google Maps API key is package/SHA restricted or move it to build-time configuration.".to_string();
    }
    if finding.risk_code == Some(RiskCode::PiiOrSecretLogging)
        || (finding.risk_code == Some(RiskCode::SecretLeak)
            && contains_any(&text, &["log", "logged", "logging", "header", "token"]))
    {
        return format!(
            "Remove or sanitize sensitive logging in {}.",
            finding_file_path(finding)
        );
    }
    if finding.risk_code == Some(RiskCode::WeakErrorHandling) {
        if contains_any(
            &text,
            &["toast", "untrusted", "application warning", "build warning"],
        ) {
            return "Replace transient Toast-only untrusted-build warning with a persistent blocking error state.".to_string();
        }
        if contains_any(
            &text,
            &["antiinstrumentation", "native security", "security check"],
        ) {
            return "Surface or log native security check failures without silently swallowing diagnostic details.".to_string();
        }
        if contains_any(
            &text,
            &[
                "signature",
                "verification",
                "broad exception",
                "exception handling",
            ],
        ) {
            return "Log expected signature-verification exceptions without weakening fail-closed behavior.".to_string();
        }
        if contains_any(&text, &["webhook", "json", "parse", "payload", "malformed"]) {
            return "Fix webhook parse failure handling so malformed payloads are not silently accepted.".to_string();
        }
        if contains_any(
            &text,
            &[
                "navigationref",
                "navigation reset",
                "max-retry",
                "max retry",
            ],
        ) {
            return format!(
                "Handle max-retry navigation reset failures with a visible fallback or error state in {}.",
                finding_file_path(finding)
            );
        }
    }
    if contains_any(
        &text,
        &["webview", "logout", "fixed timeout", "cleanup timeout"],
    ) {
        return "Add monitoring or fallback behavior for WebView cleanup timeout during logout."
            .to_string();
    }
    if finding.risk_code == Some(RiskCode::DataIntegrityRisk)
        && contains_any(&text, &["wipe", "delete", "local data"])
    {
        return "Add guardrails for compromised-device false positives before wiping local user data."
            .to_string();
    }
    if let Some(fix) = finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|fix| specific_suggested_fix(fix))
    {
        return sentence_from_text(fix);
    }
    format!(
        "Address {} in {}.",
        sentence_fragment(&finding.title),
        finding_file_path(finding)
    )
}

fn specific_suggested_fix(fix: &str) -> bool {
    let lower = fix.to_ascii_lowercase();
    !lower.is_empty()
        && !matches!(
            lower.as_str(),
            "fix" | "none" | "n/a" | "na" | "no action needed"
        )
        && !lower.starts_with("handle the validated")
}

fn true_policy_hard_blocker(item: &RiskGateItem) -> bool {
    if item.label.contains("Modified offline sync")
        || item.label.contains("Changed API response contract")
        || item.label.contains("Added DB migration")
        || item.label.contains("Touched protected module")
    {
        return hardcoded_item_has_matching_evidence(item);
    }
    item.evidence.iter().any(|evidence| {
        evidence.rule_id.contains("protected_path")
            || evidence.rule_id.contains("migration_or_schema")
            || evidence.rule_id.contains("migration_missing_rollback")
            || evidence.rule_id.contains("api_contract")
            || evidence.rule_id.contains("api_contract_missing_snapshot")
            || evidence.rule_id.contains("offline_sync")
            || evidence
                .rule_id
                .contains("offline_sync_missing_recovery_test")
    })
}

fn medium_only_score_cap(analysis: &ReviewAnalysis, assessment: &MergeRiskAssessment) -> u8 {
    let finding_score = analysis
        .findings
        .iter()
        .filter(|finding| validated_actionable_finding(finding))
        .map(|finding| match finding.severity {
            Severity::Critical => 35,
            Severity::High => 18,
            Severity::Medium => 8,
            Severity::Low => 2,
            Severity::Note => 0,
        })
        .sum::<u8>();
    let partial_review_points = if assessment.blast_radius.failed_chunks > 0
        || assessment.blast_radius.collapsed_files > 0
        || assessment.blast_radius.too_large_files > 0
        || assessment
            .risk_factors
            .iter()
            .any(|factor| factor.rule_id.contains("large") || factor.rule_id.contains("partial"))
    {
        16
    } else {
        0
    };
    finding_score.saturating_add(partial_review_points).min(74)
}

fn should_need_human(analysis: &ReviewAnalysis, assessment: &MergeRiskAssessment) -> bool {
    let medium_count = analysis
        .findings
        .iter()
        .filter(|finding| {
            validated_actionable_finding(finding) && finding.severity == Severity::Medium
        })
        .count();
    medium_count > 1
        || assessment.score >= 40
        || assessment.blast_radius.failed_chunks > 0
        || assessment.blast_radius.collapsed_files > 0
        || assessment.blast_radius.too_large_files > 0
        || assessment
            .risk_factors
            .iter()
            .any(|factor| factor.rule_id.contains("large") || factor.rule_id.contains("partial"))
}

fn validated_actionable_finding(finding: &ReviewFinding) -> bool {
    finding.actionable
        && !matches!(finding.severity, Severity::Note)
        && !matches!(
            finding.evidence_status,
            Some(
                EvidenceValidationStatus::WeakEvidence
                    | EvidenceValidationStatus::StaleContext
                    | EvidenceValidationStatus::NeedsManualConfirmation
                    | EvidenceValidationStatus::PositiveChange
            )
        )
}

fn validated_positive_note(finding: &ReviewFinding) -> bool {
    !finding.actionable
        && finding.severity == Severity::Note
        && !matches!(
            finding.evidence_status,
            Some(
                EvidenceValidationStatus::WeakEvidence
                    | EvidenceValidationStatus::StaleContext
                    | EvidenceValidationStatus::NeedsManualConfirmation
            )
        )
}

fn positive_note_safe_topic(finding: &ReviewFinding) -> bool {
    let text = finding_text(finding);
    contains_any(
        &text,
        &[
            "screen security",
            "input validation coverage",
            "test coverage",
            "coverage improved",
            "storage tests",
            "token storage tests",
            "temporary files",
            "cache-backed storage",
            "redacted",
            "removed",
            "cleanup improved",
            "tests were added",
        ],
    )
}

fn negative_positive_note_text(finding: &ReviewFinding) -> bool {
    contains_any(
        &finding_text(finding),
        &[
            "commented-out",
            "commented out",
            "debug code",
            "secret",
            "token",
            "logging",
            "leak",
            "error",
            "fail",
            "crash",
            "vulnerability",
        ],
    )
}

fn has_item_evidence(item: &str, findings: &[ReviewFinding]) -> bool {
    if contains_forbidden_hardcoded_text(item) {
        return false;
    }
    let item = item.to_ascii_lowercase();
    findings.iter().any(|finding| {
        let path = finding
            .file_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let text = finding_text(finding);
        (!path.is_empty() && item.contains(&path))
            || significant_words(&finding.title)
                .iter()
                .filter(|word| item.contains(word.as_str()))
                .count()
                >= 2
            || finding
                .risk_code
                .is_some_and(|risk_code| item.contains(risk_code.display_lower()))
            || significant_words(&text)
                .iter()
                .filter(|word| item.contains(word.as_str()))
                .count()
                >= 3
    })
}

fn significant_words(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|word| {
            word.len() > 4
                && !matches!(
                    word.as_str(),
                    "without" | "should" | "could" | "finding" | "review" | "validated"
                )
        })
        .collect()
}

fn is_generic_required_action(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    lower.contains("handle the validated error-handling failure")
        || lower.contains("fix error handling so failures are not silently accepted")
        || lower == "fix error handling."
        || lower == "add tests."
}

fn contains_forbidden_hardcoded_text(value: &str) -> bool {
    [
        "Modified offline sync",
        "Add sync recovery test",
        "Fix error handling so failures are not silently accepted",
        "Handle the validated error-handling failure",
        "Changed API response contract",
        "Added DB migration",
        "Touched protected module",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn dedupe_gate_items(items: &mut Vec<RiskGateItem>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(normalize_key(&item.label)));
}

fn normalize_key(value: &str) -> String {
    value
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn is_bullet(line: &str) -> bool {
    line.starts_with("- ") || line.starts_with("* ")
}

fn bullet_text(line: &str) -> &str {
    line.trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_whitespace())
}

fn finding_text(finding: &ReviewFinding) -> String {
    format!("{} {}", finding.title, finding.body).to_ascii_lowercase()
}

fn finding_file_path(finding: &ReviewFinding) -> String {
    finding
        .file_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or("unknown file")
        .to_string()
}

fn sentence_from_text(text: &str) -> String {
    let mut sentence = text.trim().to_string();
    if !matches!(sentence.chars().last(), Some('.') | Some('!') | Some('?')) {
        sentence.push('.');
    }
    sentence
}

fn sentence_fragment(text: &str) -> String {
    text.trim().trim_end_matches(['.', '!', '?']).to_string()
}

fn offline_sync_path_signal(path: &str) -> bool {
    contains_any(
        &path.replace('\\', "/").to_ascii_lowercase(),
        &[
            "sync", "offline", "queue", "retry", "cache", "pending", "recovery",
        ],
    )
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    terms
        .iter()
        .any(|term| value.contains(&term.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::{sanitize_merge_risk_assessment, sanitize_review_report, ReviewReport};
    use crate::review::{
        risk::{
            BlastRadius, MergeDecision, MergeRiskAssessment, RiskEvidence, RiskEvidenceSource,
            RiskFactor, RiskGateItem,
        },
        types::{
            Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory,
            ReviewFinding, RiskCode, Severity,
        },
    };

    #[test]
    fn medium_only_findings_cannot_publish_blocked_by_default() {
        let analysis = analysis(vec![
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::SecretLeak),
                "AndroidManifest.xml",
                "Hardcoded Google Maps API key",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "MainActivity.kt",
                "Untrusted application warning is easily missed",
            ),
        ]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 100,
                decision: MergeDecision::Blocked,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![factor("verification.large_review.failed_chunks")],
                blast_radius: BlastRadius {
                    failed_chunks: 1,
                    ..BlastRadius::default()
                },
            },
        );

        assert_eq!(sanitized.decision, MergeDecision::NeedsHuman);
        assert!(sanitized.score <= 74);
    }

    #[test]
    fn offline_sync_blocker_removed_without_sync_path_evidence() {
        let sanitized = sanitize_merge_risk_assessment(
            &analysis(vec![]),
            MergeRiskAssessment {
                score: 80,
                decision: MergeDecision::Blocked,
                blocking_issues: vec![RiskGateItem {
                    label: "Modified offline sync layer without adding recovery test".to_string(),
                    evidence: vec![evidence(
                        "src/paymentClient.ts",
                        "changed_file.offline_sync_missing_recovery_test",
                    )],
                }],
                required_before_merge: vec![RiskGateItem {
                    label: "Add sync recovery test".to_string(),
                    evidence: vec![evidence(
                        "src/paymentClient.ts",
                        "changed_file.offline_sync_missing_recovery_test",
                    )],
                }],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert!(sanitized.blocking_issues.is_empty());
        assert!(sanitized.required_before_merge.is_empty());
        assert_ne!(sanitized.decision, MergeDecision::Blocked);
    }

    #[test]
    fn generic_required_action_is_replaced_with_finding_specific_action() {
        let analysis = analysis(vec![finding(
            Severity::Medium,
            ReviewCategory::Security,
            Some(RiskCode::WeakErrorHandling),
            "MainActivity.kt",
            "Untrusted application warning is easily missed",
        )]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 40,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![RiskGateItem {
                    label: "Handle the validated error-handling failure in MainActivity.kt"
                        .to_string(),
                    evidence: vec![evidence("MainActivity.kt", "finding.weak_error_handling")],
                }],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert!(sanitized.required_before_merge.iter().any(|item| item.label
            == "Replace transient Toast-only untrusted-build warning with a persistent blocking error state."));
        assert!(!sanitized
            .required_before_merge
            .iter()
            .any(|item| item.label.contains("Handle the validated")));
    }

    #[test]
    fn current_android_sample_regression() {
        let analysis = analysis(vec![
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::SecretLeak),
                "AndroidManifest.xml",
                "Hardcoded Google Maps API key in android manifest",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "MainActivity.kt",
                "Untrusted application warning is easily missed",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AntiInstrumentationModule.kt",
                "Security check fails silently",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AppSignatureVerifier.kt",
                "Overly broad exception handling in signature verification",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Reliability,
                Some(RiskCode::PerformanceRegression),
                "Profile/index.tsx",
                "Logout relies on fixed timeout for WebView cleanup",
            ),
        ]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 100,
                decision: MergeDecision::Blocked,
                blocking_issues: vec![RiskGateItem {
                    label: "Modified offline sync layer without adding recovery test".to_string(),
                    evidence: vec![evidence(
                        "Profile/index.tsx",
                        "changed_file.offline_sync_missing_recovery_test",
                    )],
                }],
                required_before_merge: vec![RiskGateItem {
                    label: "Add sync recovery test".to_string(),
                    evidence: vec![evidence(
                        "Profile/index.tsx",
                        "changed_file.offline_sync_missing_recovery_test",
                    )],
                }],
                risk_factors: vec![factor("verification.large_review.failed_chunks")],
                blast_radius: BlastRadius {
                    failed_chunks: 1,
                    ..BlastRadius::default()
                },
            },
        );

        assert_eq!(sanitized.score, 56);
        assert_eq!(sanitized.decision, MergeDecision::NeedsHuman);
        assert!(sanitized.blocking_issues.is_empty());
        assert!(!labels(&sanitized.required_before_merge)
            .contains(&"Add sync recovery test".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(&"Confirm the Google Maps API key is package/SHA restricted or move it to build-time configuration.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(&"Replace transient Toast-only untrusted-build warning with a persistent blocking error state.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(&"Surface or log native security check failures without silently swallowing diagnostic details.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(&"Log expected signature-verification exceptions without weakening fail-closed behavior.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(
            &"Add monitoring or fallback behavior for WebView cleanup timeout during logout."
                .to_string()
        ));
    }

    #[test]
    fn critical_sql_injection_remains_blocked() {
        let analysis = analysis(vec![finding(
            Severity::Critical,
            ReviewCategory::Security,
            Some(RiskCode::SqlInjection),
            "src/paymentClient.ts",
            "SQL injection in payment lookup",
        )]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 90,
                decision: MergeDecision::Blocked,
                blocking_issues: vec![RiskGateItem {
                    label: "SQL injection in `src/paymentClient.ts`".to_string(),
                    evidence: vec![evidence("src/paymentClient.ts", "finding.injection")],
                }],
                required_before_merge: vec![],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert_eq!(sanitized.decision, MergeDecision::Blocked);
        assert_eq!(sanitized.blocking_issues.len(), 1);
    }

    #[test]
    fn policy_hard_blocker_with_path_evidence_remains_blocked() {
        let sanitized = sanitize_merge_risk_assessment(
            &analysis(vec![]),
            MergeRiskAssessment {
                score: 90,
                decision: MergeDecision::Blocked,
                blocking_issues: vec![RiskGateItem {
                    label: "Touched protected module: `src/auth/**`".to_string(),
                    evidence: vec![evidence("src/auth/session.rs", "policy.protected_path")],
                }],
                required_before_merge: vec![],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert_eq!(sanitized.decision, MergeDecision::Blocked);
        assert_eq!(sanitized.blocking_issues.len(), 1);
    }

    #[test]
    fn unsafe_positive_notes_are_removed() {
        let report = sanitize_review_report(ReviewReport {
            analysis: analysis(vec![
                positive("Commented-out debug code was removed."),
                positive("Screen security hooks were added."),
            ]),
            risk_assessment: None,
        });

        assert_eq!(report.analysis.findings.len(), 1);
        assert_eq!(
            report.analysis.findings[0].title,
            "Screen security hooks were added."
        );
    }

    fn analysis(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Low,
        }
    }

    fn finding(
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
            evidence_status: Some(EvidenceValidationStatus::Validated),
            evidence_reason: None,
        }
    }

    fn positive(title: &str) -> ReviewFinding {
        ReviewFinding {
            severity: Severity::Note,
            category: ReviewCategory::Security,
            risk_code: Some(RiskCode::PositiveNote),
            anchor_id: None,
            file_path: Some("src/App.tsx".to_string()),
            line: Some(1),
            title: title.to_string(),
            body: title.to_string(),
            suggested_fix: None,
            effort: Effort::Moderate,
            actionable: false,
            evidence_status: Some(EvidenceValidationStatus::PositiveChange),
            evidence_reason: None,
        }
    }

    fn evidence(path: &str, rule_id: &str) -> RiskEvidence {
        RiskEvidence {
            source: RiskEvidenceSource::ChangedFile,
            file_path: Some(path.to_string()),
            finding_id: None,
            risk_code: None,
            rule_id: rule_id.to_string(),
            description: "evidence".to_string(),
        }
    }

    fn factor(rule_id: &str) -> RiskFactor {
        RiskFactor {
            rule_id: rule_id.to_string(),
            label: "Large MR review was partial or high-risk files were prioritized.".to_string(),
            score: 16,
            evidence: vec![evidence("src/App.tsx", rule_id)],
            points: 16,
        }
    }

    fn labels(items: &[RiskGateItem]) -> Vec<String> {
        items.iter().map(|item| item.label.clone()).collect()
    }
}
