use crate::{
    config::{ReviewConfig, RiskGateConfig},
    error::Result as ReviewGateResult,
    gitlab::{context::DiffStats, types::MergeRequestDiff},
    review::{
        anchors::AnchoredDiffContext,
        claims::{
            validate_finding_claim_against_current_file, validate_finding_claim_against_diff,
            ClaimEvidence, ClaimSupport,
        },
        comparison::ReviewComparison,
        evidence::validate_review_analysis_evidence,
        large::LargeReviewReport,
        publisher_sanitizer::{sanitize_review_report, ReviewReport},
        quality,
        risk::{
            assess_merge_risk, BlastRadius, MergeDecision, MergeRiskAssessment, RiskGateRunSignals,
        },
        security_intent::{apply_security_intent_guard, SecurityIntentValidationContext},
        types::{
            EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewFinding, RiskCode,
            Severity,
        },
    },
};
use std::{collections::HashSet, sync::Arc};

pub type DiffContext = AnchoredDiffContext;
pub type LargeReviewStats = LargeReviewReport;

pub trait CurrentFileProvider: Send + Sync {
    fn current_file(&self, path: &str) -> Option<String>;
}

pub struct ReviewQualityPipelineInput {
    pub analysis: ReviewAnalysis,
    pub changed_files: Vec<String>,
    pub diff_context: Option<DiffContext>,
    pub current_file_provider: Option<Arc<dyn CurrentFileProvider>>,
    pub comparison: Option<ReviewComparison>,
    pub large_review_stats: Option<LargeReviewStats>,
    pub config: ReviewConfig,
    pub risk_gate_config: Option<RiskGateConfig>,
    pub diffs: Vec<MergeRequestDiff>,
    pub diff_stats: Option<DiffStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewQualityPipelineOutput {
    pub analysis: ReviewAnalysis,
    pub risk_assessment: MergeRiskAssessment,
    pub quality_report: QualityReport,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QualityReport {
    pub raw_findings: usize,
    pub normalized_findings: usize,
    pub dropped_findings: usize,
    pub downgraded_findings: usize,
    pub deduped_findings: usize,
    pub final_priority_findings: usize,
}

pub fn run_review_quality_pipeline(
    input: ReviewQualityPipelineInput,
) -> ReviewGateResult<ReviewQualityPipelineOutput> {
    let raw_findings = input.analysis.findings.len();
    let mut report = QualityReport {
        raw_findings,
        ..QualityReport::default()
    };

    let mut analysis = input.analysis;
    analysis.findings = normalize_findings(analysis.findings);
    analysis.overall_risk = overall_risk_from_findings(&analysis.findings);
    report.normalized_findings = analysis.findings.len();

    let before_claims = analysis.findings.clone();
    analysis.findings =
        validate_claims_against_diff(analysis.findings, input.diff_context.as_ref());
    accumulate_stage_stats(&mut report, &before_claims, &analysis.findings);

    if let Some(diff_context) = input.diff_context.as_ref() {
        analysis = validate_review_analysis_evidence(analysis, diff_context);
    }

    let before_current = analysis.findings.clone();
    analysis.findings = validate_findings_against_current_files(
        analysis.findings,
        input.current_file_provider.as_deref(),
    );
    accumulate_stage_stats(&mut report, &before_current, &analysis.findings);

    let before_security_intent = analysis.findings.clone();
    analysis.findings = apply_security_intent_guard(
        analysis.findings,
        &SecurityIntentValidationContext {
            diffs: &input.diffs,
            diff_context: input.diff_context.as_ref(),
        },
    );
    accumulate_stage_stats(&mut report, &before_security_intent, &analysis.findings);

    let before_calibration = analysis.findings.clone();
    analysis.findings = calibrate_severity(analysis.findings);
    accumulate_stage_stats(&mut report, &before_calibration, &analysis.findings);

    let before_dedupe = analysis.findings.len();
    analysis.findings = dedupe_findings(analysis.findings);
    report.deduped_findings += before_dedupe.saturating_sub(analysis.findings.len());

    analysis.findings = rank_findings(analysis.findings);
    analysis.overall_risk = overall_risk_from_findings(&analysis.findings);

    let mut risk_assessment = build_merge_risk_assessment(
        &analysis,
        &input.changed_files,
        &input.diffs,
        input.diff_stats.as_ref(),
        input.risk_gate_config.as_ref(),
        input.large_review_stats.as_ref(),
        input.comparison.as_ref(),
    );

    let sanitized = sanitize_published_report(ReviewReport {
        analysis,
        risk_assessment: Some(risk_assessment),
    });
    let analysis = sanitized.analysis;
    risk_assessment = sanitized
        .risk_assessment
        .unwrap_or_else(|| finding_only_risk_assessment(&analysis, &input.changed_files));
    report.final_priority_findings = final_priority_count(&analysis.findings);
    report.dropped_findings = raw_findings.saturating_sub(analysis.findings.len());

    let _ = input.config;

    Ok(ReviewQualityPipelineOutput {
        analysis,
        risk_assessment,
        quality_report: report,
    })
}

pub fn normalize_findings(findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    quality::normalize_findings(findings)
}

pub fn validate_claims_against_diff(
    findings: Vec<ReviewFinding>,
    diff_context: Option<&DiffContext>,
) -> Vec<ReviewFinding> {
    let Some(diff_context) = diff_context else {
        return findings;
    };
    findings
        .into_iter()
        .filter_map(|finding| {
            let validation = validate_finding_claim_against_diff(&finding, Some(diff_context));
            apply_claim_validation(finding, validation)
        })
        .collect()
}

pub fn validate_findings_against_current_files(
    findings: Vec<ReviewFinding>,
    current_file_provider: Option<&dyn CurrentFileProvider>,
) -> Vec<ReviewFinding> {
    let Some(provider) = current_file_provider else {
        return findings;
    };
    findings
        .into_iter()
        .filter_map(|finding| {
            let current_file = finding
                .file_path
                .as_deref()
                .and_then(|path| provider.current_file(path));
            let validation =
                validate_finding_claim_against_current_file(&finding, current_file.as_deref());
            apply_claim_validation(finding, validation)
        })
        .collect()
}

pub fn calibrate_severity(findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    findings
        .into_iter()
        .map(calibrate_finding_severity)
        .collect()
}

pub fn dedupe_findings(findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for finding in rank_findings(findings) {
        let key = finding_dedupe_key(&finding);
        if seen.insert(key) {
            output.push(finding);
        }
    }
    output
}

pub fn rank_findings(mut findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    findings.sort_by(|left, right| {
        left.severity
            .sort_key()
            .cmp(&right.severity.sort_key())
            .then_with(|| finding_has_evidence(right).cmp(&finding_has_evidence(left)))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.title.cmp(&right.title))
    });
    findings
}

pub fn build_merge_risk_assessment(
    analysis: &ReviewAnalysis,
    changed_files: &[String],
    diffs: &[MergeRequestDiff],
    diff_stats: Option<&DiffStats>,
    risk_gate_config: Option<&RiskGateConfig>,
    large_review_stats: Option<&LargeReviewStats>,
    comparison: Option<&ReviewComparison>,
) -> MergeRiskAssessment {
    match (risk_gate_config, diff_stats) {
        (Some(config), Some(stats)) => assess_merge_risk(
            analysis,
            diffs,
            stats,
            config,
            RiskGateRunSignals {
                large_review: large_review_stats,
                comparison,
            },
        ),
        _ => finding_only_risk_assessment(analysis, changed_files),
    }
}

pub fn sanitize_published_report(report: ReviewReport) -> ReviewReport {
    sanitize_review_report(report)
}

pub fn format_quality_report_terminal(report: &QualityReport) -> String {
    format!(
        "Review quality pipeline:\nRaw findings: {}\nDropped: {}\nDowngraded: {}\nDeduped: {}\nFinal priority findings: {}\n",
        report.raw_findings,
        report.dropped_findings,
        report.downgraded_findings,
        report.deduped_findings,
        report.final_priority_findings
    )
}

fn apply_claim_validation(
    mut finding: ReviewFinding,
    validation: ClaimEvidence,
) -> Option<ReviewFinding> {
    match validation.support {
        ClaimSupport::Strong => {
            finding.evidence_status = Some(EvidenceValidationStatus::Validated);
            finding.evidence_reason = Some(format!("claim validation: {}", validation.reason));
            Some(finding)
        }
        ClaimSupport::Partial => {
            finding.severity = match finding.severity {
                Severity::Critical | Severity::High => Severity::Medium,
                Severity::Medium => Severity::Low,
                severity => severity,
            };
            finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
            finding.evidence_reason = Some(format!("claim validation: {}", validation.reason));
            Some(finding)
        }
        ClaimSupport::Weak => {
            downgrade_to(&mut finding, Severity::Low);
            finding.actionable = false;
            finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
            finding.evidence_reason = Some(format!("claim validation: {}", validation.reason));
            Some(finding)
        }
        ClaimSupport::Contradicted | ClaimSupport::NotFound => None,
    }
}

fn calibrate_finding_severity(mut finding: ReviewFinding) -> ReviewFinding {
    if !finding.actionable || finding.severity == Severity::Note {
        return finding;
    }

    match finding.severity {
        Severity::Critical if !critical_evidence_requirements_met(&finding) => {
            finding.severity = if high_evidence_requirements_met(&finding) {
                Severity::High
            } else {
                Severity::Medium
            };
            mark_calibrated(&mut finding, "critical evidence requirements were not met");
        }
        Severity::High if !high_evidence_requirements_met(&finding) => {
            finding.severity = Severity::Medium;
            mark_calibrated(&mut finding, "high evidence requirements were not met");
        }
        Severity::Medium if !medium_evidence_requirements_met(&finding) => {
            finding.severity = Severity::Low;
            mark_calibrated(&mut finding, "medium evidence requirements were not met");
        }
        _ => {}
    }

    finding
}

fn critical_evidence_requirements_met(finding: &ReviewFinding) -> bool {
    has_actionable_fix(finding)
        && has_location_evidence(finding)
        && direct_critical_impact(finding)
        && !speculative_finding(finding)
}

fn high_evidence_requirements_met(finding: &ReviewFinding) -> bool {
    has_actionable_fix(finding)
        && has_location_evidence(finding)
        && high_impact(finding)
        && !speculative_finding(finding)
        && !debug_only_unproven(finding)
}

fn medium_evidence_requirements_met(finding: &ReviewFinding) -> bool {
    has_location_evidence(finding)
        || finding.evidence_status == Some(EvidenceValidationStatus::Validated)
}

fn direct_critical_impact(finding: &ReviewFinding) -> bool {
    matches!(
        finding.risk_code,
        Some(
            RiskCode::AuthBypass
                | RiskCode::MissingAuthorizationCheck
                | RiskCode::SecretLeak
                | RiskCode::PiiOrSecretLogging
                | RiskCode::SqlInjection
                | RiskCode::CommandInjection
                | RiskCode::UnsafeDeserialization
                | RiskCode::DataIntegrityRisk
                | RiskCode::MigrationRisk
        )
    ) || contains_any(
        &finding_text(finding),
        &[
            "auth bypass",
            "secret exposure",
            "credential exposure",
            "data loss",
            "build break",
            "production build failure",
            "sql injection",
            "command injection",
        ],
    )
}

fn high_impact(finding: &ReviewFinding) -> bool {
    direct_critical_impact(finding)
        || contains_any(
            &finding_text(finding),
            &[
                "high impact",
                "security",
                "privacy",
                "data integrity",
                "production",
                "user data",
                "payment",
            ],
        )
}

fn has_actionable_fix(finding: &ReviewFinding) -> bool {
    finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .is_some_and(|fix| {
            !fix.is_empty()
                && !matches!(
                    fix.to_ascii_lowercase().as_str(),
                    "none" | "n/a" | "na" | "no action needed" | "no fix needed"
                )
        })
}

fn has_location_evidence(finding: &ReviewFinding) -> bool {
    finding
        .file_path
        .as_deref()
        .is_some_and(|path| !path.trim().is_empty())
        && (finding.line.is_some()
            || finding
                .anchor_id
                .as_deref()
                .is_some_and(|anchor| !anchor.trim().is_empty()))
}

fn speculative_finding(finding: &ReviewFinding) -> bool {
    contains_any(
        &finding_text(finding),
        &[
            "may ",
            "might ",
            "could ",
            "if ",
            "unclear",
            "not visible",
            "cannot confirm",
            "cannot be confirmed",
            "needs manual",
        ],
    ) || matches!(
        finding.evidence_status,
        Some(
            EvidenceValidationStatus::WeakEvidence
                | EvidenceValidationStatus::StaleContext
                | EvidenceValidationStatus::NeedsManualConfirmation
        )
    )
}

fn debug_only_unproven(finding: &ReviewFinding) -> bool {
    let text = finding_text(finding);
    contains_any(&text, &["debug-only", "debug only", "debug config"])
        && !contains_any(&text, &["production", "release"])
}

fn mark_calibrated(finding: &mut ReviewFinding, reason: &str) {
    finding.evidence_reason = Some(format!(
        "{}{}severity calibration: {reason}",
        finding
            .evidence_reason
            .as_deref()
            .map(|existing| format!("{existing}; "))
            .unwrap_or_default(),
        ""
    ));
}

fn finding_only_risk_assessment(
    analysis: &ReviewAnalysis,
    changed_files: &[String],
) -> MergeRiskAssessment {
    let has_critical = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable(finding) && finding.severity == Severity::Critical);
    let has_high_blocker = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable(finding) && high_blocking_finding(finding));
    let has_high = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable(finding) && finding.severity == Severity::High);
    let medium_count = analysis
        .findings
        .iter()
        .filter(|finding| validated_actionable(finding) && finding.severity == Severity::Medium)
        .count();

    let score = if has_critical {
        100
    } else if has_high_blocker {
        90
    } else if has_high {
        70
    } else if medium_count > 0 {
        (medium_count as u8).saturating_mul(8).min(74)
    } else {
        0
    };
    let decision = if has_critical || has_high_blocker {
        MergeDecision::Blocked
    } else if has_high || medium_count > 1 {
        MergeDecision::NeedsHuman
    } else {
        MergeDecision::Pass
    };

    MergeRiskAssessment {
        score,
        decision,
        blocking_issues: Vec::new(),
        required_before_merge: Vec::new(),
        risk_factors: Vec::new(),
        blast_radius: BlastRadius {
            changed_files: changed_files.len(),
            ..BlastRadius::default()
        },
    }
}

fn validated_actionable(finding: &ReviewFinding) -> bool {
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

fn high_blocking_finding(finding: &ReviewFinding) -> bool {
    finding.severity == Severity::High
        && matches!(
            finding.risk_code,
            Some(
                RiskCode::SqlInjection
                    | RiskCode::CommandInjection
                    | RiskCode::SecretLeak
                    | RiskCode::PiiOrSecretLogging
                    | RiskCode::AuthBypass
                    | RiskCode::MissingAuthorizationCheck
                    | RiskCode::DataIntegrityRisk
                    | RiskCode::MigrationRisk
            )
        )
}

fn accumulate_stage_stats(
    report: &mut QualityReport,
    before: &[ReviewFinding],
    after: &[ReviewFinding],
) {
    report.dropped_findings += before.len().saturating_sub(after.len());
    report.downgraded_findings += before
        .iter()
        .zip(after.iter())
        .filter(|(left, right)| right.severity.sort_key() > left.severity.sort_key())
        .count();
}

fn final_priority_count(findings: &[ReviewFinding]) -> usize {
    findings
        .iter()
        .filter(|finding| {
            finding.actionable
                && matches!(
                    finding.severity,
                    Severity::Critical | Severity::High | Severity::Medium
                )
        })
        .count()
}

fn overall_risk_from_findings(findings: &[ReviewFinding]) -> OverallRisk {
    findings
        .iter()
        .filter(|finding| finding.actionable)
        .map(|finding| match finding.severity {
            Severity::Critical => OverallRisk::Critical,
            Severity::High => OverallRisk::High,
            Severity::Medium => OverallRisk::Medium,
            Severity::Low => OverallRisk::Low,
            Severity::Note => OverallRisk::Note,
        })
        .min_by_key(|risk| match risk {
            OverallRisk::Critical => 0,
            OverallRisk::High => 1,
            OverallRisk::Medium => 2,
            OverallRisk::Low => 3,
            OverallRisk::Note => 4,
        })
        .unwrap_or(OverallRisk::Note)
}

fn finding_dedupe_key(finding: &ReviewFinding) -> String {
    format!(
        "{}:{}:{}:{}",
        finding
            .file_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        finding.line.unwrap_or_default(),
        finding
            .risk_code
            .map(|risk_code| risk_code.display_lower())
            .unwrap_or("none"),
        normalized_text(&finding.title)
    )
}

fn finding_has_evidence(finding: &ReviewFinding) -> bool {
    has_location_evidence(finding)
        || finding.evidence_status == Some(EvidenceValidationStatus::Validated)
}

fn finding_text(finding: &ReviewFinding) -> String {
    format!(
        "{} {} {}",
        finding.title,
        finding.body,
        finding.suggested_fix.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn normalized_text(value: &str) -> String {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn downgrade_to(finding: &mut ReviewFinding, severity: Severity) {
    if severity.sort_key() > finding.severity.sort_key() {
        finding.severity = severity;
    }
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| value.contains(term))
}

#[cfg(test)]
mod tests {
    use super::{
        calibrate_severity, dedupe_findings, format_quality_report_terminal,
        run_review_quality_pipeline, validate_claims_against_diff, CurrentFileProvider,
        QualityReport, ReviewQualityPipelineInput,
    };
    use crate::{
        config::{ReviewConfig, RiskGateConfig},
        gitlab::context::DiffStats,
        review::{
            anchors::{AnchorLineKind, AnchoredDiffContext, ReviewLineAnchor},
            risk::MergeDecision,
            types::{
                Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode,
                Severity,
            },
        },
    };
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn raw_positive_finding_cannot_reach_final_priority_findings() {
        let output = run_review_quality_pipeline(input(vec![finding(
            Severity::High,
            Some(RiskCode::PositiveNote),
            "Positive: token logging removed",
            "No action needed.",
            Some("No action needed"),
        )]))
        .unwrap();

        assert_eq!(output.quality_report.final_priority_findings, 0);
        assert!(
            output.analysis.findings.is_empty()
                || output.analysis.findings[0].severity == Severity::Note
        );
    }

    #[test]
    fn missing_await_false_positive_is_dropped() {
        let findings = validate_claims_against_diff(
            vec![finding(
                Severity::High,
                Some(RiskCode::MissingAuthorizationCheck),
                "Missing await on getToken",
                "getToken is called without await.",
                Some("Await getToken."),
            )],
            Some(&anchors(
                "src/app.ts",
                10,
                "const token = await getToken();",
            )),
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn toctou_overstated_finding_is_downgraded() {
        let output = run_review_quality_pipeline(input(vec![finding(
            Severity::High,
            Some(RiskCode::DataIntegrityRisk),
            "TOCTOU symlink deletion",
            "Cache cleanup can follow a symlink and delete user data.",
            Some("Use non-following deletion."),
        )]))
        .unwrap();

        assert!(output
            .analysis
            .findings
            .iter()
            .all(|finding| finding.severity != Severity::High));
    }

    #[test]
    fn medium_only_cannot_become_blocked() {
        let output = run_review_quality_pipeline(input(vec![finding(
            Severity::Medium,
            Some(RiskCode::WeakErrorHandling),
            "Error handling can hide sync failure",
            "The retry failure is not surfaced.",
            Some("Surface the failed retry state."),
        )]))
        .unwrap();

        assert_ne!(output.risk_assessment.decision, MergeDecision::Blocked);
        assert!(output.risk_assessment.score <= 74);
    }

    #[test]
    fn final_pipeline_quality_report_counts_dropped_unsupported_claims() {
        let output = run_review_quality_pipeline(input(vec![
            finding(
                Severity::High,
                Some(RiskCode::MissingAuthorizationCheck),
                "Missing await on getToken",
                "getToken is called without await.",
                Some("Await getToken."),
            ),
            finding(
                Severity::High,
                Some(RiskCode::DataIntegrityRisk),
                "TOCTOU symlink deletion",
                "Cache cleanup can follow a symlink and delete user data.",
                Some("Use non-following deletion."),
            ),
        ]))
        .unwrap();

        assert!(output.quality_report.dropped_findings >= 1);
        assert_eq!(output.quality_report.final_priority_findings, 0);
    }

    #[test]
    fn dedupe_keeps_single_copy_of_same_finding() {
        let finding = finding(
            Severity::Medium,
            Some(RiskCode::WeakErrorHandling),
            "Retry failure is swallowed",
            "The failure is ignored.",
            Some("Return the error."),
        );

        assert_eq!(dedupe_findings(vec![finding.clone(), finding]).len(), 1);
    }

    #[test]
    fn severity_requires_location_for_high() {
        let mut item = finding(
            Severity::High,
            Some(RiskCode::SqlInjection),
            "SQL injection",
            "User input reaches a SQL query.",
            Some("Use parameterized queries."),
        );
        item.file_path = None;
        item.line = None;

        assert_eq!(calibrate_severity(vec![item])[0].severity, Severity::Medium);
    }

    #[test]
    fn terminal_quality_report_is_internal_text() {
        let text = format_quality_report_terminal(&QualityReport {
            raw_findings: 18,
            dropped_findings: 5,
            downgraded_findings: 4,
            deduped_findings: 2,
            final_priority_findings: 3,
            normalized_findings: 18,
        });

        assert!(text.contains("Review quality pipeline:"));
        assert!(text.contains("Final priority findings: 3"));
    }

    #[test]
    fn current_file_provider_can_drop_false_variable_scope_claim() {
        struct Provider;
        impl CurrentFileProvider for Provider {
            fn current_file(&self, _path: &str) -> Option<String> {
                Some(
                    "let tempFile = null;\ntry { tempFile = create(); }\nfinally { cleanup(tempFile); }"
                        .to_string(),
                )
            }
        }

        let mut pipeline_input = input(vec![finding(
            Severity::High,
            Some(RiskCode::NilOrNullRisk),
            "tempFile is out of scope in finally",
            "The finally block cannot access `tempFile`.",
            Some("Declare tempFile outside try."),
        )]);
        pipeline_input.current_file_provider = Some(Arc::new(Provider));
        let output = run_review_quality_pipeline(pipeline_input).unwrap();

        assert!(output.analysis.findings.is_empty());
    }

    fn input(findings: Vec<ReviewFinding>) -> ReviewQualityPipelineInput {
        ReviewQualityPipelineInput {
            analysis: ReviewAnalysis {
                summary: "summary".to_string(),
                findings,
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::High,
            },
            changed_files: vec!["src/app.ts".to_string()],
            diff_context: Some(anchors(
                "src/app.ts",
                10,
                "const token = await getToken();\nconst root = file.canonicalPath.startsWith(cacheDir.canonicalPath);",
            )),
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
            diffs: Vec::new(),
            diff_stats: Some(DiffStats {
                changed_file_count: 1,
                ..DiffStats::default()
            }),
        }
    }

    fn anchors(path: &str, line: u32, content: &str) -> AnchoredDiffContext {
        let anchors = content
            .lines()
            .enumerate()
            .map(|(index, content)| ReviewLineAnchor {
                anchor_id: format!("A{index}"),
                file_path: path.to_string(),
                old_path: path.to_string(),
                new_path: path.to_string(),
                old_line: None,
                new_line: Some(line + index as u32),
                kind: AnchorLineKind::Added,
                content_preview: content.to_string(),
            })
            .collect::<Vec<_>>();
        AnchoredDiffContext {
            total_anchors: anchors.len(),
            anchors,
            prompt_text: content.to_string(),
            truncated: false,
        }
    }

    fn finding(
        severity: Severity,
        risk_code: Option<RiskCode>,
        title: &str,
        body: &str,
        suggested_fix: Option<&str>,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Security,
            risk_code,
            anchor_id: Some("A0".to_string()),
            file_path: Some("src/app.ts".to_string()),
            line: Some(10),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: suggested_fix.map(str::to_string),
            effort: Effort::Moderate,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }
}
