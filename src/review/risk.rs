use crate::{
    config::RiskGateConfig,
    gitlab::{context::DiffStats, types::MergeRequestDiff},
    plan::{DEFAULT_LARGE_MR_DIFF_BYTES, DEFAULT_LARGE_MR_FILE_THRESHOLD},
    review::{
        comparison::ReviewComparison,
        large::LargeReviewReport,
        types::{
            EvidenceValidationStatus, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode,
            Severity,
        },
    },
};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    Pass,
    NeedsHuman,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRiskAssessment {
    pub score: u8,
    pub decision: MergeDecision,
    pub blocking_issues: Vec<RiskGateItem>,
    pub required_before_merge: Vec<RiskGateItem>,
    pub risk_factors: Vec<RiskFactor>,
    pub blast_radius: BlastRadius,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskEvidenceSource {
    Finding,
    ChangedFile,
    PolicyRule,
    Comparison,
    Verification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskEvidence {
    pub source: RiskEvidenceSource,
    pub file_path: Option<String>,
    pub finding_id: Option<String>,
    pub risk_code: Option<String>,
    pub rule_id: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskFactor {
    pub rule_id: String,
    pub label: String,
    pub score: u8,
    pub evidence: Vec<RiskEvidence>,
    pub points: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskGateItem {
    pub label: String,
    pub evidence: Vec<RiskEvidence>,
}

impl RiskGateItem {
    pub fn new(label: impl Into<String>, evidence: Vec<RiskEvidence>) -> Option<Self> {
        if evidence.is_empty() {
            return None;
        }
        Some(Self {
            label: label.into(),
            evidence,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlastRadius {
    pub changed_files: usize,
    pub diff_bytes: usize,
    pub collapsed_files: usize,
    pub too_large_files: usize,
    pub failed_chunks: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RiskGateRunSignals<'a> {
    pub large_review: Option<&'a LargeReviewReport>,
    pub comparison: Option<&'a ReviewComparison>,
}

impl MergeDecision {
    pub fn display_label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::NeedsHuman => "NEEDS HUMAN",
            Self::Blocked => "BLOCKED",
        }
    }
}

pub fn assess_merge_risk(
    analysis: &ReviewAnalysis,
    diffs: &[MergeRequestDiff],
    stats: &DiffStats,
    config: &RiskGateConfig,
    signals: RiskGateRunSignals<'_>,
) -> MergeRiskAssessment {
    let changed_files = changed_file_paths(diffs);
    let changed_test_files = changed_files
        .iter()
        .filter(|path| is_test_path(path))
        .cloned()
        .collect::<Vec<_>>();
    let mut builder = RiskBuilder::default();
    let mut blocking_issues = Vec::new();
    let mut required_before_merge = Vec::new();
    let mut needs_human = false;
    let mut has_high_actionable = false;
    let mut has_critical_actionable = false;
    let mut has_high_blocking_finding = false;

    for finding in analysis.findings.iter().filter(|finding| {
        finding.actionable && finding.severity != Severity::Note && has_validated_evidence(finding)
    }) {
        match finding.severity {
            Severity::Critical => {
                has_critical_actionable = true;
                builder.add(
                    35,
                    "finding.severity.critical",
                    "Validated critical actionable finding",
                    vec![finding_evidence(
                        "finding.severity.critical",
                        finding,
                        "Critical actionable finding validated in the current review.",
                    )],
                );
            }
            Severity::High => {
                has_high_actionable = true;
                builder.add(
                    18,
                    "finding.severity.high",
                    "Validated high actionable finding",
                    vec![finding_evidence(
                        "finding.severity.high",
                        finding,
                        "High actionable finding validated in the current review.",
                    )],
                );
                if high_blocking_finding(finding) {
                    has_high_blocking_finding = true;
                }
            }
            Severity::Medium => {
                builder.add(
                    8,
                    "finding.severity.medium",
                    "Validated medium actionable finding",
                    vec![finding_evidence(
                        "finding.severity.medium",
                        finding,
                        "Medium actionable finding validated in the current review.",
                    )],
                );
            }
            Severity::Low => {
                builder.add(
                    2,
                    "finding.severity.low",
                    "Validated low actionable finding",
                    vec![finding_evidence(
                        "finding.severity.low",
                        finding,
                        "Low actionable finding validated in the current review.",
                    )],
                );
            }
            Severity::Note => {}
        }

        if let Some(label) = blocking_issue_label(finding) {
            push_unique_item(
                &mut blocking_issues,
                label,
                vec![finding_evidence(
                    "finding.blocking_issue",
                    finding,
                    "Final validated blocker finding used for Merge Risk Gate.",
                )],
            );
        }
        if let Some(label) = required_action_for_finding(finding) {
            push_unique_item(
                &mut required_before_merge,
                label,
                vec![finding_evidence(
                    "finding.required_action",
                    finding,
                    "Final validated finding used for required merge action.",
                )],
            );
        }

        if security_finding_signal(
            finding,
            &[RiskCode::PiiOrSecretLogging, RiskCode::SecretLeak],
        ) {
            builder.add(
                25,
                "finding.secret_or_pii_logging",
                "Secret or PII exposure security finding",
                vec![finding_evidence(
                    "finding.secret_or_pii_logging",
                    finding,
                    "Validated secret or PII exposure finding.",
                )],
            );
        }
        if security_finding_signal(
            finding,
            &[RiskCode::AuthBypass, RiskCode::MissingAuthorizationCheck],
        ) {
            builder.add(
                35,
                "finding.auth_bypass",
                "Authentication bypass security finding",
                vec![finding_evidence(
                    "finding.auth_bypass",
                    finding,
                    "Validated authorization or authentication bypass finding.",
                )],
            );
        }
        if security_finding_signal(
            finding,
            &[RiskCode::SqlInjection, RiskCode::CommandInjection],
        ) {
            builder.add(
                35,
                "finding.injection",
                "SQL or command injection security finding",
                vec![finding_evidence(
                    "finding.injection",
                    finding,
                    "Validated SQL or command injection finding.",
                )],
            );
        }
        if weak_error_handling_required_finding(finding) {
            builder.add(
                8,
                "finding.weak_error_handling",
                "Weak error handling finding",
                vec![finding_evidence(
                    "finding.weak_error_handling",
                    finding,
                    "Validated weak error handling finding.",
                )],
            );
        }
        if data_integrity_wipe_finding(finding) {
            builder.add(
                30,
                "finding.data_integrity.local_data_wipe",
                "Local data wipe data-integrity finding",
                vec![finding_evidence(
                    "finding.data_integrity.local_data_wipe",
                    finding,
                    "Validated automatic local data deletion finding.",
                )],
            );
        }
    }

    if stats.changed_file_count > DEFAULT_LARGE_MR_FILE_THRESHOLD {
        builder.add(
            10,
            "verification.large_mr.changed_files",
            "Changed files exceed large MR threshold",
            vec![verification_evidence(
                "verification.large_mr.changed_files",
                format!(
                    "{} changed files exceed the large MR threshold.",
                    stats.changed_file_count
                ),
            )],
        );
    }
    if stats.total_diff_bytes > DEFAULT_LARGE_MR_DIFF_BYTES {
        builder.add(
            10,
            "verification.large_mr.diff_bytes",
            "Diff bytes exceed large MR threshold",
            vec![verification_evidence(
                "verification.large_mr.diff_bytes",
                format!(
                    "{} diff bytes exceed the large MR threshold.",
                    stats.total_diff_bytes
                ),
            )],
        );
    }
    if stats.collapsed_file_count > 0 || stats.too_large_file_count > 0 {
        builder.add(
            10,
            "verification.gitlab.partial_diff",
            "GitLab collapsed or too-large files are present",
            vec![verification_evidence(
                "verification.gitlab.partial_diff",
                format!(
                    "{} collapsed and {} too-large files are present.",
                    stats.collapsed_file_count, stats.too_large_file_count
                ),
            )],
        );
    }

    if let Some(report) = signals.large_review {
        if report.failed_chunks > 0 {
            let points = (report.failed_chunks * 8).min(20) as i16;
            builder.add(
                points,
                "verification.large_review.failed_chunks",
                "Large MR review had failed chunks",
                vec![verification_evidence(
                    "verification.large_review.failed_chunks",
                    format!("{} review chunks failed.", report.failed_chunks),
                )],
            );
            needs_human = true;
        }
    }

    let source_changed = changed_files
        .iter()
        .any(|path| is_source_behavior_path(path) && !is_test_path(path));
    if source_changed && changed_test_files.is_empty() {
        builder.add(
            10,
            "changed_file.source_without_tests",
            "Source behavior changed without changed tests",
            changed_files
                .iter()
                .filter(|path| is_source_behavior_path(path) && !is_test_path(path))
                .map(|path| {
                    changed_file_evidence(
                        "changed_file.source_without_tests",
                        path,
                        "Source behavior changed and no test files changed.",
                    )
                })
                .collect(),
        );
    }

    let protected_matches = protected_path_matches(&changed_files, config);
    for protected in &protected_matches {
        let protected_evidence = vec![policy_evidence(
            "policy.protected_path",
            &protected.matched_path,
            &protected.pattern,
            "Changed file matches a configured protected path.",
        )];
        builder.add(
            20,
            "policy.protected_path",
            format!("Protected path touched: {}", protected.pattern),
            protected_evidence.clone(),
        );
        if let Some(owner) = protected.owner.as_deref() {
            let owner_evidence = vec![policy_evidence(
                "policy.protected_path.owner_review",
                &protected.matched_path,
                &protected.pattern,
                format!("Protected path requires owner review from {owner}."),
            )];
            builder.add(
                30,
                "policy.protected_path.owner_review",
                format!(
                    "Protected path touched without required owner review: {}",
                    protected.pattern
                ),
                owner_evidence.clone(),
            );
        }
        if !changed_test_files
            .iter()
            .any(|path| test_matches_required_terms(path, protected.required_tests.as_slice()))
        {
            builder.add(
                15,
                "policy.protected_path.missing_tests",
                "Protected module changed without matching test file",
                protected_evidence,
            );
        }
        needs_human = true;
    }

    let auth_touched = any_path_or_diff_signal(
        diffs,
        &[
            "auth",
            "security",
            "session",
            "root",
            "jailbreak",
            "integrity",
        ],
    );
    if auth_touched {
        builder.add(
            15,
            "changed_file.auth_security_area",
            "Architecture-sensitive auth or security area touched",
            path_signal_evidence(
                diffs,
                "changed_file.auth_security_area",
                &[
                    "auth",
                    "security",
                    "session",
                    "root",
                    "jailbreak",
                    "integrity",
                ],
                "Changed file or diff text matches an auth/security signal.",
            ),
        );
        needs_human = true;
    }
    let sync_changed_files = changed_files
        .iter()
        .filter(|path| offline_sync_path_signal(path) && !is_test_path(path))
        .cloned()
        .collect::<Vec<_>>();
    if !sync_changed_files.is_empty() {
        let sync_evidence = sync_changed_files
            .iter()
            .map(|path| {
                changed_file_evidence(
                    "changed_file.offline_sync_area",
                    path,
                    "Changed file path matches offline sync/cache/queue/retry/recovery terms.",
                )
            })
            .collect::<Vec<_>>();
        builder.add(
            15,
            "changed_file.offline_sync_area",
            "Offline sync, cache, queue, or retry area touched",
            sync_evidence.clone(),
        );
        needs_human = true;
        if !has_test_with_terms(
            &changed_test_files,
            &["sync", "offline", "recovery", "retry", "queue"],
        ) {
            builder.add(
                25,
                "changed_file.offline_sync_missing_recovery_test",
                "Offline sync layer changed without recovery test",
                sync_evidence.clone(),
            );
        }
    }
    if any_path_or_diff_signal(diffs, &["payment", "billing", "money"]) {
        builder.add(
            20,
            "changed_file.payment_area",
            "Payment, billing, or money area touched",
            path_signal_evidence(
                diffs,
                "changed_file.payment_area",
                &["payment", "billing", "money"],
                "Changed file or diff text matches a payment/billing/money signal.",
            ),
        );
        needs_human = true;
    }

    let migration_evidence = migration_evidence(diffs, config);
    if !migration_evidence.is_empty() {
        builder.add(
            20,
            "changed_file.migration_or_schema",
            "Database migration or schema area touched",
            migration_evidence.clone(),
        );
        needs_human = true;
        if !rollback_note_detected(diffs) {
            builder.add(
                25,
                "changed_file.migration_missing_rollback",
                "Database migration changed without rollback plan",
                migration_evidence.clone(),
            );
        }
    }

    let contract_evidence = contract_evidence(diffs, config);
    if !contract_evidence.is_empty() {
        builder.add(
            15,
            "changed_file.api_contract",
            "API contract area touched",
            contract_evidence.clone(),
        );
        needs_human = true;
        if !contract_snapshot_updated(diffs, config) {
            builder.add(
                20,
                "changed_file.api_contract_missing_snapshot",
                "API contract changed without contract snapshot update",
                contract_evidence.clone(),
            );
        }
    }

    if let Some(comparison) = signals.comparison {
        if comparison.still_detected > 0 {
            builder.add(
                15,
                "comparison.previous_finding_still_detected",
                "Previous high-priority finding still detected",
                vec![comparison_evidence(
                    "comparison.previous_finding_still_detected",
                    format!(
                        "{} previous high-priority findings are still detected.",
                        comparison.still_detected
                    ),
                )],
            );
            needs_human = true;
        }
        if comparison.not_detected > 0 {
            builder.add(
                5,
                "comparison.previous_finding_not_verified",
                "Previous finding no longer detected but not verified",
                vec![comparison_evidence(
                    "comparison.previous_finding_not_verified",
                    format!(
                        "{} previous findings are no longer detected but still need verification.",
                        comparison.not_detected
                    ),
                )],
            );
        }
        if comparison.verified_fixed > 0 {
            let points = -10 * comparison.verified_fixed.min(2) as i16;
            builder.add(
                points,
                "comparison.previous_finding_verified_fixed",
                "Previous finding verified fixed",
                vec![comparison_evidence(
                    "comparison.previous_finding_verified_fixed",
                    format!(
                        "{} previous findings were verified fixed.",
                        comparison.verified_fixed
                    ),
                )],
            );
        }
    }

    required_before_merge.truncate(6);

    let mut score = builder.score();
    let blocked = has_critical_actionable || has_high_blocking_finding;
    let has_medium_actionable = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable_finding_with_severity(finding, Severity::Medium));
    let needs_human = needs_human
        || score >= config.needs_human_threshold
        || has_high_actionable
        || signals
            .comparison
            .is_some_and(|comparison| comparison.still_detected > 0);
    let mut decision = if blocked {
        MergeDecision::Blocked
    } else if needs_human {
        MergeDecision::NeedsHuman
    } else {
        MergeDecision::Pass
    };
    let score_100_allowed = has_critical_actionable || has_high_blocking_finding;
    if !score_100_allowed {
        score = if has_high_actionable {
            score.min(89)
        } else if has_medium_actionable {
            score.min(74)
        } else {
            score.min(49)
        };
    }

    if !has_critical_actionable && !has_high_actionable {
        score = score.min(74);
        if decision == MergeDecision::Blocked {
            decision = if needs_human || score >= config.needs_human_threshold {
                MergeDecision::NeedsHuman
            } else {
                MergeDecision::Pass
            };
        }
    }
    if !has_critical_actionable && !has_high_actionable && !has_medium_actionable {
        let non_low_finding_positive_factor = builder
            .factors
            .iter()
            .any(|factor| factor.points > 0 && factor.rule_id != "finding.severity.low");
        if !non_low_finding_positive_factor {
            decision = MergeDecision::Pass;
        }
    }

    MergeRiskAssessment {
        score,
        decision,
        blocking_issues,
        required_before_merge,
        risk_factors: builder.factors,
        blast_radius: BlastRadius {
            changed_files: stats.changed_file_count,
            diff_bytes: stats.total_diff_bytes,
            collapsed_files: stats.collapsed_file_count,
            too_large_files: stats.too_large_file_count,
            failed_chunks: signals
                .large_review
                .map(|report| report.failed_chunks)
                .unwrap_or_default(),
        },
    }
}

pub fn format_merge_risk_gate_markdown(assessment: &MergeRiskAssessment) -> String {
    let mut output = String::new();
    output.push_str("## Merge Risk Gate\n\n");
    output.push_str(&format!("Risk Score: {}/100  \n", assessment.score));
    output.push_str(&format!(
        "Decision: {}\n\n",
        assessment.decision.display_label()
    ));

    if assessment
        .blocking_issues
        .iter()
        .any(|issue| !issue.evidence.is_empty())
    {
        output.push_str("Blocking Issues:\n");
        for issue in assessment
            .blocking_issues
            .iter()
            .filter(|issue| !issue.evidence.is_empty())
        {
            output.push_str("- ");
            output.push_str(&issue.label);
            output.push('\n');
        }
        output.push('\n');
    } else if assessment.decision == MergeDecision::Pass {
        output.push_str("No blocking issues detected by ReviewGate.\n\n");
    } else {
        output.push_str("Why:\n");
        for factor in assessment
            .risk_factors
            .iter()
            .filter(|factor| factor.points > 0)
            .take(4)
        {
            output.push_str("- ");
            output.push_str(&factor.label);
            output.push('\n');
        }
        output.push('\n');
    }

    if assessment
        .required_before_merge
        .iter()
        .any(|item| !item.evidence.is_empty())
    {
        output.push_str("Required Before Merge:\n");
        for item in assessment
            .required_before_merge
            .iter()
            .filter(|item| !item.evidence.is_empty())
        {
            output.push_str("- ");
            output.push_str(&item.label);
            output.push('\n');
        }
        output.push('\n');
    }

    output.trim_end().to_string()
}

pub fn format_merge_risk_gate_terminal(assessment: &MergeRiskAssessment) -> String {
    format!(
        "Merge Risk Gate:\nRisk Score: {}/100\nDecision: {}\nBlocking Issues: {}\nRequired Before Merge: {}\n",
        assessment.score,
        assessment.decision.display_label(),
        assessment
            .blocking_issues
            .iter()
            .filter(|item| !item.evidence.is_empty())
            .count(),
        assessment
            .required_before_merge
            .iter()
            .filter(|item| !item.evidence.is_empty())
            .count()
    )
}

#[derive(Default)]
struct RiskBuilder {
    total: i16,
    factors: Vec<RiskFactor>,
}

impl RiskBuilder {
    fn add(
        &mut self,
        points: i16,
        rule_id: impl Into<String>,
        label: impl Into<String>,
        evidence: Vec<RiskEvidence>,
    ) -> usize {
        self.total = self.total.saturating_add(points);
        self.factors.push(RiskFactor {
            rule_id: rule_id.into(),
            label: label.into(),
            score: points.clamp(0, 100) as u8,
            evidence,
            points,
        });
        self.factors.len() - 1
    }

    fn score(&self) -> u8 {
        self.total.clamp(0, 100) as u8
    }
}

#[derive(Debug)]
struct ProtectedMatch {
    pattern: String,
    matched_path: String,
    owner: Option<String>,
    required_tests: Vec<String>,
}

fn changed_file_paths(diffs: &[MergeRequestDiff]) -> Vec<String> {
    diffs
        .iter()
        .map(|diff| diff.new_path.trim())
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_validated_evidence(finding: &ReviewFinding) -> bool {
    !matches!(
        finding.evidence_status,
        Some(
            EvidenceValidationStatus::WeakEvidence
                | EvidenceValidationStatus::StaleContext
                | EvidenceValidationStatus::NeedsManualConfirmation
                | EvidenceValidationStatus::PositiveChange
        )
    )
}

fn security_finding_signal(finding: &ReviewFinding, risk_codes: &[RiskCode]) -> bool {
    if !matches!(
        finding.category,
        ReviewCategory::Security | ReviewCategory::Privacy
    ) {
        return false;
    }
    finding
        .risk_code
        .is_some_and(|risk_code| risk_codes.contains(&risk_code))
}

fn high_blocking_finding(finding: &ReviewFinding) -> bool {
    finding.severity == Severity::High
        && finding.actionable
        && has_validated_evidence(finding)
        && blocker_risk_code(finding.risk_code)
}

fn blocker_risk_code(risk_code: Option<RiskCode>) -> bool {
    matches!(
        risk_code,
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

fn validated_actionable_finding_with_severity(finding: &ReviewFinding, severity: Severity) -> bool {
    finding.actionable && finding.severity == severity && has_validated_evidence(finding)
}

fn protected_path_matches(paths: &[String], config: &RiskGateConfig) -> Vec<ProtectedMatch> {
    let mut seen = HashSet::new();
    let mut matches = Vec::new();
    for pattern in &config.protected_paths {
        let Some(matched_path) = paths
            .iter()
            .find(|path| path_matches_pattern(path, pattern))
            .cloned()
        else {
            continue;
        };
        if !seen.insert(pattern.clone()) {
            continue;
        }
        matches.push(ProtectedMatch {
            pattern: pattern.clone(),
            matched_path,
            owner: config.owner_reviews.get(pattern).cloned(),
            required_tests: config
                .required_tests
                .get(pattern)
                .cloned()
                .unwrap_or_default(),
        });
    }
    matches
}

fn finding_evidence(rule_id: &str, finding: &ReviewFinding, description: &str) -> RiskEvidence {
    RiskEvidence {
        source: RiskEvidenceSource::Finding,
        file_path: finding.file_path.clone(),
        finding_id: finding.anchor_id.clone(),
        risk_code: finding
            .risk_code
            .map(|risk_code| risk_code.display_lower().to_string()),
        rule_id: rule_id.to_string(),
        description: description.to_string(),
    }
}

fn changed_file_evidence(
    rule_id: &str,
    file_path: &str,
    description: impl Into<String>,
) -> RiskEvidence {
    RiskEvidence {
        source: RiskEvidenceSource::ChangedFile,
        file_path: Some(file_path.to_string()),
        finding_id: None,
        risk_code: None,
        rule_id: rule_id.to_string(),
        description: description.into(),
    }
}

fn policy_evidence(
    rule_id: &str,
    file_path: &str,
    pattern: &str,
    description: impl Into<String>,
) -> RiskEvidence {
    RiskEvidence {
        source: RiskEvidenceSource::PolicyRule,
        file_path: Some(file_path.to_string()),
        finding_id: None,
        risk_code: Some(pattern.to_string()),
        rule_id: rule_id.to_string(),
        description: description.into(),
    }
}

fn comparison_evidence(rule_id: &str, description: impl Into<String>) -> RiskEvidence {
    RiskEvidence {
        source: RiskEvidenceSource::Comparison,
        file_path: None,
        finding_id: None,
        risk_code: None,
        rule_id: rule_id.to_string(),
        description: description.into(),
    }
}

fn verification_evidence(rule_id: &str, description: impl Into<String>) -> RiskEvidence {
    RiskEvidence {
        source: RiskEvidenceSource::Verification,
        file_path: None,
        finding_id: None,
        risk_code: None,
        rule_id: rule_id.to_string(),
        description: description.into(),
    }
}

fn path_signal_evidence(
    diffs: &[MergeRequestDiff],
    rule_id: &str,
    terms: &[&str],
    description: &str,
) -> Vec<RiskEvidence> {
    diffs
        .iter()
        .filter(|diff| {
            let path = normalize_path(&diff.new_path);
            let body = diff.diff.to_ascii_lowercase();
            terms
                .iter()
                .any(|term| path.contains(term) || body.contains(term))
        })
        .map(|diff| changed_file_evidence(rule_id, &diff.new_path, description))
        .collect()
}

fn any_path_or_diff_signal(diffs: &[MergeRequestDiff], terms: &[&str]) -> bool {
    diffs.iter().any(|diff| {
        let path = normalize_path(&diff.new_path);
        let body = diff.diff.to_ascii_lowercase();
        terms
            .iter()
            .any(|term| path.contains(term) || body.contains(term))
    })
}

fn migration_evidence(diffs: &[MergeRequestDiff], config: &RiskGateConfig) -> Vec<RiskEvidence> {
    diffs
        .iter()
        .filter(|diff| {
            let path = normalize_path(&diff.new_path);
            config
                .migration_paths
                .iter()
                .any(|pattern| path_matches_pattern(&path, pattern))
                || path.contains("migration")
                || path.contains("migrations/")
                || path.ends_with("schema.sql")
                || migration_ddl_signal(&diff.diff)
        })
        .map(|diff| {
            changed_file_evidence(
                "changed_file.migration_or_schema",
                &diff.new_path,
                "Changed file or diff text contains migration/schema evidence.",
            )
        })
        .collect()
}

fn migration_ddl_signal(diff: &str) -> bool {
    contains_any(
        diff,
        &[
            "ALTER TABLE",
            "CREATE TABLE",
            "DROP TABLE",
            "CREATE INDEX",
            "DROP INDEX",
            "ADD COLUMN",
            "DROP COLUMN",
        ],
    )
}

fn rollback_note_detected(diffs: &[MergeRequestDiff]) -> bool {
    diffs.iter().any(|diff| {
        contains_any(
            &format!("{} {}", diff.new_path, diff.diff),
            &[
                "rollback",
                "down.sql",
                "revert",
                "migration note",
                "rollback plan",
            ],
        )
    })
}

fn contract_evidence(diffs: &[MergeRequestDiff], config: &RiskGateConfig) -> Vec<RiskEvidence> {
    diffs
        .iter()
        .filter(|diff| {
            let path = normalize_path(&diff.new_path);
            config
                .contract_paths
                .iter()
                .any(|pattern| path_matches_pattern(&path, pattern))
                || contract_path_signal(&path)
        })
        .map(|diff| {
            changed_file_evidence(
                "changed_file.api_contract",
                &diff.new_path,
                "Changed file path matches API contract evidence.",
            )
        })
        .collect()
}

fn contract_path_signal(path: &str) -> bool {
    path.contains("openapi")
        || path.contains("swagger")
        || path.ends_with(".proto")
        || path.contains("/contract")
        || path.contains("contract/")
        || path.contains("_dto.")
        || path.contains("/dto/")
        || path.contains("generated-client")
        || path.contains("generated_client")
        || (path.contains("endpoint") && path.contains("schema"))
}

fn contract_snapshot_updated(diffs: &[MergeRequestDiff], config: &RiskGateConfig) -> bool {
    diffs.iter().any(|diff| {
        let path = normalize_path(&diff.new_path);
        config
            .contract_paths
            .iter()
            .any(|pattern| path_matches_pattern(&path, pattern))
            || contains_any(
                &path,
                &["openapi", "swagger", ".proto", "snapshot", "contract"],
            )
    })
}

fn blocking_issue_label(finding: &ReviewFinding) -> Option<String> {
    let is_blocker = finding.severity == Severity::Critical || high_blocking_finding(finding);
    if !is_blocker {
        return None;
    }

    let file = finding_file_path(finding);
    let label = match finding.risk_code {
        Some(RiskCode::SqlInjection) => format!("SQL injection in `{file}`"),
        Some(RiskCode::CommandInjection) => format!("Command injection in `{file}`"),
        Some(RiskCode::SecretLeak | RiskCode::PiiOrSecretLogging)
            if credential_logging_finding(finding) =>
        {
            format!("Sensitive credential/header logging in `{file}`")
        }
        Some(RiskCode::PiiOrSecretLogging) if payload_logging_finding(finding) => {
            format!("Sensitive payload logging in `{file}`")
        }
        Some(RiskCode::AuthBypass) => format!("Authentication bypass in `{file}`"),
        Some(RiskCode::MissingAuthorizationCheck) => {
            format!("Missing authorization check in `{file}`")
        }
        Some(RiskCode::DataIntegrityRisk) if data_integrity_wipe_finding(finding) => {
            format!("Automatic local data wipe risk in `{file}`")
        }
        Some(RiskCode::DataIntegrityRisk) => format!("Data integrity risk in `{file}`"),
        Some(RiskCode::MigrationRisk) => format!("Migration risk in `{file}`"),
        _ => format!("{} in `{file}`", sentence_fragment(&finding.title)),
    };
    Some(label)
}

fn required_action_for_finding(finding: &ReviewFinding) -> Option<String> {
    if !matches!(
        finding.severity,
        Severity::Critical | Severity::High | Severity::Medium
    ) {
        return None;
    }

    if let Some(fix) = finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|fix| specific_suggested_fix(fix))
    {
        return Some(sentence_from_suggested_fix(fix));
    }

    Some(format!(
        "Address \"{}\" in {}.",
        sentence_fragment(&finding.title),
        finding_file_path(finding)
    ))
}

fn specific_suggested_fix(fix: &str) -> bool {
    let lower = fix.trim().to_ascii_lowercase();
    !lower.is_empty()
        && !matches!(
            lower.as_str(),
            "fix"
                | "fix it"
                | "fix this"
                | "none"
                | "n/a"
                | "na"
                | "no action needed"
                | "add tests"
                | "add test"
                | "handle this"
                | "address this"
        )
        && !lower.starts_with("handle the validated")
        && !lower.contains("fix error handling so failures are not silently accepted")
}

fn sentence_from_suggested_fix(fix: &str) -> String {
    let compact = fix.split_whitespace().collect::<Vec<_>>().join(" ");
    let first_sentence = first_sentence(&compact);
    let mut sentence = if first_sentence.chars().count() > 180 {
        truncate_at_word(first_sentence, 180)
    } else {
        first_sentence.to_string()
    };
    if !matches!(sentence.chars().last(), Some('.') | Some('!') | Some('?')) {
        sentence.push('.');
    }
    sentence
}

fn first_sentence(value: &str) -> &str {
    for (index, ch) in value.char_indices() {
        if !matches!(ch, '.' | '!' | '?') {
            continue;
        }
        let next = &value[index + ch.len_utf8()..];
        if next.is_empty() || next.starts_with(char::is_whitespace) {
            return &value[..=index];
        }
    }
    value
}

fn truncate_at_word(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    for word in value.split_whitespace() {
        let next_len = output.chars().count() + usize::from(!output.is_empty()) + word.len();
        if next_len > max_chars {
            break;
        }
        if !output.is_empty() {
            output.push(' ');
        }
        output.push_str(word);
    }
    output.trim_end_matches(['.', '!', '?']).to_string()
}

fn credential_logging_finding(finding: &ReviewFinding) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::SecretLeak | RiskCode::PiiOrSecretLogging)
    ) && contains_any(
        &finding_text(finding),
        &[
            "authorization",
            "header",
            "token",
            "password",
            "cookie",
            "credential",
        ],
    ) && contains_any(&finding_text(finding), &["log", "logged", "logging"])
}

fn payload_logging_finding(finding: &ReviewFinding) -> bool {
    finding.risk_code == Some(RiskCode::PiiOrSecretLogging)
        && matches!(
            finding.category,
            ReviewCategory::Security | ReviewCategory::Privacy
        )
        && contains_any(
            &format!(
                "{} {}",
                finding.file_path.as_deref().unwrap_or_default(),
                finding_text(finding)
            ),
            &["payload", "webhook", "body", "log", "logged", "logging"],
        )
}

fn weak_error_handling_required_finding(finding: &ReviewFinding) -> bool {
    finding.risk_code == Some(RiskCode::WeakErrorHandling)
        && matches!(finding.severity, Severity::High | Severity::Medium)
        && finding.actionable
}

fn data_integrity_wipe_finding(finding: &ReviewFinding) -> bool {
    let text = format!(
        "{} {}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding_text(finding)
    );
    finding.risk_code == Some(RiskCode::DataIntegrityRisk)
        && matches!(
            finding.category,
            ReviewCategory::DataIntegrity | ReviewCategory::Security | ReviewCategory::Correctness
        )
        && matches!(finding.severity, Severity::Critical | Severity::High)
        && contains_any(
            &text,
            &["wipe", "wiping", "delete", "deletion", "clear local"],
        )
        && contains_any(
            &text,
            &["local data", "user data", "compromised", "security threat"],
        )
}

fn sentence_fragment(text: &str) -> String {
    text.trim().trim_end_matches(['.', '!', '?']).to_string()
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

fn offline_sync_path_signal(path: &str) -> bool {
    contains_any(
        &normalize_path(path),
        &[
            "sync", "offline", "queue", "retry", "cache", "pending", "recovery",
        ],
    )
}

fn is_source_behavior_path(path: &str) -> bool {
    let path = normalize_path(path);
    !path.is_empty()
        && !path.contains("/docs/")
        && !path.starts_with("docs/")
        && !path.ends_with(".md")
        && !path.ends_with(".txt")
}

fn is_test_path(path: &str) -> bool {
    let path = normalize_path(path);
    path.contains("/__tests__/")
        || path.starts_with("__tests__/")
        || path.contains("/tests/")
        || path.starts_with("tests/")
        || path.contains("/androidtest/")
        || path.contains("/test/")
        || path.ends_with(".test.rs")
        || path.ends_with(".spec.rs")
        || path.contains(".test.")
        || path.contains(".spec.")
}

fn test_matches_required_terms(path: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return is_test_path(path);
    }
    let path = normalize_path(path);
    terms
        .iter()
        .any(|term| path.contains(&term.to_ascii_lowercase()))
}

fn has_test_with_terms(paths: &[String], terms: &[&str]) -> bool {
    paths.iter().any(|path| {
        let path = normalize_path(path);
        terms.iter().any(|term| path.contains(term))
    })
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    terms
        .iter()
        .any(|term| value.contains(&term.to_ascii_lowercase()))
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let path = normalize_path(path);
    let pattern = normalize_path(pattern);

    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = pattern.strip_prefix("**/*") {
        return path.ends_with(suffix);
    }
    if let Some(suffix) = pattern.strip_prefix("**/") {
        return path.ends_with(suffix);
    }
    if pattern.contains('*') {
        return wildcard_match(&path, &pattern);
    }
    path.starts_with(&pattern)
}

fn wildcard_match(path: &str, pattern: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.is_empty() {
        return path.is_empty();
    }

    let mut remaining = path;
    if let Some(first) = parts.first().filter(|part| !part.is_empty()) {
        let Some(stripped) = remaining.strip_prefix(first) else {
            return false;
        };
        remaining = stripped;
    }

    for part in parts.iter().skip(1).filter(|part| !part.is_empty()) {
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
    }

    pattern.ends_with('*') || parts.last().is_none_or(|last| remaining.ends_with(last))
}

fn normalize_path(path: &str) -> String {
    path.trim().replace('\\', "/").to_ascii_lowercase()
}

fn push_unique_item(values: &mut Vec<RiskGateItem>, label: String, evidence: Vec<RiskEvidence>) {
    if evidence.is_empty() || values.iter().any(|item| item.label == label) {
        return;
    }
    values.push(RiskGateItem { label, evidence });
}

#[cfg(test)]
mod tests {
    use super::{
        assess_merge_risk, format_merge_risk_gate_markdown, format_merge_risk_gate_terminal,
        MergeDecision, RiskGateRunSignals,
    };
    use crate::{
        config::RiskGateConfig,
        gitlab::{context::DiffStats, types::MergeRequestDiff},
        review::{
            comparison::ReviewComparison,
            large::LargeReviewReport,
            risk::path_matches_pattern,
            types::{
                Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory,
                ReviewFinding, RiskCode, Severity,
            },
        },
    };

    #[test]
    fn risk_score_from_validated_findings() {
        let assessment = assess(
            &[
                finding(Severity::Critical, ReviewCategory::Correctness, None),
                finding(Severity::High, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Low, ReviewCategory::Correctness, None),
            ],
            &[],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.score, 63);
    }

    #[test]
    fn critical_finding_blocks() {
        let assessment = assess(
            &[finding(
                Severity::Critical,
                ReviewCategory::Correctness,
                None,
            )],
            &[],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::Blocked);
    }

    #[test]
    fn high_security_finding_blocks() {
        let assessment = assess(
            &[finding(
                Severity::High,
                ReviewCategory::Security,
                Some(RiskCode::AuthBypass),
            )],
            &[],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::Blocked);
    }

    #[test]
    fn high_non_security_finding_needs_human() {
        let assessment = assess(
            &[finding(Severity::High, ReviewCategory::Correctness, None)],
            &[],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn low_and_notes_do_not_inflate_decision() {
        let mut note = finding(Severity::Note, ReviewCategory::Correctness, None);
        note.actionable = false;

        let assessment = assess(
            &[
                finding(Severity::Low, ReviewCategory::Correctness, None),
                note,
            ],
            &[diff("src/lib.rs", "+fn changed() {}")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::Pass);
    }

    #[test]
    fn large_mr_partial_review_and_failed_chunks_increase_score() {
        let report = large_report(3);
        let assessment = assess(
            &[],
            &[],
            DiffStats {
                changed_file_count: 31,
                total_diff_bytes: 200_001,
                collapsed_file_count: 1,
                ..DiffStats::default()
            },
            RiskGateRunSignals {
                large_review: Some(&report),
                comparison: None,
            },
        );

        assert_eq!(assessment.score, 49);
        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn failed_chunk_score_is_capped() {
        let report = large_report(9);
        let assessment = assess(
            &[],
            &[],
            stats(1, 100),
            RiskGateRunSignals {
                large_review: Some(&report),
                comparison: None,
            },
        );

        assert_eq!(assessment.score, 20);
    }

    #[test]
    fn offline_sync_without_recovery_test_needs_human_without_policy_blocker() {
        let assessment = assess(
            &[],
            &[diff("src/features/sync/worker.rs", "+retry queue")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
        assert!(!has_requirement(&assessment, "Add sync recovery test"));
    }

    #[test]
    fn offline_sync_with_recovery_test_does_not_block_for_sync_gate() {
        let assessment = assess(
            &[],
            &[
                diff("src/sync/worker.rs", "+retry queue"),
                diff("tests/sync_recovery.test.rs", "+recovers pending queue"),
            ],
            stats(2, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
    }

    #[test]
    fn offline_sync_blocker_does_not_appear_without_sync_file_change() {
        let assessment = assess(
            &[],
            &[diff(
                "src/paymentClient.ts",
                "+logger.info('retry payment request')",
            )],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
    }

    #[test]
    fn empty_evidence_blockers_and_actions_are_not_rendered() {
        let assessment = super::MergeRiskAssessment {
            score: 80,
            decision: MergeDecision::Blocked,
            blocking_issues: vec![super::RiskGateItem {
                label: "Modified offline sync layer without adding recovery test".to_string(),
                evidence: vec![],
            }],
            required_before_merge: vec![super::RiskGateItem {
                label: "Add sync recovery test".to_string(),
                evidence: vec![],
            }],
            risk_factors: vec![],
            blast_radius: super::BlastRadius::default(),
        };

        let markdown = format_merge_risk_gate_markdown(&assessment);
        let terminal = format_merge_risk_gate_terminal(&assessment);

        assert!(!markdown.contains("Modified offline sync layer without adding recovery test"));
        assert!(!markdown.contains("Add sync recovery test"));
        assert!(terminal.contains("Blocking Issues: 0"));
        assert!(terminal.contains("Required Before Merge: 0"));
    }

    #[test]
    fn sample_android_findings_emit_only_evidence_bound_actions() {
        let report = large_report(1);
        let assessment = assess(
            &[
                finding_with_details_and_fix(
                    Severity::High,
                    ReviewCategory::DataIntegrity,
                    Some(RiskCode::DataIntegrityRisk),
                    "android/app/src/main/java/id/go/bgn/sipgn/distribusi/MainApplication.kt",
                    "Automatic data deletion on security threat detection",
                    "Startup deletes local user data after compromised-device security threat detection.",
                    "Add guardrails for compromised-device false positives before wiping local user data.",
                ),
                finding_with_details_and_fix(
                    Severity::Medium,
                    ReviewCategory::Security,
                    Some(RiskCode::SecretLeak),
                    "android/app/src/main/AndroidManifest.xml",
                    "Hardcoded Google Maps API key",
                    "The Android manifest contains a Google Maps API key.",
                    "Move the Google Maps API key to build-time config or confirm package/SHA restrictions.",
                ),
                finding_with_details_and_fix(
                    Severity::Medium,
                    ReviewCategory::Reliability,
                    Some(RiskCode::WeakErrorHandling),
                    "src/routes/navigationRef.ts",
                    "Navigation reset failures are not bubbled up",
                    "Max-retry navigation reset failures are swallowed without a visible fallback.",
                    "Handle max-retry navigation reset failures with a visible fallback or error state in src/routes/navigationRef.ts.",
                ),
            ],
            &[
                diff(
                    "android/app/src/main/java/id/go/bgn/sipgn/distribusi/MainApplication.kt",
                    "+wipeLocalDataOnSecurityThreat()",
                ),
                diff(
                    "android/app/src/main/AndroidManifest.xml",
                    "+<meta-data android:name=\"com.google.android.geo.API_KEY\" />",
                ),
                diff(
                    "src/routes/navigationRef.ts",
                    "+if (attempts > maxRetry) return;",
                ),
            ],
            stats(3, 100),
            RiskGateRunSignals {
                large_review: Some(&report),
                comparison: None,
            },
        );

        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
        assert!(!has_requirement(&assessment, "Add sync recovery test"));
        assert!(!has_requirement(
            &assessment,
            "Fix error handling so failures are not silently accepted"
        ));
        assert!(has_blocker(
            &assessment,
            "Automatic local data wipe risk in `android/app/src/main/java/id/go/bgn/sipgn/distribusi/MainApplication.kt`"
        ));
        assert!(has_requirement(
            &assessment,
            "Add guardrails for compromised-device false positives before wiping local user data."
        ));
        assert!(has_requirement(
            &assessment,
            "Move the Google Maps API key to build-time config or confirm package/SHA restrictions."
        ));
        assert!(has_requirement(
            &assessment,
            "Handle max-retry navigation reset failures with a visible fallback or error state in src/routes/navigationRef.ts."
        ));
    }

    #[test]
    fn offline_sync_path_without_recovery_test_no_longer_blocks() {
        let assessment = assess(
            &[],
            &[diff(
                "src/features/sync/offlineQueue.ts",
                "+pending retry queue",
            )],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
        assert!(!has_requirement(&assessment, "Add sync recovery test"));
    }

    #[test]
    fn api_contract_without_snapshot_needs_human_without_policy_blocker() {
        let assessment = assess(
            &[],
            &[diff("src/api/user_dto.rs", "+api response changes")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
        assert!(!has_blocker(
            &assessment,
            "Changed API response contract without updating contract snapshot"
        ));
    }

    #[test]
    fn api_contract_blocker_does_not_appear_for_generic_client_file() {
        let assessment = assess(
            &[],
            &[diff("src/paymentClient.ts", "+fetch('/api/payments')")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Changed API response contract without updating contract snapshot"
        ));
    }

    #[test]
    fn api_contract_with_snapshot_does_not_block() {
        let assessment = assess(
            &[],
            &[
                diff("src/api/user_dto.rs", "+api response changes"),
                diff("openapi/user.yaml", "+schema update"),
            ],
            stats(2, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Changed API response contract without updating contract snapshot"
        ));
    }

    #[test]
    fn db_migration_without_rollback_needs_human_without_policy_blocker() {
        let assessment = assess(
            &[],
            &[diff(
                "migrations/001.sql",
                "+ALTER TABLE users ADD COLUMN role",
            )],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
        assert!(!has_blocker(
            &assessment,
            "Added DB migration without rollback plan"
        ));
    }

    #[test]
    fn migration_with_rollback_note_does_not_block() {
        let assessment = assess(
            &[],
            &[
                diff("migrations/001.sql", "+ALTER TABLE users ADD COLUMN role"),
                diff("migrations/down.sql", "+rollback plan"),
            ],
            stats(2, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Added DB migration without rollback plan"
        ));
    }

    #[test]
    fn migration_blocker_does_not_appear_without_migration_evidence() {
        let assessment = assess(
            &[],
            &[diff(
                "src/paymentClient.ts",
                "+const migrationNote = 'none';",
            )],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Added DB migration without rollback plan"
        ));
    }

    #[test]
    fn protected_path_touched_needs_human_without_policy_blocker() {
        let assessment = assess(
            &[],
            &[diff("src/auth/session.rs", "+renew session")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
        assert!(!has_blocker(
            &assessment,
            "Touched protected module: `src/auth/**`"
        ));
    }

    #[test]
    fn protected_path_owner_does_not_emit_required_before_merge_template() {
        let assessment = assess(
            &[],
            &[diff("src/auth/session.rs", "+renew session")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_requirement(
            &assessment,
            "Request owner review from Security Lead"
        ));
    }

    #[test]
    fn protected_path_blocker_template_is_not_emitted() {
        let assessment = assess(
            &[],
            &[diff("src/features/sync/worker.rs", "+start queue")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(!has_blocker(
            &assessment,
            "Touched protected module: `src/features/sync/**`"
        ));
    }

    #[test]
    fn sql_injection_finding_emits_evidence_bound_blocker_and_requirement() {
        let assessment = assess(
            &[finding_with_details_and_fix(
                Severity::Critical,
                ReviewCategory::Security,
                Some(RiskCode::SqlInjection),
                "src/paymentClient.ts",
                "Raw SQL interpolation",
                "findPaymentsByCustomer interpolates customer input into SQL.",
                "Replace raw SQL interpolation with a parameterized query or safe query builder.",
            )],
            &[diff("src/paymentClient.ts", "+db.query(`SELECT ${id}`)")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(has_blocker(
            &assessment,
            "SQL injection in `src/paymentClient.ts`"
        ));
        assert!(has_requirement(
            &assessment,
            "Replace raw SQL interpolation with a parameterized query or safe query builder."
        ));
    }

    #[test]
    fn secret_leak_finding_emits_credential_logging_blocker() {
        let assessment = assess(
            &[finding_with_details_and_fix(
                Severity::High,
                ReviewCategory::Security,
                Some(RiskCode::SecretLeak),
                "src/paymentClient.ts",
                "Authorization header is logged",
                "The raw Authorization header token is written to logs.",
                "Remove raw Authorization header logging in src/paymentClient.ts.",
            )],
            &[diff(
                "src/paymentClient.ts",
                "+logger.info(headers.authorization)",
            )],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(has_blocker(
            &assessment,
            "Sensitive credential/header logging in `src/paymentClient.ts`"
        ));
        assert!(has_requirement(
            &assessment,
            "Remove raw Authorization header logging in src/paymentClient.ts."
        ));
    }

    #[test]
    fn webhook_pii_logging_finding_emits_payload_logging_blocker() {
        let assessment = assess(
            &[finding_with_details_and_fix(
                Severity::High,
                ReviewCategory::Privacy,
                Some(RiskCode::PiiOrSecretLogging),
                "src/webhook.ts",
                "Webhook payload is logged",
                "The full webhook body payload is logged.",
                "Remove or sanitize full webhook payload logging in src/webhook.ts.",
            )],
            &[diff("src/webhook.ts", "+console.log(req.body)")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(has_blocker(
            &assessment,
            "Sensitive payload logging in `src/webhook.ts`"
        ));
        assert!(has_requirement(
            &assessment,
            "Remove or sanitize full webhook payload logging in src/webhook.ts."
        ));
    }

    #[test]
    fn weak_error_handling_finding_adds_requirement_without_unrelated_blocker() {
        let assessment = assess(
            &[finding_with_details_and_fix(
                Severity::Medium,
                ReviewCategory::Reliability,
                Some(RiskCode::WeakErrorHandling),
                "src/webhook.ts",
                "JSON parse errors are suppressed",
                "Malformed webhook JSON is silently accepted.",
                "Fix webhook parse failure handling so malformed payloads are not silently accepted.",
            )],
            &[diff("src/webhook.ts", "+try { JSON.parse(body) } catch {}")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert!(has_requirement(
            &assessment,
            "Fix webhook parse failure handling so malformed payloads are not silently accepted."
        ));
        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
    }

    #[test]
    fn sample_payment_webhook_findings_block_without_unrelated_policy_blockers() {
        let assessment = assess(
            &[
                finding_with_details_and_fix(
                    Severity::Critical,
                    ReviewCategory::Security,
                    Some(RiskCode::SqlInjection),
                    "src/paymentClient.ts",
                    "SQL injection in payment lookup",
                    "findPaymentsByCustomer uses raw SQL interpolation.",
                    "Use parameterized queries or a safe query builder in src/paymentClient.ts.",
                ),
                finding_with_details_and_fix(
                    Severity::High,
                    ReviewCategory::Security,
                    Some(RiskCode::SecretLeak),
                    "src/paymentClient.ts",
                    "Authorization header is logged",
                    "The raw Authorization header token is logged.",
                    "Remove Authorization header logging in src/paymentClient.ts.",
                ),
                finding_with_details_and_fix(
                    Severity::High,
                    ReviewCategory::Privacy,
                    Some(RiskCode::PiiOrSecretLogging),
                    "src/webhook.ts",
                    "Webhook payload is logged",
                    "The full webhook body payload is logged.",
                    "Remove or sanitize full webhook payload logging in src/webhook.ts.",
                ),
                finding_with_details_and_fix(
                    Severity::Medium,
                    ReviewCategory::Reliability,
                    Some(RiskCode::WeakErrorHandling),
                    "src/webhook.ts",
                    "JSON parse errors are suppressed",
                    "Malformed webhook JSON is silently accepted.",
                    "Fix webhook parse failure handling so malformed payloads are not silently accepted.",
                ),
            ],
            &[
                diff("src/paymentClient.ts", "+db.query(`SELECT ${id}`)"),
                diff("src/webhook.ts", "+console.log(req.body)"),
            ],
            stats(2, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::Blocked);
        assert!(has_blocker(
            &assessment,
            "SQL injection in `src/paymentClient.ts`"
        ));
        assert!(has_blocker(
            &assessment,
            "Sensitive credential/header logging in `src/paymentClient.ts`"
        ));
        assert!(has_blocker(
            &assessment,
            "Sensitive payload logging in `src/webhook.ts`"
        ));
        assert!(!has_blocker(
            &assessment,
            "Modified offline sync layer without adding recovery test"
        ));
        assert!(!has_blocker(
            &assessment,
            "Added DB migration without rollback plan"
        ));
        assert!(!has_blocker(
            &assessment,
            "Changed API response contract without updating contract snapshot"
        ));
        assert!(has_requirement(
            &assessment,
            "Use parameterized queries or a safe query builder in src/paymentClient.ts."
        ));
        assert!(has_requirement(
            &assessment,
            "Remove Authorization header logging in src/paymentClient.ts."
        ));
        assert!(has_requirement(
            &assessment,
            "Remove or sanitize full webhook payload logging in src/webhook.ts."
        ));
        assert!(has_requirement(
            &assessment,
            "Fix webhook parse failure handling so malformed payloads are not silently accepted."
        ));
    }

    #[test]
    fn previous_finding_still_detected_increases_score() {
        let comparison = comparison(1, 0, 0);
        let assessment = assess(
            &[],
            &[],
            stats(1, 100),
            RiskGateRunSignals {
                large_review: None,
                comparison: Some(&comparison),
            },
        );

        assert_eq!(assessment.score, 15);
        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn verified_fixed_reduces_score() {
        let comparison = comparison(0, 0, 3);
        let assessment = assess(
            &[finding(Severity::High, ReviewCategory::Correctness, None)],
            &[],
            stats(1, 100),
            RiskGateRunSignals {
                large_review: None,
                comparison: Some(&comparison),
            },
        );

        assert_eq!(assessment.score, 0);
    }

    #[test]
    fn pass_decision_when_no_risk() {
        let assessment = assess(&[], &[], stats(1, 100), RiskGateRunSignals::default());

        assert_eq!(assessment.decision, MergeDecision::Pass);
    }

    #[test]
    fn needs_human_decision_when_score_moderate() {
        let assessment = assess(
            &[
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
                finding(Severity::Medium, ReviewCategory::Correctness, None),
            ],
            &[],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.score, 56);
        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn medium_only_findings_cannot_block_or_exceed_74() {
        let findings = (0..20)
            .map(|_| finding(Severity::Medium, ReviewCategory::Reliability, None))
            .collect::<Vec<_>>();
        let assessment = assess(&findings, &[], stats(1, 100), RiskGateRunSignals::default());

        assert_eq!(assessment.score, 74);
        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn low_and_note_only_findings_pass_without_large_review_failure() {
        let mut note = finding(Severity::Note, ReviewCategory::Correctness, None);
        note.actionable = false;
        let mut findings = (0..60)
            .map(|_| finding(Severity::Low, ReviewCategory::Reliability, None))
            .collect::<Vec<_>>();
        findings.push(note);

        let assessment = assess(&findings, &[], stats(1, 100), RiskGateRunSignals::default());

        assert_eq!(assessment.score, 49);
        assert_eq!(assessment.decision, MergeDecision::Pass);
    }

    #[test]
    fn high_non_severe_findings_are_capped_at_89_and_need_human() {
        let findings = (0..6)
            .map(|_| finding(Severity::High, ReviewCategory::Correctness, None))
            .collect::<Vec<_>>();
        let assessment = assess(&findings, &[], stats(1, 100), RiskGateRunSignals::default());

        assert_eq!(assessment.score, 89);
        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn critical_findings_can_block_and_reach_100() {
        let findings = (0..3)
            .map(|_| finding(Severity::Critical, ReviewCategory::Correctness, None))
            .collect::<Vec<_>>();
        let assessment = assess(&findings, &[], stats(1, 100), RiskGateRunSignals::default());

        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.decision, MergeDecision::Blocked);
    }

    #[test]
    fn broad_offline_sync_signal_does_not_block_without_validated_blocker_finding() {
        let assessment = assess(
            &[],
            &[diff("src/offline/cache.rs", "+pending queue")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );

        assert_eq!(assessment.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn markdown_output_matches_target_shape() {
        let assessment = assess(
            &[],
            &[diff("src/offline/cache.rs", "+pending queue")],
            stats(1, 100),
            RiskGateRunSignals::default(),
        );
        let markdown = format_merge_risk_gate_markdown(&assessment);

        assert!(markdown.starts_with("## Merge Risk Gate\n\nRisk Score: "));
        assert!(markdown.contains("Decision: NEEDS HUMAN"));
        assert!(!markdown.contains("Blocking Issues:"));
        assert!(!markdown.contains("Modified offline sync layer"));
        assert!(!markdown.contains("Add sync recovery test"));
    }

    #[test]
    fn runtime_output_does_not_emit_hardcoded_policy_templates() {
        let assessment = assess(
            &[],
            &[
                diff("src/features/sync/offlineQueue.ts", "+pending retry queue"),
                diff("src/api/user_dto.rs", "+api response changes"),
                diff("migrations/001.sql", "+ALTER TABLE users ADD COLUMN role"),
                diff("src/auth/session.rs", "+renew session"),
            ],
            stats(4, 100),
            RiskGateRunSignals::default(),
        );
        let markdown = format_merge_risk_gate_markdown(&assessment);

        for forbidden in [
            "Modified offline sync layer without adding recovery test",
            "Add sync recovery test",
            "Fix error handling so failures are not silently accepted",
            "Handle the validated error-handling failure",
            "Changed API response contract without updating contract snapshot",
            "Added DB migration without rollback plan",
            "Touched protected module",
            "Request owner review",
            "Update OpenAPI",
            "Attach migration rollback",
        ] {
            assert!(!markdown.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn required_actions_are_deduped_and_capped_from_suggested_fixes() {
        let findings = (0..8)
            .map(|index| {
                let suggested_fix = if index < 2 {
                    "Handle the shared failure mode in the affected file.".to_string()
                } else {
                    format!("Handle specific failure mode {index} in the affected file.")
                };
                finding_with_details_and_fix(
                    Severity::Medium,
                    ReviewCategory::Reliability,
                    Some(RiskCode::WeakErrorHandling),
                    &format!("src/file{index}.rs"),
                    &format!("Finding {index}"),
                    "body",
                    &suggested_fix,
                )
            })
            .collect::<Vec<_>>();
        let assessment = assess(&findings, &[], stats(1, 100), RiskGateRunSignals::default());
        let labels = assessment
            .required_before_merge
            .iter()
            .map(|item| item.label.as_str())
            .collect::<Vec<_>>();

        assert!(labels.len() <= 6);
        assert_eq!(
            labels
                .iter()
                .filter(|label| **label == "Handle the shared failure mode in the affected file.")
                .count(),
            1
        );
    }

    #[test]
    fn terminal_output_includes_score_and_decision() {
        let assessment = assess(&[], &[], stats(1, 100), RiskGateRunSignals::default());
        let output = format_merge_risk_gate_terminal(&assessment);

        assert!(output.contains("Merge Risk Gate:"));
        assert!(output.contains("Risk Score: 0/100"));
        assert!(output.contains("Decision: PASS"));
    }

    #[test]
    fn wildcard_matching_supports_config_shapes() {
        assert!(path_matches_pattern("src/auth/session.rs", "src/auth/**"));
        assert!(path_matches_pattern("api/user.proto", "**/*.proto"));
        assert!(path_matches_pattern("db/schema.sql", "**/schema.sql"));
    }

    fn assess(
        findings: &[ReviewFinding],
        diffs: &[MergeRequestDiff],
        stats: DiffStats,
        signals: RiskGateRunSignals<'_>,
    ) -> super::MergeRiskAssessment {
        let config = RiskGateConfig::default();
        assess_merge_risk(
            &analysis(findings.to_vec()),
            diffs,
            &stats,
            &config,
            signals,
        )
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
    ) -> ReviewFinding {
        finding_with_details(severity, category, risk_code, "src/lib.rs", "title", "body")
    }

    fn finding_with_details(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        file_path: &str,
        title: &str,
        body: &str,
    ) -> ReviewFinding {
        finding_with_details_and_fix(severity, category, risk_code, file_path, title, body, "fix")
    }

    fn finding_with_details_and_fix(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        file_path: &str,
        title: &str,
        body: &str,
        suggested_fix: &str,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category,
            risk_code,
            anchor_id: None,
            file_path: Some(file_path.to_string()),
            line: Some(1),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: Some(suggested_fix.to_string()),
            effort: Effort::Moderate,
            actionable: true,
            evidence_status: Some(EvidenceValidationStatus::Validated),
            evidence_reason: None,
        }
    }

    fn diff(path: &str, body: &str) -> MergeRequestDiff {
        MergeRequestDiff {
            old_path: path.to_string(),
            new_path: path.to_string(),
            diff: body.to_string(),
            new_file: false,
            renamed_file: false,
            deleted_file: false,
            generated_file: None,
            collapsed: None,
            too_large: None,
        }
    }

    fn stats(changed_file_count: usize, total_diff_bytes: usize) -> DiffStats {
        DiffStats {
            changed_file_count,
            total_diff_bytes,
            ..DiffStats::default()
        }
    }

    fn large_report(failed_chunks: usize) -> LargeReviewReport {
        LargeReviewReport {
            total_chunks: failed_chunks.max(1),
            reviewed_chunks: 1,
            retried_chunks: 0,
            failed_chunks,
            reviewed_files: 1,
            skipped_files: 0,
            skipped_reasons: Vec::new(),
        }
    }

    fn comparison(
        still_detected: usize,
        not_detected: usize,
        verified_fixed: usize,
    ) -> ReviewComparison {
        ReviewComparison {
            previous_run_id: Some("previous".to_string()),
            current_run_id: "current".to_string(),
            new_findings: 0,
            still_detected,
            not_detected,
            verified_fixed,
            needs_verification: not_detected,
            previous_total_actionable: 0,
            current_total_actionable: 0,
        }
    }

    fn has_blocker(assessment: &super::MergeRiskAssessment, label: &str) -> bool {
        assessment
            .blocking_issues
            .iter()
            .any(|item| item.label == label && !item.evidence.is_empty())
    }

    fn has_requirement(assessment: &super::MergeRiskAssessment, label: &str) -> bool {
        assessment
            .required_before_merge
            .iter()
            .any(|item| item.label == label && !item.evidence.is_empty())
    }
}
