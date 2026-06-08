use crate::{
    counters::count_findings_from_analysis,
    review::{
        risk::{MergeDecision, MergeRiskAssessment, RiskEvidence, RiskFactor, RiskGateItem},
        types::{
            EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding,
            RiskCode, Severity,
        },
    },
};
use std::collections::HashSet;

const DECISION_NEEDS_HUMAN_SCORE: u8 = 25;
const NO_PRIORITY_PASS_SCORE_CAP: u8 = 24;
const NO_PRIORITY_UNCERTAINTY_CAP: u8 = 10;
const NO_PRIORITY_LOW_AND_UNCERTAINTY_SCORE: u8 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReport {
    pub analysis: ReviewAnalysis,
    pub risk_assessment: Option<MergeRiskAssessment>,
}

pub fn sanitize_review_report(mut report: ReviewReport) -> ReviewReport {
    report.analysis = sanitize_review_analysis(report.analysis);
    if let Some(assessment) = report.risk_assessment.take() {
        let assessment = sanitize_merge_risk_assessment(&report.analysis, assessment);
        report.analysis.overall_risk = calibrated_overall_risk(&report.analysis, Some(&assessment));
        report.risk_assessment = Some(assessment);
    } else {
        report.analysis.overall_risk = calibrated_overall_risk(&report.analysis, None);
    }
    report
}

pub fn sanitize_merge_risk_assessment(
    analysis: &ReviewAnalysis,
    mut assessment: MergeRiskAssessment,
) -> MergeRiskAssessment {
    assessment.blocking_issues.clear();
    assessment.required_before_merge.clear();
    add_finding_blockers(analysis, &mut assessment.blocking_issues);
    add_missing_finding_actions(analysis, &mut assessment.required_before_merge);
    dedupe_gate_items(&mut assessment.blocking_issues);
    dedupe_gate_items(&mut assessment.required_before_merge);
    assessment.required_before_merge.truncate(5);

    let has_critical = analysis.findings.iter().any(|finding| {
        validated_actionable_finding(finding) && finding.severity == Severity::Critical
    });
    let has_high = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable_finding(finding) && finding.severity == Severity::High);
    let has_high_blocking = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable_finding(finding) && high_blocking_finding(finding));
    let score_100_allowed = has_critical || has_high_blocking;

    if !score_100_allowed {
        assessment.score = if has_high {
            assessment.score.min(89)
        } else if has_medium(analysis) {
            assessment
                .score
                .min(medium_only_score_cap(analysis, &assessment))
        } else {
            assessment
                .score
                .min(low_or_note_score_cap(analysis, &assessment))
        };
    }

    if !has_critical && !has_high {
        assessment.score = assessment
            .score
            .min(medium_only_score_cap(analysis, &assessment));
    }
    if no_priority_pass_override(analysis, &assessment) {
        assessment.score = calibrated_no_priority_score(analysis, &assessment);
    }

    assessment.decision = calibrated_merge_decision(analysis, &assessment);
    add_calibrated_why_factors(analysis, &mut assessment);

    assessment
}

fn calibrated_merge_decision(
    analysis: &ReviewAnalysis,
    assessment: &MergeRiskAssessment,
) -> MergeDecision {
    let counters = count_findings_from_analysis(analysis);
    let blocking_issues = assessment
        .blocking_issues
        .iter()
        .any(|item| !item.evidence.is_empty());
    let has_critical = analysis.findings.iter().any(|finding| {
        validated_actionable_finding(finding) && finding.severity == Severity::Critical
    });
    let has_high_blocking = analysis
        .findings
        .iter()
        .any(|finding| validated_actionable_finding(finding) && high_blocking_finding(finding));

    if has_critical || has_high_blocking || blocking_issues {
        return MergeDecision::Blocked;
    }

    let has_priority_findings = counters.open_priority > 0;
    if has_priority_findings
        || assessment.blast_radius.failed_chunks > 0
        || assessment.score >= DECISION_NEEDS_HUMAN_SCORE
    {
        return MergeDecision::NeedsHuman;
    }

    MergeDecision::Pass
}

fn calibrated_overall_risk(
    analysis: &ReviewAnalysis,
    assessment: Option<&MergeRiskAssessment>,
) -> OverallRisk {
    let finding_risk = strongest_actionable_risk(analysis).unwrap_or(OverallRisk::Low);
    let Some(assessment) = assessment else {
        return finding_risk;
    };
    if priority_findings(analysis).is_empty()
        && !assessment
            .blocking_issues
            .iter()
            .any(|item| !item.evidence.is_empty())
    {
        return OverallRisk::Low;
    }

    match assessment.decision {
        MergeDecision::Blocked => stronger_risk(finding_risk, OverallRisk::High),
        MergeDecision::NeedsHuman => {
            if assessment.score >= 75 {
                stronger_risk(finding_risk, OverallRisk::High)
            } else {
                stronger_risk(finding_risk, OverallRisk::Medium)
            }
        }
        MergeDecision::Pass => {
            if matches!(finding_risk, OverallRisk::Note) {
                OverallRisk::Low
            } else {
                finding_risk
            }
        }
    }
}

fn no_priority_pass_override(analysis: &ReviewAnalysis, assessment: &MergeRiskAssessment) -> bool {
    count_findings_from_analysis(analysis).open_priority == 0
        && assessment.blast_radius.failed_chunks == 0
        && !assessment
            .blocking_issues
            .iter()
            .any(|item| !item.evidence.is_empty())
        && !assessment
            .risk_factors
            .iter()
            .any(|factor| factor.rule_id == "comparison.previous_finding_still_detected")
}

fn calibrated_no_priority_score(analysis: &ReviewAnalysis, assessment: &MergeRiskAssessment) -> u8 {
    let uncertainty_score = assessment
        .risk_factors
        .iter()
        .filter(|factor| factor.points > 0 && no_priority_uncertainty_factor(factor))
        .map(|factor| factor.points as u16)
        .sum::<u16>()
        .min(NO_PRIORITY_UNCERTAINTY_CAP as u16) as u8;
    let code_score = assessment
        .risk_factors
        .iter()
        .filter(|factor| factor.points > 0 && !no_priority_uncertainty_factor(factor))
        .map(|factor| factor.points as u16)
        .sum::<u16>()
        .min(u8::MAX as u16) as u8;
    let score = if assessment.risk_factors.is_empty() {
        assessment.score
    } else {
        code_score.saturating_add(uncertainty_score)
    };
    let low_count = analysis
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Low)
        .count();
    let has_low_or_note = analysis
        .findings
        .iter()
        .any(|finding| matches!(finding.severity, Severity::Low | Severity::Note));

    if has_low_or_note && uncertainty_score > 0 {
        if low_count <= 1 {
            NO_PRIORITY_LOW_AND_UNCERTAINTY_SCORE
        } else {
            score.max(NO_PRIORITY_LOW_AND_UNCERTAINTY_SCORE)
        }
    } else {
        score
    }
    .min(NO_PRIORITY_PASS_SCORE_CAP)
}

fn no_priority_uncertainty_factor(factor: &RiskFactor) -> bool {
    matches!(
        factor.rule_id.as_str(),
        "verification.large_mr.changed_files"
            | "verification.large_mr.diff_bytes"
            | "verification.gitlab.partial_diff"
            | "changed_file.auth_security_area"
    ) || factor.rule_id.contains("large")
        || factor.rule_id.contains("partial")
}

fn strongest_actionable_risk(analysis: &ReviewAnalysis) -> Option<OverallRisk> {
    analysis
        .findings
        .iter()
        .filter(|finding| finding.actionable)
        .map(|finding| match finding.severity {
            Severity::Critical => OverallRisk::Critical,
            Severity::High => OverallRisk::High,
            Severity::Medium => OverallRisk::Medium,
            Severity::Low => OverallRisk::Low,
            Severity::Note => OverallRisk::Note,
        })
        .min_by_key(|risk| risk_sort_key(*risk))
}

fn stronger_risk(left: OverallRisk, right: OverallRisk) -> OverallRisk {
    if risk_sort_key(left) <= risk_sort_key(right) {
        left
    } else {
        right
    }
}

fn risk_sort_key(risk: OverallRisk) -> u8 {
    match risk {
        OverallRisk::Critical => 0,
        OverallRisk::High => 1,
        OverallRisk::Medium => 2,
        OverallRisk::Low => 3,
        OverallRisk::Note => 4,
    }
}

fn sanitize_review_analysis(mut analysis: ReviewAnalysis) -> ReviewAnalysis {
    for finding in &mut analysis.findings {
        sanitize_security_exception_fix(finding);
    }
    analysis.findings.retain(renderable_final_finding);
    analysis.summary = sanitize_summary(&analysis.summary, &analysis.findings);
    analysis.test_coverage_note =
        sanitize_optional_note(analysis.test_coverage_note, &analysis.findings);
    analysis.privacy_note = sanitize_optional_note(analysis.privacy_note, &analysis.findings);
    analysis
}

fn sanitize_summary(summary: &str, findings: &[ReviewFinding]) -> String {
    let mut metadata = Vec::new();
    let mut caveat = None;
    let mut overview = None;
    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_bullet(trimmed) {
            let item = bullet_text(trimmed);
            if is_review_summary_metadata(item) && !is_engineish_phrase(item) {
                metadata.push(trimmed.to_string());
            }
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if is_engineish_phrase(trimmed)
            || policy_template_without_finding_evidence(trimmed, findings)
        {
            continue;
        }
        if lower.contains("partial")
            || lower.contains("risk-prioritized")
            || lower.contains("not a full exhaustive review")
            || lower.contains("not a full-file exhaustive review")
        {
            caveat.get_or_insert(sentence_from_suggested_fix(trimmed));
        } else if overview.is_none() {
            overview = Some(sentence_from_suggested_fix(trimmed));
        }
    }

    let mut output = metadata.join("\n");
    let titles = priority_finding_titles(findings, 3);
    if titles.is_empty() {
        if !output.is_empty() {
            output.push_str("\n\n");
        }
        output.push_str(
            overview
                .as_deref()
                .filter(|_| metadata.is_empty())
                .unwrap_or("No priority risks remain open from the reviewed chunks."),
        );
    } else {
        if !output.is_empty() {
            output.push_str("\n\n");
        }
        output.push_str("Main risks found:\n");
        for title in titles {
            output.push_str("- ");
            output.push_str(&title);
            output.push('\n');
        }
        output = output.trim_end().to_string();
    }
    if let Some(caveat) = caveat {
        output.push_str("\n\n");
        output.push_str(&caveat);
    }
    output
}

fn sanitize_optional_note(note: Option<String>, findings: &[ReviewFinding]) -> Option<String> {
    note.map(|note| {
        note.lines()
            .filter(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return false;
                }
                if is_engineish_phrase(trimmed) {
                    return false;
                }
                if is_bullet(trimmed) {
                    return has_item_evidence(bullet_text(trimmed), findings);
                }
                !policy_template_without_finding_evidence(trimmed, findings)
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

fn add_finding_blockers(analysis: &ReviewAnalysis, items: &mut Vec<RiskGateItem>) {
    for finding in analysis
        .findings
        .iter()
        .filter(|finding| validated_actionable_finding(finding))
        .filter(|finding| finding.severity == Severity::Critical || high_blocking_finding(finding))
    {
        let evidence = finding_evidence(finding);
        if evidence.is_empty() {
            continue;
        }
        items.push(RiskGateItem {
            label: finding_blocking_issue(finding),
            evidence,
        });
    }
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

fn finding_blocking_issue(finding: &ReviewFinding) -> String {
    let file = finding_file_path(finding);
    match finding.risk_code {
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
        Some(RiskCode::DataIntegrityRisk) if local_data_wipe_finding(finding) => {
            format!("Automatic local data wipe risk in `{file}`")
        }
        Some(RiskCode::DataIntegrityRisk) => format!("Data integrity risk in `{file}`"),
        Some(RiskCode::MigrationRisk) => format!("Migration risk in `{file}`"),
        _ => format!("{} in `{file}`", sentence_fragment(&finding.title)),
    }
}

fn finding_required_action(finding: &ReviewFinding) -> String {
    if let Some(fix) = finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|fix| specific_suggested_fix(fix))
    {
        let action = sentence_from_suggested_fix(fix);
        if !weakens_security_posture(&action) {
            return action;
        }
    }
    format!(
        "Address \"{}\" in {}{}.",
        sentence_fragment(&finding.title),
        finding_file_path(finding),
        if security_sensitive_finding(finding) {
            " while preserving the existing security posture"
        } else {
            ""
        }
    )
}

fn specific_suggested_fix(fix: &str) -> bool {
    let lower = fix.to_ascii_lowercase();
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
        && !generic_placeholder_fix(&lower)
        && !is_engineish_phrase(fix)
        && !lower.contains("handle the issue")
        && !lower.contains("handle this issue")
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
    if finding_score == 0 {
        return if assessment
            .risk_factors
            .iter()
            .any(|factor| factor.points > 0)
        {
            assessment.score.min(74)
        } else {
            0
        };
    }
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

fn low_or_note_score_cap(analysis: &ReviewAnalysis, assessment: &MergeRiskAssessment) -> u8 {
    if analysis.findings.iter().any(validated_actionable_finding)
        || assessment
            .risk_factors
            .iter()
            .any(|factor| factor.points > 0)
    {
        assessment.score.min(49)
    } else {
        medium_only_score_cap(analysis, assessment).min(49)
    }
}

fn has_medium(analysis: &ReviewAnalysis) -> bool {
    analysis.findings.iter().any(|finding| {
        validated_actionable_finding(finding) && finding.severity == Severity::Medium
    })
}

fn add_calibrated_why_factors(analysis: &ReviewAnalysis, assessment: &mut MergeRiskAssessment) {
    let mut original_factors = std::mem::take(&mut assessment.risk_factors);
    let mut public_reasons = public_why_factors(analysis, assessment);
    public_reasons.append(&mut original_factors);
    assessment.risk_factors = public_reasons;
    dedupe_risk_factors_by_label(&mut assessment.risk_factors);
}

fn public_why_factors(
    analysis: &ReviewAnalysis,
    assessment: &MergeRiskAssessment,
) -> Vec<RiskFactor> {
    let mut factors = Vec::new();
    let priority = priority_findings(analysis);
    let large = large_review_partial(assessment);
    let high_risk = security_sensitive_modified(assessment)
        || priority
            .iter()
            .any(|finding| security_sensitive_finding(finding));
    match assessment.decision {
        MergeDecision::Pass => {
            factors.push(public_why_factor(
                "published.why.no_priority",
                "No priority findings remain open.",
            ));
            if large {
                factors.push(public_why_factor(
                    "published.why.large_review",
                    "Review was large and risk-prioritized, so low-priority notes were summarized only.",
                ));
            }
        }
        MergeDecision::Blocked | MergeDecision::NeedsHuman => {
            if priority.len() == 1 {
                factors.push(public_why_factor(
                    "published.why.single_finding",
                    format!(
                        "{} remains open.",
                        clean_finding_title(priority[0]).trim_end_matches(['.', '!', '?'])
                    ),
                ));
                if high_risk {
                    factors.push(public_why_factor(
                        "published.why.high_risk_code",
                        "Review touched security-sensitive or high-risk code.",
                    ));
                }
            } else if priority.len() > 1 {
                factors.push(public_why_factor(
                    "published.why.multiple_findings",
                    multiple_findings_why(&priority),
                ));
                if high_risk {
                    factors.push(public_why_factor(
                        "published.why.high_risk_paths",
                        "Review touched high-risk code paths.",
                    ));
                }
            } else {
                factors.push(public_why_factor(
                    "published.why.no_priority",
                    "No priority findings remain open.",
                ));
            }
            if large && factors.len() < 3 {
                factors.push(public_why_factor(
                    "published.why.large_review",
                    "Review was large and risk-prioritized, so low-priority notes were summarized only.",
                ));
            }
        }
    }
    factors.truncate(3);
    factors
}

fn priority_findings(analysis: &ReviewAnalysis) -> Vec<&ReviewFinding> {
    let mut findings = analysis
        .findings
        .iter()
        .filter(|finding| validated_actionable_finding(finding))
        .filter(|finding| {
            matches!(
                finding.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.severity
            .sort_key()
            .cmp(&right.severity.sort_key())
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.title.cmp(&right.title))
    });
    findings
}

fn priority_finding_titles(findings: &[ReviewFinding], limit: usize) -> Vec<String> {
    let analysis = ReviewAnalysis {
        summary: String::new(),
        findings: findings.to_vec(),
        test_coverage_note: None,
        privacy_note: None,
        overall_risk: OverallRisk::Low,
    };
    let mut seen = HashSet::new();
    priority_findings(&analysis)
        .into_iter()
        .filter_map(|finding| {
            let title = clean_finding_title(finding);
            let key = normalize_key(&title);
            if key.is_empty() || is_engineish_phrase(&title) || !seen.insert(key) {
                return None;
            }
            Some(title)
        })
        .take(limit)
        .collect()
}

fn multiple_findings_why(findings: &[&ReviewFinding]) -> String {
    let mut areas = findings
        .iter()
        .map(|finding| finding.category.display_lower().replace('_', " "))
        .filter(|area| !area.trim().is_empty())
        .collect::<Vec<_>>();
    areas.sort();
    areas.dedup();
    let areas = areas.into_iter().take(2).collect::<Vec<_>>();
    if areas.is_empty() {
        "Multiple priority findings remain open.".to_string()
    } else {
        format!(
            "Multiple priority findings remain open across {} areas.",
            areas.join("/")
        )
    }
}

fn clean_finding_title(finding: &ReviewFinding) -> String {
    let mut title = finding.title.trim().trim_end_matches(['.', '!', '?']);
    if title.is_empty() {
        title = finding.body.trim().trim_end_matches(['.', '!', '?']);
    }
    let mut title = if title.chars().count() > 140 {
        truncate_at_word(title, 140)
    } else {
        title.to_string()
    };
    if !matches!(title.chars().last(), Some('.') | Some('!') | Some('?')) {
        title.push('.');
    }
    title
}

fn public_why_factor(rule_id: &str, label: impl Into<String>) -> RiskFactor {
    RiskFactor {
        rule_id: rule_id.to_string(),
        label: label.into(),
        score: 1,
        evidence: Vec::new(),
        points: 1,
    }
}

fn large_review_partial(assessment: &MergeRiskAssessment) -> bool {
    assessment.blast_radius.failed_chunks > 0
        || assessment.blast_radius.collapsed_files > 0
        || assessment.blast_radius.too_large_files > 0
        || assessment.blast_radius.skipped_files > 0
        || assessment
            .risk_factors
            .iter()
            .any(|factor| factor.rule_id.contains("large") || factor.rule_id.contains("partial"))
}

fn security_sensitive_modified(assessment: &MergeRiskAssessment) -> bool {
    assessment
        .risk_factors
        .iter()
        .any(|factor| factor.rule_id == "changed_file.auth_security_area")
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

fn sanitize_security_exception_fix(finding: &mut ReviewFinding) {
    if !finding.actionable || !security_sensitive_finding(finding) {
        return;
    }
    let Some(fix) = finding.suggested_fix.as_deref() else {
        return;
    };
    if !broad_security_exception_fix(fix) {
        return;
    }

    let text = format!(
        "{} {} {}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding.title,
        finding.body
    );
    let replacement = if localhost_port_probe_context(&text) {
        "Distinguish expected closed-port failures from suspicious failures: treat connection-refused/closed port as no threat, but treat timeouts, security exceptions, and unexpected I/O errors as unsafe or at least emit explicit telemetry/reason codes."
    } else {
        "Distinguish expected benign probe failures from suspicious failures: preserve the current safe interpretation for known harmless outcomes, but log and handle timeouts, permission/security failures, and unexpected errors conservatively with explicit telemetry/reason codes. Do not blanket allow or blanket block every exception unless evidence proves that behavior is safe."
    };
    finding.suggested_fix = Some(replacement.to_string());
}

fn security_sensitive_finding(finding: &ReviewFinding) -> bool {
    matches!(
        finding.category,
        ReviewCategory::Security | ReviewCategory::Privacy | ReviewCategory::DataIntegrity
    ) || matches!(
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
                | RiskCode::WeakErrorHandling
        )
    ) || contains_any(
        &format!(
            "{} {} {}",
            finding.file_path.as_deref().unwrap_or_default(),
            finding.title,
            finding.body
        ),
        &[
            "security",
            "integrity",
            "instrumentation",
            "tamper",
            "root",
            "jailbreak",
            "signature",
            "certificate",
            "auth",
            "permission",
            "token",
            "runtime guard",
            "compromised",
        ],
    )
}

fn broad_security_exception_fix(fix: &str) -> bool {
    let lower = fix
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let mentions_exception = contains_any(
        &lower,
        &[
            "exception",
            "exceptions",
            "throwable",
            "error",
            "errors",
            "ioexception",
            "securityexception",
        ],
    );
    mentions_exception
        && (contains_any(
            &lower,
            &[
                "return true on exception",
                "return true for exception",
                "return true for every exception",
                "return true on any exception",
                "return true when",
                "return true if",
            ],
        ) || contains_any(
            &lower,
            &[
                "return false on exception",
                "return false for exception",
                "return false for every exception",
                "return false on any exception",
                "return false when",
                "return false if",
            ],
        ) || contains_any(
            &lower,
            &[
                "treat all exceptions as unsafe",
                "treat every exception as unsafe",
                "treat any exception as unsafe",
                "treat all errors as unsafe",
                "treat all exceptions as safe",
                "treat every exception as safe",
                "treat any exception as safe",
                "treat all errors as safe",
            ],
        ))
}

fn localhost_port_probe_context(value: &str) -> bool {
    contains_any(
        value,
        &[
            "localhost",
            "127.0.0.1",
            "loopback",
            "socket",
            "port",
            "connect",
            "connection refused",
            "instrumentation port",
        ],
    )
}

fn dedupe_risk_factors_by_label(factors: &mut Vec<RiskFactor>) {
    let mut seen = HashSet::new();
    factors.retain(|factor| {
        if factor.points <= 0 {
            return true;
        }
        if !factor.rule_id.starts_with("published.why.") && is_engineish_phrase(&factor.label) {
            return true;
        }
        let key = normalize_key(&factor.label);
        key.is_empty() || seen.insert(key)
    });
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

fn is_review_summary_metadata(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    lower.starts_with("reviewed files:")
        || lower.starts_with("reviewed chunks:")
        || lower.starts_with("skipped files:")
        || lower.starts_with("review mode:")
        || lower.starts_with("scope:")
}

fn policy_template_without_finding_evidence(value: &str, findings: &[ReviewFinding]) -> bool {
    let lower = value.to_ascii_lowercase();
    let looks_like_required_action = lower.starts_with("add ")
        || lower.starts_with("fix ")
        || lower.starts_with("handle ")
        || lower.starts_with("request ")
        || lower.starts_with("update ")
        || lower.starts_with("attach ");
    let looks_like_policy_finding = contains_any(
        &lower,
        &[
            "without adding",
            "without updating",
            "without rollback",
            "protected module",
            "owner review",
        ],
    );
    (looks_like_required_action || looks_like_policy_finding) && !has_item_evidence(value, findings)
}

fn generic_placeholder_fix(lower: &str) -> bool {
    let words = lower.split_whitespace().collect::<Vec<_>>();
    let mentions_validated_placeholder = words.contains(&"validated") && words.len() <= 8;
    let generic_failure_acceptance =
        words.contains(&"failures") && words.contains(&"silently") && words.len() <= 10;
    mentions_validated_placeholder || generic_failure_acceptance
}

fn weakens_security_posture(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "disable certificate validation",
            "disable cert validation",
            "skip certificate validation",
            "turn off certificate validation",
            "disable signature verification",
            "skip signature verification",
            "disable auth",
            "bypass auth",
            "remove authorization",
            "log the token",
            "log tokens",
            "return true on exception",
            "return true for every exception",
            "treat all exceptions as safe",
            "ignore security exception",
            "ignore security exceptions",
        ],
    )
}

pub fn is_engineish_phrase(text: &str) -> bool {
    let lower = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|ch: char| ch.is_ascii_punctuation() || ch.is_whitespace())
        .to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "validated",
            "actionable finding",
            "weak error handling finding",
            "changed files exceed",
            "diff bytes exceed",
            "architecture-sensitive",
            "partial or risk-prioritized",
            "no tests are visible",
            "visible in this chunk",
            "test coverage is insufficient",
        ],
    )
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

fn sentence_from_suggested_fix(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let first_sentence = first_sentence(&compact);
    let cleaned = strip_action_filler(first_sentence);
    let mut sentence = if cleaned.chars().count() > 180 {
        truncate_at_word(&cleaned, 180)
    } else {
        cleaned
    };
    if !matches!(sentence.chars().last(), Some('.') | Some('!') | Some('?')) {
        sentence.push('.');
    }
    sentence
}

fn strip_action_filler(value: &str) -> String {
    let trimmed = value.trim();
    for prefix in [
        "Please consider ",
        "please consider ",
        "Consider ",
        "consider ",
        "Maybe ",
        "maybe ",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let mut chars = rest.chars();
            if let Some(first) = chars.next() {
                let mut output = first.to_uppercase().collect::<String>();
                output.push_str(chars.as_str());
                return output;
            }
        }
    }
    trimmed.to_string()
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

fn sentence_fragment(text: &str) -> String {
    text.trim().trim_end_matches(['.', '!', '?']).to_string()
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
        && contains_any(
            &format!(
                "{} {}",
                finding.file_path.as_deref().unwrap_or_default(),
                finding_text(finding)
            ),
            &["payload", "webhook", "body", "log", "logged", "logging"],
        )
}

fn local_data_wipe_finding(finding: &ReviewFinding) -> bool {
    let text = format!(
        "{} {}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding_text(finding)
    );
    finding.risk_code == Some(RiskCode::DataIntegrityRisk)
        && contains_any(
            &text,
            &["wipe", "wiping", "delete", "deletion", "clear local"],
        )
        && contains_any(
            &text,
            &["local data", "user data", "compromised", "security threat"],
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
        formatter::{format_review_markdown_for_mode_with_risk_gate, MarkdownRenderMode},
        risk::{
            format_merge_risk_gate_markdown, BlastRadius, MergeDecision, MergeRiskAssessment,
            RiskEvidence, RiskEvidenceSource, RiskFactor, RiskGateItem,
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
        let analysis = analysis(vec![finding_with_fix(
            Severity::Medium,
            ReviewCategory::Security,
            Some(RiskCode::WeakErrorHandling),
            "MainActivity.kt",
            "Untrusted application warning is easily missed",
            "Replace transient Toast-only untrusted-build warning with a persistent blocking error state.",
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
            finding_with_fix(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::SecretLeak),
                "AndroidManifest.xml",
                "Hardcoded Google Maps API key in android manifest",
                "Move the Google Maps API key to build-time configuration or confirm package/SHA restrictions.",
            ),
            finding_with_fix(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "MainActivity.kt",
                "Untrusted application warning is easily missed",
                "Replace transient Toast-only untrusted-build warning with a persistent blocking error state.",
            ),
            finding_with_fix(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AntiInstrumentationModule.kt",
                "Security check fails silently",
                "Surface or log native security check failures in AntiInstrumentationModule.kt.",
            ),
            finding_with_fix(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AppSignatureVerifier.kt",
                "Overly broad exception handling in signature verification",
                "Log expected signature-verification exceptions without weakening fail-closed behavior.",
            ),
            finding_with_fix(
                Severity::Medium,
                ReviewCategory::Reliability,
                Some(RiskCode::PerformanceRegression),
                "Profile/index.tsx",
                "Logout relies on fixed timeout for WebView cleanup",
                "Add monitoring or fallback behavior for WebView cleanup timeout during logout.",
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
        assert!(labels(&sanitized.required_before_merge).contains(&"Move the Google Maps API key to build-time configuration or confirm package/SHA restrictions.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(&"Replace transient Toast-only untrusted-build warning with a persistent blocking error state.".to_string()));
        assert!(labels(&sanitized.required_before_merge).contains(
            &"Surface or log native security check failures in AntiInstrumentationModule.kt."
                .to_string()
        ));
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
    fn policy_hard_blocker_with_path_evidence_is_removed_for_now() {
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

        assert_eq!(sanitized.decision, MergeDecision::Pass);
        assert!(sanitized.blocking_issues.is_empty());
    }

    #[test]
    fn final_calibration_caps_large_mr_uncertainty_without_priority_findings() {
        let sanitized = sanitize_merge_risk_assessment(
            &analysis(vec![]),
            MergeRiskAssessment {
                score: 49,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![risk_factor(
                    "verification.large_mr.changed_files",
                    "Changed files exceed large MR threshold",
                )],
                blast_radius: BlastRadius {
                    changed_files: 31,
                    ..BlastRadius::default()
                },
            },
        );
        let markdown = format_merge_risk_gate_markdown(&sanitized);

        assert_eq!(sanitized.score, 8);
        assert_eq!(sanitized.decision, MergeDecision::Pass);
        assert!(markdown.contains("Decision: PASS"));
        assert!(markdown.contains("- No priority findings remain open."));
        assert!(markdown.contains(
            "- Review was large and risk-prioritized, so low-priority notes were summarized only."
        ));
        assert!(!markdown.contains("Changed files exceed large MR threshold"));
    }

    #[test]
    fn final_calibration_needs_human_for_medium_findings_with_score_42() {
        let findings = (0..6)
            .map(|index| {
                finding(
                    Severity::Medium,
                    ReviewCategory::Reliability,
                    Some(RiskCode::WeakErrorHandling),
                    &format!("src/file{index}.rs"),
                    &format!("Medium finding {index}"),
                )
            })
            .collect::<Vec<_>>();
        let sanitized = sanitize_merge_risk_assessment(
            &analysis(findings),
            MergeRiskAssessment {
                score: 42,
                decision: MergeDecision::Pass,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert_eq!(sanitized.score, 42);
        assert_eq!(sanitized.decision, MergeDecision::NeedsHuman);
    }

    #[test]
    fn final_calibration_blocks_for_critical_finding() {
        let sanitized = sanitize_merge_risk_assessment(
            &analysis(vec![finding(
                Severity::Critical,
                ReviewCategory::Security,
                Some(RiskCode::SqlInjection),
                "src/paymentClient.ts",
                "SQL injection in payment lookup",
            )]),
            MergeRiskAssessment {
                score: 35,
                decision: MergeDecision::Pass,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );

        assert_eq!(sanitized.decision, MergeDecision::Blocked);
        assert!(!sanitized.blocking_issues.is_empty());
    }

    #[test]
    fn published_summary_aligns_open_count_score_decision_and_overall_risk() {
        let report = sanitize_review_report(ReviewReport {
            analysis: ReviewAnalysis {
                overall_risk: OverallRisk::High,
                ..analysis(vec![finding(
                    Severity::Low,
                    ReviewCategory::Reliability,
                    None,
                    "src/lib.rs",
                    "Low-priority cleanup remains",
                )])
            },
            risk_assessment: Some(MergeRiskAssessment {
                score: 49,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![
                    risk_factor("finding.severity.low", "Validated low actionable finding"),
                    risk_factor(
                        "verification.large_mr.changed_files",
                        "Changed files exceed large MR threshold",
                    ),
                    risk_factor(
                        "verification.gitlab.partial_diff",
                        "GitLab collapsed or too-large files are present",
                    ),
                ],
                blast_radius: BlastRadius {
                    changed_files: 31,
                    skipped_files: 3,
                    ..BlastRadius::default()
                },
            }),
        });
        let assessment = report.risk_assessment.as_ref().unwrap();
        let markdown = format_review_markdown_for_mode_with_risk_gate(
            &report.analysis,
            MarkdownRenderMode::Publish,
            false,
            Some(assessment),
        );

        assert!(markdown.contains("Open priority findings: 0"));
        assert!(markdown.contains("Risk Score: 20/100"));
        assert!(markdown.contains("Decision: PASS"));
        assert!(markdown.contains("## Overall Risk\n\nLow"));
        assert!(!markdown.contains("Decision: NEEDS HUMAN"));
        assert!(!markdown.contains("## Overall Risk\n\nHigh"));
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

    #[test]
    fn broad_security_exception_fix_is_rewritten_with_exception_specific_nuance() {
        let mut finding = finding_with_fix(
            Severity::Medium,
            ReviewCategory::Security,
            Some(RiskCode::WeakErrorHandling),
            "RuntimeSecurityGuard.kt",
            "Runtime instrumentation port checks treat socket exceptions too broadly",
            "Return true on exception.",
        );
        finding.body =
            "A localhost socket probe treats any IOException from the port check as compromised."
                .to_string();

        let report = sanitize_review_report(ReviewReport {
            analysis: analysis(vec![finding]),
            risk_assessment: None,
        });
        let fix = report.analysis.findings[0]
            .suggested_fix
            .as_deref()
            .unwrap();

        assert!(fix.contains("connection-refused/closed port as no threat"));
        assert!(fix.contains("timeouts, security exceptions, and unexpected I/O errors"));
        assert!(fix.contains("telemetry/reason codes"));
        assert!(!fix.contains("Return true on exception"));
        assert!(!fix.contains("every exception"));
    }

    #[test]
    fn generic_why_lines_are_replaced_with_finding_titles_in_rendered_gate() {
        let analysis = analysis(vec![
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "RuntimeSecurityGuard.kt",
                "Runtime instrumentation port checks treat unexpected socket failures as safe",
            ),
            finding(
                Severity::Medium,
                ReviewCategory::Security,
                Some(RiskCode::WeakErrorHandling),
                "AppSignatureVerifier.kt",
                "Debug signature trust can be enabled outside debug builds",
            ),
        ]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 48,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![
                    risk_factor(
                        "finding.severity.medium",
                        "Validated medium actionable finding",
                    ),
                    risk_factor("finding.weak_error_handling", "Weak error handling finding"),
                ],
                blast_radius: BlastRadius::default(),
            },
        );
        let markdown = format_merge_risk_gate_markdown(&sanitized);

        assert!(
            markdown.contains("- Multiple priority findings remain open across security areas.")
        );
        assert!(markdown.contains("- Review touched high-risk code paths."));
        assert!(!markdown.contains("Validated medium actionable finding"));
        assert!(!markdown.contains("Weak error handling finding"));
        assert!(
            markdown
                .split("Why:\n")
                .nth(1)
                .unwrap()
                .matches("\n- ")
                .count()
                <= 3
        );
    }

    #[test]
    fn one_priority_finding_creates_finding_specific_why() {
        let analysis = analysis(vec![finding(
            Severity::Medium,
            ReviewCategory::Reliability,
            Some(RiskCode::WeakErrorHandling),
            "src/upload.rs",
            "Upload failure path drops retry errors",
        )]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 42,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![risk_factor(
                    "finding.severity.medium",
                    "Validated medium actionable finding",
                )],
                blast_radius: BlastRadius::default(),
            },
        );
        let markdown = format_merge_risk_gate_markdown(&sanitized);

        assert!(markdown.contains("- Upload failure path drops retry errors remains open."));
        assert!(!markdown.contains("Validated medium actionable finding"));
        assert!(!markdown.contains("Weak error handling finding"));
    }

    #[test]
    fn required_action_rewrites_security_weakening_fix() {
        let analysis = analysis(vec![finding_with_fix(
            Severity::High,
            ReviewCategory::Security,
            Some(RiskCode::MissingAuthorizationCheck),
            "src/auth/session.rs",
            "Admin route misses authorization check",
            "Disable auth for this route until clients are migrated.",
        )]);
        let sanitized = sanitize_merge_risk_assessment(
            &analysis,
            MergeRiskAssessment {
                score: 80,
                decision: MergeDecision::NeedsHuman,
                blocking_issues: vec![],
                required_before_merge: vec![],
                risk_factors: vec![],
                blast_radius: BlastRadius::default(),
            },
        );
        let labels = labels(&sanitized.required_before_merge);

        assert!(labels
            .iter()
            .any(|label| label.contains("Admin route misses authorization check")));
        assert!(labels
            .iter()
            .any(|label| label.contains("preserving the existing security posture")));
        assert!(!labels.iter().any(|label| label.contains("Disable auth")));
    }

    #[test]
    fn engineish_phrase_filter_catches_public_leak_patterns() {
        for phrase in [
            "Validated medium actionable finding",
            "Weak error handling finding",
            "Changed files exceed large MR threshold",
            "Architecture-sensitive auth or security area touched",
            "No tests are visible in this chunk",
            "Test coverage is insufficient",
        ] {
            assert!(super::is_engineish_phrase(phrase), "{phrase}");
        }
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
        finding_with_optional_fix(severity, category, risk_code, file_path, title, None)
    }

    fn finding_with_fix(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        file_path: &str,
        title: &str,
        suggested_fix: &str,
    ) -> ReviewFinding {
        finding_with_optional_fix(
            severity,
            category,
            risk_code,
            file_path,
            title,
            Some(suggested_fix),
        )
    }

    fn finding_with_optional_fix(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        file_path: &str,
        title: &str,
        suggested_fix: Option<&str>,
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
            suggested_fix: suggested_fix.map(str::to_string),
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

    fn risk_factor(rule_id: &str, label: &str) -> RiskFactor {
        RiskFactor {
            rule_id: rule_id.to_string(),
            label: label.to_string(),
            score: 8,
            evidence: vec![evidence("RuntimeSecurityGuard.kt", rule_id)],
            points: 8,
        }
    }

    fn labels(items: &[RiskGateItem]) -> Vec<String> {
        items.iter().map(|item| item.label.clone()).collect()
    }
}
