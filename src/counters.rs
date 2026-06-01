use crate::{
    review::types::{ReviewAnalysis, ReviewFinding, Severity},
    storage::StoredReviewFinding,
    verify::{VerificationOutcome, VerificationResult, VerificationStatus},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingCounters {
    pub total: usize,
    pub actionable: usize,
    pub open_actionable: usize,
    pub open_priority: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub note: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationCounters {
    pub total: usize,
    pub fixed: usize,
    pub still_open: usize,
    pub skipped: usize,
    pub needs_manual_confirmation: usize,
}

pub fn count_findings_from_analysis(analysis: &ReviewAnalysis) -> FindingCounters {
    count_review_findings(&analysis.findings)
}

pub fn count_review_findings(findings: &[ReviewFinding]) -> FindingCounters {
    let mut counters = FindingCounters::default();
    for finding in findings {
        counters.total += 1;
        if finding.actionable {
            counters.actionable += 1;
            if finding.severity != Severity::Note {
                counters.open_actionable += 1;
            }
            if is_priority_severity(finding.severity) {
                counters.open_priority += 1;
            }
        }
        increment_severity(&mut counters, finding.severity);
    }
    counters
}

pub fn count_stored_findings(findings: &[StoredReviewFinding]) -> FindingCounters {
    let mut counters = FindingCounters::default();
    for finding in findings {
        counters.total += 1;
        let severity = parse_severity(&finding.severity);
        if finding.actionable {
            counters.actionable += 1;
            if matches!(
                severity,
                Some(Severity::Critical | Severity::High | Severity::Medium | Severity::Low)
            ) {
                counters.open_actionable += 1;
            }
            if matches!(
                severity,
                Some(Severity::Critical | Severity::High | Severity::Medium)
            ) {
                counters.open_priority += 1;
            }
        }
        if let Some(severity) = severity {
            increment_severity(&mut counters, severity);
        }
    }
    counters
}

pub fn count_verification_results(outcome: &VerificationOutcome) -> VerificationCounters {
    count_verification_result_slice(&outcome.results)
}

pub fn count_verification_result_slice(results: &[VerificationResult]) -> VerificationCounters {
    let mut counters = VerificationCounters::default();
    for result in results {
        counters.total += 1;
        increment_verification_status(&mut counters, result.status);
    }
    counters
}

pub fn count_verification_status_strings<'a>(
    statuses: impl IntoIterator<Item = &'a str>,
) -> VerificationCounters {
    let mut counters = VerificationCounters::default();
    for status in statuses {
        counters.total += 1;
        increment_verification_status(&mut counters, VerificationStatus::parse(status));
    }
    counters
}

pub fn format_finding_counters_terminal(counters: &FindingCounters, emoji: bool) -> String {
    format!(
        "Finding counters:\nOpen priority findings: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n",
        counters.open_priority,
        finding_label(Severity::Critical, emoji),
        counters.critical,
        finding_label(Severity::High, emoji),
        counters.high,
        finding_label(Severity::Medium, emoji),
        counters.medium,
        low_priority_label(emoji),
        counters.low,
        finding_label(Severity::Note, emoji),
        counters.note,
    )
}

pub fn format_finding_counters_markdown(counters: &FindingCounters, emoji: bool) -> String {
    format!(
        "## Finding Summary\n\nOpen priority findings: {}\n\n| Severity | Count |\n|---|---:|\n| {} | {} |\n| {} | {} |\n| {} | {} |\n\nAdditional:\n- {}: {}\n- {}: {}\n",
        counters.open_priority,
        finding_label(Severity::Critical, emoji),
        counters.critical,
        finding_label(Severity::High, emoji),
        counters.high,
        finding_label(Severity::Medium, emoji),
        counters.medium,
        low_priority_label(emoji),
        counters.low,
        finding_label(Severity::Note, emoji),
        counters.note,
    )
}

pub fn format_finding_summary_markdown(counters: &FindingCounters, emoji: bool) -> String {
    format_finding_counters_markdown(counters, emoji)
}

pub fn format_verification_counters_terminal(
    counters: &VerificationCounters,
    emoji: bool,
) -> String {
    format!(
        "Verification counters:\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n",
        verification_label(VerificationStatus::Fixed, emoji),
        counters.fixed,
        verification_label(VerificationStatus::StillOpen, emoji),
        counters.still_open,
        verification_label(VerificationStatus::Skipped, emoji),
        counters.skipped,
        verification_label(VerificationStatus::NeedsManualConfirmation, emoji),
        counters.needs_manual_confirmation,
    )
}

pub fn format_verification_counters_markdown(
    counters: &VerificationCounters,
    emoji: bool,
) -> String {
    format!(
        "## Verification Summary\n\n| Status | Count |\n|---|---:|\n| {} | {} |\n| {} | {} |\n| {} | {} |\n| {} | {} |\n",
        verification_label(VerificationStatus::Fixed, emoji),
        counters.fixed,
        verification_label(VerificationStatus::StillOpen, emoji),
        counters.still_open,
        verification_label(VerificationStatus::Skipped, emoji),
        counters.skipped,
        verification_label(VerificationStatus::NeedsManualConfirmation, emoji),
        counters.needs_manual_confirmation,
    )
}

pub fn format_verification_summary_markdown(
    counters: &VerificationCounters,
    emoji: bool,
) -> String {
    format_verification_counters_markdown(counters, emoji)
}

pub fn emoji_enabled() -> bool {
    std::env::var("REVIEWGATE_EMOJI")
        .ok()
        .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true)
}

fn increment_severity(counters: &mut FindingCounters, severity: Severity) {
    match severity {
        Severity::Critical => counters.critical += 1,
        Severity::High => counters.high += 1,
        Severity::Medium => counters.medium += 1,
        Severity::Low => counters.low += 1,
        Severity::Note => counters.note += 1,
    }
}

fn is_priority_severity(severity: Severity) -> bool {
    matches!(
        severity,
        Severity::Critical | Severity::High | Severity::Medium
    )
}

fn increment_verification_status(counters: &mut VerificationCounters, status: VerificationStatus) {
    match status {
        VerificationStatus::Fixed => counters.fixed += 1,
        VerificationStatus::StillOpen => counters.still_open += 1,
        VerificationStatus::Skipped => counters.skipped += 1,
        VerificationStatus::NeedsManualConfirmation => counters.needs_manual_confirmation += 1,
    }
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "NOTE" | "INFO" | "INFORMATIONAL" => Some(Severity::Note),
        _ => None,
    }
}

fn finding_label(severity: Severity, emoji: bool) -> String {
    let label = match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Note => "Notes",
    };
    if emoji {
        format!("{} {label}", severity.emoji())
    } else {
        label.to_string()
    }
}

fn low_priority_label(emoji: bool) -> String {
    if emoji {
        "🟢 Low-priority findings".to_string()
    } else {
        "Low-priority findings".to_string()
    }
}

fn verification_label(status: VerificationStatus, emoji: bool) -> String {
    let (icon, label) = match status {
        VerificationStatus::Fixed => ("✅", "Fixed"),
        VerificationStatus::StillOpen => ("⚠️", "Still open"),
        VerificationStatus::Skipped => ("⏭️", "Skipped"),
        VerificationStatus::NeedsManualConfirmation => ("❓", "Needs manual confirmation"),
    };
    if emoji {
        format!("{icon} {label}")
    } else {
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        count_findings_from_analysis, count_stored_findings, count_verification_result_slice,
        count_verification_status_strings, format_finding_counters_markdown,
        format_finding_counters_terminal, format_verification_counters_markdown,
        format_verification_counters_terminal,
    };
    use crate::{
        review::types::{
            Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, Severity,
        },
        storage::{StoredPreviousFinding, StoredReviewFinding},
        verify::{VerificationResult, VerificationStatus},
    };

    #[test]
    fn finding_counter_from_review_analysis_counts_severity_and_actionable() {
        let analysis = ReviewAnalysis {
            summary: "summary".to_string(),
            findings: vec![
                finding(Severity::Critical, true),
                finding(Severity::High, true),
                finding(Severity::Medium, true),
                finding(Severity::Low, true),
                finding(Severity::Note, true),
            ],
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::High,
        };

        let counters = count_findings_from_analysis(&analysis);

        assert_eq!(counters.total, 5);
        assert_eq!(counters.actionable, 5);
        assert_eq!(counters.open_actionable, 4);
        assert_eq!(counters.open_priority, 3);
        assert_eq!(counters.critical, 1);
        assert_eq!(counters.note, 1);
    }

    #[test]
    fn stored_finding_counter_does_not_require_raw_diff_or_llm_payload() {
        let findings = vec![
            stored_finding("HIGH", true),
            stored_finding("NOTE", true),
            stored_finding("LOW", false),
        ];

        let counters = count_stored_findings(&findings);

        assert_eq!(counters.total, 3);
        assert_eq!(counters.actionable, 2);
        assert_eq!(counters.open_actionable, 1);
        assert_eq!(counters.open_priority, 1);
        assert_eq!(counters.high, 1);
        assert_eq!(counters.note, 1);
        assert_eq!(counters.low, 1);
    }

    #[test]
    fn markdown_finding_summary_table_formats_expected_rows() {
        let markdown = format_finding_counters_markdown(
            &super::FindingCounters {
                open_priority: 7,
                critical: 3,
                high: 2,
                medium: 2,
                low: 6,
                note: 21,
                ..super::FindingCounters::default()
            },
            true,
        );

        assert!(markdown.contains("## Finding Summary"));
        assert!(markdown.contains("Open priority findings: 7"));
        assert!(markdown.contains("| 🔴 Critical | 3 |"));
        assert!(markdown.contains("| 🟠 High | 2 |"));
        assert!(markdown.contains("| 🟡 Medium | 2 |"));
        assert!(markdown.contains("Additional:"));
        assert!(markdown.contains("- 🟢 Low-priority findings: 6"));
        assert!(markdown.contains("- 🔵 Notes: 21"));
        assert!(!markdown.contains("Open actionable findings"));
    }

    #[test]
    fn markdown_verification_summary_table_formats_expected_rows() {
        let markdown = format_verification_counters_markdown(
            &super::VerificationCounters {
                still_open: 7,
                ..super::VerificationCounters::default()
            },
            true,
        );

        assert!(markdown.contains("## Verification Summary"));
        assert!(markdown.contains("| ✅ Fixed | 0 |"));
        assert!(markdown.contains("| ⚠️ Still open | 7 |"));
        assert!(markdown.contains("| ⏭️ Skipped | 0 |"));
        assert!(markdown.contains("| ❓ Needs manual confirmation | 0 |"));
    }

    #[test]
    fn terminal_finding_counter_formatting() {
        let output = format_finding_counters_terminal(
            &super::FindingCounters {
                open_priority: 7,
                critical: 3,
                high: 2,
                medium: 2,
                low: 6,
                note: 21,
                ..super::FindingCounters::default()
            },
            true,
        );

        assert!(output.contains("Finding counters:"));
        assert!(output.contains("Open priority findings: 7"));
        assert!(output.contains("🔴 Critical: 3"));
        assert!(output.contains("🟠 High: 2"));
        assert!(output.contains("🟢 Low-priority findings: 6"));
        assert!(output.contains("🔵 Notes: 21"));
        assert!(!output.contains("Open actionable findings"));
    }

    #[test]
    fn terminal_verification_counter_formatting() {
        let output = format_verification_counters_terminal(
            &super::VerificationCounters {
                still_open: 7,
                ..super::VerificationCounters::default()
            },
            true,
        );

        assert!(output.contains("Verification counters:"));
        assert!(output.contains("✅ Fixed: 0"));
        assert!(output.contains("⚠️ Still open: 7"));
        assert!(output.contains("❓ Needs manual confirmation: 0"));
    }

    #[test]
    fn emoji_disabled_formatting_uses_plain_labels() {
        let finding = format_finding_counters_markdown(
            &super::FindingCounters {
                critical: 1,
                ..super::FindingCounters::default()
            },
            false,
        );
        let verification = format_verification_counters_markdown(
            &super::VerificationCounters {
                fixed: 1,
                ..super::VerificationCounters::default()
            },
            false,
        );

        assert!(finding.contains("| Critical | 1 |"));
        assert!(finding.contains("| Severity | Count |\n|---|---:|"));
        assert!(!finding.contains("🔴"));
        assert!(verification.contains("| Fixed | 1 |"));
        assert!(verification.contains("| Status | Count |\n|---|---:|"));
        assert!(!verification.contains("✅"));
    }

    #[test]
    fn verification_counters_map_unknown_status_to_manual_confirmation() {
        let counters = count_verification_status_strings(["fixed", "surprise"]);

        assert_eq!(counters.total, 2);
        assert_eq!(counters.fixed, 1);
        assert_eq!(counters.needs_manual_confirmation, 1);
    }

    #[test]
    fn verification_counter_from_results_counts_statuses() {
        let counters = count_verification_result_slice(&[
            result(VerificationStatus::Fixed),
            result(VerificationStatus::StillOpen),
            result(VerificationStatus::Skipped),
            result(VerificationStatus::NeedsManualConfirmation),
        ]);

        assert_eq!(counters.total, 4);
        assert_eq!(counters.fixed, 1);
        assert_eq!(counters.still_open, 1);
        assert_eq!(counters.skipped, 1);
        assert_eq!(counters.needs_manual_confirmation, 1);
    }

    fn finding(severity: Severity, actionable: bool) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Correctness,
            risk_code: None,
            anchor_id: None,
            file_path: Some("src/example.rs".to_string()),
            line: Some(42),
            title: "title".to_string(),
            body: "body".to_string(),
            suggested_fix: None,
            effort: Effort::Quick,
            actionable,
        }
    }

    fn stored_finding(severity: &str, actionable: bool) -> StoredReviewFinding {
        StoredReviewFinding {
            id: format!("finding-{severity}"),
            severity: severity.to_string(),
            effort: "quick".to_string(),
            category: "correctness".to_string(),
            risk_code: None,
            file_path: Some("src/example.rs".to_string()),
            old_line: None,
            new_line: Some(42),
            title: "title".to_string(),
            body: "body".to_string(),
            suggested_fix: None,
            actionable,
        }
    }

    fn result(status: VerificationStatus) -> VerificationResult {
        VerificationResult {
            previous_finding: StoredPreviousFinding {
                id: "finding-1".to_string(),
                severity: "HIGH".to_string(),
                effort: "quick".to_string(),
                category: "correctness".to_string(),
                risk_code: None,
                anchor_id: None,
                file_path: Some("src/example.rs".to_string()),
                old_line: None,
                new_line: Some(42),
                title: "title".to_string(),
                body: "body".to_string(),
                suggested_fix: None,
                actionable: true,
                fingerprint_v2: None,
            },
            status,
            reason: "reason".to_string(),
            evidence: None,
        }
    }
}
