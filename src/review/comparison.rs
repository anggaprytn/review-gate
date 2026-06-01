use crate::{
    counters::emoji_enabled,
    error::Result,
    storage::{LatestReviewRun, Storage, StoredPreviousFinding, StoredVerificationStatus},
    verify::VerificationStatus,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewComparison {
    pub previous_run_id: Option<String>,
    pub current_run_id: String,
    pub new_findings: usize,
    pub still_detected: usize,
    pub not_detected: usize,
    pub verified_fixed: usize,
    pub needs_verification: usize,
    pub previous_total_actionable: usize,
    pub current_total_actionable: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingDeltaStatus {
    New,
    StillDetected,
    NotDetected,
    PossiblyResolvedNeedsVerification,
    VerifiedFixed,
    NeedsVerification,
}

impl ReviewComparison {
    pub fn possibly_resolved_needs_verification(&self) -> usize {
        self.not_detected
    }
}

pub fn compare_current_run_with_previous(
    storage: &Storage,
    project_path: &str,
    mr_iid: u64,
    current_run_id: &str,
) -> Result<ReviewComparison> {
    let current_findings = storage.comparison_findings_for_run(current_run_id)?;
    let Some(previous_run) =
        storage.previous_completed_published_review_run(project_path, mr_iid, current_run_id)?
    else {
        return Ok(ReviewComparison {
            previous_run_id: None,
            current_run_id: current_run_id.to_string(),
            new_findings: 0,
            still_detected: 0,
            not_detected: 0,
            verified_fixed: 0,
            needs_verification: 0,
            previous_total_actionable: 0,
            current_total_actionable: current_findings.len(),
        });
    };

    let previous_findings = storage.comparison_findings_for_run(&previous_run.id)?;
    let verification_statuses =
        storage.latest_verification_statuses(&previous_run.project_path, previous_run.mr_iid)?;

    Ok(compare_findings(
        current_run_id,
        Some(&previous_run),
        &previous_findings,
        &current_findings,
        &verification_statuses,
    ))
}

pub fn compare_findings(
    current_run_id: &str,
    previous_run: Option<&LatestReviewRun>,
    previous_findings: &[StoredPreviousFinding],
    current_findings: &[StoredPreviousFinding],
    verification_statuses: &[StoredVerificationStatus],
) -> ReviewComparison {
    let previous_priority = previous_findings
        .iter()
        .filter(|finding| is_priority_finding(finding))
        .cloned()
        .collect::<Vec<_>>();
    let current_priority = current_findings
        .iter()
        .filter(|finding| is_priority_finding(finding))
        .cloned()
        .collect::<Vec<_>>();

    if previous_run.is_none() {
        return ReviewComparison {
            previous_run_id: None,
            current_run_id: current_run_id.to_string(),
            new_findings: 0,
            still_detected: 0,
            not_detected: 0,
            verified_fixed: 0,
            needs_verification: 0,
            previous_total_actionable: 0,
            current_total_actionable: current_priority.len(),
        };
    }

    let current_index = FindingKeyIndex::from_findings(&current_priority);
    let previous_index = FindingKeyIndex::from_findings(&previous_priority);
    let latest_status_by_finding = latest_status_map(verification_statuses);

    let mut still_detected = 0;
    let mut not_detected = 0;
    let mut verified_fixed = 0;
    let mut needs_verification = 0;

    for previous in &previous_priority {
        if current_index.contains_finding(previous) {
            still_detected += 1;
            continue;
        }

        match latest_status_by_finding.get(previous.id.as_str()).copied() {
            Some(VerificationStatus::Fixed) => verified_fixed += 1,
            _ => {
                not_detected += 1;
                needs_verification += 1;
            }
        }
    }

    let new_findings = current_priority
        .iter()
        .filter(|finding| !previous_index.contains_finding(finding))
        .count();

    ReviewComparison {
        previous_run_id: previous_run.map(|run| run.id.clone()),
        current_run_id: current_run_id.to_string(),
        new_findings,
        still_detected,
        not_detected,
        verified_fixed,
        needs_verification,
        previous_total_actionable: previous_priority.len(),
        current_total_actionable: current_priority.len(),
    }
}

pub fn format_comparison_markdown(comparison: &ReviewComparison, emoji: bool) -> String {
    let mut output = String::new();
    output.push_str("## Change Since Previous Published Review\n\n");
    let Some(previous_run_id) = comparison.previous_run_id.as_deref() else {
        output.push_str("No previous published ReviewGate run found for this MR.\n");
        return output;
    };

    output.push_str(&format!("Compared with: `{previous_run_id}`\n\n"));
    output.push_str("Current review:\n");
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::New, emoji),
        comparison.new_findings
    ));
    output.push_str(&format!(
        "- {}: {}\n\n",
        comparison_label(FindingDeltaStatus::StillDetected, emoji),
        comparison.still_detected
    ));
    output.push_str("Previous review:\n");
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::PossiblyResolvedNeedsVerification, emoji),
        comparison.possibly_resolved_needs_verification()
    ));
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::VerifiedFixed, emoji),
        comparison.verified_fixed
    ));
    output.push_str(
        "\nNote: \"No longer detected\" is not counted as fixed until `reviewgate verify` confirms it.\n",
    );
    output
}

pub fn format_review_status_markdown(comparison: &ReviewComparison) -> String {
    format!(
        "## Review Status\n\nCurrent open priority findings: {}\nPreviously detected priority findings still present: {}\nNo longer detected, needs verification: {}\nVerified fixed: {}\n",
        comparison.current_total_actionable,
        comparison.still_detected,
        comparison.possibly_resolved_needs_verification(),
        comparison.verified_fixed
    )
}

pub fn format_comparison_terminal(comparison: &ReviewComparison, emoji: bool) -> String {
    let mut output = String::new();
    let Some(previous_run_id) = comparison.previous_run_id.as_deref() else {
        output
            .push_str("Change since previous published review: no previous published run found\n");
        return output;
    };

    output.push_str("Change since previous published review:\n");
    output.push_str(&format!("Compared with: {previous_run_id}\n"));
    output.push_str("Current review:\n");
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::New, emoji),
        comparison.new_findings
    ));
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::StillDetected, emoji),
        comparison.still_detected
    ));
    output.push_str("Previous review:\n");
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::PossiblyResolvedNeedsVerification, emoji),
        comparison.possibly_resolved_needs_verification()
    ));
    output.push_str(&format!(
        "- {}: {}\n",
        comparison_label(FindingDeltaStatus::VerifiedFixed, emoji),
        comparison.verified_fixed
    ));
    output.push_str(
        "Note: \"No longer detected\" is not counted as fixed until reviewgate verify confirms it.\n",
    );
    output
}

pub fn format_comparison_terminal_default(comparison: &ReviewComparison) -> String {
    format_comparison_terminal(comparison, emoji_enabled())
}

pub fn insert_comparison_section(markdown: &str, comparison: &ReviewComparison) -> String {
    insert_comparison_section_with_emoji(markdown, comparison, emoji_enabled())
}

pub fn insert_comparison_section_with_emoji(
    markdown: &str,
    comparison: &ReviewComparison,
    emoji: bool,
) -> String {
    let section = format_comparison_markdown(comparison, emoji);
    if markdown.contains("## Change Since Previous Review")
        || markdown.contains("## Change Since Previous Published Review")
    {
        return markdown.to_string();
    }
    if markdown.contains("## Review Status") {
        return markdown.to_string();
    }
    if let Some((before, after)) = markdown.split_once("\n## Summary\n\n") {
        return format!("{before}\n{section}\n## Summary\n\n{after}");
    }
    format!("{markdown}\n{section}")
}

fn latest_status_map(statuses: &[StoredVerificationStatus]) -> HashMap<&str, VerificationStatus> {
    let mut latest = HashMap::new();
    for status in statuses {
        latest
            .entry(status.previous_finding_id.as_str())
            .or_insert_with(|| VerificationStatus::parse(&status.status));
    }
    latest
}

fn is_priority_finding(finding: &StoredPreviousFinding) -> bool {
    finding.actionable
        && matches!(
            finding.severity.trim().to_ascii_uppercase().as_str(),
            "CRITICAL" | "HIGH" | "MEDIUM"
        )
}

fn comparison_label(status: FindingDeltaStatus, emoji: bool) -> String {
    let (icon, label) = match status {
        FindingDeltaStatus::New => ("🆕", "New priority findings"),
        FindingDeltaStatus::StillDetected => {
            ("⚠️", "Previously detected priority findings still present")
        }
        FindingDeltaStatus::NotDetected => ("🟣", "No longer detected"),
        FindingDeltaStatus::PossiblyResolvedNeedsVerification => {
            ("🟣", "No longer detected, needs verification")
        }
        FindingDeltaStatus::VerifiedFixed => ("✅", "Verified fixed"),
        FindingDeltaStatus::NeedsVerification => ("❓", "Needs verification"),
    };
    if emoji {
        format!("{icon} {label}")
    } else {
        label.to_string()
    }
}

#[derive(Debug, Default)]
struct FindingKeyIndex {
    fingerprints: HashSet<String>,
    positions: HashSet<String>,
    semantics: HashSet<String>,
}

impl FindingKeyIndex {
    fn from_findings(findings: &[StoredPreviousFinding]) -> Self {
        let mut index = Self::default();
        for finding in findings {
            for key in finding_keys(finding) {
                match key {
                    FindingKey::Fingerprint(value) => {
                        index.fingerprints.insert(value);
                    }
                    FindingKey::Position(value) => {
                        index.positions.insert(value);
                    }
                    FindingKey::Semantic(value) => {
                        index.semantics.insert(value);
                    }
                }
            }
        }
        index
    }

    fn contains_finding(&self, finding: &StoredPreviousFinding) -> bool {
        finding_keys(finding).into_iter().any(|key| match key {
            FindingKey::Fingerprint(value) => self.fingerprints.contains(&value),
            FindingKey::Position(value) => self.positions.contains(&value),
            FindingKey::Semantic(value) => self.semantics.contains(&value),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FindingKey {
    Fingerprint(String),
    Position(String),
    Semantic(String),
}

fn finding_keys(finding: &StoredPreviousFinding) -> Vec<FindingKey> {
    let mut keys = Vec::new();
    if let Some(fingerprint) = finding
        .fingerprint_v2
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        keys.push(FindingKey::Fingerprint(fingerprint.to_string()));
    }
    if let Some(position) = position_key(finding) {
        keys.push(FindingKey::Position(position));
    }
    if let Some(semantic) = semantic_key(finding) {
        keys.push(FindingKey::Semantic(semantic));
    }
    keys
}

fn position_key(finding: &StoredPreviousFinding) -> Option<String> {
    let file_path = normalized_path(finding.file_path.as_deref())?;
    if finding.old_line.is_none() && finding.new_line.is_none() {
        return None;
    }
    Some(format!(
        "pos|{}|{}|{}|{}|{}|{}",
        file_path,
        optional_line(finding.old_line),
        optional_line(finding.new_line),
        normalize_token(&finding.severity),
        normalize_token(&finding.category),
        normalize_optional_token(finding.risk_code.as_deref()),
    ))
}

fn semantic_key(finding: &StoredPreviousFinding) -> Option<String> {
    let title = normalize_title(&finding.title);
    if title.is_empty() {
        return None;
    }
    Some(format!(
        "sem|{}|{}|{}|{}|{}",
        normalized_path(finding.file_path.as_deref()).unwrap_or_default(),
        normalize_token(&finding.severity),
        normalize_token(&finding.category),
        normalize_optional_token(finding.risk_code.as_deref()),
        title,
    ))
}

fn normalized_path(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.replace('\\', "/"))
}

fn optional_line(value: Option<u32>) -> String {
    value
        .map(|line| line.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn normalize_optional_token(value: Option<&str>) -> String {
    value.map(normalize_token).unwrap_or_default()
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_title(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{
        compare_findings, format_comparison_markdown, format_comparison_terminal,
        format_review_status_markdown, insert_comparison_section_with_emoji, ReviewComparison,
    };
    use crate::{
        storage::{LatestReviewRun, StoredPreviousFinding, StoredVerificationStatus},
        verify::VerificationStatus,
    };

    #[test]
    fn no_previous_run_returns_clean_comparison() {
        let current = vec![finding("current-1", Some("fp"), Some(10), "A")];

        let comparison = compare_findings("current-run", None, &[], &current, &[]);

        assert_eq!(comparison.previous_run_id, None);
        assert_eq!(comparison.current_run_id, "current-run");
        assert_eq!(comparison.current_total_actionable, 1);
        assert_eq!(comparison.new_findings, 0);
        assert_eq!(
            format_comparison_terminal(&comparison, false),
            "Change since previous published review: no previous published run found\n"
        );
        assert_eq!(
            format_comparison_markdown(&comparison, false),
            "## Change Since Previous Published Review\n\nNo previous published ReviewGate run found for this MR.\n"
        );
    }

    #[test]
    fn current_finding_matches_previous_by_fingerprint() {
        let previous = vec![finding("prev-1", Some("fp-stable"), Some(10), "Old")];
        let current = vec![finding("current-1", Some("fp-stable"), Some(20), "Changed")];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &current, &[]);

        assert_eq!(comparison.still_detected, 1);
        assert_eq!(comparison.new_findings, 0);
    }

    #[test]
    fn current_finding_matches_previous_by_position_signature() {
        let previous = vec![finding("prev-1", Some("old-fp"), Some(42), "Old title")];
        let current = vec![finding("current-1", Some("new-fp"), Some(42), "New title")];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &current, &[]);

        assert_eq!(comparison.still_detected, 1);
        assert_eq!(comparison.new_findings, 0);
    }

    #[test]
    fn current_finding_matches_previous_by_fallback_semantic_key() {
        let mut previous = finding("prev-1", None, None, "Missing timeout");
        previous.file_path = Some("src/client.rs".to_string());
        let mut current = finding("current-1", None, None, "  missing   timeout ");
        current.file_path = Some("src/client.rs".to_string());

        let comparison =
            compare_findings("current-run", Some(&run()), &[previous], &[current], &[]);

        assert_eq!(comparison.still_detected, 1);
        assert_eq!(comparison.new_findings, 0);
    }

    #[test]
    fn new_still_and_not_detected_counts_are_reported() {
        let previous = vec![
            finding("prev-still", Some("fp-still"), Some(10), "Still"),
            finding("prev-gone", Some("fp-gone"), Some(20), "Gone"),
        ];
        let current = vec![
            finding("current-still", Some("fp-still"), Some(10), "Still"),
            finding("current-new", Some("fp-new"), Some(30), "New"),
        ];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &current, &[]);

        assert_eq!(comparison.new_findings, 1);
        assert_eq!(comparison.still_detected, 1);
        assert_eq!(comparison.not_detected, 1);
        assert_eq!(comparison.needs_verification, 1);
    }

    #[test]
    fn comparison_counts_priority_findings_only() {
        let mut previous_low = finding("prev-low", Some("fp-low"), Some(40), "Low");
        previous_low.severity = "LOW".to_string();
        let mut current_low = finding("current-low", Some("fp-low-new"), Some(41), "Low new");
        current_low.severity = "LOW".to_string();
        let mut current_note = finding("current-note", Some("fp-note"), Some(42), "Note");
        current_note.severity = "NOTE".to_string();

        let previous = vec![
            finding("prev-high", Some("fp-high"), Some(10), "High"),
            previous_low,
        ];
        let current = vec![
            finding("current-high", Some("fp-high-new"), Some(20), "New High"),
            current_low,
            current_note,
        ];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &current, &[]);

        assert_eq!(comparison.new_findings, 1);
        assert_eq!(comparison.not_detected, 1);
        assert_eq!(comparison.previous_total_actionable, 1);
        assert_eq!(comparison.current_total_actionable, 1);
    }

    #[test]
    fn verified_fixed_is_counted_from_latest_verification_result() {
        let previous = vec![finding("prev-fixed", Some("fp-fixed"), Some(10), "Fixed")];
        let statuses = vec![status("prev-fixed", VerificationStatus::Fixed)];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &[], &statuses);

        assert_eq!(comparison.verified_fixed, 1);
        assert_eq!(comparison.not_detected, 0);
        assert_eq!(comparison.needs_verification, 0);
    }

    #[test]
    fn absent_without_verified_fixed_needs_verification() {
        let previous = vec![finding("prev-gone", Some("fp-gone"), Some(10), "Gone")];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &[], &[]);

        assert_eq!(comparison.not_detected, 1);
        assert_eq!(comparison.needs_verification, 1);
        assert_eq!(comparison.verified_fixed, 0);
    }

    #[test]
    fn still_open_verification_disagreement_is_needs_verification() {
        let previous = vec![finding("prev-open", Some("fp-open"), Some(10), "Open")];
        let statuses = vec![status("prev-open", VerificationStatus::StillOpen)];

        let comparison = compare_findings("current-run", Some(&run()), &previous, &[], &statuses);

        assert_eq!(comparison.not_detected, 1);
        assert_eq!(comparison.needs_verification, 1);
        assert_eq!(comparison.verified_fixed, 0);
    }

    #[test]
    fn markdown_comparison_table_with_emoji() {
        let markdown = format_comparison_markdown(&comparison(), true);

        assert!(markdown.contains("## Change Since Previous Published Review"));
        assert!(markdown.contains("Compared with: `previous-run`"));
        assert!(markdown.contains("Current review:"));
        assert!(markdown.contains("- 🆕 New priority findings: 4"));
        assert!(markdown.contains("- ⚠️ Previously detected priority findings still present: 12"));
        assert!(markdown.contains("Previous review:"));
        assert!(markdown.contains("- 🟣 No longer detected, needs verification: 3"));
        assert!(markdown.contains("- ✅ Verified fixed: 2"));
        assert!(!markdown.contains("| Status | Count |"));
        assert!(!markdown.contains("| ❓ Needs verification |"));
        assert!(markdown.contains("not counted as fixed until `reviewgate verify` confirms it."));
        assert!(!markdown.contains('━'));
        assert!(!markdown.contains('─'));
    }

    #[test]
    fn markdown_comparison_collapses_absent_unverified_findings_without_double_count_row() {
        let mut comparison = comparison();
        comparison.not_detected = 15;
        comparison.needs_verification = 15;

        let markdown = format_comparison_markdown(&comparison, true);

        assert!(markdown.contains("- 🟣 No longer detected, needs verification: 15"));
        assert!(!markdown.contains("| 🟣 Not detected in this review |"));
        assert!(!markdown.contains("| ❓ Needs verification |"));
        assert!(!markdown.contains("No longer detected, needs verification: 30"));
    }

    #[test]
    fn markdown_comparison_keeps_verified_fixed_separate_from_possibly_resolved() {
        let mut comparison = comparison();
        comparison.not_detected = 15;
        comparison.needs_verification = 15;
        comparison.verified_fixed = 4;

        let markdown = format_comparison_markdown(&comparison, true);

        assert!(markdown.contains("- 🟣 No longer detected, needs verification: 15"));
        assert!(markdown.contains("- ✅ Verified fixed: 4"));
    }

    #[test]
    fn markdown_comparison_table_without_emoji() {
        let markdown = format_comparison_markdown(&comparison(), false);

        assert!(markdown.contains("- New priority findings: 4"));
        assert!(markdown.contains("- Previously detected priority findings still present: 12"));
        assert!(markdown.contains("- No longer detected, needs verification: 3"));
        assert!(!markdown.contains("🆕"));
    }

    #[test]
    fn terminal_comparison_formatting() {
        let output = format_comparison_terminal(&comparison(), true);

        assert!(output.contains("Change since previous published review:"));
        assert!(output.contains("Compared with: previous-run"));
        assert!(output.contains("- ⚠️ Previously detected priority findings still present: 12"));
        assert!(output.contains("- 🟣 No longer detected, needs verification: 3"));
        assert!(!output.contains("Needs verification:"));
    }

    #[test]
    fn review_status_headline_formats_progress_counts() {
        let markdown = format_review_status_markdown(&comparison());

        assert!(markdown.contains("## Review Status"));
        assert!(markdown.contains("Current open priority findings: 16"));
        assert!(markdown.contains("Previously detected priority findings still present: 12"));
        assert!(markdown.contains("No longer detected, needs verification: 3"));
        assert!(markdown.contains("Verified fixed: 2"));
    }

    #[test]
    fn comparison_included_in_review_markdown() {
        let markdown =
            "# ReviewGate AI Code Review\n\n## Finding Summary\n\nx\n\n## Summary\n\nbody\n";

        let output = insert_comparison_section_with_emoji(markdown, &comparison(), false);

        assert!(
            output.contains("## Finding Summary\n\nx\n\n## Change Since Previous Published Review")
        );
        assert!(!output.contains("## Review Status"));
        assert!(output.contains("\n## Summary\n\nbody"));
    }

    #[test]
    fn comparison_included_in_large_review_markdown() {
        let markdown = "# ReviewGate AI Code Review\n\n## Large MR Review Plan\n\nplan\n\n## Finding Summary\n\nx\n\n## Summary\n\nbody\n";

        let output = insert_comparison_section_with_emoji(markdown, &comparison(), false);

        assert!(output.contains("## Large MR Review Plan"));
        assert!(
            output.contains("## Finding Summary\n\nx\n\n## Change Since Previous Published Review")
        );
    }

    fn comparison() -> ReviewComparison {
        ReviewComparison {
            previous_run_id: Some("previous-run".to_string()),
            current_run_id: "current-run".to_string(),
            new_findings: 4,
            still_detected: 12,
            not_detected: 3,
            verified_fixed: 2,
            needs_verification: 3,
            previous_total_actionable: 17,
            current_total_actionable: 16,
        }
    }

    fn run() -> LatestReviewRun {
        LatestReviewRun {
            id: "previous-run".to_string(),
            project_path: "group/repo".to_string(),
            mr_iid: 59,
            mr_url: "https://gitlab.company.local/group/repo/-/merge_requests/59".to_string(),
            head_sha: "head".to_string(),
            model_provider: "codex_cli".to_string(),
            model_name: "gpt-5.5".to_string(),
            completed_at: Some("001".to_string()),
        }
    }

    fn status(finding_id: &str, status: VerificationStatus) -> StoredVerificationStatus {
        StoredVerificationStatus {
            previous_finding_id: finding_id.to_string(),
            status: status.display_lower().to_string(),
        }
    }

    fn finding(
        id: &str,
        fingerprint_v2: Option<&str>,
        new_line: Option<u32>,
        title: &str,
    ) -> StoredPreviousFinding {
        StoredPreviousFinding {
            id: id.to_string(),
            severity: "HIGH".to_string(),
            effort: "quick".to_string(),
            category: "correctness".to_string(),
            risk_code: Some("missing_timeout".to_string()),
            anchor_id: None,
            file_path: Some("src/client.rs".to_string()),
            old_line: None,
            new_line,
            title: title.to_string(),
            body: "Body".to_string(),
            suggested_fix: Some("Fix".to_string()),
            actionable: true,
            fingerprint_v2: fingerprint_v2.map(str::to_string),
        }
    }
}
