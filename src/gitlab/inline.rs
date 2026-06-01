use crate::{
    config::InlineConfig,
    error::{Result, ReviewGateError},
    gitlab::{
        types::{CreateMergeRequestDiscussionRequest, GitLabDiscussion},
        url::GitLabMrUrl,
    },
    review::{
        inline::{
            InlineCandidate, InlineEligibilityReason, InlinePublishResult, InlinePublishStatus,
        },
        types::{ReviewFinding, Severity},
    },
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, future::Future};

const INLINE_MARKER_PREFIX: &str = "<!-- reviewgate:inline";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InlinePublishReport {
    pub results: Vec<InlinePublishResult>,
    pub duplicate_warnings: Vec<String>,
}

impl InlinePublishReport {
    pub fn created_count(&self) -> usize {
        self.count_status(InlinePublishStatus::Created)
    }

    pub fn skipped_duplicate_count(&self) -> usize {
        self.count_status(InlinePublishStatus::SkippedDuplicate)
    }

    pub fn failed_count(&self) -> usize {
        self.count_status(InlinePublishStatus::Failed)
    }

    pub fn fallback_count(&self) -> usize {
        self.count_status(InlinePublishStatus::NotEligible)
    }

    pub fn eligible_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status != InlinePublishStatus::NotEligible)
            .count()
    }

    fn count_status(&self, status: InlinePublishStatus) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == status)
            .count()
    }
}

pub async fn publish_inline_comments_with<L, LFut, C, CFut>(
    mr: &GitLabMrUrl,
    candidates: &[InlineCandidate],
    findings: &[ReviewFinding],
    config: &InlineConfig,
    list_discussions: L,
    mut create_discussion: C,
) -> Result<InlinePublishReport>
where
    L: FnOnce() -> LFut,
    LFut: Future<Output = Result<Vec<GitLabDiscussion>>>,
    C: FnMut(CreateMergeRequestDiscussionRequest) -> CFut,
    CFut: Future<Output = Result<GitLabDiscussion>>,
{
    let mut report = InlinePublishReport::default();
    let eligible_count = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .count();

    if eligible_count == 0 {
        for candidate in candidates {
            report
                .results
                .push(not_eligible_result(candidate, candidate.reason));
        }
        return Ok(report);
    }

    let mut existing_fingerprints = if config.dedupe {
        existing_inline_fingerprints(&list_discussions().await?)
    } else {
        HashMap::new()
    };

    for (index, candidate) in candidates.iter().enumerate() {
        let Some(finding) = findings.get(index) else {
            report.results.push(failed_result(
                candidate,
                "malformed review result: finding index was missing".to_string(),
            ));
            continue;
        };

        if !candidate.eligible {
            report
                .results
                .push(not_eligible_result(candidate, candidate.reason));
            continue;
        }

        let Some(position) = candidate.position.clone() else {
            report.results.push(failed_result(
                candidate,
                "eligible inline candidate did not include a GitLab position".to_string(),
            ));
            continue;
        };

        let fingerprint = inline_fingerprint(
            &mr.project_path,
            mr.mr_iid,
            &position.head_sha,
            candidate
                .file_path
                .as_deref()
                .unwrap_or(position.new_path.as_str()),
            position.old_line,
            position.new_line,
            candidate.severity,
            &candidate.title,
        );

        if let Some(count) = existing_fingerprints.get(&fingerprint).copied() {
            if count > 1 {
                report.duplicate_warnings.push(format!(
                    "multiple existing ReviewGate inline notes share fingerprint {fingerprint}"
                ));
            }
            report.results.push(skipped_duplicate_result(candidate));
            continue;
        }

        let body = format_inline_comment_body(mr, finding, &fingerprint, &position.head_sha)?;
        let request = CreateMergeRequestDiscussionRequest { body, position };

        match create_discussion(request).await {
            Ok(discussion) => match created_note_id(&discussion) {
                Some(note_id) => {
                    if config.dedupe {
                        existing_fingerprints.insert(fingerprint, 1);
                    }
                    report.results.push(InlinePublishResult {
                        finding_id: candidate.finding_id.clone(),
                        title: candidate.title.clone(),
                        severity: candidate.severity,
                        file_path: candidate.file_path.clone(),
                        line: candidate.requested_line,
                        status: InlinePublishStatus::Created,
                        discussion_id: Some(discussion.id),
                        note_id: Some(note_id),
                        error: None,
                    });
                }
                None => report.results.push(failed_result(
                    candidate,
                    "malformed discussion response: created discussion did not include a note"
                        .to_string(),
                )),
            },
            Err(err) => report
                .results
                .push(failed_result(candidate, inline_publish_error(&err))),
        }
    }

    Ok(report)
}

pub fn inline_fingerprint(
    project_path: &str,
    mr_iid: u64,
    head_sha: &str,
    file_path: &str,
    old_line: Option<u32>,
    new_line: Option<u32>,
    severity: Severity,
    title: &str,
) -> String {
    let mut hasher = Sha256::new();
    let parts = vec![
        project_path.trim().to_string(),
        mr_iid.to_string(),
        head_sha.trim().to_string(),
        file_path.trim().to_string(),
        old_line.map(|line| line.to_string()).unwrap_or_default(),
        new_line.map(|line| line.to_string()).unwrap_or_default(),
        severity.display_upper().to_string(),
        normalize_title(title),
    ];

    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }

    hex_lower(&hasher.finalize())
}

pub fn inline_marker(project_path: &str, mr_iid: u64, fingerprint: &str, head_sha: &str) -> String {
    format!(
        "<!-- reviewgate:inline project=\"{}\" mr=\"{}\" fingerprint=\"{}\" head_sha=\"{}\" -->",
        escape_marker_attr(project_path),
        mr_iid,
        escape_marker_attr(fingerprint),
        escape_marker_attr(head_sha)
    )
}

pub fn extract_inline_fingerprints_from_note_body(body: &str) -> Vec<String> {
    let marker_regex =
        Regex::new(r#"<!--\s*reviewgate:inline\b[^>]*\bfingerprint="([^"]+)"[^>]*-->"#)
            .expect("inline marker regex compiles");
    marker_regex
        .captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

pub fn existing_inline_fingerprints(discussions: &[GitLabDiscussion]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();

    for discussion in discussions {
        for note in &discussion.notes {
            if note.system || !note.body.contains(INLINE_MARKER_PREFIX) {
                continue;
            }
            for fingerprint in extract_inline_fingerprints_from_note_body(&note.body) {
                *counts.entry(fingerprint).or_insert(0) += 1;
            }
        }
    }

    counts
}

pub fn format_inline_comment_body(
    mr: &GitLabMrUrl,
    finding: &ReviewFinding,
    fingerprint: &str,
    head_sha: &str,
) -> Result<String> {
    let title = blank_fallback(&finding.title, "Untitled finding");
    let body = blank_fallback(&finding.body, "No details returned.");
    let mut output = String::new();

    output.push_str("**ReviewGate: ");
    output.push_str(finding.severity.display_upper());
    output.push_str(" - ");
    output.push_str(title);
    output.push_str("**\n\n");
    output.push_str(&clean_inline_text(body));
    output.push_str("\n\n");

    if let Some(suggested_fix) = finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        output.push_str("Suggested fix:\n");
        output.push_str(&clean_inline_text(suggested_fix));
        output.push_str("\n\n");
    }

    output.push_str("Confidence: ");
    output.push_str(finding.confidence.display_lower());
    output.push('\n');
    output.push_str("Category: ");
    output.push_str(finding.category.display_lower());
    output.push_str("\n\n");
    output.push_str(&inline_marker(
        &mr.project_path,
        mr.mr_iid,
        fingerprint,
        head_sha,
    ));

    if output.trim().is_empty() {
        return Err(ReviewGateError::EmptyInlineCommentBody);
    }

    Ok(output)
}

pub fn format_inline_publish_report(report: &InlinePublishReport) -> String {
    let mut output = String::new();

    output.push_str("Inline publish report:\n\n");
    output.push_str(&format!(
        "Created inline comments: {}\n",
        report.created_count()
    ));
    output.push_str(&format!(
        "Skipped duplicates: {}\n",
        report.skipped_duplicate_count()
    ));
    output.push_str(&format!(
        "Failed inline comments: {}\n",
        report.failed_count()
    ));
    output.push_str(&format!(
        "Fallback to summary: {}\n\n",
        report.fallback_count()
    ));

    push_result_section(
        &mut output,
        "Created",
        &report.results,
        InlinePublishStatus::Created,
    );
    push_result_section(
        &mut output,
        "Skipped duplicate",
        &report.results,
        InlinePublishStatus::SkippedDuplicate,
    );
    push_result_section(
        &mut output,
        "Failed",
        &report.results,
        InlinePublishStatus::Failed,
    );
    push_result_section(
        &mut output,
        "Fallback",
        &report.results,
        InlinePublishStatus::NotEligible,
    );

    if !report.duplicate_warnings.is_empty() {
        output.push_str("\nWarnings:\n");
        for warning in &report.duplicate_warnings {
            output.push_str("- ");
            output.push_str(warning);
            output.push('\n');
        }
    }

    output
}

fn push_result_section(
    output: &mut String,
    title: &str,
    results: &[InlinePublishResult],
    status: InlinePublishStatus,
) {
    output.push_str(title);
    output.push_str(":\n");

    let matching: Vec<&InlinePublishResult> = results
        .iter()
        .filter(|result| result.status == status)
        .collect();

    if matching.is_empty() {
        output.push_str("- none\n\n");
        return;
    }

    for result in matching {
        output.push_str("- ");
        output.push_str(result.severity.display_upper());
        output.push(' ');
        output.push_str(&result_location(result));
        output.push('\n');

        match status {
            InlinePublishStatus::Created => {
                output.push_str("  Discussion ID: ");
                output.push_str(result.discussion_id.as_deref().unwrap_or("unavailable"));
                output.push('\n');
            }
            InlinePublishStatus::SkippedDuplicate => {
                output.push_str("  Reason: existing ReviewGate inline fingerprint\n");
            }
            InlinePublishStatus::Failed | InlinePublishStatus::NotEligible => {
                output.push_str("  Reason: ");
                output.push_str(result.error.as_deref().unwrap_or("unknown"));
                output.push('\n');
            }
        }
    }

    output.push('\n');
}

fn not_eligible_result(
    candidate: &InlineCandidate,
    reason: InlineEligibilityReason,
) -> InlinePublishResult {
    InlinePublishResult {
        finding_id: candidate.finding_id.clone(),
        title: candidate.title.clone(),
        severity: candidate.severity,
        file_path: candidate.file_path.clone(),
        line: candidate.requested_line,
        status: InlinePublishStatus::NotEligible,
        discussion_id: None,
        note_id: None,
        error: Some(reason.display_lower().to_string()),
    }
}

fn skipped_duplicate_result(candidate: &InlineCandidate) -> InlinePublishResult {
    InlinePublishResult {
        finding_id: candidate.finding_id.clone(),
        title: candidate.title.clone(),
        severity: candidate.severity,
        file_path: candidate.file_path.clone(),
        line: candidate.requested_line,
        status: InlinePublishStatus::SkippedDuplicate,
        discussion_id: None,
        note_id: None,
        error: Some("existing ReviewGate inline fingerprint".to_string()),
    }
}

fn failed_result(candidate: &InlineCandidate, error: String) -> InlinePublishResult {
    InlinePublishResult {
        finding_id: candidate.finding_id.clone(),
        title: candidate.title.clone(),
        severity: candidate.severity,
        file_path: candidate.file_path.clone(),
        line: candidate.requested_line,
        status: InlinePublishStatus::Failed,
        discussion_id: None,
        note_id: None,
        error: Some(error),
    }
}

fn created_note_id(discussion: &GitLabDiscussion) -> Option<u64> {
    discussion.notes.first().map(|note| note.id)
}

fn inline_publish_error(err: &ReviewGateError) -> String {
    match err {
        ReviewGateError::GitLabValidation(message) => {
            format!("GitLab rejected inline position: {message}")
        }
        _ => err.to_string(),
    }
}

fn result_location(result: &InlinePublishResult) -> String {
    let path = result
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let line = result
        .line
        .map(|line| line.to_string())
        .unwrap_or_else(|| "none".to_string());
    format!("{path}:{line}")
}

fn normalize_title(title: &str) -> String {
    title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn clean_inline_text(value: &str) -> String {
    let marker_regex =
        Regex::new(r#"<!--\s*reviewgate:inline\b[^>]*-->"#).expect("inline marker regex compiles");
    marker_regex
        .replace_all(value.trim(), "")
        .trim()
        .to_string()
}

fn blank_fallback<'a>(value: &'a str, fallback: &'static str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn escape_marker_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        existing_inline_fingerprints, extract_inline_fingerprints_from_note_body,
        format_inline_comment_body, format_inline_publish_report, inline_fingerprint,
        inline_marker, publish_inline_comments_with, InlinePublishReport,
    };
    use crate::{
        config::InlineConfig,
        error::{Result, ReviewGateError},
        gitlab::{
            types::{GitLabDiscussion, GitLabDiscussionNote, GitLabNotePosition},
            url::GitLabMrUrl,
        },
        review::{
            inline::{
                GitLabInlinePosition, InlineCandidate, InlineEligibilityReason,
                InlinePublishResult, InlinePublishStatus,
            },
            types::{Confidence, ReviewCategory, ReviewFinding, Severity},
        },
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn inline_fingerprint_generation_is_deterministic() {
        let first = inline_fingerprint(
            "group/repo",
            59,
            "head",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            "  HTTP   request has no timeout ",
        );
        let second = inline_fingerprint(
            "group/repo",
            59,
            "head",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            "http request has no timeout",
        );

        assert_eq!(first, second);
    }

    #[test]
    fn inline_fingerprint_changes_when_head_sha_changes() {
        let first = inline_fingerprint(
            "group/repo",
            59,
            "head-1",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            "finding",
        );
        let second = inline_fingerprint(
            "group/repo",
            59,
            "head-2",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            "finding",
        );

        assert_ne!(first, second);
    }

    #[test]
    fn marker_generation_uses_hidden_reviewgate_marker() {
        assert_eq!(
            inline_marker("group/repo", 59, "abc123", "head"),
            r#"<!-- reviewgate:inline project="group/repo" mr="59" fingerprint="abc123" head_sha="head" -->"#
        );
    }

    #[test]
    fn marker_extraction_reads_existing_discussion_notes() {
        let fingerprints = extract_inline_fingerprints_from_note_body(
            r#"body
<!-- reviewgate:inline project="group/repo" mr="59" fingerprint="abc123" head_sha="head" -->"#,
        );

        assert_eq!(fingerprints, vec!["abc123".to_string()]);
    }

    #[test]
    fn duplicate_detection_ignores_system_notes() {
        let discussions = vec![discussion(
            "d1",
            vec![
                note(
                    1,
                    r#"<!-- reviewgate:inline fingerprint="abc123" -->"#,
                    false,
                ),
                note(
                    2,
                    r#"<!-- reviewgate:inline fingerprint="abc123" -->"#,
                    true,
                ),
            ],
        )];

        let fingerprints = existing_inline_fingerprints(&discussions);

        assert_eq!(fingerprints.get("abc123"), Some(&1));
    }

    #[test]
    fn inline_body_formatting_uses_safe_reviewgate_shape() {
        let mr = mr();
        let body = format_inline_comment_body(&mr, &finding(), "fp", "head").unwrap();

        assert!(body.contains("**ReviewGate: HIGH - HTTP request has no timeout**"));
        assert!(body.contains("The call can hang indefinitely."));
        assert!(body.contains("Suggested fix:\nUse a timeout."));
        assert!(body.contains("Confidence: high"));
        assert!(body.contains("Category: reliability"));
        assert!(body.contains(r#"<!-- reviewgate:inline project="group/repo" mr="59" fingerprint="fp" head_sha="head" -->"#));
        assert!(!body.contains("raw prompt"));
    }

    #[tokio::test]
    async fn failed_candidate_does_not_stop_other_candidates() {
        let create_calls = Arc::new(AtomicUsize::new(0));
        let create_calls_in_closure = Arc::clone(&create_calls);
        let candidates = vec![candidate("finding-1", 1), candidate("finding-2", 2)];
        let findings = vec![finding(), finding()];

        let report = publish_inline_comments_with(
            &mr(),
            &candidates,
            &findings,
            &config(),
            || async { Ok(Vec::new()) },
            move |_| {
                let count = create_calls_in_closure.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count == 0 {
                        Err(ReviewGateError::GitLabValidation(
                            "400 Bad Request".to_string(),
                        ))
                    } else {
                        Ok(discussion("created", vec![note(123, "created", false)]))
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(create_calls.load(Ordering::SeqCst), 2);
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.created_count(), 1);
    }

    #[tokio::test]
    async fn no_eligible_candidates_is_non_fatal_and_does_not_list_discussions() {
        let list_calls = Arc::new(AtomicUsize::new(0));
        let list_calls_in_closure = Arc::clone(&list_calls);
        let mut candidate = candidate("finding-1", 1);
        candidate.eligible = false;
        candidate.reason = InlineEligibilityReason::SeverityTooLow;
        candidate.position = None;

        let report = publish_inline_comments_with(
            &mr(),
            &[candidate],
            &[finding()],
            &config(),
            move || {
                list_calls_in_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok(Vec::new()) }
            },
            |_| async { Ok(discussion("created", vec![note(123, "created", false)])) },
        )
        .await
        .unwrap();

        assert_eq!(list_calls.load(Ordering::SeqCst), 0);
        assert_eq!(report.fallback_count(), 1);
    }

    #[tokio::test]
    async fn duplicate_detection_skips_same_fingerprint_inside_one_run() {
        let create_calls = Arc::new(AtomicUsize::new(0));
        let create_calls_in_closure = Arc::clone(&create_calls);
        let duplicate = candidate("finding-1", 1);

        let report = publish_inline_comments_with(
            &mr(),
            &[duplicate.clone(), duplicate],
            &[finding(), finding()],
            &config(),
            || async { Ok(Vec::new()) },
            move |_| {
                create_calls_in_closure.fetch_add(1, Ordering::SeqCst);
                async { Ok(discussion("created", vec![note(123, "created", false)])) }
            },
        )
        .await
        .unwrap();

        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.created_count(), 1);
        assert_eq!(report.skipped_duplicate_count(), 1);
    }

    #[test]
    fn publish_report_formatting() {
        let report = InlinePublishReport {
            results: vec![
                result(InlinePublishStatus::Created, Some("abc123"), None),
                result(
                    InlinePublishStatus::SkippedDuplicate,
                    None,
                    Some("existing ReviewGate inline fingerprint"),
                ),
                result(
                    InlinePublishStatus::Failed,
                    None,
                    Some("GitLab rejected inline position: 400 Bad Request"),
                ),
                result(
                    InlinePublishStatus::NotEligible,
                    None,
                    Some("severity too low"),
                ),
            ],
            duplicate_warnings: Vec::new(),
        };

        let output = format_inline_publish_report(&report);

        assert!(output.contains("Inline publish report:"));
        assert!(output.contains("Created inline comments: 1"));
        assert!(output.contains("Skipped duplicates: 1"));
        assert!(output.contains("Failed inline comments: 1"));
        assert!(output.contains("Fallback to summary: 1"));
        assert!(output.contains("Discussion ID: abc123"));
        assert!(output.contains("Reason: existing ReviewGate inline fingerprint"));
        assert!(output.contains("Reason: GitLab rejected inline position: 400 Bad Request"));
        assert!(output.contains("Reason: severity too low"));
    }

    fn mr() -> GitLabMrUrl {
        GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59").unwrap()
    }

    fn config() -> InlineConfig {
        InlineConfig {
            enabled: false,
            dry_run: false,
            dedupe: true,
            max_inline_total: 10,
            max_high_inline: 8,
            max_medium_inline: 5,
        }
    }

    fn finding() -> ReviewFinding {
        ReviewFinding {
            severity: Severity::High,
            category: ReviewCategory::Reliability,
            file_path: Some("src/a.rs".to_string()),
            line: Some(42),
            title: "HTTP request has no timeout".to_string(),
            body: "The call can hang indefinitely.".to_string(),
            suggested_fix: Some("Use a timeout.".to_string()),
            confidence: Confidence::High,
            actionable: true,
        }
    }

    fn candidate(finding_id: &str, line: u32) -> InlineCandidate {
        InlineCandidate {
            finding_id: finding_id.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            file_path: Some("src/a.rs".to_string()),
            requested_line: Some(line),
            title: "HTTP request has no timeout".to_string(),
            eligible: true,
            reason: InlineEligibilityReason::Eligible,
            position: Some(GitLabInlinePosition {
                position_type: "text".to_string(),
                base_sha: "base".to_string(),
                start_sha: "start".to_string(),
                head_sha: "head".to_string(),
                old_path: "src/a.rs".to_string(),
                new_path: "src/a.rs".to_string(),
                old_line: None,
                new_line: Some(line),
            }),
        }
    }

    fn discussion(id: &str, notes: Vec<GitLabDiscussionNote>) -> GitLabDiscussion {
        GitLabDiscussion {
            id: id.to_string(),
            individual_note: Some(false),
            notes,
        }
    }

    fn note(id: u64, body: &str, system: bool) -> GitLabDiscussionNote {
        GitLabDiscussionNote {
            id,
            body: body.to_string(),
            system,
            resolvable: Some(true),
            resolved: Some(false),
            position: Some(GitLabNotePosition {
                position_type: Some("text".to_string()),
                base_sha: Some("base".to_string()),
                start_sha: Some("start".to_string()),
                head_sha: Some("head".to_string()),
                old_path: Some("src/a.rs".to_string()),
                new_path: Some("src/a.rs".to_string()),
                old_line: None,
                new_line: Some(1),
            }),
            created_at: None,
            updated_at: None,
        }
    }

    fn result(
        status: InlinePublishStatus,
        discussion_id: Option<&str>,
        error: Option<&str>,
    ) -> InlinePublishResult {
        InlinePublishResult {
            finding_id: "finding-1".to_string(),
            title: "finding".to_string(),
            severity: Severity::High,
            file_path: Some("src/a.rs".to_string()),
            line: Some(42),
            status,
            discussion_id: discussion_id.map(str::to_string),
            note_id: Some(123),
            error: error.map(str::to_string),
        }
    }
}
