use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
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
        types::{ReviewCategory, ReviewFinding, RiskCode, Severity},
    },
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, future::Future};

const INLINE_MARKER_PREFIX: &str = "<!-- reviewgate:inline";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExistingInlineDedupe {
    pub fingerprints: HashMap<String, usize>,
    pub position_signatures: HashMap<String, usize>,
    pub location_risk_signatures: HashMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineMarker {
    pub version: Option<u8>,
    pub project: Option<String>,
    pub mr: Option<u64>,
    pub fingerprint: String,
    pub head_sha: Option<String>,
    pub risk_code: Option<RiskCode>,
}

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

    let mut existing_dedupe = if config.dedupe {
        existing_inline_dedupe(&list_discussions().await?)
    } else {
        ExistingInlineDedupe::default()
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

        let file_path = resolved_position_file_path(&position);
        let fingerprint = inline_fingerprint_v2(
            &mr.project_path,
            mr.mr_iid,
            &position.head_sha,
            file_path,
            position.old_line,
            position.new_line,
            candidate.severity,
            &finding.category,
            finding.risk_code,
        );
        let v1_fingerprint = inline_fingerprint_v1(
            &mr.project_path,
            mr.mr_iid,
            &position.head_sha,
            file_path,
            position.old_line,
            position.new_line,
            candidate.severity,
            &candidate.title,
        );
        let position_signature = inline_position_signature(
            &position.head_sha,
            &position.old_path,
            &position.new_path,
            position.old_line,
            position.new_line,
            candidate.severity,
            finding.risk_code.unwrap_or(RiskCode::Other),
        );
        let v1_position_signature = inline_position_signature(
            &position.head_sha,
            &position.old_path,
            &position.new_path,
            position.old_line,
            position.new_line,
            candidate.severity,
            RiskCode::Other,
        );
        let location_risk_signature = inline_location_risk_signature(
            &position.head_sha,
            &position.old_path,
            &position.new_path,
            position.old_line,
            position.new_line,
            finding.risk_code.unwrap_or(RiskCode::Other),
        );
        let v1_location_risk_signature = inline_location_risk_signature(
            &position.head_sha,
            &position.old_path,
            &position.new_path,
            position.old_line,
            position.new_line,
            RiskCode::Other,
        );

        let duplicate_count = existing_dedupe
            .fingerprints
            .get(&fingerprint)
            .or_else(|| existing_dedupe.fingerprints.get(&v1_fingerprint))
            .or_else(|| existing_dedupe.position_signatures.get(&position_signature))
            .or_else(|| {
                existing_dedupe
                    .position_signatures
                    .get(&v1_position_signature)
            })
            .or_else(|| {
                existing_dedupe
                    .location_risk_signatures
                    .get(&location_risk_signature)
            })
            .or_else(|| {
                existing_dedupe
                    .location_risk_signatures
                    .get(&v1_location_risk_signature)
            })
            .copied();

        if let Some(count) = duplicate_count {
            if count > 1 {
                report.duplicate_warnings.push(format!(
                    "multiple existing ReviewGate inline notes match dedupe key {fingerprint}"
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
                        existing_dedupe.fingerprints.insert(fingerprint, 1);
                        existing_dedupe
                            .position_signatures
                            .insert(position_signature, 1);
                        existing_dedupe
                            .location_risk_signatures
                            .insert(location_risk_signature, 1);
                        existing_dedupe
                            .location_risk_signatures
                            .insert(v1_location_risk_signature, 1);
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

#[allow(clippy::too_many_arguments)]
pub fn inline_fingerprint_v2(
    project_path: &str,
    mr_iid: u64,
    head_sha: &str,
    file_path: &str,
    old_line: Option<u32>,
    new_line: Option<u32>,
    severity: Severity,
    category: &ReviewCategory,
    risk_code: Option<RiskCode>,
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
        category.display_lower().to_string(),
        risk_code
            .unwrap_or(RiskCode::Other)
            .display_lower()
            .to_string(),
    ];

    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }

    hex_lower(&hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
pub fn inline_fingerprint_v1(
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

pub fn inline_marker(
    project_path: &str,
    mr_iid: u64,
    fingerprint: &str,
    head_sha: &str,
    risk_code: Option<RiskCode>,
) -> String {
    format!(
        "<!-- reviewgate:inline version=\"2\" project=\"{}\" mr=\"{}\" fingerprint=\"{}\" head_sha=\"{}\" risk_code=\"{}\" -->",
        escape_marker_attr(project_path),
        mr_iid,
        escape_marker_attr(fingerprint),
        escape_marker_attr(head_sha),
        risk_code.unwrap_or(RiskCode::Other).display_lower()
    )
}

pub fn extract_inline_fingerprints_from_note_body(body: &str) -> Vec<String> {
    extract_inline_markers_from_note_body(body)
        .into_iter()
        .map(|marker| marker.fingerprint)
        .collect()
}

pub fn existing_inline_fingerprints(discussions: &[GitLabDiscussion]) -> HashMap<String, usize> {
    existing_inline_dedupe(discussions).fingerprints
}

pub fn extract_inline_markers_from_note_body(body: &str) -> Vec<InlineMarker> {
    let marker_regex = Regex::new(r#"<!--\s*reviewgate:inline\b(?P<attrs>[^>]*)-->"#)
        .expect("inline marker regex compiles");
    marker_regex
        .captures_iter(body)
        .filter_map(|captures| {
            let attrs = captures.name("attrs")?.as_str();
            let fingerprint = marker_attr(attrs, "fingerprint")?;
            Some(InlineMarker {
                version: marker_attr(attrs, "version").and_then(|value| value.parse().ok()),
                project: marker_attr(attrs, "project"),
                mr: marker_attr(attrs, "mr").and_then(|value| value.parse().ok()),
                fingerprint,
                head_sha: marker_attr(attrs, "head_sha"),
                risk_code: marker_attr(attrs, "risk_code")
                    .and_then(|value| serde_json::from_str(&format!("{value:?}")).ok()),
            })
        })
        .collect()
}

pub fn existing_inline_dedupe(discussions: &[GitLabDiscussion]) -> ExistingInlineDedupe {
    let mut dedupe = ExistingInlineDedupe::default();

    for discussion in discussions {
        for note in &discussion.notes {
            if note.system || !note.body.contains(INLINE_MARKER_PREFIX) {
                continue;
            }
            let markers = extract_inline_markers_from_note_body(&note.body);
            for marker in &markers {
                *dedupe
                    .fingerprints
                    .entry(marker.fingerprint.clone())
                    .or_insert(0) += 1;
            }
            let Some(position) = note.position.as_ref() else {
                continue;
            };
            if let Some(signature) =
                existing_note_position_signature(&note.body, position, &markers)
            {
                *dedupe.position_signatures.entry(signature).or_insert(0) += 1;
            }
            if let Some(signature) = existing_note_location_risk_signature(position, &markers) {
                *dedupe
                    .location_risk_signatures
                    .entry(signature)
                    .or_insert(0) += 1;
            }
            if let Some(signature) =
                existing_note_location_signature_with_risk(position, RiskCode::Other)
            {
                *dedupe
                    .location_risk_signatures
                    .entry(signature)
                    .or_insert(0) += 1;
            }
        }
    }

    dedupe
}

pub fn inline_position_signature(
    head_sha: &str,
    old_path: &str,
    new_path: &str,
    old_line: Option<u32>,
    new_line: Option<u32>,
    severity: Severity,
    risk_code: RiskCode,
) -> String {
    let mut hasher = Sha256::new();
    let parts = vec![
        head_sha.trim().to_string(),
        old_path.trim().to_string(),
        new_path.trim().to_string(),
        old_line.map(|line| line.to_string()).unwrap_or_default(),
        new_line.map(|line| line.to_string()).unwrap_or_default(),
        severity.display_upper().to_string(),
        risk_code.display_lower().to_string(),
    ];

    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }

    hex_lower(&hasher.finalize())
}

pub fn inline_location_risk_signature(
    head_sha: &str,
    old_path: &str,
    new_path: &str,
    old_line: Option<u32>,
    new_line: Option<u32>,
    risk_code: RiskCode,
) -> String {
    let mut hasher = Sha256::new();
    let parts = vec![
        head_sha.trim().to_string(),
        old_path.trim().to_string(),
        new_path.trim().to_string(),
        old_line.map(|line| line.to_string()).unwrap_or_default(),
        new_line.map(|line| line.to_string()).unwrap_or_default(),
        risk_code.display_lower().to_string(),
    ];

    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }

    hex_lower(&hasher.finalize())
}

fn existing_note_position_signature(
    body: &str,
    position: &crate::gitlab::types::GitLabNotePosition,
    markers: &[InlineMarker],
) -> Option<String> {
    let head_sha = position.head_sha.as_deref()?.trim();
    let old_path = position.old_path.as_deref().unwrap_or_default();
    let new_path = position.new_path.as_deref().unwrap_or_default();
    let severity = parse_reviewgate_severity(body)?;
    let risk_code = markers
        .iter()
        .find_map(|marker| marker.risk_code)
        .unwrap_or(RiskCode::Other);

    Some(inline_position_signature(
        head_sha,
        old_path,
        new_path,
        position.old_line,
        position.new_line,
        severity,
        risk_code,
    ))
}

fn existing_note_location_risk_signature(
    position: &crate::gitlab::types::GitLabNotePosition,
    markers: &[InlineMarker],
) -> Option<String> {
    let risk_code = markers
        .iter()
        .find_map(|marker| marker.risk_code)
        .unwrap_or(RiskCode::Other);

    existing_note_location_signature_with_risk(position, risk_code)
}

fn existing_note_location_signature_with_risk(
    position: &crate::gitlab::types::GitLabNotePosition,
    risk_code: RiskCode,
) -> Option<String> {
    let head_sha = position.head_sha.as_deref()?.trim();
    let old_path = position.old_path.as_deref().unwrap_or_default();
    let new_path = position.new_path.as_deref().unwrap_or_default();

    Some(inline_location_risk_signature(
        head_sha,
        old_path,
        new_path,
        position.old_line,
        position.new_line,
        risk_code,
    ))
}

fn parse_reviewgate_severity(body: &str) -> Option<Severity> {
    let severity_regex =
        Regex::new(r"(?i)\*\*(?:[^\w*]+\s*)?ReviewGate:\s*(CRITICAL|HIGH|MEDIUM|LOW|NOTE)\b")
            .expect("severity regex compiles");
    let value = severity_regex.captures(body)?.get(1)?.as_str();
    serde_json::from_str(&format!("{value:?}")).ok()
}

fn marker_attr(attrs: &str, name: &str) -> Option<String> {
    let attr_regex = Regex::new(&format!(r#"\b{}\s*=\s*"([^"]*)""#, regex::escape(name)))
        .expect("marker attr regex compiles");
    attr_regex
        .captures(attrs)
        .and_then(|captures| captures.get(1))
        .map(|value| unescape_marker_attr(value.as_str()))
}

fn unescape_marker_attr(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn resolved_position_file_path(position: &crate::review::inline::GitLabInlinePosition) -> &str {
    if position.new_line.is_some() {
        &position.new_path
    } else {
        &position.old_path
    }
}

pub fn format_inline_comment_body(
    mr: &GitLabMrUrl,
    finding: &ReviewFinding,
    fingerprint: &str,
    head_sha: &str,
) -> Result<String> {
    format_inline_comment_body_with_emoji(mr, finding, fingerprint, head_sha, emoji_enabled())
}

pub fn format_inline_comment_body_with_emoji(
    mr: &GitLabMrUrl,
    finding: &ReviewFinding,
    fingerprint: &str,
    head_sha: &str,
    emoji: bool,
) -> Result<String> {
    let title = blank_fallback(&finding.title, "Untitled finding");
    let body = blank_fallback(&finding.body, "No details returned.");
    let mut output = String::new();

    output.push_str("**");
    if emoji {
        output.push_str(finding.severity.emoji());
        output.push(' ');
    }
    output.push_str("ReviewGate: ");
    output.push_str(finding.severity.display_upper());
    output.push_str(" · ");
    output.push_str(&finding.effort.display_label(emoji));
    output.push_str("**\n\n");
    output.push_str("**");
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

    output.push_str("Category: ");
    output.push_str(finding.category.display_lower());
    if let Some(risk_code) = finding.risk_code {
        output.push_str("\nRisk code: ");
        output.push_str(risk_code.display_lower());
    }
    output.push_str("\n\n");
    output.push_str(REVIEWGATE_ATTRIBUTION);
    output.push_str("\n\n");
    output.push_str(&inline_marker(
        &mr.project_path,
        mr.mr_iid,
        fingerprint,
        head_sha,
        finding.risk_code,
    ));

    if output.trim().is_empty() {
        return Err(ReviewGateError::EmptyInlineCommentBody);
    }

    Ok(output)
}

fn emoji_enabled() -> bool {
    std::env::var("REVIEWGATE_EMOJI")
        .ok()
        .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true)
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
        existing_inline_dedupe, existing_inline_fingerprints,
        extract_inline_fingerprints_from_note_body, extract_inline_markers_from_note_body,
        format_inline_comment_body_with_emoji, format_inline_publish_report, inline_fingerprint_v1,
        inline_fingerprint_v2, inline_marker, publish_inline_comments_with, InlinePublishReport,
    };
    use crate::{
        config::InlineConfig,
        error::ReviewGateError,
        gitlab::{
            types::{GitLabDiscussion, GitLabDiscussionNote, GitLabNotePosition},
            url::GitLabMrUrl,
        },
        review::{
            inline::{
                GitLabInlinePosition, InlineCandidate, InlineEligibilityReason,
                InlinePublishResult, InlinePublishStatus,
            },
            types::{Effort, ReviewCategory, ReviewFinding, RiskCode, Severity},
        },
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn v2_fingerprint_ignores_title_changes() {
        let first = inline_fingerprint_v2(
            "group/repo",
            59,
            "head",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::MissingTimeout),
        );
        let second = inline_fingerprint_v2(
            "group/repo",
            59,
            "head",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::MissingTimeout),
        );

        assert_eq!(first, second);
    }

    #[test]
    fn v2_fingerprint_changes_when_position_head_or_risk_changes() {
        let first = inline_fingerprint_v2(
            "group/repo",
            59,
            "head-1",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::MissingTimeout),
        );
        let moved = inline_fingerprint_v2(
            "group/repo",
            59,
            "head-1",
            "src/a.rs",
            None,
            Some(43),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::MissingTimeout),
        );
        let new_head = inline_fingerprint_v2(
            "group/repo",
            59,
            "head-2",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::MissingTimeout),
        );
        let different_risk = inline_fingerprint_v2(
            "group/repo",
            59,
            "head-1",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            &ReviewCategory::Reliability,
            Some(RiskCode::UnboundedRetry),
        );

        assert_ne!(first, moved);
        assert_ne!(first, new_head);
        assert_ne!(first, different_risk);
    }

    #[test]
    fn marker_generation_uses_hidden_reviewgate_marker() {
        assert_eq!(
            inline_marker(
                "group/repo",
                59,
                "abc123",
                "head",
                Some(RiskCode::MissingTimeout)
            ),
            r#"<!-- reviewgate:inline version="2" project="group/repo" mr="59" fingerprint="abc123" head_sha="head" risk_code="missing_timeout" -->"#
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
    fn marker_extraction_reads_v2_risk_code_and_v1_marker() {
        let markers = extract_inline_markers_from_note_body(
            r#"body
<!-- reviewgate:inline version="2" project="group/repo" mr="59" fingerprint="v2" head_sha="head" risk_code="missing-timeout" -->
<!-- reviewgate:inline project="group/repo" mr="59" fingerprint="v1" head_sha="head" -->"#,
        );

        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0].version, Some(2));
        assert_eq!(markers[0].risk_code, Some(RiskCode::MissingTimeout));
        assert_eq!(markers[1].version, None);
        assert_eq!(markers[1].fingerprint, "v1");
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
    fn existing_v1_comment_can_be_deduped_by_position_signature() {
        let discussions = vec![discussion(
            "d1",
            vec![note(
                1,
                r#"**ReviewGate: HIGH - HTTP request has no timeout**

body

<!-- reviewgate:inline project="group/repo" mr="59" fingerprint="old" head_sha="head" -->"#,
                false,
            )],
        )];

        let dedupe = existing_inline_dedupe(&discussions);
        let signature = super::inline_position_signature(
            "head",
            "src/a.rs",
            "src/a.rs",
            None,
            Some(1),
            Severity::High,
            RiskCode::Other,
        );

        assert_eq!(dedupe.position_signatures.get(&signature), Some(&1));
    }

    #[test]
    fn existing_comment_can_be_deduped_when_severity_changes() {
        let discussions = vec![discussion(
            "d1",
            vec![note(
                1,
                r#"**ReviewGate: MEDIUM - HTTP request has no timeout**

body

<!-- reviewgate:inline version="2" project="group/repo" mr="59" fingerprint="old" head_sha="head" risk_code="missing_timeout" -->"#,
                false,
            )],
        )];

        let dedupe = existing_inline_dedupe(&discussions);
        let signature = super::inline_location_risk_signature(
            "head",
            "src/a.rs",
            "src/a.rs",
            None,
            Some(1),
            RiskCode::MissingTimeout,
        );

        assert_eq!(dedupe.location_risk_signatures.get(&signature), Some(&1));
    }

    #[test]
    fn inline_body_formatting_uses_safe_reviewgate_shape() {
        let mr = mr();
        let body =
            format_inline_comment_body_with_emoji(&mr, &finding(), "fp", "head", true).unwrap();

        assert!(body.contains("**🟠 ReviewGate: HIGH · ⚡ Quick fix**"));
        assert!(body.contains("**HTTP request has no timeout**"));
        assert!(body.contains("The call can hang indefinitely."));
        assert!(body.contains("Suggested fix:\nUse a timeout."));
        assert!(body.contains("Category: reliability"));
        assert!(body.contains("Risk code: missing_timeout"));
        assert!(!body.contains("Confidence:"));
        assert!(body.contains(r#"<!-- reviewgate:inline version="2" project="group/repo" mr="59" fingerprint="fp" head_sha="head" risk_code="missing_timeout" -->"#));
        assert!(!body.contains("raw prompt"));
        assert!(!body.contains("Change Since Previous Review"));
    }

    #[test]
    fn inline_body_can_disable_emoji() {
        let body =
            format_inline_comment_body_with_emoji(&mr(), &finding(), "fp", "head", false).unwrap();

        assert!(body.contains("**ReviewGate: HIGH · Quick fix**"));
        assert!(!body.contains("🟠"));
        assert!(!body.contains("⚡"));
    }

    #[test]
    fn v1_fingerprint_still_matches_old_title_based_marker() {
        let first = inline_fingerprint_v1(
            "group/repo",
            59,
            "head",
            "src/a.rs",
            None,
            Some(42),
            Severity::High,
            "  HTTP   request has no timeout ",
        );
        let second = inline_fingerprint_v1(
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
            risk_code: Some(RiskCode::MissingTimeout),
            anchor_id: None,
            file_path: Some("src/a.rs".to_string()),
            line: Some(42),
            title: "HTTP request has no timeout".to_string(),
            body: "The call can hang indefinitely.".to_string(),
            suggested_fix: Some("Use a timeout.".to_string()),
            effort: Effort::Quick,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }

    fn candidate(finding_id: &str, line: u32) -> InlineCandidate {
        InlineCandidate {
            finding_id: finding_id.to_string(),
            severity: Severity::High,
            effort: Effort::Quick,
            file_path: Some("src/a.rs".to_string()),
            requested_line: Some(line),
            anchor_id: None,
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
