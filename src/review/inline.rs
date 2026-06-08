use crate::{
    config::InlineConfig,
    gitlab::types::{DiffRefs, MergeRequestDiff},
    review::{
        anchors::{AnchoredDiffContext, ReviewLineAnchor},
        types::{Effort, EvidenceValidationStatus, ReviewAnalysis, ReviewFinding, Severity},
    },
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineKind {
    Added,
    Removed,
    Context,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLinePosition {
    pub old_path: String,
    pub new_path: String,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
    pub kind: DiffLineKind,
    pub content_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLabInlinePosition {
    pub position_type: String,
    pub base_sha: String,
    pub start_sha: String,
    pub head_sha: String,
    pub old_path: String,
    pub new_path: String,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineEligibilityReason {
    Eligible,
    SeverityTooLow,
    NotActionable,
    NeedsManualConfirmation,
    MissingFilePath,
    MissingLine,
    InvalidAnchorId,
    FileNotInDiff,
    LineNotInDiff,
    GeneratedFile,
    TooLargeFile,
    CollapsedFile,
    MissingDiffRefs,
    MaxInlineLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlinePublishStatus {
    Created,
    SkippedDuplicate,
    Failed,
    NotEligible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinePublishResult {
    pub finding_id: String,
    pub title: String,
    pub severity: Severity,
    pub file_path: Option<String>,
    pub line: Option<u32>,
    pub status: InlinePublishStatus,
    pub discussion_id: Option<String>,
    pub note_id: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineCandidate {
    pub finding_id: String,
    pub severity: Severity,
    pub effort: Effort,
    pub file_path: Option<String>,
    pub requested_line: Option<u32>,
    pub anchor_id: Option<String>,
    pub title: String,
    pub eligible: bool,
    pub reason: InlineEligibilityReason,
    pub position: Option<GitLabInlinePosition>,
}

#[derive(Debug, Clone, Default)]
pub struct DiffPositionIndex {
    new_positions: HashMap<(String, u32), DiffLinePosition>,
    old_positions: HashMap<(String, u32), DiffLinePosition>,
    files: HashMap<String, DiffFileStatus>,
}

#[derive(Debug, Clone, Copy, Default)]
struct DiffFileStatus {
    generated: bool,
    collapsed: bool,
    too_large: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HunkHeader {
    old_start: u32,
    new_start: u32,
}

pub fn parse_diff_line_positions(diff: &MergeRequestDiff) -> Vec<DiffLinePosition> {
    let mut positions = Vec::new();
    let mut old_line = 0;
    let mut new_line = 0;
    let mut in_hunk = false;

    for line in diff.diff.lines() {
        if let Some(header) = parse_hunk_header(line) {
            old_line = header.old_start;
            new_line = header.new_start;
            in_hunk = true;
            continue;
        }

        if !in_hunk || line.starts_with("\\ No newline at end of file") {
            continue;
        }

        if let Some(content) = line.strip_prefix('+') {
            positions.push(DiffLinePosition {
                old_path: diff.old_path.clone(),
                new_path: diff.new_path.clone(),
                old_line: None,
                new_line: Some(new_line),
                kind: DiffLineKind::Added,
                content_preview: preview_content(content),
            });
            new_line += 1;
        } else if let Some(content) = line.strip_prefix('-') {
            positions.push(DiffLinePosition {
                old_path: diff.old_path.clone(),
                new_path: diff.new_path.clone(),
                old_line: Some(old_line),
                new_line: None,
                kind: DiffLineKind::Removed,
                content_preview: preview_content(content),
            });
            old_line += 1;
        } else if let Some(content) = line.strip_prefix(' ') {
            positions.push(DiffLinePosition {
                old_path: diff.old_path.clone(),
                new_path: diff.new_path.clone(),
                old_line: Some(old_line),
                new_line: Some(new_line),
                kind: DiffLineKind::Context,
                content_preview: preview_content(content),
            });
            old_line += 1;
            new_line += 1;
        }
    }

    positions
}

pub fn build_diff_position_index(diffs: &[MergeRequestDiff]) -> DiffPositionIndex {
    let mut index = DiffPositionIndex::default();

    for diff in diffs {
        index.insert_file_status(
            &diff.old_path,
            DiffFileStatus {
                generated: diff.is_generated(),
                collapsed: diff.is_collapsed(),
                too_large: diff.is_too_large(),
            },
        );
        index.insert_file_status(
            &diff.new_path,
            DiffFileStatus {
                generated: diff.is_generated(),
                collapsed: diff.is_collapsed(),
                too_large: diff.is_too_large(),
            },
        );

        for position in parse_diff_line_positions(diff) {
            if let Some(new_line) = position.new_line {
                index
                    .new_positions
                    .insert((position.new_path.clone(), new_line), position.clone());
            }
            if let Some(old_line) = position.old_line {
                index
                    .old_positions
                    .insert((position.old_path.clone(), old_line), position.clone());
            }
        }
    }

    index
}

pub fn resolve_inline_candidates(
    analysis: &ReviewAnalysis,
    diffs: &[MergeRequestDiff],
    diff_refs: Option<&DiffRefs>,
    config: &InlineConfig,
) -> Vec<InlineCandidate> {
    resolve_inline_candidates_with_anchors(analysis, diffs, None, diff_refs, config)
}

pub fn resolve_inline_candidates_with_anchors(
    analysis: &ReviewAnalysis,
    diffs: &[MergeRequestDiff],
    anchors: Option<&AnchoredDiffContext>,
    diff_refs: Option<&DiffRefs>,
    config: &InlineConfig,
) -> Vec<InlineCandidate> {
    let index = build_diff_position_index(diffs);
    let refs = complete_diff_refs(diff_refs);
    let context = InlineResolveContext {
        index: &index,
        anchors,
        diff_refs: refs.as_ref(),
        config,
    };
    let mut counts = InlineResolveCounts::default();

    analysis
        .findings
        .iter()
        .enumerate()
        .map(|(index_in_review, finding)| {
            resolve_candidate(index_in_review, finding, &context, &mut counts)
        })
        .collect()
}

struct InlineResolveContext<'a> {
    index: &'a DiffPositionIndex,
    anchors: Option<&'a AnchoredDiffContext>,
    diff_refs: Option<&'a CompleteDiffRefs>,
    config: &'a InlineConfig,
}

#[derive(Default)]
struct InlineResolveCounts {
    total: usize,
    high: usize,
    medium: usize,
}

pub fn format_inline_dry_run_report(candidates: &[InlineCandidate]) -> String {
    format_inline_dry_run_report_with_emoji(candidates, emoji_enabled())
}

pub fn format_inline_dry_run_report_with_emoji(
    candidates: &[InlineCandidate],
    emoji: bool,
) -> String {
    let eligible: Vec<&InlineCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .collect();
    let fallback: Vec<&InlineCandidate> = candidates
        .iter()
        .filter(|candidate| !candidate.eligible)
        .collect();

    let mut output = String::new();
    output.push_str("Inline dry-run report:\n\n");
    output.push_str(&format!("Eligible inline candidates: {}\n", eligible.len()));
    output.push_str(&format!("Fallback to summary: {}\n\n", fallback.len()));

    output.push_str("Eligible:\n");
    push_candidate_section(&mut output, &eligible, true, emoji);
    output.push_str("\nFallback:\n");
    push_candidate_section(&mut output, &fallback, false, emoji);

    output
}

fn resolve_candidate(
    index_in_review: usize,
    finding: &ReviewFinding,
    context: &InlineResolveContext<'_>,
    counts: &mut InlineResolveCounts,
) -> InlineCandidate {
    let base = InlineCandidate {
        finding_id: format!("finding-{}", index_in_review + 1),
        severity: finding.severity,
        effort: finding.effort,
        file_path: finding.file_path.clone(),
        requested_line: finding.line,
        anchor_id: finding.anchor_id.clone(),
        title: finding.title.clone(),
        eligible: false,
        reason: InlineEligibilityReason::Eligible,
        position: None,
    };

    if !matches!(
        finding.severity,
        Severity::Critical | Severity::High | Severity::Medium
    ) {
        return ineligible(base, InlineEligibilityReason::SeverityTooLow);
    }
    if !finding.actionable {
        return ineligible(base, InlineEligibilityReason::NotActionable);
    }
    if finding.evidence_status == Some(EvidenceValidationStatus::NeedsManualConfirmation) {
        return ineligible(base, InlineEligibilityReason::NeedsManualConfirmation);
    }

    let invalid_anchor = finding
        .anchor_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|anchor_id| {
            context
                .anchors
                .and_then(|anchors| anchors.get(anchor_id))
                .is_none()
        });

    let Some(diff_refs) = context.diff_refs else {
        return ineligible(base, InlineEligibilityReason::MissingDiffRefs);
    };

    if let Some(anchor) = finding
        .anchor_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|anchor_id| context.anchors.and_then(|anchors| anchors.get(anchor_id)))
    {
        return resolve_with_anchor(base, anchor, context, diff_refs, counts);
    }

    let Some(file_path) = finding
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return ineligible(
            base,
            if invalid_anchor {
                InlineEligibilityReason::InvalidAnchorId
            } else {
                InlineEligibilityReason::MissingFilePath
            },
        );
    };
    let Some(line) = finding.line else {
        return ineligible(
            base,
            if invalid_anchor {
                InlineEligibilityReason::InvalidAnchorId
            } else {
                InlineEligibilityReason::MissingLine
            },
        );
    };

    let Some(file_status) = context.index.file_status(file_path) else {
        return ineligible(base, InlineEligibilityReason::FileNotInDiff);
    };
    if file_status.generated {
        return ineligible(base, InlineEligibilityReason::GeneratedFile);
    }
    if file_status.too_large {
        return ineligible(base, InlineEligibilityReason::TooLargeFile);
    }
    if file_status.collapsed {
        return ineligible(base, InlineEligibilityReason::CollapsedFile);
    }

    let Some(diff_position) = context.index.resolve(file_path, line) else {
        return ineligible(
            base,
            if invalid_anchor {
                InlineEligibilityReason::InvalidAnchorId
            } else {
                InlineEligibilityReason::LineNotInDiff
            },
        );
    };

    if counts.total >= context.config.max_inline_total {
        return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
    }

    match finding.severity {
        Severity::Critical => {}
        Severity::High => {
            if counts.high >= context.config.max_high_inline {
                return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
            }
            counts.high += 1;
        }
        Severity::Medium => {
            if counts.medium >= context.config.max_medium_inline {
                return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
            }
            counts.medium += 1;
        }
        Severity::Low | Severity::Note => unreachable!("low and note severities returned earlier"),
    }

    counts.total += 1;

    InlineCandidate {
        eligible: true,
        reason: InlineEligibilityReason::Eligible,
        position: Some(GitLabInlinePosition {
            position_type: "text".to_string(),
            base_sha: diff_refs.base_sha.clone(),
            start_sha: diff_refs.start_sha.clone(),
            head_sha: diff_refs.head_sha.clone(),
            old_path: diff_position.old_path,
            new_path: diff_position.new_path,
            old_line: diff_position.old_line,
            new_line: diff_position.new_line,
        }),
        ..base
    }
}

fn resolve_with_anchor(
    mut base: InlineCandidate,
    anchor: &ReviewLineAnchor,
    context: &InlineResolveContext<'_>,
    diff_refs: &CompleteDiffRefs,
    counts: &mut InlineResolveCounts,
) -> InlineCandidate {
    let Some(file_status) = context
        .index
        .file_status(&anchor.new_path)
        .or_else(|| context.index.file_status(&anchor.old_path))
    else {
        return ineligible(base, InlineEligibilityReason::FileNotInDiff);
    };
    if file_status.generated {
        return ineligible(base, InlineEligibilityReason::GeneratedFile);
    }
    if file_status.too_large {
        return ineligible(base, InlineEligibilityReason::TooLargeFile);
    }
    if file_status.collapsed {
        return ineligible(base, InlineEligibilityReason::CollapsedFile);
    }

    if counts.total >= context.config.max_inline_total {
        return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
    }

    match base.severity {
        Severity::Critical => {}
        Severity::High => {
            if counts.high >= context.config.max_high_inline {
                return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
            }
            counts.high += 1;
        }
        Severity::Medium => {
            if counts.medium >= context.config.max_medium_inline {
                return ineligible(base, InlineEligibilityReason::MaxInlineLimitReached);
            }
            counts.medium += 1;
        }
        Severity::Low | Severity::Note => unreachable!("low and note severities returned earlier"),
    }

    counts.total += 1;
    base.file_path = Some(anchor.file_path.clone());
    base.requested_line = anchor.new_line.or(anchor.old_line);

    InlineCandidate {
        eligible: true,
        reason: InlineEligibilityReason::Eligible,
        position: Some(GitLabInlinePosition {
            position_type: "text".to_string(),
            base_sha: diff_refs.base_sha.clone(),
            start_sha: diff_refs.start_sha.clone(),
            head_sha: diff_refs.head_sha.clone(),
            old_path: anchor.old_path.clone(),
            new_path: anchor.new_path.clone(),
            old_line: anchor.old_line,
            new_line: anchor.new_line,
        }),
        ..base
    }
}

fn ineligible(mut candidate: InlineCandidate, reason: InlineEligibilityReason) -> InlineCandidate {
    candidate.eligible = false;
    candidate.reason = reason;
    candidate.position = None;
    candidate
}

impl DiffPositionIndex {
    fn insert_file_status(&mut self, path: &str, status: DiffFileStatus) {
        let existing = self.files.entry(path.to_string()).or_default();
        existing.generated |= status.generated;
        existing.collapsed |= status.collapsed;
        existing.too_large |= status.too_large;
    }

    fn file_status(&self, path: &str) -> Option<DiffFileStatus> {
        self.files.get(path).copied()
    }

    fn resolve(&self, path: &str, line: u32) -> Option<DiffLinePosition> {
        self.new_positions
            .get(&(path.to_string(), line))
            .or_else(|| self.old_positions.get(&(path.to_string(), line)))
            .cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompleteDiffRefs {
    base_sha: String,
    start_sha: String,
    head_sha: String,
}

fn complete_diff_refs(diff_refs: Option<&DiffRefs>) -> Option<CompleteDiffRefs> {
    let diff_refs = diff_refs?;
    Some(CompleteDiffRefs {
        base_sha: non_empty_sha(diff_refs.base_sha.as_deref())?.to_string(),
        start_sha: non_empty_sha(diff_refs.start_sha.as_deref())?.to_string(),
        head_sha: non_empty_sha(diff_refs.head_sha.as_deref())?.to_string(),
    })
}

fn non_empty_sha(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn parse_hunk_header(line: &str) -> Option<HunkHeader> {
    let after_open = line.strip_prefix("@@")?;
    let end = after_open.find("@@")?;
    let header = &after_open[..end];
    let mut old_start = None;
    let mut new_start = None;

    for token in header.split_whitespace() {
        if token.starts_with('-') {
            old_start = parse_hunk_range_start(token, '-');
        } else if token.starts_with('+') {
            new_start = parse_hunk_range_start(token, '+');
        }
    }

    Some(HunkHeader {
        old_start: old_start?,
        new_start: new_start?,
    })
}

fn parse_hunk_range_start(token: &str, prefix: char) -> Option<u32> {
    let range = token.strip_prefix(prefix)?;
    let start = range.split_once(',').map_or(range, |(start, _)| start);
    start.parse().ok()
}

fn preview_content(content: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 120;
    content.chars().take(MAX_PREVIEW_CHARS).collect()
}

fn push_candidate_section(
    output: &mut String,
    candidates: &[&InlineCandidate],
    eligible: bool,
    emoji: bool,
) {
    if candidates.is_empty() {
        output.push_str("- none\n");
        return;
    }

    for (index, candidate) in candidates.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str("- ");
        output.push_str(&candidate.severity.display_label(emoji));
        output.push_str(" · ");
        output.push_str(&candidate.effort.display_label(emoji));
        output.push_str(" · ");
        output.push_str(&candidate_location(candidate));
        if let Some(anchor_id) = candidate.anchor_id.as_deref() {
            output.push_str(" anchor=");
            output.push_str(anchor_id);
        }
        output.push('\n');
        if eligible {
            output.push_str("  Title: ");
            output.push_str(blank_fallback(&candidate.title, "Untitled finding"));
            output.push('\n');
            output.push_str("  Position: ");
            output.push_str(&format_position(
                candidate
                    .position
                    .as_ref()
                    .expect("eligible candidates include a position"),
            ));
            output.push('\n');
        } else {
            output.push_str("  Reason: ");
            output.push_str(candidate.reason.display_lower());
            output.push('\n');
        }
    }
}

fn emoji_enabled() -> bool {
    std::env::var("REVIEWGATE_EMOJI")
        .ok()
        .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true)
}

fn candidate_location(candidate: &InlineCandidate) -> String {
    let path = candidate
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let line = candidate
        .requested_line
        .map(|line| line.to_string())
        .unwrap_or_else(|| "none".to_string());
    format!("{path}:{line}")
}

fn format_position(position: &GitLabInlinePosition) -> String {
    format!(
        "new_path={} new_line={} old_line={}",
        position.new_path,
        optional_line(position.new_line),
        optional_line(position.old_line)
    )
}

fn optional_line(line: Option<u32>) -> String {
    line.map(|line| line.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn blank_fallback<'a>(value: &'a str, fallback: &'static str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

impl InlineEligibilityReason {
    pub fn display_lower(self) -> &'static str {
        match self {
            InlineEligibilityReason::Eligible => "eligible",
            InlineEligibilityReason::SeverityTooLow => "severity too low",
            InlineEligibilityReason::NotActionable => "not actionable",
            InlineEligibilityReason::NeedsManualConfirmation => "needs manual confirmation",
            InlineEligibilityReason::MissingFilePath => "missing file path",
            InlineEligibilityReason::MissingLine => "missing line",
            InlineEligibilityReason::InvalidAnchorId => "invalid anchor id",
            InlineEligibilityReason::FileNotInDiff => "file not in diff",
            InlineEligibilityReason::LineNotInDiff => "line not in diff",
            InlineEligibilityReason::GeneratedFile => "generated file",
            InlineEligibilityReason::TooLargeFile => "too-large file",
            InlineEligibilityReason::CollapsedFile => "collapsed file",
            InlineEligibilityReason::MissingDiffRefs => "missing diff refs",
            InlineEligibilityReason::MaxInlineLimitReached => "max inline limit reached",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_diff_position_index, format_inline_dry_run_report_with_emoji,
        parse_diff_line_positions, parse_hunk_header, resolve_inline_candidates, DiffLineKind,
        HunkHeader, InlineEligibilityReason,
    };
    use crate::{
        config::InlineConfig,
        gitlab::types::{DiffRefs, MergeRequestDiff},
        review::{
            anchors::AnchorBuilder,
            evidence::validate_review_analysis_evidence,
            quality::normalize_review_analysis,
            types::{
                Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory,
                ReviewFinding, RiskCode, Severity,
            },
        },
    };

    #[test]
    fn parses_hunk_header_variations() {
        assert_eq!(
            parse_hunk_header("@@ -12,7 +12,10 @@"),
            Some(HunkHeader {
                old_start: 12,
                new_start: 12
            })
        );
        assert_eq!(
            parse_hunk_header("@@ -1 +1,2 @@"),
            Some(HunkHeader {
                old_start: 1,
                new_start: 1
            })
        );
        assert_eq!(
            parse_hunk_header("@@ -0,0 +1,20 @@"),
            Some(HunkHeader {
                old_start: 0,
                new_start: 1
            })
        );
        assert_eq!(
            parse_hunk_header("@@ -40,5 +0,0 @@"),
            Some(HunkHeader {
                old_start: 40,
                new_start: 0
            })
        );
    }

    #[test]
    fn parses_added_lines() {
        let positions = parse_diff_line_positions(&diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new"));

        assert_eq!(positions[1].kind, DiffLineKind::Added);
        assert_eq!(positions[1].old_line, None);
        assert_eq!(positions[1].new_line, Some(2));
        assert_eq!(positions[1].content_preview, "new");
    }

    #[test]
    fn parses_removed_lines() {
        let positions = parse_diff_line_positions(&diff("src/a.rs", "@@ -7,2 +7 @@\n-old\n same"));

        assert_eq!(positions[0].kind, DiffLineKind::Removed);
        assert_eq!(positions[0].old_line, Some(7));
        assert_eq!(positions[0].new_line, None);
    }

    #[test]
    fn parses_context_lines() {
        let positions =
            parse_diff_line_positions(&diff("src/a.rs", "@@ -7,2 +8,2 @@\n same\n+new"));

        assert_eq!(positions[0].kind, DiffLineKind::Context);
        assert_eq!(positions[0].old_line, Some(7));
        assert_eq!(positions[0].new_line, Some(8));
    }

    #[test]
    fn handles_renamed_file_paths() {
        let renamed = MergeRequestDiff {
            old_path: "src/old.rs".to_string(),
            new_path: "src/new.rs".to_string(),
            renamed_file: true,
            ..diff("src/new.rs", "@@ -2 +2 @@\n-old\n+new")
        };
        let index = build_diff_position_index(&[renamed]);

        assert_eq!(
            index.resolve("src/new.rs", 2).unwrap().kind,
            DiffLineKind::Added
        );
        assert_eq!(
            index.resolve("src/old.rs", 2).unwrap().kind,
            DiffLineKind::Removed
        );
    }

    #[test]
    fn handles_new_file_positions() {
        let new_file = MergeRequestDiff {
            new_file: true,
            ..diff("src/new.rs", "@@ -0,0 +1,2 @@\n+one\n+two")
        };
        let positions = parse_diff_line_positions(&new_file);

        assert_eq!(positions[0].old_line, None);
        assert_eq!(positions[0].new_line, Some(1));
        assert_eq!(positions[1].new_line, Some(2));
    }

    #[test]
    fn handles_deleted_file_positions() {
        let deleted_file = MergeRequestDiff {
            deleted_file: true,
            ..diff("src/deleted.rs", "@@ -40,2 +0,0 @@\n-one\n-two")
        };
        let positions = parse_diff_line_positions(&deleted_file);

        assert_eq!(positions[0].old_line, Some(40));
        assert_eq!(positions[0].new_line, None);
        assert_eq!(positions[1].old_line, Some(41));
    }

    #[test]
    fn ignores_no_newline_marker() {
        let positions = parse_diff_line_positions(&diff(
            "src/a.rs",
            "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file",
        ));

        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn model_finding_line_maps_to_new_line() {
        let analysis = analysis(vec![finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(2),
        )]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert!(candidates[0].eligible);
        assert_eq!(candidates[0].position.as_ref().unwrap().new_line, Some(2));
        assert_eq!(candidates[0].position.as_ref().unwrap().old_line, None);
    }

    #[test]
    fn model_finding_line_maps_to_old_line_when_relevant() {
        let analysis = analysis(vec![finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(4),
        )]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -4 +9 @@\n-removed\n+added")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert!(candidates[0].eligible);
        assert_eq!(candidates[0].position.as_ref().unwrap().old_line, Some(4));
        assert_eq!(candidates[0].position.as_ref().unwrap().new_line, None);
    }

    #[test]
    fn valid_anchor_id_is_preferred_over_wrong_file_path_and_line() {
        let diff = diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new");
        let anchors = anchored_context(&diff);
        let mut anchored_finding = finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/wrong.rs"),
            Some(999),
        );
        anchored_finding.anchor_id = Some("A0002".to_string());
        let candidates = super::resolve_inline_candidates_with_anchors(
            &analysis(vec![anchored_finding]),
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert!(candidates[0].eligible);
        assert_eq!(candidates[0].file_path.as_deref(), Some("src/a.rs"));
        assert_eq!(candidates[0].requested_line, Some(2));
        assert_eq!(candidates[0].position.as_ref().unwrap().new_line, Some(2));
    }

    #[test]
    fn invalid_anchor_id_falls_back_to_summary_when_line_is_not_valid() {
        let diff = diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new");
        let anchors = anchored_context(&diff);
        let mut anchored_finding = finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(999),
        );
        anchored_finding.anchor_id = Some("A9999".to_string());
        let candidates = super::resolve_inline_candidates_with_anchors(
            &analysis(vec![anchored_finding]),
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert!(!candidates[0].eligible);
        assert_eq!(
            candidates[0].reason,
            InlineEligibilityReason::InvalidAnchorId
        );
    }

    #[test]
    fn missing_anchor_id_falls_back_to_file_path_and_line() {
        let diff = diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new");
        let anchors = anchored_context(&diff);
        let candidates = super::resolve_inline_candidates_with_anchors(
            &analysis(vec![finding(
                Severity::High,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(2),
            )]),
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert!(candidates[0].eligible);
        assert_eq!(candidates[0].position.as_ref().unwrap().new_line, Some(2));
    }

    #[test]
    fn generated_file_rejected() {
        assert_reason(
            MergeRequestDiff {
                generated_file: Some(true),
                ..diff("src/generated.rs", "@@ -1 +1 @@\n-old\n+new")
            },
            "src/generated.rs",
            InlineEligibilityReason::GeneratedFile,
        );
    }

    #[test]
    fn collapsed_file_rejected() {
        assert_reason(
            MergeRequestDiff {
                collapsed: Some(true),
                ..diff("src/collapsed.rs", "@@ -1 +1 @@\n-old\n+new")
            },
            "src/collapsed.rs",
            InlineEligibilityReason::CollapsedFile,
        );
    }

    #[test]
    fn too_large_file_rejected() {
        assert_reason(
            MergeRequestDiff {
                too_large: Some(true),
                ..diff("src/large.rs", "@@ -1 +1 @@\n-old\n+new")
            },
            "src/large.rs",
            InlineEligibilityReason::TooLargeFile,
        );
    }

    #[test]
    fn missing_diff_refs_rejected() {
        let analysis = analysis(vec![finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(1),
        )]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1 @@\n-old\n+new")],
            None,
            &inline_config(8, 5),
        );

        assert_eq!(
            candidates[0].reason,
            InlineEligibilityReason::MissingDiffRefs
        );
    }

    #[test]
    fn severity_low_rejected() {
        let candidate = single_candidate(Severity::Low, Effort::Quick, true);

        assert_eq!(candidate.reason, InlineEligibilityReason::SeverityTooLow);
    }

    #[test]
    fn note_rejected() {
        let candidate = single_candidate(Severity::Note, Effort::Quick, true);

        assert_eq!(candidate.reason, InlineEligibilityReason::SeverityTooLow);
    }

    #[test]
    fn heavy_effort_does_not_block_inline_eligibility() {
        let candidate = single_candidate(Severity::High, Effort::Heavy, true);

        assert!(candidate.eligible);
    }

    #[test]
    fn not_actionable_rejected() {
        let candidate = single_candidate(Severity::High, Effort::Quick, false);

        assert_eq!(candidate.reason, InlineEligibilityReason::NotActionable);
    }

    #[test]
    fn needs_manual_confirmation_is_not_inline_candidate() {
        let mut finding = finding(
            Severity::Medium,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(1),
        );
        finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
        let analysis = analysis(vec![finding]);

        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1 @@\n-old\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        assert_eq!(
            candidates[0].reason,
            InlineEligibilityReason::NeedsManualConfirmation
        );
    }

    #[test]
    fn normalized_positive_notes_are_not_inline_candidates() {
        let mut positive = finding(
            Severity::Critical,
            Effort::Moderate,
            true,
            Some("src/a.rs"),
            Some(1),
        );
        positive.title = "Positive: Credentials removed from Redux state".to_string();
        positive.body = "This change improves credential handling.".to_string();
        positive.suggested_fix = Some("No action needed".to_string());
        let analysis = normalize_review_analysis(analysis(vec![positive]));

        let candidate = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1 @@\n-old\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        )
        .remove(0);

        assert!(!candidate.eligible);
        assert_eq!(candidate.severity, Severity::Note);
        assert_eq!(candidate.reason, InlineEligibilityReason::SeverityTooLow);
    }

    #[test]
    fn inline_candidates_use_post_validation_severity() {
        let diff = diff("src/a.rs", "@@ -0,0 +1 @@\n+const enabled = true");
        let anchors = anchored_context(&diff);
        let mut timeout = finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(1),
        );
        timeout.risk_code = Some(RiskCode::MissingTimeout);
        timeout.anchor_id = Some("A0001".to_string());
        timeout.title = "HTTP request has no timeout".to_string();
        timeout.body = "The request can hang indefinitely.".to_string();
        timeout.suggested_fix = Some("Add a timeout.".to_string());
        let analysis = validate_review_analysis_evidence(analysis(vec![timeout]), &anchors);

        let candidate = super::resolve_inline_candidates_with_anchors(
            &analysis,
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        )
        .remove(0);

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert_eq!(candidate.severity, Severity::Medium);
    }

    #[test]
    fn unvalidated_build_break_finding_is_not_inline_candidate() {
        let diff = diff("src/app.kt", "@@ -0,0 +1 @@\n+return enabled");
        let anchors = anchored_context(&diff);
        let mut build_break = finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/app.kt"),
            Some(1),
        );
        build_break.anchor_id = Some("A0001".to_string());
        build_break.title = "Invalid Kotlin syntax will break android build".to_string();
        build_break.body = "The line contains `return @../../tmp false`.".to_string();
        build_break.suggested_fix = Some("Use a valid Kotlin labeled return.".to_string());
        let analysis = validate_review_analysis_evidence(analysis(vec![build_break]), &anchors);

        let candidate = super::resolve_inline_candidates_with_anchors(
            &analysis,
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        )
        .remove(0);

        assert_eq!(analysis.findings[0].severity, Severity::Low);
        assert!(!candidate.eligible);
        assert_eq!(candidate.reason, InlineEligibilityReason::SeverityTooLow);
    }

    #[test]
    fn max_high_limit_enforced() {
        let analysis = analysis(vec![
            finding(
                Severity::High,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(1),
            ),
            finding(
                Severity::High,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(2),
            ),
        ]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -0,0 +1,2 @@\n+one\n+two")],
            Some(&diff_refs()),
            &inline_config(1, 5),
        );

        assert!(candidates[0].eligible);
        assert_eq!(
            candidates[1].reason,
            InlineEligibilityReason::MaxInlineLimitReached
        );
    }

    #[test]
    fn max_medium_limit_enforced() {
        let analysis = analysis(vec![
            finding(
                Severity::Medium,
                Effort::Moderate,
                true,
                Some("src/a.rs"),
                Some(1),
            ),
            finding(
                Severity::Medium,
                Effort::Moderate,
                true,
                Some("src/a.rs"),
                Some(2),
            ),
        ]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -0,0 +1,2 @@\n+one\n+two")],
            Some(&diff_refs()),
            &inline_config(8, 1),
        );

        assert!(candidates[0].eligible);
        assert_eq!(
            candidates[1].reason,
            InlineEligibilityReason::MaxInlineLimitReached
        );
    }

    #[test]
    fn inline_report_formatting() {
        let analysis = analysis(vec![
            finding(
                Severity::High,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(2),
            ),
            finding(
                Severity::Low,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(1),
            ),
        ]);
        let candidates = resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1,2 @@\n old\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        let report = format_inline_dry_run_report_with_emoji(&candidates, true);

        assert!(report.contains("Inline dry-run report:"));
        assert!(report.contains("Eligible inline candidates: 1"));
        assert!(report.contains("Fallback to summary: 1"));
        assert!(report.contains("- 🟠 HIGH · ⚡ Quick fix · src/a.rs:2"));
        assert!(report.contains("Title: finding"));
        assert!(report.contains("Position: new_path=src/a.rs new_line=2 old_line=none"));
        assert!(report.contains("- 🟢 LOW · ⚡ Quick fix · src/a.rs:1"));
        assert!(report.contains("Reason: severity too low"));
    }

    #[test]
    fn inline_report_can_disable_emoji() {
        let candidates = resolve_inline_candidates(
            &analysis(vec![finding(
                Severity::High,
                Effort::Quick,
                true,
                Some("src/a.rs"),
                Some(1),
            )]),
            &[diff("src/a.rs", "@@ -0,0 +1 @@\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        let report = format_inline_dry_run_report_with_emoji(&candidates, false);

        assert!(report.contains("- HIGH · Quick fix · src/a.rs:1"));
        assert!(!report.contains("🟠"));
    }

    #[test]
    fn inline_report_includes_anchor_id() {
        let diff = diff("src/a.rs", "@@ -0,0 +1 @@\n+new");
        let anchors = anchored_context(&diff);
        let mut anchored_finding = finding(
            Severity::High,
            Effort::Quick,
            true,
            Some("src/a.rs"),
            Some(1),
        );
        anchored_finding.anchor_id = Some("A0001".to_string());
        let candidates = super::resolve_inline_candidates_with_anchors(
            &analysis(vec![anchored_finding]),
            &[diff],
            Some(&anchors),
            Some(&diff_refs()),
            &inline_config(8, 5),
        );

        let report = format_inline_dry_run_report_with_emoji(&candidates, true);

        assert!(report.contains("- 🟠 HIGH · ⚡ Quick fix · src/a.rs:1 anchor=A0001"));
    }

    fn assert_reason(diff: MergeRequestDiff, path: &str, reason: InlineEligibilityReason) {
        let analysis = analysis(vec![finding(
            Severity::High,
            Effort::Quick,
            true,
            Some(path),
            Some(1),
        )]);
        let candidates =
            resolve_inline_candidates(&analysis, &[diff], Some(&diff_refs()), &inline_config(8, 5));

        assert_eq!(candidates[0].reason, reason);
    }

    fn single_candidate(
        severity: Severity,
        effort: Effort,
        actionable: bool,
    ) -> super::InlineCandidate {
        let analysis = analysis(vec![finding(
            severity,
            effort,
            actionable,
            Some("src/a.rs"),
            Some(1),
        )]);
        resolve_inline_candidates(
            &analysis,
            &[diff("src/a.rs", "@@ -1 +1 @@\n-old\n+new")],
            Some(&diff_refs()),
            &inline_config(8, 5),
        )
        .remove(0)
    }

    fn analysis(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Medium,
        }
    }

    fn finding(
        severity: Severity,
        effort: Effort,
        actionable: bool,
        file_path: Option<&str>,
        line: Option<u32>,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Correctness,
            risk_code: None,
            anchor_id: None,
            file_path: file_path.map(str::to_string),
            line,
            title: "finding".to_string(),
            body: "body".to_string(),
            suggested_fix: None,
            effort,
            actionable,
            evidence_status: None,
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

    fn anchored_context(diff: &MergeRequestDiff) -> crate::review::anchors::AnchoredDiffContext {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(diff);
        builder.finish(false)
    }

    fn diff_refs() -> DiffRefs {
        DiffRefs {
            base_sha: Some("base".to_string()),
            start_sha: Some("start".to_string()),
            head_sha: Some("head".to_string()),
        }
    }

    fn inline_config(max_high_inline: usize, max_medium_inline: usize) -> InlineConfig {
        InlineConfig {
            enabled: false,
            dry_run: true,
            dedupe: true,
            max_inline_total: 10,
            max_high_inline,
            max_medium_inline,
        }
    }
}
