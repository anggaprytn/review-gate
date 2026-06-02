use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
    counters::{count_findings_from_analysis, emoji_enabled, format_finding_counters_markdown},
    review::{
        parser::ReviewParseError,
        types::{EvidenceValidationStatus, ReviewAnalysis, ReviewFinding, RiskCode, Severity},
    },
};
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkdownRenderMode {
    Preview,
    Publish,
}

pub fn format_review_markdown(analysis: &ReviewAnalysis) -> String {
    format_review_markdown_for_mode(analysis, MarkdownRenderMode::Publish)
}

pub fn format_review_markdown_with_emoji(analysis: &ReviewAnalysis, emoji: bool) -> String {
    format_review_markdown_for_mode_with_emoji(analysis, MarkdownRenderMode::Publish, emoji)
}

pub fn format_review_markdown_for_mode(
    analysis: &ReviewAnalysis,
    mode: MarkdownRenderMode,
) -> String {
    format_review_markdown_for_mode_with_emoji(analysis, mode, emoji_enabled())
}

pub fn format_review_markdown_for_mode_with_emoji(
    analysis: &ReviewAnalysis,
    mode: MarkdownRenderMode,
    emoji: bool,
) -> String {
    let sorted_findings = sorted_findings(&analysis.findings);
    let sorted_findings = match mode {
        MarkdownRenderMode::Preview => sorted_findings,
        MarkdownRenderMode::Publish => sorted_findings
            .into_iter()
            .filter(|finding| !suppressed_current_file_invalidated_finding(finding))
            .collect(),
    };
    let mut output = String::new();

    output.push_str("# ReviewGate AI Code Review\n\n");
    output.push_str(&format_finding_counters_markdown(
        &count_findings_from_analysis(analysis),
        emoji,
    ));
    output.push('\n');
    output.push_str("## Summary\n\n");
    output.push_str(&format_summary_note(&analysis.summary, mode));
    output.push_str("\n\n");
    output.push_str("## Overall Risk\n\n");
    output.push_str(&analysis.overall_risk.display_label(emoji));
    output.push_str("\n\n");
    output.push_str(&format!(
        "## {}\n\n",
        Severity::Critical.section_label_with_emoji(emoji)
    ));
    push_severity_section(
        &mut output,
        &sorted_findings,
        &[Severity::Critical],
        mode,
        emoji,
    );
    output.push_str(&format!(
        "\n## {}\n\n",
        Severity::High.section_label_with_emoji(emoji)
    ));
    push_severity_section(
        &mut output,
        &sorted_findings,
        &[Severity::High],
        mode,
        emoji,
    );
    output.push_str(&format!(
        "\n## {}\n\n",
        Severity::Medium.section_label_with_emoji(emoji)
    ));
    push_severity_section(
        &mut output,
        &sorted_findings,
        &[Severity::Medium],
        mode,
        emoji,
    );
    output.push_str("\n## ");
    if emoji && mode == MarkdownRenderMode::Preview {
        output.push_str("🟢 Low / 🔵 Notes\n\n");
    } else {
        output.push_str("Low / Notes\n\n");
    }
    push_severity_section(
        &mut output,
        &sorted_findings,
        &[Severity::Low, Severity::Note],
        mode,
        emoji,
    );
    output.push_str("\n## Test Coverage\n\n");
    output.push_str(&format_test_coverage_note(
        analysis.test_coverage_note.as_deref(),
        mode,
    ));
    output.push_str("\n\n## Privacy\n\n");
    output.push_str(&format_privacy_note(analysis.privacy_note.as_deref(), mode));
    output.push_str("\n\n");
    output.push_str(REVIEWGATE_ATTRIBUTION);
    output.push('\n');

    output
}

pub fn format_malformed_review_markdown(raw_model_text: &str, error: &ReviewParseError) -> String {
    let raw_model_text = scrub_confidence_from_raw_text(raw_model_text);
    format!(
        r#"# ReviewGate AI Code Review

## Warning

The model response could not be parsed as structured ReviewGate JSON: {error}

## Raw Model Response

````text
{raw_model_text}
````

{attribution}
"#,
        attribution = REVIEWGATE_ATTRIBUTION
    )
}

pub fn sorted_findings(findings: &[ReviewFinding]) -> Vec<&ReviewFinding> {
    let mut sorted: Vec<&ReviewFinding> = findings.iter().collect();
    sorted.sort_by(|left, right| {
        left.severity
            .sort_key()
            .cmp(&right.severity.sort_key())
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.title.cmp(&right.title))
    });
    sorted
}

fn push_severity_section(
    output: &mut String,
    sorted_findings: &[&ReviewFinding],
    severities: &[Severity],
    mode: MarkdownRenderMode,
    emoji: bool,
) {
    let section_findings: Vec<&ReviewFinding> = sorted_findings
        .iter()
        .copied()
        .filter(|finding| severities.contains(&finding.severity))
        .collect();

    if section_findings.is_empty() {
        output.push_str(no_findings_line(severities));
        output.push('\n');
        return;
    }

    if severities == [Severity::Low, Severity::Note] {
        match mode {
            MarkdownRenderMode::Preview => push_findings(output, &section_findings, emoji),
            MarkdownRenderMode::Publish => push_compact_low_note_section(output, &section_findings),
        }
        return;
    }

    push_findings(output, &section_findings, emoji);
}

fn push_compact_low_note_section(output: &mut String, section_findings: &[&ReviewFinding]) {
    let low_count = section_findings
        .iter()
        .filter(|finding| finding.severity == Severity::Low)
        .count();
    let note_count = section_findings
        .iter()
        .filter(|finding| finding.severity == Severity::Note)
        .count();

    if low_count == 0 && note_count == 0 {
        output.push_str("No low-priority findings or notes.\n");
        return;
    }

    output.push_str(&format!(
        "{} and {} were summarized only.\n",
        pluralize(low_count, "low-priority finding", "low-priority findings"),
        pluralize(note_count, "note", "notes")
    ));

    let positive_notes = compact_positive_notes(section_findings, 3);
    if !positive_notes.is_empty() {
        output.push_str("\nPositive notes:\n");
        for note in positive_notes {
            output.push_str("- ");
            output.push_str(&note);
            output.push('\n');
        }
    }

    output.push_str(
        "\nRun `reviewgate review <MR_URL> --preview --include-low-risk` or inspect SQLite history for full details.\n",
    );
}

fn push_findings(output: &mut String, findings: &[&ReviewFinding], emoji: bool) {
    for (index, finding) in findings.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        push_finding(output, finding, emoji);
    }
}

fn push_finding(output: &mut String, finding: &ReviewFinding, emoji: bool) {
    output.push_str("### ");
    output.push_str(&finding_heading(finding, emoji));
    output.push_str("\n\n");
    output.push_str("**");
    output.push_str(blank_fallback(&finding.title, "Untitled finding"));
    output.push_str("**\n\n");
    output.push_str(blank_fallback(&finding.body, "No details returned."));
    output.push_str("\n\n");
    if let Some(suggested_fix) = renderable_suggested_fix(finding) {
        output.push_str(suggested_fix_label(finding, suggested_fix));
        output.push_str(":\n");
        output.push_str(suggested_fix);
        output.push_str("\n\n");
    }
    output.push_str("Category: ");
    output.push_str(finding.category.display_lower());
    if let Some(risk_code) = finding.risk_code {
        output.push_str("\nRisk code: ");
        output.push_str(risk_code.display_lower());
    }
    if finding.severity == Severity::Low || finding.severity == Severity::Note {
        output.push_str("\n\nPreview only: low and note findings are not inline-ready in v0.1.");
    }
    output.push('\n');
}

fn finding_heading(finding: &ReviewFinding, emoji: bool) -> String {
    let mut parts = vec![
        finding.severity.display_label(emoji),
        finding.effort.display_label(emoji),
    ];
    match (finding.file_path.as_deref(), finding.line) {
        (Some(path), Some(line)) if !path.trim().is_empty() => {
            parts.push(format!("{}:{}", path.trim(), line));
        }
        (Some(path), None) if !path.trim().is_empty() => {
            parts.push(path.trim().to_string());
        }
        _ => {}
    }
    parts.join(" · ")
}

fn no_findings_line(severities: &[Severity]) -> &'static str {
    match severities {
        [Severity::Critical] => "No critical findings.",
        [Severity::High] => "No high findings.",
        [Severity::Medium] => "No medium findings.",
        [Severity::Low, Severity::Note] => "No low or note findings.",
        _ => "No findings.",
    }
}

fn blank_fallback<'a>(value: &'a str, fallback: &'static str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn format_summary_note(summary: &str, mode: MarkdownRenderMode) -> String {
    let fallback = blank_fallback(summary, "No summary returned.");
    if mode == MarkdownRenderMode::Preview {
        return fallback.to_string();
    }

    let lines = fallback
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    let mut overview = None;
    let mut bullets = Vec::new();
    let mut caveat = None;
    let mut seen_bullets = HashSet::new();

    for line in lines {
        let stripped = line
            .trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_whitespace())
            .trim();
        if stripped.is_empty() || stripped.eq_ignore_ascii_case("main risks found:") {
            continue;
        }
        let sentence = sentence_from_text(stripped);
        let lower = sentence.to_ascii_lowercase();
        if lower.contains("partial")
            || lower.contains("risk-prioritized review")
            || lower.contains("not a full exhaustive review")
            || lower.contains("not a full-file exhaustive review")
        {
            caveat.get_or_insert(sentence);
            continue;
        }
        if line.starts_with('-') || line.starts_with('*') {
            let key = normalize_sentence_key(&sentence);
            if !key.is_empty() && seen_bullets.insert(key) && bullets.len() < 5 {
                bullets.push(sentence);
            }
            continue;
        }
        if overview.is_none() {
            overview = Some(sentence);
        } else if bullets.len() < 5 {
            let key = normalize_sentence_key(&sentence);
            if !key.is_empty() && seen_bullets.insert(key) {
                bullets.push(sentence);
            }
        }
    }

    let mut output = overview.unwrap_or_else(|| "No summary returned.".to_string());
    if !bullets.is_empty() {
        output.push_str("\n\nMain risks found:\n");
        for bullet in bullets {
            output.push_str("- ");
            output.push_str(&bullet);
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

fn renderable_suggested_fix(finding: &ReviewFinding) -> Option<&str> {
    if !finding.actionable
        || finding.severity == Severity::Note
        || finding.risk_code == Some(RiskCode::PositiveNote)
    {
        return None;
    }
    finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| {
            let normalized = value
                .trim_matches(|ch: char| ch.is_ascii_punctuation() || ch.is_whitespace())
                .to_ascii_lowercase();
            !matches!(
                normalized.as_str(),
                "no action needed" | "none" | "n/a" | "na"
            )
        })
}

fn suggested_fix_label(finding: &ReviewFinding, suggested_fix: &str) -> &'static str {
    if finding.severity == Severity::Low && is_broad_process_suggested_fix(suggested_fix) {
        "Suggested follow-up"
    } else {
        "Suggested fix"
    }
}

fn is_broad_process_suggested_fix(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    ["ensure", "consider", "audit", "review", "make sure"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn compact_positive_notes(findings: &[&ReviewFinding], limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut notes = Vec::new();
    for finding in findings.iter().copied().filter(|finding| {
        finding.severity == Severity::Note
            && finding.risk_code == Some(RiskCode::PositiveNote)
            && !matches!(
                finding.evidence_status,
                Some(
                    crate::review::types::EvidenceValidationStatus::StaleContext
                        | crate::review::types::EvidenceValidationStatus::WeakEvidence
                        | crate::review::types::EvidenceValidationStatus::NeedsManualConfirmation
                )
            )
    }) {
        let sentence = sentence_from_text(&finding.title);
        let key = normalize_sentence_key(&sentence);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        notes.push(sentence);
        if notes.len() >= limit {
            break;
        }
    }
    notes
}

fn suppressed_current_file_invalidated_finding(finding: &ReviewFinding) -> bool {
    !finding.actionable
        && matches!(
            finding.evidence_status,
            Some(
                EvidenceValidationStatus::StaleContext
                    | EvidenceValidationStatus::WeakEvidence
                    | EvidenceValidationStatus::NeedsManualConfirmation
            )
        )
        && finding
            .evidence_reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("current-file validation:"))
}

fn format_test_coverage_note(note: Option<&str>, mode: MarkdownRenderMode) -> String {
    if mode == MarkdownRenderMode::Preview {
        return note
            .map(|note| blank_fallback(note, "No specific test coverage note.").to_string())
            .unwrap_or_else(|| "No specific test coverage note.".to_string());
    }

    let text = note.unwrap_or_default();
    let raw_items = split_note_items(text);
    let has_generic_no_tests = raw_items
        .iter()
        .map(|item| sentence_from_text(item))
        .any(|item| is_generic_no_tests_item(&item));
    let items = useful_note_items(text, 8, is_generic_test_coverage_item);
    if items.is_empty() {
        return if has_generic_no_tests {
            "ReviewGate did not find visible tests for the reviewed high-risk changes.".to_string()
        } else {
            "No specific test coverage gaps were detected from the reviewed diff.".to_string()
        };
    }

    let mut gaps = Vec::new();
    let mut positives = Vec::new();
    for item in items {
        if is_positive_test_coverage_item(&item) {
            positives.push(item);
        } else {
            gaps.push(item);
        }
    }

    let mut output = String::new();
    if !gaps.is_empty() {
        output.push_str("Coverage gaps:\n");
        for gap in gaps.into_iter().take(4) {
            output.push_str("- ");
            output.push_str(&gap);
            output.push('\n');
        }
    }
    if !positives.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("Positive:\n");
        for positive in positives.into_iter().take(2) {
            output.push_str("- ");
            output.push_str(&positive);
            output.push('\n');
        }
    }

    output.trim_end().to_string()
}

fn format_privacy_note(note: Option<&str>, mode: MarkdownRenderMode) -> String {
    if mode == MarkdownRenderMode::Preview {
        return note
            .map(|note| blank_fallback(note, "No specific privacy note.").to_string())
            .unwrap_or_else(|| "No specific privacy note.".to_string());
    }

    let items = useful_note_items(note.unwrap_or_default(), 8, is_generic_privacy_item);
    if items.is_empty() {
        return "No obvious new PII or secret exposure detected.".to_string();
    }

    let mut positives = Vec::new();
    let mut risks = Vec::new();
    for item in items {
        if is_no_secret_or_pii_item(&item) {
            continue;
        } else if is_positive_privacy_item(&item) {
            positives.push(sanitize_privacy_item(&item));
        } else {
            risks.push(sanitize_privacy_item(&item));
        }
    }

    let mut output = if risks.is_empty() {
        "No obvious new PII or secret exposure detected.".to_string()
    } else {
        "Potential privacy risks were detected in reviewed chunks.".to_string()
    };
    if !risks.is_empty() {
        output.push_str("\n\nPrivacy risks:\n");
        for item in risks.into_iter().take(3) {
            output.push_str("- ");
            output.push_str(&item);
            output.push('\n');
        }
        output = output.trim_end().to_string();
    }
    if !positives.is_empty() {
        output.push_str("\n\nPrivacy-positive changes:\n");
        for item in positives.into_iter().take(3) {
            output.push_str("- ");
            output.push_str(&item);
            output.push('\n');
        }
    }
    output.trim_end().to_string()
}

fn useful_note_items(text: &str, limit: usize, is_generic: impl Fn(&str) -> bool) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for item in split_note_items(text) {
        let sentence = sentence_from_text(&item);
        if is_generic(&sentence) {
            continue;
        }
        let key = normalize_sentence_key(&sentence);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        items.push(sentence);
        if items.len() >= limit {
            break;
        }
    }
    items
}

fn split_note_items(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in text.lines() {
        let line = line
            .trim()
            .trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_whitespace())
            .trim();
        if line.is_empty() {
            continue;
        }
        for part in line.split(['.', '!', '?']) {
            let part = part.trim();
            if !part.is_empty() {
                items.push(part.to_string());
            }
        }
    }
    items
}

fn sentence_from_text(text: &str) -> String {
    let mut sentence = text
        .trim()
        .trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_whitespace())
        .trim()
        .to_string();
    if sentence.is_empty() {
        return sentence;
    }
    if !matches!(sentence.chars().last(), Some('.') | Some('!') | Some('?')) {
        sentence.push('.');
    }
    sentence
}

fn normalize_sentence_key(sentence: &str) -> String {
    sentence
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn is_generic_test_coverage_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    is_generic_no_tests_item(item)
        || lower.contains("cannot be assessed")
        || lower.contains("should be thoroughly tested")
        || lower == "recommended to add tests."
        || lower == "add tests."
}

fn is_positive_test_coverage_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    let uncertain_or_negative = [
        "no ",
        "not ",
        "without ",
        "missing ",
        "needs ",
        "need ",
        "should ",
        "cannot ",
        "unclear ",
        "recommended ",
        "recommend ",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    !uncertain_or_negative
        && (lower.contains("has unit test")
            || lower.contains("has tests")
            || lower.contains("tests were added")
            || lower.contains("test was added")
            || lower.contains("unit tests cover")
            || lower.contains("integration tests cover")
            || lower.contains("covered by"))
}

fn is_generic_no_tests_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    lower.contains("no tests are visible in this chunk")
        || lower.contains("no tests are visible")
        || lower.contains("did not find visible tests")
}

fn is_no_secret_or_pii_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    lower.contains("no obvious")
        && (lower.contains("secret") || lower.contains("pii"))
        && (lower.contains("exposure") || lower.contains("detected"))
}

fn is_positive_privacy_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    [
        "redacted",
        "wiped",
        "cleared",
        "removed",
        "disabled cleartext",
        "cache-backed",
        "cache storage",
        "cleanup",
        "sensitive",
        "secure",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_generic_privacy_item(item: &str) -> bool {
    let lower = item.to_ascii_lowercase();
    lower.contains("privacy improvement")
        || lower.contains("privacy-positive change")
        || lower.contains("good privacy practice")
}

fn sanitize_privacy_item(item: &str) -> String {
    let mut cleaned = item.to_string();
    for word in [
        "strong",
        "strongly",
        "excellent",
        "commendable",
        "crucial",
        "significant",
    ] {
        cleaned = Regex::new(&format!(r"(?i)\b{}\b\s*", regex::escape(word)))
            .expect("privacy fluff regex compiles")
            .replace_all(&cleaned, "")
            .to_string();
    }
    sentence_from_text(&cleaned)
}

fn scrub_confidence_from_raw_text(value: &str) -> String {
    let json_confidence = Regex::new(r#"(?m)^\s*"confidence"\s*:\s*"[^"]*",?\s*$"#)
        .expect("confidence scrub regex compiles");
    let markdown_confidence =
        Regex::new(r#"(?im)^\s*confidence\s*:\s*[^\n\r]+$"#).expect("confidence regex compiles");
    let without_json = json_confidence.replace_all(value, "");
    markdown_confidence
        .replace_all(&without_json, "")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        format_malformed_review_markdown, format_review_markdown_for_mode_with_emoji,
        format_review_markdown_with_emoji, sorted_findings, MarkdownRenderMode,
    };
    use crate::{
        gitlab::types::MergeRequestDiff,
        review::{
            anchors::AnchorBuilder,
            evidence::validate_review_analysis_evidence,
            parser::ReviewParseError,
            types::{
                Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode,
                Severity,
            },
        },
    };

    #[test]
    fn sorts_findings_by_severity_order() {
        let findings = vec![
            finding(Severity::Note, "note"),
            finding(Severity::Medium, "medium"),
            finding(Severity::Critical, "critical"),
            finding(Severity::High, "high"),
            finding(Severity::Low, "low"),
        ];

        let sorted = sorted_findings(&findings);

        assert_eq!(
            sorted
                .iter()
                .map(|finding| finding.severity)
                .collect::<Vec<_>>(),
            vec![
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Note
            ]
        );
    }

    #[test]
    fn formats_reviewgate_markdown_by_group() {
        let markdown = format_review_markdown_with_emoji(
            &ReviewAnalysis {
                summary: "Payment callback risk found.".to_string(),
                findings: vec![ReviewFinding {
                    severity: Severity::High,
                    category: ReviewCategory::Reliability,
                    risk_code: Some(RiskCode::MissingTimeout),
                    anchor_id: None,
                    file_path: Some("src/payment/client.ts".to_string()),
                    line: Some(42),
                    title: "HTTP request has no timeout".to_string(),
                    body: "The new callback call can hang indefinitely.".to_string(),
                    suggested_fix: Some("Use a request-scoped timeout.".to_string()),
                    effort: Effort::Quick,
                    actionable: true,
                    evidence_status: None,
                    evidence_reason: None,
                }],
                test_coverage_note: Some("No test covers timeout behavior.".to_string()),
                privacy_note: Some("No obvious exposure detected.".to_string()),
                overall_risk: OverallRisk::Medium,
            },
            true,
        );

        assert!(markdown.contains("# ReviewGate AI Code Review"));
        assert!(markdown.contains("## Finding Summary"));
        assert!(markdown.contains("Open priority findings: 1"));
        assert!(!markdown.contains("Open actionable findings"));
        assert!(markdown.contains("| 🟠 High | 1 |"));
        assert!(markdown.contains("## Overall Risk\n\n🟡 Medium"));
        assert!(markdown.contains("## 🔴 Critical\n\nNo critical findings."));
        assert!(markdown.contains("## 🟠 High"));
        assert!(markdown.contains("### 🟠 HIGH · ⚡ Quick fix · src/payment/client.ts:42"));
        assert!(markdown.contains("**HTTP request has no timeout**"));
        assert!(markdown.contains("Suggested fix:\nUse a request-scoped timeout."));
        assert!(markdown.contains("Risk code: missing_timeout"));
        assert!(!markdown.contains("Confidence:"));
    }

    #[test]
    fn markdown_can_disable_emoji_labels() {
        let markdown = format_review_markdown_with_emoji(
            &ReviewAnalysis {
                summary: "Payment callback risk found.".to_string(),
                findings: vec![ReviewFinding {
                    severity: Severity::High,
                    category: ReviewCategory::Reliability,
                    risk_code: None,
                    anchor_id: None,
                    file_path: Some("src/payment/client.ts".to_string()),
                    line: Some(42),
                    title: "HTTP request has no timeout".to_string(),
                    body: "The new callback call can hang indefinitely.".to_string(),
                    suggested_fix: None,
                    effort: Effort::Quick,
                    actionable: true,
                    evidence_status: None,
                    evidence_reason: None,
                }],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Medium,
            },
            false,
        );

        assert!(markdown.contains("## High"));
        assert!(markdown.contains("| High | 1 |"));
        assert!(markdown.contains("### HIGH · Quick fix · src/payment/client.ts:42"));
        assert!(!markdown.contains("🟠"));
    }

    #[test]
    fn malformed_json_fallback_includes_warning_and_raw_text() {
        let markdown =
            format_malformed_review_markdown("plain text output", &ReviewParseError::new("bad"));

        assert!(markdown.contains("could not be parsed"));
        assert!(markdown.contains("plain text output"));
    }

    #[test]
    fn malformed_json_fallback_does_not_surface_confidence() {
        let markdown = format_malformed_review_markdown(
            r#"{
              "summary": "bad",
              "confidence": "high"
            }
            Confidence: high"#,
            &ReviewParseError::new("bad"),
        );

        assert!(!markdown.contains("confidence"));
        assert!(!markdown.contains("Confidence:"));
    }

    #[test]
    fn low_and_note_details_are_collapsed_in_published_markdown() {
        let findings = (0..4)
            .map(|index| finding(Severity::Low, &format!("low {index}")))
            .chain((0..5).map(|index| finding(Severity::Note, &format!("note {index}"))))
            .collect::<Vec<_>>();
        let markdown = format_review_markdown_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings,
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            false,
        );

        assert_eq!(markdown.matches("### LOW").count(), 0);
        assert_eq!(markdown.matches("### NOTE").count(), 0);
        assert!(markdown.contains("4 low-priority findings and 5 notes were summarized only."));
        assert!(markdown.contains(
            "Run `reviewgate review <MR_URL> --preview --include-low-risk` or inspect SQLite history for full details."
        ));
    }

    #[test]
    fn preview_markdown_can_include_low_and_note_details() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![
                    finding(Severity::Low, "low"),
                    finding(Severity::Note, "note"),
                ],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Preview,
            false,
        );

        assert_eq!(markdown.matches("### LOW").count(), 1);
        assert_eq!(markdown.matches("### NOTE").count(), 1);
    }

    #[test]
    fn published_markdown_does_not_show_unvalidated_high_build_break() {
        let mut build_break = finding(
            Severity::High,
            "Invalid Kotlin syntax will break android build",
        );
        build_break.category = ReviewCategory::Correctness;
        build_break.file_path = Some("src/app.kt".to_string());
        build_break.line = Some(1);
        build_break.anchor_id = Some("A0001".to_string());
        build_break.body = "The line contains `return @../../tmp false`.".to_string();
        build_break.suggested_fix = Some("Use a valid Kotlin labeled return.".to_string());
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff("src/app.kt", "@@ -0,0 +1 @@\n+return enabled"));
        let anchors = builder.finish(false);
        let analysis = validate_review_analysis_evidence(
            ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![build_break],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::High,
            },
            &anchors,
        );

        let markdown = format_review_markdown_for_mode_with_emoji(
            &analysis,
            MarkdownRenderMode::Publish,
            false,
        );

        assert!(markdown.contains("| High | 0 |"));
        assert!(markdown.contains("Open priority findings: 0"));
        assert!(markdown.contains("## High\n\nNo high findings."));
        assert!(!markdown.contains("### HIGH"));
        assert!(!markdown.contains("Invalid Kotlin syntax will break android build"));
    }

    #[test]
    fn non_actionable_note_and_positive_note_hide_suggested_fix() {
        let mut non_actionable = finding(Severity::Medium, "non-actionable");
        non_actionable.actionable = false;
        non_actionable.suggested_fix = Some("No action needed".to_string());
        let mut note = finding(Severity::Note, "note");
        note.suggested_fix = Some("None".to_string());
        let mut positive = finding(Severity::Note, "positive");
        positive.risk_code = Some(RiskCode::PositiveNote);
        positive.suggested_fix = Some("No action needed".to_string());

        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![non_actionable, note, positive],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Medium,
            },
            MarkdownRenderMode::Preview,
            false,
        );

        assert!(!markdown.contains("Suggested fix:\nNo action needed"));
        assert!(!markdown.contains("Suggested fix:\nNone"));
    }

    #[test]
    fn compact_test_coverage_removes_repeated_chunk_noise() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![],
                test_coverage_note: Some(
                    "Device integrity flows need tests. No tests are visible in this chunk. authTokenStorage has unit tests. Device integrity flows need tests."
                        .to_string(),
                ),
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );

        assert!(markdown.contains("Coverage gaps:\n- Device integrity flows need tests."));
        assert_eq!(
            markdown
                .matches("Device integrity flows need tests.")
                .count(),
            1
        );
        assert!(markdown.contains("Positive:\n- authTokenStorage has unit tests."));
        assert!(!markdown.contains("No tests are visible in this chunk"));
        assert!(!markdown.contains("cannot be assessed"));
    }

    #[test]
    fn compact_test_coverage_moves_uncertain_text_to_gaps_and_caps_sections() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![],
                test_coverage_note: Some(
                    "Positive: Native security modules may not be tested. authTokenStorage has unit tests. Upload cleanup needs regression tests. Compromised-device flows should be tested across failure scenarios. Redux security state needs integration tests. Token rotation has tests. Another module has tests."
                        .to_string(),
                ),
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );
        let section = markdown_section(&markdown, "## Test Coverage");

        assert!(section.contains("Coverage gaps:"));
        assert!(section.contains("- Positive: Native security modules may not be tested."));
        assert!(section.contains("- Upload cleanup needs regression tests."));
        assert!(section.contains("Positive:\n- authTokenStorage has unit tests."));
        assert!(section.contains("- Token rotation has tests."));
        assert!(!section.contains("- Another module has tests."));
    }

    #[test]
    fn compact_test_coverage_reports_only_generic_no_tests_once() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![],
                test_coverage_note: Some(
                    "No tests are visible in this chunk. No tests are visible in this chunk."
                        .to_string(),
                ),
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );

        assert!(markdown
            .contains("ReviewGate did not find visible tests for the reviewed high-risk changes."));
        assert_eq!(
            markdown
                .matches("No tests are visible in this chunk")
                .count(),
            0
        );
    }

    #[test]
    fn compact_privacy_collapses_repeated_no_pii_statements() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![],
                test_coverage_note: None,
                privacy_note: Some(
                    "No obvious secret or PII exposure detected. No obvious secret or PII exposure detected. Local session data is wiped on compromised environment detection."
                        .to_string(),
                ),
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );

        assert_eq!(
            markdown
                .matches("No obvious new PII or secret exposure detected.")
                .count(),
            1
        );
        assert!(markdown.contains(
            "Privacy-positive changes:\n- Local session data is wiped on compromised environment detection."
        ));
    }

    #[test]
    fn compact_privacy_starts_with_status_and_caps_factual_positives() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![],
                test_coverage_note: None,
                privacy_note: Some(
                    "No obvious secret or PII exposure detected. Authorization and Cookie headers are strongly redacted from Chucker. Upload temp files now use cache storage and cleanup paths. This is an excellent privacy improvement. Session cleanup is commendable."
                        .to_string(),
                ),
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );
        let section = markdown_section(&markdown, "## Privacy");

        assert!(section.starts_with("No obvious new PII or secret exposure detected."));
        assert_eq!(
            section
                .matches("No obvious new PII or secret exposure detected.")
                .count(),
            1
        );
        assert!(section.contains("Privacy-positive changes:"));
        assert!(!section.contains("excellent"));
        assert!(!section.contains("commendable"));
        assert_eq!(section.matches("\n- ").count(), 3);
    }

    #[test]
    fn low_broad_suggested_fix_renders_as_follow_up() {
        let mut low = finding(Severity::Low, "weak low");
        low.suggested_fix = Some("Consider auditing the debug configuration.".to_string());
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![low],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Preview,
            false,
        );

        assert!(
            markdown.contains("Suggested follow-up:\nConsider auditing the debug configuration.")
        );
        assert!(!markdown.contains("Suggested fix:\nConsider auditing the debug configuration."));
    }

    #[test]
    fn published_summary_is_compact() {
        let markdown = format_review_markdown_for_mode_with_emoji(
            &ReviewAnalysis {
                summary: "ReviewGate reviewed 64 risk-prioritized files across 8 chunks.\n\nMain risks found:\n- First risk.\n- Second risk.\n- Third risk.\n- Fourth risk.\n- Fifth risk.\n- Sixth risk.\n\nThis is a partial risk-prioritized review, not a full exhaustive review.\nExtra trailing sentence that should not survive."
                    .to_string(),
                findings: vec![],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::Low,
            },
            MarkdownRenderMode::Publish,
            false,
        );
        let section = markdown_section(&markdown, "## Summary");

        assert!(
            section.starts_with("ReviewGate reviewed 64 risk-prioritized files across 8 chunks.")
        );
        assert!(section.contains("Main risks found:\n- First risk."));
        assert!(section.contains("- Fifth risk."));
        assert!(!section.contains("- Sixth risk."));
        assert!(section
            .contains("This is a partial risk-prioritized review, not a full exhaustive review."));
        assert!(!section.contains("Extra trailing sentence"));
    }

    fn finding(severity: Severity, title: &str) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Correctness,
            risk_code: None,
            anchor_id: None,
            file_path: None,
            line: None,
            title: title.to_string(),
            body: title.to_string(),
            suggested_fix: None,
            effort: Effort::Moderate,
            actionable: true,
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

    fn markdown_section(markdown: &str, heading: &str) -> String {
        let Some((_, rest)) = markdown.split_once(heading) else {
            panic!("missing markdown section {heading}");
        };
        rest.trim_start()
            .split("\n## ")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    }
}
