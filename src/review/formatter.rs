use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
    counters::{count_findings_from_analysis, emoji_enabled, format_finding_counters_markdown},
    review::{
        parser::ReviewParseError,
        types::{ReviewAnalysis, ReviewFinding, Severity},
    },
};
use regex::Regex;

pub fn format_review_markdown(analysis: &ReviewAnalysis) -> String {
    format_review_markdown_with_emoji(analysis, emoji_enabled())
}

pub fn format_review_markdown_with_emoji(analysis: &ReviewAnalysis, emoji: bool) -> String {
    let sorted_findings = sorted_findings(&analysis.findings);
    let mut output = String::new();

    output.push_str("# ReviewGate AI Code Review\n\n");
    output.push_str(&format_finding_counters_markdown(
        &count_findings_from_analysis(analysis),
        emoji,
    ));
    output.push('\n');
    output.push_str("## Summary\n\n");
    output.push_str(blank_fallback(&analysis.summary, "No summary returned."));
    output.push_str("\n\n");
    output.push_str("## Overall Risk\n\n");
    output.push_str(&analysis.overall_risk.display_label(emoji));
    output.push_str("\n\n");
    output.push_str(&format!(
        "## {}\n\n",
        Severity::Critical.section_label_with_emoji(emoji)
    ));
    push_severity_section(&mut output, &sorted_findings, &[Severity::Critical], emoji);
    output.push_str(&format!(
        "\n## {}\n\n",
        Severity::High.section_label_with_emoji(emoji)
    ));
    push_severity_section(&mut output, &sorted_findings, &[Severity::High], emoji);
    output.push_str(&format!(
        "\n## {}\n\n",
        Severity::Medium.section_label_with_emoji(emoji)
    ));
    push_severity_section(&mut output, &sorted_findings, &[Severity::Medium], emoji);
    output.push_str("\n## ");
    if emoji {
        output.push_str("🟢 Low / 🔵 Notes\n\n");
    } else {
        output.push_str("Low / Notes\n\n");
    }
    push_severity_section(
        &mut output,
        &sorted_findings,
        &[Severity::Low, Severity::Note],
        emoji,
    );
    output.push_str("\n## Test Coverage\n\n");
    output.push_str(
        analysis
            .test_coverage_note
            .as_deref()
            .map(|note| blank_fallback(note, "No specific test coverage note."))
            .unwrap_or("No specific test coverage note."),
    );
    output.push_str("\n\n## Privacy\n\n");
    output.push_str(
        analysis
            .privacy_note
            .as_deref()
            .map(|note| blank_fallback(note, "No specific privacy note."))
            .unwrap_or("No specific privacy note."),
    );
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

    for (index, finding) in section_findings.iter().enumerate() {
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
    if let Some(suggested_fix) = finding
        .suggested_fix
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        output.push_str("Suggested fix:\n");
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
        format_malformed_review_markdown, format_review_markdown_with_emoji, sorted_findings,
    };
    use crate::review::{
        parser::ReviewParseError,
        types::{
            Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode, Severity,
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
                }],
                test_coverage_note: Some("No test covers timeout behavior.".to_string()),
                privacy_note: Some("No obvious exposure detected.".to_string()),
                overall_risk: OverallRisk::Medium,
            },
            true,
        );

        assert!(markdown.contains("# ReviewGate AI Code Review"));
        assert!(markdown.contains("## Finding Summary"));
        assert!(markdown.contains("Open actionable findings: 1"));
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
        }
    }
}
