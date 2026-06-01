use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
    counters::{count_verification_results, emoji_enabled, format_verification_counters_markdown},
    error::Result,
    gitlab::context::MergeRequestContext,
    llm::types::{LlmReviewResponse, LlmRunMetadata},
    review::{engine::estimate_prompt_tokens, types::Severity},
    storage::StoredPreviousFinding,
};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, future::Future};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationStatus {
    Fixed,
    StillOpen,
    Skipped,
    NeedsManualConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub previous_finding: StoredPreviousFinding,
    pub status: VerificationStatus,
    pub reason: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub summary: String,
    pub results: Vec<VerificationResult>,
    pub parsed: bool,
    pub parse_warning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerificationPreview {
    pub markdown: String,
    pub metadata: LlmRunMetadata,
    pub prompt_token_estimate: u64,
    pub outcome: VerificationOutcome,
}

#[derive(Debug, Deserialize)]
struct RawVerificationOutput {
    summary: Option<String>,
    #[serde(default)]
    results: Vec<RawVerificationResult>,
}

#[derive(Debug, Deserialize)]
struct RawVerificationResult {
    previous_finding_id: String,
    status: Option<String>,
    reason: Option<String>,
    evidence: Option<String>,
}

impl VerificationStatus {
    pub fn parse(value: &str) -> Self {
        match normalize_status(value).as_str() {
            "fixed" => Self::Fixed,
            "still_open" | "open" | "unfixed" | "not_fixed" => Self::StillOpen,
            "skipped" | "skip" | "acknowledged" => Self::Skipped,
            "needs_manual_confirmation" | "manual_confirmation" | "manual" | "unknown" => {
                Self::NeedsManualConfirmation
            }
            _ => Self::NeedsManualConfirmation,
        }
    }

    pub fn display_lower(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::StillOpen => "still_open",
            Self::Skipped => "skipped",
            Self::NeedsManualConfirmation => "needs_manual_confirmation",
        }
    }
}

pub async fn verification_prompt_with_llm<F, Fut>(
    context: &MergeRequestContext,
    previous_findings: &[StoredPreviousFinding],
    llm_label: &str,
    publish_mode: &str,
    previous_run_id: &str,
    call_llm: F,
) -> Result<VerificationPreview>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<LlmReviewResponse>>,
{
    let prompt = build_verification_prompt(context, previous_findings);
    let prompt_token_estimate = estimate_prompt_tokens(&prompt);
    let llm_response = call_llm(prompt).await?;
    let outcome = parse_verification_output(&llm_response.text, previous_findings);
    let markdown = format_verification_markdown(
        &outcome,
        previous_run_id,
        head_sha(context),
        llm_label,
        publish_mode,
    );

    Ok(VerificationPreview {
        markdown,
        metadata: llm_response.metadata,
        prompt_token_estimate,
        outcome,
    })
}

pub fn build_verification_prompt(
    context: &MergeRequestContext,
    previous_findings: &[StoredPreviousFinding],
) -> String {
    let findings = previous_findings
        .iter()
        .map(|finding| {
            json!({
                "previous_finding_id": finding.id,
                "severity": finding.severity,
                "category": finding.category,
                "risk_code": finding.risk_code,
                "file_path": finding.file_path,
                "old_line": finding.old_line,
                "new_line": finding.new_line,
                "title": finding.title,
                "body": finding.body,
                "suggested_fix": finding.suggested_fix,
            })
        })
        .collect::<Vec<_>>();

    format!(
        r#"You are ReviewGate change verification.

Verify only the previous findings against the current sanitized anchored diff.
Do not introduce new findings.
Do not review unrelated code.
If evidence is insufficient, use needs_manual_confirmation.
Do not claim fixed unless the current diff clearly resolves the issue.
Return JSON only.

Allowed statuses:
- fixed
- still_open
- skipped
- needs_manual_confirmation

MR:
- project: {project}
- mr: !{mr_iid}
- title: {title}
- current_head_sha: {head_sha}

Previous findings JSON:
{findings_json}

Current sanitized anchored diff:
{anchored_diff}

Return this schema:
{{
  "summary": "1 fixed, 2 still open, 1 needs manual confirmation.",
  "results": [
    {{
      "previous_finding_id": "finding-id",
      "status": "fixed",
      "reason": "The risky code is no longer present in the latest diff.",
      "evidence": "The new code uses a safe request identifier."
    }}
  ]
}}
"#,
        project = context.mr_url.project_path,
        mr_iid = context.metadata.iid,
        title = context.metadata.title,
        head_sha = head_sha(context),
        findings_json =
            serde_json::to_string_pretty(&findings).unwrap_or_else(|_| "[]".to_string()),
        anchored_diff = if context.anchored_diff.prompt_text.trim().is_empty() {
            "(no anchored diff content available)"
        } else {
            context.anchored_diff.prompt_text.trim()
        },
    )
}

pub fn parse_verification_output(
    model_output: &str,
    previous_findings: &[StoredPreviousFinding],
) -> VerificationOutcome {
    let parsed = json_candidate(model_output)
        .ok_or_else(|| "model output did not contain a JSON verification object".to_string())
        .and_then(|candidate| {
            serde_json::from_str::<RawVerificationOutput>(candidate)
                .map_err(|err| format!("malformed JSON verification output: {err}"))
        });

    match parsed {
        Ok(raw) => outcome_from_raw(raw, previous_findings),
        Err(err) => fallback_outcome(previous_findings, err),
    }
}

pub fn format_verification_markdown(
    outcome: &VerificationOutcome,
    previous_run_id: &str,
    current_head_sha: &str,
    llm_label: &str,
    publish_mode: &str,
) -> String {
    let mut output = String::new();
    output.push_str("# ReviewGate Change Verification\n\n");
    output.push_str(&format_verification_counters_markdown(
        &count_verification_results(outcome),
        emoji_enabled(),
    ));
    output.push('\n');
    output.push_str("## Summary\n\n");
    output.push_str(blank_fallback(
        &outcome.summary,
        "No verification summary returned.",
    ));
    output.push_str("\n\n");
    push_status_section(
        &mut output,
        "## ✅ Fixed",
        outcome,
        VerificationStatus::Fixed,
    );
    push_status_section(
        &mut output,
        "## ⚠️ Still Open",
        outcome,
        VerificationStatus::StillOpen,
    );
    push_status_section(
        &mut output,
        "## ⏭️ Skipped",
        outcome,
        VerificationStatus::Skipped,
    );
    push_status_section(
        &mut output,
        "## ❓ Needs Manual Confirmation",
        outcome,
        VerificationStatus::NeedsManualConfirmation,
    );

    if let Some(warning) = outcome.parse_warning.as_deref() {
        output.push_str("\n## Warning\n\n");
        output.push_str(warning);
        output.push('\n');
    }

    output.push_str("\n---\n\n");
    output.push_str("ReviewGate verification metadata:\n\n");
    output.push_str("- Previous run: ");
    output.push_str(previous_run_id);
    output.push('\n');
    output.push_str("- Current head SHA: ");
    output.push_str(current_head_sha);
    output.push('\n');
    output.push_str("- LLM: ");
    output.push_str(llm_label);
    output.push('\n');
    output.push_str("- Publish mode: ");
    output.push_str(publish_mode);
    output.push_str("\n\n");
    output.push_str(REVIEWGATE_ATTRIBUTION);
    output.push('\n');
    output
}

pub fn no_previous_run_message() -> &'static str {
    "No previous ReviewGate run found for this MR. Run `reviewgate review <mr-url> --publish` first."
}

fn outcome_from_raw(
    raw: RawVerificationOutput,
    previous_findings: &[StoredPreviousFinding],
) -> VerificationOutcome {
    let mut by_id = HashMap::new();
    for result in raw.results {
        by_id.insert(result.previous_finding_id.clone(), result);
    }

    let mut results = Vec::new();
    for finding in previous_findings {
        if let Some(raw_result) = by_id.remove(&finding.id) {
            results.push(VerificationResult {
                previous_finding: finding.clone(),
                status: raw_result
                    .status
                    .as_deref()
                    .map(VerificationStatus::parse)
                    .unwrap_or(VerificationStatus::NeedsManualConfirmation),
                reason: non_empty(raw_result.reason).unwrap_or_else(|| {
                    "The verification model did not provide a reason.".to_string()
                }),
                evidence: non_empty(raw_result.evidence),
            });
        } else {
            results.push(VerificationResult {
                previous_finding: finding.clone(),
                status: VerificationStatus::NeedsManualConfirmation,
                reason: "The verification model did not return a result for this previous finding."
                    .to_string(),
                evidence: None,
            });
        }
    }

    let summary = non_empty(raw.summary).unwrap_or_else(|| summarize_counts(&results));
    VerificationOutcome {
        summary,
        results,
        parsed: true,
        parse_warning: None,
    }
}

fn fallback_outcome(
    previous_findings: &[StoredPreviousFinding],
    warning: String,
) -> VerificationOutcome {
    let results = previous_findings
        .iter()
        .cloned()
        .map(|finding| VerificationResult {
            previous_finding: finding,
            status: VerificationStatus::NeedsManualConfirmation,
            reason: "The verification model response could not be parsed safely.".to_string(),
            evidence: None,
        })
        .collect::<Vec<_>>();
    VerificationOutcome {
        summary: summarize_counts(&results),
        results,
        parsed: false,
        parse_warning: Some(warning),
    }
}

fn summarize_counts(results: &[VerificationResult]) -> String {
    let fixed = count_status(results, VerificationStatus::Fixed);
    let still_open = count_status(results, VerificationStatus::StillOpen);
    let skipped = count_status(results, VerificationStatus::Skipped);
    let needs_manual = count_status(results, VerificationStatus::NeedsManualConfirmation);

    let mut parts = Vec::new();
    parts.push(format!("{fixed} fixed"));
    parts.push(format!("{still_open} still open"));
    if skipped > 0 {
        parts.push(format!("{skipped} skipped"));
    }
    parts.push(format!("{needs_manual} needs manual confirmation"));
    format!("{}.", parts.join(", "))
}

fn push_status_section(
    output: &mut String,
    heading: &str,
    outcome: &VerificationOutcome,
    status: VerificationStatus,
) {
    output.push_str(heading);
    output.push_str("\n\n");
    let matches = outcome
        .results
        .iter()
        .filter(|result| result.status == status)
        .collect::<Vec<_>>();

    if matches.is_empty() {
        output.push_str("No findings.\n\n");
        return;
    }

    for result in matches {
        output.push_str("### ");
        output.push_str(&finding_heading(&result.previous_finding));
        output.push_str("\n\n");
        output.push_str(blank_fallback(
            &result.previous_finding.title,
            "Untitled previous finding",
        ));
        output.push_str("\n\nReason:\n");
        output.push_str(blank_fallback(&result.reason, "No reason returned."));
        output.push_str("\n\nEvidence:\n");
        output.push_str(
            result
                .evidence
                .as_deref()
                .map(|value| blank_fallback(value, "No evidence returned."))
                .unwrap_or("No evidence returned."),
        );
        output.push_str("\n\n");
    }
}

fn finding_heading(finding: &StoredPreviousFinding) -> String {
    let severity = parse_severity(&finding.severity);
    let mut heading = severity
        .map(|severity| severity.display_label(true))
        .unwrap_or_else(|| finding.severity.clone());
    if let Some(location) = finding_location(finding) {
        heading.push_str(" · ");
        heading.push_str(&location);
    }
    heading
}

fn finding_location(finding: &StoredPreviousFinding) -> Option<String> {
    let path = finding
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let line = finding
        .new_line
        .or(finding.old_line)
        .map(|line| format!(":{line}"))
        .unwrap_or_default();
    Some(format!("{path}{line}"))
}

fn parse_severity(value: &str) -> Option<Severity> {
    serde_json::from_str(&format!("{value:?}")).ok()
}

fn count_status(results: &[VerificationResult], status: VerificationStatus) -> usize {
    results
        .iter()
        .filter(|result| result.status == status)
        .count()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn blank_fallback<'a>(value: &'a str, fallback: &'static str) -> &'a str {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    }
}

fn normalize_status(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn json_candidate(output: &str) -> Option<&str> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_fence = strip_json_code_fence(trimmed);
    if without_fence.trim_start().starts_with('{') {
        let candidate = without_fence.trim();
        if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
            return Some(candidate);
        }
    }

    first_valid_json_object(without_fence)
}

fn strip_json_code_fence(input: &str) -> &str {
    let trimmed = input.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let after_open = after_open
        .strip_prefix("json")
        .or_else(|| after_open.strip_prefix("JSON"))
        .unwrap_or(after_open)
        .trim_start();
    after_open
        .strip_suffix("```")
        .map(str::trim_end)
        .unwrap_or(after_open)
}

fn first_valid_json_object(input: &str) -> Option<&str> {
    for (start, char_value) in input.char_indices() {
        if char_value != '{' {
            continue;
        }
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (relative_index, current) in input[start..].char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '"' {
                    in_string = false;
                }
                continue;
            }

            match current {
                '"' => in_string = true,
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = start + relative_index + current.len_utf8();
                        let candidate = input[start..end].trim();
                        if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
                            return Some(candidate);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn head_sha(context: &MergeRequestContext) -> &str {
    context
        .metadata
        .diff_refs
        .as_ref()
        .and_then(|refs| refs.head_sha.as_deref())
        .unwrap_or(&context.metadata.sha)
}

#[cfg(test)]
mod tests {
    use super::{
        format_verification_markdown, no_previous_run_message, parse_verification_output,
        VerificationOutcome, VerificationResult, VerificationStatus,
    };
    use crate::storage::StoredPreviousFinding;

    #[test]
    fn parses_verification_status_flexibly() {
        assert_eq!(
            VerificationStatus::parse("FIXED"),
            VerificationStatus::Fixed
        );
        assert_eq!(
            VerificationStatus::parse("still-open"),
            VerificationStatus::StillOpen
        );
        assert_eq!(
            VerificationStatus::parse("needs manual confirmation"),
            VerificationStatus::NeedsManualConfirmation
        );
        assert_eq!(
            VerificationStatus::parse("surprise"),
            VerificationStatus::NeedsManualConfirmation
        );
    }

    #[test]
    fn parser_maps_missing_and_unknown_results_safely() {
        let findings = vec![finding("f1"), finding("f2")];
        let outcome = parse_verification_output(
            r#"{
              "summary": "custom summary",
              "results": [
                {"previous_finding_id": "f1", "status": "fixed", "reason": "gone", "evidence": "new code"}
              ]
            }"#,
            &findings,
        );

        assert!(outcome.parsed);
        assert_eq!(outcome.summary, "custom summary");
        assert_eq!(outcome.results[0].status, VerificationStatus::Fixed);
        assert_eq!(
            outcome.results[1].status,
            VerificationStatus::NeedsManualConfirmation
        );
    }

    #[test]
    fn malformed_output_falls_back_without_panicking() {
        let outcome = parse_verification_output("not json", &[finding("f1")]);

        assert!(!outcome.parsed);
        assert_eq!(
            outcome.results[0].status,
            VerificationStatus::NeedsManualConfirmation
        );
        assert!(outcome.parse_warning.unwrap().contains("JSON"));
    }

    #[test]
    fn verification_formatter_groups_statuses() {
        let outcome = VerificationOutcome {
            summary: "1 fixed, 1 still open, 1 skipped, 1 needs manual confirmation.".to_string(),
            results: vec![
                result("fixed", VerificationStatus::Fixed),
                result("open", VerificationStatus::StillOpen),
                result("skip", VerificationStatus::Skipped),
                result("manual", VerificationStatus::NeedsManualConfirmation),
            ],
            parsed: true,
            parse_warning: None,
        };

        let markdown = format_verification_markdown(
            &outcome,
            "run-1",
            "abc123",
            "gemini_cli/gemini-2.5-pro",
            "verification summary note",
        );

        assert!(markdown.contains("# ReviewGate Change Verification"));
        assert!(markdown.contains("## Verification Summary"));
        assert!(markdown.contains("| ✅ Fixed | 1 |"));
        assert!(markdown.contains("| ⚠️ Still open | 1 |"));
        assert!(markdown.contains("## ✅ Fixed"));
        assert!(markdown.contains("## ⚠️ Still Open"));
        assert!(markdown.contains("## ⏭️ Skipped"));
        assert!(markdown.contains("## ❓ Needs Manual Confirmation"));
        assert!(markdown.contains("- Previous run: run-1"));
        assert!(markdown.contains("- Current head SHA: abc123"));
    }

    #[test]
    fn no_previous_run_message_matches_cli_copy() {
        assert_eq!(
            no_previous_run_message(),
            "No previous ReviewGate run found for this MR. Run `reviewgate review <mr-url> --publish` first."
        );
    }

    fn result(id: &str, status: VerificationStatus) -> VerificationResult {
        VerificationResult {
            previous_finding: finding(id),
            status,
            reason: "reason".to_string(),
            evidence: Some("evidence".to_string()),
        }
    }

    fn finding(id: &str) -> StoredPreviousFinding {
        StoredPreviousFinding {
            id: id.to_string(),
            severity: "HIGH".to_string(),
            effort: "quick".to_string(),
            category: "security".to_string(),
            risk_code: Some("missing_authorization_check".to_string()),
            anchor_id: None,
            file_path: Some("src/paymentClient.ts".to_string()),
            old_line: None,
            new_line: Some(11),
            title: format!("finding {id}"),
            body: "body".to_string(),
            suggested_fix: None,
            actionable: true,
            fingerprint_v2: Some(format!("fp-{id}")),
        }
    }
}
