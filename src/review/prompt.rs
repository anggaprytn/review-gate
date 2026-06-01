use crate::{gitlab::types::MergeRequestMetadata, review::anchors::AnchoredDiffContext};

pub fn build_review_prompt(
    metadata: &MergeRequestMetadata,
    diff_context: &AnchoredDiffContext,
) -> String {
    let partial_notice = if diff_context.truncated {
        "The anchored diff is partial because ReviewGate omitted some files or bytes due to configured limits. Review only the visible anchors and say when a conclusion is limited by missing context."
    } else {
        "The anchored diff includes all reviewable diff content selected for this run."
    };
    let anchored_diff = if diff_context.prompt_text.trim().is_empty() {
        "No reviewable anchored diff lines were available.".to_string()
    } else {
        diff_context.prompt_text.trim_end().to_string()
    };

    format!(
        r#"You are ReviewGate, a risk oriented merge request reviewer for private GitLab teams.

Review only the provided anchored merge request diff. Do not guess about code, files, functions, tests, or runtime behavior that are not visible in the diff context.

Merge request:
- IID: !{iid}
- Title: {title}
- Source branch: {source_branch}
- Target branch: {target_branch}
- URL: {web_url}

Anchored diff status:
- Total anchors: {total_anchors}
- Partial review: {partial}
- {partial_notice}

Rules:
- Prioritize CRITICAL, HIGH, and MEDIUM findings.
- Review focus: security, privacy, reliability, correctness, API contract risk, data integrity, deployment risk, observability, and test coverage.
- Suppress generic style nits, naming comments, broad refactor suggestions, and obvious diff descriptions.
- Prefer fewer, sharper findings over many weak comments.
- A finding must describe a concrete risk introduced or exposed by this MR.
- Use anchor_id from the provided anchors whenever a finding maps to a visible line.
- Do not invent anchors. If no exact anchor exists, use null for anchor_id.
- Prefer anchors on added lines for newly introduced risks.
- Use removed or context anchors only when the risk clearly concerns those lines.
- Include file_path and line from the same anchor when anchor_id is present. If a line is not visible, use null.
- Use risk_code from the allowed list. If no specific value fits, use other.
- For every finding, include effort.
- effort=quick means the fix is likely small/local, usually less than 15 minutes.
- effort=moderate means the fix needs some code change or test update, usually 15-60 minutes.
- effort=heavy means the fix may require design, refactor, migration, or cross-file changes.
- Use NOTE for positive or informational observations.
- Positive changes must be returned as NOTE only with actionable=false.
- Do not assign CRITICAL, HIGH, or MEDIUM to positive notes.
- Do not create a finding if the suggested fix is "No action needed."
- CRITICAL is reserved for exploitable security flaws, data loss, auth bypass, credential exposure, destructive migration, or build/runtime breakage.
- If a finding is just a good practice or improvement, either omit it or return as NOTE with actionable=false.
- Return fewer findings. Prefer no finding over a weak finding.
- Do not include confidence.
- Do not ask for full AST, LSP, Semgrep, repository-wide analysis, or code not shown.
- Produce JSON only. Do not wrap the JSON in markdown fences. Do not include prose before or after the JSON.

Finding limits:
- At most 3 CRITICAL findings.
- At most 5 HIGH findings.
- At most 7 MEDIUM findings.
- At most 5 LOW and NOTE findings combined.

Return exactly one JSON object matching this schema:
{{
  "summary": "Short MR-level review summary.",
  "overall_risk": "medium",
  "findings": [
    {{
      "severity": "HIGH",
      "category": "reliability",
      "risk_code": "missing_timeout",
      "anchor_id": "A0002",
      "file_path": "src/payment/client.ts",
      "line": 42,
      "title": "HTTP request has no timeout",
      "body": "The new payment callback call can hang indefinitely under upstream failure.",
      "suggested_fix": "Use a client timeout or request-scoped timeout.",
      "effort": "quick",
      "actionable": true
    }}
  ],
  "test_coverage_note": "No test covers the timeout behavior.",
  "privacy_note": "No obvious secret or PII exposure detected in the sanitized diff."
}}

Allowed severity values: CRITICAL, HIGH, MEDIUM, LOW, NOTE.
Allowed effort values: quick, moderate, heavy.
Use these category values when possible: security, privacy, reliability, correctness, api_contract, data_integrity, deployment_risk, observability, test_coverage.
Allowed risk_code values: auth_bypass, missing_authorization_check, secret_leak, pii_or_secret_logging, sql_injection, command_injection, unsafe_deserialization, missing_timeout, unbounded_retry, unclosed_resource, nil_or_null_risk, api_contract_break, data_integrity_risk, migration_risk, missing_test_coverage, weak_error_handling, observability_gap, performance_regression, maintainability_risk, positive_note, other.

Anchored sanitized diff:
```text
{anchored_diff}
```
"#,
        iid = metadata.iid,
        title = metadata.title,
        source_branch = metadata.source_branch,
        target_branch = metadata.target_branch,
        web_url = metadata.web_url,
        total_anchors = diff_context.total_anchors,
        partial = if diff_context.truncated { "yes" } else { "no" },
        partial_notice = partial_notice,
        anchored_diff = anchored_diff,
    )
}

#[cfg(test)]
mod tests {
    use super::build_review_prompt;
    use crate::gitlab::types::MergeRequestMetadata;
    use crate::review::anchors::{AnchorLineKind, AnchoredDiffContext, ReviewLineAnchor};

    #[test]
    fn prompt_requires_json_only_and_review_focus() {
        let prompt = build_review_prompt(&metadata(), &anchored_context(false));

        assert!(prompt.contains("Produce JSON only"));
        assert!(prompt.contains("At most 3 CRITICAL"));
        assert!(prompt.contains("security, privacy, reliability, correctness"));
        assert!(prompt.contains("Do not guess about code"));
        assert!(prompt.contains("anchor_id"));
        assert!(prompt.contains("risk_code"));
        assert!(prompt.contains("effort"));
        assert!(prompt.contains("Positive changes must be returned as NOTE only"));
        assert!(prompt
            .contains("Do not create a finding if the suggested fix is \"No action needed.\""));
        assert!(prompt.contains("Prefer no finding over a weak finding."));
        assert!(!prompt.contains(r#""confidence": "high""#));
        assert!(prompt.contains("[A0001] new_line=42 old_line=- kind=added"));
    }

    #[test]
    fn prompt_warns_when_anchored_diff_is_partial() {
        let prompt = build_review_prompt(&metadata(), &anchored_context(true));

        assert!(prompt.contains("Partial review: yes"));
        assert!(prompt.contains("The anchored diff is partial"));
    }

    fn metadata() -> MergeRequestMetadata {
        MergeRequestMetadata {
            id: 123,
            iid: 59,
            project_id: 456,
            title: "Fix payment callback timeout".to_string(),
            description: None,
            state: "opened".to_string(),
            draft: Some(false),
            source_branch: "feature/payment-timeout".to_string(),
            target_branch: "main".to_string(),
            sha: "abc123".to_string(),
            web_url: "https://gitlab.company.local/group/repo/-/merge_requests/59".to_string(),
            author: None,
            detailed_merge_status: Some("mergeable".to_string()),
            changes_count: Some("4".to_string()),
            diff_refs: None,
        }
    }

    fn anchored_context(truncated: bool) -> AnchoredDiffContext {
        AnchoredDiffContext {
            anchors: vec![ReviewLineAnchor {
                anchor_id: "A0001".to_string(),
                file_path: "src/payment/client.ts".to_string(),
                old_path: "src/payment/client.ts".to_string(),
                new_path: "src/payment/client.ts".to_string(),
                old_line: None,
                new_line: Some(42),
                kind: AnchorLineKind::Added,
                content_preview: "fetch(url)".to_string(),
            }],
            prompt_text:
                "File: src/payment/client.ts\n\n[A0001] new_line=42 old_line=- kind=added   | fetch(url)\n"
                    .to_string(),
            total_anchors: 1,
            truncated,
        }
    }
}
