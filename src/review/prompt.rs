use crate::gitlab::types::MergeRequestMetadata;

pub fn build_review_prompt(metadata: &MergeRequestMetadata, diff_text: &str) -> String {
    format!(
        r#"You are ReviewGate, a risk-focused merge request reviewer for private GitLab teams.

Review only the provided merge request diff. Do not guess about code, files, functions, tests, or runtime behavior that are not visible in the diff context.

Merge request:
- IID: !{iid}
- Title: {title}
- Source branch: {source_branch}
- Target branch: {target_branch}
- URL: {web_url}

Rules:
- Prioritize CRITICAL, HIGH, and MEDIUM findings.
- Review focus: security, privacy, reliability, correctness, API contract risk, data integrity, deployment risk, observability, and test coverage.
- Suppress generic style nits, naming comments, broad refactor suggestions, and obvious diff descriptions.
- Prefer fewer, sharper findings over many weak comments.
- A finding must describe a concrete risk introduced or exposed by this MR.
- Include file_path and line only when visible from diff context. If a line is not visible, use null.
- Use NOTE for positive or informational observations.
- Mark confidence honestly. Use low confidence when the diff gives only weak evidence.
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
      "file_path": "src/payment/client.ts",
      "line": 42,
      "title": "HTTP request has no timeout",
      "body": "The new payment callback call can hang indefinitely under upstream failure.",
      "suggested_fix": "Use a client timeout or request-scoped timeout.",
      "confidence": "high",
      "actionable": true
    }}
  ],
  "test_coverage_note": "No test covers the timeout behavior.",
  "privacy_note": "No obvious secret or PII exposure detected in the sanitized diff."
}}

Allowed severity values: CRITICAL, HIGH, MEDIUM, LOW, NOTE.
Allowed confidence values: high, medium, low.
Use these category values when possible: security, privacy, reliability, correctness, api_contract, data_integrity, deployment_risk, observability, test_coverage.

Diff:
```diff
{diff_text}
```
"#,
        iid = metadata.iid,
        title = metadata.title,
        source_branch = metadata.source_branch,
        target_branch = metadata.target_branch,
        web_url = metadata.web_url,
        diff_text = diff_text
    )
}

#[cfg(test)]
mod tests {
    use super::build_review_prompt;
    use crate::gitlab::types::MergeRequestMetadata;

    #[test]
    fn prompt_requires_json_only_and_review_focus() {
        let prompt = build_review_prompt(&metadata(), "diff --git a/a b/a\n+change");

        assert!(prompt.contains("Produce JSON only"));
        assert!(prompt.contains("At most 3 CRITICAL"));
        assert!(prompt.contains("security, privacy, reliability, correctness"));
        assert!(prompt.contains("Do not guess about code"));
        assert!(prompt.contains("diff --git"));
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
}
