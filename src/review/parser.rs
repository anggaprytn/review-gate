use crate::review::types::ReviewAnalysis;
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewParseError {
    message: String,
}

impl ReviewParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ReviewParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ReviewParseError {}

pub fn parse_review_analysis(model_output: &str) -> Result<ReviewAnalysis, ReviewParseError> {
    let candidate = json_candidate(model_output).ok_or_else(|| {
        ReviewParseError::new("model output did not contain a JSON review object")
    })?;

    serde_json::from_str::<ReviewAnalysis>(candidate)
        .map_err(|err| ReviewParseError::new(format!("malformed JSON review output: {err}")))
}

fn json_candidate(output: &str) -> Option<&str> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_fence = strip_json_code_fence(trimmed);
    if without_fence.trim_start().starts_with('{') {
        return Some(without_fence.trim());
    }

    let start = without_fence.find('{')?;
    let end = without_fence.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(without_fence[start..=end].trim())
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

#[cfg(test)]
mod tests {
    use super::parse_review_analysis;
    use crate::review::types::Severity;

    #[test]
    fn parses_json_wrapped_in_code_fence() {
        let parsed = parse_review_analysis(
            r#"```json
            {
              "summary": "Looks good.",
              "overall_risk": "LOW",
              "findings": [
                {
                  "severity": "note",
                  "category": "test_coverage",
                  "file_path": null,
                  "line": null,
                  "title": "Tests cover the changed path",
                  "body": "The MR includes a regression test.",
                  "suggested_fix": null,
                  "confidence": "medium",
                  "actionable": false
                }
              ],
              "test_coverage_note": null,
              "privacy_note": null
            }
            ```"#,
        )
        .unwrap();

        assert_eq!(parsed.findings[0].severity, Severity::Note);
    }

    #[test]
    fn malformed_json_model_output_returns_error() {
        let err = parse_review_analysis("not json").unwrap_err();

        assert!(err.to_string().contains("JSON review object"));
    }
}
