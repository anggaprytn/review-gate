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

    #[test]
    fn parses_first_valid_json_object_with_extra_text() {
        let parsed = parse_review_analysis(
            r#"logs {not json}
            {
              "summary": "Looks good.",
              "overall_risk": "LOW",
              "findings": [],
              "test_coverage_note": null,
              "privacy_note": null
            }
            more logs"#,
        )
        .unwrap();

        assert_eq!(parsed.summary, "Looks good.");
    }
}
