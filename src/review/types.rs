use serde::{de, Deserialize, Deserializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReviewAnalysis {
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<ReviewFinding>,
    pub test_coverage_note: Option<String>,
    pub privacy_note: Option<String>,
    pub overall_risk: OverallRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReviewFinding {
    pub severity: Severity,
    pub category: ReviewCategory,
    pub file_path: Option<String>,
    pub line: Option<u32>,
    pub title: String,
    pub body: String,
    pub suggested_fix: Option<String>,
    pub confidence: Confidence,
    #[serde(default)]
    pub actionable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverallRisk {
    Critical,
    High,
    Medium,
    Low,
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReviewCategory {
    Security,
    Privacy,
    Reliability,
    Correctness,
    ApiContract,
    DataIntegrity,
    DeploymentRisk,
    Observability,
    TestCoverage,
    Other(String),
}

impl Severity {
    pub fn sort_key(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Note => 4,
        }
    }

    pub fn section_label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low | Severity::Note => "Low / Notes",
        }
    }

    pub fn display_upper(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Note => "NOTE",
        }
    }

    pub fn display_lower(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Note => "note",
        }
    }
}

impl OverallRisk {
    pub fn display_upper(self) -> &'static str {
        match self {
            OverallRisk::Critical => "CRITICAL",
            OverallRisk::High => "HIGH",
            OverallRisk::Medium => "MEDIUM",
            OverallRisk::Low => "LOW",
            OverallRisk::Note => "NOTE",
        }
    }
}

impl Confidence {
    pub fn display_lower(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

impl ReviewCategory {
    pub fn display_lower(&self) -> &str {
        match self {
            ReviewCategory::Security => "security",
            ReviewCategory::Privacy => "privacy",
            ReviewCategory::Reliability => "reliability",
            ReviewCategory::Correctness => "correctness",
            ReviewCategory::ApiContract => "api_contract",
            ReviewCategory::DataIntegrity => "data_integrity",
            ReviewCategory::DeploymentRisk => "deployment_risk",
            ReviewCategory::Observability => "observability",
            ReviewCategory::TestCoverage => "test_coverage",
            ReviewCategory::Other(value) => value.as_str(),
        }
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match normalize_enum_value(&value).as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "note" | "info" | "informational" => Ok(Severity::Note),
            _ => Err(de::Error::custom(format!("unknown severity '{value}'"))),
        }
    }
}

impl<'de> Deserialize<'de> for OverallRisk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match normalize_enum_value(&value).as_str() {
            "critical" => Ok(OverallRisk::Critical),
            "high" => Ok(OverallRisk::High),
            "medium" => Ok(OverallRisk::Medium),
            "low" => Ok(OverallRisk::Low),
            "note" | "none" | "informational" => Ok(OverallRisk::Note),
            _ => Err(de::Error::custom(format!("unknown overall risk '{value}'"))),
        }
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match normalize_enum_value(&value).as_str() {
            "high" => Ok(Confidence::High),
            "medium" => Ok(Confidence::Medium),
            "low" => Ok(Confidence::Low),
            _ => Err(de::Error::custom(format!("unknown confidence '{value}'"))),
        }
    }
}

impl<'de> Deserialize<'de> for ReviewCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let normalized = normalize_enum_value(&value);
        Ok(match normalized.as_str() {
            "security" => ReviewCategory::Security,
            "privacy" => ReviewCategory::Privacy,
            "reliability" => ReviewCategory::Reliability,
            "correctness" => ReviewCategory::Correctness,
            "api_contract" | "api_contract_risk" | "contract" => ReviewCategory::ApiContract,
            "data_integrity" => ReviewCategory::DataIntegrity,
            "deployment_risk" | "deployment" => ReviewCategory::DeploymentRisk,
            "observability" => ReviewCategory::Observability,
            "test_coverage" | "tests" | "testing" => ReviewCategory::TestCoverage,
            _ => ReviewCategory::Other(normalized),
        })
    }
}

impl fmt::Display for ReviewCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.display_lower())
    }
}

fn normalize_enum_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::{Confidence, OverallRisk, ReviewAnalysis, ReviewCategory, Severity};

    #[test]
    fn parses_review_json_into_typed_structs_with_flexible_enums() {
        let review: ReviewAnalysis = serde_json::from_str(
            r#"{
              "summary": "Short MR-level review summary.",
              "overall_risk": "medium",
              "findings": [
                {
                  "severity": "HIGH",
                  "category": "api-contract",
                  "file_path": "src/payment/client.ts",
                  "line": 42,
                  "title": "HTTP request has no timeout",
                  "body": "The callback call can hang indefinitely.",
                  "suggested_fix": "Use a request-scoped timeout.",
                  "confidence": "high",
                  "actionable": true
                }
              ],
              "test_coverage_note": "No test covers timeout behavior.",
              "privacy_note": "No obvious exposure detected."
            }"#,
        )
        .unwrap();

        assert_eq!(review.overall_risk, OverallRisk::Medium);
        assert_eq!(review.findings[0].severity, Severity::High);
        assert_eq!(review.findings[0].category, ReviewCategory::ApiContract);
        assert_eq!(review.findings[0].confidence, Confidence::High);
    }
}
