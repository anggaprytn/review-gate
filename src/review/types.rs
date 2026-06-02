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
    #[serde(default)]
    pub risk_code: Option<RiskCode>,
    #[serde(default)]
    pub anchor_id: Option<String>,
    pub file_path: Option<String>,
    pub line: Option<u32>,
    pub title: String,
    pub body: String,
    pub suggested_fix: Option<String>,
    #[serde(default)]
    pub effort: Effort,
    #[serde(default)]
    pub actionable: bool,
    #[serde(default)]
    pub evidence_status: Option<EvidenceValidationStatus>,
    #[serde(default)]
    pub evidence_reason: Option<String>,
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
pub enum EvidenceValidationStatus {
    Validated,
    WeakEvidence,
    StaleContext,
    NotInDiff,
    PositiveChange,
    NeedsManualConfirmation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Effort {
    Quick,
    #[default]
    Moderate,
    Heavy,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskCode {
    AuthBypass,
    MissingAuthorizationCheck,
    SecretLeak,
    PiiOrSecretLogging,
    SqlInjection,
    CommandInjection,
    UnsafeDeserialization,
    MissingTimeout,
    UnboundedRetry,
    UnclosedResource,
    NilOrNullRisk,
    ApiContractBreak,
    DataIntegrityRisk,
    MigrationRisk,
    MissingTestCoverage,
    WeakErrorHandling,
    ObservabilityGap,
    PerformanceRegression,
    MaintainabilityRisk,
    PositiveNote,
    Other,
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

    pub fn display_label(self, emoji: bool) -> String {
        if emoji {
            format!("{} {}", self.emoji(), self.display_upper())
        } else {
            self.display_upper().to_string()
        }
    }

    pub fn section_label_with_emoji(self, emoji: bool) -> String {
        let label = self.section_label();
        if emoji {
            format!("{} {}", self.emoji(), label)
        } else {
            label.to_string()
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Note => "🔵",
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

    pub fn display_label(self, emoji: bool) -> String {
        let label = match self {
            OverallRisk::Critical => "Critical",
            OverallRisk::High => "High",
            OverallRisk::Medium => "Medium",
            OverallRisk::Low => "Low",
            OverallRisk::Note => "Note",
        };
        if emoji {
            format!("{} {}", self.emoji(), label)
        } else {
            label.to_string()
        }
    }

    fn emoji(self) -> &'static str {
        match self {
            OverallRisk::Critical => "🔴",
            OverallRisk::High => "🟠",
            OverallRisk::Medium => "🟡",
            OverallRisk::Low => "🟢",
            OverallRisk::Note => "🔵",
        }
    }
}

impl Effort {
    pub fn display_lower(self) -> &'static str {
        match self {
            Effort::Quick => "quick",
            Effort::Moderate => "moderate",
            Effort::Heavy => "heavy",
        }
    }

    pub fn display_label(self, emoji: bool) -> String {
        let label = match self {
            Effort::Quick => "Quick fix",
            Effort::Moderate => "Moderate fix",
            Effort::Heavy => "Heavy fix",
        };
        if emoji {
            format!("{} {}", self.emoji(), label)
        } else {
            label.to_string()
        }
    }

    fn emoji(self) -> &'static str {
        match self {
            Effort::Quick => "⚡",
            Effort::Moderate => "🛠️",
            Effort::Heavy => "🧱",
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

impl RiskCode {
    pub fn display_lower(self) -> &'static str {
        match self {
            RiskCode::AuthBypass => "auth_bypass",
            RiskCode::MissingAuthorizationCheck => "missing_authorization_check",
            RiskCode::SecretLeak => "secret_leak",
            RiskCode::PiiOrSecretLogging => "pii_or_secret_logging",
            RiskCode::SqlInjection => "sql_injection",
            RiskCode::CommandInjection => "command_injection",
            RiskCode::UnsafeDeserialization => "unsafe_deserialization",
            RiskCode::MissingTimeout => "missing_timeout",
            RiskCode::UnboundedRetry => "unbounded_retry",
            RiskCode::UnclosedResource => "unclosed_resource",
            RiskCode::NilOrNullRisk => "nil_or_null_risk",
            RiskCode::ApiContractBreak => "api_contract_break",
            RiskCode::DataIntegrityRisk => "data_integrity_risk",
            RiskCode::MigrationRisk => "migration_risk",
            RiskCode::MissingTestCoverage => "missing_test_coverage",
            RiskCode::WeakErrorHandling => "weak_error_handling",
            RiskCode::ObservabilityGap => "observability_gap",
            RiskCode::PerformanceRegression => "performance_regression",
            RiskCode::MaintainabilityRisk => "maintainability_risk",
            RiskCode::PositiveNote => "positive_note",
            RiskCode::Other => "other",
        }
    }
}

impl EvidenceValidationStatus {
    pub fn display_lower(self) -> &'static str {
        match self {
            EvidenceValidationStatus::Validated => "validated",
            EvidenceValidationStatus::WeakEvidence => "weak_evidence",
            EvidenceValidationStatus::StaleContext => "stale_context",
            EvidenceValidationStatus::NotInDiff => "not_in_diff",
            EvidenceValidationStatus::PositiveChange => "positive_change",
            EvidenceValidationStatus::NeedsManualConfirmation => "needs_manual_confirmation",
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

impl<'de> Deserialize<'de> for Effort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match normalize_enum_value(&value).as_str() {
            "quick" | "low" | "small" | "easy" => Ok(Effort::Quick),
            "moderate" | "medium" | "normal" => Ok(Effort::Moderate),
            "heavy" | "high" | "large" | "hard" => Ok(Effort::Heavy),
            _ => Err(de::Error::custom(format!("unknown effort '{value}'"))),
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

impl<'de> Deserialize<'de> for RiskCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let normalized = normalize_enum_value(&value);
        Ok(match normalized.as_str() {
            "auth_bypass" => RiskCode::AuthBypass,
            "missing_authorization_check" => RiskCode::MissingAuthorizationCheck,
            "secret_leak" => RiskCode::SecretLeak,
            "pii_or_secret_logging" => RiskCode::PiiOrSecretLogging,
            "sql_injection" => RiskCode::SqlInjection,
            "command_injection" => RiskCode::CommandInjection,
            "unsafe_deserialization" => RiskCode::UnsafeDeserialization,
            "missing_timeout" => RiskCode::MissingTimeout,
            "unbounded_retry" => RiskCode::UnboundedRetry,
            "unclosed_resource" => RiskCode::UnclosedResource,
            "nil_or_null_risk" | "null_risk" | "nil_risk" => RiskCode::NilOrNullRisk,
            "api_contract_break" | "api_contract_risk" => RiskCode::ApiContractBreak,
            "data_integrity_risk" => RiskCode::DataIntegrityRisk,
            "migration_risk" => RiskCode::MigrationRisk,
            "missing_test_coverage" => RiskCode::MissingTestCoverage,
            "weak_error_handling" => RiskCode::WeakErrorHandling,
            "observability_gap" => RiskCode::ObservabilityGap,
            "performance_regression" => RiskCode::PerformanceRegression,
            "maintainability_risk" => RiskCode::MaintainabilityRisk,
            "positive_note" => RiskCode::PositiveNote,
            "other" => RiskCode::Other,
            _ => RiskCode::Other,
        })
    }
}

impl<'de> Deserialize<'de> for EvidenceValidationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match normalize_enum_value(&value).as_str() {
            "validated" => Ok(EvidenceValidationStatus::Validated),
            "weak_evidence" => Ok(EvidenceValidationStatus::WeakEvidence),
            "stale_context" => Ok(EvidenceValidationStatus::StaleContext),
            "not_in_diff" => Ok(EvidenceValidationStatus::NotInDiff),
            "positive_change" => Ok(EvidenceValidationStatus::PositiveChange),
            "needs_manual_confirmation" => Ok(EvidenceValidationStatus::NeedsManualConfirmation),
            _ => Err(de::Error::custom(format!(
                "unknown evidence validation status '{value}'"
            ))),
        }
    }
}

impl fmt::Display for ReviewCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.display_lower())
    }
}

impl fmt::Display for RiskCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.display_lower())
    }
}

impl fmt::Display for EvidenceValidationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.display_lower())
    }
}

fn normalize_enum_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::{
        Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory, RiskCode,
        Severity,
    };

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
                  "risk_code": "missing-timeout",
                  "anchor_id": "A0001",
                  "file_path": "src/payment/client.ts",
                  "line": 42,
                  "title": "HTTP request has no timeout",
                  "body": "The callback call can hang indefinitely.",
                  "suggested_fix": "Use a request-scoped timeout.",
                  "confidence": "high",
                  "effort": "quick",
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
        assert_eq!(review.findings[0].risk_code, Some(RiskCode::MissingTimeout));
        assert_eq!(review.findings[0].anchor_id.as_deref(), Some("A0001"));
        assert_eq!(review.findings[0].effort, Effort::Quick);
        assert_eq!(review.findings[0].evidence_status, None);
    }

    #[test]
    fn missing_effort_defaults_to_moderate_and_legacy_confidence_is_ignored() {
        let review: ReviewAnalysis = serde_json::from_str(
            r#"{
              "summary": "Short MR-level review summary.",
              "overall_risk": "medium",
              "findings": [
                {
                  "severity": "HIGH",
                  "category": "reliability",
                  "file_path": "src/payment/client.ts",
                  "line": 42,
                  "title": "HTTP request has no timeout",
                  "body": "The callback call can hang indefinitely.",
                  "suggested_fix": null,
                  "confidence": "low",
                  "actionable": true
                }
              ],
              "test_coverage_note": null,
              "privacy_note": null
            }"#,
        )
        .unwrap();

        assert_eq!(review.findings[0].effort, Effort::Moderate);
    }

    #[test]
    fn parses_effort_variants_flexibly() {
        for value in ["quick", "low", "small", "easy"] {
            let parsed: Effort = serde_json::from_str(&format!(r#""{value}""#)).unwrap();
            assert_eq!(parsed, Effort::Quick);
        }
        for value in ["moderate", "medium", "normal"] {
            let parsed: Effort = serde_json::from_str(&format!(r#""{value}""#)).unwrap();
            assert_eq!(parsed, Effort::Moderate);
        }
        for value in ["heavy", "high", "large", "hard"] {
            let parsed: Effort = serde_json::from_str(&format!(r#""{value}""#)).unwrap();
            assert_eq!(parsed, Effort::Heavy);
        }
    }

    #[test]
    fn parses_risk_code_variants_flexibly() {
        for value in [
            "missing_timeout",
            "MISSING_TIMEOUT",
            "missing-timeout",
            "missing timeout",
        ] {
            let json = format!(r#""{value}""#);
            let parsed: RiskCode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, RiskCode::MissingTimeout);
        }
    }

    #[test]
    fn parses_evidence_validation_status_variants_flexibly() {
        let parsed: EvidenceValidationStatus = serde_json::from_str(r#""weak-evidence""#).unwrap();

        assert_eq!(parsed, EvidenceValidationStatus::WeakEvidence);
    }

    #[test]
    fn unknown_risk_code_does_not_crash() {
        let parsed: RiskCode = serde_json::from_str(r#""surprising_new_risk""#).unwrap();

        assert_eq!(parsed, RiskCode::Other);
    }
}
