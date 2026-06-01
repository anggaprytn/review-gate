use crate::review::types::{
    Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode, Severity,
};

const POSITIVE_PHRASES: &[&str] = &[
    "positive:",
    "good practice",
    "improved",
    "enhanced",
    "correctly",
    "no action needed",
    "commendable",
    "this change improves",
    "fix for",
    "removed",
    "hardening",
    "security improvement",
    "robust",
    "redacted",
];

const NO_ACTION_PHRASES: &[&str] = &[
    "no action needed",
    "no fix needed",
    "this is correct",
    "this change correctly",
    "this is a good practice",
];

const CRITICAL_PHRASES: &[&str] = &[
    "production build failure",
    "data loss",
    "credential exposure",
    "auth bypass",
    "sql injection",
    "command injection",
    "destructive migration",
    "session remains active after compromised device detection",
];

const MISLEADING_TITLE_PREFIXES: &[&str] = &[
    "critical:",
    "high:",
    "positive:",
    "good practice:",
    "fix for",
    "improved",
];

pub fn normalize_review_analysis(mut input: ReviewAnalysis) -> ReviewAnalysis {
    input.findings = normalize_findings(input.findings);
    input.overall_risk = normalized_overall_risk(&input.findings);
    input
}

pub fn normalize_findings(findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    findings.into_iter().map(normalize_finding).collect()
}

fn normalize_finding(mut finding: ReviewFinding) -> ReviewFinding {
    let original_title = finding.title.clone();
    finding.title = cleanup_title(&finding.title);

    let no_action = no_action_signal(&original_title)
        || no_action_signal(&finding.title)
        || no_action_signal(&finding.body)
        || no_action_suggested_fix(finding.suggested_fix.as_deref());
    let missing_fix = missing_suggested_fix(finding.suggested_fix.as_deref());
    let positive = is_positive_note(&finding, &original_title) || missing_fix || no_action;

    if positive || no_action || !finding.actionable {
        finding.severity = Severity::Note;
        finding.actionable = false;
        finding.risk_code = Some(RiskCode::PositiveNote);
        finding.effort = Effort::Quick;
        return finding;
    }

    if finding.severity == Severity::Critical && !critical_allowed(&finding) {
        finding.severity = Severity::High;
    }

    finding
}

fn is_positive_note(finding: &ReviewFinding, original_title: &str) -> bool {
    finding.risk_code == Some(RiskCode::PositiveNote)
        || category_is_positive_note(&finding.category)
        || positive_signal(original_title)
        || positive_signal(&finding.title)
        || positive_signal(&finding.body)
        || no_action_suggested_fix(finding.suggested_fix.as_deref())
}

fn category_is_positive_note(category: &ReviewCategory) -> bool {
    category
        .display_lower()
        .eq_ignore_ascii_case("positive_note")
}

fn positive_signal(value: &str) -> bool {
    let lower = normalize_text(value);
    POSITIVE_PHRASES.iter().any(|phrase| lower.contains(phrase))
}

fn no_action_signal(value: &str) -> bool {
    let lower = normalize_text(value);
    if lower == "none" {
        return true;
    }
    NO_ACTION_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
}

fn missing_suggested_fix(value: Option<&str>) -> bool {
    value.map(str::trim).is_none_or(str::is_empty)
}

fn no_action_suggested_fix(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let lower = normalize_text(value);
    lower == "none"
        || matches!(
            lower.as_str(),
            "no action needed" | "no fix needed" | "no fix required"
        )
}

fn critical_allowed(finding: &ReviewFinding) -> bool {
    finding.actionable
        && !missing_suggested_fix(finding.suggested_fix.as_deref())
        && !no_action_suggested_fix(finding.suggested_fix.as_deref())
        && (critical_risk_code(finding.risk_code) || critical_text_signal(finding))
}

fn critical_risk_code(risk_code: Option<RiskCode>) -> bool {
    matches!(
        risk_code,
        Some(
            RiskCode::AuthBypass
                | RiskCode::MissingAuthorizationCheck
                | RiskCode::SecretLeak
                | RiskCode::PiiOrSecretLogging
                | RiskCode::SqlInjection
                | RiskCode::CommandInjection
                | RiskCode::UnsafeDeserialization
                | RiskCode::DataIntegrityRisk
                | RiskCode::MigrationRisk
        )
    )
}

fn critical_text_signal(finding: &ReviewFinding) -> bool {
    let text = normalize_text(&format!("{} {}", finding.title, finding.body));
    CRITICAL_PHRASES.iter().any(|phrase| text.contains(phrase))
}

fn cleanup_title(title: &str) -> String {
    let mut cleaned = title.trim();
    loop {
        let lower = cleaned.to_ascii_lowercase();
        let Some(prefix) = MISLEADING_TITLE_PREFIXES
            .iter()
            .find(|prefix| lower.starts_with(**prefix))
        else {
            break;
        };
        cleaned = cleaned[prefix.len()..]
            .trim_start_matches([':', '-', ' '])
            .trim();
    }

    sentence_case_title(cleaned)
}

fn sentence_case_title(title: &str) -> String {
    let words = title
        .split_whitespace()
        .map(cleanup_title_word)
        .collect::<Vec<_>>();
    let mut output = words.join(" ");
    if let Some(first) = output.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    output
}

fn cleanup_title_word(word: &str) -> String {
    let trimmed = word.trim();
    if trimmed.is_empty() || is_preserved_word(trimmed) {
        return trimmed.to_string();
    }
    if trimmed.chars().any(|ch| ch.is_ascii_lowercase()) {
        let mut chars = trimmed.chars();
        let Some(first) = chars.next() else {
            return String::new();
        };
        if first.is_ascii_uppercase() && chars.clone().all(|ch| ch.is_ascii_lowercase()) {
            return trimmed.to_ascii_lowercase();
        }
    }
    trimmed.to_string()
}

fn is_preserved_word(word: &str) -> bool {
    matches!(
        word,
        "API"
            | "HTTP"
            | "HTTPS"
            | "JWT"
            | "PII"
            | "SQL"
            | "URL"
            | "GitLab"
            | "GitHub"
            | "Redux"
            | "Sentry"
    )
}

fn normalized_overall_risk(findings: &[ReviewFinding]) -> OverallRisk {
    findings
        .iter()
        .filter(|finding| finding.actionable)
        .map(|finding| match finding.severity {
            Severity::Critical => OverallRisk::Critical,
            Severity::High => OverallRisk::High,
            Severity::Medium => OverallRisk::Medium,
            Severity::Low => OverallRisk::Low,
            Severity::Note => OverallRisk::Note,
        })
        .min_by_key(|risk| overall_sort_key(*risk))
        .unwrap_or(OverallRisk::Note)
}

fn overall_sort_key(risk: OverallRisk) -> u8 {
    match risk {
        OverallRisk::Critical => 0,
        OverallRisk::High => 1,
        OverallRisk::Medium => 2,
        OverallRisk::Low => 3,
        OverallRisk::Note => 4,
    }
}

fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{cleanup_title, normalize_review_analysis};
    use crate::{
        counters::count_findings_from_analysis,
        review::types::{
            Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode, Severity,
        },
    };

    #[test]
    fn positive_note_risk_code_becomes_note_and_non_actionable() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::High,
            Some(RiskCode::PositiveNote),
            "Credentials removed",
            "This change improves security.",
            Some("No action needed"),
        )]));

        assert_note(&normalized.findings[0]);
        assert_eq!(
            normalized.findings[0].risk_code,
            Some(RiskCode::PositiveNote)
        );
    }

    #[test]
    fn no_action_needed_becomes_note_and_non_actionable() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::High,
            Some(RiskCode::MissingTimeout),
            "Timeout handling",
            "No action needed.",
            Some("No action needed"),
        )]));

        assert_note(&normalized.findings[0]);
    }

    #[test]
    fn good_practice_title_becomes_note_and_non_actionable() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Medium,
            Some(RiskCode::MaintainabilityRisk),
            "Good Practice: Add screen security hook",
            "This is a good practice.",
            Some("No fix needed"),
        )]));

        assert_note(&normalized.findings[0]);
        assert_eq!(normalized.findings[0].title, "Add screen security hook");
    }

    #[test]
    fn critical_password_redacted_becomes_note_and_non_actionable() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Critical,
            Some(RiskCode::SecretLeak),
            "Critical: Password Redacted From Sentry Logs",
            "Password redacted from Sentry logs.",
            Some("No action needed"),
        )]));

        assert_note(&normalized.findings[0]);
        assert_eq!(
            normalized.findings[0].title,
            "Password redacted from Sentry logs"
        );
    }

    #[test]
    fn critical_positive_finding_is_downgraded() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Critical,
            Some(RiskCode::Other),
            "Positive: Logout cleanup improved",
            "The logout cleanup is improved.",
            Some("No fix needed"),
        )]));

        assert_note(&normalized.findings[0]);
    }

    #[test]
    fn critical_auth_bypass_actionable_remains_critical() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Critical,
            Some(RiskCode::AuthBypass),
            "Session check can be bypassed",
            "The new guard can allow auth bypass.",
            Some("Reject the request before loading the session."),
        )]));

        assert_eq!(normalized.findings[0].severity, Severity::Critical);
        assert!(normalized.findings[0].actionable);
    }

    #[test]
    fn critical_sql_injection_actionable_remains_critical() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Critical,
            Some(RiskCode::SqlInjection),
            "SQL injection in search",
            "User input is interpolated into SQL.",
            Some("Use parameterized queries."),
        )]));

        assert_eq!(normalized.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn critical_with_no_suggested_fix_and_positive_body_becomes_note() {
        let normalized = normalize_review_analysis(analysis(vec![finding(
            Severity::Critical,
            Some(RiskCode::Other),
            "Hardening added",
            "This change improves credential cleanup.",
            None,
        )]));

        assert_note(&normalized.findings[0]);
    }

    #[test]
    fn open_actionable_counter_excludes_normalized_notes() {
        let normalized = normalize_review_analysis(analysis(vec![
            finding(
                Severity::High,
                Some(RiskCode::MissingTimeout),
                "Timeout missing",
                "The request can hang.",
                Some("Add a timeout."),
            ),
            finding(
                Severity::Critical,
                Some(RiskCode::PositiveNote),
                "Positive: Credentials removed",
                "No action needed.",
                Some("No action needed"),
            ),
        ]));

        let counters = count_findings_from_analysis(&normalized);

        assert_eq!(counters.open_actionable, 1);
        assert_eq!(counters.note, 1);
    }

    #[test]
    fn title_cleanup_removes_misleading_prefixes() {
        assert_eq!(
            cleanup_title("Critical: Password Redacted From Sentry Logs"),
            "Password redacted from Sentry logs"
        );
        assert_eq!(
            cleanup_title("Fix for Missing Authorization Check"),
            "Missing authorization check"
        );
    }

    fn assert_note(finding: &ReviewFinding) {
        assert_eq!(finding.severity, Severity::Note);
        assert!(!finding.actionable);
        assert_eq!(finding.effort, Effort::Quick);
    }

    fn analysis(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Critical,
        }
    }

    fn finding(
        severity: Severity,
        risk_code: Option<RiskCode>,
        title: &str,
        body: &str,
        suggested_fix: Option<&str>,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Correctness,
            risk_code,
            anchor_id: None,
            file_path: None,
            line: None,
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: suggested_fix.map(str::to_string),
            effort: Effort::Moderate,
            actionable: true,
        }
    }
}
