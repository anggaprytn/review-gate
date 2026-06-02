use crate::review::{
    anchors::{AnchoredDiffContext, ReviewLineAnchor},
    types::{
        EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding,
        RiskCode, Severity,
    },
};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceValidationResult {
    pub status: EvidenceValidationStatus,
    pub reason: String,
}

const NEARBY_ANCHOR_WINDOW: usize = 5;

const POSITIVE_PHRASES: &[&str] = &[
    "positive:",
    "good practice",
    "improved",
    "enhanced",
    "correctly",
    "no action needed",
    "this change improves",
    "fix for",
    "removed",
    "hardening",
    "security improvement",
    "robust",
    "redacted",
];

const SPECULATIVE_PHRASES: &[&str] = &[
    " may ",
    " might ",
    " could ",
    " if ",
    " unless ",
    "not visible",
    "unclear",
    "cannot confirm",
    "cannot be confirmed",
    "defaults are not visible",
];

const STALE_CONTEXT_PHRASES: &[&str] = &[
    "old state",
    "previously",
    "before this change",
    "before the current diff",
    "prior implementation",
];

const STOPWORDS: &[&str] = &[
    "about", "action", "added", "after", "against", "also", "because", "before", "being",
    "between", "body", "cannot", "change", "changed", "code", "could", "does", "finding", "from",
    "have", "high", "impact", "into", "line", "lines", "might", "more", "must", "needs", "risk",
    "should", "this", "through", "title", "unless", "when", "where", "with", "without",
];

pub fn validate_review_analysis_evidence(
    mut analysis: ReviewAnalysis,
    anchors: &AnchoredDiffContext,
) -> ReviewAnalysis {
    analysis.findings = analysis
        .findings
        .into_iter()
        .map(|finding| validate_finding_evidence(finding, anchors))
        .collect();
    analysis.overall_risk = overall_risk_from_findings(&analysis.findings);
    analysis
}

pub fn validate_finding_evidence(
    mut finding: ReviewFinding,
    anchors: &AnchoredDiffContext,
) -> ReviewFinding {
    if !matches!(finding.severity, Severity::Critical | Severity::High) {
        return finding;
    }

    let result = validate_high_priority_finding(&finding, anchors);
    apply_validation_result(&mut finding, &result, anchors);
    finding.evidence_status = Some(result.status);
    finding.evidence_reason = Some(result.reason);
    finding
}

pub fn validate_high_priority_finding(
    finding: &ReviewFinding,
    anchors: &AnchoredDiffContext,
) -> EvidenceValidationResult {
    if positive_change_signal(finding) {
        return result(
            EvidenceValidationStatus::PositiveChange,
            "finding describes a positive or no-action change",
        );
    }

    let location = match resolve_location(finding, anchors) {
        LocationEvidence::Valid(location) => location,
        LocationEvidence::MissingAnchor { fallback_valid } => {
            return result(
                EvidenceValidationStatus::NotInDiff,
                if fallback_valid {
                    "anchor_id is not present in the current anchored diff; file/line fallback exists"
                } else {
                    "anchor_id is not present in the current anchored diff"
                },
            );
        }
        LocationEvidence::MissingFileLine => {
            return result(
                EvidenceValidationStatus::NotInDiff,
                "finding does not map to a current changed or context line",
            );
        }
    };

    let finding_text = finding_text(finding);
    let finding_text_lower = finding_text.to_ascii_lowercase();
    let evidence_text = nearby_evidence_text(anchors, location.anchor_index);
    let evidence_lower = evidence_text.to_ascii_lowercase();
    let build_break = build_break_evidence(&evidence_lower);
    let risk_supported = risk_specific_evidence(finding, &finding_text_lower, &evidence_lower);
    let generic_supported = generic_keyword_overlap(&finding_text_lower, &evidence_lower);
    let strong_evidence = build_break || risk_supported;

    if speculative_signal(&finding_text_lower) && !strong_evidence {
        let status = if stale_context_signal(&finding_text_lower) {
            EvidenceValidationStatus::StaleContext
        } else {
            EvidenceValidationStatus::WeakEvidence
        };
        return result(
            status,
            "finding uses speculative or stale language without concrete supporting diff evidence",
        );
    }

    if build_break {
        return result(
            EvidenceValidationStatus::Validated,
            "current changed lines contain compiler-breaking syntax evidence",
        );
    }

    if risk_supported || generic_supported {
        return result(
            EvidenceValidationStatus::Validated,
            "finding is supported by the anchored changed lines",
        );
    }

    result(
        EvidenceValidationStatus::WeakEvidence,
        "nearby changed lines do not support the high-priority risk claim",
    )
}

fn apply_validation_result(
    finding: &mut ReviewFinding,
    result: &EvidenceValidationResult,
    anchors: &AnchoredDiffContext,
) {
    match result.status {
        EvidenceValidationStatus::Validated => {
            if finding.severity == Severity::Critical
                && build_break_finding(finding, anchors)
                && !critical_build_break_allowed(finding)
            {
                finding.severity = Severity::High;
            }
        }
        EvidenceValidationStatus::PositiveChange => {
            finding.severity = Severity::Note;
            finding.actionable = false;
            finding.risk_code = Some(RiskCode::PositiveNote);
        }
        EvidenceValidationStatus::NotInDiff => {
            finding.severity = Severity::Medium;
            finding.actionable = fallback_line_anchor(finding, anchors).is_some();
        }
        EvidenceValidationStatus::StaleContext => {
            finding.severity = match finding.severity {
                Severity::Critical | Severity::High => Severity::Medium,
                severity => severity,
            };
        }
        EvidenceValidationStatus::WeakEvidence
        | EvidenceValidationStatus::NeedsManualConfirmation => {
            finding.severity = match finding.severity {
                Severity::Critical if critical_risk_code(finding.risk_code) => Severity::High,
                Severity::Critical | Severity::High => Severity::Medium,
                severity => severity,
            };
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ValidLocation {
    anchor_index: usize,
}

enum LocationEvidence {
    Valid(ValidLocation),
    MissingAnchor { fallback_valid: bool },
    MissingFileLine,
}

fn resolve_location(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> LocationEvidence {
    if let Some(anchor_id) = finding
        .anchor_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(anchor_index) = anchors
            .anchors
            .iter()
            .position(|anchor| anchor.anchor_id == anchor_id)
        {
            return LocationEvidence::Valid(ValidLocation { anchor_index });
        }
        return LocationEvidence::MissingAnchor {
            fallback_valid: fallback_line_anchor(finding, anchors).is_some(),
        };
    }

    fallback_line_anchor(finding, anchors)
        .map(|anchor_index| LocationEvidence::Valid(ValidLocation { anchor_index }))
        .unwrap_or(LocationEvidence::MissingFileLine)
}

fn fallback_line_anchor(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> Option<usize> {
    let file_path = finding.file_path.as_deref()?.trim();
    let line = finding.line?;
    if file_path.is_empty() {
        return None;
    }

    anchors
        .anchors
        .iter()
        .position(|anchor| anchor_matches_file_line(anchor, file_path, line))
}

fn anchor_matches_file_line(anchor: &ReviewLineAnchor, file_path: &str, line: u32) -> bool {
    let file_matches = anchor.file_path == file_path
        || anchor.new_path == file_path
        || anchor.old_path == file_path;
    file_matches && (anchor.new_line == Some(line) || anchor.old_line == Some(line))
}

fn nearby_evidence_text(anchors: &AnchoredDiffContext, anchor_index: usize) -> String {
    let Some(anchor) = anchors.anchors.get(anchor_index) else {
        return String::new();
    };
    let start = anchor_index.saturating_sub(NEARBY_ANCHOR_WINDOW);
    let end = (anchor_index + NEARBY_ANCHOR_WINDOW + 1).min(anchors.anchors.len());

    anchors.anchors[start..end]
        .iter()
        .filter(|nearby| {
            nearby.file_path == anchor.file_path
                || nearby.new_path == anchor.new_path
                || nearby.old_path == anchor.old_path
        })
        .map(|nearby| nearby.content_preview.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn finding_text(finding: &ReviewFinding) -> String {
    format!(
        "{} {} {} {}",
        finding.title,
        finding
            .risk_code
            .map(|risk_code| risk_code.display_lower())
            .unwrap_or_default(),
        finding.body,
        finding.suggested_fix.as_deref().unwrap_or_default()
    )
}

fn positive_change_signal(finding: &ReviewFinding) -> bool {
    if finding.risk_code == Some(RiskCode::PositiveNote) {
        return true;
    }
    if matches!(
        finding.category,
        ReviewCategory::Other(ref value) if value == "positive_note"
    ) {
        return true;
    }
    let text = finding_text(finding).to_ascii_lowercase();
    POSITIVE_PHRASES.iter().any(|phrase| text.contains(phrase))
}

fn speculative_signal(text: &str) -> bool {
    let padded = format!(" {text} ");
    SPECULATIVE_PHRASES
        .iter()
        .any(|phrase| padded.contains(phrase))
        || STALE_CONTEXT_PHRASES
            .iter()
            .any(|phrase| padded.contains(phrase))
}

fn stale_context_signal(text: &str) -> bool {
    STALE_CONTEXT_PHRASES
        .iter()
        .any(|phrase| text.contains(phrase))
}

fn risk_specific_evidence(finding: &ReviewFinding, finding_text: &str, evidence: &str) -> bool {
    match finding.risk_code {
        Some(RiskCode::MissingTimeout) => network_call_signal(evidence),
        Some(RiskCode::SqlInjection) => sql_signal(evidence) && interpolation_signal(evidence),
        Some(RiskCode::PiiOrSecretLogging) | Some(RiskCode::SecretLeak) => {
            logging_signal(evidence) && sensitive_data_signal(evidence)
        }
        Some(RiskCode::AuthBypass) | Some(RiskCode::MissingAuthorizationCheck) => {
            auth_signal(evidence)
        }
        Some(RiskCode::DataIntegrityRisk) | Some(RiskCode::MigrationRisk) => {
            data_integrity_signal(evidence)
        }
        Some(RiskCode::ApiContractBreak) => api_contract_signal(evidence),
        Some(RiskCode::CommandInjection) => command_injection_signal(evidence),
        Some(RiskCode::UnsafeDeserialization) => unsafe_deserialization_signal(evidence),
        Some(RiskCode::UnboundedRetry) => retry_signal(evidence),
        Some(RiskCode::UnclosedResource) => resource_signal(evidence),
        Some(RiskCode::NilOrNullRisk) => null_signal(evidence),
        Some(RiskCode::PerformanceRegression) => performance_signal(evidence),
        Some(RiskCode::WeakErrorHandling) => error_handling_signal(evidence),
        Some(RiskCode::MissingTestCoverage)
        | Some(RiskCode::ObservabilityGap)
        | Some(RiskCode::MaintainabilityRisk)
        | Some(RiskCode::PositiveNote)
        | Some(RiskCode::Other)
        | None => category_specific_evidence(finding, finding_text, evidence),
    }
}

fn category_specific_evidence(finding: &ReviewFinding, finding_text: &str, evidence: &str) -> bool {
    match finding.category {
        ReviewCategory::Correctness => {
            build_break_evidence(evidence)
                || (contains_any(finding_text, &["build", "compile", "syntax"])
                    && contains_any(evidence, &["todo", "panic!", "unwrap(", "expect("]))
        }
        ReviewCategory::Security => {
            auth_signal(evidence)
                || sql_signal(evidence)
                || command_injection_signal(evidence)
                || sensitive_data_signal(evidence)
        }
        ReviewCategory::Privacy => logging_signal(evidence) && sensitive_data_signal(evidence),
        ReviewCategory::Reliability => {
            network_call_signal(evidence) || retry_signal(evidence) || resource_signal(evidence)
        }
        ReviewCategory::ApiContract => api_contract_signal(evidence),
        ReviewCategory::DataIntegrity => data_integrity_signal(evidence),
        ReviewCategory::DeploymentRisk => {
            build_break_evidence(evidence) || contains_any(evidence, &["deploy", "release", "ci"])
        }
        ReviewCategory::Observability => contains_any(
            evidence,
            &["log", "logger", "metric", "trace", "span", "sentry"],
        ),
        ReviewCategory::TestCoverage | ReviewCategory::Other(_) => false,
    }
}

fn generic_keyword_overlap(finding_text: &str, evidence: &str) -> bool {
    let evidence_tokens = token_set(evidence);
    let mut overlap = 0usize;
    for token in token_set(finding_text) {
        if evidence_tokens.contains(&token) {
            overlap += 1;
        }
        if overlap >= 2 {
            return true;
        }
    }
    false
}

fn token_set(value: &str) -> HashSet<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map(str::trim)
        .filter(|token| token.len() >= 4)
        .map(str::to_ascii_lowercase)
        .filter(|token| !STOPWORDS.contains(&token.as_str()))
        .collect()
}

fn build_break_finding(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> bool {
    let Some(anchor_index) = (match resolve_location(finding, anchors) {
        LocationEvidence::Valid(location) => Some(location.anchor_index),
        LocationEvidence::MissingAnchor { .. } | LocationEvidence::MissingFileLine => None,
    }) else {
        return false;
    };
    build_break_evidence(&nearby_evidence_text(anchors, anchor_index).to_ascii_lowercase())
}

fn build_break_evidence(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "<<<<<<<",
            "=======",
            ">>>>>>>",
            "return @",
            "=> @",
            "= @",
            " @../../",
            "syntax error",
            "unterminated",
            "unexpected token",
            "invalid token",
        ],
    )
}

fn critical_build_break_allowed(finding: &ReviewFinding) -> bool {
    let text = finding_text(finding).to_ascii_lowercase();
    contains_any(
        &text,
        &[
            "deploy",
            "release",
            "production",
            "data loss",
            "destructive migration",
            "migration",
        ],
    )
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

fn network_call_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "fetch(",
            "axios",
            "httpclient",
            "http.",
            "https.",
            "request(",
            "client.get",
            "client.post",
            "reqwest",
            "timeout",
            "abortcontroller",
            "settimeout",
        ],
    )
}

fn sql_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "select ", "insert ", "update ", "delete ", " from ", " where ", "query(", "execute(",
            "rawquery",
        ],
    )
}

fn interpolation_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "${", "$", "format!(", "+ user", "+ input", "concat", "`select",
        ],
    )
}

fn logging_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "console.log",
            "console.error",
            "logger.",
            "log.",
            "log(",
            "sentry",
            "captureexception",
            "capturemessage",
            "println!",
            "dbg!",
        ],
    )
}

fn sensitive_data_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "authorization",
            "cookie",
            "token",
            "password",
            "secret",
            "apikey",
            "api_key",
            "email",
            "phone",
            "ssn",
            "bearer",
        ],
    )
}

fn auth_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "auth",
            "session",
            "guard",
            "permission",
            "role",
            "policy",
            "acl",
            "jwt",
            "login",
            "authorize",
            "isadmin",
            "security",
        ],
    )
}

fn data_integrity_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "delete",
            "clear",
            "write",
            "save",
            "update",
            "insert",
            "migration",
            "cache",
            "storage",
            "database",
            "transaction",
            "state",
            "token",
            "persist",
        ],
    )
}

fn api_contract_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "json",
            "schema",
            "response",
            "request",
            "status",
            "field",
            "api",
            "endpoint",
            "serde",
            "deserialize",
        ],
    )
}

fn command_injection_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "command(",
            "exec(",
            "spawn(",
            "shell",
            "bash",
            "sh -c",
            "processbuilder",
            "std::process",
        ],
    )
}

fn unsafe_deserialization_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "deserialize",
            "pickle",
            "yaml.load",
            "objectinputstream",
            "eval(",
            "fromjson",
        ],
    )
}

fn retry_signal(evidence: &str) -> bool {
    contains_any(evidence, &["retry", "while true", "loop {", "backoff"])
}

fn resource_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "open(", "connect(", "close", "drop", "file", "stream", "socket",
        ],
    )
}

fn null_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["null", "nil", "none", "unwrap(", "expect(", "optional"],
    )
}

fn performance_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "for ", "while ", "loop", "clone(", "collect(", "n+1", "query(",
        ],
    )
}

fn error_handling_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "unwrap(", "expect(", "catch", "except", "error", "panic!", "throw",
        ],
    )
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn overall_risk_from_findings(findings: &[ReviewFinding]) -> OverallRisk {
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
        .min_by_key(|risk| match risk {
            OverallRisk::Critical => 0,
            OverallRisk::High => 1,
            OverallRisk::Medium => 2,
            OverallRisk::Low => 3,
            OverallRisk::Note => 4,
        })
        .unwrap_or(OverallRisk::Note)
}

fn result(status: EvidenceValidationStatus, reason: &str) -> EvidenceValidationResult {
    EvidenceValidationResult {
        status,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_review_analysis_evidence;
    use crate::{
        gitlab::types::MergeRequestDiff,
        review::{
            anchors::AnchorBuilder,
            types::{
                Effort, EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory,
                ReviewFinding, RiskCode, Severity,
            },
        },
    };

    #[test]
    fn high_with_valid_anchor_and_matching_evidence_remains_high() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Reliability,
                Some(RiskCode::MissingTimeout),
                Some("A0001"),
                Some("src/client.ts"),
                Some(1),
                "HTTP request has no timeout",
                "fetch can hang indefinitely.",
                "Pass an AbortController timeout.",
                true,
            )],
            "@@ -0,0 +1 @@\n+fetch('/api/payments')",
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert_eq!(
            analysis.findings[0].evidence_status,
            Some(EvidenceValidationStatus::Validated)
        );
    }

    #[test]
    fn high_with_invalid_anchor_downgrades_to_medium() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Reliability,
                Some(RiskCode::MissingTimeout),
                Some("A9999"),
                Some("src/client.ts"),
                Some(1),
                "HTTP request has no timeout",
                "fetch can hang indefinitely.",
                "Pass an AbortController timeout.",
                true,
            )],
            "@@ -0,0 +1 @@\n+fetch('/api/payments')",
        );

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert!(analysis.findings[0].actionable);
        assert_eq!(
            analysis.findings[0].evidence_status,
            Some(EvidenceValidationStatus::NotInDiff)
        );
    }

    #[test]
    fn high_with_stale_language_and_no_evidence_downgrades() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Security,
                Some(RiskCode::AuthBypass),
                Some("A0001"),
                Some("src/app.ts"),
                Some(1),
                "Auth bypass may remain from old state",
                "Previously this route was unguarded before this change.",
                "Add a permission guard.",
                true,
            )],
            "@@ -0,0 +1 @@\n+export const route = '/status'",
        );

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert_eq!(
            analysis.findings[0].evidence_status,
            Some(EvidenceValidationStatus::StaleContext)
        );
    }

    #[test]
    fn critical_positive_note_becomes_note_non_actionable() {
        let analysis = validated(
            vec![finding(
                Severity::Critical,
                ReviewCategory::Security,
                Some(RiskCode::PositiveNote),
                Some("A0001"),
                Some("src/auth.ts"),
                Some(1),
                "Positive: auth hardening improved",
                "This change correctly adds a permission guard.",
                "No action needed.",
                true,
            )],
            "@@ -0,0 +1 @@\n+requirePermission(session)",
        );

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
        assert_eq!(
            analysis.findings[0].evidence_status,
            Some(EvidenceValidationStatus::PositiveChange)
        );
    }

    #[test]
    fn high_missing_timeout_without_http_evidence_downgrades() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Reliability,
                Some(RiskCode::MissingTimeout),
                Some("A0001"),
                Some("src/config.ts"),
                Some(1),
                "Request has no timeout",
                "The operation can hang.",
                "Add a timeout.",
                true,
            )],
            "@@ -0,0 +1 @@\n+const enabled = true",
        );

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn high_missing_timeout_with_fetch_no_timeout_evidence_remains_high() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Reliability,
                Some(RiskCode::MissingTimeout),
                Some("A0001"),
                Some("src/client.ts"),
                Some(1),
                "Fetch has no timeout",
                "fetch can hang.",
                "Use AbortController.",
                true,
            )],
            "@@ -0,0 +1 @@\n+return fetch(url)",
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    #[test]
    fn high_sql_injection_with_sql_interpolation_evidence_remains_high() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Security,
                Some(RiskCode::SqlInjection),
                Some("A0001"),
                Some("src/db.ts"),
                Some(1),
                "SQL injection through interpolated query",
                "User input is interpolated into SQL.",
                "Use parameterized queries.",
                true,
            )],
            "@@ -0,0 +1 @@\n+db.query(`SELECT * FROM users WHERE id = ${userId}`)",
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    #[test]
    fn high_pii_logging_with_authorization_log_evidence_remains_high() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Privacy,
                Some(RiskCode::PiiOrSecretLogging),
                Some("A0001"),
                Some("src/log.ts"),
                Some(1),
                "Authorization token is logged",
                "The token can be exposed in logs.",
                "Remove the sensitive value from logs.",
                true,
            )],
            "@@ -0,0 +1 @@\n+console.log('Authorization', request.headers.Authorization)",
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    #[test]
    fn high_auth_bypass_with_no_auth_evidence_downgrades() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Security,
                Some(RiskCode::AuthBypass),
                Some("A0001"),
                Some("src/route.ts"),
                Some(1),
                "Auth bypass",
                "The route may skip authorization.",
                "Add an auth guard.",
                true,
            )],
            "@@ -0,0 +1 @@\n+return renderStatusPage()",
        );

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn build_break_invalid_syntax_remains_high() {
        let analysis = validated(
            vec![finding(
                Severity::High,
                ReviewCategory::Correctness,
                None,
                Some("A0001"),
                Some("src/app.ts"),
                Some(1),
                "Build break from malformed return",
                "The changed line is syntactically invalid.",
                "Remove the corrupted token.",
                true,
            )],
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert_eq!(
            analysis.findings[0].evidence_status,
            Some(EvidenceValidationStatus::Validated)
        );
    }

    #[test]
    fn critical_build_break_downgrades_to_high_without_deploy_evidence() {
        let analysis = validated(
            vec![finding(
                Severity::Critical,
                ReviewCategory::Correctness,
                None,
                Some("A0001"),
                Some("src/app.ts"),
                Some(1),
                "Build break from malformed return",
                "The changed line is syntactically invalid.",
                "Remove the corrupted token.",
                true,
            )],
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    #[test]
    fn validation_does_not_require_raw_diff_or_raw_llm_output() {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff("src/client.ts", "@@ -0,0 +1 @@\n+fetch('/api')"));
        let anchors = builder.finish(false);

        let analysis = validate_review_analysis_evidence(
            analysis(vec![finding(
                Severity::High,
                ReviewCategory::Reliability,
                Some(RiskCode::MissingTimeout),
                Some("A0001"),
                Some("src/client.ts"),
                Some(1),
                "Fetch has no timeout",
                "fetch can hang.",
                "Use AbortController.",
                true,
            )]),
            &anchors,
        );

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    fn validated(findings: Vec<ReviewFinding>, diff_body: &str) -> ReviewAnalysis {
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff("src/client.ts", diff_body));
        let anchors = builder.finish(false);
        validate_review_analysis_evidence(analysis(findings), &anchors)
    }

    fn analysis(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Medium,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finding(
        severity: Severity,
        category: ReviewCategory,
        risk_code: Option<RiskCode>,
        anchor_id: Option<&str>,
        file_path: Option<&str>,
        line: Option<u32>,
        title: &str,
        body: &str,
        suggested_fix: &str,
        actionable: bool,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category,
            risk_code,
            anchor_id: anchor_id.map(str::to_string),
            file_path: file_path.map(str::to_string),
            line,
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: Some(suggested_fix.to_string()),
            effort: Effort::Quick,
            actionable,
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
}
