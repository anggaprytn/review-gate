use crate::review::{
    anchors::AnchoredDiffContext,
    types::{ReviewFinding, RiskCode},
};
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimValidationVerdict {
    Valid,
    Invalid,
    PartiallyValid,
    NeedsManualConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimValidationResult {
    pub verdict: ClaimValidationVerdict,
    pub reason: String,
}

static API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            AIza[0-9A-Za-z_-]{20,}
            | AKIA[0-9A-Z]{16}
            | (?i:api[_-]?key|secret|token)\s*[:=]\s*["'][^"'\s]{16,}["']
        )
        "#,
    )
    .expect("valid API key evidence regex")
});

static IDENTIFIER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"`?([A-Za-z_$][A-Za-z0-9_$]*)`?").expect("valid identifier regex")
});

pub fn validate_finding_claim_against_diff(
    finding: &ReviewFinding,
    diff_context: Option<&AnchoredDiffContext>,
) -> ClaimValidationResult {
    let evidence = diff_context
        .map(|context| diff_evidence_for_finding(finding, context))
        .unwrap_or_default();
    validate_finding_claim(finding, &evidence)
}

pub fn validate_finding_claim_against_current_file(
    finding: &ReviewFinding,
    current_file: Option<&str>,
) -> ClaimValidationResult {
    validate_finding_claim(finding, current_file.unwrap_or_default())
}

pub fn validate_finding_claim(finding: &ReviewFinding, evidence: &str) -> ClaimValidationResult {
    let text = finding_text(finding);
    let evidence = evidence.to_ascii_lowercase();

    if missing_await_claim(&text) {
        return validate_missing_await_claim(&text, &evidence);
    }
    if await_in_non_async_function_claim(&text) {
        return validate_await_in_non_async_function_claim(&evidence);
    }
    if variable_out_of_scope_finally_claim(&text) {
        return validate_variable_scope_finally_claim(&text, &evidence);
    }
    if build_break_invalid_syntax_claim(&text) {
        return validate_build_break_claim(&evidence);
    }
    if toctou_symlink_deletion_claim(&text) {
        return validate_toctou_symlink_claim(&evidence);
    }
    if debug_only_config_risk_claim(&text) {
        return validate_debug_only_config_claim(&evidence);
    }
    if vague_complexity_claim(&text) {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "vague complexity claim lacks a concrete failure mode",
        );
    }
    if hardcoded_api_key_claim(finding, &text) {
        return validate_hardcoded_api_key_claim(&evidence);
    }
    if secret_or_pii_logging_claim(finding, &text) {
        return validate_secret_or_pii_logging_claim(&evidence);
    }

    verdict(
        ClaimValidationVerdict::Valid,
        "no specialized claim validator matched",
    )
}

pub fn missing_await_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "missing await",
            "without await",
            "not awaited",
            "called without await",
            "promise object",
            "auth token retrieval not awaited",
        ],
    )
}

pub fn await_in_non_async_function_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "await in non-async",
            "await inside non-async",
            "await used in non-async",
            "await expression is only allowed",
            "non-async function",
        ],
    )
}

pub fn variable_out_of_scope_finally_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "out of scope",
            "not in scope",
            "undefined in finally",
            "finally cannot access",
            "finally block cannot access",
        ],
    ) && text.contains("finally")
}

pub fn build_break_invalid_syntax_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "invalid syntax",
            "build failure",
            "build fail",
            "break build",
            "compile failure",
            "compilation failure",
            "does not compile",
            "won't compile",
            "malformed code",
            "merge conflict",
        ],
    )
}

pub fn toctou_symlink_deletion_claim(text: &str) -> bool {
    contains_any(text, &["toctou", "symlink"])
        && contains_any(text, &["delete", "deletion", "cleanup", "remove", "wipe"])
}

pub fn debug_only_config_risk_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "debug-only",
            "debug only",
            "debug config",
            "debug configuration",
            "debug build",
        ],
    )
}

pub fn vague_complexity_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "complex logic",
            "difficult to reason",
            "could introduce",
            "subtle race conditions",
            "fragility",
            "performance issues",
            "consider simpler",
            "exploring simpler patterns",
        ],
    )
}

pub fn hardcoded_api_key_claim(finding: &ReviewFinding, text: &str) -> bool {
    finding.risk_code == Some(RiskCode::SecretLeak)
        || contains_any(
            text,
            &[
                "hardcoded api key",
                "hard-coded api key",
                "api key",
                "secret key",
                "access key",
            ],
        )
}

pub fn secret_or_pii_logging_claim(finding: &ReviewFinding, text: &str) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::PiiOrSecretLogging | RiskCode::SecretLeak)
    ) && contains_any(text, &["log", "logging", "logged", "console.", "logger"])
}

fn validate_missing_await_claim(text: &str, evidence: &str) -> ClaimValidationResult {
    if evidence.trim().is_empty() {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "missing-await claim lacks current code evidence",
        );
    }
    if evidence.contains("await ") {
        return verdict(
            ClaimValidationVerdict::Invalid,
            "current evidence shows the claimed async call is awaited",
        );
    }
    if call_name_from_claim(text)
        .as_deref()
        .is_some_and(|name| evidence.contains(&format!("{name}(")))
    {
        return verdict(
            ClaimValidationVerdict::Valid,
            "current evidence shows the claimed call without nearby await",
        );
    }
    verdict(
        ClaimValidationVerdict::NeedsManualConfirmation,
        "missing-await claim could not be tied to a concrete call site",
    )
}

fn validate_await_in_non_async_function_claim(evidence: &str) -> ClaimValidationResult {
    if evidence.trim().is_empty() || !evidence.contains("await ") {
        return verdict(
            ClaimValidationVerdict::Invalid,
            "await/non-async claim lacks an await expression in evidence",
        );
    }
    if contains_any(
        evidence,
        &[
            "async function",
            "async (",
            "async(",
            "async =>",
            "async\n",
            "= async",
        ],
    ) {
        return verdict(
            ClaimValidationVerdict::Invalid,
            "nearest evidence shows an async function or callback",
        );
    }
    verdict(
        ClaimValidationVerdict::NeedsManualConfirmation,
        "non-async function context is not fully visible",
    )
}

fn validate_variable_scope_finally_claim(text: &str, evidence: &str) -> ClaimValidationResult {
    if evidence.trim().is_empty() {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "variable-scope claim lacks current code evidence",
        );
    }
    let Some(variable) = variable_name_from_claim(text) else {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "variable-scope claim does not name a clear variable",
        );
    };
    let declaration_before_finally = evidence
        .find("finally")
        .is_some_and(|finally_index| evidence[..finally_index].contains(&format!(" {variable}")));
    if declaration_before_finally {
        return verdict(
            ClaimValidationVerdict::Invalid,
            "variable is declared before the finally block in current evidence",
        );
    }
    verdict(
        ClaimValidationVerdict::NeedsManualConfirmation,
        "current evidence does not prove the variable is out of scope",
    )
}

fn validate_build_break_claim(evidence: &str) -> ClaimValidationResult {
    if contains_any(
        evidence,
        &[
            "<<<<<<<",
            "=======",
            ">>>>>>>",
            "return @",
            "return@/",
            "=> @",
            "undefined undefined",
            "todo_remove_this",
        ],
    ) {
        return verdict(
            ClaimValidationVerdict::Valid,
            "exact invalid syntax evidence is present",
        );
    }
    verdict(
        ClaimValidationVerdict::Invalid,
        "build-break claim lacks exact invalid syntax evidence",
    )
}

fn validate_toctou_symlink_claim(evidence: &str) -> ClaimValidationResult {
    let has_canonical = contains_any(
        evidence,
        &[
            "canonicalpath",
            "canonical_path",
            "getcanonicalpath",
            "canonicalize",
            "realpath",
        ],
    );
    let has_root_check = contains_any(evidence, &["startswith", "starts_with", "relative_to"]);
    if has_canonical && has_root_check {
        return verdict(
            ClaimValidationVerdict::PartiallyValid,
            "canonical root validation is visible, so exploitability is a hardening concern",
        );
    }
    if evidence.trim().is_empty() {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "TOCTOU/symlink claim lacks current code evidence",
        );
    }
    verdict(
        ClaimValidationVerdict::NeedsManualConfirmation,
        "TOCTOU/symlink exploitability needs manual threat-model confirmation",
    )
}

fn validate_debug_only_config_claim(evidence: &str) -> ClaimValidationResult {
    if contains_any(evidence, &["release", "production", "prod"]) {
        return verdict(
            ClaimValidationVerdict::PartiallyValid,
            "production or release context is visible",
        );
    }
    verdict(
        ClaimValidationVerdict::PartiallyValid,
        "debug-only configuration is not proven to affect production",
    )
}

fn validate_hardcoded_api_key_claim(evidence: &str) -> ClaimValidationResult {
    if API_KEY_RE.is_match(evidence) {
        return verdict(
            ClaimValidationVerdict::Valid,
            "actual hardcoded key-like value is present in evidence",
        );
    }
    if contains_any(
        evidence,
        &[
            "${",
            "$env",
            "process.env",
            "buildconfig",
            "manifestplaceholder",
        ],
    ) {
        return verdict(
            ClaimValidationVerdict::Invalid,
            "evidence points to configuration indirection rather than an actual key",
        );
    }
    verdict(
        ClaimValidationVerdict::NeedsManualConfirmation,
        "hardcoded API key claim lacks exact key evidence",
    )
}

fn validate_secret_or_pii_logging_claim(evidence: &str) -> ClaimValidationResult {
    if contains_any(
        evidence,
        &[
            "console.log",
            "console.error",
            "logger.",
            "log.",
            "log(",
            "sentry",
            "captureexception",
            "println!",
            "dbg!",
        ],
    ) && contains_any(
        evidence,
        &[
            "authorization",
            "cookie",
            "token",
            "password",
            "secret",
            "api_key",
            "apikey",
            "email",
            "phone",
            "ssn",
            "bearer",
        ],
    ) {
        return verdict(
            ClaimValidationVerdict::Valid,
            "logging statement and sensitive field are present in evidence",
        );
    }
    if evidence.trim().is_empty() {
        return verdict(
            ClaimValidationVerdict::NeedsManualConfirmation,
            "secret/PII logging claim lacks code evidence",
        );
    }
    verdict(
        ClaimValidationVerdict::Invalid,
        "evidence does not show both logging and sensitive data",
    )
}

fn diff_evidence_for_finding(finding: &ReviewFinding, context: &AnchoredDiffContext) -> String {
    if let Some(anchor_id) = finding.anchor_id.as_deref() {
        if let Some(anchor) = context.get(anchor_id) {
            return anchor.content_preview.clone();
        }
    }

    let Some(path) = finding.file_path.as_deref() else {
        return String::new();
    };
    context
        .anchors
        .iter()
        .filter(|anchor| {
            anchor.file_path == path
                || anchor.new_path == path
                || anchor.old_path == path
                || finding.line.is_some_and(|line| {
                    anchor.new_line == Some(line) || anchor.old_line == Some(line)
                })
        })
        .map(|anchor| anchor.content_preview.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn finding_text(finding: &ReviewFinding) -> String {
    format!(
        "{} {} {}",
        finding.title,
        finding.body,
        finding.suggested_fix.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase()
}

fn call_name_from_claim(text: &str) -> Option<String> {
    IDENTIFIER_RE
        .captures_iter(text)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .find(|word| {
            word.len() > 3
                && !matches!(
                    word.as_str(),
                    "await" | "missing" | "without" | "called" | "promise" | "object" | "token"
                )
        })
}

fn variable_name_from_claim(text: &str) -> Option<String> {
    text.split('`')
        .nth(1)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| call_name_from_claim(text))
}

fn verdict(verdict: ClaimValidationVerdict, reason: &str) -> ClaimValidationResult {
    ClaimValidationResult {
        verdict,
        reason: reason.to_string(),
    }
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    terms.iter().any(|term| value.contains(term))
}

#[cfg(test)]
mod tests {
    use super::{validate_finding_claim, ClaimValidationVerdict};
    use crate::review::types::{Effort, ReviewCategory, ReviewFinding, RiskCode, Severity};

    #[test]
    fn false_missing_await_claim_is_invalid_when_await_is_visible() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::MissingAuthorizationCheck),
                "Missing await on getToken",
                "getToken is not awaited.",
            ),
            "const token = await getToken();",
        );

        assert_eq!(result.verdict, ClaimValidationVerdict::Invalid);
    }

    #[test]
    fn hardcoded_api_key_requires_actual_key_evidence() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::SecretLeak),
                "Hardcoded API key",
                "Google Maps API key is hardcoded.",
            ),
            "manifestPlaceholders = [ mapsApiKey: MAPS_API_KEY ]",
        );

        assert_eq!(result.verdict, ClaimValidationVerdict::Invalid);
    }

    #[test]
    fn secret_logging_requires_logging_and_sensitive_data() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::PiiOrSecretLogging),
                "Secret logging",
                "Authorization header is logged.",
            ),
            "logger.info(\"auth\", authorization_header);",
        );

        assert_eq!(result.verdict, ClaimValidationVerdict::Valid);
    }

    fn finding(risk_code: Option<RiskCode>, title: &str, body: &str) -> ReviewFinding {
        ReviewFinding {
            severity: Severity::High,
            category: ReviewCategory::Security,
            risk_code,
            anchor_id: None,
            file_path: Some("src/app.ts".to_string()),
            line: Some(10),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: Some("Fix the issue.".to_string()),
            effort: Effort::Moderate,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }
}
