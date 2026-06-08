use crate::{
    gitlab::types::MergeRequestDiff,
    review::{
        anchors::AnchoredDiffContext,
        types::{EvidenceValidationStatus, ReviewCategory, ReviewFinding, RiskCode, Severity},
    },
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityIntentValidationContext<'a> {
    pub diffs: &'a [MergeRequestDiff],
    pub diff_context: Option<&'a AnchoredDiffContext>,
}

const SECURITY_TERMS: &[&str] = &[
    "security",
    "integrity",
    "tamper",
    "instrumentation",
    "root",
    "jailbreak",
    "emulator",
    "overlay",
    "tapjacking",
    "signature",
    "certificate",
    "pinning",
    "auth",
    "session",
    "token",
    "permission",
    "policy",
    "runtime guard",
    "compromised",
    "blocked",
    "denied",
];

const FAIL_CLOSED_TERMS: &[&str] = &[
    "fail closed",
    "fail-safe",
    "failsafe",
    "default deny",
    "block",
    "reject",
    "deny",
    "compromised",
    "unsafe",
    "untrusted",
    "clear session",
    "wipe",
    "revoke",
    "disable",
    "return true for threat",
    "throw",
    "terminate",
    "exit",
];

const WEAKENING_TERMS: &[&str] = &[
    "return false",
    "allow",
    "ignore",
    "skip",
    "bypass",
    "continue anyway",
    "do not block",
    "remove check",
    "disable check",
    "relax",
    "whitelist all",
    "catch and ignore",
    "swallow",
    "proceed",
];

const OBSERVABILITY_TERMS: &[&str] = &[
    "missing log",
    "logging",
    "log",
    "telemetry",
    "diagnostic",
    "diagnostics",
    "reason code",
    "reason codes",
    "debug",
    "observable",
    "observability",
    "swallow",
    "swallowed exception",
    "catch-all",
    "broad exception",
    "hard to debug",
    "difficult to diagnose",
];

const USER_IMPACT_TERMS: &[&str] = &[
    "false positive",
    "legitimate user",
    "legitimate users",
    "block users",
    "blocks users",
    "locked out",
    "no diagnostic",
    "no diagnostics",
    "without diagnostics",
    "cannot diagnose",
    "hard to diagnose",
];

const DESTRUCTIVE_TERMS: &[&str] = &[
    "wipe data",
    "wipe local data",
    "clear tokens",
    "clear token",
    "clear session",
    "revoke session",
    "delete cache",
    "delete database",
    "delete storage",
    "delete local storage",
    "clear cache",
    "clear database",
    "remove local data",
];

const SEVERE_EVIDENCE_TERMS: &[&str] = &[
    "production outage",
    "outage",
    "data loss",
    "credential exposure",
    "secret exposure",
    "auth bypass",
    "authentication bypass",
    "authorization bypass",
];

const FAIL_CLOSED_FIX: &str = "Preserve fail-closed behavior. Add explicit reason codes, telemetry, and user/developer-visible diagnostics for each failure path so false positives can be investigated while uncertain security states still fail closed.";
const OBSERVABILITY_FIX: &str =
    "Keep the fail-closed behavior, but emit explicit reason codes and telemetry for each failure path.";
const TRADEOFF_FIX: &str = "Confirm the intended security posture with the security/application owner. If fail-closed behavior is required, add diagnostic reason codes and telemetry rather than weakening the check.";
const DESTRUCTIVE_FIX: &str = "Confirm the destructive security-response policy with the product/security owner. If the response is required, keep enforcement and add reason codes, telemetry, recovery guidance, and policy-configurable handling where compatible with the threat model.";

pub fn apply_security_intent_guard(
    findings: Vec<ReviewFinding>,
    context: &SecurityIntentValidationContext<'_>,
) -> Vec<ReviewFinding> {
    findings
        .into_iter()
        .filter_map(|finding| validate_security_intent(finding, context))
        .collect()
}

pub fn validate_security_intent(
    mut finding: ReviewFinding,
    context: &SecurityIntentValidationContext<'_>,
) -> Option<ReviewFinding> {
    if !finding.actionable || finding.severity == Severity::Note {
        return Some(finding);
    }

    let code_text = code_context_text(&finding, context);
    let review_text = finding_text(&finding);
    let combined_text = format!("{review_text} {code_text}");
    let suggested_fix = finding.suggested_fix.as_deref().unwrap_or_default();
    let suggested_fix_text = normalize_text(suggested_fix);

    let security_sensitive =
        security_sensitive(&finding) || contains_any(&combined_text, SECURITY_TERMS);
    if !security_sensitive {
        return Some(finding);
    }

    let fail_closed = contains_any(&combined_text, FAIL_CLOSED_TERMS);
    let weakening_fix = contains_any(&suggested_fix_text, WEAKENING_TERMS);
    let destructive_action = contains_any(&combined_text, DESTRUCTIVE_TERMS);
    let observability_issue = observability_signal(&review_text, &suggested_fix_text);
    let policy_tradeoff = policy_tradeoff_signal(&review_text, &suggested_fix_text)
        || (fail_closed && weakening_fix)
        || (destructive_action && weakening_fix);

    if destructive_action {
        finding = handle_destructive_security_action(finding, weakening_fix, &combined_text);
    }

    if fail_closed && observability_issue {
        finding = rewrite_as_observability_gap(finding, &combined_text);
    }

    if weakening_fix {
        finding.suggested_fix = Some(if destructive_action {
            DESTRUCTIVE_FIX.to_string()
        } else if policy_tradeoff {
            TRADEOFF_FIX.to_string()
        } else {
            FAIL_CLOSED_FIX.to_string()
        });
        cap_severity(&mut finding, Severity::Medium);
        append_reason(
            &mut finding,
            "security intent validation: suggested fix was rewritten to preserve security posture",
        );
    }

    if policy_tradeoff {
        cap_severity(&mut finding, Severity::Medium);
        finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
        append_reason(
            &mut finding,
            "security intent validation: security-policy tradeoff requires owner confirmation",
        );
    }

    if fail_closed
        && observability_issue
        && !contains_any(&combined_text, SEVERE_EVIDENCE_TERMS)
        && matches!(finding.severity, Severity::Critical | Severity::High)
    {
        cap_severity(&mut finding, Severity::Medium);
    }

    if fail_closed
        && observability_issue
        && !contains_any(&combined_text, USER_IMPACT_TERMS)
        && matches!(finding.severity, Severity::Medium)
    {
        cap_severity(&mut finding, Severity::Low);
    }

    if finding
        .suggested_fix
        .as_deref()
        .is_some_and(unsafe_security_fix)
    {
        finding.suggested_fix = Some(FAIL_CLOSED_FIX.to_string());
        cap_severity(&mut finding, Severity::Medium);
        append_reason(
            &mut finding,
            "security intent validation: unsafe security-weakening language was removed",
        );
    }

    Some(finding)
}

fn handle_destructive_security_action(
    mut finding: ReviewFinding,
    weakening_fix: bool,
    combined_text: &str,
) -> ReviewFinding {
    if weakening_fix || finding.suggested_fix.as_deref().is_none_or(str::is_empty) {
        finding.suggested_fix = Some(DESTRUCTIVE_FIX.to_string());
    }

    if contains_any(combined_text, USER_IMPACT_TERMS)
        && !contains_any(combined_text, SEVERE_EVIDENCE_TERMS)
    {
        cap_severity(&mut finding, Severity::Medium);
    }
    append_reason(
        &mut finding,
        "security intent validation: destructive security action must preserve threat model",
    );
    finding
}

fn rewrite_as_observability_gap(mut finding: ReviewFinding, combined_text: &str) -> ReviewFinding {
    finding.title = "Security failure reason is not observable enough".to_string();
    finding.body = "The current implementation preserves a strict fail-closed security posture, but failures are difficult to diagnose because distinct failure reasons are not surfaced or logged clearly.".to_string();
    finding.suggested_fix = Some(OBSERVABILITY_FIX.to_string());
    finding.category = ReviewCategory::Observability;
    finding.risk_code = Some(RiskCode::ObservabilityGap);
    if contains_any(combined_text, USER_IMPACT_TERMS) {
        cap_severity(&mut finding, Severity::Medium);
    } else {
        cap_severity(&mut finding, Severity::Low);
    }
    append_reason(
        &mut finding,
        "security intent validation: reframed fail-closed concern as diagnostics/observability",
    );
    finding
}

fn security_sensitive(finding: &ReviewFinding) -> bool {
    matches!(
        finding.category,
        ReviewCategory::Security | ReviewCategory::Privacy | ReviewCategory::DataIntegrity
    ) || matches!(
        finding.risk_code,
        Some(
            RiskCode::AuthBypass
                | RiskCode::MissingAuthorizationCheck
                | RiskCode::SecretLeak
                | RiskCode::PiiOrSecretLogging
                | RiskCode::SqlInjection
                | RiskCode::CommandInjection
                | RiskCode::UnsafeDeserialization
                | RiskCode::DataIntegrityRisk
        )
    )
}

fn observability_signal(review_text: &str, suggested_fix_text: &str) -> bool {
    contains_any(review_text, OBSERVABILITY_TERMS)
        || contains_any(suggested_fix_text, OBSERVABILITY_TERMS)
        || (contains_any(review_text, &["exception", "catch", "throws", "thrown"])
            && contains_any(
                review_text,
                &["no detail", "generic", "same result", "hidden"],
            ))
}

fn policy_tradeoff_signal(review_text: &str, suggested_fix_text: &str) -> bool {
    let text = format!("{review_text} {suggested_fix_text}");
    contains_any(
        &text,
        &[
            "fail open",
            "fail-open",
            "fail closed vs fail open",
            "block vs allow",
            "wipe vs preserve",
            "reject vs continue",
            "remove strict validation",
            "relax root",
            "relax jailbreak",
            "relax emulator",
            "relax integrity",
            "change security policy",
            "security policy",
        ],
    ) || (contains_any(&text, &["block", "fail closed", "wipe", "reject"])
        && contains_any(suggested_fix_text, WEAKENING_TERMS))
}

fn unsafe_security_fix(value: &str) -> bool {
    let normalized = normalize_text(value);
    contains_any(&normalized, WEAKENING_TERMS)
}

fn code_context_text(
    finding: &ReviewFinding,
    context: &SecurityIntentValidationContext<'_>,
) -> String {
    let mut parts = Vec::new();
    if let Some(path) = finding.file_path.as_deref() {
        for diff in context.diffs.iter().filter(|diff| {
            diff.old_path == path || diff.new_path == path || path.ends_with(&diff.new_path)
        }) {
            parts.push(diff.diff.as_str());
        }
    }
    if parts.is_empty() {
        if let Some(diff_context) = context.diff_context {
            parts.push(diff_context.prompt_text.as_str());
        }
    }
    normalize_text(&parts.join(" "))
}

fn finding_text(finding: &ReviewFinding) -> String {
    normalize_text(&format!(
        "{} {} {} {} {}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding.title,
        finding.body,
        finding.suggested_fix.as_deref().unwrap_or_default(),
        finding
            .risk_code
            .map(|risk_code| risk_code.display_lower())
            .unwrap_or_default()
    ))
}

fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn contains_any(value: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| value.contains(term))
}

fn cap_severity(finding: &mut ReviewFinding, max_severity: Severity) {
    if finding.severity.sort_key() < max_severity.sort_key() {
        finding.severity = max_severity;
    }
}

fn append_reason(finding: &mut ReviewFinding, reason: &str) {
    let mut reasons = finding.evidence_reason.take().unwrap_or_default();
    if !reasons.is_empty() {
        reasons.push_str("; ");
    }
    reasons.push_str(reason);
    finding.evidence_reason = Some(reasons);
}

#[cfg(test)]
mod tests {
    use super::{
        apply_security_intent_guard, SecurityIntentValidationContext, DESTRUCTIVE_FIX,
        FAIL_CLOSED_FIX, OBSERVABILITY_FIX, TRADEOFF_FIX,
    };
    use crate::{
        gitlab::types::MergeRequestDiff,
        review::types::{
            Effort, EvidenceValidationStatus, ReviewCategory, ReviewFinding, RiskCode, Severity,
        },
    };

    #[test]
    fn return_false_on_security_exception_is_rewritten() {
        let finding = guarded(finding(
            Severity::High,
            "Runtime integrity check false positive",
            "The integrity check catches all exceptions and returns true for threat, blocking users without diagnostics.",
            "Return false when the runtime check throws so users can continue.",
        ));

        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.category, ReviewCategory::Observability);
        assert_eq!(finding.risk_code, Some(RiskCode::ObservabilityGap));
        let fix = finding.suggested_fix.unwrap();
        assert!(fix.contains("fail-closed"));
        assert!(fix.contains("reason codes"));
        assert!(!fix.to_ascii_lowercase().contains("return false"));
    }

    #[test]
    fn allow_user_to_continue_is_manual_tradeoff() {
        let finding = guarded(finding(
            Severity::Critical,
            "Root detection blocks legitimate users",
            "The root runtime guard fails closed and blocks on untrusted device state.",
            "Allow the user to continue when root detection is uncertain.",
        ));

        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(
            finding.evidence_status,
            Some(EvidenceValidationStatus::NeedsManualConfirmation)
        );
        assert_eq!(finding.suggested_fix.as_deref(), Some(TRADEOFF_FIX));
    }

    #[test]
    fn remove_check_suggestion_is_rewritten() {
        let finding = guarded(finding(
            Severity::High,
            "Certificate pinning can reject users",
            "The certificate pinning policy rejects untrusted sessions.",
            "Remove check to avoid false positives.",
        ));

        assert_eq!(finding.severity, Severity::Medium);
        let fix = finding.suggested_fix.unwrap();
        assert_ne!(fix, "Remove check to avoid false positives.");
        assert!(!fix.to_ascii_lowercase().contains("remove check"));
    }

    #[test]
    fn fail_closed_observability_gap_keeps_enforcement() {
        let finding = guarded(finding(
            Severity::High,
            "Security check has no telemetry",
            "The runtime guard fails closed and blocks compromised sessions, but no reason code is logged.",
            "Add telemetry.",
        ));

        assert_eq!(
            finding.title,
            "Security failure reason is not observable enough"
        );
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.suggested_fix.as_deref(), Some(OBSERVABILITY_FIX));
    }

    #[test]
    fn destructive_security_action_does_not_suggest_no_wipe() {
        let finding = guarded(finding(
            Severity::High,
            "Automatic token wipe can affect legitimate users",
            "A false positive in the tamper detector can clear tokens and wipe local data.",
            "Do not wipe data; allow the user to continue.",
        ));

        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.suggested_fix.as_deref(), Some(DESTRUCTIVE_FIX));
        let fix = finding.suggested_fix.unwrap().to_ascii_lowercase();
        assert!(!fix.contains("do not wipe"));
        assert!(!fix.contains("allow the user to continue"));
    }

    #[test]
    fn non_security_reliability_finding_is_unchanged() {
        let original = ReviewFinding {
            category: ReviewCategory::Reliability,
            risk_code: Some(RiskCode::MissingTimeout),
            file_path: Some("src/http.rs".to_string()),
            ..finding(
                Severity::High,
                "Request can hang",
                "The HTTP client has no timeout.",
                "Return false on timeout.",
            )
        };
        let finding = apply_security_intent_guard(
            vec![original.clone()],
            &SecurityIntentValidationContext::default(),
        )
        .remove(0);

        assert_eq!(finding, original);
    }

    #[test]
    fn safe_fail_closed_fix_constant_has_no_weakening_terms() {
        let lower = FAIL_CLOSED_FIX.to_ascii_lowercase();
        for term in ["return false", "allow", "ignore", "bypass", "remove check"] {
            assert!(!lower.contains(term), "{term}");
        }
    }

    fn guarded(finding: ReviewFinding) -> ReviewFinding {
        apply_security_intent_guard(
            vec![finding],
            &SecurityIntentValidationContext {
                diffs: &[diff(
                    "src/security.rs",
                    "@@ -1 +1 @@\n+if integrity_unknown { block(); return true; }",
                )],
                diff_context: None,
            },
        )
        .remove(0)
    }

    fn finding(severity: Severity, title: &str, body: &str, suggested_fix: &str) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Security,
            risk_code: Some(RiskCode::AuthBypass),
            anchor_id: None,
            file_path: Some("src/security.rs".to_string()),
            line: Some(1),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: Some(suggested_fix.to_string()),
            effort: Effort::Moderate,
            actionable: true,
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
