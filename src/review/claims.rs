use crate::review::{
    anchors::AnchoredDiffContext,
    types::{ReviewFinding, RiskCode},
};
use regex::Regex;
use std::{collections::HashSet, sync::LazyLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSupport {
    Strong,
    Partial,
    Weak,
    Contradicted,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEvidence {
    pub support: ClaimSupport,
    pub reason: String,
    pub matched_files: Vec<String>,
    pub matched_lines: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimFamily {
    AsyncAwaitCorrectness,
    VariableScopeLifetime,
    BuildSyntaxBreak,
    SecretOrPiiLogging,
    UnsafeSqlQueryConstruction,
    WeakErrorHandling,
    TimeoutRetryRisk,
    AuthSessionTokenFlowRisk,
    DestructiveDataOperation,
    DebugOnlyProductionRisk,
    ConfigManifestSecretExposure,
    VagueComplexityMaintainability,
    GenericEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceLine {
    file_path: String,
    line: Option<u32>,
    text: String,
}

static IDENTIFIER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"`?([A-Za-z_$][A-Za-z0-9_$]*)`?").expect("valid identifier regex")
});

static API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            AIza[0-9A-Za-z_-]{20,}
            | AKIA[0-9A-Z]{16}
            | (?i:api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"'\s]{16,}["']
        )
        "#,
    )
    .expect("valid secret evidence regex")
});

static SQL_INTERPOLATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)
        (select|insert|update|delete)\s+[^;\n]*
        (\$\{|`|\+\s*[A-Za-z_$]|\bformat!\s*\(|\bformat\s*\(|concat\s*\()
        "#,
    )
    .expect("valid sql interpolation regex")
});

const STOPWORDS: &[&str] = &[
    "about", "action", "added", "after", "against", "also", "because", "before", "being",
    "between", "body", "cannot", "change", "changed", "claim", "code", "could", "does", "finding",
    "from", "have", "high", "impact", "into", "line", "lines", "might", "more", "must", "needs",
    "risk", "should", "this", "through", "title", "unless", "when", "where", "with", "without",
];

pub fn validate_finding_claim_against_diff(
    finding: &ReviewFinding,
    diff_context: Option<&AnchoredDiffContext>,
) -> ClaimEvidence {
    let evidence = diff_context
        .map(|context| diff_evidence_for_finding(finding, context))
        .unwrap_or_default();
    validate_finding_claim(finding, evidence)
}

pub fn validate_finding_claim_against_current_file(
    finding: &ReviewFinding,
    current_file: Option<&str>,
) -> ClaimEvidence {
    let evidence = current_file
        .map(|file| current_file_evidence(finding, file))
        .unwrap_or_default();
    validate_finding_claim(finding, evidence)
}

pub(crate) fn validate_finding_claim(
    finding: &ReviewFinding,
    evidence: Vec<EvidenceLine>,
) -> ClaimEvidence {
    let claim = finding_text(finding);
    let family = classify_claim(finding, &claim);
    let text = evidence_text(&evidence);

    let mut result = match family {
        ClaimFamily::AsyncAwaitCorrectness => validate_async_await_claim(&claim, &text),
        ClaimFamily::VariableScopeLifetime => validate_scope_lifetime_claim(&claim, &text),
        ClaimFamily::BuildSyntaxBreak => validate_build_syntax_claim(&text),
        ClaimFamily::SecretOrPiiLogging => validate_secret_logging_claim(&text),
        ClaimFamily::UnsafeSqlQueryConstruction => validate_sql_claim(&text),
        ClaimFamily::WeakErrorHandling => validate_error_handling_claim(&claim, &text),
        ClaimFamily::TimeoutRetryRisk => validate_timeout_retry_claim(&claim, &text),
        ClaimFamily::AuthSessionTokenFlowRisk => validate_auth_flow_claim(&claim, &text),
        ClaimFamily::DestructiveDataOperation => validate_destructive_operation_claim(&text),
        ClaimFamily::DebugOnlyProductionRisk => validate_debug_production_claim(&text),
        ClaimFamily::ConfigManifestSecretExposure => validate_config_secret_claim(&text),
        ClaimFamily::VagueComplexityMaintainability => validate_complexity_claim(&claim, &text),
        ClaimFamily::GenericEvidence => validate_generic_claim(&claim, &text),
    };

    result.matched_files = matched_files(&evidence, &text);
    result.matched_lines = matched_lines(&evidence, &text);
    result
}

fn classify_claim(finding: &ReviewFinding, claim: &str) -> ClaimFamily {
    if missing_await_claim(claim) || await_in_non_async_function_claim(claim) {
        return ClaimFamily::AsyncAwaitCorrectness;
    }
    if variable_scope_claim(claim) {
        return ClaimFamily::VariableScopeLifetime;
    }
    if build_break_claim(claim) {
        return ClaimFamily::BuildSyntaxBreak;
    }
    if sql_claim(finding, claim) {
        return ClaimFamily::UnsafeSqlQueryConstruction;
    }
    if secret_or_pii_logging_claim(finding, claim) {
        return ClaimFamily::SecretOrPiiLogging;
    }
    if config_secret_claim(finding, claim) {
        return ClaimFamily::ConfigManifestSecretExposure;
    }
    if weak_error_handling_claim(finding, claim) {
        return ClaimFamily::WeakErrorHandling;
    }
    if timeout_retry_claim(finding, claim) {
        return ClaimFamily::TimeoutRetryRisk;
    }
    if auth_session_token_claim(finding, claim) {
        return ClaimFamily::AuthSessionTokenFlowRisk;
    }
    if destructive_operation_claim(finding, claim) {
        return ClaimFamily::DestructiveDataOperation;
    }
    if debug_only_claim(claim) {
        return ClaimFamily::DebugOnlyProductionRisk;
    }
    if vague_complexity_claim(claim) {
        return ClaimFamily::VagueComplexityMaintainability;
    }
    ClaimFamily::GenericEvidence
}

fn validate_async_await_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "async/await claim has no current code evidence",
        );
    }

    if await_in_non_async_function_claim(claim) {
        if !contains_any(evidence, &["await "]) {
            return claim_evidence(
                ClaimSupport::Contradicted,
                "claim expects an await expression, but evidence does not contain one",
            );
        }
        if async_context_signal(evidence) {
            return claim_evidence(
                ClaimSupport::Contradicted,
                "current code shows the await expression inside an async function or callback",
            );
        }
        return claim_evidence(
            ClaimSupport::Partial,
            "await is visible, but the nearest function boundary is not fully proven",
        );
    }

    let call_name = call_name_from_claim(claim);
    if let Some(name) = call_name.as_deref() {
        let awaited_call = format!("await {name}(");
        let call = format!("{name}(");
        if evidence.contains(&awaited_call) {
            return claim_evidence(
                ClaimSupport::Contradicted,
                "current code shows the claimed async call is awaited",
            );
        }
        if evidence.contains(&call) {
            return claim_evidence(
                ClaimSupport::Strong,
                "current code shows the claimed call without a nearby await",
            );
        }
    }

    if async_call_without_await(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code contains an async-looking call whose result is used without await",
        );
    }
    if evidence.contains("await ") {
        return claim_evidence(
            ClaimSupport::Contradicted,
            "current code contains await evidence that contradicts the missing-await claim",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "async/await claim is not tied to a concrete call site in current code",
    )
}

fn validate_scope_lifetime_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "variable scope/lifetime claim has no current code evidence",
        );
    }
    let Some(variable) = variable_name_from_claim(claim) else {
        return claim_evidence(
            ClaimSupport::Weak,
            "variable scope/lifetime claim does not name a clear variable",
        );
    };
    let Some(use_index) = evidence
        .find("finally")
        .or_else(|| evidence.rfind(&variable))
    else {
        return claim_evidence(
            ClaimSupport::NotFound,
            "current code does not show the claimed variable use site",
        );
    };
    let before_use = &evidence[..use_index];
    let declared_before_use = declaration_signal(before_use, &variable);
    let declared_inside_try = before_use
        .rfind("try")
        .is_some_and(|try_index| declaration_signal(&before_use[try_index..], &variable));

    if declared_before_use && !declared_inside_try {
        return claim_evidence(
            ClaimSupport::Contradicted,
            "current code declares the variable before the claimed lifetime boundary",
        );
    }
    if declared_inside_try && evidence[use_index..].contains(&variable) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code declares the variable inside a narrower scope and uses it outside",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "current code does not prove the variable is outside its valid lifetime",
    )
}

fn validate_build_syntax_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "build/syntax claim has no code evidence",
        );
    }
    if build_break_evidence(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code contains exact build- or syntax-breaking evidence",
        );
    }
    claim_evidence(
        ClaimSupport::Contradicted,
        "build/syntax claim lacks exact invalid syntax evidence in current code",
    )
}

fn validate_secret_logging_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "secret/PII logging claim has no code evidence",
        );
    }
    let logging = logging_signal(evidence);
    let sensitive = sensitive_data_signal(evidence);
    match (logging, sensitive) {
        (true, true) => claim_evidence(
            ClaimSupport::Strong,
            "current code contains both a logging sink and sensitive data",
        ),
        (true, false) | (false, true) => claim_evidence(
            ClaimSupport::Partial,
            "current code contains only one side of the logging and sensitive-data claim",
        ),
        (false, false) => claim_evidence(
            ClaimSupport::Contradicted,
            "current code does not show both logging and sensitive data",
        ),
    }
}

fn validate_sql_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "SQL/query claim has no code evidence",
        );
    }
    if SQL_INTERPOLATION_RE.is_match(evidence)
        || (sql_signal(evidence) && interpolation_signal(evidence))
    {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code constructs a SQL/query string with interpolation or concatenation",
        );
    }
    if sql_signal(evidence) && parameterized_query_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Contradicted,
            "current code shows a parameterized query shape instead of unsafe interpolation",
        );
    }
    if sql_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code shows SQL/query construction, but unsafe interpolation is not proven",
        );
    }
    claim_evidence(
        ClaimSupport::NotFound,
        "current code does not show SQL/query construction evidence",
    )
}

fn validate_error_handling_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "weak error-handling claim has no code evidence",
        );
    }
    if swallowed_error_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code contains a failure path that swallows or silently accepts errors",
        );
    }
    if error_handling_signal(evidence) && observable_failure_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Contradicted,
            "current code shows the failure is propagated, logged, returned, or surfaced",
        );
    }
    if error_handling_signal(evidence) || contains_any(claim, &["failure", "error", "exception"]) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code shows an error path, but silent failure is not fully proven",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "weak error-handling claim is not tied to a concrete failure path",
    )
}

fn validate_timeout_retry_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "timeout/retry claim has no code evidence",
        );
    }
    let retry_or_network = retry_signal(evidence) || network_call_signal(evidence);
    if retry_or_network && !timeout_or_failure_handling_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code shows retry or network behavior without observable timeout/failure handling",
        );
    }
    if retry_or_network && timeout_or_failure_handling_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code shows retry/network behavior with some timeout or failure handling",
        );
    }
    if contains_any(claim, &["retry", "timeout"]) {
        return claim_evidence(
            ClaimSupport::Weak,
            "timeout/retry claim lacks a concrete retry or network code path",
        );
    }
    claim_evidence(ClaimSupport::NotFound, "timeout/retry evidence not found")
}

fn validate_auth_flow_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "auth/session/token flow claim has no code evidence",
        );
    }
    if auth_signal(evidence)
        && (missing_guard_signal(evidence)
            || async_call_without_await(evidence)
            || swallowed_error_signal(evidence))
    {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code shows auth/session/token flow evidence with a concrete missing guard, await, or failure handling path",
        );
    }
    if auth_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code shows auth/session/token flow evidence, but the claimed failure mode is not fully proven",
        );
    }
    if contains_any(claim, &["auth", "session", "token", "credential"]) {
        return claim_evidence(
            ClaimSupport::NotFound,
            "current code does not show auth/session/token flow evidence",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "auth/session/token claim is not concrete",
    )
}

fn validate_destructive_operation_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "destructive data operation claim has no code evidence",
        );
    }
    if destructive_signal(evidence)
        && (unguarded_signal(evidence)
            || contains_any(
                evidence,
                &["user data", "local data", "all", "queue", "cache"],
            ))
    {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code contains a destructive operation with user/local/bulk data or missing guard evidence",
        );
    }
    if destructive_signal(evidence) && guard_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code contains a destructive operation with some visible guard evidence",
        );
    }
    if destructive_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code shows destructive-operation evidence, but unsafe reachability is not fully proven",
        );
    }
    claim_evidence(
        ClaimSupport::NotFound,
        "current code does not show a destructive operation",
    )
}

fn validate_debug_production_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "debug-only production-risk claim has no code evidence",
        );
    }
    if debug_signal(evidence) && production_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code ties debug-only behavior to a production or release path",
        );
    }
    if debug_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Weak,
            "debug-only behavior is visible, but production reachability is not proven",
        );
    }
    claim_evidence(
        ClaimSupport::NotFound,
        "current code does not show debug-only behavior",
    )
}

fn validate_config_secret_claim(evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "configuration/manifest secret claim has no code evidence",
        );
    }
    if API_KEY_RE.is_match(evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current configuration contains a literal secret-like value",
        );
    }
    if config_indirection_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Contradicted,
            "current configuration uses placeholder or environment indirection instead of a literal secret",
        );
    }
    if config_file_signal(evidence) && sensitive_data_signal(evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current configuration references sensitive material, but a literal secret is not proven",
        );
    }
    claim_evidence(
        ClaimSupport::NotFound,
        "current code does not show configuration secret exposure evidence",
    )
}

fn validate_complexity_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(
            ClaimSupport::NotFound,
            "maintainability/complexity claim has no code evidence",
        );
    }
    if concrete_failure_mode_signal(claim) && generic_keyword_overlap(claim, evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "maintainability claim names a concrete failure mode and overlaps current code",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "vague complexity or maintainability claim lacks a concrete evidence-backed failure mode",
    )
}

fn validate_generic_claim(claim: &str, evidence: &str) -> ClaimEvidence {
    if evidence.trim().is_empty() {
        return claim_evidence(ClaimSupport::NotFound, "claim has no current code evidence");
    }
    let risk_supported = sql_signal(evidence)
        || logging_signal(evidence)
        || auth_signal(evidence)
        || destructive_signal(evidence)
        || build_break_evidence(evidence)
        || swallowed_error_signal(evidence);
    if risk_supported && generic_keyword_overlap(claim, evidence) {
        return claim_evidence(
            ClaimSupport::Strong,
            "current code contains generic bug-class evidence matching the claim",
        );
    }
    if generic_keyword_overlap(claim, evidence) {
        return claim_evidence(
            ClaimSupport::Partial,
            "current code overlaps the claim, but the exact failure mode is only partially proven",
        );
    }
    claim_evidence(
        ClaimSupport::Weak,
        "current code evidence does not directly support the claim text",
    )
}

fn diff_evidence_for_finding(
    finding: &ReviewFinding,
    context: &AnchoredDiffContext,
) -> Vec<EvidenceLine> {
    let mut lines = Vec::new();
    let target_anchor = finding
        .anchor_id
        .as_deref()
        .and_then(|anchor_id| context.get(anchor_id));

    if let Some(anchor) = target_anchor {
        lines.extend(context.anchors.iter().filter(|candidate| {
            candidate.file_path == anchor.file_path
                || candidate.new_path == anchor.new_path
                || candidate.old_path == anchor.old_path
        }));
    } else if let Some(path) = finding.file_path.as_deref() {
        lines.extend(context.anchors.iter().filter(|anchor| {
            anchor.file_path == path
                || anchor.new_path == path
                || anchor.old_path == path
                || finding.line.is_some_and(|line| {
                    anchor.new_line == Some(line) || anchor.old_line == Some(line)
                })
        }));
    }

    lines
        .into_iter()
        .map(|anchor| EvidenceLine {
            file_path: anchor.file_path.clone(),
            line: anchor.new_line.or(anchor.old_line),
            text: anchor.content_preview.clone(),
        })
        .collect()
}

fn current_file_evidence(finding: &ReviewFinding, current_file: &str) -> Vec<EvidenceLine> {
    let file_path = finding
        .file_path
        .as_deref()
        .unwrap_or("current file")
        .to_string();
    current_file
        .lines()
        .enumerate()
        .map(|(index, line)| EvidenceLine {
            file_path: file_path.clone(),
            line: Some(index as u32 + 1),
            text: line.to_string(),
        })
        .collect()
}

fn claim_evidence(support: ClaimSupport, reason: &str) -> ClaimEvidence {
    ClaimEvidence {
        support,
        reason: reason.to_string(),
        matched_files: Vec::new(),
        matched_lines: Vec::new(),
    }
}

fn evidence_text(evidence: &[EvidenceLine]) -> String {
    evidence
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase()
}

fn matched_files(evidence: &[EvidenceLine], text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    evidence
        .iter()
        .filter(|line| !text.trim().is_empty() && text.contains(&line.text.to_ascii_lowercase()))
        .filter_map(|line| {
            if seen.insert(line.file_path.clone()) {
                Some(line.file_path.clone())
            } else {
                None
            }
        })
        .collect()
}

fn matched_lines(evidence: &[EvidenceLine], text: &str) -> Vec<u32> {
    let mut seen = HashSet::new();
    evidence
        .iter()
        .filter(|line| !text.trim().is_empty() && text.contains(&line.text.to_ascii_lowercase()))
        .filter_map(|line| line.line)
        .filter(|line| seen.insert(*line))
        .collect()
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
    .to_ascii_lowercase()
}

fn missing_await_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "missing await",
            "without await",
            "not awaited",
            "called without await",
            "promise object",
        ],
    )
}

fn await_in_non_async_function_claim(text: &str) -> bool {
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

fn variable_scope_claim(text: &str) -> bool {
    contains_any(
        text,
        &[
            "out of scope",
            "not in scope",
            "undefined in finally",
            "finally cannot access",
            "lifetime",
            "borrowed value",
        ],
    )
}

fn build_break_claim(text: &str) -> bool {
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

fn secret_or_pii_logging_claim(finding: &ReviewFinding, text: &str) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::PiiOrSecretLogging | RiskCode::SecretLeak)
    ) && contains_any(text, &["log", "logging", "logged", "console.", "logger"])
}

fn sql_claim(finding: &ReviewFinding, text: &str) -> bool {
    finding.risk_code == Some(RiskCode::SqlInjection)
        || contains_any(
            text,
            &[
                "sql injection",
                "query injection",
                "interpolated into a sql",
            ],
        )
}

fn config_secret_claim(finding: &ReviewFinding, text: &str) -> bool {
    finding.risk_code == Some(RiskCode::SecretLeak)
        || (contains_any(text, &["api key", "secret", "token", "password"])
            && contains_any(text, &["manifest", "config", "configuration", ".env"]))
}

fn weak_error_handling_claim(finding: &ReviewFinding, text: &str) -> bool {
    finding.risk_code == Some(RiskCode::WeakErrorHandling)
        || contains_any(
            text,
            &[
                "weak error",
                "swallowed",
                "silently accepted",
                "not propagated",
                "not surfaced",
                "error handling",
            ],
        )
}

fn timeout_retry_claim(finding: &ReviewFinding, text: &str) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::MissingTimeout | RiskCode::UnboundedRetry)
    ) || contains_any(text, &["timeout", "retry", "backoff", "retry exhaustion"])
}

fn auth_session_token_claim(finding: &ReviewFinding, text: &str) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::AuthBypass | RiskCode::MissingAuthorizationCheck)
    ) || contains_any(text, &["auth", "session", "token", "credential"])
}

fn destructive_operation_claim(finding: &ReviewFinding, text: &str) -> bool {
    matches!(
        finding.risk_code,
        Some(RiskCode::DataIntegrityRisk | RiskCode::MigrationRisk)
    ) || contains_any(
        text,
        &[
            "delete",
            "deletion",
            "wipe",
            "clear",
            "drop table",
            "truncate",
        ],
    )
}

fn debug_only_claim(text: &str) -> bool {
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

fn vague_complexity_claim(text: &str) -> bool {
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
            "maintainability",
        ],
    )
}

fn call_name_from_claim(text: &str) -> Option<String> {
    IDENTIFIER_RE
        .captures_iter(text)
        .filter_map(|capture| {
            capture
                .get(1)
                .map(|value| value.as_str().to_ascii_lowercase())
        })
        .find(|word| {
            word.len() > 3
                && !matches!(
                    word.as_str(),
                    "await"
                        | "missing"
                        | "without"
                        | "called"
                        | "promise"
                        | "object"
                        | "token"
                        | "auth"
                        | "session"
                )
        })
}

fn variable_name_from_claim(text: &str) -> Option<String> {
    text.split('`')
        .nth(1)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_ascii_lowercase)
        .or_else(|| call_name_from_claim(text))
}

fn declaration_signal(text: &str, variable: &str) -> bool {
    contains_any(
        text,
        &[
            &format!("let {variable}"),
            &format!("const {variable}"),
            &format!("var {variable}"),
            &format!("mut {variable}"),
            &format!("{variable}:"),
        ],
    )
}

fn async_context_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "async function",
            "async (",
            "async(",
            "async =>",
            "= async",
            "async fn",
            "| async",
        ],
    )
}

fn async_call_without_await(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["get", "fetch", "load", "request", "token", "session"],
    ) && evidence.contains('(')
        && !evidence.contains("await ")
}

fn build_break_evidence(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "<<<<<<<",
            "=======",
            ">>>>>>>",
            "return @",
            "return@/",
            "=> @",
            "= @",
            "undefined undefined",
            "todo_remove_this",
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
            "api_key",
            "apikey",
            "email",
            "phone",
            "ssn",
            "bearer",
            "credential",
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
            "${", "$", "format!(", "format(", "+ user", "+ input", "concat", "`select",
        ],
    )
}

fn parameterized_query_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["? ", "$1", ":param", "params", "bind(", "prepare("],
    )
}

fn error_handling_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "catch",
            "except",
            "rescue",
            "error",
            "err",
            "failure",
            "exception",
            "try ",
        ],
    )
}

fn swallowed_error_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "catch {}",
            "catch (",
            "except:",
            "return false",
            "return null",
            "return;",
            "ok = true",
            "// ignore",
            "ignore error",
            "swallow",
        ],
    ) && !observable_failure_signal(evidence)
}

fn observable_failure_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "throw",
            "raise",
            "return err",
            "return error",
            "result.err",
            "logger.",
            "console.error",
            "metric",
            "alert",
            "notify",
            "fallback",
        ],
    )
}

fn retry_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["retry", "backoff", "attempt", "maxretry", "max_retry"],
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
        ],
    )
}

fn timeout_or_failure_handling_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "timeout",
            "abortcontroller",
            "settimeout",
            "deadline",
            "context.withtimeout",
            "catch",
            "throw",
            "return err",
            "logger.",
        ],
    )
}

fn auth_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "auth",
            "authorization",
            "authenticate",
            "authorize",
            "session",
            "token",
            "credential",
            "jwt",
            "bearer",
        ],
    )
}

fn missing_guard_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["if (!", "if not", "guard", "allow", "bypass", "skip"],
    ) && !contains_any(
        evidence,
        &["deny", "forbidden", "unauthorized", "return err", "throw"],
    )
}

fn destructive_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "delete",
            "remove",
            "unlink",
            "rmtree",
            "rm -rf",
            "wipe",
            "clear(",
            ".clear()",
            "drop table",
            "truncate",
        ],
    )
}

fn unguarded_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["without guard", "unguarded", "force", "all", "recursive"],
    ) || !guard_signal(evidence)
}

fn guard_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "if ",
            "guard",
            "confirm",
            "dry_run",
            "dryrun",
            "transaction",
            "where ",
            "limit ",
            "starts_with",
            "startswith",
            "canonical",
        ],
    )
}

fn debug_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["debug", "dev", "__debug__", "buildconfig.debug"],
    )
}

fn production_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &["production", "prod", "release", "dist", "runtime"],
    )
}

fn config_file_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "manifest", "config", ".env", "yaml", "toml", "gradle", "plist",
        ],
    )
}

fn config_indirection_signal(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "${",
            "$env",
            "process.env",
            "buildconfig",
            "manifestplaceholder",
            "secrets.",
            "env.",
        ],
    )
}

fn concrete_failure_mode_signal(text: &str) -> bool {
    contains_any(
        text,
        &[
            "deadlock",
            "race",
            "panic",
            "crash",
            "leak",
            "data loss",
            "timeout",
            "retry",
            "wrong",
            "incorrect",
            "unauthorized",
        ],
    )
}

fn generic_keyword_overlap(claim: &str, evidence: &str) -> bool {
    let evidence_tokens = token_set(evidence);
    let mut overlap = 0usize;
    for token in token_set(claim) {
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

fn contains_any(value: &str, terms: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    terms.iter().any(|term| value.contains(term))
}

#[cfg(test)]
mod tests {
    use super::{validate_finding_claim, ClaimSupport, EvidenceLine};
    use crate::review::types::{Effort, ReviewCategory, ReviewFinding, RiskCode, Severity};

    #[test]
    fn false_async_claim_contradicted_by_async_wrapper_is_dropped_signal() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::MissingAuthorizationCheck),
                "Await used in non-async function",
                "The callback uses await inside a non-async wrapper.",
            ),
            evidence(
                "src/auth.ts",
                10,
                "const run = async () => { await getToken(); };",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Contradicted);
    }

    #[test]
    fn true_missing_await_is_strong() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::MissingAuthorizationCheck),
                "Missing await",
                "The token fetch is called without await.",
            ),
            evidence("src/auth.ts", 10, "const token = getToken();"),
        );

        assert_eq!(result.support, ClaimSupport::Strong);
    }

    #[test]
    fn false_scope_claim_contradicted_by_outer_declaration() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::NilOrNullRisk),
                "tempFile is out of scope in finally",
                "The finally block cannot access `tempFile`.",
            ),
            evidence(
                "src/upload.ts",
                30,
                "let tempFile = null; try { tempFile = createTempFile(); } finally { cleanup(tempFile); }",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Contradicted);
    }

    #[test]
    fn true_scope_bug_is_strong() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::NilOrNullRisk),
                "tempFile is out of scope in finally",
                "The finally block cannot access `tempFile`.",
            ),
            evidence(
                "src/upload.ts",
                30,
                "try { let tempFile = createTempFile(); } finally { cleanup(tempFile); }",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Strong);
    }

    #[test]
    fn sql_interpolation_is_strong() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::SqlInjection),
                "SQL injection",
                "User input is interpolated into a query.",
            ),
            evidence(
                "src/db.ts",
                10,
                "db.query(`select * from users where id = ${userId}`);",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Strong);
    }

    #[test]
    fn secret_logging_is_strong() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::PiiOrSecretLogging),
                "Secret logging",
                "Authorization token is logged.",
            ),
            evidence(
                "src/logger.ts",
                20,
                "logger.info('Authorization', authorizationToken);",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Strong);
    }

    #[test]
    fn vague_complexity_is_weak_without_concrete_failure_mode() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::MaintainabilityRisk),
                "Complex logic",
                "This complex logic may be difficult to reason about.",
            ),
            evidence(
                "src/lib.ts",
                8,
                "const result = items.map(transform).filter(Boolean);",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Weak);
    }

    #[test]
    fn debug_only_risk_is_weak_without_production_path() {
        let result = validate_finding_claim(
            &finding(
                Some(RiskCode::Other),
                "Debug-only configuration can reach production",
                "Debug logging is enabled.",
            ),
            evidence(
                "src/config.ts",
                8,
                "if (BuildConfig.DEBUG) enableDebugLogging();",
            ),
        );

        assert_eq!(result.support, ClaimSupport::Weak);
    }

    fn evidence(path: &str, line: u32, text: &str) -> Vec<EvidenceLine> {
        vec![EvidenceLine {
            file_path: path.to_string(),
            line: Some(line),
            text: text.to_string(),
        }]
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
