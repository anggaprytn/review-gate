use crate::{
    config::CurrentFileValidationConfig,
    redaction::redact_secrets,
    review::{
        anchors::AnchoredDiffContext,
        types::{
            EvidenceValidationStatus, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding,
            RiskCode, Severity,
        },
    },
};
use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, future::Future, sync::LazyLock};

const SPECULATIVE_PHRASES: &[&str] = &[
    "out of scope",
    "will crash",
    "will fail build",
    "toctou",
    "symlink",
    " if ",
    " may ",
    " could ",
    "not visible",
    "unclear",
];

const BUILD_BREAK_CLAIM_PHRASES: &[&str] = &[
    "invalid syntax",
    "build failure",
    "build fail",
    "fail build",
    "will fail build",
    "break build",
    "compile failure",
    "compilation failure",
    "does not compile",
    "won't compile",
    "malformed code",
    "merge conflict",
];

const AWAIT_CONTEXT_SCAN_WINDOW: usize = 20;

static AWAIT_EXPRESSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bawait\b").expect("valid await expression regex"));
static ASYNC_FUNCTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\basync\s+function\b").expect("valid async function regex"));
static ASYNC_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|let|var)\s+[$A-Za-z_][$A-Za-z0-9_]*\s*=\s*async\b")
        .expect("valid async assignment regex")
});
static ASYNC_ARROW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\basync\s*\([^)]*\)\s*=>").expect("valid async arrow regex"));
static ASYNC_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\basync\s*[$A-Za-z_][$A-Za-z0-9_]*\s*\(").expect("valid async method regex")
});
static CALL_ASYNC_CALLBACK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[$A-Za-z_][$A-Za-z0-9_]*\s*\(\s*async\b").expect("valid async callback regex")
});
static NON_ASYNC_FUNCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfunction\s+[$A-Za-z_][$A-Za-z0-9_]*\s*\(")
        .expect("valid non-async function regex")
});
static NON_ASYNC_ASSIGNMENT_ARROW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:const|let|var)\s+[$A-Za-z_][$A-Za-z0-9_]*\s*=\s*(?:\([^)]*\)|[$A-Za-z_][$A-Za-z0-9_]*)\s*=>",
    )
    .expect("valid non-async assignment arrow regex")
});
static NON_ASYNC_CALLBACK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[$A-Za-z_][$A-Za-z0-9_]*\s*\(\s*(?:\([^)]*\)|[$A-Za-z_][$A-Za-z0-9_]*)\s*=>")
        .expect("valid non-async callback regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentFileValidationOptions {
    pub enabled: bool,
    pub validate_priority_with_model: bool,
    pub max_file_bytes: usize,
    pub context_lines: usize,
}

impl From<&CurrentFileValidationConfig> for CurrentFileValidationOptions {
    fn from(config: &CurrentFileValidationConfig) -> Self {
        Self {
            enabled: config.enabled,
            validate_priority_with_model: config.validate_priority_with_model,
            max_file_bytes: config.max_file_bytes,
            context_lines: config.context_lines,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentFileFetch {
    pub content: Result<String, String>,
}

pub async fn validate_review_analysis_current_file<F, Fut, M, MFut>(
    mut analysis: ReviewAnalysis,
    anchors: &AnchoredDiffContext,
    options: CurrentFileValidationOptions,
    mut fetch_file: F,
    mut validate_with_model: M,
) -> ReviewAnalysis
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
    M: FnMut(String) -> MFut,
    MFut: Future<Output = Result<String, String>>,
{
    if !options.enabled {
        return analysis;
    }

    let mut file_cache = HashMap::<String, CurrentFileFetch>::new();
    for path in candidate_file_paths(&analysis, anchors) {
        let content = fetch_file(path.clone()).await;
        file_cache.insert(path, CurrentFileFetch { content });
    }

    analysis.findings = validate_findings(
        analysis.findings,
        anchors,
        &options,
        &file_cache,
        &mut validate_with_model,
    )
    .await;
    analysis.overall_risk = overall_risk_from_findings(&analysis.findings);
    analysis
}

async fn validate_findings<M, MFut>(
    findings: Vec<ReviewFinding>,
    anchors: &AnchoredDiffContext,
    options: &CurrentFileValidationOptions,
    file_cache: &HashMap<String, CurrentFileFetch>,
    validate_with_model: &mut M,
) -> Vec<ReviewFinding>
where
    M: FnMut(String) -> MFut,
    MFut: Future<Output = Result<String, String>>,
{
    let mut validated = Vec::with_capacity(findings.len());
    for finding in findings {
        if !should_validate_current_file(&finding) {
            validated.push(finding);
            continue;
        }

        validated.push(
            validate_finding_current_file(
                finding,
                anchors,
                options,
                file_cache,
                validate_with_model,
            )
            .await,
        );
    }
    validated
}

async fn validate_finding_current_file<M, MFut>(
    mut finding: ReviewFinding,
    anchors: &AnchoredDiffContext,
    options: &CurrentFileValidationOptions,
    file_cache: &HashMap<String, CurrentFileFetch>,
    validate_with_model: &mut M,
) -> ReviewFinding
where
    M: FnMut(String) -> MFut,
    MFut: Future<Output = Result<String, String>>,
{
    let Some(file_path) = finding_file_path(&finding, anchors) else {
        return downgrade_unconfirmed(finding, "current file path is unavailable");
    };
    let Some(fetch) = file_cache.get(&file_path) else {
        return downgrade_unconfirmed(finding, "current file was not fetched");
    };
    let content = match &fetch.content {
        Ok(content) => content,
        Err(reason) => {
            return downgrade_unconfirmed(
                finding,
                &format!("current file could not be fetched: {reason}"),
            );
        }
    };

    let line = finding_line(&finding, anchors).unwrap_or(1);
    let snippet = build_validation_snippet(&file_path, content, line, options.context_lines);
    if let Some(result) = deterministic_validation(&finding, content, &snippet) {
        apply_current_file_result(&mut finding, result);
        return finding;
    }

    if options.validate_priority_with_model && should_model_validate(&finding) {
        let prompt = build_model_validation_prompt(&finding, &snippet, anchors);
        match validate_with_model(prompt).await {
            Ok(response) => match parse_model_validation_response(&response) {
                Some(result) => apply_current_file_result(&mut finding, result),
                None => apply_current_file_result(
                    &mut finding,
                    CurrentFileResult::needs_manual(
                        Severity::Medium,
                        "validation model returned malformed JSON",
                    ),
                ),
            },
            Err(err) => apply_current_file_result(
                &mut finding,
                CurrentFileResult::needs_manual(
                    Severity::Medium,
                    &format!("validation model failed: {err}"),
                ),
            ),
        }
    }

    finding
}

fn candidate_file_paths(analysis: &ReviewAnalysis, anchors: &AnchoredDiffContext) -> Vec<String> {
    let mut paths = Vec::new();
    for finding in &analysis.findings {
        if !should_validate_current_file(finding) {
            continue;
        }
        let Some(path) = finding_file_path(finding, anchors) else {
            continue;
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

fn should_validate_current_file(finding: &ReviewFinding) -> bool {
    if matches!(finding.severity, Severity::Critical | Severity::High)
        || (finding.severity == Severity::Medium && priority_category(&finding.category))
    {
        return true;
    }

    speculative_signal(&finding_text(finding).to_ascii_lowercase())
}

fn should_model_validate(finding: &ReviewFinding) -> bool {
    matches!(finding.severity, Severity::Critical | Severity::High)
        || (finding.severity == Severity::Medium
            && priority_category(&finding.category)
            && speculative_signal(&finding_text(finding).to_ascii_lowercase()))
}

fn priority_category(category: &ReviewCategory) -> bool {
    matches!(
        category,
        ReviewCategory::Security
            | ReviewCategory::Correctness
            | ReviewCategory::DataIntegrity
            | ReviewCategory::Reliability
    )
}

fn deterministic_validation(
    finding: &ReviewFinding,
    content: &str,
    snippet: &ValidationSnippet,
) -> Option<CurrentFileResult> {
    let text = finding_text(finding).to_ascii_lowercase();
    let snippet_lower = snippet.text.to_ascii_lowercase();

    if text.contains("out of scope") {
        return Some(validate_variable_scope_claim(finding, content));
    }
    if contains_any(&text, &["toctou", "symlink"]) {
        return Some(validate_symlink_toctou_claim(finding, &snippet_lower));
    }
    if contains_any(
        &text,
        &[
            "debug-only",
            "debug only",
            "debug config",
            "debug configuration",
        ],
    ) {
        return Some(validate_debug_config_claim(&snippet_lower));
    }
    if build_break_claim(&text) {
        return Some(validate_build_break_claim(&snippet_lower));
    }
    if await_non_async_claim(&text) {
        return Some(validate_await_non_async_claim(
            content,
            finding.line,
            finding.severity,
        ));
    }

    None
}

fn validate_await_non_async_claim(
    snippet: &str,
    finding_line: Option<u32>,
    original_severity: Severity,
) -> CurrentFileResult {
    let snippet_lines = parse_validation_snippet_lines(snippet);
    let Some(await_index) = find_await_line_index(&snippet_lines, finding_line) else {
        return CurrentFileResult::needs_manual(
            Severity::Low,
            "await/non-async claim lacks an await expression in the current file snippet",
        );
    };

    match nearest_await_function_context(&snippet_lines, await_index) {
        AwaitFunctionContext::Async => CurrentFileResult {
            verdict: CurrentFileVerdict::Stale,
            final_severity: Severity::Note,
            actionable: false,
            corrected_title: None,
            corrected_body: None,
            corrected_suggested_fix: None,
            reason: "nearest enclosing function/callback for await is marked async".to_string(),
        },
        AwaitFunctionContext::NonAsync => CurrentFileResult::valid(
            original_severity,
            "current file snippet shows await inside a non-async function/callback",
        ),
        AwaitFunctionContext::Unknown => CurrentFileResult::needs_manual(
            Severity::Low,
            "current file snippet does not show the enclosing async/non-async function context",
        ),
    }
}

fn validate_variable_scope_claim(finding: &ReviewFinding, content: &str) -> CurrentFileResult {
    let variable = variable_from_scope_claim(finding);
    let Some(variable) = variable.as_deref() else {
        return CurrentFileResult::needs_manual(Severity::Medium, "variable name was not clear");
    };

    if variable_declared_before_try_or_finally(content, variable) {
        if temp_file_created_before_try(content) {
            return CurrentFileResult {
                verdict: CurrentFileVerdict::PartiallyValid,
                final_severity: Severity::Medium,
                actionable: true,
                corrected_title: Some("Temp file creation happens before cleanup guard".to_string()),
                corrected_body: Some(
                    "The variable is visible to `finally`, so the original scope claim is stale. The remaining risk is that temporary file creation can happen before the `try/finally`; if creation fails first, cleanup and loading reset may be skipped.".to_string(),
                ),
                corrected_suggested_fix: Some(
                    "Move temporary file creation inside a cleanup-guarded `try/finally`, or initialize cleanup state before any operation that can fail.".to_string(),
                ),
                reason: "variable is declared before finally; related cleanup guard issue remains".to_string(),
            };
        }

        return CurrentFileResult {
            verdict: CurrentFileVerdict::Invalid,
            final_severity: Severity::Note,
            actionable: false,
            corrected_title: None,
            corrected_body: None,
            corrected_suggested_fix: None,
            reason: format!("`{variable}` is declared in an outer scope visible to finally"),
        };
    }

    CurrentFileResult {
        verdict: CurrentFileVerdict::Valid,
        final_severity: finding.severity,
        actionable: finding.actionable,
        corrected_title: None,
        corrected_body: None,
        corrected_suggested_fix: None,
        reason: format!("no outer declaration for `{variable}` is visible before finally"),
    }
}

fn validate_symlink_toctou_claim(
    finding: &ReviewFinding,
    snippet_lower: &str,
) -> CurrentFileResult {
    let canonical = contains_any(
        snippet_lower,
        &[
            "canonicalpath",
            "canonical_path",
            "getcanonicalpath",
            "canonicalize",
            "realpath",
        ],
    );
    let cache_root = contains_any(
        snippet_lower,
        &["cachedir", "cache_dir", "cachesdirectory", "cache"],
    );
    let root_check = contains_any(snippet_lower, &["startswith", "starts_with", "relative_to"]);

    if canonical && cache_root && root_check {
        return CurrentFileResult {
            verdict: CurrentFileVerdict::PartiallyValid,
            final_severity: Severity::Low,
            actionable: true,
            corrected_title: Some("Cache cleanup symlink handling is a hardening concern".to_string()),
            corrected_body: Some(
                "The current file shows canonical cache-root validation before cleanup, so the original TOCTOU/symlink claim is not proven as a medium security issue. Treat this as low-severity hardening unless the threat model includes attacker control of app-private cache entries.".to_string(),
            ),
            corrected_suggested_fix: Some(
                "Keep canonical cache-root validation and consider non-following deletion APIs or extra checks only if untrusted cache entries are in scope.".to_string(),
            ),
            reason: "canonical cache-root validation is visible; exploitability needs a stronger threat model".to_string(),
        };
    }

    CurrentFileResult {
        verdict: CurrentFileVerdict::Valid,
        final_severity: match finding.severity {
            Severity::Critical | Severity::High => Severity::Medium,
            severity => severity,
        },
        actionable: finding.actionable,
        corrected_title: None,
        corrected_body: None,
        corrected_suggested_fix: None,
        reason: "canonical cache-root validation is not visible in the current snippet".to_string(),
    }
}

fn validate_debug_config_claim(snippet_lower: &str) -> CurrentFileResult {
    let production_proven = contains_any(snippet_lower, &["release", "production", "prod"])
        && !contains_any(
            snippet_lower,
            &["debugimplementation", "debug_only", "debug-only"],
        );
    if production_proven {
        return CurrentFileResult::valid(
            Severity::Medium,
            "current snippet includes production/release context",
        );
    }

    CurrentFileResult {
        verdict: CurrentFileVerdict::PartiallyValid,
        final_severity: Severity::Low,
        actionable: true,
        corrected_title: None,
        corrected_body: None,
        corrected_suggested_fix: None,
        reason: "debug configuration is not proven to affect production/release builds".to_string(),
    }
}

fn validate_build_break_claim(snippet_lower: &str) -> CurrentFileResult {
    if build_break_evidence(snippet_lower) {
        return CurrentFileResult::valid(
            Severity::High,
            "current file snippet shows exact invalid syntax evidence",
        );
    }

    CurrentFileResult {
        verdict: CurrentFileVerdict::Invalid,
        final_severity: Severity::Note,
        actionable: false,
        corrected_title: None,
        corrected_body: None,
        corrected_suggested_fix: None,
        reason: "build-break claim lacks exact invalid syntax evidence in the current file snippet"
            .to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationSnippet {
    text: String,
}

fn build_validation_snippet(
    file_path: &str,
    content: &str,
    line: u32,
    context_lines: usize,
) -> ValidationSnippet {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let target = line.max(1) as usize;
    let start = target.saturating_sub(context_lines).max(1);
    let end = (target + context_lines).min(total.max(1));
    let width = end.to_string().len().max(1);

    let mut text = String::new();
    text.push_str("Current file snippet at head SHA:\n\n");
    text.push_str(&format!("File: {file_path}\n"));
    text.push_str(&format!("Lines: {start}-{end}\n\n"));
    for line_number in start..=end {
        let content = lines.get(line_number - 1).copied().unwrap_or_default();
        text.push_str(&format!(
            "{line_number:>width$} | {}\n",
            redact_secrets(content).replace('\t', "    ")
        ));
    }

    ValidationSnippet { text }
}

fn build_model_validation_prompt(
    finding: &ReviewFinding,
    snippet: &ValidationSnippet,
    anchors: &AnchoredDiffContext,
) -> String {
    let mut prompt = String::new();
    prompt
        .push_str("Validate only the given ReviewGate finding against the current file snippet.\n");
    prompt.push_str("Do not trust the original finding. If it contradicts the snippet, mark invalid or stale.\n");
    prompt.push_str(
        "If a related real bug exists, return partially_valid and rewrite to the precise issue.\n",
    );
    prompt.push_str("Do not invent issues outside the snippet. Do not keep HIGH unless the snippet directly proves the issue.\n");
    prompt.push_str(
        "For speculative threat-model-only issues, use LOW or needs_manual_confirmation.\n",
    );
    prompt.push_str("Return JSON only with this schema: {\"verdict\":\"valid|invalid|partially_valid|stale|needs_manual_confirmation\",\"final_severity\":\"CRITICAL|HIGH|MEDIUM|LOW|NOTE\",\"actionable\":true,\"corrected_title\":null,\"corrected_body\":null,\"corrected_suggested_fix\":null,\"reason\":\"short explanation\"}.\n\n");
    prompt.push_str("Finding:\n");
    prompt.push_str(&format!("Severity: {}\n", finding.severity.display_upper()));
    prompt.push_str(&format!("Category: {}\n", finding.category.display_lower()));
    prompt.push_str(&format!("Title: {}\n", finding.title));
    prompt.push_str(&format!("Body: {}\n", finding.body));
    prompt.push_str(&format!(
        "Suggested fix: {}\n\n",
        finding.suggested_fix.as_deref().unwrap_or("none")
    ));
    prompt.push_str(&snippet.text);
    if let Some(anchor_text) = relevant_anchor_text(finding, anchors) {
        prompt.push_str("\nRelevant diff anchor content:\n");
        prompt.push_str(&anchor_text);
    }
    prompt
}

fn relevant_anchor_text(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> Option<String> {
    let anchor = finding
        .anchor_id
        .as_deref()
        .and_then(|anchor_id| anchors.get(anchor_id))
        .or_else(|| {
            let file_path = finding.file_path.as_deref()?;
            let line = finding.line?;
            anchors.anchors.iter().find(|anchor| {
                (anchor.file_path == file_path || anchor.new_path == file_path)
                    && anchor.new_line == Some(line)
            })
        })?;
    Some(format!(
        "[{}] new_line={} old_line={} | {}\n",
        anchor.anchor_id,
        anchor
            .new_line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "-".to_string()),
        anchor
            .old_line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "-".to_string()),
        anchor.content_preview
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CurrentFileVerdict {
    Valid,
    Invalid,
    PartiallyValid,
    Stale,
    NeedsManualConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentFileResult {
    verdict: CurrentFileVerdict,
    final_severity: Severity,
    actionable: bool,
    corrected_title: Option<String>,
    corrected_body: Option<String>,
    corrected_suggested_fix: Option<String>,
    reason: String,
}

impl CurrentFileResult {
    fn valid(final_severity: Severity, reason: &str) -> Self {
        Self {
            verdict: CurrentFileVerdict::Valid,
            final_severity,
            actionable: true,
            corrected_title: None,
            corrected_body: None,
            corrected_suggested_fix: None,
            reason: reason.to_string(),
        }
    }

    fn needs_manual(final_severity: Severity, reason: &str) -> Self {
        Self {
            verdict: CurrentFileVerdict::NeedsManualConfirmation,
            final_severity,
            actionable: final_severity == Severity::Low,
            corrected_title: None,
            corrected_body: None,
            corrected_suggested_fix: None,
            reason: reason.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ModelValidationResponse {
    verdict: String,
    final_severity: String,
    actionable: bool,
    corrected_title: Option<String>,
    corrected_body: Option<String>,
    corrected_suggested_fix: Option<String>,
    reason: String,
}

fn parse_model_validation_response(value: &str) -> Option<CurrentFileResult> {
    let json = extract_json_object(value)?;
    let parsed: ModelValidationResponse = serde_json::from_str(json).ok()?;
    Some(CurrentFileResult {
        verdict: parse_verdict(&parsed.verdict)?,
        final_severity: parse_severity(&parsed.final_severity)?,
        actionable: parsed.actionable,
        corrected_title: parsed.corrected_title,
        corrected_body: parsed.corrected_body,
        corrected_suggested_fix: parsed.corrected_suggested_fix,
        reason: parsed.reason,
    })
}

fn extract_json_object(value: &str) -> Option<&str> {
    let start = value.find('{')?;
    let end = value.rfind('}')?;
    (start <= end).then_some(&value[start..=end])
}

fn parse_verdict(value: &str) -> Option<CurrentFileVerdict> {
    match value.trim().to_ascii_lowercase().as_str() {
        "valid" => Some(CurrentFileVerdict::Valid),
        "invalid" => Some(CurrentFileVerdict::Invalid),
        "partially_valid" => Some(CurrentFileVerdict::PartiallyValid),
        "stale" => Some(CurrentFileVerdict::Stale),
        "needs_manual_confirmation" => Some(CurrentFileVerdict::NeedsManualConfirmation),
        _ => None,
    }
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "NOTE" => Some(Severity::Note),
        _ => None,
    }
}

fn apply_current_file_result(finding: &mut ReviewFinding, result: CurrentFileResult) {
    match result.verdict {
        CurrentFileVerdict::Valid => {
            finding.severity = result.final_severity;
            finding.actionable = result.actionable;
            finding.evidence_status = Some(EvidenceValidationStatus::Validated);
        }
        CurrentFileVerdict::PartiallyValid => {
            finding.severity = result.final_severity;
            finding.actionable = result.actionable;
            if let Some(title) = result.corrected_title {
                finding.title = title;
            }
            if let Some(body) = result.corrected_body {
                finding.body = body;
            }
            if result.corrected_suggested_fix.is_some() {
                finding.suggested_fix = result.corrected_suggested_fix;
            }
            finding.evidence_status = Some(EvidenceValidationStatus::Validated);
        }
        CurrentFileVerdict::Invalid | CurrentFileVerdict::Stale => {
            finding.severity = Severity::Note;
            finding.actionable = false;
            finding.risk_code = Some(RiskCode::PositiveNote);
            finding.evidence_status = Some(if result.verdict == CurrentFileVerdict::Stale {
                EvidenceValidationStatus::StaleContext
            } else {
                EvidenceValidationStatus::WeakEvidence
            });
        }
        CurrentFileVerdict::NeedsManualConfirmation => {
            finding.severity = result.final_severity;
            finding.actionable = result.actionable && result.final_severity == Severity::Low;
            finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
        }
    }
    finding.evidence_reason = Some(format!("current-file validation: {}", result.reason));
}

fn downgrade_unconfirmed(mut finding: ReviewFinding, reason: &str) -> ReviewFinding {
    if matches!(finding.severity, Severity::Critical | Severity::High) {
        finding.severity = Severity::Medium;
    }
    finding.evidence_status = Some(EvidenceValidationStatus::NeedsManualConfirmation);
    finding.evidence_reason = Some(format!("current-file validation: {reason}"));
    finding
}

fn finding_file_path(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> Option<String> {
    finding
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .or_else(|| {
            finding
                .anchor_id
                .as_deref()
                .and_then(|anchor_id| anchors.get(anchor_id))
                .map(|anchor| anchor.new_path.clone())
        })
}

fn finding_line(finding: &ReviewFinding, anchors: &AnchoredDiffContext) -> Option<u32> {
    finding.line.or_else(|| {
        finding
            .anchor_id
            .as_deref()
            .and_then(|anchor_id| anchors.get(anchor_id))
            .and_then(|anchor| anchor.new_line.or(anchor.old_line))
    })
}

fn variable_from_scope_claim(finding: &ReviewFinding) -> Option<String> {
    let text = finding_text(finding);
    let out_index = text.to_ascii_lowercase().find("out of scope")?;
    let before = &text[..out_index];
    if let Some(captures) = Regex::new(r"`([A-Za-z_][A-Za-z0-9_]*)`")
        .ok()?
        .captures_iter(before)
        .last()
    {
        return captures.get(1).map(|value| value.as_str().to_string());
    }

    before
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .rev()
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                && !matches!(*token, "is" | "was" | "variable" | "the")
        })
        .map(str::to_string)
}

fn variable_declared_before_try_or_finally(content: &str, variable: &str) -> bool {
    let first_try_or_finally = content
        .lines()
        .position(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("try") || lower.contains("finally")
        })
        .unwrap_or_else(|| content.lines().count());
    let escaped = regex::escape(variable);
    let pattern = format!(
        r"\b(let|const|var|val|private|protected|public|final)\s+[^;\n]*\b{escaped}\b|\b{escaped}\s*[:=]"
    );
    let Ok(regex) = Regex::new(&pattern) else {
        return false;
    };

    content
        .lines()
        .take(first_try_or_finally)
        .any(|line| regex.is_match(line))
}

fn temp_file_created_before_try(content: &str) -> bool {
    let Some(try_line) = content
        .lines()
        .position(|line| line.to_ascii_lowercase().contains("try"))
    else {
        return false;
    };
    let before_try = content
        .lines()
        .take(try_line)
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    contains_any(
        &before_try,
        &[
            "createtemp",
            "temporaryfile",
            "temporary file",
            "tempfile",
            "filepaths.push",
            "file_paths.push",
        ],
    )
}

fn finding_text(finding: &ReviewFinding) -> String {
    format!(
        "{} {} {}",
        finding.title,
        finding.body,
        finding.suggested_fix.as_deref().unwrap_or_default()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnippetLine {
    number: Option<u32>,
    code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AwaitFunctionContext {
    Async,
    NonAsync,
    Unknown,
}

fn parse_validation_snippet_lines(snippet: &str) -> Vec<SnippetLine> {
    let parsed = snippet
        .lines()
        .filter_map(|line| {
            let (number, code) = line.split_once('|')?;
            let number = number.trim().parse::<u32>().ok();
            Some(SnippetLine {
                number,
                code: code.trim_start().to_string(),
            })
        })
        .collect::<Vec<_>>();

    if !parsed.is_empty() {
        return parsed;
    }

    snippet
        .lines()
        .enumerate()
        .map(|(index, code)| SnippetLine {
            number: Some(index as u32 + 1),
            code: code.to_string(),
        })
        .collect()
}

fn find_await_line_index(lines: &[SnippetLine], finding_line: Option<u32>) -> Option<usize> {
    if let Some(finding_line) = finding_line {
        if let Some(index) = lines
            .iter()
            .position(|line| line.number == Some(finding_line) && await_expression(&line.code))
        {
            return Some(index);
        }
    }

    lines.iter().position(|line| await_expression(&line.code))
}

fn nearest_await_function_context(
    lines: &[SnippetLine],
    await_index: usize,
) -> AwaitFunctionContext {
    let start = await_index.saturating_sub(AWAIT_CONTEXT_SCAN_WINDOW);
    for line in lines[start..=await_index].iter().rev() {
        let code = line.code.trim();
        if code.is_empty() {
            continue;
        }
        if clear_previous_block_boundary(code) {
            break;
        }
        if async_function_or_callback_opener(code) {
            return AwaitFunctionContext::Async;
        }
        if non_async_function_or_callback_opener(code) {
            return AwaitFunctionContext::NonAsync;
        }
    }

    AwaitFunctionContext::Unknown
}

fn await_non_async_claim(text: &str) -> bool {
    let normalized = text.replace(['-', '_'], " ");
    (normalized.contains("await used in non async")
        || normalized.contains("await used in a non async")
        || normalized.contains("await in non async")
        || (normalized.contains("await call") && normalized.contains("not async"))
        || (normalized.contains("syntax error") && normalized.contains("await")))
        && normalized.contains("await")
}

fn await_expression(code: &str) -> bool {
    AWAIT_EXPRESSION_RE.is_match(code)
}

fn async_function_or_callback_opener(code: &str) -> bool {
    let compact = code.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = compact.to_ascii_lowercase();
    lower.contains("usecallback(async")
        || lower.contains("usememo(async")
        || ASYNC_FUNCTION_RE.is_match(&lower)
        || ASYNC_ASSIGNMENT_RE.is_match(&compact)
        || ASYNC_ARROW_RE.is_match(&lower)
        || ASYNC_METHOD_RE.is_match(&compact)
        || CALL_ASYNC_CALLBACK_RE.is_match(&compact)
}

fn non_async_function_or_callback_opener(code: &str) -> bool {
    if async_function_or_callback_opener(code) {
        return false;
    }

    let compact = code.split_whitespace().collect::<Vec<_>>().join(" ");
    NON_ASYNC_FUNCTION_RE.is_match(&compact)
        || NON_ASYNC_ASSIGNMENT_ARROW_RE.is_match(&compact)
        || NON_ASYNC_CALLBACK_RE.is_match(&compact)
}

fn clear_previous_block_boundary(code: &str) -> bool {
    let trimmed = code.trim_start();
    trimmed.starts_with('}') || trimmed.starts_with(");") || trimmed.starts_with("];")
}

fn speculative_signal(text: &str) -> bool {
    let padded = format!(" {text} ");
    SPECULATIVE_PHRASES
        .iter()
        .any(|phrase| padded.contains(phrase))
}

fn build_break_claim(text: &str) -> bool {
    contains_any(text, BUILD_BREAK_CLAIM_PHRASES)
}

fn build_break_evidence(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "<<<<<<<",
            "=======",
            ">>>>>>>",
            "return @",
            "return@../../",
            "return @../../",
            "return @/",
            "return@/",
            " @../../",
            "=> @",
            "= @",
            "<unknown>",
            "undefined undefined",
            "todo_remove_this",
        ],
    )
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn overall_risk_from_findings(findings: &[ReviewFinding]) -> OverallRisk {
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        OverallRisk::Critical
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::High)
    {
        OverallRisk::High
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Medium)
    {
        OverallRisk::Medium
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Low)
    {
        OverallRisk::Low
    } else {
        OverallRisk::Note
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_review_analysis_current_file, CurrentFileValidationOptions};
    use crate::{
        counters::count_findings_from_analysis,
        review::{
            anchors::AnchoredDiffContext,
            formatter::{format_review_markdown_for_mode_with_emoji, MarkdownRenderMode},
            inline::{resolve_inline_candidates, InlineEligibilityReason},
            types::{Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, Severity},
        },
    };

    #[tokio::test]
    async fn variable_out_of_scope_false_positive_invalidated_when_declared_before_try() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "filePaths is out of scope in finally",
            "`filePaths` is declared inside try and will crash in finally.",
        )])
        .with_file(
            "src/a.ts",
            r#"
let filePaths: string[] = []
try {
  await upload()
} finally {
  await Promise.all(filePaths.map(remove))
}
"#,
        )
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
        assert!(analysis.findings[0]
            .evidence_reason
            .as_deref()
            .unwrap()
            .contains("declared in an outer scope"));
    }

    #[tokio::test]
    async fn temp_file_creation_before_try_finally_is_rewritten_as_medium() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "filePaths is out of scope in finally",
            "`filePaths` is declared inside try and will crash in finally.",
        )])
        .with_file(
            "src/a.ts",
            r#"
let filePaths: string[] = []
const created = await createTempFile()
filePaths.push(created)
try {
  await upload()
} finally {
  await Promise.all(filePaths.map(remove))
}
"#,
        )
        .run()
        .await;

        let finding = &analysis.findings[0];
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(
            finding.title,
            "Temp file creation happens before cleanup guard"
        );
        assert!(finding.body.contains("original scope claim is stale"));
        assert!(finding
            .suggested_fix
            .as_deref()
            .unwrap()
            .contains("try/finally"));
    }

    #[tokio::test]
    async fn variable_truly_out_of_scope_remains_valid() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "filePaths is out of scope in finally",
            "`filePaths` is out of scope in finally.",
        )])
        .with_file(
            "src/a.ts",
            r#"
try {
  let filePaths: string[] = []
  await upload()
} finally {
  await Promise.all(filePaths.map(remove))
}
"#,
        )
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert!(analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn toctou_with_canonical_cache_root_validation_is_downgraded_to_low() {
        let analysis = validate(vec![finding(
            Severity::Medium,
            ReviewCategory::Security,
            "TOCTOU symlink deletion can escape cache",
            "The cleanup may follow a symlink outside the app cache.",
        )])
        .with_file(
            "src/Cleanup.java",
            r#"
String root = cacheDir.getCanonicalPath();
String target = file.getCanonicalPath();
if (target.startsWith(root)) {
  file.delete();
}
"#,
        )
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Low);
        assert!(analysis.findings[0].body.contains("not proven"));
    }

    #[tokio::test]
    async fn toctou_without_canonical_validation_remains_medium() {
        let analysis = validate(vec![finding(
            Severity::Medium,
            ReviewCategory::Security,
            "TOCTOU symlink deletion can escape cache",
            "The cleanup may follow a symlink outside the app cache.",
        )])
        .with_file(
            "src/Cleanup.java",
            "for (File file : cacheFiles) { file.delete(); }",
        )
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn debug_only_config_warning_is_downgraded_to_low() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Security,
            "Debug-only config may leak",
            "Debug config could be enabled.",
        )])
        .with_file("build.gradle", "debugImplementation(\"tooling\")")
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Low);
    }

    #[tokio::test]
    async fn build_break_without_exact_current_syntax_evidence_is_downgraded() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "Build will fail",
            "This will fail build.",
        )])
        .with_file("src/a.kt", "fun ok() = true")
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn build_break_with_exact_invalid_syntax_remains_high() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "Build will fail",
            "This will fail build.",
        )])
        .with_file("src/a.kt", "<<<<<<< HEAD\nfun broken()")
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn await_non_async_claim_invalidated_for_async_use_callback() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
const getToken = useCallback(async () => {
  const token = await messaging().getToken()
  return token
})
"#,
            )
            .run()
            .await;

        let finding = &analysis.findings[0];
        assert_eq!(finding.severity, Severity::Note);
        assert!(!finding.actionable);
        assert_eq!(
            finding.evidence_status,
            Some(crate::review::types::EvidenceValidationStatus::StaleContext)
        );
        assert!(finding
            .evidence_reason
            .as_deref()
            .unwrap()
            .contains("nearest enclosing function/callback"));
    }

    #[tokio::test]
    async fn await_non_async_claim_invalidated_for_async_arrow_assignment() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
const getToken = async () => {
  const token = await messaging().getToken()
  return token
}
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_invalidated_for_async_function_declaration() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
async function getToken() {
  const token = await messaging().getToken()
  return token
}
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_kept_for_non_async_use_callback() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
const getToken = useCallback(() => {
  const token = await messaging().getToken()
  return token
})
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert!(analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_kept_for_non_async_function_declaration() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
function getToken() {
  const token = await messaging().getToken()
  return token
}
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert!(analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_kept_for_non_async_arrow_assignment() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
const getToken = () => {
  const token = await messaging().getToken()
  return token
}
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::High);
        assert!(analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_invalidated_for_nested_async_function_in_effect() {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
useEffect(() => {
  async function load() {
    await foo()
  }
  load()
}, [])
"#,
            )
            .run()
            .await;

        assert_eq!(analysis.findings[0].severity, Severity::Note);
        assert!(!analysis.findings[0].actionable);
    }

    #[tokio::test]
    async fn await_non_async_claim_with_uncertain_context_downgrades_to_low_manual_confirmation() {
        let analysis = validate(vec![await_finding()])
            .with_file("src/a.ts", "const token = await messaging().getToken()")
            .run()
            .await;

        let finding = &analysis.findings[0];
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(
            finding.evidence_status,
            Some(crate::review::types::EvidenceValidationStatus::NeedsManualConfirmation)
        );
        assert!(finding
            .evidence_reason
            .as_deref()
            .unwrap()
            .contains("does not show the enclosing"));
    }

    #[tokio::test]
    async fn invalidated_await_non_async_finding_is_excluded_from_counters_inline_and_publish_body()
    {
        let analysis = validate(vec![await_finding()])
            .with_file(
                "src/a.ts",
                r#"
const getToken = useCallback(async () => {
  const token = await messaging().getToken()
  return token
})
"#,
            )
            .run()
            .await;

        let counters = count_findings_from_analysis(&analysis);
        assert_eq!(counters.total, 0);
        assert_eq!(counters.open_priority, 0);
        assert_eq!(counters.open_actionable, 0);

        let candidates = resolve_inline_candidates(
            &analysis,
            &[],
            None,
            &crate::config::InlineConfig {
                enabled: true,
                dry_run: true,
                dedupe: true,
                max_inline_total: 10,
                max_high_inline: 8,
                max_medium_inline: 5,
            },
        );
        assert_eq!(
            candidates[0].reason,
            InlineEligibilityReason::SeverityTooLow
        );

        let markdown = format_review_markdown_for_mode_with_emoji(
            &analysis,
            MarkdownRenderMode::Publish,
            false,
        );
        assert!(!markdown.contains("Syntax Error: await used in non-async function"));
        assert!(!markdown.contains("await is inside a non-async callback"));
        assert!(!markdown.contains("1 note"));
        assert!(markdown.contains("Open priority findings: 0"));
    }

    #[tokio::test]
    async fn invalid_finding_is_excluded_from_counters_and_inline_candidates() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "filePaths is out of scope in finally",
            "`filePaths` is out of scope in finally.",
        )])
        .with_file(
            "src/a.ts",
            "let filePaths = []\ntry {\n work()\n} finally {\n cleanup(filePaths)\n}",
        )
        .run()
        .await;

        let counters = count_findings_from_analysis(&analysis);
        assert_eq!(counters.open_priority, 0);

        let candidates = resolve_inline_candidates(
            &analysis,
            &[],
            None,
            &crate::config::InlineConfig {
                enabled: true,
                dry_run: true,
                dedupe: true,
                max_inline_total: 10,
                max_high_inline: 8,
                max_medium_inline: 5,
            },
        );
        assert_eq!(
            candidates[0].reason,
            InlineEligibilityReason::SeverityTooLow
        );
    }

    #[tokio::test]
    async fn partially_valid_model_result_rewrites_title_body_and_fix() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Reliability,
            "Something may fail",
            "This may fail.",
        )])
        .with_file("src/a.ts", "if (ready) run()")
        .with_model(
            r#"{"verdict":"partially_valid","final_severity":"MEDIUM","actionable":true,"corrected_title":"Precise issue","corrected_body":"Precise body","corrected_suggested_fix":"Precise fix","reason":"related issue"}"#,
        )
        .run()
        .await;

        let finding = &analysis.findings[0];
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.title, "Precise issue");
        assert_eq!(finding.body, "Precise body");
        assert_eq!(finding.suggested_fix.as_deref(), Some("Precise fix"));
    }

    #[tokio::test]
    async fn current_file_fetch_failure_downgrades_high() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Reliability,
            "Request may fail",
            "This may fail.",
        )])
        .with_fetch_error("not found")
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert!(analysis.findings[0]
            .evidence_reason
            .as_deref()
            .unwrap()
            .contains("could not be fetched"));
    }

    #[tokio::test]
    async fn raw_current_file_content_does_not_escape_final_finding() {
        let raw_content = "let filePaths = []\nconst rawCurrentFileSentinel = 'do-not-store'\ntry {}\nfinally { cleanup(filePaths) }";
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Correctness,
            "filePaths is out of scope in finally",
            "`filePaths` is out of scope in finally.",
        )])
        .with_file("src/a.ts", raw_content)
        .run()
        .await;

        let serialized = format!("{:?}", analysis.findings);
        assert!(!serialized.contains("rawCurrentFileSentinel"));
        assert!(!serialized.contains("do-not-store"));
    }

    #[tokio::test]
    async fn model_validator_malformed_json_fails_safe() {
        let analysis = validate(vec![finding(
            Severity::High,
            ReviewCategory::Reliability,
            "Request may fail",
            "This may fail.",
        )])
        .with_file("src/a.ts", "if (ready) run()")
        .with_model("not json")
        .run()
        .await;

        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert!(analysis.findings[0]
            .evidence_reason
            .as_deref()
            .unwrap()
            .contains("malformed JSON"));
    }

    struct ValidationFixture {
        analysis: ReviewAnalysis,
        file_content: Result<String, String>,
        model_response: Result<String, String>,
    }

    fn validate(findings: Vec<ReviewFinding>) -> ValidationFixture {
        ValidationFixture {
            analysis: ReviewAnalysis {
                summary: "summary".to_string(),
                findings,
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::High,
            },
            file_content: Ok("".to_string()),
            model_response: Err("model not called".to_string()),
        }
    }

    impl ValidationFixture {
        fn with_file(mut self, _path: &str, content: &str) -> Self {
            self.file_content = Ok(content.to_string());
            self
        }

        fn with_fetch_error(mut self, error: &str) -> Self {
            self.file_content = Err(error.to_string());
            self
        }

        fn with_model(mut self, response: &str) -> Self {
            self.model_response = Ok(response.to_string());
            self
        }

        async fn run(self) -> ReviewAnalysis {
            let content = self.file_content;
            let model = self.model_response;
            validate_review_analysis_current_file(
                self.analysis,
                &AnchoredDiffContext::default(),
                CurrentFileValidationOptions {
                    enabled: true,
                    validate_priority_with_model: true,
                    max_file_bytes: 80_000,
                    context_lines: 40,
                },
                move |_path| {
                    let content = content.clone();
                    async move { content }
                },
                move |_prompt| {
                    let model = model.clone();
                    async move { model }
                },
            )
            .await
        }
    }

    fn finding(
        severity: Severity,
        category: ReviewCategory,
        title: &str,
        body: &str,
    ) -> ReviewFinding {
        ReviewFinding {
            severity,
            category,
            risk_code: None,
            anchor_id: None,
            file_path: Some("src/a.ts".to_string()),
            line: Some(3),
            title: title.to_string(),
            body: body.to_string(),
            suggested_fix: Some("Fix it.".to_string()),
            effort: Effort::Moderate,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }

    fn await_finding() -> ReviewFinding {
        finding(
            Severity::High,
            ReviewCategory::Correctness,
            "Syntax Error: await used in non-async function",
            "The await is inside a non-async callback and will fail.",
        )
    }
}
