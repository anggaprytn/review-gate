use crate::{
    error::{Result, ReviewGateError},
    gitlab::types::{MergeRequestDiff, MergeRequestMetadata},
    llm::types::{LlmReviewResponse, LlmRunMetadata},
    plan::{FileRiskLevel, PlannedFile, ReviewPlan},
    redaction::redact_secrets,
    review::{
        anchors::{AnchorLineKind, AnchoredDiffContext, ReviewLineAnchor},
        engine::{estimate_prompt_tokens, ReviewPreview},
        evidence::validate_review_analysis_evidence,
        formatter::{format_review_markdown_for_mode, MarkdownRenderMode},
        parser::parse_review_analysis,
        quality::normalize_review_analysis,
        types::{OverallRisk, ReviewAnalysis, ReviewFinding, Severity},
    },
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    future::Future,
    time::Instant,
};

pub const DEFAULT_LARGE_REVIEW_ENABLED: bool = true;
pub const DEFAULT_LARGE_REVIEW_MAX_CHUNKS: usize = 6;
pub const DEFAULT_LARGE_REVIEW_MAX_FILES_PER_CHUNK: usize = 8;
pub const DEFAULT_LARGE_REVIEW_MAX_DIFF_BYTES_PER_CHUNK: usize = 60_000;
pub const DEFAULT_LARGE_REVIEW_INCLUDE_LOW: bool = false;
pub const DEFAULT_LARGE_REVIEW_PARALLEL: bool = true;
pub const DEFAULT_LARGE_REVIEW_PARALLELISM: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargeReviewOptions {
    pub enabled: bool,
    pub max_chunks: usize,
    pub max_files_per_chunk: usize,
    pub max_diff_bytes_per_chunk: usize,
    pub include_low_risk: bool,
    pub parallel: bool,
    pub parallelism: usize,
}

#[derive(Debug, Clone)]
pub struct ReviewChunk {
    pub index: usize,
    pub risk_focus: String,
    pub files: Vec<PlannedFile>,
    pub diff_text: String,
    pub diff_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct LargeReviewSelection {
    pub files: Vec<PlannedFile>,
    pub skipped_files: usize,
    pub skipped_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LargeReviewPlan {
    pub selection: LargeReviewSelection,
    pub chunks: Vec<ReviewChunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargeReviewExecutionOptions {
    pub parallel: bool,
    pub parallelism: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeReviewReport {
    pub total_chunks: usize,
    pub reviewed_chunks: usize,
    pub failed_chunks: usize,
    pub reviewed_files: usize,
    pub skipped_files: usize,
    pub skipped_reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct LargeReviewRunContext<'a> {
    pub metadata: &'a MergeRequestMetadata,
    pub selection: &'a LargeReviewSelection,
    pub anchors: &'a AnchoredDiffContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkFailure {
    pub chunk_index: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkReviewStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ChunkReviewResult {
    pub chunk_index: usize,
    pub status: ChunkReviewStatus,
    pub analysis: Option<ReviewAnalysis>,
    pub error: Option<String>,
    pub duration_ms: Option<u128>,
    pub metadata: LlmRunMetadata,
    pub prompt_token_estimate: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkReviewProgress {
    Started {
        chunk_index: usize,
        total_chunks: usize,
    },
    Completed {
        chunk_index: usize,
        total_chunks: usize,
        duration_ms: Option<u128>,
    },
    Failed {
        chunk_index: usize,
        total_chunks: usize,
        duration_ms: Option<u128>,
        error: String,
    },
}

impl Default for LargeReviewOptions {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_LARGE_REVIEW_ENABLED,
            max_chunks: DEFAULT_LARGE_REVIEW_MAX_CHUNKS,
            max_files_per_chunk: DEFAULT_LARGE_REVIEW_MAX_FILES_PER_CHUNK,
            max_diff_bytes_per_chunk: DEFAULT_LARGE_REVIEW_MAX_DIFF_BYTES_PER_CHUNK,
            include_low_risk: DEFAULT_LARGE_REVIEW_INCLUDE_LOW,
            parallel: DEFAULT_LARGE_REVIEW_PARALLEL,
            parallelism: DEFAULT_LARGE_REVIEW_PARALLELISM,
        }
    }
}

impl LargeReviewOptions {
    pub fn from_env() -> Self {
        let (parallel, parallel_warning) = env_bool_with_warning(
            "REVIEWGATE_LARGE_REVIEW_PARALLEL",
            DEFAULT_LARGE_REVIEW_PARALLEL,
        );
        if let Some(warning) = parallel_warning {
            eprintln!("{warning}");
        }
        let (parallelism, parallelism_warning) = env_usize_with_warning(
            "REVIEWGATE_LARGE_REVIEW_PARALLELISM",
            DEFAULT_LARGE_REVIEW_PARALLELISM,
        );
        if let Some(warning) = parallelism_warning {
            eprintln!("{warning}");
        }

        Self {
            enabled: env_bool("REVIEWGATE_LARGE_REVIEW_ENABLED")
                .unwrap_or(DEFAULT_LARGE_REVIEW_ENABLED),
            max_chunks: env_usize("REVIEWGATE_LARGE_REVIEW_MAX_CHUNKS")
                .unwrap_or(DEFAULT_LARGE_REVIEW_MAX_CHUNKS)
                .max(1),
            max_files_per_chunk: env_usize("REVIEWGATE_LARGE_REVIEW_MAX_FILES_PER_CHUNK")
                .unwrap_or(DEFAULT_LARGE_REVIEW_MAX_FILES_PER_CHUNK)
                .max(1),
            max_diff_bytes_per_chunk: env_usize("REVIEWGATE_LARGE_REVIEW_MAX_DIFF_BYTES_PER_CHUNK")
                .unwrap_or(DEFAULT_LARGE_REVIEW_MAX_DIFF_BYTES_PER_CHUNK)
                .max(1),
            include_low_risk: env_bool("REVIEWGATE_LARGE_REVIEW_INCLUDE_LOW")
                .unwrap_or(DEFAULT_LARGE_REVIEW_INCLUDE_LOW),
            parallel,
            parallelism,
        }
    }
}

impl From<LargeReviewOptions> for LargeReviewExecutionOptions {
    fn from(options: LargeReviewOptions) -> Self {
        Self {
            parallel: options.parallel,
            parallelism: options.parallelism,
        }
    }
}

impl LargeReviewExecutionOptions {
    pub fn effective_parallelism(self, chunk_count: usize) -> usize {
        if chunk_count == 0 || !self.parallel {
            return 1;
        }
        self.parallelism.max(1).min(chunk_count)
    }
}

pub fn build_large_review_plan(
    plan: &ReviewPlan,
    diffs: &[MergeRequestDiff],
    anchors: &AnchoredDiffContext,
    options: LargeReviewOptions,
    include_low_risk_flag: bool,
) -> Result<LargeReviewPlan> {
    if !options.enabled {
        return Err(ReviewGateError::LargeReviewDisabled);
    }

    let include_low = include_low_risk_flag || options.include_low_risk;
    let selection = select_large_review_files(plan, options, include_low);
    if selection.files.is_empty() {
        return Err(ReviewGateError::LargeReviewNoReviewableFiles);
    }

    let chunks = chunk_selected_files(&selection.files, diffs, anchors, options)?;
    if chunks.is_empty() {
        return Err(ReviewGateError::LargeReviewNoReviewableFiles);
    }
    if chunks.len() > options.max_chunks {
        return Err(ReviewGateError::LargeReviewTooManyChunks);
    }

    Ok(LargeReviewPlan { selection, chunks })
}

pub fn select_large_review_files(
    plan: &ReviewPlan,
    options: LargeReviewOptions,
    include_low_risk: bool,
) -> LargeReviewSelection {
    let mut selected = Vec::new();
    let mut skipped_reasons = Vec::new();
    let file_budget = options.max_chunks * options.max_files_per_chunk;
    let byte_budget = options.max_chunks * options.max_diff_bytes_per_chunk;
    let mut budgeted_files = 0usize;
    let mut budgeted_bytes = 0usize;

    for file in &plan.files {
        if let Some(reason) = file.skip_reason {
            if reason == crate::plan::SkipReason::ExceedsPlanLimit
                && file.risk == FileRiskLevel::Low
                && !include_low_risk
            {
                push_reason(&mut skipped_reasons, "low-risk");
            } else if reason == crate::plan::SkipReason::ExceedsPlanLimit {
                push_reason(&mut skipped_reasons, "over limit");
            } else {
                push_reason(&mut skipped_reasons, reason.label());
            }
            continue;
        }

        match file.risk {
            FileRiskLevel::Critical | FileRiskLevel::High => {
                selected.push(file.clone());
                budgeted_files += 1;
                budgeted_bytes += file.diff_bytes;
            }
            FileRiskLevel::Medium => {
                if budgeted_files < file_budget && budgeted_bytes + file.diff_bytes <= byte_budget {
                    selected.push(file.clone());
                    budgeted_files += 1;
                    budgeted_bytes += file.diff_bytes;
                } else {
                    push_reason(&mut skipped_reasons, "over limit");
                }
            }
            FileRiskLevel::Low => {
                if include_low_risk
                    && budgeted_files < file_budget
                    && budgeted_bytes + file.diff_bytes <= byte_budget
                {
                    selected.push(file.clone());
                    budgeted_files += 1;
                    budgeted_bytes += file.diff_bytes;
                } else if include_low_risk {
                    push_reason(&mut skipped_reasons, "over limit");
                } else {
                    push_reason(&mut skipped_reasons, "low-risk");
                }
            }
            FileRiskLevel::Skip => {
                push_reason(&mut skipped_reasons, "skipped");
            }
        }
    }

    LargeReviewSelection {
        skipped_files: plan.summary.changed_files.saturating_sub(selected.len()),
        files: selected,
        skipped_reasons,
    }
}

pub fn chunk_selected_files(
    files: &[PlannedFile],
    diffs: &[MergeRequestDiff],
    anchors: &AnchoredDiffContext,
    options: LargeReviewOptions,
) -> Result<Vec<ReviewChunk>> {
    let mut chunks = Vec::new();
    let mut current_files = Vec::new();
    let mut current_bytes = 0usize;

    for file in files {
        let diff_bytes = sanitized_diff_bytes(diffs, file);
        let would_exceed_file_limit = current_files.len() >= options.max_files_per_chunk;
        let would_exceed_byte_limit = !current_files.is_empty()
            && current_bytes + diff_bytes > options.max_diff_bytes_per_chunk;

        if would_exceed_file_limit || would_exceed_byte_limit {
            chunks.push(finish_chunk(
                chunks.len() + 1,
                current_files,
                current_bytes,
                anchors,
            ));
            current_files = Vec::new();
            current_bytes = 0;
        }

        current_bytes += diff_bytes;
        current_files.push(file.clone());
    }

    if !current_files.is_empty() {
        chunks.push(finish_chunk(
            chunks.len() + 1,
            current_files,
            current_bytes,
            anchors,
        ));
    }

    if chunks.len() > options.max_chunks {
        return Err(ReviewGateError::LargeReviewTooManyChunks);
    }

    Ok(chunks)
}

pub fn selected_diffs_in_order(
    diffs: &[MergeRequestDiff],
    selected_files: &[PlannedFile],
) -> Vec<MergeRequestDiff> {
    let mut selected = Vec::new();
    for file in selected_files {
        if let Some(diff) = diffs
            .iter()
            .find(|diff| diff.new_path == file.new_path && diff.old_path == file.old_path)
        {
            selected.push(diff.clone());
        }
    }
    selected
}

pub fn build_large_chunk_prompt(
    metadata: &MergeRequestMetadata,
    chunk: &ReviewChunk,
    total_chunks: usize,
) -> String {
    let file_list = chunk
        .files
        .iter()
        .map(|file| format!("- {} ({})", file.new_path, file.risk.label()))
        .collect::<Vec<_>>()
        .join("\n");
    let anchored_diff = if chunk.diff_text.trim().is_empty() {
        "No reviewable anchored diff lines were available for this chunk.".to_string()
    } else {
        chunk.diff_text.trim_end().to_string()
    };

    format!(
        r#"You are ReviewGate, a risk oriented merge request reviewer for private GitLab teams.

This is chunk {chunk_index} of {total_chunks} from a large MR.
Review only this chunk.
Do not comment on files outside this chunk.
Return JSON only.
Prioritize CRITICAL, HIGH, MEDIUM.
Use anchor_id/risk_code/effort schema.

Merge request:
- IID: !{iid}
- Title: {title}
- Source branch: {source_branch}
- Target branch: {target_branch}
- URL: {web_url}

Chunk focus:
- Risk focus: {risk_focus}
- Files:
{file_list}

Rules:
- Review only the provided anchored sanitized diff.
- Do not guess about code, files, functions, tests, or runtime behavior that are not visible in this chunk.
- Use anchor_id from the provided anchors whenever a finding maps to a visible line.
- Do not invent anchors. If no exact anchor exists, use null for anchor_id.
- Prefer anchors on added lines for newly introduced risks.
- Include file_path and line from the same anchor when anchor_id is present. If a line is not visible, use null.
- Use risk_code from the allowed list. If no specific value fits, use other.
- For every finding, include effort.
- Positive changes must be returned as NOTE only with actionable=false.
- Do not assign CRITICAL, HIGH, or MEDIUM to positive notes.
- Do not create a finding if the suggested fix is "No action needed."
- CRITICAL is reserved for exploitable security flaws, data loss, auth bypass, credential exposure, destructive migration, or build/runtime breakage.
- If a finding is just a good practice or improvement, either omit it or return as NOTE with actionable=false.
- Return fewer findings. Prefer no finding over a weak finding.
- Produce JSON only. Do not wrap the JSON in markdown fences. Do not include prose before or after the JSON.

Return exactly one JSON object matching this schema:
{{
  "summary": "Short chunk-level review summary.",
  "overall_risk": "medium",
  "findings": [
    {{
      "severity": "HIGH",
      "category": "reliability",
      "risk_code": "missing_timeout",
      "anchor_id": "A0002",
      "file_path": "src/payment/client.ts",
      "line": 42,
      "title": "HTTP request has no timeout",
      "body": "The new payment callback call can hang indefinitely under upstream failure.",
      "suggested_fix": "Use a client timeout or request-scoped timeout.",
      "effort": "quick",
      "actionable": true
    }}
  ],
  "test_coverage_note": "No test covers the timeout behavior.",
  "privacy_note": "No obvious secret or PII exposure detected in the sanitized diff."
}}

Allowed severity values: CRITICAL, HIGH, MEDIUM, LOW, NOTE.
Allowed effort values: quick, moderate, heavy.
Use these category values when possible: security, privacy, reliability, correctness, api_contract, data_integrity, deployment_risk, observability, test_coverage.
Allowed risk_code values: auth_bypass, missing_authorization_check, secret_leak, pii_or_secret_logging, sql_injection, command_injection, unsafe_deserialization, missing_timeout, unbounded_retry, unclosed_resource, nil_or_null_risk, api_contract_break, data_integrity_risk, migration_risk, missing_test_coverage, weak_error_handling, observability_gap, performance_regression, maintainability_risk, positive_note, other.

Anchored sanitized diff:
```text
{anchored_diff}
```
"#,
        chunk_index = chunk.index,
        total_chunks = total_chunks,
        iid = metadata.iid,
        title = metadata.title,
        source_branch = metadata.source_branch,
        target_branch = metadata.target_branch,
        web_url = metadata.web_url,
        risk_focus = chunk.risk_focus,
        file_list = file_list,
        anchored_diff = anchored_diff,
    )
}

pub async fn review_large_chunks_with_llm<F, Fut>(
    context: LargeReviewRunContext<'_>,
    chunks: &[ReviewChunk],
    execution: LargeReviewExecutionOptions,
    mode: MarkdownRenderMode,
    show_prompt: bool,
    mut progress: impl FnMut(ChunkReviewProgress),
    call_llm: F,
) -> Result<ReviewPreview>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<LlmReviewResponse>>,
{
    let total_chunks = chunks.len();
    let parallelism = execution.effective_parallelism(total_chunks);
    let mut pending = chunks.iter().cloned();
    let mut running = FuturesUnordered::new();
    let mut results = Vec::new();

    while running.len() < parallelism {
        let Some(chunk) = pending.next() else {
            break;
        };
        progress(ChunkReviewProgress::Started {
            chunk_index: chunk.index,
            total_chunks,
        });
        running.push(review_one_large_chunk(
            context,
            chunk,
            total_chunks,
            show_prompt,
            &call_llm,
        ));
    }

    while let Some(result) = running.next().await {
        match result.status {
            ChunkReviewStatus::Completed => progress(ChunkReviewProgress::Completed {
                chunk_index: result.chunk_index,
                total_chunks,
                duration_ms: result.duration_ms,
            }),
            ChunkReviewStatus::Failed => progress(ChunkReviewProgress::Failed {
                chunk_index: result.chunk_index,
                total_chunks,
                duration_ms: result.duration_ms,
                error: result
                    .error
                    .clone()
                    .unwrap_or_else(|| "unknown error".to_string()),
            }),
        }
        results.push(result);

        if let Some(chunk) = pending.next() {
            progress(ChunkReviewProgress::Started {
                chunk_index: chunk.index,
                total_chunks,
            });
            running.push(review_one_large_chunk(
                context,
                chunk,
                total_chunks,
                show_prompt,
                &call_llm,
            ));
        }
    }

    results.sort_by_key(|result| result.chunk_index);
    let mut analyses = Vec::new();
    let mut failures = Vec::new();
    let mut metadata_total = LlmRunMetadata::default();
    let mut prompt_token_estimate = 0u64;

    for result in results {
        prompt_token_estimate += result.prompt_token_estimate;
        match result.status {
            ChunkReviewStatus::Completed => {
                merge_metadata(&mut metadata_total, &result.metadata);
                if let Some(analysis) = result.analysis {
                    analyses.push(analysis);
                }
            }
            ChunkReviewStatus::Failed => failures.push(ChunkFailure {
                chunk_index: result.chunk_index,
                message: result.error.unwrap_or_else(|| "unknown error".to_string()),
            }),
        }
    }

    if analyses.is_empty() {
        let message = failures
            .iter()
            .map(|failure| format!("chunk {}: {}", failure.chunk_index, failure.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ReviewGateError::LargeReviewAllChunksFailed(message));
    }

    let report = LargeReviewReport {
        total_chunks,
        reviewed_chunks: analyses.len(),
        failed_chunks: failures.len(),
        reviewed_files: context.selection.files.len(),
        skipped_files: context.selection.skipped_files,
        skipped_reasons: context.selection.skipped_reasons.clone(),
    };
    let analysis = validate_review_analysis_evidence(
        normalize_review_analysis(merge_chunk_analyses(analyses, &report)),
        context.anchors,
    );
    let markdown = format_large_review_markdown(&analysis, &report, mode);

    Ok(ReviewPreview {
        markdown,
        metadata: metadata_total,
        prompt_token_estimate,
        parsed: true,
        analysis: Some(analysis),
    })
}

async fn review_one_large_chunk<F, Fut>(
    context: LargeReviewRunContext<'_>,
    chunk: ReviewChunk,
    total_chunks: usize,
    show_prompt: bool,
    call_llm: &F,
) -> ChunkReviewResult
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<LlmReviewResponse>>,
{
    let prompt = build_large_chunk_prompt(context.metadata, &chunk, total_chunks);
    let prompt_token_estimate = estimate_prompt_tokens(&prompt);
    if show_prompt {
        println!("ReviewGate sanitized chunk prompt {}", chunk.index);
        println!("====================================");
        println!("{prompt}");
        println!("====================================");
        println!();
    }

    let started = Instant::now();
    match call_llm(prompt).await {
        Ok(response) => match parse_review_analysis(&response.text) {
            Ok(analysis) => ChunkReviewResult {
                chunk_index: chunk.index,
                status: ChunkReviewStatus::Completed,
                analysis: Some(validate_review_analysis_evidence(
                    normalize_review_analysis(analysis),
                    context.anchors,
                )),
                error: None,
                duration_ms: Some(started.elapsed().as_millis()),
                metadata: response.metadata,
                prompt_token_estimate,
            },
            Err(err) => ChunkReviewResult {
                chunk_index: chunk.index,
                status: ChunkReviewStatus::Failed,
                analysis: None,
                error: Some(err.to_string()),
                duration_ms: Some(started.elapsed().as_millis()),
                metadata: LlmRunMetadata::default(),
                prompt_token_estimate,
            },
        },
        Err(err) => ChunkReviewResult {
            chunk_index: chunk.index,
            status: ChunkReviewStatus::Failed,
            analysis: None,
            error: Some(err.to_string()),
            duration_ms: Some(started.elapsed().as_millis()),
            metadata: LlmRunMetadata::default(),
            prompt_token_estimate,
        },
    }
}

pub fn merge_chunk_analyses(
    analyses: Vec<ReviewAnalysis>,
    report: &LargeReviewReport,
) -> ReviewAnalysis {
    let mut findings = Vec::new();
    let mut summaries = Vec::new();
    let mut test_notes = Vec::new();
    let mut privacy_notes = Vec::new();
    let mut overall_risk = OverallRisk::Note;

    for analysis in analyses {
        overall_risk = stronger_overall_risk(overall_risk, analysis.overall_risk);
        if !analysis.summary.trim().is_empty() {
            summaries.push(analysis.summary);
        }
        if let Some(note) = analysis
            .test_coverage_note
            .filter(|note| !note.trim().is_empty())
        {
            test_notes.push(note);
        }
        if let Some(note) = analysis.privacy_note.filter(|note| !note.trim().is_empty()) {
            privacy_notes.push(note);
        }
        findings.extend(analysis.findings);
    }

    let findings = dedupe_findings(findings);

    let mut summary = compact_large_review_summary(&findings, report);
    if findings.is_empty() && !summaries.is_empty() {
        let compacted = compact_sentences(&summaries.join(" "), 3);
        if !compacted.is_empty() {
            summary.push_str("\n\n");
            summary.push_str(&compacted.join(" "));
        }
    }

    ReviewAnalysis {
        summary,
        findings,
        test_coverage_note: compact_note_bullets(test_notes, 5),
        privacy_note: compact_privacy_notes(privacy_notes),
        overall_risk,
    }
}

pub fn dedupe_findings(findings: Vec<ReviewFinding>) -> Vec<ReviewFinding> {
    let mut deduped: Vec<ReviewFinding> = Vec::new();

    for finding in findings {
        if let Some(existing) = deduped
            .iter_mut()
            .find(|existing| duplicate_conflict_key(existing) == duplicate_conflict_key(&finding))
        {
            if prefer_replacement(existing, &finding) {
                *existing = finding;
            }
        } else {
            deduped.push(finding);
        }
    }

    deduped.sort_by(|left, right| {
        left.severity
            .sort_key()
            .cmp(&right.severity.sort_key())
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.title.cmp(&right.title))
    });
    deduped
}

pub fn format_large_review_markdown(
    analysis: &ReviewAnalysis,
    report: &LargeReviewReport,
    mode: MarkdownRenderMode,
) -> String {
    let markdown = format_review_markdown_for_mode(analysis, mode);
    let mut section = format!(
        "## Large MR Review Plan\n\nPlanned chunks: {}\nReviewed chunks: {}\n",
        report.total_chunks, report.reviewed_chunks
    );
    if report.failed_chunks > 0 {
        section.push_str(&format!("Failed chunks: {}\n", report.failed_chunks));
    }
    section.push_str(&format!(
        "Reviewed files: {}\nSkipped files: {}\nReview mode: risk-prioritized partial review\n\nThis is not a full-file exhaustive review. ReviewGate prioritized high-risk changed files.\n\n",
        report.reviewed_files, report.skipped_files
    ));

    if let Some((title, rest)) = markdown.split_once("\n\n") {
        format!("{title}\n\n{section}{rest}")
    } else {
        format!("{section}{markdown}")
    }
}

pub fn validate_large_inline_mapping(
    analysis: &ReviewAnalysis,
    anchors: &AnchoredDiffContext,
) -> Result<()> {
    for finding in &analysis.findings {
        let Some(anchor_id) = finding.anchor_id.as_deref() else {
            continue;
        };
        if anchor_id.trim().is_empty() {
            continue;
        }
        if anchors.get(anchor_id).is_none() {
            return Err(ReviewGateError::LargeReviewInlineMappingUnavailable);
        }
    }
    Ok(())
}

fn finish_chunk(
    index: usize,
    files: Vec<PlannedFile>,
    diff_bytes: usize,
    anchors: &AnchoredDiffContext,
) -> ReviewChunk {
    let risk_focus = files
        .iter()
        .map(|file| file.risk)
        .min_by_key(|risk| risk.priority())
        .map(|risk| risk.label().to_string())
        .unwrap_or_else(|| "Mixed".to_string());
    let paths = files
        .iter()
        .map(|file| file.new_path.as_str())
        .collect::<HashSet<_>>();
    let diff_text = anchored_prompt_for_files(anchors, &paths);

    ReviewChunk {
        index,
        risk_focus,
        files,
        diff_text,
        diff_bytes,
    }
}

fn anchored_prompt_for_files(anchors: &AnchoredDiffContext, paths: &HashSet<&str>) -> String {
    let mut output = String::new();
    let mut current_file = "";

    for anchor in &anchors.anchors {
        if !paths.contains(anchor.new_path.as_str()) {
            continue;
        }

        if current_file != anchor.new_path {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str("File: ");
            output.push_str(&anchor.new_path);
            if anchor.old_path != anchor.new_path {
                output.push_str(" (renamed from ");
                output.push_str(&anchor.old_path);
                output.push(')');
            }
            output.push_str("\n\n");
            current_file = &anchor.new_path;
        }
        output.push_str(&anchor_prompt_line(anchor));
        output.push('\n');
    }

    output
}

fn anchor_prompt_line(anchor: &ReviewLineAnchor) -> String {
    format!(
        "[{}] new_line={} old_line={} kind={:<7} | {}",
        anchor.anchor_id,
        optional_line(anchor.new_line),
        optional_line(anchor.old_line),
        anchor_kind(anchor.kind),
        anchor.content_preview
    )
}

fn optional_line(line: Option<u32>) -> String {
    line.map(|line| line.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn anchor_kind(kind: AnchorLineKind) -> &'static str {
    match kind {
        AnchorLineKind::Added => "added",
        AnchorLineKind::Removed => "removed",
        AnchorLineKind::Context => "context",
    }
}

fn sanitized_diff_bytes(diffs: &[MergeRequestDiff], file: &PlannedFile) -> usize {
    diffs
        .iter()
        .find(|diff| diff.new_path == file.new_path && diff.old_path == file.old_path)
        .map(|diff| redact_secrets(&diff.to_unified_diff()).len())
        .unwrap_or(file.diff_bytes)
}

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

fn skipped_reason_suffix(reasons: &[String]) -> String {
    if reasons.is_empty() {
        String::new()
    } else {
        format!(": {}", reasons.join(", "))
    }
}

fn duplicate_conflict_key(finding: &ReviewFinding) -> String {
    format!(
        "{}|{:?}|{:?}|{:?}|{}",
        finding.file_path.as_deref().unwrap_or_default(),
        finding.line,
        finding.category,
        finding.risk_code,
        normalize_title(&finding.title)
    )
}

fn normalize_title(title: &str) -> String {
    let mut normalized = String::new();
    let mut last_space = false;
    for ch in title.to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch);
            last_space = false;
        } else if !last_space {
            normalized.push(' ');
            last_space = true;
        }
    }
    normalized.trim().to_string()
}

fn prefer_replacement(existing: &ReviewFinding, candidate: &ReviewFinding) -> bool {
    if candidate.severity.sort_key() != existing.severity.sort_key() {
        return candidate.severity.sort_key() < existing.severity.sort_key();
    }
    let existing_fix = existing
        .suggested_fix
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let candidate_fix = candidate
        .suggested_fix
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if candidate_fix != existing_fix {
        return candidate_fix;
    }
    candidate.anchor_id.is_some() && existing.anchor_id.is_none()
}

fn stronger_overall_risk(left: OverallRisk, right: OverallRisk) -> OverallRisk {
    if overall_sort_key(right) < overall_sort_key(left) {
        right
    } else {
        left
    }
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

fn compact_large_review_summary(findings: &[ReviewFinding], report: &LargeReviewReport) -> String {
    let mut summary = format!(
        "ReviewGate reviewed {} risk-prioritized files across {} chunks.",
        report.reviewed_files, report.reviewed_chunks
    );
    if report.skipped_files > 0 {
        summary.push_str(&format!(
            " Skipped {} files{}.",
            report.skipped_files,
            skipped_reason_suffix(&report.skipped_reasons)
        ));
    }

    let bullets = top_finding_theme_bullets(findings, 5);
    if bullets.is_empty() {
        summary.push_str("\n\nNo critical, high, or medium actionable findings were detected in reviewed chunks.");
    } else {
        summary.push_str("\n\nMain risks found:\n");
        for bullet in bullets {
            summary.push_str("- ");
            summary.push_str(&bullet);
            summary.push('\n');
        }
        summary = summary.trim_end().to_string();
    }

    summary
        .push_str("\n\nThis is a partial risk-prioritized review, not a full exhaustive review.");
    summary
}

fn top_finding_theme_bullets(findings: &[ReviewFinding], limit: usize) -> Vec<String> {
    let mut groups: BTreeMap<String, Vec<&ReviewFinding>> = BTreeMap::new();
    for finding in findings.iter().filter(|finding| {
        finding.actionable
            && matches!(
                finding.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
    }) {
        let key = finding
            .risk_code
            .map(|risk_code| risk_code.display_lower().to_string())
            .unwrap_or_else(|| finding.category.display_lower().to_string());
        groups.entry(key).or_default().push(finding);
    }

    let mut grouped = groups.into_values().collect::<Vec<_>>();
    grouped.sort_by(|left, right| {
        let left_best = left
            .iter()
            .map(|finding| finding.severity.sort_key())
            .min()
            .unwrap_or(u8::MAX);
        let right_best = right
            .iter()
            .map(|finding| finding.severity.sort_key())
            .min()
            .unwrap_or(u8::MAX);
        left_best
            .cmp(&right_best)
            .then_with(|| right.len().cmp(&left.len()))
            .then_with(|| left[0].title.cmp(&right[0].title))
    });

    grouped
        .into_iter()
        .take(limit)
        .filter_map(|group| {
            group
                .into_iter()
                .min_by_key(|finding| finding.severity.sort_key())
        })
        .map(|finding| sentence_from_title(&finding.title))
        .collect()
}

fn sentence_from_title(title: &str) -> String {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return "Untitled risk requires review.".to_string();
    }
    let mut sentence = trimmed
        .trim_start_matches(|value: char| value == '-' || value.is_whitespace())
        .trim()
        .to_string();
    if !matches!(sentence.chars().last(), Some('.') | Some('!') | Some('?')) {
        sentence.push('.');
    }
    sentence
}

fn compact_note_bullets(notes: Vec<String>, limit: usize) -> Option<String> {
    let sentences = compact_sentences(&notes.join(" "), limit);
    if sentences.is_empty() {
        None
    } else {
        Some(
            sentences
                .into_iter()
                .map(|sentence| format!("- {sentence}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

fn compact_privacy_notes(notes: Vec<String>) -> Option<String> {
    if notes.is_empty() {
        return None;
    }
    let sentences = compact_sentences(&notes.join(" "), 3);
    if sentences.is_empty() {
        return None;
    }
    let no_secret_count = sentences
        .iter()
        .filter(|sentence| is_no_secret_or_pii_sentence(sentence))
        .count();
    if no_secret_count > 1 || no_secret_count == sentences.len() {
        return Some("No obvious new PII or secret exposure detected.".to_string());
    }
    Some(sentences.join(" "))
}

fn compact_sentences(text: &str, limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut sentences = Vec::new();
    for sentence in split_sentences(text) {
        let cleaned = strip_chunk_review_prefix(&sentence_from_title(&sentence));
        let key = normalize_sentence_key(&cleaned);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        sentences.push(cleaned);
        if sentences.len() >= limit {
            break;
        }
    }
    sentences
}

fn split_sentences(text: &str) -> Vec<String> {
    text.split(['\n', '.', '!', '?'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn strip_chunk_review_prefix(sentence: &str) -> String {
    let lower = sentence.to_ascii_lowercase();
    for prefix in [
        "chunk review found ",
        "chunk review finds ",
        "chunk review identified ",
        "chunk review introduces ",
        "chunk found ",
        "chunk finds ",
        "chunk introduces ",
    ] {
        if lower.starts_with(prefix) {
            let stripped = sentence[prefix.len()..].trim();
            return sentence_from_title(stripped);
        }
    }
    sentence.to_string()
}

fn normalize_sentence_key(sentence: &str) -> String {
    sentence
        .trim_matches(|value: char| !value.is_alphanumeric())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn is_no_secret_or_pii_sentence(sentence: &str) -> bool {
    let lower = sentence.to_ascii_lowercase();
    lower.contains("no obvious")
        && (lower.contains("secret") || lower.contains("pii"))
        && (lower.contains("exposure") || lower.contains("detected"))
}

fn merge_metadata(total: &mut LlmRunMetadata, next: &LlmRunMetadata) {
    total.prompt_eval_count = sum_option(total.prompt_eval_count, next.prompt_eval_count);
    total.eval_count = sum_option(total.eval_count, next.eval_count);
    total.total_duration = sum_option(total.total_duration, next.total_duration);
    total.load_duration = sum_option(total.load_duration, next.load_duration);
}

fn sum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left + right),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok().and_then(|value| value.parse().ok())
}

fn env_usize_with_warning(name: &str, default: usize) -> (usize, Option<String>) {
    parse_env_usize_value_with_warning(name, env::var(name).ok(), default)
}

fn parse_env_usize_value_with_warning(
    name: &str,
    value: Option<String>,
    default: usize,
) -> (usize, Option<String>) {
    let Some(value) = value else {
        return (default, None);
    };
    match value.trim().parse::<usize>() {
        Ok(value) if value >= 1 => (value, None),
        _ => (
            default,
            Some(format!(
                "Warning: invalid {name}={value:?}; using default {default}"
            )),
        ),
    }
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn env_bool_with_warning(name: &str, default: bool) -> (bool, Option<String>) {
    parse_env_bool_value_with_warning(name, env::var(name).ok(), default)
}

fn parse_env_bool_value_with_warning(
    name: &str,
    value: Option<String>,
    default: bool,
) -> (bool, Option<String>) {
    let Some(value) = value else {
        return (default, None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => (true, None),
        "0" | "false" | "no" | "off" => (false, None),
        _ => (
            default,
            Some(format!(
                "Warning: invalid {name}={value:?}; using default {default}"
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gitlab::types::MergeRequestMetadata,
        plan::{PlanMergeRequest, PlanSummary, ReviewPlan, SkipReason},
        review::{
            anchors::AnchorBuilder,
            types::{Effort, ReviewCategory, RiskCode, Severity},
        },
    };

    #[test]
    fn selected_files_exclude_skipped() {
        let plan = plan_with_files(vec![
            planned("src/auth.rs", FileRiskLevel::Critical, 20, None),
            planned(
                "Cargo.lock",
                FileRiskLevel::Skip,
                20,
                Some(SkipReason::Lockfile),
            ),
        ]);

        let selection = select_large_review_files(&plan, options(), false);

        assert_eq!(selection.files.len(), 1);
        assert_eq!(selection.files[0].new_path, "src/auth.rs");
        assert_eq!(selection.skipped_files, 1);
    }

    #[test]
    fn critical_and_high_retained_even_over_medium_budget() {
        let opts = LargeReviewOptions {
            max_chunks: 1,
            max_files_per_chunk: 1,
            ..options()
        };
        let plan = plan_with_files(vec![
            planned("src/auth.rs", FileRiskLevel::Critical, 20, None),
            planned("src/api.rs", FileRiskLevel::High, 20, None),
            planned("src/normal.rs", FileRiskLevel::Medium, 20, None),
        ]);

        let selection = select_large_review_files(&plan, opts, false);

        assert_eq!(
            selection
                .files
                .iter()
                .map(|file| file.new_path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/auth.rs", "src/api.rs"]
        );
    }

    #[test]
    fn chunk_respects_max_files() {
        let opts = LargeReviewOptions {
            max_files_per_chunk: 2,
            ..options()
        };
        let files = vec![
            planned("src/a.rs", FileRiskLevel::Medium, 20, None),
            planned("src/b.rs", FileRiskLevel::Medium, 20, None),
            planned("src/c.rs", FileRiskLevel::Medium, 20, None),
        ];
        let diffs = diffs_for(&files);
        let anchors = anchors_for(&diffs);

        let chunks = chunk_selected_files(&files, &diffs, &anchors, opts).unwrap();

        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|chunk| chunk.files.len() <= 2));
    }

    #[test]
    fn chunk_respects_max_diff_bytes() {
        let opts = LargeReviewOptions {
            max_diff_bytes_per_chunk: 90,
            ..options()
        };
        let files = vec![
            planned("src/a.rs", FileRiskLevel::Medium, 40, None),
            planned("src/b.rs", FileRiskLevel::Medium, 40, None),
            planned("src/c.rs", FileRiskLevel::Medium, 40, None),
        ];
        let diffs = diffs_for(&files);
        let anchors = anchors_for(&diffs);

        let chunks = chunk_selected_files(&files, &diffs, &anchors, opts).unwrap();

        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| chunk.diff_bytes <= 90));
    }

    #[test]
    fn low_files_excluded_by_default() {
        let plan = plan_with_files(vec![planned("README.md", FileRiskLevel::Low, 20, None)]);

        let selection = select_large_review_files(&plan, options(), false);

        assert!(selection.files.is_empty());
        assert!(selection.skipped_reasons.contains(&"low-risk".to_string()));
    }

    #[test]
    fn low_files_included_when_requested() {
        let plan = plan_with_files(vec![planned("README.md", FileRiskLevel::Low, 20, None)]);

        let selection = select_large_review_files(&plan, options(), true);

        assert_eq!(selection.files.len(), 1);
    }

    #[test]
    fn chunk_prompt_includes_chunk_index() {
        let chunk = chunk(2, vec![planned("src/a.rs", FileRiskLevel::High, 20, None)]);

        let prompt = build_large_chunk_prompt(&metadata(), &chunk, 5);

        assert!(prompt.contains("This is chunk 2 of 5 from a large MR."));
    }

    #[test]
    fn chunk_prompt_forbids_outside_file_comments() {
        let chunk = chunk(1, vec![planned("src/a.rs", FileRiskLevel::High, 20, None)]);

        let prompt = build_large_chunk_prompt(&metadata(), &chunk, 5);

        assert!(prompt.contains("Review only this chunk."));
        assert!(prompt.contains("Do not comment on files outside this chunk."));
        assert!(prompt.contains("Positive changes must be returned as NOTE only"));
        assert!(prompt.contains("Prefer no finding over a weak finding."));
    }

    #[test]
    fn merge_findings_from_multiple_chunks() {
        let merged = merge_chunk_analyses(
            vec![
                analysis(vec![finding("A", Severity::High, None)]),
                analysis(vec![finding("B", Severity::Medium, None)]),
            ],
            &report(2, 2),
        );

        assert_eq!(merged.findings.len(), 2);
    }

    #[test]
    fn large_summary_compacts_chunk_summary_noise_into_finding_themes() {
        let merged = merge_chunk_analyses(
            vec![
                analysis(vec![finding(
                    "Security guard failure paths may leave sessions active",
                    Severity::High,
                    None,
                )]),
                analysis(vec![finding(
                    "Upload cleanup paths can leak temp files",
                    Severity::Medium,
                    None,
                )]),
            ],
            &report(9, 0),
        );

        assert!(merged
            .summary
            .contains("ReviewGate reviewed 2 risk-prioritized files across 9 chunks."));
        assert!(merged.summary.contains("Main risks found:\n- "));
        assert!(!merged.summary.contains("Chunk review"));
        assert!(!merged.summary.contains("Chunk summaries:"));
        assert!(
            merged
                .summary
                .lines()
                .filter(|line| line.starts_with("- "))
                .count()
                <= 5
        );
    }

    #[test]
    fn test_coverage_notes_are_deduped_and_limited() {
        let mut first = analysis(vec![]);
        first.test_coverage_note = Some(
            "No visible tests cover upload cleanup. No visible tests cover upload cleanup."
                .to_string(),
        );
        let mut second = analysis(vec![]);
        second.test_coverage_note = Some(
            "No visible tests cover authVersion refresh. No visible tests cover token migration."
                .to_string(),
        );

        let merged = merge_chunk_analyses(vec![first, second], &report(2, 0));
        let note = merged.test_coverage_note.unwrap();

        assert_eq!(
            note.matches("No visible tests cover upload cleanup.")
                .count(),
            1
        );
        assert!(note.lines().all(|line| line.starts_with("- ")));
        assert!(note.lines().count() <= 5);
    }

    #[test]
    fn privacy_notes_collapse_repeated_no_secret_detection() {
        let mut first = analysis(vec![]);
        first.privacy_note =
            Some("No obvious secret or PII exposure detected in the sanitized diff.".to_string());
        let mut second = analysis(vec![]);
        second.privacy_note =
            Some("No obvious secret or PII exposure detected in the sanitized diff.".to_string());

        let merged = merge_chunk_analyses(vec![first, second], &report(2, 0));

        assert_eq!(
            merged.privacy_note.as_deref(),
            Some("No obvious new PII or secret exposure detected.")
        );
    }

    #[test]
    fn dedupe_duplicate_findings() {
        let merged = dedupe_findings(vec![
            finding("Same title", Severity::High, None),
            finding("same title", Severity::High, None),
        ]);

        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn stronger_severity_wins_duplicate_conflict() {
        let merged = dedupe_findings(vec![
            finding("Same title", Severity::Medium, None),
            finding("Same title", Severity::High, None),
        ]);

        assert_eq!(merged[0].severity, Severity::High);
    }

    #[test]
    fn anchor_id_preserved_in_merge() {
        let mut without_anchor = finding("Same title", Severity::High, None);
        without_anchor.anchor_id = None;
        let mut with_anchor = finding("Same title", Severity::High, None);
        with_anchor.anchor_id = Some("A0001".to_string());

        let merged = dedupe_findings(vec![without_anchor, with_anchor]);

        assert_eq!(merged[0].anchor_id.as_deref(), Some("A0001"));
    }

    #[test]
    fn chunk_failure_partial_success_summary_is_not_noisy() {
        let merged = merge_chunk_analyses(vec![analysis(vec![])], &report(4, 3));

        assert!(!merged.summary.contains("review chunks failed"));
        assert!(merged
            .summary
            .contains("This is a partial risk-prioritized review, not a full exhaustive review."));
    }

    #[test]
    fn parallelism_is_capped_to_chunk_count() {
        let execution = LargeReviewExecutionOptions {
            parallel: true,
            parallelism: 9,
        };

        assert_eq!(execution.effective_parallelism(3), 3);
    }

    #[test]
    fn parallelism_one_behaves_as_serial() {
        let execution = LargeReviewExecutionOptions {
            parallel: true,
            parallelism: 1,
        };

        assert_eq!(execution.effective_parallelism(3), 1);
    }

    #[test]
    fn disabled_parallelism_behaves_as_serial() {
        let execution = LargeReviewExecutionOptions {
            parallel: false,
            parallelism: 6,
        };

        assert_eq!(execution.effective_parallelism(3), 1);
    }

    #[test]
    fn env_parallelism_parser_accepts_valid_value() {
        let (value, warning) = parse_env_usize_value_with_warning(
            "REVIEWGATE_LARGE_REVIEW_PARALLELISM",
            Some("6".to_string()),
            3,
        );
        assert_eq!(value, 6);
        assert!(warning.is_none());
    }

    #[test]
    fn env_parallelism_parser_warns_on_invalid_value() {
        let (value, warning) = parse_env_usize_value_with_warning(
            "REVIEWGATE_LARGE_REVIEW_PARALLELISM",
            Some("0".to_string()),
            3,
        );

        assert_eq!(value, 3);
        assert!(warning.unwrap().contains("using default 3"));
    }

    #[test]
    fn env_parallel_parser_accepts_boolean_value() {
        let (value, warning) = parse_env_bool_value_with_warning(
            "REVIEWGATE_LARGE_REVIEW_PARALLEL",
            Some("false".to_string()),
            true,
        );

        assert!(!value);
        assert!(warning.is_none());
    }

    #[tokio::test]
    async fn all_chunk_failures_error() {
        let selection = LargeReviewSelection {
            files: vec![planned("src/a.rs", FileRiskLevel::High, 20, None)],
            skipped_files: 0,
            skipped_reasons: Vec::new(),
        };
        let chunks = vec![chunk(
            1,
            vec![planned("src/a.rs", FileRiskLevel::High, 20, None)],
        )];
        let anchors = AnchoredDiffContext::default();
        let metadata = metadata();

        let err = review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: false,
                parallelism: 1,
            },
            MarkdownRenderMode::Preview,
            false,
            |_| {},
            |_| async {
                Ok(LlmReviewResponse {
                    text: "not json".to_string(),
                    metadata: LlmRunMetadata::default(),
                })
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            ReviewGateError::LargeReviewAllChunksFailed(_)
        ));
    }

    #[tokio::test]
    async fn one_failed_chunk_does_not_fail_whole_review() {
        let (selection, chunks, anchors, metadata) = run_fixture(3);

        let preview = review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: true,
                parallelism: 3,
            },
            MarkdownRenderMode::Preview,
            false,
            |_| {},
            |prompt| async move {
                if prompt.contains("This is chunk 2 of 3") {
                    return Ok(LlmReviewResponse {
                        text: "not json".to_string(),
                        metadata: LlmRunMetadata::default(),
                    });
                }
                Ok(LlmReviewResponse {
                    text: chunk_json("Chunk passed", None),
                    metadata: LlmRunMetadata::default(),
                })
            },
        )
        .await
        .unwrap();

        assert!(preview.markdown.contains("Reviewed chunks: 2"));
        assert!(preview.markdown.contains("Failed chunks: 1"));
    }

    #[tokio::test]
    async fn chunk_results_merge_in_chunk_index_order() {
        let (selection, chunks, anchors, metadata) = run_fixture(2);

        let preview = review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: true,
                parallelism: 2,
            },
            MarkdownRenderMode::Preview,
            false,
            |_| {},
            |prompt| async move {
                if prompt.contains("This is chunk 1 of 2") {
                    for _ in 0..10 {
                        tokio::task::yield_now().await;
                    }
                    return Ok(LlmReviewResponse {
                        text: chunk_json("Chunk one", Some("First chunk note.")),
                        metadata: LlmRunMetadata::default(),
                    });
                }
                Ok(LlmReviewResponse {
                    text: chunk_json("Chunk two", Some("Second chunk note.")),
                    metadata: LlmRunMetadata::default(),
                })
            },
        )
        .await
        .unwrap();

        let note = preview.analysis.unwrap().test_coverage_note.unwrap();
        assert!(note.find("First chunk note.").unwrap() < note.find("Second chunk note.").unwrap());
    }

    #[tokio::test]
    async fn max_parallelism_is_respected_by_mock_reviewer() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let (selection, chunks, anchors, metadata) = run_fixture(5);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));

        let preview = review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: true,
                parallelism: 2,
            },
            MarkdownRenderMode::Preview,
            false,
            |_| {},
            {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                move |_| {
                    let active = Arc::clone(&active);
                    let max_active = Arc::clone(&max_active);
                    async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(now, Ordering::SeqCst);
                        for _ in 0..5 {
                            tokio::task::yield_now().await;
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(LlmReviewResponse {
                            text: chunk_json("Chunk passed", None),
                            metadata: LlmRunMetadata::default(),
                        })
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(preview.parsed);
        assert_eq!(max_active.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn progress_events_are_serial_when_parallelism_is_one() {
        let (selection, chunks, anchors, metadata) = run_fixture(2);
        let mut events = Vec::new();

        review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: true,
                parallelism: 1,
            },
            MarkdownRenderMode::Preview,
            false,
            |progress| events.push(progress),
            |_| async {
                Ok(LlmReviewResponse {
                    text: chunk_json("Chunk passed", None),
                    metadata: LlmRunMetadata::default(),
                })
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            events.as_slice(),
            [
                ChunkReviewProgress::Started { chunk_index: 1, .. },
                ChunkReviewProgress::Completed { chunk_index: 1, .. },
                ChunkReviewProgress::Started { chunk_index: 2, .. },
                ChunkReviewProgress::Completed { chunk_index: 2, .. },
            ]
        ));
    }

    #[tokio::test]
    async fn large_review_merged_findings_are_validated_after_merge() {
        let selection = LargeReviewSelection {
            files: vec![planned("src/a.rs", FileRiskLevel::High, 20, None)],
            skipped_files: 0,
            skipped_reasons: Vec::new(),
        };
        let chunks = vec![chunk(
            1,
            vec![planned("src/a.rs", FileRiskLevel::High, 20, None)],
        )];
        let mut builder = AnchorBuilder::new();
        builder.add_diff(&diff("src/a.rs"));
        let anchors = builder.finish(false);
        let metadata = metadata();

        let preview = review_large_chunks_with_llm(
            LargeReviewRunContext {
                metadata: &metadata,
                selection: &selection,
                anchors: &anchors,
            },
            &chunks,
            LargeReviewExecutionOptions {
                parallel: false,
                parallelism: 1,
            },
            MarkdownRenderMode::Preview,
            false,
            |_| {},
            |_| async {
                Ok(LlmReviewResponse {
                    text: r#"{
                        "summary": "Route risk.",
                        "overall_risk": "high",
                        "findings": [{
                            "severity": "HIGH",
                            "category": "security",
                            "risk_code": "auth_bypass",
                            "anchor_id": "A0001",
                            "file_path": "src/a.rs",
                            "line": 1,
                            "title": "Route lacks authorization",
                            "body": "The changed route returns data without authorization.",
                            "suggested_fix": "Add an authorization guard.",
                            "effort": "quick",
                            "actionable": true
                        }],
                        "test_coverage_note": null,
                        "privacy_note": null
                    }"#
                    .to_string(),
                    metadata: LlmRunMetadata::default(),
                })
            },
        )
        .await
        .unwrap();

        let analysis = preview.analysis.unwrap();
        assert_eq!(analysis.findings[0].severity, Severity::Medium);
        assert!(preview.markdown.contains("## 🟡 Medium"));
    }

    #[test]
    fn large_summary_section_rendered() {
        let markdown = format_large_review_markdown(
            &analysis(vec![]),
            &report(3, 0),
            MarkdownRenderMode::Publish,
        );

        assert!(markdown.contains("## Large MR Review Plan"));
        assert!(markdown.contains("## Finding Summary"));
        assert!(markdown.contains("Planned chunks: 3"));
        assert!(markdown.contains("Reviewed chunks: 3"));
        assert!(!markdown.contains("Failed chunks:"));
        assert!(markdown.contains("Review mode: risk-prioritized partial review"));
    }

    #[test]
    fn large_summary_section_renders_failed_chunks_without_duplicate_warning() {
        let markdown = format_large_review_markdown(
            &analysis(vec![]),
            &report(9, 1),
            MarkdownRenderMode::Publish,
        );

        assert!(markdown.contains("Planned chunks: 9"));
        assert!(markdown.contains("Reviewed chunks: 8"));
        assert!(markdown.contains("Failed chunks: 1"));
        assert_eq!(markdown.matches("review chunks failed").count(), 0);
    }

    #[test]
    fn large_review_publish_markdown_collapses_note_findings_by_default() {
        let findings = (0..8)
            .map(|index| finding(&format!("note {index}"), Severity::Note, None))
            .collect::<Vec<_>>();
        let markdown = format_large_review_markdown(
            &analysis(findings),
            &report(3, 0),
            MarkdownRenderMode::Publish,
        );

        let note_headings = markdown
            .lines()
            .filter(|line| line.starts_with("### ") && line.contains("NOTE"))
            .count();
        assert_eq!(note_headings, 0);
        assert!(markdown.contains("0 low-priority findings and 8 notes were summarized only."));
    }

    fn options() -> LargeReviewOptions {
        LargeReviewOptions {
            max_chunks: 6,
            max_files_per_chunk: 8,
            max_diff_bytes_per_chunk: 60_000,
            ..LargeReviewOptions::default()
        }
    }

    fn run_fixture(
        chunk_count: usize,
    ) -> (
        LargeReviewSelection,
        Vec<ReviewChunk>,
        AnchoredDiffContext,
        MergeRequestMetadata,
    ) {
        let files = (1..=chunk_count)
            .map(|index| planned(&format!("src/{index}.rs"), FileRiskLevel::High, 20, None))
            .collect::<Vec<_>>();
        let selection = LargeReviewSelection {
            files: files.clone(),
            skipped_files: 0,
            skipped_reasons: Vec::new(),
        };
        let chunks = files
            .into_iter()
            .enumerate()
            .map(|(offset, file)| chunk(offset + 1, vec![file]))
            .collect();
        (
            selection,
            chunks,
            AnchoredDiffContext::default(),
            metadata(),
        )
    }

    fn chunk_json(summary: &str, test_note: Option<&str>) -> String {
        format!(
            r#"{{
                "summary": "{summary}",
                "overall_risk": "low",
                "findings": [],
                "test_coverage_note": {test_note},
                "privacy_note": null
            }}"#,
            test_note = test_note
                .map(|note| format!(r#""{note}""#))
                .unwrap_or_else(|| "null".to_string())
        )
    }

    fn planned(
        path: &str,
        risk: FileRiskLevel,
        diff_bytes: usize,
        skip_reason: Option<SkipReason>,
    ) -> PlannedFile {
        PlannedFile {
            old_path: path.to_string(),
            new_path: path.to_string(),
            risk,
            reasons: vec!["test".to_string()],
            added_lines: 1,
            removed_lines: 0,
            diff_bytes,
            skip_reason,
        }
    }

    fn plan_with_files(files: Vec<PlannedFile>) -> ReviewPlan {
        ReviewPlan {
            mr: PlanMergeRequest {
                project_path: "group/repo".to_string(),
                mr_iid: 1,
                title: "MR".to_string(),
                head_sha: "abc".to_string(),
            },
            summary: PlanSummary {
                changed_files: files.len(),
                reviewable_files: files
                    .iter()
                    .filter(|file| file.skip_reason.is_none())
                    .count(),
                skipped_files: files
                    .iter()
                    .filter(|file| file.skip_reason.is_some())
                    .count(),
                total_diff_bytes: files.iter().map(|file| file.diff_bytes).sum(),
                large_mr: true,
            },
            files,
            warnings: Vec::new(),
        }
    }

    fn diff(path: &str) -> MergeRequestDiff {
        MergeRequestDiff {
            old_path: path.to_string(),
            new_path: path.to_string(),
            diff: "@@ -1 +1 @@\n-old\n+new".to_string(),
            new_file: false,
            renamed_file: false,
            deleted_file: false,
            generated_file: None,
            collapsed: None,
            too_large: None,
        }
    }

    fn diffs_for(files: &[PlannedFile]) -> Vec<MergeRequestDiff> {
        files.iter().map(|file| diff(&file.new_path)).collect()
    }

    fn anchors_for(diffs: &[MergeRequestDiff]) -> AnchoredDiffContext {
        let mut builder = AnchorBuilder::new();
        for diff in diffs {
            builder.add_diff(diff);
        }
        builder.finish(false)
    }

    fn chunk(index: usize, files: Vec<PlannedFile>) -> ReviewChunk {
        ReviewChunk {
            index,
            risk_focus: "High".to_string(),
            files,
            diff_text: "File: src/a.rs\n\n[A0001] new_line=1 old_line=- kind=added   | new\n"
                .to_string(),
            diff_bytes: 20,
        }
    }

    fn metadata() -> MergeRequestMetadata {
        MergeRequestMetadata {
            id: 123,
            iid: 59,
            project_id: 456,
            title: "Fix payment callback timeout".to_string(),
            description: None,
            state: "opened".to_string(),
            draft: Some(false),
            source_branch: "feature/payment-timeout".to_string(),
            target_branch: "main".to_string(),
            sha: "abc123".to_string(),
            web_url: "https://gitlab.company.local/group/repo/-/merge_requests/59".to_string(),
            author: None,
            detailed_merge_status: Some("mergeable".to_string()),
            changes_count: Some("4".to_string()),
            diff_refs: None,
        }
    }

    fn analysis(findings: Vec<ReviewFinding>) -> ReviewAnalysis {
        ReviewAnalysis {
            summary: "chunk summary".to_string(),
            findings,
            test_coverage_note: None,
            privacy_note: None,
            overall_risk: OverallRisk::Medium,
        }
    }

    fn finding(title: &str, severity: Severity, suggested_fix: Option<&str>) -> ReviewFinding {
        ReviewFinding {
            severity,
            category: ReviewCategory::Reliability,
            risk_code: Some(RiskCode::MissingTimeout),
            anchor_id: Some("A0001".to_string()),
            file_path: Some("src/a.rs".to_string()),
            line: Some(1),
            title: title.to_string(),
            body: "body".to_string(),
            suggested_fix: suggested_fix.map(str::to_string),
            effort: Effort::Quick,
            actionable: true,
            evidence_status: None,
            evidence_reason: None,
        }
    }

    fn report(total_chunks: usize, failed_chunks: usize) -> LargeReviewReport {
        LargeReviewReport {
            total_chunks,
            reviewed_chunks: total_chunks - failed_chunks,
            failed_chunks,
            reviewed_files: 2,
            skipped_files: 3,
            skipped_reasons: vec!["low-risk".to_string(), "over limit".to_string()],
        }
    }
}
