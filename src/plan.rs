use crate::gitlab::{
    types::{MergeRequestDiff, MergeRequestMetadata},
    url::GitLabMrUrl,
};
use serde::Serialize;
use std::{cmp::Ordering, env};

pub const DEFAULT_LARGE_MR_FILE_THRESHOLD: usize = 30;
pub const DEFAULT_LARGE_MR_DIFF_BYTES: usize = 200_000;
pub const DEFAULT_PLAN_MAX_FILES: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileRiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Skip,
}

impl FileRiskLevel {
    fn priority(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
            Self::Skip => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Skip => "Skipped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Generated,
    TooLarge,
    Collapsed,
    Lockfile,
    Snapshot,
    Minified,
    Vendored,
    Binary,
    DocumentationOnly,
    ExceedsPlanLimit,
}

impl SkipReason {
    fn label(self) -> &'static str {
        match self {
            Self::Generated => "generated file",
            Self::TooLarge => "too large",
            Self::Collapsed => "collapsed by GitLab",
            Self::Lockfile => "lockfile",
            Self::Snapshot => "snapshot",
            Self::Minified => "minified file",
            Self::Vendored => "vendored file",
            Self::Binary => "binary file",
            Self::DocumentationOnly => "documentation only",
            Self::ExceedsPlanLimit => "exceeds plan limit",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewPlan {
    pub mr: PlanMergeRequest,
    pub summary: PlanSummary,
    pub files: Vec<PlannedFile>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanMergeRequest {
    pub project_path: String,
    pub mr_iid: u64,
    pub title: String,
    pub head_sha: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanSummary {
    pub changed_files: usize,
    pub reviewable_files: usize,
    pub skipped_files: usize,
    pub total_diff_bytes: usize,
    pub large_mr: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedFile {
    pub old_path: String,
    #[serde(rename = "path")]
    pub new_path: String,
    pub risk: FileRiskLevel,
    pub reasons: Vec<String>,
    pub added_lines: u32,
    pub removed_lines: u32,
    pub diff_bytes: usize,
    pub skip_reason: Option<SkipReason>,
}

#[derive(Debug, Clone, Copy)]
pub struct PlanOptions {
    pub max_files: usize,
    pub max_diff_bytes: usize,
    pub include_low_risk: bool,
    pub large_mr_file_threshold: usize,
    pub large_mr_diff_bytes: usize,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_PLAN_MAX_FILES,
            max_diff_bytes: DEFAULT_LARGE_MR_DIFF_BYTES,
            include_low_risk: false,
            large_mr_file_threshold: DEFAULT_LARGE_MR_FILE_THRESHOLD,
            large_mr_diff_bytes: DEFAULT_LARGE_MR_DIFF_BYTES,
        }
    }
}

impl PlanOptions {
    pub fn from_env() -> Self {
        Self {
            max_files: env_usize("REVIEWGATE_PLAN_MAX_FILES").unwrap_or(DEFAULT_PLAN_MAX_FILES),
            max_diff_bytes: env_usize("REVIEWGATE_LARGE_MR_DIFF_BYTES")
                .unwrap_or(DEFAULT_LARGE_MR_DIFF_BYTES),
            include_low_risk: false,
            large_mr_file_threshold: env_usize("REVIEWGATE_LARGE_MR_FILE_THRESHOLD")
                .unwrap_or(DEFAULT_LARGE_MR_FILE_THRESHOLD),
            large_mr_diff_bytes: env_usize("REVIEWGATE_LARGE_MR_DIFF_BYTES")
                .unwrap_or(DEFAULT_LARGE_MR_DIFF_BYTES),
        }
    }
}

pub fn build_review_plan(
    mr_url: &GitLabMrUrl,
    metadata: MergeRequestMetadata,
    diffs: Vec<MergeRequestDiff>,
    options: PlanOptions,
) -> ReviewPlan {
    let total_diff_bytes = diffs.iter().map(diff_size).sum();
    let large_by_files = diffs.len() > options.large_mr_file_threshold;
    let large_by_bytes = total_diff_bytes > options.large_mr_diff_bytes;
    let large_mr = large_by_files || large_by_bytes;
    let mut files: Vec<PlannedFile> = diffs.into_iter().map(classify_file).collect();

    files.sort_by(compare_planned_files);
    apply_plan_limits(&mut files, options);

    let reviewable_files = files
        .iter()
        .filter(|file| file.skip_reason.is_none())
        .count();
    let skipped_files = files.len().saturating_sub(reviewable_files);
    let mut warnings = Vec::new();
    if large_mr {
        warnings.push(
            "This is a large MR. ReviewGate should review high-risk files first. A full single-pass review may be incomplete."
                .to_string(),
        );
    }
    if large_by_files {
        warnings.push(format!(
            "Changed file count {} exceeds REVIEWGATE_LARGE_MR_FILE_THRESHOLD={}.",
            files.len(),
            options.large_mr_file_threshold
        ));
    }
    if large_by_bytes {
        warnings.push(format!(
            "Total diff bytes {} exceeds REVIEWGATE_LARGE_MR_DIFF_BYTES={}.",
            total_diff_bytes, options.large_mr_diff_bytes
        ));
    }

    ReviewPlan {
        mr: PlanMergeRequest {
            project_path: mr_url.project_path.clone(),
            mr_iid: metadata.iid,
            title: metadata.title,
            head_sha: metadata
                .diff_refs
                .and_then(|refs| refs.head_sha)
                .unwrap_or(metadata.sha),
        },
        summary: PlanSummary {
            changed_files: files.len(),
            reviewable_files,
            skipped_files,
            total_diff_bytes,
            large_mr,
        },
        files,
        warnings,
    }
}

pub fn format_review_plan(plan: &ReviewPlan) -> String {
    let mut output = String::new();
    output.push_str("ReviewGate plan\n\n");
    output.push_str(&format!("MR: !{} {}\n", plan.mr.mr_iid, plan.mr.title));
    output.push_str(&format!("Project: {}\n", plan.mr.project_path));
    output.push_str(&format!("Head SHA: {}\n\n", plan.mr.head_sha));
    output.push_str(&format!("Changed files: {}\n", plan.summary.changed_files));
    output.push_str(&format!(
        "Reviewable files: {}\n",
        plan.summary.reviewable_files
    ));
    output.push_str(&format!("Skipped files: {}\n", plan.summary.skipped_files));
    output.push_str(&format!(
        "Total diff bytes: {}\n",
        plan.summary.total_diff_bytes
    ));
    output.push_str(&format!(
        "Plan mode: {}\n\n",
        if plan.summary.large_mr {
            "risk-prioritized partial review"
        } else {
            "risk-prioritized review"
        }
    ));

    for risk in [
        FileRiskLevel::Critical,
        FileRiskLevel::High,
        FileRiskLevel::Medium,
        FileRiskLevel::Low,
    ] {
        let files: Vec<&PlannedFile> = plan
            .files
            .iter()
            .filter(|file| file.risk == risk && file.skip_reason.is_none())
            .collect();
        if files.is_empty() {
            continue;
        }
        output.push_str(&format!("{}:\n", risk.label()));
        for file in files {
            output.push_str(&format!("- {}\n", file.new_path));
            output.push_str(&format!("  Reason: {}\n", file.reasons.join(", ")));
            output.push_str(&format!(
                "  Added: {} Removed: {}\n",
                file.added_lines, file.removed_lines
            ));
        }
        output.push('\n');
    }

    let skipped: Vec<&PlannedFile> = plan
        .files
        .iter()
        .filter(|file| file.skip_reason.is_some())
        .collect();
    if !skipped.is_empty() {
        output.push_str("Skipped:\n");
        for file in skipped {
            output.push_str(&format!("- {}\n", file.new_path));
            let reason = file.skip_reason.map(SkipReason::label).unwrap_or("skipped");
            output.push_str(&format!("  Reason: {reason}\n\n"));
        }
    }

    if !plan.warnings.is_empty() {
        output.push_str("Warning:\n");
        for warning in &plan.warnings {
            output.push_str(warning);
            output.push('\n');
        }
    }

    output
}

fn classify_file(diff: MergeRequestDiff) -> PlannedFile {
    let line_stats = count_diff_lines(&diff.diff);
    let diff_bytes = diff_size(&diff);
    let skip_reason = skip_reason_for_file(&diff.new_path, &diff);
    let mut planned = PlannedFile {
        old_path: diff.old_path,
        new_path: diff.new_path,
        risk: FileRiskLevel::Low,
        reasons: Vec::new(),
        added_lines: line_stats.added,
        removed_lines: line_stats.removed,
        diff_bytes,
        skip_reason: None,
    };

    if let Some(skip_reason) = skip_reason {
        planned.risk = FileRiskLevel::Skip;
        planned.reasons.push(skip_reason.label().to_string());
        planned.skip_reason = Some(skip_reason);
        return planned;
    }

    let (path_risk, mut reasons) = classify_path(&planned.new_path);
    let (content_risk, content_reasons) = classify_diff_content(&diff.diff);
    reasons.extend(content_reasons);
    planned.risk = max_risk(path_risk, content_risk);
    if planned.risk == FileRiskLevel::Low && reasons.is_empty() {
        reasons.push("low-risk path".to_string());
    }
    planned.reasons = dedupe_reasons(reasons);
    planned
}

fn skip_reason_for_file(path: &str, diff: &MergeRequestDiff) -> Option<SkipReason> {
    if diff.is_too_large() {
        return Some(SkipReason::TooLarge);
    }
    if diff.is_collapsed() {
        return Some(SkipReason::Collapsed);
    }
    if diff.is_generated() {
        return Some(SkipReason::Generated);
    }

    let normalized = normalize_path(path);
    let basename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    if is_lockfile(basename) {
        return Some(SkipReason::Lockfile);
    }
    if normalized.contains("__snapshots__/")
        || normalized.contains("/__snapshots__/")
        || normalized.ends_with(".snap")
        || normalized.contains(".snap.")
    {
        return Some(SkipReason::Snapshot);
    }
    if basename.ends_with(".min.js") || basename.ends_with(".min.css") {
        return Some(SkipReason::Minified);
    }
    if has_path_segment(&normalized, "vendor")
        || has_path_segment(&normalized, "vendors")
        || has_path_segment(&normalized, "third_party")
        || has_path_segment(&normalized, "node_modules")
    {
        return Some(SkipReason::Vendored);
    }
    if has_path_segment(&normalized, "generated")
        || has_path_segment(&normalized, "gen")
        || has_path_segment(&normalized, "dist")
        || has_path_segment(&normalized, "build")
        || basename.contains("generated")
    {
        return Some(SkipReason::Generated);
    }
    if is_binary_path(&normalized) || diff.diff.starts_with("Binary files ") {
        return Some(SkipReason::Binary);
    }

    None
}

fn classify_path(path: &str) -> (FileRiskLevel, Vec<String>) {
    let normalized = normalize_path(path);
    let basename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let mut risk = FileRiskLevel::Low;
    let mut reasons = Vec::new();

    if is_test_path(&normalized) {
        return (FileRiskLevel::Medium, vec!["test file".to_string()]);
    }

    if matches_any(
        &normalized,
        &[
            "auth",
            "authorization",
            "permission",
            "session",
            "middleware",
            "security",
            "token",
            "secret",
        ],
    ) {
        risk = FileRiskLevel::Critical;
        reasons.push("auth/session/security path".to_string());
    }
    if matches_any(
        &normalized,
        &["payment", "billing", "money", "wallet", "invoice", "kyc"],
    ) {
        risk = max_risk(risk, FileRiskLevel::Critical);
        reasons.push("payment/billing path".to_string());
    }
    if matches_any(
        &normalized,
        &[
            "migration",
            "schema",
            "sql",
            "database",
            "repo",
            "repository",
            "terraform",
            "k8s",
            "helm",
            "production",
            "prod",
        ],
    ) {
        risk = max_risk(risk, FileRiskLevel::Critical);
        reasons.push("database or production infrastructure path".to_string());
    }
    if matches_any(
        &normalized,
        &[
            "webhook",
            "controller",
            "handler",
            "route",
            "api",
            "service",
            "worker",
            "job",
            "queue",
            "upload",
            "storage",
            "cache",
        ],
    ) {
        risk = max_risk(risk, FileRiskLevel::High);
        reasons.push("API/service/worker path".to_string());
    }
    if matches_any(
        &normalized,
        &["client", "http", "fetch", "request", "retry", "timeout"],
    ) {
        risk = max_risk(risk, FileRiskLevel::High);
        reasons.push("external HTTP or retry path".to_string());
    }
    if is_frontend_form_path(&normalized) {
        risk = max_risk(risk, FileRiskLevel::Medium);
        reasons.push("frontend user-data path".to_string());
    } else if is_docs_path(&normalized, basename) {
        risk = max_risk(risk, FileRiskLevel::Low);
        reasons.push("documentation-only path".to_string());
    } else if is_style_or_copy_path(&normalized, basename) {
        risk = max_risk(risk, FileRiskLevel::Low);
        reasons.push("UI/style-only path".to_string());
    } else if risk == FileRiskLevel::Low {
        risk = FileRiskLevel::Medium;
        reasons.push("normal application code".to_string());
    }

    (risk, reasons)
}

fn classify_diff_content(diff: &str) -> (FileRiskLevel, Vec<String>) {
    let lower = diff.to_lowercase();
    let mut risk = FileRiskLevel::Low;
    let mut reasons = Vec::new();

    if contains_any(
        &lower,
        &[
            "authorization",
            "permission",
            "bearer",
            "password",
            "token",
            "secret",
            "auth",
        ],
    ) {
        risk = FileRiskLevel::Critical;
        reasons.push("auth/token content".to_string());
    }
    if contains_any(
        &lower,
        &[
            "select ",
            "insert ",
            "update ",
            "delete from",
            "create table",
            "alter table",
            "drop table",
            "migration",
            "execute(",
            "query(",
        ],
    ) || lower.contains("${") && lower.contains("select")
    {
        risk = max_risk(risk, FileRiskLevel::Critical);
        reasons.push("SQL or migration content".to_string());
    }
    if contains_any(
        &lower,
        &[
            "fetch(",
            "axios",
            "http.client",
            "timeout",
            "retry",
            "webhook",
            "cache",
            "upload",
        ],
    ) {
        risk = max_risk(risk, FileRiskLevel::High);
        reasons.push("external HTTP/retry/storage content".to_string());
    }
    if contains_any(&lower, &["console.log", "log.", "logger."]) {
        risk = max_risk(risk, FileRiskLevel::High);
        reasons.push("logging content".to_string());
    }
    if contains_any(&lower, &["panic", "unwrap", "unsafe"]) {
        risk = max_risk(risk, FileRiskLevel::High);
        reasons.push("panic/unwrap/unsafe content".to_string());
    }
    if contains_any(&lower, &["formdata", "submit", "email", "phone", "pii"]) {
        risk = max_risk(risk, FileRiskLevel::Medium);
        reasons.push("user-data content".to_string());
    }

    (risk, reasons)
}

fn apply_plan_limits(files: &mut [PlannedFile], options: PlanOptions) {
    let mut included = files
        .iter()
        .filter(|file| {
            file.skip_reason.is_none()
                && matches!(file.risk, FileRiskLevel::Critical | FileRiskLevel::High)
        })
        .count();
    let mut included_bytes: usize = files
        .iter()
        .filter(|file| {
            file.skip_reason.is_none()
                && matches!(file.risk, FileRiskLevel::Critical | FileRiskLevel::High)
        })
        .map(|file| file.diff_bytes)
        .sum();

    for file in files {
        if file.skip_reason.is_some()
            || matches!(file.risk, FileRiskLevel::Critical | FileRiskLevel::High)
        {
            continue;
        }
        let include_by_risk = file.risk == FileRiskLevel::Medium
            || (file.risk == FileRiskLevel::Low && options.include_low_risk);
        let has_file_budget = included < options.max_files;
        let has_byte_budget = included_bytes + file.diff_bytes <= options.max_diff_bytes;
        if include_by_risk && has_file_budget && has_byte_budget {
            included += 1;
            included_bytes += file.diff_bytes;
            continue;
        }
        if file.risk == FileRiskLevel::Low && !options.include_low_risk {
            file.reasons
                .push("low risk excluded by default".to_string());
        }
        file.skip_reason = Some(SkipReason::ExceedsPlanLimit);
    }
}

fn compare_planned_files(left: &PlannedFile, right: &PlannedFile) -> Ordering {
    left.risk
        .priority()
        .cmp(&right.risk.priority())
        .then_with(|| right.diff_bytes.cmp(&left.diff_bytes))
        .then_with(|| left.new_path.cmp(&right.new_path))
}

fn count_diff_lines(diff: &str) -> LineStats {
    let mut added = 0;
    let mut removed = 0;
    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            added += 1;
        } else if line.starts_with('-') {
            removed += 1;
        }
    }
    LineStats { added, removed }
}

#[derive(Debug, Clone, Copy)]
struct LineStats {
    added: u32,
    removed: u32,
}

fn diff_size(diff: &MergeRequestDiff) -> usize {
    diff.to_unified_diff().len()
}

fn max_risk(left: FileRiskLevel, right: FileRiskLevel) -> FileRiskLevel {
    if left.priority() <= right.priority() {
        left
    } else {
        right
    }
}

fn dedupe_reasons(reasons: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for reason in reasons {
        if !deduped.contains(&reason) {
            deduped.push(reason);
        }
    }
    deduped
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok().and_then(|value| value.parse().ok())
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

fn matches_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        haystack
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|part| part == *needle)
            || (needle.len() >= 5 && haystack.contains(needle))
    })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn has_path_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|part| part == segment)
}

fn is_lockfile(basename: &str) -> bool {
    matches!(
        basename,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "cargo.lock"
            | "gemfile.lock"
            | "poetry.lock"
            | "pipfile.lock"
            | "composer.lock"
            | "go.sum"
    )
}

fn is_binary_path(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "pdf"
                | "zip"
                | "gz"
                | "tgz"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "mp4"
                | "mov"
                | "mp3"
        )
    )
}

fn is_test_path(path: &str) -> bool {
    has_path_segment(path, "test")
        || has_path_segment(path, "tests")
        || path.contains(".test.")
        || path.contains(".spec.")
        || path.ends_with("_test.rs")
}

fn is_docs_path(path: &str, basename: &str) -> bool {
    has_path_segment(path, "docs") || basename == "readme.md" || path.ends_with(".md")
}

fn is_frontend_form_path(path: &str) -> bool {
    (path.ends_with(".tsx")
        || path.ends_with(".jsx")
        || path.ends_with(".vue")
        || path.ends_with(".svelte"))
        && contains_any(path, &["form", "profile", "account", "user", "checkout"])
}

fn is_style_or_copy_path(path: &str, basename: &str) -> bool {
    path.ends_with(".css")
        || path.ends_with(".scss")
        || path.ends_with(".sass")
        || basename.contains("button")
        || basename.contains("copy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::types::DiffRefs;

    #[test]
    fn lockfile_skipped() {
        assert_skipped(diff("package-lock.json", "+{}"), SkipReason::Lockfile);
    }

    #[test]
    fn generated_file_skipped() {
        assert_skipped(
            diff("generated/api-client.ts", "+code"),
            SkipReason::Generated,
        );
    }

    #[test]
    fn too_large_file_skipped() {
        assert_skipped(
            MergeRequestDiff {
                too_large: Some(true),
                ..diff("src/huge.rs", "+huge")
            },
            SkipReason::TooLarge,
        );
    }

    #[test]
    fn collapsed_file_skipped() {
        assert_skipped(
            MergeRequestDiff {
                collapsed: Some(true),
                ..diff("src/collapsed.rs", "+visible")
            },
            SkipReason::Collapsed,
        );
    }

    #[test]
    fn snapshot_skipped() {
        assert_skipped(
            diff("src/__snapshots__/component.snap", "+snapshot"),
            SkipReason::Snapshot,
        );
    }

    #[test]
    fn minified_skipped() {
        assert_skipped(diff("public/app.min.js", "+minified"), SkipReason::Minified);
    }

    #[test]
    fn auth_path_classified_critical() {
        let file = classify_file(diff("src/auth/session.ts", "+return token"));
        assert_eq!(file.risk, FileRiskLevel::Critical);
    }

    #[test]
    fn payment_path_classified_critical() {
        let file = classify_file(diff("src/payment/client.ts", "+charge"));
        assert_eq!(file.risk, FileRiskLevel::Critical);
    }

    #[test]
    fn migration_path_classified_critical() {
        let file = classify_file(diff(
            "db/migrations/001_create_users.sql",
            "+CREATE TABLE users",
        ));
        assert_eq!(file.risk, FileRiskLevel::Critical);
    }

    #[test]
    fn webhook_path_classified_high() {
        let file = classify_file(diff("src/webhooks/stripe_handler.ts", "+handle"));
        assert_eq!(file.risk, FileRiskLevel::High);
    }

    #[test]
    fn http_fetch_diff_content_increases_risk() {
        let file = classify_file(diff(
            "src/button.ts",
            "+fetch('/api/payments')\n+timeout = 1000",
        ));
        assert_eq!(file.risk, FileRiskLevel::High);
    }

    #[test]
    fn token_logging_diff_content_increases_risk() {
        let file = classify_file(diff("src/util.ts", "+console.log(token)\n+Bearer abc"));
        assert_eq!(file.risk, FileRiskLevel::Critical);
    }

    #[test]
    fn docs_only_file_low_risk() {
        let file = classify_file(diff("docs/review.md", "+copy"));
        assert_eq!(file.risk, FileRiskLevel::Low);
    }

    #[test]
    fn test_file_medium_risk() {
        let file = classify_file(diff("tests/payment_client.test.ts", "+assert"));
        assert_eq!(file.risk, FileRiskLevel::Medium);
    }

    #[test]
    fn large_mr_warning_by_file_count() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![diff("src/a.rs", "+a"), diff("src/b.rs", "+b")],
            PlanOptions {
                large_mr_file_threshold: 1,
                ..PlanOptions::default()
            },
        );

        assert!(plan.summary.large_mr);
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("file count")));
    }

    #[test]
    fn large_mr_warning_by_diff_bytes() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![diff("src/a.rs", "+abcdef")],
            PlanOptions {
                large_mr_diff_bytes: 1,
                ..PlanOptions::default()
            },
        );

        assert!(plan.summary.large_mr);
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("diff bytes")));
    }

    #[test]
    fn plan_max_files_keeps_critical_and_high_first() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![
                diff("src/components/button.tsx", "+copy"),
                diff("src/normal.rs", "+business"),
                diff("src/auth/session.rs", "+check"),
                diff("src/webhook/handler.rs", "+handle"),
            ],
            PlanOptions {
                max_files: 1,
                ..PlanOptions::default()
            },
        );

        let included: Vec<&str> = plan
            .files
            .iter()
            .filter(|file| file.skip_reason.is_none())
            .map(|file| file.new_path.as_str())
            .collect();
        assert!(included.contains(&"src/auth/session.rs"));
        assert!(included.contains(&"src/webhook/handler.rs"));
        assert!(!included.contains(&"src/normal.rs"));
    }

    #[test]
    fn json_output_includes_expected_fields() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![diff("src/payment/client.ts", "+fetch('/payments')")],
            PlanOptions::default(),
        );
        let json = serde_json::to_value(&plan).unwrap();

        assert_eq!(json["mr"]["project_path"], "group/repo");
        assert_eq!(json["mr"]["mr_iid"], 59);
        assert_eq!(json["files"][0]["risk"], "critical");
        assert!(json["files"][0].get("skip_reason").is_some());
    }

    #[test]
    fn human_output_includes_skipped_reasons() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![diff("Cargo.lock", "+lock")],
            PlanOptions::default(),
        );
        let output = format_review_plan(&plan);

        assert!(output.contains("Skipped:"));
        assert!(output.contains("Reason: lockfile"));
    }

    #[test]
    fn plan_builder_does_not_call_llm_or_publish_callbacks() {
        let plan = build_review_plan(
            &mr_url(),
            metadata(),
            vec![diff("src/auth/session.rs", "+check")],
            PlanOptions::default(),
        );

        assert_eq!(plan.summary.reviewable_files, 1);
    }

    fn assert_skipped(diff: MergeRequestDiff, reason: SkipReason) {
        let file = classify_file(diff);

        assert_eq!(file.risk, FileRiskLevel::Skip);
        assert_eq!(file.skip_reason, Some(reason));
    }

    fn mr_url() -> GitLabMrUrl {
        GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59").unwrap()
    }

    fn metadata() -> MergeRequestMetadata {
        MergeRequestMetadata {
            id: 123,
            iid: 59,
            project_id: 456,
            title: "ReviewGate E2E Risky Change".to_string(),
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
            diff_refs: Some(DiffRefs {
                base_sha: Some("base123".to_string()),
                start_sha: Some("start123".to_string()),
                head_sha: Some("head123".to_string()),
            }),
        }
    }

    fn diff(path: &str, diff: &str) -> MergeRequestDiff {
        MergeRequestDiff {
            old_path: path.to_string(),
            new_path: path.to_string(),
            diff: diff.to_string(),
            new_file: false,
            renamed_file: false,
            deleted_file: false,
            generated_file: None,
            collapsed: None,
            too_large: None,
        }
    }
}
