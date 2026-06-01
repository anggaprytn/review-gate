use crate::{
    config::{AppConfig, StorageConfig},
    error::{Result, ReviewGateError},
    gitlab::{
        inline::inline_fingerprint_v2,
        types::{PublishAction, PublishResult},
    },
    review::{
        engine::ReviewPreview,
        inline::{InlinePublishResult, InlinePublishStatus},
        types::ReviewFinding,
    },
    verify::VerificationOutcome,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MIGRATION_VERSION: i64 = 1;

#[derive(Debug)]
pub struct Storage {
    conn: Connection,
    db_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageOpenOutcome {
    pub enabled: bool,
    pub db_path: PathBuf,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedReviewRun {
    pub id: String,
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestReviewRun {
    pub id: String,
    pub project_path: String,
    pub mr_iid: u64,
    pub mr_url: String,
    pub head_sha: String,
    pub model_provider: String,
    pub model_name: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPreviousFinding {
    pub id: String,
    pub severity: String,
    pub effort: String,
    pub category: String,
    pub risk_code: Option<String>,
    pub anchor_id: Option<String>,
    pub file_path: Option<String>,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
    pub title: String,
    pub body: String,
    pub suggested_fix: Option<String>,
    pub actionable: bool,
    pub fingerprint_v2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedVerificationRun {
    pub id: String,
}

impl Storage {
    pub fn open(config: &StorageConfig) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        Self::open_path(&config.db_path).map(Some)
    }

    pub fn open_best_effort(config: &StorageConfig) -> (Option<Self>, StorageOpenOutcome) {
        if !config.enabled {
            return (
                None,
                StorageOpenOutcome {
                    enabled: false,
                    db_path: config.db_path.clone(),
                    warning: None,
                },
            );
        }

        match Self::open_path(&config.db_path) {
            Ok(storage) => (
                Some(storage),
                StorageOpenOutcome {
                    enabled: true,
                    db_path: config.db_path.clone(),
                    warning: None,
                },
            ),
            Err(err) => (
                None,
                StorageOpenOutcome {
                    enabled: true,
                    db_path: config.db_path.clone(),
                    warning: Some(err.to_string()),
                },
            ),
        }
    }

    pub fn open_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(storage_error)?;
        let mut storage = Self {
            conn,
            db_path: path.to_path_buf(),
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn migrate(&mut self) -> Result<()> {
        let tx = self.conn.transaction().map_err(storage_error)?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )",
            [],
        )
        .map_err(storage_error)?;

        let applied: Option<i64> = tx
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = ?1",
                [MIGRATION_VERSION],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;

        if applied.is_none() {
            tx.execute_batch(SCHEMA_V1).map_err(storage_error)?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![MIGRATION_VERSION, now_text()],
            )
            .map_err(storage_error)?;
        }

        tx.commit().map_err(storage_error)
    }

    pub fn persist_review_run(
        &mut self,
        context: &crate::gitlab::context::MergeRequestContext,
        config: &AppConfig,
        preview: &ReviewPreview,
    ) -> Result<PersistedReviewRun> {
        let completed_at = now_text();
        let run_id = review_run_id(
            &context.mr_url.project_path,
            context.metadata.iid,
            head_sha(context),
            &config.llm.provider,
            &config.llm.model,
            &completed_at,
        );
        let tx = self.conn.transaction().map_err(storage_error)?;

        tx.execute(
            "INSERT INTO review_runs (
                id, provider, project_path, mr_iid, mr_url, mr_title, source_branch,
                target_branch, head_sha, model_provider, model_name, local_only, status,
                started_at, completed_at, raw_diff_stored, raw_llm_stored
            ) VALUES (?1, 'gitlab', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'completed', ?12, ?13, ?14, ?15)",
            params![
                run_id.as_str(),
                context.mr_url.project_path.as_str(),
                context.metadata.iid as i64,
                context.metadata.web_url.as_str(),
                context.metadata.title.as_str(),
                context.metadata.source_branch.as_str(),
                context.metadata.target_branch.as_str(),
                head_sha(context),
                config.llm.provider.as_str(),
                config.llm.model.as_str(),
                bool_int(crate::llm::provider_local_only(&config.llm)),
                completed_at.as_str(),
                completed_at.as_str(),
                bool_int(false),
                bool_int(false),
            ],
        )
        .map_err(storage_error)?;

        let mut finding_ids = Vec::new();
        if let Some(analysis) = preview.analysis.as_ref() {
            for (index, finding) in analysis.findings.iter().enumerate() {
                let normalized = normalize_finding(context, finding);
                let fingerprint = normalized.fingerprint_v2.clone();
                let finding_id = finding_id(&run_id, index, fingerprint.as_deref(), finding);
                tx.execute(
                    "INSERT INTO review_findings (
                        id, run_id, project_path, mr_iid, head_sha, severity, effort,
                        category, risk_code, anchor_id, file_path, old_line, new_line,
                        title, body, suggested_fix, actionable, fingerprint_v2, created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                    params![
                        finding_id.as_str(),
                        run_id.as_str(),
                        context.mr_url.project_path.as_str(),
                        context.metadata.iid as i64,
                        head_sha(context),
                        finding.severity.display_upper(),
                        finding.effort.display_lower(),
                        finding.category.display_lower(),
                        finding.risk_code.map(|risk| risk.display_lower().to_string()),
                        finding.anchor_id.as_deref(),
                        normalized.file_path.as_deref(),
                        normalized.old_line.map(i64::from),
                        normalized.new_line.map(i64::from),
                        finding.title.as_str(),
                        finding.body.as_str(),
                        finding.suggested_fix.as_deref(),
                        bool_int(finding.actionable),
                        fingerprint.as_deref(),
                        completed_at.as_str(),
                    ],
                )
                .map_err(storage_error)?;
                finding_ids.push(finding_id);
            }
        }

        tx.commit().map_err(storage_error)?;
        Ok(PersistedReviewRun {
            id: run_id,
            finding_ids,
        })
    }

    pub fn update_summary_publish(&mut self, run_id: &str, result: &PublishResult) -> Result<()> {
        let action = publish_action_label(result.action);
        self.conn
            .execute(
                "UPDATE review_runs
                 SET summary_note_id = ?2, summary_publish_action = ?3
                 WHERE id = ?1",
                params![run_id, result.note_id.map(|value| value as i64), action],
            )
            .map_err(storage_error)?;

        let head_sha = head_sha_from_run(&self.conn, run_id)?.unwrap_or_default();
        self.insert_published_comment(PublishedComment {
            run_id,
            kind: "summary",
            gitlab_note_id: result.note_id,
            gitlab_discussion_id: None,
            fingerprint: None,
            status: "published",
            head_sha: &head_sha,
        })
    }

    pub fn update_inline_publish(
        &mut self,
        run_id: &str,
        finding_ids: &[String],
        report: &crate::gitlab::inline::InlinePublishReport,
    ) -> Result<()> {
        let tx = self.conn.transaction().map_err(storage_error)?;
        tx.execute(
            "UPDATE review_runs
             SET inline_created_count = ?2,
                 inline_skipped_duplicate_count = ?3,
                 inline_failed_count = ?4,
                 fallback_count = ?5
             WHERE id = ?1",
            params![
                run_id,
                report.created_count() as i64,
                report.skipped_duplicate_count() as i64,
                report.failed_count() as i64,
                report.fallback_count() as i64,
            ],
        )
        .map_err(storage_error)?;

        let head_sha = head_sha_from_tx(&tx, run_id)?.unwrap_or_default();
        for result in &report.results {
            let Some(finding_id) = result_finding_db_id(finding_ids, result) else {
                continue;
            };
            let status = inline_status_label(result.status);
            tx.execute(
                "UPDATE review_findings
                 SET inline_status = ?2, discussion_id = ?3, note_id = ?4
                 WHERE id = ?1",
                params![
                    finding_id,
                    status,
                    result.discussion_id.as_deref(),
                    result.note_id.map(|value| value as i64),
                ],
            )
            .map_err(storage_error)?;

            let fingerprint: Option<String> = tx
                .query_row(
                    "SELECT fingerprint_v2 FROM review_findings WHERE id = ?1",
                    [finding_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage_error)?
                .flatten();
            insert_published_comment_tx(
                &tx,
                &PublishedComment {
                    run_id,
                    kind: "inline",
                    gitlab_note_id: result.note_id,
                    gitlab_discussion_id: result.discussion_id.as_deref(),
                    fingerprint: fingerprint.as_deref(),
                    status,
                    head_sha: &head_sha,
                },
            )?;
        }

        tx.commit().map_err(storage_error)
    }

    pub fn latest_completed_review_run(
        &self,
        project_path: &str,
        mr_iid: u64,
    ) -> Result<Option<LatestReviewRun>> {
        self.conn
            .query_row(
                "SELECT id, project_path, mr_iid, mr_url, head_sha, model_provider, model_name, completed_at
                 FROM review_runs
                 WHERE project_path = ?1 AND mr_iid = ?2 AND status = 'completed'
                 ORDER BY completed_at DESC
                 LIMIT 1",
                params![project_path, mr_iid as i64],
                |row| {
                    Ok(LatestReviewRun {
                        id: row.get(0)?,
                        project_path: row.get(1)?,
                        mr_iid: i64_to_u64(row.get::<_, i64>(2)?),
                        mr_url: row.get(3)?,
                        head_sha: row.get(4)?,
                        model_provider: row.get(5)?,
                        model_name: row.get(6)?,
                        completed_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(storage_error)
    }

    pub fn previous_findings_for_verification(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredPreviousFinding>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, severity, effort, category, risk_code, anchor_id, file_path,
                        old_line, new_line, title, body, suggested_fix, actionable, fingerprint_v2
                 FROM review_findings
                 WHERE run_id = ?1 AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                 ORDER BY
                   CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                   file_path,
                   COALESCE(new_line, old_line, 0),
                   title
                 LIMIT ?2",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![run_id, limit as i64], |row| {
                Ok(StoredPreviousFinding {
                    id: row.get(0)?,
                    severity: row.get(1)?,
                    effort: row.get(2)?,
                    category: row.get(3)?,
                    risk_code: row.get(4)?,
                    anchor_id: row.get(5)?,
                    file_path: row.get(6)?,
                    old_line: optional_i64_to_u32(row.get(7)?),
                    new_line: optional_i64_to_u32(row.get(8)?),
                    title: row.get(9)?,
                    body: row.get(10)?,
                    suggested_fix: row.get(11)?,
                    actionable: row.get::<_, i64>(12)? != 0,
                    fingerprint_v2: row.get(13)?,
                })
            })
            .map_err(storage_error)?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(storage_error)?);
        }
        Ok(findings)
    }

    pub fn persist_verification_run(
        &mut self,
        context: &crate::gitlab::context::MergeRequestContext,
        config: &AppConfig,
        previous_run_id: Option<&str>,
        outcome: &VerificationOutcome,
    ) -> Result<PersistedVerificationRun> {
        let completed_at = now_text();
        let run_id = verification_run_id(
            &context.mr_url.project_path,
            context.metadata.iid,
            head_sha(context),
            &config.llm.provider,
            &config.llm.model,
            &completed_at,
        );
        let tx = self.conn.transaction().map_err(storage_error)?;
        tx.execute(
            "INSERT INTO verification_runs (
                id, project_path, mr_iid, mr_url, previous_run_id, current_head_sha,
                model_provider, model_name, status, started_at, completed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'completed', ?9, ?10)",
            params![
                run_id.as_str(),
                context.mr_url.project_path.as_str(),
                context.metadata.iid as i64,
                context.metadata.web_url.as_str(),
                previous_run_id,
                head_sha(context),
                config.llm.provider.as_str(),
                config.llm.model.as_str(),
                completed_at.as_str(),
                completed_at.as_str(),
            ],
        )
        .map_err(storage_error)?;

        for result in &outcome.results {
            tx.execute(
                "INSERT INTO verification_results (
                    id, verification_run_id, previous_finding_id, status, severity,
                    risk_code, file_path, old_line, new_line, title, reason, evidence, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    verification_result_id(&run_id, &result.previous_finding.id),
                    run_id.as_str(),
                    result.previous_finding.id.as_str(),
                    result.status.display_lower(),
                    result.previous_finding.severity.as_str(),
                    result.previous_finding.risk_code.as_deref(),
                    result.previous_finding.file_path.as_deref(),
                    result.previous_finding.old_line.map(i64::from),
                    result.previous_finding.new_line.map(i64::from),
                    result.previous_finding.title.as_str(),
                    result.reason.as_str(),
                    result.evidence.as_deref(),
                    completed_at.as_str(),
                ],
            )
            .map_err(storage_error)?;
        }

        tx.commit().map_err(storage_error)?;
        Ok(PersistedVerificationRun { id: run_id })
    }

    pub fn update_verification_publish(
        &mut self,
        verification_run_id: &str,
        result: &PublishResult,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE verification_runs
                 SET verification_note_id = ?2, publish_action = ?3
                 WHERE id = ?1",
                params![
                    verification_run_id,
                    result.note_id.map(|value| value as i64),
                    publish_action_label(result.action),
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    fn insert_published_comment(&mut self, comment: PublishedComment<'_>) -> Result<()> {
        insert_published_comment_conn(&self.conn, &comment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedFinding {
    file_path: Option<String>,
    old_line: Option<u32>,
    new_line: Option<u32>,
    fingerprint_v2: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct PublishedComment<'a> {
    run_id: &'a str,
    kind: &'a str,
    gitlab_note_id: Option<u64>,
    gitlab_discussion_id: Option<&'a str>,
    fingerprint: Option<&'a str>,
    status: &'a str,
    head_sha: &'a str,
}

fn normalize_finding(
    context: &crate::gitlab::context::MergeRequestContext,
    finding: &ReviewFinding,
) -> NormalizedFinding {
    let anchor = finding
        .anchor_id
        .as_deref()
        .and_then(|anchor_id| context.anchored_diff.get(anchor_id));
    let file_path = anchor
        .map(|anchor| anchor.file_path.clone())
        .or_else(|| finding.file_path.clone());
    let old_line = anchor.and_then(|anchor| anchor.old_line);
    let new_line = anchor.and_then(|anchor| anchor.new_line).or(finding.line);
    let fingerprint_v2 = file_path.as_deref().map(|file_path| {
        inline_fingerprint_v2(
            &context.mr_url.project_path,
            context.metadata.iid,
            head_sha(context),
            file_path,
            old_line,
            new_line,
            finding.severity,
            &finding.category,
            finding.risk_code,
        )
    });

    NormalizedFinding {
        file_path,
        old_line,
        new_line,
        fingerprint_v2,
    }
}

fn insert_published_comment_conn(conn: &Connection, comment: &PublishedComment<'_>) -> Result<()> {
    let created_at = now_text();
    let id = published_comment_id(
        comment.run_id,
        comment.kind,
        comment.gitlab_note_id,
        comment.gitlab_discussion_id,
        comment.fingerprint,
    );
    conn.execute(
        "INSERT INTO published_comments (
            id, run_id, project_path, mr_iid, kind, gitlab_note_id, gitlab_discussion_id,
            fingerprint, head_sha, status, created_at, updated_at
        )
        SELECT ?1, id, project_path, mr_iid, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8
        FROM review_runs
        WHERE id = ?9",
        params![
            id,
            comment.kind,
            comment.gitlab_note_id.map(|value| value as i64),
            comment.gitlab_discussion_id,
            comment.fingerprint,
            comment.head_sha,
            comment.status,
            created_at,
            comment.run_id,
        ],
    )
    .map_err(storage_error)?;
    Ok(())
}

fn insert_published_comment_tx(
    tx: &rusqlite::Transaction<'_>,
    comment: &PublishedComment<'_>,
) -> Result<()> {
    let created_at = now_text();
    let id = published_comment_id(
        comment.run_id,
        comment.kind,
        comment.gitlab_note_id,
        comment.gitlab_discussion_id,
        comment.fingerprint,
    );
    tx.execute(
        "INSERT INTO published_comments (
            id, run_id, project_path, mr_iid, kind, gitlab_note_id, gitlab_discussion_id,
            fingerprint, head_sha, status, created_at, updated_at
        )
        SELECT ?1, id, project_path, mr_iid, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8
        FROM review_runs
        WHERE id = ?9",
        params![
            id,
            comment.kind,
            comment.gitlab_note_id.map(|value| value as i64),
            comment.gitlab_discussion_id,
            comment.fingerprint,
            comment.head_sha,
            comment.status,
            created_at,
            comment.run_id,
        ],
    )
    .map_err(storage_error)?;
    Ok(())
}

fn head_sha_from_run(conn: &Connection, run_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT head_sha FROM review_runs WHERE id = ?1",
        [run_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage_error)
}

fn head_sha_from_tx(tx: &rusqlite::Transaction<'_>, run_id: &str) -> Result<Option<String>> {
    tx.query_row(
        "SELECT head_sha FROM review_runs WHERE id = ?1",
        [run_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(storage_error)
}

fn result_finding_db_id<'a>(
    finding_ids: &'a [String],
    result: &InlinePublishResult,
) -> Option<&'a str> {
    let index = result
        .finding_id
        .strip_prefix("finding-")?
        .parse::<usize>()
        .ok()?;
    finding_ids.get(index.checked_sub(1)?).map(String::as_str)
}

fn head_sha(context: &crate::gitlab::context::MergeRequestContext) -> &str {
    context
        .metadata
        .diff_refs
        .as_ref()
        .and_then(|refs| refs.head_sha.as_deref())
        .unwrap_or(&context.metadata.sha)
}

fn bool_int(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn publish_action_label(action: PublishAction) -> &'static str {
    match action {
        PublishAction::Created => "created",
        PublishAction::Updated => "updated",
    }
}

fn inline_status_label(status: InlinePublishStatus) -> &'static str {
    match status {
        InlinePublishStatus::Created => "created",
        InlinePublishStatus::SkippedDuplicate => "skipped_duplicate",
        InlinePublishStatus::Failed => "failed",
        InlinePublishStatus::NotEligible => "not_eligible",
    }
}

fn review_run_id(
    project_path: &str,
    mr_iid: u64,
    head_sha: &str,
    provider: &str,
    model: &str,
    completed_at: &str,
) -> String {
    stable_id(
        "rgrun",
        &[
            project_path,
            &mr_iid.to_string(),
            head_sha,
            provider,
            model,
            completed_at,
        ],
    )
}

fn finding_id(
    run_id: &str,
    index: usize,
    fingerprint: Option<&str>,
    finding: &ReviewFinding,
) -> String {
    stable_id(
        "rgfind",
        &[
            run_id,
            &index.to_string(),
            fingerprint.unwrap_or_default(),
            &finding.title,
            &finding.body,
        ],
    )
}

fn verification_run_id(
    project_path: &str,
    mr_iid: u64,
    head_sha: &str,
    provider: &str,
    model: &str,
    completed_at: &str,
) -> String {
    stable_id(
        "rgverify",
        &[
            project_path,
            &mr_iid.to_string(),
            head_sha,
            provider,
            model,
            completed_at,
        ],
    )
}

fn verification_result_id(run_id: &str, finding_id: &str) -> String {
    stable_id("rgvresult", &[run_id, finding_id])
}

fn published_comment_id(
    run_id: &str,
    kind: &str,
    note_id: Option<u64>,
    discussion_id: Option<&str>,
    fingerprint: Option<&str>,
) -> String {
    stable_id(
        "rgpub",
        &[
            run_id,
            kind,
            &note_id.map(|id| id.to_string()).unwrap_or_default(),
            discussion_id.unwrap_or_default(),
            fingerprint.unwrap_or_default(),
        ],
    )
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.trim().as_bytes());
        hasher.update(b"\0");
    }
    format!("{prefix}_{}", &hex_lower(&hasher.finalize())[..24])
}

fn now_text() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:020}", duration.as_nanos())
}

fn optional_i64_to_u32(value: Option<i64>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn storage_error(error: rusqlite::Error) -> ReviewGateError {
    ReviewGateError::Storage(error.to_string())
}

const SCHEMA_V1: &str = r#"
CREATE TABLE review_runs (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  project_path TEXT NOT NULL,
  mr_iid INTEGER NOT NULL,
  mr_url TEXT NOT NULL,
  mr_title TEXT,
  source_branch TEXT,
  target_branch TEXT,
  head_sha TEXT NOT NULL,
  model_provider TEXT NOT NULL,
  model_name TEXT NOT NULL,
  local_only INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  summary_note_id INTEGER,
  summary_publish_action TEXT,
  inline_created_count INTEGER DEFAULT 0,
  inline_skipped_duplicate_count INTEGER DEFAULT 0,
  inline_failed_count INTEGER DEFAULT 0,
  fallback_count INTEGER DEFAULT 0,
  raw_diff_stored INTEGER DEFAULT 0,
  raw_llm_stored INTEGER DEFAULT 0
);

CREATE TABLE review_findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  project_path TEXT NOT NULL,
  mr_iid INTEGER NOT NULL,
  head_sha TEXT NOT NULL,
  severity TEXT NOT NULL,
  effort TEXT NOT NULL,
  category TEXT NOT NULL,
  risk_code TEXT,
  anchor_id TEXT,
  file_path TEXT,
  old_line INTEGER,
  new_line INTEGER,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  suggested_fix TEXT,
  actionable INTEGER NOT NULL,
  fingerprint_v2 TEXT,
  inline_status TEXT DEFAULT 'not_attempted',
  discussion_id TEXT,
  note_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES review_runs(id)
);

CREATE TABLE published_comments (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  project_path TEXT NOT NULL,
  mr_iid INTEGER NOT NULL,
  kind TEXT NOT NULL,
  gitlab_note_id INTEGER,
  gitlab_discussion_id TEXT,
  fingerprint TEXT,
  head_sha TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY(run_id) REFERENCES review_runs(id)
);

CREATE TABLE verification_runs (
  id TEXT PRIMARY KEY,
  project_path TEXT NOT NULL,
  mr_iid INTEGER NOT NULL,
  mr_url TEXT NOT NULL,
  previous_run_id TEXT,
  current_head_sha TEXT NOT NULL,
  model_provider TEXT NOT NULL,
  model_name TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  verification_note_id INTEGER,
  publish_action TEXT
);

CREATE TABLE verification_results (
  id TEXT PRIMARY KEY,
  verification_run_id TEXT NOT NULL,
  previous_finding_id TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  risk_code TEXT,
  file_path TEXT,
  old_line INTEGER,
  new_line INTEGER,
  title TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(verification_run_id) REFERENCES verification_runs(id)
);

CREATE INDEX idx_review_runs_project_mr_completed
  ON review_runs(project_path, mr_iid, completed_at);
CREATE INDEX idx_review_findings_project_mr_head
  ON review_findings(project_path, mr_iid, head_sha);
CREATE INDEX idx_review_findings_fingerprint_v2
  ON review_findings(fingerprint_v2);
CREATE INDEX idx_published_comments_project_mr_fingerprint
  ON published_comments(project_path, mr_iid, fingerprint);
CREATE INDEX idx_verification_runs_project_mr_completed
  ON verification_runs(project_path, mr_iid, completed_at);
"#;

#[cfg(test)]
mod tests {
    use super::Storage;
    use crate::{
        config::{
            AppConfig, CiConfig, GitLabTokenSource, InlineConfig, LlmConfig, PrivacyConfig,
            PublishConfig, ReviewConfig, StorageConfig,
        },
        gitlab::{
            inline::InlinePublishReport,
            types::{DiffRefs, MergeRequestMetadata, PublishAction, PublishResult},
            url::GitLabMrUrl,
        },
        review::{
            engine::ReviewPreview,
            inline::{InlinePublishResult, InlinePublishStatus},
            types::{
                Effort, OverallRisk, ReviewAnalysis, ReviewCategory, ReviewFinding, RiskCode,
                Severity,
            },
        },
        verify::{VerificationOutcome, VerificationResult, VerificationStatus},
    };
    use rusqlite::Connection;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn migration_creates_all_tables() {
        let path = temp_db_path("migration_creates_all_tables");
        let storage = Storage::open_path(&path).unwrap();

        for table in [
            "schema_migrations",
            "review_runs",
            "review_findings",
            "published_comments",
            "verification_runs",
            "verification_results",
        ] {
            assert!(table_exists(&storage.conn, table));
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let path = temp_db_path("migration_is_idempotent");
        let mut storage = Storage::open_path(&path).unwrap();

        storage.migrate().unwrap();
        storage.migrate().unwrap();

        let count: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn db_path_creates_reviewgate_directory() {
        let dir = temp_dir("db_path_creates_reviewgate_directory");
        let path = dir.join(".reviewgate/reviewgate.sqlite");

        let _storage = Storage::open_path(&path).unwrap();

        assert!(path.exists());
    }

    #[test]
    fn review_run_and_findings_are_inserted() {
        let path = temp_db_path("review_run_and_findings_are_inserted");
        let mut storage = Storage::open_path(&path).unwrap();

        let persisted = storage
            .persist_review_run(&context(), &config(path), &preview_with_findings())
            .unwrap();

        assert_eq!(persisted.finding_ids.len(), 2);
        assert_eq!(count(&storage.conn, "review_runs"), 1);
        assert_eq!(count(&storage.conn, "review_findings"), 2);
    }

    #[test]
    fn publish_metadata_update_records_summary_and_inline_counts() {
        let path = temp_db_path("publish_metadata_update_records_summary_and_inline_counts");
        let mut storage = Storage::open_path(&path).unwrap();
        let persisted = storage
            .persist_review_run(&context(), &config(path), &preview_with_findings())
            .unwrap();

        storage
            .update_summary_publish(
                &persisted.id,
                &PublishResult {
                    action: PublishAction::Updated,
                    note_id: Some(3404005852),
                    web_url: None,
                    duplicate_count: 1,
                },
            )
            .unwrap();
        storage
            .update_inline_publish(
                &persisted.id,
                &persisted.finding_ids,
                &InlinePublishReport {
                    results: vec![
                        inline_result("finding-1", InlinePublishStatus::Created),
                        inline_result("finding-2", InlinePublishStatus::SkippedDuplicate),
                    ],
                    duplicate_warnings: Vec::new(),
                },
            )
            .unwrap();

        let row: (i64, String, i64, i64) = storage
            .conn
            .query_row(
                "SELECT summary_note_id, summary_publish_action, inline_created_count, inline_skipped_duplicate_count FROM review_runs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (3404005852, "updated".to_string(), 1, 1));
        assert_eq!(count(&storage.conn, "published_comments"), 3);
    }

    #[test]
    fn latest_run_query_by_project_and_mr_returns_latest_completed() {
        let path = temp_db_path("latest_run_query_by_project_and_mr_returns_latest_completed");
        let mut storage = Storage::open_path(&path).unwrap();
        let first = storage
            .persist_review_run(&context(), &config(path.clone()), &preview_with_findings())
            .unwrap();
        let second = storage
            .persist_review_run(&context(), &config(path), &preview_with_findings())
            .unwrap();

        let latest = storage
            .latest_completed_review_run("group/repo", 59)
            .unwrap()
            .unwrap();

        assert_eq!(latest.id, second.id);
        assert_ne!(latest.id, first.id);
    }

    #[test]
    fn previous_findings_query_excludes_note_by_default() {
        let path = temp_db_path("previous_findings_query_excludes_note_by_default");
        let mut storage = Storage::open_path(&path).unwrap();
        let persisted = storage
            .persist_review_run(&context(), &config(path), &preview_with_findings())
            .unwrap();

        let findings = storage
            .previous_findings_for_verification(&persisted.id, 30)
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "HIGH");
    }

    #[test]
    fn verification_run_and_results_are_inserted() {
        let path = temp_db_path("verification_run_and_results_are_inserted");
        let mut storage = Storage::open_path(&path).unwrap();
        let persisted_review = storage
            .persist_review_run(&context(), &config(path.clone()), &preview_with_findings())
            .unwrap();
        let previous = storage
            .previous_findings_for_verification(&persisted_review.id, 30)
            .unwrap();
        let outcome = VerificationOutcome {
            summary: "1 fixed.".to_string(),
            results: vec![VerificationResult {
                previous_finding: previous[0].clone(),
                status: VerificationStatus::Fixed,
                reason: "fixed".to_string(),
                evidence: Some("evidence".to_string()),
            }],
            parsed: true,
            parse_warning: None,
        };

        let verification = storage
            .persist_verification_run(
                &context(),
                &config(path),
                Some(&persisted_review.id),
                &outcome,
            )
            .unwrap();

        assert!(verification.id.starts_with("rgverify_"));
        assert_eq!(count(&storage.conn, "verification_runs"), 1);
        assert_eq!(count(&storage.conn, "verification_results"), 1);
    }

    #[test]
    fn storage_disabled_skips_db_writes() {
        let path = temp_db_path("storage_disabled_skips_db_writes");
        let storage = Storage::open(&StorageConfig {
            enabled: false,
            db_path: path.clone(),
            store_raw_diff: false,
            store_raw_llm: false,
            verify_max_previous_findings: 30,
        })
        .unwrap();

        assert!(storage.is_none());
        assert!(!path.exists());
    }

    #[test]
    fn raw_diff_and_llm_are_not_stored_by_default() {
        let path = temp_db_path("raw_diff_and_llm_are_not_stored_by_default");
        let mut storage = Storage::open_path(&path).unwrap();
        storage
            .persist_review_run(&context(), &config(path), &preview_with_findings())
            .unwrap();

        let flags: (i64, i64) = storage
            .conn
            .query_row(
                "SELECT raw_diff_stored, raw_llm_stored FROM review_runs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(flags, (0, 0));
    }

    #[test]
    fn storage_failure_warning_does_not_fail_best_effort_open() {
        let dir = temp_dir("storage_failure_warning_does_not_fail_best_effort_open");
        let file_parent = dir.join("not_a_directory");
        fs::write(&file_parent, "file").unwrap();
        let (_storage, outcome) = Storage::open_best_effort(&StorageConfig {
            enabled: true,
            db_path: file_parent.join("reviewgate.sqlite"),
            store_raw_diff: false,
            store_raw_llm: false,
            verify_max_previous_findings: 30,
        });

        assert!(outcome.warning.is_some());
    }

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn inline_result(finding_id: &str, status: InlinePublishStatus) -> InlinePublishResult {
        InlinePublishResult {
            finding_id: finding_id.to_string(),
            title: "title".to_string(),
            severity: Severity::High,
            file_path: Some("src/paymentClient.ts".to_string()),
            line: Some(11),
            status,
            discussion_id: Some("discussion-1".to_string()),
            note_id: Some(10),
            error: None,
        }
    }

    fn config(path: PathBuf) -> AppConfig {
        AppConfig {
            gitlab_token: Some("token".to_string()),
            gitlab_token_source: Some(GitLabTokenSource::GitLabToken),
            gitlab_base_url: None,
            llm: LlmConfig {
                provider: "gemini_cli".to_string(),
                ollama_base_url: "http://localhost:11434".to_string(),
                model: "gemini-2.5-pro".to_string(),
                timeout_seconds: 180,
                max_context_tokens: 12000,
                temperature: 0.1,
                codex_timeout_seconds: 240,
                codex_bin: "codex".to_string(),
                codex_full_auto: false,
                gemini_timeout_seconds: 240,
                gemini_bin: "gemini".to_string(),
                gemini_output_format: "json".to_string(),
            },
            privacy: PrivacyConfig {
                local_only: false,
                redact_secrets: true,
            },
            review: ReviewConfig {
                max_inline_comments: 8,
                severity_threshold: "medium".to_string(),
                max_diff_bytes: 200_000,
                max_files: 50,
            },
            inline: InlineConfig {
                enabled: false,
                dry_run: true,
                dedupe: true,
                max_inline_total: 10,
                max_high_inline: 8,
                max_medium_inline: 5,
            },
            publish: PublishConfig {
                max_note_chars: 60_000,
                internal_note: false,
            },
            storage: StorageConfig {
                enabled: true,
                db_path: path,
                store_raw_diff: false,
                store_raw_llm: false,
                verify_max_previous_findings: 30,
            },
            ci: CiConfig {
                allow_ci_job_token: false,
                history_required: false,
            },
        }
    }

    fn context() -> crate::gitlab::context::MergeRequestContext {
        crate::gitlab::context::build_merge_request_context(
            GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59")
                .unwrap(),
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
                changes_count: Some("1".to_string()),
                diff_refs: Some(DiffRefs {
                    base_sha: Some("base123".to_string()),
                    start_sha: Some("start123".to_string()),
                    head_sha: Some("head123".to_string()),
                }),
            },
            vec![crate::gitlab::types::MergeRequestDiff {
                old_path: "src/paymentClient.ts".to_string(),
                new_path: "src/paymentClient.ts".to_string(),
                diff: "@@ -10,2 +10,2 @@\n context\n+Authorization: Bearer token".to_string(),
                new_file: false,
                renamed_file: false,
                deleted_file: false,
                generated_file: None,
                collapsed: None,
                too_large: None,
            }],
            &ReviewConfig {
                max_inline_comments: 8,
                severity_threshold: "medium".to_string(),
                max_diff_bytes: 200_000,
                max_files: 50,
            },
            true,
        )
    }

    fn preview_with_findings() -> ReviewPreview {
        ReviewPreview {
            markdown: "# ReviewGate AI Code Review".to_string(),
            metadata: crate::llm::types::LlmRunMetadata::default(),
            prompt_token_estimate: 10,
            parsed: true,
            analysis: Some(ReviewAnalysis {
                summary: "summary".to_string(),
                findings: vec![
                    ReviewFinding {
                        severity: Severity::High,
                        category: ReviewCategory::Privacy,
                        risk_code: Some(RiskCode::PiiOrSecretLogging),
                        anchor_id: Some("A0002".to_string()),
                        file_path: Some("src/paymentClient.ts".to_string()),
                        line: Some(11),
                        title: "Authorization header is logged".to_string(),
                        body: "body".to_string(),
                        suggested_fix: Some("fix".to_string()),
                        effort: Effort::Quick,
                        actionable: true,
                    },
                    ReviewFinding {
                        severity: Severity::Note,
                        category: ReviewCategory::TestCoverage,
                        risk_code: Some(RiskCode::PositiveNote),
                        anchor_id: None,
                        file_path: Some("src/paymentClient.ts".to_string()),
                        line: Some(11),
                        title: "Positive note".to_string(),
                        body: "body".to_string(),
                        suggested_fix: None,
                        effort: Effort::Quick,
                        actionable: false,
                    },
                ],
                test_coverage_note: None,
                privacy_note: None,
                overall_risk: OverallRisk::High,
            }),
        }
    }

    fn temp_db_path(name: &str) -> PathBuf {
        temp_dir(name).join("reviewgate.sqlite")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("reviewgate-{name}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
