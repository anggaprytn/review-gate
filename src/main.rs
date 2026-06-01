use clap::Parser;
use reviewgate::cli::{Cli, Commands, VerifyArgs};
use reviewgate::config::AppConfig;
use reviewgate::error::Result;
use reviewgate::gitlab::client::GitLabClient;
use reviewgate::gitlab::context::{build_merge_request_context, MergeRequestContext};
use reviewgate::gitlab::inline::InlinePublishReport;
use reviewgate::gitlab::inline::{format_inline_publish_report, publish_inline_comments_with};
use reviewgate::gitlab::publish::{
    build_summary_note_body, build_verification_note_body, publish_summary_with,
};
use reviewgate::gitlab::types::{DiffRefs, PublishAction, PublishResult};
use reviewgate::gitlab::url::GitLabMrUrl;
use reviewgate::llm::types::LlmRunMetadata;
use reviewgate::llm::{
    auth_label, external_model_call_label, payload_label, provider_local_only, review_with_config,
};
use reviewgate::review::engine::{
    build_sanitized_review_prompt, review_prompt_with_llm, ReviewPreview,
};
use reviewgate::review::inline::{
    format_inline_dry_run_report, resolve_inline_candidates_with_anchors,
};
use reviewgate::storage::{PersistedReviewRun, Storage};
use reviewgate::verify::{
    no_previous_run_message, verification_prompt_with_llm, VerificationPreview,
};

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Review(args) => {
            args.validate()?;
            let publish_inline = args.publishes_inline()?;
            let mr = GitLabMrUrl::parse(&args.mr_url)?;
            let config = AppConfig::load()?;
            if args.calls_llm() {
                config.validate_for_preview()?;
            }
            let (mut storage, storage_open) = if args.calls_llm() {
                Storage::open_best_effort(&config.storage)
            } else {
                (
                    None,
                    reviewgate::storage::StorageOpenOutcome {
                        enabled: config.storage.enabled,
                        db_path: config.storage.db_path.clone(),
                        warning: None,
                    },
                )
            };
            print_storage_open_warning(&storage_open);
            let gitlab = GitLabClient::new(mr.base_url.clone(), config.gitlab_token.clone())?;
            let metadata = gitlab.fetch_merge_request(&mr).await?;
            let diffs = gitlab.fetch_merge_request_diffs(&mr).await?;
            let context = build_merge_request_context(
                mr,
                metadata,
                diffs.clone(),
                &config.review,
                config.privacy.redact_secrets,
            );
            let inline_dry_run = args.inline_dry_run;

            if args.dry_run {
                print_dry_run_summary(&context);
            } else if args.publish {
                publish_review(
                    &gitlab,
                    &context,
                    &diffs,
                    &config,
                    args.force_new_note,
                    args.internal_note,
                    publish_inline,
                    inline_dry_run,
                    &mut storage,
                )
                .await?;
            } else {
                print_preview(
                    &context,
                    &diffs,
                    &config,
                    args.show_prompt,
                    inline_dry_run,
                    &mut storage,
                )
                .await?;
            }
        }
        Commands::Verify(args) => {
            let publish = args.publishes();
            verify_merge_request(args, publish).await?;
        }
    }

    Ok(())
}

async fn publish_review(
    gitlab: &GitLabClient,
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
    force_new_note: bool,
    internal_note_flag: bool,
    publish_inline: bool,
    inline_dry_run: bool,
    storage: &mut Option<Storage>,
) -> Result<()> {
    let preview = generate_preview(context, config, false).await?;
    if !preview.parsed {
        return Err(reviewgate::error::ReviewGateError::PublishRequiresParsedReview);
    }
    let persisted = persist_review_run_best_effort(storage, context, config, &preview);

    let body = build_summary_note_body(
        &preview.markdown,
        &context.mr_url.project_path,
        context.metadata.iid,
        &format!("{}/{}", config.llm.provider, config.llm.model),
        provider_local_only(&config.llm),
        external_model_call_label(&config.llm),
        head_sha(context),
        inline_summary_label(publish_inline, inline_dry_run),
        config.publish.max_note_chars,
    )?;

    println!("{body}");

    let internal_note = internal_note_flag || config.publish.internal_note;
    let result = publish_summary_with(body, |body| async move {
        gitlab
            .publish_merge_request_summary(&context.mr_url, body, force_new_note, internal_note)
            .await
    })
    .await?;
    if let Some(persisted) = persisted.as_ref() {
        update_summary_publish_best_effort(storage, &persisted.id, &result);
    }

    print_publish_result(&result, publish_inline, inline_dry_run);
    if inline_dry_run {
        print_inline_dry_run_report(&preview, context, diffs, config);
    } else if publish_inline {
        if !has_complete_diff_refs(context.metadata.diff_refs.as_ref()) {
            return Err(reviewgate::error::ReviewGateError::MissingGitLabDiffRefs);
        }
        let report =
            publish_inline_review_comments(gitlab, &preview, context, diffs, config).await?;
        if let Some(persisted) = persisted.as_ref() {
            update_inline_publish_best_effort(
                storage,
                &persisted.id,
                &persisted.finding_ids,
                &report,
            );
        }
    }
    print_persisted_review_run(storage, persisted.as_ref());

    Ok(())
}

async fn publish_inline_review_comments(
    gitlab: &GitLabClient,
    preview: &ReviewPreview,
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
) -> Result<InlinePublishReport> {
    let Some(analysis) = preview.analysis.as_ref() else {
        return Err(reviewgate::error::ReviewGateError::PublishRequiresParsedReview);
    };
    let candidates = resolve_inline_candidates_with_anchors(
        analysis,
        diffs,
        Some(&context.anchored_diff),
        context.metadata.diff_refs.as_ref(),
        &config.inline,
    );

    let report = publish_inline_comments_with(
        &context.mr_url,
        &candidates,
        &analysis.findings,
        &config.inline,
        || async { gitlab.list_merge_request_discussions(&context.mr_url).await },
        |request| async move {
            gitlab
                .create_merge_request_discussion(&context.mr_url, &request)
                .await
        },
    )
    .await?;

    println!();
    if report.eligible_count() == 0 {
        println!("No eligible inline comments to publish. Summary note was still published.");
    }
    println!("{}", format_inline_publish_report(&report));

    Ok(report)
}

fn print_dry_run_summary(context: &MergeRequestContext) {
    println!("ReviewGate dry run");
    println!();
    print_mr_summary(context);
    print_diff_summary(context);
    print_file_summary(context);
    print_warnings(context);
    println!("Status:");
    println!("GitLab reachable: yes");
    println!("Token valid: yes");
    println!("Diff fetched: yes");
    println!("LLM call: skipped in dry-run");
    println!("Publish: skipped");
}

async fn print_preview(
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
    show_prompt: bool,
    inline_dry_run: bool,
    storage: &mut Option<Storage>,
) -> Result<()> {
    let preview = generate_preview(context, config, show_prompt).await?;

    println!("{}", preview.markdown);
    print_run_metadata(
        config,
        &preview.metadata,
        preview.prompt_token_estimate,
        preview.parsed,
    );
    if inline_dry_run {
        print_inline_dry_run_report(&preview, context, diffs, config);
    }
    let persisted = persist_review_run_best_effort(storage, context, config, &preview);
    print_persisted_review_run(storage, persisted.as_ref());

    Ok(())
}

async fn generate_preview(
    context: &MergeRequestContext,
    config: &AppConfig,
    show_prompt: bool,
) -> Result<ReviewPreview> {
    let prompt = build_sanitized_review_prompt(context);
    if show_prompt {
        println!("ReviewGate sanitized prompt");
        println!("===========================");
        println!("{prompt}");
        println!("===========================");
        println!();
    }

    let llm_config = config.llm.clone();
    let preview = review_prompt_with_llm(prompt, move |prompt| async move {
        review_with_config(&llm_config, &prompt).await
    })
    .await?;

    Ok(preview)
}

fn print_mr_summary(context: &MergeRequestContext) {
    println!("Provider: GitLab");
    println!("Base URL: {}", context.mr_url.base_url);
    println!("Project: {}", context.mr_url.project_path);
    println!("MR: !{}", context.metadata.iid);
    println!("Title: {}", context.metadata.title);
    println!("State: {}", context.metadata.state);
    if let Some(draft) = context.metadata.draft {
        println!("Draft: {}", yes_no(draft));
    }
    println!("Source: {}", context.metadata.source_branch);
    println!("Target: {}", context.metadata.target_branch);
    println!("Head SHA: {}", head_sha(context));
    if let Some(author) = author_label(context) {
        println!("Author: {author}");
    }
    if let Some(status) = context.metadata.detailed_merge_status.as_deref() {
        println!("Merge status: {status}");
    }
    println!();
}

fn print_diff_summary(context: &MergeRequestContext) {
    println!("Diff summary:");
    println!("Changed files: {}", context.stats.changed_file_count);
    println!(
        "Generated files skipped: {}",
        context.stats.generated_file_count
    );
    println!("Collapsed files: {}", context.stats.collapsed_file_count);
    println!("Too large files: {}", context.stats.too_large_file_count);
    println!(
        "Approx added lines: {}",
        context.stats.approximate_added_lines
    );
    println!(
        "Approx removed lines: {}",
        context.stats.approximate_removed_lines
    );
    println!(
        "Diff bytes after redaction: {}",
        context.stats.total_diff_bytes
    );
    if context.partial {
        println!("Partial review warning: some diff content was omitted");
    }
    println!();
}

fn print_file_summary(context: &MergeRequestContext) {
    println!("Files:");
    if context.files.is_empty() {
        println!("- no reviewable diff content");
    } else {
        for file in &context.files {
            let marker = if file.renamed_file {
                " renamed"
            } else if file.new_file {
                " new"
            } else if file.deleted_file {
                " deleted"
            } else {
                ""
            };
            println!(
                "- {} (+{} -{}){}",
                file.new_path, file.added_lines, file.removed_lines, marker
            );
        }
    }
    println!();
}

fn print_warnings(context: &MergeRequestContext) {
    if context.warnings.is_empty() {
        return;
    }

    println!("Warnings:");
    for warning in &context.warnings {
        println!("- {warning}");
    }
    println!();
}

fn head_sha(context: &MergeRequestContext) -> &str {
    context
        .metadata
        .diff_refs
        .as_ref()
        .and_then(|refs| refs.head_sha.as_deref())
        .unwrap_or(&context.metadata.sha)
}

fn author_label(context: &MergeRequestContext) -> Option<String> {
    let author = context.metadata.author.as_ref()?;
    match (author.name.as_deref(), author.username.as_deref()) {
        (Some(name), Some(username)) => Some(format!("{name} (@{username})")),
        (Some(name), None) => Some(name.to_string()),
        (None, Some(username)) => Some(format!("@{username}")),
        (None, None) => None,
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn print_run_metadata(
    config: &AppConfig,
    metadata: &LlmRunMetadata,
    prompt_token_estimate: u64,
    parsed: bool,
) {
    println!();
    println!("ReviewGate run metadata:");
    println!("Provider: GitLab");
    println!("LLM: {}/{}", config.llm.provider, config.llm.model);
    if let Some(auth) = auth_label(&config.llm) {
        println!("Auth: {auth}");
    }
    println!("Local-only: {}", provider_local_only(&config.llm));
    println!(
        "External model call: {}",
        external_model_call_label(&config.llm)
    );
    println!("Payload: {}", payload_label(&config.llm));
    match metadata.prompt_eval_count {
        Some(tokens) => println!("Prompt tokens: {tokens}"),
        None => println!("Prompt tokens: ~{prompt_token_estimate}"),
    }
    match metadata.eval_count {
        Some(tokens) => println!("Completion tokens: {tokens}"),
        None => println!("Completion tokens: unavailable"),
    }
    if let Some(total_duration) = metadata.total_duration {
        println!(
            "Review duration: {}",
            format_ollama_duration(total_duration)
        );
    }
    println!(
        "Structured JSON: {}",
        if parsed { "parsed" } else { "fallback" }
    );
    println!("Publish: skipped");
}

fn print_publish_result(result: &PublishResult, publish_inline: bool, inline_dry_run: bool) {
    println!();
    println!("Publish result:");
    println!(
        "Action: {}",
        match result.action {
            PublishAction::Created => "created",
            PublishAction::Updated => "updated",
        }
    );
    match result.note_id {
        Some(note_id) => println!("GitLab note ID: {note_id}"),
        None => println!("GitLab note ID: unavailable"),
    }
    if let Some(web_url) = result.web_url.as_deref() {
        println!("GitLab note URL: {web_url}");
    }
    println!(
        "Duplicate ReviewGate notes found: {}",
        result.duplicate_count
    );
    if result.duplicate_count > 1 {
        println!(
            "Warning: multiple ReviewGate summary notes were found; updated the most recently updated one"
        );
    }
    let inline_status = if inline_dry_run {
        "dry-run only"
    } else if publish_inline {
        "publishing enabled"
    } else {
        "skipped"
    };
    println!("Inline comments: {inline_status}");
}

fn print_inline_dry_run_report(
    preview: &ReviewPreview,
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
) {
    let candidates = preview
        .analysis
        .as_ref()
        .map(|analysis| {
            resolve_inline_candidates_with_anchors(
                analysis,
                diffs,
                Some(&context.anchored_diff),
                context.metadata.diff_refs.as_ref(),
                &config.inline,
            )
        })
        .unwrap_or_default();

    println!();
    println!("{}", format_inline_dry_run_report(&candidates));
}

fn format_ollama_duration(nanoseconds: u64) -> String {
    let seconds = nanoseconds as f64 / 1_000_000_000.0;
    format!("{seconds:.2}s")
}

fn has_complete_diff_refs(diff_refs: Option<&DiffRefs>) -> bool {
    let Some(diff_refs) = diff_refs else {
        return false;
    };
    has_sha(diff_refs.base_sha.as_deref())
        && has_sha(diff_refs.start_sha.as_deref())
        && has_sha(diff_refs.head_sha.as_deref())
}

fn has_sha(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|value| !value.is_empty())
}

fn inline_summary_label(publish_inline: bool, inline_dry_run: bool) -> &'static str {
    if inline_dry_run {
        "dry-run only"
    } else if publish_inline {
        "publishing enabled"
    } else {
        "disabled"
    }
}

async fn verify_merge_request(args: VerifyArgs, publish: bool) -> Result<()> {
    let mr = GitLabMrUrl::parse(&args.mr_url)?;
    let config = AppConfig::load()?;
    config.validate_for_preview()?;

    let mut storage = match Storage::open(&config.storage)? {
        Some(storage) => storage,
        None => {
            println!("{}", no_previous_run_message());
            return Ok(());
        }
    };

    let gitlab = GitLabClient::new(mr.base_url.clone(), config.gitlab_token.clone())?;
    let metadata = gitlab.fetch_merge_request(&mr).await?;
    let diffs = gitlab.fetch_merge_request_diffs(&mr).await?;
    let context = build_merge_request_context(
        mr,
        metadata,
        diffs,
        &config.review,
        config.privacy.redact_secrets,
    );

    let Some(previous_run) =
        storage.latest_completed_review_run(&context.mr_url.project_path, context.metadata.iid)?
    else {
        println!("{}", no_previous_run_message());
        return Ok(());
    };

    let previous_findings = storage.previous_findings_for_verification(
        &previous_run.id,
        config.storage.verify_max_previous_findings,
    )?;
    if previous_findings.is_empty() {
        println!("No previous CRITICAL, HIGH, or MEDIUM ReviewGate findings found for this MR.");
        return Ok(());
    }

    let llm_label = format!("{}/{}", config.llm.provider, config.llm.model);
    let publish_mode = if publish {
        "verification summary note"
    } else {
        "preview"
    };
    let llm_config = config.llm.clone();
    let preview = verification_prompt_with_llm(
        &context,
        &previous_findings,
        &llm_label,
        publish_mode,
        &previous_run.id,
        move |prompt| async move { review_with_config(&llm_config, &prompt).await },
    )
    .await?;

    println!("{}", preview.markdown);
    print_verification_run_metadata(&config, &preview);

    let persisted = storage.persist_verification_run(
        &context,
        &config,
        Some(&previous_run.id),
        &preview.outcome,
    )?;
    println!(
        "Storage: verification run stored in {} (run ID: {})",
        storage.db_path().display(),
        persisted.id
    );

    if publish {
        let body = build_verification_note_body(
            &preview.markdown,
            &context.mr_url.project_path,
            context.metadata.iid,
            config.publish.max_note_chars,
        )?;
        let result = publish_summary_with(body, |body| async move {
            gitlab
                .publish_merge_request_verification(
                    &context.mr_url,
                    body,
                    args.force_new_note,
                    config.publish.internal_note,
                )
                .await
        })
        .await?;
        storage.update_verification_publish(&persisted.id, &result)?;
        print_verification_publish_result(&result);
    }

    Ok(())
}

fn persist_review_run_best_effort(
    storage: &mut Option<Storage>,
    context: &MergeRequestContext,
    config: &AppConfig,
    preview: &ReviewPreview,
) -> Option<PersistedReviewRun> {
    let Some(storage) = storage.as_mut() else {
        return None;
    };

    match storage.persist_review_run(context, config, preview) {
        Ok(persisted) => Some(persisted),
        Err(err) => {
            eprintln!("warning: storage failed; review will continue: {err}");
            None
        }
    }
}

fn update_summary_publish_best_effort(
    storage: &mut Option<Storage>,
    run_id: &str,
    result: &PublishResult,
) {
    let Some(storage) = storage.as_mut() else {
        return;
    };
    if let Err(err) = storage.update_summary_publish(run_id, result) {
        eprintln!("warning: storage failed; review will continue: {err}");
    }
}

fn update_inline_publish_best_effort(
    storage: &mut Option<Storage>,
    run_id: &str,
    finding_ids: &[String],
    report: &InlinePublishReport,
) {
    let Some(storage) = storage.as_mut() else {
        return;
    };
    if let Err(err) = storage.update_inline_publish(run_id, finding_ids, report) {
        eprintln!("warning: storage failed; review will continue: {err}");
    }
}

fn print_persisted_review_run(storage: &Option<Storage>, persisted: Option<&PersistedReviewRun>) {
    let (Some(storage), Some(persisted)) = (storage.as_ref(), persisted) else {
        return;
    };
    println!(
        "Storage: review run stored in {} (run ID: {})",
        storage.db_path().display(),
        persisted.id
    );
}

fn print_storage_open_warning(outcome: &reviewgate::storage::StorageOpenOutcome) {
    if let Some(warning) = outcome.warning.as_deref() {
        eprintln!("warning: storage unavailable; review will continue without history: {warning}");
    }
}

fn print_verification_run_metadata(config: &AppConfig, preview: &VerificationPreview) {
    println!();
    println!("ReviewGate verification metadata:");
    println!("LLM: {}/{}", config.llm.provider, config.llm.model);
    match preview.metadata.prompt_eval_count {
        Some(tokens) => println!("Prompt tokens: {tokens}"),
        None => println!("Prompt tokens: ~{}", preview.prompt_token_estimate),
    }
    match preview.metadata.eval_count {
        Some(tokens) => println!("Completion tokens: {tokens}"),
        None => println!("Completion tokens: unavailable"),
    }
    println!(
        "Structured JSON: {}",
        if preview.outcome.parsed {
            "parsed"
        } else {
            "fallback"
        }
    );
}

fn print_verification_publish_result(result: &PublishResult) {
    println!();
    println!("Verification publish result:");
    println!(
        "Action: {}",
        match result.action {
            PublishAction::Created => "created",
            PublishAction::Updated => "updated",
        }
    );
    match result.note_id {
        Some(note_id) => println!("GitLab verification note ID: {note_id}"),
        None => println!("GitLab verification note ID: unavailable"),
    }
    println!(
        "Duplicate ReviewGate verification notes found: {}",
        result.duplicate_count
    );
    println!("Inline verification comments: skipped");
}
