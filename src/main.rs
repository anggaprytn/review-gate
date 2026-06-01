use clap::Parser;
use reviewgate::cli::{
    exit_code_for_result, Cli, Commands, ContextArgs, FindingsArgs, FixPromptArgs, PlanArgs,
    ReviewArgs, VerifyArgs,
};
use reviewgate::config::AppConfig;
use reviewgate::counters::{
    count_findings_from_analysis, count_verification_results, emoji_enabled,
    format_finding_counters_terminal, format_verification_counters_terminal,
};
use reviewgate::doctor::{run_doctor, DoctorOptions};
use reviewgate::error::Result;
use reviewgate::fix_prompt::{
    build_fix_prompt, copy_to_clipboard, effective_min_severity, format_findings_summary,
    latest_findings_summary, write_prompt_output, FixPromptFormat, FixPromptOptions,
};
use reviewgate::gitlab::ci::{CiContextError, GitLabCiContext};
use reviewgate::gitlab::client::GitLabClient;
use reviewgate::gitlab::context::{build_merge_request_context, MergeRequestContext};
use reviewgate::gitlab::inline::InlinePublishReport;
use reviewgate::gitlab::inline::{format_inline_publish_report, publish_inline_comments_with};
use reviewgate::gitlab::publish::{
    build_summary_note_body, build_verification_note_body, publish_summary_with,
};
use reviewgate::gitlab::types::{DiffRefs, PublishAction, PublishResult};
use reviewgate::gitlab::url::GitLabMrUrl;
use reviewgate::llm::types::LlmProvider;
use reviewgate::llm::types::LlmRunMetadata;
use reviewgate::llm::{
    auth_label, external_model_call_label, payload_label, provider_local_only, review_with_config,
};
use reviewgate::plan::{build_review_plan, format_review_plan, PlanOptions};
use reviewgate::review::comparison::{
    compare_current_run_with_previous, format_comparison_terminal_default,
    insert_comparison_section, ReviewComparison,
};
use reviewgate::review::engine::{
    build_sanitized_review_prompt, review_prompt_with_llm_for_mode, ReviewPreview,
};
use reviewgate::review::formatter::MarkdownRenderMode;
use reviewgate::review::inline::{
    format_inline_dry_run_report, resolve_inline_candidates_with_anchors,
};
use reviewgate::review::large::{
    build_large_review_plan, review_large_chunks_with_llm, selected_diffs_in_order,
    validate_large_inline_mapping, LargeReviewOptions,
};
use reviewgate::review::mode::{
    build_auto_review_plan, decide_auto_review_mode, AutoLargeOptions, AutoReviewDecision,
    ReviewMode, SelectedReviewMode,
};
use reviewgate::storage::{PersistedReviewRun, Storage};
use reviewgate::verify::{
    no_previous_run_message, verification_prompt_with_llm, VerificationPreview,
};

#[tokio::main]
async fn main() {
    let exit_code = run().await;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

async fn run() -> i32 {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    let soft_fail = cli.soft_fail();

    match run_command(cli).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            exit_code_for_result(true, soft_fail)
        }
    }
}

async fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Plan(args) => run_plan(args).await?,
        Commands::Review(args) => run_review(args).await?,
        Commands::Verify(args) => {
            let publish = args.publishes();
            verify_merge_request(args, publish).await?;
        }
        Commands::FixPrompt(args) => run_fix_prompt(args)?,
        Commands::Findings(args) => run_findings(args)?,
        Commands::Doctor(args) => {
            let output = run_doctor(DoctorOptions {
                network: args.network,
            })
            .await?;
            print!("{output}");
        }
        Commands::Context(args) => run_context(args).await?,
    }

    Ok(())
}

async fn run_context(args: ContextArgs) -> Result<()> {
    let mr_url = resolve_mr_url(args.ci, args.mr_url.as_deref(), false)?;
    let mr = GitLabMrUrl::parse(&mr_url)?;
    let config = AppConfig::load()?;
    let gitlab = GitLabClient::new_with_token_source(
        mr.base_url.clone(),
        config.gitlab_token.clone(),
        config.gitlab_token_source,
    )?;
    let metadata = gitlab.fetch_merge_request(&mr).await?;
    let diffs = gitlab.fetch_merge_request_diffs(&mr).await?;

    let context = build_merge_request_context(
        mr,
        metadata,
        diffs,
        &config.review,
        config.privacy.redact_secrets,
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&context)?);
    } else {
        print_mr_summary(&context);
        print_diff_summary(&context);
        print_file_summary(&context);
        print_warnings(&context);
    }
    Ok(())
}

async fn run_plan(args: PlanArgs) -> Result<()> {
    let mr_url = resolve_mr_url(args.ci, args.mr_url.as_deref(), false)?;
    let mr = GitLabMrUrl::parse(&mr_url)?;
    let config = AppConfig::load()?;
    let gitlab = GitLabClient::new_with_token_source(
        mr.base_url.clone(),
        config.gitlab_token.clone(),
        config.gitlab_token_source,
    )?;
    let metadata = gitlab.fetch_merge_request(&mr).await?;
    let diffs = gitlab.fetch_merge_request_diffs(&mr).await?;
    let mut options = PlanOptions::from_env();
    if let Some(max_files) = args.max_files {
        options.max_files = max_files;
    }
    if let Some(max_diff_bytes) = args.max_diff_bytes {
        options.max_diff_bytes = max_diff_bytes;
        options.large_mr_diff_bytes = max_diff_bytes;
    }
    options.include_low_risk = args.include_low_risk;

    let plan = build_review_plan(&mr, metadata, diffs, options);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print!("{}", format_review_plan(&plan));
    }
    Ok(())
}

fn run_fix_prompt(args: FixPromptArgs) -> Result<()> {
    let mr = GitLabMrUrl::parse(&args.mr_url)?;
    let config = AppConfig::load()?;
    if !config.storage.db_path.exists() {
        return Err(reviewgate::error::ReviewGateError::SqliteDbMissing(
            config.storage.db_path.display().to_string(),
        ));
    }

    let storage = Storage::open_read_only(&config.storage.db_path)?;
    let min_severity = effective_min_severity(args.min_severity.as_deref(), args.include_low)?;
    let format = FixPromptFormat::parse(&args.format)?;
    let generated = build_fix_prompt(
        &storage,
        &mr,
        FixPromptOptions {
            run_id: args.run_id,
            min_severity,
            include_notes: args.include_notes,
            format,
        },
    )?;

    if let Some(output) = args.output.as_deref() {
        write_prompt_output(output, &generated.prompt, args.force)?;
    }

    print!("{}", generated.prompt);

    if args.copy {
        copy_to_clipboard(&generated.prompt)?;
    }

    Ok(())
}

fn run_findings(args: FindingsArgs) -> Result<()> {
    let mr = GitLabMrUrl::parse(&args.mr_url)?;
    let config = AppConfig::load()?;
    if !config.storage.db_path.exists() {
        return Err(reviewgate::error::ReviewGateError::SqliteDbMissing(
            config.storage.db_path.display().to_string(),
        ));
    }

    let storage = Storage::open_read_only(&config.storage.db_path)?;
    let summary = latest_findings_summary(&storage, &mr)?;
    print!("{}", format_findings_summary(&summary));
    Ok(())
}

async fn run_review(args: ReviewArgs) -> Result<()> {
    args.validate()?;
    let publish_inline = args.publishes_inline()?;
    let mr_url = resolve_mr_url(args.ci, args.mr_url.as_deref(), args.allow_non_mr_ci)?;
    let mr = GitLabMrUrl::parse(&mr_url)?;
    let config = AppConfig::load()?;
    if args.ci {
        let ci_mode = if args.dry_run {
            "dry-run, no LLM call or GitLab note publishing"
        } else if args.publish {
            "summary note publishing enabled"
        } else {
            "preview, no GitLab note publishing"
        };
        print_ci_guidance(&config, ci_mode);
    }
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
    let gitlab = GitLabClient::new_with_token_source(
        mr.base_url.clone(),
        config.gitlab_token.clone(),
        config.gitlab_token_source,
    )?;
    let metadata = gitlab.fetch_merge_request(&mr).await?;
    let diffs = gitlab.fetch_merge_request_diffs(&mr).await?;
    let review_mode = args.effective_review_mode()?;
    let selected_review_mode = match review_mode {
        ReviewMode::Auto => {
            let auto_options = AutoLargeOptions::from_env();
            let auto_plan =
                build_auto_review_plan(&mr, metadata.clone(), diffs.clone(), auto_options);
            let decision = decide_auto_review_mode(&auto_plan, auto_options);
            print_auto_review_decision(&decision);
            decision.selected
        }
        ReviewMode::Single => SelectedReviewMode::SinglePass,
        ReviewMode::Large => SelectedReviewMode::Large,
    };

    if selected_review_mode == SelectedReviewMode::Large {
        run_large_review(args, mr, metadata, diffs, config, gitlab, &mut storage).await?;
        return Ok(());
    }

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
            PublishOptions {
                force_new_note: args.force_new_note,
                internal_note_flag: args.internal_note,
                publish_inline,
                inline_dry_run,
                large_review: false,
            },
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

    Ok(())
}

fn resolve_mr_url(ci: bool, mr_url: Option<&str>, allow_non_mr_ci: bool) -> Result<String> {
    if ci {
        match GitLabCiContext::from_env(allow_non_mr_ci) {
            Ok(context) => {
                println!("ReviewGate CI mode");
                println!("Inferred MR URL: {}", context.mr_url);
                Ok(context.mr_url)
            }
            Err(reviewgate::error::ReviewGateError::CiContext(
                CiContextError::NotMergeRequestPipeline { source },
            )) => {
                eprintln!(
                    "Warning: GitLab CI pipeline source is '{source}', not 'merge_request_event'. ReviewGate CI mode fails closed unless --allow-non-mr-ci is passed."
                );
                Err(CiContextError::NotMergeRequestPipeline { source }.into())
            }
            Err(err) => Err(err),
        }
    } else {
        Ok(mr_url
            .expect("clap requires MR_URL when --ci is not present")
            .to_string())
    }
}

fn print_ci_guidance(config: &AppConfig, mode: &str) {
    if matches!(
        LlmProvider::parse(&config.llm.provider),
        Ok(LlmProvider::GeminiCli | LlmProvider::CodexCli)
    ) {
        eprintln!(
            "Warning: gemini_cli/codex_cli may require cached interactive auth. For CI, prefer ollama inside the network or a future direct API provider."
        );
    }

    println!(
        "CI storage: {} is local to this job unless persisted as an artifact or cache.",
        config.storage.db_path.display()
    );
    println!(
        "CI verification history: verify --ci requires previous ReviewGate history in the job workspace, cache, or artifact."
    );
    println!("CI mode: {mode}.");
}

#[derive(Debug, Clone, Copy)]
struct PublishOptions {
    force_new_note: bool,
    internal_note_flag: bool,
    publish_inline: bool,
    inline_dry_run: bool,
    large_review: bool,
}

async fn run_large_review(
    args: ReviewArgs,
    mr: GitLabMrUrl,
    metadata: reviewgate::gitlab::types::MergeRequestMetadata,
    diffs: Vec<reviewgate::gitlab::types::MergeRequestDiff>,
    config: AppConfig,
    gitlab: GitLabClient,
    storage: &mut Option<Storage>,
) -> Result<()> {
    let publish_inline = args.publishes_inline()?;
    let mut large_options = LargeReviewOptions::from_env();
    large_options.include_low_risk = large_options.include_low_risk || args.include_low_risk;

    let mut plan_options = PlanOptions::from_env();
    plan_options.max_files = large_options.max_chunks * large_options.max_files_per_chunk;
    plan_options.max_diff_bytes = large_options.max_chunks * large_options.max_diff_bytes_per_chunk;
    plan_options.large_mr_diff_bytes = plan_options.max_diff_bytes;
    plan_options.include_low_risk = large_options.include_low_risk;

    let review_plan = build_review_plan(&mr, metadata.clone(), diffs.clone(), plan_options);
    let anchor_review_config = review_config_for_large_anchors(&config, &diffs);
    let context = build_merge_request_context(
        mr,
        metadata,
        diffs.clone(),
        &anchor_review_config,
        config.privacy.redact_secrets,
    );
    let large_plan = build_large_review_plan(
        &review_plan,
        &diffs,
        &context.anchored_diff,
        large_options,
        args.include_low_risk,
    )?;
    let selected_diffs = selected_diffs_in_order(&diffs, &large_plan.selection.files);

    print_large_review_plan(
        &large_plan,
        &config,
        review_mode_label(args.publish, publish_inline, args.dry_run),
    );

    if args.dry_run {
        println!("LLM call: skipped in dry-run");
        println!("Publish: skipped");
        return Ok(());
    }

    let llm_config = config.llm.clone();
    let render_mode = if args.publish {
        MarkdownRenderMode::Publish
    } else {
        MarkdownRenderMode::Preview
    };
    let preview = review_large_chunks_with_llm(
        &context.metadata,
        &large_plan.chunks,
        &large_plan.selection,
        render_mode,
        args.show_prompt,
        |chunk, total| {
            println!(
                "Reviewing chunk {}/{}: {} files, {}KB",
                chunk.index,
                total,
                chunk.files.len(),
                chunk.diff_bytes.div_ceil(1024)
            );
        },
        move |prompt| {
            let llm_config = llm_config.clone();
            async move { review_with_config(&llm_config, &prompt).await }
        },
    )
    .await?;

    if args.publish {
        publish_review_preview(
            &gitlab,
            &context,
            &selected_diffs,
            &config,
            PublishOptions {
                force_new_note: args.force_new_note,
                internal_note_flag: args.internal_note,
                publish_inline,
                inline_dry_run: args.inline_dry_run,
                large_review: true,
            },
            storage,
            preview,
        )
        .await?;
    } else {
        let mut preview = preview;
        let (persisted, comparison) =
            persist_review_run_and_apply_comparison(storage, &context, &config, &mut preview);
        println!("{}", preview.markdown);
        print_finding_counters(&preview);
        print_review_comparison(comparison.as_ref());
        print_run_metadata(
            &config,
            &preview.metadata,
            preview.prompt_token_estimate,
            preview.parsed,
        );
        if args.inline_dry_run {
            print_inline_dry_run_report(&preview, &context, &selected_diffs, &config);
        }
        print_persisted_review_run(storage, persisted.as_ref());
    }

    Ok(())
}

async fn publish_review(
    gitlab: &GitLabClient,
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
    options: PublishOptions,
    storage: &mut Option<Storage>,
) -> Result<()> {
    let preview = generate_preview(context, config, false, MarkdownRenderMode::Publish).await?;
    publish_review_preview(gitlab, context, diffs, config, options, storage, preview).await
}

async fn publish_review_preview(
    gitlab: &GitLabClient,
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
    options: PublishOptions,
    storage: &mut Option<Storage>,
    preview: ReviewPreview,
) -> Result<()> {
    if !preview.parsed {
        return Err(reviewgate::error::ReviewGateError::PublishRequiresParsedReview);
    }
    let mut preview = preview;
    let (persisted, comparison) =
        persist_review_run_and_apply_comparison(storage, context, config, &mut preview);

    let body = build_summary_note_body(
        &preview.markdown,
        &context.mr_url.project_path,
        context.metadata.iid,
        &format!("{}/{}", config.llm.provider, config.llm.model),
        provider_local_only(&config.llm),
        external_model_call_label(&config.llm),
        head_sha(context),
        inline_summary_label(options.publish_inline, options.inline_dry_run),
        config.publish.max_note_chars,
    )?;

    println!("{body}");

    let internal_note = options.internal_note_flag || config.publish.internal_note;
    let result = publish_summary_with(body, |body| async move {
        gitlab
            .publish_merge_request_summary(
                &context.mr_url,
                body,
                options.force_new_note,
                internal_note,
            )
            .await
    })
    .await?;
    if let Some(persisted) = persisted.as_ref() {
        update_summary_publish_best_effort(storage, &persisted.id, &result);
    }

    print_publish_result(&result, options.publish_inline, options.inline_dry_run);
    print_finding_counters(&preview);
    print_review_comparison(comparison.as_ref());
    if options.inline_dry_run {
        print_inline_dry_run_report(&preview, context, diffs, config);
    } else if options.publish_inline {
        if !has_complete_diff_refs(context.metadata.diff_refs.as_ref()) {
            return Err(reviewgate::error::ReviewGateError::MissingGitLabDiffRefs);
        }
        if options.large_review {
            let Some(analysis) = preview.analysis.as_ref() else {
                return Err(reviewgate::error::ReviewGateError::PublishRequiresParsedReview);
            };
            validate_large_inline_mapping(analysis, &context.anchored_diff)?;
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

fn print_large_review_plan(
    plan: &reviewgate::review::large::LargeReviewPlan,
    config: &AppConfig,
    mode: &str,
) {
    println!("Large MR review");
    println!();
    println!("Reviewable files: {}", plan.selection.files.len());
    println!("Chunks: {}", plan.chunks.len());
    println!("Skipped files: {}", plan.selection.skipped_files);
    println!("Provider: {}/{}", config.llm.provider, config.llm.model);
    println!("Mode: {mode}");
    println!();
}

fn review_mode_label(publish: bool, publish_inline: bool, dry_run: bool) -> &'static str {
    if dry_run {
        "dry-run"
    } else if publish && publish_inline {
        "publish+inline"
    } else if publish {
        "publish"
    } else {
        "preview"
    }
}

fn print_auto_review_decision(decision: &AutoReviewDecision) {
    match decision.selected {
        SelectedReviewMode::SinglePass => {
            println!("Review mode: auto -> single-pass");
            println!("Reason: MR below large-review thresholds");
        }
        SelectedReviewMode::Large => {
            println!("Review mode: auto -> large");
            println!("Reason: MR exceeds large-review threshold");
            println!("Changed files: {}", decision.changed_files);
            println!("Diff bytes: {}", decision.diff_bytes);
        }
    }
    println!();
}

fn review_config_for_large_anchors(
    config: &AppConfig,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
) -> reviewgate::config::ReviewConfig {
    let mut review_config = config.review.clone();
    review_config.max_files = diffs.len().max(1);
    review_config.max_diff_bytes = diffs
        .iter()
        .map(|diff| diff.to_unified_diff().len())
        .sum::<usize>()
        .saturating_add(1);
    review_config
}

async fn print_preview(
    context: &MergeRequestContext,
    diffs: &[reviewgate::gitlab::types::MergeRequestDiff],
    config: &AppConfig,
    show_prompt: bool,
    inline_dry_run: bool,
    storage: &mut Option<Storage>,
) -> Result<()> {
    let mut preview =
        generate_preview(context, config, show_prompt, MarkdownRenderMode::Preview).await?;
    let (persisted, comparison) =
        persist_review_run_and_apply_comparison(storage, context, config, &mut preview);

    println!("{}", preview.markdown);
    print_finding_counters(&preview);
    print_review_comparison(comparison.as_ref());
    print_run_metadata(
        config,
        &preview.metadata,
        preview.prompt_token_estimate,
        preview.parsed,
    );
    if inline_dry_run {
        print_inline_dry_run_report(&preview, context, diffs, config);
    }
    print_persisted_review_run(storage, persisted.as_ref());

    Ok(())
}

async fn generate_preview(
    context: &MergeRequestContext,
    config: &AppConfig,
    show_prompt: bool,
    mode: MarkdownRenderMode,
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
    let preview = review_prompt_with_llm_for_mode(prompt, mode, move |prompt| async move {
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
    let mr_url = resolve_mr_url(args.ci, args.mr_url.as_deref(), args.allow_non_mr_ci)?;
    let mr = GitLabMrUrl::parse(&mr_url)?;
    let config = AppConfig::load()?;
    if args.ci {
        let ci_mode = if publish {
            "verification summary note publishing enabled"
        } else {
            "verification preview, no GitLab note publishing"
        };
        print_ci_guidance(&config, ci_mode);
    }
    config.validate_for_preview()?;

    let mut storage = match Storage::open(&config.storage)? {
        Some(storage) => storage,
        None => {
            println!("{}", no_previous_run_message());
            if args.ci {
                return Err(reviewgate::error::ReviewGateError::NoPreviousVerificationHistory);
            }
            return Ok(());
        }
    };

    let gitlab = GitLabClient::new_with_token_source(
        mr.base_url.clone(),
        config.gitlab_token.clone(),
        config.gitlab_token_source,
    )?;
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
        if args.ci {
            return Err(reviewgate::error::ReviewGateError::NoPreviousVerificationHistory);
        }
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
    print_verification_counters(&preview);
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
    let storage = storage.as_mut()?;

    match storage.persist_review_run(context, config, preview) {
        Ok(persisted) => Some(persisted),
        Err(err) => {
            eprintln!("warning: storage failed; review will continue: {err}");
            None
        }
    }
}

fn persist_review_run_and_apply_comparison(
    storage: &mut Option<Storage>,
    context: &MergeRequestContext,
    config: &AppConfig,
    preview: &mut ReviewPreview,
) -> (Option<PersistedReviewRun>, Option<ReviewComparison>) {
    let persisted = persist_review_run_best_effort(storage, context, config, preview);
    let comparison = persisted.as_ref().and_then(|persisted| {
        compare_review_run_best_effort(storage, context, persisted.id.as_str())
    });
    if let Some(comparison) = comparison.as_ref() {
        preview.markdown = insert_comparison_section(&preview.markdown, comparison);
    }
    (persisted, comparison)
}

fn compare_review_run_best_effort(
    storage: &Option<Storage>,
    context: &MergeRequestContext,
    current_run_id: &str,
) -> Option<ReviewComparison> {
    let storage = storage.as_ref()?;
    match compare_current_run_with_previous(
        storage,
        &context.mr_url.project_path,
        context.metadata.iid,
        current_run_id,
    ) {
        Ok(comparison) => Some(comparison),
        Err(err) => {
            eprintln!("warning: comparison failed; review will continue: {err}");
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

fn print_finding_counters(preview: &ReviewPreview) {
    let Some(analysis) = preview.analysis.as_ref() else {
        return;
    };
    println!();
    print!(
        "{}",
        format_finding_counters_terminal(&count_findings_from_analysis(analysis), emoji_enabled())
    );
}

fn print_review_comparison(comparison: Option<&ReviewComparison>) {
    let Some(comparison) = comparison else {
        return;
    };
    println!();
    print!("{}", format_comparison_terminal_default(comparison));
}

fn print_storage_open_warning(outcome: &reviewgate::storage::StorageOpenOutcome) {
    if let Some(warning) = outcome.warning.as_deref() {
        eprintln!("warning: storage unavailable; review will continue without history: {warning}");
    }
}

fn print_verification_counters(preview: &VerificationPreview) {
    println!();
    print!(
        "{}",
        format_verification_counters_terminal(
            &count_verification_results(&preview.outcome),
            emoji_enabled()
        )
    );
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
