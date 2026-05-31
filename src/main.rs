use clap::Parser;
use reviewgate::cli::{Cli, Commands};
use reviewgate::config::AppConfig;
use reviewgate::error::Result;
use reviewgate::gitlab::client::GitLabClient;
use reviewgate::gitlab::context::{build_merge_request_context, MergeRequestContext};
use reviewgate::gitlab::url::GitLabMrUrl;
use reviewgate::review::prompt::build_review_prompt;

const PROMPT_PREVIEW_LIMIT: usize = 8_000;

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
            let mr = GitLabMrUrl::parse(&args.mr_url)?;
            let config = AppConfig::load()?;
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

            if args.dry_run {
                print_dry_run_summary(&context);
            } else {
                print_preview(&context);
            }
        }
    }

    Ok(())
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

fn print_preview(context: &MergeRequestContext) {
    println!("ReviewGate preview");
    println!();
    print_mr_summary(context);
    print_diff_summary(context);
    print_file_summary(context);
    print_warnings(context);

    let prompt = build_review_prompt(&context.metadata, &context.sanitized_diff);
    let prompt_preview = truncate_for_terminal(&prompt, PROMPT_PREVIEW_LIMIT);

    println!("Prompt preview:");
    println!("{prompt_preview}");
    if prompt.len() > PROMPT_PREVIEW_LIMIT {
        println!(
            "[truncated: showing first {} of {} bytes]",
            PROMPT_PREVIEW_LIMIT,
            prompt.len()
        );
    }
    println!("LLM review not implemented in this step");
    println!("Publish: skipped");
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

fn truncate_for_terminal(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}
