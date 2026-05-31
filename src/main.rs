use clap::Parser;
use reviewgate::cli::{Cli, Commands};
use reviewgate::config::AppConfig;
use reviewgate::error::Result;
use reviewgate::gitlab::client::GitLabClient;
use reviewgate::gitlab::url::GitLabMrUrl;
use reviewgate::llm::ollama::OllamaClient;
use reviewgate::redaction::redact_secrets;
use reviewgate::review::formatter::format_review_markdown;
use reviewgate::review::prompt::build_review_prompt;

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

            if args.dry_run {
                println!("ReviewGate dry run");
                println!("base_url: {}", mr.base_url);
                println!("project_path: {}", mr.project_path);
                println!("encoded_project_path: {}", mr.encoded_project_path);
                println!("mr_iid: {}", mr.mr_iid);
                println!("llm_provider: {}", config.llm.provider);
                println!("model: {}", config.llm.model);
                return Ok(());
            }

            config.validate_for_preview()?;

            let gitlab = GitLabClient::new(
                mr.base_url.clone(),
                config.gitlab_token.clone(),
                reqwest::Client::new(),
            )?;
            let metadata = gitlab.fetch_merge_request(&mr).await?;
            let diff = gitlab.fetch_merge_request_diff(&mr).await?;
            let redacted_diff = redact_secrets(&diff.to_unified_diff());
            let prompt = build_review_prompt(&metadata, &redacted_diff);

            let ollama = OllamaClient::new(
                config.llm.ollama_base_url.clone(),
                config.llm.model.clone(),
                reqwest::Client::new(),
            );
            let review_text = ollama.review(&prompt).await?;
            println!("{}", format_review_markdown(&review_text));
        }
    }

    Ok(())
}
