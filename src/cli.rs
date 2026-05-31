use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "reviewgate")]
#[command(about = "Local-first AI merge request review for private GitLab")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Review(ReviewArgs),
}

#[derive(Debug, Args)]
pub struct ReviewArgs {
    pub mr_url: String,

    #[arg(long, conflicts_with = "preview")]
    pub dry_run: bool,

    #[arg(long, conflicts_with = "dry_run")]
    pub preview: bool,
}
