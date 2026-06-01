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

    #[arg(long, requires = "preview")]
    pub show_prompt: bool,
}

impl ReviewArgs {
    pub fn calls_llm(&self) -> bool {
        !self.dry_run
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Commands};

    #[test]
    fn dry_run_mode_does_not_call_llm() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--dry-run",
        ]);

        let Commands::Review(args) = cli.command;
        assert!(!args.calls_llm());
    }

    #[test]
    fn preview_mode_calls_llm() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--preview",
        ]);

        let Commands::Review(args) = cli.command;
        assert!(args.calls_llm());
    }
}
