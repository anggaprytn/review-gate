use clap::{Args, Parser, Subcommand};

use crate::error::{Result, ReviewGateError};

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
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct ReviewArgs {
    pub mr_url: String,

    #[arg(long, conflicts_with_all = ["preview", "publish"])]
    pub dry_run: bool,

    #[arg(long, conflicts_with_all = ["dry_run", "publish"])]
    pub preview: bool,

    #[arg(long, conflicts_with_all = ["dry_run", "preview"])]
    pub publish: bool,

    #[arg(long, requires = "publish")]
    pub force_new_note: bool,

    #[arg(long, requires = "publish")]
    pub internal_note: bool,

    #[arg(long, requires = "preview")]
    pub show_prompt: bool,

    #[arg(long, conflicts_with = "dry_run")]
    pub inline_dry_run: bool,

    #[arg(long)]
    pub publish_inline: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    pub mr_url: String,

    #[arg(long, conflicts_with = "publish")]
    pub preview: bool,

    #[arg(long, conflicts_with = "preview")]
    pub publish: bool,

    #[arg(long, requires = "publish")]
    pub force_new_note: bool,
}

impl VerifyArgs {
    pub fn publishes(&self) -> bool {
        self.publish
    }
}

impl ReviewArgs {
    pub fn validate(&self) -> Result<()> {
        if self.publish_inline && !self.publish {
            return Err(ReviewGateError::PublishInlineRequiresPublish);
        }

        Ok(())
    }

    pub fn calls_llm(&self) -> bool {
        !self.dry_run
    }

    pub fn publishes(&self) -> bool {
        self.publish
    }

    pub fn publishes_inline(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.publish && self.publish_inline && !self.inline_dry_run)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Commands, ReviewArgs};

    #[test]
    fn dry_run_mode_does_not_call_llm() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--dry-run",
        ]);

        let args = review_args(cli.command);
        assert!(!args.calls_llm());
        assert!(!args.publishes());
    }

    #[test]
    fn preview_mode_calls_llm() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--preview",
        ]);

        let args = review_args(cli.command);
        assert!(args.calls_llm());
        assert!(!args.publishes());
    }

    #[test]
    fn publish_mode_calls_llm_and_publishes() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--publish",
        ]);

        let args = review_args(cli.command);
        assert!(args.calls_llm());
        assert!(args.publishes());
    }

    #[test]
    fn inline_dry_run_can_run_with_preview() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--preview",
            "--inline-dry-run",
        ]);

        let args = review_args(cli.command);
        assert!(args.inline_dry_run);
        assert!(args.calls_llm());
        assert!(!args.publishes());
    }

    #[test]
    fn inline_dry_run_can_run_with_publish() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--publish",
            "--inline-dry-run",
        ]);

        let args = review_args(cli.command);
        assert!(args.inline_dry_run);
        assert!(args.calls_llm());
        assert!(args.publishes());
    }

    #[test]
    fn force_new_note_requires_publish() {
        let err = Cli::try_parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--force-new-note",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn publish_inline_without_publish_is_rejected() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--publish-inline",
        ]);

        let args = review_args(cli.command);
        let err = args.validate().unwrap_err();

        assert!(matches!(
            err,
            crate::error::ReviewGateError::PublishInlineRequiresPublish
        ));
        assert_eq!(err.to_string(), "--publish-inline requires --publish");
    }

    #[test]
    fn inline_dry_run_prevents_inline_publish() {
        let cli = Cli::parse_from([
            "reviewgate",
            "review",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--publish",
            "--publish-inline",
            "--inline-dry-run",
        ]);

        let args = review_args(cli.command);

        assert!(!args.publishes_inline().unwrap());
    }

    #[test]
    fn verify_defaults_to_preview_without_publish() {
        let cli = Cli::parse_from([
            "reviewgate",
            "verify",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
        ]);

        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(!args.publishes());
    }

    #[test]
    fn verify_publish_mode_publishes() {
        let cli = Cli::parse_from([
            "reviewgate",
            "verify",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--publish",
        ]);

        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(args.publishes());
    }

    #[test]
    fn verify_force_new_note_requires_publish() {
        let err = Cli::try_parse_from([
            "reviewgate",
            "verify",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "--force-new-note",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    fn review_args(command: Commands) -> ReviewArgs {
        match command {
            Commands::Review(args) => args,
            Commands::Verify(_) => panic!("expected review command"),
        }
    }
}
