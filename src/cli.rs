use clap::{Args, Parser, Subcommand};

use crate::error::{Result, ReviewGateError};

#[derive(Debug, Parser)]
#[command(name = "reviewgate")]
#[command(about = "Local-first AI merge request review for private GitLab")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Plan(PlanArgs),
    Review(ReviewArgs),
    Verify(VerifyArgs),
    FixPrompt(FixPromptArgs),
    Findings(FindingsArgs),
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub network: bool,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[arg(required_unless_present = "ci", value_name = "MR_URL")]
    pub mr_url: Option<String>,

    #[arg(long, conflicts_with = "mr_url")]
    pub ci: bool,

    #[arg(long)]
    pub json: bool,

    #[arg(long, value_name = "N")]
    pub max_files: Option<usize>,

    #[arg(long, value_name = "BYTES")]
    pub max_diff_bytes: Option<usize>,

    #[arg(long)]
    pub include_low_risk: bool,
}

#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[arg(required_unless_present = "ci", value_name = "MR_URL")]
    pub mr_url: Option<String>,

    #[arg(long, conflicts_with = "mr_url")]
    pub ci: bool,

    #[arg(long, requires = "ci")]
    pub allow_non_mr_ci: bool,

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

    #[arg(long)]
    pub soft_fail: bool,
}

#[derive(Debug, Args)]
pub struct FixPromptArgs {
    #[arg(value_name = "MR_URL")]
    pub mr_url: String,

    #[arg(long, conflicts_with = "run_id")]
    pub latest: bool,

    #[arg(long, value_name = "RUN_ID")]
    pub run_id: Option<String>,

    #[arg(long, value_name = "CRITICAL|HIGH|MEDIUM|LOW")]
    pub min_severity: Option<String>,

    #[arg(long)]
    pub include_low: bool,

    #[arg(long)]
    pub include_notes: bool,

    #[arg(long, default_value = "markdown", value_name = "markdown|codex|gemini")]
    pub format: String,

    #[arg(long, value_name = "PATH")]
    pub output: Option<std::path::PathBuf>,

    #[arg(long, requires = "output")]
    pub force: bool,

    #[arg(long)]
    pub copy: bool,
}

#[derive(Debug, Args)]
pub struct FindingsArgs {
    #[arg(value_name = "MR_URL")]
    pub mr_url: String,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(required_unless_present = "ci", value_name = "MR_URL")]
    pub mr_url: Option<String>,

    #[arg(long, conflicts_with = "mr_url")]
    pub ci: bool,

    #[arg(long, requires = "ci")]
    pub allow_non_mr_ci: bool,

    #[arg(long, conflicts_with = "publish")]
    pub preview: bool,

    #[arg(long, conflicts_with = "preview")]
    pub publish: bool,

    #[arg(long, requires = "publish")]
    pub force_new_note: bool,

    #[arg(long)]
    pub soft_fail: bool,
}

impl Cli {
    pub fn soft_fail(&self) -> bool {
        match &self.command {
            Commands::Plan(_) => false,
            Commands::Review(args) => args.soft_fail,
            Commands::Verify(args) => args.soft_fail,
            Commands::FixPrompt(_) | Commands::Findings(_) => false,
            Commands::Doctor(_) => false,
        }
    }
}

impl VerifyArgs {
    pub fn publishes(&self) -> bool {
        self.publish
    }
}

impl PlanArgs {
    pub fn calls_llm(&self) -> bool {
        false
    }

    pub fn publishes(&self) -> bool {
        false
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

pub fn exit_code_for_result(failed: bool, soft_fail: bool) -> i32 {
    if failed && !soft_fail {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{exit_code_for_result, Cli, Commands, PlanArgs, ReviewArgs};

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
    fn plan_mode_does_not_call_llm_or_publish() {
        let cli = Cli::parse_from([
            "reviewgate",
            "plan",
            "https://gitlab.company.local/group/repo/-/merge_requests/59",
        ]);

        let args = plan_args(cli.command);
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
    fn publish_inline_without_publish_is_rejected_in_ci() {
        let cli = Cli::parse_from(["reviewgate", "review", "--ci", "--publish-inline"]);

        let args = review_args(cli.command);
        let err = args.validate().unwrap_err();

        assert!(matches!(
            err,
            crate::error::ReviewGateError::PublishInlineRequiresPublish
        ));
    }

    #[test]
    fn review_ci_defaults_to_preview_behavior() {
        let cli = Cli::parse_from(["reviewgate", "review", "--ci"]);

        let args = review_args(cli.command);
        assert!(args.ci);
        assert!(args.calls_llm());
        assert!(!args.publishes());
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
    fn verify_ci_defaults_to_preview_behavior() {
        let cli = Cli::parse_from(["reviewgate", "verify", "--ci"]);

        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(args.ci);
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

    #[test]
    fn soft_fail_maps_failure_to_success_exit_code() {
        assert_eq!(exit_code_for_result(true, true), 0);
        assert_eq!(exit_code_for_result(true, false), 1);
        assert_eq!(exit_code_for_result(false, false), 0);
    }

    fn review_args(command: Commands) -> ReviewArgs {
        match command {
            Commands::Plan(_) => panic!("expected review command"),
            Commands::Review(args) => args,
            Commands::Verify(_) => panic!("expected review command"),
            Commands::FixPrompt(_) => panic!("expected review command"),
            Commands::Findings(_) => panic!("expected review command"),
            Commands::Doctor(_) => panic!("expected review command"),
        }
    }

    fn plan_args(command: Commands) -> PlanArgs {
        match command {
            Commands::Plan(args) => args,
            Commands::Review(_) => panic!("expected plan command"),
            Commands::Verify(_) => panic!("expected plan command"),
            Commands::FixPrompt(_) => panic!("expected plan command"),
            Commands::Findings(_) => panic!("expected plan command"),
            Commands::Doctor(_) => panic!("expected plan command"),
        }
    }
}
