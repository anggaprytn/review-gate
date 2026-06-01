use std::env;

use clap::ValueEnum;

use crate::{
    error::{Result, ReviewGateError},
    gitlab::{
        types::{MergeRequestDiff, MergeRequestMetadata},
        url::GitLabMrUrl,
    },
    plan::{build_review_plan, PlanOptions, ReviewPlan},
};

pub const DEFAULT_AUTO_LARGE_FILE_THRESHOLD: usize = 30;
pub const DEFAULT_AUTO_LARGE_DIFF_BYTES: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReviewMode {
    Auto,
    Single,
    Large,
}

impl ReviewMode {
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(value) = env::var("REVIEWGATE_REVIEW_MODE") else {
            return Ok(None);
        };

        value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| ReviewGateError::InvalidReviewMode(value))
    }
}

impl std::str::FromStr for ReviewMode {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "single" | "single-pass" | "single_pass" => Ok(Self::Single),
            "large" => Ok(Self::Large),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedReviewMode {
    SinglePass,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLargeOptions {
    pub file_threshold: usize,
    pub diff_bytes_threshold: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoReviewDecision {
    pub selected: SelectedReviewMode,
    pub changed_files: usize,
    pub diff_bytes: usize,
    pub file_threshold: usize,
    pub diff_bytes_threshold: usize,
    pub by_file_count: bool,
    pub by_diff_bytes: bool,
}

impl Default for AutoLargeOptions {
    fn default() -> Self {
        Self {
            file_threshold: DEFAULT_AUTO_LARGE_FILE_THRESHOLD,
            diff_bytes_threshold: DEFAULT_AUTO_LARGE_DIFF_BYTES,
        }
    }
}

impl AutoLargeOptions {
    pub fn from_env() -> Self {
        Self {
            file_threshold: env_usize("REVIEWGATE_AUTO_LARGE_FILE_THRESHOLD")
                .unwrap_or(DEFAULT_AUTO_LARGE_FILE_THRESHOLD)
                .max(1),
            diff_bytes_threshold: env_usize("REVIEWGATE_AUTO_LARGE_DIFF_BYTES")
                .unwrap_or(DEFAULT_AUTO_LARGE_DIFF_BYTES)
                .max(1),
        }
    }
}

pub fn build_auto_review_plan(
    mr: &GitLabMrUrl,
    metadata: MergeRequestMetadata,
    diffs: Vec<MergeRequestDiff>,
    options: AutoLargeOptions,
) -> ReviewPlan {
    build_review_plan(
        mr,
        metadata,
        diffs,
        PlanOptions {
            max_files: usize::MAX,
            max_diff_bytes: usize::MAX,
            include_low_risk: true,
            large_mr_file_threshold: options.file_threshold,
            large_mr_diff_bytes: options.diff_bytes_threshold,
        },
    )
}

pub fn decide_auto_review_mode(plan: &ReviewPlan, options: AutoLargeOptions) -> AutoReviewDecision {
    let changed_files = plan.summary.changed_files;
    let diff_bytes = plan.summary.total_diff_bytes;
    let by_file_count = changed_files >= options.file_threshold;
    let by_diff_bytes = diff_bytes >= options.diff_bytes_threshold;
    let selected = if by_file_count || by_diff_bytes {
        SelectedReviewMode::Large
    } else {
        SelectedReviewMode::SinglePass
    };

    AutoReviewDecision {
        selected,
        changed_files,
        diff_bytes,
        file_threshold: options.file_threshold,
        diff_bytes_threshold: options.diff_bytes_threshold,
        by_file_count,
        by_diff_bytes,
    }
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok().and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{PlanMergeRequest, PlanSummary};

    #[test]
    fn auto_mode_selects_single_when_below_thresholds() {
        let decision = decide_auto_review_mode(
            &plan(29, 199_999),
            AutoLargeOptions {
                file_threshold: 30,
                diff_bytes_threshold: 200_000,
            },
        );

        assert_eq!(decision.selected, SelectedReviewMode::SinglePass);
        assert!(!decision.by_file_count);
        assert!(!decision.by_diff_bytes);
    }

    #[test]
    fn auto_mode_selects_large_by_file_count() {
        let decision = decide_auto_review_mode(
            &plan(30, 10),
            AutoLargeOptions {
                file_threshold: 30,
                diff_bytes_threshold: 200_000,
            },
        );

        assert_eq!(decision.selected, SelectedReviewMode::Large);
        assert!(decision.by_file_count);
        assert!(!decision.by_diff_bytes);
    }

    #[test]
    fn auto_mode_selects_large_by_diff_bytes() {
        let decision = decide_auto_review_mode(
            &plan(1, 200_000),
            AutoLargeOptions {
                file_threshold: 30,
                diff_bytes_threshold: 200_000,
            },
        );

        assert_eq!(decision.selected, SelectedReviewMode::Large);
        assert!(!decision.by_file_count);
        assert!(decision.by_diff_bytes);
    }

    fn plan(changed_files: usize, total_diff_bytes: usize) -> ReviewPlan {
        ReviewPlan {
            mr: PlanMergeRequest {
                project_path: "group/repo".to_string(),
                mr_iid: 59,
                title: "Test MR".to_string(),
                head_sha: "abc123".to_string(),
            },
            summary: PlanSummary {
                changed_files,
                reviewable_files: changed_files,
                skipped_files: 0,
                total_diff_bytes,
                large_mr: false,
            },
            files: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
