use crate::{
    config::ReviewConfig,
    gitlab::{
        types::{MergeRequestDiff, MergeRequestMetadata},
        url::GitLabMrUrl,
    },
    redaction::redact_secrets,
    review::anchors::{AnchorBuilder, AnchoredDiffContext},
};

#[derive(Debug, Clone)]
pub struct MergeRequestContext {
    pub mr_url: GitLabMrUrl,
    pub metadata: MergeRequestMetadata,
    pub files: Vec<NormalizedDiffFile>,
    pub stats: DiffStats,
    pub sanitized_diff: String,
    pub anchored_diff: AnchoredDiffContext,
    pub warnings: Vec<String>,
    pub partial: bool,
}

#[derive(Debug, Clone)]
pub struct NormalizedDiffFile {
    pub old_path: String,
    pub new_path: String,
    pub added_lines: usize,
    pub removed_lines: usize,
    pub new_file: bool,
    pub renamed_file: bool,
    pub deleted_file: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffStats {
    pub changed_file_count: usize,
    pub generated_file_count: usize,
    pub collapsed_file_count: usize,
    pub too_large_file_count: usize,
    pub total_diff_bytes: usize,
    pub approximate_added_lines: usize,
    pub approximate_removed_lines: usize,
}

pub fn build_merge_request_context(
    mr_url: GitLabMrUrl,
    metadata: MergeRequestMetadata,
    diffs: Vec<MergeRequestDiff>,
    review_config: &ReviewConfig,
    should_redact: bool,
) -> MergeRequestContext {
    let mut stats = DiffStats {
        changed_file_count: diffs.len(),
        ..DiffStats::default()
    };
    let mut files = Vec::new();
    let mut diff_parts = Vec::new();
    let mut anchor_builder = AnchorBuilder::new();
    let mut warnings = Vec::new();
    let mut partial = false;
    let mut warned_file_limit = false;
    let mut warned_byte_limit = false;

    for diff in diffs {
        if diff.is_generated() {
            stats.generated_file_count += 1;
            warnings.push(format!("Skipped generated file: {}", diff.new_path));
            continue;
        }

        if diff.is_collapsed() {
            stats.collapsed_file_count += 1;
            warnings.push(format!(
                "GitLab marked file as collapsed: {}",
                diff.new_path
            ));
        }

        if diff.is_too_large() {
            stats.too_large_file_count += 1;
            partial = true;
            warnings.push(format!("Skipped too-large file: {}", diff.new_path));
            continue;
        }

        if files.len() >= review_config.max_files {
            partial = true;
            if !warned_file_limit {
                warnings.push(format!(
                    "Stopped adding diff content after REVIEWGATE_MAX_FILES={} files",
                    review_config.max_files
                ));
                warned_file_limit = true;
            }
            continue;
        }

        let raw_unified_diff = diff.to_unified_diff();
        let sanitized = if should_redact {
            redact_secrets(&raw_unified_diff)
        } else {
            raw_unified_diff
        };
        let sanitized_bytes = sanitized.len();

        if stats.total_diff_bytes + sanitized_bytes > review_config.max_diff_bytes {
            partial = true;
            if !warned_byte_limit {
                warnings.push(format!(
                    "Stopped adding diff content after REVIEWGATE_MAX_DIFF_BYTES={} bytes",
                    review_config.max_diff_bytes
                ));
                warned_byte_limit = true;
            }
            continue;
        }

        let line_stats = count_diff_lines(&diff.diff);
        stats.total_diff_bytes += sanitized_bytes;
        stats.approximate_added_lines += line_stats.added;
        stats.approximate_removed_lines += line_stats.removed;
        if !diff.is_collapsed() {
            anchor_builder.add_diff(&diff);
        }

        files.push(NormalizedDiffFile {
            old_path: diff.old_path,
            new_path: diff.new_path,
            added_lines: line_stats.added,
            removed_lines: line_stats.removed,
            new_file: diff.new_file,
            renamed_file: diff.renamed_file,
            deleted_file: diff.deleted_file,
        });
        diff_parts.push(sanitized);
    }

    MergeRequestContext {
        mr_url,
        metadata,
        files,
        stats,
        sanitized_diff: diff_parts.join("\n"),
        anchored_diff: anchor_builder.finish(partial),
        warnings,
        partial,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LineStats {
    added: usize,
    removed: usize,
}

fn count_diff_lines(diff: &str) -> LineStats {
    let mut added = 0;
    let mut removed = 0;

    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }

        if line.starts_with('+') {
            added += 1;
        } else if line.starts_with('-') {
            removed += 1;
        }
    }

    LineStats { added, removed }
}

#[cfg(test)]
mod tests {
    use super::{build_merge_request_context, count_diff_lines};
    use crate::{
        config::ReviewConfig,
        gitlab::{
            types::{MergeRequestDiff, MergeRequestMetadata},
            url::GitLabMrUrl,
        },
    };

    #[test]
    fn counts_diff_added_and_removed_lines_without_headers() {
        let stats = count_diff_lines("--- a/file\n+++ b/file\n-old\n+new\n context\n+more");

        assert_eq!(stats.added, 2);
        assert_eq!(stats.removed, 1);
    }

    #[test]
    fn builds_stats_and_skips_generated_and_too_large_files() {
        let context = build_merge_request_context(
            mr_url(),
            metadata(),
            vec![
                diff("src/a.rs", "@@ -1 +1 @@\n-old\n+new"),
                MergeRequestDiff {
                    generated_file: Some(true),
                    ..diff("dist/app.js", "+generated")
                },
                MergeRequestDiff {
                    too_large: Some(true),
                    ..diff("src/huge.rs", "+huge")
                },
                MergeRequestDiff {
                    collapsed: Some(true),
                    ..diff("src/collapsed.rs", "+visible")
                },
            ],
            &review_config(200_000, 50),
            true,
        );

        assert_eq!(context.stats.changed_file_count, 4);
        assert_eq!(context.stats.generated_file_count, 1);
        assert_eq!(context.stats.too_large_file_count, 1);
        assert_eq!(context.stats.collapsed_file_count, 1);
        assert_eq!(context.files.len(), 2);
        assert!(context.partial);
        assert!(context
            .warnings
            .iter()
            .any(|warning| warning.contains("generated")));
        assert!(!context.sanitized_diff.contains("dist/app.js"));
        assert!(!context.sanitized_diff.contains("src/huge.rs"));
    }

    #[test]
    fn stops_adding_content_after_byte_limit() {
        let context = build_merge_request_context(
            mr_url(),
            metadata(),
            vec![
                diff("src/a.rs", "+short"),
                diff("src/b.rs", "+this is too long"),
            ],
            &review_config(60, 50),
            true,
        );

        assert!(context.partial);
        assert_eq!(context.files.len(), 1);
        assert!(context
            .warnings
            .iter()
            .any(|warning| warning.contains("REVIEWGATE_MAX_DIFF_BYTES")));
    }

    fn mr_url() -> GitLabMrUrl {
        GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59").unwrap()
    }

    fn metadata() -> MergeRequestMetadata {
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
            changes_count: Some("4".to_string()),
            diff_refs: None,
        }
    }

    fn diff(path: &str, diff: &str) -> MergeRequestDiff {
        MergeRequestDiff {
            old_path: path.to_string(),
            new_path: path.to_string(),
            diff: diff.to_string(),
            new_file: false,
            renamed_file: false,
            deleted_file: false,
            generated_file: None,
            collapsed: None,
            too_large: None,
        }
    }

    fn review_config(max_diff_bytes: usize, max_files: usize) -> ReviewConfig {
        ReviewConfig {
            max_inline_comments: 8,
            severity_threshold: "medium".to_string(),
            max_diff_bytes,
            max_files,
        }
    }
}
