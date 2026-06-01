use crate::{
    branding::REVIEWGATE_ATTRIBUTION,
    error::{Result, ReviewGateError},
    gitlab::types::{GitLabNote, PublishAction},
};
use std::future::Future;

const TRUNCATION_NOTICE: &str = "\n\n---\n\n⚠️ ReviewGate output truncated because it exceeded the configured publish size limit.\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishTarget {
    pub action: PublishAction,
    pub note_id: Option<u64>,
    pub duplicate_count: usize,
}

pub async fn publish_summary_with<P, Fut>(
    body: String,
    publish: P,
) -> Result<crate::gitlab::types::PublishResult>
where
    P: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<crate::gitlab::types::PublishResult>>,
{
    if body.trim().is_empty() {
        return Err(ReviewGateError::PublishEmptyMarkdown);
    }

    publish(body).await
}

pub fn summary_marker(project_path: &str, mr_iid: u64) -> String {
    format!(
        "<!-- reviewgate:summary project=\"{}\" mr=\"{}\" -->",
        escape_marker_attr(project_path),
        mr_iid
    )
}

pub fn verification_marker(project_path: &str, mr_iid: u64) -> String {
    format!(
        "<!-- reviewgate:verification project=\"{}\" mr=\"{}\" -->",
        escape_marker_attr(project_path),
        mr_iid
    )
}

pub fn build_summary_note_body(
    markdown: &str,
    project_path: &str,
    mr_iid: u64,
    llm_label: &str,
    local_only: bool,
    external_model_call: &str,
    head_sha: &str,
    inline_comments: &str,
    max_chars: usize,
) -> Result<String> {
    if markdown.trim().is_empty() {
        return Err(ReviewGateError::PublishEmptyMarkdown);
    }

    let body = format!(
        "{marker}\n\n{markdown}\n\n---\n\nReviewGate run metadata:\n\n- Provider: GitLab\n- LLM: {llm_label}\n- Local-only: {local_only}\n- External model call: {external_model_call}\n- Payload: sanitized diff only\n- Head SHA: {head_sha}\n- Publish mode: summary note\n- Inline comments: {inline_comments}\n\n{REVIEWGATE_ATTRIBUTION}\n",
        marker = summary_marker(project_path, mr_iid),
        markdown = strip_terminal_ai_footer(markdown).trim_end(),
    );

    truncate_note_body(&body, max_chars)
}

pub fn build_verification_note_body(
    markdown: &str,
    project_path: &str,
    mr_iid: u64,
    max_chars: usize,
) -> Result<String> {
    if markdown.trim().is_empty() {
        return Err(ReviewGateError::PublishEmptyMarkdown);
    }

    let body = format!(
        "{marker}\n\n{markdown}\n\n{REVIEWGATE_ATTRIBUTION}\n",
        marker = verification_marker(project_path, mr_iid),
        markdown = strip_terminal_ai_footer(markdown).trim_end(),
    );

    truncate_note_body(&body, max_chars)
}

pub fn truncate_note_body(body: &str, max_chars: usize) -> Result<String> {
    if char_count(body) <= max_chars {
        return Ok(body.to_string());
    }

    let notice_chars = char_count(TRUNCATION_NOTICE);
    if notice_chars >= max_chars {
        return Err(ReviewGateError::PublishNoteBodyTooLarge);
    }

    let keep_chars = max_chars - notice_chars;
    let mut truncated = take_chars(body, keep_chars).trim_end().to_string();
    truncated.push_str(TRUNCATION_NOTICE);

    if char_count(&truncated) > max_chars {
        return Err(ReviewGateError::PublishNoteBodyTooLarge);
    }

    Ok(truncated)
}

pub fn select_publish_target(
    notes: &[GitLabNote],
    marker: &str,
    force_new_note: bool,
) -> PublishTarget {
    if force_new_note {
        return PublishTarget {
            action: PublishAction::Created,
            note_id: None,
            duplicate_count: 0,
        };
    }

    let matching_notes = reviewgate_notes(notes, marker);
    let duplicate_count = matching_notes.len();
    let note_id = matching_notes
        .into_iter()
        .max_by(|left, right| note_sort_key(left).cmp(&note_sort_key(right)))
        .map(|note| note.id);

    match note_id {
        Some(note_id) => PublishTarget {
            action: PublishAction::Updated,
            note_id: Some(note_id),
            duplicate_count,
        },
        None => PublishTarget {
            action: PublishAction::Created,
            note_id: None,
            duplicate_count: 0,
        },
    }
}

pub fn reviewgate_note_count(notes: &[GitLabNote], marker: &str) -> usize {
    reviewgate_notes(notes, marker).len()
}

fn reviewgate_notes<'a>(notes: &'a [GitLabNote], marker: &str) -> Vec<&'a GitLabNote> {
    notes
        .iter()
        .filter(|note| !note.system && note.body.contains(marker))
        .collect()
}

fn note_sort_key(note: &GitLabNote) -> (&str, &str) {
    (
        note.updated_at.as_deref().unwrap_or_default(),
        note.created_at.as_deref().unwrap_or_default(),
    )
}

fn strip_terminal_ai_footer(markdown: &str) -> &str {
    let trimmed = markdown.trim_end();
    trimmed
        .strip_suffix(REVIEWGATE_ATTRIBUTION)
        .map(str::trim_end)
        .unwrap_or(trimmed)
}

fn escape_marker_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn char_count(value: &str) -> usize {
    value.chars().count()
}

fn take_chars(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        build_summary_note_body, build_verification_note_body, publish_summary_with,
        reviewgate_note_count, select_publish_target, summary_marker, truncate_note_body,
        verification_marker,
    };
    use crate::{
        error::ReviewGateError,
        gitlab::types::{GitLabNote, GitLabUser, PublishAction, PublishResult},
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn generates_stable_reviewgate_summary_marker() {
        assert_eq!(
            summary_marker("group/repo", 59),
            r#"<!-- reviewgate:summary project="group/repo" mr="59" -->"#
        );
    }

    #[test]
    fn generates_stable_reviewgate_verification_marker() {
        assert_eq!(
            verification_marker("group/repo", 59),
            r#"<!-- reviewgate:verification project="group/repo" mr="59" -->"#
        );
    }

    #[test]
    fn detects_existing_reviewgate_notes_and_ignores_system_notes() {
        let marker = summary_marker("group/repo", 59);
        let notes = vec![
            note(1, &marker, false, "2026-01-01T00:00:00Z"),
            note(2, &marker, true, "2026-01-02T00:00:00Z"),
            note(3, "ordinary user note", false, "2026-01-03T00:00:00Z"),
        ];

        assert_eq!(reviewgate_note_count(&notes, &marker), 1);

        let target = select_publish_target(&notes, &marker, false);

        assert_eq!(target.action, PublishAction::Updated);
        assert_eq!(target.note_id, Some(1));
        assert_eq!(target.duplicate_count, 1);
    }

    #[test]
    fn detects_existing_verification_note_with_generic_selector() {
        let marker = verification_marker("group/repo", 59);
        let notes = vec![
            note(1, &marker, false, "2026-01-01T00:00:00Z"),
            note(2, "ordinary note", false, "2026-01-02T00:00:00Z"),
        ];

        let target = select_publish_target(&notes, &marker, false);

        assert_eq!(target.action, PublishAction::Updated);
        assert_eq!(target.note_id, Some(1));
        assert_eq!(target.duplicate_count, 1);
    }

    #[test]
    fn multiple_reviewgate_notes_update_most_recent() {
        let marker = summary_marker("group/repo", 59);
        let notes = vec![
            note(1, &marker, false, "2026-01-01T00:00:00Z"),
            note(2, &marker, false, "2026-01-03T00:00:00Z"),
            note(3, &marker, false, "2026-01-02T00:00:00Z"),
        ];

        let target = select_publish_target(&notes, &marker, false);

        assert_eq!(target.action, PublishAction::Updated);
        assert_eq!(target.note_id, Some(2));
        assert_eq!(target.duplicate_count, 3);
    }

    #[test]
    fn force_new_note_selects_create_even_when_marker_exists() {
        let marker = summary_marker("group/repo", 59);
        let notes = vec![note(1, &marker, false, "2026-01-01T00:00:00Z")];

        let target = select_publish_target(&notes, &marker, true);

        assert_eq!(target.action, PublishAction::Created);
        assert_eq!(target.note_id, None);
        assert_eq!(target.duplicate_count, 0);
    }

    #[test]
    fn builds_published_body_with_marker_and_metadata() {
        let body = build_summary_note_body(
            "# ReviewGate AI Code Review\n\nBody\n\n[AI generated by ReviewGate]\n",
            "group/repo",
            59,
            "ollama/qwen2.5-coder:7b",
            true,
            "disabled",
            "abc123",
            "disabled",
            10_000,
        )
        .unwrap();

        assert!(body.starts_with(r#"<!-- reviewgate:summary project="group/repo" mr="59" -->"#));
        assert!(body.contains("- Provider: GitLab"));
        assert!(body.contains("- LLM: ollama/qwen2.5-coder:7b"));
        assert!(body.contains("- External model call: disabled"));
        assert!(body.contains("- Payload: sanitized diff only"));
        assert!(body.contains("- Head SHA: abc123"));
        assert!(body.contains("- Inline comments: disabled"));
        assert_eq!(body.matches("[AI generated by ReviewGate]").count(), 1);
    }

    #[test]
    fn builds_verification_body_with_marker() {
        let body = build_verification_note_body(
            "# ReviewGate Change Verification\n\nBody\n\n[AI generated by ReviewGate]\n",
            "group/repo",
            59,
            10_000,
        )
        .unwrap();

        assert!(
            body.starts_with(r#"<!-- reviewgate:verification project="group/repo" mr="59" -->"#)
        );
        assert!(body.contains("# ReviewGate Change Verification"));
        assert_eq!(body.matches("[AI generated by ReviewGate]").count(), 1);
    }

    #[test]
    fn truncates_note_body_safely_with_notice() {
        let body = truncate_note_body("abcdef", 5).unwrap_err();
        assert!(matches!(body, ReviewGateError::PublishNoteBodyTooLarge));

        let long_body = "a".repeat(200);
        let truncated = truncate_note_body(&long_body, 120).unwrap();

        assert!(truncated.chars().count() <= 120);
        assert!(truncated.contains("ReviewGate output truncated"));
    }

    #[tokio::test]
    async fn publish_calls_publisher_through_mockable_boundary() {
        let called = Arc::new(AtomicBool::new(false));
        let called_in_closure = Arc::clone(&called);

        let result = publish_summary_with("markdown".to_string(), move |body| async move {
            called_in_closure.store(true, Ordering::SeqCst);
            assert_eq!(body, "markdown");
            Ok(PublishResult {
                action: PublishAction::Created,
                note_id: Some(123),
                web_url: None,
                duplicate_count: 0,
            })
        })
        .await
        .unwrap();

        assert!(called.load(Ordering::SeqCst));
        assert_eq!(result.note_id, Some(123));
    }

    fn note(id: u64, body: &str, system: bool, updated_at: &str) -> GitLabNote {
        GitLabNote {
            id,
            body: body.to_string(),
            system,
            created_at: Some(updated_at.to_string()),
            updated_at: Some(updated_at.to_string()),
            author: Some(GitLabUser {
                username: Some("reviewgate".to_string()),
                name: Some("ReviewGate".to_string()),
            }),
        }
    }
}
