use crate::review::inline::GitLabInlinePosition;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeRequestMetadata {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub draft: Option<bool>,
    pub source_branch: String,
    pub target_branch: String,
    pub sha: String,
    pub web_url: String,
    pub author: Option<GitLabUser>,
    pub detailed_merge_status: Option<String>,
    pub changes_count: Option<String>,
    pub diff_refs: Option<DiffRefs>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabUser {
    pub username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabNote {
    pub id: u64,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub system: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub author: Option<GitLabUser>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabDiscussion {
    pub id: String,
    pub individual_note: Option<bool>,
    #[serde(default)]
    pub notes: Vec<GitLabDiscussionNote>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabDiscussionNote {
    pub id: u64,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub system: bool,
    pub resolvable: Option<bool>,
    pub resolved: Option<bool>,
    pub position: Option<GitLabNotePosition>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabNotePosition {
    pub position_type: Option<String>,
    pub base_sha: Option<String>,
    pub start_sha: Option<String>,
    pub head_sha: Option<String>,
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateMergeRequestNoteRequest {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateMergeRequestNoteRequest {
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct CreateMergeRequestDiscussionRequest {
    pub body: String,
    pub position: GitLabInlinePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishAction {
    Created,
    Updated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResult {
    pub action: PublishAction,
    pub note_id: Option<u64>,
    pub web_url: Option<String>,
    pub duplicate_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiffRefs {
    pub base_sha: Option<String>,
    pub start_sha: Option<String>,
    pub head_sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeRequestDiff {
    pub old_path: String,
    pub new_path: String,
    #[serde(default)]
    pub diff: String,
    #[serde(default)]
    pub new_file: bool,
    #[serde(default)]
    pub renamed_file: bool,
    #[serde(default)]
    pub deleted_file: bool,
    pub generated_file: Option<bool>,
    pub collapsed: Option<bool>,
    pub too_large: Option<bool>,
}

impl MergeRequestDiff {
    pub fn is_generated(&self) -> bool {
        self.generated_file.unwrap_or(false)
    }

    pub fn is_collapsed(&self) -> bool {
        self.collapsed.unwrap_or(false)
    }

    pub fn is_too_large(&self) -> bool {
        self.too_large.unwrap_or(false)
    }

    pub fn to_unified_diff(&self) -> String {
        format!(
            "diff --git a/{old_path} b/{new_path}\n{diff}",
            old_path = self.old_path,
            new_path = self.new_path,
            diff = self.diff
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreateMergeRequestNoteRequest, MergeRequestDiff, MergeRequestMetadata,
        UpdateMergeRequestNoteRequest,
    };
    use serde_json::json;

    #[test]
    fn parses_merge_request_metadata_fixture() {
        let json = r#"{
            "id": 123,
            "iid": 59,
            "project_id": 456,
            "title": "Fix payment callback timeout",
            "description": null,
            "state": "opened",
            "draft": false,
            "source_branch": "feature/payment-timeout",
            "target_branch": "main",
            "sha": "abc123",
            "web_url": "https://gitlab.company.local/group/repo/-/merge_requests/59",
            "author": {"username": "jdoe", "name": "Jane Doe"},
            "detailed_merge_status": "mergeable",
            "changes_count": "7",
            "diff_refs": {
                "base_sha": "base123",
                "start_sha": "start123",
                "head_sha": "head123"
            }
        }"#;

        let metadata: MergeRequestMetadata = serde_json::from_str(json).unwrap();

        assert_eq!(metadata.iid, 59);
        assert_eq!(metadata.author.unwrap().username.unwrap(), "jdoe");
        assert_eq!(metadata.diff_refs.unwrap().head_sha.unwrap(), "head123");
    }

    #[test]
    fn parses_diff_fixture_with_optional_flags() {
        let json = r#"{
            "old_path": "src/payment/client.ts",
            "new_path": "src/payment/client.ts",
            "diff": "@@ -1 +1 @@\n-old\n+new",
            "new_file": false,
            "renamed_file": false,
            "deleted_file": false,
            "generated_file": true,
            "collapsed": true,
            "too_large": false
        }"#;

        let diff: MergeRequestDiff = serde_json::from_str(json).unwrap();

        assert!(diff.is_generated());
        assert!(diff.is_collapsed());
        assert!(!diff.is_too_large());
    }

    #[test]
    fn serializes_create_note_request_body() {
        let request = CreateMergeRequestNoteRequest {
            body: "review markdown".to_string(),
            internal: Some(false),
        };

        let body = serde_json::to_value(request).unwrap();

        assert_eq!(
            body,
            json!({
                "body": "review markdown",
                "internal": false
            })
        );
    }

    #[test]
    fn serializes_update_note_request_body() {
        let request = UpdateMergeRequestNoteRequest {
            body: "updated review markdown".to_string(),
        };

        let body = serde_json::to_value(request).unwrap();

        assert_eq!(
            body,
            json!({
                "body": "updated review markdown"
            })
        );
    }
}
