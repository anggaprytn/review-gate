use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct GitLabUser {
    pub username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiffRefs {
    pub base_sha: Option<String>,
    pub start_sha: Option<String>,
    pub head_sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
    use super::{MergeRequestDiff, MergeRequestMetadata};

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
}
