use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct MergeRequestMetadata {
    pub iid: u64,
    pub title: String,
    pub state: String,
    pub source_branch: String,
    pub target_branch: String,
    pub web_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MergeRequestChanges {
    #[serde(default)]
    pub changes: Vec<MergeRequestChange>,
}

impl MergeRequestChanges {
    pub fn to_unified_diff(&self) -> String {
        self.changes
            .iter()
            .map(|change| {
                format!(
                    "diff --git a/{old_path} b/{new_path}\n{diff}",
                    old_path = change.old_path,
                    new_path = change.new_path,
                    diff = change.diff
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MergeRequestChange {
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
}
