use crate::error::Result;
use std::{collections::HashMap, env, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLabCiContext {
    pub api_v4_url: Option<String>,
    pub server_url: Option<String>,
    pub project_path: String,
    pub project_url: Option<String>,
    pub project_id: Option<String>,
    pub merge_request_iid: u64,
    pub pipeline_source: Option<String>,
    pub commit_sha: Option<String>,
    pub mr_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiContextError {
    MissingMergeRequestIid,
    MissingProjectPath,
    MissingProjectUrl,
    NotMergeRequestPipeline { source: String },
}

impl fmt::Display for CiContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMergeRequestIid => write!(
                formatter,
                "ReviewGate CI mode requires a GitLab merge request pipeline. CI_MERGE_REQUEST_IID is missing."
            ),
            Self::MissingProjectPath => write!(
                formatter,
                "ReviewGate CI mode requires CI_PROJECT_PATH to identify the GitLab project."
            ),
            Self::MissingProjectUrl => write!(
                formatter,
                "ReviewGate CI mode requires CI_PROJECT_URL, or CI_SERVER_URL with CI_PROJECT_PATH, to construct the merge request URL."
            ),
            Self::NotMergeRequestPipeline { source } => write!(
                formatter,
                "GitLab CI pipeline source is '{source}', not 'merge_request_event'. Pass --allow-non-mr-ci only when merge request variables are present."
            ),
        }
    }
}

impl std::error::Error for CiContextError {}

impl GitLabCiContext {
    pub fn from_env(allow_non_mr_ci: bool) -> Result<Self> {
        let vars = env::vars().collect::<HashMap<_, _>>();
        Self::from_vars(&vars, allow_non_mr_ci)
    }

    pub fn from_vars(vars: &HashMap<String, String>, allow_non_mr_ci: bool) -> Result<Self> {
        let merge_request_iid = required_var(vars, "CI_MERGE_REQUEST_IID")
            .ok_or(CiContextError::MissingMergeRequestIid)?
            .parse::<u64>()
            .map_err(|_| CiContextError::MissingMergeRequestIid)?;

        let pipeline_source = optional_var(vars, "CI_PIPELINE_SOURCE");
        if let Some(source) = pipeline_source.as_deref() {
            if source != "merge_request_event" && !allow_non_mr_ci {
                return Err(CiContextError::NotMergeRequestPipeline {
                    source: source.to_string(),
                }
                .into());
            }
        }

        let project_path =
            required_var(vars, "CI_PROJECT_PATH").ok_or(CiContextError::MissingProjectPath)?;
        let project_url = optional_var(vars, "CI_PROJECT_URL");
        let server_url = optional_var(vars, "CI_SERVER_URL");
        let mr_url = match project_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            Some(project_url) => format!(
                "{}/-/merge_requests/{merge_request_iid}",
                project_url.trim_end_matches('/')
            ),
            None => match server_url
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                Some(server_url) => format!(
                    "{}/{}/-/merge_requests/{merge_request_iid}",
                    server_url.trim_end_matches('/'),
                    project_path.trim_matches('/')
                ),
                None => return Err(CiContextError::MissingProjectUrl.into()),
            },
        };

        Ok(Self {
            api_v4_url: optional_var(vars, "CI_API_V4_URL"),
            server_url,
            project_path,
            project_url,
            project_id: optional_var(vars, "CI_PROJECT_ID"),
            merge_request_iid,
            pipeline_source,
            commit_sha: optional_var(vars, "CI_COMMIT_SHA"),
            mr_url,
        })
    }
}

fn required_var(vars: &HashMap<String, String>, name: &str) -> Option<String> {
    optional_var(vars, name).filter(|value| !value.trim().is_empty())
}

fn optional_var(vars: &HashMap<String, String>, name: &str) -> Option<String> {
    vars.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::{CiContextError, GitLabCiContext};
    use crate::error::ReviewGateError;
    use std::collections::HashMap;

    #[test]
    fn constructs_mr_url_from_project_url() {
        let ctx = GitLabCiContext::from_vars(&base_vars(), false).unwrap();

        assert_eq!(
            ctx.mr_url,
            "https://gitlab.com/group/repo/-/merge_requests/7"
        );
        assert_eq!(ctx.project_path, "group/repo");
        assert_eq!(ctx.merge_request_iid, 7);
    }

    #[test]
    fn constructs_fallback_mr_url_from_server_url_and_project_path() {
        let mut vars = base_vars();
        vars.remove("CI_PROJECT_URL");

        let ctx = GitLabCiContext::from_vars(&vars, false).unwrap();

        assert_eq!(
            ctx.mr_url,
            "https://gitlab.com/group/repo/-/merge_requests/7"
        );
    }

    #[test]
    fn rejects_missing_merge_request_iid() {
        let mut vars = base_vars();
        vars.remove("CI_MERGE_REQUEST_IID");

        let err = GitLabCiContext::from_vars(&vars, false).unwrap_err();

        assert!(matches!(
            err,
            ReviewGateError::CiContext(CiContextError::MissingMergeRequestIid)
        ));
        assert_eq!(
            err.to_string(),
            "ReviewGate CI mode requires a GitLab merge request pipeline. CI_MERGE_REQUEST_IID is missing."
        );
    }

    #[test]
    fn rejects_missing_project_path() {
        let mut vars = base_vars();
        vars.remove("CI_PROJECT_PATH");

        let err = GitLabCiContext::from_vars(&vars, false).unwrap_err();

        assert!(matches!(
            err,
            ReviewGateError::CiContext(CiContextError::MissingProjectPath)
        ));
    }

    #[test]
    fn rejects_non_merge_request_pipeline_by_default() {
        let mut vars = base_vars();
        vars.insert("CI_PIPELINE_SOURCE".to_string(), "push".to_string());

        let err = GitLabCiContext::from_vars(&vars, false).unwrap_err();

        assert!(matches!(
            err,
            ReviewGateError::CiContext(CiContextError::NotMergeRequestPipeline { .. })
        ));
    }

    #[test]
    fn allows_non_merge_request_pipeline_when_overridden() {
        let mut vars = base_vars();
        vars.insert("CI_PIPELINE_SOURCE".to_string(), "push".to_string());

        let ctx = GitLabCiContext::from_vars(&vars, true).unwrap();

        assert_eq!(
            ctx.mr_url,
            "https://gitlab.com/group/repo/-/merge_requests/7"
        );
    }

    #[test]
    fn ci_context_debug_does_not_include_tokens() {
        let mut vars = base_vars();
        vars.insert("GITLAB_TOKEN".to_string(), "secret-token".to_string());

        let ctx = GitLabCiContext::from_vars(&vars, false).unwrap();
        let debug = format!("{ctx:?}");

        assert!(!debug.contains("secret-token"));
    }

    fn base_vars() -> HashMap<String, String> {
        HashMap::from([
            (
                "CI_API_V4_URL".to_string(),
                "https://gitlab.com/api/v4".to_string(),
            ),
            (
                "CI_SERVER_URL".to_string(),
                "https://gitlab.com".to_string(),
            ),
            ("CI_PROJECT_PATH".to_string(), "group/repo".to_string()),
            (
                "CI_PROJECT_URL".to_string(),
                "https://gitlab.com/group/repo".to_string(),
            ),
            ("CI_PROJECT_ID".to_string(), "123".to_string()),
            ("CI_MERGE_REQUEST_IID".to_string(), "7".to_string()),
            (
                "CI_PIPELINE_SOURCE".to_string(),
                "merge_request_event".to_string(),
            ),
            ("CI_COMMIT_SHA".to_string(), "abc123".to_string()),
        ])
    }
}
