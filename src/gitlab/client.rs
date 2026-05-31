use crate::{
    error::{Result, ReviewGateError},
    gitlab::{
        types::{MergeRequestChanges, MergeRequestMetadata},
        url::GitLabMrUrl,
    },
};
use reqwest::{header::HeaderName, StatusCode};

const PRIVATE_TOKEN_HEADER: HeaderName = HeaderName::from_static("private-token");

#[derive(Debug, Clone)]
pub struct GitLabClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl GitLabClient {
    pub fn new(base_url: String, token: Option<String>, http: reqwest::Client) -> Result<Self> {
        let token = token.ok_or(ReviewGateError::MissingGitLabToken)?;
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    pub async fn fetch_merge_request(&self, mr: &GitLabMrUrl) -> Result<MergeRequestMetadata> {
        let url = format!(
            "{}/api/v4/projects/{}/merge_requests/{}",
            self.base_url, mr.encoded_project_path, mr.mr_iid
        );
        self.get_json(&url).await
    }

    pub async fn fetch_merge_request_diff(&self, mr: &GitLabMrUrl) -> Result<MergeRequestChanges> {
        let url = format!(
            "{}/api/v4/projects/{}/merge_requests/{}/changes",
            self.base_url, mr.encoded_project_path, mr.mr_iid
        );
        self.get_json(&url).await
    }

    async fn get_json<T>(&self, url: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .get(url)
            .header(PRIVATE_TOKEN_HEADER, &self.token)
            .send()
            .await
            .map_err(map_gitlab_request_error)?;

        match response.status() {
            StatusCode::OK => response.json::<T>().await.map_err(ReviewGateError::from),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(ReviewGateError::InvalidGitLabToken)
            }
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(ReviewGateError::GitLabApi(format!(
                    "request failed with status {status}: {body}"
                )))
            }
        }
    }
}

fn map_gitlab_request_error(err: reqwest::Error) -> ReviewGateError {
    if err.is_connect() || err.is_timeout() {
        ReviewGateError::GitLabUnreachable
    } else {
        ReviewGateError::Reqwest(err)
    }
}
