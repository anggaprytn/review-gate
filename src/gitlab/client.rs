use crate::{
    error::{Result, ReviewGateError},
    gitlab::{
        publish::{select_publish_target, summary_marker, verification_marker},
        types::{
            CreateMergeRequestDiscussionRequest, CreateMergeRequestNoteRequest, GitLabDiscussion,
            GitLabNote, MergeRequestDiff, MergeRequestMetadata, PublishAction, PublishResult,
            UpdateMergeRequestNoteRequest,
        },
        url::GitLabMrUrl,
    },
};
use reqwest::{
    header::{HeaderMap, HeaderName},
    StatusCode,
};
use std::{fmt, time::Duration};

const PRIVATE_TOKEN_HEADER: HeaderName = HeaderName::from_static("private-token");
const DEFAULT_PER_PAGE: u16 = 100;

#[derive(Clone)]
pub struct GitLabClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl fmt::Debug for GitLabClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabClient")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl GitLabClient {
    pub fn new(base_url: String, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(format!("reviewgate/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Self::with_http(base_url, token, http)
    }

    pub fn with_http(
        base_url: String,
        token: Option<String>,
        http: reqwest::Client,
    ) -> Result<Self> {
        let token = token.ok_or(ReviewGateError::MissingGitLabToken)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    pub async fn fetch_merge_request(&self, mr: &GitLabMrUrl) -> Result<MergeRequestMetadata> {
        let url = metadata_api_url(&self.base_url, mr);
        self.get_json(&url).await
    }

    pub async fn fetch_merge_request_diffs(
        &self,
        mr: &GitLabMrUrl,
    ) -> Result<Vec<MergeRequestDiff>> {
        match self.fetch_merge_request_diff_pages(mr, true).await {
            Err(ReviewGateError::UnsupportedGitLabParameter(_)) => {
                self.fetch_merge_request_diff_pages(mr, false).await
            }
            result => result,
        }
    }

    async fn fetch_merge_request_diff_pages(
        &self,
        mr: &GitLabMrUrl,
        unidiff: bool,
    ) -> Result<Vec<MergeRequestDiff>> {
        let mut page = 1;
        let mut diffs = Vec::new();

        loop {
            let url = diffs_api_url(&self.base_url, mr, page, DEFAULT_PER_PAGE, unidiff);
            let (mut page_diffs, pagination) = self.get_json_with_headers(&url, unidiff).await?;
            diffs.append(&mut page_diffs);

            match pagination.next_page {
                Some(next_page) => page = next_page,
                None => break,
            }
        }

        Ok(diffs)
    }

    pub async fn list_merge_request_notes(&self, mr: &GitLabMrUrl) -> Result<Vec<GitLabNote>> {
        let mut page = 1;
        let mut notes = Vec::new();

        loop {
            let url = notes_api_url(&self.base_url, mr, page, DEFAULT_PER_PAGE);
            let (mut page_notes, pagination) = self.get_json_with_headers(&url, false).await?;
            notes.append(&mut page_notes);

            match pagination.next_page {
                Some(next_page) => page = next_page,
                None => break,
            }
        }

        Ok(notes)
    }

    pub async fn list_merge_request_discussions(
        &self,
        mr: &GitLabMrUrl,
    ) -> Result<Vec<GitLabDiscussion>> {
        let mut page = 1;
        let mut discussions = Vec::new();

        loop {
            let url = discussions_api_url(&self.base_url, mr, page, DEFAULT_PER_PAGE);
            let (mut page_discussions, pagination) =
                self.get_json_with_headers(&url, false).await?;
            discussions.append(&mut page_discussions);

            match pagination.next_page {
                Some(next_page) => page = next_page,
                None => break,
            }
        }

        Ok(discussions)
    }

    pub async fn create_merge_request_note(
        &self,
        mr: &GitLabMrUrl,
        request: &CreateMergeRequestNoteRequest,
    ) -> Result<GitLabNote> {
        let url = create_note_api_url(&self.base_url, mr);
        self.send_json(reqwest::Method::POST, &url, request).await
    }

    pub async fn update_merge_request_note(
        &self,
        mr: &GitLabMrUrl,
        note_id: u64,
        request: &UpdateMergeRequestNoteRequest,
    ) -> Result<GitLabNote> {
        let url = update_note_api_url(&self.base_url, mr, note_id);
        self.send_json(reqwest::Method::PUT, &url, request).await
    }

    pub async fn create_merge_request_discussion(
        &self,
        mr: &GitLabMrUrl,
        request: &CreateMergeRequestDiscussionRequest,
    ) -> Result<GitLabDiscussion> {
        let url = create_discussion_api_url(&self.base_url, mr);
        self.send_form(
            reqwest::Method::POST,
            &url,
            &discussion_form_fields(request),
        )
        .await
    }

    pub async fn publish_merge_request_summary(
        &self,
        mr: &GitLabMrUrl,
        body: String,
        force_new_note: bool,
        internal_note: bool,
    ) -> Result<PublishResult> {
        let marker = summary_marker(&mr.project_path, mr.mr_iid);
        let notes = if force_new_note {
            Vec::new()
        } else {
            self.list_merge_request_notes(mr).await?
        };
        let target = select_publish_target(&notes, &marker, force_new_note);

        match target.action {
            PublishAction::Created => {
                let note = self
                    .create_merge_request_note(
                        mr,
                        &CreateMergeRequestNoteRequest {
                            body,
                            internal: Some(internal_note),
                        },
                    )
                    .await?;
                Ok(PublishResult {
                    action: PublishAction::Created,
                    note_id: Some(note.id),
                    web_url: None,
                    duplicate_count: target.duplicate_count,
                })
            }
            PublishAction::Updated => {
                let note_id = target.note_id.ok_or_else(|| {
                    ReviewGateError::GitLabApi(
                        "selected ReviewGate note did not include a note ID".to_string(),
                    )
                })?;
                let note = self
                    .update_merge_request_note(mr, note_id, &UpdateMergeRequestNoteRequest { body })
                    .await?;
                Ok(PublishResult {
                    action: PublishAction::Updated,
                    note_id: Some(note.id),
                    web_url: None,
                    duplicate_count: target.duplicate_count,
                })
            }
        }
    }

    pub async fn publish_merge_request_verification(
        &self,
        mr: &GitLabMrUrl,
        body: String,
        force_new_note: bool,
        internal_note: bool,
    ) -> Result<PublishResult> {
        let marker = verification_marker(&mr.project_path, mr.mr_iid);
        let notes = if force_new_note {
            Vec::new()
        } else {
            self.list_merge_request_notes(mr).await?
        };
        let target = select_publish_target(&notes, &marker, force_new_note);

        match target.action {
            PublishAction::Created => {
                let note = self
                    .create_merge_request_note(
                        mr,
                        &CreateMergeRequestNoteRequest {
                            body,
                            internal: Some(internal_note),
                        },
                    )
                    .await?;
                Ok(PublishResult {
                    action: PublishAction::Created,
                    note_id: Some(note.id),
                    web_url: None,
                    duplicate_count: target.duplicate_count,
                })
            }
            PublishAction::Updated => {
                let note_id = target.note_id.ok_or_else(|| {
                    ReviewGateError::GitLabApi(
                        "selected ReviewGate verification note did not include a note ID"
                            .to_string(),
                    )
                })?;
                let note = self
                    .update_merge_request_note(mr, note_id, &UpdateMergeRequestNoteRequest { body })
                    .await?;
                Ok(PublishResult {
                    action: PublishAction::Updated,
                    note_id: Some(note.id),
                    web_url: None,
                    duplicate_count: target.duplicate_count,
                })
            }
        }
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

        let status = response.status();
        if status == StatusCode::OK {
            return response
                .json::<T>()
                .await
                .map_err(|err| ReviewGateError::MalformedGitLabResponse(err.to_string()));
        }

        let body = response.text().await.unwrap_or_default();
        Err(map_gitlab_status_error(status, body, false))
    }

    async fn get_json_with_headers<T>(
        &self,
        url: &str,
        allow_unidiff_fallback: bool,
    ) -> Result<(T, Pagination)>
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

        let status = response.status();
        let headers = response.headers().clone();
        if status == StatusCode::OK {
            let value = response
                .json::<T>()
                .await
                .map_err(|err| ReviewGateError::MalformedGitLabResponse(err.to_string()))?;
            return Ok((value, Pagination::from_headers(&headers)));
        }

        let body = response.text().await.unwrap_or_default();
        Err(map_gitlab_status_error(
            status,
            body,
            allow_unidiff_fallback,
        ))
    }

    async fn send_json<T, R>(&self, method: reqwest::Method, url: &str, body: &R) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        R: serde::Serialize + ?Sized,
    {
        let response = self
            .http
            .request(method, url)
            .header(PRIVATE_TOKEN_HEADER, &self.token)
            .json(body)
            .send()
            .await
            .map_err(map_gitlab_request_error)?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<T>()
                .await
                .map_err(|err| ReviewGateError::MalformedGitLabResponse(err.to_string()));
        }

        let body = response.text().await.unwrap_or_default();
        Err(map_gitlab_status_error(status, body, false))
    }

    async fn send_form<T>(
        &self,
        method: reqwest::Method,
        url: &str,
        fields: &[(String, String)],
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .request(method, url)
            .header(PRIVATE_TOKEN_HEADER, &self.token)
            .form(fields)
            .send()
            .await
            .map_err(map_gitlab_request_error)?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<T>()
                .await
                .map_err(|err| ReviewGateError::MalformedGitLabResponse(err.to_string()));
        }

        let body = response.text().await.unwrap_or_default();
        Err(map_gitlab_status_error(status, body, false))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    pub page: Option<u32>,
    pub next_page: Option<u32>,
    pub total_pages: Option<u32>,
}

impl Pagination {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            page: header_u32(headers, "x-page"),
            next_page: header_u32(headers, "x-next-page"),
            total_pages: header_u32(headers, "x-total-pages"),
        }
    }
}

pub fn metadata_api_url(base_url: &str, mr: &GitLabMrUrl) -> String {
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn diffs_api_url(
    base_url: &str,
    mr: &GitLabMrUrl,
    page: u32,
    per_page: u16,
    unidiff: bool,
) -> String {
    let unidiff_query = if unidiff { "&unidiff=true" } else { "" };
    let page_query = if page > 1 {
        format!("&page={page}")
    } else {
        String::new()
    };
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}/diffs?per_page={per_page}{unidiff_query}{page_query}",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn notes_api_url(base_url: &str, mr: &GitLabMrUrl, page: u32, per_page: u16) -> String {
    let page_query = if page > 1 {
        format!("&page={page}")
    } else {
        String::new()
    };
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}/notes?per_page={per_page}&sort=desc&order_by=updated_at{page_query}",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn create_note_api_url(base_url: &str, mr: &GitLabMrUrl) -> String {
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}/notes",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn update_note_api_url(base_url: &str, mr: &GitLabMrUrl, note_id: u64) -> String {
    format!("{}/{}", create_note_api_url(base_url, mr), note_id)
}

pub fn discussions_api_url(base_url: &str, mr: &GitLabMrUrl, page: u32, per_page: u16) -> String {
    let page_query = if page > 1 {
        format!("&page={page}")
    } else {
        String::new()
    };
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}/discussions?per_page={per_page}{page_query}",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn create_discussion_api_url(base_url: &str, mr: &GitLabMrUrl) -> String {
    format!(
        "{}/api/v4/projects/{}/merge_requests/{}/discussions",
        base_url.trim_end_matches('/'),
        mr.encoded_project_path,
        mr.mr_iid
    )
}

pub fn discussion_form_fields(
    request: &CreateMergeRequestDiscussionRequest,
) -> Vec<(String, String)> {
    let position = &request.position;
    let mut fields = vec![
        ("body".to_string(), request.body.clone()),
        (
            "position[position_type]".to_string(),
            position.position_type.clone(),
        ),
        ("position[base_sha]".to_string(), position.base_sha.clone()),
        (
            "position[start_sha]".to_string(),
            position.start_sha.clone(),
        ),
        ("position[head_sha]".to_string(), position.head_sha.clone()),
        ("position[old_path]".to_string(), position.old_path.clone()),
        ("position[new_path]".to_string(), position.new_path.clone()),
    ];

    if let Some(old_line) = position.old_line {
        fields.push(("position[old_line]".to_string(), old_line.to_string()));
    }
    if let Some(new_line) = position.new_line {
        fields.push(("position[new_line]".to_string(), new_line.to_string()));
    }

    fields
}

fn header_u32(headers: &HeaderMap, name: &str) -> Option<u32> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.parse().ok()
            }
        })
}

fn map_gitlab_status_error(
    status: StatusCode,
    body: String,
    allow_unidiff_fallback: bool,
) -> ReviewGateError {
    if allow_unidiff_fallback && unsupported_unidiff_response(status, &body) {
        return ReviewGateError::UnsupportedGitLabParameter("unidiff=true".to_string());
    }

    match status {
        StatusCode::UNAUTHORIZED => ReviewGateError::InvalidGitLabToken,
        StatusCode::FORBIDDEN => ReviewGateError::GitLabForbidden,
        StatusCode::NOT_FOUND => ReviewGateError::GitLabNotFound,
        StatusCode::TOO_MANY_REQUESTS => ReviewGateError::GitLabRateLimited,
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            ReviewGateError::GitLabValidation(clean_error_body(&body))
        }
        StatusCode::PAYLOAD_TOO_LARGE => ReviewGateError::PublishNoteBodyTooLarge,
        _ => ReviewGateError::GitLabApi(format!(
            "request failed with status {status}: {}",
            clean_error_body(&body)
        )),
    }
}

fn unsupported_unidiff_response(status: StatusCode, body: &str) -> bool {
    if !matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return false;
    }

    let body = body.to_lowercase();
    body.contains("unidiff")
        && (body.contains("unsupported")
            || body.contains("unknown")
            || body.contains("invalid")
            || body.contains("not allowed"))
}

fn clean_error_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "empty response body".to_string()
    } else {
        trimmed.chars().take(500).collect()
    }
}

fn map_gitlab_request_error(err: reqwest::Error) -> ReviewGateError {
    if err.is_timeout() {
        ReviewGateError::GitLabTimeout
    } else if err.is_connect() || err.is_request() {
        ReviewGateError::GitLabUnreachable
    } else {
        ReviewGateError::Reqwest(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        create_discussion_api_url, create_note_api_url, diffs_api_url, discussion_form_fields,
        discussions_api_url, map_gitlab_status_error, metadata_api_url, notes_api_url,
        unsupported_unidiff_response, update_note_api_url, Pagination,
    };
    use crate::{
        error::ReviewGateError,
        gitlab::{types::CreateMergeRequestDiscussionRequest, url::GitLabMrUrl},
        review::inline::GitLabInlinePosition,
    };
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn builds_gitlab_api_urls_without_changes_endpoint() {
        let mr = GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59")
            .unwrap();

        assert_eq!(
            metadata_api_url("https://gitlab.company.local/", &mr),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59"
        );
        assert_eq!(
            diffs_api_url("https://gitlab.company.local", &mr, 2, 100, true),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/diffs?per_page=100&unidiff=true&page=2"
        );
        assert_eq!(
            diffs_api_url("https://gitlab.company.local", &mr, 1, 100, true),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/diffs?per_page=100&unidiff=true"
        );
        assert!(
            !diffs_api_url("https://gitlab.company.local", &mr, 1, 100, false).contains("/changes")
        );
        assert_eq!(
            notes_api_url("https://gitlab.company.local", &mr, 2, 100),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/notes?per_page=100&sort=desc&order_by=updated_at&page=2"
        );
        assert_eq!(
            create_note_api_url("https://gitlab.company.local", &mr),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/notes"
        );
        assert_eq!(
            update_note_api_url("https://gitlab.company.local", &mr, 123),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/notes/123"
        );
        assert_eq!(
            discussions_api_url("https://gitlab.company.local", &mr, 2, 100),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/discussions?per_page=100&page=2"
        );
        assert_eq!(
            create_discussion_api_url("https://gitlab.company.local", &mr),
            "https://gitlab.company.local/api/v4/projects/group%2Frepo/merge_requests/59/discussions"
        );
    }

    #[test]
    fn builds_added_line_discussion_form_payload() {
        let fields = discussion_form_fields(&discussion_request(None, Some(42)));

        assert!(has_field(&fields, "position[new_line]", "42"));
        assert!(!fields.iter().any(|(key, _)| key == "position[old_line]"));
    }

    #[test]
    fn builds_removed_line_discussion_form_payload() {
        let fields = discussion_form_fields(&discussion_request(Some(7), None));

        assert!(has_field(&fields, "position[old_line]", "7"));
        assert!(!fields.iter().any(|(key, _)| key == "position[new_line]"));
    }

    #[test]
    fn builds_context_line_discussion_form_payload() {
        let fields = discussion_form_fields(&discussion_request(Some(7), Some(9)));

        assert!(has_field(&fields, "position[old_line]", "7"));
        assert!(has_field(&fields, "position[new_line]", "9"));
    }

    #[test]
    fn parses_gitlab_pagination_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-page", HeaderValue::from_static("1"));
        headers.insert("x-next-page", HeaderValue::from_static("2"));
        headers.insert("x-total-pages", HeaderValue::from_static("3"));

        let pagination = Pagination::from_headers(&headers);

        assert_eq!(pagination.page, Some(1));
        assert_eq!(pagination.next_page, Some(2));
        assert_eq!(pagination.total_pages, Some(3));
    }

    #[test]
    fn treats_empty_next_page_as_end_of_pagination() {
        let mut headers = HeaderMap::new();
        headers.insert("x-next-page", HeaderValue::from_static(""));

        let pagination = Pagination::from_headers(&headers);

        assert_eq!(pagination.next_page, None);
    }

    #[test]
    fn detects_unsupported_unidiff_client_error() {
        assert!(unsupported_unidiff_response(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":"unknown parameter: unidiff"}"#
        ));
        assert!(!unsupported_unidiff_response(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"unknown parameter: unidiff"}"#
        ));
    }

    #[test]
    fn missing_token_returns_clear_error() {
        let err =
            super::GitLabClient::new("https://gitlab.company.local".to_string(), None).unwrap_err();

        assert!(matches!(err, ReviewGateError::MissingGitLabToken));
    }

    #[test]
    fn debug_output_redacts_token() {
        let client = super::GitLabClient::new(
            "https://gitlab.company.local".to_string(),
            Some("secret-token".to_string()),
        )
        .unwrap();

        let debug = format!("{client:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn maps_publish_status_errors_to_user_facing_errors() {
        assert!(matches!(
            map_gitlab_status_error(reqwest::StatusCode::UNAUTHORIZED, String::new(), false),
            ReviewGateError::InvalidGitLabToken
        ));
        assert!(matches!(
            map_gitlab_status_error(reqwest::StatusCode::FORBIDDEN, String::new(), false),
            ReviewGateError::GitLabForbidden
        ));
        assert!(matches!(
            map_gitlab_status_error(reqwest::StatusCode::NOT_FOUND, String::new(), false),
            ReviewGateError::GitLabNotFound
        ));
        assert!(matches!(
            map_gitlab_status_error(reqwest::StatusCode::TOO_MANY_REQUESTS, String::new(), false),
            ReviewGateError::GitLabRateLimited
        ));
        assert!(matches!(
            map_gitlab_status_error(
                reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                "body is too long".to_string(),
                false
            ),
            ReviewGateError::GitLabValidation(_)
        ));
    }

    fn discussion_request(
        old_line: Option<u32>,
        new_line: Option<u32>,
    ) -> CreateMergeRequestDiscussionRequest {
        CreateMergeRequestDiscussionRequest {
            body: "body".to_string(),
            position: GitLabInlinePosition {
                position_type: "text".to_string(),
                base_sha: "base".to_string(),
                start_sha: "start".to_string(),
                head_sha: "head".to_string(),
                old_path: "src/a.rs".to_string(),
                new_path: "src/a.rs".to_string(),
                old_line,
                new_line,
            },
        }
    }

    fn has_field(fields: &[(String, String)], key: &str, value: &str) -> bool {
        fields
            .iter()
            .any(|(field_key, field_value)| field_key == key && field_value == value)
    }
}
