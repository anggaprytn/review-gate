use crate::error::{Result, ReviewGateError};
use serde::{Deserialize, Serialize};
use url::{form_urlencoded::byte_serialize, Url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabMrUrl {
    pub base_url: String,
    pub project_path: String,
    pub encoded_project_path: String,
    pub mr_iid: u64,
}

impl GitLabMrUrl {
    pub fn parse(input: &str) -> Result<Self> {
        let url = Url::parse(input).map_err(|_| ReviewGateError::InvalidMrUrl(input.into()))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(ReviewGateError::InvalidMrUrl(input.into()));
        }

        let segments: Vec<&str> = url
            .path_segments()
            .ok_or_else(|| ReviewGateError::InvalidMrUrl(input.into()))?
            .collect();

        let marker_index = segments
            .iter()
            .position(|segment| *segment == "-")
            .ok_or_else(|| ReviewGateError::InvalidMrUrl(input.into()))?;

        if segments.get(marker_index + 1) != Some(&"merge_requests") {
            return Err(ReviewGateError::InvalidMrUrl(input.into()));
        }

        let mr_iid = segments
            .get(marker_index + 2)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| ReviewGateError::InvalidMrUrl(input.into()))?;

        if marker_index == 0 {
            return Err(ReviewGateError::InvalidMrUrl(input.into()));
        }

        let project_path = segments[..marker_index].join("/");
        let encoded_project_path: String = byte_serialize(project_path.as_bytes()).collect();
        let base_url = base_url(&url)?;

        Ok(Self {
            base_url,
            project_path,
            encoded_project_path,
            mr_iid,
        })
    }
}

fn base_url(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| ReviewGateError::InvalidMrUrl(url.as_str().into()))?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Ok(format!("{}://{}{}", url.scheme(), host, port))
}
