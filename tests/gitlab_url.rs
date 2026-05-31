use reviewgate::gitlab::url::GitLabMrUrl;

#[test]
fn parses_simple_project_merge_request_url() {
    let parsed =
        GitLabMrUrl::parse("https://gitlab.company.local/group/repo/-/merge_requests/59").unwrap();

    assert_eq!(parsed.base_url, "https://gitlab.company.local");
    assert_eq!(parsed.project_path, "group/repo");
    assert_eq!(parsed.encoded_project_path, "group%2Frepo");
    assert_eq!(parsed.mr_iid, 59);
}

#[test]
fn parses_subgroup_project_merge_request_url() {
    let parsed =
        GitLabMrUrl::parse("https://gitlab.company.local/group/subgroup/repo/-/merge_requests/59")
            .unwrap();

    assert_eq!(parsed.base_url, "https://gitlab.company.local");
    assert_eq!(parsed.project_path, "group/subgroup/repo");
    assert_eq!(parsed.encoded_project_path, "group%2Fsubgroup%2Frepo");
    assert_eq!(parsed.mr_iid, 59);
}

#[test]
fn rejects_invalid_merge_request_url() {
    let err = GitLabMrUrl::parse("https://gitlab.company.local/group/repo/issues/59");

    assert!(err.is_err());
}

#[test]
fn encodes_project_path_for_gitlab_api() {
    let parsed =
        GitLabMrUrl::parse("https://gitlab.company.local/group/subgroup/repo/-/merge_requests/1")
            .unwrap();

    assert_eq!(parsed.encoded_project_path, "group%2Fsubgroup%2Frepo");
}
