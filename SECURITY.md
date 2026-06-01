# Security Policy

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through the repository security advisory flow if available. If that is not available, contact the maintainers using the private channel listed on the project page.

Do not open a public issue that includes exploit details, private GitLab URLs, tokens, or proprietary source code.

## Supported Scope

ReviewGate is a local-first CLI. It fetches merge request data from GitLab using your token and sends sanitized review payloads to the selected provider.

Provider privacy differs:

- `ollama` can keep model inference local when Ollama runs inside your environment.
- `gemini_cli` and `codex_cli` are local CLI clients, but they make external model calls.

ReviewGate does not persist tokens. Raw diffs and raw model payloads are not stored by default.

## Token Handling

Use `GITLAB_TOKEN` or `REVIEWGATE_GITLAB_TOKEN`. `CI_JOB_TOKEN` is opt-in with `REVIEWGATE_ALLOW_CI_JOB_TOKEN=true`.

Never include token values in bug reports, logs, screenshots, or test fixtures.
