# ReviewGate

ReviewGate is a CLI-first AI merge request reviewer for private GitLab teams. v0.1 focuses on GitLab self-managed instances behind VPN and local-first review workflows.

ReviewGate does not include a dashboard, SaaS backend, GitHub support, inline comment publishing, SQLite storage, Docker, GitLab Runner mode, Semgrep, LSP, or a full AST engine in v0.1.

## Real GitLab Dry Run

Connect to your VPN, export a GitLab token, then run:

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --dry-run
```

Dry-run contacts GitLab, fetches MR metadata, fetches MR diffs from the current `/diffs` API, redacts obvious secrets, applies local size limits, and prints a summary. It does not call an LLM and does not publish comments.

Example output:

```txt
ReviewGate dry run

Provider: GitLab
Base URL: https://gitlab.company.local
Project: group/repo
MR: !59
Title: Fix payment callback timeout
State: opened
Source: feature/payment-timeout
Target: main
Head SHA: abc123

Diff summary:
Changed files: 7
Generated files skipped: 0
Collapsed files: 0
Too large files: 0
Approx added lines: 120
Approx removed lines: 42
Diff bytes after redaction: 18342

Files:
- src/payment/client.ts (+42 -10)
- src/payment/webhook.ts (+55 -12)
- tests/payment/client.test.ts (+23 -20)

Status:
GitLab reachable: yes
Token valid: yes
Diff fetched: yes
LLM call: skipped in dry-run
Publish: skipped
```

## Preview

Preview fetches real GitLab metadata and diffs, builds the sanitized review prompt, and prints a truncated prompt preview:

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview
```

Preview does not publish comments. LLM review is not implemented in this step, so preview stops after prompt construction.

## Environment

Copy `.env.example` to `.env` or export variables in your shell:

```env
GITLAB_TOKEN=
REVIEWGATE_MAX_DIFF_BYTES=200000
REVIEWGATE_MAX_FILES=50
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
```

`GITLAB_TOKEN` needs permission to read merge request metadata and diffs. For GitLab personal, project, or group access tokens, use `read_api` when available; some self-managed instances may require `api` depending on policy.

## Diff Limits

ReviewGate skips generated files and files GitLab marks as `too_large`. It reports collapsed files as warnings. If sanitized diff content exceeds `REVIEWGATE_MAX_DIFF_BYTES` or included files exceed `REVIEWGATE_MAX_FILES`, ReviewGate stops adding more diff content and prints a partial review warning instead of failing the command.

## VPN Troubleshooting

If dry-run fails with a GitLab reachability or timeout error:

- Confirm the VPN is connected.
- Open the MR URL in a browser from the same machine.
- Check that DNS for the GitLab host resolves on VPN.
- Confirm the MR URL base host is the same host your token can access.
- Retry with a token that has `read_api` or `api` scope if you see 401 or 403.

ReviewGate never prints the token and does not include it in debug output.

## Privacy

Before diff text is printed in preview or passed to downstream review code, ReviewGate redacts common secret patterns such as authorization headers, bearer tokens, passwords, API keys, cookies, database URLs, `.env`-style credentials, and multiline private keys.
