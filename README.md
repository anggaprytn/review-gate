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

## Ollama Preview

Preview fetches real GitLab metadata and diffs, builds a sanitized review prompt, sends it to local Ollama, parses the model JSON, and prints ReviewGate markdown. It does not publish comments.

Install Ollama from https://ollama.com, start it, then pull a local coding model:

```bash
ollama pull qwen2.5-coder:7b
```

Example environment:

```env
GITLAB_TOKEN=xxx
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
REVIEWGATE_LLM_TIMEOUT_SECONDS=180
REVIEWGATE_MAX_CONTEXT_TOKENS=12000
REVIEWGATE_TEMPERATURE=0.1
```

Run a preview:

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview
```

To inspect model input while debugging, print the sanitized prompt before the Ollama call:

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview --show-prompt
```

## GitLab Summary Publish

Publish fetches real GitLab metadata and diffs, calls local Ollama, prints the normalized ReviewGate markdown, then creates or updates one top-level merge request note. Inline comments are not implemented yet.

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --publish
```

By default, ReviewGate adds a hidden marker like `<!-- reviewgate:summary project="group/repo" mr="59" -->`. On later publish runs, it lists existing MR notes and updates the existing non-system ReviewGate note instead of creating duplicates. Use `--force-new-note` only when you intentionally want another summary note:

```bash
cargo run -- review "$MR_URL" --publish --force-new-note
```

To create an internal GitLab note, use either `--internal-note` or `REVIEWGATE_GITLAB_INTERNAL_NOTE=true`:

```bash
cargo run -- review "$MR_URL" --publish --internal-note
```

For publishing, `GITLAB_TOKEN` needs write permission for MR notes. On GitLab personal, project, or group access tokens, use `api` scope unless your instance has a narrower custom policy that permits note creation and updates.

## Inline Dry Run

Inline dry-run evaluates whether model findings can be mapped to valid GitLab inline diff positions. It does not post inline comments and does not call the GitLab Discussions API.

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview --inline-dry-run
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --publish --inline-dry-run
```

With `--preview --inline-dry-run`, ReviewGate fetches GitLab data, calls local Ollama, prints ReviewGate markdown, and prints an inline candidate mapping report. It does not publish anything. With `--publish --inline-dry-run`, ReviewGate still only creates or updates the top-level summary note, then prints the inline candidate mapping report.

Findings are eligible for inline placement only when severity is CRITICAL, HIGH, or MEDIUM; confidence is high or medium; the finding is actionable; file and line are present; the file exists in the MR diff; the requested line maps to a parsed diff position; the file is not generated, collapsed, or too large; GitLab `diff_refs` are available; and the severity limit has not been reached. Defaults are unlimited CRITICAL, up to 8 HIGH findings, up to 5 MEDIUM findings, and no LOW or NOTE inline candidates.

Invalid or unsafe mappings fall back to the summary. Real inline publishing is planned for the next step.

## Environment

Copy `.env.example` to `.env` or export variables in your shell:

```env
GITLAB_TOKEN=
REVIEWGATE_MAX_DIFF_BYTES=200000
REVIEWGATE_MAX_FILES=50
REVIEWGATE_INLINE_ENABLED=false
REVIEWGATE_INLINE_DRY_RUN=true
REVIEWGATE_MAX_HIGH_INLINE=8
REVIEWGATE_MAX_MEDIUM_INLINE=5
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
REVIEWGATE_LLM_TIMEOUT_SECONDS=180
REVIEWGATE_MAX_CONTEXT_TOKENS=12000
REVIEWGATE_TEMPERATURE=0.1
REVIEWGATE_PUBLISH_MAX_NOTE_CHARS=60000
REVIEWGATE_GITLAB_INTERNAL_NOTE=false
```

`GITLAB_TOKEN` needs permission to read merge request metadata and diffs. For publish mode it also needs permission to create and update merge request notes, which usually means `api` scope.

## Diff Limits

ReviewGate skips generated files and files GitLab marks as `too_large`. It reports collapsed files as warnings. If sanitized diff content exceeds `REVIEWGATE_MAX_DIFF_BYTES` or included files exceed `REVIEWGATE_MAX_FILES`, ReviewGate stops adding more diff content and prints a partial review warning instead of failing the command.

## VPN Troubleshooting

If dry-run fails with a GitLab reachability or timeout error:

- Confirm the VPN is connected.
- Open the MR URL in a browser from the same machine.
- Check that DNS for the GitLab host resolves on VPN.
- Confirm the MR URL base host is the same host your token can access.
- Retry with a token that has `read_api` or `api` scope if you see 401 or 403.
- If publish returns 403, the token likely lacks write permission for MR notes.
- If ReviewGate says the GitLab base URL is unreachable, connect or reconnect the VPN and retry.

ReviewGate never prints the token and does not include it in debug output.

## Common Errors

- `cannot reach Ollama`: start Ollama and confirm `OLLAMA_BASE_URL` is reachable from this machine.
- `Ollama model ... was not found`: run `ollama pull qwen2.5-coder:7b` or set `REVIEWGATE_MODEL` to a model you have locally.
- `cannot reach GitLab base URL`: connect to VPN and confirm the MR URL opens from the same machine.
- `GITLAB_TOKEN is required`: export a token with permission to read merge request metadata and diffs.
- `Only Ollama provider is implemented in this version`: set `REVIEWGATE_LLM_PROVIDER=ollama`.
- Existing ReviewGate note is updated by default: pass `--force-new-note` only when a new summary note is intentional.
- Ollama must be running for both `--preview` and `--publish`.

## Disposable E2E Test

Use the prepared local repo without deleting it:

```bash
cd /Users/macbookprom1pro/Documents/Project/review-gate-test
git status
git remote -v
```

If the repo has no remote, set one of `REVIEWGATE_TEST_REMOTE_URL`, `GITLAB_TEST_REMOTE_URL`, or `REVIEWGATE_TEST_PROJECT_URL` before running the E2E flow. Create a branch such as `reviewgate/e2e-risky-change`, add harmless fake TypeScript or JavaScript code with reviewable risks, commit, push, and create or reuse a GitLab MR. Then run from this repository:

```bash
cargo run -- review "$MR_URL" --dry-run
cargo run -- review "$MR_URL" --preview
cargo run -- review "$MR_URL" --preview --inline-dry-run
cargo run -- review "$MR_URL" --publish
cargo run -- review "$MR_URL" --publish --inline-dry-run
cargo run -- review "$MR_URL" --publish
```

The first publish should create one ReviewGate summary note. The second publish should update that same note, not create a duplicate. Inline comments remain disabled.

## Privacy

Before diff text is printed with `--show-prompt` or sent to the configured model endpoint, ReviewGate redacts common secret patterns such as authorization headers, bearer tokens, passwords, API keys, cookies, database URLs, `.env`-style credentials, and multiline private keys.

Local Ollama mode keeps the model call local to the configured `OLLAMA_BASE_URL`. The sanitized diff is sent only to that endpoint. ReviewGate does not publish GitLab comments in preview mode.

Publish mode posts only normalized ReviewGate markdown with run metadata. It does not publish the raw prompt, raw diff, or raw Ollama response.
