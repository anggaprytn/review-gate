# ReviewGate

ReviewGate is a CLI-first AI merge request reviewer for private GitLab teams. v0.1 focuses on GitLab self-managed instances behind VPN and local-first review workflows.

ReviewGate does not include a dashboard, SaaS backend, GitHub support, SQLite storage, Docker, GitLab Runner mode, Semgrep, LSP, remote LLM providers, or a full AST engine in this step.

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

## LLM Providers

Preview fetches real GitLab metadata and diffs, builds an anchored sanitized review prompt, sends it to the configured provider, parses the model JSON, and prints ReviewGate markdown. It does not publish comments.

Default dev mode is Gemini CLI:

```env
REVIEWGATE_LLM_PROVIDER=gemini_cli
REVIEWGATE_MODEL=gemini-2.5-pro
REVIEWGATE_GEMINI_TIMEOUT_SECONDS=240
REVIEWGATE_GEMINI_BIN=gemini
REVIEWGATE_GEMINI_OUTPUT_FORMAT=json
```

Run `gemini` once and choose Login with Google, or configure Gemini CLI auth. ReviewGate does not require a direct `GEMINI_API_KEY` when Gemini CLI cached auth is available. Gemini CLI is a local client, but it still makes an external model call, so ReviewGate reports `Local-only: false` and `External model call: enabled through Gemini CLI`.

Codex CLI mode is also available:

```env
REVIEWGATE_LLM_PROVIDER=codex_cli
REVIEWGATE_MODEL=gpt-5.2-codex
REVIEWGATE_CODEX_TIMEOUT_SECONDS=240
REVIEWGATE_CODEX_BIN=codex
REVIEWGATE_CODEX_FULL_AUTO=false
```

Run `codex login` first. Codex CLI mode uses local Codex CLI authentication and does not require ReviewGate to read `OPENAI_API_KEY`. It is also an external model call and is not zero-code-exfiltration mode.

Ollama remains the true local-only provider:

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

The prompt converts the selected diff hunks into compact line anchors:

```txt
File: src/paymentClient.ts

[A0001] new_line=10 old_line=8 kind=context | export async function chargeUser(...) {
[A0002] new_line=11 old_line=- kind=added   | Authorization: [REDACTED_TOKEN]
```

The model is instructed to return `anchor_id` for line-specific findings and must not invent anchors. When an anchor is present, ReviewGate prefers it over model-provided `file_path` and `line`. If no exact anchor exists, the model may omit `anchor_id` and ReviewGate falls back to file and line mapping.

Findings also include `risk_code`, a stable machine-readable risk label such as `missing_timeout`, `pii_or_secret_logging`, `missing_authorization_check`, `api_contract_break`, or `other`. Risk codes help keep inline dedupe stable even when the model changes the title or body wording.

ReviewGate renders severity and effort labels in markdown:

```md
## 🟠 High

### 🟠 HIGH · ⚡ Quick fix · src/paymentClient.ts:11

**Authorization header is logged**

Suggested fix:
Remove the raw authorization header log or replace it with a sanitized request identifier.

Category: privacy
Risk code: pii_or_secret_logging
```

Severity is impact/risk. Effort is estimated fix complexity. Confidence is accepted from old model outputs but ignored and not shown. Set `REVIEWGATE_EMOJI=false` for plain labels in CI logs.

## GitLab Summary Publish

Publish fetches real GitLab metadata and diffs, calls the configured provider, prints the normalized ReviewGate markdown, then creates or updates one top-level merge request note. Plain `--publish` is summary-only and never posts inline comments.

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

## GitLab Inline Publish

Inline publishing is behind a second explicit safety gate:

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --publish --publish-inline
```

`--publish-inline` requires `--publish`. `REVIEWGATE_INLINE_ENABLED=true` does not publish inline comments by itself; the CLI flag is the final publish gate.

ReviewGate posts only eligible single-line findings through the GitLab merge request Discussions API. It does not post LOW or NOTE findings inline, does not create multi-line comments, and does not resolve or delete existing discussions.

Before posting, ReviewGate lists existing MR discussions and scans non-system notes for hidden markers like:

```md
<!-- reviewgate:inline version="2" project="group/repo" mr="59" fingerprint="..." head_sha="..." risk_code="missing_timeout" -->
```

If the deterministic fingerprint already exists, ReviewGate skips that inline comment and prints the skipped duplicate count. v2 fingerprints include project path, MR IID, head SHA, resolved file path, old/new line, severity, category, and `risk_code`. They intentionally do not include title, body, or suggested fix, so model wording variance should not create duplicate inline comments.

ReviewGate still reads old v1 inline markers where possible. It checks v2 fingerprints, old v1 title-based fingerprints, and position signatures from existing ReviewGate inline notes on the same head SHA. Those signatures let old v1 comments suppress equivalent new v2 comments when the resolved line and compatible risk code match, even if model wording or severity shifts between runs.

GitLab can reject a position even when local diff parsing found a candidate, especially after force-pushes, collapsed diffs, or instance-specific validation differences. Those failures are isolated per candidate and reported as failed inline comments; the summary note remains published.

## Inline Dry Run

Inline dry-run evaluates whether model findings can be mapped to valid GitLab inline diff positions. It does not post inline comments and does not call the GitLab Discussions API.

```bash
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview --inline-dry-run
GITLAB_TOKEN=xxx cargo run -- review "https://gitlab.company.local/group/repo/-/merge_requests/59" --publish --inline-dry-run
```

With `--preview --inline-dry-run`, ReviewGate fetches GitLab data, calls the configured provider, prints ReviewGate markdown, and prints an inline candidate mapping report. It does not publish anything. With `--publish --inline-dry-run`, ReviewGate still only creates or updates the top-level summary note, then prints the inline candidate mapping report.

Findings are eligible for inline placement only when severity is CRITICAL, HIGH, or MEDIUM; the finding is actionable; a valid `anchor_id` or file and line are present; the file exists in the MR diff; the requested line maps to a parsed diff position; the file is not generated, collapsed, or too large; GitLab `diff_refs` are available; and the inline limits have not been reached. Effort does not block inline placement. Defaults are 10 total inline candidates, up to 8 HIGH findings, up to 5 MEDIUM findings, and no LOW or NOTE inline candidates.

Invalid or unsafe mappings fall back to the summary. Add `--inline-dry-run` to publish mode when you want the summary note updated but no inline comments posted:

```bash
GITLAB_TOKEN=xxx cargo run -- review "$MR_URL" --publish --publish-inline --inline-dry-run
```

Dry-run wins: this updates the summary note, prints the inline mapping report, and posts zero inline discussions.

## Environment

Copy `.env.example` to `.env` or export variables in your shell:

```env
GITLAB_TOKEN=
REVIEWGATE_MAX_DIFF_BYTES=200000
REVIEWGATE_MAX_FILES=50
REVIEWGATE_INLINE_ENABLED=false
REVIEWGATE_INLINE_DRY_RUN=true
REVIEWGATE_INLINE_DEDUPE=true
REVIEWGATE_MAX_INLINE_TOTAL=10
REVIEWGATE_MAX_HIGH_INLINE=8
REVIEWGATE_MAX_MEDIUM_INLINE=5
REVIEWGATE_EMOJI=true
REVIEWGATE_LLM_PROVIDER=gemini_cli
REVIEWGATE_MODEL=gemini-2.5-pro
REVIEWGATE_GEMINI_TIMEOUT_SECONDS=240
REVIEWGATE_GEMINI_BIN=gemini
REVIEWGATE_GEMINI_OUTPUT_FORMAT=json
REVIEWGATE_CODEX_TIMEOUT_SECONDS=240
REVIEWGATE_CODEX_BIN=codex
REVIEWGATE_CODEX_FULL_AUTO=false
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_LLM_TIMEOUT_SECONDS=180
REVIEWGATE_MAX_CONTEXT_TOKENS=12000
REVIEWGATE_TEMPERATURE=0.1
REVIEWGATE_PUBLISH_MAX_NOTE_CHARS=60000
REVIEWGATE_GITLAB_INTERNAL_NOTE=false
```

`GITLAB_TOKEN` needs permission to read merge request metadata and diffs. For publish mode it also needs permission to create and update merge request notes, which usually means `api` scope.

## Diff Limits

ReviewGate skips generated files and files GitLab marks as `too_large`. It reports collapsed files as warnings and excludes collapsed files from anchored prompt lines. If sanitized diff content exceeds `REVIEWGATE_MAX_DIFF_BYTES` or included files exceed `REVIEWGATE_MAX_FILES`, ReviewGate stops adding more diff content and prints a partial review warning instead of failing the command.

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
- `Gemini CLI binary was not found`: install Gemini CLI or set `REVIEWGATE_GEMINI_BIN`.
- `Gemini CLI is not authenticated`: run `gemini` once and choose Login with Google, or configure Gemini CLI auth.
- `Gemini CLI request timed out`: increase `REVIEWGATE_GEMINI_TIMEOUT_SECONDS` or use a faster model.
- Unsupported Gemini `--output-format json`: ReviewGate falls back to text mode when detected and still extracts JSON when possible.
- Malformed Gemini JSON output: ReviewGate renders the existing malformed-output fallback and skips publish.
- `Codex CLI binary was not found`: install Codex CLI or set `REVIEWGATE_CODEX_BIN`.
- `Codex CLI is not authenticated`: run `codex login`.
- `Codex CLI request timed out`: increase `REVIEWGATE_CODEX_TIMEOUT_SECONDS` or use a faster model.
- `cannot reach GitLab base URL`: connect to VPN and confirm the MR URL opens from the same machine.
- `GITLAB_TOKEN is required`: export a token with permission to read merge request metadata and diffs.
- `unsupported LLM provider`: set `REVIEWGATE_LLM_PROVIDER=gemini_cli`, `codex_cli`, or `ollama`.
- Existing ReviewGate summary note is updated by default: pass `--force-new-note` only when a new summary note is intentional.
- `--publish-inline requires --publish`: add `--publish` or remove `--publish-inline`.
- GitLab rejected inline position: the candidate could not be placed on the current diff; ReviewGate reports the failure and continues with other candidates.
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
cargo run -- review "$MR_URL" --publish --publish-inline
cargo run -- review "$MR_URL" --publish --publish-inline
cargo run -- review "$MR_URL" --publish
```

The first publish should create one ReviewGate summary note. Later summary publishes should update that same note, not create a duplicate. The first inline publish may create eligible inline comments. Re-running inline publish should skip duplicates by ReviewGate fingerprint instead of posting the same inline comments again.

## Privacy

Before diff text is printed with `--show-prompt` or sent to the configured model endpoint, ReviewGate redacts common secret patterns such as authorization headers, bearer tokens, passwords, API keys, cookies, database URLs, `.env`-style credentials, and multiline private keys.

Local Ollama mode keeps the model call local to the configured `OLLAMA_BASE_URL`. The sanitized diff is sent only to that endpoint. ReviewGate does not publish GitLab comments in preview mode.

Publish mode posts only normalized ReviewGate markdown with run metadata. It does not publish the raw prompt, raw diff, or raw Ollama response.
