# Quickstart

ReviewGate is an alpha CLI for GitLab merge request review. It can run from your local machine, GitLab CI, or a private network without a ReviewGate SaaS backend or public webhook.

## 1. Install ReviewGate

```bash
curl -fsSL https://raw.githubusercontent.com/anggaprytn/review-gate/main/scripts/install.sh | sh
reviewgate doctor
```

The installer resolves the latest GitHub Release by default. You do not need `REVIEWGATE_VERSION` unless you are intentionally testing a specific release.

## 2. Configure GitLab Access

Use a token that can read merge requests and, for publishing, write merge request notes.

```bash
export GITLAB_TOKEN="your-token"
```

`REVIEWGATE_GITLAB_TOKEN` is also supported. `CI_JOB_TOKEN` is opt-in in CI only with `REVIEWGATE_ALLOW_CI_JOB_TOKEN=true`.

## 3. Choose A Provider

Default:

```bash
export REVIEWGATE_LLM_PROVIDER=gemini_cli
export REVIEWGATE_MODEL=gemini-2.5-pro
```

`gemini_cli` and `codex_cli` use local CLI clients and local CLI auth, but they still make external model calls with the sanitized review payload.

For true local-only inference with Ollama:

```bash
export REVIEWGATE_LLM_PROVIDER=ollama
export OLLAMA_BASE_URL=http://localhost:11434
export REVIEWGATE_MODEL=qwen2.5-coder:7b
```

## 4. Run ReviewGate

```bash
reviewgate review "$MR_URL" --dry-run
reviewgate review "$MR_URL" --preview
reviewgate review "$MR_URL" --publish
reviewgate review "$MR_URL" --publish --publish-inline
reviewgate review "$MR_URL" --mode single --preview
reviewgate review "$MR_URL" --mode large --preview
reviewgate verify "$MR_URL" --preview
reviewgate verify "$MR_URL" --publish
```

Dry-run fetches GitLab metadata and diffs but skips model calls and publishing.

Preview fetches GitLab data, calls the configured provider, and prints markdown.

Review defaults to `--mode auto`, which keeps small MRs on single-pass review and switches large MRs to plan-driven chunked review. `--large` is still accepted as an alias for `--mode large`.

Plain `--publish` creates or updates one summary note. It does not publish inline comments.

Inline publishing requires both `--publish` and `--publish-inline`.

Verification uses local SQLite history from a previous ReviewGate run.

## 5. Check The Environment

```bash
reviewgate doctor
reviewgate doctor --network
```

Default doctor checks local config, token source, storage path, CI detection, and provider binaries. It does not contact GitLab or model APIs unless `--network` is used.
