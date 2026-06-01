# Configuration

ReviewGate reads environment variables and an optional `.reviewgate.toml` in the current directory.

## GitLab

```bash
GITLAB_TOKEN=
REVIEWGATE_GITLAB_TOKEN=
GITLAB_BASE_URL=https://gitlab.example.com
REVIEWGATE_ALLOW_CI_JOB_TOKEN=false
```

Recommended token source is `GITLAB_TOKEN` or `REVIEWGATE_GITLAB_TOKEN`.

## Provider

```bash
REVIEWGATE_LLM_PROVIDER=gemini_cli
REVIEWGATE_MODEL=gemini-2.5-pro
```

Supported providers:

- `gemini_cli`
- `codex_cli`
- `ollama`

## Review Limits

```bash
REVIEWGATE_REVIEW_MODE=auto
REVIEWGATE_AUTO_LARGE_FILE_THRESHOLD=30
REVIEWGATE_AUTO_LARGE_DIFF_BYTES=200000
REVIEWGATE_MAX_DIFF_BYTES=200000
REVIEWGATE_MAX_FILES=50
REVIEWGATE_MAX_CONTEXT_TOKENS=12000
REVIEWGATE_TEMPERATURE=0.1
```

`reviewgate review` defaults to `--mode auto`. Auto mode runs a lightweight plan first and switches to large-review chunking when the changed file count or total diff bytes meets the auto-large thresholds. `--large` remains supported as an alias for `--mode large`.

## Publishing

```bash
REVIEWGATE_PUBLISH_MAX_NOTE_CHARS=60000
REVIEWGATE_GITLAB_INTERNAL_NOTE=false
```

Plain `--publish` is summary-only. Inline publishing requires `--publish --publish-inline`.

## Inline Controls

```bash
REVIEWGATE_INLINE_ENABLED=false
REVIEWGATE_INLINE_DRY_RUN=true
REVIEWGATE_INLINE_DEDUPE=true
REVIEWGATE_MAX_INLINE_TOTAL=10
REVIEWGATE_MAX_HIGH_INLINE=8
REVIEWGATE_MAX_MEDIUM_INLINE=5
```

The CLI flag `--publish-inline` is still required to publish inline comments.

## Storage

```bash
REVIEWGATE_STORAGE_ENABLED=true
REVIEWGATE_DB_PATH=.reviewgate/reviewgate.sqlite
REVIEWGATE_STORE_RAW_DIFF=false
REVIEWGATE_STORE_RAW_LLM=false
REVIEWGATE_VERIFY_MAX_PREVIOUS_FINDINGS=30
```

Raw diffs and raw model payloads are not stored by default.
