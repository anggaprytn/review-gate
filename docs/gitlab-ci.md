# GitLab CI

ReviewGate can run inside GitLab merge request pipelines.

```yaml
reviewgate:
  stage: review
  script:
    - reviewgate review --ci --publish
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

`reviewgate review --ci` infers the merge request URL from GitLab CI environment variables and fails closed unless the pipeline source is `merge_request_event`.

## Token Source

Recommended token sources:

- `GITLAB_TOKEN`
- `REVIEWGATE_GITLAB_TOKEN`

`CI_JOB_TOKEN` is opt-in with:

```bash
REVIEWGATE_ALLOW_CI_JOB_TOKEN=true
```

Only enable `CI_JOB_TOKEN` if your GitLab instance permits the required merge request note APIs for job tokens.

## Local CI History

ReviewGate history is local to the job workspace by default:

```bash
REVIEWGATE_DB_PATH=.reviewgate/reviewgate.sqlite
```

Verification needs previous ReviewGate history. In CI, that history is local unless `.reviewgate/reviewgate.sqlite` is cached or uploaded as an artifact and restored in later jobs.

## Provider Notes

`gemini_cli` and `codex_cli` may require cached interactive authentication. For locked-down CI, use a runner image or private runner where the CLI auth is already configured, or use `ollama` inside the private network.
