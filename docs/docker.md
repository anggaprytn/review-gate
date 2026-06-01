# Docker

ReviewGate publishes a container image for GitLab CI, private runners, and internal networks where installing from source is not desirable.

## Local Image

Build and smoke test a local image:

```bash
docker build -t reviewgate:local .
docker run --rm reviewgate:local --version
docker run --rm reviewgate:local doctor
```

The ReviewGate binary is installed at:

```text
/usr/local/bin/reviewgate
```

The image starts as a non-root user and defaults to `reviewgate --help`.

## GitLab CI

Use the Docker image directly in merge request pipelines:

```yaml
reviewgate:
  stage: review
  image: ghcr.io/anggaprytn/review-gate:v0.1.0-alpha.3
  variables:
    REVIEWGATE_LLM_PROVIDER: "ollama"
    OLLAMA_BASE_URL: "http://ollama:11434"
  script:
    - reviewgate doctor
    - reviewgate review --ci --publish
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

For early rollout, use `--soft-fail` so ReviewGate reports findings without failing the pipeline:

```yaml
script:
  - reviewgate review --ci --publish --soft-fail
```

See [../examples/gitlab-ci-docker-reviewgate.yml](../examples/gitlab-ci-docker-reviewgate.yml) for a complete example.

## Provider Notes

`ollama` is the recommended Docker and CI provider for private networks. Run Ollama where the CI runner can reach it and set `OLLAMA_BASE_URL` to that internal endpoint.

`gemini_cli` and `codex_cli` inside Docker are not recommended unless their authentication is explicitly mounted and understood. Do not mount local authentication tokens into CI containers by default.

Privacy depends on the provider mode you choose. With `ollama`, model inference can stay inside your machine or private network. With `gemini_cli` or `codex_cli`, the sanitized review payload is still sent to the external model service used by that CLI.

ReviewGate does not bake tokens, `.env`, `.reviewgate/`, `docs/PRD.md`, or local build output into the Docker image.
