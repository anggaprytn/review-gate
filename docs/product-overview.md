# Product Overview

ReviewGate helps teams review GitLab merge requests with a local-first AI workflow.

The product goal is to make AI review useful in private engineering environments where code, tokens, and network access must stay under team control.

## v0.1 Focus

- GitLab merge request review.
- Local CLI usage.
- GitLab CI usage.
- Private network and VPN-friendly operation.
- Summary publishing.
- Optional inline comments.
- Verification of previous findings.
- Local SQLite history.
- Provider modes for Gemini CLI, Codex CLI, and Ollama.

## Non-Goals For v0.1

- SaaS backend.
- Dashboard.
- Public webhook.
- GitHub provider.
- Direct model API providers.
- Semgrep integration.
- Docker image.

## Privacy Direction

ReviewGate should be explicit about where data goes. Ollama can keep inference local. CLI providers are convenient local clients, but they still make external model calls.
