# Privacy

ReviewGate is local-first alpha software for GitLab merge request review.

- No SaaS backend.
- No public webhook required.
- No dashboard service.
- No ReviewGate-hosted queue or worker.

ReviewGate fetches merge request metadata and diffs from GitLab using your configured token. It redacts obvious secrets, applies size limits, and sends a sanitized review payload to the selected provider.

## Provider Privacy

`ollama` is the local-only model mode when Ollama and the selected model run inside your machine or private network.

`gemini_cli` and `codex_cli` are local CLI clients, but they still send the sanitized review payload to external model services through those CLIs.

ReviewGate does not send code, prompts, or model output to a ReviewGate-operated service because there is no ReviewGate SaaS backend in v0.1.

## Storage

ReviewGate stores local SQLite history at `.reviewgate/reviewgate.sqlite` by default.

By default:

- Raw diffs are not stored.
- Raw model payloads are not stored.
- Raw prompts are not stored.
- Tokens are not persisted.

Stored data includes run metadata, normalized findings, publish metadata, inline dedupe metadata, and verification results.

## Tokens

Tokens are loaded from environment or config at runtime. ReviewGate never prints token values intentionally and does not persist tokens.

Secret redaction is best-effort. Treat ReviewGate output as review assistance, not as a substitute for normal secret scanning, access controls, or human review.
