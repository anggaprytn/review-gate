# Privacy

ReviewGate is local-first.

- No SaaS backend.
- No public webhook required.
- No dashboard service.
- No ReviewGate-hosted queue or worker.

ReviewGate fetches merge request metadata and diffs from GitLab using your configured token. It redacts obvious secrets, applies size limits, and sends a sanitized review payload to the selected provider.

## Provider Privacy

`ollama` can keep model inference local when Ollama and the selected model run inside your machine or private network.

`gemini_cli` and `codex_cli` are local CLI clients, but they still send the sanitized review payload to external model services through those CLIs.

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
