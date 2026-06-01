# Providers

ReviewGate v0.1 supports three provider modes.

## gemini_cli

`gemini_cli` is the default provider.

```bash
export REVIEWGATE_LLM_PROVIDER=gemini_cli
export REVIEWGATE_MODEL=gemini-2.5-pro
export REVIEWGATE_GEMINI_BIN=gemini
```

Run and authenticate the Gemini CLI before using ReviewGate. This is a local CLI client, but the sanitized review payload is still sent to an external model service.

## codex_cli

```bash
export REVIEWGATE_LLM_PROVIDER=codex_cli
export REVIEWGATE_MODEL=gpt-5.2-codex
export REVIEWGATE_CODEX_BIN=codex
```

Run `codex login` before using this provider. This is a local CLI client, but the sanitized review payload is still sent to an external model service.

`REVIEWGATE_CODEX_FULL_AUTO=true` is intentionally rejected because ReviewGate's Codex CLI provider must stay read-only.

## ollama

```bash
export REVIEWGATE_LLM_PROVIDER=ollama
export OLLAMA_BASE_URL=http://localhost:11434
export REVIEWGATE_MODEL=qwen2.5-coder:7b
```

Ollama is the true local-only model mode when Ollama and the model run inside your environment.

## Unsupported In v0.1

ReviewGate does not include direct OpenAI API, direct Gemini API, GitHub provider, Semgrep, or dashboard integrations in v0.1.
