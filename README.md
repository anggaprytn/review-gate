# ReviewGate

ReviewGate is a CLI-first AI merge request reviewer for private GitLab teams. v0.1 focuses on GitLab self-managed instances behind VPN and local Ollama-compatible models, so review data can stay on your machine or inside your network.

ReviewGate does not include a dashboard, SaaS backend, GitHub support, inline comment publishing, SQLite storage, Semgrep, LSP, or a full AST engine in v0.1.

## Local GitLab MR Review

Connect to your VPN, make sure your GitLab instance and local model runtime are reachable, then run:

```bash
reviewgate review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview
```

To validate URL parsing and request planning without contacting GitLab or Ollama:

```bash
reviewgate review "https://gitlab.company.local/group/repo/-/merge_requests/59" --dry-run
```

## Environment

Copy `.env.example` to `.env` or export the variables in your shell:

```env
GITLAB_TOKEN=
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
```

`GITLAB_TOKEN` needs access to read merge request metadata and diffs. For GitLab, use `read_api` or `api` scope depending on your instance policy.

## Optional Config

ReviewGate also reads `.reviewgate.toml` from the current directory. Environment variables override file values. See `.reviewgate.example.toml` for the minimal v0.1 configuration.

## Privacy

Before sending diff text to the local model, ReviewGate redacts common secret patterns such as authorization headers, bearer tokens, passwords, API keys, cookies, database URLs, and private keys.
