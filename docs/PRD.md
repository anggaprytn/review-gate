# PRD: ReviewGate

## 1. Product Summary

**ReviewGate** is a local-first AI merge request review engine for private engineering teams using GitLab self-managed, GitLab behind VPN, GitHub Enterprise, or GitHub.

The first product wedge is **GitLab behind VPN**.

ReviewGate runs from a developer machine, internal server, or GitLab Runner. It fetches MR diffs through the private GitLab API, analyzes changes with a local or BYOK LLM, then posts structured review comments back into the merge request.

The core value:

> CodeRabbit-like MR review, but local-first, on-prem friendly, BYOK, and usable inside private VPN networks.

The sharper enterprise value:

> 100% private AI code review for GitLab behind VPN, with optional zero-code-exfiltration mode using local models.

## 2. Strategic Product Decision

ReviewGate v0.1 will **not** start with a dashboard.

The first version must prove the core loop:

```txt
Private GitLab MR URL
-> fetch diff locally through VPN
-> analyze with local LLM or BYOK model
-> generate review markdown
-> optionally post MR comments
```

Dashboard is deferred until the review loop is already useful.

Reason:

Developers do not want another tab. They want the review inside the MR comment thread or CI pipeline.

## 3. Product Positioning

### 3.1 Simple Positioning

Local AI code reviewer for private GitLab teams.

### 3.2 Strong Positioning

CodeRabbit-like MR review, but local-first, BYOK, and built for GitLab behind VPN.

### 3.3 Enterprise Positioning

ReviewGate helps private engineering teams reduce review bottlenecks and catch risky code changes inside their own network without exposing repositories to external code review SaaS.

### 3.4 Security-first Positioning

ReviewGate can run fully inside the customer network using local models such as Llama, Qwen, or other Ollama-compatible models.

When configured in local-only mode:

- no repository code leaves the network
- no public webhook is required
- no SaaS reviewer needs access to GitLab
- no inbound public URL is required
- review runs can execute inside GitLab Runner

## 4. Product Identity

ReviewGate is not a generic chatbot for code.

ReviewGate is not a code formatter.

ReviewGate is not a replacement for human reviewers.

ReviewGate is a **risk-focused MR review assistant** that posts high-signal comments where developers already work.

## 5. Problem Statement

Many engineering teams use GitLab self-managed or GitHub Enterprise instances that are only accessible through VPN or internal networks.

This creates several problems:

1. Cloud AI review tools cannot access the repository.
2. Public webhooks are not possible or not allowed.
3. Security teams do not want private code sent to third-party SaaS platforms.
4. Senior engineers become review bottlenecks.
5. Review quality varies across reviewers.
6. Important risks are missed in ordinary-looking diffs.
7. Existing AI reviewers are often noisy, generic, or too SaaS-oriented.
8. Compliance and vendor onboarding make cloud AI tools hard to approve.

Common missed risks include:

- missing HTTP timeout
- unsafe debug logging
- PII leakage in logs
- nil pointer risk
- unclosed response body
- missing authorization check
- weak input validation
- retry loop bugs
- unsafe SQL usage
- API contract breakage
- no test coverage for behavior changes

## 6. Product Hypothesis

Teams will use and pay for ReviewGate if it can:

1.  Run locally while connected to VPN.
2.  Run automatically inside GitLab Runner.
3.  Access private GitLab without public webhook exposure.
4.  Use local models as a first-class option.
5.  Use OpenAI, Gemini, Anthropic, or Azure OpenAI as optional quality modes.
6.  Post high-signal comments directly into MR discussions.
7.  Reduce senior reviewer workload without spamming developers.
8.  Verify whether previous review findings were fixed.
9.  Adapt to team-specific review policies.
10. Provide auditability and privacy controls for internal teams.

## 7. Target Users

## 7.1 Primary User

Tech Lead, Engineering Manager, or Senior Engineer in a private software team using GitLab self-managed.

Needs:

- faster MR review
- fewer avoidable production bugs
- consistent review standard
- lower senior reviewer fatigue
- private deployment
- comments directly inside GitLab
- no public webhook dependency

## 7.2 Secondary User

DevOps, Platform Engineer, or Security Engineer.

Needs:

- run inside internal network
- avoid public webhook exposure
- keep tokens and code private
- integrate with GitLab Runner
- enforce review policy
- produce audit logs
- support local model mode

## 7.3 Tertiary User

Solo engineer, consultant, or vendor engineer.

Needs:

- review MRs before human reviewers see them
- produce professional code review comments
- improve quality with low model cost
- use personal LLM key or local model

## 8. Goals

## 8.1 Product Goals

1.  Let users review a private GitLab MR from CLI while connected to VPN.
2.  Support GitLab instances reachable only through VPN.
3.  Support local LLM review via Ollama-compatible models.
4.  Support OpenAI/Gemini/Anthropic/Azure OpenAI as optional remote model modes.
5.  Post structured summary comments into GitLab MR.
6.  Post inline comments when line mapping is valid.
7.  Reduce noise through severity and confidence filtering.
8.  Store review history locally.
9.  Verify whether previous findings were fixed after new commits.
10. Provide GitLab Runner mode for CI-based automation.

## 8.2 Business Goals

1. Create a sellable internal tooling product.
2. Monetize through enterprise implementation, support, policy tuning, and annual licensing.
3. Target teams using GitLab on-prem or private GitHub Enterprise.
4. Avoid direct competition with generic cloud AI reviewers.
5. Sell the private-network workflow as the wedge.
6. Avoid cheap tiers that create support burden without enterprise budget.

## 9. Non-goals

For v0.1, ReviewGate will not:

1.  Build a web dashboard.
2.  Replace human reviewers.
3.  Auto-merge code.
4.  Auto-approve MRs.
5.  Build a full AST engine from scratch.
6.  Build a full LSP orchestration layer from scratch.
7.  Guarantee perfect vulnerability detection.
8.  Support every programming language deeply.
9.  Store full repository source code permanently.
10. Require public webhook access.
11. Require GitLab admin-level access.
12. Require a SaaS backend.
13. Integrate with JIRA or external project management tools.
14. Optimize first for GitHub cloud.

## 10. Key Product Principle

ReviewGate must prioritize **high-signal risk comments** over comment volume.

Default behavior:

- CRITICAL and HIGH findings: publish inline when line mapping is valid.
- MEDIUM findings: publish inline if actionable and high-confidence.
- LOW findings: summary only.
- NOTE findings: summary only.
- Style nitpicks: disabled by default.
- Generic advice: suppressed by default.

A good ReviewGate comment should feel like a serious senior engineer spotted a real risk.

A bad ReviewGate comment sounds like generic AI filler.

## 11. Core Use Cases

## 11.1 Local VPN CLI Review

User connects to VPN, runs ReviewGate locally, and reviews a private GitLab MR.

Flow:

1. User connects VPN.
2. User runs CLI command.
3. ReviewGate fetches MR metadata and diff through GitLab API.
4. ReviewGate sanitizes diff and context.
5. ReviewGate analyzes diff using local LLM or remote BYOK model.
6. ReviewGate generates markdown findings.
7. User previews result in terminal.
8. User optionally publishes summary and inline comments.
9. Comments appear in GitLab MR.

Command:

```bash
reviewgate review "https://gitlab.company.local/group/repo/-/merge_requests/59" --preview
```

Publish:

```bash
reviewgate review "https://gitlab.company.local/group/repo/-/merge_requests/59" --publish
```

## 11.2 GitLab Runner Review

ReviewGate runs inside GitLab CI/CD.

Flow:

1. MR is opened or updated.
2. GitLab Runner starts review job.
3. ReviewGate uses CI environment variables.
4. ReviewGate fetches diff and metadata.
5. ReviewGate analyzes diff.
6. ReviewGate posts comments back to MR.
7. No public webhook is required.

This is the preferred enterprise automation mode.

## 11.3 Internal Server Mode

ReviewGate runs on an internal server that can reach GitLab.

Flow:

1. Internal server has network access to GitLab.
2. Team triggers review from CLI, scheduled job, or internal API.
3. ReviewGate posts comments to MR.

Dashboard remains optional and deferred.

## 11.4 GitHub Review

User pastes GitHub PR URL or runs CLI against GitHub.

GitHub support is important, but it is not the first wedge. GitLab behind VPN is the priority.

## 12. MVP Scope

## 12.1 MVP Must Have

1.  GitLab self-managed support.
2.  GitLab behind VPN support.
3.  CLI review command.
4.  Local Ollama-compatible LLM support.
5.  OpenAI BYOK support as optional quality mode.
6.  Fetch MR metadata.
7.  Fetch MR diff.
8.  Generate AI review summary.
9.  Generate severity-ranked findings.
10. Preview markdown output in terminal.
11. Post top-level summary comment to GitLab MR.
12. Post inline comments when line mapping is valid.
13. Store review runs locally.
14. Configurable review policy.
15. Redact secrets before model calls.
16. Basic cost and token estimate for remote model mode.
17. Basic test coverage detection.
18. Basic change request verification.
19. Duplicate comment prevention.
20. Large MR partial review warning.

## 12.2 MVP Should Have

1. GitLab Runner mode.
2. Semgrep integration.
3. SQLite local storage.
4. Docker image.
5. Docker Compose example for internal server mode.
6. Max inline comment limit.
7. Export review as Markdown.
8. Gemini support as optional remote model mode.

## 12.3 MVP Nice to Have

1.  GitHub PR support.
2.  GitHub Enterprise support.
3.  Anthropic support.
4.  Azure OpenAI support.
5.  Cross-MR bug class memory.
6.  Repo-specific prompt packs.
7.  Slack or Telegram notification.
8.  Web dashboard.
9.  SSO login for team mode.
10. External issue tracker integration.

## 13. Explicitly Deferred From v0.1

These are deferred because they do not prove the core product value:

1.  Web dashboard.
2.  JIRA mapping.
3.  Linear mapping.
4.  GitHub issue mapping.
5.  Full LSP integration.
6.  Full repository semantic graph.
7.  Auto-fix generation.
8.  Team analytics dashboard.
9.  Billing portal.
10. SaaS mode.

## 14. Phase 0 Spike: 3-day Build Plan

The first spike must prove the private review pipeline.

## 14.1 Day 1: GitLab Diff Fetch

Build:

- CLI command accepts GitLab MR URL
- parse base URL, namespace, project, MR IID
- accept GitLab token from env
- call GitLab API
- fetch MR metadata
- fetch MR diff
- print changed files and raw diff summary

Command:

```bash
GITLAB_TOKEN=xxx reviewgate review "https://gitlab.company.local/group/repo/-/merge_requests/59" --dry-run
```

Success criteria:

- works while VPN is active
- fails cleanly when VPN is disconnected
- no dashboard required

## 14.2 Day 2: Local Ollama Review

Build:

- local Ollama provider adapter
- send diff payload to Ollama
- use default local model config
- generate rough markdown review
- print to terminal

Example config:

```env
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
```

Success criteria:

- diff can be reviewed without sending code outside machine/network
- output has severity sections
- output is not completely generic

## 14.3 Day 3: Publish GitLab Summary Comment

Build:

- markdown summary formatter
- GitLab MR note publisher
- duplicate comment marker
- preview mode
- publish mode

Command:

```bash
reviewgate review "$MR_URL" --publish
```

Success criteria:

- AI-generated review appears in GitLab MR comments
- duplicate run updates or avoids repost spam
- result is useful enough to demo

## 15. User Stories

## 15.1 Review MR Locally

As a developer, I want to run a CLI review against a GitLab MR while connected to VPN so that I can get AI review feedback without exposing GitLab publicly.

Acceptance criteria:

- User can pass MR URL.
- System validates provider and URL format.
- System fetches MR metadata.
- System fetches diff.
- System generates review.
- User can preview result in terminal.
- User can publish comment.

## 15.2 Publish Summary Comment

As a developer, I want ReviewGate to post a clean summary comment so that my team can read the review inside GitLab.

Acceptance criteria:

- Comment includes severity sections.
- Comment includes file paths and line numbers when available.
- Comment includes static diagnostics section if enabled.
- Comment includes test coverage note.
- Comment includes AI-generated label.
- Comment avoids generic noise.

## 15.3 Publish Inline Comments

As a reviewer, I want high-confidence findings posted inline so that the author can fix issues directly in the diff.

Acceptance criteria:

- Inline comments only appear on valid diff lines.
- Invalid line mapping falls back to summary.
- Duplicate comments are not reposted.
- LOW severity is not posted inline by default.

## 15.4 Verify Previous Findings

As a reviewer, I want ReviewGate to check whether previous findings were fixed after new commits so that I do not manually re-review the same issues.

Acceptance criteria:

- System stores previous findings.
- System compares latest diff/code against previous findings.
- System marks findings as Fixed, Still Open, Skipped, or Needs Manual Confirmation.
- System posts verification summary.

## 15.5 Configure Review Policy

As a tech lead, I want per-repo review policies so that ReviewGate follows our team standards.

Acceptance criteria:

- Repo can define `.reviewgate.toml`.
- Config can set severity threshold.
- Config can set max comments.
- Config can enable or disable categories.
- Config can define banned patterns.

## 16. Review Output Template

Default summary format:

```md
AI Code Review Summary

🟡 MEDIUM

controllers/third_party.go:200 - Raw upstream response is written to logs. This may expose PII or sensitive third-party data.
Suggested fix: remove raw body logging or sanitize fields before logging.

controllers/third_party.go:458 - Timeout branch may break with resp still nil. Confirm downstream logic handles nil safely.

🟢 LOW

controllers/third_party.go:456 - Direct err.(net.Error) assertion may miss wrapped errors. Prefer errors.As.

🔬 SAST / Static Diagnostics

Semgrep skipped: repository not checked out locally.
LSP skipped: MVP does not run full language server analysis.

✅ Test Coverage

No test changes accompany the timeout behavior change.
Consider a unit test that asserts client.Timeout == 10s.

[AI generated by ReviewGate]
```

## 17. Change Request Verification Output

Example:

```md
Change Request Verification

Checked against latest diff.

✅ Fixed

🟡 MEDIUM - controllers/third_party.go:469 - resp.Body.Close() not scoped per retry attempt.
How fixed: each retry attempt now wraps response handling with defer resp.Body.Close().

⏭️ Skipped / Acknowledged

📝 NOTE - controllers/third_party.go:446 - Positive timeout addition.
Reason: informational note, no fix required.

⚠️ Still Open

🟡 MEDIUM - helpers/location.go:23 - http.DefaultClient.Do still has no timeout.

Summary: 1 fixed, 1 still open, 1 skipped.
[AI generated by ReviewGate]
```

## 18. Severity Model

## 18.1 CRITICAL

Must fix before merge.

Examples:

- auth bypass
- exposed secret
- SQL injection
- command injection
- broken permission check
- destructive migration risk
- production data loss risk

## 18.2 HIGH

Strongly recommended to fix before merge.

Examples:

- missing authorization guard
- unsafe external request
- PII logging
- unbounded retry
- nil pointer risk in critical path
- missing timeout in production HTTP call
- migration without rollback plan

## 18.3 MEDIUM

Should fix or explicitly acknowledge.

Examples:

- weak error handling
- partial timeout coverage
- missing test for behavior change
- fragile parsing
- inconsistent API contract
- possible observability gap

## 18.4 LOW

Summary only by default.

Examples:

- minor maintainability issue
- simpler API usage
- wrapped error handling improvement
- naming clarity
- small refactor suggestion

## 18.5 NOTE

Informational only.

Examples:

- positive change
- context reminder
- possible follow-up
- no action required

## 19. Review Categories

Findings must be classified into:

1.  Security
2.  Privacy
3.  Reliability
4.  Correctness
5.  Performance
6.  Maintainability
7.  Observability
8.  Test Coverage
9.  API Contract
10. Data Integrity
11. Deployment Risk
12. Compliance
13. Documentation
14. Positive Note

## 20. Comment Publishing Rules

Default rule:

```txt
Publish inline only if:
- severity is CRITICAL, HIGH, or MEDIUM
- confidence is medium or high
- finding is actionable
- finding maps to a valid diff line
- max inline comment limit has not been reached
```

Fallback behavior:

```txt
If inline comment fails:
- include finding in summary comment
- mark inline_status = failed
- store provider error
```

Default max inline comments:

```txt
CRITICAL: unlimited
HIGH: max 8
MEDIUM: max 5
LOW: 0 inline
NOTE: 0 inline
```

## 21. Engine Strategy

ReviewGate should not build the AI review engine from scratch in MVP.

Recommended MVP engine stack:

```txt
Primary Review Interface: CLI
Automation Interface: GitLab Runner
Primary Local Model Runtime: Ollama-compatible provider
Optional Remote Model Providers: OpenAI, Gemini, Anthropic, Azure OpenAI
SAST Layer: Semgrep
Comment Publisher: custom GitLab API integration
Storage: SQLite first, Postgres later
Deployment: binary, Docker image, GitLab Runner image
```

## 21.1 Candidate Open-source Engines

### Ollama-compatible Local Models

Best for privacy-first on-prem narrative.

Use local models for:

- zero-code-exfiltration mode
- security-sensitive customers
- internal audits
- GitLab Runner inside private network
- first-class enterprise positioning

Recommended model families to test:

- Qwen Coder
- Llama Coder variants
- DeepSeek Coder variants if available in customer environment
- other local coding models supported by the customer

Caveat:

Local models may produce weaker review quality than top commercial models. ReviewGate should expose quality modes, not hide this tradeoff.

### PR-Agent

Candidate for AI review baseline and provider inspiration.

Use it for:

- prompt reference
- review behavior inspiration
- possible subprocess adapter
- output comparison

Do not let PR-Agent own the product UX. ReviewGate should normalize and format findings itself.

### Semgrep

Best candidate for deterministic security and bug-pattern scanning.

Use it for:

- security rules
- custom internal rules
- bug-pattern checks
- SARIF/JSON diagnostics

Semgrep should be an analysis layer, not the whole product.

### Reviewdog

Useful for publishing linter-style diagnostics into PR/MR comments.

Use it optionally for:

- linter output
- static diagnostics
- CI-style review comments

For AI comments, custom GitLab publisher is better because ReviewGate needs tighter control over formatting, severity grouping, and duplicate handling.

### Codex / Gemini CLI

Useful as optional review adapters.

Use them for:

- experimental local review flow
- alternative review backend
- manual developer workflow

Do not make them the core dependency for MVP.

## 21.2 Why Not Build Full Engine From Scratch

Do not build in MVP:

- full AST engine
- custom multi-language parser
- custom language server orchestration
- codebase-wide semantic graph
- auto-fix engine
- agent swarm
- perfect repository RAG

Reason:

These are engineering tar pits. MVP value is in workflow, privacy, local execution, comment quality, and provider integration.

## 21.3 What ReviewGate Owns

ReviewGate should own:

1.  Local-first workflow.
2.  GitLab VPN support.
3.  GitLab Runner workflow.
4.  Provider token handling.
5.  Diff fetching.
6.  Local model adapter.
7.  Prompt policy.
8.  Finding normalization.
9.  Severity filtering.
10. Comment formatting.
11. Inline comment publishing.
12. Review history.
13. Change verification.
14. Team policy configuration.
15. Cost control for remote models.
16. Privacy controls.

## 22. System Architecture

```txt
CLI / GitLab Runner
  ↓
ReviewGate Core
  ↓
Provider Adapter
  - GitLab first
  - GitHub later
  ↓
Diff Fetcher
  ↓
Context Builder
  ↓
Secret Redactor
  ↓
Analysis Engines
  - Local LLM via Ollama
  - Remote BYOK LLM optional
  - Semgrep optional
  - Test Coverage Heuristic
  - Change Verification Engine
  ↓
Finding Normalizer
  ↓
Markdown Formatter
  ↓
Comment Publisher
  ↓
GitLab MR Comments
```

## 23. Deployment Modes

## 23.1 Local CLI Mode

Best for first MVP.

```bash
reviewgate review "$MR_URL"
```

Options:

```bash
reviewgate review "$MR_URL" --preview
reviewgate review "$MR_URL" --publish
reviewgate review "$MR_URL" --provider gitlab
reviewgate review "$MR_URL" --config .reviewgate.toml
reviewgate review "$MR_URL" --model qwen2.5-coder:7b
```

## 23.2 GitLab Runner Mode

Best for enterprise automation.

Example:

```yaml
stages:
  - review

reviewgate:
  stage: review
  image: reviewgate/reviewgate:latest
  script:
    - reviewgate review --ci --publish
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

## 23.3 Internal Server Mode

Best for team usage after CLI is proven.

```txt
Internal VPS / office server
connected to VPN or same private network
running ReviewGate worker/API
```

## 23.4 Dashboard Mode

Deferred.

Dashboard should only be built after CLI and GitLab Runner usage prove that review output is valuable.

Dashboard future use:

- run history
- policy config
- model config
- analytics
- customer demos
- admin usage

## 24. Provider Requirements

## 24.1 GitLab Adapter

Must support:

- GitLab self-managed
- GitLab behind VPN
- [GitLab.com](http://GitLab.com) later
- custom base URL
- personal access token
- project access token
- CI job token where possible
- MR metadata fetch
- MR diff fetch
- MR version fetch
- overview comment
- inline diff discussion
- duplicate comment detection

Required GitLab token scopes:

```txt
read_api
api
read_repository optional
```

## 24.2 GitHub Adapter

Deferred from v0.1.

Should eventually support:

- [GitHub.com](http://GitHub.com)
- GitHub Enterprise Server
- custom base URL
- personal access token
- PR metadata fetch
- PR diff fetch
- PR review comment
- issue comment summary
- duplicate comment detection

## 25. LLM Provider Requirements

## 25.1 MVP Default: Local Model Mode

Default provider:

```env
REVIEWGATE_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
REVIEWGATE_MODEL=qwen2.5-coder:7b
```

Local model mode must support:

- no external model API
- no code leaving local machine or internal network
- configurable model name
- timeout handling
- max context control
- fallback error message if Ollama is unreachable

## 25.2 Optional Quality Mode: Remote BYOK

Remote providers:

- OpenAI
- Gemini
- Anthropic
- Azure OpenAI

Example:

```env
REVIEWGATE_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-xxx
REVIEWGATE_MODEL=gpt-4.1
REVIEWGATE_MAX_COST_PER_RUN_USD=1.00
```

Remote model mode must show:

- estimated token usage
- estimated cost
- outbound payload preview option
- redaction status
- privacy warning

## 26. Privacy Requirements

ReviewGate must support:

1.  No public webhook requirement.
2.  Local-only deployment.
3.  Local LLM mode.
4.  BYOK remote model mode.
5.  Secret redaction before model calls.
6.  Optional no-persistence mode.
7.  Optional diff-only mode.
8.  LLM payload preview.
9.  Audit log of outbound model payload metadata.
10. Encrypted token storage.
11. Configurable data retention.
12. Clear local-only mode flag.

Default storage behavior:

```txt
Store:
- MR URL
- provider
- run timestamp
- finding metadata
- comment IDs
- severity
- status

Do not store by default:
- full repository
- full source files
- secrets
- raw LLM payloads
```

## 27. Secret Redaction

Before sending data to any model, ReviewGate must redact:

- API keys
- JWT
- bearer tokens
- private keys
- `.env` values
- passwords
- database URLs
- phone numbers
- emails
- access tokens
- internal hostnames if configured
- authorization headers
- cookies

Redaction output example:

```txt
Authorization: Bearer [REDACTED_TOKEN]
DATABASE_URL=[REDACTED_DATABASE_URL]
```

## 28. Policy Configuration

Repo-level config file:

```toml
[review]
max_inline_comments = 8
publish_low_inline = false
publish_notes_inline = false
minimum_confidence = "medium"
include_positive_notes = true
include_test_coverage = true
include_cross_mr_notes = false

[providers.gitlab]
base_url = "https://gitlab.company.local"

[llm]
provider = "ollama"
model = "qwen2.5-coder:7b"
max_context_tokens = 12000
max_review_seconds = 180

[llm.remote]
enabled = false
provider = "openai"
model = "gpt-4.1"
max_cost_per_run_usd = 1.00

[privacy]
local_only = true
redact_secrets = true
store_raw_diff = false
store_llm_payload = false
payload_preview = true

[security]
detect_pii_logging = true
detect_secret_leak = true
detect_missing_auth = true

[reliability]
detect_http_without_timeout = true
detect_unclosed_response_body = true
detect_nil_after_timeout = true
detect_unbounded_retry = true

[testing]
warn_behavior_change_without_tests = true
```

## 29. Data Model

## 29.1 Review Run

```ts
type ReviewRun = {
  id: string;
  provider: "gitlab" | "github";
  repoUrl: string;
  mrNumber: string;
  mrTitle: string;
  sourceBranch: string;
  targetBranch: string;
  commitSha: string;
  status: "queued" | "running" | "completed" | "failed";
  startedAt: string;
  completedAt?: string;
  estimatedCostUsd?: number;
  modelProvider: string;
  modelName: string;
  localOnly: boolean;
};
```

## 29.2 Finding

```ts
type ReviewFinding = {
  id: string;
  runId: string;
  filePath: string;
  oldPath?: string;
  newPath?: string;
  line?: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NOTE";
  category:
    | "security"
    | "privacy"
    | "reliability"
    | "correctness"
    | "performance"
    | "maintainability"
    | "observability"
    | "test_coverage"
    | "api_contract"
    | "data_integrity"
    | "deployment_risk"
    | "documentation"
    | "positive_note";
  title: string;
  body: string;
  suggestedFix?: string;
  confidence: "high" | "medium" | "low";
  source: "ai" | "semgrep" | "policy" | "test_heuristic";
  dedupeKey: string;
  shouldPublishInline: boolean;
  publishStatus: "pending" | "published" | "failed" | "skipped";
  providerCommentId?: string;
  status: "open" | "fixed" | "skipped" | "needs_manual_confirmation";
};
```

## 29.3 Provider Connection

```ts
type ProviderConnection = {
  id: string;
  provider: "gitlab" | "github";
  name: string;
  baseUrl: string;
  tokenEncrypted: string;
  createdAt: string;
  updatedAt: string;
};
```

## 30. CLI Commands

```bash
reviewgate review <mr-url>
reviewgate review <mr-url> --preview
reviewgate review <mr-url> --publish
reviewgate review <mr-url> --local-only
reviewgate review <mr-url> --provider gitlab
reviewgate review <mr-url> --model qwen2.5-coder:7b
reviewgate verify <mr-url>
reviewgate init
reviewgate config validate
reviewgate connections test
reviewgate models test
```

## 31. Large MR Handling

If MR is too large, ReviewGate must prioritize:

1. security-sensitive files
2. auth/middleware files
3. database/migration files
4. API/client files
5. payment/user-data files
6. changed test files
7. high-risk language patterns

Skip by default:

- lockfiles
- generated files
- minified files
- snapshots
- vendored files
- binary files

Large MR warning:

```md
Large MR detected. Review is partial and prioritized by risk.
Skipped generated files, lockfiles, vendored files, and snapshots.
```

## 32. Cost Control

Cost control applies mainly to remote BYOK model mode.

ReviewGate must show estimated cost before remote model calls when possible.

Cost controls:

1. max files per review
2. max changed lines
3. skip generated files
4. compress diff
5. summarize large files
6. model routing
7. max cost per run
8. cache previous review context

Example:

```txt
Estimated remote LLM cost: $0.18
Model: gpt-4.1
Changed files analyzed: 8 of 12
Skipped files: package-lock.json, generated.ts
```

For local model mode, show resource hints instead:

```txt
Local model: qwen2.5-coder:7b
Estimated prompt size: 9,200 tokens
Review mode: local-only
External model calls: disabled
```

## 33. Failure Modes

## 33.1 VPN Not Connected

Error:

```txt
Cannot reach GitLab base URL.
Check VPN connection or GitLab base URL.
```

## 33.2 Token Invalid

Error:

```txt
GitLab token is invalid or missing required scope.
```

## 33.3 Ollama Not Running

Error:

```txt
Cannot reach Ollama at http://localhost:11434.
Start Ollama or configure another model provider.
```

## 33.4 Inline Comment Mapping Failed

Fallback:

```txt
Finding added to summary comment because inline diff position could not be resolved.
```

## 33.5 LLM Failure

Fallback:

```txt
AI review failed. Static diagnostics may still be available.
```

## 33.6 Large Diff

Fallback:

```txt
Review is partial. Some files were skipped due to size.
```

## 34. MVP Milestones

## 34.1 Phase 0: 3-day Spike

Duration: 3 days

Deliverables:

- CLI accepts GitLab MR URL
- GitLab token config
- fetch MR metadata
- fetch MR diff
- local Ollama adapter
- rough markdown review in terminal
- publish summary comment to GitLab MR

Success criteria:

- one private GitLab MR can be reviewed from local machine while VPN is active
- review can run with local model
- no dashboard required
- markdown output is useful enough to demo

## 34.2 Phase 1: CLI MVP

Duration: 1 week

Deliverables:

- polished CLI review command
- GitLab provider adapter
- local model config
- optional OpenAI quality mode
- Markdown summary output
- publish overview comment
- local SQLite run history
- basic redaction
- duplicate comment prevention

Success criteria:

- user can run one command and post AI summary to GitLab MR

## 34.3 Phase 2: GitLab Runner MVP

Duration: 1 week

Deliverables:

- CI mode
- GitLab Runner documentation
- environment variable support
- auto-review on MR pipeline
- publish comment from CI

Success criteria:

- ReviewGate can run automatically inside GitLab CI without public webhook

## 34.4 Phase 3: Inline Comments and Verification

Duration: 1-2 weeks

Deliverables:

- inline GitLab comments
- duplicate comment prevention
- previous finding storage
- change request verification
- fixed/still-open summary

Success criteria:

- ReviewGate can verify whether previously raised findings were fixed

## 34.5 Phase 4: Productization

Duration: 2-4 weeks

Deliverables:

- Docker image
- installer script
- config templates
- policy presets
- Semgrep integration
- customer deployment guide
- internal server mode

Success criteria:

- deployable in a private team without hand-holding from the creator

## 34.6 Phase 5: Dashboard

Deferred until the CLI/Runner workflow proves real value.

Dashboard only becomes worth building after:

- at least 50 real MRs reviewed
- useful finding rate is acceptable
- at least one team asks for admin controls or history UI

## 35. Monetization Strategy

## 35.1 Best Initial Offer

Do not sell it as “free CodeRabbit”.

Sell it as:

**Private AI MR Review Implementation for GitLab VPN / On-Prem Teams**

## 35.2 Pricing Hypothesis

Cheap pricing is strategically wrong for the target customer.

Enterprise customers using GitLab self-managed behind VPN often require:

- vendor onboarding
- NDA
- security review
- procurement process
- compliance discussion
- deployment support
- internal training

The sales and implementation burden is similar whether the price is Rp 15jt or Rp 150jt.

Therefore, ReviewGate should avoid low-ticket implementation pricing.

### One-time Implementation

```txt
Rp 100jt - Rp 250jt
```

Includes:

- private GitLab integration
- local model setup
- GitLab Runner setup
- review policy configuration
- security/privacy configuration
- pilot on real MRs
- team training
- deployment documentation

### Annual Support License

```txt
Rp 100jt - Rp 300jt/year
```

Includes:

- maintenance
- policy tuning
- prompt tuning
- model config updates
- bug class rule updates
- GitLab version compatibility support
- deployment support
- limited customizations

### Internal Pilot Package

Optional, only for high-quality leads:

```txt
Rp 50jt - Rp 75jt fixed-scope pilot
```

Rules:

- max 1 GitLab instance
- max 3 repositories
- max 30 days
- no dashboard
- CLI + Runner only
- conversion target into annual license

Avoid public cheap tiers in the first version.

## 35.3 Target Customers

Best first customers:

1. government vendors
2. banking vendors
3. insurance vendors
4. logistics platforms
5. enterprise software houses
6. companies using GitLab self-managed
7. teams with many junior/mid engineers
8. teams with few senior reviewers
9. companies with VPN-only engineering environments

Avoid first:

1. open-source teams
2. indie hackers
3. tiny teams with no review pain
4. teams already happy with GitHub cloud tools
5. teams that cannot pay for implementation

## 36. Competitive Differentiation

## 36.1 Against CodeRabbit-like SaaS

ReviewGate wins on:

- VPN/private GitLab support
- local-first deployment
- local model mode
- BYOK cost control
- no public webhook requirement
- private network compatibility
- customizable policy
- internal setup service

ReviewGate loses on:

- polish
- hosted convenience
- mature UX
- codebase-wide intelligence
- managed cloud workflow

## 36.2 Against Static Analysis

ReviewGate wins on:

- contextual explanation
- MR summary
- natural language review
- test coverage reasoning
- change verification
- cross-MR notes later

Static analysis wins on:

- deterministic results
- lower cost
- less hallucination
- stronger rule guarantees

Best product strategy:

Use both.

## 36.3 Against Internal Scripts

ReviewGate wins on:

- reusable review policies
- model abstraction
- GitLab comment publishing
- severity normalization
- verification loop
- deployable package

Internal scripts win on:

- speed to hack
- lower complexity
- team-specific shortcuts

ReviewGate must stay simple enough to beat ad-hoc scripts.

## 37. Success Metrics

## 37.1 Product Metrics

- review run success rate
- average review time
- number of findings per MR
- useful finding rate
- false positive rate
- inline comment publish success rate
- fixed finding rate
- local model quality score
- remote model quality score
- estimated cost per MR for remote mode

## 37.2 Business Metrics

- enterprise pilots started
- implementation contracts sold
- annual support revenue
- active teams
- active repos
- MRs reviewed per week
- retention after pilot
- number of policies configured

## 38. Acceptance Criteria

MVP is accepted when:

1.  User can run ReviewGate locally while connected to VPN.
2.  User can pass a GitLab MR URL to CLI.
3.  System fetches MR metadata and diff.
4.  System can use local Ollama-compatible model.
5.  System can optionally use OpenAI BYOK.
6.  System generates AI code review summary.
7.  System groups findings by severity.
8.  User can preview output in terminal.
9.  System posts top-level GitLab MR comment.
10. System posts inline comments for valid diff lines.
11. System stores review run locally.
12. System can verify previous findings after MR update.
13. System redacts secrets before model call.
14. System does not require public webhook.
15. System can run in GitLab Runner mode.

## 39. Brutal Product Decision

Build ReviewGate as a CLI-first and GitLab Runner-first local orchestration product.

Do not start with a dashboard.

Do not start with SaaS.

Do not start with cheap indie pricing.

Do not start with GitHub cloud as the main wedge.

The moat is not the LLM.

The moat is:

1. GitLab VPN support.
2. Local-first workflow.
3. Local model mode.
4. GitLab Runner automation.
5. Low-noise review policy.
6. BYOK quality mode.
7. Change request verification.
8. Private team deployment.
9. Enterprise implementation and policy tuning.

The first version should be ugly but useful.

The output must feel like a serious senior engineer reviewed the MR, not like a generic chatbot generated comments.

## 40. Final MVP Statement

ReviewGate v0.1 allows a user connected to VPN to review a private GitLab MR from CLI, analyze the diff using a local Ollama-compatible model or optional OpenAI BYOK mode, preview high-signal findings in terminal, and publish a clean review summary plus optional inline comments back to GitLab.

The MVP does not include a dashboard, JIRA, ticket mapping, external project management integrations, or SaaS mode.

## 41. Deferred Features

The following features are deferred until after the core MR review loop is proven:

1.  Web dashboard.
2.  JIRA integration.
3.  Linear integration.
4.  GitLab issue mapping.
5.  GitHub issue mapping.
6.  Project management summary.
7.  Requirement-to-code traceability.
8.  Ticket compliance checking.
9.  Full LSP integration.
10. Full repository semantic graph.
11. Auto-fix generation.
12. SaaS hosted mode.
13. Public webhook mode.
14. Billing portal.

These should only be added if users explicitly ask for workflow traceability, admin UX, or deeper codebase intelligence after the CLI and Runner workflow is useful.
