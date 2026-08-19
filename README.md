# secaudit

> [Leer esto en español](README.es.md)

Defensive security audit CLI. Orchestrates an LLM to audit a web app against
a standard checklist and tracks findings across runs.

## Requirements

- Python 3.10+
- One of the supported backends (see below)

## Quick setup

```bash
# 1. Install the `secaudit` shell alias (writes one line to ~/.zshrc or ~/.bashrc)
python3 ~/tools/secaudit/secaudit.py init

# 2. Reload your shell
source ~/.zshrc   # or open a new terminal

# 3. Register your first project (run from inside the project directory)
cd ~/dev/myproject
secaudit projects add myproject

# 4. Audit it
secaudit myproject --staged
```

`init` is idempotent — running it twice does not duplicate the alias.

## Supported backends

Select a backend with `--backend` or set it permanently in `~/.secaudit/config.toml`
(created automatically on first run with commented examples).

### claude-code (default)

Uses the [Claude Code CLI](https://docs.claude.com) installed locally.

```bash
# No extra config needed if `claude` is in PATH
secaudit . --staged
secaudit . --staged --backend claude-code
```

### anthropic-api

Direct HTTP to the Anthropic API. No Claude Code CLI required.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
secaudit . --staged --backend anthropic-api
```

`~/.secaudit/config.toml`:
```toml
backend = "anthropic-api"
model = "claude-sonnet-4-6"
```

### openai-api

```bash
export OPENAI_API_KEY=sk-...
secaudit . --staged --backend openai-api
```

`~/.secaudit/config.toml`:
```toml
backend = "openai-api"
model = "gpt-4o"
```

### ollama — local, no cost, no account

The zero-cost option: runs a local model via [Ollama](https://ollama.com).
No API key, no data sent to third parties.

```bash
# 1. Install Ollama: https://ollama.com/download
# 2. Pull a model
ollama pull llama3          # or qwen2.5-coder, codellama, mistral…
# 3. Run
secaudit . --staged --backend ollama
```

`~/.secaudit/config.toml`:
```toml
backend = "ollama"
model = "llama3"
# ollama_url = "http://localhost:11434"   # default
```

## Project aliases

Register short names so you never type a full path again.

Aliases are not guessed — you register them first. The workflow is:

```bash
cd ~/stela      # navigate to your project (or wherever it lives)
secaudit projects add stela
```

This saves `stela → /Users/you/stela` (or whatever the resolved path is) to
`~/.secaudit/projects.json`. From then on, `secaudit stela` works from
anywhere, just like any other registered project.

To check which projects you have registered at any time:

```bash
secaudit projects list
```

Other operations:

```bash
# Register an explicit path from anywhere (no need to cd first)
secaudit projects add api ~/dev/mycompany/api

# Use alias anywhere a path is accepted
secaudit stela --staged
secaudit api --diff main --backend ollama

# Remove an alias
secaudit projects remove stela
```

If the directory is not a git repo, secaudit warns and asks for confirmation.
Pass `--force` to skip the prompt:

```bash
secaudit projects add scratch /tmp/scratch --force
```

Aliases are stored in `~/.secaudit/projects.json`.

## One-shot mode (v1, backward compatible)

Full audit, no state tracking.

```bash
secaudit.py .                                    # audit + apply critical/high fixes
secaudit.py . --report-only                      # audit, report only (no edits)
secaudit.py . --report-only -o report.md         # write report to file
secaudit.py . --stack "Django + Vue"             # hint the tech stack
secaudit.py . --scope backend                    # backend only
secaudit.py . --print-prompt                     # preview the prompt, no run
```

## Differential mode (v2)

Audits a subset of files and tracks findings across runs. State is stored in
`~/.secaudit/state/<project-id>.json` — **never inside the project tree**.

### Daily diff workflow

```bash
# Audit only staged files (before committing)
secaudit.py . --staged

# Audit files changed vs a branch
secaudit.py . --diff main
secaudit.py . --diff origin/main

# Show all findings, not just NEW + REGRESSED
secaudit.py . --staged --all

# Output classified findings as JSON
secaudit.py . --staged --json
```

Default output shows only **NEW** and **REGRESSED** findings. Use `--all` to
also see PERSISTING and FIXED.

### Finding statuses

| Status | Meaning |
|--------|---------|
| `new` | First time seen |
| `persisting` | Present in previous run too |
| `regressed` | Was fixed, now back |
| `fixed` | Was present, no longer detected |
| `accepted` | Manually suppressed |

### Suppression

```bash
# Suppress a finding by its 8-char ID
secaudit.py suppress a1b2c3d4 --reason "false positive: rate limiting is at the proxy layer"

# Suppress from a specific project directory
secaudit.py suppress a1b2c3d4 --reason "wontfix" --project /path/to/project

# List all suppressed findings
secaudit.py . --show-suppressed
```

Suppressed (ACCEPTED) findings never surface as NEW or REGRESSED.

### Baseline (for legacy repos)

Accept all current findings on first run so only future regressions are
surfaced:

```bash
secaudit.py baseline .
secaudit.py baseline /path/to/project
```

## Web app

The same engine is exposed over HTTP by `web/`, with a dashboard for submitting
repositories and reading findings, and a GitHub webhook that audits every push.
`secaudit.py` is imported unmodified — the CLI keeps working exactly as above.

```bash
pip install -r requirements.txt
alembic upgrade head                    # SQLite by default; set DATABASE_URL for PostgreSQL
uvicorn web.main:app --reload
```

Then open <http://127.0.0.1:8000>.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/audits` | queue an audit of a repository (202 with the pending record) |
| `GET /api/audits` | every audit, newest first, with severity counts |
| `GET /api/audits/{id}` | one audit including its findings |
| `GET /api/audits/{id}?verified_only=true` | only the findings backed by code |
| `POST /api/webhook/github` | signed push deliveries from GitHub |
| `GET /api/health` | git, database, and backend readiness |

Audits run as background tasks: the endpoint answers immediately and the record
moves from `pending` through `running` to `done` or `error`.

### Evidence behind a finding

Every finding says whether it is anchored to code that was actually audited:

- `verification_status: "verified"` comes with `file`, `anchor` and a
  `code_snippet` copied from the repository. Open the file, find the code, see
  the flaw.
- `verification_status: "unverified"` is a finding the engine could not tie to
  any code. It is still reported, with `verification_note` saying why, and is
  never presented as confirmed. Restating what a category means is not a
  finding, and the prompt forbids it.

Anything reported as verified without a file or a snippet is downgraded to
`unverified` before it is stored, so the guarantee does not depend on the model
behaving. `?verified_only=true` leaves the unverified ones out entirely.

### How the code reaches the model

`claude-code` is an agent: it runs with the checkout as its working directory
and opens files itself. Every other backend is a single HTTP request and can
open nothing, so the repository is packed into that request — the file tree,
then the contents of as many files as the budget allows, line-numbered so a
finding can point at a line. The files whose paths suggest attack surface
(auth, session, routes, queries, uploads, config…) go in first, and whatever
did not fit is named in the prompt so the model can say it was not shown that
file instead of guessing about it.

`SECAUDIT_CONTEXT_CHARS` sets the budget (default 200000 characters, about 50k
tokens; ollama gets a quarter of it). A larger budget covers more of a big
repository and costs more per audit.

### Language

Findings are written in the requested language by the backend itself — there is
no translation pass afterwards:

```bash
curl -X POST /api/audits -H 'Content-Type: application/json' \
     -d '{"repo_url": "https://github.com/owner/repo", "language": "es"}'
```

`language` is `"en"` (default) or `"es"`; anything else is a 400. The dashboard
sends the language it is displayed in, and its own selector switches between
English and Spanish. Webhook audits have no caller to ask, so they follow
`SECAUDIT_DEFAULT_LANGUAGE`. The CLI takes the same choice as `--language es`.
Only prose is translated: paths, identifiers, categories and snippets are kept
as they appear in the code.

Set `GITHUB_WEBHOOK_SECRET` to enable the webhook — without it the endpoint
refuses every delivery with 503 rather than accepting unverified ones.
See [DEPLOY.md](DEPLOY.md) for running it in production.

## Security notes

- State files live in `~/.secaudit/` — never written inside the audited repo.
- API keys are read from environment variables and **never** logged, stored in
  state, or printed in any output.
- For `secrets` category findings, secret values are **redacted** before storage
  and display. Only the type, file path, and a 6-char hash hint are kept.
- `.gitignore` excludes `.secaudit/`, `*.secaudit.json`, `.env*`.

## Running tests

```bash
python3 -m pytest tests/ -v
```
