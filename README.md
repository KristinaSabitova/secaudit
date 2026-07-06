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
