# secaudit

Defensive security audit CLI. Orchestrates Claude Code to audit a web app
against a standard checklist and tracks findings across runs.

## Requirements

- Python 3.10+
- [Claude Code CLI](https://docs.claude.com) installed and authenticated

## Installation

```bash
# Invoke directly
python3 ~/tools/secaudit/secaudit.py /path/to/project

# Or use the shell function (add to ~/.zshrc):
secaudit() {
  local project="$1"
  local projpath="$HOME/$project"
  local stamp=$(/bin/date +%Y%m%d)
  local output="$HOME/Desktop/${project}-audit-${stamp}.md"
  python3 ~/tools/secaudit/secaudit.py "$projpath" --report-only -o "$output"
}
```

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
- For `secrets` category findings, secret values are **redacted** in stored
  state and all output. Only the type, file path, and a 6-char hash hint are
  kept.
- `.gitignore` excludes `.secaudit/`, `*.secaudit.json`, `.env*`.

## Running tests

```bash
python3 -m pytest tests/ -v
```
