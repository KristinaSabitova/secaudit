# The lab: what is in it, and what secaudit should make of it

`make_lab.py` builds two repositories, published as
`KristinaSabitova/secaudit-lab` and `KristinaSabitova/secaudit-lab-clean`.
Everything in them is inert: hooks and scripts are `true` or `echo`, nothing
writes a file or reaches the network, and the applications refuse to start.
This key lives here and not in the lab, where the auditor would read it.

`tests/test_lab.py` audits both through the server with the model's answer
canned to the findings below, and checks every line of this table.

## Two stages

Module 3 learns from a fix *between two audits*, so the lab is audited twice:

1. Push only the first commit and audit it:
   `git push origin <sha of "feat: shop skeleton…">:refs/heads/main`.
   The product search builds its query by concatenation.
2. Push the rest (`git push origin main`) and audit again. The search was
   fixed in between, and the same pattern came back in the review search.

## secaudit-lab

| Module | Case | Where | Expected |
|---|---|---|---|
| 1 Parallax | Instructions in Unicode tag characters, invisible on GitHub | `CLAUDE.md` | `hidden_content` |
| 1 Parallax | A hook that runs on opening the folder with Claude Code | `.claude/settings.json` → `scripts/warmup.sh` | `unexpected_execution` |
| 1 Parallax | 24 near-identical files: filler to push something out of the context | `src/locales/` | `audit_blind_spot` (padding) |
| 1 Parallax | Published package different from the tag | — | Not in the lab: nothing is published to PyPI or npm. Covered by `tests/test_parallax.py` with a registry of its own. |
| 2 Falsifiability | SQL built with an f-string, from a value cast with `int()` by the only caller | `src/db.py:order_for` | `refuted` (sanitizer) |
| 2 Falsifiability | SQL concatenation in a function nothing calls | `src/legacy.py:export_table` | `refuted` (dead code) |
| 2 Falsifiability | The real ones: review search, backup label | `src/db.py:search_reviews`, `src/backup.py` | `reachable` (`corroborated` with the devil's advocate) |
| 3 Memory | Search by concatenation (stage 1), fixed with a bound parameter | `src/db.py:search_products` | fix commit = `fix: bind the product search term…` |
| 3 Memory | The same pattern back, as an f-string | `src/db.py:search_reviews` | zombie, if the rule the model proposes validates (needs Semgrep: on the server) |
| 4 Leverage | Deploy on push with a secret and `contents: write`, no owner | `.github/workflows/deploy.yml` | leverage ≥ 0.7, oversight < 0.3 |
| 4 Agents | Reads `~/.ssh`, `curl`, a fetch domain, and a hook that runs on its own | `.claude/settings.json` | `exfiltration` combination |
| 5 Attacker | Guest session with no login (low) → profile writes `role` into the session (low) → command injection only an admin reaches (low) | `src/app.py`, `src/backup.py` | anonymous → `executes_code`, cost 3, **critical**; each of the three gets contextual severity critical; the cut is any one of them |

The third step needs the crown jewel `code_execution`, which is not suggested:
declare it in the settings (or `POST /api/projects/{id}/crown-jewels`)
between the two audits. Through `reads_secret` the same chain is `high`.

## secaudit-lab-clean

The same shop written with care: bound parameters, the role read from the
database on every request, a whitelist of profile fields, a validated label
and no shell, secret key from the environment, secure cookies, no agent
configuration, `CODEOWNERS` over everything and a read-only workflow.

Expected: no divergence, no agent surface, no attack path. Every finding a
real model reports here is a false positive, and is counted as one.
