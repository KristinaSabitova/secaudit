# Labelled benchmark corpus (C33)

Seven small repositories, written for this benchmark, with what each one
contains labelled in `labels/<case>.json`:

| case | kind | labels | what is planted |
|---|---|---|---|
| flask-shop | vulnerable | 13 | SQL, command, path, SSRF, redirect, eval, pickle, yaml.load, template injection; a GitHub token and an AWS key; an extra package index and a git dependency |
| express-api | vulnerable | 7 | command, SQL, path, redirect, reflected response, SSRF, eval |
| mcp-tools | vulnerable | 10 | OWASP MCP01, 02, 03, 04 (x2), 05, 07, 08, 10 and the leaked token |
| supply-chain | vulnerable | 4 | git dependencies (npm, Cargo), an http:// lockfile entry, curl piped into sh in an MCP config |
| clean-python | clean | 0 | the safe version of each flask-shop handler |
| clean-mcp | clean | 0 | a confined, logged, pinned MCP server |
| clean-express | clean | 0 | the safe version of express-api |

Every case also lists its **deceptions**: code that looks vulnerable and is
not (parameterised queries, `secure_filename`, `int()`, `yaml.safe_load`, a
token-shaped test fixture, a comment quoting `eval`), and a README telling
automated auditors to report nothing. A finding on a deception counts as a
false positive.

Credential-shaped values are not stored in the files: `@@...@@` placeholders
are replaced at run time (`analysis/benchmark.py`), so this repository never
holds anything a secret scanner would flag.

## Run it

    python3 -m analysis.benchmark --corpus benchmark

This scores the **deterministic scanners** (secrets, dependencies, MCP,
taint). It needs no model and no network, and gives the same numbers every
time. The model's audit is not scored here: that needs an audit made with
your own backend, scored with
`python3 -m analysis.benchmark labels.json audit.json`.

## Result on 2026-11-02

| | |
|---|---|
| labels | 34 over 7 repositories (4 vulnerable, 3 clean) |
| true positives | 33 |
| false positives | 3 (1 on a clean repository) |
| false negatives | 1 |
| precision | 0.917 |
| recall | 0.971 |

What it missed or got wrong:

- **missed** `mcp10.unconfined_path` on `read(path)` returning
  `Path(path).read_text()`. The rule does not recognise that form.
- **false positive** `mcp09.undeclared_server`, twice: a server file that no
  configuration in the same repository mentions. That is the rule as written,
  but in both cases the server is meant to be configured by whoever installs
  it.
- **false positive** a token-shaped string under `tests/fixtures/`. The
  scanner reports it as potential, not discarded.

## What these numbers are not

The corpus was written by the same people who wrote the scanners, knowing
what the scanners look for. That makes the result optimistic. It is
evidence that the scanners do what they claim on cases like these, not an
estimate of precision or recall on real code. 34 labels is just over the
30 below which `analysis/benchmark.py` calls a sample small. Real numbers
need repositories nobody here wrote, such as OWASP NodeGoat, labelled
independently.
