# Labelled benchmark corpus (C33)

Eight small repositories, written for this benchmark, with what each one
contains labelled in `labels/<case>.json`:

| case | kind | labels | what is planted |
|---|---|---|---|
| flask-shop | vulnerable | 13 | SQL, command, path, SSRF, redirect, eval, pickle, yaml.load, template injection; a GitHub token and an AWS key; an extra package index and a git dependency |
| express-api | vulnerable | 7 | command, SQL, path, redirect, reflected response, SSRF, eval |
| mcp-tools | vulnerable | 10 | OWASP MCP01, 02, 03, 04 (x2), 05, 07, 08, 10 and the leaked token |
| supply-chain | vulnerable | 4 | git dependencies (npm, Cargo), an http:// lockfile entry, curl piped into sh in an MCP config |
| flask-helpers | vulnerable | 4 | command, SQL and path flows through helper functions of the same file (added after the inter-procedural taint, by its author) |
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
| labels | 38 over 8 repositories (5 vulnerable, 3 clean) |
| true positives | 37 |
| false positives | 3 (1 on a clean repository) |
| false negatives | 1 |
| precision | 0.925 |
| recall | 0.974 |

The first run, before flask-helpers was added, gave 34 labels, 33 true
positives, 3 false positives and 1 false negative (precision 0.917, recall
0.971). Adding flask-helpers found one real false positive, now fixed: the
result of a helper that sanitises with `int()` was treated as tainted.

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
30 below which `analysis/benchmark.py` calls a sample small (38 now). Real numbers
need repositories nobody here wrote, such as OWASP NodeGoat, labelled
independently.

## An external repository: OWASP NodeGoat

`benchmark/external/nodegoat.json` labels OWASP NodeGoat at commit
`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`. The source of truth is
NodeGoat's own tutorial (`app/views/tutorial/*.html`), not secaudit. Each
documented vulnerability was located in the code by reading it, and the
labels were written **before** any secaudit scanner ran on NodeGoat. Each
label has a scope:

- `scanners`: what the deterministic scanners claim to cover (5 labels);
- `cross_file`: a taint flow across files, which they say they do not follow
  (1);
- `model`: authorization, configuration, cryptography and ReDoS, which only
  the model's audit can find (8).

    python3 -m analysis.benchmark --external benchmark/external/nodegoat.json

The command clones that exact commit with hooks off and runs nothing from it.

### Result on 2026-11-02 (deterministic scanners only, no model)

| scope | labels | found | recall |
|---|---|---|---|
| scanners | 5 | 5 | 1.0 |
| cross_file | 1 | 0 | 0.0 |
| model | 8 | 0 | 0.0 |
| **all** | 14 | 5 | 0.357 |

Against the labels, 2 findings are unexpected, so precision is 0.714. Read
by hand, both are real issues that the tutorial does not mention:

- `artifacts/cert/server.key`: an RSA private key committed to the
  repository.
- `package.json:51`: a dev dependency (`grunt-if`) fetched from a GitHub
  tarball of `master`, unpinned.

They were not added to the labels after the fact. One more finding (mixed
registries in `package-lock.json`, caused by that same tarball) is reported
as unverifiable because it has no line, so it is not counted as a positive.

**For comparison:** the same run with the earlier pattern-based JavaScript
reader, before tree-sitter, found 1 of the 5 in-scope labels. The three
`eval()` calls and the SSRF were missed.

The 9 labels outside the scanners' scope are the measure of what the
deterministic layer leaves to the model. Scoring the model needs an audit
made with a real backend:

    python3 -m analysis.benchmark benchmark/external/nodegoat.json audit.json
