# Changelog

## Unreleased

Added
- Maven versions taken from properties the same pom defines, and from
  `dependencyManagement`. Gradle `build.gradle(.kts)` is read as text and
  never evaluated, together with version catalogs and `gradle.lockfile`.
  Gradle repositories over http are flagged.
- Python taint follows helper functions of the same file, up to three calls
  deep, into and out of them.
- Twin simulation (`POST /api/audits/{id}/twin/simulate` and a panel in the
  Twin section). Fix or confirm findings and see which attack paths close,
  change or open. Nothing is run or written.
- A benchmark case with flows through helper functions (38 labels now).
- JavaScript and TypeScript taint on a tree-sitter syntax tree (optional,
  pinned dependency): callbacks, same-file helpers, destructuring, renamed
  request and response parameters, MongoDB `$where` (CWE-943). Without
  tree-sitter the pattern reader is used and the output says so.
- Pull request report, off by default: one comment edited in place and a
  `secaudit` commit status, with `SECAUDIT_PR_COMMENTS` (`summary` or
  `full`) and `SECAUDIT_GITHUB_WRITE_TOKEN`. Migration `0018`.
- What If can run the repository's tests before and after the patch in a
  Docker sandbox (`SECAUDIT_WHATIF_SANDBOX=docker`), off by default: no
  network, read-only root, no capabilities, nobody, limits.
- External benchmark: OWASP NodeGoat at a pinned commit, labelled from its
  own tutorial (`--external`). The scanners find 5 of the 5 cases in their
  scope.

Fixed
- The result of a summarised helper that sanitises its input is no longer
  treated as tainted.

## 0.4.0 — 2026-11-02

Added
- Taint analysis (`analysis/taint.py`): intra-procedural for Python with ast,
  by pattern for JavaScript/TypeScript. Each finding records its
  source → sink flow and stays potential.
- Documentation against code (`analysis/doc_claims.py`): security claims in
  READMEs and docs, each marked backed, unbacked or contradicted. Unbacked
  claims lower confidence.
- Dead code (`analysis/deadcode.py`): unreferenced functions, exports and
  files, and unregistered Flask blueprints.
- Dependencies:
  - crates.io, RubyGems, Packagist and Maven (literal versions only);
  - opt-in stale and deprecated package checks (`SECAUDIT_ABANDONED_CHECK`);
  - a note when only direct dependencies are known.
- Surface: per-entry input validation, and an inventory of services
  (containers, Kubernetes objects, datastores, external hosts, third-party
  SDKs).
- MCP findings become steps in attack paths, and there is an MCP tool decoy.
  The OWASP taxonomy can be checked against the official page on demand.
- A PDF report written without a PDF library (`analysis/pdf.py`).
- What If (`web/whatif.py`): try a patch on a temporary clone of the audited
  commit and measure it without running anything. The repository's tests
  are listed, not run.
- Replay on the exact commit, with a reproducibility comparison.
- Differential audits against a chosen base, and pull request webhooks
  audited at their head against their base.
- Digital twin (`analysis/twin.py`) with the uncertainty of every node.
- UI:
  - Views (executive, developer, analyst), Twin and Blue Team;
  - What If, replay, PDF and rule approval;
  - taint flows, documentation claims, dead code and services;
  - branch, base and commit fields on the audit form.
- A labelled benchmark corpus (`benchmark/`, 34 labels over 7 repositories),
  run with `python3 -m analysis.benchmark --corpus benchmark`.
- Migration `0017_approval_replay_whatif`.

Changed
- The rule scanners run in an isolated child process (`analysis/scan.py`,
  `web/scanproc.py`), with:
  - a reduced environment;
  - CPU, memory and file-size limits;
  - a timeout (`SECAUDIT_SCAN_TIMEOUT`, `SECAUDIT_SCAN_MEMORY_MB`).
- Learnt immune rules need a person's approval before they look for
  regressions or are exported. Existing rules start unapproved.

Fixed
- Dependency signals from Cargo.toml and lockfiles now quote the manifest
  line as written, so the evidence check can verify them.

## 0.3.0 — 2026-11-02

Added
- An assessment on every finding: confirmed, potential, discarded, or
  unverifiable / needs a dynamic test. It is computed from the evidence and
  never stored (`analysis/assessment.py`).
- An evidence chain per finding, with SHA-256 digests of the chain and of the
  quoted snippet, plus counterfactual exploitation conditions
  (`analysis/evidence_chain.py`).
- Trust: coverage, evidence and adversarial resistance, scored separately with
  no overall number. Its limits always state that a clean audit is not a
  guarantee (`analysis/trust.py`).
- Deterministic scanners whose findings sit next to the model's
  (`source="rule"`):
  - secrets, with an exposure timeline over the fetched history
    (`analysis/secrets_scan.py`);
  - dependencies, dependency-confusion signals, ghost dependencies, a
    CycloneDX 1.5 SBOM and opt-in OSV.dev queries (`analysis/deps.py`);
  - an OWASP MCP Top 10 (2025 beta) auditor for MCP01-MCP10
    (`analysis/mcp_audit.py`, also usable as `python3 -m analysis.mcp_audit DIR`).
- Attack surface inventory and trust boundaries (`analysis/surface.py`).
- Security drift and finding diffs between audits (`analysis/drift.py`).
- Exports (`analysis/reports.py`):
  - SARIF 2.1.0;
  - a JSON report;
  - a self-contained HTML report with executive, developer and analyst views
    and unvalidated Blue Team detection templates;
  - a replay manifest.
- Challenge Mode scoring against labelled repositories (`analysis/benchmark.py`).
- New API endpoints: trust, evidence-chain, report.sarif, report.json,
  report.html, components, sbom.cdx.json, diff, replay.json, project history
  and the MCP catalog.
- New UI sections (MCP, Supply chain, Attack surface, Changes), an assessment
  filter and badges, and trust and exports on the summary.
- New settings:
  - `SECAUDIT_ALLOWED_REPO_OWNERS` limits which repository owners may be
    audited;
  - `SECAUDIT_OSV_CHECK` turns on OSV.dev queries (off by default);
  - `SECAUDIT_MAX_SCAN_CHARS` and `SECAUDIT_MAX_SCAN_FILES` bound what the
    scanners read.
- Migration `0016_rules_and_components`, which adds `findings.source`,
  `findings.rule_id`, `findings.detail` and the `components` table.

Security
- An audit process cannot mark its own findings as rule findings.
- Secret values are masked as `[REDACTED:<hash>]` in every output. Tests check
  that no value leaks through the API or the exports.
- Nothing about the audited repository leaves the server unless
  `SECAUDIT_OSV_CHECK=1`, and then only package names and versions.
