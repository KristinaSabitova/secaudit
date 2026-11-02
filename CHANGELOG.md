# Changelog

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
