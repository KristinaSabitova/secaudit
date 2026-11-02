"""Exports of one audit: SARIF, a JSON report, a printable HTML report (B15, C30, C31).

Every export is built from the same stored evidence, so they cannot disagree:
the assessment of each finding (analysis/assessment), its CWE when known,
the commit, file and lines, the redacted snippet, the mitigation and its
triage state. No CVSS is computed — a score needs facts about deployment
this tool does not have; a vulnerability from OSV.dev carries the advisory's
own severity word and references, nothing more.

The HTML report has three views over the same findings (Explain Like an
Analyst): the developer's (where and how to fix), the analyst's (evidence,
checks, counterfactuals, detections) and the executive's (what is at stake,
in numbers that come from the findings). It is meant to be printed to PDF
from the browser: no script, and every value from the repository is escaped.

Blue Team proposals are templates per category: what to log and a Sigma
rule skeleton. They are marked NOT VALIDATED everywhere they appear — no
detection here was ever tested against real logs.
"""

import html
import json
from datetime import datetime, timezone

from . import assessment, evidence_chain

REPORT_VERSION = "1"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
          "info": "note"}


def _findings(audit: dict) -> list[dict]:
    return audit.get("findings") or []


def to_sarif(audit: dict, tool_version: str) -> dict:
    """SARIF 2.1.0: one run, one result per finding, rules per rule_id/category."""
    rules, index, results = [], {}, []
    for f in _findings(audit):
        rid = f.get("rule_id") or f"secaudit.{f.get('category') or 'other'}"
        if rid not in index:
            index[rid] = len(rules)
            cwe = assessment.cwe_of(f)
            props = {"tags": [t for t in ("security", f.get("category"),
                                          (f.get("detail") or {}).get("owasp_mcp"), cwe) if t]}
            rules.append({"id": rid, "name": rid,
                          "shortDescription": {"text": rid},
                          "properties": props,
                          **({"helpUri": f"https://cwe.mitre.org/data/definitions/"
                                         f"{cwe.split('-')[1]}.html"} if cwe else {})})
        a = assessment.assess(f)
        result = {
            "ruleId": rid, "ruleIndex": index[rid],
            "level": "none" if a == assessment.DISCARDED else _LEVEL.get(f.get("severity"), "note"),
            "message": {"text": f"{f.get('title')}\n\n{f.get('description') or ''}"[:5000]},
            "partialFingerprints": {"secaudit/v1": f.get("fingerprint") or ""},
            "properties": {"severity": f.get("severity"),
                           "contextualSeverity": f.get("contextual_severity"),
                           "assessment": a, "epistemicStatus": f.get("epistemic_status"),
                           "verification": f.get("verification_status"),
                           "source": assessment.source_of(f),
                           "cwe": assessment.cwe_of(f),
                           "owaspMcp": (f.get("detail") or {}).get("owasp_mcp")},
        }
        if a == assessment.DISCARDED:
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": "refuted by a check on the code"}]
        if f.get("file"):
            region = {}
            if f.get("line"):
                region = {"startLine": f["line"], "endLine": f.get("line_end") or f["line"]}
                if f.get("code_snippet"):
                    region["snippet"] = {"text": f["code_snippet"]}
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"], "uriBaseId": "SRCROOT"},
                **({"region": region} if region else {})}}]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "secaudit", "version": tool_version,
                                "informationUri": "https://github.com/KristinaSabitova/secaudit",
                                "rules": rules}},
            "versionControlProvenance": [{"repositoryUri": audit.get("repo_url"),
                                          "revisionId": audit.get("commit_sha"),
                                          **({"branch": audit["branch"]}
                                             if audit.get("branch") else {})}],
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///"}},
            "results": results,
            "properties": {"auditId": audit.get("id"),
                           "note": "No CVSS is computed. Assessment: confirmed, potential, "
                                   "discarded or unverifiable (needs a dynamic test)."},
        }],
    }


# ---------------------------------------------------------------------------
# Blue Team: proposals, never validated
# ---------------------------------------------------------------------------

BLUE_TEAM = {
    "injection": {
        "log": ["query errors with the route and the parameter names (never the values)",
                "rejected inputs at the validation layer"],
        "detect": "database syntax errors from one client in a short window",
        "keywords": ["syntax error", "unterminated quoted string", "UNION SELECT"],
    },
    "authz": {
        "log": ["every denied access with user id, resource id and route",
                "access to another user's resource ids"],
        "detect": "one user requesting many distinct object ids of other owners",
        "keywords": ["403", "forbidden", "not owner"],
    },
    "sessions": {
        "log": ["session creation, rotation and revocation with user and IP"],
        "detect": "one session token used from several IPs or user agents",
        "keywords": ["session", "token reuse"],
    },
    "rate_limiting": {
        "log": ["failed logins with user and source IP"],
        "detect": "many failed logins from one IP or against one account",
        "keywords": ["login failed", "invalid password"],
    },
    "secrets": {
        "log": ["use of the exposed credential at its provider (cloud audit log)"],
        "detect": "any use of the credential after the date it was committed",
        "keywords": ["AccessKeyId", "token used"],
    },
    "dependencies": {
        "log": ["package installs in CI with versions and registries"],
        "detect": "a package resolved from an unexpected registry",
        "keywords": ["resolved", "registry"],
    },
    "file_handling": {
        "log": ["file paths requested, after normalisation, and rejections"],
        "detect": "requested paths containing ../ or absolute paths",
        "keywords": ["../", "..%2f", "/etc/passwd"],
    },
    "xss": {
        "log": ["CSP violation reports"],
        "detect": "CSP reports for inline script on pages that render user content",
        "keywords": ["csp-report", "script-src"],
    },
    "csrf": {
        "log": ["state-changing requests with Origin/Referer headers"],
        "detect": "state-changing requests whose Origin is not the application's",
        "keywords": ["Origin", "Referer"],
    },
    "cors": {
        "log": ["requests with an Origin header and the CORS decision"],
        "detect": "credentialed requests from origins outside an allowlist",
        "keywords": ["Access-Control-Allow-Origin"],
    },
    "mcp": {
        "log": ["every MCP tool call: client, tool name, arguments (redacted), result status",
                "tool list changes between sessions (descriptions and names)"],
        "detect": "a tool call reading credential paths (~/.ssh, .env) or running a shell",
        "keywords": ["tools/call", ".ssh", "id_rsa", ".env"],
    },
}


def blue_team(f: dict, language: str = "en") -> dict | None:
    """A detection proposal for one finding. Always marked not validated."""
    t = BLUE_TEAM.get(f.get("category") or "")
    if not t:
        return None
    title = f.get("title") or f.get("category")
    sigma = "\n".join([
        f"title: secaudit proposal - {str(title)[:80]}",
        "status: experimental   # NOT VALIDATED: never tested against real logs",
        f"description: {t['detect']}",
        "logsource:",
        "  category: application   # adapt to where these events are logged",
        "detection:",
        "  keywords:",
        *[f"    - '{k}'" for k in t["keywords"]],
        "  condition: keywords",
        "falsepositives:",
        "  - unknown: to be measured on real traffic",
        "level: medium",
    ])
    return {"validated": False,
            "label": "PROPUESTA NO VALIDADA" if language == "es" else "NOT VALIDATED PROPOSAL",
            "log": t["log"], "detect": t["detect"], "sigma": sigma}


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def to_json_report(audit: dict, trust: dict, tool_version: str) -> dict:
    language = audit.get("language") or "en"
    findings = []
    for f in _findings(audit):
        findings.append({**f, "assessment": assessment.assess(f),
                         "cwe": assessment.cwe_of(f),
                         "evidence_chain": evidence_chain.build(f, audit, language=language),
                         "blue_team": blue_team(f, language)})
    return {
        "report_version": REPORT_VERSION, "tool": "secaudit", "tool_version": tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit": {k: audit.get(k) for k in ("id", "repo_url", "branch", "commit_sha",
                                            "trigger", "status", "language", "created_at",
                                            "summary", "coverage", "verified_count")},
        "trust": trust,
        "modules": audit.get("modules") or [],
        "findings": findings,
        "notes": ["No CVSS is computed.",
                  "No code from the repository was executed.",
                  "An audit without alerts is not a guarantee of security."],
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_T = {
    "en": {"title": "Security audit", "commit": "commit", "generated": "generated",
           "views": "Views", "dev": "Developer", "analyst": "Analyst", "exec": "Executive",
           "where": "where", "fix": "fix", "evidence": "evidence", "checks": "checks",
           "unknowns": "unknowns", "conditions": "exploitation conditions",
           "trust": "Audit confidence", "coverage": "coverage", "evidenceq": "evidence quality",
           "adversarial": "adversarial resistance", "limits": "limits",
           "assessment": "assessment", "severity": "severity", "none": "No findings.",
           "notscore": "not measured", "blue": "detection proposal",
           "stake": "What is at stake", "counts": "Findings by assessment",
           "top": "Most severe, confirmed or potential",
           "nocvss": "No CVSS score is computed. No code from the repository was executed. "
                     "An audit without alerts is not a guarantee of security."},
    "es": {"title": "Auditoría de seguridad", "commit": "commit", "generated": "generado",
           "views": "Vistas", "dev": "Desarrollo", "analyst": "Analista", "exec": "Dirección",
           "where": "dónde", "fix": "corrección", "evidence": "evidencia", "checks": "comprobaciones",
           "unknowns": "incógnitas", "conditions": "condiciones de explotación",
           "trust": "Confianza de la auditoría", "coverage": "cobertura",
           "evidenceq": "calidad de la evidencia", "adversarial": "resistencia adversarial",
           "limits": "límites", "assessment": "evaluación", "severity": "gravedad",
           "none": "Sin hallazgos.", "notscore": "no medido", "blue": "propuesta de detección",
           "stake": "Qué está en juego", "counts": "Hallazgos por evaluación",
           "top": "Los más graves, confirmados o potenciales",
           "nocvss": "No se calcula CVSS. No se ejecutó código del repositorio. Una auditoría "
                     "sin alertas no es una garantía de seguridad."},
}

_CSS = """
body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;
color:#1b1f24;background:#fff}
h1{font-size:1.6rem}h2{border-bottom:1px solid #ccd;padding-bottom:.2rem;margin-top:2rem}
h3{margin:1.2rem 0 .3rem}code,pre{font:12px/1.4 ui-monospace,monospace}
pre{background:#f4f5f7;padding:.6rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.tag{display:inline-block;padding:0 .4rem;border:1px solid #889;border-radius:3px;font-size:12px;
margin-right:.3rem}.confirmed{border-color:#a11;color:#a11}.potential{border-color:#a60;color:#a60}
.discarded{color:#667}.unverifiable{border-color:#357;color:#357}
.nv{color:#a11;font-weight:600}table{border-collapse:collapse}td,th{padding:.2rem .6rem;
border-bottom:1px solid #e3e5e8;text-align:left}nav a{margin-right:1rem}
.finding{page-break-inside:avoid;border-left:3px solid #ccd;padding-left:.8rem;margin:1rem 0}
@media print{nav{display:none}.view{page-break-before:always}}
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _tag(a: str, label: str) -> str:
    return f'<span class="tag {_e(a)}">{_e(label)}</span>'


def to_html(audit: dict, trust: dict, tool_version: str) -> str:
    lang = "es" if audit.get("language") == "es" else "en"
    T = _T[lang]
    labels = assessment.LABELS[lang]
    findings = _findings(audit)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: (
        [assessment.CONFIRMED, assessment.POTENTIAL, assessment.UNVERIFIABLE,
         assessment.DISCARDED].index(assessment.assess(f)),
        order.get(f.get("contextual_severity") or f.get("severity"), 5)))
    parts = [f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
             f'<meta name="viewport" content="width=device-width, initial-scale=1">'
             f'<title>{_e(T["title"])} · {_e(audit.get("repo_url"))}</title>'
             f'<style>{_CSS}</style></head><body>',
             f'<h1>{_e(T["title"])}</h1>',
             f'<p><code>{_e(audit.get("repo_url"))}</code> · {_e(T["commit"])} '
             f'<code>{_e(audit.get("commit_sha"))}</code> · {_e(T["generated"])} '
             f'{_e(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))} · '
             f'secaudit {_e(tool_version)}</p>',
             f'<p>{_e(T["nocvss"])}</p>',
             f'<nav>{_e(T["views"])}: <a href="#exec">{_e(T["exec"])}</a>'
             f'<a href="#dev">{_e(T["dev"])}</a><a href="#analyst">{_e(T["analyst"])}</a></nav>']

    # Trust, kept in parts.
    parts.append(f'<h2>{_e(T["trust"])}</h2><table>')
    for key, name in (("coverage", "coverage"), ("evidence", "evidenceq"),
                      ("adversarial", "adversarial")):
        d = trust.get(key) or {}
        score = f'{d["score"]:.2f} ({_e(d.get("band"))})' if d.get("score") is not None \
            else _e(T["notscore"])
        parts.append(f'<tr><th>{_e(T[name])}</th><td>{score}</td>'
                     f'<td>{_e("; ".join(d.get("reasons") or []))}</td></tr>')
    parts.append(f'</table><h3>{_e(T["limits"])}</h3><ul>'
                 + "".join(f"<li>{_e(x)}</li>" for x in trust.get("limits") or []) + "</ul>")

    # Executive view.
    counts = {a: 0 for a in assessment.ASSESSMENTS}
    for f in findings:
        counts[assessment.assess(f)] += 1
    parts.append(f'<section class="view" id="exec"><h2>{_e(T["exec"])}</h2>'
                 f'<h3>{_e(T["counts"])}</h3><table>'
                 + "".join(f"<tr><th>{_e(labels[a])}</th><td>{n}</td></tr>"
                           for a, n in counts.items()) + "</table>")
    top = [f for f in findings if assessment.assess(f) in
           (assessment.CONFIRMED, assessment.POTENTIAL)][:5]
    parts.append(f'<h3>{_e(T["top"])}</h3>')
    parts.append("<ol>" + "".join(
        f"<li>{_tag(assessment.assess(f), labels[assessment.assess(f)])}"
        f"<strong>{_e(f.get('contextual_severity') or f.get('severity'))}</strong> — "
        f"{_e(f.get('title'))}"
        + (f" — {_e((f.get('detail') or {}).get('impact'))}"
           if (f.get("detail") or {}).get("impact") else "") + "</li>"
        for f in top) + "</ol>" if top else f"<p>{_e(T['none'])}</p>")
    parts.append("</section>")

    # Developer view.
    parts.append(f'<section class="view" id="dev"><h2>{_e(T["dev"])}</h2>')
    if not findings:
        parts.append(f"<p>{_e(T['none'])}</p>")
    for f in findings:
        a = assessment.assess(f)
        where = f.get("file") or ""
        if f.get("line"):
            where += f":{f['line']}" + (f"-{f['line_end']}" if f.get("line_end")
                                        and f["line_end"] != f["line"] else "")
        mitigation = (f.get("detail") or {}).get("mitigation")
        parts.append(
            f'<div class="finding"><h3>{_tag(a, labels[a])}{_e(f.get("severity"))} · '
            f'{_e(f.get("title"))}</h3><p><strong>{_e(T["where"])}:</strong> '
            f'<code>{_e(where)}</code> · {_e(assessment.cwe_of(f))}</p>'
            + (f"<pre>{_e(f.get('code_snippet'))}</pre>" if f.get("code_snippet") else "")
            + f"<p>{_e(f.get('description'))}</p>"
            + (f"<p><strong>{_e(T['fix'])}:</strong> {_e(mitigation)}</p>" if mitigation else "")
            + "</div>")
    parts.append("</section>")

    # Analyst view: the evidence chain and the detection proposal.
    parts.append(f'<section class="view" id="analyst"><h2>{_e(T["analyst"])}</h2>')
    for f in findings:
        chain = evidence_chain.build(f, audit, language=lang)
        bt = blue_team(f, lang)
        parts.append(
            f'<div class="finding"><h3>{_e(f.get("title"))}</h3>'
            f'<p>{_tag(chain["conclusion"]["assessment"], chain["conclusion"]["label"])}'
            f'{_e(chain["conclusion"]["why"])} · confidence: {_e(chain["confidence"])} · '
            f'sha256 <code>{_e(chain["sha256"][:16])}</code></p>'
            + (f"<p><strong>flow:</strong> <code>{_e(chain['flow']['source'])}</code> → "
               f"{_e(' → '.join(chain['flow']['path']))} → "
               f"<code>{_e(chain['flow']['sink'])}</code></p>" if chain.get("flow") else "")
            + f"<p><strong>{_e(T['checks'])}:</strong></p><ul>"
            + "".join(f"<li>{_e(c['check'])}: {_e(c['result'])} — {_e(c.get('note'))}</li>"
                      for c in chain["checks"]) + "</ul>"
            + f"<p><strong>{_e(T['conditions'])}:</strong></p><ul>"
            + "".join(f"<li>[{_e(c['status'])}] {_e(c['condition'])}</li>"
                      for c in chain["counterfactuals"]) + "</ul>"
            + f"<p><strong>{_e(T['unknowns'])}:</strong> {_e('; '.join(chain['unknowns']))}</p>"
            + (f'<p><strong>{_e(T["blue"])}</strong> <span class="nv">{_e(bt["label"])}</span>: '
               f'{_e(bt["detect"])}</p><pre>{_e(bt["sigma"])}</pre>' if bt else "")
            + "</div>")
    parts.append("</section></body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# SecAudit Replay
# ---------------------------------------------------------------------------

def replay_manifest(audit: dict, config: dict, versions: dict, immune_rules: list[dict],
                    tool_version: str) -> dict:
    """Everything needed to repeat this audit, and what cannot be repeated.

    config is the non-secret engine configuration in force; no key, token or
    URL with credentials belongs here.
    """
    import hashlib
    llm = [m for m in audit.get("modules") or [] if m.get("module") == "audit"]
    manifest = {
        "replay_version": "1",
        "tool": "secaudit", "tool_version": tool_version,
        "repository": audit.get("repo_url"), "branch": audit.get("branch"),
        "commit_sha": audit.get("commit_sha"), "audit_id": audit.get("id"),
        "language": audit.get("language"), "created_at": audit.get("created_at"),
        "engine": versions,
        "config": config,
        "model": [{"backend": m.get("backend"), "model": m.get("model")} for m in llm],
        "coverage": audit.get("coverage"),
        "immune_rules": [{"rule_id": r.get("rule_id"), "validated": r.get("validated"),
                          "sha256": hashlib.sha256((r.get("yaml") or "").encode()).hexdigest()}
                         for r in immune_rules],
        "references": {
            "owasp_mcp_top10": versions.get("owasp_mcp"),
            "sarif": "2.1.0", "cyclonedx": "1.5", "osv": "https://api.osv.dev/v1",
        },
        "modules": [{"module": m.get("module"), "status": m.get("status"),
                     "tokens_in": m.get("tokens_in"), "tokens_out": m.get("tokens_out")}
                    for m in audit.get("modules") or []],
        "reproducible": ["the commit, the coverage plan, every deterministic module "
                         "(evidence, falsifiability without the devil's advocate, parallax "
                         "without canaries, leverage, attacker, secrets, dependencies, MCP, "
                         "surface, drift) given the same versions and configuration"],
        "not_reproducible": ["the model's findings and arguments: the same prompt can "
                             "yield different findings; canary placement is random by "
                             "design; OSV.dev and GitHub answers change over time"],
    }
    manifest["sha256"] = hashlib.sha256(json.dumps(manifest, sort_keys=True, default=str)
                                        .encode()).hexdigest()
    return manifest
