"""From a conclusion back to the code it rests on (Evidence Chain).

For one finding: the commit and the file and lines it points at, the snippet
and its hash, the flow it claims, every check that was run on it and what it
concluded, the hypotheses that were discarded on the way, what is still
unknown, and the confidence that leaves. Nothing here is new analysis — it is
what the other modules already stored, laid out so each link can be followed.

The chain can be hashed. The hash says whether this record changed since it
was computed; it says nothing about whether what the record states is true,
and the database it lives in is not append-only, so it is not immutable
either.

Counterfactuals are the conditions an exploitation would need — the
hypothesis' preconditions and the facts the refutation methods test — each
marked verified, discarded or unknown. Unknown is the default: a condition is
only marked otherwise when a check on the code decided it.
"""

import hashlib
import json

from . import assessment

CHAIN_VERSION = "1"

VERIFIED_CONDITION = "verified"
DISCARDED_CONDITION = "discarded"
UNKNOWN_CONDITION = "unknown"

# What each refutation method decides when it does not refute the finding,
# and what it disproves when it does.
_METHOD_FACT = {
    "callgraph": ("a chain of calls connects the source to the sink",
                  "una cadena de llamadas conecta el origen con el sumidero"),
    "sanitizer": ("what reaches the sink is not only constants, bound parameters "
                  "or a cast", "lo que llega al sumidero no son solo constantes, "
                  "parámetros enlazados o una conversión"),
    "reachability": ("an entry point (route, command, handler) reaches the code",
                     "un punto de entrada (ruta, comando, manejador) alcanza el código"),
    "devil_advocate": ("the strongest argument against it, quoting code, did not hold",
                       "el mejor argumento en contra, citando código, no se sostuvo"),
}


def snippet_hash(snippet: str | None) -> str | None:
    if not snippet:
        return None
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()


def _attempts(finding: dict) -> list[dict]:
    h = finding.get("hypothesis") or {}
    return [a for a in h.get("attempts") or [] if isinstance(a, dict)]


def counterfactuals(finding: dict, language: str = "en") -> list[dict]:
    """The conditions exploitation needs, each with what decided it, if anything."""
    es = language == "es"
    out = []
    for a in _attempts(finding):
        fact = _METHOD_FACT.get(a.get("method"))
        if not fact:
            continue
        status = {"survived": VERIFIED_CONDITION,
                  "refuted": DISCARDED_CONDITION}.get(a.get("result"), UNKNOWN_CONDITION)
        out.append({"condition": fact[1] if es else fact[0], "status": status,
                    "decided_by": a.get("method"), "note": a.get("note")})
    for p in (finding.get("hypothesis") or {}).get("preconditions") or []:
        # The model's own words: nothing on the code decided them.
        out.append({"condition": str(p), "status": UNKNOWN_CONDITION,
                    "decided_by": None,
                    "note": ("precondición declarada por el modelo; ningún análisis "
                             "estático la comprobó" if es else
                             "precondition stated by the model; no static check tested it")})
    if not out and finding.get("verification_status") == "verified":
        out.append({"condition": ("que el código señalado se ejecute con datos del atacante"
                                  if es else "that the code shown runs on attacker data"),
                    "status": UNKNOWN_CONDITION, "decided_by": None,
                    "note": ("no se dio hipótesis de flujo" if es
                             else "no flow hypothesis was given")})
    return out


def _unknowns(finding: dict, language: str) -> list[str]:
    es = language == "es"
    out = []
    if finding.get("verification_status") != "verified":
        out.append("no hay código que respalde el hallazgo" if es
                   else "no code backs the finding")
    h = finding.get("hypothesis")
    if finding.get("verification_status") == "verified" and not (h and h.get("complete")):
        out.append("no hay hipótesis completa (origen y sumidero), así que no se pudo "
                   "refutar el flujo" if es else
                   "no complete hypothesis (source and sink), so the flow could not "
                   "be refuted")
    file = str(finding.get("file") or "")
    if file and not file.endswith(".py") and (h and h.get("complete")):
        out.append("el análisis de flujo solo cubre Python" if es
                   else "flow analysis covers Python only")
    if any(a.get("result") == "inconclusive" for a in _attempts(finding)):
        out.append("al menos una comprobación no fue concluyente" if es
                   else "at least one check was inconclusive")
    out.append("no se ha ejecutado ninguna prueba dinámica: la explotación no está "
               "demostrada" if es else
               "no dynamic test was run: exploitation is not demonstrated")
    return out


def _confidence(finding: dict) -> str:
    a = assessment.assess(finding)
    if a == assessment.CONFIRMED:
        return "high"
    if a == assessment.DISCARDED:
        return "high"           # confident it does not hold as stated
    if a == assessment.UNVERIFIABLE:
        return "low"
    detail = finding.get("detail") or {}
    if detail.get("confidence") in ("high", "medium", "low"):
        return detail["confidence"]
    return "medium" if finding.get("epistemic_status") == "reachable" else "low"


def build(finding: dict, audit: dict, evidence_run: dict | None = None,
          language: str = "en") -> dict:
    """The chain for one finding. audit carries repo_url, commit_sha, id."""
    es = language == "es"
    a = assessment.assess(finding)
    h = finding.get("hypothesis") or None
    checks = []
    if finding.get("verification_status") == "verified":
        checks.append({"check": "evidence", "result": "passed",
                       "note": ("el fragmento aparece en el fichero, en las líneas "
                                "enviadas al auditor" if es else
                                "the snippet appears in the file, within the lines "
                                "sent to the auditor")
                       if assessment.source_of(finding) == assessment.SOURCE_MODEL else
                       ("calculado por una regla sobre la copia del servidor" if es else
                        "computed by a rule on the server's own checkout")})
    else:
        checks.append({"check": "evidence", "result": "failed",
                       "note": finding.get("verification_note")})
    for att in _attempts(finding):
        checks.append({"check": att.get("method"), "result": att.get("result"),
                       "note": att.get("note"), "evidence": att.get("evidence")})
    discarded = [{"hypothesis": c["condition"], "by": c["decided_by"], "note": c["note"]}
                 for c in counterfactuals(finding, language)
                 if c["status"] == DISCARDED_CONDITION]
    chain = {
        "version": CHAIN_VERSION,
        "finding_id": finding.get("id"),
        "conclusion": {"assessment": a,
                       "label": assessment.LABELS["es" if es else "en"][a],
                       "why": assessment.why(finding, language),
                       "title": finding.get("title"),
                       "severity": finding.get("severity"),
                       "contextual_severity": finding.get("contextual_severity"),
                       "category": finding.get("category"),
                       "cwe": assessment.cwe_of(finding),
                       "source": assessment.source_of(finding),
                       "rule_id": finding.get("rule_id")},
        "anchor": {"repo_url": audit.get("repo_url"), "audit_id": audit.get("id"),
                   "commit_sha": audit.get("commit_sha"),
                   "file": finding.get("file") or None,
                   "line": finding.get("line"), "line_end": finding.get("line_end"),
                   "snippet": finding.get("code_snippet"),
                   "snippet_sha256": snippet_hash(finding.get("code_snippet"))},
        "flow": ({"source": h.get("source"), "path": h.get("path") or [],
                  "sink": h.get("sink"), "complete": bool(h.get("complete"))}
                 if h else None),
        "checks": checks,
        "discarded_hypotheses": discarded,
        "counterfactuals": counterfactuals(finding, language),
        "unknowns": _unknowns(finding, language),
        "confidence": _confidence(finding),
        "provenance": finding.get("provenance"),
    }
    chain["sha256"] = digest(chain)
    chain["integrity_note"] = (
        "El hash detecta si este registro cambió desde que se calculó; no garantiza "
        "que sea cierto ni que la base de datos sea inmutable." if es else
        "The hash detects whether this record changed since it was computed; it does "
        "not make it true, and the database it lives in is not immutable.")
    return chain


def digest(chain: dict) -> str:
    """sha256 of the chain without its own hash fields, in canonical JSON."""
    body = {k: v for k, v in chain.items() if k not in ("sha256", "integrity_note")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), default=str)
                          .encode("utf-8")).hexdigest()
