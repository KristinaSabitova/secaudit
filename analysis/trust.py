"""How far an audit can be trusted, measured in parts that are kept apart.

Audit Confidence is not one number. Folding coverage, the quality of the
evidence and the auditor's resistance to the repository into a single score
would let a well-covered audit hide that its auditor was being steered, or a
clean result hide that half the code was never read. So each dimension is
scored on its own, from what the other modules stored, with the reasons that
moved it; and the limits — what no score here can account for — are listed
next to them, never folded in.

A dimension that cannot be measured is None and says why. A clean audit with
no findings is never a guarantee: that sentence is in the limits of every
audit, and a clean audit whose auditor missed planted decoys is flagged.
"""

TRUST_VERSION = "1"

# How much each risk tier weighs in coverage: the files that run on their own
# and the ones agents read matter more than tests and docs.
TIER_WEIGHT = {1: 3.0, 2: 3.0, 3: 2.5, 4: 2.5, 5: 1.5, 6: 0.5}


def _lang(language: str):
    """Pick the sentence in the audit's language."""
    return (lambda en, es: es) if language == "es" else (lambda en, es: en)


def _band(score: float | None) -> str | None:
    if score is None:
        return None
    return "high" if score >= 0.8 else "medium" if score >= 0.5 else "low"


def coverage_score(rows: list[dict] | None, summary: dict | None, L=None) -> dict:
    """Share of the repository, weighted by risk, that the auditor was shown."""
    L = L or _lang("en")
    reasons = []
    files = [r for r in rows or [] if not str(r.get("file", "")).endswith("/")]
    readable = [r for r in files if "not text" not in str(r.get("reason"))
                and "ignored by git" not in str(r.get("reason"))]
    if readable:
        total = got = 0.0
        for r in readable:
            w = TIER_WEIGHT.get(r.get("risk_tier"), 1.5)
            total += w
            if r.get("audited"):
                got += w * (0.5 if str(r.get("reason")).startswith("audited in part") else 1)
        score = got / total if total else None
    elif summary and summary.get("files"):
        score = summary.get("audited", 0) / summary["files"]
        reasons.append(L("unweighted: the per-file coverage was not available", "sin ponderar: no se tenía la cobertura por fichero"))
    else:
        return {"score": None, "band": None,
                "reasons": [L("no coverage was recorded for this audit", "esta auditoría no registró cobertura")]}
    s = summary or {}
    if s.get("high_risk_not_audited"):
        reasons.append(L(f"{s['high_risk_not_audited']} high-risk file(s) were not audited", f"{s['high_risk_not_audited']} fichero(s) de alto riesgo sin auditar"))
    if s.get("failed_requests"):
        reasons.append(L(f"{s['failed_requests']} request(s) to the backend failed", f"fallaron {s['failed_requests']} petición(es) al backend"))
    if s.get("padding_suspected"):
        reasons.append(L("padding was suspected: something may have been pushed out", "se sospecha relleno: algo pudo quedar fuera"))
    if score is not None and s.get("high_risk_not_audited"):
        score = min(score, 0.79)        # never "high" with a high-risk gap
    return {"score": round(score, 3) if score is not None else None,
            "band": _band(score), "reasons": reasons}


def evidence_score(findings: list[dict], L=None) -> dict:
    """How well the findings are backed: by code, and by surviving refutation."""
    L = L or _lang("en")
    if not findings:
        return {"score": None, "band": None,
                "reasons": [L("no findings: there is no evidence to weigh, which is "
                              "not evidence of safety", "sin hallazgos: no hay evidencia que pesar, "
                              "y eso no es evidencia de seguridad")]}
    verified = [f for f in findings if f.get("verification_status") == "verified"]
    share = len(verified) / len(findings)
    tested = [f for f in verified if f.get("epistemic_status") in
              ("reachable", "corroborated", "refuted", "inconclusive")]
    held = [f for f in verified if f.get("epistemic_status") in ("reachable", "corroborated")]
    reasons = [L(f"{len(verified)} of {len(findings)} finding(s) are backed by code "
                 f"found in the file", f"{len(verified)} de {len(findings)} hallazgo(s) "
                 f"respaldados por código encontrado en el fichero")]
    score = share
    if verified:
        reasons.append(L(f"{len(held)} shown reachable or corroborated, "
                         f"{len(tested) - len(held)} refuted or inconclusive, "
                         f"{len(verified) - len(tested)} never tested past existence",
                         f"{len(held)} alcanzables o corroborados, "
                         f"{len(tested) - len(held)} refutados o no concluyentes, "
                         f"{len(verified) - len(tested)} sin probar más allá de su existencia"))
        # Half the weight is having code at all; half is having been tested.
        score = 0.5 * share + 0.5 * (len(held) + 0.5 * (len(verified) - len(tested))) \
            / len(verified)
    return {"score": round(score, 3), "band": _band(score), "reasons": reasons}


def adversarial_score(canary: dict | None, divergences: list[dict],
                      summary: dict | None, L=None) -> dict:
    """How well the auditor held up against this repository."""
    L = L or _lang("en")
    reasons = []
    hidden = [d for d in divergences if d.get("kind") == "hidden_content"]
    if canary and canary.get("planted"):
        score = float(canary.get("integrity_score")
                      if canary.get("integrity_score") is not None
                      else canary.get("found", 0) / canary["planted"])
        reasons.append(L(f"found {canary.get('found', 0)} of {canary['planted']} "
                         f"planted decoy(s)", f"encontró {canary.get('found', 0)} de "
                         f"{canary['planted']} señuelo(s) plantados"))
    else:
        score = None
        reasons.append(L("no decoys were planted, so the auditor's integrity on this "
                         "repository was not measured", "no se plantaron señuelos: la "
                         "integridad del auditor en este repositorio no se midió"))
    if hidden:
        reasons.append(L(f"{len(hidden)} place(s) hide content from a human reader "
                         f"(instructions, invisible characters)", f"{len(hidden)} sitio(s) "
                         f"ocultan contenido a un lector humano (instrucciones, caracteres "
                         f"invisibles)"))
        if score is not None:
            score = min(score, 0.79)
    if (summary or {}).get("padding_suspected"):
        reasons.append(L("padding suspected", "se sospecha relleno"))
    return {"score": round(score, 3) if score is not None else None,
            "band": _band(score), "reasons": reasons}


def limits(audit: dict, findings: list[dict], modules: list[dict], L=None) -> list[str]:
    """What none of the scores accounts for. Always listed."""
    L = L or _lang("en")
    out = [
        L("An audit without alerts is not a guarantee of security.",
          "Una auditoría sin alertas no es una garantía de seguridad."),
        L("No code from the repository is executed: exploitation is never "
          "demonstrated, only argued from the code.",
          "No se ejecuta código del repositorio: la explotación nunca se demuestra, "
          "solo se argumenta desde el código."),
        L("Findings from a model vary between runs; the same commit can yield "
          "different findings.",
          "Los hallazgos de un modelo varían entre ejecuciones; el mismo commit puede "
          "dar hallazgos distintos."),
        L("Flow analysis (refutation by call graph and sanitizers) reads Python only.",
          "El análisis de flujo (refutación por grafo de llamadas y saneado) solo lee "
          "Python."),
    ]
    names = {m.get("module"): m for m in modules}
    deps = names.get("dependencies")
    if deps is None:
        out.append(L("Dependencies were not inventoried in this audit.",
                     "Esta auditoría no inventarió las dependencias."))
    elif not ((deps.get("detail") or {}).get("osv") or {}).get("queried"):
        out.append(L("Known vulnerabilities in dependencies were not looked up "
                     "(OSV.dev is only asked with SECAUDIT_OSV_CHECK=1).",
                     "No se consultaron vulnerabilidades conocidas de las dependencias "
                     "(OSV.dev solo se consulta con SECAUDIT_OSV_CHECK=1)."))
    lev = (names.get("leverage") or {}).get("detail") or {}
    if lev and not (lev.get("github") or {}).get("used"):
        out.append(L("Review and branch protection were not asked of GitHub "
                     "(no SECAUDIT_GITHUB_TOKEN): oversight is partly unknown.",
                     "No se preguntó a GitHub por revisiones ni protección de rama "
                     "(sin SECAUDIT_GITHUB_TOKEN): la vigilancia es en parte desconocida."))
    for name, m in names.items():
        if m.get("status") == "error":
            out.append(L(f"The module '{name}' failed in this audit; its part is missing.",
                         f"El módulo '{name}' falló en esta auditoría; falta su parte."))
    return out


def compute(audit: dict, coverage_rows: list[dict] | None = None) -> dict:
    """Every dimension of trust for one audit (as audit_to_dict serialises it)."""
    L = _lang(audit.get("language") or "en")
    findings = audit.get("findings") or []
    modules = audit.get("modules") or []
    summary = audit.get("coverage")
    canary = audit.get("canary") or {}
    return {
        "version": TRUST_VERSION,
        "coverage": coverage_score(coverage_rows, summary, L),
        "evidence": evidence_score(findings, L),
        "adversarial": adversarial_score(audit.get("canary"),
                                         audit.get("divergences") or [], summary, L),
        "limits": limits(audit, findings, modules, L),
        # A clean result from an auditor that missed what was planted.
        "unreliable_clean": bool(audit.get("status") == "done" and not findings
                                 and canary.get("planted")
                                 and canary.get("found", 0) < canary["planted"]),
    }
