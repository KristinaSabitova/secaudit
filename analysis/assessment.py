"""What a finding is worth, in the four words a report can use.

Every other module speaks its own vocabulary — verified or not (the evidence
check), exists/reachable/corroborated/refuted (falsifiability), a rule's own
confirmation conditions (the deterministic scanners). A reader needs one
answer, and it has to be the honest one:

- confirmed: the evidence is enough. A snippet that is really in the file and
  survived every attempt to refute it, or a deterministic rule whose
  confirmation conditions hold on the code itself (a literal credential in a
  config file needs nothing else to be true).
- potential: there are signs — the code is there — but nothing established
  that it can be reached or exploited.
- discarded: an attempt to refute it succeeded. Kept, with the reason.
- unverifiable: no code backs it, or what it claims can only be settled by a
  dynamic test (a missing header the proxy may add, an exploit).

None of these is a statement about exploitation: no module runs the audited
code, so "confirmed" never means "exploited".
"""

CONFIRMED = "confirmed"
POTENTIAL = "potential"
DISCARDED = "discarded"
UNVERIFIABLE = "unverifiable"
ASSESSMENTS = (CONFIRMED, POTENTIAL, DISCARDED, UNVERIFIABLE)

LABELS = {
    "en": {CONFIRMED: "CONFIRMED", POTENTIAL: "POTENTIAL", DISCARDED: "DISCARDED",
           UNVERIFIABLE: "NOT VERIFIABLE / NEEDS A DYNAMIC TEST"},
    "es": {CONFIRMED: "CONFIRMADO", POTENTIAL: "POTENCIAL", DISCARDED: "DESCARTADO",
           UNVERIFIABLE: "NO VERIFICABLE / REQUIERE PRUEBA DINÁMICA"},
}

# Where a finding came from. The model's are claims checked afterwards; a
# rule's are computed on the server's own checkout.
SOURCE_MODEL = "model"
SOURCE_RULE = "rule"
SOURCE_IMMUNE = "immune"

# The CWE a category most often stands for. A category is broad, so this is a
# classification aid for SARIF and the reports, never a claim about the flaw:
# a finding that states its own CWE (rules do) keeps that one.
CATEGORY_CWE = {
    "injection": "CWE-74",
    "authz": "CWE-285",
    "sessions": "CWE-613",
    "rate_limiting": "CWE-307",
    "error_handling": "CWE-209",
    "dependencies": "CWE-1395",
    "file_handling": "CWE-22",
    "secrets": "CWE-798",
    "cors": "CWE-942",
    "xss": "CWE-79",
    "csp": "CWE-1021",
    "csrf": "CWE-352",
    "client_security": "CWE-602",
    "mcp": None,                    # each MCP rule names its own
}


def cwe_of(finding: dict) -> str | None:
    detail = finding.get("detail") or {}
    return detail.get("cwe") or CATEGORY_CWE.get(finding.get("category") or "")


def source_of(finding: dict) -> str:
    if finding.get("source") in (SOURCE_RULE, SOURCE_IMMUNE):
        return finding["source"]
    if finding.get("zombie_of") and (finding.get("verification_note") or "").startswith(
            "matched by immune rule"):
        return SOURCE_IMMUNE
    return SOURCE_MODEL


def assess(finding: dict) -> str:
    """The one word for this finding. See the module docstring."""
    if finding.get("epistemic_status") == "refuted":
        return DISCARDED
    if finding.get("verification_status") != "verified":
        return UNVERIFIABLE
    detail = finding.get("detail") or {}
    if detail.get("needs_dynamic_test"):
        return UNVERIFIABLE
    stated = detail.get("assessment")
    if stated in (CONFIRMED, POTENTIAL, UNVERIFIABLE):
        return stated
    if finding.get("epistemic_status") == "corroborated":
        return CONFIRMED
    return POTENTIAL


def why(finding: dict, language: str = "en") -> str:
    """One sentence on how the assessment was reached."""
    es = language == "es"
    a = assess(finding)
    detail = finding.get("detail") or {}
    if a == DISCARDED:
        return ("Un intento de refutación tuvo éxito; se conserva con el motivo."
                if es else "An attempt to refute it succeeded; kept with the reason.")
    if a == UNVERIFIABLE:
        if finding.get("verification_status") != "verified":
            return ("Ningún fragmento del repositorio lo respalda."
                    if es else "No code from the repository backs it.")
        return ("Solo una prueba dinámica puede decidirlo."
                if es else "Only a dynamic test can settle it.")
    if a == CONFIRMED:
        if detail.get("assessment") == CONFIRMED:
            return ("Las condiciones de confirmación de la regla se cumplen en el código."
                    if es else "The rule's confirmation conditions hold on the code.")
        return ("El fragmento está en el fichero y sobrevivió a todos los intentos de refutarlo."
                if es else "The snippet is in the file and survived every attempt to refute it.")
    return ("El código existe, pero nada estableció que sea alcanzable o explotable."
            if es else "The code is there, but nothing established it can be reached or exploited.")
