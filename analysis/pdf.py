"""A PDF report with no PDF library (B15).

A small PDF 1.4 writer: Helvetica and Courier from the standard 14 fonts
(nothing embedded), WinAnsi encoding, A4 pages, wrapped text. Enough for a
report someone prints, signs or attaches; no images, no links, no scripts —
a PDF that carries text and nothing able to run.

Characters outside Windows-1252 (most of Unicode beyond Western European
letters) are written as "?": the PDF says what the JSON and HTML exports
say in full.
"""

from datetime import datetime, timezone

from . import assessment

PAGE_W, PAGE_H = 595.28, 841.89       # A4 in points
MARGIN = 50
LEADING = {"title": 22, "h": 16, "b": 12.5, "m": 11}
SIZE = {"title": 17, "h": 12.5, "b": 9.5, "m": 8}
FONT = {"title": "F2", "h": "F2", "b": "F1", "m": "F3"}
# Average glyph widths (per 1000 em) used only to wrap lines.
_AVG = {"F1": 520, "F2": 560, "F3": 600}


def _enc(text: str) -> bytes:
    out = []
    for ch in str(text):
        try:
            b = ch.encode("cp1252")
        except UnicodeEncodeError:
            b = b"?"
        if b in (b"(", b")", b"\\"):
            b = b"\\" + b
        elif b < b" " and b != b"\t":
            b = b" "
        out.append(b)
    return b"".join(out)


def _wrap(text: str, style: str) -> list[str]:
    width = PAGE_W - 2 * MARGIN
    per_line = max(20, int(width / (SIZE[style] * _AVG[FONT[style]] / 1000)))
    lines = []
    for para in str(text).split("\n"):
        while len(para) > per_line:
            cut = para.rfind(" ", 0, per_line)
            cut = cut if cut > per_line // 2 else per_line
            lines.append(para[:cut])
            para = para[cut:].lstrip(" ")
        lines.append(para)
    return lines


class _Doc:
    def __init__(self):
        self.pages: list[list[bytes]] = []
        self._new_page()

    def _new_page(self):
        self.pages.append([])
        self.y = PAGE_H - MARGIN

    def add(self, text: str, style: str = "b", gap: float = 0):
        self.y -= gap
        for line in _wrap(text, style):
            if self.y - LEADING[style] < MARGIN:
                self._new_page()
            self.y -= LEADING[style]
            self.pages[-1].append(
                b"BT /" + FONT[style].encode() + b" " + str(SIZE[style]).encode() +
                b" Tf " + f"{MARGIN:.2f} {self.y:.2f}".encode() + b" Td (" + _enc(line) +
                b") Tj ET")

    def render(self, footer: str) -> bytes:
        objects: list[bytes] = []

        def obj(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        catalog = obj(b"")                       # filled in below
        pages_id = obj(b"")
        f1 = obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                 b"/Encoding /WinAnsiEncoding >>")
        f2 = obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                 b"/Encoding /WinAnsiEncoding >>")
        f3 = obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                 b"/Encoding /WinAnsiEncoding >>")
        kids = []
        total = len(self.pages)
        for i, ops in enumerate(self.pages, 1):
            foot = (b"BT /F1 7.5 Tf " + f"{MARGIN:.2f} {MARGIN / 2:.2f}".encode() +
                    b" Td (" + _enc(f"{footer}  -  {i}/{total}") + b") Tj ET")
            stream = b"\n".join(ops + [foot])
            content = obj(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" +
                          stream + b"\nendstream")
            kids.append(obj(
                b"<< /Type /Page /Parent " + str(pages_id).encode() + b" 0 R /MediaBox [0 0 " +
                f"{PAGE_W} {PAGE_H}".encode() + b"] /Resources << /Font << /F1 " +
                str(f1).encode() + b" 0 R /F2 " + str(f2).encode() + b" 0 R /F3 " +
                str(f3).encode() + b" 0 R >> >> /Contents " + str(content).encode() +
                b" 0 R >>"))
        objects[catalog - 1] = (b"<< /Type /Catalog /Pages " + str(pages_id).encode() +
                                b" 0 R >>")
        objects[pages_id - 1] = (b"<< /Type /Pages /Kids [" +
                                 b" ".join(str(k).encode() + b" 0 R" for k in kids) +
                                 b"] /Count " + str(len(kids)).encode() + b" >>")
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for n, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root " +
                str(catalog).encode() + b" 0 R >>\nstartxref\n" + str(xref).encode() +
                b"\n%%EOF\n")
        return bytes(out)


_T = {
    "en": {"title": "Security audit", "repo": "Repository", "commit": "Commit",
           "generated": "Generated", "trust": "Audit confidence", "findings": "Findings",
           "where": "Where", "assessment": "Assessment", "severity": "Severity",
           "evidence": "Evidence", "fix": "Mitigation", "limits": "Limits",
           "none": "No findings.", "counts": "By assessment", "status": "Triage status",
           "na": "not measured", "coverage": "coverage", "evidence_q": "evidence quality",
           "adversarial": "adversarial resistance"},
    "es": {"title": "Auditoría de seguridad", "repo": "Repositorio", "commit": "Commit",
           "generated": "Generado", "trust": "Confianza de la auditoría",
           "findings": "Hallazgos", "where": "Dónde", "assessment": "Evaluación",
           "severity": "Severidad", "evidence": "Evidencia", "fix": "Mitigación",
           "limits": "Límites", "none": "Sin hallazgos.", "counts": "Por evaluación",
           "status": "Estado de triaje", "na": "no medido", "coverage": "cobertura",
           "evidence_q": "calidad de la evidencia", "adversarial": "resistencia adversarial"},
}
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def to_pdf(audit: dict, trust: dict, tool_version: str) -> bytes:
    lang = audit.get("language") or "en"
    T = _T["es" if lang == "es" else "en"]
    doc = _Doc()
    doc.add(T["title"], "title")
    doc.add(f"{T['repo']}: {audit.get('repo_url')}")
    doc.add(f"{T['commit']}: {audit.get('commit_sha') or '-'}")
    doc.add(f"{T['generated']}: {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
            f"- secaudit {tool_version}")
    doc.add(T["trust"], "h", gap=8)
    for key in ("coverage", "evidence", "adversarial"):
        dim = trust.get(key) or {}
        score = f"{round(dim['score'] * 100)}%" if dim.get("score") is not None else T["na"]
        name = T["evidence_q"] if key == "evidence" else T[key]
        doc.add(f"{name}: {score} {dim.get('band') or ''} - "
                + "; ".join(str(r) for r in dim.get("reasons") or []))
    findings = [f for f in audit.get("findings") or []]
    counts: dict[str, int] = {}
    for f in findings:
        a = assessment.assess(f)
        counts[a] = counts.get(a, 0) + 1
    labels = assessment.LABELS["es" if lang == "es" else "en"]
    doc.add(T["counts"] + ": " + ", ".join(f"{labels.get(k, k)} {v}"
                                          for k, v in sorted(counts.items())))
    doc.add(T["findings"], "h", gap=8)
    if not findings:
        doc.add(T["none"])
    findings.sort(key=lambda f: (assessment.assess(f) == assessment.DISCARDED,
                                 _ORDER.get(f.get("severity"), 9)))
    for f in findings:
        a = assessment.assess(f)
        cwe = assessment.cwe_of(f)
        doc.add(f"[{(f.get('severity') or '').upper()}] {f.get('title')}", "h", gap=4)
        doc.add(f"{T['where']}: {f.get('file')}:{f.get('line') or '-'}  -  "
                f"{T['assessment']}: {labels.get(a, a)}" + (f"  -  {cwe}" if cwe else "")
                + (f"  -  OWASP {(f.get('detail') or {}).get('owasp_mcp')}"
                   if (f.get("detail") or {}).get("owasp_mcp") else ""))
        doc.add(f"{T['status']}: {f.get('status') or '-'} / "
                f"{f.get('verification_status') or '-'} / {f.get('epistemic_status') or '-'}")
        if f.get("description"):
            doc.add(str(f["description"])[:1500])
        if f.get("code_snippet"):
            doc.add(T["evidence"] + ":", "b")
            for line in str(f["code_snippet"]).split("\n")[:12]:
                doc.add(line[:400], "m")
        mitigation = (f.get("detail") or {}).get("mitigation") or f.get("recommendation")
        if mitigation:
            doc.add(f"{T['fix']}: {str(mitigation)[:800]}")
    doc.add(T["limits"], "h", gap=8)
    for line in trust.get("limits") or []:
        doc.add(f"- {line}")
    return doc.render(f"secaudit - {audit.get('repo_url')} @ "
                      f"{(audit.get('commit_sha') or '')[:12]}")
