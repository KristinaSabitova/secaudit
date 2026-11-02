"""Challenge Mode: score an audit against a labelled repository (C33).

The labels say what a repository contains — each expected finding by file
and, optionally, category, rule or line range — and, for a clean control,
that it contains nothing. An audit is scored against them:

- true positive: a finding the labels expect (same file, category or rule
  when given, overlapping lines when given), assessed confirmed or potential;
- false negative: an expected finding nothing matched;
- false positive: a confirmed or potential finding no label expects;
- discarded and unverifiable findings are counted apart, not as positives.

Precision, recall and F1 follow, with the coverage, tokens and time the
audit records. A score on a handful of repositories is a score on those
repositories: the result says how many labels it rests on and refuses to
call a sample under 30 labels anything but small.

    python3 -m analysis.benchmark labels.json audit.json
    python3 -m analysis.benchmark --corpus benchmark

The second form runs the deterministic scanners (secrets, dependencies, MCP,
taint) over the labelled corpus in benchmark/ and scores them: no model, no
network, so anyone can reproduce the numbers. It measures the scanners, not
the model's audit; that needs an audit made with the person's own backend,
scored with the first form.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import assessment

SMALL_SAMPLE = 30


def _matches(label: dict, f: dict) -> bool:
    if (f.get("file") or "").lstrip("./") != str(label.get("file") or "").lstrip("./"):
        return False
    for key in ("category", "rule_id"):
        if label.get(key) and f.get(key) != label[key]:
            return False
    if label.get("owasp_mcp") and (f.get("detail") or {}).get("owasp_mcp") != label["owasp_mcp"]:
        return False
    lines = label.get("lines")
    if lines and f.get("line"):
        lo, hi = lines
        if not (f["line"] <= hi and lo <= (f.get("line_end") or f["line"])):
            return False
    return True


def score(labels: dict, audit: dict) -> dict:
    expected = list(labels.get("expected") or [])
    findings = audit.get("findings") or []
    positive = [f for f in findings if assessment.assess(f) in
                (assessment.CONFIRMED, assessment.POTENTIAL)]
    matched_labels, matched_findings = set(), set()
    for i, label in enumerate(expected):
        for j, f in enumerate(positive):
            if j not in matched_findings and _matches(label, f):
                matched_labels.add(i)
                matched_findings.add(j)
                break
    tp = len(matched_labels)
    fn = len(expected) - tp
    fp = len(positive) - len(matched_findings)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)
    modules = audit.get("modules") or []
    return {
        "repository": labels.get("repository") or audit.get("repo_url"),
        "commit_sha": audit.get("commit_sha"),
        "kind": labels.get("kind", "vulnerable" if expected else "clean"),
        "labels": len(expected), "true_positives": tp, "false_positives": fp,
        "false_negatives": fn,
        "discarded": sum(1 for f in findings if assessment.assess(f) == assessment.DISCARDED),
        "unverifiable": sum(1 for f in findings
                            if assessment.assess(f) == assessment.UNVERIFIABLE),
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "missed": [expected[i] for i in range(len(expected)) if i not in matched_labels],
        "unexpected": [{"file": positive[j].get("file"), "title": positive[j].get("title")}
                       for j in range(len(positive)) if j not in matched_findings][:50],
        "coverage": audit.get("coverage"),
        "tokens": sum((m.get("tokens_in") or 0) + (m.get("tokens_out") or 0) for m in modules),
        "duration_ms": sum(m.get("duration_ms") or 0 for m in modules),
        "canary": audit.get("canary"),
        "sample_note": (f"small sample: {len(expected)} label(s); do not generalise"
                        if len(expected) < SMALL_SAMPLE else None),
    }


def aggregate(scores: list[dict]) -> dict:
    tp = sum(s["true_positives"] for s in scores)
    fp = sum(s["false_positives"] for s in scores)
    fn = sum(s["false_negatives"] for s in scores)
    labels = sum(s["labels"] for s in scores)
    return {"repositories": len(scores), "labels": labels, "true_positives": tp,
            "false_positives": fp, "false_negatives": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "clean_false_positives": sum(s["false_positives"] for s in scores
                                         if s["kind"] == "clean"),
            "sample_note": (f"small sample: {labels} label(s) over {len(scores)} "
                            f"repositor(ies); do not generalise"
                            if labels < SMALL_SAMPLE else None)}


# Credential-shaped values are kept out of the corpus files (a repository
# holding them trips every secret scanner, GitHub's included) and written in
# at run time. They match the formats and are not real.
_PLACEHOLDERS = {
    "@@GITHUB_TOKEN@@": "ghp_" + "Zq8RtY2uWx4Vb6Nm1Kp3Ls5Dj7Hg9Fc0Ae2B",
    "@@GITHUB_TOKEN_2@@": "ghp_" + "Mn4Bv6Cx8Zl1Kj3Hg5Fd7Sa9Qw2Er4Ty6Uio",
    "@@GITHUB_TOKEN_FIXTURE@@": "ghp_" + "Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fx0Fx1Fx2",
    "@@AWS_KEY@@": "AKIA" + "Q3RZ7TBN2KWX5YLD",
}


def _materialise(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest)
    for f in dest.rglob("*"):
        if f.is_file():
            text = f.read_text()
            for k, v in _PLACEHOLDERS.items():
                text = text.replace(k, v)
            f.write_text(text)
    for args in (("init", "-q"), ("add", "-A"),
                 ("-c", "user.name=bench", "-c", "user.email=bench@invalid",
                  "-c", "commit.gpgsign=false", "commit", "-qm", "corpus", "--no-verify")):
        subprocess.run(["git", *args], cwd=dest, check=True, capture_output=True)


def scanner_findings(project: Path, language: str = "en") -> list[dict]:
    """What the deterministic scanners report on a checkout, verified as the
    server verifies them."""
    from . import evidence, scan
    result = scan.run(project, language, 10)
    if result["errors"]:
        raise RuntimeError(f"scanner errors: {result['errors']}")
    found = []
    for key in ("secrets", "mcp", "taint"):
        found += (result.get(key) or {}).get("findings") or []
    found += (result.get("dependencies") or {}).get("signals") or []
    evidence.verify_findings(project, found, None)
    return found


def run_corpus(root: Path) -> dict:
    scores = []
    for labels_file in sorted((root / "labels").glob("*.json")):
        labels = json.loads(labels_file.read_text())
        with tempfile.TemporaryDirectory(prefix="secaudit-bench-") as tmp:
            dest = Path(tmp) / labels_file.stem
            _materialise(root / "corpus" / labels_file.stem, dest)
            found = scanner_findings(dest)
        s = score(labels, {"findings": found, "repo_url": labels_file.stem})
        s["deceptions"] = labels.get("deceptions") or []
        scores.append(s)
    return {"measured": "deterministic scanners only (no model)",
            "cases": scores, "total": aggregate(scores)}


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--corpus":
        json.dump(run_corpus(Path(argv[1])), sys.stdout, indent=2)
        print()
        return 0
    if len(argv) != 2:
        print("usage: python3 -m analysis.benchmark labels.json audit.json\n"
              "       python3 -m analysis.benchmark --corpus DIR", file=sys.stderr)
        return 2
    with open(argv[0]) as a, open(argv[1]) as b:
        json.dump(score(json.load(a), json.load(b)), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
