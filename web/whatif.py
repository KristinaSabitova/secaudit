"""What If?: try a fix on a temporary copy of the audited commit (C29).

The person proposes a patch (a unified diff) for a finding. The server:

1. clones the audited commit into a temporary directory, never the original
   repository, and nothing is pushed or written anywhere else;
2. checks the patch applies cleanly and touches only regular files inside
   the repository (no symlinks, no .git, no submodules);
3. applies it and commits it locally with hooks disabled;
4. measures, without running anything from the repository:
   - whether the code the finding cites is still there;
   - what the deterministic scanners (secrets, dependencies, MCP, taint) find
     before and after: which rule findings go, which appear;
   - whether the project's approved immune rules still match;
   - whether the patch itself weakens a control (security drift);
   - which test files cover the changed files, by name.

The repository's tests are NOT run: running them is running the audited
code, which secaudit never does by default. The result says so, lists the
tests a person should run, and gives the verdict for what was measured
only: "the cited code is gone and nothing new appeared" is evidence for a
fix, never proof of one.
"""

import re
import subprocess
import tempfile
from pathlib import Path

from analysis import drift, evidence, immune
from analysis.parallax import _git_run
from analysis.secrets_scan import redact_line

from . import scanproc
from .gitclone import CloneError, clone_at_commit

MAX_PATCH = 200_000
MAX_DIFF_SHOWN = 60_000


class WhatIfError(Exception):
    pass


def _files_of(patch: str) -> list[str]:
    files = []
    for line in patch.splitlines():
        m = re.match(r"^\+\+\+ (?:b/)?(.+?)\s*$", line) or re.match(r"^--- (?:a/)?(.+?)\s*$",
                                                                     line)
        if m and m.group(1) != "/dev/null" and m.group(1) not in files:
            files.append(m.group(1))
    return files


def check_patch(patch: str) -> list[str]:
    """The files a patch touches, or WhatIfError if it does anything but
    change regular files inside the repository."""
    if not patch.strip():
        raise WhatIfError("the patch is empty")
    if len(patch) > MAX_PATCH:
        raise WhatIfError(f"the patch is larger than {MAX_PATCH} characters")
    if re.search(r"(?m)^(new|old|deleted) file mode 120000|^(new|old) mode 120000|"
                 r"^(new|deleted) file mode 160000|^GIT binary patch", patch):
        raise WhatIfError("the patch creates symlinks, submodules or binary files")
    files = _files_of(patch)
    if not files:
        raise WhatIfError("not a unified diff: no file headers (--- a/... +++ b/...)")
    for f in files:
        parts = Path(f).parts
        if f.startswith("/") or ".." in parts or (parts and parts[0] == ".git"):
            raise WhatIfError(f"the patch reaches outside the repository: {f}")
    return files


def _rule_keys(found: list[dict]) -> dict[tuple, dict]:
    return {(f.get("rule_id"), f.get("file"), f.get("anchor")): f for f in found}


def _scan_findings(scan: dict) -> list[dict]:
    out = []
    for key in ("secrets", "mcp", "taint"):
        part = scan.get(key) or {}
        out += part.get("findings") or []
    out += (scan.get("dependencies") or {}).get("signals") or []
    return out


def _tests_for(project: Path, files: list[str]) -> list[str]:
    r = _git_run(project, "ls-files")
    if r.returncode != 0:
        return []
    tests = [p for p in r.stdout.splitlines()
             if re.search(r"(^|/)(tests?|spec|__tests__)/|(^|/)test_[^/]+\.py$|"
                          r"\.(test|spec)\.\w+$", p)]
    stems = {Path(f).stem for f in files}
    out = []
    for t in tests:
        if any(re.search(rf"(^|[/_.\-]){re.escape(s)}([/_.\-]|$)", t) for s in stems if s):
            out.append(t)
    return out[:50]


def run(repo_url: str, commit: str, finding: dict, patch: str, language: str,
        immune_rules: list[dict], history: int) -> dict:
    files = check_patch(patch)
    with tempfile.TemporaryDirectory(prefix="secaudit-whatif-") as tmp:
        dest = Path(tmp) / "repo"
        try:
            clone_at_commit(repo_url, dest, commit)
        except CloneError as e:
            raise WhatIfError(f"the audited commit could not be checked out: {e}")
        before = scanproc.run_scan(dest, language, history)
        patch_file = Path(tmp) / "fix.patch"
        patch_file.write_text(patch if patch.endswith("\n") else patch + "\n")
        check = _git_run(dest, "apply", "--check", "--whitespace=nowarn", str(patch_file))
        if check.returncode != 0:
            raise WhatIfError("the patch does not apply to the audited commit: "
                              + redact_line((check.stderr or "").strip()[-300:]))
        applied = _git_run(dest, "apply", "--whitespace=nowarn", str(patch_file))
        if applied.returncode != 0:
            raise WhatIfError("the patch could not be applied")
        for args in (("add", "-A"),
                     ("-c", "user.name=secaudit", "-c", "user.email=whatif@secaudit.invalid",
                      "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify",
                      "-m", "what if")):
            r = _git_run(dest, *args)
            if r.returncode != 0:
                raise WhatIfError("the patched copy could not be committed: "
                                  + (r.stderr or "").strip()[-200:])
        diff = _git_run(dest, "diff", "--no-ext-diff", "--no-textconv", "HEAD~1", "HEAD")
        shown = "\n".join(redact_line(l) for l in diff.stdout.splitlines())[:MAX_DIFF_SHOWN]

        # 1. The code the finding cites.
        # check() only ever degrades a verified finding, so start from verified
        # and see whether the patched copy still holds the cited code.
        cited = dict(finding, verification_status="verified")
        evidence.verify_findings(dest, [cited], None)
        still_cited = cited.get("verification_status") == "verified"

        # 2. Rule findings before and after.
        after = scanproc.run_scan(dest, language, history)
        old, new = _rule_keys(_scan_findings(before)), _rule_keys(_scan_findings(after))
        gone = [{"rule_id": k[0], "file": k[1], "title": old[k].get("title")}
                for k in old if k not in new]
        appeared = [{"rule_id": k[0], "file": k[1], "title": new[k].get("title"),
                     "line": new[k].get("line")} for k in new if k not in old]

        # 3. The project's approved immune rules.
        rules = [r["rule"] for r in immune_rules if r.get("rule")]
        immune_result = {"rules": len(rules), "matches": None, "ran": False}
        if rules and immune.semgrep_bin():
            try:
                hits = immune.run_semgrep(rules, dest)
                immune_result = {"rules": len(rules), "ran": True,
                                 "matches": [{"rule": m["rule"], "file": m["file"],
                                              "line": m["line"]} for m in hits][:50]}
            except Exception as e:
                immune_result["error"] = str(e)[:200]

        # 4. Does the patch itself weaken a control?
        weakened = drift.drift(dest, "HEAD~1", "HEAD", language)

        tests = _tests_for(dest, files)

    same_file_gone = [g for g in gone if g["file"] == finding.get("file")]
    if finding.get("source") == "rule":
        target_gone = any(g["rule_id"] == finding.get("rule_id") for g in gone)
    else:
        target_gone = not still_cited
    regressions = appeared or weakened or (immune_result.get("matches") or [])
    verdict = ("promising" if target_gone and not still_cited and not regressions else
               "introduces_issues" if regressions else
               "not_shown")
    es = language == "es"
    return {
        "files": files, "diff": shown,
        "cited_code_still_present": still_cited,
        "finding_rule_gone": target_gone if finding.get("source") == "rule" else None,
        "rule_findings_gone": gone[:100], "rule_findings_new": appeared[:100],
        "rule_findings_gone_same_file": len(same_file_gone),
        "immune": immune_result, "drift": weakened[:50],
        "tests": {"run": False, "candidates": tests,
                  "reason": ("No se ejecutan los tests del repositorio: sería ejecutar el "
                             "código auditado. Ejecútalos tú en un entorno aislado."
                             if es else
                             "The repository's tests are not run: that would run the audited "
                             "code. Run them yourself in an isolated environment.")},
        "verdict": verdict,
        "verdict_note": ("Medido sin ejecutar nada: es indicio de arreglo, no prueba."
                         if es else
                         "Measured without running anything: evidence of a fix, not proof."),
        "original_untouched": True,
    }
