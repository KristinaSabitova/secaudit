"""Module 5: the attack graph, its cheapest paths and the fix that cuts most."""

import pytest

from analysis import attacker

JEWELS = [{"kind": k, "target": k} for k in
          ("secrets", "user_data", "deployment", "administration")]


def finding(id, category, title, status="reachable", severity="low", **kw):
    return {"id": id, "category": category, "title": title, "severity": severity,
            "description": kw.pop("description", ""), "file": kw.pop("file", "app.py"),
            "line": kw.pop("line", 10), "verification_status": "verified",
            "epistemic_status": status, "hypothesis": kw.pop("hypothesis", None), **kw}


# Two low findings that, together, give an anonymous visitor the user data,
# and a third that gives nobody anything.
LOW_CHAIN = [
    finding(1, "authz", "Debug endpoint without authentication",
            description="/debug/login issues a session without auth (unauthenticated)"),
    finding(2, "authz", "Role not checked on /admin/export",
            description="the admin role is not checked; any account may call it"),
    finding(3, "error_handling", "Stack trace in error responses",
            description="debug tracebacks expose internals"),
]


def run(findings=(), divergences=(), leverage=(), agent=None, jewels=JEWELS):
    return attacker.analyze(list(findings), list(divergences), list(leverage),
                            agent or {}, jewels)


def path(result, persona, jewel):
    return next((p for p in result["paths"]
                 if p["persona"] == persona and p["jewel"] == jewel), None)


def steps(result, p):
    return [(result["edges"][i].source, result["edges"][i].target) for i in p["edges"]]


class TestFindingsAsSteps:
    @pytest.mark.parametrize("category, title, kind, cwe", [
        ("injection", "SQL injection in /products", "sql_injection", "CWE-89"),
        ("injection", "Command injection via subprocess", "command_injection", "CWE-78"),
        ("injection", "eval of user input", "code_injection", "CWE-94"),
        ("file_handling", "Path traversal in download", "path_traversal", "CWE-22"),
        ("authz", "IDOR: any order readable by id", "idor", "CWE-639"),
        ("authz", "Asignación masiva en la sesión: escalada a admin y lectura de pedidos "
         "de otro usuario", "privilege", "CWE-285"),
        ("authz", "Bypass de autenticación: usuario admin con contraseña vacía",
         "missing_auth", "CWE-306"),
        ("authz", "La ruta de depuración da la sesión de otro usuario y no exige "
         "ninguna autenticación", "missing_auth", "CWE-306"),
        ("xss", "Reflected XSS in search", "xss", "CWE-79"),
        ("secrets", "Hardcoded API key", "hardcoded_secret", "CWE-798"),
        ("rate_limiting", "No rate limit on login", "brute_force", "CWE-307"),
    ])
    def test_each_kind_has_its_technique(self, category, title, kind, cwe):
        f = finding(1, category, title)
        assert attacker.kind_of(f) == kind
        [e, *_] = attacker.finding_edges(f)
        assert e.explanation["cwe"] == cwe and e.explanation["attack"]
        assert e.finding_id == 1

    def test_a_door_with_no_lock_needs_no_account(self):
        f = finding(1, "authz", "Endpoint de depuración permite suplantar a cualquier "
                    "usuario", description="no exige ninguna autenticación")
        [e] = attacker.finding_edges(f)
        assert e.source == attacker.REQUESTS

    def test_only_findings_shown_to_hold_become_steps(self):
        for status in ("exists", "refuted", None):
            assert attacker.finding_edges(finding(1, "injection", "SQL injection",
                                                  status=status)) == []
        unverified = finding(1, "injection", "SQL injection")
        unverified["verification_status"] = "unverified"
        assert attacker.finding_edges(unverified) == []

    def test_an_inconclusive_finding_is_a_tentative_step(self):
        [e, *_] = attacker.finding_edges(finding(1, "injection", "SQL injection",
                                                 status="inconclusive"))
        assert e.tentative

    def test_preconditions_say_what_it_needs(self):
        f = finding(1, "injection", "SQL injection", hypothesis={
            "source": "the q argument", "preconditions": ["logged-in user"]})
        [e, *_] = attacker.finding_edges(f)
        assert e.source == attacker.ACCOUNT
        assert e.explanation["needs"] == ["logged-in user"]
        assert e.explanation["sees"]["entry"] == "the q argument"

    def test_no_exploit_in_the_explanation(self):
        [e, *_] = attacker.finding_edges(finding(1, "injection", "SQL injection"))
        assert set(e.explanation) == {"kind", "cwe", "attack", "sees", "works",
                                      "needs", "gains"}


class TestPaths:
    def test_two_low_findings_make_a_critical_path(self):
        result = run(LOW_CHAIN)
        p = path(result, "anonymous", "user_data")
        assert steps(result, p) == [("start:anonymous", "sends_requests"),
                                    ("sends_requests", "user_account"),
                                    ("user_account", "accesses_admin"),
                                    ("accesses_admin", "reads_user_data")]
        assert p["severity"] == "critical" and not p["tentative"]
        # Each low finding is worth the critical path it is a step of.
        assert result["contextual"][1] == {"severity": "critical",
                                          "personas": ["anonymous"]}
        assert result["contextual"][2]["severity"] == "critical"
        assert 3 not in result["contextual"]       # it is on no path

    def test_three_low_findings_make_a_critical_path(self):
        # Each one is needed: no account without the first, no admin without
        # the second, no code without the third.
        injection = finding(4, "injection", "Command injection in the backup tool",
                            description="the file name reaches subprocess with shell=True",
                            hypothesis={"preconditions": ["only reachable to an admin"]})
        result = run(LOW_CHAIN[:2] + [injection],
                     jewels=[{"kind": "code_execution", "target": "the server"}])
        p = path(result, "anonymous", "code_execution")
        assert [result["edges"][i].finding_id for i in p["edges"]] == [None, 1, 2, 4]
        assert p["severity"] == "critical"
        assert all(result["contextual"][f]["severity"] == "critical" for f in (1, 2, 4))
        [cut] = attacker.min_cut(result["edges"], result["goals"], result["paths"])[:1]
        assert ["anonymous", "code_execution"] in cut["cuts"]
        assert cut["fix"]["type"] == "finding" and cut["fix"]["id"] in (1, 2, 4)

    def test_an_admin_only_flaw_starts_behind_the_admin_door(self):
        f = finding(1, "injection", "Inyección de comandos",
                    description="subprocess con shell=True",
                    hypothesis={"preconditions": ["requiere rol de administrador"]})
        [e] = attacker.finding_edges(f)
        assert e.source == attacker.ADMIN

    @pytest.mark.parametrize("pre", ["session['role'] == 'admin', alcanzable vía /profile",
                                     "an admin session", "is_admin must be true"])
    def test_ways_of_saying_it_needs_an_admin(self, pre):
        f = finding(1, "injection", "Command injection", description="shell=True",
                    hypothesis={"preconditions": [pre]})
        assert attacker.finding_edges(f)[0].source == attacker.ADMIN

    def test_a_missing_admin_check_does_not_need_an_admin(self):
        f = finding(1, "authz", "Exportación sin comprobación de rol",
                    description="Corrección: comprobar un rol de administrador en el servidor",
                    hypothesis={"preconditions": ["cualquier sesión"]})
        [e] = attacker.finding_edges(f)
        assert e.source == attacker.ACCOUNT

    def test_the_flaw_that_loses_a_tie_is_worth_as_much(self):
        twin = finding(4, "authz", "Login bypass", description="authentication bypass")
        result = run(LOW_CHAIN + [twin])
        assert result["contextual"][1]["severity"] == "critical"
        assert result["contextual"][4] == {"severity": "critical",
                                          "personas": ["anonymous"]}

    def test_a_path_with_no_flaw_is_not_reported(self):
        # A compromised dependency runs code by definition: without any finding,
        # that it reads the environment is not news.
        assert run([])["paths"] == []

    def test_an_inconclusive_step_makes_the_path_tentative_and_milder(self):
        chain = [dict(LOW_CHAIN[0]), dict(LOW_CHAIN[1], epistemic_status="inconclusive")]
        p = path(run(chain), "anonymous", "administration")
        assert p["tentative"] and p["severity"] == "high"

    def test_the_cheapest_way_is_taken(self):
        sqli = finding(9, "injection", "SQL injection in /products")
        result = run(LOW_CHAIN + [sqli])
        p = path(result, "anonymous", "user_data")
        assert [result["edges"][i].finding_id for i in p["edges"]] == [None, 9]

    def test_only_declared_jewels_are_targets(self):
        result = run(LOW_CHAIN, jewels=[{"kind": "administration", "target": "x"}])
        assert {p["jewel"] for p in result["paths"]} == {"administration"}


class TestMinCut:
    def test_the_shared_step_is_the_fix(self):
        # Two ways in (no auth, brute force), one way up (the role check).
        brute = finding(4, "rate_limiting", "No rate limit on /login")
        result = run(LOW_CHAIN + [brute], jewels=[{"kind": "administration", "target": "x"},
                                                  {"kind": "user_data", "target": "y"}])
        [first, *_] = result["min_cut"]
        assert first["fix"] == {"type": "finding", "id": 2}
        assert first["remaining"] == 0

    def test_tentative_steps_are_never_the_recommendation(self):
        chain = [LOW_CHAIN[0], dict(LOW_CHAIN[1], epistemic_status="inconclusive")]
        assert run(chain)["min_cut"] == []

    def test_a_reroute_is_not_a_cut(self):
        brute = finding(4, "rate_limiting", "No rate limit on /login")
        result = run(LOW_CHAIN + [brute], jewels=[{"kind": "administration", "target": "x"}])
        fixes = [c["fix"] for c in result["min_cut"]]
        # Removing the missing-auth step alone leaves brute force: not the first fix.
        assert fixes[0] == {"type": "finding", "id": 2}


class TestOtherModules:
    WORKFLOW = {"id": 70, "file": ".github/workflows/deploy.yml", "leverage": 1.0,
                "oversight": 0.0, "reasons": [{"code": c} for c in (
                    "ci_workflow", "ci_deploy", "ci_secrets", "no_owner", "direct")]}

    def test_an_unwatched_deploy_workflow_lets_a_contributor_deploy(self):
        result = run(leverage=[self.WORKFLOW])
        p = path(result, "malicious_contributor", "deployment")
        assert steps(result, p) == [("start:malicious_contributor", "changes_code"),
                                    ("changes_code", "runs_in_ci"),
                                    ("runs_in_ci", "publishes_release")]
        assert {result["edges"][i].leverage_id for i in p["edges"]} == {70}
        assert ".github/workflows/deploy.yml" in result["attack_files"]

    def test_oversight_makes_the_merge_dearer(self):
        watched = dict(self.WORKFLOW, oversight=0.5)
        cheap = path(run(leverage=[self.WORKFLOW]), "malicious_contributor", "deployment")
        dear = path(run(leverage=[watched]), "malicious_contributor", "deployment")
        assert dear["cost"] > cheap["cost"]

    def test_codeowners_is_no_step_of_its_own(self):
        rows = [{"id": 1, "file": ".github/CODEOWNERS", "leverage": 0.85, "oversight": 0.0,
                 "reasons": [{"code": "codeowners_file"}]}]
        assert all(e.source != e.target for e in attacker.leverage_edges(rows))

    def test_pull_request_target_needs_no_merge(self):
        pr = dict(self.WORKFLOW, reasons=self.WORKFLOW["reasons"] + [{"code": "ci_pr_target"}],
                  oversight=0.9)
        result = run(leverage=[pr])
        p = path(result, "malicious_contributor", "secrets")
        assert steps(result, p) == [("start:malicious_contributor", "runs_in_ci"),
                                    ("runs_in_ci", "reads_secret")]

    def test_hidden_instructions_and_the_agent_surface(self):
        caps = [{"id": 1, "capability": "runs_on_start", "source_file": ".claude/settings.json"},
                {"id": 2, "capability": "reads_files", "source_file": ".claude/settings.json"},
                {"id": 3, "capability": "network", "source_file": ".claude/settings.json"}]
        agent = {"capabilities": caps, "combinations": [
            {"kind": "exfiltration", "unattended": True, "steps": [1, 2, 3]}]}
        hidden = {"id": 5, "kind": "hidden_content", "file": "CLAUDE.md"}
        result = run(divergences=[hidden], leverage=[self.WORKFLOW], agent=agent)
        p = path(result, "manipulated_agent", "secrets")
        assert steps(result, p) == [("start:manipulated_agent", "controls_agent"),
                                    ("controls_agent", "reads_secret")]
        c = path(result, "malicious_contributor", "secrets")
        kinds = [result["edges"][i].explanation["kind"] for i in c["edges"]]
        assert kinds in (["merge", "hidden_instructions", "agent_exfiltration"],
                         ["merge", "high_leverage_file", "ci_secrets"])


class TestJewels:
    def test_suggested_from_what_the_repository_shows(self):
        texts = {"app.py": "import sqlite3\n@app.route('/admin')\ndef admin(): pass\n"}
        leverage = [{"file": ".github/workflows/deploy.yml",
                     "reasons": [{"code": "ci_deploy"}]}]
        kinds = {j["kind"]: j["target"] for j in attacker.suggest_jewels(texts, leverage, [])}
        assert set(kinds) == {"secrets", "user_data", "deployment", "administration"}
        assert "app.py" in kinds["user_data"] and "deploy.yml" in kinds["deployment"]

    def test_in_the_language_of_the_audit(self):
        texts = {"app.py": "import sqlite3\n"}
        kinds = {j["kind"]: j["target"] for j in attacker.suggest_jewels(texts, [], [], "es")}
        assert kinds["secrets"].startswith("los secretos")
        assert kinds["user_data"] == "los datos de usuarios de la base de datos (se usa en app.py)"

    def test_nothing_to_point_at_only_the_secrets(self):
        assert [j["kind"] for j in attacker.suggest_jewels({"a.py": "x=1"}, [], [])] == ["secrets"]
