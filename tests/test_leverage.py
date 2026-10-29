"""Module 4: leverage against oversight per file, and the agent surface."""

import io
import json
import subprocess
import urllib.error

import pytest

from analysis import leverage
from analysis.parallax import repository_texts

DEPLOY = """name: deploy
on:
  push:
    branches: [main]
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"""
TESTS_CI = """name: tests
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
"""


def git(repo, *args, author="Ana Dev"):
    return subprocess.run(["git", "-c", f"user.name={author}", "-c",
                           "user.email=ana@example.com", *args], cwd=repo,
                          check=True, capture_output=True, text=True).stdout.strip()


def write(repo, files):
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)


@pytest.fixture
def lab(tmp_path):
    """A shop whose deploy workflow nobody owns and an agent last touched."""
    repo = tmp_path / "lab"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    write(repo, {"README.md": "# shop\n", "docs/guide.md": "how to\n",
                 ".github/CODEOWNERS": "/src/ @shop/backend\n/.github/workflows/tests.yml @ana\n",
                 ".github/workflows/tests.yml": TESTS_CI,
                 "src/app.py": "def main():\n    pass\n",
                 "tests/test_app.py": "def test():\n    pass\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "skeleton")
    # src/auth.py arrives through a merged pull request.
    git(repo, "checkout", "-qb", "feature")
    write(repo, {"src/auth.py": "def login(user, password):\n    return True\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "login")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "feature", "-m",
        "Merge pull request #7 from ana/feature")
    # The deploy workflow goes straight to main, written with an agent.
    write(repo, {".github/workflows/deploy.yml": DEPLOY})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "deploy on push",
        "-m", "Co-Authored-By: Claude <noreply@anthropic.com>")
    return repo


def run(repo, **kw):
    return leverage.analyze(repo, repository_texts(repo), {}, {}, **kw)


class FakeGitHub(leverage.GitHub):
    def __init__(self, answers, **kw):
        super().__init__("https://github.com/acme/shop", "t0ken", **kw)
        self.answers = answers
        self.asked = []

    def get(self, path):
        if not self.usable:
            return None
        self.calls += 1
        self.asked.append(path)
        return self.answers.get(path)


class TestLeverage:
    def test_the_deploy_workflow_comes_first_with_its_reasons(self, lab):
        result = run(lab)
        top = result["files"][0]
        assert top["file"] == ".github/workflows/deploy.yml"
        assert top["leverage_score"] == 1.0
        codes = {r["code"] for r in top["reasons"]}
        assert {"ci_workflow", "ci_deploy", "ci_secrets", "ci_write_perms",
                "no_owner", "direct", "ai_unreviewed", "protection_unknown"} <= codes
        assert top["oversight_score"] == 0.0

    def test_owned_and_merged_through_a_pull_request_is_watched(self, lab):
        rows = {r["file"]: r for r in run(lab)["files"]}
        auth = rows["src/auth.py"]
        codes = {r["code"]: r for r in auth["reasons"]}
        assert codes["owner"]["args"]["owners"] == ["@shop/backend"]
        # The merge commit names the pull request; without GitHub, whether
        # it was approved is not known, and it is said.
        assert codes["pr_approval_unknown"]["args"]["count"] == 1
        assert auth["oversight_score"] == pytest.approx(0.5)
        assert rows["src/auth.py"]["priority"] < rows[".github/workflows/deploy.yml"]["priority"]

    def test_a_script_a_workflow_runs_inherits_its_leverage(self, lab):
        write(lab, {"scripts/deploy.sh": "#!/bin/sh\necho deploy\n",
                    "scripts/lint.sh": "#!/bin/sh\n"})
        git(lab, "add", "-A")
        git(lab, "commit", "-qm", "scripts")
        rows = {r["file"]: r for r in run(lab)["files"]}
        deploy = rows["scripts/deploy.sh"]
        assert deploy["leverage_score"] == 0.85
        assert {"code": "run_by", "side": "leverage", "delta": 0.45,
                "args": {"by": ".github/workflows/deploy.yml"}} in deploy["reasons"]
        assert rows["scripts/lint.sh"]["leverage_score"] == 0.4

    def test_runners_resolve_paths_relative_to_the_file(self):
        texts = {".husky/pre-commit": "sh ./check.py && node tools/x.js",
                 "README.md": "run ./tools/x.js"}
        files = {".husky/pre-commit", ".husky/check.py", "tools/x.js"}
        assert leverage.runners_of(texts, files) == {
            ".husky/check.py": ".husky/pre-commit", "tools/x.js": ".husky/pre-commit"}

    def test_mentioning_a_script_is_not_running_it(self):
        texts = {"Dockerfile": "COPY app.py ./\n# see deploy.sh\nENTRYPOINT [\"./entry.sh\"]\n",
                 "docker-compose.yml": "# ./deploy.sh ships it\n    command: python serve.py\n"}
        files = {"Dockerfile", "docker-compose.yml", "app.py", "deploy.sh",
                 "entry.sh", "serve.py"}
        assert leverage.runners_of(texts, files) == {"entry.sh": "Dockerfile",
                                                     "serve.py": "docker-compose.yml"}

    def test_tests_and_docs_have_little_leverage(self, lab):
        rows = {r["file"]: r for r in run(lab)["files"]}
        assert rows["tests/test_app.py"]["leverage_score"] == 0.1
        assert rows["docs/guide.md"]["leverage_score"] == 0.1

    @pytest.mark.parametrize("rel, text, code", [
        ("package.json", '{"scripts": {"postinstall": "node x.js"}}', "install_script"),
        ("Dockerfile", "FROM python", "container"),
        ("poetry.lock", "", "lockfile"),
        (".env.production", "A=1", "env_file"),
        ("CLAUDE.md", "be nice", "agent_config"),
        (".github/CODEOWNERS", "* @a", "codeowners_file"),
    ])
    def test_what_each_kind_of_file_is_worth(self, rel, text, code):
        score, reasons = leverage.leverage_of(rel, text)
        assert reasons[0]["code"] == code and score >= 0.5

    def test_pull_request_target_adds_leverage(self):
        wf = "on:\n  pull_request_target:\njobs: {}\n"
        _, reasons = leverage.leverage_of(".github/workflows/pr.yml", wf)
        assert "ci_pr_target" in {r["code"] for r in reasons}

    def test_findings_divergences_and_attack_paths_add_leverage(self):
        base, _ = leverage.leverage_of("src/x.py", "")
        more, reasons = leverage.leverage_of("src/x.py", "", findings=2,
                                             divergences=["hidden_content", "audit_blind_spot"],
                                             on_attack_path=True)
        assert more == pytest.approx(base + 0.3)
        assert [r["code"] for r in reasons][1:] == ["finding", "divergence", "attack_path"]


class TestCodeowners:
    RULES = leverage.parse_codeowners(
        "# owners\n*.js @front\n/docs/ @docs\napps/ @apps\n**/logs @ops\n"
        "/build/logs/ @build\n/src/secret.py\n")

    @pytest.mark.parametrize("path, owners", [
        ("web/app.js", ["@front"]),
        ("docs/a/b.md", ["@docs"]),
        ("x/apps/y.py", ["@apps"]),
        ("deep/logs/out.txt", ["@ops"]),
        ("build/logs/out.txt", ["@build"]),
        ("src/secret.py", []),
        ("src/other.py", None),
    ])
    def test_the_last_matching_rule_wins(self, path, owners):
        found = leverage.owners_of(self.RULES, path)
        assert (found[0] if found else None) == owners

    def test_no_codeowners_is_said(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        git(repo, "init", "-q")
        write(repo, {"a.py": "x = 1\n"})
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "a")
        result = run(repo)
        assert result["codeowners"] is None
        assert "no_codeowners" in {r["code"] for r in result["files"][0]["reasons"]}


class TestGitHub:
    def answers(self, lab, approved=True):
        deploy_sha = git(lab, "rev-parse", "HEAD")
        auth_sha = git(lab, "rev-parse", "HEAD~1^2")
        return {
            "": {"default_branch": "main"},
            "/branches/main": {"protected": True, "protection": {
                "required_pull_request_reviews": {"required_approving_review_count": 1}}},
            "/rules/branches/main": [],
            f"/commits/{deploy_sha}/pulls": [],
            f"/commits/{auth_sha}/pulls": [{"number": 7, "merged_at": "2026-01-01",
                                            "user": {"login": "ana"}}],
            "/pulls/7/reviews": [{"state": "APPROVED" if approved else "COMMENTED",
                                  "user": {"login": "luis"}}],
        }

    def test_an_approved_pull_request_and_a_protected_branch(self, lab):
        gh = FakeGitHub(self.answers(lab))
        rows = {r["file"]: r for r in run(lab, github=gh)["files"]}
        codes = {r["code"]: r for r in rows["src/auth.py"]["reasons"]}
        assert codes["approved"]["args"] == {"count": 1, "of": 1}
        assert codes["protected_reviews"]["args"]["count"] == 1
        assert rows["src/auth.py"]["oversight_score"] == 1.0
        deploy = {r["code"] for r in rows[".github/workflows/deploy.yml"]["reasons"]}
        assert {"direct", "ai_unreviewed", "protected_reviews"} <= deploy

    def test_an_approval_by_the_author_is_not_one(self, lab):
        answers = self.answers(lab)
        answers["/pulls/7/reviews"] = [{"state": "APPROVED", "user": {"login": "ana"}}]
        rows = {r["file"]: r for r in run(lab, github=FakeGitHub(answers))["files"]}
        assert "pr_unapproved" in {r["code"] for r in rows["src/auth.py"]["reasons"]}

    def test_rulesets_count_as_protection(self, lab):
        answers = self.answers(lab)
        answers["/branches/main"] = {"protected": False}
        answers["/rules/branches/main"] = [{"type": "pull_request", "parameters": {
            "required_approving_review_count": 2}}]
        gh = FakeGitHub(answers)
        assert gh.protection()["required_reviews"] == 2

    def test_the_budget_is_kept(self, lab):
        gh = FakeGitHub(self.answers(lab), budget=2)
        gh.get = leverage.GitHub.get.__get__(gh)      # the real accounting
        gh._opener = type("O", (), {"open": lambda self, req, timeout: io.BytesIO(b"{}")})()
        result = run(lab, github=gh)
        assert gh.calls == 2 and "budget" in result["github"]["error"]

    def test_an_error_is_reported_and_nothing_guessed(self, lab):
        def boom(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 401, "bad", {}, None)
        gh = leverage.GitHub("https://github.com/acme/shop", "t0ken")
        gh._opener = type("O", (), {"open": lambda self, req, timeout: boom(req, timeout)})()
        result = run(lab, github=gh)
        assert result["github"]["error"] == "GitHub answered 401"
        assert result["github"]["protection"] == {"known": False}

    def test_no_token_asks_nothing(self, lab, monkeypatch):
        monkeypatch.delenv("SECAUDIT_GITHUB_TOKEN", raising=False)
        result = run(lab, repo_url="https://github.com/acme/shop")
        assert result["github"] == {"used": False, "token": False, "calls": 0,
                                    "error": None, "protection": {"known": False}}


class TestAgentSurface:
    def surface(self, files, hidden=None):
        return leverage.agent_surface(files, hidden)

    def test_a_complete_path_is_reported_as_one(self):
        settings = {"permissions": {"allow": ["Read(~/.ssh/**)", "WebFetch"]},
                    "hooks": {"SessionStart": [{"hooks": [
                        {"type": "command", "command": "./scripts/warmup.sh"}]}]}}
        s = self.surface({".claude/settings.json": json.dumps(settings)})
        caps = {c["capability"] for c in s["capabilities"]}
        assert {"reads_files", "network", "runs_on_start", "executes"} <= caps
        [combo] = s["combinations"]
        assert combo["kind"] == "exfiltration" and combo["severity"] == "critical"
        steps = [s["capabilities"][i]["capability"] for i in combo["steps"]]
        assert steps == ["runs_on_start", "reads_files", "network"]

    def test_bypass_permissions_is_everything(self):
        s = self.surface({".claude/settings.json": json.dumps(
            {"permissions": {"defaultMode": "bypassPermissions"}})})
        assert s["combinations"][0]["severity"] == "high"
        assert s["combinations"][0]["unattended"] is False

    def test_mcp_servers_approved_in_advance_start_on_their_own(self):
        s = self.surface({
            ".claude/settings.json": json.dumps({"enableAllProjectMcpServers": True}),
            ".mcp.json": json.dumps({"mcpServers": {
                "helper": {"command": "npx", "args": ["-y", "some-mcp"]},
                "remote": {"url": "https://mcp.example.invalid/sse"}}})})
        details = [c["detail"] for c in s["capabilities"]]
        assert any("approved in advance" in d for d in details)
        assert any("mcp.example.invalid" in d for d in details)
        assert s["combinations"][0]["kind"] == "exfiltration"

    def test_instructions_that_hide_content_steer_the_tools(self):
        s = self.surface({"CLAUDE.md": "rules\n",
                          ".claude/settings.json": json.dumps(
                              {"permissions": {"allow": ["Bash(curl:*)"]}})},
                         hidden={"CLAUDE.md"})
        steered = [c for c in s["combinations"] if c["kind"] == "steered_tools"][0]
        assert steered["severity"] == "high"
        assert s["capabilities"][steered["steps"][0]]["source_file"] == "CLAUDE.md"

    def test_a_narrow_permission_alone_is_no_path(self):
        s = self.surface({".claude/settings.json": json.dumps(
            {"permissions": {"allow": ["Bash(npm test)"]}})})
        assert s["combinations"] == []
        assert [c["capability"] for c in s["capabilities"]] == ["executes"]

    def test_no_agent_config_no_surface(self):
        assert self.surface({"app.py": "x"}) == {"capabilities": [], "combinations": []}
