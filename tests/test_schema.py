"""The v3 data model: migrations that match the models, both ways."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from web import db as web_db
from web import models as m

ROOT = Path(__file__).resolve().parent.parent

V3_TABLES = {"projects", "module_runs", "hypotheses", "refutation_attempts",
             "view_divergences", "canary_runs", "immune_rules", "file_leverage",
             "agent_capabilities", "crown_jewels", "attack_nodes", "attack_edges",
             "attack_paths", "coverage"}


def alembic(db_file, *args):
    r = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT,
                       text=True, capture_output=True,
                       env={**os.environ, "DATABASE_URL": f"sqlite:///{db_file}"})
    assert r.returncode == 0, r.stderr
    return r


def schema(url):
    insp = inspect(create_engine(url))
    out = {}
    for table in insp.get_table_names():
        if table == "alembic_version":
            continue
        out[table] = {
            "columns": {c["name"]: c["nullable"] for c in insp.get_columns(table)},
            "fks": sorted((tuple(fk["constrained_columns"]), fk["referred_table"],
                           (fk.get("options") or {}).get("ondelete"))
                          for fk in insp.get_foreign_keys(table)),
        }
    return out


class TestMigrationsMatchTheModels:
    def test_the_migrated_schema_is_the_models_schema(self, tmp_path):
        """A column added to one and not the other fails here, not in production."""
        migrated = tmp_path / "migrated.db"
        alembic(migrated, "upgrade", "head")
        modelled = tmp_path / "modelled.db"
        engine = create_engine(f"sqlite:///{modelled}")
        web_db.Base.metadata.create_all(engine)

        a, b = schema(f"sqlite:///{migrated}"), schema(f"sqlite:///{modelled}")
        assert set(a) == set(b)
        assert V3_TABLES <= set(a)
        for table in a:
            assert a[table]["columns"] == b[table]["columns"], table
            assert a[table]["fks"] == b[table]["fks"], table

    def test_every_v3_migration_goes_back_down(self, tmp_path):
        db_file = tmp_path / "mig.db"
        alembic(db_file, "upgrade", "head")
        alembic(db_file, "downgrade", "0009")
        tables = set(schema(f"sqlite:///{db_file}"))
        assert not (V3_TABLES - {"coverage"}) & tables
        cols = schema(f"sqlite:///{db_file}")["findings"]["columns"]
        assert "epistemic_status" not in cols and "zombie_of" not in cols
        assert "project_id" not in schema(f"sqlite:///{db_file}")["audits"]["columns"]
        alembic(db_file, "upgrade", "head")

    @pytest.mark.parametrize("step", ["0010", "0011", "0012", "0013", "0014", "0015"])
    def test_each_step_is_reversible_on_its_own(self, tmp_path, step):
        db_file = tmp_path / "mig.db"
        previous = f"{int(step) - 1:04d}"
        alembic(db_file, "upgrade", previous)
        before = schema(f"sqlite:///{db_file}")
        alembic(db_file, "upgrade", step)
        alembic(db_file, "downgrade", previous)
        assert schema(f"sqlite:///{db_file}") == before


class TestProjectsBackfill:
    def test_existing_audits_get_a_project_per_owner_and_repository(self, tmp_path):
        db_file = tmp_path / "mig.db"
        alembic(db_file, "upgrade", "0009")
        con = sqlite3.connect(db_file)
        con.execute("INSERT INTO users (id, github_id, login, is_admin, created_at) "
                    "VALUES (1, 'g1', 'kris', 1, '2026-09-01'), "
                    "(2, 'g2', 'ana', 0, '2026-09-01')")
        rows = [("a1", 1, "https://github.com/x/one.git"),
                ("a2", 1, "https://github.com/x/one.git"),
                ("a3", 2, "https://github.com/x/one.git"),
                ("a4", None, "https://github.com/x/one.git"),
                ("a5", None, "https://github.com/x/one.git"),
                ("a6", 1, "https://github.com/x/two.git")]
        for audit_id, user_id, url in rows:
            con.execute("INSERT INTO audits (id, repo_url, user_id, trigger, status, "
                        "created_at, summary, language) VALUES (?, ?, ?, 'manual', "
                        "'done', '2026-09-01', '{}', 'en')", (audit_id, url, user_id))
        con.commit()
        con.close()

        alembic(db_file, "upgrade", "head")
        con = sqlite3.connect(db_file)
        projects = con.execute("SELECT id, user_id, repo_url FROM projects").fetchall()
        assert len(projects) == 4
        by_audit = dict(con.execute("SELECT id, project_id FROM audits").fetchall())
        con.close()
        assert by_audit["a1"] == by_audit["a2"]          # same owner, same repo
        assert by_audit["a3"] != by_audit["a1"]          # another owner
        assert by_audit["a4"] == by_audit["a5"] != by_audit["a1"]   # the instance's
        assert by_audit["a6"] not in (by_audit["a1"], by_audit["a3"])
        assert all(by_audit.values())

    def test_old_findings_are_not_said_to_exist(self, tmp_path):
        """They were verified on the model's word, never checked against a file."""
        db_file = tmp_path / "mig.db"
        alembic(db_file, "upgrade", "0010")
        con = sqlite3.connect(db_file)
        con.execute("INSERT INTO audits (id, repo_url, trigger, status, created_at, "
                    "summary, language) VALUES ('a1', 'u', 'manual', 'done', "
                    "'2026-09-01', '{}', 'en')")
        con.execute("INSERT INTO findings (audit_id, severity, category, title, "
                    "description, file, anchor, fingerprint, verification_status) "
                    "VALUES ('a1', 'high', 'x', 't', 'd', 'f', 'a', 'fp', 'verified')")
        con.commit()
        con.close()
        alembic(db_file, "upgrade", "head")
        con = sqlite3.connect(db_file)
        assert con.execute("SELECT epistemic_status FROM findings").fetchone() == (None,)
        con.close()


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'orm.db'}")
    web_db.reset_engine()
    web_db.Base.metadata.create_all(web_db.get_engine())
    s = web_db.get_session()
    yield s
    s.close()
    web_db.reset_engine()


class TestCascades:
    """Deleting an audit takes everything computed for it along."""

    def test_deleting_an_audit_leaves_nothing_behind(self, session):
        project = m.Project(repo_url="https://github.com/x/y.git")
        session.add(project)
        session.flush()
        audit = m.Audit(repo_url=project.repo_url, project_id=project.id)
        session.add(audit)
        session.flush()
        finding = m.Finding(audit_id=audit.id, severity="high", title="t")
        session.add(finding)
        session.flush()
        hypothesis = m.Hypothesis(finding_id=finding.id, source="request.args",
                                  sink="cursor.execute", complete=True)
        session.add(hypothesis)
        session.flush()
        session.add(m.RefutationAttempt(hypothesis_id=hypothesis.id,
                                        method="callgraph", result="survived"))
        divergence = m.ViewDivergence(audit_id=audit.id, file="CLAUDE.md",
                                      view_a="human", view_b="bytes",
                                      kind="hidden_content", detail="d",
                                      severity="high")
        session.add(divergence)
        session.add(m.CanaryRun(audit_id=audit.id, canaries_planted=3,
                                canaries_found=2, integrity_score=0.67))
        leverage = m.FileLeverage(audit_id=audit.id, file="ci.yml",
                                  leverage_score=0.9, oversight_score=0.1)
        session.add(leverage)
        session.add(m.AgentCapability(audit_id=audit.id, source_file=".mcp.json",
                                      capability="network", detail="d"))
        session.add(m.ModuleRun(audit_id=audit.id, module="audit", status="ok"))
        session.add(m.Coverage(audit_id=audit.id, file="a.py", audited=True,
                               reason="audited", risk_tier=5))
        session.flush()
        a = m.AttackNode(audit_id=audit.id, key="internet", label="Internet",
                         persona="anonymous")
        b = m.AttackNode(audit_id=audit.id, key="reads_secret", label="Reads a secret")
        session.add_all([a, b])
        session.flush()
        edge = m.AttackEdge(audit_id=audit.id, source_node_id=a.id,
                            target_node_id=b.id, finding_id=finding.id, cost=1.0)
        session.add(edge)
        session.flush()
        session.add(m.AttackPath(audit_id=audit.id, persona="anonymous",
                                 target_node_id=b.id, cost=1.0, edges=[edge.id],
                                 severity="critical"))
        session.commit()

        session.delete(audit)
        session.commit()
        for model in (m.Finding, m.Hypothesis, m.RefutationAttempt, m.ViewDivergence,
                      m.CanaryRun, m.FileLeverage, m.AgentCapability, m.ModuleRun,
                      m.Coverage, m.AttackNode, m.AttackEdge, m.AttackPath):
            assert session.scalars(select(model)).all() == [], model.__name__
        # The project outlives its audits: rules and jewels belong to it.
        assert session.get(m.Project, project.id) is not None

    def test_a_zombie_outlives_the_finding_it_brought_back(self, session):
        old = m.Audit(repo_url="u")
        new = m.Audit(repo_url="u")
        session.add_all([old, new])
        session.flush()
        fixed = m.Finding(audit_id=old.id, severity="high", title="t",
                          fix_commit="a" * 40)
        session.add(fixed)
        session.flush()
        zombie = m.Finding(audit_id=new.id, severity="high", title="t",
                           zombie_of=fixed.id)
        session.add(zombie)
        session.commit()
        session.delete(old)
        session.commit()
        session.refresh(zombie)
        assert zombie.zombie_of is None

    def test_a_rule_outlives_the_finding_it_was_learnt_from(self, session):
        project = m.Project(repo_url="u")
        audit = m.Audit(repo_url="u")
        session.add_all([project, audit])
        session.flush()
        finding = m.Finding(audit_id=audit.id, severity="high", title="t")
        session.add(finding)
        session.flush()
        rule = m.ImmuneRule(project_id=project.id, finding_id=finding.id,
                            rule_id="r1", rule_yaml="rules: []",
                            source_fix_commit="a" * 40, vulnerable_commit="b" * 40)
        session.add(rule)
        session.commit()
        session.delete(audit)
        session.commit()
        session.refresh(rule)
        assert rule.finding_id is None
