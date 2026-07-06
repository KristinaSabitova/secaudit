"""Tests for project alias registration and resolution."""
import json
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secaudit import (
    load_projects,
    save_projects,
    resolve_project,
    _PROJECTS_FILE,
)


def _patch_projects(tmp_path, data: dict):
    """Write a projects.json to a temp file and patch _PROJECTS_FILE."""
    pfile = tmp_path / "projects.json"
    pfile.write_text(json.dumps(data))
    return patch("secaudit._PROJECTS_FILE", pfile)


class TestLoadSaveProjects:
    def test_load_empty_when_no_file(self, tmp_path):
        missing = tmp_path / "nope.json"
        with patch("secaudit._PROJECTS_FILE", missing):
            assert load_projects() == {}

    def test_save_and_reload(self, tmp_path):
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            save_projects({"myapp": "/home/user/myapp"})
            loaded = load_projects()
        assert loaded == {"myapp": "/home/user/myapp"}

    def test_save_is_atomic(self, tmp_path):
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            save_projects({"a": "/tmp/a"})
            save_projects({"b": "/tmp/b"})
            loaded = load_projects()
        assert loaded == {"b": "/tmp/b"}

    def test_corrupt_file_returns_empty(self, tmp_path):
        pfile = tmp_path / "projects.json"
        pfile.write_text("not valid json{{{")
        with patch("secaudit._PROJECTS_FILE", pfile):
            assert load_projects() == {}


class TestResolveProject:
    def test_alias_resolves_to_path(self, tmp_path):
        with _patch_projects(tmp_path, {"myapp": "/dev/myapp"}):
            result = resolve_project("myapp")
        assert result == Path("/dev/myapp")

    def test_unknown_arg_treated_as_literal_path(self, tmp_path):
        with _patch_projects(tmp_path, {}):
            result = resolve_project("/some/path")
        assert result == Path("/some/path")

    def test_dot_resolves_to_cwd(self, tmp_path):
        with _patch_projects(tmp_path, {}):
            result = resolve_project(".")
        assert result == Path(".").resolve()

    def test_tilde_expanded(self, tmp_path):
        with _patch_projects(tmp_path, {}):
            result = resolve_project("~/tools")
        assert not str(result).startswith("~")

    def test_alias_takes_priority_over_literal(self, tmp_path):
        """If 'tools' is both an alias and a real dir, alias wins."""
        with _patch_projects(tmp_path, {"tools": "/registered/path"}):
            result = resolve_project("tools")
        assert result == Path("/registered/path")
