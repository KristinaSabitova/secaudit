"""Tests for `secaudit init` and `projects add` improvements."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secaudit import (
    _INIT_MARKER,
    _confirm,
    _is_git_repo,
    cmd_init,
    cmd_projects,
    detect_shell_rc,
    load_projects,
    save_projects,
    _PROJECTS_FILE,
)


# ---------------------------------------------------------------------------
# detect_shell_rc
# ---------------------------------------------------------------------------

class TestDetectShellRc:
    def test_zsh_shell(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/zsh")
        assert detect_shell_rc().name == ".zshrc"

    def test_bash_shell(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/bash")
        assert detect_shell_rc().name == ".bashrc"

    def test_bash_in_path(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/usr/local/bin/bash")
        assert detect_shell_rc().name == ".bashrc"

    def test_unknown_shell_defaults_to_zshrc(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/usr/local/bin/fish")
        assert detect_shell_rc().name == ".zshrc"

    def test_no_shell_env_defaults_to_zshrc(self, monkeypatch):
        monkeypatch.delenv("SHELL", raising=False)
        assert detect_shell_rc().name == ".zshrc"

    def test_returns_path_under_home(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/zsh")
        rc = detect_shell_rc()
        assert rc.parent == Path.home()


# ---------------------------------------------------------------------------
# cmd_init — idempotency and alias injection
# ---------------------------------------------------------------------------

class TestCmdInit:
    def test_installs_alias_in_empty_rc(self, tmp_path):
        rc = tmp_path / ".zshrc"
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        content = rc.read_text()
        assert _INIT_MARKER in content
        assert f'alias secaudit="python3 {script}"' in content

    def test_creates_rc_file_if_missing(self, tmp_path):
        rc = tmp_path / ".zshrc"
        assert not rc.exists()
        cmd_init(rc_file=rc, script=tmp_path / "secaudit.py")
        assert rc.exists()

    def test_idempotent_first_run(self, tmp_path):
        rc = tmp_path / ".zshrc"
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        cmd_init(rc_file=rc, script=script)  # second call
        content = rc.read_text()
        assert content.count(_INIT_MARKER) == 1

    def test_idempotent_preserves_existing_content(self, tmp_path):
        rc = tmp_path / ".zshrc"
        rc.write_text("export PATH=$PATH:/usr/local/bin\n")
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        cmd_init(rc_file=rc, script=script)
        content = rc.read_text()
        assert "export PATH" in content
        assert content.count(_INIT_MARKER) == 1

    def test_does_not_touch_rc_when_already_installed(self, tmp_path):
        rc = tmp_path / ".zshrc"
        original = "# existing stuff\n# secaudit alias\nalias secaudit=\"python3 /old/path\"\n"
        rc.write_text(original)
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        # File must be unchanged
        assert rc.read_text() == original

    def test_alias_uses_absolute_script_path(self, tmp_path):
        rc = tmp_path / ".zshrc"
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        content = rc.read_text()
        assert str(script.resolve()) in content

    def test_never_prints_rc_contents(self, tmp_path, capsys):
        rc = tmp_path / ".zshrc"
        rc.write_text("VERY_SECRET_LINE=do_not_print_me\n")
        script = tmp_path / "secaudit.py"
        cmd_init(rc_file=rc, script=script)
        out = capsys.readouterr().out
        assert "VERY_SECRET_LINE" not in out
        assert "do_not_print_me" not in out

    def test_prints_source_instruction(self, tmp_path, capsys):
        rc = tmp_path / ".zshrc"
        cmd_init(rc_file=rc, script=tmp_path / "secaudit.py")
        out = capsys.readouterr().out
        assert "source" in out

    def test_already_installed_message_does_not_reveal_contents(self, tmp_path, capsys):
        rc = tmp_path / ".zshrc"
        rc.write_text(f"MY_API_KEY=secret123\n{_INIT_MARKER}\nalias secaudit=...\n")
        cmd_init(rc_file=rc, script=tmp_path / "secaudit.py")
        out = capsys.readouterr().out
        assert "secret123" not in out
        assert "MY_API_KEY" not in out


# ---------------------------------------------------------------------------
# projects add — optional path defaults to cwd
# ---------------------------------------------------------------------------

class TestProjectsAddCwd:
    def test_no_path_uses_cwd(self, tmp_path, monkeypatch):
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            cmd_projects(["add", "myapp"])
        data = json.loads(pfile.read_text())
        assert data["myapp"] == str(tmp_path)

    def test_explicit_path_still_works(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / ".git").mkdir()
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            cmd_projects(["add", "myapp", str(target)])
        data = json.loads(pfile.read_text())
        assert data["myapp"] == str(target)

    def test_no_git_with_force_saves(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            cmd_projects(["add", "myapp", "--force"])
        data = json.loads(pfile.read_text())
        assert "myapp" in data

    def test_no_git_no_force_non_tty_exits(self, tmp_path, monkeypatch):
        """Non-interactive (non-TTY) without --force must exit."""
        monkeypatch.chdir(tmp_path)
        pfile = tmp_path / "projects.json"
        # _confirm returns False when not a TTY (default in tests)
        with patch("secaudit._PROJECTS_FILE", pfile):
            with patch("secaudit._confirm", return_value=False):
                with pytest.raises(SystemExit):
                    cmd_projects(["add", "myapp"])

    def test_no_git_confirm_yes_saves(self, tmp_path, monkeypatch):
        """User confirms → saves even without .git and without --force."""
        monkeypatch.chdir(tmp_path)
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            with patch("secaudit._confirm", return_value=True):
                cmd_projects(["add", "myapp"])
        data = json.loads(pfile.read_text())
        assert "myapp" in data

    def test_git_repo_skips_confirmation(self, tmp_path, monkeypatch):
        """When .git exists, _confirm is never called."""
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            with patch("secaudit._confirm", side_effect=AssertionError("should not be called")):
                cmd_projects(["add", "myapp"])  # must not raise
        data = json.loads(pfile.read_text())
        assert "myapp" in data

    def test_nonexistent_path_exits(self, tmp_path):
        pfile = tmp_path / "projects.json"
        with patch("secaudit._PROJECTS_FILE", pfile):
            with pytest.raises(SystemExit):
                cmd_projects(["add", "myapp", "/nonexistent/path/xyz"])


# ---------------------------------------------------------------------------
# _is_git_repo
# ---------------------------------------------------------------------------

class TestIsGitRepo:
    def test_dir_with_git_dir(self, tmp_path):
        (tmp_path / ".git").mkdir()
        assert _is_git_repo(tmp_path) is True

    def test_dir_with_git_file(self, tmp_path):
        # worktree / submodule: .git is a file
        (tmp_path / ".git").write_text("gitdir: ../.git/worktrees/foo\n")
        assert _is_git_repo(tmp_path) is True

    def test_plain_dir_is_not_git(self, tmp_path):
        assert _is_git_repo(tmp_path) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
