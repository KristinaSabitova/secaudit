"""Tests for backend selection logic (no real API calls)."""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secaudit import (
    select_backend,
    ClaudeCodeBackend,
    AnthropicAPIBackend,
    OpenAIBackend,
    OllamaBackend,
    _parse_toml,
    load_config,
    _CONFIG_FILE,
)


# ---------------------------------------------------------------------------
# _parse_toml
# ---------------------------------------------------------------------------

class TestParseToml:
    def test_basic_key_value(self):
        assert _parse_toml('backend = "ollama"') == {"backend": "ollama"}

    def test_comments_ignored(self):
        txt = '# comment\nbackend = "claude-code"\n# another'
        assert _parse_toml(txt) == {"backend": "claude-code"}

    def test_multiple_keys(self):
        txt = 'backend = "anthropic-api"\nmodel = "claude-opus-4-8"'
        result = _parse_toml(txt)
        assert result["backend"] == "anthropic-api"
        assert result["model"] == "claude-opus-4-8"

    def test_single_quoted_values(self):
        assert _parse_toml("backend = 'ollama'") == {"backend": "ollama"}

    def test_empty_lines_ignored(self):
        txt = "\n\nbackend = \"openai-api\"\n\n"
        assert _parse_toml(txt) == {"backend": "openai-api"}


# ---------------------------------------------------------------------------
# select_backend — priority: flag > config > default
# ---------------------------------------------------------------------------

class TestSelectBackend:
    def test_default_is_claude_code(self):
        backend = select_backend(None, {})
        assert isinstance(backend, ClaudeCodeBackend)

    def test_flag_selects_anthropic(self):
        backend = select_backend("anthropic-api", {})
        assert isinstance(backend, AnthropicAPIBackend)

    def test_flag_selects_openai(self):
        backend = select_backend("openai-api", {})
        assert isinstance(backend, OpenAIBackend)

    def test_flag_selects_ollama(self):
        backend = select_backend("ollama", {})
        assert isinstance(backend, OllamaBackend)

    def test_flag_selects_claude_code(self):
        backend = select_backend("claude-code", {})
        assert isinstance(backend, ClaudeCodeBackend)

    def test_config_used_when_no_flag(self):
        config = {"backend": "openai-api"}
        backend = select_backend(None, config)
        assert isinstance(backend, OpenAIBackend)

    def test_flag_overrides_config(self):
        """Flag must win over config, even when config says something different."""
        config = {"backend": "ollama"}
        backend = select_backend("anthropic-api", config)
        assert isinstance(backend, AnthropicAPIBackend)

    def test_config_model_passed_to_anthropic(self):
        config = {"backend": "anthropic-api", "model": "claude-opus-4-8"}
        backend = select_backend(None, config)
        assert isinstance(backend, AnthropicAPIBackend)
        assert backend.model == "claude-opus-4-8"

    def test_config_model_passed_to_openai(self):
        config = {"backend": "openai-api", "model": "gpt-4-turbo"}
        backend = select_backend(None, config)
        assert backend.model == "gpt-4-turbo"

    def test_config_model_passed_to_ollama(self):
        config = {"backend": "ollama", "model": "qwen2.5-coder"}
        backend = select_backend(None, config)
        assert isinstance(backend, OllamaBackend)
        assert backend.model == "qwen2.5-coder"

    def test_ollama_url_from_config(self):
        config = {"backend": "ollama", "ollama_url": "http://myserver:11434"}
        backend = select_backend(None, config)
        assert backend.base_url == "http://myserver:11434"

    def test_ollama_default_url(self):
        backend = select_backend("ollama", {})
        assert backend.base_url == "http://localhost:11434"

    def test_anthropic_default_model(self):
        backend = select_backend("anthropic-api", {})
        assert backend.model == AnthropicAPIBackend.DEFAULT_MODEL

    def test_openai_default_model(self):
        backend = select_backend("openai-api", {})
        assert backend.model == OpenAIBackend.DEFAULT_MODEL

    def test_ollama_default_model(self):
        backend = select_backend("ollama", {})
        assert backend.model == OllamaBackend.DEFAULT_MODEL

    def test_invalid_backend_exits(self):
        with pytest.raises(SystemExit):
            select_backend("nonexistent-llm", {})

    def test_invalid_backend_in_config_exits(self):
        with pytest.raises(SystemExit):
            select_backend(None, {"backend": "fake-backend"})

    def test_flag_none_with_empty_config_gives_claude_code(self):
        """Passing None flag and empty config must always land on claude-code."""
        backend = select_backend(None, {"model": "something"})
        assert isinstance(backend, ClaudeCodeBackend)


# ---------------------------------------------------------------------------
# load_config — writes example file on first run, never exposes keys
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_creates_example_on_first_run(self, tmp_path):
        cfg = tmp_path / "config.toml"
        with patch("secaudit._CONFIG_FILE", cfg):
            result = load_config()
        assert cfg.exists()
        assert result == {}  # example file has only comments + default

    def test_reads_existing_config(self, tmp_path):
        cfg = tmp_path / "config.toml"
        cfg.write_text('backend = "ollama"\nmodel = "llama3"\n')
        with patch("secaudit._CONFIG_FILE", cfg):
            result = load_config()
        assert result["backend"] == "ollama"
        assert result["model"] == "llama3"

    def test_api_key_never_stored_in_config(self, tmp_path):
        cfg = tmp_path / "config.toml"
        cfg.write_text('backend = "anthropic-api"\nmodel = "claude-sonnet-4-6"\n')
        with patch("secaudit._CONFIG_FILE", cfg):
            result = load_config()
        # config must not contain any key/token field
        for k in result:
            assert "key" not in k.lower()
            assert "token" not in k.lower()
            assert "secret" not in k.lower()


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
