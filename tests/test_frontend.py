"""The interface: what it ships, what the CSP lets it do, and how it reads."""
import os
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

STATIC = Path(__file__).resolve().parent.parent / "web" / "static"
HTML = (STATIC / "index.html").read_text()
JS = (STATIC / "app.js").read_text()
CSS = (STATIC / "style.css").read_text()

FONTS = ["ibm-plex-sans-400", "ibm-plex-sans-500", "ibm-plex-sans-600",
         "ibm-plex-mono-400", "ibm-plex-mono-500"]


@pytest.fixture(scope="module")
def client():
    """Static files only: nothing here touches the database."""
    from web.main import app
    return TestClient(app)


class TestWhatIsServed:
    def test_the_theme_script_is_served(self, client):
        r = client.get("/theme.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]

    @pytest.mark.parametrize("name", FONTS)
    def test_each_font_is_served_from_here(self, client, name):
        r = client.get(f"/fonts/{name}.woff2")
        assert r.status_code == 200
        assert r.content[:4] == b"wOF2"
        assert f'url("/fonts/{name}.woff2")' in CSS

    def test_the_font_licences_ship_with_them(self):
        for family in ("ibm-plex-sans", "ibm-plex-mono"):
            text = (STATIC / "fonts" / f"LICENSE-{family}.txt").read_text()
            assert "SIL Open Font License" in text


class TestWhatTheCSPAllows:
    """script-src 'self': no inline script, no handler attributes."""

    def test_no_inline_script(self):
        for tag in re.findall(r"<script\b[^>]*>", HTML):
            assert "src=" in tag, tag
        assert not re.search(r"<script\b[^>]*>\s*(?!</script>)\S", HTML)

    def test_no_inline_event_handlers(self):
        assert not re.search(r"\son[a-z]+\s*=", HTML)

    def test_the_theme_is_set_before_the_stylesheet_paints(self):
        head = HTML.split("</head>")[0]
        assert head.index('src="/theme.js"') < head.index('href="/style.css"')

    def test_the_page_is_never_built_from_markup(self):
        """What it shows comes from audited repositories."""
        code = re.sub(r"^\s*//.*$", "", JS, flags=re.M)
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            assert sink not in code, sink


def tokens(selector):
    match = re.search(re.escape(selector) + r"[^{]*\{([^}]*)\}", CSS)
    assert match, selector
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})", match.group(1)))


def luminance(hex_colour):
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    channels = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
                for c in channels]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


TEXT_TOKENS = ["text", "muted", "accent", "error", "sev-critical", "sev-high",
               "sev-medium", "sev-low", "sev-info", "ok", "warn"]
BACKGROUNDS = ["surface", "panel", "panel-2", "selected"]


class TestThemes:
    @pytest.fixture(params=['[data-theme="light"]', '[data-theme="dark"]'])
    def theme(self, request):
        return tokens(":root" + request.param)

    def test_the_draft_tokens_are_kept(self):
        dark, light = tokens(':root[data-theme="dark"]'), tokens(':root[data-theme="light"]')
        assert (dark["surface"], dark["panel"], dark["text"], dark["muted"],
                dark["accent"], dark["annotation"]) == (
            "#16222B", "#1E2E39", "#D8E2E8", "#8A9BA6", "#5FB3C9", "#E8C35A")
        assert (light["surface"], light["panel"], light["text"], light["muted"],
                light["annotation"]) == (
            "#EEF3F6", "#FFFFFF", "#1B2A33", "#5E707B", "#A87A00")

    def test_every_text_colour_meets_aa_on_every_background(self, theme):
        for fg in TEXT_TOKENS:
            for bg in BACKGROUNDS:
                ratio = contrast(theme[fg], theme[bg])
                assert ratio >= 4.5, f"--{fg} on --{bg}: {ratio:.2f}"

    def test_buttons_are_readable(self, theme):
        assert contrast(theme["on-accent"], theme["accent"]) >= 4.5

    def test_annotations_stand_out_from_the_code_they_mark(self, theme):
        """Marks, not text: the non-text bar of 3:1."""
        for bg in BACKGROUNDS:
            assert contrast(theme["annotation"], theme[bg]) >= 3

    def test_both_themes_define_the_same_tokens(self):
        assert set(tokens(':root[data-theme="dark"]')) == set(
            tokens(':root[data-theme="light"]'))

    def test_without_script_the_system_preference_gets_the_dark_tokens(self):
        fallback = re.search(r"prefers-color-scheme:\s*dark\)\s*\{\s*:root:not\(\[data-theme\]\)"
                             r"\s*\{([^}]*)\}", CSS)
        assert fallback
        assert dict(re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})",
                               fallback.group(1))) == tokens(':root[data-theme="dark"]')

    def test_reduced_motion_is_respected(self):
        assert re.search(r"prefers-reduced-motion:\s*reduce", CSS)

    def test_the_toggle_has_a_label_in_both_languages(self):
        for language in ("en", "es"):
            assert {"theme.todark", "theme.tolight"} <= language_keys(language)
        assert "Cambiar a modo claro" in JS and "Cambiar a modo oscuro" in JS


def language_keys(language):
    body = JS.split(f"\n  {language}: {{")[1].split("\n  },")[0]
    return set(re.findall(r'^\s+"([\w.]+)":', body, re.M))


class TestStructure:
    SECTIONS = ["summary", "findings", "parallax", "falsifiability", "memory",
                "leverage", "attacker", "history", "settings"]

    def test_every_section_has_a_link_and_a_view(self):
        for section in self.SECTIONS:
            assert f'data-section="{section}"' in HTML, section
            assert f'data-view="{section}"' in HTML, section

    def test_every_element_the_script_uses_exists(self):
        used = set(re.findall(r'el\("([\w-]+)"\)', JS))
        present = set(re.findall(r'\bid="([\w-]+)"', HTML))
        assert used <= present, used - present

    def test_every_text_is_in_both_languages(self):
        en, es = language_keys("en"), language_keys("es")
        assert en == es, en ^ es
        in_page = set(re.findall(r'data-i18n(?:-placeholder|-label)?="([\w.]+)"', HTML))
        assert in_page <= en, in_page - en
