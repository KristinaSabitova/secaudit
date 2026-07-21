"""Tests para domainaudit — solo lógica pura, sin llamadas de red reales."""
import json
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import domainaudit as da
from domainaudit import (
    Finding,
    HostReport,
    valid_domain,
    risk_score,
    to_dict,
    to_markdown,
    audit_email,
    audit_headers,
    audit_takeover,
    _all_findings,
)


# ---------------------------------------------------------------------------
# Validación de dominios
# ---------------------------------------------------------------------------

class TestValidDomain:
    def test_simple(self):
        assert valid_domain("ejemplo.com")

    def test_subdomain(self):
        assert valid_domain("api.staging.ejemplo.com")

    def test_trailing_dot_ok(self):
        assert valid_domain("ejemplo.com.")

    def test_rejects_no_tld(self):
        assert not valid_domain("localhost")

    def test_rejects_scheme(self):
        assert not valid_domain("https://ejemplo.com")

    def test_rejects_spaces(self):
        assert not valid_domain("ejemplo .com")

    def test_rejects_leading_hyphen(self):
        assert not valid_domain("-mal.com")

    def test_rejects_empty(self):
        assert not valid_domain("")


# ---------------------------------------------------------------------------
# Puntuación de riesgo
# ---------------------------------------------------------------------------

class TestRiskScore:
    def _rep_with(self, *sevs):
        r = HostReport(host="x.com")
        for s in sevs:
            r.add(s, "dns", "t", "d")
        return [r]

    def test_empty_is_zero(self):
        assert risk_score([HostReport(host="x.com")]) == 0

    def test_info_is_zero(self):
        assert risk_score(self._rep_with("info", "info")) == 0

    def test_critical_weight(self):
        assert risk_score(self._rep_with("critical")) == 40

    def test_saturates_at_100(self):
        assert risk_score(self._rep_with(*(["critical"] * 10))) == 100

    def test_mixed(self):
        # high(20) + medium(8) + low(2) = 30
        assert risk_score(self._rep_with("high", "medium", "low")) == 30


# ---------------------------------------------------------------------------
# Ordenación de hallazgos
# ---------------------------------------------------------------------------

class TestAllFindings:
    def test_sorted_by_severity(self):
        r = HostReport(host="x.com")
        r.add("low", "dns", "l", "d")
        r.add("critical", "tls", "c", "d")
        r.add("medium", "headers", "m", "d")
        out = _all_findings([r])
        assert [f.severity for f in out] == ["critical", "medium", "low"]


# ---------------------------------------------------------------------------
# Reportes
# ---------------------------------------------------------------------------

class TestReports:
    def _reports(self):
        r = HostReport(host="ejemplo.com", resolved=True, addresses=["1.2.3.4"])
        r.add("high", "tls", "Cert caducado", "detalle", "renueva")
        return [r]

    def test_to_dict_shape(self):
        d = to_dict("ejemplo.com", self._reports())
        assert d["domain"] == "ejemplo.com"
        assert d["risk_score"] == 20
        assert d["hosts"][0]["addresses"] == ["1.2.3.4"]
        assert d["hosts"][0]["findings"][0]["title"] == "Cert caducado"
        # serializable
        json.dumps(d)

    def test_markdown_contains_finding(self):
        md = to_markdown("ejemplo.com", self._reports())
        assert "Cert caducado" in md
        assert "renueva" in md
        assert "ejemplo.com" in md


# ---------------------------------------------------------------------------
# audit_email (DNS mockeado)
# ---------------------------------------------------------------------------

class TestAuditEmail:
    def _run(self, txt_map):
        """txt_map: dict[nombre -> lista de TXT]; MX simulado con clave '_mx'."""
        def fake_records(name, rtype):
            if rtype == "MX":
                return txt_map.get("_mx", [])
            if rtype == "TXT":
                return txt_map.get(name, [])
            return []
        rep = HostReport(host="ejemplo.com")
        with patch.object(da, "dns_records", side_effect=fake_records):
            audit_email(rep, "ejemplo.com")
        return rep.findings

    def test_no_spf_no_dmarc(self):
        fs = self._run({"_mx": ["10 mail.ejemplo.com"]})
        titles = [f.title for f in fs]
        assert any("SPF" in t for t in titles)
        assert any("DMARC" in t for t in titles)

    def test_permissive_spf_flagged_high(self):
        fs = self._run({
            "_mx": ["10 mail.ejemplo.com"],
            "ejemplo.com": ["v=spf1 include:_spf.google.com +all"],
        })
        spf = [f for f in fs if "SPF permisivo" in f.title]
        assert spf and spf[0].severity == "high"

    def test_good_spf_and_dmarc_no_finding(self):
        fs = self._run({
            "_mx": ["10 mail.ejemplo.com"],
            "ejemplo.com": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.ejemplo.com": ["v=DMARC1; p=reject; rua=mailto:d@ejemplo.com"],
            "default._domainkey.ejemplo.com": ["v=DKIM1; k=rsa; p=MIGf..."],
        })
        titles = [f.title for f in fs]
        assert not any("SPF" in t for t in titles)
        assert not any("DMARC" in t for t in titles)
        assert not any("DKIM" in t for t in titles)

    def test_dmarc_p_none_is_low(self):
        fs = self._run({
            "_mx": ["10 mail.ejemplo.com"],
            "ejemplo.com": ["v=spf1 -all"],
            "_dmarc.ejemplo.com": ["v=DMARC1; p=none"],
            "default._domainkey.ejemplo.com": ["v=DKIM1; p=abc"],
        })
        dmarc = [f for f in fs if "monitor" in f.title.lower()]
        assert dmarc and dmarc[0].severity == "low"


# ---------------------------------------------------------------------------
# audit_headers (HTTP mockeado)
# ---------------------------------------------------------------------------

class TestAuditHeaders:
    def _run(self, https_resp, http_resp=None):
        def fake_fetch(host, scheme, timeout=8.0):
            return https_resp if scheme == "https" else (http_resp or {})
        rep = HostReport(host="ejemplo.com")
        with patch.object(da, "fetch_http", side_effect=fake_fetch):
            audit_headers(rep)
        return rep.findings

    def test_missing_all_headers(self):
        fs = self._run({"status": 200, "headers": {}, "url": "https://ejemplo.com/"})
        titles = " ".join(f.title for f in fs)
        assert "strict-transport-security" in titles
        assert "content-security-policy" in titles

    def test_full_headers_clean(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        }
        fs = self._run({"status": 200, "headers": headers, "url": "https://ejemplo.com/"})
        assert not any(f.category == "headers" for f in fs)

    def test_leaky_server_header(self):
        headers = {"strict-transport-security": "max-age=1",
                   "content-security-policy": "x", "x-frame-options": "DENY",
                   "x-content-type-options": "nosniff", "referrer-policy": "x",
                   "permissions-policy": "x",
                   "server": "Apache/2.2.15"}
        fs = self._run({"status": 200, "headers": headers, "url": "https://ejemplo.com/"})
        leak = [f for f in fs if f.category == "exposure"]
        assert leak and "Apache/2.2.15" in leak[0].detail

    def test_insecure_cookie(self):
        headers = {"strict-transport-security": "max-age=1",
                   "content-security-policy": "x", "x-frame-options": "DENY",
                   "x-content-type-options": "nosniff", "referrer-policy": "x",
                   "permissions-policy": "x",
                   "set-cookie": "sessionid=abc; Path=/"}
        fs = self._run({"status": 200, "headers": headers, "url": "https://ejemplo.com/"})
        cookie = [f for f in fs if "Cookie" in f.title]
        assert cookie and cookie[0].severity == "medium"


# ---------------------------------------------------------------------------
# audit_takeover
# ---------------------------------------------------------------------------

class TestAuditTakeover:
    def test_dangling_cname_unresolved_is_high(self):
        def fake_records(name, rtype):
            return ["myapp.herokuapp.com"] if rtype == "CNAME" else []
        rep = HostReport(host="app.ejemplo.com")
        with patch.object(da, "dns_records", side_effect=fake_records), \
             patch.object(da, "resolve_host", return_value=[]):
            audit_takeover(rep, "app.ejemplo.com")
        assert rep.findings and rep.findings[0].severity == "high"
        assert "secuestro" in rep.findings[0].title.lower()

    def test_no_cname_no_finding(self):
        with patch.object(da, "dns_records", return_value=[]):
            rep = HostReport(host="app.ejemplo.com")
            audit_takeover(rep, "app.ejemplo.com")
        assert not rep.findings

    def test_cname_to_unknown_service_ignored(self):
        def fake_records(name, rtype):
            return ["cdn.otrositio.com"] if rtype == "CNAME" else []
        rep = HostReport(host="app.ejemplo.com")
        with patch.object(da, "dns_records", side_effect=fake_records), \
             patch.object(da, "resolve_host", return_value=[]):
            audit_takeover(rep, "app.ejemplo.com")
        assert not rep.findings
