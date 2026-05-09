"""Tests for report.py -- on-demand system health report generator (#15)."""

import json

import pytest

# ── PII redaction ────────────────────────────────────────────────────────────


class TestRedactPii:
    """The redactor MUST default to over-redacting -- the cost of leaking a
    service tag in a public support post is real; the cost of false-positive
    redaction in the user's personal record is one toggle click."""

    def test_redacts_mac_address(self):
        from report import _redact_pii

        out = _redact_pii("device 88:DE:7C:C2:57:36 is online")
        assert "88:DE:7C" not in out
        assert "[redacted-mac]" in out

    def test_redacts_mac_with_hyphens(self):
        from report import _redact_pii

        out = _redact_pii("MAC: 88-DE-7C-C2-57-36")
        assert "[redacted-mac]" in out

    def test_redacts_lan_ipv4(self):
        from report import _redact_pii

        out = _redact_pii("Router at 192.168.1.1 is up")
        assert "192.168.1.1" not in out
        assert "[redacted-ip]" in out

    def test_redacts_public_ipv4(self):
        from report import _redact_pii

        out = _redact_pii("WAN address 98.109.66.15")
        assert "98.109.66.15" not in out

    def test_keeps_loopback_and_zero(self):
        """0.0.0.0 and 127.0.0.1 are placeholders / not PII -- preserve so
        the report stays readable for those common diagnostic strings."""
        from report import _redact_pii

        out = _redact_pii("listening on 0.0.0.0:5000, loopback 127.0.0.1")
        assert "0.0.0.0" in out
        assert "127.0.0.1" in out

    def test_redacts_ipv6(self):
        from report import _redact_pii

        out = _redact_pii("WAN6 fe80::7a67:eff:febd:a43e")
        assert "fe80::" not in out
        assert "[redacted-ipv6]" in out

    def test_redacts_email(self):
        from report import _redact_pii

        out = _redact_pii("contact higs78@example.com about this")
        assert "higs78@example.com" not in out
        assert "[redacted-email]" in out

    def test_redacts_hostname_when_supplied(self):
        from report import _redact_pii

        out = _redact_pii("computer DESKTOP-XYZ123 is healthy", hostname="DESKTOP-XYZ123")
        assert "DESKTOP-XYZ123" not in out
        assert "[redacted-hostname]" in out

    def test_hostname_redaction_case_insensitive(self):
        from report import _redact_pii

        out = _redact_pii("see host desktop-xyz123 logs", hostname="DESKTOP-XYZ123")
        assert "desktop-xyz123" not in out

    def test_redacts_service_tag_when_supplied(self):
        from report import _redact_pii

        out = _redact_pii("Service tag: 9T46D14", service_tag="9T46D14")
        assert "9T46D14" not in out
        assert "[redacted-servicetag]" in out

    def test_short_hostname_not_redacted_to_avoid_overmatch(self):
        """A 1-2 char hostname would replace every occurrence of those
        characters. Skip the exact-match pass below a length threshold."""
        from report import _redact_pii

        out = _redact_pii("DC is the domain controller", hostname="DC")
        # "DC" must remain (not exact-redacted to placeholder)
        assert "DC" in out

    def test_empty_input_returns_empty(self):
        from report import _redact_pii

        assert _redact_pii("") == ""
        assert _redact_pii(None) is None


# ── Markdown renderer ────────────────────────────────────────────────────────


class TestRenderMarkdown:
    def test_includes_header_and_metadata(self):
        from report import render_markdown

        md = render_markdown({"generated_at": "2026-05-09T00:00:00Z", "scope": "full"})
        assert "WinDesktopMgr System Health Report" in md
        assert "**Generated:**" in md
        assert "2026-05-09" in md
        assert "**Scope:**" in md

    def test_renders_overall_status_section(self):
        from report import render_markdown

        md = render_markdown({"summary": {"overall": "critical", "concerns": []}})
        assert "## Overall Status" in md
        assert "CRITICAL" in md
        assert "**Concerns:** none" in md

    def test_renders_concerns_sorted_critical_first(self):
        """A warning-then-critical input must render with critical first."""
        from report import render_markdown

        md = render_markdown(
            {
                "summary": {
                    "overall": "critical",
                    "concerns": [
                        {"level": "warning", "title": "RAM pressure", "detail": "78%"},
                        {"level": "critical", "title": "BSOD detected", "detail": "kernel"},
                        {"level": "info", "title": "Old drivers", "detail": "18"},
                    ],
                }
            }
        )
        # Critical must appear before warning, which must appear before info
        crit_pos = md.find("BSOD detected")
        warn_pos = md.find("RAM pressure")
        info_pos = md.find("Old drivers")
        assert 0 <= crit_pos < warn_pos < info_pos

    def test_concern_breakdown_in_summary(self):
        from report import render_markdown

        md = render_markdown(
            {
                "summary": {
                    "overall": "warning",
                    "concerns": [
                        {"level": "critical", "title": "X"},
                        {"level": "critical", "title": "Y"},
                        {"level": "warning", "title": "Z"},
                    ],
                }
            }
        )
        assert "**Concerns:**" in md
        assert "2 critical" in md
        assert "1 warning" in md

    def test_renders_bsod_section(self):
        from report import render_markdown

        md = render_markdown(
            {
                "bsod": [
                    {
                        "Timestamp": "2026-05-01T03:14:00",
                        "BugCheckCode": "0x0000007E",
                        "FaultingModule": "intelppm.sys",
                    },
                ]
            }
        )
        assert "## Recent BSODs (1)" in md
        assert "0x0000007E" in md
        assert "intelppm.sys" in md

    def test_caps_bsod_list_at_10_with_ellipsis_note(self):
        """A system with hundreds of BSODs shouldn't bloat the report --
        cap at 10 + show how many were truncated."""
        from report import render_markdown

        bsods = [{"Timestamp": f"2026-05-0{i % 9 + 1}", "BugCheckCode": f"0x{i:08X}"} for i in range(15)]
        md = render_markdown({"bsod": bsods})
        assert "## Recent BSODs (15)" in md
        # 10 should be rendered, and the "_… and 5 more_" footer should appear
        assert "_… and 5 more_" in md

    def test_no_concerns_section_when_empty(self):
        from report import render_markdown

        md = render_markdown({"summary": {"overall": "ok", "concerns": []}})
        assert "## Active Concerns" not in md


# ── HTML renderer ────────────────────────────────────────────────────────────


class TestRenderHtml:
    def test_returns_complete_html_document(self):
        from report import render_html

        out = render_html({"summary": {"overall": "ok", "concerns": []}})
        assert "<!DOCTYPE html>" in out
        assert "<html" in out
        assert "</html>" in out
        assert "<title>" in out

    def test_converts_h1_h2_h3(self):
        from report import render_html

        out = render_html(
            {"summary": {"overall": "ok", "concerns": [{"level": "critical", "title": "X", "detail": "Y"}]}}
        )
        assert "<h1>WinDesktopMgr System Health Report</h1>" in out
        assert "<h2>" in out
        assert "<h3>" in out

    def test_converts_bullets_to_ul_li(self):
        from report import render_html

        out = render_html(
            {
                "bios": {
                    "manufacturer": "Dell Inc.",
                    "product": "XPS 8960",
                    "bios_version": "2.22.0",
                }
            }
        )
        assert "<ul>" in out
        assert "<li>" in out
        assert "</ul>" in out

    def test_escapes_html_in_user_text(self):
        """Concern titles / details might contain < > & -- must be escaped
        so they render as text, not as HTML tags."""
        from report import render_html

        out = render_html(
            {
                "summary": {
                    "overall": "warning",
                    "concerns": [{"level": "warning", "title": "<script>alert(1)</script>", "detail": "<b>x</b>"}],
                }
            }
        )
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_includes_inline_css_for_standalone_render(self):
        """Opening the report in a fresh browser tab shouldn't depend on
        the dashboard's CSS. Inline <style> must be present."""
        from report import render_html

        out = render_html({"summary": {"overall": "ok", "concerns": []}})
        assert "<style>" in out
        assert "font-family" in out


# ── JSON renderer ────────────────────────────────────────────────────────────


class TestRenderJson:
    def test_is_valid_json(self):
        from report import render_json

        text = render_json({"summary": {"overall": "ok"}})
        parsed = json.loads(text)
        assert parsed["summary"]["overall"] == "ok"

    def test_pretty_printed_with_indent(self):
        from report import render_json

        text = render_json({"a": 1, "b": 2})
        # Pretty-printed (multi-line) means at least one newline + indent
        assert "\n" in text
        assert "  " in text

    def test_keys_sorted(self):
        """Sorted keys → diff-friendly output across runs."""
        from report import render_json

        text = render_json({"z": 1, "a": 2, "m": 3})
        a_pos = text.find('"a"')
        m_pos = text.find('"m"')
        z_pos = text.find('"z"')
        assert 0 <= a_pos < m_pos < z_pos


# ── generate_report public entry point ───────────────────────────────────────


class TestGenerateReport:
    """Public entry point validation. The ``_collect_report_data`` helper
    is monkey-patched so these tests don't drive the real WMI/dashboard
    fan-out -- they exercise the validation + format dispatch + redaction."""

    @staticmethod
    def _stub_data():
        return {
            "generated_at": "2026-05-09T00:00:00Z",
            "scope": "full",
            "summary": {
                "overall": "warning",
                "concerns": [
                    {"level": "warning", "title": "Old drivers", "detail": "18 found"},
                ],
            },
            "bios": {"manufacturer": "Dell Inc.", "serial_number": "9T46D14", "hostname": "MYDESKTOP"},
            "bsod": [],
        }

    def test_unknown_format_raises(self):
        from report import generate_report

        with pytest.raises(ValueError, match="format"):
            generate_report(fmt="excel")

    def test_unknown_scope_raises(self):
        from report import generate_report

        with pytest.raises(ValueError, match="scope"):
            generate_report(scope="kitchen-sink")

    def test_markdown_format_returns_text_markdown_mime(self, mocker):
        mocker.patch("report._collect_report_data", return_value=self._stub_data())
        from report import generate_report

        content, mime = generate_report(scope="full", fmt="markdown", redact_pii=False)
        assert "text/markdown" in mime
        assert "WinDesktopMgr" in content

    def test_html_format_returns_text_html_mime(self, mocker):
        mocker.patch("report._collect_report_data", return_value=self._stub_data())
        from report import generate_report

        content, mime = generate_report(scope="full", fmt="html", redact_pii=False)
        assert "text/html" in mime
        assert "<!DOCTYPE html>" in content

    def test_json_format_returns_application_json_mime(self, mocker):
        mocker.patch("report._collect_report_data", return_value=self._stub_data())
        from report import generate_report

        content, mime = generate_report(scope="full", fmt="json", redact_pii=False)
        assert mime == "application/json"
        json.loads(content)  # raises if not valid JSON

    def test_redact_pii_true_strips_service_tag_from_output(self, mocker):
        """End-to-end: BIOS service tag in the input data -> redacted in
        the rendered output."""
        mocker.patch("report._collect_report_data", return_value=self._stub_data())
        from report import generate_report

        content, _ = generate_report(scope="full", fmt="markdown", redact_pii=True)
        # The stub's service_tag is 9T46D14 and hostname is MYDESKTOP --
        # both should be gone after redaction.
        assert "9T46D14" not in content
        assert "MYDESKTOP" not in content

    def test_redact_pii_false_keeps_identifiers(self, mocker):
        """Default-OFF behaviour preserves PII for personal-record exports."""
        mocker.patch("report._collect_report_data", return_value=self._stub_data())
        from report import generate_report

        # Drive the data so it's actually printed in the markdown body
        # (the default markdown renderer prints serial_number under
        # System / BIOS section -- check the field WAS preserved when
        # redact is off).
        content, _ = generate_report(scope="full", fmt="markdown", redact_pii=False)
        # Service tag is in bios.serial_number -- the markdown renderer
        # iterates known BIOS fields. Confirm the redactor didn't fire.
        # (The renderer may not print the literal "9T46D14" unless that
        # field is in the iteration list; the more reliable assertion is
        # that no [redacted-*] placeholder appears.)
        assert "[redacted-" not in content


# ── Flask route /api/report/export ───────────────────────────────────────────


class TestReportExportRoute:
    def test_default_call_returns_markdown(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={"summary": {"overall": "ok", "concerns": []}, "bios": {}, "bsod": []},
        )
        r = client.get("/api/report/export")
        assert r.status_code == 200
        assert "text/markdown" in r.headers.get("Content-Type", "")
        assert b"WinDesktopMgr" in r.data

    def test_format_html_returns_html(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={"summary": {"overall": "ok", "concerns": []}, "bios": {}, "bsod": []},
        )
        r = client.get("/api/report/export?format=html")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")
        assert b"<!DOCTYPE html>" in r.data

    def test_format_json_returns_json(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={"summary": {"overall": "ok", "concerns": []}, "bios": {}, "bsod": []},
        )
        r = client.get("/api/report/export?format=json")
        assert r.status_code == 200
        assert "application/json" in r.headers.get("Content-Type", "")
        json.loads(r.data)

    def test_invalid_format_returns_400(self, client):
        r = client.get("/api/report/export?format=excel")
        assert r.status_code == 400
        body = r.get_json()
        assert body["ok"] is False
        assert "format" in body["error"].lower()

    def test_invalid_scope_returns_400(self, client):
        r = client.get("/api/report/export?scope=kitchen-sink")
        assert r.status_code == 400

    def test_attachment_param_sets_content_disposition(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={"summary": {"overall": "ok", "concerns": []}, "bios": {}, "bsod": []},
        )
        r = client.get("/api/report/export?attachment=1")
        assert "Content-Disposition" in r.headers
        assert "attachment" in r.headers["Content-Disposition"]
        assert "windesktopmgr_report_" in r.headers["Content-Disposition"]
        assert r.headers["Content-Disposition"].endswith('.md"')

    def test_no_attachment_serves_inline(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={"summary": {"overall": "ok", "concerns": []}, "bios": {}, "bsod": []},
        )
        r = client.get("/api/report/export")
        assert "Content-Disposition" not in r.headers

    def test_redact_pii_default_on(self, client, mocker):
        """No explicit redact_pii param → default ON (the conservative choice)."""
        mocker.patch(
            "report._collect_report_data",
            return_value={
                "summary": {"overall": "ok", "concerns": []},
                "bios": {"manufacturer": "Dell", "serial_number": "ABC1234", "hostname": "MYHOST"},
                "bsod": [{"Timestamp": "2026-05-01", "BugCheckCode": "192.168.1.1"}],
            },
        )
        r = client.get("/api/report/export")
        # The IP-shaped string in the bsod data must be redacted by default
        assert b"192.168.1.1" not in r.data
        assert b"[redacted-ip]" in r.data

    def test_redact_pii_explicit_off_keeps_identifiers(self, client, mocker):
        mocker.patch(
            "report._collect_report_data",
            return_value={
                "summary": {"overall": "ok", "concerns": []},
                "bios": {},
                "bsod": [{"Timestamp": "2026-05-01", "BugCheckCode": "192.168.1.1"}],
            },
        )
        r = client.get("/api/report/export?redact_pii=0")
        assert b"192.168.1.1" in r.data
        assert b"[redacted-ip]" not in r.data

    def test_collector_failure_returns_500_with_json_body(self, client, mocker):
        """If _collect_report_data raises, the route must return 500 with
        a clean JSON error body, not crash with a stack trace."""
        mocker.patch("report._collect_report_data", side_effect=RuntimeError("WMI exploded"))
        r = client.get("/api/report/export")
        assert r.status_code == 500
        body = r.get_json()
        assert body["ok"] is False
        assert "WMI exploded" in body["error"]
