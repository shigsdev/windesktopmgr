"""
test_bsod_parsing.py
Tests for BSOD event parsing, health-report parsing, and recommendation building.
"""

import os
import pytest
import windesktopmgr as wdm


# ══════════════════════════════════════════════════════════════════════════════
# parse_event(evt)
# ══════════════════════════════════════════════════════════════════════════════

class TestParseEvent:
    # ── Event ID 1001 (Windows Error Reporting / BugCheck) ──────────────────

    def test_1001_known_stop_code_name(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "The computer has rebooted from a bugcheck. The bugcheck was: 0x00020001.",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["error_code"] == "HYPERVISOR_ERROR"
        assert result["stop_code"] == "0x00020001"

    def test_1001_unknown_code_gets_fallback_name(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "bugcheck was: 0xdeadbeef",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert "BUGCHECK_" in result["error_code"]

    def test_1001_faulty_driver_extracted(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "bugcheck was: 0x00020001. ntoskrnl.sys caused the crash.",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["faulty_driver"] == "ntoskrnl.sys"

    def test_1001_no_faulty_driver_when_absent(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "bugcheck was: 0x00020001. No driver info here.",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["faulty_driver"] is None

    def test_1001_missing_bugcheck_line_returns_none(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "The computer restarted unexpectedly.",
        }
        assert wdm.parse_event(evt) is None

    def test_1001_short_code_normalised(self):
        # 0x9f should be normalised to 0x0000009f → DRIVER_POWER_STATE_FAILURE
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "bugcheck was: 0x9f",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["error_code"] == "DRIVER_POWER_STATE_FAILURE"
        assert result["stop_code"] == "0x0000009f"

    def test_1001_source_and_event_id_fields(self):
        evt = {
            "EventId": 1001,
            "TimeCreated": "2026-03-01T10:00:00+00:00",
            "Message": "bugcheck was: 0x00000139",
        }
        result = wdm.parse_event(evt)
        assert result["source"] == "event_log"
        assert result["event_id"] == 1001

    # ── Event ID 41 (Kernel Power) ───────────────────────────────────────────

    def test_41_kernel_power_loss(self):
        evt = {
            "EventId": 41,
            "TimeCreated": "2026-03-02T12:00:00+00:00",
            "Message": "The system has rebooted without cleanly shutting down first.",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["error_code"] == "KERNEL_POWER_LOSS"
        assert result["faulty_driver"] is None
        assert result["stop_code"] is None

    # ── Event ID 6008 (Unexpected Shutdown) ─────────────────────────────────

    def test_6008_unexpected_shutdown(self):
        evt = {
            "EventId": 6008,
            "TimeCreated": "2026-03-03T09:15:00+00:00",
            "Message": "The previous system shutdown was unexpected.",
        }
        result = wdm.parse_event(evt)
        assert result is not None
        assert result["error_code"] == "UNEXPECTED_SHUTDOWN"
        assert result["faulty_driver"] is None

    # ── Unknown Event ID ────────────────────────────────────────────────────

    def test_unknown_event_id_returns_none(self):
        evt = {
            "EventId": 9999,
            "TimeCreated": "2026-03-04T08:00:00+00:00",
            "Message": "Some unrelated event.",
        }
        assert wdm.parse_event(evt) is None

    def test_empty_event_returns_none(self):
        assert wdm.parse_event({}) is None


# ══════════════════════════════════════════════════════════════════════════════
# parse_report_crashes(report_path)
# ══════════════════════════════════════════════════════════════════════════════

class TestParseReportCrashes:
    def _write_report(self, tmp_path, filename, content):
        p = tmp_path / filename
        p.write_text(content, encoding="utf-8")
        return str(p)

    def test_known_error_code_extracted(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html><body>HYPERVISOR_ERROR occurred today</body></html>",
        )
        results = wdm.parse_report_crashes(path)
        assert len(results) == 1
        assert results[0]["error_code"] == "HYPERVISOR_ERROR"

    def test_timestamp_from_filename(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html>HYPERVISOR_ERROR</html>",
        )
        results = wdm.parse_report_crashes(path)
        assert results[0]["timestamp"] == "2026-03-15T10:00:00"

    def test_stop_code_extracted(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html>HYPERVISOR_ERROR code 0x00020001</html>",
        )
        results = wdm.parse_report_crashes(path)
        assert results[0]["stop_code"] == "0x00020001"

    def test_faulty_driver_from_sys_file(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html>HYPERVISOR_ERROR intelppm.sys intelppm.sys ntoskrnl.exe</html>",
        )
        results = wdm.parse_report_crashes(path)
        # intelppm.sys appears twice → most common
        assert results[0]["faulty_driver"] == "intelppm.sys"

    def test_no_timestamp_in_filename_returns_empty(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "no_timestamp_report.html",
            "<html>HYPERVISOR_ERROR</html>",
        )
        results = wdm.parse_report_crashes(path)
        assert results == []

    def test_no_error_codes_returns_empty(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html>All systems normal today.</html>",
        )
        results = wdm.parse_report_crashes(path)
        assert results == []

    def test_nonexistent_file_returns_empty(self, tmp_path):
        results = wdm.parse_report_crashes(str(tmp_path / "missing.html"))
        assert results == []

    def test_source_field_is_health_report(self, tmp_path):
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_20260315_100000.html",
            "<html>HYPERVISOR_ERROR</html>",
        )
        results = wdm.parse_report_crashes(path)
        assert results[0]["source"] == "health_report"

    def test_new_format_timestamp(self, tmp_path):
        # Format: YYYY-MM-DD_HH-MM-SS
        path = self._write_report(
            tmp_path,
            "SystemHealthReport_2026-03-15_10-00-00.html",
            "<html>HYPERVISOR_ERROR</html>",
        )
        # This format is handled by get_health_report_history, not parse_report_crashes
        # parse_report_crashes only handles YYYYMMDD_HHMMSS — confirm graceful handling
        results = wdm.parse_report_crashes(path)
        # No YYYYMMDD_HHMMSS match → empty (no crash added without timestamp)
        assert isinstance(results, list)


# ══════════════════════════════════════════════════════════════════════════════
# build_recommendations(crashes)
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildRecommendations:
    def test_zero_crashes_system_stable(self):
        recs = wdm.build_recommendations([])
        assert len(recs) == 1
        assert recs[0]["priority"] == "info"
        assert "stable" in recs[0]["title"].lower()

    def test_more_than_ten_crashes_critical_rec(self):
        crashes = [
            {"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"}
        ] * 12
        recs = wdm.build_recommendations(crashes)
        priorities = [r["priority"] for r in recs]
        assert "critical" in priorities

    def test_three_to_ten_crashes_high_rec(self):
        crashes = [
            {"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"}
        ] * 5
        recs = wdm.build_recommendations(crashes)
        # Should have a "Recurring crashes" or "High crash frequency" rec
        titles = " ".join(r["title"] for r in recs)
        assert "crash" in titles.lower()

    def test_hypervisor_error_gets_dedicated_rec(self):
        crashes = [{"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"}]
        recs = wdm.build_recommendations(crashes)
        titles = [r["title"] for r in recs]
        assert any("14900K" in t or "i9" in t or "microcode" in t.lower() for t in titles)

    def test_deduplication_no_duplicate_titles(self):
        crashes = [
            {"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"},
        ] * 15  # triggers both > 10 and HYPERVISOR_ERROR recs
        recs = wdm.build_recommendations(crashes)
        titles = [r["title"] for r in recs]
        assert len(titles) == len(set(titles)), "Duplicate recommendation titles found"

    def test_sorted_critical_before_high_before_info(self):
        crashes = [
            {"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"}
        ] * 12
        recs = wdm.build_recommendations(crashes)
        order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        priorities = [order.get(r.get("priority", "info"), 3) for r in recs]
        assert priorities == sorted(priorities), "Recommendations not sorted by priority"

    def test_static_kb_source_for_known_code(self):
        crashes = [{"error_code": "HYPERVISOR_ERROR", "faulty_driver": "intelppm.sys"}]
        recs = wdm.build_recommendations(crashes)
        # The HYPERVISOR_ERROR rec should come from static_kb
        static_recs = [r for r in recs if r.get("source") == "static_kb"]
        assert len(static_recs) > 0
