"""tests/test_task_watcher.py -- tests for scheduled-task health observer.

All file I/O is tmp_path-based and all schtasks calls are mocked so nothing
touches the real filesystem or Windows Task Scheduler.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import task_watcher

# ── Helpers ────────────────────────────────────────────────────────


SUCCESS_BODY = """[1/13] Checking Intel CPU Microcode...
  passed
[13/13] Running unit tests...
  passed
Report saved to: C:\\shigsapps\\windesktopmgr\\System Health Reports\\Report_2026-04-18.html
"""

FAILURE_BODY = """[1/13] Checking Intel CPU Microcode...
  passed
Traceback (most recent call last):
  File "SystemHealthDiag.py", line 1865, in main
    cprint(f"  \u2717 failures", "red")
UnicodeEncodeError: 'charmap' codec can't encode character '\\u2717' in position 2: character maps to <undefined>
"""


def _write_log(dir_path, name: str, body: str, *, utf16: bool = False) -> str:
    """Create a log file with the given body; return its path.

    utf16=True mimics the legacy PowerShell Tee-Object pipeline (UTF-16 LE
    with BOM). utf16=False is the new wrapper's UTF-8 default.
    """
    p = dir_path / name
    if utf16:
        p.write_bytes(b"\xff\xfe" + body.encode("utf-16-le"))
    else:
        p.write_text(body, encoding="utf-8")
    return str(p)


# ── Log parsing ────────────────────────────────────────────────────


class TestParseLog:
    def test_success_marked_ok(self, tmp_path):
        path = _write_log(tmp_path, "SystemHealthDiag_2026-04-18_07-00-00.log", SUCCESS_BODY)
        s = task_watcher.parse_log(path)
        assert s.ok is True
        assert s.exception_signature is None
        assert s.timestamp == datetime(2026, 4, 18, 7, 0, 0)

    def test_failure_marked_not_ok(self, tmp_path):
        path = _write_log(tmp_path, "SystemHealthDiag_2026-04-18_08-00-00.log", FAILURE_BODY)
        s = task_watcher.parse_log(path)
        assert s.ok is False
        assert s.exception_signature == "UnicodeEncodeError"

    def test_utf16_le_with_bom_is_decoded(self, tmp_path):
        path = _write_log(
            tmp_path,
            "SystemHealthDiag_2026-04-18_09-00-00.log",
            FAILURE_BODY,
            utf16=True,
        )
        s = task_watcher.parse_log(path)
        assert s.ok is False
        assert s.exception_signature == "UnicodeEncodeError"

    def test_unparseable_timestamp_is_none_not_error(self, tmp_path):
        path = _write_log(tmp_path, "SystemHealthDiag_nodatenotime.log", SUCCESS_BODY)
        s = task_watcher.parse_log(path)
        assert s.timestamp is None
        assert s.ok is True

    def test_missing_file_returns_empty(self, tmp_path):
        s = task_watcher.parse_log(str(tmp_path / "doesnotexist.log"))
        # Not found -> no tail content -> no error markers -> ok=True
        # This is acceptable: a missing log doesn't indicate a failed run.
        assert s.ok is True
        assert s.size_bytes == 0


# ── Aggregation ────────────────────────────────────────────────────


class TestAnalyzeTaskLogs:
    def test_no_logs_marks_inactive(self, tmp_path):
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_")
        assert r["log_count"] == 0
        assert r["inactive"] is True
        assert r["success_stale"] is True
        assert r["crashloop_detected"] is False

    def test_single_recent_success_is_healthy(self, tmp_path):
        now = datetime.now()
        stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        _write_log(tmp_path, f"SystemHealthDiag_{stamp}.log", SUCCESS_BODY)
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_", now=now)
        assert r["runs_in_24h"] == 1
        assert r["failures_in_24h"] == 0
        assert r["crashloop_detected"] is False
        assert r["success_stale"] is False
        assert r["inactive"] is False

    def test_three_recent_failures_flags_crashloop(self, tmp_path):
        now = datetime.now()
        for i in range(3):
            stamp = (now - timedelta(minutes=i * 10)).strftime("%Y-%m-%d_%H-%M-%S")
            _write_log(tmp_path, f"SystemHealthDiag_{stamp}.log", FAILURE_BODY)
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_", now=now)
        assert r["failures_in_24h"] == 3
        assert r["crashloop_detected"] is True
        assert r["dominant_exception"] == "UnicodeEncodeError"

    def test_two_failures_not_enough_for_crashloop(self, tmp_path):
        now = datetime.now()
        for i in range(2):
            stamp = (now - timedelta(minutes=i * 10)).strftime("%Y-%m-%d_%H-%M-%S")
            _write_log(tmp_path, f"SystemHealthDiag_{stamp}.log", FAILURE_BODY)
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_", now=now)
        assert r["crashloop_detected"] is False

    def test_stale_success_flags_success_stale(self, tmp_path):
        now = datetime.now()
        old = (now - timedelta(hours=72)).strftime("%Y-%m-%d_%H-%M-%S")
        _write_log(tmp_path, f"SystemHealthDiag_{old}.log", SUCCESS_BODY)
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_", now=now)
        assert r["success_stale"] is True
        assert r["inactive"] is True

    def test_recent_logs_slice_newest_first(self, tmp_path):
        now = datetime.now()
        for i in range(12):
            stamp = (now - timedelta(hours=i)).strftime("%Y-%m-%d_%H-%M-%S")
            body = SUCCESS_BODY if i % 2 == 0 else FAILURE_BODY
            _write_log(tmp_path, f"SystemHealthDiag_{stamp}.log", body)
        r = task_watcher.analyze_task_logs(str(tmp_path), "SystemHealthDiag_", now=now)
        assert len(r["recent_logs"]) == 10
        # newest first
        ts_list = [e["timestamp"] for e in r["recent_logs"]]
        assert ts_list == sorted(ts_list, reverse=True)


# ── schtasks ──────────────────────────────────────────────────────


class TestGetSchtaskInfo:
    _CSV_OK = (
        '"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours And X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"\n'
        '"MYPC","SystemHealthDiagnostic","4/19/2026 6:00:00 AM","Ready","Interactive/Background","4/18/2026 6:00:00 AM","0","user","powershell.exe ...","","","Enabled","","","user","Disabled","","","Daily","6:00:00 AM","3/15/2026","N/A","Every 1 day(s)","","","","",""\n'
    )

    def test_registered_task_parsed(self, mocker):
        mock = mocker.MagicMock()
        mock.returncode = 0
        mock.stdout = self._CSV_OK
        mock.stderr = ""
        mocker.patch("task_watcher.subprocess.run", return_value=mock)
        info = task_watcher.get_schtask_info("SystemHealthDiagnostic")
        assert info["registered"] is True
        assert info["last_result"] == 0
        assert info["last_run"] == "4/18/2026 6:00:00 AM"

    def test_unregistered_task_marked_false(self, mocker):
        mock = mocker.MagicMock()
        mock.returncode = 1
        mock.stdout = ""
        mock.stderr = "ERROR: The system cannot find the file specified."
        mocker.patch("task_watcher.subprocess.run", return_value=mock)
        info = task_watcher.get_schtask_info("Nonexistent")
        assert info["registered"] is False
        assert info["error"]

    def test_subprocess_timeout_does_not_raise(self, mocker):
        import subprocess as sp

        mocker.patch(
            "task_watcher.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="schtasks", timeout=15),
        )
        info = task_watcher.get_schtask_info("SystemHealthDiagnostic")
        assert info["registered"] is False
        assert info["error"]


# ── Concerns ──────────────────────────────────────────────────────


class TestConcernsFromHealth:
    def _healthy(self):
        return {
            "display_name": "System Health Diagnostic",
            "task_name": "SystemHealthDiagnostic",
            "log_summary": {
                "crashloop_detected": False,
                "success_stale": False,
                "failures_in_24h": 0,
                "dominant_exception": None,
                "last_success": "2026-04-18T06:00:00",
                "log_count": 3,
            },
            "schtasks": {"registered": True, "error": None},
        }

    def test_healthy_produces_no_concern(self):
        assert task_watcher.concerns_from_health([self._healthy()]) == []

    def test_crashloop_is_critical(self):
        r = self._healthy()
        r["log_summary"]["crashloop_detected"] = True
        r["log_summary"]["failures_in_24h"] = 5
        r["log_summary"]["dominant_exception"] = "UnicodeEncodeError"
        concerns = task_watcher.concerns_from_health([r])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "critical"
        assert "crash loop" in concerns[0]["title"].lower()
        assert "UnicodeEncodeError" in concerns[0]["detail"]

    def test_unregistered_with_no_logs_is_silent(self):
        """User simply hasn't set this task up -- don't nag."""
        r = self._healthy()
        r["schtasks"]["registered"] = False
        r["log_summary"]["log_count"] = 0
        concerns = task_watcher.concerns_from_health([r])
        assert concerns == []

    def test_unregistered_with_logs_is_warning(self):
        """Task WAS set up at some point -- worth warning that it vanished."""
        r = self._healthy()
        r["schtasks"]["registered"] = False
        r["log_summary"]["log_count"] = 5  # has historical logs
        concerns = task_watcher.concerns_from_health([r])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "warning"
        assert "unregistered" in concerns[0]["title"].lower()

    def test_stale_success_is_warning(self):
        r = self._healthy()
        r["log_summary"]["success_stale"] = True
        r["log_summary"]["last_success"] = "2026-04-15T06:00:00"
        concerns = task_watcher.concerns_from_health([r])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "warning"
        assert "no successful run" in concerns[0]["title"].lower()

    def test_stale_success_ignored_when_unregistered(self):
        """If the task isn't registered AND has no logs, stale-success is not a concern."""
        r = self._healthy()
        r["schtasks"]["registered"] = False
        r["log_summary"]["success_stale"] = True
        r["log_summary"]["log_count"] = 0
        assert task_watcher.concerns_from_health([r]) == []

    def test_crashloop_wins_over_stale(self):
        """Crashloop is more actionable than 'stale success'. Report it first."""
        r = self._healthy()
        r["log_summary"]["crashloop_detected"] = True
        r["log_summary"]["success_stale"] = True
        r["log_summary"]["failures_in_24h"] = 3
        concerns = task_watcher.concerns_from_health([r])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "critical"


# ── End-to-end route test ─────────────────────────────────────────


class TestTaskHealthRoute:
    def test_route_returns_structure(self, client, mocker, tmp_path):
        # Stand up a fake log dir with a single healthy log
        now = datetime.now()
        stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        _write_log(tmp_path, f"SystemHealthDiag_{stamp}.log", SUCCESS_BODY)

        mocker.patch.object(
            task_watcher,
            "MANAGED_TASKS",
            [("System Health Diagnostic", "SystemHealthDiagnostic", str(tmp_path), "SystemHealthDiag_")],
        )
        mock = mocker.MagicMock()
        mock.returncode = 0
        mock.stdout = TestGetSchtaskInfo._CSV_OK
        mock.stderr = ""
        mocker.patch("task_watcher.subprocess.run", return_value=mock)

        resp = client.get("/api/tasks/health")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert len(body["tasks"]) == 1
        task = body["tasks"][0]
        assert task["display_name"] == "System Health Diagnostic"
        assert task["log_summary"]["runs_in_24h"] == 1
        assert task["schtasks"]["registered"] is True
