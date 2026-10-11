"""Tests for scripts/post_restart_check.py.

Focus: wait_for_background_queues(), added 2026-05-21 so the CPU-budget
check samples a genuinely idle tray instead of the post-selftest queue
drain. Before the fix, post_restart_check ran its 2 s CPU sample
immediately after the full /api/selftest — which floods the BSOD /
event-ID / startup / process / service lookup queues — so verify
reported a false 70-90 % CPU failure on every run.

The check functions are imported directly and fed stub responses via a
patched _get_json, so no running tray is required.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

# Make scripts/ importable (same pattern as test_post_deploy_topology_check).
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import post_restart_check as prc  # noqa: E402


def _status(pending=0, in_flight=0):
    """Build a lookup-status payload like /api/bsod/cache etc. return."""
    return {"queue_pending": pending, "in_flight": in_flight}


class TestWaitForBackgroundQueues:
    """wait_for_background_queues() — drains before the CPU sample."""

    def test_returns_true_immediately_when_all_queues_empty(self, mocker):
        """Every status endpoint reports 0 pending / 0 in-flight → drained
        on the first poll, no waiting."""
        mocker.patch.object(prc, "_get_json", return_value=_status(0, 0))
        sleep = mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=10) is True
        # Drained on the first poll — the sleep/retry path is never taken.
        sleep.assert_not_called()

    def test_returns_true_after_queues_drain(self, mocker):
        """Queues start busy, then drain → True once outstanding hits 0."""
        # Round 1: the bsod endpoint still has 3 pending. Round 2: all empty.
        # Two full rounds over every endpoint in QUEUE_STATUS_ENDPOINTS.
        n = len(prc.QUEUE_STATUS_ENDPOINTS)
        responses = [_status(3, 0)] + [_status(0, 0)] * (n - 1) + [_status(0, 0)] * n
        mocker.patch.object(prc, "_get_json", side_effect=responses)
        mocker.patch.object(prc.time, "sleep")  # no real 3 s waits in tests
        assert prc.wait_for_background_queues("http://x", timeout_s=30) is True

    def test_in_flight_lookups_also_block(self, mocker):
        """A drained queue with a worker still in-flight must keep us
        waiting — that lookup thread is exactly the CPU we'd misread."""
        n = len(prc.QUEUE_STATUS_ENDPOINTS)
        responses = [_status(0, 2)] + [_status(0, 0)] * (n - 1) + [_status(0, 0)] * n
        mocker.patch.object(prc, "_get_json", side_effect=responses)
        mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=30) is True

    def test_returns_false_on_timeout_when_queues_never_drain(self, mocker):
        """A queue that never empties → False once the budget expires. The
        caller still samples — a permanently stuck queue is a real signal,
        not something to hide by skipping the check."""
        mocker.patch.object(prc, "_get_json", return_value=_status(5, 1))
        mocker.patch.object(prc.time, "sleep")  # no-op so the test is fast
        # Tiny budget — the loop spins briefly then times out.
        assert prc.wait_for_background_queues("http://x", timeout_s=0.05) is False

    def test_returns_false_when_endpoints_unreachable(self, mocker):
        """If no status endpoint answers, bail out immediately instead of
        blocking the whole budget — verify must still finish."""
        mocker.patch.object(prc, "_get_json", return_value=None)
        sleep = mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=120) is False
        sleep.assert_not_called()

    def test_polls_every_queue_status_endpoint(self, mocker):
        """All five background-lookup endpoints must be polled — missing one
        would let its queue drain unobserved and reintroduce the false
        positive."""
        get = mocker.patch.object(prc, "_get_json", return_value=_status(0, 0))
        prc.wait_for_background_queues("http://host", timeout_s=10)
        polled = {call.args[0] for call in get.call_args_list}
        for endpoint in prc.QUEUE_STATUS_ENDPOINTS:
            assert f"http://host{endpoint}" in polled


class TestCheckTrayResourceBudget:
    """check_tray_resource_budget() — must drain queues before sampling."""

    def _patch_tray(self, mocker, cpu_values, threads=14):
        """Wire a fake tray process returning the given CPU samples in order."""
        order = []
        fake_conn = types.SimpleNamespace(laddr=types.SimpleNamespace(port=5000), status="LISTEN", pid=999)
        fake_proc = mocker.MagicMock()
        it = iter(cpu_values)
        last = [cpu_values[-1]]

        def _cpu(*_a, **_k):
            order.append("sample")
            try:
                last[0] = next(it)
            except StopIteration:
                pass  # exhausted -> keep returning the last value (sustained case)
            return last[0]

        fake_proc.cpu_percent.side_effect = _cpu
        fake_proc.num_threads.return_value = threads
        psutil_mock = mocker.MagicMock()
        psutil_mock.net_connections.return_value = [fake_conn]
        psutil_mock.Process.return_value = fake_proc
        psutil_mock.NoSuchProcess = Exception
        mocker.patch.dict(sys.modules, {"psutil": psutil_mock})
        mocker.patch.object(prc, "wait_for_background_queues", side_effect=lambda *a, **k: order.append("wait"))
        return order

    def test_drains_queues_before_sampling_cpu(self, mocker):
        """Regression for the false-positive verify failure: the queue
        drain must happen BEFORE the CPU sample, not after."""
        order = self._patch_tray(mocker, [3.0])
        result = prc.check_tray_resource_budget("http://localhost:5000")
        assert result is True  # within budget on the first idle sample
        assert order[0] == "wait", "queues must drain before the CPU sample"
        assert "sample" in order

    def test_transient_spike_then_idle_passes(self, mocker):
        """A high burst that settles to idle (cold dashboard fan-out / AI drain)
        must PASS -- we keep sampling until the tray reaches idle."""
        self._patch_tray(mocker, [98.0, 90.0, 40.0, 2.0])
        assert prc.check_tray_resource_budget("http://localhost:5000") is True

    def test_sustained_high_cpu_times_out_and_fails(self, mocker):
        """A genuine poll/refresh leak never idles -> the wait-for-idle loop
        hits its deadline with CPU still over budget -> FAIL."""
        # Tiny idle-confirm window so the loop times out quickly in the test.
        mocker.patch.object(prc, "IDLE_CONFIRM_TIMEOUT_S", 0.01)
        self._patch_tray(mocker, [97.0, 98.0, 96.0, 99.0, 97.0])
        assert prc.check_tray_resource_budget("http://localhost:5000") is False


# ── HTTP helpers ─────────────────────────────────────────────────────


class _Resp:
    """Minimal context-manager stand-in for urlopen()'s response."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestHttpHelpers:
    def test_get_json_parses_body(self, mocker):
        mocker.patch.object(prc.urllib.request, "urlopen", return_value=_Resp(b'{"ok": true}'))
        assert prc._get_json("http://x/api/health") == {"ok": True}

    def test_get_json_connection_error_returns_none(self, mocker):
        mocker.patch.object(prc.urllib.request, "urlopen", side_effect=prc.urllib.error.URLError("refused"))
        assert prc._get_json("http://x") is None

    def test_get_json_bad_json_returns_none(self, mocker):
        mocker.patch.object(prc.urllib.request, "urlopen", return_value=_Resp(b"<html>500</html>"))
        assert prc._get_json("http://x") is None

    def test_post_returns_status_and_body(self, mocker):
        urlopen = mocker.patch.object(prc.urllib.request, "urlopen", return_value=_Resp(b'{"ok": true}', 202))
        assert prc._post("http://x/api/restart") == (202, {"ok": True})
        assert urlopen.call_args.args[0].get_method() == "POST"

    def test_post_http_error_returns_code(self, mocker):
        err = prc.urllib.error.HTTPError("http://x", 500, "err", {}, None)
        mocker.patch.object(prc.urllib.request, "urlopen", side_effect=err)
        assert prc._post("http://x") == (500, None)

    def test_post_connection_error_returns_zero(self, mocker):
        mocker.patch.object(prc.urllib.request, "urlopen", side_effect=ConnectionResetError())
        assert prc._post("http://x") == (0, None)


class TestTriggerRestart:
    def test_202_ok_is_success(self, mocker):
        post = mocker.patch.object(prc, "_post", return_value=(202, {"ok": True}))
        assert prc.trigger_restart("http://h") is True
        assert post.call_args.args[0] == "http://h/api/restart"

    def test_non_202_is_failure(self, mocker):
        mocker.patch.object(prc, "_post", return_value=(500, None))
        assert prc.trigger_restart("http://h") is False

    def test_202_without_ok_is_failure(self, mocker):
        mocker.patch.object(prc, "_post", return_value=(202, {"ok": False}))
        assert prc.trigger_restart("http://h") is False


class TestWaitForHeartbeat:
    def test_returns_true_once_health_ok(self, mocker):
        mocker.patch.object(prc.time, "sleep")
        get = mocker.patch.object(prc, "_get_json", side_effect=[None, {"ok": False}, {"ok": True}])
        assert prc.wait_for_heartbeat("http://h", timeout_s=30) is True
        assert get.call_count == 3
        assert get.call_args.args[0] == "http://h/api/health"

    def test_times_out_when_never_up(self, mocker):
        mocker.patch.object(prc.time, "sleep")
        mocker.patch.object(prc, "_get_json", return_value=None)
        assert prc.wait_for_heartbeat("http://h", timeout_s=0.05) is False


class TestRunSelftest:
    def test_no_response_returns_none(self, mocker, capsys):
        mocker.patch.object(prc, "_get_json", return_value=None)
        assert prc.run_selftest("http://h") is None
        assert "FAILED" in capsys.readouterr().out

    def test_uses_long_timeout(self, mocker):
        """The client must wait at least as long as the server's own
        selftest budget (180 s) or it gives up on a legit cold run."""
        get = mocker.patch.object(prc, "_get_json", return_value={"ok": True})
        prc.run_selftest("http://h")
        assert get.call_args.kwargs["timeout"] >= 180

    def test_failed_count_reported(self, mocker, capsys):
        mocker.patch.object(prc, "_get_json", return_value={"ok": False, "failed": 2})
        assert prc.run_selftest("http://h") == {"ok": False, "failed": 2}
        assert "2 failed" in capsys.readouterr().out


class TestPrintResults:
    def test_no_checks_prints_nothing(self, capsys):
        prc.print_results({"ok": True, "checks": []})
        assert capsys.readouterr().out == ""

    def test_failed_check_shows_error_and_totals(self, capsys):
        body = {
            "ok": False,
            "total": 2,
            "passed": 1,
            "failed": 1,
            "checks": [
                {"name": "disk", "ok": True, "duration_ms": 12},
                {"name": "drivers", "ok": False, "duration_ms": 900, "error": "WMI timeout"},
            ],
        }
        prc.print_results(body)
        out = capsys.readouterr().out
        assert "WMI timeout" in out
        assert "1/2 checks failed" in out

    def test_all_passed_totals(self, capsys):
        checks = [{"name": "a", "ok": True, "duration_ms": 1}]
        prc.print_results({"ok": True, "total": 1, "passed": 1, "checks": checks})
        assert "1/1 checks passed" in capsys.readouterr().out


class TestCheckDashboard:
    def test_no_response_fails(self, mocker):
        mocker.patch.object(prc, "_get_json", return_value=None)
        assert prc.check_dashboard("http://h") is False

    def test_valid_summary_passes(self, mocker, capsys):
        mocker.patch.object(prc, "_get_json", return_value={"overall": "warning", "total": 3, "concerns": []})
        assert prc.check_dashboard("http://h") is True
        assert "overall=warning" in capsys.readouterr().out

    def test_unknown_overall_warns_but_passes(self, mocker, capsys):
        mocker.patch.object(prc, "_get_json", return_value={"concerns": []})
        assert prc.check_dashboard("http://h") is True
        assert "unusual state" in capsys.readouterr().out


def _log(ts, msg, level="INFO"):
    return {"timestamp": ts, "message": msg, "level": level}


class TestCheckIdlePollRate:
    def test_scan_in_progress_skips(self, mocker, capsys):
        get = mocker.patch.object(prc, "_get_json", return_value={"status": "running"})
        assert prc.check_idle_poll_rate("http://h") is True
        assert get.call_count == 1  # never fetched logs
        assert "scan in progress" in capsys.readouterr().out

    def test_logs_unavailable_skips(self, mocker):
        mocker.patch.object(prc.time, "sleep")
        mocker.patch.object(prc, "_get_json", side_effect=[{"status": "idle"}, None])
        assert prc.check_idle_poll_rate("http://h") is True

    def test_runaway_poller_fails(self, mocker):
        """10 polls in a 3 s window = 3.3 req/s > 2.0 threshold -> FAIL.
        Timestamps are far in the future so they're all inside the window."""
        mocker.patch.object(prc.time, "sleep")
        entries = [_log("2999-01-01 00:00:00", '"GET /api/scan/status HTTP/1.1" 200') for _ in range(10)]
        mocker.patch.object(prc, "_get_json", side_effect=[{"status": "idle"}, {"entries": entries}])
        assert prc.check_idle_poll_rate("http://h") is False

    def test_old_unrelated_and_unparseable_entries_ignored(self, mocker):
        mocker.patch.object(prc.time, "sleep")
        entries = [_log("2000-01-01 00:00:00", "GET /api/scan/status")] * 20  # before the window
        entries += [_log("2999-01-01 00:00:00", "GET /api/dashboard/summary")] * 20  # other path
        entries += [_log("not-a-date", "GET /api/scan/status")]  # unparseable -> skipped
        mocker.patch.object(prc, "_get_json", side_effect=[{"status": "complete"}, {"entries": entries}])
        assert prc.check_idle_poll_rate("http://h") is True


def _fake_psutil(mocker, proc, port=5000):
    conn = types.SimpleNamespace(laddr=types.SimpleNamespace(port=port), status="LISTEN", pid=7)
    psutil_mock = mocker.MagicMock()
    psutil_mock.net_connections.return_value = [conn]
    psutil_mock.Process.return_value = proc
    psutil_mock.NoSuchProcess = ProcessLookupError
    mocker.patch.dict(sys.modules, {"psutil": psutil_mock})
    return psutil_mock


class TestCheckTrayResourceBudgetEdges:
    def test_psutil_missing_skips(self, mocker):
        mocker.patch.dict(sys.modules, {"psutil": None})  # import raises ImportError
        assert prc.check_tray_resource_budget("http://localhost:5000") is True

    def test_no_listener_skips(self, mocker, capsys):
        psutil_mock = _fake_psutil(mocker, mocker.MagicMock())
        psutil_mock.net_connections.return_value = []
        wait = mocker.patch.object(prc, "wait_for_background_queues")
        assert prc.check_tray_resource_budget("http://localhost:5123") is True
        assert "port 5123" in capsys.readouterr().out
        wait.assert_not_called()

    def test_too_many_threads_fails(self, mocker):
        proc = mocker.MagicMock()
        proc.cpu_percent.return_value = 1.0
        proc.num_threads.return_value = prc.THREAD_THRESHOLD + 1
        _fake_psutil(mocker, proc)
        mocker.patch.object(prc, "wait_for_background_queues")
        assert prc.check_tray_resource_budget("http://localhost:5000") is False

    def test_process_exits_mid_sample_skips(self, mocker):
        proc = mocker.MagicMock()
        proc.cpu_percent.side_effect = ProcessLookupError()
        _fake_psutil(mocker, proc)
        mocker.patch.object(prc, "wait_for_background_queues")
        assert prc.check_tray_resource_budget("http://localhost:5000") is True


class TestCheckPlaywrightSmoke:
    def test_disabled_by_default(self, mocker, monkeypatch):
        monkeypatch.delenv("PLAYWRIGHT_SMOKE", raising=False)
        run = mocker.patch("subprocess.run")
        assert prc.check_playwright_smoke() is True
        run.assert_not_called()

    def test_enabled_pass(self, mocker, monkeypatch):
        monkeypatch.setenv("PLAYWRIGHT_SMOKE", "1")
        done = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        run = mocker.patch("subprocess.run", return_value=done)
        assert prc.check_playwright_smoke() is True
        cmd = run.call_args.args[0]
        assert cmd[cmd.index("-m", 3) + 1] == "playwright"

    def test_enabled_failure_fails(self, mocker, monkeypatch, capsys):
        monkeypatch.setenv("PLAYWRIGHT_SMOKE", "yes")
        done = types.SimpleNamespace(returncode=1, stdout="1 failed", stderr="")
        mocker.patch("subprocess.run", return_value=done)
        assert prc.check_playwright_smoke() is False
        assert "1 failed" in capsys.readouterr().out


class TestCheckLogs:
    def _logs(self, mocker, errors, warnings):
        return mocker.patch.object(prc, "_get_json", side_effect=[{"entries": errors}, {"entries": warnings}])

    def test_clean_logs_pass(self, mocker):
        self._logs(mocker, [], [])
        assert prc.check_logs("http://h") is True

    def test_error_after_restart_fails(self, mocker):
        self._logs(mocker, [_log("2026-10-11 10:05:00.123", "boom", "ERROR")], [])
        assert prc.check_logs("http://h", since="2026-10-11T10:00:00") is False

    def test_errors_before_restart_ignored(self, mocker):
        self._logs(mocker, [_log("2026-10-11 09:00:00.000", "old", "ERROR")], [])
        assert prc.check_logs("http://h", since="2026-10-11T10:00:00") is True

    def test_warnings_only_pass(self, mocker, capsys):
        warnings = [_log("2026-10-11 10:05:00", f"w{i}", "WARNING") for i in range(7)]
        self._logs(mocker, [], warnings)
        assert prc.check_logs("http://h", since="2026-10-11T10:00:00") is True
        assert "and 2 more" in capsys.readouterr().out

    def test_unreachable_logs_do_not_fail(self, mocker):
        mocker.patch.object(prc, "_get_json", return_value=None)
        assert prc.check_logs("http://h", since="2026-10-11T10:00:00") is True

    def test_malformed_timestamp_does_not_crash(self, mocker):
        """Regression: one entry with an unparseable timestamp used to raise
        ValueError out of check_logs and abort the whole verify with a
        traceback. It must be skipped, like check_idle_poll_rate does."""
        errors = [
            _log("2026-10-11 10:00:00.abc", "garbled", "ERROR"),
            _log("2026-10-11 10:05:00", "real", "ERROR"),
        ]
        self._logs(mocker, errors, [])
        assert prc.check_logs("http://h", since="2026-10-11T10:00:00") is False

    def test_long_message_truncated(self, mocker, capsys):
        self._logs(mocker, [], [_log("2026-10-11 10:05:00", "x" * 300, "WARNING")])
        prc.check_logs("http://h")
        assert "x" * 97 + "..." in capsys.readouterr().out


class TestMain:
    """main() exit codes: 0 = all green, 1 = a check failed, 2 = server
    never came back. dev.py verify relies on these."""

    CHECKS = (
        "check_dashboard",
        "check_idle_poll_rate",
        "check_tray_resource_budget",
        "check_logs",
        "check_playwright_smoke",
    )

    @pytest.fixture
    def all_green(self, mocker, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["post_restart_check.py"])
        patches = {
            "trigger_restart": mocker.patch.object(prc, "trigger_restart", return_value=True),
            "wait_for_heartbeat": mocker.patch.object(prc, "wait_for_heartbeat", return_value=True),
            "run_selftest": mocker.patch.object(prc, "run_selftest", return_value={"ok": True, "checks": []}),
        }
        for name in self.CHECKS:
            patches[name] = mocker.patch.object(prc, name, return_value=True)
        return patches

    def test_all_green_returns_0(self, all_green):
        assert prc.main() == 0
        all_green["trigger_restart"].assert_called_once()

    def test_no_restart_skips_restart(self, all_green, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["post_restart_check.py", "--no-restart", "--host", "http://h:1"])
        assert prc.main() == 0
        all_green["trigger_restart"].assert_not_called()
        assert all_green["run_selftest"].call_args.args[0] == "http://h:1"

    def test_restart_failure_returns_2(self, all_green):
        all_green["trigger_restart"].return_value = False
        assert prc.main() == 2

    def test_heartbeat_timeout_returns_2(self, all_green):
        all_green["wait_for_heartbeat"].return_value = False
        assert prc.main() == 2

    def test_selftest_no_response_returns_2(self, all_green):
        all_green["run_selftest"].return_value = None
        assert prc.main() == 2

    def test_selftest_failure_returns_1(self, all_green):
        all_green["run_selftest"].return_value = {"ok": False, "checks": []}
        assert prc.main() == 1

    @pytest.mark.parametrize("check", CHECKS)
    def test_any_post_selftest_check_failure_returns_1(self, all_green, check):
        all_green[check].return_value = False
        assert prc.main() == 1
