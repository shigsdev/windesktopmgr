"""Tests for stallwatch.py -- the stall watchdog (backlog #106)."""

import threading

import pytest

import stallwatch


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Fresh in-flight table and a stalls.log under tmp_path for every test."""
    monkeypatch.setattr(stallwatch, "STALL_LOG", str(tmp_path / "stalls.log"))
    monkeypatch.setattr(stallwatch, "LOG_DIR", str(tmp_path))
    stallwatch._inflight.clear()
    yield
    stallwatch._inflight.clear()


def _start_at(mocker, t, method="GET", path="/api/x"):
    mocker.patch("stallwatch.time.monotonic", return_value=t)
    return stallwatch.request_started(method, path)


class TestInflightTracking:
    def test_started_then_finished_leaves_nothing(self, mocker):
        token = _start_at(mocker, 100.0)
        assert token in stallwatch._inflight
        stallwatch.request_finished(token)
        assert stallwatch._inflight == {}

    def test_exempt_path_is_not_tracked(self, mocker):
        token = _start_at(mocker, 100.0, path="/api/selftest")
        assert token is None
        assert stallwatch._inflight == {}
        stallwatch.request_finished(None)  # no-op, no raise

    def test_finishing_unknown_token_is_harmless(self):
        stallwatch.request_finished(999_999)

    def test_records_thread_name(self, mocker):
        token = _start_at(mocker, 100.0)
        assert stallwatch._inflight[token]["thread"] == threading.current_thread().name


class TestStalledRequests:
    def test_under_threshold_not_reported(self, mocker):
        _start_at(mocker, 100.0)
        assert stallwatch.stalled_requests(100.0 + stallwatch.REQUEST_STALL_S) == []

    def test_over_threshold_reported_once(self, mocker):
        _start_at(mocker, 100.0, path="/api/slow")
        now = 100.0 + stallwatch.REQUEST_STALL_S + 1
        first = stallwatch.stalled_requests(now)
        assert [r["path"] for r in first] == ["/api/slow"]
        assert first[0]["elapsed_s"] == pytest.approx(stallwatch.REQUEST_STALL_S + 1)
        assert stallwatch.stalled_requests(now + 10) == []

    def test_inflight_summary_oldest_first(self, mocker):
        _start_at(mocker, 105.0, path="/api/b")
        _start_at(mocker, 100.0, path="/api/a")
        lines = stallwatch.inflight_summary(110.0)
        assert lines[0].startswith("GET /api/a 10.0s")
        assert lines[1].startswith("GET /api/b 5.0s")


class TestFormatAllStacks:
    def test_includes_named_threads_and_this_function(self):
        out = stallwatch.format_all_stacks()
        assert f'Thread "{threading.current_thread().name}"' in out
        assert "test_includes_named_threads_and_this_function" in out


class TestTick:
    def test_quiet_tick_writes_nothing(self, tmp_path):
        stallwatch.StallWatchdog().tick(100.0)
        assert not (tmp_path / "stalls.log").exists()

    def test_request_stall_dumps_stacks_and_warns(self, mocker, tmp_path):
        warn = mocker.patch.object(stallwatch.log, "warning")
        _start_at(mocker, 100.0, path="/api/dashboard/summary")
        stallwatch.StallWatchdog().tick(125.0)
        text = (tmp_path / "stalls.log").read_text(encoding="utf-8")
        assert "request stall" in text
        assert "in flight: GET /api/dashboard/summary 25.0s" in text
        assert 'Thread "' in text
        assert any("Request stall" in c.args[0] for c in warn.call_args_list)

    def test_cooldown_limits_dumps(self, mocker, tmp_path):
        dog = stallwatch.StallWatchdog()
        _start_at(mocker, 100.0, path="/api/one")
        dog.tick(125.0)
        _start_at(mocker, 130.0, path="/api/two")
        dog.tick(155.0)  # inside cooldown: logged, not dumped
        text = (tmp_path / "stalls.log").read_text(encoding="utf-8")
        assert text.count("request stall") == 1
        _start_at(mocker, 600.0, path="/api/three")
        dog.tick(125.0 + stallwatch.DUMP_COOLDOWN_S + 500)
        text = (tmp_path / "stalls.log").read_text(encoding="utf-8")
        assert text.count("request stall") == 2

    def test_full_log_stops_request_dumps(self, mocker, tmp_path, monkeypatch):
        monkeypatch.setattr(stallwatch, "MAX_LOG_BYTES", 10)
        (tmp_path / "stalls.log").write_text("x" * 20, encoding="utf-8")
        _start_at(mocker, 100.0)
        stallwatch.StallWatchdog().tick(125.0)
        assert (tmp_path / "stalls.log").read_text(encoding="utf-8") == "x" * 20

    def test_heartbeat_gap_is_noted(self, mocker, tmp_path):
        warn = mocker.patch.object(stallwatch.log, "warning")
        dog = stallwatch.StallWatchdog()
        dog.tick(100.0)
        dog.tick(100.0 + stallwatch.PROCESS_STALL_S + 7)
        text = (tmp_path / "stalls.log").read_text(encoding="utf-8")
        assert f"after a {stallwatch.PROCESS_STALL_S + 7:.1f}s gap" in text
        assert any("Heartbeat gap" in c.args[0] for c in warn.call_args_list)

    def test_normal_tick_spacing_is_not_a_gap(self, tmp_path):
        dog = stallwatch.StallWatchdog()
        dog.tick(100.0)
        dog.tick(100.0 + stallwatch.TICK_S)
        assert not (tmp_path / "stalls.log").exists()

    def test_write_failure_is_logged_not_raised(self, mocker):
        mocker.patch("stallwatch._append", side_effect=OSError("disk full"))
        warn = mocker.patch.object(stallwatch.log, "warning")
        dog = stallwatch.StallWatchdog()
        dog.tick(100.0)
        dog.tick(200.0)
        assert any("Could not write" in c.args[0] for c in warn.call_args_list)


class TestFaulthandlerRearm:
    def test_rearms_each_tick_when_open(self, mocker):
        arm = mocker.patch("stallwatch.faulthandler.dump_traceback_later")
        dog = stallwatch.StallWatchdog()
        dog._fh_file = object()
        dog.tick(100.0)
        dog.tick(105.0)
        assert arm.call_count == 2
        assert arm.call_args.args[0] == stallwatch.PROCESS_STALL_S
        assert arm.call_args.kwargs["exit"] is False

    def test_not_armed_without_file(self, mocker):
        arm = mocker.patch("stallwatch.faulthandler.dump_traceback_later")
        stallwatch.StallWatchdog().tick(100.0)
        arm.assert_not_called()

    def test_rearm_failure_turns_process_watch_off(self, mocker):
        mocker.patch("stallwatch.faulthandler.dump_traceback_later", side_effect=ValueError("bad fd"))
        dog = stallwatch.StallWatchdog()
        dog._fh_file = object()
        dog.tick(100.0)
        assert dog._fh_file is None


class TestStart:
    def test_start_opens_log_and_starts_named_thread(self, mocker, tmp_path):
        thread_cls = mocker.patch("stallwatch.threading.Thread")
        dog = stallwatch.StallWatchdog()
        dog.start()
        try:
            assert dog._fh_file is not None
            assert thread_cls.call_args.kwargs["name"] == "StallWatchdog"
            assert thread_cls.call_args.kwargs["daemon"] is True
            thread_cls.return_value.start.assert_called_once()
        finally:
            dog._fh_file.close()

    def test_start_rotates_oversized_log(self, mocker, tmp_path, monkeypatch):
        mocker.patch("stallwatch.threading.Thread")
        monkeypatch.setattr(stallwatch, "MAX_LOG_BYTES", 10)
        (tmp_path / "stalls.log").write_text("old" * 10, encoding="utf-8")
        dog = stallwatch.StallWatchdog()
        dog.start()
        dog._fh_file.close()
        assert (tmp_path / "stalls.log.1").read_text(encoding="utf-8") == "old" * 10
        assert (tmp_path / "stalls.log").read_text(encoding="utf-8") == ""

    def test_start_survives_unopenable_log(self, mocker):
        mocker.patch("stallwatch.threading.Thread")
        mocker.patch("stallwatch.open", side_effect=OSError("denied"), create=True)
        dog = stallwatch.StallWatchdog()
        dog.start()
        assert dog._fh_file is None

    def test_module_start_is_idempotent(self, mocker, monkeypatch):
        monkeypatch.setattr(stallwatch, "_watchdog", None)
        start = mocker.patch.object(stallwatch.StallWatchdog, "start")
        first = stallwatch.start()
        assert stallwatch.start() is first
        start.assert_called_once()

    def test_stop_cancels_faulthandler(self, mocker):
        cancel = mocker.patch("stallwatch.faulthandler.cancel_dump_traceback_later")
        dog = stallwatch.StallWatchdog()
        dog._fh_file = object()
        dog.stop()
        cancel.assert_called_once()
        assert dog._stop.is_set()


class TestRun:
    def test_run_survives_tick_error_and_stops(self, mocker):
        dog = stallwatch.StallWatchdog()
        calls = []

        def boom(now):
            calls.append(now)
            dog._stop.set()
            raise RuntimeError("tick broke")

        mocker.patch.object(dog, "tick", side_effect=boom)
        mocker.patch.object(dog._stop, "wait", side_effect=lambda _t: dog._stop.is_set())
        warn = mocker.patch.object(stallwatch.log, "warning")
        dog._run()
        assert len(calls) == 1
        assert any("tick failed" in c.args[0] for c in warn.call_args_list)


class TestFlaskHooks:
    def test_request_is_tracked_then_cleared(self, client, mocker):
        seen = {}

        def spy(method, path):
            token = real(method, path)
            seen["during"] = dict(stallwatch._inflight)
            return token

        real = stallwatch.request_started
        mocker.patch("windesktopmgr.stallwatch.request_started", side_effect=spy)
        client.get("/api/health")
        assert any(r["path"] == "/api/health" for r in seen["during"].values())
        assert stallwatch._inflight == {}

    def test_request_that_raises_is_still_cleared(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError):  # TESTING=True propagates route errors
            client.get("/api/thermals/data")
        assert stallwatch._inflight == {}
