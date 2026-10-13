"""tests/test_kernel_cpu.py -- stuck kernel-driver thread detection (backlog #75).

Coverage: the SystemProcessInformation parser (synthetic x64 buffers), the
ntdll query wrapper (mocked ctypes), the interval/streak sampler, the
dashboard concern, the /api/selftest probe, and the get_thermals() +
dashboard wiring. No real ntdll call: conftest patches
snapshot_system_threads to None for every test; the real function is
captured here at import time for the wrapper tests.
"""

from __future__ import annotations

import struct

import pytest

import kernel_cpu

_REAL_SNAPSHOT = kernel_cpu.snapshot_system_threads  # captured before conftest's patch


def _entry(pid: int, threads: list[tuple[int, int, int]], last: bool = False) -> bytes:
    """One SYSTEM_PROCESS_INFORMATION entry + its thread records (x64)."""
    size = kernel_cpu._PROC_HEADER + len(threads) * kernel_cpu._THREAD_SIZE
    buf = bytearray(size)
    struct.pack_into("<II", buf, 0, 0 if last else size, len(threads))
    struct.pack_into("<Q", buf, kernel_cpu._PID_OFF, pid)
    for i, (tid, kernel, user) in enumerate(threads):
        t = kernel_cpu._PROC_HEADER + i * kernel_cpu._THREAD_SIZE
        struct.pack_into("<qq", buf, t, kernel, user)
        struct.pack_into("<Q", buf, t + kernel_cpu._TID_OFF, tid)
    return bytes(buf)


def _buffer(*procs: tuple[int, list[tuple[int, int, int]]]) -> bytes:
    return b"".join(_entry(pid, th, last=(i == len(procs) - 1)) for i, (pid, th) in enumerate(procs))


# ══════════════════════════════════════════════════════════════════════
# parse_process_threads
# ══════════════════════════════════════════════════════════════════════


class TestParseProcessThreads:
    def test_finds_system_process_after_idle(self):
        raw = _buffer((0, [(0, 5, 0)]), (4, [(100, 7, 3), (104, 50, 0)]), (428, []))
        assert kernel_cpu.parse_process_threads(raw, 4) == {100: 10, 104: 50}

    def test_missing_pid_returns_none(self):
        raw = _buffer((0, [(0, 1, 1)]), (428, []))
        assert kernel_cpu.parse_process_threads(raw, 4) is None

    def test_truncated_thread_block_returns_none(self):
        raw = _buffer((4, [(100, 1, 1), (104, 1, 1)]))
        assert kernel_cpu.parse_process_threads(raw[:-10], 4) is None

    def test_buffer_shorter_than_header_returns_none(self):
        assert kernel_cpu.parse_process_threads(b"\x00" * 16, 4) is None

    def test_offset_past_end_returns_none(self):
        raw = bytearray(_buffer((0, [])))
        struct.pack_into("<I", raw, 0, 10_000)  # NextEntryOffset beyond the buffer
        assert kernel_cpu.parse_process_threads(bytes(raw), 4) is None

    def test_offset_landing_past_end_terminates(self):
        raw = bytearray(_buffer((0, [])))
        struct.pack_into("<I", raw, 0, 0x100)  # points at itself + header -> past end
        assert kernel_cpu.parse_process_threads(bytes(raw), 4) is None


# ══════════════════════════════════════════════════════════════════════
# ntdll wrapper
# ══════════════════════════════════════════════════════════════════════


class _FakeNtdll:
    """NtQuerySystemInformation stand-in: replays statuses, writes payload."""

    def __init__(self, statuses, payload=b""):
        self.statuses = list(statuses)
        self.payload = payload
        self.sizes = []

    def NtQuerySystemInformation(self, cls, buf, size, ret_ref):  # noqa: N802 -- Win32 name
        self.sizes.append(size)
        status = self.statuses.pop(0)
        ret_ref._obj.value = len(self.payload) or 1024
        if status == 0:
            import ctypes

            ctypes.memmove(buf, self.payload, len(self.payload))
        return status


class TestQueryProcessInfo:
    def _patch(self, mocker, monkeypatch, fake):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "win32")
        mocker.patch("ctypes.WinDLL", return_value=fake, create=True)

    def test_non_windows_returns_none(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "linux")
        assert kernel_cpu._query_process_info() is None

    def test_success_returns_written_bytes(self, mocker, monkeypatch):
        payload = _buffer((4, [(100, 1, 2)]))
        self._patch(mocker, monkeypatch, _FakeNtdll([0], payload))
        assert kernel_cpu._query_process_info() == payload

    def test_grows_buffer_on_length_mismatch(self, mocker, monkeypatch):
        payload = _buffer((4, [(100, 1, 2)]))
        fake = _FakeNtdll([0xC0000004, 0], payload)
        self._patch(mocker, monkeypatch, fake)
        assert kernel_cpu._query_process_info() == payload
        assert fake.sizes[1] > fake.sizes[0]

    def test_other_error_status_returns_none(self, mocker, monkeypatch):
        self._patch(mocker, monkeypatch, _FakeNtdll([0xC0000022]))  # ACCESS_DENIED
        assert kernel_cpu._query_process_info() is None

    def test_never_fitting_gives_up(self, mocker, monkeypatch):
        self._patch(mocker, monkeypatch, _FakeNtdll([0xC0000004] * 8))
        assert kernel_cpu._query_process_info() is None


class TestSnapshotSystemThreads:
    def test_parses_system_process(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu, "_query_process_info", lambda: _buffer((4, [(9, 3, 4)])))
        assert _REAL_SNAPSHOT() == {9: 7}

    def test_no_buffer_is_none(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu, "_query_process_info", lambda: None)
        assert _REAL_SNAPSHOT() is None

    def test_exception_is_none(self, monkeypatch):
        def boom():
            raise OSError("ntdll gone")

        monkeypatch.setattr(kernel_cpu, "_query_process_info", boom)
        assert _REAL_SNAPSHOT() is None


# ══════════════════════════════════════════════════════════════════════
# sample() -- interval diff + stuck streaks
# ══════════════════════════════════════════════════════════════════════

# 1% of one core over 30 s = 30 * 100_000 ticks.
_PCT_30S = 30 * kernel_cpu._TICKS_PER_PCT_SECOND


def _snap(**pcts_so_far):
    """Cumulative ticks: thread id -> accumulated %-of-core x 30 s units."""
    return {int(k[1:]): int(v * _PCT_30S) for k, v in pcts_so_far.items()}


class TestSample:
    def test_unreadable_snapshot_is_unavailable(self):
        out = kernel_cpu.sample(now=0.0)  # conftest snapshot -> None
        assert out["available"] is False
        assert out["stuck"] == []

    def test_first_sample_is_warming_up(self):
        out = kernel_cpu.sample(now=0.0, snap=_snap(t1=0))
        assert out["available"] is False and out["warming_up"] is True

    def test_short_interval_keeps_previous_verdict(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=0))
        first = kernel_cpu.sample(now=30.0, snap=_snap(t1=10))
        again = kernel_cpu.sample(now=35.0, snap=_snap(t1=99))
        assert again is first

    def test_short_interval_before_any_verdict_is_warming_up(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=0))
        assert kernel_cpu.sample(now=5.0, snap=_snap(t1=1))["warming_up"] is True

    def test_percent_of_core_math_and_busiest(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=0, t2=0))
        out = kernel_cpu.sample(now=30.0, snap=_snap(t1=12.5, t2=3))
        assert out["available"] is True
        assert out["interval_s"] == 30.0
        assert out["busiest"] == {"tid": 1, "pct": 12.5}
        assert out["total_pct"] == 15.5
        assert out["stuck"] == []

    def test_one_hot_interval_is_not_yet_stuck(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t7=0))
        assert kernel_cpu.sample(now=30.0, snap=_snap(t7=99))["stuck"] == []

    def test_two_hot_intervals_flag_stuck_with_duration(self):
        # The 2026-10-11 Killer case: one System thread at ~99% of a core.
        kernel_cpu.sample(now=0.0, snap=_snap(t7=0, t8=0))
        kernel_cpu.sample(now=30.0, snap=_snap(t7=99, t8=5))
        out = kernel_cpu.sample(now=60.0, snap=_snap(t7=198, t8=10))
        assert out["stuck"] == [{"tid": 7, "pct": 99.0, "minutes": 1.0}]

    def test_cooling_interval_resets_streak(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t7=0))
        kernel_cpu.sample(now=30.0, snap=_snap(t7=99))
        kernel_cpu.sample(now=60.0, snap=_snap(t7=100))  # 1% -> streak cleared
        out = kernel_cpu.sample(now=90.0, snap=_snap(t7=199))
        assert out["stuck"] == []

    def test_exactly_threshold_is_not_hot(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=0))
        kernel_cpu.sample(now=30.0, snap=_snap(t1=50))
        assert kernel_cpu.sample(now=60.0, snap=_snap(t1=100))["stuck"] == []

    def test_new_and_reset_threads_are_ignored(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=50))
        out = kernel_cpu.sample(now=30.0, snap=_snap(t1=10, t2=99))  # t1 went backwards, t2 is new
        assert out["busiest"] is None
        assert out["total_pct"] == 0

    def test_stuck_sorted_hottest_first(self):
        kernel_cpu.sample(now=0.0, snap=_snap(t1=0, t2=0))
        kernel_cpu.sample(now=30.0, snap=_snap(t1=60, t2=95))
        out = kernel_cpu.sample(now=60.0, snap=_snap(t1=120, t2=190))
        assert [s["tid"] for s in out["stuck"]] == [2, 1]


# ══════════════════════════════════════════════════════════════════════
# Concern + selftest
# ══════════════════════════════════════════════════════════════════════


class TestStuckConcern:
    @pytest.mark.parametrize("state", [None, {}, {"stuck": []}, {"available": False, "stuck": []}])
    def test_no_stuck_no_concern(self, state):
        assert kernel_cpu.stuck_concern(state) is None

    def test_concern_names_load_duration_and_killer(self):
        c = kernel_cpu.stuck_concern({"stuck": [{"tid": 7, "pct": 99.4, "minutes": 12.2}]})
        assert c["level"] == "warning"
        assert c["tab"] == "thermals"
        assert "~99% of a core for 12 min" in c["title"]
        assert "Killer" in c["detail"]
        assert "switchTab('thermals')" in c["action_fn"]

    def test_concern_counts_extra_threads(self):
        stuck = [{"tid": 1, "pct": 90, "minutes": 5}, {"tid": 2, "pct": 60, "minutes": 5}]
        assert "(+1 more thread(s))" in kernel_cpu.stuck_concern({"stuck": stuck})["title"]


class TestSelftest:
    def test_ok_with_plausible_thread_count(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu, "snapshot_system_threads", lambda: {i: 0 for i in range(600)})
        assert kernel_cpu.kernel_cpu_selftest() == {"ok": True, "threads": 600}

    def test_unreadable_is_error(self):
        assert "error" in kernel_cpu.kernel_cpu_selftest()  # conftest snapshot -> None

    def test_implausible_count_flags_layout_change(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu, "snapshot_system_threads", lambda: {1: 0, 2: 0})
        assert "layout" in kernel_cpu.kernel_cpu_selftest()["error"]

    def test_registered_in_selftest_checks(self):
        import windesktopmgr as wdm

        assert ("kernel_cpu", "kernel_cpu_selftest", 10) in wdm.SELFTEST_CHECKS
        assert wdm.kernel_cpu_selftest is kernel_cpu.kernel_cpu_selftest


# ══════════════════════════════════════════════════════════════════════
# Wiring: get_thermals() + dashboard concern
# ══════════════════════════════════════════════════════════════════════


class TestWiring:
    def test_get_thermals_carries_kernel_state(self, mocker):
        mocker.patch("windesktopmgr.bounded_wmi_query", return_value=([], []))
        mocker.patch("lhm.get_lhm_temps", return_value=[])
        mocker.patch.object(kernel_cpu, "sample", return_value={"available": True, "stuck": [], "busiest": None})
        import thermals

        assert thermals.get_thermals()["kernel_cpu"]["available"] is True

    def test_get_thermals_survives_probe_crash(self, mocker):
        mocker.patch("windesktopmgr.bounded_wmi_query", return_value=([], []))
        mocker.patch("lhm.get_lhm_temps", return_value=[])
        mocker.patch.object(kernel_cpu, "sample", side_effect=RuntimeError("boom"))
        import thermals

        out = thermals.get_thermals()
        assert out["kernel_cpu"]["available"] is False
        assert "perf" in out

    def test_dashboard_emits_concern_for_stuck_thread(self, client, mocker):
        import windesktopmgr as wdm

        therm = {
            "temps": [],
            "perf": {"CPUPct": 5},
            "fans": [],
            "kernel_cpu": {"available": True, "stuck": [{"tid": 7, "pct": 99.0, "minutes": 30}]},
        }
        mocker.patch.object(wdm, "get_thermals", return_value=therm)
        for fn in (
            "get_driver_health",
            "get_disk_health",
            "get_credentials_network_health",
            "get_memory_analysis",
        ):
            mocker.patch.object(wdm, fn, return_value={})
        mocker.patch.object(wdm, "get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch.object(wdm, "get_nas_storage", return_value={"nas": [], "configured": 0})
        concerns = client.get("/api/dashboard/summary").get_json().get("concerns", [])
        match = [c for c in concerns if "keeping one CPU core busy" in c.get("title", "")]
        assert match and match[0]["level"] == "warning"
