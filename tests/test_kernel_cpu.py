"""tests/test_kernel_cpu.py -- stuck kernel-driver thread detection (backlog #75).

Coverage: the SystemProcessInformation parser (synthetic x64 buffers), the
ntdll query wrapper (mocked ctypes), the interval/streak sampler, the
dashboard concern, the /api/selftest probe, and the get_thermals() +
dashboard wiring. No real ntdll call: conftest patches
snapshot_system_threads to None for every test; the real function is
captured here at import time for the wrapper tests.
"""

from __future__ import annotations

import json
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


# ══════════════════════════════════════════════════════════════════════
# #75 PR 2 -- "Identify driver" (elevated, on demand)
# ══════════════════════════════════════════════════════════════════════


def _entry_with_starts(pid, threads, last=True):
    """Like _entry() but each thread is (tid, ticks, start address)."""
    size = kernel_cpu._PROC_HEADER + len(threads) * kernel_cpu._THREAD_SIZE
    buf = bytearray(size)
    struct.pack_into("<II", buf, 0, 0 if last else size, len(threads))
    struct.pack_into("<Q", buf, kernel_cpu._PID_OFF, pid)
    for i, (tid, ticks, start) in enumerate(threads):
        t = kernel_cpu._PROC_HEADER + i * kernel_cpu._THREAD_SIZE
        struct.pack_into("<qq", buf, t, ticks, 0)
        struct.pack_into("<Q", buf, t + kernel_cpu._START_OFF, start)
        struct.pack_into("<Q", buf, t + kernel_cpu._TID_OFF, tid)
    return bytes(buf)


_DRIVERS = [(0x1000, "ntoskrnl.exe"), (0x5000, "ndis.sys"), (0x9000, "KfeCo11X64.sys")]
_TEN_S_PCT = 10 * kernel_cpu._TICKS_PER_PCT_SECOND  # 1% of a core over 10 s


class TestThreadDetails:
    def test_start_addresses_parsed(self):
        raw = _entry_with_starts(4, [(7, 100, 0x9100), (8, 5, 0)])
        assert kernel_cpu.parse_process_thread_details(raw, 4) == {7: (100, 0x9100), 8: (5, 0)}

    def test_ticks_only_view_unchanged(self):
        raw = _entry_with_starts(4, [(7, 100, 0x9100)])
        assert kernel_cpu.parse_process_threads(raw, 4) == {7: 100}


class TestDriverMapping:
    @pytest.mark.parametrize(
        ("addr", "name"),
        [
            (0, "(hidden)"),
            (0x500, "(unknown)"),
            (0x1000, "ntoskrnl.exe"),
            (0x5123, "ndis.sys"),
            (0xFFFF, "KfeCo11X64.sys"),
        ],
    )
    def test_driver_for_address(self, addr, name):
        assert kernel_cpu.driver_for_address(addr, _DRIVERS) == name

    def test_killer_hint_is_case_insensitive(self):
        assert "Prioritization Engine" in kernel_cpu.hint_for_driver("KfeCo11X64.sys")

    @pytest.mark.parametrize("name", ["", None, "mystery.sys", "(hidden)"])
    def test_unknown_driver_has_no_hint(self, name):
        assert kernel_cpu.hint_for_driver(name) is None

    def test_storage_spaces_hint(self):
        assert "Storage tab" in kernel_cpu.hint_for_driver("spaceport.sys")


class TestSummarizeByDriver:
    def test_groups_sorts_and_hints(self):
        before = {1: (0, 0x9100), 2: (0, 0x5100), 3: (0, 0x5200), 4: (50, 0x1100)}
        after = {
            1: (99 * _TEN_S_PCT, 0x9100),
            2: (3 * _TEN_S_PCT, 0x5100),
            3: (2 * _TEN_S_PCT, 0x5200),
            4: (50, 0x1100),  # no CPU used -> dropped
            5: (40 * _TEN_S_PCT, 0x1100),  # new thread -> no baseline, ignored
        }
        rows = kernel_cpu.summarize_by_driver(before, after, 10.0, _DRIVERS)
        assert [r["driver"] for r in rows] == ["KfeCo11X64.sys", "ndis.sys"]
        assert rows[0]["pct"] == 99.0 and rows[0]["threads"] == 1
        assert "Killer" in rows[0]["hint"]
        assert rows[1]["pct"] == 5.0 and rows[1]["threads"] == 2

    def test_hint_only_when_busy_enough(self):
        """A fix-it hint on a sliver of a core is misleading (a 0.2% NVIDIA row
        said 'reinstall the GPU driver'): below HINT_MIN_PCT a row has none,
        except the kernel's own reassurance note."""
        drivers = [(0x1000, "ntoskrnl.exe"), (0x2000, "nvlddmkm.sys"), (0x3000, "ndis.sys")]
        before = {1: (0, 0x1100), 2: (0, 0x2100), 3: (0, 0x3100)}
        after = {
            1: (15 * _TEN_S_PCT, 0x1100),
            2: (_TEN_S_PCT // 5, 0x2100),
            3: (20 * _TEN_S_PCT, 0x3100),  # exactly at the threshold
        }
        rows = {r["driver"]: r for r in kernel_cpu.summarize_by_driver(before, after, 10.0, drivers)}
        assert rows["nvlddmkm.sys"]["pct"] == 0.2 and rows["nvlddmkm.sys"]["hint"] is None
        assert "normal" in rows["ntoskrnl.exe"]["hint"]
        assert rows["ndis.sys"]["pct"] == kernel_cpu.HINT_MIN_PCT
        assert "network driver" in rows["ndis.sys"]["hint"]

    def test_limit_and_zero_interval(self):
        before = {i: (0, 0x1000 + i) for i in range(20)}
        after = {i: (_TEN_S_PCT, 0x1000 + i) for i in range(20)}
        drivers = [(0x1000 + i, f"d{i:02}.sys") for i in range(20)]
        assert len(kernel_cpu.summarize_by_driver(before, after, 10.0, drivers, limit=3)) == 3
        assert kernel_cpu.summarize_by_driver(before, after, 0, drivers) == []


class _FakeBaseName:
    """GetDeviceDriverBaseNameW stand-in; an instance accepts ``.argtypes``."""

    def __call__(self, base, buf, size):
        buf.value = {0x9000: "KfeCo11X64.sys", 0x1000: "ntoskrnl.exe"}.get(base, "")
        return len(buf.value)


class _FakePsapi:
    def __init__(self, bases, ok=True):
        self.bases, self.ok = bases, ok
        self.GetDeviceDriverBaseNameW = _FakeBaseName()

    def EnumDeviceDrivers(self, arr, size, needed_ref):  # noqa: N802 -- Win32 name
        import ctypes

        for i, b in enumerate(self.bases):
            arr[i] = b
        needed_ref._obj.value = len(self.bases) * ctypes.sizeof(ctypes.c_void_p)
        return 1 if self.ok else 0


class TestEnumDeviceDrivers:
    def _patch(self, mocker, monkeypatch, fake):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "win32")
        mocker.patch("ctypes.WinDLL", return_value=fake, create=True)

    def test_non_windows_is_empty(self, monkeypatch):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "linux")
        assert kernel_cpu.enum_device_drivers() == []

    def test_sorted_names_zero_bases_dropped(self, mocker, monkeypatch):
        self._patch(mocker, monkeypatch, _FakePsapi([0x9000, 0, 0x1000, 0x3000]))
        assert kernel_cpu.enum_device_drivers() == [
            (0x1000, "ntoskrnl.exe"),
            (0x3000, "(unnamed)"),
            (0x9000, "KfeCo11X64.sys"),
        ]

    def test_enum_failure_is_empty(self, mocker, monkeypatch):
        self._patch(mocker, monkeypatch, _FakePsapi([0x1000], ok=False))
        assert kernel_cpu.enum_device_drivers() == []

    def test_psapi_missing_is_empty(self, mocker, monkeypatch):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "win32")
        mocker.patch("ctypes.WinDLL", side_effect=OSError("no psapi"), create=True)
        assert kernel_cpu.enum_device_drivers() == []


@pytest.fixture
def app_dir(tmp_path, monkeypatch):
    """Point kernel_cpu's session files + helper lookup at tmp_path."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "kernel_cpu_elevated.py").write_text("# stub", encoding="utf-8")
    monkeypatch.setattr(kernel_cpu, "APP_DIR", str(tmp_path))
    return tmp_path


class TestRequestIdentify:
    def _shell(self, mocker, rc):
        windll = mocker.MagicMock()
        windll.shell32.ShellExecuteW.return_value = rc
        mocker.patch("ctypes.windll", windll, create=True)
        return windll.shell32.ShellExecuteW

    def test_accepted_prompt_returns_session_and_keeps_request(self, app_dir, mocker):
        shell = self._shell(mocker, 42)
        out = kernel_cpu.request_identify()
        assert out["ok"] is True and kernel_cpu.SESSION_RE.fullmatch(out["session_id"])
        req = json.loads((app_dir / f"kernel_identify_request_{out['session_id']}.json").read_text())
        assert req == {"session_id": out["session_id"], "action": "identify", "seconds": kernel_cpu.IDENTIFY_SECONDS}
        verb, params = shell.call_args[0][1], shell.call_args[0][3]
        assert verb == "runas" and "kernel_cpu_elevated.py" in params and "--request" in params

    def test_declined_prompt_errors_and_removes_request(self, app_dir, mocker):
        self._shell(mocker, 5)
        out = kernel_cpu.request_identify()
        assert out["ok"] is False and "declined" in out["error"]
        assert not list(app_dir.glob("kernel_identify_request_*.json"))

    def test_no_shell32_errors_cleanly(self, app_dir, mocker):
        mocker.patch("ctypes.windll", None, create=True)  # attribute access -> AttributeError
        out = kernel_cpu.request_identify()
        assert out["ok"] is False and "cannot launch" in out["error"]

    def test_missing_helper(self, app_dir):
        (app_dir / "scripts" / "kernel_cpu_elevated.py").unlink()
        assert "not found" in kernel_cpu.request_identify()["error"]

    def test_unwritable_request_file(self, app_dir, mocker):
        mocker.patch("builtins.open", side_effect=OSError("disk full"))
        assert "request file" in kernel_cpu.request_identify()["error"]


class TestIdentifyStatus:
    SID = "0123456789ab"

    @pytest.mark.parametrize("sid", ["", "../../etc", "0123456789AB", "0123456789ab0", "zzzzzzzzzzzz"])
    def test_invalid_session_rejected(self, sid, app_dir):
        assert kernel_cpu.get_identify_status(sid)["error"] == "invalid session_id"

    def test_pending_until_result(self, app_dir):
        assert kernel_cpu.get_identify_status(self.SID)["state"] == "pending"

    def test_done_returns_result_and_cleans_up(self, app_dir):
        (app_dir / f"kernel_identify_request_{self.SID}.json").write_text("{}")
        (app_dir / f"kernel_identify_result_{self.SID}.json").write_text(json.dumps({"ok": True, "rows": []}))
        out = kernel_cpu.get_identify_status(self.SID)
        assert out["state"] == "done" and out["result"]["ok"] is True
        assert not list(app_dir.glob("kernel_identify_*.json"))

    def test_unreadable_result(self, app_dir):
        (app_dir / f"kernel_identify_result_{self.SID}.json").write_text("{not json")
        out = kernel_cpu.get_identify_status(self.SID)
        assert out["state"] == "missing" and "unreadable" in out["error"]


class TestRunIdentify:
    def _patch(self, monkeypatch, buffers, drivers=_DRIVERS, admin=True, debug=True):
        it = iter(buffers)
        monkeypatch.setattr(kernel_cpu, "_query_process_info", lambda: next(it))
        monkeypatch.setattr(kernel_cpu, "enum_device_drivers", lambda: drivers)
        monkeypatch.setattr(kernel_cpu, "is_admin", lambda: admin)
        monkeypatch.setattr(kernel_cpu, "enable_debug_privilege", lambda: debug)

    @pytest.mark.parametrize(
        ("admin", "debug", "phrase"),
        [
            (False, False, "did not run as Administrator"),
            (True, False, "refused the debug privilege"),  # the 2026-10-13 live result, now told apart
            (True, True, "even with Administrator + debug privilege"),
        ],
    )
    def test_hidden_note_says_why(self, monkeypatch, admin, debug, phrase):
        self._patch(
            monkeypatch,
            [_entry_with_starts(4, [(7, 0, 0)]), _entry_with_starts(4, [(7, _TEN_S_PCT, 0)])],
            drivers=[],
            admin=admin,
            debug=debug,
        )
        out = kernel_cpu.run_identify(0, sleep=lambda s: None)
        assert out["named"] is False and phrase in out["note"]
        assert out["admin"] is admin and out["debug_privilege"] is debug

    def test_privilege_enabled_before_drivers_and_threads_are_read(self, monkeypatch):
        order = []
        monkeypatch.setattr(kernel_cpu, "is_admin", lambda: True)
        monkeypatch.setattr(kernel_cpu, "enable_debug_privilege", lambda: order.append("priv") or True)
        monkeypatch.setattr(kernel_cpu, "enum_device_drivers", lambda: order.append("drivers") or _DRIVERS)
        monkeypatch.setattr(kernel_cpu, "_query_process_info", lambda: order.append("threads") or None)
        kernel_cpu.run_identify(0, sleep=lambda s: None)
        assert order[:3] == ["priv", "drivers", "threads"]

    def test_names_the_pinned_driver(self, monkeypatch):
        self._patch(
            monkeypatch,
            [_entry_with_starts(4, [(7, 0, 0x9100)]), _entry_with_starts(4, [(7, 99 * _TEN_S_PCT, 0x9100)])],
        )
        clock = iter([100.0, 110.0])
        monkeypatch.setattr(kernel_cpu.time, "monotonic", lambda: next(clock))
        out = kernel_cpu.run_identify(10, sleep=lambda s: None)
        assert out["ok"] is True and out["named"] is True and out["note"] == ""
        assert out["rows"][0]["driver"] == "KfeCo11X64.sys"
        assert out["rows"][0]["pct"] == 99.0

    def test_hidden_addresses_flagged(self, monkeypatch):
        self._patch(
            monkeypatch,
            [_entry_with_starts(4, [(7, 0, 0)]), _entry_with_starts(4, [(7, _TEN_S_PCT, 0)])],
            drivers=[],
        )
        out = kernel_cpu.run_identify(0, sleep=lambda s: None)
        assert out["named"] is False and "Administrator" in out["note"]

    def test_unreadable_threads(self, monkeypatch):
        self._patch(monkeypatch, [None, None])
        out = kernel_cpu.run_identify(0, sleep=lambda s: None)
        assert out == {"ok": False, "error": "could not read System process threads"}


class _Fn:
    """Win32 function stand-in: callable, and accepts argtypes/restype."""

    def __init__(self, impl):
        self.impl = impl

    def __call__(self, *args):
        return self.impl(*args)


class TestPrivileges:
    def _patch_dlls(self, mocker, monkeypatch, open_ok=1, lookup_ok=1, adjust_ok=1, last_error=0):
        import ctypes
        import types

        closed = []

        def adjust(*_a):
            ctypes.set_last_error(last_error)
            return adjust_ok

        advapi = types.SimpleNamespace(
            OpenProcessToken=_Fn(lambda *_a: open_ok),
            LookupPrivilegeValueW=_Fn(lambda *_a: lookup_ok),
            AdjustTokenPrivileges=_Fn(adjust),
        )
        kernel = types.SimpleNamespace(
            GetCurrentProcess=_Fn(lambda: -1),
            CloseHandle=_Fn(lambda h: closed.append(h) or 1),
        )
        monkeypatch.setattr(kernel_cpu.sys, "platform", "win32")
        mocker.patch(
            "ctypes.WinDLL", side_effect=lambda name, **_kw: advapi if name == "advapi32" else kernel, create=True
        )
        return closed

    def test_enabled_when_adjust_succeeds_cleanly(self, mocker, monkeypatch):
        closed = self._patch_dlls(mocker, monkeypatch)
        assert kernel_cpu.enable_debug_privilege() is True
        assert len(closed) == 1  # token handle always closed

    def test_not_all_assigned_means_not_enabled(self, mocker, monkeypatch):
        # Unelevated: AdjustTokenPrivileges "succeeds" but sets ERROR_NOT_ALL_ASSIGNED.
        self._patch_dlls(mocker, monkeypatch, last_error=1300)
        assert kernel_cpu.enable_debug_privilege() is False

    @pytest.mark.parametrize("field", ["lookup_ok", "adjust_ok"])
    def test_api_failure_is_false_and_closes_token(self, mocker, monkeypatch, field):
        closed = self._patch_dlls(mocker, monkeypatch, **{field: 0})
        assert kernel_cpu.enable_debug_privilege() is False
        assert len(closed) == 1

    def test_open_token_failure(self, mocker, monkeypatch):
        closed = self._patch_dlls(mocker, monkeypatch, open_ok=0)
        assert kernel_cpu.enable_debug_privilege() is False
        assert closed == []

    def test_non_windows_and_missing_dll(self, mocker, monkeypatch):
        monkeypatch.setattr(kernel_cpu.sys, "platform", "linux")
        assert kernel_cpu.enable_debug_privilege() is False
        monkeypatch.setattr(kernel_cpu.sys, "platform", "win32")
        mocker.patch("ctypes.WinDLL", side_effect=OSError("no advapi32"), create=True)
        assert kernel_cpu.enable_debug_privilege() is False

    def test_is_admin(self, mocker):
        windll = mocker.MagicMock()
        windll.shell32.IsUserAnAdmin.return_value = 1
        mocker.patch("ctypes.windll", windll, create=True)
        assert kernel_cpu.is_admin() is True
        mocker.patch("ctypes.windll", None, create=True)
        assert kernel_cpu.is_admin() is False


def _load_helper():
    import importlib.util
    import os

    path = os.path.join(os.path.dirname(kernel_cpu.__file__), "scripts", "kernel_cpu_elevated.py")
    spec = importlib.util.spec_from_file_location("kernel_cpu_elevated", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestElevatedHelper:
    SID = "abcdef012345"

    def _request(self, tmp_path, payload):
        req = tmp_path / "req.json"
        req.write_text(json.dumps(payload) if not isinstance(payload, str) else payload, encoding="utf-8")
        return req

    def test_writes_result_and_removes_request(self, app_dir, tmp_path, monkeypatch):
        helper = _load_helper()
        calls = []
        monkeypatch.setattr(kernel_cpu, "run_identify", lambda s: calls.append(s) or {"ok": True, "rows": []})
        req = self._request(tmp_path, {"session_id": self.SID, "action": "identify", "seconds": 999})
        assert helper.main(["--request", str(req)]) == 0
        assert calls == [helper.MAX_SECONDS]  # clamped
        result = json.loads((app_dir / f"kernel_identify_result_{self.SID}.json").read_text())
        assert result == {"ok": True, "rows": [], "session_id": self.SID}
        assert not req.exists()

    def test_invalid_session_writes_nothing(self, app_dir, tmp_path):
        helper = _load_helper()
        req = self._request(tmp_path, {"session_id": "..\\..\\evil", "action": "identify"})
        assert helper.main(["--request", str(req)]) == 2
        assert not list(app_dir.glob("kernel_identify_result_*.json"))

    def test_unknown_action_reports_error(self, app_dir, tmp_path):
        helper = _load_helper()
        req = self._request(tmp_path, {"session_id": self.SID, "action": "unload_driver"})
        assert helper.main(["--request", str(req)]) == 1
        result = json.loads((app_dir / f"kernel_identify_result_{self.SID}.json").read_text())
        assert "unknown action" in result["error"]

    def test_crash_still_writes_result(self, app_dir, tmp_path, monkeypatch):
        helper = _load_helper()

        def boom(_s):
            raise RuntimeError("psapi exploded")

        monkeypatch.setattr(kernel_cpu, "run_identify", boom)
        req = self._request(tmp_path, {"session_id": self.SID, "action": "identify", "seconds": "x"})
        assert helper.main(["--request", str(req)]) == 1
        result = json.loads((app_dir / f"kernel_identify_result_{self.SID}.json").read_text())
        assert "psapi exploded" in result["error"]

    @pytest.mark.parametrize("payload", ["{not json", "[1, 2]"])
    def test_bad_request_file(self, app_dir, tmp_path, payload):
        helper = _load_helper()
        assert helper.main(["--request", str(self._request(tmp_path, payload))]) == 2

    def test_result_write_failure_is_swallowed(self, app_dir, monkeypatch):
        helper = _load_helper()
        monkeypatch.setattr(helper.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("locked")))
        helper._write_result(self.SID, {"ok": True})  # must not raise
        assert not list(app_dir.glob("kernel_identify_result_*"))


class TestIdentifyRoutes:
    def test_launch_ok(self, client, mocker):
        mocker.patch.object(kernel_cpu, "request_identify", return_value={"ok": True, "session_id": "0123456789ab"})
        resp = client.post("/api/thermals/kernel/identify")
        assert resp.status_code == 200 and resp.get_json()["session_id"] == "0123456789ab"

    def test_launch_declined_is_502(self, client, mocker):
        mocker.patch.object(kernel_cpu, "request_identify", return_value={"ok": False, "error": "declined"})
        assert client.post("/api/thermals/kernel/identify").status_code == 502

    def test_status_requires_session(self, client):
        assert client.get("/api/thermals/kernel/identify/status").status_code == 400

    def test_status_invalid_session_is_400(self, client):
        assert client.get("/api/thermals/kernel/identify/status?session_id=../x").status_code == 400

    def test_status_pending_is_200(self, client, app_dir):
        resp = client.get("/api/thermals/kernel/identify/status?session_id=0123456789ab")
        assert resp.status_code == 200 and resp.get_json()["state"] == "pending"
