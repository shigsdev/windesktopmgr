"""Tests for diagnose_perf_probes: the speed & heat bundle's evidence.

Every OS source (psutil, LHM, the Windows sensors, the GPU reader, the
stuck-driver detector, the event log, the registry, the metrics history) is
replaced, so each test states exactly what Windows would have reported.
"""

from __future__ import annotations

import json
import os
import types

import psutil
import pytest

import diagnose_perf_probes as dpp
import diagnose_probes as dp

GIB = 1024**3


class _Proc:
    """A psutil.Process stand-in with NO shared ``.info``: probes must read
    their fields with ``as_dict`` (``proc.info`` is shared between threads)."""

    calls: list = []

    def __init__(self, fields, gone=False):
        self._fields, self._gone = fields, gone

    def as_dict(self, attrs, ad_value=None):
        _Proc.calls.append(tuple(attrs))
        if self._gone:
            raise psutil.NoSuchProcess(self._fields.get("pid", 0))
        return {a: self._fields.get(a, ad_value) for a in attrs}


def _cpu_proc(pid, name, seconds):
    times = None if seconds is None else types.SimpleNamespace(user=seconds * 0.75, system=seconds * 0.25)
    return _Proc({"pid": pid, "name": name, "cpu_times": times})


def _mem_proc(pid, name, rss_gb, created):
    mem = None if rss_gb is None else types.SimpleNamespace(rss=int(rss_gb * GIB))
    return _Proc({"pid": pid, "name": name, "memory_info": mem, "create_time": created})


@pytest.fixture
def cpu_env(mocker):
    """8 cores, a 3 s sample, and two process snapshots the test fills in."""
    mocker.patch("diagnose_perf_probes.time.sleep")
    mocker.patch("diagnose_perf_probes.psutil.cpu_count", return_value=8)
    mocker.patch(
        "diagnose_perf_probes.psutil.cpu_percent",
        side_effect=lambda interval=None, percpu=False: [10.0, 100.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0] if percpu else 22.5,
    )
    it = mocker.patch("diagnose_perf_probes.psutil.process_iter")

    def load(before, after):
        it.side_effect = [list(before), list(after)]
        return it

    return load


def _chrome_and_code():
    before = [
        _cpu_proc(101, "chrome.exe", 10.0),
        _cpu_proc(102, "chrome.exe", 4.0),
        _cpu_proc(103, "chrome.exe", 2.0),
        _cpu_proc(200, "code.exe", 1.0),
    ]
    after = [
        _cpu_proc(101, "chrome.exe", 16.0),
        _cpu_proc(102, "chrome.exe", 7.0),
        _cpu_proc(103, "chrome.exe", 5.0),
        _cpu_proc(200, "code.exe", 2.2),
    ]
    return before, after


class TestAppMatches:
    @pytest.mark.parametrize(
        ("app_name", "exe", "expected"),
        [
            ("Chrome", "chrome.exe", True),
            ("Microsoft Teams", "ms-teams.exe", True),
            ("google chrome", "chrome.exe", True),
            ("Teams", "chrome.exe", False),
            (None, "chrome.exe", False),
            ("", "x.exe", False),
        ],
    )
    def test_app_matches(self, app_name, exe, expected):
        assert dpp.app_matches(app_name, exe) is expected


class TestCpu:
    def test_cpu_groups_by_name_and_shares_whole_cpu(self, cpu_env):
        cpu_env(*_chrome_and_code())
        data = dpp.REGISTERED["perf.cpu"].fn({})
        assert data["top"][0] == {"name": "chrome.exe", "pid": 101, "count": 3, "cpu_pct": 50.0}
        assert data["top"][1]["name"] == "code.exe"
        assert data["top"][1]["cpu_pct"] == 5.0
        assert data["cores"] == 8
        assert data["busiest_core_pct"] == 100.0
        assert data["total_pct"] == 22.5
        assert data["seconds"] == dpp.CPU_SAMPLE_S

    def test_cpu_excludes_idle(self, cpu_env):
        before, after = _chrome_and_code()
        cpu_env(
            [*before, _cpu_proc(0, "System Idle Process", 0.0), _cpu_proc(5, "Idle", 0.0)],
            [*after, _cpu_proc(0, "System Idle Process", 20.0), _cpu_proc(5, "Idle", 20.0)],
        )
        names = [row["name"] for row in dpp.REGISTERED["perf.cpu"].fn({})["top"]]
        assert "System Idle Process" not in names
        assert "Idle" not in names

    def test_cpu_excludes_own_process(self, cpu_env):
        before, after = _chrome_and_code()
        me = os.getpid()
        cpu_env([*before, _cpu_proc(me, "python.exe", 0.0)], [*after, _cpu_proc(me, "python.exe", 20.0)])
        assert all(row["pid"] != me for row in dpp.REGISTERED["perf.cpu"].fn({})["top"])

    def test_cpu_skips_denied_and_vanished(self, cpu_env):
        before, after = _chrome_and_code()
        cpu_env(
            [*before, _cpu_proc(300, "secure.exe", None), _cpu_proc(400, "gone.exe", 1.0)],
            [*after, _cpu_proc(300, "secure.exe", None), _cpu_proc(500, "new.exe", 9.0)],
        )
        names = [row["name"] for row in dpp.REGISTERED["perf.cpu"].fn({})["top"]]
        assert not {"secure.exe", "gone.exe", "new.exe"} & set(names)

    def test_cpu_caps_top_at_five(self, cpu_env):
        before = [_cpu_proc(i, f"app{i}.exe", 0.0) for i in range(1, 9)]
        after = [_cpu_proc(i, f"app{i}.exe", float(i)) for i in range(1, 9)]
        cpu_env(before, after)
        top = dpp.REGISTERED["perf.cpu"].fn({})["top"]
        assert [row["name"] for row in top] == ["app8.exe", "app7.exe", "app6.exe", "app5.exe", "app4.exe"]

    def test_cpu_focus_app(self, cpu_env):
        cpu_env(*_chrome_and_code())
        data = dpp.REGISTERED["perf.cpu"].fn({"app_name": " Chrome "})
        assert data["focus_app"] == "Chrome"
        assert data["focus"] == {"name": "chrome.exe", "cpu_pct": 50.0, "count": 3}

    def test_cpu_focus_none_without_app(self, cpu_env):
        cpu_env(*_chrome_and_code())
        data = dpp.REGISTERED["perf.cpu"].fn({})
        assert data["focus_app"] is None
        assert data["focus"] is None

    def test_cpu_never_asks_for_identifying_attrs(self, cpu_env, mocker):
        cpu_env(*_chrome_and_code())
        _Proc.calls.clear()
        dpp.REGISTERED["perf.cpu"].fn({})
        assert _Proc.calls
        for attrs in _Proc.calls:
            assert set(attrs) <= dpp.ALLOWED_PROC_ATTRS

    def test_cpu_skips_a_process_that_exits_mid_read(self, cpu_env):
        before, after = _chrome_and_code()
        cpu_env(before, [*after, _Proc({"pid": 900, "name": "gone.exe"}, gone=True)])
        assert dpp.REGISTERED["perf.cpu"].fn({})["top"][0]["name"] == "chrome.exe"


class TestMemory:
    @pytest.fixture
    def mem_env(self, mocker):
        mocker.patch("diagnose_perf_probes.time.time", return_value=1_000_000.0)
        mocker.patch(
            "diagnose_perf_probes.psutil.virtual_memory",
            return_value=types.SimpleNamespace(total=64 * GIB, available=int(1.5 * GIB), percent=97.7),
        )
        mocker.patch("diagnose_perf_probes.psutil.swap_memory", return_value=types.SimpleNamespace(percent=85.0))
        it = mocker.patch("diagnose_perf_probes.psutil.process_iter")
        it.return_value = [
            _mem_proc(10, "Teams.exe", 3.0, 1_000_000.0 - 30 * 3600),
            _mem_proc(11, "Teams.exe", 2.0, 1_000_000.0 - 2 * 3600),
            _mem_proc(12, "code.exe", 1.0, 1_000_000.0 - 3600),
            _mem_proc(13, "locked.exe", None, None),
        ]
        return it

    def test_memory_happy_path(self, mem_env):
        data = dpp.REGISTERED["perf.memory"].fn({})
        assert data["used_pct"] == 97.7
        assert data["available_gb"] == 1.5
        assert data["total_gb"] == 64.0
        assert data["swap_used_pct"] == 85.0
        assert data["top"][0] == {
            "name": "Teams.exe",
            "pid": 10,
            "count": 2,
            "rss_gb": 5.0,
            "running_h": 30.0,
            "max_proc_gb": 3.0,
            "max_proc_h": 30.0,
        }
        assert [row["name"] for row in data["top"]] == ["Teams.exe", "code.exe"]
        assert data["focus"] is None

    def test_memory_focus_app(self, mem_env):
        data = dpp.REGISTERED["perf.memory"].fn({"app_name": "teams"})
        assert data["focus"] == {
            "name": "Teams.exe",
            "rss_gb": 5.0,
            "count": 2,
            "running_h": 30.0,
            "max_proc_gb": 3.0,
            "max_proc_h": 30.0,
        }

    def test_memory_psutil_failure_raises_for_the_engine(self, mocker):
        mocker.patch("diagnose_perf_probes.psutil.virtual_memory", side_effect=OSError("no"))
        with pytest.raises(OSError):
            dpp.REGISTERED["perf.memory"].fn({})

    def test_memory_never_asks_for_identifying_attrs(self, mem_env):
        _Proc.calls.clear()
        dpp.REGISTERED["perf.memory"].fn({})
        assert _Proc.calls
        for attrs in _Proc.calls:
            assert set(attrs) <= dpp.ALLOWED_PROC_ATTRS


class TestRegistry:
    def test_registry_invariants(self):
        assert dpp.REGISTERED
        for key, probe in dpp.REGISTERED.items():
            assert dp.PROBES[key] is probe
            assert key.startswith("perf.")
            assert probe.category == "perf"
            assert probe.redact == ("username", "serial", "mac", "self_host")
            assert 8 <= probe.timeout_s <= 20

    def test_identifying_attrs_are_never_allowed(self):
        assert not {"cmdline", "exe", "cwd", "username", "environ"} & dpp.ALLOWED_PROC_ATTRS

    def test_performance_class_entry(self):
        import diagnose

        c = diagnose.SYMPTOM_CLASSES["performance"]
        assert c["label"] == "Speed & heat"
        assert c["slots"] == ()
        assert c["optional_slots"] == ("app_name",)
        assert c["actions"] == ("reboot_system",)
        assert c["wave1"][:2] == ("perf.cpu", "perf.memory")
        assert c["prompt"]

    def test_stub_rules_say_nothing_found(self):
        import diagnose

        verdict = diagnose.SYMPTOM_CLASSES["performance"]["rules"]({}, None)
        assert verdict["status"] == "inconclusive"
        assert verdict["rule_hits"][0] == "nothing_found"


# ── Task 2: readers of the app's existing monitors ──────────────────────────


def _leaf(text, kind, value, sid):
    return {"Text": text, "Type": kind, "Value": value, "SensorId": sid, "Children": []}


def _group(text, *children):
    return {"Text": text, "Children": list(children)}


def _lhm_tree(distances=True):
    """Trimmed from the live 2026-10-17 LHM tree on this PC."""
    temps = [
        _leaf("Core Max", "Temperature", "51.0 °C", "/intelcpu/0/temperature/0"),
        _leaf("P-Core #1", "Temperature", "41.0 °C", "/intelcpu/0/temperature/2"),
        _leaf("P-Core #5", "Temperature", "50.0 °C", "/intelcpu/0/temperature/6"),
        _leaf("CPU Package", "Temperature", "51.0 °C", "/intelcpu/0/temperature/26"),
    ]
    if distances:
        temps += [
            _leaf("P-Core #1 Distance to TjMax", "Temperature", "59.0 °C", "/intelcpu/0/temperature/27"),
            _leaf("P-Core #5 Distance to TjMax", "Temperature", "49.0 °C", "/intelcpu/0/temperature/31"),
            _leaf("E-Core #1 Distance to TjMax", "Temperature", "58.0 °C", "/intelcpu/0/temperature/35"),
        ]
    cpu = _group(
        "Intel Core i9-14900K",
        _group("Temperatures", *temps),
        _group("Powers", _leaf("CPU Package", "Power", "48.9 W", "/intelcpu/0/power/0")),
        _group(
            "Clocks",
            _leaf("P-Core #1", "Clock", "1394.4 MHz", "/intelcpu/0/clock/1"),
            _leaf("E-Core #1", "Clock", "4400.0 MHz", "/intelcpu/0/clock/9"),
        ),
    )
    gpu = _group(
        "NVIDIA GeForce RTX 4060 Ti",
        _group("Temperatures", _leaf("GPU Core", "Temperature", "45.0 °C", "/gpu-nvidia/0/temperature/0")),
        _group("Fans", _leaf("GPU Fan 1", "Fan", "0 RPM", "/gpu-nvidia/0/fan/1")),
    )
    board = _group("Dell 0XYZ", _group("Fans", _leaf("CPU Fan", "Fan", "1250 RPM", "/lpc/nct6687d/fan/0")))
    return {"Text": "Sensor", "Children": [_group("SHIGS78-PC24", cpu, gpu, board)]}


class TestThermals:
    def test_parse_lhm_cpu_live_shape(self):
        out = dpp.parse_lhm_cpu(_lhm_tree())
        assert out["package_c"] == 51.0
        assert out["core_max_c"] == 51.0
        assert out["min_tjmax_distance_c"] == 49.0
        assert out["tjmax_c"] == 100.0
        assert out["package_w"] == 48.9
        assert out["p_core_mhz"] == 1394.4
        assert out["gpu_temp_c"] == 45.0
        assert {"name": "CPU Fan", "rpm": 1250.0} in out["fans"]

    def test_thermals_lhm_source(self, mocker):
        mocker.patch("diagnose_perf_probes.lhm._fetch_data_json", return_value=_lhm_tree())
        data = dpp.REGISTERED["perf.thermals"].fn({})
        assert data["source"] == "lhm"
        assert data["min_tjmax_distance_c"] == 49.0

    def test_thermals_never_carries_pc_name(self, mocker):
        mocker.patch("diagnose_perf_probes.lhm._fetch_data_json", return_value=_lhm_tree())
        assert "SHIGS78-PC24" not in json.dumps(dpp.REGISTERED["perf.thermals"].fn({}))

    def test_thermals_no_distance_sensors(self):
        out = dpp.parse_lhm_cpu(_lhm_tree(distances=False))
        assert out["min_tjmax_distance_c"] is None
        assert out["tjmax_c"] is None
        assert out["core_max_c"] == 51.0

    def test_thermals_windows_fallback(self, mocker):
        mocker.patch("diagnose_perf_probes.lhm._fetch_data_json", return_value=None)
        mocker.patch(
            "diagnose_perf_probes.thermals.get_thermals",
            return_value={
                "temps": [{"Name": "TZ00", "TempC": 88.0}, {"Name": "TZ01", "TempC": 61.0}],
                "fans": [{"Name": "Fan 1", "DesiredSpeed": 1800}],
            },
        )
        data = dpp.REGISTERED["perf.thermals"].fn({})
        assert data["source"] == "windows"
        assert data["core_max_c"] == 88.0
        assert data["min_tjmax_distance_c"] is None
        assert data["fans"] == [{"name": "Fan 1", "rpm": 1800.0}]

    def test_thermals_none_when_both_fail(self, mocker):
        mocker.patch("diagnose_perf_probes.lhm._fetch_data_json", return_value=None)
        mocker.patch("diagnose_perf_probes.thermals.get_thermals", side_effect=RuntimeError("wmi wedged"))
        data = dpp.REGISTERED["perf.thermals"].fn({})
        assert data["source"] == "none"
        assert data["core_max_c"] is None

    @pytest.mark.parametrize("tree", [None, [], {"Children": "x"}, "garbage"])
    def test_parse_lhm_cpu_malformed(self, tree):
        out = dpp.parse_lhm_cpu(tree)
        assert out["core_max_c"] is None
        assert out["fans"] == []

    def test_parse_lhm_cpu_depth_cap(self):
        node = _leaf("CPU Package", "Temperature", "99.0 °C", "/intelcpu/0/temperature/26")
        for _ in range(70):
            node = _group("x", node)
        assert dpp.parse_lhm_cpu(node)["package_c"] is None


class TestGpu:
    def test_gpu_maps_utilization(self, mocker):
        mocker.patch(
            "diagnose_perf_probes.gpu.get_gpu_metrics",
            return_value={
                "available": True,
                "name": "RTX 4060 Ti",
                "utilization_pct": 97,
                "temp_c": 70,
                "vram_pct": 40,
            },
        )
        assert dpp.REGISTERED["perf.gpu"].fn({}) == {
            "available": True,
            "name": "RTX 4060 Ti",
            "util_pct": 97,
            "temp_c": 70,
            "vram_pct": 40,
        }

    def test_gpu_reader_failure(self, mocker):
        mocker.patch("diagnose_perf_probes.gpu.get_gpu_metrics", side_effect=RuntimeError("nvidia-smi gone"))
        data = dpp.REGISTERED["perf.gpu"].fn({})
        assert data["available"] is False
        assert data["util_pct"] is None


class TestKernel:
    def test_kernel_stuck_passthrough(self, mocker):
        mocker.patch(
            "diagnose_perf_probes.kernel_cpu.sample",
            return_value={
                "available": True,
                "busiest": {"tid": 8, "pct": 96.0},
                "stuck": [{"tid": 8, "pct": 96.0, "minutes": 12.0}],
            },
        )
        data = dpp.REGISTERED["perf.kernel"].fn({})
        assert data["available"] is True
        assert data["warming_up"] is False
        assert data["stuck"] == [{"tid": 8, "pct": 96.0, "minutes": 12.0}]

    def test_kernel_warming_up(self, mocker):
        mocker.patch(
            "diagnose_perf_probes.kernel_cpu.sample",
            return_value={"available": False, "reason": "warming up", "warming_up": True},
        )
        data = dpp.REGISTERED["perf.kernel"].fn({})
        assert data == {"available": False, "warming_up": True, "busiest": None, "stuck": []}


class TestDiskBusy:
    def test_disk_busy_names_drives(self, mocker):
        sample = mocker.patch(
            "diagnose_perf_probes.dsp._io_sample",
            return_value={
                "seconds": 3,
                "disks": [{"disk_number": 0, "busy_pct": 100}, {"disk_number": 9, "busy_pct": 4}],
            },
        )
        mocker.patch(
            "diagnose_perf_probes.dsp.collect_physical_disks",
            return_value={
                "drives": [
                    {
                        "disk_number": 0,
                        "model": "Samsung SSD 990 PRO 2TB",
                        "slot": "M.2 slot 1",
                        "label_serial_tail": "5B40",
                    }
                ]
            },
        )
        data = dpp.REGISTERED["perf.disk_busy"].fn({})
        sample.assert_called_once_with(3)
        assert "…5B40" in data["disks"][0]["name"]
        assert data["disks"][1]["name"] == "Disk 9"


class TestHwErrors:
    def test_hw_errors_counts(self, mocker):
        whea = mocker.patch(
            "diagnose_perf_probes.dcp._p_whea",
            return_value={
                "fatal": 0,
                "corrected": 110,
                "by_component": {"processor": 110, "memory": 0, "pcie": 0, "other": 0},
                "first": "2026-10-13T09:00:00Z",
                "last": "2026-10-17T11:00:00Z",
            },
        )
        data = dpp.REGISTERED["perf.hw_errors"].fn({})
        assert whea.call_args.kwargs["days"] == 7
        assert data == {
            "processor": 110,
            "memory": 0,
            "pcie": 0,
            "fatal": 0,
            "corrected": 110,
            "last": "2026-10-17T11:00:00Z",
        }


# ── Task 3: history, startup, power plan, escalations ───────────────────────

NOW = 1_800_000_000.0


class TestSinceBoot:
    def test_since_boot_memory_movement(self, mocker):
        mocker.patch("diagnose_perf_probes.time.time", return_value=NOW)
        mocker.patch("diagnose_perf_probes.psutil.boot_time", return_value=NOW - 96 * 3600)
        series = {
            "memory_percent": [{"ts": "a", "value": 40.0}, {"ts": "b", "value": 60.0}, {"ts": "c", "value": 85.0}],
            "cpu_temp_c": [{"ts": "a", "value": 70.0}, {"ts": "b", "value": 99.0}],
        }
        get = mocker.patch(
            "diagnose_perf_probes.metrics_history.get_series", side_effect=lambda metric, window: series[metric]
        )
        data = dpp.REGISTERED["perf.since_boot"].fn({})
        assert data["uptime_h"] == 96.0
        assert data["memory_first_pct"] == 40.0
        assert data["memory_now_pct"] == 85.0
        assert data["temp_max_c"] == 99.0
        assert data["samples"] == 3
        assert data["boot"].endswith("Z")
        assert abs(get.call_args.kwargs["window"].total_seconds() - 96 * 3600) < 5

    def test_since_boot_empty_history(self, mocker):
        mocker.patch("diagnose_perf_probes.time.time", return_value=NOW)
        mocker.patch("diagnose_perf_probes.psutil.boot_time", return_value=NOW - 3600)
        mocker.patch("diagnose_perf_probes.metrics_history.get_series", return_value=[])
        data = dpp.REGISTERED["perf.since_boot"].fn({})
        assert data["samples"] == 0
        assert data["memory_first_pct"] is None
        assert data["memory_now_pct"] is None
        assert data["temp_max_c"] is None
        assert data["uptime_h"] == 1.0


class TestStartup:
    def test_pair_startups_live_shape(self):
        rows = dpp.pair_startups(
            ["2026-10-16T12:24:48Z", "2026-10-17T12:08:53Z"],
            ["2026-10-16T12:26:14Z", "2026-10-17T12:25:10Z"],
        )
        assert [r["gap_s"] for r in rows] == [977, 86]
        assert rows[0]["boot"] == "2026-10-17T12:08:53Z"

    def test_startup_boot_without_signin_is_skipped(self):
        rows = dpp.pair_startups(["2026-10-16T08:00:00Z", "2026-10-16T09:00:00Z"], ["2026-10-16T09:00:30Z"])
        assert rows == [{"boot": "2026-10-16T09:00:00Z", "signin": "2026-10-16T09:00:30Z", "gap_s": 30}]

    def test_pair_startups_caps_at_five(self):
        boots = [f"2026-10-1{d}T08:00:00Z" for d in range(7)]
        signins = [f"2026-10-1{d}T08:01:00Z" for d in range(7)]
        assert len(dpp.pair_startups(boots, signins)) == 5

    @pytest.fixture
    def events(self, mocker):
        def load(boots, signins, unreadable=False):
            def fake_query(channel, xpath, unavailable=None, **kw):
                if unreadable:
                    if unavailable is not None:
                        unavailable.append(channel)
                    return []
                stamps = signins if "7001" in xpath else boots
                return [{"time": t} for t in stamps]

            return mocker.patch("diagnose_perf_probes.dcp._query", side_effect=fake_query)

        return load

    def test_startup_fastest_and_median(self, events, mocker):
        mocker.patch("windesktopmgr.get_startup_items", return_value=[])
        q = events(
            ["2026-10-14T08:00:00Z", "2026-10-15T08:00:00Z", "2026-10-16T08:00:00Z"],
            ["2026-10-14T08:03:10Z", "2026-10-15T08:03:20Z", "2026-10-16T08:06:40Z"],
        )
        data = dpp.REGISTERED["perf.startup"].fn({})
        assert data["fastest_gap_s"] == 190
        assert data["median_gap_s"] == 200
        assert data["last_gap_s"] == 400
        xpaths = " ".join(c.args[1] for c in q.call_args_list)
        assert "Microsoft-Windows-Kernel-General" in xpaths
        assert "Microsoft-Windows-Winlogon" in xpaths

    def test_startup_names_only(self, events, mocker):
        events([], [])
        mocker.patch(
            "windesktopmgr.get_startup_items",
            return_value=[
                {"Name": "OneDrive", "Command": "C:\\Users\\higs7\\OneDrive.exe /background", "Enabled": True},
                {"Name": "Spotify", "Command": "C:\\Users\\higs7\\Spotify.exe", "Enabled": False},
            ],
        )
        data = dpp.REGISTERED["perf.startup"].fn({})
        assert data["startup_programs"] == 1
        assert data["program_names"] == ["OneDrive"]
        assert "higs7" not in json.dumps(data)

    def test_startup_names_drop_account_sid(self, events, mocker):
        events([], [])
        mocker.patch(
            "windesktopmgr.get_startup_items",
            return_value=[
                {
                    "Name": "OneDrive Standalone Update Task-S-1-5-21-1234567890-2345678901-3456789012-1001",
                    "Enabled": True,
                }
            ],
        )
        names = dpp.REGISTERED["perf.startup"].fn({})["program_names"]
        assert names == ["OneDrive Standalone Update Task"]

    def test_startup_unreadable_log(self, events, mocker):
        mocker.patch("windesktopmgr.get_startup_items", side_effect=OSError("no"))
        events([], [], unreadable=True)
        data = dpp.REGISTERED["perf.startup"].fn({})
        assert data["fastest_gap_s"] is None
        assert data["median_gap_s"] is None
        assert data["boots"] == []
        assert "System" in data["unavailable"]
        assert data["startup_programs"] is None


class TestPowerPlan:
    @pytest.mark.parametrize(
        ("guid", "name"),
        [
            ("381b4222-f694-41f0-9685-ff5bb260df2e", "Balanced"),
            ("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "High performance"),
            ("a1841308-3541-4fab-bc81-f71556f20b4a", "Power saver"),
            ("E9A42B02-D5DF-448D-AA00-03F14749EB61", "Ultimate performance"),
            ("12345678-0000-0000-0000-000000000000", "Custom"),
        ],
    )
    def test_power_plan_known_and_custom(self, mocker, guid, name):
        mocker.patch("diagnose_perf_probes.winreg.OpenKey")
        mocker.patch("diagnose_perf_probes.winreg.QueryValueEx", return_value=(guid, 1))
        assert dpp.REGISTERED["perf.power_plan"].fn({}) == {"scheme_guid": guid.lower(), "name": name}

    def test_power_plan_unreadable(self, mocker):
        mocker.patch("diagnose_perf_probes.winreg.OpenKey", side_effect=OSError("denied"))
        assert dpp.REGISTERED["perf.power_plan"].fn({}) == {"scheme_guid": None, "name": "Unknown"}


class TestEscalation:
    def test_cpu_long_uses_15s(self, mocker):
        sample = mocker.patch("diagnose_perf_probes.cpu_sample", return_value={"seconds": 15, "top": [], "_all": []})
        data = dpp.REGISTERED["perf.cpu_long"].fn({})
        sample.assert_called_once_with(15)
        assert "_all" not in data

    def _groups(self, mocker):
        mocker.patch(
            "diagnose_perf_probes.cpu_sample",
            side_effect=lambda seconds: {
                "seconds": seconds,
                "top": [{"name": "chrome.exe", "pid": 1, "count": 4, "cpu_pct": 30.0}],
                "_all": [
                    {"name": "chrome.exe", "pid": 1, "count": 4, "cpu_pct": 30.0},
                    {"name": "Teams.exe", "pid": 9, "count": 2, "cpu_pct": 2.5},
                ],
            },
        )
        mocker.patch(
            "diagnose_perf_probes._memory_groups",
            return_value=[
                {"name": "chrome.exe", "pid": 1, "count": 4, "rss_gb": 3.0, "running_h": 5.0, "_rss": 3 * GIB},
                {"name": "Teams.exe", "pid": 9, "count": 2, "rss_gb": 1.5, "running_h": 30.0, "_rss": int(1.5 * GIB)},
            ],
        )

    def test_app_detail_matches_named_app(self, mocker):
        self._groups(mocker)
        data = dpp.REGISTERED["perf.app_detail"].fn({"app_name": "Teams"})
        assert data == {
            "app": "Teams",
            "matched": 2,
            "cpu_pct": 2.5,
            "rss_gb": 1.5,
            "running_h": 30.0,
            "children": 1,
        }

    def test_app_detail_defaults_to_top_cpu_app(self, mocker):
        self._groups(mocker)
        data = dpp.REGISTERED["perf.app_detail"].fn({})
        assert data["app"] == "chrome.exe"
        assert data["matched"] == 4
        assert data["children"] == 3

    def test_app_detail_no_match(self, mocker):
        self._groups(mocker)
        data = dpp.REGISTERED["perf.app_detail"].fn({"app_name": "Photoshop"})
        assert data["matched"] == 0
        assert data["cpu_pct"] is None

    def test_trend_daily_max_median(self, mocker):
        series = {
            "memory_percent": [
                {"ts": "2026-10-16T08:00:00", "value": 40.0},
                {"ts": "2026-10-16T12:00:00", "value": 60.0},
                {"ts": "2026-10-16T18:00:00", "value": 90.0},
                {"ts": "2026-10-17T08:00:00", "value": 50.0},
            ],
            "cpu_percent": [],
            "cpu_temp_c": [{"ts": "2026-10-17T08:00:00", "value": 99.0}],
        }
        get = mocker.patch(
            "diagnose_perf_probes.metrics_history.get_series", side_effect=lambda metric, window: series[metric]
        )
        data = dpp.REGISTERED["perf.trend_7d"].fn({})
        assert data["memory_percent"] == [
            {"day": "2026-10-16", "max": 90.0, "median": 60.0},
            {"day": "2026-10-17", "max": 50.0, "median": 50.0},
        ]
        assert data["cpu_percent"] == []
        assert data["cpu_temp_c"] == [{"day": "2026-10-17", "max": 99.0, "median": 99.0}]
        assert get.call_args.kwargs["window"].days == 7


def test_wave1_and_escalate_complete():
    import diagnose

    c = diagnose.SYMPTOM_CLASSES["performance"]
    assert c["wave1"] == (
        "perf.cpu",
        "perf.memory",
        "perf.thermals",
        "perf.gpu",
        "perf.kernel",
        "perf.disk_busy",
        "perf.since_boot",
        "perf.startup",
        "perf.power_plan",
        "perf.hw_errors",
    )
    assert c["escalate"] == ("perf.cpu_long", "perf.app_detail", "perf.trend_7d")
