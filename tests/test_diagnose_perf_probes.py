"""Tests for diagnose_perf_probes: the speed & heat bundle's evidence.

Every OS source (psutil, LHM, the Windows sensors, the GPU reader, the
stuck-driver detector, the event log, the registry, the metrics history) is
replaced, so each test states exactly what Windows would have reported.
"""

from __future__ import annotations

import os
import types

import pytest

import diagnose_perf_probes as dpp
import diagnose_probes as dp

GIB = 1024**3


def _cpu_proc(pid, name, seconds):
    times = None if seconds is None else types.SimpleNamespace(user=seconds * 0.75, system=seconds * 0.25)
    return types.SimpleNamespace(info={"pid": pid, "name": name, "cpu_times": times})


def _mem_proc(pid, name, rss_gb, created):
    mem = None if rss_gb is None else types.SimpleNamespace(rss=int(rss_gb * GIB))
    return types.SimpleNamespace(info={"pid": pid, "name": name, "memory_info": mem, "create_time": created})


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
        it = cpu_env(*_chrome_and_code())
        dpp.REGISTERED["perf.cpu"].fn({})
        for call in it.call_args_list:
            attrs = call.kwargs.get("attrs") or (call.args[0] if call.args else [])
            assert set(attrs) <= dpp.ALLOWED_PROC_ATTRS


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
        assert data["top"][0] == {"name": "Teams.exe", "pid": 10, "count": 2, "rss_gb": 5.0, "running_h": 30.0}
        assert [row["name"] for row in data["top"]] == ["Teams.exe", "code.exe"]
        assert data["focus"] is None

    def test_memory_focus_app(self, mem_env):
        data = dpp.REGISTERED["perf.memory"].fn({"app_name": "teams"})
        assert data["focus"] == {"name": "Teams.exe", "rss_gb": 5.0, "count": 2, "running_h": 30.0}

    def test_memory_psutil_failure_raises_for_the_engine(self, mocker):
        mocker.patch("diagnose_perf_probes.psutil.virtual_memory", side_effect=OSError("no"))
        with pytest.raises(OSError):
            dpp.REGISTERED["perf.memory"].fn({})

    def test_memory_never_asks_for_identifying_attrs(self, mem_env):
        dpp.REGISTERED["perf.memory"].fn({})
        for call in mem_env.call_args_list:
            attrs = call.kwargs.get("attrs") or (call.args[0] if call.args else [])
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
