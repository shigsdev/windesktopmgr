"""Tests for diagnose_perf_rules: the speed & heat class's evidence-only verdicts.

Evidence starts from the recorded idle baseline of this PC (2026-10-17) and
each test changes only the readings it is about.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

import diagnose
import diagnose_perf_rules as dpr

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "diagnose"
_IDLE = json.loads((FIXTURE_DIR / "perf_idle_2026_10_17.json").read_text(encoding="utf-8"))["evidence"]
PERF_FIXTURES = sorted(FIXTURE_DIR.glob("perf_*.json"))


def _ev(**over):
    """The idle baseline with ``over = {"perf_thermals": {...}}`` merged in
    (underscores stand for the dot in the probe key)."""
    ev = copy.deepcopy(_IDLE)
    for name, fields in over.items():
        ev[name.replace("_", ".", 1)]["data"].update(fields)
    return ev


def _rule(ev):
    return dpr.evaluate_perf_rules(ev)["rule_hits"][0]


def _top(name, pct):
    return {"top": [{"name": name, "pid": 1, "count": 1, "cpu_pct": pct}]}


class TestBoundaries:
    @pytest.mark.parametrize(("distance", "rule"), [(2.0, "thermal_throttling"), (3.0, "nothing_found")])
    def test_throttle_distance(self, distance, rule):
        assert _rule(_ev(perf_thermals={"min_tjmax_distance_c": distance})) == rule

    @pytest.mark.parametrize(("temp", "rule"), [(90.0, "running_hot"), (89.9, "nothing_found")])
    def test_cpu_hot(self, temp, rule):
        assert _rule(_ev(perf_thermals={"core_max_c": temp, "package_c": temp})) == rule

    @pytest.mark.parametrize(("temp", "rule"), [(87, "running_hot"), (86.9, "nothing_found")])
    def test_gpu_hot(self, temp, rule):
        assert _rule(_ev(perf_gpu={"temp_c": temp}, perf_thermals={"gpu_temp_c": temp})) == rule

    @pytest.mark.parametrize(("pct", "rule"), [(50.0, "cpu_hog"), (49.9, "nothing_found")])
    def test_hog_share(self, pct, rule):
        assert _rule(_ev(perf_cpu=_top("chrome.exe", pct))) == rule

    @pytest.mark.parametrize(("total", "rule"), [(90.0, "cpu_hog"), (89.9, "nothing_found")])
    def test_hog_busy_total(self, total, rule):
        assert _rule(_ev(perf_cpu={"total_pct": total, **_top("chrome.exe", 25.0)})) == rule

    @pytest.mark.parametrize(
        ("fields", "rule"),
        [
            ({"used_pct": 90.0}, "memory_low"),
            ({"used_pct": 89.9}, "nothing_found"),
            ({"available_gb": 1.99}, "memory_low"),
            ({"available_gb": 2.0}, "nothing_found"),
            ({"swap_used_pct": 80.0}, "memory_low"),
            ({"swap_used_pct": 79.9}, "nothing_found"),
        ],
    )
    def test_memory_low(self, fields, rule):
        assert _rule(_ev(perf_memory=fields)) == rule

    @pytest.mark.parametrize(
        ("since", "rule"),
        [
            ({"uptime_h": 48.0, "memory_first_pct": 30.0, "memory_now_pct": 55.0}, "memory_creep"),
            ({"uptime_h": 47.9, "memory_first_pct": 30.0, "memory_now_pct": 55.0}, "nothing_found"),
            ({"uptime_h": 48.0, "memory_first_pct": 30.0, "memory_now_pct": 54.9}, "nothing_found"),
        ],
    )
    def test_memory_creep_since_boot(self, since, rule):
        assert _rule(_ev(perf_since_boot=since)) == rule

    @pytest.mark.parametrize(("hours", "rule"), [(24.0, "memory_creep"), (23.9, "nothing_found")])
    def test_memory_creep_one_app(self, hours, rule):
        top = [
            {
                "name": "Teams.exe",
                "pid": 2,
                "count": 2,
                "rss_gb": 4.5,
                "running_h": 40.0,
                "max_proc_gb": 4.0,
                "max_proc_h": hours,
            }
        ]
        assert _rule(_ev(perf_memory={"top": top})) == rule

    def test_many_small_processes_are_not_a_leak(self):
        """Final review #1: 29 python.exe processes summing 7.8 GB after a day is not one app leaking."""
        top = [
            {
                "name": "python.exe",
                "pid": 3,
                "count": 29,
                "rss_gb": 7.8,
                "running_h": 26.0,
                "max_proc_gb": 0.8,
                "max_proc_h": 2.0,
            },
            {
                "name": "svchost.exe",
                "pid": 4,
                "count": 103,
                "rss_gb": 1.8,
                "running_h": 26.0,
                "max_proc_gb": 0.2,
                "max_proc_h": 26.0,
            },
        ]
        assert _rule(_ev(perf_memory={"top": top})) == "nothing_found"

    def test_system_processes_never_leak(self):
        top = [
            {
                "name": "svchost.exe",
                "pid": 4,
                "count": 1,
                "rss_gb": 5.0,
                "running_h": 90.0,
                "max_proc_gb": 5.0,
                "max_proc_h": 90.0,
            }
        ]
        assert _rule(_ev(perf_memory={"top": top})) == "nothing_found"

    @pytest.mark.parametrize(("share", "rule"), [(3.0, "cpu_hog"), (2.8, "nothing_found")])
    def test_one_core_runaway(self, share, rule):
        """Final review #4: on 32 threads one pinned core is ~3% of the whole CPU."""
        ev = _ev(perf_cpu={"cores": 32, "busiest_core_pct": 100.0, **_top("python.exe", share)})
        assert _rule(ev) == rule

    def test_one_core_runaway_headline(self):
        ev = _ev(perf_cpu={"cores": 32, "busiest_core_pct": 100.0, **_top("python.exe", 3.1)})
        assert dpr.evaluate_perf_rules(ev)["headline"] == "python.exe is keeping one CPU core fully busy"

    def test_one_core_needs_a_busy_core(self):
        ev = _ev(perf_cpu={"cores": 32, "busiest_core_pct": 60.0, **_top("python.exe", 3.1)})
        assert _rule(ev) == "nothing_found"

    @pytest.mark.parametrize(("busy", "rule"), [(90, "disk_busy"), (89, "nothing_found")])
    def test_disk_busy(self, busy, rule):
        disk = dict(_IDLE["perf.disk_busy"]["data"]["disks"][0], busy_pct=busy)
        assert _rule(_ev(perf_disk_busy={"disks": [disk]})) == rule

    @pytest.mark.parametrize(("util", "rule"), [(95, "gpu_busy"), (94, "nothing_found")])
    def test_gpu_busy(self, util, rule):
        assert _rule(_ev(perf_gpu={"util_pct": util})) == rule

    @pytest.mark.parametrize(
        ("startup", "rule"),
        [
            ({"fastest_gap_s": 121, "median_gap_s": 130, "last_gap_s": 125}, "slow_startup"),
            ({"fastest_gap_s": 120, "median_gap_s": 130, "last_gap_s": 125}, "nothing_found"),
            # One long gap is someone away from the sign-in screen, not a slow startup.
            ({"fastest_gap_s": 30, "median_gap_s": 40, "last_gap_s": 977}, "nothing_found"),
        ],
    )
    def test_slow_startup(self, startup, rule):
        assert _rule(_ev(perf_startup=startup)) == rule

    @pytest.mark.parametrize(("hours", "rule"), [(168.0, "long_uptime"), (167.9, "nothing_found")])
    def test_long_uptime(self, hours, rule):
        assert _rule(_ev(perf_since_boot={"uptime_h": hours})) == rule

    def test_power_saver(self):
        assert _rule(_ev(perf_power_plan={"name": "Power saver"})) == "power_saver"


class TestVerdicts:
    def test_order_hardware_risk_first(self):
        ev = _ev(perf_thermals={"min_tjmax_distance_c": 0.0, "core_max_c": 100.0}, perf_cpu=_top("chrome.exe", 80.0))
        assert _rule(ev) == "thermal_throttling"

    def test_throttling_headline_and_status(self):
        v = dpr.evaluate_perf_rules(_ev(perf_thermals={"min_tjmax_distance_c": 0.0, "core_max_c": 100.0}))
        assert v["headline"] == "Your CPU hit 100 °C and is slowing itself down to cool off"
        assert (v["status"], v["locus"]) == ("confident", "local")

    def test_no_distance_never_throttles(self):
        ev = _ev(perf_thermals={"min_tjmax_distance_c": None, "tjmax_c": None, "core_max_c": 95.0})
        assert _rule(ev) == "running_hot"

    def test_running_hot_gpu_wording(self):
        v = dpr.evaluate_perf_rules(_ev(perf_gpu={"temp_c": 88}, perf_thermals={"gpu_temp_c": 88.0}))
        assert v["headline"] == "Your graphics card is running hot (88 °C)"

    def test_cpu_hog_names_app(self):
        v = dpr.evaluate_perf_rules(_ev(perf_cpu=_top("chrome.exe", 50.0)))
        assert v["headline"] == "chrome.exe is using 50% of the CPU"
        assert any("chrome.exe" in s for s in v["manual_steps"])

    def test_memory_low_names_biggest_app(self):
        top = [{"name": "chrome.exe", "pid": 1, "count": 40, "rss_gb": 21.5, "running_h": 6.0}]
        v = dpr.evaluate_perf_rules(_ev(perf_memory={"used_pct": 94.0, "top": top}))
        assert v["headline"] == "Memory is nearly full (94%); chrome.exe is using 21.5 GB"

    def test_memory_creep_headline(self):
        v = dpr.evaluate_perf_rules(
            _ev(perf_since_boot={"uptime_h": 96.0, "memory_first_pct": 40.0, "memory_now_pct": 85.0})
        )
        assert v["headline"] == "Memory has crept from 40% to 85% over the 4 days since the last restart"

    def test_focus_app_leads_with_also(self):
        focus = {
            "name": "ms-teams.exe",
            "rss_gb": 6.0,
            "count": 3,
            "running_h": 30.0,
            "max_proc_gb": 6.0,
            "max_proc_h": 30.0,
        }
        ev = _ev(
            perf_cpu={"focus_app": "Teams", "focus": {"name": "ms-teams.exe", "cpu_pct": 1.0, "count": 3}},
            perf_memory={"focus": focus},
            perf_thermals={"min_tjmax_distance_c": 1.0, "core_max_c": 99.0},
        )
        v = dpr.evaluate_perf_rules(ev)
        assert v["rule_hits"][0] == "memory_creep"
        assert "ms-teams.exe" in v["headline"]
        assert "also_thermal_throttling" in v["rule_hits"]
        assert "Also:" in v["reasoning"]

    def test_focus_app_quiet_falls_back_to_whole_pc(self):
        ev = _ev(
            perf_cpu={"focus_app": "Teams", "focus": {"name": "ms-teams.exe", "cpu_pct": 1.0, "count": 3}},
            perf_power_plan={"name": "Power saver"},
        )
        assert _rule(ev) == "power_saver"

    def test_hw_errors_annotation(self):
        v = dpr.evaluate_perf_rules(
            _ev(perf_thermals={"min_tjmax_distance_c": 0.0, "core_max_c": 100.0}, perf_hw_errors={"processor": 110})
        )
        assert "hw_errors" in v["rule_hits"]
        assert "Windows also logged 110 processor hardware errors this week" in v["reasoning"]

    def test_hw_errors_noted_even_when_nothing_found(self):
        v = dpr.evaluate_perf_rules(_ev(perf_hw_errors={"processor": 105}))
        assert v["rule_hits"][:2] == ["nothing_found", "hw_errors"]

    def test_sensors_fallback_annotation(self):
        v = dpr.evaluate_perf_rules(_ev(perf_thermals={"source": "windows"}, perf_power_plan={"name": "Power saver"}))
        assert "sensors_fallback" in v["rule_hits"]
        assert "LibreHardwareMonitor" in v["reasoning"]

    def test_nothing_found_lists_unread(self):
        ev = _ev()
        ev["perf.gpu"] = {"key": "perf.gpu", "ok": False, "error": "timed out after 10s"}
        v = dpr.evaluate_perf_rules(ev)
        assert (v["status"], v["locus"]) == ("inconclusive", "unknown")
        assert v["headline"] == "Nothing is slowing the PC down right now"
        assert "perf.gpu" in v["reasoning"]

    def test_empty_evidence_is_a_full_verdict(self):
        v = dpr.evaluate_perf_rules({})
        assert v["rule_hits"][0] == "nothing_found"
        assert v["suggested_actions"] == []


@pytest.mark.parametrize("path", PERF_FIXTURES, ids=lambda p: p.stem)
def test_reboot_only_for_creep_and_uptime(path):
    v = dpr.evaluate_perf_rules(json.loads(path.read_text(encoding="utf-8"))["evidence"])
    assert set(v["suggested_actions"]) <= {"reboot_system"}
    assert bool(v["suggested_actions"]) == (v["rule_hits"][0] in ("memory_creep", "long_uptime"))


@pytest.mark.parametrize("path", PERF_FIXTURES, ids=lambda p: p.stem)
def test_steps_capped_and_never_drastic(path):
    v = dpr.evaluate_perf_rules(json.loads(path.read_text(encoding="utf-8"))["evidence"])
    assert len(v["manual_steps"]) <= diagnose.MAX_MANUAL_STEPS
    for step in v["manual_steps"]:
        assert not re.search(r"taskkill|end task|bios|overclock", step, re.IGNORECASE), step


class TestPerfClassifier:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Chrome is slow", "Chrome"),
            ("Microsoft Teams is laggy", "Microsoft Teams"),
            ("Teams is eating my RAM", "Teams"),
            ("Photoshop is using all my memory", "Photoshop"),
            ("Chrome is really slow", "Chrome"),
            ("my computer is slow", None),
            ("my PC is slow and running hot", None),
            ("the fans are hot", None),
            ("Word and Excel are slow", None),
            ("everything is slow", None),
            ("my PC got hot", None),
            ("my computer gets hot", None),
            ("my PC runs hot", None),
            ("the CPU gets very hot", None),
            ("my PC is extremely slow", None),
            ("it gets really hot when gaming", None),
            ("my PC rebooted itself when it got hot", None),
            ("Spotify gets really slow", "Spotify"),
            ("", None),
        ],
    )
    def test_extract_perf_app(self, text, expected):
        assert dpr.extract_perf_app(text) == expected

    @pytest.mark.parametrize(
        ("text", "kind"),
        [
            ("it overheats", "strong"),
            ("the CPU is throttling", "strong"),
            ("high cpu", "strong"),
            ("out of memory", "strong"),
            ("loud fans", "strong"),
            ("fans keep spinning up", "strong"),
            ("slow boot", "strong"),
            ("it's sluggish", "weak"),
            ("games stutter", "weak"),
            ("video is lagging", "weak"),
            ("clear the temp folder", None),
            ("I'm a fan of this app", None),
            ("hotspot won't connect", None),
        ],
    )
    def test_perf_strength(self, text, kind):
        assert dpr.perf_strength(text) == kind
