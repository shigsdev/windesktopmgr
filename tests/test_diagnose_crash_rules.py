"""Tests for diagnose_crash_rules: the crash bundle's evidence-only verdicts.

Scenario-level coverage lives in tests/fixtures/diagnose/crash_*.json (run by
test_diagnose.TestRuleFixtures); these tests pin the thresholds, the order
of the rules, the context lines and the time wording.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import diagnose_crash_rules as dcr

FIXTURES = Path(__file__).parent / "fixtures" / "diagnose"
EDT = timezone(timedelta(hours=-4))


def fixture_evidence(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["evidence"]


def quiet() -> dict:
    return fixture_evidence("crash_nothing_found")


def put(evidence: dict, key: str, data: dict) -> dict:
    evidence[key] = {"key": key, "label": key, "ok": True, "data": data}
    return evidence


def unexpected(time, code=0, button=False, long_press=False):
    return {
        "time": time,
        "bugcheck_code": code,
        "power_button": button,
        "long_press": long_press,
        "sleep_in_progress": False,
    }


def app(name, crashes, system=0, hangs=0, module="m.dll"):
    return {
        "app": name,
        "crashes": crashes,
        "hangs": hangs,
        "last": "2026-10-08T10:00:00Z",
        "modules": [{"module": module, "count": crashes}],
        "exception_codes": [],
        "system_module_crashes": system,
    }


@pytest.fixture
def edt(monkeypatch):
    """Show times as a UTC-4 user sees them (EDT on 2026-10-08)."""
    monkeypatch.setattr(
        dcr,
        "_local",
        lambda ts: datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone(EDT),
    )


def whea(fatal=0, processor=0, memory=0, pcie=0, other=0):
    return {
        "fatal": fatal,
        "corrected": processor + memory + pcie + other - fatal,
        "by_component": {"processor": processor, "memory": memory, "pcie": pcie, "other": other},
        "first": "2026-10-07T10:00:00Z",
        "last": "2026-10-08T10:00:00Z",
    }


class TestOrder:
    def test_whea_beats_bugcheck(self):
        v = dcr.evaluate_crash_rules(fixture_evidence("crash_whea_beats_bugcheck"))
        assert v["rule_hits"][0] == "whea_fatal"
        assert v["headline"] == "Your hardware is reporting errors (processor)"

    def test_bugcheck_beats_hung_shutdown(self):
        ev = fixture_evidence("crash_hung_shutdown_2026_10_08")
        put(ev, "crash.unexpected_shutdowns", {"events": [unexpected("2026-10-09T12:17:51Z", 159)]})
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "bugcheck"

    def test_hung_shutdown_beats_power_loss(self):
        assert (
            dcr.evaluate_crash_rules(fixture_evidence("crash_hung_shutdown_2026_10_08"))["rule_hits"][0]
            == "hung_shutdown"
        )

    def test_power_button_beats_power_loss(self):
        ev = put(
            quiet(),
            "crash.unexpected_shutdowns",
            {"events": [unexpected("2026-10-08T10:00:00Z"), unexpected("2026-10-07T10:00:00Z", button=True)]},
        )
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "power_button"

    def test_whole_pc_failure_beats_app_crashes(self):
        ev = put(quiet(), "crash.unexpected_shutdowns", {"events": [unexpected("2026-10-08T10:00:00Z")]})
        put(ev, "crash.app_crashes", {"named": None, "apps": [app("chrome.exe", 9)]})
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "power_loss_or_freeze"


class TestThresholds:
    def test_nine_corrected_on_one_component_is_not_enough(self):
        ev = put(quiet(), "crash.whea", whea(memory=9))
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "nothing_found"

    def test_ten_corrected_on_one_component_fires(self):
        v = dcr.evaluate_crash_rules(put(quiet(), "crash.whea", whea(memory=10)))
        assert v["rule_hits"][0] == "whea_fatal"
        assert v["headline"] == "Your hardware is reporting errors (memory)"

    def test_two_app_failures_are_not_a_pattern(self):
        ev = put(quiet(), "crash.app_crashes", {"named": None, "apps": [app("chrome.exe", 1, hangs=1)]})
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "nothing_found"

    def test_three_app_failures_fire(self):
        v = dcr.evaluate_crash_rules(
            put(
                quiet(),
                "crash.app_crashes",
                {"named": None, "apps": [app("chrome.exe", 2, hangs=1, module="chrome.dll")]},
            )
        )
        assert v["rule_hits"][0] == "app_crash_repeat"
        assert v["headline"] == "chrome.exe keeps crashing in chrome.dll"

    def test_two_failed_boots_31_minutes_apart_do_not_fire(self):
        ev = put(
            quiet(),
            "crash.boot_health",
            {
                "boot_failures": ["2026-10-08T10:31:00Z", "2026-10-08T10:00:00Z"],
                "startup_repair_runs": 0,
                "boot_durations_ms": [],
                "unavailable": [],
            },
        )
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "nothing_found"

    def test_a_startup_repair_run_fires_on_its_own(self):
        ev = put(
            quiet(),
            "crash.boot_health",
            {
                "boot_failures": ["2026-10-08T10:00:00Z"],
                "startup_repair_runs": 1,
                "boot_durations_ms": [],
                "unavailable": [],
            },
        )
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "boot_failure"

    def test_repair_image_needs_three_different_apps_in_system_modules(self):
        two = {"named": None, "apps": [app("a.exe", 5, system=5), app("b.exe", 5, system=5), app("c.exe", 5)]}
        v = dcr.evaluate_crash_rules(put(quiet(), "crash.app_crashes", two))
        assert "system_modules" not in v["rule_hits"]
        assert v["suggested_actions"] == []

    def test_repair_image_never_rides_on_hardware_errors(self):
        ev = fixture_evidence("crash_system_modules_multi_app")
        put(ev, "crash.whea", whea(fatal=1, processor=1))
        v = dcr.evaluate_crash_rules(ev)
        assert v["rule_hits"][0] == "whea_fatal"
        assert v["suggested_actions"] == []


class TestWording:
    def test_hung_shutdown_reasoning_uses_local_times(self, edt):
        """Review Focus 3: 03:37Z is 23:37 for a UTC-4 user, and the BIOS change
        is given as an absolute local time, never 'the day before'."""
        v = dcr.evaluate_crash_rules(fixture_evidence("crash_hung_shutdown_2026_10_08"))
        assert v["headline"] == "The PC got stuck shutting down"
        text = v["reasoning"]
        assert "23:37" in text  # shutdown began
        assert "04:11" in text  # last activity
        assert "04:45" in text  # last alive
        assert "At 11:39 on 2026-10-08, secure_boot changed from enabled to disabled." in text
        assert "the day before" not in text.lower()

    def test_clean_shutdown_then_normal_boot_is_nothing_found(self):
        """Review Focus 2: a shutdown that started and a next boot that logged
        no unexpected shutdown is a normal shutdown."""
        ev = put(
            quiet(),
            "crash.power_timeline",
            {
                "window_days": 7,
                "events": [],
                "unavailable": [],
                "episodes": [
                    {
                        "boot": "2026-10-08T10:00:00Z",
                        "next_boot": "2026-10-09T08:00:00Z",
                        "shutdown_requested_at": "2026-10-08T20:00:00Z",
                        "shutdown_started_at": "2026-10-08T20:00:01Z",
                        "next_boot_unexpected": False,
                        "last_alive": None,
                    }
                ],
            },
        )
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "nothing_found"

    def test_nothing_found_is_inconclusive_with_since_date(self, monkeypatch):
        monkeypatch.setattr(dcr, "_now_utc", lambda: datetime(2026, 10, 9, 13, 0, tzinfo=timezone.utc))
        v = dcr.evaluate_crash_rules(quiet())
        assert v["status"] == "inconclusive"
        assert v["headline"] == "No crashes or unexpected shutdowns recorded since 2026-10-02"
        assert v["suggested_actions"] == []

    def test_fast_startup_is_noted(self):
        ev = put(fixture_evidence("crash_power_loss"), "crash.power_config", {"fast_startup": True, "hibernate": False})
        v = dcr.evaluate_crash_rules(ev)
        assert "fast_startup" in v["rule_hits"]
        assert "Fast Startup" in v["reasoning"]

    def test_repeated_install_names_are_listed_once(self):
        ev = put(
            fixture_evidence("crash_power_loss"),
            "crash.recent_changes",
            {
                "installs": [
                    {"time": "2026-10-07T12:00:00Z", "kind": "service", "name": "MagicianSataModeReader"},
                    {"time": "2026-10-07T11:00:00Z", "kind": "service", "name": "MagicianSataModeReader"},
                    {"time": "2026-10-07T10:00:00Z", "kind": "driver", "name": "ACX HD Audio Driver"},
                ]
            },
        )
        text = dcr.evaluate_crash_rules(ev)["reasoning"]
        assert text.count("MagicianSataModeReader") == 1
        assert "ACX HD Audio Driver" in text

    def test_recent_install_within_48_hours_is_noted(self):
        ev = put(
            fixture_evidence("crash_power_loss"),
            "crash.recent_changes",
            {
                "installs": [
                    {"time": "2026-10-07T12:00:00Z", "kind": "driver", "name": "nvlddmkm.inf"},
                    {"time": "2026-10-01T12:00:00Z", "kind": "update", "name": "too old"},
                ]
            },
        )
        v = dcr.evaluate_crash_rules(ev)
        assert "recent_install" in v["rule_hits"]
        assert "nvlddmkm.inf" in v["reasoning"]
        assert "too old" not in v["reasoning"]

    def test_steps_are_capped_and_cite_probes(self):
        for name in (
            "crash_hung_shutdown_2026_10_08",
            "crash_whea_beats_bugcheck",
            "crash_bugcheck_repeat",
            "crash_power_button",
            "crash_power_loss",
            "crash_boot_failure",
            "crash_app_repeat_chrome",
        ):
            v = dcr.evaluate_crash_rules(fixture_evidence(name))
            assert 1 <= len(v["manual_steps"]) <= 6, name
            assert v["evidence_refs"], name
            assert all(ref.startswith("crash.") for ref in v["evidence_refs"]), name


class TestRobustness:
    def test_failed_or_missing_probes_are_no_evidence(self):
        ev = {"crash.whea": {"key": "crash.whea", "ok": False, "error": "timed out"}}
        assert dcr.evaluate_crash_rules(ev)["rule_hits"][0] == "nothing_found"

    def test_empty_evidence(self):
        assert dcr.evaluate_crash_rules({})["status"] == "inconclusive"
