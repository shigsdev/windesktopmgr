"""Tests for diagnose_storage_rules: storage verdicts, focus drive, context, steps.

Scenario coverage lives in tests/fixtures/diagnose/storage_*.json (run by
test_diagnose.py's fixture test). These tests start from the healthy
``storage_nothing_found`` evidence and change one thing at a time.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

import diagnose_storage_rules as dsr

FIXTURES = Path(__file__).parent / "fixtures" / "diagnose"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["evidence"]


@pytest.fixture
def healthy():
    return copy.deepcopy(_load("storage_nothing_found"))


def _data(ev, key):
    return ev[key]["data"]


def _focus(ev, letter):
    _data(ev, "storage.physical_disks")["focus"] = letter
    return ev


def _rebuild(ev):
    _data(ev, "storage.pool")["repair_jobs"] = [{"name": "Regeneration", "state": "Running", "pct": 63}]
    return ev


def _c_full(ev):
    _data(ev, "storage.volumes")["volumes"][0].update(free_gb=6.0, free_pct=0.7)
    return ev


class TestHeadlines:
    def test_pool_headline_names_label_model_slot(self):
        """S2: the 2026-10-08 replay names the dropped drive by label tail, model and slot."""
        verdict = dsr.evaluate_storage_rules(_load("storage_pool_degraded_2026_10_08"))
        assert verdict["rule_hits"][0] == "pool_trouble"
        for part in ("…20C4", "Samsung SSD 970 EVO Plus 2TB", "PCI Slot 9", "E:"):
            assert part in verdict["headline"], part

    def test_hot_ambiguous_never_names_a_drive(self):
        """S3: two identical models, one hot -- the model and count only, no serial tail."""
        verdict = dsr.evaluate_storage_rules(_load("storage_drive_hot_ambiguous"))
        assert verdict["headline"].startswith("One of your two Samsung SSD 990 PRO 2TB drives")
        assert "…" not in verdict["headline"]
        assert "82" in verdict["headline"]

    def test_hot_unique_model_names_the_drive(self, healthy):
        _data(healthy, "storage.drive_wear")["drives"][0]["temp_c"] = 70.0  # warn 69 on the 1TB heatsink drive
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "drive_hot"
        assert "Samsung SSD 990 PRO with Heatsink 1TB" in verdict["headline"]
        assert "one of your" not in verdict["headline"].lower()

    def test_failing_headline(self):
        verdict = dsr.evaluate_storage_rules(_load("storage_drive_failing"))
        assert verdict["headline"] == "Drive …163R (Samsung SSD 990 PRO 2TB, PCI Slot 5) is failing"

    def test_full_headline(self):
        verdict = dsr.evaluate_storage_rules(_load("storage_c_full"))
        assert verdict["headline"] == "C: has 6 GB free (0.7%)"

    def test_spare_below_threshold_is_failing(self, healthy):
        row = _data(healthy, "storage.drive_wear")["drives"][3]
        row.update(spare_pct=5.0, spare_threshold_pct=10.0)
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "drive_failing"
        assert verdict["headline"].startswith("One of your two Samsung SSD 970 EVO Plus 2TB drives")

    def test_wear_at_threshold_is_failing(self, healthy):
        _data(healthy, "storage.drive_wear")["drives"][0]["pct_used"] = float(dsr.WEAR_FAIL_PCT)
        assert dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "drive_failing"

    def test_wear_below_threshold_is_not(self, healthy):
        _data(healthy, "storage.drive_wear")["drives"][0]["pct_used"] = dsr.WEAR_FAIL_PCT - 1.0
        assert dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "nothing_found"


class TestThresholds:
    def test_four_errors_on_a_drive_is_not_enough(self, healthy):
        _data(healthy, "storage.disk_errors")["by_disk"] = {"3": {"count": 4, "first": "x", "last": "x"}}
        assert dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "nothing_found"

    def test_any_ntfs_corruption_fires(self, healthy):
        _data(healthy, "storage.disk_errors")["ntfs_corruption"] = 1
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "drive_errors"
        assert "file system" in verdict["headline"].lower()

    def test_errors_on_an_absent_disk_are_a_note_not_a_verdict(self, healthy):
        """Live 2026-10-13: 50 paging errors on Harddisk7 while Backup and Restore mounted its image."""
        _data(healthy, "storage.disk_errors")["by_disk"] = {"7": {"count": 50, "first": "x", "last": "x"}}
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "nothing_found"
        assert "no longer" in verdict["reasoning"]

    def test_errors_on_the_pool_virtual_disk_count(self, healthy):
        _data(healthy, "storage.disk_errors")["by_disk"] = {"6": {"count": 9, "first": "x", "last": "x"}}
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "drive_errors"
        assert "E:" in verdict["headline"]

    @pytest.mark.parametrize(
        ("free_gb", "free_pct", "full"), [(9.9, 50.0, True), (10.0, 10.0, False), (500, 9.9, True)]
    )
    def test_full_boundaries(self, healthy, free_gb, free_pct, full):
        _data(healthy, "storage.volumes")["volumes"][1].update(free_gb=free_gb, free_pct=free_pct)
        assert (dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "volume_full") is full

    def test_removable_full_volume_is_ignored(self, healthy):
        vols = _data(healthy, "storage.volumes")["volumes"]
        vols.append(
            {
                "letter": "F:",
                "label": "USB",
                "fs": "FAT32",
                "total_gb": 16,
                "free_gb": 0.1,
                "free_pct": 0.6,
                "fixed": False,
            }
        )
        assert dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "nothing_found"

    @pytest.mark.parametrize(
        ("busy", "avg", "slow"), [(90, None, True), (89, None, False), (10, 20.1, True), (10, 20.0, False)]
    )
    def test_slow_boundaries(self, healthy, busy, avg, slow):
        _data(healthy, "storage.io_sample")["disks"][3].update(busy_pct=busy, avg_read_ms=avg)
        assert (dsr.evaluate_storage_rules(healthy)["rule_hits"][0] == "slow_now") is slow


class TestFocus:
    def test_focus_drive_leads(self, healthy):
        ev = _c_full(_rebuild(healthy))
        assert dsr.evaluate_storage_rules(ev)["rule_hits"][0] == "pool_rebuilding"
        assert dsr.evaluate_storage_rules(_focus(ev, "C:"))["rule_hits"][0] == "volume_full"

    def test_focus_virtual_disk_maps_to_pool(self, healthy):
        """Review Focus 2: E: is the pool's virtual disk (6), not a physical drive."""
        ev = _c_full(copy.deepcopy(_load("storage_pool_degraded_2026_10_08")))
        assert dsr.evaluate_storage_rules(_focus(ev, "E:"))["rule_hits"][0] == "pool_trouble"

    def test_focus_e_prefers_pool_over_c_full(self, healthy):
        ev = _focus(_c_full(_rebuild(healthy)), "E:")
        assert dsr.evaluate_storage_rules(ev)["rule_hits"][0] == "pool_rebuilding"

    def test_focus_with_nothing_wrong_falls_back_to_everything(self, healthy):
        ev = _focus(_c_full(healthy), "D:")
        assert dsr.evaluate_storage_rules(ev)["rule_hits"][0] == "volume_full"

    def test_unknown_focus_letter_is_harmless(self, healthy):
        assert dsr.evaluate_storage_rules(_focus(healthy, "Q:"))["rule_hits"][0] == "nothing_found"


class TestContext:
    def test_wear_unavailable_annotation(self, healthy):
        _data(healthy, "storage.drive_wear").update(
            available=False, reason="LibreHardwareMonitor isn't running", drives=[]
        )
        verdict = dsr.evaluate_storage_rules(_c_full(healthy))
        assert "wear_unavailable" in verdict["rule_hits"]
        assert "LibreHardwareMonitor" in verdict["reasoning"]

    def test_slow_with_rebuild_annotation(self, healthy):
        """slow_now leads only under a focus; then the running rebuild is a note."""
        _rebuild(healthy)
        _data(healthy, "storage.io_sample")["disks"][0].update(busy_pct=100)
        verdict = dsr.evaluate_storage_rules(_focus(healthy, "C:"))
        assert verdict["rule_hits"][0] == "slow_now"
        assert "rebuild_in_progress" in verdict["rule_hits"]

    def test_nas_stale_annotation(self):
        ev = copy.deepcopy(_load("storage_nas_problem"))
        _data(ev, "storage.nas")["nas"][0]["age_s"] = 7200
        verdict = dsr.evaluate_storage_rules(ev)
        assert verdict["rule_hits"][0] == "nas_problem"
        assert "nas_stale" in verdict["rule_hits"]

    def test_stale_nas_alone_is_a_nas_problem(self, healthy):
        _data(healthy, "storage.nas")["nas"][0]["age_s"] = 7200
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "nas_problem"
        assert verdict["locus"] == "external_cause"

    def test_unread_sources_note_on_nothing_found(self, healthy):
        healthy["storage.pool"] = {
            "key": "storage.pool",
            "label": "Storage Spaces pool",
            "ok": False,
            "error": "timeout",
        }
        verdict = dsr.evaluate_storage_rules(healthy)
        assert verdict["rule_hits"][0] == "nothing_found"
        assert "Storage Spaces pool" in verdict["reasoning"]

    def test_missing_evidence_is_nothing_found_not_crash(self):
        assert dsr.evaluate_storage_rules({})["rule_hits"][0] == "nothing_found"
        assert dsr.evaluate_storage_rules(None)["status"] == "inconclusive"


_WRITE_COMMANDS = re.compile(r"chkdsk\s+\S+\s+/(?:f|r|x)\b|Repair-VirtualDisk|format\s+[a-z]:|Optimize-Volume", re.I)


class TestStepsAndActions:
    @pytest.mark.parametrize("path", sorted(FIXTURES.glob("storage_*.json")), ids=lambda p: p.stem)
    def test_steps_never_contain_write_commands(self, path):
        verdict = dsr.evaluate_storage_rules(json.loads(path.read_text(encoding="utf-8"))["evidence"])
        assert not any(_WRITE_COMMANDS.search(step) for step in verdict["manual_steps"])

    def test_drive_errors_steps_offer_read_only_scan(self):
        verdict = dsr.evaluate_storage_rules(_load("storage_drive_errors"))
        assert any("/scan" in step for step in verdict["manual_steps"])

    def test_clear_temp_only_for_the_system_drive(self, healthy, monkeypatch):
        monkeypatch.setenv("SYSTEMDRIVE", "C:")
        assert dsr.evaluate_storage_rules(_c_full(healthy))["suggested_actions"] == ["clear_temp"]
        monkeypatch.setenv("SYSTEMDRIVE", "D:")
        assert dsr.evaluate_storage_rules(_c_full(healthy))["suggested_actions"] == []


def test_storage_class_uses_these_rules():
    import diagnose

    verdict = diagnose.SYMPTOM_CLASSES["storage"]["rules"](_load("storage_c_full"), None)
    assert verdict["rule_hits"][0] == "volume_full"


class TestStorageClassifier:
    @pytest.mark.parametrize(
        ("text", "drive"),
        [
            ("copy to drive E please", "E:"),
            ("c: and d: are full", "C:"),
            ("see https://example.com/x", None),
            ("it froze at 10:30", None),
            ("Re: my disk", None),
            ("I drive a car", None),
            ("my Google Drive is full", None),
            (r"see C:\Users\Zed\log.txt", None),
            (r"free up C:\ please", "C:"),
        ],
    )
    def test_extract_drive(self, text, drive):
        assert dsr.extract_drive(text) == drive

    @pytest.mark.parametrize(
        ("text", "subject"),
        [("my hard drive crashed", True), ("the ssd just died", True), ("the PC crashed while copying", False)],
    )
    def test_storage_subject_crash(self, text, subject):
        assert dsr.is_storage_subject_crash(text) is subject
