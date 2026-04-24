"""tests/test_baseline.py -- System baseline / drift detection (backlog #14).

Coverage areas:
  - Collectors (mock subprocess + psutil; no real system calls)
  - diff_snapshots semantics (add / remove / change, fields we care about)
  - Persistence (atomic write, load, accept)
  - compute_drift + record_drift_if_any (history append invariants)
  - recent_drift windowing
  - Flask routes (snapshot / drift / accept / history)
  - First-run state (no baseline exists)
  - Dashboard concern integration

All tests redirect ``BASELINE_FILE`` and ``HISTORY_FILE`` to tmp_path so
no real baseline / history on disk is touched.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

import baseline

# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def baseline_tmp(tmp_path, monkeypatch):
    """Redirect both baseline files to tmp paths."""
    snap = tmp_path / "baseline_snapshot.json"
    hist = tmp_path / "baseline_history.json"
    monkeypatch.setattr(baseline, "BASELINE_FILE", str(snap))
    monkeypatch.setattr(baseline, "HISTORY_FILE", str(hist))
    return {"snapshot": snap, "history": hist}


def _fake_svc(name="svc1", display="Service 1", start="Auto", status="Running", binpath=r"C:\bin\x.exe"):
    """Build a psutil.win_service-like object with .as_dict() returning usable fields."""
    svc = SimpleNamespace()
    svc.as_dict = lambda: {
        "name": name,
        "display_name": display,
        # psutil emits "automatic"/"manual"/"disabled", not "auto"/etc.
        "start_type": {"Auto": "automatic", "Manual": "manual", "Disabled": "disabled"}.get(start, "automatic"),
        "status": status.lower(),
        "binpath": binpath,
    }
    return svc


# ── Collectors ─────────────────────────────────────────────────────


class TestCollectors:
    def test_collect_startup_shapes_keys_and_fields(self, mocker):
        mocker.patch(
            "windesktopmgr.get_startup_items",
            return_value=[
                {
                    "Name": "Foo",
                    "Location": "HKLM Run",
                    "Command": r"C:\foo.exe",
                    "Type": "registry_hklm",
                    "Enabled": True,
                },
                {
                    "Name": "Bar",
                    "Location": "HKCU Run",
                    "Command": r"C:\bar.exe",
                    "Type": "registry_hkcu",
                    "Enabled": False,
                },
                {
                    "Name": "Foo",
                    "Location": "HKCU Run",
                    "Command": r"C:\foo2.exe",
                    "Type": "registry_hkcu",
                    "Enabled": True,
                },
            ],
        )
        got = baseline._collect_startup()
        # Same name in two locations must produce two distinct keys.
        assert "HKLM Run::Foo" in got
        assert "HKCU Run::Foo" in got
        assert got["HKLM Run::Foo"]["command"] == r"C:\foo.exe"
        assert got["HKCU Run::Bar"]["enabled"] is False

    def test_collect_startup_empty_on_exception(self, mocker):
        mocker.patch("windesktopmgr.get_startup_items", side_effect=RuntimeError("boom"))
        assert baseline._collect_startup() == {}

    def test_collect_startup_skips_malformed_entries(self, mocker):
        mocker.patch(
            "windesktopmgr.get_startup_items",
            return_value=[
                {"Name": "", "Location": "HKLM Run"},  # no name -> skip
                "not-a-dict",  # wrong type -> skip
                {"Name": "Valid", "Location": "HKLM Run", "Command": "x", "Enabled": True},
            ],
        )
        got = baseline._collect_startup()
        assert list(got.keys()) == ["HKLM Run::Valid"]

    def test_collect_services_happy(self, mocker):
        fake_svcs = [
            _fake_svc("Dhcp", "DHCP Client", "Auto", "Running", r"C:\Windows\svchost.exe -k NetworkService"),
            _fake_svc("Spooler", "Print Spooler", "Auto", "Running", r"C:\Windows\System32\spoolsv.exe"),
        ]
        mocker.patch("psutil.win_service_iter", return_value=fake_svcs)
        got = baseline._collect_services()
        assert "Dhcp" in got
        assert got["Dhcp"]["display_name"] == "DHCP Client"
        assert got["Dhcp"]["start_mode"] == "Auto"
        assert got["Dhcp"]["image_path"].endswith("NetworkService")

    def test_collect_services_skips_unreadable(self, mocker):
        # One service raises on .as_dict(), another succeeds. Must skip not crash.
        class _Bad:
            def as_dict(self):
                raise PermissionError("nope")

        mocker.patch("psutil.win_service_iter", return_value=[_Bad(), _fake_svc("Good")])
        got = baseline._collect_services()
        assert list(got.keys()) == ["Good"]

    def test_collect_services_iter_exception_empty(self, mocker):
        mocker.patch("psutil.win_service_iter", side_effect=OSError("RPC fail"))
        assert baseline._collect_services() == {}

    def test_collect_tasks_parses_csv(self, mocker):
        csv_out = (
            '"HostName","TaskName","Next Run Time","Status","Author","Task To Run","Run As User","Scheduled Task State"\n'
            '"WIN","\\Adobe Acrobat Update Task","At startup","Ready","Adobe Systems","C:\\ARM.exe","INTERACTIVE","Enabled"\n'
            '"WIN","\\Microsoft\\Foo","9999","Ready","Microsoft","C:\\foo.exe","SYSTEM","Enabled"\n'
        )
        mocker.patch(
            "subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=csv_out, stderr=""),
        )
        got = baseline._collect_scheduled_tasks()
        assert r"\Adobe Acrobat Update Task" in got
        adobe = got[r"\Adobe Acrobat Update Task"]
        assert adobe["author"] == "Adobe Systems"
        assert adobe["state"] == "Enabled"
        assert adobe["image_path"] == r"C:\ARM.exe"
        # First-row wins for duplicates (schtasks /v expands triggers)
        ms = got[r"\Microsoft\Foo"]
        assert ms["run_as"] == "SYSTEM"

    def test_collect_tasks_timeout_empty(self, mocker):
        import subprocess as sp

        mocker.patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="schtasks", timeout=30))
        assert baseline._collect_scheduled_tasks() == {}

    def test_collect_tasks_nonzero_exit_empty(self, mocker):
        mocker.patch(
            "subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout="", stderr="access denied\n"),
        )
        assert baseline._collect_scheduled_tasks() == {}


# ── Snapshot shape ─────────────────────────────────────────────────


class TestSnapshot:
    def test_take_snapshot_returns_expected_shape(self, mocker):
        mocker.patch("baseline._collect_startup", return_value={"HKLM Run::Foo": {"name": "Foo"}})
        mocker.patch("baseline._collect_services", return_value={"Dhcp": {"name": "Dhcp"}})
        mocker.patch("baseline._collect_scheduled_tasks", return_value={r"\T1": {"name": "T1"}})
        snap = baseline.take_snapshot()
        assert "timestamp" in snap
        assert snap["startup"]["by_key"] == {"HKLM Run::Foo": {"name": "Foo"}}
        assert snap["services"]["by_key"] == {"Dhcp": {"name": "Dhcp"}}
        assert snap["tasks"]["by_key"] == {r"\T1": {"name": "T1"}}
        assert snap["counts"] == {"startup": 1, "services": 1, "tasks": 1}


# ── Diff semantics ─────────────────────────────────────────────────


class TestDiffSnapshots:
    def test_empty_old_returns_zero_diff(self):
        new = {
            "startup": {"by_key": {"a::b": {"name": "b", "command": "x", "enabled": True}}},
            "services": {"by_key": {}},
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots({}, new)
        assert diff["total_changes"] == 0
        for cat in ("startup", "services", "tasks"):
            assert diff[cat]["added"] == [] and diff[cat]["removed"] == [] and diff[cat]["changed"] == []

    def test_identical_snapshots_produce_no_diff(self):
        snap = {
            "startup": {"by_key": {"a::b": {"name": "b", "command": "x", "enabled": True}}},
            "services": {"by_key": {"Dhcp": {"name": "Dhcp", "start_mode": "Auto", "image_path": "x"}}},
            "tasks": {"by_key": {r"\T": {"name": "T", "state": "Ready", "image_path": "x", "run_as": "SYSTEM"}}},
        }
        diff = baseline.diff_snapshots(snap, snap)
        assert diff["total_changes"] == 0

    def test_added_service_detected(self):
        old = {"startup": {"by_key": {}}, "services": {"by_key": {}}, "tasks": {"by_key": {}}}
        new = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"Malware": {"name": "Malware", "start_mode": "Auto", "image_path": r"C:\tmp\m.exe"}}
            },
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots(old, new)
        assert diff["total_changes"] == 1
        assert len(diff["services"]["added"]) == 1
        assert diff["services"]["added"][0]["key"] == "Malware"

    def test_removed_startup_item_detected(self):
        old = {
            "startup": {"by_key": {"HKLM Run::Old": {"name": "Old", "command": "x", "enabled": True}}},
            "services": {"by_key": {}},
            "tasks": {"by_key": {}},
        }
        new = {"startup": {"by_key": {}}, "services": {"by_key": {}}, "tasks": {"by_key": {}}}
        diff = baseline.diff_snapshots(old, new)
        assert diff["total_changes"] == 1
        assert diff["startup"]["removed"][0]["key"] == "HKLM Run::Old"

    def test_changed_ships_full_old_and_new_dicts(self):
        """The ``old`` / ``new`` payloads must carry EVERY tracked field
        (not just the delta ones) so the UI can render a Parameter /
        Previous / Current table across all parameters. ``delta`` lists
        the subset that actually differs."""
        old = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {
                    "Spooler": {
                        "name": "Spooler",
                        "display_name": "Print Spooler",
                        "start_mode": "Auto",
                        "image_path": r"C:\Windows\System32\spoolsv.exe",
                        "status": "Running",  # non-tracked but still shipped
                    }
                }
            },
            "tasks": {"by_key": {}},
        }
        new = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {
                    "Spooler": {
                        "name": "Spooler",
                        "display_name": "Print Spooler",
                        "start_mode": "Auto",  # unchanged
                        "image_path": r"C:\tmp\rogue.exe",  # CHANGED
                        "status": "Running",
                    }
                }
            },
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots(old, new)
        entry = diff["services"]["changed"][0]
        # delta lists only the changed field
        assert entry["delta"] == ["image_path"]
        # But full old/new dicts carry EVERY field so UI can tabulate
        for k in ("name", "display_name", "start_mode", "image_path", "status"):
            assert k in entry["old"], f"old missing {k}"
            assert k in entry["new"], f"new missing {k}"
        # Unchanged fields have matching values in both
        assert entry["old"]["start_mode"] == entry["new"]["start_mode"] == "Auto"
        # Changed fields differ
        assert entry["old"]["image_path"] != entry["new"]["image_path"]

    def test_changed_image_path_detected(self):
        """Attacker swaps a service binary -- the image_path change MUST fire."""
        old = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {
                    "Spooler": {
                        "name": "Spooler",
                        "start_mode": "Auto",
                        "image_path": r"C:\Windows\System32\spoolsv.exe",
                    }
                }
            },
            "tasks": {"by_key": {}},
        }
        new = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"Spooler": {"name": "Spooler", "start_mode": "Auto", "image_path": r"C:\tmp\rogue.exe"}}
            },
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots(old, new)
        assert diff["total_changes"] == 1
        changed = diff["services"]["changed"]
        assert len(changed) == 1
        assert "image_path" in changed[0]["delta"]
        assert changed[0]["old"]["image_path"].endswith("spoolsv.exe")
        assert changed[0]["new"]["image_path"] == r"C:\tmp\rogue.exe"

    def test_changed_start_mode_detected(self):
        """Auto → Disabled is the sabotage pattern (disable a security service)."""
        old = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"WinDefend": {"name": "WinDefend", "start_mode": "Auto", "image_path": r"C:\x.exe"}}
            },
            "tasks": {"by_key": {}},
        }
        new = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"WinDefend": {"name": "WinDefend", "start_mode": "Disabled", "image_path": r"C:\x.exe"}}
            },
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots(old, new)
        assert diff["services"]["changed"][0]["delta"] == ["start_mode"]

    def test_task_run_as_change_detected(self):
        """INTERACTIVE → SYSTEM privilege escalation."""
        old = {
            "startup": {"by_key": {}},
            "services": {"by_key": {}},
            "tasks": {"by_key": {r"\T": {"name": "T", "state": "Ready", "image_path": "x", "run_as": "INTERACTIVE"}}},
        }
        new = {
            "startup": {"by_key": {}},
            "services": {"by_key": {}},
            "tasks": {"by_key": {r"\T": {"name": "T", "state": "Ready", "image_path": "x", "run_as": "SYSTEM"}}},
        }
        diff = baseline.diff_snapshots(old, new)
        assert diff["tasks"]["changed"][0]["delta"] == ["run_as"]

    def test_non_tracked_field_change_is_not_a_diff(self):
        """Status (running/stopped) flaps all the time -- NOT in _DIFF_FIELDS."""
        old = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"Spooler": {"name": "Spooler", "start_mode": "Auto", "image_path": "x", "status": "Running"}}
            },
            "tasks": {"by_key": {}},
        }
        new = {
            "startup": {"by_key": {}},
            "services": {
                "by_key": {"Spooler": {"name": "Spooler", "start_mode": "Auto", "image_path": "x", "status": "Stopped"}}
            },
            "tasks": {"by_key": {}},
        }
        diff = baseline.diff_snapshots(old, new)
        assert diff["total_changes"] == 0


# ── Persistence ────────────────────────────────────────────────────


class TestPersistence:
    def test_load_baseline_returns_none_when_missing(self, baseline_tmp):
        assert baseline.load_baseline() is None

    def test_accept_current_writes_baseline(self, baseline_tmp, mocker):
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "2026-04-24T10:00:00",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
            },
        )
        result = baseline.accept_current_as_baseline()
        assert result["ok"] is True
        loaded = baseline.load_baseline()
        assert loaded["timestamp"] == "2026-04-24T10:00:00"

    def test_accept_handles_write_failure(self, baseline_tmp, mocker):
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "2026-04-24",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
            },
        )
        mocker.patch("baseline.os.replace", side_effect=OSError("disk full"))
        result = baseline.accept_current_as_baseline()
        assert result["ok"] is False
        assert "atomic write failed" in result["error"]

    def test_load_history_empty_when_missing(self, baseline_tmp):
        assert baseline.load_history() == []

    def test_load_history_corrupt_returns_empty(self, baseline_tmp):
        baseline_tmp["history"].write_text("{not json", encoding="utf-8")
        assert baseline.load_history() == []

    def test_append_history_writes_and_caps(self, baseline_tmp, monkeypatch):
        monkeypatch.setattr(baseline, "MAX_HISTORY", 3)
        for i in range(5):
            baseline._append_history({"timestamp": f"2026-01-0{i + 1}", "total_changes": i})
        h = baseline.load_history()
        assert len(h) == 3  # oldest two dropped
        assert [e["total_changes"] for e in h] == [2, 3, 4]


# ── Compute drift + record ─────────────────────────────────────────


class TestComputeDrift:
    def test_no_baseline_has_baseline_false(self, baseline_tmp, mocker):
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "now",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
                "counts": {"startup": 0, "services": 0, "tasks": 0},
            },
        )
        result = baseline.compute_drift()
        assert result["has_baseline"] is False
        assert result["drift"]["total_changes"] == 0
        assert result["baseline_timestamp"] is None

    def test_drift_between_baseline_and_current(self, baseline_tmp, mocker):
        # Write an accepted baseline directly
        baseline._atomic_write(
            baseline.BASELINE_FILE,
            {
                "timestamp": "2026-04-20T10:00:00",
                "startup": {"by_key": {"HKLM Run::Old": {"name": "Old", "command": "x", "enabled": True}}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
            },
        )
        # Current snapshot: Old is gone, New added
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "2026-04-24T10:00:00",
                "startup": {"by_key": {"HKLM Run::New": {"name": "New", "command": "y", "enabled": True}}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
                "counts": {"startup": 1, "services": 0, "tasks": 0},
            },
        )
        result = baseline.compute_drift()
        assert result["has_baseline"] is True
        assert result["drift"]["total_changes"] == 2
        assert len(result["drift"]["startup"]["added"]) == 1
        assert len(result["drift"]["startup"]["removed"]) == 1

    def test_record_drift_appends_history_when_drift(self, baseline_tmp, mocker):
        baseline._atomic_write(
            baseline.BASELINE_FILE,
            {
                "timestamp": "2026-04-20",
                "startup": {"by_key": {}},
                "services": {"by_key": {"A": {"name": "A", "start_mode": "Auto", "image_path": "x"}}},
                "tasks": {"by_key": {}},
            },
        )
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "2026-04-24",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},  # A removed
                "tasks": {"by_key": {}},
                "counts": {"startup": 0, "services": 0, "tasks": 0},
            },
        )
        result = baseline.record_drift_if_any()
        assert result["recorded"] is True
        history = baseline.load_history()
        assert len(history) == 1
        assert history[0]["total_changes"] == 1

    def test_record_drift_noop_when_no_drift(self, baseline_tmp, mocker):
        baseline._atomic_write(
            baseline.BASELINE_FILE,
            {"timestamp": "ts", "startup": {"by_key": {}}, "services": {"by_key": {}}, "tasks": {"by_key": {}}},
        )
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "now",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
                "counts": {"startup": 0, "services": 0, "tasks": 0},
            },
        )
        result = baseline.record_drift_if_any()
        assert result["recorded"] is False
        assert baseline.load_history() == []

    def test_record_drift_noop_when_no_baseline(self, baseline_tmp, mocker):
        """First-run: there's no baseline so drift can't be logged."""
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "now",
                "startup": {"by_key": {"a::b": {"name": "b"}}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
                "counts": {"startup": 1, "services": 0, "tasks": 0},
            },
        )
        result = baseline.record_drift_if_any()
        assert result["recorded"] is False
        assert result["has_baseline"] is False


class TestRecentDrift:
    def test_empty_when_no_history(self, baseline_tmp):
        assert baseline.recent_drift() == []

    def test_filters_by_window(self, baseline_tmp):
        now = datetime.now()
        baseline._append_history({"timestamp": (now - timedelta(hours=48)).isoformat(), "total_changes": 5})
        baseline._append_history({"timestamp": (now - timedelta(hours=2)).isoformat(), "total_changes": 3})
        recent = baseline.recent_drift(window=timedelta(hours=24))
        assert len(recent) == 1
        assert recent[0]["total_changes"] == 3


# ── Flask routes ───────────────────────────────────────────────────


class TestBaselineRoutes:
    def test_drift_route_empty_baseline(self, client, baseline_tmp, mocker):
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "now",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
                "counts": {"startup": 0, "services": 0, "tasks": 0},
            },
        )
        resp = client.get("/api/baseline/drift")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["has_baseline"] is False
        assert d["drift"]["total_changes"] == 0

    def test_snapshot_route_returns_current(self, client, baseline_tmp, mocker):
        mocker.patch("baseline._collect_startup", return_value={"a::b": {"name": "b"}})
        mocker.patch("baseline._collect_services", return_value={})
        mocker.patch("baseline._collect_scheduled_tasks", return_value={})
        resp = client.get("/api/baseline/snapshot")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["ok"] is True
        assert d["snapshot"]["counts"]["startup"] == 1

    def test_accept_route_writes_baseline(self, client, baseline_tmp, mocker):
        mocker.patch(
            "baseline.take_snapshot",
            return_value={
                "timestamp": "2026-04-24",
                "startup": {"by_key": {}},
                "services": {"by_key": {}},
                "tasks": {"by_key": {}},
            },
        )
        resp = client.post("/api/baseline/accept")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert baseline.load_baseline() is not None

    def test_history_route_honours_hours_param(self, client, baseline_tmp):
        now = datetime.now()
        baseline._append_history({"timestamp": (now - timedelta(hours=48)).isoformat(), "total_changes": 1})
        baseline._append_history({"timestamp": (now - timedelta(hours=1)).isoformat(), "total_changes": 2})
        # 24h window -> only the recent one
        resp = client.get("/api/baseline/history?hours=24")
        assert len(resp.get_json()["entries"]) == 1
        # 72h window -> both
        resp = client.get("/api/baseline/history?hours=72")
        assert len(resp.get_json()["entries"]) == 2

    def test_history_route_clamps_hours(self, client, baseline_tmp):
        resp = client.get("/api/baseline/history?hours=99999")
        assert resp.get_json()["hours"] == 720  # clamped to 30d

    def test_history_route_invalid_hours_defaults_to_24(self, client, baseline_tmp):
        resp = client.get("/api/baseline/history?hours=abc")
        assert resp.get_json()["hours"] == 24


# ── Dashboard concern wiring ───────────────────────────────────────


class TestBaselineDashboardConcern:
    """When recent_drift() returns entries, /api/dashboard/summary must
    include a 'System baseline drift detected' concern that deep-links
    to the Baseline tab."""

    def _mock_collectors(self, mocker):
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_driver_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch.object(wdm, "get_disk_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_thermals", return_value={"temps": [], "perf": {"CPUPct": 0}, "fans": []})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"used_mb": 1, "total_mb": 2})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={})

    def test_concern_fires_when_drift_in_last_24h(self, client, baseline_tmp, mocker):
        now = datetime.now()
        baseline._append_history(
            {
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "total_changes": 3,
                "drift": {
                    "startup": {"added": [{"name": "Foo"}], "removed": [], "changed": []},
                    "services": {"added": [], "removed": [], "changed": [{"name": "Spooler"}]},
                    "tasks": {"added": [{"name": "NewTask"}], "removed": [], "changed": []},
                },
            }
        )
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json().get("concerns", [])
        matching = [c for c in concerns if "baseline drift" in c.get("title", "").lower()]
        assert matching, f"no drift concern emitted; got: {[c.get('title') for c in concerns]}"
        assert matching[0]["tab"] == "baseline"
        assert "switchTab('baseline')" in matching[0]["action_fn"]

    def test_no_concern_when_no_drift(self, client, baseline_tmp, mocker):
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        assert not any("baseline drift" in c.get("title", "").lower() for c in resp.get_json().get("concerns", []))
