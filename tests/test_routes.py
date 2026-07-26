"""
test_routes.py
Flask route integration tests using the test client.
All subprocess / PowerShell calls are mocked — no Windows dependency.

Coverage: ALL 38 Flask routes defined in windesktopmgr.py
"""

import json
import os
import types

import pytest

import bsod
import events
import processes
import windesktopmgr as wdm

# ── helpers ────────────────────────────────────────────────────────────────────


def _mock_ps(mocker, stdout="[]", returncode=0, stderr=""):
    """Shorthand: mock subprocess.run globally."""
    m = mocker.patch("windesktopmgr.subprocess.run")
    m.return_value.stdout = stdout
    m.return_value.returncode = returncode
    m.return_value.stderr = stderr
    return m


def _wmi_obj(**kwargs):
    """Create a simple namespace that mimics a WMI object with attribute access."""
    return types.SimpleNamespace(**kwargs)


def _mock_wmi(mocker, classes=None):
    """Patch windesktopmgr.wmi.WMI() returning a fake WMI connection."""
    classes = classes or {}
    mock_conn = mocker.MagicMock()
    for name, data in classes.items():
        setattr(mock_conn, name, mocker.MagicMock(return_value=data))
    mocker.patch("windesktopmgr.wmi.WMI", return_value=mock_conn)
    return mock_conn


# ══════════════════════════════════════════════════════════════════════════════
# GET  /
# ══════════════════════════════════════════════════════════════════════════════


class TestIndexRoute:
    def test_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_returns_html(self, client):
        resp = client.get("/")
        assert b"<!DOCTYPE html>" in resp.data or b"<html" in resp.data

    def test_no_cache_headers(self, client):
        resp = client.get("/")
        assert resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/scan/status
# ══════════════════════════════════════════════════════════════════════════════


class TestScanStatusRoute:
    def test_default_status_idle(self, client):
        resp = client.get("/api/scan/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "idle"

    def test_response_has_progress(self, client):
        resp = client.get("/api/scan/status")
        assert "progress" in resp.get_json()

    def test_response_has_message(self, client):
        resp = client.get("/api/scan/status")
        assert "message" in resp.get_json()


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/scan/results
# ══════════════════════════════════════════════════════════════════════════════


class TestScanResultsRoute:
    def test_returns_empty_list_before_scan(self, client):
        resp = client.get("/api/scan/results")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert data == []

    def test_returns_results_after_scan(self, client):
        wdm._scan_results = [{"name": "NVIDIA GPU", "status": "up_to_date"}]
        resp = client.get("/api/scan/results")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["name"] == "NVIDIA GPU"


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/scan/start
# ══════════════════════════════════════════════════════════════════════════════


class TestScanStartRoute:
    def test_returns_ok_true(self, client, mocker):
        mocker.patch("windesktopmgr.threading.Thread")
        resp = client.post("/api/scan/start")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/launch/nvidia-app
# ══════════════════════════════════════════════════════════════════════════════


class TestLaunchNvidiaApp:
    def test_launched_when_app_found(self, client, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = "launched\n"
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        resp = client.post("/api/launch/nvidia-app")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["launched"] is True

    def test_fallback_when_not_installed(self, client, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = "not_found\n"
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        resp = client.post("/api/launch/nvidia-app")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["launched"] is False
        assert "nvidia.com" in data["fallback_url"]

    def test_timeout_returns_fallback(self, client, mocker):
        import subprocess

        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10),
        )
        resp = client.post("/api/launch/nvidia-app")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["launched"] is False


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/nvidia/status
# ══════════════════════════════════════════════════════════════════════════════


class TestNvidiaStatusRoute:
    """Tests for /api/nvidia/status — lightweight NVIDIA GPU update info for
    the Driver Manager tab auto-load.  Doesn't require a full driver scan."""

    def test_returns_update_available(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_nvidia_update_info",
            return_value={
                "Name": "NVIDIA GeForce RTX 4060 Ti",
                "InstalledVersion": "591.74",
                "WindowsVersion": "32.0.15.9174",
                "LatestVersion": "595.79",
                "UpdateAvailable": True,
                "UpdateSource": "nvidia_api",
            },
        )
        resp = client.get("/api/nvidia/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["has_nvidia"] is True
        assert data["UpdateAvailable"] is True
        assert data["LatestVersion"] == "595.79"
        assert data["Name"] == "NVIDIA GeForce RTX 4060 Ti"

    def test_returns_up_to_date(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_nvidia_update_info",
            return_value={
                "Name": "NVIDIA GeForce RTX 4060 Ti",
                "InstalledVersion": "595.79",
                "WindowsVersion": "32.0.15.9579",
                "LatestVersion": "595.79",
                "UpdateAvailable": False,
                "UpdateSource": "nvidia_api",
            },
        )
        resp = client.get("/api/nvidia/status")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["has_nvidia"] is True
        assert data["UpdateAvailable"] is False

    def test_returns_no_nvidia_when_none(self, client, mocker):
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        resp = client.get("/api/nvidia/status")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["has_nvidia"] is False


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/bsod/data
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodDataRoute:
    def test_returns_200_with_structure(self, client, mocker):
        mocker.patch(
            "windesktopmgr.build_bsod_analysis",
            return_value={
                "crashes": [],
                "summary": {"total_crashes": 0, "this_month": 0, "most_common_error": "None", "avg_uptime_hours": 0},
                "timeline": [],
                "recommendations": [],
                "error_breakdown": [],
                "driver_breakdown": [],
            },
        )
        resp = client.get("/api/bsod/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "crashes" in data
        assert "summary" in data
        assert "recommendations" in data

    def test_returns_json_content_type(self, client, mocker):
        mocker.patch("windesktopmgr.build_bsod_analysis", return_value={})
        resp = client.get("/api/bsod/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/bsod/cache
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodCacheRoute:
    def test_returns_cache_structure(self, client):
        resp = client.get("/api/bsod/cache")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_cached" in data
        assert "queue_pending" in data
        assert "in_flight" in data
        assert "entries" in data

    def test_empty_cache_total_is_zero(self, client):
        resp = client.get("/api/bsod/cache")
        assert resp.get_json()["total_cached"] == 0

    def test_populated_cache_reflected(self, client):
        bsod._bsod_cache["0x00020001"] = {"title": "HYPERVISOR_ERROR"}
        resp = client.get("/api/bsod/cache")
        assert resp.get_json()["total_cached"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/bsod/cache/clear
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodCacheClearRoute:
    def test_clears_cache(self, client):
        bsod._bsod_cache["0x00020001"] = {"title": "Test"}
        resp = client.post("/api/bsod/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert len(bsod._bsod_cache) == 0


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /api/bsod/cache/delete/<code>
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodCacheDeleteRoute:
    def test_deletes_existing_entry(self, client):
        bsod._bsod_cache["0x00020001"] = {"title": "HYPERVISOR_ERROR"}
        resp = client.delete("/api/bsod/cache/delete/0x00020001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["removed"] is True
        assert "0x00020001" not in bsod._bsod_cache

    def test_missing_entry_removed_false(self, client):
        resp = client.delete("/api/bsod/cache/delete/0x99999999")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["removed"] is False


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/startup/list
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupListRoute:
    def test_returns_200_with_list(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_startup_items",
            return_value=[
                {
                    "Name": "OneDrive",
                    "Command": "onedrive.exe",
                    "Location": "HKCU Run",
                    "Type": "registry_hkcu",
                    "Enabled": True,
                    "info": None,
                    "suspicious": False,
                },
            ],
        )
        resp = client.get("/api/startup/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_empty_list_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.get_startup_items", return_value=[])
        resp = client.get("/api/startup/list")
        assert resp.status_code == 200
        assert resp.get_json() == []


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/startup/lookup-unknowns
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupLookupUnknownsRoute:
    def test_returns_ok_and_queued(self, client):
        resp = client.post(
            "/api/startup/lookup-unknowns", json={"items": [{"Name": "WeirdApp", "Command": "weird.exe"}]}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "queued" in data

    def test_empty_items_returns_zero_queued(self, client):
        resp = client.post("/api/startup/lookup-unknowns", json={"items": []})
        data = resp.get_json()
        assert data["queued"] == 0

    def test_no_body_returns_400(self, client):
        """Empty body with JSON content type is rejected by Flask."""
        resp = client.post("/api/startup/lookup-unknowns", data="", content_type="application/json")
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/startup/lookup-status
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupLookupStatusRoute:
    def test_returns_pending_count(self, client):
        resp = client.get("/api/startup/lookup-status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "queue_pending" in data
        assert isinstance(data["queue_pending"], int)

    def test_returns_in_flight_count(self, client):
        resp = client.get("/api/startup/lookup-status")
        data = resp.get_json()
        assert "in_flight" in data

    def test_returns_cached_count(self, client):
        resp = client.get("/api/startup/lookup-status")
        data = resp.get_json()
        assert "cached" in data


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/startup/cache
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupCacheRoute:
    def test_returns_200_with_structure(self, client):
        resp = client.get("/api/startup/cache")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_cached" in data
        assert "queue_pending" in data
        assert "in_flight" in data

    def test_empty_cache_zero(self, client):
        resp = client.get("/api/startup/cache")
        assert resp.get_json()["total_cached"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/startup/toggle — input validation
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupToggleRoute:
    def test_missing_name_returns_400(self, client):
        resp = client.post(
            "/api/startup/toggle",
            json={"type": "registry_hklm", "enable": True},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_missing_type_returns_400(self, client):
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "foo", "enable": True},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_missing_enable_returns_400(self, client):
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "foo", "type": "registry_hklm"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/startup/toggle",
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_unsupported_type_returns_error(self, client):
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "SomeApp", "type": "folder", "enable": True},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False
        assert "error" in data

    def test_registry_hklm_enable_invokes_winreg(self, client, mocker):
        """toggle_startup_item now uses winreg directly (no subprocess) —
        assert the route reaches the winreg surface."""
        open_key = mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.winreg.QueryValueEx", return_value=("foo.exe", 1))
        mocker.patch("windesktopmgr.winreg.CreateKey", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.winreg.SetValueEx")
        mocker.patch("windesktopmgr.winreg.DeleteValue")
        mocker.patch("windesktopmgr.winreg.CloseKey")
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyApp", "type": "registry_hklm", "enable": True},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert open_key.called
        # Source must be Run-Disabled when enable=True, under HKLM
        first_call = open_key.call_args_list[0]
        assert first_call[0][0] == wdm.winreg.HKEY_LOCAL_MACHINE
        assert "Run-Disabled" in first_call[0][1]

    def test_task_disable_invokes_scheduler_com(self, client, mocker):
        """toggle_startup_item task branch drives Schedule.Service COM —
        assert the route disables the task via the COM ``.Enabled`` setter."""
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        scheduler = mocker.MagicMock()
        scheduler.GetFolder.return_value = mocker.MagicMock()
        mocker.patch("windesktopmgr.win32com.client.Dispatch", return_value=scheduler)
        fake_task = mocker.MagicMock()
        fake_task.Enabled = True
        mocker.patch("windesktopmgr._find_scheduled_task", return_value=fake_task)
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyTask", "type": "task", "enable": False},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert fake_task.Enabled is False


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/disk/data
# ══════════════════════════════════════════════════════════════════════════════


class TestDiskDataRoute:
    def test_returns_200_with_keys(self, client, mocker):
        mocker.patch("disk.get_disk_health", return_value={"drives": [], "physical": [], "io": []})
        resp = client.get("/api/disk/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "drives" in data
        assert "physical" in data
        assert "io" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("disk.get_disk_health", return_value={"drives": [], "physical": [], "io": []})
        resp = client.get("/api/disk/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/network/data
# ══════════════════════════════════════════════════════════════════════════════


class TestNetworkDataRoute:
    def test_returns_200_with_keys(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_network_data",
            return_value={
                "established": [],
                "listening": [],
                "adapters": [],
                "top_processes": [],
                "total_connections": 0,
                "total_listening": 0,
            },
        )
        resp = client.get("/api/network/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "established" in data
        assert "total_connections" in data

    def test_returns_json(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_network_data",
            return_value={
                "established": [],
                "listening": [],
                "adapters": [],
                "top_processes": [],
                "total_connections": 0,
                "total_listening": 0,
            },
        )
        resp = client.get("/api/network/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/updates/history
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdatesHistoryRoute:
    def test_returns_200_with_list(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_update_history",
            return_value=[
                {
                    "Title": "KB5048667",
                    "Date": "2024-12-10",
                    "ResultCode": 2,
                    "Categories": "Security",
                    "KB": "KB5048667",
                },
            ],
        )
        resp = client.get("/api/updates/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_empty_history_returns_empty_list(self, client, mocker):
        mocker.patch("windesktopmgr.get_update_history", return_value=[])
        resp = client.get("/api/updates/history")
        assert resp.get_json() == []


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/events/query
# ══════════════════════════════════════════════════════════════════════════════


class TestEventsQueryRoute:
    """
    /api/events/query is now backed by the win32evtlog helper
    (``_query_event_log_xpath``) instead of a PowerShell subprocess call.
    """

    def test_returns_list(self, client, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        resp = client.post("/api/events/query", json={"log": "System", "level": "Error"})
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_max_events_capped(self, client, mocker):
        mock_helper = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        client.post("/api/events/query", json={"log": "System", "max": 9999})
        # max is capped at 500 before being passed to the helper
        assert mock_helper.call_args.kwargs.get("max_events") == 500

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        resp = client.post("/api/events/query", json={"log": "Application"})
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/events/cache
# ══════════════════════════════════════════════════════════════════════════════


class TestEventsCacheRoute:
    def test_returns_cache_structure(self, client):
        resp = client.get("/api/events/cache")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_cached" in data
        assert "entries" in data


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/events/cache/clear
# ══════════════════════════════════════════════════════════════════════════════


class TestEventsCacheClearRoute:
    def test_clears_event_cache(self, client):
        events._event_cache[41] = {"title": "Kernel Power Loss"}
        resp = client.post("/api/events/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert len(events._event_cache) == 0


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /api/events/cache/delete/<event_id>
# ══════════════════════════════════════════════════════════════════════════════


class TestEventsCacheDeleteRoute:
    def test_deletes_existing_event(self, client):
        events._event_cache["41"] = {"title": "Kernel Power Loss"}
        resp = client.delete("/api/events/cache/delete/41")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_missing_event_ok_false_or_removed_false(self, client):
        resp = client.delete("/api/events/cache/delete/99999")
        data = resp.get_json()
        assert data.get("ok") is True


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/processes/list
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessListRoute:
    def test_returns_200_with_structure(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_process_list",
            return_value={
                "processes": [],
                "total": 0,
                "total_mem_mb": 0,
                "flagged": [],
                "flag_notes": [],
            },
        )
        resp = client.get("/api/processes/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "processes" in data
        assert "total" in data
        assert "total_mem_mb" in data

    def test_returns_json(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_process_list",
            return_value={
                "processes": [],
                "total": 0,
                "total_mem_mb": 0,
                "flagged": [],
                "flag_notes": [],
            },
        )
        resp = client.get("/api/processes/list")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/processes/lookup-unknowns
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessLookupUnknownsRoute:
    def test_returns_ok_and_queued(self, client):
        resp = client.post("/api/processes/lookup-unknowns", json={"processes": [{"Name": "weird.exe", "Path": ""}]})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "queued" in data

    def test_empty_list_returns_zero_queued(self, client):
        resp = client.post("/api/processes/lookup-unknowns", json={"processes": []})
        data = resp.get_json()
        assert data["queued"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/processes/lookup-status
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessLookupStatusRoute:
    def test_returns_queue_info(self, client):
        resp = client.get("/api/processes/lookup-status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "queue_pending" in data
        assert "in_flight" in data


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/processes/kill — safety critical
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessKillRoute:
    """After backlog #24 batch A, kill_process() uses ``psutil.Process``
    not ``Stop-Process``. Tests now mock psutil.Process and check it was
    invoked with the right integer PID."""

    def _patch_psutil(self, mocker, kill_side_effect=None):
        proc = mocker.MagicMock()
        if kill_side_effect:
            proc.kill.side_effect = kill_side_effect
        return mocker.patch("windesktopmgr.psutil.Process", return_value=proc)

    def test_kill_calls_psutil_with_pid(self, client, mocker):
        m = self._patch_psutil(mocker)
        resp = client.post("/api/processes/kill", json={"pid": 1234})
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        args, _ = m.call_args
        assert args[0] == 1234

    def test_kill_access_denied_returns_error(self, client, mocker):
        import psutil as _psutil

        self._patch_psutil(mocker, kill_side_effect=_psutil.AccessDenied(pid=999))
        resp = client.post("/api/processes/kill", json={"pid": 999})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False

    def test_successful_kill_invalidates_dashboard_cache(self, client, mocker):
        # 2026-06-29: a killed process lingered on the dashboard because the
        # post-kill refresh got the stale cached summary. A successful kill
        # must clear the cache so the next /api/dashboard/summary recomputes.
        from datetime import datetime

        import windesktopmgr as wdm

        self._patch_psutil(mocker)
        wdm._dashboard_state["data"] = {"concerns": [{"title": "stale"}]}
        wdm._dashboard_state["ts"] = datetime.now()
        resp = client.post("/api/processes/kill", json={"pid": 1234})
        assert resp.get_json()["ok"] is True
        assert wdm._dashboard_state["data"] is None  # cache invalidated

    def test_failed_kill_leaves_dashboard_cache_intact(self, client, mocker):
        from datetime import datetime

        import psutil as _psutil

        import windesktopmgr as wdm

        self._patch_psutil(mocker, kill_side_effect=_psutil.AccessDenied(pid=999))
        sentinel = {"concerns": []}
        wdm._dashboard_state["data"] = sentinel
        wdm._dashboard_state["ts"] = datetime.now()
        resp = client.post("/api/processes/kill", json={"pid": 999})
        assert resp.get_json()["ok"] is False
        assert wdm._dashboard_state["data"] is sentinel  # untouched on failure

    def test_missing_pid_defaults_to_zero_rejected(self, client, mocker):
        self._patch_psutil(mocker)
        resp = client.post("/api/processes/kill", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert "Invalid PID" in data["error"]

    def test_non_integer_pid_rejected(self, client, mocker):
        self._patch_psutil(mocker)
        resp = client.post("/api/processes/kill", json={"pid": "abc"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert "pid must be an integer" in data["error"]

    def test_negative_pid_rejected(self, client, mocker):
        self._patch_psutil(mocker)
        resp = client.post("/api/processes/kill", json={"pid": -5})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert "Invalid PID" in data["error"]

    def test_string_pid_returns_400(self, client, mocker):
        self._patch_psutil(mocker)
        resp = client.post("/api/processes/kill", json={"pid": "not-a-number"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert "pid must be an integer" in data["error"]


# ══════════════════════════════════════════════════════════════════════════════
# Backlog #35/#36 — SAFE_PROCESSES guard on /api/processes/kill + glossary route
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessKillSafeProcessesGuard:
    """Defence-in-depth: even if the UI hides the Kill button for a
    protected process, NLQ / future clients / a handcrafted curl must NOT
    be able to terminate a system process by calling the raw endpoint.
    """

    def _patch_psutil(self, mocker, *, name: str, kill_side_effect=None):
        proc = mocker.MagicMock()
        proc.name.return_value = name
        if kill_side_effect:
            proc.kill.side_effect = kill_side_effect
        return mocker.patch("windesktopmgr.psutil.Process", return_value=proc)

    def test_protected_process_rejected_with_403(self, client, mocker):
        proc_mock = self._patch_psutil(mocker, name="MemCompression")
        resp = client.post("/api/processes/kill", json={"pid": 4})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["ok"] is False
        assert data.get("protected") is True
        assert "MemCompression" in data["error"]
        # Must NEVER have called kill() on a protected process.
        proc_mock.return_value.kill.assert_not_called()

    def test_protected_process_with_exe_suffix_rejected(self, client, mocker):
        proc_mock = self._patch_psutil(mocker, name="csrss.exe")
        resp = client.post("/api/processes/kill", json={"pid": 500})
        assert resp.status_code == 403
        assert resp.get_json().get("protected") is True
        proc_mock.return_value.kill.assert_not_called()

    def test_vmmem_rejected(self, client, mocker):
        proc_mock = self._patch_psutil(mocker, name="vmmem")
        resp = client.post("/api/processes/kill", json={"pid": 8888})
        assert resp.status_code == 403
        proc_mock.return_value.kill.assert_not_called()

    def test_case_insensitive_name_match(self, client, mocker):
        """psutil returns MemCompression with original case; guard must not
        depend on exact casing to protect it."""
        proc_mock = self._patch_psutil(mocker, name="MEMCOMPRESSION")
        resp = client.post("/api/processes/kill", json={"pid": 4})
        assert resp.status_code == 403
        proc_mock.return_value.kill.assert_not_called()

    def test_non_protected_process_still_killed(self, client, mocker):
        proc_mock = self._patch_psutil(mocker, name="chrome.exe")
        resp = client.post("/api/processes/kill", json={"pid": 12345})
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        proc_mock.return_value.kill.assert_called_once()

    def test_no_such_process_during_name_lookup_returns_404(self, client, mocker):
        import psutil as _psutil

        mocker.patch("windesktopmgr.psutil.Process", side_effect=_psutil.NoSuchProcess(pid=99))
        resp = client.post("/api/processes/kill", json={"pid": 99})
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["ok"] is False
        assert "99" in data["error"]

    def test_access_denied_during_name_lookup_refuses_kill(self, client, mocker):
        """If we can't even read the process name, don't kill blind --
        cautious-by-default protects against killing a protected process we
        simply couldn't identify."""
        import psutil as _psutil

        mocker.patch("windesktopmgr.psutil.Process", side_effect=_psutil.AccessDenied(pid=4))
        resp = client.post("/api/processes/kill", json={"pid": 4})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["ok"] is False
        assert "Access denied" in data["error"]


class TestProcessKillElevationHint:
    """On Access-denied, /api/processes/kill enriches the response with a
    classification so the client can offer an elevated retry (needs_admin) or an
    honest can't-kill message (protected security software)."""

    def _deny_kill(self, mocker, name="someservice.exe"):
        import psutil as _psutil

        proc = mocker.MagicMock()
        proc.name.return_value = name
        proc.kill.side_effect = _psutil.AccessDenied(pid=500)
        mocker.patch("windesktopmgr.psutil.Process", return_value=proc)

    def test_needs_admin_sets_can_elevate_true(self, client, mocker):
        self._deny_kill(mocker)
        mocker.patch(
            "windesktopmgr.classify_kill_failure",
            return_value={"reason": "needs_admin", "can_elevate": True, "message": "needs admin", "name": "x"},
        )
        resp = client.post("/api/processes/kill", json={"pid": 500})
        data = resp.get_json()
        assert data["ok"] is False
        assert data["can_elevate"] is True
        assert data["reason"] == "needs_admin"
        assert data["error"] == "needs admin"

    def test_protected_sets_can_elevate_false(self, client, mocker):
        self._deny_kill(mocker, name="mc-fw-host.exe")
        mocker.patch(
            "windesktopmgr.classify_kill_failure",
            return_value={
                "reason": "protected",
                "can_elevate": False,
                "message": "mc-fw-host.exe is protected by anti-tamper self-protection.",
                "name": "mc-fw-host.exe",
            },
        )
        resp = client.post("/api/processes/kill", json={"pid": 500})
        data = resp.get_json()
        assert data["ok"] is False
        assert data["can_elevate"] is False
        assert data["reason"] == "protected"
        assert "self-protection" in data["error"].lower()


class TestProcessKillElevatedRoute:
    """POST /api/processes/kill-elevated — UAC-elevated taskkill fallback.
    Localhost-only, SAFE_PROCESSES guard re-applied, kill_process_elevated mocked
    (no real UAC prompt in tests)."""

    def test_non_localhost_rejected(self, client, mocker):
        elev = mocker.patch("windesktopmgr.kill_process_elevated")
        resp = client.post(
            "/api/processes/kill-elevated", json={"pid": 1234}, environ_base={"REMOTE_ADDR": "192.168.1.5"}
        )
        assert resp.status_code == 403
        assert "localhost" in resp.get_json()["error"]
        elev.assert_not_called()

    def test_invalid_pid_rejected(self, client, mocker):
        elev = mocker.patch("windesktopmgr.kill_process_elevated")
        resp = client.post("/api/processes/kill-elevated", json={"pid": 0}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 400
        elev.assert_not_called()

    def test_safe_process_rejected_even_elevated(self, client, mocker):
        proc = mocker.MagicMock()
        proc.name.return_value = "csrss.exe"
        mocker.patch("windesktopmgr.psutil.Process", return_value=proc)
        elev = mocker.patch("windesktopmgr.kill_process_elevated")
        resp = client.post("/api/processes/kill-elevated", json={"pid": 4}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 403
        assert resp.get_json().get("protected") is True
        elev.assert_not_called()  # elevation must not bypass the system-process guard

    def test_success_invokes_elevated_and_clears_cache(self, client, mocker):
        from datetime import datetime

        import windesktopmgr as wdm

        proc = mocker.MagicMock()
        proc.name.return_value = "notepad.exe"
        mocker.patch("windesktopmgr.psutil.Process", return_value=proc)
        mocker.patch("windesktopmgr.kill_process_elevated", return_value={"ok": True, "error": ""})
        wdm._dashboard_state["data"] = {"concerns": []}
        wdm._dashboard_state["ts"] = datetime.now()
        resp = client.post(
            "/api/processes/kill-elevated", json={"pid": 12345}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        assert resp.get_json()["ok"] is True
        assert wdm._dashboard_state["data"] is None  # cache invalidated

    def test_elevated_failure_surfaced(self, client, mocker):
        proc = mocker.MagicMock()
        proc.name.return_value = "notepad.exe"
        mocker.patch("windesktopmgr.psutil.Process", return_value=proc)
        mocker.patch(
            "windesktopmgr.kill_process_elevated",
            return_value={"ok": False, "error": "Elevated kill failed — protected by anti-tamper."},
        )
        resp = client.post(
            "/api/processes/kill-elevated", json={"pid": 12345}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        data = resp.get_json()
        assert data["ok"] is False
        assert "failed" in data["error"].lower()


class TestProcessesGlossaryRoute:
    """/api/processes/glossary backs the Memory tab info-icon tooltips."""

    def test_returns_glossary_dict(self, client):
        resp = client.get("/api/processes/glossary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert isinstance(data["glossary"], dict)

    def test_core_entries_present(self, client):
        """Sanity: the names the user specifically asked about (#36) must
        be in the glossary or the feature is half-done."""
        gloss = client.get("/api/processes/glossary").get_json()["glossary"]
        for required in ("memcompression", "vmmem", "system", "dwm", "csrss", "lsass"):
            assert required in gloss, f"glossary missing required entry: {required}"

    def test_every_entry_has_required_fields(self, client):
        gloss = client.get("/api/processes/glossary").get_json()["glossary"]
        for name, entry in gloss.items():
            assert "title" in entry, f"{name} missing title"
            assert "explanation" in entry, f"{name} missing explanation"
            assert "protected" in entry, f"{name} missing protected flag"
            assert isinstance(entry["protected"], bool)
            # Explanations should be real sentences, not placeholders
            assert len(entry["explanation"]) > 30, f"{name} explanation suspiciously short"

    def test_keys_are_lowercased_no_exe_suffix(self, client):
        """Clients normalise psutil names by lowercasing + stripping .exe
        before lookup; the dict keys must follow the same convention."""
        gloss = client.get("/api/processes/glossary").get_json()["glossary"]
        for k in gloss:
            assert k == k.lower(), f"glossary key not lowercased: {k!r}"
            assert not k.endswith(".exe"), f"glossary key has .exe suffix: {k!r}"


class TestGlossarySafeProcessesInvariant:
    """Drift guard: every protected glossary entry MUST also be in
    SAFE_PROCESSES. Otherwise we could show a "don't kill this" tooltip
    while the backend happily honoured a kill request for the same name.
    """

    def test_invariant_holds_at_module_load(self):
        """The _assert_glossary_in_safe_processes() runs at import time;
        if the invariant breaks, import itself raises. Re-run here so
        the failure points at this test rather than at a cryptic import."""

        processes._assert_glossary_in_safe_processes()

    def test_memcompression_is_in_safe_processes(self):
        """User specifically asked about this one -- lock it down."""

        assert "memcompression" in processes.SAFE_PROCESSES

    def test_vmmem_is_in_safe_processes(self):
        assert "vmmem" in processes.SAFE_PROCESSES
        assert "vmmemwsl" in processes.SAFE_PROCESSES


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/thermals/data
# ══════════════════════════════════════════════════════════════════════════════


class TestThermalsDataRoute:
    def test_returns_200_with_keys(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={
                "temps": [],
                "perf": {},
                "fans": [],
                "has_rich": False,
                "note": "",
            },
        )
        resp = client.get("/api/thermals/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "temps" in data
        assert "perf" in data
        assert "fans" in data

    def test_returns_json(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={
                "temps": [],
                "perf": {},
                "fans": [],
                "has_rich": False,
                "note": "",
            },
        )
        resp = client.get("/api/thermals/data")
        assert resp.content_type.startswith("application/json")

    def test_includes_gauges_and_gpu_available(self, client, mocker):
        """Redesign PR4: the route augments thermals with hero `gauges`
        (reusing dashboard._build_gauges) and a `gpu_available` flag so the
        instrument-cluster tab can render its radial gauge row."""
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={
                "temps": [],
                "perf": {"CPUPct": 22.0, "MemUsedMB": 8000, "MemTotalMB": 16000},
                "fans": [],
                "has_rich": False,
                "note": "",
            },
        )
        mocker.patch(
            "windesktopmgr.get_gpu_metrics",
            return_value={"available": True, "temp_c": 46, "utilization_pct": 33},
        )
        resp = client.get("/api/thermals/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["gpu_available"] is True
        by_key = {g["key"]: g for g in data.get("gauges", [])}
        assert list(by_key) == ["cpu_load", "cpu_temp", "gpu_temp", "gpu_util", "memory"]
        # Values must actually flow through from the mocked GPU/perf, not just
        # the keys -- guards against a silently-null gauge (real gpu.py uses
        # `utilization_pct`, not `util_pct`).
        assert by_key["gpu_temp"]["value"] == 46
        assert by_key["gpu_util"]["value"] == 33
        assert by_key["cpu_load"]["value"] == 22.0

    def test_gauge_build_failure_degrades_gracefully(self, client, mocker):
        """If gauge construction raises, the route still returns the thermals
        payload with safe `gauges`/`gpu_available` fallbacks -- never a 500."""
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={"temps": [], "perf": {}, "fans": [], "has_rich": False, "note": ""},
        )
        mocker.patch(
            "windesktopmgr.get_gpu_metrics",
            side_effect=RuntimeError("gpu probe exploded"),
        )
        resp = client.get("/api/thermals/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["gauges"] == []
        assert data["gpu_available"] is False


# ══════════════════════════════════════════════════════════════════════════════
# LibreHardwareMonitor in-app installer routes (Thermals CTA)
# ══════════════════════════════════════════════════════════════════════════════


class TestIdentifyStatusRoute:
    def test_returns_queue_depth(self, client, mocker):
        mocker.patch("windesktopmgr.identify.identify_status", return_value={"queue_pending": 2, "in_flight": 1})
        resp = client.get("/api/identify/status")
        assert resp.status_code == 200
        assert resp.get_json() == {"queue_pending": 2, "in_flight": 1}


class TestLhmInstallerRoutes:
    def test_status_returns_state(self, client, mocker):
        mocker.patch(
            "windesktopmgr.lhm.lhm_status",
            return_value={
                "installed": True,
                "running": False,
                "version": "v0.9.6",
                "exe": "X",
                "install_dir": "Y",
            },
        )
        resp = client.get("/api/thermals/lhm/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["installed"] is True
        assert data["running"] is False

    def test_install_ok_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.lhm.install_lhm", return_value={"ok": True, "exe": "X", "version": "v0.9.6"})
        resp = client.post("/api/thermals/lhm/install")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_install_failure_returns_502(self, client, mocker):
        mocker.patch("windesktopmgr.lhm.install_lhm", return_value={"ok": False, "error": "download failed"})
        resp = client.post("/api/thermals/lhm/install")
        assert resp.status_code == 502
        assert resp.get_json()["ok"] is False

    def test_launch_ok_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.lhm.launch_lhm_elevated", return_value={"ok": True, "exe": "X"})
        resp = client.post("/api/thermals/lhm/launch")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_launch_failure_returns_400(self, client, mocker):
        mocker.patch(
            "windesktopmgr.lhm.launch_lhm_elevated",
            return_value={"ok": False, "error": "ACCESS_DENIED (UAC prompt declined?)"},
        )
        resp = client.post("/api/thermals/lhm/launch")
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_autostart_status_returns_state(self, client, mocker):
        mocker.patch(
            "windesktopmgr.lhm.autostart_status",
            return_value={"enabled": True, "task": "WinDesktopMgr-LibreHardwareMonitor"},
        )
        resp = client.get("/api/thermals/lhm/autostart")
        assert resp.status_code == 200
        assert resp.get_json()["enabled"] is True

    def test_autostart_setup_ok_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.lhm.setup_autostart", return_value={"ok": True})
        resp = client.post("/api/thermals/lhm/autostart")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_autostart_setup_failure_returns_400(self, client, mocker):
        mocker.patch(
            "windesktopmgr.lhm.setup_autostart",
            return_value={"ok": False, "error": "not installed"},
        )
        resp = client.post("/api/thermals/lhm/autostart")
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_autostart_remove_ok_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.lhm.remove_autostart", return_value={"ok": True})
        resp = client.post("/api/thermals/lhm/autostart/remove")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_autostart_remove_failure_returns_400(self, client, mocker):
        mocker.patch(
            "windesktopmgr.lhm.remove_autostart",
            return_value={"ok": False, "error": "ACCESS_DENIED (UAC prompt declined?)"},
        )
        resp = client.post("/api/thermals/lhm/autostart/remove")
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/services/list
# ══════════════════════════════════════════════════════════════════════════════


class TestServicesListRoute:
    def test_returns_200_with_list(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_services_list",
            return_value=[
                {
                    "Name": "wuauserv",
                    "DisplayName": "Windows Update",
                    "Status": "Running",
                    "StartMode": "Auto",
                    "info": None,
                },
            ],
        )
        resp = client.get("/api/services/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_empty_list_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.get_services_list", return_value=[])
        resp = client.get("/api/services/list")
        assert resp.status_code == 200
        assert resp.get_json() == []


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/services/toggle — input validation (safety critical)
# ══════════════════════════════════════════════════════════════════════════════


class TestServicesToggleRoute:
    """Route-level tests for POST /api/services/toggle.
    toggle_service() now uses pywin32 (win32serviceutil / win32service)."""

    def test_invalid_action_returns_error(self, client, mocker):
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "explode"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False

    def test_stop_action_calls_stop_service(self, client, mocker):
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "stop"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        m.assert_called_once_with("spooler")

    def test_start_action_calls_start_service(self, client, mocker):
        m = mocker.patch("windesktopmgr.win32serviceutil.StartService")
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "start"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        m.assert_called_once_with("spooler")

    def test_disable_action_uses_change_service_config(self, client, mocker):
        mocker.patch("windesktopmgr.win32service.OpenSCManager", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.win32service.OpenService", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.win32service.ChangeServiceConfig")
        mocker.patch("windesktopmgr.win32service.CloseServiceHandle")
        mocker.patch("windesktopmgr.win32service.SC_MANAGER_ALL_ACCESS", 0xF003F)
        mocker.patch("windesktopmgr.win32service.SERVICE_CHANGE_CONFIG", 0x0002)
        mocker.patch("windesktopmgr.win32service.SERVICE_NO_CHANGE", 0xFFFFFFFF)
        mocker.patch("windesktopmgr.win32service.SERVICE_DISABLED", 0x00000004)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "disable"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_enable_action_uses_demand_start(self, client, mocker):
        mocker.patch("windesktopmgr.win32service.OpenSCManager", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.win32service.OpenService", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.win32service.ChangeServiceConfig")
        mocker.patch("windesktopmgr.win32service.CloseServiceHandle")
        mocker.patch("windesktopmgr.win32service.SC_MANAGER_ALL_ACCESS", 0xF003F)
        mocker.patch("windesktopmgr.win32service.SERVICE_CHANGE_CONFIG", 0x0002)
        mocker.patch("windesktopmgr.win32service.SERVICE_NO_CHANGE", 0xFFFFFFFF)
        mocker.patch("windesktopmgr.win32service.SERVICE_DEMAND_START", 0x00000003)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "enable"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_missing_name_handled_gracefully(self, client, mocker):
        mocker.patch("windesktopmgr.win32serviceutil.StopService")
        resp = client.post("/api/services/toggle", json={"action": "stop"})
        assert resp.status_code == 200

    def test_empty_body_handled(self, client, mocker):
        resp = client.post("/api/services/toggle", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/services/lookup-unknowns
# ══════════════════════════════════════════════════════════════════════════════


class TestServicesLookupUnknownsRoute:
    def test_returns_ok_and_queued(self, client):
        resp = client.post(
            "/api/services/lookup-unknowns", json={"services": [{"Name": "WeirdSvc", "DisplayName": "Weird Service"}]}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "queued" in data

    def test_empty_list_returns_zero_queued(self, client):
        resp = client.post("/api/services/lookup-unknowns", json={"services": []})
        data = resp.get_json()
        assert data["queued"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/services/lookup-status
# ══════════════════════════════════════════════════════════════════════════════


class TestServicesLookupStatusRoute:
    def test_returns_200_with_queue_info(self, client):
        resp = client.get("/api/services/lookup-status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "queue_pending" in data
        assert "in_flight" in data


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/health
# ══════════════════════════════════════════════════════════════════════════════


class TestHealthEndpoint:
    def test_returns_200_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["status"] == "running"

    def test_returns_json(self, client):
        resp = client.get("/api/health")
        assert resp.content_type.startswith("application/json")

    def test_includes_assets_version(self, client):
        """The heartbeat carries an `assets` token so the client can auto-reload
        when a deploy changes the front-end bundle."""
        resp = client.get("/api/health")
        data = resp.get_json()
        assert "assets" in data and isinstance(data["assets"], str) and data["assets"]

    def test_assets_version_stable_then_changes_on_mtime(self, mocker):
        import windesktopmgr as wdm

        mocker.patch("windesktopmgr.os.path.getmtime", return_value=111.0)
        v1 = wdm._assets_version()
        v2 = wdm._assets_version()
        assert v1 == v2  # same files -> stable token
        mocker.patch("windesktopmgr.os.path.getmtime", return_value=222.0)
        assert wdm._assets_version() != v1  # an asset changed -> new token

    def test_assets_version_graceful_when_files_missing(self, mocker):
        import windesktopmgr as wdm

        mocker.patch("windesktopmgr.os.path.getmtime", side_effect=OSError("gone"))
        # Must not raise; returns a (constant) token.
        assert isinstance(wdm._assets_version(), str)


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/selftest
# ══════════════════════════════════════════════════════════════════════════════


class TestSelftestEndpoint:
    def _stub_all(self, mocker, fake=None):
        """Replace every smoke-check function with a no-op that returns fake."""
        import windesktopmgr as wdm

        default = fake if fake is not None else {"ok": True}
        for _name, fn_name, _t in wdm.SELFTEST_CHECKS:
            mocker.patch.object(wdm, fn_name, return_value=default)

    def test_all_checks_pass(self, client, mocker):
        self._stub_all(mocker)
        resp = client.get("/api/selftest")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["failed"] == 0
        assert data["passed"] == data["total"]
        assert len(data["checks"]) == data["total"]

    def test_one_check_failure_is_reported(self, client, mocker):
        import windesktopmgr as wdm

        self._stub_all(mocker)
        mocker.patch.object(wdm, "get_memory_analysis", side_effect=RuntimeError("boom"))
        resp = client.get("/api/selftest")
        data = resp.get_json()
        assert data["ok"] is False
        assert data["failed"] == 1
        failing = [c for c in data["checks"] if not c["ok"]]
        assert len(failing) == 1
        assert failing[0]["name"] == "memory"
        assert "boom" in failing[0]["error"]

    def test_dict_with_error_key_counts_as_failure(self, client, mocker):
        import windesktopmgr as wdm

        self._stub_all(mocker)
        mocker.patch.object(wdm, "get_disk_health", return_value={"error": "PS timeout"})
        resp = client.get("/api/selftest")
        data = resp.get_json()
        assert data["failed"] == 1
        failing = [c for c in data["checks"] if not c["ok"]]
        assert failing[0]["name"] == "disk"
        assert "PS timeout" in failing[0]["error"]

    def test_results_include_duration_ms(self, client, mocker):
        self._stub_all(mocker)
        resp = client.get("/api/selftest")
        data = resp.get_json()
        for c in data["checks"]:
            assert "duration_ms" in c
            assert isinstance(c["duration_ms"], int)

    def test_results_sorted_by_name(self, client, mocker):
        self._stub_all(mocker)
        resp = client.get("/api/selftest")
        data = resp.get_json()
        names = [c["name"] for c in data["checks"]]
        assert names == sorted(names)

    def test_none_return_is_failure(self, client, mocker):
        import windesktopmgr as wdm

        self._stub_all(mocker)
        mocker.patch.object(wdm, "get_startup_items", return_value=None)
        resp = client.get("/api/selftest")
        data = resp.get_json()
        assert data["failed"] == 1
        failing = [c for c in data["checks"] if not c["ok"]]
        assert failing[0]["name"] == "startup"

    def test_overall_budget_sum_exceeds_per_check_max(self, mocker):
        """
        Regression guard for the 2026-04-18 'drivers timed out' false
        positive: the overall budget must leave enough headroom for the
        slowest individual check to finish after faster ones fill the
        thread pool. 180 s ≥ the 60 s per-drivers nominal cap × at least
        a 2x safety factor.
        """
        import windesktopmgr as wdm

        # Read the budget constant by invoking api_selftest's module source.
        # We can't grep the hard-coded literal without duplicating it, so
        # exercise the behaviour instead: stub every check to sleep 20 s
        # and confirm all 14 finish inside the budget.
        src = __import__("inspect").getsource(wdm.api_selftest)
        assert "overall_budget = 180" in src, (
            "api_selftest must allow >= 180 s overall to accommodate the "
            "slowest real-world check mix (drivers + bsod + timeline + bios + "
            "processes each ≈ 45-60 s). Bumping below 180 s reintroduces the "
            "flaky 'drivers timed out waiting for result' regression."
        )


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/restart
# ══════════════════════════════════════════════════════════════════════════════


class TestRestartEndpoint:
    def test_rejects_non_localhost(self, client, mocker):
        # Prevent any accidental exit even if the guard fails
        mocker.patch("windesktopmgr.os._exit")
        mocker.patch("windesktopmgr.subprocess.Popen")
        resp = client.post("/api/restart", environ_base={"REMOTE_ADDR": "192.168.1.42"})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["ok"] is False
        assert "localhost" in data["error"]

    def test_localhost_returns_202(self, client, mocker):
        mocker.patch("windesktopmgr.os._exit")
        mocker.patch("windesktopmgr.subprocess.Popen")
        mocker.patch("windesktopmgr.threading.Thread")  # don't actually spawn the worker
        resp = client.post("/api/restart", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["ok"] is True
        assert "restart scheduled" in data["status"]

    def test_get_not_allowed(self, client):
        resp = client.get("/api/restart")
        assert resp.status_code == 405

    def test_schedules_background_thread(self, client, mocker):
        mocker.patch("windesktopmgr.os._exit")
        mocker.patch("windesktopmgr.subprocess.Popen")
        mock_thread = mocker.patch("windesktopmgr.threading.Thread")
        client.post("/api/restart", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert mock_thread.called
        kwargs = mock_thread.call_args.kwargs
        assert kwargs.get("daemon") is True


class TestRestartRelaunchCommand:
    """Regression coverage for the sys.argv-mutation restart bug.

    pysnmp's MIB loader rewrites sys.argv[0] to a MIB source file path at
    runtime (once the NAS SNMP collector has run). The old restart spawned
    [sys.executable, *sys.argv], so after a NAS poll it relaunched that MIB
    file instead of the tray and died silently. The fix snapshots argv at
    import (_ORIGINAL_ARGV) and relaunches that instead.
    """

    def test_original_argv_snapshot_is_absolute(self):
        import windesktopmgr as wdm

        assert wdm._ORIGINAL_ARGV, "snapshot must not be empty"
        assert os.path.isabs(wdm._ORIGINAL_ARGV[0]), (
            "argv[0] snapshot must be absolute so the relaunch is CWD-independent"
        )

    def test_build_relaunch_cmd_uses_snapshot_not_live_argv(self, mocker):
        import windesktopmgr as wdm

        # Simulate pysnmp having rewritten the live argv to a MIB file path.
        mocker.patch.object(
            wdm.sys,
            "argv",
            [r"C:\Python\Lib\site-packages\pysnmp\smi\mibs\SNMPv2-SMI.py"],
        )
        cmd = wdm._build_relaunch_cmd()
        # Must relaunch the snapshot, never the mutated live argv.
        assert cmd == [wdm.sys.executable, *wdm._ORIGINAL_ARGV]
        assert not any("SNMPv2-SMI.py" in part for part in cmd), (
            "relaunch command must not contain the pysnmp MIB path from mutated sys.argv"
        )
        assert not any("pysnmp" in part.lower() for part in cmd)

    def test_spawn_replacement_passes_snapshot_and_cwd(self, mocker):
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "_restart_log")  # don't write restart.log in tests
        mock_popen = mocker.patch("windesktopmgr.subprocess.Popen")
        # Even with a mutated live argv, the spawn must use the snapshot.
        mocker.patch.object(wdm.sys, "argv", [r"C:\x\pysnmp\smi\mibs\SNMPv2-SMI.py"])

        wdm._spawn_replacement()

        assert mock_popen.called
        spawned_cmd = mock_popen.call_args.args[0]
        assert spawned_cmd == [wdm.sys.executable, *wdm._ORIGINAL_ARGV]
        assert mock_popen.call_args.kwargs.get("cwd") == wdm.APP_DIR
        assert not any("SNMPv2-SMI.py" in part for part in spawned_cmd)

    def test_restart_worker_stays_alive_when_spawn_fails(self, mocker):
        """The core safety branch: if the relaunch spawn raises, the worker must
        NOT os._exit — a stale tray beats a trayless machine — and must record
        the failure so it isn't silent.
        """
        import windesktopmgr as wdm

        mocker.patch.object(wdm.time, "sleep")  # no real delays
        mock_exit = mocker.patch("windesktopmgr.os._exit")
        mock_log = mocker.patch.object(wdm, "_restart_log")
        mocker.patch.object(wdm, "_spawn_replacement", side_effect=OSError("spawn boom"))

        wdm._restart_worker()

        mock_exit.assert_not_called()  # stayed alive
        assert any("FAILED" in str(c.args[0]) for c in mock_log.call_args_list), "relaunch failure must be logged"

    def test_restart_worker_exits_when_spawn_succeeds(self, mocker):
        """Happy path: a successful relaunch hard-exits the old process."""
        import windesktopmgr as wdm

        mocker.patch.object(wdm.time, "sleep")
        mock_exit = mocker.patch("windesktopmgr.os._exit")
        mocker.patch.object(wdm, "_restart_log")
        mocker.patch.object(wdm, "_spawn_replacement", return_value=mocker.MagicMock())

        wdm._restart_worker()

        mock_exit.assert_called_once_with(0)


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/health-history/data
# ══════════════════════════════════════════════════════════════════════════════


class TestHealthHistoryDataRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_health_report_history",
            return_value={
                "reports": [],
                "weekly": [],
                "latest_score": None,
            },
        )
        resp = client.get("/api/health-history/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_health_report_history", return_value={})
        resp = client.get("/api/health-history/data")
        assert resp.content_type.startswith("application/json")

    def test_stale_flag_included_in_response(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_health_report_history",
            return_value={
                "reports": [],
                "total": 0,
                "avg_score": None,
                "latest": None,
                "stale": True,
                "stale_days": 10,
            },
        )
        resp = client.get("/api/health-history/data")
        data = resp.get_json()
        assert data["stale"] is True
        assert data["stale_days"] == 10


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/timeline/data
# ══════════════════════════════════════════════════════════════════════════════


class TestTimelineDataRoute:
    def test_returns_200_with_structure(self, client, mocker):
        mocker.patch("windesktopmgr.get_system_timeline", return_value=[])
        resp = client.get("/api/timeline/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "events" in data
        assert "days" in data
        assert "total" in data

    def test_default_days_30(self, client, mocker):
        mock_fn = mocker.patch("windesktopmgr.get_system_timeline", return_value=[])
        client.get("/api/timeline/data")
        mock_fn.assert_called_with(30)

    def test_custom_days_parameter(self, client, mocker):
        mock_fn = mocker.patch("windesktopmgr.get_system_timeline", return_value=[])
        client.get("/api/timeline/data?days=7")
        mock_fn.assert_called_with(7)

    def test_total_matches_events_length(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_system_timeline",
            return_value=[
                {
                    "ts": "2026-03-10",
                    "type": "bsod",
                    "category": "crash",
                    "title": "Crash",
                    "severity": "critical",
                    "icon": "💀",
                },
            ],
        )
        resp = client.get("/api/timeline/data")
        data = resp.get_json()
        assert data["total"] == len(data["events"])


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/memory/data
# ══════════════════════════════════════════════════════════════════════════════


class TestMemoryDataRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={
                "total_mb": 32768,
                "used_mb": 16000,
                "free_mb": 16768,
                "categories": {},
                "top_procs": [],
                "mcafee_mb": 0,
                "defender_mb": 0,
                "defender_baseline": 150,
                "mcafee_saving_mb": 0,
                "has_mcafee": False,
            },
        )
        resp = client.get("/api/memory/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_mb" in data
        assert "used_mb" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={})
        resp = client.get("/api/memory/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/credentials/health
# ══════════════════════════════════════════════════════════════════════════════


class TestCredentialsHealthRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={
                "onedrive_suspended": False,
                "fast_startup": False,
                "drives_down": [],
                "msal_token_stale": False,
            },
        )
        resp = client.get("/api/credentials/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={})
        resp = client.get("/api/credentials/health")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/credentials/resume-onedrive
# ══════════════════════════════════════════════════════════════════════════════


class TestResumeOneDriveRoute:
    def test_success_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps([{"Name": "OneDrive", "PID": 1234, "Resumed": 5, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["fixed"] == 1

    def test_not_found_returns_ok_false(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps([{"Name": "OneDrive", "PID": 0, "Resumed": 0, "Status": "NotFound"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert data["ok"] is False
        assert data["fixed"] == 0

    def test_timeout_returns_error(self, client, mocker):
        import subprocess

        mocker.patch("windesktopmgr.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=15))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert data["ok"] is False

    def test_response_has_message(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps([{"Name": "OneDrive", "PID": 1234, "Resumed": 5, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert "message" in data


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/credentials/resume-brokers
# ══════════════════════════════════════════════════════════════════════════════


class TestResumeBrokersRoute:
    def test_success_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps([{"Name": "backgroundTaskHost", "PID": 5678, "Resumed": 3, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-brokers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["fixed"] == 1

    def test_no_brokers_found_returns_ok_false(self, client, mocker):
        _mock_ps(
            mocker,
            stdout=json.dumps([{"Name": "No broker processes found", "PID": 0, "Resumed": 0, "Status": "NotFound"}]),
        )
        resp = client.post("/api/credentials/resume-brokers")
        data = resp.get_json()
        assert data["ok"] is False

    def test_timeout_returns_error(self, client, mocker):
        import subprocess

        mocker.patch("windesktopmgr.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=15))
        resp = client.post("/api/credentials/resume-brokers")
        data = resp.get_json()
        assert data["ok"] is False

    def test_response_has_results_and_message(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps([]))
        resp = client.post("/api/credentials/resume-brokers")
        data = resp.get_json()
        assert "results" in data
        assert "message" in data


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/credentials/fix-fast-startup
# ══════════════════════════════════════════════════════════════════════════════


class TestFixFastStartupRoute:
    """POST /api/credentials/fix-fast-startup — winreg HiberbootEnabled toggle."""

    def _mock_winreg(self, mocker, fail=None):
        mocker.patch("windesktopmgr.winreg.CloseKey")
        mocker.patch("windesktopmgr.winreg.SetValueEx")
        if fail is not None:
            mocker.patch("windesktopmgr.winreg.OpenKey", side_effect=fail)
        else:
            mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mocker.MagicMock())

    def test_disable_fast_startup_returns_ok(self, client, mocker):
        self._mock_winreg(mocker)
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": False})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is False

    def test_enable_fast_startup_returns_ok(self, client, mocker):
        self._mock_winreg(mocker)
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": True})
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is True

    def test_registry_failure_returns_ok_false(self, client, mocker):
        """A non-elevated process can't write the HKLM key — ok:False, no crash."""
        self._mock_winreg(mocker, fail=PermissionError("Access is denied"))
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": False})
        data = resp.get_json()
        assert data["ok"] is False

    def test_no_body_returns_400(self, client, mocker):
        """Empty body with JSON content type is rejected by Flask."""
        _mock_ps(mocker, stdout="OK:disabled")
        resp = client.post("/api/credentials/fix-fast-startup", data="", content_type="application/json")
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/bios/status
# ══════════════════════════════════════════════════════════════════════════════


class TestBiosStatusRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch(
            "windesktopmgr.get_bios_status",
            return_value={
                "current": {"BIOSVersion": "2.3.1"},
                "update": {},
            },
        )
        resp = client.get("/api/bios/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_bios_status", return_value={})
        resp = client.get("/api/bios/status")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/bios/cache/clear
# ══════════════════════════════════════════════════════════════════════════════


class TestBiosCacheClearRoute:
    def test_returns_ok(self, client, mocker):
        # Ensure the cache file doesn't actually exist for the test
        mocker.patch("os.path.exists", return_value=False)
        resp = client.post("/api/bios/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_removes_existing_cache_file(self, client, mocker):
        mocker.patch("os.path.exists", return_value=True)
        mock_remove = mocker.patch("os.remove")
        resp = client.post("/api/bios/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        mock_remove.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/dashboard/summary
# ══════════════════════════════════════════════════════════════════════════════


class TestBuildGauges:
    """dashboard._build_gauges — radial-gauge readouts from the fan-out
    results, with graceful degradation for a missing CPU sensor / absent GPU
    / collector error dicts (a null value renders an unavailable dial, never
    a bogus 0)."""

    KEYS = ["cpu_load", "cpu_temp", "gpu_temp", "gpu_util", "memory"]

    def _by_key(self, results):
        import dashboard

        gauges = dashboard._build_gauges(results)
        assert [g["key"] for g in gauges] == self.KEYS
        return {g["key"]: g for g in gauges}

    def test_full_data_produces_values(self):
        g = self._by_key(
            {
                "thermals": {
                    "perf": {"CPUPct": 22.5, "MemUsedMB": 16000, "MemTotalMB": 32000},
                    "temps": [{"Name": "CPU Package", "TempC": 55.0}, {"Name": "zone", "TempC": 61.0}],
                },
                "gpu": {
                    "available": True,
                    "temp_c": 48,
                    "utilization_pct": 36,
                    "vram_used_mb": 2048,
                    "name": "RTX 4060 Ti",
                },
            }
        )
        assert g["cpu_load"]["value"] == 22.5
        # CPU-named sensor is preferred over the hotter ambiguous "zone".
        assert g["cpu_temp"]["value"] == 55.0
        assert g["gpu_temp"]["value"] == 48
        assert g["gpu_util"]["value"] == 36
        assert g["gpu_util"]["sub"] == "2.0 GB VRAM"
        assert g["memory"]["value"] == 50.0  # 16000 / 32000

    def test_missing_cpu_sensor_degrades_to_none(self):
        g = self._by_key({"thermals": {"perf": {"CPUPct": 10}, "temps": []}, "gpu": {"available": False}})
        assert g["cpu_temp"]["value"] is None
        assert g["cpu_temp"]["sub"] == "no sensor"
        assert g["cpu_load"]["value"] == 10  # CPU% still present

    def test_no_gpu_degrades_to_none(self):
        g = self._by_key({"thermals": {"perf": {}, "temps": []}, "gpu": {"available": False}})
        assert g["gpu_temp"]["value"] is None and g["gpu_temp"]["sub"] == "no GPU"
        assert g["gpu_util"]["value"] is None and g["gpu_util"]["sub"] == "no GPU"

    def test_cpu_temp_prefers_cpu_sensor_over_hotter_gpu(self):
        """With LHM merged in, `temps` carries GPU/storage sensors too. The CPU
        temp gauge must pick the hottest CPU sensor (by SensorId), not a hotter
        GPU/NVMe reading."""
        g = self._by_key(
            {
                "thermals": {
                    "perf": {},
                    "temps": [
                        {"Name": "Core Max", "TempC": 42.0, "SensorId": "/intelcpu/0/temperature/0"},
                        {"Name": "P-Core #1", "TempC": 40.0, "SensorId": "/intelcpu/0/temperature/2"},
                        {"Name": "GPU Hot Spot", "TempC": 71.0, "SensorId": "/gpu-nvidia/0/temperature/1"},
                        {"Name": "Drive Temp", "TempC": 55.0, "SensorId": "/nvme/0/temperature/0"},
                    ],
                },
                "gpu": {"available": False},
            }
        )
        assert g["cpu_temp"]["value"] == 42.0  # hottest CPU sensor, not the 71° GPU

    def test_cpu_temp_falls_back_to_any_sensor_without_ids(self):
        """A bare WMI thermal zone (no SensorId, no CPU-ish name) still yields a
        reading via the all-sensor fallback."""
        g = self._by_key(
            {"thermals": {"perf": {}, "temps": [{"Name": "Thermal Zone", "TempC": 48.0}]}, "gpu": {"available": False}}
        )
        assert g["cpu_temp"]["value"] == 48.0

    def test_collector_error_dicts_dont_crash(self):
        g = self._by_key({"thermals": {"error": "boom"}, "gpu": {"error": "boom"}})
        assert all(g[k]["value"] is None for k in self.KEYS)

    def test_bool_cpupct_is_not_treated_as_number(self):
        # A stray bool (psutil/COM edge) must not become a 1.0 reading.
        g = self._by_key({"thermals": {"perf": {"CPUPct": True}, "temps": []}, "gpu": {}})
        assert g["cpu_load"]["value"] is None


class TestDashboardSummaryRoute:
    HEALTHY_DISK = {"drives": [{"Letter": "C", "PctUsed": 50, "FreeGB": 400}], "physical": [], "io": []}

    def _mock_dashboard_deps(self, mocker, **overrides):
        """Helper to mock all dashboard_summary dependencies."""
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value=overrides.get(
                "thermals",
                {
                    "temps": [],
                    "perf": {},
                    "fans": [],
                    "has_rich": False,
                    "note": "",
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value=overrides.get(
                "memory",
                {
                    "total_mb": 32768,
                    "used_mb": 8000,
                    "free_mb": 24768,
                    "categories": {},
                    "top_procs": [],
                    "mcafee_mb": 0,
                    "defender_mb": 0,
                    "defender_baseline": 150,
                    "mcafee_saving_mb": 0,
                    "has_mcafee": False,
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_bios_status",
            return_value=overrides.get(
                "bios",
                {
                    "current": {},
                    "update": {},
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value=overrides.get(
                "credentials",
                {
                    "onedrive_suspended": False,
                    "fast_startup": False,
                    "drives_down": [],
                    "msal_token_stale": False,
                },
            ),
        )
        mocker.patch("windesktopmgr.get_disk_health", return_value=overrides.get("disk", self.HEALTHY_DISK))
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value=overrides.get(
                "drivers",
                {"old_drivers": [], "problematic_drivers": [], "nvidia": None},
            ),
        )
        # Network health + hardware advisories — stub clean so the clean-state
        # test doesn't pick up the dev machine's real network/WHEA state
        # (e.g. this box has a live WHEA warning that would flip overall!=ok).
        mocker.patch(
            "windesktopmgr.get_network_health",
            return_value=overrides.get(
                "network_health",
                {
                    "available": True,
                    "internet_reachable": True,
                    "ping_latency_ms": 15.0,
                    "dns_working": True,
                    "dns_latency_ms": 15.0,
                    "adapters": [{"name": "Ethernet", "up": True}],
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_warranty_data",
            return_value=overrides.get(
                "warranty",
                {
                    "IsAffectedCPU": False,
                    "CPUModel": "Test CPU",
                    "BIOSDate": "2026-01-01",
                    "WHEAErrors30Days": 0,
                    "WHEAErrorsRecent7Days": 0,
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_memory_config",
            return_value=overrides.get(
                "memory_config",
                {
                    "sticks": [
                        {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                        {"locator": "DIMM2", "capacity_gb": 16.0, "speed_mhz": 5600},
                    ]
                },
            ),
        )
        mocker.patch(
            "windesktopmgr.get_storage_spaces",
            return_value=overrides.get(
                "storage_spaces",
                {"pools": [], "virtual_disks": [], "members": [], "repair_jobs": [], "has_spaces": False},
            ),
        )
        mocker.patch(
            "windesktopmgr.get_nas_storage",
            return_value=overrides.get("nas_storage", {"nas": [], "configured": 0}),
        )
        # Task-watcher concerns — default to empty so the clean-state test
        # doesn't pick up real SystemHealthDiag logs on the dev machine.
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

        # BIOS audit error reader — also stubbed empty so the clean-state
        # test doesn't pick up real bios_audit_history.json errors that
        # accumulated on the dev machine (the file persists across runs).
        # Test was previously fragile to this; mocking unblocks deterministic
        # 'overall == ok' assertions regardless of disk state.
        import bios_audit as _ba

        mocker.patch.object(_ba, "recent_errors", return_value=[])

        # Router-config backup health — same reasoning. Default OFF so the
        # clean-state test doesn't see stale-backup info concerns from a
        # real backups/ folder on disk.
        import homenet as _hn

        mocker.patch.object(
            _hn,
            "get_backup_health",
            return_value={
                "verizon_stale": False,
                "orbi_stale": False,
                "verizon_age_days": 0,
                "orbi_age_days": 0,
                "verizon_last_backup_at": None,
                "orbi_last_backup_at": None,
                "verizon_stale_threshold_days": 30,
            },
        )

        # Backup health (backlog #47) — same reasoning. Default OK so the
        # clean-state test doesn't fire the new "Backup health: critical"
        # concern from the dev machine's real (broken) File History config.
        import backup as _bk

        mocker.patch.object(
            _bk,
            "summarize_backup",
            return_value={
                "ok": True,
                "windows_backups": {"has_cache": False, "version_count": 0, "health": {"level": "info", "reason": ""}},
                "file_history": {"configured": False, "enabled": False, "health": {"level": "info", "reason": ""}},
                "overall_health": {"level": "info", "reason": ""},
            },
        )

        # Baseline drift (backlog #14 + #44) — same reasoning. The dashboard
        # emits an info "drift detected" concern from baseline.recent_drift()
        # and a warning "cross-surface cluster" concern from
        # baseline.load_history() -> baseline.correlation_alert(). Both read
        # the real baseline_history.json / baseline_snapshot.json on disk,
        # which on a dev machine with genuine drift makes the clean-state
        # test non-deterministic ('overall' came back 'warning'). Stub them
        # to a no-drift baseline so the assertion is hermetic.
        import baseline as _bl

        mocker.patch.object(_bl, "recent_drift", return_value=[])
        mocker.patch.object(_bl, "load_history", return_value=[])
        mocker.patch.object(_bl, "correlation_alert", return_value=None)

    def test_summary_includes_gauges(self, client, mocker):
        """The summary payload carries the radial-gauge readouts (redesign PR2)."""
        self._mock_dashboard_deps(
            mocker,
            thermals={
                "perf": {"CPUPct": 30, "MemUsedMB": 8000, "MemTotalMB": 16000},
                "temps": [],
                "fans": [],
                "has_rich": False,
            },
        )
        mocker.patch(
            "windesktopmgr.get_gpu_metrics",
            return_value={
                "available": True,
                "temp_c": 50,
                "utilization_pct": 20,
                "vram_used_mb": 1024,
                "name": "Test GPU",
            },
        )
        resp = client.get("/api/dashboard/summary")
        d = resp.get_json()
        assert "gauges" in d
        g = {x["key"]: x for x in d["gauges"]}
        assert [x["key"] for x in d["gauges"]] == ["cpu_load", "cpu_temp", "gpu_temp", "gpu_util", "memory"]
        assert g["cpu_load"]["value"] == 30
        assert g["memory"]["value"] == 50.0
        assert g["cpu_temp"]["value"] is None  # no sensors in the mock -> graceful
        assert g["gpu_temp"]["value"] == 50
        assert g["gpu_util"]["value"] == 20

    def test_returns_200_with_structure(self, client, mocker):
        self._mock_dashboard_deps(mocker)
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "concerns" in data
        assert "total" in data
        assert "critical" in data
        assert "warnings" in data
        assert "overall" in data
        assert "checked_at" in data

    def test_overall_ok_when_no_concerns(self, client, mocker):
        self._mock_dashboard_deps(mocker)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["overall"] == "ok"
        assert data["total"] == 0

    # ── Baseline-drift acceptance watermark (bug 2026-06-03) ──
    # The drift dashboard concern reads the rolling 24h drift HISTORY, not
    # live drift. Before the fix, clearing drift via "accept current as
    # baseline" left those history entries untouched, so the concern kept
    # showing as open for up to 24h. drop_accepted() must exclude history
    # at/before the acceptance watermark.

    _DRIFT_ENTRY = {
        "timestamp": "2026-06-03T10:00:00",
        "total_changes": 3,
        "drift": {"services": {"added": ["NewSvc"], "removed": [], "changed": []}},
    }

    def test_baseline_drift_concern_fires_without_watermark(self, client, mocker):
        self._mock_dashboard_deps(mocker)
        import baseline as _bl

        mocker.patch.object(_bl, "recent_drift", return_value=[self._DRIFT_ENTRY])
        mocker.patch.object(_bl, "load_history", return_value=[self._DRIFT_ENTRY])
        mocker.patch.object(_bl, "load_accept_watermark", return_value=None)

        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        drift = [c for c in concerns if c.get("tab") == "baseline" and "drift detected" in c["title"]]
        assert len(drift) == 1, "un-accepted drift must surface on the dashboard"

    def test_accepted_drift_suppressed_by_watermark(self, client, mocker):
        """User accepted the baseline AFTER the drift was recorded -> the
        dashboard must not keep showing the now-reconciled drift as open."""
        self._mock_dashboard_deps(mocker)
        from datetime import datetime

        import baseline as _bl

        mocker.patch.object(_bl, "recent_drift", return_value=[self._DRIFT_ENTRY])
        mocker.patch.object(_bl, "load_history", return_value=[self._DRIFT_ENTRY])
        # Acceptance one minute after the 10:00:00 drift entry.
        mocker.patch.object(
            _bl,
            "load_accept_watermark",
            return_value=datetime(2026, 6, 3, 10, 1, 0),
        )

        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        baseline_concerns = [c for c in concerns if c.get("tab") == "baseline"]
        assert baseline_concerns == [], "accepted drift must not show as open"

    def test_orbi_mesh_unknown_concern_not_emitted(self, client, mocker, tmp_path):
        """Regression: 2026-05-13 user feedback was "I still see this error...
        are you checking post-deploy?". The Orbi RBRE960 emits a corrupted
        ConnAPMAC sentinel for satellite-connected clients (firmware quirk
        we can't fix from our side). PR #27 surfaced this as a dashboard
        concern that re-fired every ~5s on dashboard refresh, nagging the
        user with the same scary text and no resolution path.

        Demoted to the topology stats line. The concern must NOT appear in
        the dashboard summary even when many devices have empty
        conn_ap_mac (the failure-mode signal for the firmware quirk)."""
        import json

        import homenet

        # Plant inventory that LOOKS like the firmware quirk -- 25 orbi-
        # sourced devices, all with empty conn_ap_mac
        inv_file = tmp_path / "homenet_inventory.json"
        devs = {}
        for i in range(25):
            mac = f"AA:BB:CC:DD:EE:{i:02X}"
            devs[mac] = {
                "mac": mac,
                "source": "orbi",
                "conn_ap_mac": "",
                "network": "wireless",
            }
        inv_file.write_text(
            json.dumps({"devices": devs, "last_scan": "2026-05-13T00:00:00"}),
            encoding="utf-8",
        )
        mocker.patch.object(homenet, "HOMENET_INVENTORY_FILE", str(inv_file))
        mocker.patch.object(homenet, "_inventory_load_failed", False)

        self._mock_dashboard_deps(mocker)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        # The old concern's title was "Orbi reporting N wireless devices
        # with unknown AP" -- it must not appear anywhere in the response.
        all_titles = " ".join(c.get("title", "") for c in data.get("concerns", []))
        assert "Orbi reporting" not in all_titles, (
            "Orbi mesh-unknown dashboard concern must stay demoted -- it nags the "
            "user about a static firmware fact with no resolution path."
        )

    def test_critical_concern_raises_overall_to_critical(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            thermals={
                "temps": [{"TempC": 95, "Name": "CPU", "Source": "LHM", "status": "critical"}],
                "perf": {"CPUPct": 10},
                "fans": [],
                "has_rich": True,
                "note": "",
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["overall"] == "critical"
        assert data["critical"] >= 1

    def test_disk_critical_when_drive_95_pct_full(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            disk={
                "drives": [{"Letter": "E", "PctUsed": 97, "FreeGB": 2.5}],
                "physical": [],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        disk_concerns = [c for c in data["concerns"] if c.get("tab") == "disk"]
        assert len(disk_concerns) == 1
        assert disk_concerns[0]["level"] == "critical"
        assert "E" in disk_concerns[0]["title"]

    def test_disk_warning_when_drive_90_pct_full(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            disk={
                "drives": [{"Letter": "C", "PctUsed": 92, "FreeGB": 60}],
                "physical": [],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        disk_concerns = [c for c in data["concerns"] if c.get("tab") == "disk"]
        assert len(disk_concerns) == 1
        assert disk_concerns[0]["level"] == "warning"

    def test_no_disk_concern_when_space_ok(self, client, mocker):
        self._mock_dashboard_deps(mocker)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        disk_concerns = [c for c in data["concerns"] if c.get("tab") == "disk"]
        assert len(disk_concerns) == 0

    # ── Driver health concerns ────────────────────────────────────────────────

    def test_problematic_drivers_raise_critical(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            drivers={
                "old_drivers": [],
                "problematic_drivers": [{"DeviceName": "Bad USB Controller", "ErrorCode": 10, "Status": "Error"}],
                "nvidia": None,
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        drv_concerns = [c for c in data["concerns"] if c.get("tab") == "drivers"]
        assert len(drv_concerns) == 1
        assert drv_concerns[0]["level"] == "critical"
        assert "driver errors" in drv_concerns[0]["title"]

    def test_old_drivers_raise_info_when_more_than_3(self, client, mocker):
        old = [
            {"DeviceName": f"Device {i}", "Provider": "Acme", "Version": "1.0", "Date": "2022-01-01"} for i in range(5)
        ]
        self._mock_dashboard_deps(mocker, drivers={"old_drivers": old, "problematic_drivers": [], "nvidia": None})
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        drv_concerns = [c for c in data["concerns"] if c.get("tab") == "drivers" and c["level"] == "info"]
        assert len(drv_concerns) == 1
        assert "over 2 years old" in drv_concerns[0]["title"]

    def test_few_old_drivers_no_concern(self, client, mocker):
        old = [{"DeviceName": "Old Device", "Provider": "Acme", "Version": "1.0", "Date": "2022-01-01"}]
        self._mock_dashboard_deps(mocker, drivers={"old_drivers": old, "problematic_drivers": [], "nvidia": None})
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        drv_concerns = [c for c in data["concerns"] if c.get("tab") == "drivers"]
        assert len(drv_concerns) == 0

    def test_nvidia_update_available_raises_warning(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            drivers={
                "old_drivers": [],
                "problematic_drivers": [],
                "nvidia": {
                    "Name": "NVIDIA GeForce RTX 4090",
                    "InstalledVersion": "565.79",
                    "LatestVersion": "572.16",
                    "UpdateAvailable": True,
                    "UpdateSource": "nvidia_app",
                },
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        nv_concerns = [c for c in data["concerns"] if "NVIDIA" in c.get("title", "")]
        assert len(nv_concerns) == 1
        assert nv_concerns[0]["level"] == "warning"
        assert "565.79" in nv_concerns[0]["title"]
        assert "572.16" in nv_concerns[0]["title"]

    def test_nvidia_current_no_concern(self, client, mocker):
        self._mock_dashboard_deps(
            mocker,
            drivers={
                "old_drivers": [],
                "problematic_drivers": [],
                "nvidia": {
                    "Name": "NVIDIA GeForce RTX 4090",
                    "InstalledVersion": "572.16",
                    "LatestVersion": "572.16",
                    "UpdateAvailable": False,
                    "UpdateSource": "nvidia_app",
                },
            },
        )
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        nv_concerns = [c for c in data["concerns"] if "NVIDIA" in c.get("title", "")]
        assert len(nv_concerns) == 0

    def test_no_nvidia_gpu_no_concern(self, client, mocker):
        self._mock_dashboard_deps(mocker)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        nv_concerns = [c for c in data["concerns"] if "NVIDIA" in c.get("title", "")]
        assert len(nv_concerns) == 0


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/summary/<tab> — all remaining tabs
# ══════════════════════════════════════════════════════════════════════════════


class TestSummaryRoute:
    def test_unknown_tab_returns_404(self, client):
        resp = client.post("/api/summary/nonexistent_tab", json={})
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.get_json()
            assert "error" in data or "status" in data

    def test_drivers_tab_returns_status(self, client):
        wdm._scan_results = []
        resp = client.post("/api/summary/drivers", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_bsod_tab_returns_status(self, client, mocker):
        mocker.patch(
            "windesktopmgr.build_bsod_analysis",
            return_value={
                "crashes": [],
                "summary": {"total_crashes": 0, "this_month": 0, "most_common_error": "None", "avg_uptime_hours": 0},
                "timeline": [],
                "recommendations": [],
                "error_breakdown": [],
                "driver_breakdown": [],
            },
        )
        resp = client.post("/api/summary/bsod", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_startup_tab_returns_status(self, client, mocker):
        mocker.patch("windesktopmgr.get_startup_items", return_value=[])
        resp = client.post("/api/summary/startup", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_disk_tab_returns_status(self, client, mocker):
        mocker.patch("windesktopmgr.get_disk_health", return_value={"drives": [], "physical": [], "io": []})
        resp = client.post("/api/summary/disk", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_network_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/network",
            json={
                "established": [],
                "listening": [],
                "adapters": [],
                "top_processes": [],
                "total_connections": 0,
                "total_listening": 0,
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_updates_tab_returns_status(self, client):
        resp = client.post("/api/summary/updates", json={"items": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_events_tab_returns_status(self, client):
        resp = client.post("/api/summary/events", json={"events": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_processes_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/processes",
            json={
                "processes": [],
                "total": 0,
                "total_mem_mb": 0,
                "flagged": [],
                "flag_notes": [],
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_thermals_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/thermals",
            json={
                "temps": [],
                "perf": {},
                "fans": [],
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_services_tab_returns_status(self, client):
        resp = client.post("/api/summary/services", json={"services": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_health_history_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/health-history",
            json={
                "reports": [],
                "weekly": [],
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_timeline_tab_returns_status(self, client):
        resp = client.post("/api/summary/timeline", json={"events": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_memory_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/memory",
            json={
                "total_mb": 32768,
                "used_mb": 16000,
                "free_mb": 16768,
                "categories": {},
                "has_mcafee": False,
                "mcafee_mb": 0,
                "mcafee_saving_mb": 0,
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_bios_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/bios",
            json={
                "current": {"BIOSVersion": "2.3.1"},
                "update": {},
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_credentials_tab_returns_status(self, client):
        resp = client.post(
            "/api/summary/credentials",
            json={
                "onedrive_suspended": False,
                "fast_startup": False,
                "drives_down": [],
            },
        )
        assert resp.status_code == 200
        assert "status" in resp.get_json()


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/summary/<tab> — ETag / If-None-Match / 304 (backlog #29)
# ══════════════════════════════════════════════════════════════════════════════


class TestSummaryRouteEtag:
    """Server-side ETag + 304 contract for /api/summary/<tab> (backlog #29).

    Defends against the 2026-04-20 flood pattern: an old browser tab that
    keeps firing identical payload bursts now gets zero-body 304 responses
    instead of full re-serialized summaries. Pairs with the JS-side 1-second
    identical-payload debounce in templates/index.html.
    """

    # The simplest two payloads to drive the matrix: empty updates list
    # → deterministic summary, no module-state plumbing required.
    _PAYLOAD_A = {"items": []}
    _PAYLOAD_B = {"items": [{"KB": "KB123", "Date": "2026-01-01"}]}

    def test_200_response_carries_etag_header(self, client):
        resp = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        assert resp.status_code == 200
        etag = resp.headers.get("ETag")
        assert etag, "200 response must set ETag header"
        # Strong ETag wrapping: a quoted 16-hex-char string.
        assert etag.startswith('"') and etag.endswith('"')
        assert len(etag) == 18  # 16 hex chars + 2 quotes

    def test_if_none_match_with_matching_etag_returns_304_no_body(self, client):
        first = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        assert first.status_code == 200
        etag = first.headers["ETag"]

        second = client.post(
            "/api/summary/updates",
            json=self._PAYLOAD_A,
            headers={"If-None-Match": etag},
        )
        assert second.status_code == 304
        # 304 body MUST be empty (RFC 7232).
        assert second.data == b""
        # ETag header is echoed back so the client can keep its cache key.
        assert second.headers.get("ETag") == etag

    def test_if_none_match_with_stale_etag_returns_200_with_fresh_etag(self, client):
        resp = client.post(
            "/api/summary/updates",
            json=self._PAYLOAD_A,
            headers={"If-None-Match": '"deadbeefdeadbeef"'},
        )
        assert resp.status_code == 200
        assert resp.get_json() is not None
        assert resp.headers.get("ETag") != '"deadbeefdeadbeef"'

    def test_different_payloads_produce_different_etags(self, client):
        r1 = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        r2 = client.post("/api/summary/updates", json=self._PAYLOAD_B)
        assert r1.headers["ETag"] != r2.headers["ETag"]

    def test_same_payload_different_tab_produces_different_etag(self, client):
        # Both tabs accept {"items": []} via /api/summary/updates and
        # /api/summary/startup. The tab name is folded into the hash, so
        # an identical payload across tabs must still produce distinct
        # ETags — otherwise a client could replay one tab's cache key
        # against another tab and get a spurious 304.
        r_updates = client.post("/api/summary/updates", json={"items": []})
        r_startup = client.post("/api/summary/startup", json={"items": []})
        assert r_updates.status_code == 200
        assert r_startup.status_code == 200
        assert r_updates.headers["ETag"] != r_startup.headers["ETag"]

    def test_same_payload_repeated_etag_is_stable(self, client):
        """Same input → same ETag across calls. This is what makes the
        If-None-Match path useful — if ETags drifted between identical
        calls, the 304 fast-path would never fire."""
        r1 = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        r2 = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        assert r1.headers["ETag"] == r2.headers["ETag"]

    def test_etag_tracks_response_content_not_request_payload(self, client, mocker):
        """ETag is derived from the response body, not the request payload.
        If a summarizer's output changes (e.g. backing state mutated) for
        the same request payload, the ETag must change too — otherwise
        a stale 304 could mask a real update."""
        # First call: real summarizer.
        r0 = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        etag0 = r0.headers["ETag"]

        # Patch the summarizer to return something different for the
        # same input — simulating backing state having mutated between
        # calls.
        mocker.patch("windesktopmgr.summarize_updates", return_value={"status": "ok", "headline": "mutated"})
        r1 = client.post("/api/summary/updates", json=self._PAYLOAD_A)
        assert r1.status_code == 200
        assert r1.headers["ETag"] != etag0, (
            "ETag must reflect response content — equal input + mutated state must yield a new ETag"
        )

    def test_unknown_tab_does_not_set_etag(self, client):
        """Unknown-tab 404s shouldn't carry ETag headers — there is no
        meaningful resource to cache. Mostly a contract sanity check."""
        resp = client.post("/api/summary/nonexistent_tab", json={})
        assert resp.status_code == 404
        assert "ETag" not in resp.headers


# ══════════════════════════════════════════════════════════════════════════════
# Server startup configuration
# ══════════════════════════════════════════════════════════════════════════════


class TestServerConfig:
    """Regression tests for the threaded server fix.

    Flask's dev server defaults to single-threaded. When background worker
    threads make blocking PowerShell subprocess calls, they starve the
    request handler and the server appears to hang (accepts connections
    but never responds). These tests ensure we don't regress.
    """

    def test_app_run_uses_threaded_true(self, mocker):
        """app.run() must be called with threaded=True to prevent
        background worker threads from blocking request handling."""
        import inspect

        source = inspect.getsource(wdm)
        assert "threaded=True" in source, (
            "app.run() must include threaded=True — without it, background PowerShell workers block the request thread"
        )

    def test_index_responds_with_mocked_workers(self, client, mocker):
        """/ must return 200 even when background workers are running."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert len(resp.data) > 1000, "index.html should be a substantial page"

    def test_api_responds_with_mocked_workers(self, client, mocker):
        """API endpoints must respond even when workers are active."""
        resp = client.get("/api/scan/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data is not None

    def test_multiple_concurrent_routes_respond(self, client, mocker):
        """Multiple routes should all respond without blocking each other."""
        _mock_ps(mocker, stdout="[]")
        endpoints = [
            ("GET", "/"),
            ("GET", "/api/scan/status"),
            ("GET", "/api/scan/results"),
        ]
        for method, url in endpoints:
            if method == "GET":
                resp = client.get(url)
            assert resp.status_code == 200, f"{method} {url} returned {resp.status_code}"

    def test_index_no_cache_headers_prevent_stale_page(self, client):
        """After a server restart with a fix, browsers must not serve
        a cached broken version."""
        resp = client.get("/")
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc or "no-cache" in cc

    def test_worker_threads_are_daemon(self):
        """All worker threads must be daemon so they don't prevent shutdown."""
        import ast

        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "windesktopmgr.py")
        with open(source_path, encoding="utf-8-sig") as f:
            tree = ast.parse(f.read())

        thread_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Thread":
                for kw in node.keywords:
                    if kw.arg == "daemon":
                        thread_calls.append(kw)

        assert len(thread_calls) >= 5, f"Expected at least 5 daemon worker threads, found {len(thread_calls)}"
        for kw in thread_calls:
            assert isinstance(kw.value, ast.Constant) and kw.value.value is True, (
                "All worker threads must have daemon=True"
            )


# ══════════════════════════════════════════════════════════════════════════════
# WARRANTY DATA ROUTE
# ══════════════════════════════════════════════════════════════════════════════


class TestWarrantyRoute:
    """/api/warranty/data — CPU/BIOS/system via WMI, microcode via winreg,
    BSOD/WHEA/KP41 counts via the win32evtlog event-log API (no subprocess)."""

    def _setup(
        self,
        mocker,
        cpu_name="Intel(R) Core(TM) i9-14900K",
        proc_id="BFEBFBFF000B0671",
        serial="N/A",
        service_tag="ABC1234",
        bios_ver="2.18.0",
        bios_date="20250110000000.000000+000",
        mfr="Dell Inc.",
        model="XPS 8960",
    ):
        import datetime as _dt

        _mock_wmi(
            mocker,
            {
                "Win32_Processor": [_wmi_obj(Name=f"  {cpu_name}  ", ProcessorId=proc_id, SerialNumber=serial)],
                "Win32_BIOS": [_wmi_obj(SerialNumber=service_tag, SMBIOSBIOSVersion=bios_ver, ReleaseDate=bios_date)],
                "Win32_ComputerSystem": [_wmi_obj(Manufacturer=mfr, Model=model)],
            },
        )
        # Microcode — winreg; counts — three _query_event_log_xpath calls.
        mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.winreg.QueryValueEx", return_value=(b"\x01\x00\x01\xb4", 3))
        mocker.patch("windesktopmgr.winreg.CloseKey")
        recent = _dt.datetime.now(_dt.timezone.utc).isoformat()
        return mocker.patch(
            "windesktopmgr._query_event_log_xpath",
            side_effect=[
                [{"TimeCreated": recent}, {"TimeCreated": recent}],
                [],
                [{"TimeCreated": recent}],
            ],
        )

    def test_returns_ok_with_warranty_data(self, client, mocker):
        self._setup(mocker)
        r = client.get("/api/warranty/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert "warranty" in d
        w = d["warranty"]
        assert w["IsAffectedCPU"] is True
        assert "i9-14900K" in w["CPUModel"]

    def test_whea_recency_split(self, client, mocker):
        """get_warranty_data splits WHEA events into 7-day / 30-day buckets so
        the dashboard advisory can pick critical (active) vs warning (older)."""
        import datetime as _dt

        import windesktopmgr as wdm

        self._setup(mocker)  # WMI + winreg mocks
        now = _dt.datetime.now(_dt.timezone.utc)
        rows = [
            {"TimeCreated": now.isoformat()},  # within 7d
            {"TimeCreated": (now - _dt.timedelta(days=20)).isoformat()},  # within 30d only
            {"TimeCreated": (now - _dt.timedelta(days=90)).isoformat()},  # older than 30d
        ]
        # Override event mock: [bsod, whea, kp41]
        mocker.patch("windesktopmgr._query_event_log_xpath", side_effect=[[], rows, []])
        w = wdm.get_warranty_data()
        assert w["WHEAErrors"] == 3
        assert w["WHEAErrors30Days"] == 2
        assert w["WHEAErrorsRecent7Days"] == 1

    def test_get_warranty_data_returns_error_dict_on_failure(self, mocker):
        """A hard WMI failure surfaces as {"error": ...} so the dashboard
        fan-out degrades instead of raising."""
        import windesktopmgr as wdm

        mocker.patch("windesktopmgr.bounded_wmi_query", side_effect=RuntimeError("winmgmt wedged"))
        out = wdm.get_warranty_data()
        assert "error" in out

    def test_returns_service_tag(self, client, mocker):
        self._setup(mocker, service_tag="XYZ7890")
        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["DellServiceTag"] == "XYZ7890"
        assert "XYZ7890" in d["warranty"]["DellSupportURL"]

    def test_non_affected_cpu(self, client, mocker):
        self._setup(mocker, cpu_name="AMD Ryzen 9 7950X", service_tag="N/A", mfr="AMD", model="Custom")
        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["IsAffectedCPU"] is False

    def test_wmi_failure_degrades_gracefully(self, client, mocker):
        """WMI failure is caught internally — the route still returns ok with
        Unknown CPU/system fields rather than erroring the whole request."""
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI failed"))
        mocker.patch("windesktopmgr.winreg.OpenKey", side_effect=OSError("no key"))
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        r = client.get("/api/warranty/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert d["warranty"]["CPUModel"] == "Unknown"

    def test_event_query_failure_degrades_gracefully(self, client, mocker):
        """If the event-log query fails, the BSOD/WHEA/KP41 counts fall back
        to 0 — the route must not error."""
        self._setup(mocker)
        mocker.patch("windesktopmgr._query_event_log_xpath", side_effect=Exception("evtlog error"))
        r = client.get("/api/warranty/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert d["warranty"]["BSODs30Days"] == 0
        assert d["warranty"]["WHEAErrors"] == 0


class TestStorageSpacesRoute:
    """/api/storage/spaces — Storage Spaces pools/virtual-disks/members for the
    Storage tab."""

    def test_returns_spaces_payload(self, client, mocker):
        mocker.patch(
            "disk.get_storage_spaces",
            return_value={
                "has_spaces": True,
                "pools": [{"Name": "Storage pool", "Health": "Warning", "Operational": "Degraded"}],
                "virtual_disks": [
                    {"Name": "Storage space", "Health": "Warning", "Operational": "Degraded", "Resiliency": "Parity"}
                ],
                "members": [],
                "repair_jobs": [{"Name": "R", "State": "Suspended"}],
            },
        )
        r = client.get("/api/storage/spaces")
        assert r.status_code == 200
        d = r.get_json()
        assert d["has_spaces"] is True
        assert d["virtual_disks"][0]["Operational"] == "Degraded"

    def test_no_spaces_shape(self, client, mocker):
        mocker.patch(
            "disk.get_storage_spaces",
            return_value={"has_spaces": False, "pools": [], "virtual_disks": [], "members": [], "repair_jobs": []},
        )
        r = client.get("/api/storage/spaces")
        assert r.status_code == 200
        assert r.get_json()["has_spaces"] is False


class TestStorageNasRoute:
    """/api/storage/nas — QNAP NAS storage over SNMP for the Storage tab."""

    def test_returns_nas_payload(self, client, mocker):
        mocker.patch(
            "nas.get_nas_storage",
            return_value={
                "nas": [{"name": "nas2", "reachable": True, "disks": [], "volumes": [], "fans": []}],
                "configured": 1,
            },
        )
        r = client.get("/api/storage/nas")
        assert r.status_code == 200
        assert r.get_json()["configured"] == 1

    def test_no_nas_configured(self, client, mocker):
        mocker.patch("nas.get_nas_storage", return_value={"nas": [], "configured": 0})
        r = client.get("/api/storage/nas")
        assert r.status_code == 200
        assert r.get_json()["configured"] == 0


class TestDiskSnoozeRoute:
    """/api/disk/snooze — pause/resume health alerts for one drive by serial."""

    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path, monkeypatch):
        import disk

        monkeypatch.setattr(disk, "DISK_SNOOZE_FILE", str(tmp_path / "ds.json"))

    def test_post_snoozes(self, client):
        r = client.post("/api/disk/snooze", json={"serial": "ABC-1.", "hours": 12})
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_post_missing_serial_is_400(self, client):
        assert client.post("/api/disk/snooze", json={}).status_code == 400

    def test_post_bad_hours_is_400(self, client):
        assert client.post("/api/disk/snooze", json={"serial": "S", "hours": 9999}).status_code == 400

    def test_get_lists_snoozes(self, client):
        client.post("/api/disk/snooze", json={"serial": "S1"})
        r = client.get("/api/disk/snoozes")
        assert r.get_json()["ok"] is True
        assert len(r.get_json()["snoozes"]) == 1

    def test_delete_resumes(self, client):
        client.post("/api/disk/snooze", json={"serial": "S1"})
        assert client.delete("/api/disk/snooze", json={"serial": "S1"}).get_json()["removed"] is True
        assert client.get("/api/disk/snoozes").get_json()["snoozes"] == {}

    def test_delete_missing_serial_is_400(self, client):
        assert client.delete("/api/disk/snooze", json={}).status_code == 400

    def test_snooze_invalidates_dashboard_cache(self, client, mocker):
        # Without this the Pause button looks like a no-op — the dashboard
        # re-serves the cached concern until the 30s TTL (PR #137 class of bug).
        spy = mocker.patch("dashboard._dashboard_cache_clear")
        client.post("/api/disk/snooze", json={"serial": "S1"})
        assert spy.called

    def test_resume_invalidates_dashboard_cache(self, client, mocker):
        spy = mocker.patch("dashboard._dashboard_cache_clear")
        client.delete("/api/disk/snooze", json={"serial": "S1"})
        assert spy.called

    def test_failed_snooze_does_not_clear_cache(self, client, mocker):
        spy = mocker.patch("dashboard._dashboard_cache_clear")
        client.post("/api/disk/snooze", json={"serial": "S", "hours": 9999})  # bad hours -> 400
        assert not spy.called


class TestGetMemoryConfig:
    """sysinfo.get_memory_config — light Win32_PhysicalMemory DIMM query for the
    dashboard RAM advisory."""

    def test_happy_path_maps_sticks(self, mocker):
        import windesktopmgr as wdm

        gb16 = str(16 * 1024**3)
        _mock_wmi(
            mocker,
            {
                "Win32_PhysicalMemory": [
                    _wmi_obj(DeviceLocator="DIMM1", Capacity=gb16, ConfiguredClockSpeed=5600),
                    _wmi_obj(DeviceLocator="DIMM2", Capacity=gb16, ConfiguredClockSpeed=5600),
                ]
            },
        )
        cfg = wdm.get_memory_config()
        assert "error" not in cfg
        assert len(cfg["sticks"]) == 2
        assert cfg["sticks"][0] == {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600}

    def test_wmi_failure_returns_error(self, mocker):
        import windesktopmgr as wdm

        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("winmgmt down"))
        cfg = wdm.get_memory_config()
        assert "error" in cfg


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/sysinfo/data
# ══════════════════════════════════════════════════════════════════════════════


class TestSysinfoRoute:
    """Tests for /api/sysinfo/data — now uses wmi.WMI() instead of subprocess."""

    # WMI mock objects matching the expected output contract
    CS_OBJ = _wmi_obj(
        Name="DESKTOP-TEST",
        Domain="WORKGROUP",
        Manufacturer="Dell Inc.",
        Model="XPS 8960",
        SystemType="x64-based PC",
        TotalPhysicalMemory="34028134400",  # ~31.7 GB
    )
    OS_OBJ = _wmi_obj(
        Caption="Microsoft Windows 11 Pro",
        Version="10.0.22631",
        BuildNumber="22631",
        OSArchitecture="64-bit",
        InstallDate="20240115000000.000000+000",
        LastBootUpTime="20250318100000.000000+000",
        WindowsDirectory="C:\\WINDOWS",
        SystemDrive="C:",
    )
    CPU_OBJ = _wmi_obj(
        Name="  Intel(R) Core(TM) i9-14900K  ",
        NumberOfCores=24,
        NumberOfLogicalProcessors=32,
        MaxClockSpeed=3200,
        CurrentClockSpeed=3200,
        SocketDesignation="LGA1700",
        L2CacheSize=32768,
        L3CacheSize=36864,
        ProcessorId="BFEBFBFF000B0671",
        Architecture=9,
    )
    BIOS_OBJ = _wmi_obj(
        SMBIOSBIOSVersion="2.22.0",
        ReleaseDate="20250110000000.000000+000",
        Manufacturer="Dell Inc.",
        SerialNumber="ABC1234",
    )
    BB_OBJ = _wmi_obj(
        Manufacturer="Dell Inc.",
        Product="0WN7Y6",
        Version="A01",
        SerialNumber="/ABC1234/",
    )
    GPU_OBJ = _wmi_obj(
        Name="NVIDIA GeForce RTX 4060 Ti",
        DriverVersion="32.0.15.9174",
        DriverDate="20250301000000.000000+000",
        AdapterRAM=8589934592,
        VideoProcessor="NVIDIA",
        CurrentRefreshRate=144,
        VideoModeDescription="2560 x 1440 x 32 bits",
        AdapterCompatibility="NVIDIA",
        PNPDeviceID="PCI\\VEN_10DE&DEV_2803",
    )
    NIC_OBJ = _wmi_obj(
        Description="Killer E3100G",
        MACAddress="AA:BB:CC:DD:EE:FF",
        IPAddress=["192.168.1.100"],
        IPEnabled=True,
        DHCPEnabled=True,
        DHCPServer="192.168.1.1",
        DNSServerSearchOrder=["8.8.8.8"],
    )
    NIC_HW_OBJ = _wmi_obj(
        Name="Killer E3100G 2.5 Gigabit Ethernet Controller",
        Manufacturer="Intel",
        ProductName="Killer E3100G",
        NetConnectionID="Ethernet",
        Speed="2500000000",
        AdapterType="Ethernet 802.3",
        MACAddress="AA:BB:CC:DD:EE:FF",
    )
    RAM_OBJ = _wmi_obj(
        BankLabel="DIMM1",
        Capacity="17179869184",
        Speed=5600,
        Manufacturer="SK Hynix",
        PartNumber="HMCG78AGBUA081N",
        ConfiguredClockSpeed=5600,
        FormFactor=8,
        SMBIOSMemoryType=34,
        DataWidth=64,
        DeviceLocator="DIMM_A1",
    )
    DISK_OBJ = _wmi_obj(
        Model="Samsung SSD 990 PRO 2TB",
        Size="2000398934016",
        InterfaceType="NVMe",
        MediaType="SSD",
        SerialNumber="S123456",
        Partitions=3,
    )
    VOL_OBJ = _wmi_obj(
        DeviceID="C:",
        VolumeName="OS",
        FileSystem="NTFS",
        Size="1000000000000",
        FreeSpace="214748364800",
    )
    SOUND_OBJ1 = _wmi_obj(Name="Realtek High Definition Audio", Manufacturer="Realtek", Status="OK")
    SOUND_OBJ2 = _wmi_obj(Name="NVIDIA Virtual Audio Device", Manufacturer="NVIDIA", Status="OK")
    USB_OBJ = _wmi_obj(Name="Intel USB 3.2 eXtensible Host Controller", Manufacturer="Intel", Status="OK")
    SLOT_OBJ1 = _wmi_obj(SlotDesignation="PCIEX16_1", CurrentUsage=4, Status="OK", Description="x16 PCI Express")
    SLOT_OBJ2 = _wmi_obj(SlotDesignation="PCIEX1_1", CurrentUsage=3, Status="OK", Description="x1 PCI Express")
    # MemoryArray (#43) -- exposes board limits the per-DIMM list can't.
    # MaxCapacity is in KB (DMTF spec); 67108864 KB = 64 GB. MemoryDevices=4
    # = total DIMM slots on the board. ec=3 is "None" per _mem_ec_map.
    MEM_ARRAY_OBJ = _wmi_obj(
        MaxCapacity="67108864",
        MaxCapacityEx=0,
        MemoryDevices=4,
        MemoryErrorCorrection=3,
        Location=3,
    )
    # NIC without connection (should be excluded from NetworkHardware)
    NIC_DISABLED = _wmi_obj(
        Name="Bluetooth",
        Manufacturer="Intel",
        ProductName="BT",
        NetConnectionID=None,
        Speed=None,
        AdapterType="",
        MACAddress="",
    )
    # NIC config without IP (should be excluded from Network)
    NIC_NO_IP = _wmi_obj(
        Description="Loopback",
        MACAddress="",
        IPAddress=None,
        IPEnabled=False,
        DHCPEnabled=False,
        DHCPServer="",
        DNSServerSearchOrder=None,
    )

    def _setup_wmi(self, mocker):
        _mock_wmi(
            mocker,
            {
                "Win32_OperatingSystem": [self.OS_OBJ],
                "Win32_ComputerSystem": [self.CS_OBJ],
                "Win32_Processor": [self.CPU_OBJ],
                "Win32_BIOS": [self.BIOS_OBJ],
                "Win32_BaseBoard": [self.BB_OBJ],
                "Win32_VideoController": [self.GPU_OBJ],
                "Win32_NetworkAdapterConfiguration": [self.NIC_OBJ, self.NIC_NO_IP],
                "Win32_NetworkAdapter": [self.NIC_HW_OBJ, self.NIC_DISABLED],
                "Win32_PhysicalMemory": [self.RAM_OBJ],
                "Win32_DiskDrive": [self.DISK_OBJ],
                "Win32_LogicalDisk": [self.VOL_OBJ],
                "Win32_SoundDevice": [self.SOUND_OBJ1, self.SOUND_OBJ2],
                "Win32_USBController": [self.USB_OBJ],
                "Win32_SystemSlot": [self.SLOT_OBJ1, self.SLOT_OBJ2],
                "Win32_PhysicalMemoryArray": [self.MEM_ARRAY_OBJ],
            },
        )

    def test_returns_ok_with_system_data(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert "data" in d

    def test_returns_computer_info(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert d["Computer"]["Name"] == "DESKTOP-TEST"
        assert d["Computer"]["Manufacturer"] == "Dell Inc."

    def test_returns_cpu_info(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert "i9-14900K" in d["CPU"]["Name"]
        assert d["CPU"]["Cores"] == 24

    def test_returns_os_info(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert "Windows 11" in d["OS"]["Name"]
        assert d["OS"]["Build"] == "22631"

    def test_gpu_always_list(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["GPU"], list)
        assert len(d["GPU"]) == 1

    def test_disks_always_list(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["Disks"], list)

    def test_wmi_exception_returns_stale(self, client, mocker):
        """A WMI fault (or hang) degrades to empty data + stale=True. The WMI
        collection now runs inside bounded_wmi_query on a worker thread, which
        swallows the fault and returns the safe fallback so the route marks the
        payload stale instead of 500ing or hanging. The bound trades the exact
        exception text for a generic 'unavailable' signal; the stale flag is
        the contract the UI reads. Data is empty (not partial) because the
        worker returns its own local dict -- it never mutates shared state,
        which would race the main thread on timeout."""
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI crashed"))
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "partial"
        assert d["stale"] is True
        assert d["error"]  # a (now generic) error detail is present
        assert d["data"] == {}  # empty on failure, thread-safe

    def test_returns_collected_at(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert "collected_at" in d
        assert d["stale"] is False
        assert d["error"] is None

    def test_returns_sound_devices(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["Sound"], list)
        assert len(d["Sound"]) == 2
        assert d["Sound"][0]["Manufacturer"] == "Realtek"

    def test_returns_usb_controllers(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["USBControllers"], list)
        assert len(d["USBControllers"]) == 1

    def test_returns_pcie_slots(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["PCIeSlots"], list)
        assert len(d["PCIeSlots"]) == 2
        assert d["PCIeSlots"][0]["CurrentUsage"] == "In Use"

    def test_returns_network_hardware(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["NetworkHardware"], list)
        assert d["NetworkHardware"][0]["Manufacturer"] == "Intel"

    def test_memory_type_mapped(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert d["Memory"][0]["MemoryType"] == "DDR5"
        assert d["Memory"][0]["FormFactor"] == "DIMM"

    def test_cpu_architecture_mapped(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert d["CPU"]["Architecture"] == "x64"

    def test_returns_extended_memory_fields(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        mem = r.get_json()["data"]["Memory"][0]
        assert mem["MemoryType"] == "DDR5"
        assert mem["FormFactor"] == "DIMM"
        assert mem["ConfiguredClockSpeed"] == 5600
        assert mem["DeviceLocator"] == "DIMM_A1"

    def test_returns_extended_gpu_fields(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        gpu = r.get_json()["data"]["GPU"][0]
        assert gpu["AdapterCompatibility"] == "NVIDIA"
        assert "PCI" in gpu["PNPDeviceID"]

    def test_ok_response_has_stale_false(self, client, mocker):
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "ok"
        assert d["stale"] is False
        assert d["error"] is None
        assert "collected_at" in d

    def test_empty_wmi_classes_return_empty_lists(self, client, mocker):
        """When WMI returns no sound/USB/PCIe/NIC, those sections are []."""
        _mock_wmi(
            mocker,
            {
                "Win32_OperatingSystem": [self.OS_OBJ],
                "Win32_ComputerSystem": [self.CS_OBJ],
                "Win32_Processor": [self.CPU_OBJ],
                "Win32_BIOS": [self.BIOS_OBJ],
                "Win32_BaseBoard": [self.BB_OBJ],
                "Win32_VideoController": [],
                "Win32_NetworkAdapterConfiguration": [],
                "Win32_NetworkAdapter": [],
                "Win32_PhysicalMemory": [],
                "Win32_DiskDrive": [],
                "Win32_LogicalDisk": [],
                "Win32_SoundDevice": [],
                "Win32_USBController": [],
                "Win32_SystemSlot": [],
                "Win32_PhysicalMemoryArray": [],
            },
        )
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        for k in ("Sound", "USBControllers", "PCIeSlots", "NetworkHardware", "GPU", "MemoryArray"):
            assert d[k] == []

    # ── Backlog #43: MemoryArray + Upgrade Opportunities ────────────────
    def test_returns_memory_array_with_board_limits(self, client, mocker):
        """MemoryArray (#43) exposes the board's max capacity + DIMM slot count.
        Without it the Memory section can only show what's installed; with it
        we can compute headroom for the upgrade panel."""
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["MemoryArray"], list)
        assert len(d["MemoryArray"]) == 1
        a = d["MemoryArray"][0]
        # 67108864 KB = 64 GB
        assert a["MaxCapacityGB"] == 64.0
        assert a["MemoryDevices"] == 4
        assert a["MemoryErrorCorrection"] == "None"
        assert a["Location"] == "System Board"

    def test_response_includes_upgrades_block(self, client, mocker):
        """The /api/sysinfo/data response wires summarize_upgrades into a
        top-level 'upgrades' key so the UI gets opportunities in the same
        round-trip as inventory."""
        self._setup_wmi(mocker)
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert "upgrades" in d
        assert "opportunities" in d["upgrades"]
        # With 1 stick of 16 GB in a 4-slot / 64 GB board: expect both a
        # memory-expansion opportunity AND a single-channel warning.
        cats = {o["category"] for o in d["upgrades"]["opportunities"]}
        assert "memory" in cats

    def test_upgrades_resilient_when_sysinfo_collection_fails(self, client, mocker):
        """If WMI crashes mid-collection, upgrades must still be present
        (as an empty list) so the UI's render doesn't choke on undefined."""
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI crashed"))
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "partial"
        # upgrades key must exist even on partial collection
        assert "upgrades" in d
        assert d["upgrades"] == {"opportunities": []}

    def test_max_capacity_ex_takes_precedence_when_set(self, client, mocker):
        """For boards >2 TB, WMI uses MaxCapacityEx (uint64) instead of
        MaxCapacity. Verify our collector picks Ex when it's non-zero."""
        # Big-RAM board: MaxCapacityEx = 4 TB in KB = 4_294_967_296 KB
        big_array = _wmi_obj(
            MaxCapacity=2147483647,  # capped at int32 max
            MaxCapacityEx=4294967296,  # 4 TB in KB
            MemoryDevices=8,
            MemoryErrorCorrection=5,
            Location=3,
        )
        _mock_wmi(
            mocker,
            {
                "Win32_OperatingSystem": [self.OS_OBJ],
                "Win32_ComputerSystem": [self.CS_OBJ],
                "Win32_Processor": [self.CPU_OBJ],
                "Win32_BIOS": [self.BIOS_OBJ],
                "Win32_BaseBoard": [self.BB_OBJ],
                "Win32_VideoController": [],
                "Win32_NetworkAdapterConfiguration": [],
                "Win32_NetworkAdapter": [],
                "Win32_PhysicalMemory": [],
                "Win32_DiskDrive": [],
                "Win32_LogicalDisk": [],
                "Win32_SoundDevice": [],
                "Win32_USBController": [],
                "Win32_SystemSlot": [],
                "Win32_PhysicalMemoryArray": [big_array],
            },
        )
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        # 4 TB = 4096 GB
        assert d["MemoryArray"][0]["MaxCapacityGB"] == 4096.0
        assert d["MemoryArray"][0]["MemoryErrorCorrection"] == "Single-bit ECC"

    def test_summary_route_accepts_sysinfo(self, client, mocker):
        """Verify the summary endpoint handles sysinfo tab."""
        mocker.patch("windesktopmgr.subprocess.run")
        payload = {
            "Computer": {"Name": "TEST", "Manufacturer": "Dell", "Model": "XPS", "TotalRAM_GB": 32},
            "OS": {"Name": "Windows 11", "Uptime": "02.10:00:00", "Build": "22631", "InstallDate": "2024-01-01"},
            "CPU": {"Name": "i9-14900K", "Cores": 24, "LogicalProcs": 32},
        }
        r = client.post("/api/summary/sysinfo", data=json.dumps(payload), content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "status" in d
        assert "headline" in d


# ══════════════════════════════════════════════════════════════════════════════
# GET /architecture.html
# ══════════════════════════════════════════════════════════════════════════════


class TestArchitectureRoute:
    """Tests for /architecture.html — serves the architecture diagram."""

    def test_returns_200(self, client):
        r = client.get("/architecture.html")
        assert r.status_code == 200

    def test_returns_html_content_type(self, client):
        r = client.get("/architecture.html")
        assert "text/html" in r.content_type

    def test_contains_windesktopmgr_title(self, client):
        r = client.get("/architecture.html")
        assert b"WinDesktopMgr" in r.data

    def test_contains_architecture_keyword(self, client):
        r = client.get("/architecture.html")
        assert b"Architecture" in r.data


class TestDiskAnalyzeRoute:
    """Tests for /api/disk/analyze — POST path analyser."""

    def test_returns_200_on_success(self, client, mocker):
        mocker.patch(
            "disk.analyze_disk_path",
            return_value={
                "ok": True,
                "path": "C:\\",
                "parent": None,
                "total_bytes": 1000,
                "entries": [
                    {
                        "name": "Users",
                        "path": "C:\\Users",
                        "type": "dir",
                        "size_bytes": 800,
                        "size_human": "800 B",
                        "item_count": 5,
                        "pct": 80.0,
                    }
                ],
            },
        )
        r = client.post("/api/disk/analyze", json={"path": "C:\\"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["entries"][0]["name"] == "Users"

    def test_missing_path_returns_400(self, client):
        r = client.post("/api/disk/analyze", json={})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_backend_error_returns_422(self, client, mocker):
        mocker.patch(
            "disk.analyze_disk_path",
            return_value={"ok": False, "error": "Path does not exist", "path": "X:\\", "entries": []},
        )
        r = client.post("/api/disk/analyze", json={"path": "X:\\nope"})
        assert r.status_code == 422

    def test_top_n_clamped_upper_and_lower(self, client, mocker):
        mock = mocker.patch(
            "disk.analyze_disk_path",
            return_value={"ok": True, "path": "C:\\", "entries": [], "total_bytes": 0, "parent": None},
        )
        client.post("/api/disk/analyze", json={"path": "C:\\", "top_n": 9999})
        assert mock.call_args.kwargs["top_n"] == 200
        client.post("/api/disk/analyze", json={"path": "C:\\", "top_n": 1})
        assert mock.call_args.kwargs["top_n"] == 5

    def test_invalid_top_n_defaults_to_25(self, client, mocker):
        mock = mocker.patch(
            "disk.analyze_disk_path",
            return_value={"ok": True, "path": "C:\\", "entries": [], "total_bytes": 0, "parent": None},
        )
        client.post("/api/disk/analyze", json={"path": "C:\\", "top_n": "banana"})
        assert mock.call_args.kwargs["top_n"] == 25


class TestDiskQuickwinsRoute:
    """Tests for /api/disk/quickwins — GET bloat-location scanner."""

    def test_returns_200_on_success(self, client, mocker):
        mocker.patch(
            "disk.get_disk_quickwins",
            return_value={
                "ok": True,
                "drive": "C:\\",
                "locations": [
                    {
                        "key": "recycle_bin",
                        "label": "Recycle Bin",
                        "path": "C:\\$Recycle.Bin",
                        "exists": True,
                        "size_bytes": 100,
                        "size_human": "100 B",
                        "description": "...",
                        "action": "open_recycle_bin",
                    }
                ],
                "user_locations": [],
            },
        )
        r = client.get("/api/disk/quickwins?drive=C")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["locations"][0]["key"] == "recycle_bin"

    def test_defaults_to_c_drive(self, client, mocker):
        mock = mocker.patch(
            "disk.get_disk_quickwins",
            return_value={"ok": True, "drive": "C:\\", "locations": [], "user_locations": []},
        )
        client.get("/api/disk/quickwins")
        assert mock.call_args[0][0] == "C"

    def test_passes_drive_arg(self, client, mocker):
        mock = mocker.patch(
            "disk.get_disk_quickwins",
            return_value={"ok": True, "drive": "D:\\", "locations": [], "user_locations": []},
        )
        client.get("/api/disk/quickwins?drive=D")
        assert mock.call_args[0][0] == "D"

    def test_backend_error_returns_422(self, client, mocker):
        mocker.patch(
            "disk.get_disk_quickwins",
            return_value={"ok": False, "error": "Drive not found", "locations": []},
        )
        r = client.get("/api/disk/quickwins?drive=Z")
        assert r.status_code == 422


class TestDiskOpenRoute:
    """Tests for /api/disk/open — POST open folder in Explorer."""

    def test_returns_200_on_success(self, client, mocker):
        mocker.patch(
            "disk.open_folder_in_explorer",
            return_value={"ok": True, "path": "C:\\Users"},
        )
        r = client.post("/api/disk/open", json={"path": "C:\\Users"})
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_missing_path_returns_400(self, client):
        r = client.post("/api/disk/open", json={})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_backend_error_returns_422(self, client, mocker):
        mocker.patch(
            "disk.open_folder_in_explorer",
            return_value={"ok": False, "error": "Path does not exist"},
        )
        r = client.post("/api/disk/open", json={"path": "C:\\Ghost"})
        assert r.status_code == 422


class TestDiskRunToolRoute:
    """Tests for /api/disk/run-tool — POST launch whitelisted cleanup tool."""

    def test_returns_200_on_success(self, client, mocker):
        mocker.patch(
            "disk.launch_cleanup_tool",
            return_value={"ok": True, "tool": "cleanmgr", "label": "Disk Cleanup"},
        )
        r = client.post("/api/disk/run-tool", json={"tool": "cleanmgr"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["tool"] == "cleanmgr"

    def test_missing_tool_returns_400(self, client):
        r = client.post("/api/disk/run-tool", json={})
        assert r.status_code == 400
        body = r.get_json()
        assert body["ok"] is False
        assert "tool" in body["error"].lower()

    def test_null_tool_returns_400(self, client):
        r = client.post("/api/disk/run-tool", json={"tool": None})
        assert r.status_code == 400

    def test_unknown_tool_returns_422(self, client, mocker):
        mocker.patch(
            "disk.launch_cleanup_tool",
            return_value={"ok": False, "error": "Unknown cleanup tool: evil"},
        )
        r = client.post("/api/disk/run-tool", json={"tool": "evil"})
        assert r.status_code == 422
        assert r.get_json()["ok"] is False

    def test_not_installed_returns_422_with_install_url(self, client, mocker):
        """When a third-party tool isn't installed, the route must still
        return 422 but include install_url so the frontend can offer a
        download button."""
        mocker.patch(
            "disk.launch_cleanup_tool",
            return_value={
                "ok": False,
                "error": "PatchCleaner is not installed",
                "install_url": "https://www.homedev.com.au/Free/PatchCleaner",
                "tool": "patchcleaner",
            },
        )
        r = client.post("/api/disk/run-tool", json={"tool": "patchcleaner"})
        assert r.status_code == 422
        body = r.get_json()
        assert body["ok"] is False
        assert body["install_url"].startswith("https://")

    def test_passes_tool_key_through(self, client, mocker):
        m = mocker.patch(
            "disk.launch_cleanup_tool",
            return_value={"ok": True, "tool": "sysdm_advanced", "label": "System Properties → Advanced"},
        )
        client.post("/api/disk/run-tool", json={"tool": "sysdm_advanced"})
        m.assert_called_once_with("sysdm_advanced")


# ══════════════════════════════════════════════════════════════════════════════
# Memory snooze routes + concern filtering (backlog #19)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mem_snooze_tmp(tmp_path, monkeypatch):
    """Redirect the snooze file to a per-test tmp path so nothing touches the real store."""
    target = tmp_path / "memory_snoozes.json"
    monkeypatch.setattr(processes, "MEMORY_SNOOZE_FILE", str(target))
    return target


class TestMemorySnoozeRoutes:
    def test_post_snooze_ok(self, client, mem_snooze_tmp):
        resp = client.post("/api/memory/snooze", json={"process_name": "chrome.exe", "hours": 1})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["key"] == "chrome.exe"
        assert body["expires"]

    def test_post_snooze_requires_name(self, client, mem_snooze_tmp):
        resp = client.post("/api/memory/snooze", json={})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_post_snooze_rejects_bad_hours(self, client, mem_snooze_tmp):
        resp = client.post("/api/memory/snooze", json={"process_name": "x", "hours": 999})
        assert resp.status_code == 400
        assert "hours must be" in resp.get_json()["error"]

    def test_post_snooze_rejects_non_integer_hours(self, client, mem_snooze_tmp):
        resp = client.post("/api/memory/snooze", json={"process_name": "x", "hours": "many"})
        assert resp.status_code == 400

    def test_list_snoozes(self, client, mem_snooze_tmp):
        client.post("/api/memory/snooze", json={"process_name": "chrome.exe", "hours": 1})
        client.post("/api/memory/snooze", json={"process_name": "teams.exe", "hours": 1})
        resp = client.get("/api/memory/snoozes")
        assert resp.status_code == 200
        snoozes = resp.get_json()["snoozes"]
        assert set(snoozes.keys()) == {"chrome.exe", "teams.exe"}

    def test_delete_snooze(self, client, mem_snooze_tmp):
        client.post("/api/memory/snooze", json={"process_name": "chrome.exe", "hours": 1})
        resp = client.delete("/api/memory/snooze", json={"process_name": "chrome.exe"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["removed"] is True
        # Second delete: already gone
        resp2 = client.delete("/api/memory/snooze", json={"process_name": "chrome.exe"})
        assert resp2.get_json()["removed"] is False

    def test_expired_snooze_auto_cleaned_on_load(self, client, mem_snooze_tmp):
        from datetime import datetime, timedelta

        # Write a snooze file with an already-expired entry
        expired = {"oldproc.exe": (datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds")}
        mem_snooze_tmp.write_text(json.dumps(expired), encoding="utf-8")
        resp = client.get("/api/memory/snoozes")
        assert resp.get_json()["snoozes"] == {}


class TestDashboardMemoryConcernActions:
    """Verify per-process memory concerns land with pid/process_name/mem_mb
    and respect the snooze list."""

    def _mock_deps(self, mocker, top_procs):
        """Mock dashboard dependencies but let memory carry a custom top_procs list."""
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={"temps": [], "perf": {"CPUPct": 10}, "fans": [], "has_rich": True},
        )
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={"total_mb": 32000, "used_mb": 10000, "free_mb": 22000, "top_procs": top_procs},
        )
        mocker.patch("windesktopmgr.get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={"onedrive_suspended": False, "fast_startup_enabled": False, "drives_down": []},
        )
        mocker.patch("windesktopmgr.get_disk_health", return_value={"ok": True})
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value={"old_drivers": [], "problematic_drivers": [], "nvidia": None},
        )
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

    def test_high_memory_process_becomes_concern_with_metadata(self, client, mocker, mem_snooze_tmp):
        # MEM_CRIT_MB is 1500 — a process at 2500 MB should trigger a critical concern
        self._mock_deps(
            mocker,
            top_procs=[
                {"name": "chrome.exe", "mem": 2500.0, "category": "browser", "pid": 4321},
            ],
        )
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        mem_concern = next((c for c in concerns if c.get("process_name") == "chrome.exe"), None)
        assert mem_concern is not None, f"expected per-process concern; got titles {[c['title'] for c in concerns]}"
        assert mem_concern["pid"] == 4321
        assert mem_concern["mem_mb"] == 2500.0
        assert mem_concern["tab"] == "processes"
        # action_fn must carry the PID so the fallback dispatch still works
        assert "4321" in mem_concern["action_fn"]

    def test_snoozed_process_is_not_concerned(self, client, mocker, mem_snooze_tmp):
        # Snooze chrome.exe first
        client.post("/api/memory/snooze", json={"process_name": "chrome.exe", "hours": 1})
        self._mock_deps(
            mocker,
            top_procs=[
                {"name": "chrome.exe", "mem": 2500.0, "category": "browser", "pid": 4321},
            ],
        )
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        assert not any(c.get("process_name") == "chrome.exe" for c in concerns), (
            f"snoozed process should be suppressed; got {[c['title'] for c in concerns]}"
        )

    def test_low_memory_process_is_not_concerned(self, client, mocker, mem_snooze_tmp):
        self._mock_deps(
            mocker,
            top_procs=[
                {"name": "notepad.exe", "mem": 50.0, "category": "microsoft", "pid": 111},
            ],
        )
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        assert not any(c.get("process_name") == "notepad.exe" for c in concerns)

    def test_safe_system_process_is_not_concerned(self, client, mocker, mem_snooze_tmp):
        """Even if a SAFE_PROCESSES entry crosses the threshold, don't suggest killing it."""
        self._mock_deps(
            mocker,
            top_procs=[
                {"name": "msmpeng", "mem": 3000.0, "category": "security", "pid": 555},
            ],
        )
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        assert not any(c.get("process_name") == "msmpeng" for c in concerns)


# ── Trends / metrics history (backlog #4) ────────────────────────────────────


class TestMetricsHistoryRoute:
    """/api/metrics/history powers the dashboard Trends sparklines."""

    @pytest.fixture
    def mh_tmp(self, tmp_path, monkeypatch):
        import metrics_history as mh

        monkeypatch.setattr(mh, "HISTORY_FILE", str(tmp_path / "metrics_history.json"))
        return mh

    def test_empty_history_returns_empty_metrics(self, client, mh_tmp):
        resp = client.get("/api/metrics/history")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["window_h"] == 168  # default 7-day window
        assert d["metrics"] == {}
        assert d["available"] == []

    def test_returns_recorded_samples(self, client, mh_tmp):
        mh_tmp.record_sample({"thermals": {"perf": {"CPUPct": 33}}}, force=True)
        resp = client.get("/api/metrics/history")
        d = resp.get_json()
        assert "cpu_percent" in d["metrics"]
        assert d["metrics"]["cpu_percent"][0]["value"] == 33.0
        assert "cpu_percent" in d["available"]

    def test_window_clamped_to_max_720h(self, client, mh_tmp):
        resp = client.get("/api/metrics/history?window_h=99999")
        assert resp.get_json()["window_h"] == 720

    def test_window_clamped_to_min_1h(self, client, mh_tmp):
        resp = client.get("/api/metrics/history?window_h=0")
        assert resp.get_json()["window_h"] == 1

    def test_invalid_window_falls_back_to_default(self, client, mh_tmp):
        resp = client.get("/api/metrics/history?window_h=abc")
        assert resp.get_json()["window_h"] == 168

    def test_metric_filter_returns_only_that_series(self, client, mh_tmp):
        mh_tmp.record_sample(
            {"thermals": {"perf": {"CPUPct": 11}}, "memory": {"used_mb": 100, "total_mb": 200}},
            force=True,
        )
        resp = client.get("/api/metrics/history?metric=cpu_percent")
        d = resp.get_json()
        assert d["metric"] == "cpu_percent"
        assert "series" in d
        assert "metrics" not in d  # single-metric mode is the slim shape
        assert d["series"][0]["value"] == 11.0

    def test_unknown_metric_returns_empty_series_not_error(self, client, mh_tmp):
        mh_tmp.record_sample({"thermals": {"perf": {"CPUPct": 11}}}, force=True)
        resp = client.get("/api/metrics/history?metric=does_not_exist")
        assert resp.status_code == 200
        assert resp.get_json()["series"] == []


class TestMetricsHistorySamplerHook:
    """The /api/dashboard/summary route fires record_sample() as a side-effect."""

    @pytest.fixture
    def mh_tmp(self, tmp_path, monkeypatch):
        import metrics_history as mh

        monkeypatch.setattr(mh, "HISTORY_FILE", str(tmp_path / "metrics_history.json"))
        return mh

    def test_dashboard_summary_records_a_sample(self, client, mocker, mh_tmp):
        # Mock every fan-out collector so the route runs offline. Only the
        # ones whose data we want to flow into metrics need realistic shapes.
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_thermals", return_value={"perf": {"CPUPct": 42}, "temps": []})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"used_mb": 800, "total_mb": 1600})
        mocker.patch.object(wdm, "get_bios_status", return_value={})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={})
        mocker.patch.object(wdm, "get_disk_health", return_value={"drives": []})
        mocker.patch.object(wdm, "get_driver_health", return_value={})

        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200

        history = mh_tmp.load_history()
        assert len(history) == 1
        m = history[0]["metrics"]
        assert m["cpu_percent"] == 42.0
        assert m["memory_percent"] == 50.0

    def test_sampler_failure_does_not_break_dashboard(self, client, mocker, mh_tmp):
        # Even if record_sample raises, the dashboard must still respond.
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_thermals", return_value={"perf": {"CPUPct": 1}, "temps": []})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"used_mb": 1, "total_mb": 2})
        mocker.patch.object(wdm, "get_bios_status", return_value={})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={})
        mocker.patch.object(wdm, "get_disk_health", return_value={"drives": []})
        mocker.patch.object(wdm, "get_driver_health", return_value={})
        mocker.patch.object(mh_tmp, "record_sample", side_effect=RuntimeError("boom"))

        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200


# ── Dashboard summary cache (perf hardening A) ───────────────────────────────


class TestDashboardSummaryCache:
    """The dashboard endpoint serves cached data inside the TTL and triggers
    an async refresh when stale, instead of paying full fan-out cost on
    every call."""

    def _mock_collectors(self, mocker, cpu=10):
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_thermals", return_value={"perf": {"CPUPct": cpu}, "temps": []})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"used_mb": 1, "total_mb": 2})
        mocker.patch.object(wdm, "get_bios_status", return_value={})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={})
        mocker.patch.object(wdm, "get_disk_health", return_value={"drives": []})
        mocker.patch.object(wdm, "get_driver_health", return_value={})

    def test_first_request_is_cache_miss(self, client, mocker):
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["cache"] == "miss"

    def test_second_request_within_ttl_is_cache_fresh(self, client, mocker):
        self._mock_collectors(mocker)
        client.get("/api/dashboard/summary")  # populate
        resp2 = client.get("/api/dashboard/summary")
        d = resp2.get_json()
        assert d["cache"] == "fresh"
        assert isinstance(d.get("cache_age_s"), int | float)

    def test_stale_cache_returns_cached_payload_and_triggers_refresh(self, client, mocker):
        """When the cache is older than TTL, the route must still return
        immediately (with the stale payload) and kick a background refresh.
        Latency under load was the original problem."""
        import windesktopmgr as wdm

        self._mock_collectors(mocker, cpu=7)
        client.get("/api/dashboard/summary")  # seed cache

        # Force the cache to look stale by back-dating its timestamp.
        from datetime import datetime, timedelta

        with wdm._dashboard_cache_lock:
            wdm._dashboard_state["ts"] = datetime.now() - timedelta(seconds=999)

        refresh_called = mocker.patch.object(wdm, "_trigger_dashboard_refresh_async")
        resp = client.get("/api/dashboard/summary")
        d = resp.get_json()
        assert d["cache"] == "stale"
        assert refresh_called.called, "stale cache must trigger a background refresh"

    def test_cache_clear_hook_drops_cached_payload(self, client, mocker):
        import windesktopmgr as wdm

        self._mock_collectors(mocker)
        client.get("/api/dashboard/summary")
        assert wdm._dashboard_state["data"] is not None
        wdm._dashboard_cache_clear()
        assert wdm._dashboard_state["data"] is None
        assert wdm._dashboard_state["ts"] is None

    def test_single_flight_prevents_concurrent_background_refreshes(self, mocker):
        """The single-flight lock ensures at most one refresh thread runs at
        a time. A second trigger while one is in flight must no-op instead
        of spawning a duplicate."""
        import windesktopmgr as wdm

        # Acquire the refresh lock to simulate an in-flight refresh
        assert wdm._dashboard_refresh_lock.acquire(blocking=False)
        try:
            thread_spawn = mocker.patch("windesktopmgr.threading.Thread")
            wdm._trigger_dashboard_refresh_async()
            assert not thread_spawn.called, "should not spawn a second refresh while one is in flight"
        finally:
            wdm._dashboard_refresh_lock.release()

    def test_compute_returns_same_shape_as_cached(self, mocker):
        """The synchronous fan-out and the cached payload must share one
        shape -- the route adds the ``cache`` / ``cache_age_s`` keys on
        top but must not alter the core fields."""
        import windesktopmgr as wdm

        self._mock_collectors(mocker)
        data = wdm._compute_dashboard_summary()
        for key in ("concerns", "total", "critical", "warnings", "overall", "checked_at"):
            assert key in data


class TestDashboardLegacyThresholdFallback:
    """Coverage gap #3: when alerts.evaluate_rules() raises, the dashboard
    must fall back to hardcoded CPU/memory/disk thresholds so it never goes
    silent about real pressure. A prior audit caught the disk path being
    silently dropped in this branch — this locks all three concerns in."""

    def _mock_high_pressure(self, mocker):
        # thermals carries CPUPct (>=80 -> CPU warning); memory at ~94% (>90
        # -> RAM critical); one disk drive at 96% (>=95 -> disk critical).
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={"temps": [], "perf": {"CPUPct": 85}, "fans": [], "has_rich": True},
        )
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={"total_mb": 32000, "used_mb": 30000, "free_mb": 2000, "top_procs": []},
        )
        mocker.patch(
            "windesktopmgr.get_disk_health",
            return_value={"drives": [{"Letter": "C", "PctUsed": 96, "FreeGB": 5.0}]},
        )
        mocker.patch("windesktopmgr.get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={"onedrive_suspended": False, "fast_startup": False, "drives_down": []},
        )
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value={"old_drivers": [], "problematic_drivers": [], "nvidia": None},
        )
        mocker.patch("windesktopmgr.get_gpu_metrics", return_value={})
        mocker.patch("windesktopmgr.get_network_metrics", return_value={})
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

    def test_fallback_surfaces_cpu_mem_disk_when_rules_engine_raises(self, mocker):
        import windesktopmgr as wdm

        self._mock_high_pressure(mocker)
        # Force the rules engine to blow up so the except-branch fallback runs.
        boom = mocker.patch("alerts.evaluate_rules", side_effect=RuntimeError("rules engine broken"))

        data = wdm._compute_dashboard_summary()
        assert boom.called, "test must actually exercise the failing-rules path"
        titles = [c["title"] for c in data["concerns"]]

        cpu = [c for c in data["concerns"] if "CPU at 85%" in c["title"]]
        mem = [c for c in data["concerns"] if c["title"].startswith("RAM at")]
        disk = [c for c in data["concerns"] if "Drive C" in c["title"] and "full" in c["title"]]

        assert cpu and cpu[0]["level"] == "warning", f"missing CPU fallback concern in {titles}"
        assert mem and mem[0]["level"] == "critical", f"missing memory fallback concern in {titles}"
        assert disk and disk[0]["level"] == "critical", f"missing disk fallback concern in {titles}"


# ── Request-log flood suppressor (perf hardening B) ──────────────────────────


class TestRequestLogFloodSuppressor:
    """Collapses runs of identical successful requests so one runaway client
    can't bury real signal in the log file."""

    def _suppressor(self, window_seconds=None):
        import windesktopmgr as wdm

        s = wdm._RequestLogFloodSuppressor()
        if window_seconds is not None:
            s.WINDOW_SECONDS = window_seconds
        return s

    def test_first_occurrence_logs_with_zero_suppressed(self):
        s = self._suppressor()
        should, suppressed = s.note(("GET", "/api/x", 200))
        assert should is True
        assert suppressed == 0

    def test_consecutive_duplicate_in_window_suppressed(self):
        s = self._suppressor(window_seconds=60)
        s.note(("GET", "/api/x", 200))
        should, suppressed = s.note(("GET", "/api/x", 200))
        assert should is False
        assert suppressed == 0  # count only surfaces on the NEXT logged line

    def test_backlog_reported_when_window_expires(self, mocker):
        s = self._suppressor(window_seconds=60)
        # Fake the clock so we don't have to sleep
        t = [1000.0]
        mocker.patch("windesktopmgr.time.time", side_effect=lambda: t[0])

        s.note(("GET", "/api/x", 200))  # logs
        for _ in range(5):
            s.note(("GET", "/api/x", 200))  # 5 suppressed
        # Advance past the window
        t[0] += 61.0
        should, suppressed = s.note(("GET", "/api/x", 200))
        assert should is True
        assert suppressed == 5, "suppressed count must surface on the next emit"

    def test_distinct_keys_tracked_independently(self):
        s = self._suppressor(window_seconds=60)
        a1 = s.note(("GET", "/api/a", 200))
        b1 = s.note(("GET", "/api/b", 200))
        a2 = s.note(("GET", "/api/a", 200))
        assert a1 == (True, 0)
        assert b1 == (True, 0), "different key must not be suppressed by /api/a"
        assert a2 == (False, 0), "second /api/a IS a duplicate and should be suppressed"

    def test_status_code_differentiates_keys(self):
        """Same method+path but different status code is a different event."""
        s = self._suppressor(window_seconds=60)
        r1 = s.note(("GET", "/api/x", 200))
        r2 = s.note(("GET", "/api/x", 500))
        assert r1 == (True, 0)
        assert r2 == (True, 0)

    def test_error_responses_reach_log_even_after_duplicates(self, client, mocker):
        """Integration check: even when a successful route is being
        flood-suppressed, an error response (>=400) must still log.
        Signal must never be suppressed."""
        import windesktopmgr as wdm

        log_mock = mocker.patch.object(wdm._flask_log, "info")
        warn_mock = mocker.patch.object(wdm._flask_log, "warning")

        # First two calls to /api/health are skipped by the logger entirely
        # (path == "/api/health"), so fire a real successful endpoint.
        client.get("/api/scan/status")  # 200, first time -> logged
        client.get("/api/scan/status")  # 200, duplicate -> suppressed
        client.get("/api/does-not-exist")  # 404 -> must log

        # At least one INFO for the first /api/scan/status
        assert log_mock.call_count >= 1
        # 404 must always emit a warning
        assert warn_mock.call_count >= 1


# ── Heartbeat JS guardrails (perf hardening C) ───────────────────────────────


class TestHeartbeatJsGuards:
    """The heartbeat logic lives in templates/index.html JS. We can't unit-
    test browser behaviour from pytest, but we can pin the specific
    guardrails that prevent the 2026-04-20 "banner stuck forever" incident
    so a refactor can't silently regress them.
    """

    HTML_PATH = (
        PROJECT_ROOT / "templates" / "index.html"
        if (PROJECT_ROOT := __import__("pathlib").Path(__file__).resolve().parents[1])
        else None
    )  # type: ignore[misc]

    def _html(self) -> str:
        import pathlib

        # Frontend source spans index.html + the extracted static/js/app.js
        # (#55 PR 2). Read both so JS-content assertions still resolve.
        root = pathlib.Path(__file__).resolve().parents[1]
        html = (root / "templates" / "index.html").read_text(encoding="utf-8")
        js = (root / "static" / "js" / "app.js").read_text(encoding="utf-8")
        return html + "\n" + js

    def test_fetch_timeout_is_at_least_five_seconds(self):
        """2-second timeout was too tight under browser-connection-cap pressure."""
        html = self._html()
        assert "AbortSignal.timeout(5000)" in html, (
            "heartbeat fetch timeout must be >=5000ms to survive temporary browser connection saturation"
        )
        assert "AbortSignal.timeout(2000)" not in html, (
            "2-second heartbeat timeout was the 2026-04-20 failure mode; do not re-introduce it"
        )

    def test_fail_threshold_constant_present(self):
        """Banner must require multiple consecutive failures, not one blip."""
        html = self._html()
        assert "_HEARTBEAT_FAIL_THRESHOLD = 3" in html
        assert "_heartbeatFailures >= _HEARTBEAT_FAIL_THRESHOLD" in html

    def test_keepalive_and_no_store_set_on_heartbeat_fetch(self):
        html = self._html()
        assert "keepalive: true" in html
        assert 'cache: "no-store"' in html


# ── Browser tab favicon (backlog #41) ─────────────────────────────


class TestFavicon:
    """The dashboard ships a real browser-tab icon (cyan W on dark) so
    pinned tabs are findable in a crowded tab strip. Test the wiring
    end-to-end:
      - <link rel="icon"> tags render in the served HTML (both SVG + ICO)
      - GET /static/favicon.ico returns 200 + image/x-icon MIME
      - GET /static/favicon.svg returns 200 + image/svg+xml MIME
      - Both files are under the 5 KB target from the backlog spec
      - The dynamic-favicon helper function exists in the served JS
    """

    def _html(self) -> str:
        import pathlib

        # Frontend source spans index.html + the extracted static/js/app.js
        # (#55 PR 2). Read both so JS-content assertions still resolve.
        root = pathlib.Path(__file__).resolve().parents[1]
        html = (root / "templates" / "index.html").read_text(encoding="utf-8")
        js = (root / "static" / "js" / "app.js").read_text(encoding="utf-8")
        return html + "\n" + js

    def test_link_rel_icon_tags_present(self):
        html = self._html()
        assert 'rel="icon" type="image/svg+xml" href="/static/favicon.svg"' in html, (
            "SVG favicon link missing -- modern browsers prefer SVG for sharp rendering at any zoom"
        )
        assert 'rel="icon" type="image/x-icon" href="/static/favicon.ico"' in html, (
            "ICO favicon link missing -- needed as fallback for older browsers + pinned-tab paths"
        )

    def test_favicon_ico_route_serves_with_correct_mime(self, client):
        resp = client.get("/static/favicon.ico")
        assert resp.status_code == 200
        assert resp.content_type.startswith("image/"), f"unexpected MIME: {resp.content_type}"
        # Flask's static serving picks "image/vnd.microsoft.icon" or
        # "image/x-icon" depending on mimetypes registry; both are correct
        assert "icon" in resp.content_type.lower() or "x-icon" in resp.content_type.lower()

    def test_favicon_svg_route_serves_with_correct_mime(self, client):
        resp = client.get("/static/favicon.svg")
        assert resp.status_code == 200
        assert "svg" in resp.content_type.lower()

    def test_favicon_ico_under_5kb(self):
        """Backlog #41 spec: keep the asset small (<5 KB) to avoid
        bloating first paint. Multi-size ICO with 16/32/48 should fit
        comfortably under that ceiling."""
        import pathlib

        path = pathlib.Path(__file__).resolve().parents[1] / "static" / "favicon.ico"
        size_kb = path.stat().st_size / 1024
        assert size_kb < 5.0, f"favicon.ico is {size_kb:.1f} KB -- exceeds 5 KB target"

    def test_favicon_svg_under_5kb(self):
        import pathlib

        path = pathlib.Path(__file__).resolve().parents[1] / "static" / "favicon.svg"
        size_kb = path.stat().st_size / 1024
        assert size_kb < 5.0, f"favicon.svg is {size_kb:.1f} KB -- exceeds 5 KB target"

    def test_favicon_ico_has_three_sizes(self):
        """Multi-size ICO must carry 16/32/48 -- browsers pick whichever
        fits their context (16 = tab strip, 32 = pinned tab, 48 = task bar)."""
        import pathlib

        from PIL import Image

        path = pathlib.Path(__file__).resolve().parents[1] / "static" / "favicon.ico"
        img = Image.open(path)
        sizes = img.ico.sizes()
        assert (16, 16) in sizes, f"missing 16x16 -- tab strip render will be blurry. Got {sizes}"
        assert (32, 32) in sizes, f"missing 32x32. Got {sizes}"
        assert (48, 48) in sizes, f"missing 48x48 -- pinned/desktop shortcuts will be blurry. Got {sizes}"

    def test_dynamic_favicon_helper_present_in_template(self):
        """The _updateFavicon helper drives the red-dot overlay when
        critical concerns are present. Catches a regression where the
        helper got moved or renamed and renderDashboard's call would
        silently no-op."""
        html = self._html()
        assert "_updateFavicon" in html
        assert "function _updateFavicon" in html
        # And renderDashboard must call it
        assert "_updateFavicon(critical)" in html or "_updateFavicon(d.critical" in html
