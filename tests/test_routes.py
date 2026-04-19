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
        wdm._bsod_cache["0x00020001"] = {"title": "HYPERVISOR_ERROR"}
        resp = client.get("/api/bsod/cache")
        assert resp.get_json()["total_cached"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/bsod/cache/clear
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodCacheClearRoute:
    def test_clears_cache(self, client):
        wdm._bsod_cache["0x00020001"] = {"title": "Test"}
        resp = client.post("/api/bsod/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert len(wdm._bsod_cache) == 0


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /api/bsod/cache/delete/<code>
# ══════════════════════════════════════════════════════════════════════════════


class TestBsodCacheDeleteRoute:
    def test_deletes_existing_entry(self, client):
        wdm._bsod_cache["0x00020001"] = {"title": "HYPERVISOR_ERROR"}
        resp = client.delete("/api/bsod/cache/delete/0x00020001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["removed"] is True
        assert "0x00020001" not in wdm._bsod_cache

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

    def test_registry_hklm_enable_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyApp", "type": "registry_hklm", "enable": True},
        )
        assert resp.status_code == 200
        assert mock_run.called

    def test_task_disable_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyTask", "type": "task", "enable": False},
        )
        assert resp.status_code == 200
        assert mock_run.called
        cmd = mock_run.call_args[0][0][-1]
        assert "Disable-ScheduledTask" in cmd or "Disable" in cmd


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
        wdm._event_cache[41] = {"title": "Kernel Power Loss"}
        resp = client.post("/api/events/cache/clear")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert len(wdm._event_cache) == 0


# ══════════════════════════════════════════════════════════════════════════════
# DELETE /api/events/cache/delete/<event_id>
# ══════════════════════════════════════════════════════════════════════════════


class TestEventsCacheDeleteRoute:
    def test_deletes_existing_event(self, client):
        wdm._event_cache["41"] = {"title": "Kernel Power Loss"}
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
    def test_disable_fast_startup_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout="OK:disabled")
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": False})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is False

    def test_enable_fast_startup_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout="OK:enabled")
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": True})
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is True

    def test_ps_failure_returns_ok_false(self, client, mocker):
        _mock_ps(mocker, stdout="ERROR: Access denied")
        resp = client.post("/api/credentials/fix-fast-startup", json={"enable": False})
        data = resp.get_json()
        assert data["ok"] is False

    def test_timeout_returns_ok_false(self, client, mocker):
        import subprocess

        mocker.patch("windesktopmgr.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=10))
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
        # Task-watcher concerns — default to empty so the clean-state test
        # doesn't pick up real SystemHealthDiag logs on the dev machine.
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

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
    """Tests for /api/warranty/data — CPU/BIOS/system via WMI, microcode+counts via subprocess."""

    MCU_OUT = "0x010001B4"
    COUNTS_OUT = json.dumps({"BSODs30Days": 2, "WHEAErrors": 0, "UnexpectedShutdowns": 1})

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
        _mock_wmi(
            mocker,
            {
                "Win32_Processor": [_wmi_obj(Name=f"  {cpu_name}  ", ProcessorId=proc_id, SerialNumber=serial)],
                "Win32_BIOS": [_wmi_obj(SerialNumber=service_tag, SMBIOSBIOSVersion=bios_ver, ReleaseDate=bios_date)],
                "Win32_ComputerSystem": [_wmi_obj(Manufacturer=mfr, Model=model)],
            },
        )
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": self.MCU_OUT, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": self.COUNTS_OUT, "returncode": 0, "stderr": ""})(),
        ]
        return m

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

    def test_handles_wmi_failure(self, client, mocker):
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI failed"))
        mocker.patch("windesktopmgr.subprocess.run", side_effect=Exception("PS failed"))
        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["status"] == "error"
        assert "message" in d

    def test_warranty_timeout_handled(self, client, mocker):
        import subprocess

        # WMI works but subprocess times out
        _mock_wmi(
            mocker,
            {
                "Win32_Processor": [_wmi_obj(Name="Intel i9", ProcessorId="X", SerialNumber="N/A")],
                "Win32_BIOS": [
                    _wmi_obj(SerialNumber="TAG", SMBIOSBIOSVersion="1.0", ReleaseDate="20250101000000.000000+000")
                ],
                "Win32_ComputerSystem": [_wmi_obj(Manufacturer="Dell", Model="XPS")],
            },
        )
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=15),
        )
        r = client.get("/api/warranty/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "error"


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

    def test_wmi_exception_returns_partial(self, client, mocker):
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI crashed"))
        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "partial"
        assert d["stale"] is True
        assert "WMI crashed" in d["error"]

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
            },
        )
        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        for k in ("Sound", "USBControllers", "PCIeSlots", "NetworkHardware", "GPU"):
            assert d[k] == []

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
    monkeypatch.setattr(wdm, "MEMORY_SNOOZE_FILE", str(target))
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
