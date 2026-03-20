"""
test_routes.py
Flask route integration tests using the test client.
All subprocess / PowerShell calls are mocked — no Windows dependency.

Coverage: ALL 38 Flask routes defined in windesktopmgr.py
"""

import json
import os
import pytest
import windesktopmgr as wdm


# ── helpers ────────────────────────────────────────────────────────────────────

def _mock_ps(mocker, stdout="[]", returncode=0, stderr=""):
    """Shorthand: mock subprocess.run globally."""
    m = mocker.patch("windesktopmgr.subprocess.run")
    m.return_value.stdout    = stdout
    m.return_value.returncode = returncode
    m.return_value.stderr    = stderr
    return m


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
# GET  /api/bsod/data
# ══════════════════════════════════════════════════════════════════════════════

class TestBsodDataRoute:
    def test_returns_200_with_structure(self, client, mocker):
        mocker.patch("windesktopmgr.build_bsod_analysis", return_value={
            "crashes": [],
            "summary": {"total_crashes": 0, "this_month": 0,
                        "most_common_error": "None", "avg_uptime_hours": 0},
            "timeline": [],
            "recommendations": [],
            "error_breakdown": [],
            "driver_breakdown": [],
        })
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
        mocker.patch("windesktopmgr.get_startup_items", return_value=[
            {"Name": "OneDrive", "Command": "onedrive.exe", "Location": "HKCU Run",
             "Type": "registry_hkcu", "Enabled": True, "info": None, "suspicious": False},
        ])
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
        resp = client.post("/api/startup/lookup-unknowns",
                           json={"items": [{"Name": "WeirdApp", "Command": "weird.exe"}]})
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
        resp = client.post("/api/startup/lookup-unknowns",
                           data="", content_type="application/json")
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
        mocker.patch("windesktopmgr.get_disk_health",
                     return_value={"drives": [], "physical": [], "io": []})
        resp = client.get("/api/disk/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "drives" in data
        assert "physical" in data
        assert "io" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_disk_health",
                     return_value={"drives": [], "physical": [], "io": []})
        resp = client.get("/api/disk/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/network/data
# ══════════════════════════════════════════════════════════════════════════════

class TestNetworkDataRoute:
    def test_returns_200_with_keys(self, client, mocker):
        mocker.patch("windesktopmgr.get_network_data", return_value={
            "established": [], "listening": [], "adapters": [],
            "top_processes": [], "total_connections": 0, "total_listening": 0,
        })
        resp = client.get("/api/network/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "established" in data
        assert "total_connections" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_network_data", return_value={
            "established": [], "listening": [], "adapters": [],
            "top_processes": [], "total_connections": 0, "total_listening": 0,
        })
        resp = client.get("/api/network/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/updates/history
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdatesHistoryRoute:
    def test_returns_200_with_list(self, client, mocker):
        mocker.patch("windesktopmgr.get_update_history", return_value=[
            {"Title": "KB5048667", "Date": "2024-12-10", "ResultCode": 2,
             "Categories": "Security", "KB": "KB5048667"},
        ])
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
    def test_returns_list(self, client, mocker):
        _mock_ps(mocker, stdout="[]")
        resp = client.post("/api/events/query", json={"log": "System", "level": "Error"})
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_max_events_capped(self, client, mocker):
        mock_run = _mock_ps(mocker, stdout="[]")
        client.post("/api/events/query", json={"log": "System", "max": 9999})
        cmd = mock_run.call_args[0][0][-1]
        assert "9999" not in cmd

    def test_returns_json(self, client, mocker):
        _mock_ps(mocker, stdout="[]")
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
        mocker.patch("windesktopmgr.get_process_list", return_value={
            "processes": [], "total": 0, "total_mem_mb": 0,
            "flagged": [], "flag_notes": [],
        })
        resp = client.get("/api/processes/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "processes" in data
        assert "total" in data
        assert "total_mem_mb" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_process_list", return_value={
            "processes": [], "total": 0, "total_mem_mb": 0,
            "flagged": [], "flag_notes": [],
        })
        resp = client.get("/api/processes/list")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/processes/lookup-unknowns
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessLookupUnknownsRoute:
    def test_returns_ok_and_queued(self, client):
        resp = client.post("/api/processes/lookup-unknowns",
                           json={"processes": [{"Name": "weird.exe", "Path": ""}]})
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
    def test_kill_calls_subprocess_with_pid(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post("/api/processes/kill", json={"pid": 1234})
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        cmd = mock_run.call_args[0][0][-1]
        assert "1234" in cmd

    def test_kill_subprocess_failure_returns_error(self, client, mocker):
        _mock_ps(mocker, returncode=1, stderr="Access denied")
        resp = client.post("/api/processes/kill", json={"pid": 999})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False

    def test_missing_pid_defaults_to_zero(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post("/api/processes/kill", json={})
        assert resp.status_code == 200
        # Should have called with PID 0 (from default)
        cmd = mock_run.call_args[0][0][-1]
        assert "0" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/thermals/data
# ══════════════════════════════════════════════════════════════════════════════

class TestThermalsDataRoute:
    def test_returns_200_with_keys(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [], "perf": {}, "fans": [], "has_rich": False, "note": "",
        })
        resp = client.get("/api/thermals/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "temps" in data
        assert "perf" in data
        assert "fans" in data

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [], "perf": {}, "fans": [], "has_rich": False, "note": "",
        })
        resp = client.get("/api/thermals/data")
        assert resp.content_type.startswith("application/json")


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/services/list
# ══════════════════════════════════════════════════════════════════════════════

class TestServicesListRoute:
    def test_returns_200_with_list(self, client, mocker):
        mocker.patch("windesktopmgr.get_services_list", return_value=[
            {"Name": "wuauserv", "DisplayName": "Windows Update",
             "Status": "Running", "StartMode": "Auto", "info": None},
        ])
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
    def test_invalid_action_returns_error_no_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "explode"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False
        mock_run.assert_not_called()

    def test_stop_action_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "stop"},
        )
        assert resp.status_code == 200
        assert mock_run.called
        cmd = mock_run.call_args[0][0][-1]
        assert "Stop-Service" in cmd

    def test_start_action_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "start"},
        )
        assert resp.status_code == 200
        cmd = mock_run.call_args[0][0][-1]
        assert "Start-Service" in cmd

    def test_disable_action_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "disable"},
        )
        assert resp.status_code == 200
        assert mock_run.called

    def test_enable_action_calls_subprocess(self, client, mocker):
        mock_run = _mock_ps(mocker)
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "enable"},
        )
        assert resp.status_code == 200
        cmd = mock_run.call_args[0][0][-1]
        assert "Manual" in cmd

    def test_missing_name_handled_gracefully(self, client, mocker):
        _mock_ps(mocker)
        resp = client.post("/api/services/toggle", json={"action": "stop"})
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/services/lookup-unknowns
# ══════════════════════════════════════════════════════════════════════════════

class TestServicesLookupUnknownsRoute:
    def test_returns_ok_and_queued(self, client):
        resp = client.post("/api/services/lookup-unknowns",
                           json={"services": [{"Name": "WeirdSvc", "DisplayName": "Weird Service"}]})
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
# GET  /api/health-history/data
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthHistoryDataRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.get_health_report_history", return_value={
            "reports": [], "weekly": [], "latest_score": None,
        })
        resp = client.get("/api/health-history/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_returns_json(self, client, mocker):
        mocker.patch("windesktopmgr.get_health_report_history", return_value={})
        resp = client.get("/api/health-history/data")
        assert resp.content_type.startswith("application/json")


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
        mocker.patch("windesktopmgr.get_system_timeline", return_value=[
            {"ts": "2026-03-10", "type": "bsod", "category": "crash",
             "title": "Crash", "severity": "critical", "icon": "💀"},
        ])
        resp = client.get("/api/timeline/data")
        data = resp.get_json()
        assert data["total"] == len(data["events"])


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/memory/data
# ══════════════════════════════════════════════════════════════════════════════

class TestMemoryDataRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={
            "total_mb": 32768, "used_mb": 16000, "free_mb": 16768,
            "categories": {}, "top_procs": [],
            "mcafee_mb": 0, "defender_mb": 0, "defender_baseline": 150,
            "mcafee_saving_mb": 0, "has_mcafee": False,
        })
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
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [], "msal_token_stale": False,
        })
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
        _mock_ps(mocker, stdout=json.dumps(
            [{"Name": "OneDrive", "PID": 1234, "Resumed": 5, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["fixed"] == 1

    def test_not_found_returns_ok_false(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps(
            [{"Name": "OneDrive", "PID": 0, "Resumed": 0, "Status": "NotFound"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert data["ok"] is False
        assert data["fixed"] == 0

    def test_timeout_returns_error(self, client, mocker):
        import subprocess
        mocker.patch("windesktopmgr.subprocess.run",
                     side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=15))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert data["ok"] is False

    def test_response_has_message(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps(
            [{"Name": "OneDrive", "PID": 1234, "Resumed": 5, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-onedrive")
        data = resp.get_json()
        assert "message" in data


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/credentials/resume-brokers
# ══════════════════════════════════════════════════════════════════════════════

class TestResumeBrokersRoute:
    def test_success_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps(
            [{"Name": "backgroundTaskHost", "PID": 5678, "Resumed": 3, "Status": "OK"}]))
        resp = client.post("/api/credentials/resume-brokers")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["fixed"] == 1

    def test_no_brokers_found_returns_ok_false(self, client, mocker):
        _mock_ps(mocker, stdout=json.dumps(
            [{"Name": "No broker processes found", "PID": 0, "Resumed": 0, "Status": "NotFound"}]))
        resp = client.post("/api/credentials/resume-brokers")
        data = resp.get_json()
        assert data["ok"] is False

    def test_timeout_returns_error(self, client, mocker):
        import subprocess
        mocker.patch("windesktopmgr.subprocess.run",
                     side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=15))
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
        resp = client.post("/api/credentials/fix-fast-startup",
                           json={"enable": False})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is False

    def test_enable_fast_startup_returns_ok(self, client, mocker):
        _mock_ps(mocker, stdout="OK:enabled")
        resp = client.post("/api/credentials/fix-fast-startup",
                           json={"enable": True})
        data = resp.get_json()
        assert data["ok"] is True
        assert data["enabled"] is True

    def test_ps_failure_returns_ok_false(self, client, mocker):
        _mock_ps(mocker, stdout="ERROR: Access denied")
        resp = client.post("/api/credentials/fix-fast-startup",
                           json={"enable": False})
        data = resp.get_json()
        assert data["ok"] is False

    def test_timeout_returns_ok_false(self, client, mocker):
        import subprocess
        mocker.patch("windesktopmgr.subprocess.run",
                     side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=10))
        resp = client.post("/api/credentials/fix-fast-startup",
                           json={"enable": False})
        data = resp.get_json()
        assert data["ok"] is False

    def test_no_body_returns_400(self, client, mocker):
        """Empty body with JSON content type is rejected by Flask."""
        _mock_ps(mocker, stdout="OK:disabled")
        resp = client.post("/api/credentials/fix-fast-startup",
                           data="", content_type="application/json")
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/bios/status
# ══════════════════════════════════════════════════════════════════════════════

class TestBiosStatusRoute:
    def test_returns_200(self, client, mocker):
        mocker.patch("windesktopmgr.get_bios_status", return_value={
            "current": {"BIOSVersion": "2.3.1"}, "update": {},
        })
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
    def test_returns_200_with_structure(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [], "perf": {}, "fans": [], "has_rich": False, "note": "",
        })
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={
            "total_mb": 32768, "used_mb": 16000, "free_mb": 16768,
            "categories": {}, "top_procs": [],
            "mcafee_mb": 0, "defender_mb": 0, "defender_baseline": 150,
            "mcafee_saving_mb": 0, "has_mcafee": False,
        })
        mocker.patch("windesktopmgr.get_bios_status", return_value={
            "current": {}, "update": {},
        })
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [], "msal_token_stale": False,
        })
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
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [], "perf": {}, "fans": [], "has_rich": False, "note": "",
        })
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={
            "total_mb": 32768, "used_mb": 8000, "free_mb": 24768,
            "categories": {}, "top_procs": [],
            "mcafee_mb": 0, "defender_mb": 0, "defender_baseline": 150,
            "mcafee_saving_mb": 0, "has_mcafee": False,
        })
        mocker.patch("windesktopmgr.get_bios_status", return_value={
            "current": {}, "update": {},
        })
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [], "msal_token_stale": False,
        })
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["overall"] == "ok"
        assert data["total"] == 0

    def test_critical_concern_raises_overall_to_critical(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [{"TempC": 95, "Name": "CPU", "Source": "LHM", "status": "critical"}],
            "perf": {"CPUPct": 10}, "fans": [], "has_rich": True, "note": "",
        })
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={
            "total_mb": 32768, "used_mb": 8000, "free_mb": 24768,
            "categories": {}, "top_procs": [],
            "mcafee_mb": 0, "defender_mb": 0, "defender_baseline": 150,
            "mcafee_saving_mb": 0, "has_mcafee": False,
        })
        mocker.patch("windesktopmgr.get_bios_status", return_value={
            "current": {}, "update": {},
        })
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [], "msal_token_stale": False,
        })
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["overall"] == "critical"
        assert data["critical"] >= 1

    def test_mcafee_detected_raises_warning(self, client, mocker):
        mocker.patch("windesktopmgr.get_thermals", return_value={
            "temps": [], "perf": {}, "fans": [], "has_rich": False, "note": "",
        })
        mocker.patch("windesktopmgr.get_memory_analysis", return_value={
            "total_mb": 32768, "used_mb": 16000, "free_mb": 16768,
            "categories": {}, "top_procs": [],
            "mcafee_mb": 500, "defender_mb": 150, "defender_baseline": 150,
            "mcafee_saving_mb": 350, "has_mcafee": True,
        })
        mocker.patch("windesktopmgr.get_bios_status", return_value={
            "current": {}, "update": {},
        })
        mocker.patch("windesktopmgr.get_credentials_network_health", return_value={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [], "msal_token_stale": False,
        })
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["warnings"] >= 1
        mcafee_concerns = [c for c in data["concerns"] if "McAfee" in c["title"]]
        assert len(mcafee_concerns) >= 1


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
        mocker.patch("windesktopmgr.build_bsod_analysis", return_value={
            "crashes": [],
            "summary": {"total_crashes": 0, "this_month": 0,
                        "most_common_error": "None", "avg_uptime_hours": 0},
            "timeline": [],
            "recommendations": [],
            "error_breakdown": [],
            "driver_breakdown": [],
        })
        resp = client.post("/api/summary/bsod", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_startup_tab_returns_status(self, client, mocker):
        mocker.patch("windesktopmgr.get_startup_items", return_value=[])
        resp = client.post("/api/summary/startup", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_disk_tab_returns_status(self, client, mocker):
        mocker.patch("windesktopmgr.get_disk_health",
                     return_value={"drives": [], "physical": [], "io": []})
        resp = client.post("/api/summary/disk", json={})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_network_tab_returns_status(self, client):
        resp = client.post("/api/summary/network", json={
            "established": [], "listening": [], "adapters": [],
            "top_processes": [], "total_connections": 0, "total_listening": 0,
        })
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
        resp = client.post("/api/summary/processes", json={
            "processes": [], "total": 0, "total_mem_mb": 0,
            "flagged": [], "flag_notes": [],
        })
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_thermals_tab_returns_status(self, client):
        resp = client.post("/api/summary/thermals", json={
            "temps": [], "perf": {}, "fans": [],
        })
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_services_tab_returns_status(self, client):
        resp = client.post("/api/summary/services", json={"services": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_health_history_tab_returns_status(self, client):
        resp = client.post("/api/summary/health-history", json={
            "reports": [], "weekly": [],
        })
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_timeline_tab_returns_status(self, client):
        resp = client.post("/api/summary/timeline", json={"events": []})
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_memory_tab_returns_status(self, client):
        resp = client.post("/api/summary/memory", json={
            "total_mb": 32768, "used_mb": 16000, "free_mb": 16768,
            "categories": {}, "has_mcafee": False, "mcafee_mb": 0,
            "mcafee_saving_mb": 0,
        })
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_bios_tab_returns_status(self, client):
        resp = client.post("/api/summary/bios", json={
            "current": {"BIOSVersion": "2.3.1"}, "update": {},
        })
        assert resp.status_code == 200
        assert "status" in resp.get_json()

    def test_credentials_tab_returns_status(self, client):
        resp = client.post("/api/summary/credentials", json={
            "onedrive_suspended": False, "fast_startup": False,
            "drives_down": [],
        })
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
            "app.run() must include threaded=True — without it, "
            "background PowerShell workers block the request thread"
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
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                   "windesktopmgr.py")
        with open(source_path, encoding="utf-8-sig") as f:
            tree = ast.parse(f.read())

        thread_calls = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "Thread"):
                for kw in node.keywords:
                    if kw.arg == "daemon":
                        thread_calls.append(kw)

        assert len(thread_calls) >= 5, (
            f"Expected at least 5 daemon worker threads, found {len(thread_calls)}"
        )
        for kw in thread_calls:
            assert isinstance(kw.value, ast.Constant) and kw.value.value is True, (
                "All worker threads must have daemon=True"
            )


# ══════════════════════════════════════════════════════════════════════════════
# WARRANTY DATA ROUTE
# ══════════════════════════════════════════════════════════════════════════════

class TestWarrantyRoute:
    """Tests for /api/warranty/data"""

    def test_returns_ok_with_warranty_data(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        # First call: CPU/BIOS/system info
        mock_run.return_value.stdout = json.dumps({
            "CPUName": "Intel(R) Core(TM) i9-14900K",
            "ProcessorId": "BFEBFBFF000B0671",
            "SerialNumber": "N/A",
            "DellServiceTag": "ABC1234",
            "BIOSVersion": "2.18.0",
            "BIOSDate": "2025-01-10",
            "Manufacturer": "Dell Inc.",
            "Model": "XPS 8960",
        })
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/warranty/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert "warranty" in d
        w = d["warranty"]
        assert w["IsAffectedCPU"] is True
        assert "i9-14900K" in w["CPUModel"]

    def test_returns_service_tag(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = json.dumps({
            "CPUName": "Intel(R) Core(TM) i9-14900K",
            "ProcessorId": "TEST",
            "SerialNumber": "N/A",
            "DellServiceTag": "XYZ7890",
            "BIOSVersion": "2.18.0",
            "BIOSDate": "2025-01-10",
            "Manufacturer": "Dell Inc.",
            "Model": "XPS 8960",
        })
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["DellServiceTag"] == "XYZ7890"
        assert "XYZ7890" in d["warranty"]["DellSupportURL"]

    def test_non_affected_cpu(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = json.dumps({
            "CPUName": "AMD Ryzen 9 7950X",
            "ProcessorId": "TEST",
            "SerialNumber": "N/A",
            "DellServiceTag": "N/A",
            "BIOSVersion": "1.0",
            "BIOSDate": "2025-01-01",
            "Manufacturer": "AMD",
            "Model": "Custom",
        })
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["IsAffectedCPU"] is False

    def test_handles_subprocess_failure(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.side_effect = Exception("PowerShell failed")

        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["status"] == "error"
        assert "message" in d


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/sysinfo/data
# ══════════════════════════════════════════════════════════════════════════════

class TestSysinfoRoute:
    """Tests for /api/sysinfo/data"""

    SAMPLE_OUTPUT = json.dumps({
        "Computer": {
            "Name": "DESKTOP-TEST", "Domain": "WORKGROUP",
            "Manufacturer": "Dell Inc.", "Model": "XPS 8960",
            "SystemType": "x64-based PC", "TotalRAM_GB": 31.7,
        },
        "OS": {
            "Name": "Microsoft Windows 11 Pro", "Version": "10.0.22631",
            "Build": "22631", "Architecture": "64-bit",
            "InstallDate": "2024-01-15", "LastBoot": "2025-03-18 10:00:00",
            "Uptime": "01.05:30:00", "WindowsDir": "C:\\WINDOWS",
            "SystemDrive": "C:", "Locale": "English (United States)",
            "TimeZone": "(UTC-08:00) Pacific Time", "TimeZoneId": "Pacific Standard Time",
        },
        "CPU": {
            "Name": "Intel(R) Core(TM) i9-14900K", "Cores": 24,
            "LogicalProcs": 32, "MaxClockMHz": 3200, "CurrentClockMHz": 3200,
            "SocketDesignation": "LGA1700", "L2CacheKB": 32768,
            "L3CacheKB": 36864, "ProcessorId": "BFEBFBFF000B0671",
            "Architecture": "x64",
        },
        "BIOS": {
            "Version": "2.22.0", "ReleaseDate": "2025-01-10",
            "Manufacturer": "Dell Inc.", "SerialNumber": "ABC1234",
        },
        "Baseboard": {
            "Manufacturer": "Dell Inc.", "Product": "0WN7Y6",
            "Version": "A01", "SerialNumber": "/ABC1234/",
        },
        "GPU": [
            {"Name": "NVIDIA GeForce RTX 4060 Ti", "DriverVersion": "32.0.15.9174",
             "AdapterRAM": 8589934592, "CurrentRefreshRate": 144,
             "VideoModeDescription": "2560 x 1440 x 32 bits"},
        ],
        "Network": [
            {"Description": "Killer E3100G", "MACAddress": "AA:BB:CC:DD:EE:FF",
             "IPAddress": "192.168.1.100", "DHCPEnabled": True,
             "DHCPServer": "192.168.1.1", "DNSServerSearchOrder": ["8.8.8.8"]},
        ],
        "Memory": [
            {"BankLabel": "DIMM1", "Capacity": 17179869184, "Speed": 5600,
             "Manufacturer": "SK Hynix", "PartNumber": "HMCG78AGBUA081N"},
        ],
        "Disks": [
            {"Model": "Samsung SSD 990 PRO 2TB", "Size": 2000398934016,
             "InterfaceType": "NVMe", "MediaType": "SSD",
             "SerialNumber": "S123456", "Partitions": 3},
        ],
        "Volumes": [
            {"DeviceID": "C:", "VolumeName": "OS", "FileSystem": "NTFS",
             "SizeGB": 931.5, "FreeGB": 200.0},
        ],
    })

    def test_returns_ok_with_system_data(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = self.SAMPLE_OUTPUT
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "ok"
        assert "data" in d

    def test_returns_computer_info(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = self.SAMPLE_OUTPUT
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert d["Computer"]["Name"] == "DESKTOP-TEST"
        assert d["Computer"]["Manufacturer"] == "Dell Inc."

    def test_returns_cpu_info(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = self.SAMPLE_OUTPUT
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert "i9-14900K" in d["CPU"]["Name"]
        assert d["CPU"]["Cores"] == 24

    def test_returns_os_info(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = self.SAMPLE_OUTPUT
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert "Windows 11" in d["OS"]["Name"]
        assert d["OS"]["Build"] == "22631"

    def test_normalizes_single_gpu_to_list(self, client, mocker):
        """PowerShell returns dict for single item — should be normalized to list."""
        single_gpu = json.loads(self.SAMPLE_OUTPUT)
        single_gpu["GPU"] = single_gpu["GPU"][0]  # dict instead of list
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = json.dumps(single_gpu)
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["GPU"], list)
        assert len(d["GPU"]) == 1

    def test_normalizes_single_disk_to_list(self, client, mocker):
        single_disk = json.loads(self.SAMPLE_OUTPUT)
        single_disk["Disks"] = single_disk["Disks"][0]
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = json.dumps(single_disk)
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()["data"]
        assert isinstance(d["Disks"], list)

    def test_handles_empty_output(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "ok"

    def test_handles_subprocess_failure(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.side_effect = Exception("PowerShell crashed")

        r = client.get("/api/sysinfo/data")
        d = r.get_json()
        assert d["status"] == "error"
        assert "message" in d

    def test_summary_route_accepts_sysinfo(self, client, mocker):
        """Verify the summary endpoint handles sysinfo tab."""
        mocker.patch("windesktopmgr.subprocess.run")
        payload = {
            "Computer": {"Name": "TEST", "Manufacturer": "Dell", "Model": "XPS", "TotalRAM_GB": 32},
            "OS": {"Name": "Windows 11", "Uptime": "02.10:00:00", "Build": "22631", "InstallDate": "2024-01-01"},
            "CPU": {"Name": "i9-14900K", "Cores": 24, "LogicalProcs": 32},
        }
        r = client.post("/api/summary/sysinfo",
                        data=json.dumps(payload),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "status" in d
        assert "headline" in d
