"""
test_routes.py
Flask route integration tests using the test client.
All subprocess / PowerShell calls are mocked — no Windows dependency.
"""

import json
import pytest
import windesktopmgr as wdm


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
        # Must be a list (not null/None) so the frontend can iterate safely
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
        # Either ok=True with removed=False, or some graceful response
        assert data.get("ok") is True


# ══════════════════════════════════════════════════════════════════════════════
# GET  /api/startup/lookup-status
# ══════════════════════════════════════════════════════════════════════════════

class TestStartupLookupStatusRoute:
    def test_returns_pending_count(self, client):
        resp = client.get("/api/startup/lookup-status")
        assert resp.status_code == 200
        data = resp.get_json()
        # Route returns queue_pending + in_flight + cached
        assert "queue_pending" in data
        assert isinstance(data["queue_pending"], int)


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
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyApp", "type": "registry_hklm", "enable": True},
        )
        assert resp.status_code == 200
        assert mock_run.called

    def test_task_disable_calls_subprocess(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        resp = client.post(
            "/api/startup/toggle",
            json={"name": "MyTask", "type": "task", "enable": False},
        )
        assert resp.status_code == 200
        assert mock_run.called
        cmd = mock_run.call_args[0][0][-1]
        assert "Disable-ScheduledTask" in cmd or "Disable" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/services/toggle — input validation (safety critical)
# ══════════════════════════════════════════════════════════════════════════════

class TestServicesToggleRoute:
    def test_invalid_action_returns_error_no_subprocess(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "explode"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False
        # subprocess must NOT have been called for invalid actions
        mock_run.assert_not_called()

    def test_stop_action_calls_subprocess(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "stop"},
        )
        assert resp.status_code == 200
        assert mock_run.called
        cmd = mock_run.call_args[0][0][-1]
        assert "Stop-Service" in cmd

    def test_disable_action_calls_subprocess(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        resp = client.post(
            "/api/services/toggle",
            json={"name": "spooler", "action": "disable"},
        )
        assert resp.status_code == 200
        assert mock_run.called


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/processes/kill — safety critical
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessKillRoute:
    def test_kill_calls_subprocess_with_pid(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        resp = client.post("/api/processes/kill", json={"pid": 1234})
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        cmd = mock_run.call_args[0][0][-1]
        assert "1234" in cmd

    def test_kill_subprocess_failure_returns_error(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Access denied"
        resp = client.post("/api/processes/kill", json={"pid": 999})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/events/query — max_events cap
# ══════════════════════════════════════════════════════════════════════════════

class TestEventsQueryRoute:
    def test_returns_list(self, client, mocker):
        mocker.patch("windesktopmgr.subprocess.run").return_value.stdout = "[]"
        mocker.patch("windesktopmgr.subprocess.run").return_value.returncode = 0
        resp = client.post("/api/events/query", json={"log": "System", "level": "Error"})
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_max_events_capped(self, client, mocker):
        mock_run = mocker.patch("windesktopmgr.subprocess.run")
        mock_run.return_value.stdout = "[]"
        mock_run.return_value.returncode = 0
        # Request more than 500 events
        client.post("/api/events/query", json={"log": "System", "max": 9999})
        cmd = mock_run.call_args[0][0][-1]
        # The PowerShell command must not allow more than 500
        assert "9999" not in cmd


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/summary/<tab>
# ══════════════════════════════════════════════════════════════════════════════

class TestSummaryRoute:
    # /api/summary/<tab> uses request.get_json() — must send content_type=application/json

    def test_unknown_tab_returns_error(self, client):
        resp = client.post("/api/summary/nonexistent_tab", json={})
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            data = resp.get_json()
            assert "error" in data or "status" in data

    def test_drivers_tab_returns_status(self, client):
        wdm._scan_results = []
        resp = client.post("/api/summary/drivers", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data

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
        data = resp.get_json()
        assert "status" in data

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
