"""
tests/test_remediation.py
Flask route, PowerShell mock, and pure-function tests for the Remediation Engine.
"""

import json
import subprocess

import remediation
import windesktopmgr as wdm


def _mock_ps(mocker, stdout="", returncode=0, stderr=""):
    m = mocker.patch("remediation.subprocess.run")
    m.return_value.stdout = stdout
    m.return_value.returncode = returncode
    m.return_value.stderr = stderr
    return m


# ── REMEDIATION_REGISTRY ─────────────────────────────────────────────────────


class TestRemediationRegistry:
    def test_has_ten_actions(self):
        assert len(remediation.REMEDIATION_REGISTRY) == 10

    def test_each_has_required_fields(self):
        for key, a in remediation.REMEDIATION_REGISTRY.items():
            assert {"id", "label", "description", "risk", "reboot", "icon"} <= a.keys()
            assert a["id"] == key

    def test_risk_values_valid(self):
        for a in remediation.REMEDIATION_REGISTRY.values():
            assert a["risk"] in {"low", "medium", "high"}

    def test_dispatch_covers_all_registry(self):
        assert set(remediation._REMEDIATION_DISPATCH.keys()) == set(remediation.REMEDIATION_REGISTRY.keys())


# ── /api/remediation/actions ─────────────────────────────────────────────────


class TestRemediationActionsRoute:
    def test_returns_list(self, client):
        r = client.get("/api/remediation/actions")
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_has_ten_actions(self, client):
        assert len(client.get("/api/remediation/actions").get_json()) == 10

    def test_each_has_required_fields(self, client):
        for a in client.get("/api/remediation/actions").get_json():
            assert {"id", "label", "description", "risk", "reboot", "icon"} <= a.keys()


# ── /api/remediation/history ─────────────────────────────────────────────────


class TestRemediationHistoryRoute:
    def test_empty_when_no_file(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "nofile.json"))
        r = client.get("/api/remediation/history")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_returns_reversed_history(self, client, tmp_path, monkeypatch):
        f = tmp_path / "h.json"
        f.write_text(json.dumps([{"id": "a", "ts": "2026-01-01"}, {"id": "b", "ts": "2026-01-02"}]))
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(f))
        data = client.get("/api/remediation/history").get_json()
        assert data[0]["id"] == "b"

    def test_corrupt_file_returns_500(self, client, tmp_path, monkeypatch):
        f = tmp_path / "h.json"
        f.write_text("NOT JSON {{")
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(f))
        r = client.get("/api/remediation/history")
        assert r.status_code == 500


# ── /api/remediation/run ─────────────────────────────────────────────────────


class TestRemediationRunRoute:
    def test_unknown_action_returns_400(self, client):
        r = client.post("/api/remediation/run", json={"action_id": "nope"})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_missing_action_id_returns_400(self, client):
        r = client.post("/api/remediation/run", json={})
        assert r.status_code == 400

    def test_flush_dns_ok(self, client, mocker, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "h.json"))
        _mock_ps(mocker, stdout="", returncode=0)
        r = client.post("/api/remediation/run", json={"action_id": "flush_dns"})
        assert r.get_json()["ok"] is True

    def test_flush_dns_logs_history(self, client, mocker, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        _mock_ps(mocker, stdout="", returncode=0)
        client.post("/api/remediation/run", json={"action_id": "flush_dns"})
        history = json.loads(hfile.read_text())
        assert len(history) == 1
        assert history[0]["id"] == "flush_dns"
        assert history[0]["ok"] is True

    def test_action_id_sanitized(self, client, mocker, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "h.json"))
        _mock_ps(mocker, stdout="", returncode=0)
        r = client.post("/api/remediation/run", json={"action_id": "flush_dns; rm -rf /"})
        # Sanitized to "flushdnsrmrf" which is not a valid action
        assert r.status_code == 400

    def test_subprocess_exception_returns_ok_false(self, client, mocker, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "h.json"))
        mocker.patch("remediation.subprocess.run", side_effect=Exception("timeout"))
        r = client.post("/api/remediation/run", json={"action_id": "flush_dns"})
        assert r.get_json()["ok"] is False
        assert "timeout" in r.get_json()["message"]

    def test_failed_action_logged_as_failure(self, client, mocker, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        _mock_ps(mocker, stdout="", returncode=1, stderr="Access denied")
        client.post("/api/remediation/run", json={"action_id": "flush_dns"})
        history = json.loads(hfile.read_text())
        assert history[0]["ok"] is False


# ── _log_remediation ─────────────────────────────────────────────────────────


class TestLogRemediation:
    def test_creates_file_if_missing(self, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        remediation._log_remediation("flush_dns", True, "done")
        assert hfile.exists()
        data = json.loads(hfile.read_text())
        assert len(data) == 1

    def test_appends_to_existing(self, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        hfile.write_text(json.dumps([{"id": "old"}]))
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        remediation._log_remediation("flush_dns", True, "done")
        data = json.loads(hfile.read_text())
        assert len(data) == 2

    def test_entry_has_correct_fields(self, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        remediation._log_remediation("flush_dns", True, "all good")
        entry = json.loads(hfile.read_text())[0]
        for field in ("id", "label", "risk", "ts", "ok", "message"):
            assert field in entry
        assert entry["ok"] is True
        assert entry["label"] == "Flush DNS Cache"
        assert entry["risk"] == "low"

    def test_corrupt_file_handled_gracefully(self, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        hfile.write_text("NOT JSON {{{{")
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        remediation._log_remediation("flush_dns", False, "err")

    def test_unknown_action_logs_with_defaults(self, tmp_path, monkeypatch):
        hfile = tmp_path / "h.json"
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(hfile))
        remediation._log_remediation("unknown_action", False, "nope")
        entry = json.loads(hfile.read_text())[0]
        assert entry["label"] == "unknown_action"
        assert entry["risk"] == "unknown"


# ── Action functions (PowerShell mocked) ─────────────────────────────────────


class TestRemActionFunctions:
    def test_flush_dns_ok(self, mocker):
        _mock_ps(mocker, stdout="", returncode=0)
        r = remediation._rem_flush_dns()
        assert r["ok"] is True
        assert "flushed" in r["message"].lower()

    def test_flush_dns_fail(self, mocker):
        _mock_ps(mocker, stdout="", returncode=1, stderr="Access denied")
        r = remediation._rem_flush_dns()
        assert r["ok"] is False

    def test_reset_winsock_ok(self, mocker):
        _mock_ps(mocker, stdout="", returncode=0)
        r = remediation._rem_reset_winsock()
        assert r["ok"] is True
        assert "reboot" in r["message"].lower()

    def test_reset_winsock_fail(self, mocker):
        _mock_ps(mocker, stdout="", returncode=1, stderr="Error")
        r = remediation._rem_reset_winsock()
        assert r["ok"] is False

    def test_reset_tcpip_ok(self, mocker):
        _mock_ps(mocker, stdout="", returncode=0)
        r = remediation._rem_reset_tcpip()
        assert r["ok"] is True
        assert "reboot" in r["message"].lower()

    def test_clear_temp_parses_count(self, mocker):
        _mock_ps(mocker, stdout="Removed:42 Errors:3", returncode=0)
        r = remediation._rem_clear_temp()
        assert r["ok"] is True
        assert "42" in r["message"]

    def test_clear_temp_no_count(self, mocker):
        _mock_ps(mocker, stdout="", returncode=0)
        r = remediation._rem_clear_temp()
        assert r["ok"] is True
        assert "0" in r["message"]

    def test_clear_temp_fail(self, mocker):
        _mock_ps(mocker, stdout="", returncode=1, stderr="Access denied")
        r = remediation._rem_clear_temp()
        assert r["ok"] is False

    def test_repair_image_ok(self, mocker):
        _mock_ps(mocker, stdout="DISM_DONE SFC_DONE OK:True", returncode=0)
        r = remediation._rem_repair_image()
        assert r["ok"] is True

    def test_repair_image_warnings(self, mocker):
        _mock_ps(mocker, stdout="DISM_DONE SFC_DONE OK:False", returncode=1)
        r = remediation._rem_repair_image()
        assert r["ok"] is False
        assert "warnings" in r["message"].lower()

    def test_clear_wu_cache_ok(self, mocker):
        _mock_ps(mocker, stdout="OK", returncode=0)
        r = remediation._rem_clear_wu_cache()
        assert r["ok"] is True

    def test_clear_wu_cache_error(self, mocker):
        _mock_ps(mocker, stdout="ERROR: Access denied", returncode=1)
        r = remediation._rem_clear_wu_cache()
        assert r["ok"] is False

    def test_restart_spooler_ok(self, mocker):
        _mock_ps(mocker, stdout="OK", returncode=0)
        r = remediation._rem_restart_spooler()
        assert r["ok"] is True

    def test_restart_spooler_fail(self, mocker):
        _mock_ps(mocker, stdout="ERROR: cannot stop", returncode=1)
        r = remediation._rem_restart_spooler()
        assert r["ok"] is False

    def test_reset_network_adapter_ok(self, mocker):
        _mock_ps(mocker, stdout="RESET:2", returncode=0)
        r = remediation._rem_reset_network_adapter()
        assert r["ok"] is True
        assert "2" in r["message"]

    def test_reset_network_adapter_none(self, mocker):
        _mock_ps(mocker, stdout="RESET:0", returncode=0)
        r = remediation._rem_reset_network_adapter()
        assert r["ok"] is False
        assert "no active" in r["message"].lower()

    def test_clear_icon_cache_ok(self, mocker):
        _mock_ps(mocker, stdout="OK", returncode=0)
        r = remediation._rem_clear_icon_cache()
        assert r["ok"] is True

    def test_clear_icon_cache_fail(self, mocker):
        _mock_ps(mocker, stdout="ERROR: access denied", returncode=1)
        r = remediation._rem_clear_icon_cache()
        assert r["ok"] is False

    def test_reboot_system_ok(self, mocker):
        _mock_ps(mocker, stdout="", returncode=0)
        r = remediation._rem_reboot_system()
        assert r["ok"] is True
        assert "10 seconds" in r["message"]

    def test_reboot_system_fail(self, mocker):
        _mock_ps(mocker, stdout="", returncode=1, stderr="Denied")
        r = remediation._rem_reboot_system()
        assert r["ok"] is False

    def test_all_actions_handle_exception(self, mocker):
        mocker.patch("remediation.subprocess.run", side_effect=TimeoutError("timed out"))
        for name, fn in remediation._REMEDIATION_DISPATCH.items():
            r = fn()
            assert r["ok"] is False, f"{name} did not return ok=False on exception"
            assert "timed out" in r["message"]

    def test_all_actions_handle_timeout_expired(self, mocker):
        mocker.patch(
            "remediation.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30),
        )
        for name, fn in remediation._REMEDIATION_DISPATCH.items():
            r = fn()
            assert r["ok"] is False, f"{name} did not return ok=False on TimeoutExpired"

    def test_flush_dns_command_content(self, mocker):
        m = _mock_ps(mocker, stdout="", returncode=0)
        remediation._rem_flush_dns()
        cmd = m.call_args[0][0][-1]
        assert "flushdns" in cmd

    def test_reboot_command_has_delay(self, mocker):
        m = _mock_ps(mocker, stdout="", returncode=0)
        remediation._rem_reboot_system()
        cmd = m.call_args[0][0][-1]
        assert "/t 10" in cmd


# ── NLQ integration ──────────────────────────────────────────────────────────


class TestRemediationNlq:
    def test_nlq_dispatch_has_remediation_entries(self):
        assert "get_remediation_history" in wdm._NLQ_DISPATCH
        assert "run_remediation_action" in wdm._NLQ_DISPATCH

    def test_nlq_tools_has_remediation_entries(self):
        names = [t["name"] for t in wdm._NLQ_TOOLS]
        assert "get_remediation_history" in names
        assert "run_remediation_action" in names

    def test_navigate_to_tab_includes_remediation(self):
        nav_tool = next(t for t in wdm._NLQ_TOOLS if t["name"] == "navigate_to_tab")
        tabs = nav_tool["input_schema"]["properties"]["tab"]["enum"]
        assert "remediation" in tabs

    def test_nlq_get_history_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "nofile.json"))
        result = remediation._nlq_get_remediation_history()
        assert result == []

    def test_nlq_get_history_returns_data(self, tmp_path, monkeypatch):
        f = tmp_path / "h.json"
        f.write_text(json.dumps([{"id": "flush_dns", "ok": True}]))
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(f))
        result = remediation._nlq_get_remediation_history()
        assert len(result) == 1

    def test_nlq_run_remediation_ok(self, mocker, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "h.json"))
        _mock_ps(mocker, stdout="", returncode=0)
        result = remediation._nlq_run_remediation({"action_id": "flush_dns"})
        assert result["ok"] is True

    def test_nlq_run_remediation_unknown(self, tmp_path, monkeypatch):
        monkeypatch.setattr(remediation, "REMEDIATION_HISTORY_FILE", str(tmp_path / "h.json"))
        result = remediation._nlq_run_remediation({"action_id": "not_real"})
        assert result["ok"] is False
