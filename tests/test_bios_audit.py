"""tests/test_bios_audit.py -- unit + route tests for bios_audit.py.

All tests use a tmp_path-backed HISTORY_FILE via the ``bios_audit_tmp``
fixture so nothing touches the real ``bios_audit_history.json``. PS calls
are fully mocked -- no subprocess ever actually runs.
"""

import json
from datetime import datetime, timedelta

import pytest

import bios_audit

# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def bios_audit_tmp(tmp_path, monkeypatch):
    """Redirect HISTORY_FILE to a per-test tmp file."""
    target = tmp_path / "bios_audit_history.json"
    monkeypatch.setattr(bios_audit, "HISTORY_FILE", str(target))
    return target


@pytest.fixture
def mock_ps(mocker):
    """Patch subprocess.run calls made from bios_audit._run_ps."""

    def _factory(responses: dict[str, str]):
        """Map a substring-of-command -> stdout. Default to ''."""

        def _fake_run(cmd, *_, **__):
            command_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            stdout = ""
            for needle, response in responses.items():
                if needle in command_str:
                    stdout = response
                    break

            class R:
                returncode = 0

            R.stdout = stdout
            R.stderr = ""
            return R

        return mocker.patch("bios_audit.subprocess.run", side_effect=_fake_run)

    return _factory


SAMPLE_BIOS = {
    "BIOSVersion": "1.2.3",
    "ReleaseDate": "20250101000000.000000+000",
    "Manufacturer": "Dell Inc.",
    "BoardProduct": "XPS 8960",
    "BoardMfr": "Dell Inc.",
    "BIOSDateFormatted": "January 01, 2025",
}


def _sample_bios_reader():
    return dict(SAMPLE_BIOS)


# ── Snapshot ───────────────────────────────────────────────────────


class TestTakeSnapshot:
    def test_structure_has_all_expected_keys(self, mock_ps):
        mock_ps(
            {
                "Confirm-SecureBootUEFI": "True",
                "Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": true, "ManufacturerVersion": "7.2.0"}',
                "PEFirmwareType": "2",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
                "Win32_BIOS).SerialNumber": "ABC123",
            }
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        for key in (
            "timestamp",
            "bios_version",
            "bios_release_date",
            "bios_manufacturer",
            "bios_serial",
            "board_product",
            "board_manufacturer",
            "secure_boot",
            "tpm",
            "boot_mode",
            "vbs",
        ):
            assert key in snap, f"missing key: {key}"

    def test_bios_fields_copied_from_reader(self, mock_ps):
        mock_ps({})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["bios_version"] == "1.2.3"
        assert snap["bios_manufacturer"] == "Dell Inc."
        assert snap["board_product"] == "XPS 8960"
        assert snap["bios_release_date"] == "January 01, 2025"

    def test_secure_boot_enabled(self, mock_ps):
        mock_ps({"Confirm-SecureBootUEFI": "True"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["secure_boot"] == "enabled"

    def test_secure_boot_disabled(self, mock_ps):
        mock_ps({"Confirm-SecureBootUEFI": "False"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["secure_boot"] == "disabled"

    def test_tpm_json_parsed(self, mock_ps):
        mock_ps(
            {"Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": false, "ManufacturerVersion": "7.2.0"}'}
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["tpm"]["present"] is True
        assert snap["tpm"]["enabled"] is True
        assert snap["tpm"]["ready"] is False
        assert snap["tpm"]["version"] == "7.2.0"

    def test_tpm_malformed_json_falls_back_to_none(self, mock_ps):
        mock_ps({"Get-Tpm": "not-json-at-all"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["tpm"] == {"present": None, "enabled": None, "ready": None, "version": None}

    def test_boot_mode_uefi(self, mock_ps):
        mock_ps({"PEFirmwareType": "2"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["boot_mode"] == "UEFI"

    def test_boot_mode_legacy(self, mock_ps):
        mock_ps({"PEFirmwareType": "1"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["boot_mode"] == "Legacy"

    def test_boot_mode_unknown(self, mock_ps):
        mock_ps({"PEFirmwareType": ""})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["boot_mode"] is None

    def test_vbs_running_with_hvci(self, mock_ps):
        mock_ps({"Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2, 1]}'})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        assert snap["vbs"]["vbs_status"] == "running"
        assert snap["vbs"]["hvci_running"] is True
        assert snap["vbs"]["cred_guard_running"] is True

    def test_ps_timeout_returns_empty_but_does_not_raise(self, mock_ps, mocker):
        import subprocess as sp

        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=10),
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader)
        # BIOS fields still populated from reader; PS-dependent fields None
        assert snap["bios_version"] == "1.2.3"
        assert snap["secure_boot"] is None
        assert snap["boot_mode"] is None

    def test_bios_reader_exception_does_not_crash(self, mock_ps):
        mock_ps({})

        def bad_reader():
            raise RuntimeError("boom")

        snap = bios_audit.take_snapshot(bios_reader=bad_reader)
        assert snap["bios_version"] is None
        assert snap["bios_manufacturer"] is None


# ── Diff ───────────────────────────────────────────────────────────


class TestDiffSnapshots:
    def test_empty_old_returns_no_changes(self):
        assert bios_audit.diff_snapshots({}, {"bios_version": "1"}) == []

    def test_none_old_returns_no_changes(self):
        assert bios_audit.diff_snapshots(None, {"bios_version": "1"}) == []  # type: ignore[arg-type]

    def test_identical_returns_empty(self):
        a = {"bios_version": "1.2.3", "tpm": {"enabled": True}}
        b = {"bios_version": "1.2.3", "tpm": {"enabled": True}}
        assert bios_audit.diff_snapshots(a, b) == []

    def test_top_level_change(self):
        a = {"bios_version": "1.2.3"}
        b = {"bios_version": "2.0.0"}
        changes = bios_audit.diff_snapshots(a, b)
        assert changes == [{"field": "bios_version", "old": "1.2.3", "new": "2.0.0"}]

    def test_nested_change_is_flattened(self):
        a = {"tpm": {"enabled": True, "ready": True}}
        b = {"tpm": {"enabled": False, "ready": True}}
        changes = bios_audit.diff_snapshots(a, b)
        assert changes == [{"field": "tpm.enabled", "old": True, "new": False}]

    def test_multiple_changes_are_sorted(self):
        a = {"secure_boot": "enabled", "vbs": {"hvci_running": True}}
        b = {"secure_boot": "disabled", "vbs": {"hvci_running": False}}
        changes = bios_audit.diff_snapshots(a, b)
        assert [c["field"] for c in changes] == ["secure_boot", "vbs.hvci_running"]

    def test_timestamp_is_ignored(self):
        a = {"timestamp": "2026-01-01", "bios_version": "1"}
        b = {"timestamp": "2026-02-01", "bios_version": "1"}
        assert bios_audit.diff_snapshots(a, b) == []

    def test_added_field_shows_as_change_from_none(self):
        a = {"bios_version": "1"}
        b = {"bios_version": "1", "secure_boot": "enabled"}
        changes = bios_audit.diff_snapshots(a, b)
        assert changes == [{"field": "secure_boot", "old": None, "new": "enabled"}]


# ── History persistence ───────────────────────────────────────────


class TestHistory:
    def test_load_empty_when_no_file(self, bios_audit_tmp):
        assert bios_audit.load_history() == []

    def test_load_empty_when_file_corrupt(self, bios_audit_tmp):
        bios_audit_tmp.write_text("not json at all", encoding="utf-8")
        assert bios_audit.load_history() == []

    def test_append_and_load_roundtrip(self, bios_audit_tmp):
        entry = {"kind": "baseline", "timestamp": "2026-01-01T00:00:00", "snapshot": {"x": 1}}
        assert bios_audit._append_history(entry) is True
        history = bios_audit.load_history()
        assert len(history) == 1
        assert history[0]["kind"] == "baseline"

    def test_history_capped_at_max(self, bios_audit_tmp, monkeypatch):
        monkeypatch.setattr(bios_audit, "MAX_HISTORY", 3)
        for i in range(5):
            bios_audit._append_history(
                {"kind": "change", "timestamp": f"2026-01-0{i + 1}T00:00:00", "snapshot": {"i": i}}
            )
        history = bios_audit.load_history()
        assert len(history) == 3
        # Oldest two dropped
        assert [e["snapshot"]["i"] for e in history] == [2, 3, 4]

    def test_latest_snapshot_returns_most_recent(self, bios_audit_tmp):
        bios_audit._append_history({"kind": "baseline", "timestamp": "2026-01-01T00:00:00", "snapshot": {"v": 1}})
        bios_audit._append_history({"kind": "change", "timestamp": "2026-01-02T00:00:00", "snapshot": {"v": 2}})
        assert bios_audit.latest_snapshot() == {"v": 2}

    def test_latest_snapshot_none_when_empty(self, bios_audit_tmp):
        assert bios_audit.latest_snapshot() is None


# ── check_and_log_bios_changes ────────────────────────────────────


class TestCheckAndLog:
    def _patch_all_ps_calls(self, mock_ps, secure="True", pe="2"):
        mock_ps(
            {
                "Confirm-SecureBootUEFI": secure,
                "Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": true, "ManufacturerVersion": "7"}',
                "PEFirmwareType": pe,
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
                "Win32_BIOS).SerialNumber": "ABC",
            }
        )

    def test_first_run_logs_baseline(self, bios_audit_tmp, mock_ps):
        self._patch_all_ps_calls(mock_ps)
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        assert result["ok"] is True
        assert result["first_run"] is True
        assert result["changes"] == []
        history = bios_audit.load_history()
        assert len(history) == 1
        assert history[0]["kind"] == "baseline"

    def test_no_change_does_not_append(self, bios_audit_tmp, mock_ps):
        self._patch_all_ps_calls(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        # Second run with identical state
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        assert result["changes"] == []
        assert len(bios_audit.load_history()) == 1  # still just the baseline

    def test_change_is_logged(self, bios_audit_tmp, mock_ps):
        self._patch_all_ps_calls(mock_ps, secure="True")
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        # Second run: Secure Boot now disabled
        self._patch_all_ps_calls(mock_ps, secure="False")
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        assert result["first_run"] is False
        assert any(c["field"] == "secure_boot" for c in result["changes"])
        history = bios_audit.load_history()
        assert len(history) == 2
        assert history[-1]["kind"] == "change"

    def test_throttle_skips_when_recent(self, bios_audit_tmp, mock_ps):
        self._patch_all_ps_calls(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        # Second call without force should be throttled
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=False)
        assert result["skipped"] is True

    def test_throttle_runs_when_interval_elapsed(self, bios_audit_tmp, mock_ps, monkeypatch):
        self._patch_all_ps_calls(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True)
        # Rewrite the baseline timestamp to be > SNAPSHOT_INTERVAL ago
        history = bios_audit.load_history()
        past = (datetime.now() - timedelta(minutes=30)).isoformat(timespec="seconds")
        history[-1]["timestamp"] = past
        bios_audit_tmp.write_text(json.dumps(history), encoding="utf-8")
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=False)
        assert result["skipped"] is False


# ── recent_changes ─────────────────────────────────────────────────


class TestRecentChanges:
    def test_empty_history(self, bios_audit_tmp):
        assert bios_audit.recent_changes() == []

    def test_only_recent_window_returned(self, bios_audit_tmp):
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "change",
                "timestamp": (now - timedelta(hours=48)).isoformat(timespec="seconds"),
                "changes": [{"field": "a", "old": 1, "new": 2}],
                "snapshot": {},
            }
        )
        bios_audit._append_history(
            {
                "kind": "change",
                "timestamp": (now - timedelta(hours=2)).isoformat(timespec="seconds"),
                "changes": [{"field": "b", "old": 1, "new": 2}],
                "snapshot": {},
            }
        )
        recent = bios_audit.recent_changes(window=timedelta(hours=24))
        assert len(recent) == 1
        assert recent[0]["changes"][0]["field"] == "b"

    def test_baseline_entries_excluded(self, bios_audit_tmp):
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "baseline",
                "timestamp": now.isoformat(timespec="seconds"),
                "snapshot": {},
            }
        )
        assert bios_audit.recent_changes() == []


# ── Flask route tests ─────────────────────────────────────────────


class TestBiosAuditRoutes:
    def test_history_empty(self, client, bios_audit_tmp):
        resp = client.get("/api/bios/audit/history")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["history"] == []

    def test_history_returns_entries(self, client, bios_audit_tmp):
        bios_audit._append_history(
            {
                "kind": "baseline",
                "timestamp": "2026-04-18T12:00:00",
                "snapshot": {"bios_version": "1.0"},
            }
        )
        resp = client.get("/api/bios/audit/history")
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(body["history"]) == 1
        assert body["history"][0]["kind"] == "baseline"

    def test_history_honors_limit(self, client, bios_audit_tmp):
        for i in range(5):
            bios_audit._append_history({"kind": "change", "timestamp": f"2026-01-0{i + 1}T00:00:00", "snapshot": {}})
        resp = client.get("/api/bios/audit/history?limit=2")
        body = resp.get_json()
        assert len(body["history"]) == 2

    def test_snapshot_returns_latest_when_available(self, client, bios_audit_tmp):
        bios_audit._append_history(
            {
                "kind": "baseline",
                "timestamp": "2026-04-18T12:00:00",
                "snapshot": {"bios_version": "9.9.9", "secure_boot": "enabled"},
            }
        )
        resp = client.get("/api/bios/audit/snapshot")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["snapshot"]["bios_version"] == "9.9.9"

    def test_snapshot_takes_fresh_when_history_empty(self, client, bios_audit_tmp, mocker):
        # Force take_snapshot() to return a known value rather than hit real PS/WMI
        stub = {
            "timestamp": "2026-04-18T12:00:00",
            "bios_version": "fresh",
            "tpm": {},
            "vbs": {},
        }
        mocker.patch("bios_audit.take_snapshot", return_value=stub)
        resp = client.get("/api/bios/audit/snapshot")
        assert resp.status_code == 200
        assert resp.get_json()["snapshot"]["bios_version"] == "fresh"


class TestDashboardBiosChangeConcern:
    """The dashboard summary must surface a recent BIOS change as an info concern."""

    def test_concern_appears_when_recent_change_exists(self, client, bios_audit_tmp, mocker):
        # Seed a change from 2h ago — inside the 24h window
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "change",
                "timestamp": (now - timedelta(hours=2)).isoformat(timespec="seconds"),
                "changes": [{"field": "secure_boot", "old": "enabled", "new": "disabled"}],
                "snapshot": {},
            }
        )
        # Prevent the real PS-backed dashboard checks from running — we only care
        # about the BIOS-audit concern path
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_driver_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch.object(wdm, "get_disk_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_network_data", return_value={"ok": True})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"ok": True})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={"ok": True})
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        titles = [c.get("title", "") for c in resp.get_json().get("concerns", [])]
        assert any("BIOS/firmware setting change" in t for t in titles), (
            f"Expected BIOS change concern, got titles: {titles}"
        )
