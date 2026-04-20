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
    def test_user_context_omits_elevated_fields(self, mock_ps):
        """User-context snapshots must NOT contain admin-gated fields,
        so filling them in later (via elevated context) does not look
        like a change-from-null."""
        mock_ps(
            {
                "Win32_BIOS).SerialNumber": "SN-USER",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
            }
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="user")
        assert snap["context"] == "user"
        for key in ("bios_version", "bios_serial", "vbs"):
            assert key in snap, f"user-context missing expected key: {key}"
        for key in ("secure_boot", "tpm", "boot_mode"):
            assert key not in snap, f"user-context leaked elevated-only key: {key}"

    def test_elevated_context_includes_all_fields(self, mock_ps):
        mock_ps(
            {
                "Confirm-SecureBootUEFI": "True",
                "Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": true, "ManufacturerVersion": "7.2.0"}',
                "PEFirmwareType": "2",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
                "Win32_BIOS).SerialNumber": "ABC123",
            }
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["context"] == "elevated"
        for key in (
            "timestamp",
            "context",
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
            assert key in snap, f"elevated-context missing key: {key}"

    def test_invalid_context_raises(self, mock_ps):
        mock_ps({})
        with pytest.raises(ValueError):
            bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="root")

    def test_bios_fields_copied_from_reader(self, mock_ps):
        mock_ps({})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["bios_version"] == "1.2.3"
        assert snap["bios_manufacturer"] == "Dell Inc."
        assert snap["board_product"] == "XPS 8960"
        assert snap["bios_release_date"] == "January 01, 2025"

    def test_secure_boot_enabled(self, mock_ps):
        mock_ps({"Confirm-SecureBootUEFI": "True"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["secure_boot"] == "enabled"

    def test_secure_boot_disabled(self, mock_ps):
        mock_ps({"Confirm-SecureBootUEFI": "False"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["secure_boot"] == "disabled"

    def test_tpm_json_parsed(self, mock_ps):
        mock_ps(
            {"Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": false, "ManufacturerVersion": "7.2.0"}'}
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["tpm"]["present"] is True
        assert snap["tpm"]["enabled"] is True
        assert snap["tpm"]["ready"] is False
        assert snap["tpm"]["version"] == "7.2.0"

    def test_tpm_malformed_json_recorded_as_error(self, mock_ps):
        """Previously we silently recorded all-None TPM fields when JSON parse failed.
        Now we omit the field entirely and record the parse failure as a collection
        error -- so the diff engine doesn't see a phantom value next cycle."""
        mock_ps({"Get-Tpm": "not-json-at-all"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert "tpm" not in snap
        errors = snap.get("_collection_errors", [])
        assert any(e.get("field") == "tpm" for e in errors)

    def test_boot_mode_uefi(self, mock_ps):
        mock_ps({"PEFirmwareType": "2"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["boot_mode"] == "UEFI"

    def test_boot_mode_legacy(self, mock_ps):
        mock_ps({"PEFirmwareType": "1"})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert snap["boot_mode"] == "Legacy"

    def test_boot_mode_unknown_is_omitted(self, mock_ps):
        """Empty registry value → unknown → omit from snapshot (no signal)."""
        mock_ps({"PEFirmwareType": ""})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        assert "boot_mode" not in snap

    def test_vbs_running_with_hvci_user_context(self, mock_ps):
        # VBS works without admin — user context should still capture it
        mock_ps({"Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2, 1]}'})
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="user")
        assert snap["vbs"]["vbs_status"] == "running"
        assert snap["vbs"]["hvci_running"] is True
        assert snap["vbs"]["cred_guard_running"] is True

    def test_ps_timeout_omits_ps_fields_and_records_errors(self, mock_ps, mocker):
        """Transient PowerShell failure must not leave null values in the snapshot.
        Instead the field is omitted and the failure is attached to
        _collection_errors. This is the core bug fix: previously the null got
        diffed against the next successful snapshot and produced a fake change."""
        import subprocess as sp

        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=10),
        )
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="elevated")
        # BIOS fields still populated from reader
        assert snap["bios_version"] == "1.2.3"
        # PS-dependent fields must be ABSENT, not None
        for key in ("bios_serial", "vbs", "secure_boot", "tpm", "boot_mode"):
            assert key not in snap, f"expected {key!r} to be omitted on PS timeout, but found {snap.get(key)!r}"
        # Every failed field should have an error entry
        errors = snap.get("_collection_errors", [])
        err_fields = {e["field"] for e in errors}
        assert {"bios_serial", "vbs", "secure_boot", "tpm", "boot_mode"}.issubset(err_fields)
        assert all("timeout" in e["error"] for e in errors)

    def test_ps_nonzero_exit_recorded_as_error(self, mock_ps, mocker):
        """Non-zero returncode with stderr should surface the stderr line as the
        error reason, not be silently treated as an empty success."""

        def _fake_run(*_, **__):
            class R:
                returncode = 1
                stdout = ""
                stderr = "CimInstance : Access denied\n"

            return R()

        mocker.patch("bios_audit.subprocess.run", side_effect=_fake_run)
        snap = bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="user")
        errors = snap.get("_collection_errors", [])
        assert errors, "non-zero exit should populate collection errors"
        assert any("Access denied" in e["error"] for e in errors)

    def test_bios_reader_exception_records_error_and_omits_fields(self, mock_ps):
        """Reader explosion is recorded so the user can tell 'reader broke'
        apart from 'reader returned empty data'."""
        mock_ps({})

        def bad_reader():
            raise RuntimeError("boom")

        snap = bios_audit.take_snapshot(bios_reader=bad_reader, context="user")
        assert "bios_version" not in snap
        assert "bios_manufacturer" not in snap
        errors = snap.get("_collection_errors", [])
        assert any(e.get("field") == "bios_reader" and "boom" in e["error"] for e in errors)

    def test_collection_error_logged_via_applogging(self, mock_ps, mocker):
        """PS failures must surface in the application log so a systemic
        outage is visible rather than hidden behind None values.

        Uses a spy rather than pytest's caplog because the windesktopmgr
        logger has propagate=False (to keep app log output out of the
        python root logger), which also means caplog doesn't see it.
        """
        import subprocess as sp

        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=10),
        )
        spy = mocker.spy(bios_audit._log, "warning")
        bios_audit.take_snapshot(bios_reader=_sample_bios_reader, context="user")
        assert spy.call_count >= 1, "expected at least one warning log on PS timeout"
        # Flatten every logged warning (format string + args) for substring check
        logged_text = " ".join(
            (call.args[0] % call.args[1:]) if len(call.args) > 1 else str(call.args[0]) for call in spy.call_args_list
        )
        assert "bios_serial" in logged_text
        assert "timeout" in logged_text


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

    def test_added_field_does_not_fire_change_from_none(self):
        """This was the false-positive pattern: a key present in one snapshot
        but missing (or None) in the other must NOT be reported as a change.
        Missing means 'no signal' (e.g. a transient PS failure omitted the
        field) -- treating it as a real value change flooded the audit trail."""
        a = {"bios_version": "1"}
        b = {"bios_version": "1", "secure_boot": "enabled"}
        assert bios_audit.diff_snapshots(a, b) == []

    def test_none_on_either_side_skipped(self):
        """Explicit None values behave the same as missing keys."""
        a = {"bios_serial": None, "vbs": {"vbs_status": "running"}}
        b = {"bios_serial": "9T46D14", "vbs": {"vbs_status": "running"}}
        assert bios_audit.diff_snapshots(a, b) == []

    def test_collection_errors_key_never_diffed(self):
        """The meta key recording collection failures must not appear as a diff."""
        a = {"bios_version": "1"}
        b = {"bios_version": "1", "_collection_errors": [{"field": "vbs", "error": "timeout"}]}
        assert bios_audit.diff_snapshots(a, b) == []

    def test_real_value_change_still_fires(self):
        """Sanity-check the fix did not break genuine change detection."""
        a = {"vbs": {"vbs_status": "running"}}
        b = {"vbs": {"vbs_status": "off"}}
        assert bios_audit.diff_snapshots(a, b) == [{"field": "vbs.vbs_status", "old": "running", "new": "off"}]


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
        # Secure Boot is an elevated-only field, so this test runs in that context
        self._patch_all_ps_calls(mock_ps, secure="True")
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
        # Second run: Secure Boot now disabled
        self._patch_all_ps_calls(mock_ps, secure="False")
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
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


# ── Two-context separation ────────────────────────────────────────


class TestTwoContexts:
    """The key invariant: user-context and elevated-context snapshots must
    diff only against others of the same context, so null-from-user doesn't
    look like a change when elevated fills it in."""

    def _patch_all(self, mock_ps, *, secure="True", pe="2"):
        mock_ps(
            {
                "Confirm-SecureBootUEFI": secure,
                "Get-Tpm": '{"TpmPresent": true, "TpmEnabled": true, "TpmReady": true, "ManufacturerVersion": "7"}',
                "PEFirmwareType": pe,
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
                "Win32_BIOS).SerialNumber": "ABC",
            }
        )

    def test_user_then_elevated_both_logged_as_baseline(self, bios_audit_tmp, mock_ps):
        self._patch_all(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
        history = bios_audit.load_history()
        assert [e["kind"] for e in history] == ["baseline", "baseline"]
        assert [e["context"] for e in history] == ["user", "elevated"]

    def test_elevated_baseline_does_not_trigger_user_change(self, bios_audit_tmp, mock_ps):
        """Even though the elevated snapshot has secure_boot/tpm/boot_mode
        and the user baseline didn't, running the user collector again
        must see NO changes (because it diffs against the last USER baseline)."""
        self._patch_all(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
        # Now the user collector runs again — should be a no-op
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")
        assert result["changes"] == []
        assert result["first_run"] is False

    def test_elevated_context_detects_secure_boot_flip(self, bios_audit_tmp, mock_ps):
        self._patch_all(mock_ps, secure="True")
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
        self._patch_all(mock_ps, secure="False")
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="elevated")
        assert any(c["field"] == "secure_boot" for c in result["changes"])

    def test_throttle_is_per_context(self, bios_audit_tmp, mock_ps):
        """A recent user snapshot should NOT throttle a subsequent elevated
        snapshot -- they are independent streams."""
        self._patch_all(mock_ps)
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")
        # Immediately run elevated without force -- should NOT be throttled
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=False, context="elevated")
        assert result["skipped"] is False
        assert result["first_run"] is True

    def test_latest_snapshot_context_filter(self, bios_audit_tmp):
        bios_audit._append_history(
            {
                "kind": "baseline",
                "context": "user",
                "timestamp": "2026-01-01T00:00:00",
                "snapshot": {"bios_version": "1.0", "context": "user"},
            }
        )
        bios_audit._append_history(
            {
                "kind": "baseline",
                "context": "elevated",
                "timestamp": "2026-01-01T01:00:00",
                "snapshot": {"bios_version": "1.0", "secure_boot": "enabled", "context": "elevated"},
            }
        )
        user_snap = bios_audit.latest_snapshot(context="user")
        elev_snap = bios_audit.latest_snapshot(context="elevated")
        assert user_snap and "secure_boot" not in user_snap
        assert elev_snap and elev_snap["secure_boot"] == "enabled"
        # Without a context filter, the most-recent entry wins (elevated here)
        assert bios_audit.latest_snapshot() == elev_snap

    def test_context_field_ignored_by_diff(self):
        """The `context` marker itself must never show up as a diff field."""
        a = {"context": "user", "bios_version": "1.0"}
        b = {"context": "elevated", "bios_version": "1.0"}
        assert bios_audit.diff_snapshots(a, b) == []


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


# ── Collection errors (false-positive fix) ────────────────────────


class TestRunPsResult:
    """The new PSResult contract: callers must be able to tell success from
    silent failure rather than having both collapse to an empty string."""

    def test_success_returns_ok_with_stdout(self, mock_ps):
        mock_ps({"Win32_BIOS).SerialNumber": "9T46D14"})
        res = bios_audit._run_ps("(Get-CimInstance Win32_BIOS).SerialNumber")
        assert res.ok is True
        assert res.stdout == "9T46D14"
        assert res.error is None

    def test_timeout_returns_error_with_duration(self, mocker):
        import subprocess as sp

        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=7),
        )
        res = bios_audit._run_ps("anything", timeout=7)
        assert res.ok is False
        assert res.stdout == ""
        assert "timeout" in res.error and "7s" in res.error

    def test_nonzero_exit_surfaces_stderr_first_line(self, mocker):
        class R:
            returncode = 2
            stdout = ""
            stderr = "Access denied.\nSecond line."

        mocker.patch("bios_audit.subprocess.run", return_value=R())
        res = bios_audit._run_ps("anything")
        assert res.ok is False
        # Only the first stderr line is captured (the rest is usually stack noise)
        assert res.error == "Access denied."

    def test_nonzero_exit_with_empty_stderr_uses_returncode(self, mocker):
        class R:
            returncode = 5
            stdout = ""
            stderr = ""

        mocker.patch("bios_audit.subprocess.run", return_value=R())
        res = bios_audit._run_ps("anything")
        assert res.ok is False
        assert "returncode=5" in res.error


class TestCheckAndLogErrorEntry:
    """When a polling cycle has collection errors and no changes, we must
    still persist an entry so the audit trail + dashboard concern can see
    that this cycle came back partial."""

    def test_error_only_entry_appended_when_no_changes(self, bios_audit_tmp, mock_ps, mocker):
        import subprocess as sp

        # First pass: everything works → baseline stored
        mock_ps(
            {
                "Win32_BIOS).SerialNumber": "ABC",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [2]}',
            }
        )
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")

        # Second pass: PS times out for everything → snapshot has errors but no value changes
        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=10),
        )
        result = bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")
        assert result["changes"] == [], "no value change occurred"
        assert result["errors"], "errors must be surfaced in the return dict"

        history = bios_audit.load_history()
        kinds = [e["kind"] for e in history]
        assert kinds == ["baseline", "error"]
        assert history[-1]["errors"], "error entry should carry the collection errors"

    def test_ps_recovery_after_failure_does_not_fire_phantom_change(self, bios_audit_tmp, mock_ps, mocker):
        """This is the exact bug the user hit: PS failed, then recovered, and
        the audit trail logged two phantom 'change' entries. After the fix
        there must be ZERO change entries in this sequence."""
        import subprocess as sp

        # Good baseline
        mock_ps(
            {
                "Win32_BIOS).SerialNumber": "9T46D14",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [1, 2]}',
            }
        )
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")

        # Transient failure
        mocker.patch(
            "bios_audit.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="powershell", timeout=10),
        )
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")

        # Recovery — same values as baseline
        mock_ps(
            {
                "Win32_BIOS).SerialNumber": "9T46D14",
                "Win32_DeviceGuard": '{"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [1, 2]}',
            }
        )
        bios_audit.check_and_log_bios_changes(bios_reader=_sample_bios_reader, force=True, context="user")

        kinds = [e["kind"] for e in bios_audit.load_history()]
        # Expected: baseline + one error (from the failure cycle). NO 'change' anywhere.
        assert "change" not in kinds, f"phantom change logged: {kinds}"
        assert kinds[0] == "baseline"
        assert "error" in kinds, "error cycle should still be recorded"


class TestRecentErrors:
    def test_empty_when_no_errors(self, bios_audit_tmp):
        assert bios_audit.recent_errors() == []

    def test_returns_standalone_error_entries_within_window(self, bios_audit_tmp):
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "error",
                "context": "user",
                "timestamp": (now - timedelta(hours=1)).isoformat(timespec="seconds"),
                "errors": [{"field": "vbs", "error": "timeout after 15s"}],
            }
        )
        bios_audit._append_history(
            {
                "kind": "error",
                "context": "user",
                "timestamp": (now - timedelta(hours=48)).isoformat(timespec="seconds"),
                "errors": [{"field": "bios_serial", "error": "Access denied"}],
            }
        )
        recent = bios_audit.recent_errors(window=timedelta(hours=24))
        assert len(recent) == 1
        assert recent[0]["errors"][0]["field"] == "vbs"

    def test_surfaces_errors_attached_to_change_entries(self, bios_audit_tmp):
        """Change entries carry _collection_errors inside the snapshot;
        recent_errors must unpack those too."""
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "change",
                "context": "user",
                "timestamp": now.isoformat(timespec="seconds"),
                "changes": [{"field": "bios_version", "old": "1", "new": "2"}],
                "snapshot": {
                    "bios_version": "2",
                    "_collection_errors": [{"field": "tpm", "error": "timeout after 10s"}],
                },
            }
        )
        recent = bios_audit.recent_errors()
        assert len(recent) == 1
        assert recent[0]["errors"][0]["field"] == "tpm"


class TestDashboardBiosErrorConcern:
    """New warning concern: surface collection errors on the dashboard so a
    systemic WMI outage doesn't hide behind silent None values."""

    def _mock_collectors(self, mocker):
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_driver_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch.object(wdm, "get_disk_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_network_data", return_value={"ok": True})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"ok": True})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={"ok": True})

    def test_concern_appears_when_recent_errors_exist(self, client, bios_audit_tmp, mocker):
        now = datetime.now()
        bios_audit._append_history(
            {
                "kind": "error",
                "context": "user",
                "timestamp": (now - timedelta(minutes=5)).isoformat(timespec="seconds"),
                "errors": [
                    {"field": "vbs", "error": "timeout after 15s"},
                    {"field": "bios_serial", "error": "timeout after 10s"},
                ],
            }
        )
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        concerns = resp.get_json().get("concerns", [])
        matching = [c for c in concerns if "BIOS audit collection errors" in c.get("title", "")]
        assert matching, f"expected error concern, got: {[c.get('title') for c in concerns]}"
        assert matching[0]["level"] == "warning"
        # Failed fields should be listed in the detail
        detail = matching[0].get("detail", "")
        assert "vbs" in detail and "bios_serial" in detail

    def test_no_concern_when_no_recent_errors(self, client, bios_audit_tmp, mocker):
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json().get("concerns", [])
        assert not any("BIOS audit collection errors" in c.get("title", "") for c in concerns)
