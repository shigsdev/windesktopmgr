"""tests/test_backup.py -- Backup tab (backlog #47, PR-1).

Coverage areas:
  - File History config XML parser (pure function -- happy path, missing
    elements, malformed XML, real fixture sampled from the live machine)
  - load_windows_backup_cache (no file, malformed file, well-formed file)
  - summarize_backup (health rollup across both sections, worst-wins)
  - Flask routes (/api/backup/windows-backups, /api/backup/file-history,
    /api/backup/summary)
  - Dashboard concern wiring (fires on critical/warning, silent on ok)

All tests redirect the module's WINDOWS_BACKUP_CACHE_FILE + the FH config
constants to tmp_path so no real backup state on disk is touched.
"""

from __future__ import annotations

import json

import pytest

import backup

# ── Fixtures ───────────────────────────────────────────────────────


# Sampled and trimmed from the live Config1.xml on the dev box (2026-05-24).
# Real schema, real shape. Keeps tests honest about what we'll actually see.
_REAL_FH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<DataProtectionUserConfig SchemaVersion="1">
  <UserName>higs7</UserName>
  <FriendlyName>Scott Higgins</FriendlyName>
  <PCName>SHIGS78-PC24</PCName>
  <UserId>430e9483-d237-4479-b254-db897ff47121</UserId>
  <Library>
    <LibraryName>*lib1</LibraryName>
    <Folder>C:\\Users\\higs7\\Music</Folder>
  </Library>
  <Library>
    <LibraryName>*lib2</LibraryName>
    <Folder>C:\\Users\\higs7\\OneDrive\\Pictures</Folder>
    <Folder>C:\\Users\\higs7\\iCloudPhotos</Folder>
  </Library>
  <UserFolder>C:\\Users\\higs7\\Documents</UserFolder>
  <UserFolder>C:\\Users\\higs7\\Downloads</UserFolder>
  <LocalCatalogPath1>C:\\catalog1.edb</LocalCatalogPath1>
  <StagingArea>
    <StagingAreaPath>C:\\Users\\higs7\\AppData\\Local\\Microsoft\\Windows\\FileHistory\\Data</StagingAreaPath>
    <StagingAreaMaximumCapacity>4894568980</StagingAreaMaximumCapacity>
    <StagingAreaWarningThreshold>3670926735</StagingAreaWarningThreshold>
  </StagingArea>
  <RetentionPolicies>
    <RetentionPolicyType>NO LIMIT</RetentionPolicyType>
    <MinimumRetentionAge>12</MinimumRetentionAge>
  </RetentionPolicies>
  <DPFrequency>3600</DPFrequency>
  <DPStatus>ENABLED</DPStatus>
  <Target>
    <TargetName>Storage space</TargetName>
    <TargetUrl>E:\\</TargetUrl>
    <TargetDriveType>FIXED</TargetDriveType>
    <TargetBackupStorePath>higs7\\SHIGS78-PC24\\Data</TargetBackupStorePath>
    <TargetWarningThreshold>98</TargetWarningThreshold>
  </Target>
</DataProtectionUserConfig>"""


@pytest.fixture
def backup_tmp(tmp_path, monkeypatch):
    """Redirect every backup-module persistence path to tmp_path so tests
    can't read or write the real machine's cache."""
    cache = tmp_path / "backup_cache.json"
    actions = tmp_path / "backup_actions_history.json"
    fh_config = tmp_path / "Config1.xml"
    fh_catalog = tmp_path / "Catalog1.edb"
    monkeypatch.setattr(backup, "WINDOWS_BACKUP_CACHE_FILE", str(cache))
    monkeypatch.setattr(backup, "BACKUP_ACTIONS_HISTORY_FILE", str(actions))
    monkeypatch.setattr(backup, "_FH_CONFIG_FILE", str(fh_config))
    monkeypatch.setattr(backup, "_FH_CATALOG_FILE", str(fh_catalog))
    return {
        "cache": cache,
        "actions": actions,
        "fh_config": fh_config,
        "fh_catalog": fh_catalog,
        "root": tmp_path,
    }


# ══════════════════════════════════════════════════════════════════════
# File History XML parser
# ══════════════════════════════════════════════════════════════════════


class TestParseFileHistoryConfig:
    """Pure XML parser. Same input → same output."""

    def test_real_schema_parses(self):
        parsed = backup.parse_file_history_config(_REAL_FH_XML)
        assert parsed["ok"] is True
        assert parsed["enabled"] is True
        assert parsed["user_name"] == "higs7"
        assert parsed["friendly_name"] == "Scott Higgins"
        assert parsed["pc_name"] == "SHIGS78-PC24"
        assert parsed["frequency_seconds"] == 3600
        assert parsed["retention_policy"] == "NO LIMIT"
        assert parsed["retention_min_age_months"] == 12
        assert parsed["target"]["url"] == "E:\\"
        assert parsed["target"]["drive_type"] == "FIXED"
        assert parsed["target"]["backup_store_path"] == "higs7\\SHIGS78-PC24\\Data"
        assert parsed["target"]["warning_threshold_percent"] == 98

    def test_libraries_with_multiple_folders(self):
        parsed = backup.parse_file_history_config(_REAL_FH_XML)
        # lib2 has two <Folder> children — both must be captured.
        lib2 = next((lib for lib in parsed["libraries"] if "lib2" in lib["name"]), None)
        assert lib2 is not None
        assert len(lib2["folders"]) == 2
        assert "OneDrive\\Pictures" in lib2["folders"][0]

    def test_user_folders_collected_in_order(self):
        parsed = backup.parse_file_history_config(_REAL_FH_XML)
        assert parsed["user_folders"][0] == "C:\\Users\\higs7\\Documents"
        assert parsed["user_folders"][1] == "C:\\Users\\higs7\\Downloads"

    def test_staging_area_fields(self):
        parsed = backup.parse_file_history_config(_REAL_FH_XML)
        s = parsed["staging_area"]
        assert "FileHistory\\Data" in s["path"]
        assert s["max_capacity_bytes"] == 4894568980
        assert s["warning_threshold_bytes"] == 3670926735

    def test_disabled_status(self):
        xml = _REAL_FH_XML.replace("<DPStatus>ENABLED</DPStatus>", "<DPStatus>DISABLED</DPStatus>")
        parsed = backup.parse_file_history_config(xml)
        assert parsed["enabled"] is False

    def test_malformed_xml_surfaces_parse_error_not_exception(self):
        parsed = backup.parse_file_history_config("<not-valid-xml")
        assert parsed["ok"] is False
        assert parsed["parse_error"]
        # All other fields keep their default empty shape so the UI can
        # still render without conditional None checks.
        assert parsed["libraries"] == []
        assert parsed["user_folders"] == []

    def test_minimal_xml_returns_safe_defaults(self):
        xml = "<DataProtectionUserConfig SchemaVersion='1'></DataProtectionUserConfig>"
        parsed = backup.parse_file_history_config(xml)
        assert parsed["ok"] is True
        assert parsed["enabled"] is False
        assert parsed["frequency_seconds"] is None
        assert parsed["libraries"] == []
        assert parsed["user_folders"] == []
        assert parsed["target"] == {
            "name": "",
            "url": "",
            "drive_type": "",
            "backup_store_path": "",
            "warning_threshold_percent": None,
        }


# ══════════════════════════════════════════════════════════════════════
# _probe_backup_store -- the ACL-aware existence probe (post-2026-05-27 bug fix)
# ══════════════════════════════════════════════════════════════════════


class TestProbeBackupStore:
    """The probe must distinguish three states the old os.path.isdir
    couldn't:
      - exists + readable
      - exists + ACL-restricted (still exists -- don't fire critical)
      - truly missing
    """

    def test_directly_readable_returns_true(self, tmp_path):
        store = tmp_path / "Data"
        store.mkdir()
        exists, reason = backup._probe_backup_store(str(store))
        assert exists is True
        assert "stat ok" in reason

    def test_truly_missing_returns_false(self, tmp_path):
        exists, reason = backup._probe_backup_store(str(tmp_path / "nope"))
        assert exists is False
        assert "missing" in reason or "doesn't exist" in reason

    def test_acl_restricted_falls_back_to_parent_listing(self, tmp_path, mocker):
        # Folder exists on disk; mock isdir(leaf) -> False to simulate
        # ACL-denied stat. Parent scandir still works.
        store = tmp_path / "Data"
        store.mkdir()
        mocker.patch.object(backup.os.path, "isdir", side_effect=lambda p: not str(p).endswith("Data"))
        exists, reason = backup._probe_backup_store(str(store))
        assert exists is True
        assert "parent listing" in reason

    def test_parent_listing_no_leaf_returns_false(self, tmp_path, mocker):
        # Parent exists, scandir works, but leaf isn't there.
        # That's a TRUE missing -- not an ACL issue.
        mocker.patch.object(backup.os.path, "isdir", return_value=False)
        exists, reason = backup._probe_backup_store(str(tmp_path / "Nothere"))
        assert exists is False
        assert "leaf" in reason or "missing" in reason

    def test_parent_permission_denied_returns_none(self, tmp_path, mocker):
        """Critical bug-fix path: never assume missing under PermissionError."""
        mocker.patch.object(backup.os.path, "isdir", return_value=False)
        mocker.patch.object(backup.os, "scandir", side_effect=PermissionError("denied"))
        exists, reason = backup._probe_backup_store(str(tmp_path / "Data"))
        assert exists is None
        assert "elevation" in reason.lower() or "can't determine" in reason.lower()

    def test_parent_not_found_returns_false(self, mocker):
        # Parent itself doesn't exist -> truly missing, not ACL.
        mocker.patch.object(backup.os.path, "isdir", return_value=False)
        mocker.patch.object(backup.os, "scandir", side_effect=FileNotFoundError())
        exists, reason = backup._probe_backup_store(r"X:\nonexistent\Data")
        assert exists is False

    def test_empty_path_returns_none(self):
        exists, reason = backup._probe_backup_store("")
        assert exists is None

    def test_case_insensitive_leaf_match(self, tmp_path, mocker):
        # Configured path says "Data" but on disk it's "DATA". Should still match.
        store = tmp_path / "DATA"
        store.mkdir()
        mocker.patch.object(backup.os.path, "isdir", return_value=False)
        # Probe with the configured (different-case) name.
        exists, reason = backup._probe_backup_store(str(tmp_path / "Data"))
        assert exists is True


# ══════════════════════════════════════════════════════════════════════
# get_file_history_state (live read + health probes)
# ══════════════════════════════════════════════════════════════════════


class TestGetFileHistoryState:
    """Top-level FH state: parses config + probes catalog + target +
    staging, returns a health verdict."""

    def test_no_config_returns_not_configured(self, backup_tmp):
        state = backup.get_file_history_state()
        assert state["configured"] is False
        assert state["health"]["level"] == "info"
        assert "not configured" in state["health"]["reason"].lower()

    def test_critical_when_target_path_missing(self, backup_tmp, tmp_path):
        # Real-world failure mode caught against the live machine on
        # 2026-05-24: FH is enabled, target drive E:\ exists, but the
        # backup-store subfolder is missing -- so File History thinks
        # it's backing up but isn't.
        xml = _REAL_FH_XML.replace(
            "<TargetUrl>E:\\</TargetUrl>",
            f"<TargetUrl>{tmp_path / 'no-such-drive'}\\</TargetUrl>",
        )
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        state = backup.get_file_history_state()
        assert state["health"]["level"] == "critical"
        assert "not accessible" in state["health"]["reason"].lower()
        assert state["target_path_exists"] is False

    def test_critical_when_target_present_but_backup_store_missing(self, backup_tmp, tmp_path):
        # Target drive exists; backup_store_path subfolder does not. This
        # is THE silent-failure pattern we want the dashboard to catch.
        drive = tmp_path / "drive"
        drive.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        state = backup.get_file_history_state()
        assert state["health"]["level"] == "critical"
        assert "missing" in state["health"]["reason"].lower()
        assert state["target_path_exists"] is True
        assert state["target_backup_store_exists"] is False

    def test_disabled_status_short_circuits_health(self, backup_tmp, tmp_path):
        # Even with a broken target path, if DPStatus=DISABLED, health is
        # info (user has explicitly turned it off — not a critical signal).
        drive = tmp_path / "drive"
        drive.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        xml = xml.replace("<DPStatus>ENABLED</DPStatus>", "<DPStatus>DISABLED</DPStatus>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        state = backup.get_file_history_state()
        assert state["health"]["level"] == "info"
        assert "disabled" in state["health"]["reason"].lower()

    def test_acl_restricted_store_is_info_not_critical(self, backup_tmp, tmp_path, mocker):
        """User report 2026-05-27: the live tray showed Backup health as
        CRITICAL with "backup store folder ... is missing -- backups are
        NOT being saved" against E:\\higs7\\SHIGS78-PC24\\Data, but the
        folder DID exist -- it was just ACL-restricted so the unelevated
        os.path.isdir returned False. Regression test: when isdir says
        False but the parent listing shows the leaf name, treat as info
        (acl-restricted) NOT critical (truly missing).
        """
        drive = tmp_path / "drive"
        store_parent = drive / "higs7" / "SHIGS78-PC24"
        store_parent.mkdir(parents=True)
        # Create the leaf folder but make os.path.isdir return False so
        # we simulate the ACL-denied stat -- the parent listing still
        # shows it, which is the user's actual scenario.
        leaf = store_parent / "Data"
        leaf.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        # Force isdir to return False for the store path only -- mimics
        # the ACL denial. The parent scan still works (real folder on disk).
        original_isdir = backup.os.path.isdir

        def isdir_patched(path):
            if str(path).endswith("Data"):
                return False
            return original_isdir(path)

        mocker.patch.object(backup.os.path, "isdir", side_effect=isdir_patched)
        state = backup.get_file_history_state()
        # Folder was found via parent listing -> True
        assert state["target_backup_store_exists"] is True, (
            f"parent listing should rescue ACL-restricted leaf; got {state}"
        )
        # And since exists=True, health should NOT be critical.
        assert state["health"]["level"] != "critical"

    def test_inaccessible_parent_is_indeterminate_info_not_critical(self, backup_tmp, tmp_path, mocker):
        """When even the parent directory raises PermissionError on scandir,
        we cannot determine missing vs ACL-denied. Must fall back to info
        (NOT critical) -- never assume missing under permission denial."""
        drive = tmp_path / "drive"
        drive.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        # isdir always returns False AND scandir raises PermissionError.
        mocker.patch.object(
            backup.os.path, "isdir", side_effect=lambda p: str(p).endswith("\\") or str(p).endswith("drive")
        )
        mocker.patch.object(backup.os, "scandir", side_effect=PermissionError("denied"))
        state = backup.get_file_history_state()
        assert state["target_backup_store_exists"] is None
        assert state["health"]["level"] == "info"
        assert "need elevation" in state["health"]["reason"].lower()

    def test_fresh_catalog_demotes_missing_store_to_info(self, backup_tmp, tmp_path):
        """Cross-check guard 2026-05-27: even when the store probe says
        missing, a fresh catalog mtime proves File History IS writing.
        Demote critical -> info so the user doesn't see a panic message
        against a working backup. The user's exact failure: catalog age
        was 0.04 days but the store probe falsely fired critical."""
        drive = tmp_path / "drive"
        drive.mkdir()
        # NOTE: do NOT create the store folder -- probe will return False.
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        # Create a FRESH catalog (just-now mtime) so backups are clearly
        # happening.
        backup_tmp["fh_catalog"].write_bytes(b"x" * 1024)
        state = backup.get_file_history_state()
        # Probe still says False -- we didn't make the folder.
        assert state["target_backup_store_exists"] is False
        # But health is info, NOT critical, because catalog is fresh.
        assert state["health"]["level"] == "info", (
            f"fresh catalog should demote store-missing to info; got {state['health']}"
        )
        assert "backups are running" in state["health"]["reason"].lower()

    def test_missing_store_with_stale_catalog_still_critical(self, backup_tmp, tmp_path):
        """Inverse of the above: when BOTH signals agree (store probe
        says missing AND catalog is stale or absent), fire critical.
        The original PR #50 use-case must still work."""
        drive = tmp_path / "drive"
        drive.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        # No catalog file at all -- catalog_age_days is None -> firing
        # critical preserved.
        state = backup.get_file_history_state()
        assert state["target_backup_store_exists"] is False
        assert state["health"]["level"] == "critical"
        assert "missing" in state["health"]["reason"].lower()

    def test_healthy_when_target_and_store_exist(self, backup_tmp, tmp_path):
        drive = tmp_path / "drive"
        store = drive / "higs7" / "SHIGS78-PC24" / "Data"
        store.mkdir(parents=True)
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        state = backup.get_file_history_state()
        assert state["health"]["level"] == "ok"
        assert state["target_path_exists"] is True
        assert state["target_backup_store_exists"] is True

    def test_catalog_age_days_reported(self, backup_tmp, tmp_path):
        drive = tmp_path / "drive"
        store = drive / "higs7" / "SHIGS78-PC24" / "Data"
        store.mkdir(parents=True)
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        # Create a catalog file with mtime in the past.
        backup_tmp["fh_catalog"].write_bytes(b"x" * 1024)
        import os
        import time

        # 10 days ago
        old_mtime = time.time() - (10 * 86400)
        os.utime(backup_tmp["fh_catalog"], (old_mtime, old_mtime))
        state = backup.get_file_history_state()
        # Stale catalog -> warning
        assert state["catalog_exists"] is True
        assert 9.5 < state["catalog_age_days"] < 10.5
        assert state["health"]["level"] == "warning"
        assert "stalled" in state["health"]["reason"].lower() or "stale" in state["health"]["reason"].lower()


# ══════════════════════════════════════════════════════════════════════
# load_windows_backup_cache
# ══════════════════════════════════════════════════════════════════════


class TestLoadWindowsBackupCache:
    def test_no_cache_returns_placeholder(self, backup_tmp):
        cache = backup.load_windows_backup_cache()
        assert cache["ok"] is True
        assert cache["has_cache"] is False
        assert cache["version_count"] == 0
        assert cache["versions"] == []
        assert cache["error"] is None

    def test_malformed_cache_returns_error(self, backup_tmp):
        backup_tmp["cache"].write_text("not-valid-json", encoding="utf-8")
        cache = backup.load_windows_backup_cache()
        assert cache["ok"] is False
        assert cache["error"]

    def test_well_formed_cache_returns_versions(self, backup_tmp):
        payload = {
            "scanned_at": "2026-05-24T20:00:00",
            "versions": [
                {
                    "version_id": "05/24/2026-04:00",
                    "backup_time": "5/24/2026 4:00 AM",
                    "target": "1394/USB Disk(E:)",
                    "can_recover": ["Volume", "File"],
                    "size_bytes": 12_345_678_901,
                },
            ],
            "total_size_bytes": 12_345_678_901,
        }
        backup_tmp["cache"].write_text(json.dumps(payload), encoding="utf-8")
        cache = backup.load_windows_backup_cache()
        assert cache["has_cache"] is True
        assert cache["version_count"] == 1
        assert cache["versions"][0]["size_bytes"] == 12_345_678_901
        assert cache["total_size_bytes"] == 12_345_678_901
        assert cache["scanned_at"] == "2026-05-24T20:00:00"
        # cache_age_seconds is computed from scanned_at; must be non-negative
        assert cache["cache_age_seconds"] is not None
        assert cache["cache_age_seconds"] >= 0

    def test_cache_with_unparseable_scanned_at_still_returns_versions(self, backup_tmp):
        # If scanned_at is garbage, we drop cache_age_seconds to None but
        # the versions list still flows through to the UI.
        payload = {"scanned_at": "not-an-iso", "versions": [{"version_id": "X"}], "total_size_bytes": 0}
        backup_tmp["cache"].write_text(json.dumps(payload), encoding="utf-8")
        cache = backup.load_windows_backup_cache()
        assert cache["has_cache"] is True
        assert cache["version_count"] == 1
        assert cache["cache_age_seconds"] is None

    def test_cache_must_be_a_dict_at_top_level(self, backup_tmp):
        # A JSON array at top level is "valid JSON" but the wrong shape.
        backup_tmp["cache"].write_text("[1,2,3]", encoding="utf-8")
        cache = backup.load_windows_backup_cache()
        assert cache["ok"] is False
        assert "not a dict" in cache["error"].lower()


# ══════════════════════════════════════════════════════════════════════
# summarize_backup
# ══════════════════════════════════════════════════════════════════════


class TestSummarizeBackup:
    def test_no_data_summary_is_info(self, backup_tmp):
        s = backup.summarize_backup()
        assert s["ok"] is True
        assert s["windows_backups"]["has_cache"] is False
        assert s["file_history"]["configured"] is False
        # No data → overall = info / "not configured"
        assert s["overall_health"]["level"] == "info"

    def test_worst_wins_when_fh_critical(self, backup_tmp, tmp_path):
        # FH critical, no WindowsImageBackup cache → overall = critical.
        xml = _REAL_FH_XML.replace(
            "<TargetUrl>E:\\</TargetUrl>",
            f"<TargetUrl>{tmp_path / 'no-such'}\\</TargetUrl>",
        )
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        s = backup.summarize_backup()
        assert s["overall_health"]["level"] == "critical"

    def test_warning_dominates_info(self, backup_tmp):
        # Manufactured WindowsImageBackup cache with zero versions (=warning),
        # no FH config (=info) -> overall = warning.
        backup_tmp["cache"].write_text(
            json.dumps({"scanned_at": "2026-05-24T20:00:00", "versions": [], "total_size_bytes": 0}),
            encoding="utf-8",
        )
        s = backup.summarize_backup()
        assert s["overall_health"]["level"] == "warning"

    def test_watched_folder_count_aggregates_libraries_and_user_folders(self, backup_tmp, tmp_path):
        drive = tmp_path / "drive"
        store = drive / "higs7" / "SHIGS78-PC24" / "Data"
        store.mkdir(parents=True)
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        s = backup.summarize_backup()
        # 1 folder in lib1, 2 in lib2, 2 user folders -> 5 total.
        assert s["file_history"]["watched_folders"] == 5


# ══════════════════════════════════════════════════════════════════════
# Flask routes
# ══════════════════════════════════════════════════════════════════════


class TestBackupRoutes:
    def test_windows_backups_no_cache(self, client, backup_tmp):
        resp = client.get("/api/backup/windows-backups")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["has_cache"] is False

    def test_windows_backups_with_cache(self, client, backup_tmp):
        backup_tmp["cache"].write_text(
            json.dumps({"scanned_at": "2026-05-24T20:00:00", "versions": [{"version_id": "v1"}]}),
            encoding="utf-8",
        )
        resp = client.get("/api/backup/windows-backups")
        assert resp.status_code == 200
        assert resp.get_json()["version_count"] == 1

    def test_file_history_no_config(self, client, backup_tmp):
        resp = client.get("/api/backup/file-history")
        assert resp.status_code == 200
        assert resp.get_json()["configured"] is False

    def test_file_history_real_config(self, client, backup_tmp):
        backup_tmp["fh_config"].write_text(_REAL_FH_XML, encoding="utf-8")
        resp = client.get("/api/backup/file-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["configured"] is True
        assert data["config"]["pc_name"] == "SHIGS78-PC24"

    def test_summary_route(self, client, backup_tmp):
        resp = client.get("/api/backup/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "windows_backups" in data
        assert "file_history" in data
        assert "overall_health" in data


# ══════════════════════════════════════════════════════════════════════
# Dashboard concern wiring
# ══════════════════════════════════════════════════════════════════════


class TestBackupDashboardConcern:
    """When summarize_backup() returns warning/critical, the dashboard
    summary must include a 'Backup health' concern that deep-links to
    the new backup tab."""

    def _mock_collectors(self, mocker):
        import windesktopmgr as wdm

        mocker.patch.object(wdm, "get_driver_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch.object(wdm, "get_disk_health", return_value={"ok": True})
        mocker.patch.object(wdm, "get_thermals", return_value={"temps": [], "perf": {"CPUPct": 0}, "fans": []})
        mocker.patch.object(wdm, "get_memory_analysis", return_value={"used_mb": 1, "total_mb": 2})
        mocker.patch.object(wdm, "get_credentials_network_health", return_value={})

    def test_critical_concern_fires_on_broken_file_history(self, client, backup_tmp, tmp_path, mocker):
        # FH enabled + target drive present + backup store MISSING -> critical
        drive = tmp_path / "drive"
        drive.mkdir()
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json().get("concerns", [])
        matching = [c for c in concerns if "backup health" in c.get("title", "").lower()]
        assert matching, f"no backup-health concern emitted; got: {[c.get('title') for c in concerns]}"
        assert matching[0]["level"] == "critical"
        assert matching[0]["tab"] == "backup"
        assert "switchTab('backup')" in matching[0]["action_fn"]

    def test_no_concern_when_healthy(self, client, backup_tmp, tmp_path, mocker):
        # FH enabled + target + store both present + populated cache -> info only
        drive = tmp_path / "drive"
        store = drive / "higs7" / "SHIGS78-PC24" / "Data"
        store.mkdir(parents=True)
        xml = _REAL_FH_XML.replace("<TargetUrl>E:\\</TargetUrl>", f"<TargetUrl>{drive}\\</TargetUrl>")
        backup_tmp["fh_config"].write_text(xml, encoding="utf-8")
        backup_tmp["cache"].write_text(
            json.dumps(
                {
                    "scanned_at": "2026-05-24T20:00:00",
                    "versions": [{"version_id": "v1", "target": "E:", "backup_time": "..."}],
                    "total_size_bytes": 1024,
                }
            ),
            encoding="utf-8",
        )
        self._mock_collectors(mocker)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json().get("concerns", [])
        assert not any("backup health" in c.get("title", "").lower() for c in concerns)


# ══════════════════════════════════════════════════════════════════════
# PR-2: wbadmin output parser
# ══════════════════════════════════════════════════════════════════════


# Real-shape sample of `wbadmin get versions` output. Captured against
# the documented format -- "Version identifier" / "Backup time" /
# "Backup target" / "Can recover" / "Snapshot ID" keys.
_REAL_WBADMIN_OUTPUT = """
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 5/24/2026 4:00 AM
Backup target: 1394/USB Disk labeled WD Passport(E:)
Version identifier: 05/24/2026-04:00
Can recover: Volume(s), File(s), Application(s), Bare Metal Recovery, System State
Snapshot ID: {12345678-1234-1234-1234-123456789012}

Backup time: 5/23/2026 4:00 AM
Backup target: 1394/USB Disk labeled WD Passport(E:)
Version identifier: 05/23/2026-04:00
Can recover: Volume(s), File(s), Application(s)
Snapshot ID: {abcdef01-2345-6789-abcd-ef0123456789}

Backup time: 5/22/2026 4:00 AM
Backup target: 1394/USB Disk labeled WD Passport(E:)
Version identifier: 05/22/2026-04:00
Can recover: Volume(s), File(s)
""".strip()


class TestParseWbadminVersions:
    """Pure parser for the multi-block ``wbadmin get versions`` output."""

    def test_real_shape_parses_three_versions(self):
        result = backup.parse_wbadmin_versions(_REAL_WBADMIN_OUTPUT)
        assert len(result) == 3
        # Newest first as in the wbadmin output.
        assert result[0]["version_id"] == "05/24/2026-04:00"
        assert result[1]["version_id"] == "05/23/2026-04:00"
        assert result[2]["version_id"] == "05/22/2026-04:00"

    def test_backup_time_field_preserved(self):
        result = backup.parse_wbadmin_versions(_REAL_WBADMIN_OUTPUT)
        assert result[0]["backup_time"] == "5/24/2026 4:00 AM"

    def test_can_recover_splits_on_comma(self):
        result = backup.parse_wbadmin_versions(_REAL_WBADMIN_OUTPUT)
        capabilities = result[0]["can_recover"]
        assert "Volume(s)" in capabilities
        assert "File(s)" in capabilities
        assert "Bare Metal Recovery" in capabilities
        assert "System State" in capabilities

    def test_target_field_preserved(self):
        result = backup.parse_wbadmin_versions(_REAL_WBADMIN_OUTPUT)
        assert "WD Passport(E:)" in result[0]["target"]

    def test_size_bytes_left_for_helper_to_populate(self):
        # Parser doesn't probe disk -- size_bytes is None and the
        # elevated helper fills it in.
        result = backup.parse_wbadmin_versions(_REAL_WBADMIN_OUTPUT)
        for v in result:
            assert v["size_bytes"] is None

    def test_empty_input_returns_empty_list(self):
        assert backup.parse_wbadmin_versions("") == []
        assert backup.parse_wbadmin_versions(None) == []

    def test_preamble_only_returns_empty(self):
        # wbadmin's first two lines are always the banner + copyright.
        # If a future wbadmin reports zero versions, that's all we'd see.
        preamble = "wbadmin 1.0 - Backup command-line tool\n(C) Copyright Microsoft.\n\n"
        assert backup.parse_wbadmin_versions(preamble) == []

    def test_block_without_version_identifier_dropped(self):
        # A partial block missing the version_id key would yield an
        # entry with empty version_id; we skip those entirely.
        partial = "Backup time: 5/24/2026 4:00 AM\nBackup target: Foo\n"
        assert backup.parse_wbadmin_versions(partial) == []

    def test_unknown_keys_silently_ignored(self):
        # Future wbadmin may add new key names. We mustn't crash on them.
        with_extra = (
            "Backup time: 5/24/2026 4:00 AM\nNew future field: some value\nVersion identifier: 05/24/2026-04:00\n"
        )
        result = backup.parse_wbadmin_versions(with_extra)
        assert len(result) == 1
        assert result[0]["version_id"] == "05/24/2026-04:00"

    def test_no_trailing_blank_line_still_flushes(self):
        text = "Backup time: 5/24/2026 4:00 AM\nVersion identifier: V1"
        result = backup.parse_wbadmin_versions(text)
        assert len(result) == 1
        assert result[0]["version_id"] == "V1"


# ══════════════════════════════════════════════════════════════════════
# PR-2: Safety validators (pure)
# ══════════════════════════════════════════════════════════════════════


class TestValidateDeleteVersionRequest:
    _CATALOG = [
        {"version_id": "05/24/2026-04:00"},  # newest, protected
        {"version_id": "05/23/2026-04:00"},
        {"version_id": "05/22/2026-04:00"},  # oldest, deletable
    ]

    def test_empty_version_id_refused(self):
        ok, err = backup.validate_delete_version_request("", self._CATALOG)
        assert not ok
        assert "non-empty" in err

    def test_non_string_refused(self):
        ok, err = backup.validate_delete_version_request(123, self._CATALOG)
        assert not ok

    def test_empty_catalog_refused(self):
        ok, err = backup.validate_delete_version_request("any", [])
        assert not ok
        assert "empty" in err.lower()

    def test_not_in_catalog_refused(self):
        ok, err = backup.validate_delete_version_request("01/01/1999", self._CATALOG)
        assert not ok
        assert "not found" in err.lower()

    def test_most_recent_protected(self):
        ok, err = backup.validate_delete_version_request("05/24/2026-04:00", self._CATALOG)
        assert not ok
        assert "most-recent" in err.lower()

    def test_only_remaining_version_protected(self):
        only_one = [{"version_id": "X"}]
        ok, err = backup.validate_delete_version_request("X", only_one)
        assert not ok
        assert "only remaining" in err.lower()

    def test_older_version_passes(self):
        ok, err = backup.validate_delete_version_request("05/22/2026-04:00", self._CATALOG)
        assert ok
        assert err == ""


class TestValidateFhCleanupRequest:
    def test_zero_days_ok(self):
        ok, err = backup.validate_fh_cleanup_request(0)
        assert ok

    def test_one_year_ok(self):
        ok, err = backup.validate_fh_cleanup_request(365)
        assert ok

    def test_negative_refused(self):
        ok, err = backup.validate_fh_cleanup_request(-1)
        assert not ok

    def test_too_large_refused(self):
        ok, err = backup.validate_fh_cleanup_request(3651)
        assert not ok

    def test_bool_refused(self):
        # Python treats True/False as int subclasses; explicit guard.
        ok, err = backup.validate_fh_cleanup_request(True)
        assert not ok

    def test_string_refused(self):
        ok, err = backup.validate_fh_cleanup_request("90")
        assert not ok


# ══════════════════════════════════════════════════════════════════════
# PR-2: Actions history persistence
# ══════════════════════════════════════════════════════════════════════


class TestActionsHistory:
    def test_empty_history_returns_empty_list(self, backup_tmp):
        assert backup.load_actions_history() == []

    def test_append_and_read_roundtrip(self, backup_tmp):
        backup.append_action_history(
            {
                "session_id": "abc123",
                "action": "scan_catalog",
                "started_at": "2026-05-24T22:00:00",
                "ended_at": "2026-05-24T22:00:30",
                "status": "completed",
            }
        )
        history = backup.load_actions_history()
        assert len(history) == 1
        assert history[0]["session_id"] == "abc123"

    def test_newest_first_ordering(self, backup_tmp):
        for ts in ("2026-05-24T22:00:00", "2026-05-24T22:01:00", "2026-05-24T22:02:00"):
            backup.append_action_history({"session_id": ts, "started_at": ts})
        history = backup.load_actions_history()
        # Sorted by started_at descending.
        assert [h["session_id"] for h in history] == [
            "2026-05-24T22:02:00",
            "2026-05-24T22:01:00",
            "2026-05-24T22:00:00",
        ]

    def test_cap_at_max_entries(self, backup_tmp):
        for i in range(250):
            backup.append_action_history({"session_id": f"s{i}", "started_at": f"2026-05-24T22:{i % 60:02d}:00"})
        history = backup.load_actions_history()
        # Default cap is 200.
        assert len(history) == 200

    def test_malformed_history_returns_empty(self, backup_tmp):
        backup_tmp["actions"].write_text("not-valid-json", encoding="utf-8")
        assert backup.load_actions_history() == []

    def test_history_must_be_list_at_top(self, backup_tmp):
        backup_tmp["actions"].write_text('{"not": "a list"}', encoding="utf-8")
        assert backup.load_actions_history() == []


# ══════════════════════════════════════════════════════════════════════
# PR-2: get_scan_status (result-file reader)
# ══════════════════════════════════════════════════════════════════════


class TestGetScanStatus:
    def test_no_result_file_returns_pending(self, backup_tmp):
        result = backup.get_scan_status("abc123def456")
        assert result["state"] == "pending"

    def test_done_returns_result_payload(self, backup_tmp, tmp_path, monkeypatch):
        # Write a result file at the path get_scan_status will look.
        from pathlib import Path

        session = "deadbeefcafe"
        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        result_path = Path(tmp_path) / f"backup_result_{session}.json"
        result_path.write_text(
            json.dumps({"ok": True, "version_count": 3, "session_id": session}),
            encoding="utf-8",
        )
        result = backup.get_scan_status(session)
        assert result["state"] == "done"
        assert result["result"]["version_count"] == 3

    def test_malformed_result_file_returns_missing(self, backup_tmp, tmp_path, monkeypatch):
        from pathlib import Path

        session = "zzz999"
        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        (Path(tmp_path) / f"backup_result_{session}.json").write_text("garbage", encoding="utf-8")
        result = backup.get_scan_status(session)
        assert result["state"] == "missing"

    def test_path_traversal_session_id_refused(self, backup_tmp):
        # Defense in depth: a session_id with a slash would let a
        # crafted query string read arbitrary files. Refuse cleanly.
        for bad in ("../../../etc/passwd", "..\\..\\windows\\system32", "x/y"):
            result = backup.get_scan_status(bad)
            assert result["state"] == "missing"

    def test_empty_session_id_refused(self, backup_tmp):
        assert backup.get_scan_status("")["state"] == "missing"


# ══════════════════════════════════════════════════════════════════════
# PR-2: request_elevated_action (ShellExecuteW launch path)
# ══════════════════════════════════════════════════════════════════════


class TestRequestElevatedAction:
    """The actual ShellExecuteW call is patched -- we don't want UAC
    prompts firing during pytest. The tests verify the request-file
    contract + return shape."""

    def test_unknown_action_refused_before_launch(self, backup_tmp):
        result = backup.request_elevated_action("nuke_everything", {})
        assert not result["ok"]
        assert "unknown action" in result["error"].lower()

    def test_helper_missing_returns_error(self, backup_tmp, tmp_path, monkeypatch):
        # Point APP_DIR at tmp so the helper script genuinely doesn't exist.
        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        result = backup.request_elevated_action("scan_catalog", {})
        assert not result["ok"]
        assert "not found" in result["error"]

    def test_successful_launch_writes_request_file(self, backup_tmp, tmp_path, monkeypatch):
        from pathlib import Path

        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        # Pretend the helper script exists.
        helper_dir = Path(tmp_path) / "scripts"
        helper_dir.mkdir()
        helper = helper_dir / "backup_helper_elevated.py"
        helper.write_text("# stub", encoding="utf-8")

        # Patch the ctypes shell32 call to fake a successful launch (rc>32).
        class _FakeShell32:
            def ShellExecuteW(self, *args):  # noqa: N802 -- match Win32 name
                return 42  # >32 = success

        class _FakeWindll:
            shell32 = _FakeShell32()

        import ctypes

        monkeypatch.setattr(ctypes, "windll", _FakeWindll(), raising=False)

        result = backup.request_elevated_action("scan_catalog", {"foo": "bar"})
        assert result["ok"] is True
        assert result["session_id"]
        # Request file written under the patched APP_DIR.
        req = list(Path(tmp_path).glob("backup_request_*.json"))
        assert len(req) == 1
        with open(req[0]) as f:
            payload = json.load(f)
        assert payload["action"] == "scan_catalog"
        assert payload["params"] == {"foo": "bar"}
        assert payload["session_id"] == result["session_id"]

    def test_uac_denied_returns_error_and_cleans_request(self, backup_tmp, tmp_path, monkeypatch):
        from pathlib import Path

        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        helper_dir = Path(tmp_path) / "scripts"
        helper_dir.mkdir()
        (helper_dir / "backup_helper_elevated.py").write_text("# stub", encoding="utf-8")

        # rc=5 = ACCESS_DENIED (user clicked No on UAC).
        class _FakeShell32:
            def ShellExecuteW(self, *args):  # noqa: N802
                return 5

        class _FakeWindll:
            shell32 = _FakeShell32()

        import ctypes

        monkeypatch.setattr(ctypes, "windll", _FakeWindll(), raising=False)

        result = backup.request_elevated_action("scan_catalog", {})
        assert not result["ok"]
        assert "rc=5" in result["error"]
        # The orphaned request file should have been cleaned up.
        leftover = list(Path(tmp_path).glob("backup_request_*.json"))
        assert leftover == []


# ══════════════════════════════════════════════════════════════════════
# PR-2: New Flask routes (scan / scan-status / delete-version / fh-cleanup / actions-history)
# ══════════════════════════════════════════════════════════════════════


class TestBackupActionRoutes:
    def test_scan_status_requires_session_id(self, client, backup_tmp):
        resp = client.get("/api/backup/scan-status")
        assert resp.status_code == 400

    def test_scan_status_pending_for_unknown_session(self, client, backup_tmp):
        resp = client.get("/api/backup/scan-status?session_id=abc123")
        assert resp.status_code == 200
        assert resp.get_json()["state"] == "pending"

    def test_scan_status_done_after_result_landed(self, client, backup_tmp, tmp_path, monkeypatch):
        from pathlib import Path

        session = "fakesession01"
        monkeypatch.setattr(backup, "APP_DIR", str(tmp_path))
        (Path(tmp_path) / f"backup_result_{session}.json").write_text(
            json.dumps({"ok": True, "version_count": 5}), encoding="utf-8"
        )
        resp = client.get(f"/api/backup/scan-status?session_id={session}")
        data = resp.get_json()
        assert data["state"] == "done"
        assert data["result"]["version_count"] == 5

    def test_scan_route_refuses_when_helper_missing(self, client, backup_tmp, mocker):
        # Force the launcher to report helper-missing without actually
        # invoking ctypes.
        mocker.patch.object(backup, "request_elevated_action", return_value={"ok": False, "error": "helper not found"})
        resp = client.post("/api/backup/scan", json={})
        assert resp.status_code == 502
        assert "helper not found" in resp.get_json()["error"]

    def test_scan_route_returns_session_id_on_launch(self, client, backup_tmp, mocker):
        mocker.patch.object(backup, "request_elevated_action", return_value={"ok": True, "session_id": "xyz789"})
        resp = client.post("/api/backup/scan", json={})
        assert resp.status_code == 200
        assert resp.get_json()["session_id"] == "xyz789"

    def test_delete_version_requires_confirm_token_match(self, client, backup_tmp):
        resp = client.post(
            "/api/backup/delete-version",
            json={"version_id": "05/24/2026-04:00", "confirm_token": "wrong"},
        )
        assert resp.status_code == 400
        assert "confirm_token" in resp.get_json()["error"]

    def test_delete_version_requires_version_id(self, client, backup_tmp):
        resp = client.post("/api/backup/delete-version", json={})
        assert resp.status_code == 400

    def test_delete_version_validates_against_cache(self, client, backup_tmp):
        # No cache present -> validator catches it (catalog empty).
        resp = client.post(
            "/api/backup/delete-version",
            json={"version_id": "missing-id", "confirm_token": "missing-id"},
        )
        assert resp.status_code == 400
        assert "catalog is empty" in resp.get_json()["error"].lower() or "not found" in resp.get_json()["error"].lower()

    def test_delete_version_refuses_most_recent(self, client, backup_tmp):
        backup_tmp["cache"].write_text(
            json.dumps(
                {
                    "scanned_at": "2026-05-24T20:00:00",
                    "versions": [
                        {"version_id": "newest"},
                        {"version_id": "older"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        resp = client.post(
            "/api/backup/delete-version",
            json={"version_id": "newest", "confirm_token": "newest"},
        )
        assert resp.status_code == 400
        assert "most-recent" in resp.get_json()["error"].lower()

    def test_delete_version_older_proceeds_to_launch(self, client, backup_tmp, mocker):
        backup_tmp["cache"].write_text(
            json.dumps(
                {
                    "scanned_at": "2026-05-24T20:00:00",
                    "versions": [
                        {"version_id": "newest"},
                        {"version_id": "older"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        mocker.patch.object(backup, "request_elevated_action", return_value={"ok": True, "session_id": "abc"})
        resp = client.post(
            "/api/backup/delete-version",
            json={"version_id": "older", "confirm_token": "older"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["session_id"] == "abc"

    def test_fh_cleanup_requires_correct_confirm_token(self, client, backup_tmp):
        resp = client.post(
            "/api/backup/file-history-cleanup",
            json={"days": 90, "confirm_token": "wrong format"},
        )
        assert resp.status_code == 400
        assert "CLEANUP 90" in resp.get_json()["error"]

    def test_fh_cleanup_rejects_non_int_days(self, client, backup_tmp):
        resp = client.post(
            "/api/backup/file-history-cleanup",
            json={"days": "ninety", "confirm_token": "CLEANUP ninety"},
        )
        assert resp.status_code == 400

    def test_fh_cleanup_rejects_out_of_range(self, client, backup_tmp):
        resp = client.post(
            "/api/backup/file-history-cleanup",
            json={"days": 99999, "confirm_token": "CLEANUP 99999"},
        )
        assert resp.status_code == 400

    def test_fh_cleanup_valid_proceeds_to_launch(self, client, backup_tmp, mocker):
        mocker.patch.object(backup, "request_elevated_action", return_value={"ok": True, "session_id": "fh1"})
        resp = client.post(
            "/api/backup/file-history-cleanup",
            json={"days": 365, "confirm_token": "CLEANUP 365"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["session_id"] == "fh1"

    def test_actions_history_empty(self, client, backup_tmp):
        resp = client.get("/api/backup/actions-history")
        assert resp.status_code == 200
        assert resp.get_json()["entries"] == []

    def test_actions_history_returns_entries(self, client, backup_tmp):
        backup.append_action_history(
            {"session_id": "s1", "action": "scan_catalog", "started_at": "2026-05-24T22:00:00"}
        )
        resp = client.get("/api/backup/actions-history")
        data = resp.get_json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["session_id"] == "s1"

    def test_scan_cleanup_requires_session_id(self, client, backup_tmp):
        resp = client.post("/api/backup/scan-cleanup", json={})
        assert resp.status_code == 400

    def test_scan_cleanup_returns_ok(self, client, backup_tmp):
        resp = client.post("/api/backup/scan-cleanup", json={"session_id": "abc"})
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
