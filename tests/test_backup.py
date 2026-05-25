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
