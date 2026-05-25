"""backup.py -- Unified backup visibility for WinDesktopMgr (backlog #47).

Surfaces what Windows already backs up + lets the user clean it up:

  Section 1: WindowsImageBackup (Windows Server Backup / Windows 7-era)
             -- Reads from a JSON cache populated by an elevated helper
                (PR-2). User-context reads of E:\\WindowsImageBackup\\ are
                blocked (folder ACL denies non-Administrators), and
                ``wbadmin get versions`` also requires elevation just to
                list the catalog. So the only viable read path from the
                unelevated tray is "cached parse" + an explicit "Scan"
                button that triggers a UAC prompt and re-populates the
                cache. PR-1 ships the cache-reader; PR-2 ships the
                elevated scanner + cleanup actions.

  Section 2: File History (Windows 8+ per-file rolling backup)
             -- Config XML lives under the user's own profile at
                %LOCALAPPDATA%\\Microsoft\\Windows\\FileHistory\\
                Configuration\\Config1.xml and reads cleanly from
                user context -- no elevation needed.  We also probe
                the target drive + the staging area for freshness +
                health signals (catalog file mtime, target path
                exists, etc.). The biggest "real" failure mode is
                File History thinks it's enabled and writing to drive
                E:\\, but the target backup-store folder on E:\\ is
                missing -- which means File History is silently NOT
                actually backing anything up.

  Section 3: OneDrive -> iCloud replicator (#46) -- separate module
             (#46), not implemented in PR-1 of #47.

  Section 4: Custom backup solution (#11) -- separate (#11), future.

Design mirrors ``baseline.py``: pure parsers, atomic JSON cache,
defensive against malformed XML / missing files / stale targets.

Public API:
    load_windows_backup_cache()    -- read backup_cache.json (PR-2 fills it)
    get_file_history_state()       -- live read of FH config + health probes
    summarize_backup()              -- combined health summary for dashboard
"""

from __future__ import annotations

import json
import os
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

try:
    from applogging import get_logger

    _log = get_logger("backup")
except Exception:  # noqa: BLE001
    import logging

    _log = logging.getLogger("windesktopmgr.backup")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
# Cache populated by the elevated helper (PR-2). PR-1 only reads it.
WINDOWS_BACKUP_CACHE_FILE = os.path.join(APP_DIR, "backup_cache.json")
# Append-only log of cleanup / delete actions (PR-2 writes to it).
BACKUP_ACTIONS_HISTORY_FILE = os.path.join(APP_DIR, "backup_actions_history.json")

# File History config + catalog live under the per-user profile and are
# readable without elevation. The schema has been stable since Windows 8
# (this code was developed against the live Config1.xml on Windows 11 24H2).
_FH_CONFIG_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "Microsoft",
    "Windows",
    "FileHistory",
    "Configuration",
)
_FH_CONFIG_FILE = os.path.join(_FH_CONFIG_DIR, "Config1.xml")
_FH_CATALOG_FILE = os.path.join(_FH_CONFIG_DIR, "Catalog1.edb")

# Health-check thresholds. Catalog stale = no FH activity in days; staging
# warn = bytes-used / capacity above this.
_FH_CATALOG_STALE_DAYS = 7
_FH_STAGING_WARN_RATIO = 0.95

_file_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════
# Section 1: WindowsImageBackup (CACHE READER ONLY in PR-1)
# ══════════════════════════════════════════════════════════════════════


def load_windows_backup_cache() -> dict:
    """Return the cached WindowsImageBackup catalog, or a 'not yet scanned'
    placeholder shape.

    The cache is populated by an elevated helper (PR-2). PR-1 just reads
    it. The placeholder shape lets the UI render a clean "Click Scan to
    populate" state without conditional NoneType handling everywhere.

    Returned shape (always):
        {
          "ok": True,
          "has_cache": bool,
          "scanned_at": "<iso>" | None,
          "cache_age_seconds": int | None,
          "versions": [
            {"version_id": "...", "backup_time": "...",
             "target": "1394/USB Disk(E:)",
             "can_recover": ["Volume", "File", ...],
             "size_bytes": int | None,  # PR-2 may probe this
            }, ...
          ],
          "version_count": int,
          "total_size_bytes": int | None,
          "error": str | None,
        }
    """
    with _file_lock:
        if not os.path.exists(WINDOWS_BACKUP_CACHE_FILE):
            return {
                "ok": True,
                "has_cache": False,
                "scanned_at": None,
                "cache_age_seconds": None,
                "versions": [],
                "version_count": 0,
                "total_size_bytes": None,
                "error": None,
            }
        try:
            with open(WINDOWS_BACKUP_CACHE_FILE, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return {
                "ok": False,
                "has_cache": False,
                "scanned_at": None,
                "cache_age_seconds": None,
                "versions": [],
                "version_count": 0,
                "total_size_bytes": None,
                "error": f"cache read failed: {e}",
            }

    if not isinstance(raw, dict):
        return {
            "ok": False,
            "has_cache": False,
            "scanned_at": None,
            "cache_age_seconds": None,
            "versions": [],
            "version_count": 0,
            "total_size_bytes": None,
            "error": "cache file is not a dict",
        }

    versions = raw.get("versions") or []
    if not isinstance(versions, list):
        versions = []
    scanned_at = raw.get("scanned_at")
    age_s: int | None = None
    if scanned_at:
        try:
            age_s = int((datetime.now() - datetime.fromisoformat(scanned_at)).total_seconds())
        except (TypeError, ValueError):
            age_s = None
    total_size = raw.get("total_size_bytes")
    return {
        "ok": True,
        "has_cache": True,
        "scanned_at": scanned_at,
        "cache_age_seconds": age_s,
        "versions": versions,
        "version_count": len(versions),
        "total_size_bytes": total_size if isinstance(total_size, (int, float)) else None,
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════
# Section 2: File History (LIVE READ from user-context XML)
# ══════════════════════════════════════════════════════════════════════


def _safe_text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _safe_int(s: str, default: int | None = None) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def parse_file_history_config(xml_text: str) -> dict:
    """Parse the File History Config1.xml text into a structured dict.

    Pure function: takes the raw XML, returns a parsed shape. Errors get
    caught and surfaced as ``parse_error`` field instead of raising — the
    UI should always render *something* even when the config is malformed.

    Output shape:
        {
          "ok": True,
          "enabled": bool,          # DPStatus == "ENABLED"
          "user_name": str,
          "friendly_name": str,
          "pc_name": str,
          "frequency_seconds": int | None,
          "retention_policy": str,  # NO LIMIT | UNTIL SPACE NEEDED | <N months>
          "retention_min_age_months": int | None,
          "target": {
            "name": str, "url": str, "drive_type": str,
            "backup_store_path": str,
            "warning_threshold_percent": int | None,
          },
          "libraries": [{"name": "...", "folders": [...]}],
          "user_folders": [str, ...],
          "staging_area": {
            "path": str,
            "max_capacity_bytes": int | None,
            "warning_threshold_bytes": int | None,
          },
          "parse_error": str | None,
        }
    """
    result = {
        "ok": True,
        "enabled": False,
        "user_name": "",
        "friendly_name": "",
        "pc_name": "",
        "frequency_seconds": None,
        "retention_policy": "",
        "retention_min_age_months": None,
        "target": {"name": "", "url": "", "drive_type": "", "backup_store_path": "", "warning_threshold_percent": None},
        "libraries": [],
        "user_folders": [],
        "staging_area": {"path": "", "max_capacity_bytes": None, "warning_threshold_bytes": None},
        "parse_error": None,
    }
    try:
        # ruff S314: the XML source is the user's own FileHistory config file
        # under %LOCALAPPDATA% -- written by Windows, not user input, no
        # external entities, and we only read it. defusedxml would be
        # disproportionate for a trusted local config.
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError as e:
        result["ok"] = False
        result["parse_error"] = str(e)
        return result

    result["enabled"] = _safe_text(root.find("DPStatus")).upper() == "ENABLED"
    result["user_name"] = _safe_text(root.find("UserName"))
    result["friendly_name"] = _safe_text(root.find("FriendlyName"))
    result["pc_name"] = _safe_text(root.find("PCName"))
    result["frequency_seconds"] = _safe_int(_safe_text(root.find("DPFrequency")))

    rp = root.find("RetentionPolicies")
    if rp is not None:
        result["retention_policy"] = _safe_text(rp.find("RetentionPolicyType"))
        result["retention_min_age_months"] = _safe_int(_safe_text(rp.find("MinimumRetentionAge")))

    target_el = root.find("Target")
    if target_el is not None:
        result["target"] = {
            "name": _safe_text(target_el.find("TargetName")),
            "url": _safe_text(target_el.find("TargetUrl")),
            "drive_type": _safe_text(target_el.find("TargetDriveType")),
            "backup_store_path": _safe_text(target_el.find("TargetBackupStorePath")),
            "warning_threshold_percent": _safe_int(_safe_text(target_el.find("TargetWarningThreshold"))),
        }

    for lib_el in root.findall("Library"):
        result["libraries"].append(
            {
                "name": _safe_text(lib_el.find("LibraryName")),
                "folders": [_safe_text(f) for f in lib_el.findall("Folder") if _safe_text(f)],
            }
        )

    result["user_folders"] = [_safe_text(f) for f in root.findall("UserFolder") if _safe_text(f)]

    sa = root.find("StagingArea")
    if sa is not None:
        result["staging_area"] = {
            "path": _safe_text(sa.find("StagingAreaPath")),
            "max_capacity_bytes": _safe_int(_safe_text(sa.find("StagingAreaMaximumCapacity"))),
            "warning_threshold_bytes": _safe_int(_safe_text(sa.find("StagingAreaWarningThreshold"))),
        }

    return result


def _staging_area_usage(staging_path: str) -> tuple[int, int]:
    """Return (used_bytes, file_count) for the staging area. Returns (0, 0)
    on any I/O error -- the staging area is normally empty (transient
    buffer) so 0 is a reasonable default."""
    if not staging_path or not os.path.isdir(staging_path):
        return (0, 0)
    total = 0
    count = 0
    try:
        for root, _dirs, files in os.walk(staging_path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                    count += 1
                except OSError:
                    continue
    except OSError:
        pass
    return (total, count)


def get_file_history_state() -> dict:
    """Live read of File History config + health probes. No elevation
    needed -- Config1.xml and the catalog live under the user's own
    profile.

    Adds health signals on top of the pure parser:
      - ``catalog_exists`` + ``catalog_mtime`` + ``catalog_age_days`` -- if
        File History is enabled but the catalog hasn't been touched in
        >7 days, something's wrong.
      - ``target_path_exists`` -- File History can be configured to a
        target drive that's offline / unplugged / never created. We
        check the configured TargetUrl + backup_store_path subfolder.
      - ``staging_usage_bytes`` / ``staging_usage_ratio`` -- staging is
        normally near-empty; persistent fill-up usually means the
        target is unreachable and files are piling up.
      - ``health`` -- one-line severity + reason.

    Shape:
        {
          "ok": True,
          "configured": bool,           # config file exists at all
          "config_path": str,
          "config": <parser output>,    # None if not configured
          "catalog_exists": bool,
          "catalog_size_bytes": int | None,
          "catalog_mtime": "<iso>" | None,
          "catalog_age_days": float | None,
          "target_path_exists": bool | None,
          "target_backup_store_exists": bool | None,
          "staging_usage_bytes": int,
          "staging_file_count": int,
          "staging_usage_ratio": float | None,
          "health": {
            "level": "ok|info|warning|critical",
            "reason": str,
          },
        }
    """
    result: dict[str, Any] = {
        "ok": True,
        "configured": False,
        "config_path": _FH_CONFIG_FILE,
        "config": None,
        "catalog_exists": False,
        "catalog_size_bytes": None,
        "catalog_mtime": None,
        "catalog_age_days": None,
        "target_path_exists": None,
        "target_backup_store_exists": None,
        "staging_usage_bytes": 0,
        "staging_file_count": 0,
        "staging_usage_ratio": None,
        "health": {"level": "info", "reason": "File History not configured"},
    }

    if not os.path.exists(_FH_CONFIG_FILE):
        return result

    result["configured"] = True
    try:
        with open(_FH_CONFIG_FILE, encoding="utf-8") as f:
            xml_text = f.read()
    except OSError as e:
        result["ok"] = False
        result["health"] = {"level": "warning", "reason": f"Config read failed: {e}"}
        return result

    cfg = parse_file_history_config(xml_text)
    result["config"] = cfg

    # Catalog freshness
    if os.path.exists(_FH_CATALOG_FILE):
        try:
            st = os.stat(_FH_CATALOG_FILE)
            result["catalog_exists"] = True
            result["catalog_size_bytes"] = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime)
            result["catalog_mtime"] = mtime.isoformat(timespec="seconds")
            result["catalog_age_days"] = round((datetime.now() - mtime).total_seconds() / 86400.0, 2)
        except OSError:
            pass

    # Target path existence
    target = cfg.get("target") or {}
    target_url = target.get("url") or ""
    if target_url:
        result["target_path_exists"] = os.path.isdir(target_url)
        store_path = target.get("backup_store_path") or ""
        if store_path and result["target_path_exists"]:
            # Backup store lives under the target drive, e.g.
            # E:\higs7\SHIGS78-PC24\Data. The backup_store_path in the
            # XML is relative to the drive.
            full_store = os.path.join(target_url.rstrip("\\/"), store_path)
            result["target_backup_store_exists"] = os.path.isdir(full_store)
        else:
            result["target_backup_store_exists"] = False if store_path else None

    # Staging usage
    staging = cfg.get("staging_area") or {}
    staging_path = staging.get("path") or ""
    used, count = _staging_area_usage(staging_path)
    result["staging_usage_bytes"] = used
    result["staging_file_count"] = count
    max_cap = staging.get("max_capacity_bytes")
    if isinstance(max_cap, (int, float)) and max_cap > 0:
        result["staging_usage_ratio"] = round(used / max_cap, 4)

    # Health verdict. Worst signal wins.
    enabled = bool(cfg.get("enabled"))
    if not enabled:
        result["health"] = {"level": "info", "reason": "File History is disabled"}
    elif result["target_path_exists"] is False:
        result["health"] = {
            "level": "critical",
            "reason": f"Target drive '{target_url}' is not accessible -- File History believes it's running but backups are NOT being saved",
        }
    elif result["target_backup_store_exists"] is False:
        result["health"] = {
            "level": "critical",
            "reason": (
                f"Target drive '{target_url}' is reachable but the backup store folder "
                f"'{(target.get('backup_store_path') or '').rstrip('/')}' is missing -- "
                f"backups are NOT being saved to disk"
            ),
        }
    elif result["catalog_age_days"] is not None and result["catalog_age_days"] > _FH_CATALOG_STALE_DAYS:
        result["health"] = {
            "level": "warning",
            "reason": f"Catalog hasn't been updated in {result['catalog_age_days']:.1f} days -- File History may have stalled",
        }
    elif result["staging_usage_ratio"] is not None and result["staging_usage_ratio"] >= _FH_STAGING_WARN_RATIO:
        result["health"] = {
            "level": "warning",
            "reason": (
                f"Staging area is {result['staging_usage_ratio'] * 100:.0f}% full -- "
                f"target drive may be unreachable and files are piling up locally"
            ),
        }
    else:
        result["health"] = {"level": "ok", "reason": "File History is healthy"}

    return result


# ══════════════════════════════════════════════════════════════════════
# Combined summary -- drives the dashboard concern + the Backup tab header
# ══════════════════════════════════════════════════════════════════════


def summarize_backup() -> dict:
    """Combined health summary across Sections 1 + 2.

    Returns:
        {
          "ok": True,
          "windows_backups": {
            "has_cache": bool, "version_count": int,
            "total_size_bytes": int | None,
            "scanned_at": "<iso>" | None,
            "cache_age_seconds": int | None,
            "health": {"level": "info|warning|...", "reason": "..."},
          },
          "file_history": {
            "configured": bool, "enabled": bool,
            "target_url": str, "version_count_proxy": int (folders watched),
            "health": {"level": "ok|warning|critical", "reason": "..."},
          },
          "overall_health": {"level": "ok|warning|critical", "reason": "..."},
        }
    """
    wb = load_windows_backup_cache()
    fh = get_file_history_state()
    fh_cfg = fh.get("config") or {}

    # WindowsImageBackup top-level health:
    # - Has cache + has versions -> "info" (no health signal until PR-2
    #   adds growth detection)
    # - Has cache + zero versions -> "warning" (configured but empty)
    # - No cache yet -> "info" (haven't scanned)
    if not wb["has_cache"]:
        wb_health = {"level": "info", "reason": "Not yet scanned -- click Scan to populate"}
    elif wb["version_count"] == 0:
        wb_health = {"level": "warning", "reason": "WindowsImageBackup catalog is empty"}
    else:
        wb_health = {"level": "info", "reason": f"{wb['version_count']} version(s) catalogued"}

    summary = {
        "ok": True,
        "windows_backups": {
            "has_cache": wb["has_cache"],
            "version_count": wb["version_count"],
            "total_size_bytes": wb["total_size_bytes"],
            "scanned_at": wb["scanned_at"],
            "cache_age_seconds": wb["cache_age_seconds"],
            "health": wb_health,
        },
        "file_history": {
            "configured": fh["configured"],
            "enabled": bool(fh_cfg.get("enabled")),
            "target_url": (fh_cfg.get("target") or {}).get("url", ""),
            "watched_folders": len(fh_cfg.get("user_folders", []))
            + sum(len(lib.get("folders", [])) for lib in fh_cfg.get("libraries", [])),
            "health": fh.get("health") or {"level": "info", "reason": ""},
        },
    }

    # Overall health = worst of the two. Critical > warning > info > ok.
    rank = {"critical": 3, "warning": 2, "info": 1, "ok": 0}
    candidates = [
        (rank.get(wb_health["level"], 1), wb_health),
        (rank.get(fh["health"]["level"], 1), fh["health"]),
    ]
    candidates.sort(key=lambda t: t[0], reverse=True)
    summary["overall_health"] = candidates[0][1]
    return summary
