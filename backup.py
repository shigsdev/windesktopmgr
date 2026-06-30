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
import re
import subprocess
import sys
import threading
import time
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

# Scheduled File History auto-cleanup (in-app retention via a recurring
# `fhmanagew -cleanup <N>` task). Fixed task name -- never user input.
_FH_CLEANUP_TASK_NAME = "WinDesktopMgr-FileHistoryCleanup"
# CREATE_NO_WINDOW: keep schtasks' console off-screen under the pythonw tray.
_NO_WINDOW = 0x08000000


def _fhmanagew_path() -> str:
    """Absolute path to the system fhmanagew.exe (a non-user-writable OS
    binary -- so a /RL HIGHEST task pointed at it carries no escalation risk,
    unlike a task pointed at a user-writable exe)."""
    return os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "fhmanagew.exe")


_file_lock = threading.Lock()

# Request / result file naming for the elevated helper (PR-2).
# Lives in APP_DIR so both the unelevated tray AND the elevated helper
# can read + write them; APP_DIR is user-owned so no privilege issue.
_REQUEST_FILE_TPL = "backup_request_{session}.json"
_RESULT_FILE_TPL = "backup_result_{session}.json"

# Allowed actions for the elevated helper. Keep tight + validated --
# anything not in this set is rejected before launch.
_ALLOWED_ACTIONS: set[str] = {
    "scan_catalog",  # wbadmin get versions + walk WindowsImageBackup for sizes
    "delete_version",  # wbadmin delete backup -version:<id> -quiet
    "fh_cleanup",  # fhmanagew.exe -cleanup <days>
    "fh_storage_scan",  # walk the FH target drive: size each store + sources
}

# File History storage breakdown (in-app "where is the space going") cache,
# populated by the elevated helper (the active store is ACL-restricted to
# admins) and read by the unelevated tray.
FH_STORAGE_CACHE_FILE = os.path.join(APP_DIR, "fh_storage_cache.json")
# Wall-clock cap for a storage scan -- File History stores hold huge numbers
# of small version files, so an unbounded walk could run for many minutes.
# On breach we mark the affected size "capped" rather than hang.
_FH_STORAGE_BUDGET_S = 240


# ══════════════════════════════════════════════════════════════════════
# wbadmin output parser  (pure function -- testable without elevation)
# ══════════════════════════════════════════════════════════════════════


def parse_wbadmin_versions(stdout: str) -> list[dict]:
    """Parse the multi-block output of ``wbadmin get versions``.

    Microsoft's wbadmin emits a fixed-key text block per version,
    separated by blank lines.  Real output captured against a Win11
    machine with WindowsImageBackup populated::

        Backup time: 5/24/2026 4:00 AM
        Backup target: 1394/USB Disk labeled WD Passport(E:)
        Version identifier: 05/24/2026-04:00
        Can recover: Volume(s), File(s), Application(s), Bare Metal Recovery, System State
        Snapshot ID: {abc-123-...}

    Returns a list of dicts with ``version_id``, ``backup_time``,
    ``target``, ``can_recover`` (list of capability strings),
    ``snapshot_id`` (optional). ``size_bytes`` is left as None here --
    the elevated helper probes the on-disk folder to fill that in.

    Tolerant to unknown keys, blank lines, and the Microsoft preamble
    ("Backup time", "wbadmin 1.0", copyright lines, etc.).
    """
    out: list[dict] = []
    if not stdout:
        return out

    current: dict = {}

    def _flush():
        if current.get("version_id"):
            out.append(
                {
                    "version_id": current.get("version_id", ""),
                    "backup_time": current.get("backup_time", ""),
                    "target": current.get("target", ""),
                    "can_recover": current.get("can_recover", []),
                    "snapshot_id": current.get("snapshot_id", ""),
                    "size_bytes": None,
                }
            )

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            # Blank line = block boundary. Flush + reset.
            _flush()
            current = {}
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "version identifier":
            current["version_id"] = value
        elif key == "backup time":
            current["backup_time"] = value
        elif key == "backup target":
            current["target"] = value
        elif key == "can recover":
            # Comma-separated, but each item may contain internal spaces.
            current["can_recover"] = [v.strip() for v in value.split(",") if v.strip()]
        elif key == "snapshot id":
            current["snapshot_id"] = value
        # Anything else (preamble like "wbadmin 1.0 - Backup command-line tool")
        # is silently ignored.

    # Final flush in case the output didn't end with a blank line.
    _flush()
    return out


# ══════════════════════════════════════════════════════════════════════
# Actions history  (append-only audit log for elevated actions)
# ══════════════════════════════════════════════════════════════════════


def load_actions_history() -> list[dict]:
    """Return the append-only log of past elevated actions, newest first.

    Each entry: ``{session_id, action, params, started_at, ended_at,
    status, returncode, stdout_tail, stderr_tail, bytes_freed_estimate}``.
    Tail fields cap at ~500 chars each so a runaway subprocess log can't
    bloat the file unbounded.
    """
    with _file_lock:
        if not os.path.exists(BACKUP_ACTIONS_HISTORY_FILE):
            return []
        try:
            with open(BACKUP_ACTIONS_HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return []
            # Newest first for UI display.
            return sorted(data, key=lambda e: e.get("started_at", ""), reverse=True)
        except (OSError, json.JSONDecodeError):
            return []


def _atomic_write_json(path: str, payload) -> bool:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def append_action_history(entry: dict, max_entries: int = 200) -> bool:
    """Append one action-history entry. Caps the file at ``max_entries``
    rows to prevent unbounded growth.  Returns True on success."""
    with _file_lock:
        # Load directly (avoid recursing through load_actions_history's lock).
        existing: list = []
        if os.path.exists(BACKUP_ACTIONS_HISTORY_FILE):
            try:
                with open(BACKUP_ACTIONS_HISTORY_FILE, encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, list):
                    existing = raw
            except (OSError, json.JSONDecodeError):
                existing = []
        existing.append(entry)
        if len(existing) > max_entries:
            existing = existing[-max_entries:]
        return _atomic_write_json(BACKUP_ACTIONS_HISTORY_FILE, existing)


# ══════════════════════════════════════════════════════════════════════
# Safety guards for destructive actions  (pure validators -- no I/O)
# ══════════════════════════════════════════════════════════════════════


def validate_delete_version_request(version_id: str, current_versions: list[dict]) -> tuple[bool, str]:
    """Return ``(ok, error_message)``.

    Refuses when:
      - ``version_id`` is empty / not a string
      - ``version_id`` doesn't exist in the current catalog
      - ``version_id`` IS the most recent version (always keep >=1)
      - Catalog has only one entry (can't delete the last one)
    """
    if not isinstance(version_id, str) or not version_id.strip():
        return (False, "version_id must be a non-empty string")
    if not current_versions:
        return (False, "catalog is empty -- nothing to delete")
    ids = [v.get("version_id", "") for v in current_versions]
    if version_id not in ids:
        return (False, f"version_id {version_id!r} not found in catalog")
    if len(current_versions) == 1:
        return (False, "refusing to delete the only remaining backup version")
    # The catalog is ordered newest-first in our parser; the most recent
    # version is index 0. (Same semantics as wbadmin: it lists newest
    # first.)
    if ids[0] == version_id:
        return (False, "refusing to delete the most-recent backup version")
    return (True, "")


def validate_fh_cleanup_request(days: int) -> tuple[bool, str]:
    """File History cleanup arg: ``-cleanup <N>`` where N is days.

    ``fhmanagew`` accepts 0 (keep only latest) through arbitrary large
    values. We cap at 3650 (~10 years) to refuse absurd windows; negative
    values are nonsense; bool is rejected (``True``/``False`` are int
    subclasses that would otherwise coerce to 1/0).
    """
    if not isinstance(days, int) or isinstance(days, bool):
        return (False, "days must be an integer")
    if days < 0:
        return (False, "days must be >= 0 (0 keeps only the newest version)")
    if days > 3650:
        return (False, "days > 3650 (>~10 years) refused -- specify a smaller window")
    return (True, "")


# ══════════════════════════════════════════════════════════════════════
# Scheduled File History auto-cleanup  (in-app retention)
#
# File History's NATIVE age-based retention only prunes when the drive is
# full or on a manual cleanup (per the FH_RETENTION_TYPES docs), so it
# doesn't enforce a rolling window or free space on its own. Instead we
# register a recurring scheduled task that runs `fhmanagew -cleanup <N>`,
# which actually deletes versions older than N days each run. The task runs
# with highest privileges (the FH store is ACL-restricted to admins), so
# setup/remove go through a UAC prompt; querying does not need elevation.
# Everything passed to schtasks is a fixed constant or a range-validated
# integer -- no user-controlled strings reach the command line.
# ══════════════════════════════════════════════════════════════════════


def fh_cleanup_schedule_status() -> dict:
    """Whether the recurring auto-cleanup task exists + its configured age.
    Never raises. Shape: {enabled, task, days, schedule}."""
    absent = {"enabled": False, "task": _FH_CLEANUP_TASK_NAME, "days": None, "schedule": None}
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", _FH_CLEANUP_TASK_NAME, "/V", "/FO", "LIST"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_NO_WINDOW,
        )
    except Exception:  # noqa: BLE001 -- schtasks missing / non-Windows / timeout
        return absent
    if result.returncode != 0:
        return absent
    out = result.stdout or ""
    days_match = re.search(r"-cleanup\s+(\d+)", out)
    sched_match = re.search(r"Schedule Type:\s*(.+)", out)
    return {
        "enabled": True,
        "task": _FH_CLEANUP_TASK_NAME,
        "days": int(days_match.group(1)) if days_match else None,
        "schedule": sched_match.group(1).strip() if sched_match else None,
    }


def _schtasks_elevated(args: str, action: str) -> dict:
    """Run ``schtasks.exe <args>`` elevated via a UAC prompt. ShellExecuteW
    returns > 32 once the elevated process starts (user accepted UAC); it does
    NOT surface schtasks' own exit code, so callers re-query the status to
    confirm the result. Mirrors lhm._schtasks_elevated."""
    try:
        import ctypes  # noqa: PLC0415 -- Windows-only
    except ImportError:
        return {"ok": False, "error": "ctypes unavailable (non-Windows host?)"}
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "schtasks.exe", args, None, 0)
    except Exception as e:  # noqa: BLE001 -- ShellExecuteW unavailable -> graceful
        return {"ok": False, "error": f"ShellExecuteW failed: {type(e).__name__}: {e}"}
    if rc <= 32:
        rc_map = {
            0: "out of memory",
            2: "FILE_NOT_FOUND",
            3: "PATH_NOT_FOUND",
            5: "ACCESS_DENIED (UAC prompt declined?)",
            8: "OUT_OF_MEMORY",
            31: "NO_ASSOCIATION",
        }
        return {"ok": False, "error": f"could not {action}: rc={rc} ({rc_map.get(rc, 'unknown')})"}
    return {"ok": True}


def setup_fh_cleanup_schedule(days: int) -> dict:
    """Register a WEEKLY task running ``fhmanagew -cleanup <days> -quiet`` with
    highest privileges (UAC prompt). Deletes versions older than ``days`` each
    run. Returns ``{"ok": True}`` once the elevated schtasks process starts."""
    ok, err = validate_fh_cleanup_request(days)
    if not ok:
        return {"ok": False, "error": err}
    fhm = _fhmanagew_path()
    # Defence in depth at the Python->schtasks boundary. fhm is a fixed system
    # path (never user input) and days is a range-validated int, but refuse a
    # stray quote rather than mangle /TR parsing.
    if '"' in fhm:
        return {"ok": False, "error": "fhmanagew path contains an invalid character"}
    args = (
        f'/Create /TN "{_FH_CLEANUP_TASK_NAME}" '
        f'/TR "\\"{fhm}\\" -cleanup {days} -quiet" '
        f"/SC WEEKLY /ST 03:00 /RL HIGHEST /F"
    )
    return _schtasks_elevated(args, "schedule File History auto-cleanup")


def remove_fh_cleanup_schedule() -> dict:
    """Delete the recurring auto-cleanup task (UAC prompt)."""
    args = f'/Delete /TN "{_FH_CLEANUP_TASK_NAME}" /F'
    return _schtasks_elevated(args, "remove the File History auto-cleanup schedule")


# ══════════════════════════════════════════════════════════════════════
# File History storage breakdown  (where is the space going)
#
# File History keeps every version of every changed file, so the store can
# balloon -- AND a reconfigure/upgrade can ORPHAN an old store on the same
# drive that nothing prunes (2026-06-29 user report: a 1.38 TB store at
# E:\FileHistory last written in 2024, separate from the active store). This
# walks the target drive, finds every File History store, sizes each + its
# top source folders, and flags the active one vs. stale/reclaimable orphans.
# The active store is ACL-restricted to admins, so the heavy scan runs in the
# elevated helper; the result is cached for the unelevated tray to read.
# ══════════════════════════════════════════════════════════════════════


def _safe_is_dir(entry) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _dir_size(path: str, deadline: float) -> tuple[int, int, bool]:
    """Return ``(total_bytes, file_count, capped)`` for ``path`` via an
    iterative ``os.scandir`` walk. Stops early (``capped=True``) once
    ``deadline`` (a ``time.monotonic()`` value) passes, so a multi-TB store
    full of tiny version files can't hang the scan. Never raises."""
    total = 0
    count = 0
    stack = [path]
    while stack:
        if time.monotonic() > deadline:
            return total, count, True
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            count += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, count, False


def find_fh_stores(drive_root: str, max_depth: int = 4, deadline: float | None = None) -> list[str]:
    """Find File History store ``Data`` directories on ``drive_root``. A File
    History store root holds BOTH a ``Data`` and a ``Configuration`` subdir
    (``<drive>\\[FileHistory\\]<user>\\<machine>\\``); we return each store's
    ``Data`` path. Depth-limited AND wall-clock-bounded (``deadline`` is a
    ``time.monotonic()`` value) so discovery never walks the huge Data trees
    or hangs on a pathologically wide/slow drive. Never raises."""
    found: list[str] = []

    def _walk(d: str, depth: int) -> None:
        if depth > max_depth or (deadline is not None and time.monotonic() > deadline):
            return
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        subdirs = {e.name.lower(): e.path for e in entries if _safe_is_dir(e)}
        if "data" in subdirs and "configuration" in subdirs:
            found.append(subdirs["data"])
            return  # a store root -- don't descend into its Data tree
        for child in subdirs.values():
            _walk(child, depth + 1)

    _walk(drive_root, 0)
    return found


def scan_fh_storage(target_url: str, store_rel_path: str, budget_s: float = _FH_STORAGE_BUDGET_S) -> dict:
    """Walk the File History target drive and break down its space usage:
    every store with its total size + top source folders. Designed to run
    elevated (the active store is ACL-restricted). Never raises -- best-effort,
    time-capped.

    Deliberately does NOT classify stores as "active" vs. "reclaimable"
    (removed 2026-06-30). The earlier version judged that by the top ``Data``
    folder's mtime, which is meaningless for File History: versions are written
    DEEP in subfolders, so the top folder can read years old while the store is
    written hourly. That mislabeled a live 1.38 TB store as a deletable orphan.
    The tool now only REPORTS where space is; it never recommends deletion.
    (``store_rel_path`` is accepted for call-site compatibility; unused.)"""
    drive_root = (target_url or "").rstrip("\\/") + os.sep
    deadline = time.monotonic() + budget_s
    stores: list[dict] = []

    for data_dir in find_fh_stores(drive_root, deadline=deadline):
        size, count, capped = _dir_size(data_dir, deadline)
        by_source: list[dict] = []
        try:
            with os.scandir(data_dir) as it:
                for entry in it:
                    if _safe_is_dir(entry):
                        ssize, _, _ = _dir_size(entry.path, deadline)
                        by_source.append({"name": entry.name, "size_bytes": ssize})
        except OSError:
            pass
        by_source.sort(key=lambda s: s["size_bytes"], reverse=True)
        stores.append(
            {
                "path": data_dir,
                "size_bytes": size,
                "file_count": count,
                "capped": capped,
                "by_source": by_source[:12],
            }
        )
    stores.sort(key=lambda s: s["size_bytes"], reverse=True)

    return {
        "ok": True,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "target_drive": drive_root,
        "store_count": len(stores),
        "total_bytes": sum(s["size_bytes"] for s in stores),
        "stores": stores,
    }


def load_fh_storage_cache() -> dict:
    """Read the last storage scan written by the elevated helper. Returns a
    ``{"has_cache": False}`` placeholder when no scan has run yet."""
    try:
        with open(FH_STORAGE_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("stores"), list):
            return {"has_cache": True, **data}
    except (OSError, json.JSONDecodeError):
        pass
    return {"has_cache": False, "stores": []}


# ══════════════════════════════════════════════════════════════════════
# Elevated-helper launcher  (ShellExecuteW + UAC prompt)
# ══════════════════════════════════════════════════════════════════════


def _session_id() -> str:
    """Short hex session id for request/result file naming. 12 hex chars
    is plenty since we only need to uniquely-name files for the in-flight
    session window (~1 minute)."""
    import secrets

    return secrets.token_hex(6)


def request_elevated_action(action: str, params: dict | None = None) -> dict:
    """Write a request file and launch the elevated helper via UAC.

    Returns ``{"ok": True, "session_id": "<hex>"}`` on launch success
    (user clicked Yes on the UAC prompt and the elevated process
    started), or ``{"ok": False, "error": "..."}`` otherwise.

    The tray polls ``get_scan_status(session_id)`` until the helper
    writes a result file. UAC interaction blocks this call -- the
    Flask route timeout (180 s in this app) is the upper bound.

    Action whitelist guard: any action not in ``_ALLOWED_ACTIONS`` is
    refused before launch, so the elevated helper only ever sees one
    of the known-safe verbs even if a future caller fat-fingers.
    """
    if action not in _ALLOWED_ACTIONS:
        return {"ok": False, "error": f"unknown action {action!r}"}

    session = _session_id()
    request_path = os.path.join(APP_DIR, _REQUEST_FILE_TPL.format(session=session))
    helper_path = os.path.join(APP_DIR, "scripts", "backup_helper_elevated.py")
    if not os.path.exists(helper_path):
        return {"ok": False, "error": f"elevated helper not found at {helper_path}"}

    payload = {
        "session_id": session,
        "action": action,
        "params": params or {},
        "queued_at": datetime.now().isoformat(timespec="seconds"),
    }
    if not _atomic_write_json(request_path, payload):
        return {"ok": False, "error": "failed to write request file"}

    # ShellExecuteW with "runas" triggers the UAC prompt. Returns >32 on
    # success, <=32 on failure. We map the documented error codes back
    # to user-readable strings.
    try:
        import ctypes
    except ImportError:
        return {"ok": False, "error": "ctypes unavailable (non-Windows host?)"}

    # SW_HIDE = 0 (no console window for the helper).
    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{helper_path}" --request "{request_path}"',
        None,
        0,
    )
    # See https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew
    # for the full error-code table.
    if rc <= 32:
        rc_map = {
            0: "out of memory",
            2: "FILE_NOT_FOUND",
            3: "PATH_NOT_FOUND",
            5: "ACCESS_DENIED (UAC prompt declined?)",
            8: "OUT_OF_MEMORY",
            11: "BAD_FORMAT",
            27: "NO_ASSOCIATION",
            31: "DDE_FAIL",
            32: "DLL_NOT_FOUND",
        }
        # Clean up the orphaned request file since the helper never
        # picked it up.
        try:
            os.remove(request_path)
        except OSError:
            pass
        return {"ok": False, "error": f"ShellExecuteW failed: rc={rc} ({rc_map.get(rc, 'unknown')})"}

    return {"ok": True, "session_id": session}


def get_scan_status(session_id: str) -> dict:
    """Read the helper's result file for ``session_id``.

    Returns one of:
      - ``{"state": "pending", "session_id": ...}`` -- helper still running
      - ``{"state": "done", "session_id": ..., "result": {...}}`` -- completed
      - ``{"state": "missing", "error": "..."}`` -- bad session id

    The "done" payload's ``result.ok`` tells whether the action itself
    succeeded; ``state: done`` only means the helper exited cleanly.
    """
    if not session_id or "/" in session_id or "\\" in session_id:
        # Defence in depth: refuse any session_id with path separators
        # so a crafted query string can't read arbitrary files.
        return {"state": "missing", "error": "invalid session_id"}
    result_path = os.path.join(APP_DIR, _RESULT_FILE_TPL.format(session=session_id))
    if not os.path.exists(result_path):
        return {"state": "pending", "session_id": session_id}
    try:
        with open(result_path, encoding="utf-8") as f:
            result = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"state": "missing", "error": f"result file unreadable: {e}"}
    return {"state": "done", "session_id": session_id, "result": result}


def cleanup_session_files(session_id: str) -> None:
    """Remove the request + result files for a completed session. Called
    by the route AFTER the UI has consumed the result so a stale file
    can't confuse a future poll on the same session id (unlikely but
    safe-by-default)."""
    if not session_id or "/" in session_id or "\\" in session_id:
        return
    for tpl in (_REQUEST_FILE_TPL, _RESULT_FILE_TPL):
        p = os.path.join(APP_DIR, tpl.format(session=session_id))
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


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
        "total_size_bytes": total_size if isinstance(total_size, int | float) else None,
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


def _join_store_path(target_url: str, store_path: str) -> str:
    """Join a File History ``TargetUrl`` with a relative ``TargetBackupStorePath``.

    Bug fix 2026-06-16: the previous code did
    ``os.path.join(target_url.rstrip("\\/"), store_path)``. For a drive-root
    target like ``E:\\`` the ``rstrip`` produced the bare drive ``E:``, and
    ``os.path.join("E:", "higs7\\...")`` yields the DRIVE-RELATIVE path
    ``E:higs7\\...`` (no separator) instead of the absolute
    ``E:\\higs7\\...``. A drive-relative path resolves against the current
    directory on that drive, so the probe checked the wrong location.
    """
    base = target_url or ""
    # A bare drive letter ("E:") joins drive-relative -- force it absolute.
    if len(base) == 2 and base[1] == ":":
        base += "\\"
    return os.path.join(base, (store_path or "").lstrip("\\/"))


def _deepest_existing_ancestor(path: str) -> str | None:
    """Return the deepest ancestor of ``path`` that exists on disk, or
    ``None`` if not even the drive root is present.

    Used to make the "store not found" probe message honest: instead of
    guessing "doesn't exist (or ACL traversal denied)", we report how far
    the configured path actually resolves -- e.g. ``E:\\`` when the
    configured ``E:\\higs7\\SHIGS78-PC24\\Data`` has no ``higs7`` level on
    disk (the 2026-06-16 config-vs-disk mismatch).
    """
    drive, rest = os.path.splitdrive(path)
    if not drive:
        return None
    cur = drive + "\\"
    try:
        deepest = cur if os.path.exists(cur) else None
    except OSError:
        return None
    for comp in rest.replace("/", "\\").strip("\\").split("\\"):
        if not comp:
            continue
        cur = os.path.join(cur, comp)
        try:
            if os.path.exists(cur):
                deepest = cur
            else:
                break
        except OSError:
            # Hit an ACL boundary -- can't see deeper, stop here.
            break
    return deepest


def _probe_backup_store(full_store: str) -> tuple[bool | None, str]:
    """Determine whether the File History backup-store folder exists.

    Returns ``(exists, reason)`` where ``exists`` is:
      - ``True``  -- folder confirmed present (either we could stat it
                      directly, OR it appeared in the parent directory's
                      listing)
      - ``False`` -- folder confirmed missing (parent listed cleanly
                      and the leaf was NOT in it)
      - ``None``  -- couldn't determine (parent itself wasn't listable;
                      the folder may exist behind an ACL boundary that
                      the unelevated tray can't cross)

    Bug fix 2026-05-27 (post-deploy user report): the previous probe
    used ``os.path.isdir`` which returns ``False`` for BOTH "doesn't
    exist" and "ACL denies access." Windows File History writes its
    backup store with restricted ACLs to prevent tampering -- a healthy
    backup setup looked identical to a missing one from the tray's
    unelevated view, and the health card fired ``critical`` against a
    perfectly-working store.

    Strategy: first try a direct ``os.path.isdir`` because that's
    cheap and handles the most common (readable) case. If that fails,
    walk the parent directory's listing and look for the leaf name.
    A folder that we can't stat but CAN see listed in its parent is
    a healthy ACL-restricted folder, not a missing one. If we can't
    even list the parent (rare -- only happens when the entire
    target drive is under restricted ACLs), return ``None`` so the
    health verdict downgrades to "info" instead of falsely firing
    "critical."
    """
    if not full_store:
        return None, "no path supplied"
    full_store = full_store.rstrip("\\/")

    # ── Fast path: directly stat-able. ──
    try:
        if os.path.isdir(full_store):
            return True, "direct stat ok"
    except OSError:
        pass

    # ── Slow path: stat said False (could be missing OR ACL-denied).
    # Walk the parent listing and look for the leaf by name. This
    # works even when stat() of the leaf itself raises PermissionError
    # because os.scandir of the parent doesn't require READ on the
    # children.
    parent = os.path.dirname(full_store)
    leaf = os.path.basename(full_store)
    if not parent or not leaf:
        return False, "malformed path -- no parent/leaf split"

    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                # Windows file system is case-insensitive; the configured
                # store path may have different casing than what's on disk.
                if entry.name.lower() == leaf.lower():
                    return True, "parent listing shows leaf (acl-restricted contents)"
        # Parent scan completed cleanly and leaf was not present.
        return False, "parent dir scanned cleanly -- leaf truly missing"
    except PermissionError:
        # Can't list the parent. Inconclusive -- never assume missing
        # under ACL denial.
        return None, "parent dir not listable -- can't determine (may need elevation)"
    except FileNotFoundError:
        # Parent dir doesn't exist (or appears not to). This could be
        # genuinely missing OR an ACL traversal denial pretending to
        # be FileNotFoundError -- on Windows the two are indistinguish-
        # able from the syscall. Return False conservatively; the
        # catalog-age cross-check in get_file_history_state() demotes this
        # to a healthy verdict when backups ARE actually happening (the
        # 2026-05-27 / 2026-06-16 user scenarios). Report how far the path
        # actually resolves so the reason is honest instead of guessing "ACL".
        deepest = _deepest_existing_ancestor(full_store)
        return False, (
            "configured store path not present on disk; deepest existing "
            f"ancestor: {deepest or '(drive root not found)'}"
        )
    except OSError as exc:
        return None, f"parent scan failed: {exc}"


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
              # True  = stat-able OR listed in parent (acl-restricted ok)
              # False = parent scanned cleanly, leaf not present
              # None  = couldn't determine (parent not listable -- may
              #         need elevation; treated as info, not critical)
          "target_backup_store_probe": str,  # one-line reason for above
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
        "target_backup_store_probe": "",
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
            # XML is relative to the drive. _join_store_path avoids the
            # drive-relative os.path.join bug (E:\ + path -> E:path).
            full_store = _join_store_path(target_url, store_path)
            exists, probe_reason = _probe_backup_store(full_store)
            result["target_backup_store_exists"] = exists
            result["target_backup_store_probe"] = probe_reason
        else:
            result["target_backup_store_exists"] = False if store_path else None
            result["target_backup_store_probe"] = (
                "no store path configured" if not store_path else "target drive offline"
            )

    # Staging usage
    staging = cfg.get("staging_area") or {}
    staging_path = staging.get("path") or ""
    used, count = _staging_area_usage(staging_path)
    result["staging_usage_bytes"] = used
    result["staging_file_count"] = count
    max_cap = staging.get("max_capacity_bytes")
    if isinstance(max_cap, int | float) and max_cap > 0:
        result["staging_usage_ratio"] = round(used / max_cap, 4)

    # Health verdict. Worst signal wins, EXCEPT a fresh catalog is
    # authoritative proof File History is actively writing and overrides the
    # fragile store-folder probe (which can false-negative on an ACL-
    # restricted store or a path that doesn't match Config1.xml -- the
    # 2026-06-16 user report: a healthy store at E:\SHIGS78-PC24 vs. a
    # configured path of E:\higs7\SHIGS78-PC24\Data). NOTE: the registry's
    # ProtectedUpToTime value is NOT used -- File History zeroes it between
    # hourly cycles (verified live 2026-06-16), so it's too volatile to
    # trust. The local Catalog1.edb mtime, updated each protection cycle, is
    # the reliable freshness signal.
    enabled = bool(cfg.get("enabled"))
    store_path_cfg = (target.get("backup_store_path") or "").rstrip("/\\")
    catalog_age = result["catalog_age_days"]
    catalog_fresh = catalog_age is not None and catalog_age <= _FH_CATALOG_STALE_DAYS
    store_unconfirmed = result["target_backup_store_exists"] is not True
    staging_full = result["staging_usage_ratio"] is not None and result["staging_usage_ratio"] >= _FH_STAGING_WARN_RATIO
    if not enabled:
        result["health"] = {"level": "info", "reason": "File History is disabled"}
    elif result["target_path_exists"] is False:
        # Target drive unreachable RIGHT NOW -- a real, active problem.
        # Checked before the catalog-fresh demote so an unplugged drive
        # still surfaces.
        result["health"] = {
            "level": "critical",
            "reason": f"Target drive '{target_url}' is not accessible -- File History believes it's running but backups are NOT being saved",
        }
    elif catalog_fresh and staging_full:
        # The last cycle wrote (fresh catalog) BUT the staging area is near-
        # full -- the target may be becoming unreachable and files are piling
        # up locally, so the NEXT cycle could fail. This must outrank the
        # healthy verdict below (checked here so the catalog-fresh short-
        # circuit doesn't silently swallow a filling staging area).
        result["health"] = {
            "level": "warning",
            "reason": (
                f"Staging area is {result['staging_usage_ratio'] * 100:.0f}% full -- "
                f"target drive may be unreachable and files are piling up locally"
            ),
        }
    elif catalog_fresh:
        # The catalog was written within the freshness window, so File
        # History IS actively protecting files -- backups are current
        # regardless of what the on-disk store probe says. This is the
        # primary healthy verdict (2026-06-16); it retires the false "store
        # missing -- verify manually" alarm against a healthy ACL-restricted
        # store.
        reason = f"File History is healthy -- last backup activity {catalog_age:.1f} days ago"
        if store_unconfirmed:
            reason += (
                " (the on-disk store folder isn't directly readable from the tray, which is "
                f"normal for an ACL-protected store; probe: {result.get('target_backup_store_probe') or 'unknown'})"
            )
        result["health"] = {"level": "ok", "reason": reason}
    elif result["target_backup_store_exists"] is False:
        # Probe says missing AND the catalog is stale (or absent) -- both
        # signals agree backups are NOT happening.
        result["health"] = {
            "level": "critical",
            "reason": (
                f"Target drive '{target_url}' is reachable but the backup store folder "
                f"'{store_path_cfg}' is missing -- "
                f"backups are NOT being saved to disk (catalog also stale)"
            ),
        }
    elif result["target_backup_store_exists"] is None and (target.get("backup_store_path") or ""):
        # Couldn't determine whether the store exists because the
        # parent dir isn't listable from the unelevated tray. This
        # happens with restricted-ACL store folders (the healthy
        # default). Surface as info -- not a fail -- with the probe
        # reason so the user knows why we're not asserting health.
        # Caught the 2026-05-27 user report where E:\higs7\... was
        # present + working but read-blocked by ACL.
        result["health"] = {
            "level": "info",
            "reason": (
                f"Backup store '{(target.get('backup_store_path') or '').rstrip('/')}' "
                f"is not directly readable from the tray (may need elevation to confirm). "
                f"Probe: {result.get('target_backup_store_probe') or 'unknown'}"
            ),
        }
    elif result["catalog_age_days"] is not None and result["catalog_age_days"] > _FH_CATALOG_STALE_DAYS:
        result["health"] = {
            "level": "warning",
            "reason": f"Catalog hasn't been updated in {result['catalog_age_days']:.1f} days -- File History may have stalled",
        }
    elif staging_full:
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
