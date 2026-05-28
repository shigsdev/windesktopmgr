"""scripts/backup_helper_elevated.py -- elevated worker for Backup tab (#47 PR-2).

Runs in an ELEVATED process spawned by the tray via ShellExecuteW
("runas" verb -> Windows UAC prompt -> if user clicks Yes, this script
runs as Administrator). The unelevated tray cannot read the wbadmin
catalog or delete backup versions, so this helper does it for them.

Invocation::

    python scripts/backup_helper_elevated.py --request <path-to-request.json>

The request file (written atomically by the unelevated tray) carries:
    {
      "session_id": "<hex>",
      "action": "scan_catalog" | "delete_version" | "fh_cleanup",
      "params": {...},
      "queued_at": "<iso>",
    }

This script:
  1. Loads the request.
  2. Validates the action is in the whitelist + sanity-checks params.
  3. Runs the appropriate subprocess (wbadmin / fhmanagew).
  4. Captures stdout / stderr / returncode + an elapsed-time estimate
     of bytes freed (for delete + cleanup).
  5. Writes a backup_result_<session_id>.json with the full outcome.
  6. Appends an entry to backup_actions_history.json for audit.
  7. For ``scan_catalog`` specifically: also writes backup_cache.json
     (the data the unelevated /api/backup/windows-backups route reads).

Designed so the elevated process is short-lived -- it does exactly one
action then exits. Nothing here listens for IPC or sticks around.

Python-first per CLAUDE.md SOP. The only PowerShell-shaped call is
``wbadmin`` itself (a Windows OS .exe with no Python binding) and
``fhmanagew.exe`` (same story); neither involves ``powershell.exe``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Make the app dir importable so we can reuse the pure parsers + safety
# guards from backup.py without copy-pasting them.
APP_DIR = str(Path(__file__).resolve().parent.parent)
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import backup as bk  # noqa: E402

# ── Helper utilities ────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _atomic_write(path: str, payload) -> bool:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            if isinstance(payload, dict | list):
                json.dump(payload, f, indent=2)
            else:
                f.write(str(payload))
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def _tail(s: str, limit: int = 500) -> str:
    if not s:
        return ""
    s = s.strip()
    if len(s) <= limit:
        return s
    return "...[truncated]...\n" + s[-limit:]


def _run(cmd: list[str], timeout: int = 600) -> dict:
    """Run a subprocess + capture everything. Returns a dict shaped
    like the audit-history entries -- stdout_tail / stderr_tail / rc /
    elapsed."""
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = time.monotonic() - started
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "stdout_tail": _tail(proc.stdout or ""),
            "stderr_tail": _tail(proc.stderr or ""),
            "elapsed_seconds": round(elapsed, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": "(timeout)",
            "stdout_tail": _tail(
                e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            ),
            "stderr_tail": "(subprocess timed out after %ds)" % timeout,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "timed_out": True,
        }


# ── Backup-store sizing  (best-effort folder walk under WindowsImageBackup) ──


def _probe_backup_size(target: str, backup_time: str) -> int | None:
    """Walk ``E:\\WindowsImageBackup\\<machine>\\Backup <date>\\`` to
    compute total bytes for a single version. Returns None if the
    folder layout doesn't match expectations -- we never block scan
    success on this best-effort sizing."""
    # Target string is like "1394/USB Disk labeled WD Passport(E:)" --
    # extract the drive letter from the parens.
    drive = ""
    if "(" in target and ":)" in target:
        drive = target[target.rfind("(") + 1 : target.rfind(":)") + 1]
    if not drive:
        return None
    root = os.path.join(drive + "\\", "WindowsImageBackup")
    if not os.path.isdir(root):
        return None
    # Look for any "Backup YYYY-MM-DD..." subfolder matching the date
    # half of backup_time. The wbadmin time format is "M/D/YYYY h:MM AM/PM".
    total = 0
    try:
        for machine_dir in os.listdir(root):
            machine_path = os.path.join(root, machine_dir)
            if not os.path.isdir(machine_path):
                continue
            for sub in os.listdir(machine_path):
                if not sub.lower().startswith("backup "):
                    continue
                # We don't try to match exact dates -- just sum every
                # Backup folder under each machine and let the size be
                # cumulative-across-versions (an honest approximation
                # since wbadmin uses VSS-style incremental storage
                # where snapshots share blocks).
                full = os.path.join(machine_path, sub)
                for dirpath, _dirs, files in os.walk(full):
                    for name in files:
                        try:
                            total += os.path.getsize(os.path.join(dirpath, name))
                        except OSError:
                            continue
    except OSError:
        return None
    return total if total > 0 else None


# ── Action handlers ─────────────────────────────────────────────────


def _action_scan_catalog(params: dict) -> dict:
    """Run wbadmin get versions, parse, probe sizes, write cache."""
    run = _run(["wbadmin.exe", "get", "versions"], timeout=120)
    if run["returncode"] != 0:
        return {
            "ok": False,
            "error": f"wbadmin returncode={run['returncode']}: {run['stderr_tail']}",
            "run": run,
        }
    versions = bk.parse_wbadmin_versions(run["stdout"])
    if not versions:
        # Could be a clean "no backups" result OR a parse fail. Either
        # way we write an empty cache and let the user see the empty
        # state.
        cache = {
            "scanned_at": _now_iso(),
            "versions": [],
            "total_size_bytes": 0,
        }
        bk._atomic_write_json(bk.WINDOWS_BACKUP_CACHE_FILE, cache)  # noqa: SLF001
        return {"ok": True, "version_count": 0, "total_size_bytes": 0, "run": run}

    # Best-effort size probe on the first version's target -- they all
    # share the target drive so one probe gives us a cumulative number.
    total = _probe_backup_size(versions[0]["target"], versions[0]["backup_time"])
    cache = {
        "scanned_at": _now_iso(),
        "versions": versions,
        "total_size_bytes": total,
    }
    if not bk._atomic_write_json(bk.WINDOWS_BACKUP_CACHE_FILE, cache):  # noqa: SLF001
        return {"ok": False, "error": "failed to write backup_cache.json", "run": run}
    return {
        "ok": True,
        "version_count": len(versions),
        "total_size_bytes": total,
        "run": run,
    }


def _action_delete_version(params: dict) -> dict:
    """wbadmin delete backup -version:<id> -quiet, but only after the
    safety validators pass."""
    version_id = (params or {}).get("version_id", "")
    # Re-validate inside the helper too (defence in depth -- never trust
    # the request file alone since it could in principle be tampered
    # between write and execute even though APP_DIR is user-owned).
    cache = bk.load_windows_backup_cache()
    ok, err = bk.validate_delete_version_request(version_id, cache.get("versions") or [])
    if not ok:
        return {"ok": False, "error": err, "validator": "delete_version"}
    # Capture size before so we can report bytes freed.
    before = cache.get("total_size_bytes") or 0
    run = _run(
        ["wbadmin.exe", "delete", "backup", f"-version:{version_id}", "-quiet"],
        timeout=600,
    )
    if run["returncode"] != 0:
        return {
            "ok": False,
            "error": f"wbadmin delete returncode={run['returncode']}: {run['stderr_tail']}",
            "run": run,
        }
    # Re-scan to refresh cache + estimate bytes freed.
    rescan = _action_scan_catalog({})
    after = (rescan.get("total_size_bytes") if rescan.get("ok") else None) or 0
    freed = max(0, before - after) if before and after else None
    return {
        "ok": True,
        "deleted_version_id": version_id,
        "bytes_freed_estimate": freed,
        "version_count_after": rescan.get("version_count"),
        "run": run,
    }


def _action_fh_cleanup(params: dict) -> dict:
    """fhmanagew.exe -cleanup <days>."""
    days = (params or {}).get("days")
    ok, err = bk.validate_fh_cleanup_request(days)
    if not ok:
        return {"ok": False, "error": err, "validator": "fh_cleanup"}
    run = _run(["fhmanagew.exe", "-cleanup", str(days), "-quiet"], timeout=600)
    # fhmanagew returns non-zero in some "nothing to clean" cases; treat
    # any non-zero with empty stderr as a soft warning rather than a
    # hard failure, but surface stderr if it's non-empty.
    if run["returncode"] != 0 and (run["stderr"] or "").strip():
        return {"ok": False, "error": f"fhmanagew failed: {run['stderr_tail']}", "run": run}
    return {"ok": True, "days": days, "run": run}


_ACTION_HANDLERS = {
    "scan_catalog": _action_scan_catalog,
    "delete_version": _action_delete_version,
    "fh_cleanup": _action_fh_cleanup,
}


# ── Entry point ─────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--request", required=True, help="Path to the request JSON file written by the unelevated tray."
    )
    args = parser.parse_args(argv)

    try:
        with open(args.request, encoding="utf-8") as f:
            request = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        # Without a valid request we can't even write a result file in
        # the right place. Best we can do is exit non-zero.
        print(f"FATAL: cannot read request file: {e}", file=sys.stderr)
        return 2

    session_id = request.get("session_id") or ""
    action = request.get("action") or ""
    params = request.get("params") or {}
    started_at = _now_iso()

    if not session_id or action not in _ACTION_HANDLERS:
        result_payload = {
            "ok": False,
            "error": f"invalid request: session_id={session_id!r}, action={action!r}",
            "session_id": session_id,
            "started_at": started_at,
            "ended_at": _now_iso(),
        }
    else:
        handler = _ACTION_HANDLERS[action]
        try:
            result_payload = handler(params)
        except Exception as e:  # noqa: BLE001 -- catch-all: helper must always exit cleanly
            result_payload = {
                "ok": False,
                "error": f"handler crashed: {type(e).__name__}: {e}",
            }
        result_payload["session_id"] = session_id
        result_payload["action"] = action
        result_payload["params"] = params
        result_payload["started_at"] = started_at
        result_payload["ended_at"] = _now_iso()

    # Audit log -- both successes and failures get a row.
    history_entry = {
        "session_id": session_id,
        "action": action,
        "params": params,
        "started_at": started_at,
        "ended_at": result_payload.get("ended_at", _now_iso()),
        "status": "completed" if result_payload.get("ok") else "failed",
        "returncode": (result_payload.get("run") or {}).get("returncode"),
        "stdout_tail": (result_payload.get("run") or {}).get("stdout_tail", ""),
        "stderr_tail": (result_payload.get("run") or {}).get("stderr_tail", ""),
        "bytes_freed_estimate": result_payload.get("bytes_freed_estimate"),
        "error": result_payload.get("error"),
    }
    bk.append_action_history(history_entry)

    # Strip the big stdout/stderr from the result payload before writing
    # -- the audit log captures the tail; the result file just needs the
    # outcome flag + summary so the unelevated route can render it.
    if "run" in result_payload and isinstance(result_payload["run"], dict):
        result_payload["run"].pop("stdout", None)
        result_payload["run"].pop("stderr", None)

    result_path = os.path.join(APP_DIR, bk._RESULT_FILE_TPL.format(session=session_id))  # noqa: SLF001
    _atomic_write(result_path, result_payload)

    # Best-effort cleanup of the request file -- we've consumed it.
    try:
        os.remove(args.request)
    except OSError:
        pass

    return 0 if result_payload.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
