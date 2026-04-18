"""bios_audit.py -- BIOS & firmware settings change audit trail.

Captures a periodic snapshot of BIOS-adjacent system settings and logs
any detected changes to an append-only history store. Triggered from the
tray polling loop (throttled to one snapshot every 15 minutes).

Snapshot fields:
- BIOS version, release date, manufacturer, serial number (via Win32_BIOS)
- Baseboard product + manufacturer
- Secure Boot state (Confirm-SecureBootUEFI)
- TPM presence + enabled + ready + manufacturer version (Get-Tpm)
- Boot mode -- UEFI vs Legacy (PEFirmwareType registry value)
- VBS / HVCI / Credential Guard state (Win32_DeviceGuard)

Persistence: ``bios_audit_history.json`` in repo root. Append-only,
capped at 500 entries. Lock-guarded for concurrent-reader safety.

Public API:
    take_snapshot()           -- capture one snapshot dict
    diff_snapshots(old, new)  -- flat change list
    load_history()            -- full list from disk
    latest_snapshot()         -- most recent snapshot dict or None
    check_and_log_bios_changes()  -- main tray-loop entry point
    recent_changes(window)    -- change entries in last N hours
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bios_audit_history.json")
MAX_HISTORY = 500
SNAPSHOT_INTERVAL = timedelta(minutes=15)
CHANGE_ALERT_WINDOW = timedelta(hours=24)

_history_lock = threading.RLock()


# ── Security-state capture helpers ─────────────────────────────────


def _run_ps(command: str, timeout: int = 10) -> str:
    """Run a short PowerShell one-liner, return stdout.strip() or ''.

    All errors swallowed -- callers must tolerate empty string.
    """
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode == 0:
            return (r.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return ""


def _get_secure_boot_state() -> str | None:
    """Return 'enabled', 'disabled', or None (unsupported / Legacy BIOS)."""
    out = _run_ps("try { Confirm-SecureBootUEFI } catch { 'unsupported' }").lower()
    if out == "true":
        return "enabled"
    if out == "false":
        return "disabled"
    if out == "unsupported":
        return "unsupported"
    return None


def _get_tpm_state() -> dict:
    """Return {present, enabled, ready, version}. Any field may be None."""
    raw = _run_ps("Get-Tpm | ConvertTo-Json -Depth 2")
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {
        "present": data.get("TpmPresent"),
        "enabled": data.get("TpmEnabled"),
        "ready": data.get("TpmReady"),
        "version": data.get("ManufacturerVersion"),
    }


def _get_boot_mode() -> str | None:
    """Return 'UEFI', 'Legacy', or None.

    PEFirmwareType in HKLM\\SYSTEM\\CurrentControlSet\\Control:
        1 = Legacy BIOS, 2 = UEFI.
    """
    out = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control').PEFirmwareType")
    if out == "2":
        return "UEFI"
    if out == "1":
        return "Legacy"
    return None


def _get_vbs_state() -> dict:
    """Virtualization-Based Security / HVCI / Credential Guard state."""
    raw = _run_ps(
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard | "
        "ConvertTo-Json -Depth 2",
        timeout=15,
    )
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    vbs_map = {0: "off", 1: "configured_not_running", 2: "running"}
    services = data.get("SecurityServicesRunning") or []
    if not isinstance(services, list):
        services = [services]
    return {
        "vbs_status": vbs_map.get(data.get("VirtualizationBasedSecurityStatus")),
        "hvci_running": 2 in services if services else None,
        "cred_guard_running": 1 in services if services else None,
    }


def _get_bios_serial() -> str | None:
    """SerialNumber from Win32_BIOS -- not exposed by get_current_bios()."""
    out = _run_ps("(Get-CimInstance Win32_BIOS).SerialNumber")
    return out or None


# ── Snapshot ───────────────────────────────────────────────────────


def take_snapshot(bios_reader: Callable[[], dict] | None = None) -> dict:
    """Capture a full BIOS + security snapshot.

    bios_reader: callable returning a dict shaped like
        windesktopmgr.get_current_bios() (BIOSVersion, ReleaseDate,
        Manufacturer, BoardProduct, BoardMfr, BIOSDateFormatted). Optional
        for testability; the default imports windesktopmgr lazily.
    """
    if bios_reader is None:
        # Lazy import: avoids circular dep and keeps tests simple
        from windesktopmgr import get_current_bios

        bios_reader = get_current_bios

    try:
        bios = bios_reader() or {}
    except Exception:  # noqa: BLE001
        bios = {}

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "bios_version": bios.get("BIOSVersion"),
        "bios_release_date": bios.get("BIOSDateFormatted") or bios.get("ReleaseDate"),
        "bios_manufacturer": bios.get("Manufacturer"),
        "bios_serial": _get_bios_serial(),
        "board_product": bios.get("BoardProduct"),
        "board_manufacturer": bios.get("BoardMfr"),
        "secure_boot": _get_secure_boot_state(),
        "tpm": _get_tpm_state(),
        "boot_mode": _get_boot_mode(),
        "vbs": _get_vbs_state(),
    }


# ── Diff ───────────────────────────────────────────────────────────

_IGNORE_KEYS = frozenset({"timestamp"})


def _flatten(d: dict, prefix: str = "") -> dict:
    """Flatten one level of nesting: {'tpm': {'enabled': True}} -> {'tpm.enabled': True}."""
    out: dict = {}
    if not isinstance(d, dict):
        return out
    for k, v in d.items():
        if k in _IGNORE_KEYS:
            continue
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=f"{key}."))
        else:
            out[key] = v
    return out


def diff_snapshots(old: dict, new: dict) -> list[dict]:
    """Return list of {field, old, new} for each changed field. Empty if none.

    Returns [] for a first-run (old is falsy) since there is no baseline.
    """
    if not old:
        return []
    old_flat = _flatten(old)
    new_flat = _flatten(new)
    changes = []
    for key in sorted(old_flat.keys() | new_flat.keys()):
        if old_flat.get(key) != new_flat.get(key):
            changes.append({"field": key, "old": old_flat.get(key), "new": new_flat.get(key)})
    return changes


# ── History persistence ────────────────────────────────────────────


def load_history() -> list:
    """Read history from disk. Returns [] on any error or missing file."""
    with _history_lock:
        try:
            if not os.path.exists(HISTORY_FILE):
                return []
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []


def _append_history(entry: dict) -> bool:
    """Append one entry atomically. Returns True on success."""
    with _history_lock:
        history = load_history()
        history.append(entry)
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]
        tmp = HISTORY_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            os.replace(tmp, HISTORY_FILE)
            return True
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False


def latest_snapshot() -> dict | None:
    """Return the most recent snapshot dict embedded in history, or None."""
    for entry in reversed(load_history()):
        snap = entry.get("snapshot") if isinstance(entry, dict) else None
        if snap:
            return snap
    return None


def _last_entry_age() -> timedelta | None:
    """Wall-clock age of the last history entry, or None if empty/invalid."""
    history = load_history()
    if not history:
        return None
    last = history[-1]
    try:
        ts = datetime.fromisoformat(last.get("timestamp", ""))
    except (ValueError, TypeError):
        return None
    return datetime.now() - ts


# ── Main entry point ───────────────────────────────────────────────


def check_and_log_bios_changes(
    bios_reader: Callable[[], dict] | None = None,
    force: bool = False,
) -> dict:
    """Take a snapshot and log any change vs the previous snapshot.

    Throttled: returns early (without running the PS calls) if the last
    snapshot is newer than SNAPSHOT_INTERVAL, unless ``force=True``.

    Return shape:
        {
            "ok": bool,
            "skipped": bool,            # true when throttled
            "first_run": bool,          # true on the very first run
            "snapshot": dict | None,
            "changes": list[dict],
        }
    """
    if not force:
        age = _last_entry_age()
        if age is not None and age < SNAPSHOT_INTERVAL:
            return {"ok": True, "skipped": True, "first_run": False, "snapshot": None, "changes": []}

    try:
        snapshot = take_snapshot(bios_reader=bios_reader)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "skipped": False,
            "first_run": False,
            "snapshot": None,
            "changes": [],
            "error": str(e),
        }

    previous = latest_snapshot()
    first_run = previous is None
    changes = diff_snapshots(previous or {}, snapshot)

    if first_run:
        _append_history(
            {
                "kind": "baseline",
                "timestamp": snapshot["timestamp"],
                "snapshot": snapshot,
                "note": "initial snapshot -- no baseline to diff against",
            }
        )
    elif changes:
        _append_history(
            {
                "kind": "change",
                "timestamp": snapshot["timestamp"],
                "changes": changes,
                "snapshot": snapshot,
            }
        )
    # If no changes and not first run, we deliberately don't append --
    # avoids file bloat with identical snapshots every 15 minutes.

    return {
        "ok": True,
        "skipped": False,
        "first_run": first_run,
        "snapshot": snapshot,
        "changes": changes,
    }


# ── Dashboard / UI helper ──────────────────────────────────────────


def recent_changes(window: timedelta = CHANGE_ALERT_WINDOW) -> list:
    """Return change entries from the last <window> hours (default 24)."""
    history = load_history()
    cutoff = datetime.now() - window
    out = []
    for entry in history:
        if not isinstance(entry, dict) or entry.get("kind") != "change":
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        if ts >= cutoff:
            out.append(entry)
    return out
