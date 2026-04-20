"""bios_audit.py -- BIOS & firmware settings change audit trail.

Captures a periodic snapshot of BIOS-adjacent system settings and logs
any detected changes to an append-only history store.

Two collection contexts, each with its own snapshot cadence:

- ``context="user"`` -- tray polling loop, every 15 min. Captures fields
  readable from a standard-user process: BIOS/Baseboard metadata,
  serial number, VBS/HVCI/Credential Guard state.
- ``context="elevated"`` -- SystemHealthDiag scheduled task, daily.
  Runs as admin so it can additionally capture TPM detail
  (Get-Tpm), Secure Boot state (Confirm-SecureBootUEFI), and Boot Mode
  (PEFirmwareType registry).

Each history entry carries its own ``context`` tag. Diffs compare against
the previous snapshot of the **same** context -- so a field that returns
None in the user context (because the cmdlet needs admin) does not
produce a spurious "null -> value" change when the elevated context
fills it in later.

Persistence: ``bios_audit_history.json`` in repo root. Append-only,
capped at 500 entries. Lock-guarded for concurrent-reader safety.

Public API:
    take_snapshot(context=...)    -- capture one snapshot dict
    diff_snapshots(old, new)      -- flat change list
    load_history()                -- full list from disk
    latest_snapshot(context=...)  -- most recent snapshot dict or None
    check_and_log_bios_changes(context=...)  -- main entry point
    recent_changes(window)        -- change entries in last N hours
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import NamedTuple

try:
    from applogging import get_logger

    _log = get_logger("bios_audit")
except Exception:  # noqa: BLE001  -- logger is best-effort, never fatal
    import logging

    _log = logging.getLogger("windesktopmgr.bios_audit")

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bios_audit_history.json")
MAX_HISTORY = 500
SNAPSHOT_INTERVAL = timedelta(minutes=15)
CHANGE_ALERT_WINDOW = timedelta(hours=24)
ERROR_ALERT_WINDOW = timedelta(hours=24)

_history_lock = threading.RLock()


# ── Security-state capture helpers ─────────────────────────────────


class PSResult(NamedTuple):
    """Outcome of a single PowerShell subprocess call.

    ``ok=True`` means the command ran and exited 0; ``stdout`` is the
    trimmed captured output. ``ok=False`` means the call failed for
    *any* reason -- timeout, non-zero exit, process-launch error --
    and ``error`` carries a short human-readable description so the
    caller can flag rather than silently swallow.
    """

    ok: bool
    stdout: str
    error: str | None


def _run_ps(command: str, timeout: int = 10) -> PSResult:
    """Run a short PowerShell one-liner and return a PSResult.

    Previously returned bare ``str`` and lost all error context, which
    meant a transient PS failure (timeout, WMI hiccup) was recorded as
    an empty snapshot value and flagged as a "change" against the
    previous successful snapshot. Callers now get an explicit
    ok/error signal and decide whether to omit the field vs. treat the
    empty result as a real value.
    """
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PSResult(False, "", f"timeout after {timeout}s")
    except OSError as e:
        return PSResult(False, "", f"OSError: {e}")
    except ValueError as e:
        return PSResult(False, "", f"ValueError: {e}")

    if r.returncode != 0:
        err = (r.stderr or "").strip().splitlines()[:1]
        err_line = err[0] if err else f"returncode={r.returncode}"
        return PSResult(False, "", err_line[:200])

    return PSResult(True, (r.stdout or "").strip(), None)


# Each _get_* helper now returns (value, error_or_None). On success
# error is None. On failure value is None AND error describes why,
# so take_snapshot can omit the field and record the reason.


def _get_secure_boot_state() -> tuple[str | None, str | None]:
    res = _run_ps("try { Confirm-SecureBootUEFI } catch { 'unsupported' }")
    if not res.ok:
        return None, res.error
    out = res.stdout.lower()
    if out == "true":
        return "enabled", None
    if out == "false":
        return "disabled", None
    if out == "unsupported":
        return "unsupported", None
    return None, None  # empty stdout -- treat as no-signal, not error


def _get_tpm_state() -> tuple[dict | None, str | None]:
    """Return ({present, enabled, ready, version}, error_or_None)."""
    res = _run_ps("Get-Tpm | ConvertTo-Json -Depth 2")
    if not res.ok:
        return None, res.error
    try:
        data = json.loads(res.stdout) if res.stdout else {}
    except json.JSONDecodeError as e:
        return None, f"json decode: {e}"
    if not isinstance(data, dict):
        return None, "unexpected shape (not a JSON object)"
    return {
        "present": data.get("TpmPresent"),
        "enabled": data.get("TpmEnabled"),
        "ready": data.get("TpmReady"),
        "version": data.get("ManufacturerVersion"),
    }, None


def _get_boot_mode() -> tuple[str | None, str | None]:
    """Return ('UEFI'|'Legacy'|None, error_or_None).

    PEFirmwareType in HKLM\\SYSTEM\\CurrentControlSet\\Control:
        1 = Legacy BIOS, 2 = UEFI.
    """
    res = _run_ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control').PEFirmwareType")
    if not res.ok:
        return None, res.error
    if res.stdout == "2":
        return "UEFI", None
    if res.stdout == "1":
        return "Legacy", None
    return None, None


def _get_vbs_state() -> tuple[dict | None, str | None]:
    """Virtualization-Based Security / HVCI / Credential Guard state."""
    res = _run_ps(
        "Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard | "
        "ConvertTo-Json -Depth 2",
        timeout=15,
    )
    if not res.ok:
        return None, res.error
    try:
        data = json.loads(res.stdout) if res.stdout else {}
    except json.JSONDecodeError as e:
        return None, f"json decode: {e}"
    if not isinstance(data, dict):
        return None, "unexpected shape (not a JSON object)"
    vbs_map = {0: "off", 1: "configured_not_running", 2: "running"}
    services = data.get("SecurityServicesRunning") or []
    if not isinstance(services, list):
        services = [services]
    return {
        "vbs_status": vbs_map.get(data.get("VirtualizationBasedSecurityStatus")),
        "hvci_running": 2 in services if services else None,
        "cred_guard_running": 1 in services if services else None,
    }, None


def _get_bios_serial() -> tuple[str | None, str | None]:
    """SerialNumber from Win32_BIOS -- not exposed by get_current_bios()."""
    res = _run_ps("(Get-CimInstance Win32_BIOS).SerialNumber")
    if not res.ok:
        return None, res.error
    return (res.stdout or None), None


# ── Snapshot ───────────────────────────────────────────────────────

USER_CONTEXT = "user"
ELEVATED_CONTEXT = "elevated"
_VALID_CONTEXTS = frozenset({USER_CONTEXT, ELEVATED_CONTEXT})

# Fields that require admin context -- collected only when context=elevated.
# In the user-context snapshot these keys are absent (not None) so the diff
# logic does not flag them when they appear in the elevated snapshot.
_ELEVATED_ONLY_FIELDS = frozenset({"secure_boot", "tpm", "boot_mode"})


def take_snapshot(
    bios_reader: Callable[[], dict] | None = None,
    context: str = USER_CONTEXT,
) -> dict:
    """Capture a BIOS + security snapshot.

    context: ``"user"`` (default) or ``"elevated"``. In ``"user"`` context
        the admin-gated fields (Secure Boot, TPM detail, Boot Mode) are
        omitted from the returned dict so they do not appear to "appear"
        later when the elevated collector runs.
    bios_reader: callable returning a dict shaped like
        windesktopmgr.get_current_bios() (BIOSVersion, ReleaseDate,
        Manufacturer, BoardProduct, BoardMfr, BIOSDateFormatted). Optional
        for testability; the default imports windesktopmgr lazily.
    """
    if context not in _VALID_CONTEXTS:
        raise ValueError(f"context must be one of {sorted(_VALID_CONTEXTS)}")

    if bios_reader is None:
        # Lazy import: avoids circular dep and keeps tests simple
        from windesktopmgr import get_current_bios

        bios_reader = get_current_bios

    errors: list[dict] = []

    try:
        bios = bios_reader() or {}
    except Exception as e:  # noqa: BLE001
        errors.append({"field": "bios_reader", "error": f"{type(e).__name__}: {e}"})
        bios = {}

    snap: dict = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "context": context,
    }

    # Fields sourced from bios_reader() (windesktopmgr.get_current_bios).
    # Omit any that came back empty -- a missing key is "no signal",
    # whereas storing None would diff against a previous real value and
    # fire a false-positive change log next cycle.
    _maybe_set(snap, "bios_version", bios.get("BIOSVersion"))
    _maybe_set(
        snap,
        "bios_release_date",
        bios.get("BIOSDateFormatted") or bios.get("ReleaseDate"),
    )
    _maybe_set(snap, "bios_manufacturer", bios.get("Manufacturer"))
    _maybe_set(snap, "board_product", bios.get("BoardProduct"))
    _maybe_set(snap, "board_manufacturer", bios.get("BoardMfr"))

    serial, err = _get_bios_serial()
    if err:
        errors.append({"field": "bios_serial", "error": err})
    else:
        _maybe_set(snap, "bios_serial", serial)

    vbs, err = _get_vbs_state()
    if err:
        errors.append({"field": "vbs", "error": err})
    elif vbs:
        snap["vbs"] = vbs

    if context == ELEVATED_CONTEXT:
        sb, err = _get_secure_boot_state()
        if err:
            errors.append({"field": "secure_boot", "error": err})
        else:
            _maybe_set(snap, "secure_boot", sb)

        tpm, err = _get_tpm_state()
        if err:
            errors.append({"field": "tpm", "error": err})
        elif tpm:
            snap["tpm"] = tpm

        bm, err = _get_boot_mode()
        if err:
            errors.append({"field": "boot_mode", "error": err})
        else:
            _maybe_set(snap, "boot_mode", bm)

    if errors:
        # Log every collection error at WARNING so it surfaces in the
        # Logs tab, then attach the list to the snapshot so the audit
        # endpoint + dashboard concern can surface it too.
        for e in errors:
            _log.warning(
                "bios_audit collection failed for field=%s context=%s: %s",
                e["field"],
                context,
                e["error"],
            )
        snap["_collection_errors"] = errors

    return snap


def _maybe_set(snap: dict, key: str, value) -> None:
    """Set snap[key]=value only if value is truthy-or-False-but-not-None.

    False/0 are legitimate values (e.g. vbs.hvci_running=False), so we
    discriminate only on None and empty-string-ish. Missing keys in a
    snapshot mean "no signal" to the diff logic.
    """
    if value is None:
        return
    if isinstance(value, str) and not value.strip():
        return
    snap[key] = value


# ── Diff ───────────────────────────────────────────────────────────

# Keys that carry metadata about the snapshot itself, not BIOS/security
# state. Skipped by _flatten so they can never appear as a diff entry.
_IGNORE_KEYS = frozenset({"timestamp", "context", "_collection_errors"})


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

    Only fires a change when *both* old and new have a real value that
    differs. A missing key, or a key whose value is None on either
    side, is treated as "no signal" -- we don't know the current or
    prior state, so we can't claim a change happened. This is what
    stops a transient PowerShell failure (previously recorded as a
    null value) from spawning two spurious "change" entries: one when
    the read fails, and the mirror entry when it recovers.
    """
    if not old:
        return []
    old_flat = _flatten(old)
    new_flat = _flatten(new)
    changes = []
    for key in sorted(old_flat.keys() | new_flat.keys()):
        o = old_flat.get(key)
        n = new_flat.get(key)
        if o is None or n is None:
            continue
        if o != n:
            changes.append({"field": key, "old": o, "new": n})
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


def latest_snapshot(context: str | None = None) -> dict | None:
    """Return the most recent snapshot dict embedded in history, or None.

    If ``context`` is given, only returns snapshots tagged with that context.
    If omitted, returns the most recent snapshot regardless of context
    (used by the /api/bios/audit/snapshot route to show "what we know").
    """
    for entry in reversed(load_history()):
        if not isinstance(entry, dict):
            continue
        snap = entry.get("snapshot")
        if not snap:
            continue
        if context is None or entry.get("context") == context:
            return snap
    return None


def _last_entry_age(context: str | None = None) -> timedelta | None:
    """Wall-clock age of the last entry, optionally filtered by context."""
    history = load_history()
    for entry in reversed(history):
        if not isinstance(entry, dict):
            continue
        if context is not None and entry.get("context") != context:
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        return datetime.now() - ts
    return None


# ── Main entry point ───────────────────────────────────────────────


def check_and_log_bios_changes(
    bios_reader: Callable[[], dict] | None = None,
    force: bool = False,
    context: str = USER_CONTEXT,
) -> dict:
    """Take a snapshot and log any change vs the previous snapshot of
    the same ``context``.

    Throttled per-context: returns early (without running the PS calls)
    if the last snapshot of this context is newer than SNAPSHOT_INTERVAL,
    unless ``force=True``.

    Return shape:
        {
            "ok": bool,
            "skipped": bool,            # true when throttled
            "first_run": bool,          # true on the very first run for this context
            "context": str,
            "snapshot": dict | None,
            "changes": list[dict],
        }
    """
    if context not in _VALID_CONTEXTS:
        raise ValueError(f"context must be one of {sorted(_VALID_CONTEXTS)}")

    if not force:
        age = _last_entry_age(context=context)
        if age is not None and age < SNAPSHOT_INTERVAL:
            return {
                "ok": True,
                "skipped": True,
                "first_run": False,
                "context": context,
                "snapshot": None,
                "changes": [],
            }

    try:
        snapshot = take_snapshot(bios_reader=bios_reader, context=context)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "skipped": False,
            "first_run": False,
            "context": context,
            "snapshot": None,
            "changes": [],
            "error": str(e),
        }

    previous = latest_snapshot(context=context)
    first_run = previous is None
    changes = diff_snapshots(previous or {}, snapshot)
    collection_errors = snapshot.get("_collection_errors") or []

    if first_run:
        _append_history(
            {
                "kind": "baseline",
                "context": context,
                "timestamp": snapshot["timestamp"],
                "snapshot": snapshot,
                "note": f"initial {context}-context snapshot -- no baseline to diff against",
            }
        )
    elif changes:
        _append_history(
            {
                "kind": "change",
                "context": context,
                "timestamp": snapshot["timestamp"],
                "changes": changes,
                "snapshot": snapshot,
            }
        )
    elif collection_errors:
        # No change to log, but the snapshot had collection failures --
        # persist an "error" entry so the dashboard / audit endpoint
        # can see that a polling cycle came back partial. Without this
        # branch the errors would only exist in the app log and vanish
        # from the user-facing audit trail.
        _append_history(
            {
                "kind": "error",
                "context": context,
                "timestamp": snapshot["timestamp"],
                "errors": collection_errors,
            }
        )
    # If no changes, no errors, and not first run, we deliberately
    # don't append -- avoids file bloat with identical snapshots every
    # 15 minutes.

    return {
        "ok": True,
        "skipped": False,
        "first_run": first_run,
        "context": context,
        "snapshot": snapshot,
        "changes": changes,
        "errors": collection_errors,
    }


# ── Dashboard / UI helper ──────────────────────────────────────────


def is_phantom_change_entry(entry: dict) -> bool:
    """Decide whether a change entry is a historical false positive.

    Before the 2026-04-20 fix, a transient PowerShell failure recorded
    fields as None in the snapshot; the next cycle (successful or also
    failed) then diffed None against the previous real value and wrote
    a ``kind="change"`` entry. One outage produced TWO of these: one
    value->None when the read failed, one None->value when it
    recovered.

    A phantom entry is recognised by a simple shape: *every* change
    inside it has None on at least one side. A legitimate change
    flipping from value-A to value-B would have None on neither side,
    so this check is conservative -- it only suppresses entries that
    could not possibly represent a real, observable transition.

    Returns False for anything that isn't a well-formed change entry.
    """
    if not isinstance(entry, dict) or entry.get("kind") != "change":
        return False
    changes = entry.get("changes")
    if not isinstance(changes, list) or not changes:
        return False
    for c in changes:
        if not isinstance(c, dict):
            return False
        if c.get("old") is not None and c.get("new") is not None:
            return False
    return True


def recent_changes(
    window: timedelta = CHANGE_ALERT_WINDOW,
    include_phantoms: bool = False,
) -> list:
    """Return change entries from the last <window> hours (default 24).

    By default, phantom entries (historical null-vs-value flickers from
    the pre-fix era -- see ``is_phantom_change_entry``) are filtered
    out so the dashboard concern and UI don't keep surfacing them.
    Pass ``include_phantoms=True`` for debugging / audit completeness.
    """
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
        if ts < cutoff:
            continue
        if not include_phantoms and is_phantom_change_entry(entry):
            continue
        out.append(entry)
    return out


def recent_errors(window: timedelta = ERROR_ALERT_WINDOW) -> list:
    """Return collection-error entries from the last <window> hours.

    Used by the dashboard concern to flag "some BIOS/security state
    fields could not be read recently" -- we want this visible so a
    systemic WMI outage or permission regression doesn't hide behind
    silent None values.

    Includes errors attached to change/baseline snapshots as well as
    standalone kind="error" entries, since any of them represent a
    polling cycle that came back partial.
    """
    history = load_history()
    cutoff = datetime.now() - window
    out: list = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        errs = entry.get("errors")
        if errs:
            out.append(entry)
            continue
        snap = entry.get("snapshot") or {}
        if isinstance(snap, dict) and snap.get("_collection_errors"):
            # Normalise to the same shape as kind="error" entries so
            # dashboard renderers can iterate uniformly.
            out.append(
                {
                    "kind": entry.get("kind"),
                    "context": entry.get("context"),
                    "timestamp": entry.get("timestamp"),
                    "errors": snap["_collection_errors"],
                }
            )
    return out
