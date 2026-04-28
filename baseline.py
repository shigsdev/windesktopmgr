"""baseline.py -- System baseline / drift-detection for WinDesktopMgr (backlog #14).

Captures a snapshot of three security-relevant system surfaces -- startup
items, Windows services, scheduled tasks -- lets the user accept a known-
good snapshot as the baseline, and surfaces any subsequent drift
(additions, removals, changes) as dashboard concerns until the user
either fixes the drift or accepts the new state as the updated baseline.

Design mirrors ``bios_audit.py``:

- Append-only JSON history (``baseline_history.json``) of every diff
  detected, bounded at ``MAX_HISTORY`` entries.
- Separate ``baseline_snapshot.json`` holds the currently-accepted
  baseline. Overwritten only on explicit user acceptance.
- Lock-guarded + atomic-write on both files so concurrent readers
  (dashboard summary fan-out + UI polls) can never see a half-written
  state.
- Category collectors are Python-first where possible:
    * services  -> psutil.win_service_iter() (no subprocess)
    * tasks     -> schtasks /query /fo CSV (no Python binding exists
                   that covers all task fields; keep as subprocess)
    * startup   -> reuses windesktopmgr.get_startup_items() (lazy
                   import to avoid circular dep)

Public API:
    take_snapshot()               -- build a full current-state snapshot
    load_baseline()               -- read accepted baseline (None if none)
    accept_current_as_baseline()  -- atomic write of current -> baseline
    diff_snapshots(old, new)      -- categorised add/remove/change list
    compute_drift()               -- current vs accepted baseline
    record_drift_if_any()         -- append a history entry when drift > 0
    recent_drift(window)          -- history entries in last N hours
    load_history()                -- raw history list (for API/tests)
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Any

try:
    from applogging import get_logger

    _log = get_logger("baseline")
except Exception:  # noqa: BLE001
    import logging

    _log = logging.getLogger("windesktopmgr.baseline")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(APP_DIR, "baseline_snapshot.json")
HISTORY_FILE = os.path.join(APP_DIR, "baseline_history.json")

MAX_HISTORY = 500
DRIFT_ALERT_WINDOW = timedelta(hours=24)

_file_lock = threading.RLock()


# ══════════════════════════════════════════════════════════════════════
# CATEGORY COLLECTORS
# ══════════════════════════════════════════════════════════════════════


def _collect_startup() -> dict:
    """Enumerate startup items via the existing get_startup_items() helper.

    Returns a dict keyed by ``<Location>:<Name>`` so two different items
    with the same display name in different locations (common for HKLM+
    HKCU Run) don't collapse. Each value carries the fields we want to
    diff against: command (image path), enabled, type.
    """
    try:
        # Lazy import -- get_startup_items lives in windesktopmgr.py which
        # imports a lot of heavy stuff; avoid pulling it in at module load.
        from windesktopmgr import get_startup_items

        items = get_startup_items() or []
    except Exception as e:  # noqa: BLE001 -- best-effort; caller handles {} as "unavailable"
        _log.warning("startup enumeration failed: %s", e)
        return {}

    by_key: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or ""
        location = item.get("Location") or ""
        if not name:
            continue
        key = f"{location}::{name}"
        by_key[key] = {
            "name": name,
            "location": location,
            "command": item.get("Command") or "",
            "type": item.get("Type") or "",
            "enabled": bool(item.get("Enabled", True)),
        }
    return by_key


def _collect_services_wmi_enrichment() -> dict:
    """Per-service WMI enrichment -- the fields psutil doesn't expose.

    Returns ``{service_name: {field: value, ...}}`` for these extra fields:
      - service_type   (Own Process / Share Process / Kernel Driver / ...)
      - error_control  (Ignore / Normal / Severe / Critical)
      - delayed_auto_start  (bool -- covert-persistence evasion pattern)
      - desktop_interact    (bool -- highly suspicious on modern Windows)
      - tag_id          (load order within service group)
      - started         (bool -- running flag; context-only)

    WMI.Win32_Service() is one round-trip for all services (~1-2 s on
    this box) so even 327 services enrich in a single query. On failure
    (WMI COM fault, insufficient rights) returns {} and the psutil path
    keeps working without enrichment.
    """
    try:
        import wmi
    except ImportError:
        _log.warning("wmi package not installed -- service enrichment skipped")
        return {}

    try:
        c = wmi.WMI()
        services = c.Win32_Service()
    except Exception as e:  # noqa: BLE001 -- WMI can fault on Win32_Service for many reasons
        _log.warning("WMI Win32_Service enumeration failed: %s", e)
        return {}

    out: dict[str, dict] = {}
    for s in services:
        try:
            name = s.Name
            if not name:
                continue
            out[name] = {
                "service_type": s.ServiceType or "",
                "error_control": s.ErrorControl or "",
                "delayed_auto_start": bool(s.DelayedAutoStart) if s.DelayedAutoStart is not None else False,
                "desktop_interact": bool(s.DesktopInteract) if s.DesktopInteract is not None else False,
                "tag_id": str(s.TagId) if s.TagId is not None else "",
                "started": bool(s.Started) if s.Started is not None else False,
            }
        except Exception:  # noqa: BLE001 -- skip unreadable rows
            continue
    return out


def _collect_services() -> dict:
    """Enumerate Windows services via psutil + WMI.

    psutil is the fast iteration path (in-process, ~100 ms) and covers
    name / display_name / status / start_type / username / image_path /
    description. WMI enrichment adds service_type, error_control, delayed
    auto-start, desktop_interact, tag_id, started -- fields the security
    baseline cares about that psutil can't reach.
    """
    try:
        import psutil
    except ImportError:
        _log.warning("psutil not installed -- services enumeration skipped")
        return {}

    by_key: dict[str, dict] = {}
    _status_map = {
        "running": "Running",
        "stopped": "Stopped",
        "start_pending": "StartPending",
        "stop_pending": "StopPending",
        "continue_pending": "ContinuePending",
        "pause_pending": "PausePending",
        "paused": "Paused",
    }
    _start_map = {
        "automatic": "Auto",
        "manual": "Manual",
        "disabled": "Disabled",
    }

    wmi_by_name = _collect_services_wmi_enrichment()

    try:
        for svc in psutil.win_service_iter():
            try:
                d = svc.as_dict()
            except Exception:  # noqa: BLE001 -- skip unreadable services
                continue
            name = d.get("name") or ""
            if not name:
                continue
            entry = {
                "name": name,
                "display_name": d.get("display_name") or "",
                "description": d.get("description") or "",
                "start_mode": _start_map.get((d.get("start_type") or "").lower(), d.get("start_type") or ""),
                "status": _status_map.get((d.get("status") or "").lower(), d.get("status") or ""),
                "username": d.get("username") or "",
                "image_path": d.get("binpath") or "",
            }
            # Merge WMI enrichment (service_type, error_control, flags, etc.)
            entry.update(wmi_by_name.get(name, {}))
            by_key[name] = entry
    except Exception as e:  # noqa: BLE001
        _log.warning("services enumeration failed: %s", e)

    return by_key


def _collect_scheduled_tasks() -> dict:
    """Enumerate scheduled tasks via ``schtasks /query /fo CSV /v``.

    No Python binding covers the full Task Scheduler surface (pywin32's
    taskscheduler COM is partial + fiddly). ``schtasks`` is the
    canonical tool, ships with every Windows, and CSV is well-formed.

    Returns dict keyed by full task path (``\\Microsoft\\Windows\\...``).
    Each value carries state, author, image path, and the "run as"
    user -- fields that distinguish a legitimate Microsoft-signed task
    from a freshly-planted persistence task.
    """
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        _log.warning("schtasks enumeration failed: %s", e)
        return {}

    if r.returncode != 0:
        _log.warning("schtasks returned non-zero: %s", (r.stderr or "").splitlines()[:1])
        return {}

    by_key: dict[str, dict] = {}
    stdout = r.stdout or ""
    if not stdout.strip():
        return {}

    try:
        reader = csv.DictReader(io.StringIO(stdout))
        for row in reader:
            # schtasks /v emits repeated header rows between tasks; skip
            task_name = (row.get("TaskName") or "").strip()
            if not task_name or task_name == "TaskName":
                continue
            # Some rows are the per-trigger expansion of one task; collapse
            # by task_name (first row wins -- they share all top-level fields).
            if task_name in by_key:
                continue
            # Capture EVERY column schtasks /v emits (except redundant
            # HostName / Status). Missing columns default to "" so the
            # shape stays uniform across Windows versions even if
            # Microsoft changes the verbose output.
            by_key[task_name] = {
                # Identity
                "name": task_name.rsplit("\\", 1)[-1],
                "path": task_name,
                # State
                "state": (row.get("Scheduled Task State") or row.get("Status") or "").strip(),
                "author": (row.get("Author") or "").strip(),
                "run_as": (row.get("Run As User") or "").strip(),
                "logon_mode": (row.get("Logon Mode") or "").strip(),
                # What it runs
                "image_path": (row.get("Task To Run") or "").strip(),
                "start_in": (row.get("Start In") or "").strip(),
                "comment": (row.get("Comment") or "").strip(),
                # When it runs
                "schedule": (row.get("Schedule") or "").strip(),
                "schedule_type": (row.get("Schedule Type") or "").strip(),
                "start_time": (row.get("Start Time") or "").strip(),
                "start_date": (row.get("Start Date") or "").strip(),
                "end_date": (row.get("End Date") or "").strip(),
                "days": (row.get("Days") or "").strip(),
                "months": (row.get("Months") or "").strip(),
                "repeat_every": (row.get("Repeat: Every") or "").strip(),
                "repeat_until_time": (row.get("Repeat: Until: Time") or "").strip(),
                "repeat_until_duration": (row.get("Repeat: Until: Duration") or "").strip(),
                "repeat_stop_if_running": (row.get("Repeat: Stop If Still Running") or "").strip(),
                # Behaviour flags
                "idle_time": (row.get("Idle Time") or "").strip(),
                "power_management": (row.get("Power Management") or "").strip(),
                "delete_if_not_rescheduled": (row.get("Delete Task If Not Rescheduled") or "").strip(),
                "stop_if_runs_x_hours": (row.get("Stop Task If Runs X Hours and X Mins") or "").strip(),
                # Run history
                "last_run_time": (row.get("Last Run Time") or "").strip(),
                "last_result": (row.get("Last Result") or "").strip(),
                "next_run_time": (row.get("Next Run Time") or "").strip(),
            }
    except Exception as e:  # noqa: BLE001 -- malformed CSV from schtasks is a real risk
        _log.warning("schtasks CSV parse failed: %s", e)

    return by_key


# ══════════════════════════════════════════════════════════════════════
# SNAPSHOT
# ══════════════════════════════════════════════════════════════════════


def take_snapshot() -> dict:
    """Capture a full current-state snapshot across all three categories.

    Runs collectors sequentially -- they're each fast enough (services
    ~100 ms, tasks ~500 ms, startup ~2 s via PowerShell) that parallelism
    adds thread-launch overhead without meaningful wall-time savings.

    Returns a dict shape:
        {
            "timestamp": "<iso8601>",
            "startup":  {"by_key": {...}},
            "services": {"by_key": {...}},
            "tasks":    {"by_key": {...}},
            "counts": {"startup": N, "services": N, "tasks": N},
        }
    """
    snap = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "startup": {"by_key": _collect_startup()},
        "services": {"by_key": _collect_services()},
        "tasks": {"by_key": _collect_scheduled_tasks()},
    }
    snap["counts"] = {
        "startup": len(snap["startup"]["by_key"]),
        "services": len(snap["services"]["by_key"]),
        "tasks": len(snap["tasks"]["by_key"]),
    }
    return snap


# ══════════════════════════════════════════════════════════════════════
# PERSISTENCE
# ══════════════════════════════════════════════════════════════════════


def _atomic_write(path: str, payload: Any) -> bool:
    """Write ``payload`` as JSON to ``path`` atomically via .tmp+replace.

    Returns True on success, False on OSError. Caller decides whether a
    failed write is fatal (history append: no, it's just this one entry)
    or reported (baseline accept: yes, the user asked for it).
    """
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def load_baseline() -> dict | None:
    """Return the currently-accepted baseline snapshot or None."""
    with _file_lock:
        if not os.path.exists(BASELINE_FILE):
            return None
        try:
            with open(BASELINE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None


def accept_current_as_baseline() -> dict:
    """Capture a fresh snapshot and persist it as the accepted baseline.

    Return shape:
        {"ok": bool, "snapshot": dict, "error": str | None}
    """
    snapshot = take_snapshot()
    with _file_lock:
        if _atomic_write(BASELINE_FILE, snapshot):
            return {"ok": True, "snapshot": snapshot, "error": None}
        return {"ok": False, "snapshot": snapshot, "error": "atomic write failed"}


def accept_drift_entry(category: str, key: str) -> dict:
    """Accept a SINGLE drift entry's current state into the baseline.

    User feedback (2026-04-28): the original "Accept current as baseline"
    button is all-or-nothing. If three changes are legit and one is
    suspicious, the user has no way to absorb the three without also
    absorbing the suspicious one. This function fixes that -- it takes
    a single (category, key) pair and updates only that entry in the
    baseline snapshot, leaving everything else untouched.

    Three sub-cases by drift kind:
      - ADDED   (in current, not in baseline)  -> insert into baseline
      - REMOVED (in baseline, not in current)  -> delete from baseline
      - CHANGED (in both, fields differ)       -> overwrite in baseline

    Returns:
        {"ok": bool, "kind": "added|removed|changed",
         "error": str|None, "baseline_timestamp": str|None}

    Failures: 404-class (key not in either snapshot), 500-class (write
    fault, no baseline yet, etc.). Atomic write + lock so concurrent
    drift checks never observe a half-applied baseline.
    """
    if category not in _DIFF_FIELDS:
        return {
            "ok": False,
            "kind": "",
            "error": f"unknown category {category!r}; expected one of {list(_DIFF_FIELDS)}",
            "baseline_timestamp": None,
        }
    if not key or not isinstance(key, str):
        return {
            "ok": False,
            "kind": "",
            "error": "key required and must be a non-empty string",
            "baseline_timestamp": None,
        }

    with _file_lock:
        baseline = load_baseline()
        if not baseline:
            return {
                "ok": False,
                "kind": "",
                "error": "no baseline exists -- use /api/baseline/accept first",
                "baseline_timestamp": None,
            }

        # Re-snapshot so we apply current state at point-of-accept (not a
        # cached state that might be seconds-stale).
        current = take_snapshot()

        baseline_cat = baseline.setdefault(category, {}).setdefault("by_key", {})
        current_cat = (current.get(category) or {}).get("by_key") or {}

        in_baseline = key in baseline_cat
        in_current = key in current_cat

        if not in_baseline and not in_current:
            return {
                "ok": False,
                "kind": "",
                "error": f"key {key!r} not found in either baseline or current snapshot",
                "baseline_timestamp": baseline.get("timestamp"),
            }

        if not in_baseline and in_current:
            kind = "added"
            baseline_cat[key] = current_cat[key]
        elif in_baseline and not in_current:
            kind = "removed"
            del baseline_cat[key]
        else:
            # Both sides present -- replace baseline with current.
            kind = "changed"
            baseline_cat[key] = current_cat[key]

        # Bump timestamp + recompute counts so the snapshot stays consistent.
        baseline["timestamp"] = datetime.now().isoformat(timespec="seconds")
        baseline["counts"] = {cat: len((baseline.get(cat) or {}).get("by_key") or {}) for cat in _DIFF_FIELDS}

        if not _atomic_write(BASELINE_FILE, baseline):
            return {
                "ok": False,
                "kind": kind,
                "error": "atomic write failed",
                "baseline_timestamp": baseline["timestamp"],
            }

    return {
        "ok": True,
        "kind": kind,
        "error": None,
        "baseline_timestamp": baseline["timestamp"],
    }


def load_history() -> list:
    """Return the raw drift-detection history list."""
    with _file_lock:
        if not os.path.exists(HISTORY_FILE):
            return []
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []


def _append_history(entry: dict) -> bool:
    with _file_lock:
        history = load_history()
        history.append(entry)
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]
        return _atomic_write(HISTORY_FILE, history)


# ══════════════════════════════════════════════════════════════════════
# DIFF
# ══════════════════════════════════════════════════════════════════════

# Fields we compare per category. If the stored value differs from the
# live value for any of these, it's a "change". Adds/removes use the
# key-presence test only.
_DIFF_FIELDS = {
    "startup": ("command", "enabled"),
    # Security-critical service fields:
    #   start_mode / image_path / username -- classic tamper surface
    #   service_type         -- flipping "Share Process" -> "Own Process" or "Kernel Driver" is unusual
    #   error_control        -- lowering to "Ignore" can hide a broken/malicious service at boot
    #   delayed_auto_start   -- toggling on is a covert-persistence evasion pattern
    #   desktop_interact     -- flipping True on modern Windows is a high-severity red flag
    "services": (
        "start_mode",
        "image_path",
        "username",
        "service_type",
        "error_control",
        "delayed_auto_start",
        "desktop_interact",
    ),
    # Security-critical task fields:
    #   state / image_path / run_as / logon_mode -- existing
    #   start_in         -- working dir flip (e.g. C:\Windows\System32 -> C:\tmp) is a masquerade signal
    #   schedule_type    -- retiming a daily task to On Logon is a persistence shift
    # last_run_time / next_run_time / last_result change on every task run
    # (context-only, never flagged as drift). Same for schedule / start_date
    # / repeat_* which can shift mildly due to time-zone or DST without
    # being malicious.
    "tasks": (
        "state",
        "image_path",
        "run_as",
        "logon_mode",
        "start_in",
        "schedule_type",
    ),
}


def _diff_category(old_by_key: dict, new_by_key: dict, fields: tuple) -> dict:
    """Return {added, removed, changed} lists for one category."""
    old_keys = set(old_by_key.keys())
    new_keys = set(new_by_key.keys())

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    changed = []
    for key in sorted(old_keys & new_keys):
        old = old_by_key[key]
        new = new_by_key[key]
        # Schema-migration tolerance: if a tracked field is MISSING from the
        # old snapshot entirely (not just None-valued), the user captured the
        # baseline before we started tracking that field. Skip those fields
        # to avoid a false-positive wave on first drift check after an
        # upgrade. Once the user re-accepts the baseline the full field set
        # gets persisted and drift detection resumes as normal.
        delta_fields = [f for f in fields if f in old and f in new and old.get(f) != new.get(f)]
        if delta_fields:
            # Ship the FULL old+new entries (not just the delta fields) so
            # the UI can render a Parameter / Previous / Current table
            # showing every tracked parameter and highlighting which ones
            # actually changed via the separate ``delta`` list. Also
            # includes display-only fields like ``display_name`` /
            # ``author`` that aren't in ``fields`` but add context.
            changed.append(
                {
                    "key": key,
                    "name": new.get("name") or old.get("name") or key,
                    "delta": delta_fields,
                    "old": dict(old),
                    "new": dict(new),
                }
            )

    return {
        "added": [{"key": k, **new_by_key[k]} for k in added],
        "removed": [{"key": k, **old_by_key[k]} for k in removed],
        "changed": changed,
    }


def diff_snapshots(old: dict, new: dict) -> dict:
    """Return a categorised diff: what's been added, removed, or changed.

    Shape:
        {
            "startup":  {"added": [...], "removed": [...], "changed": [...]},
            "services": {...},
            "tasks":    {...},
            "total_changes": int,
        }

    A first-run (old is None / empty) returns zero-length lists for every
    category so the UI doesn't splash a 500-item "drift" panel on day one.
    """
    result = {}
    total = 0
    if not old:
        for cat in _DIFF_FIELDS:
            result[cat] = {"added": [], "removed": [], "changed": []}
        result["total_changes"] = 0
        return result

    for cat, fields in _DIFF_FIELDS.items():
        old_by_key = (old.get(cat) or {}).get("by_key") or {}
        new_by_key = (new.get(cat) or {}).get("by_key") or {}
        cat_diff = _diff_category(old_by_key, new_by_key, fields)
        result[cat] = cat_diff
        total += len(cat_diff["added"]) + len(cat_diff["removed"]) + len(cat_diff["changed"])

    result["total_changes"] = total
    return result


# ══════════════════════════════════════════════════════════════════════
# COMPUTE DRIFT + RECORD
# ══════════════════════════════════════════════════════════════════════


def _schema_migration_fields(baseline: dict | None, current: dict) -> list:
    """Return ``[cat.field, ...]`` for every tracked field that exists in the
    current schema but NOT in the baseline snapshot's entries.

    Shape example: ``["services.username", "tasks.logon_mode", ...]``

    Used by the UI to explain why Previous-column cells show "—" for certain
    rows: the baseline predates those fields being tracked. The user can
    accept the current snapshot as the new baseline to absorb them and
    resume normal drift detection.
    """
    if not baseline:
        return []
    out: list[str] = []
    for cat, fields in _DIFF_FIELDS.items():
        bl_by_key = (baseline.get(cat) or {}).get("by_key") or {}
        cur_by_key = (current.get(cat) or {}).get("by_key") or {}
        if not bl_by_key or not cur_by_key:
            continue
        # Sample one baseline entry and one current entry to compare schemas.
        # All entries in the same snapshot share the same keys (collector
        # writes a uniform shape), so one sample is representative.
        sample_old = next(iter(bl_by_key.values()))
        sample_new = next(iter(cur_by_key.values()))
        if not isinstance(sample_old, dict) or not isinstance(sample_new, dict):
            continue
        for f in fields:
            if f in sample_new and f not in sample_old:
                out.append(f"{cat}.{f}")
    return sorted(out)


def compute_drift() -> dict:
    """Snap the current state and diff it against the accepted baseline.

    Return shape:
        {
            "ok": True,
            "baseline_timestamp": "<iso | null>",
            "current_timestamp": "<iso>",
            "drift": { ... same shape as diff_snapshots(...) ... },
            "has_baseline": bool,
            "schema_migration_fields": [str],  # new tracked fields not in baseline
        }

    If no baseline exists, ``drift.total_changes`` is 0 and
    ``has_baseline`` is False -- the UI uses that to show the
    "Set initial baseline" first-run state.
    """
    baseline = load_baseline()
    current = take_snapshot()
    drift = diff_snapshots(baseline or {}, current)
    return {
        "ok": True,
        "baseline_timestamp": (baseline or {}).get("timestamp"),
        "current_timestamp": current["timestamp"],
        "drift": drift,
        "has_baseline": baseline is not None,
        "counts": current.get("counts", {}),
        "schema_migration_fields": _schema_migration_fields(baseline, current),
    }


def record_drift_if_any() -> dict:
    """Compute drift; if any, append an entry to the history log.

    Returns the compute_drift() result dict with an extra ``recorded``
    bool indicating whether an entry was actually written.
    """
    result = compute_drift()
    drift = result["drift"]
    if drift["total_changes"] > 0 and result["has_baseline"]:
        _append_history(
            {
                "timestamp": result["current_timestamp"],
                "baseline_timestamp": result["baseline_timestamp"],
                "total_changes": drift["total_changes"],
                "drift": drift,
            }
        )
        result["recorded"] = True
    else:
        result["recorded"] = False
    return result


def recent_drift(window: timedelta = DRIFT_ALERT_WINDOW) -> list:
    """Return drift history entries whose timestamp falls in the window."""
    history = load_history()
    cutoff = datetime.now() - window
    out = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        if ts >= cutoff:
            out.append(entry)
    return out


# ══════════════════════════════════════════════════════════════════════
# DRIFT INVESTIGATOR -- "why did this change happen?" decision support
# ══════════════════════════════════════════════════════════════════════
#
# When the user sees a drift entry, the table tells them WHAT changed
# but not WHY. Without context they're left guessing whether it's safe
# to accept. The investigator surfaces three signals to help them
# decide:
#   1. Path safety classification (System32 = trusted; Temp = suspicious)
#   2. Recent Windows Updates correlated with the drift
#   3. Inferred cause + recommended action
#
# Each signal is independently useful but combining them is what makes
# the recommendation actionable. Order in _PATH_CLASSIFICATIONS matters
# -- more specific patterns must come first (System32 before Windows).

_PATH_CLASSIFICATIONS: tuple[tuple[str, str, str], ...] = (
    # (substring_to_match, friendly_label, severity)
    # severity: "trusted" | "standard" | "user-app" | "suspicious" | "unknown"
    # Patterns use single trailing backslash (\) to anchor "after the
    # folder name" so e.g. "system32" matches "...\system32\..." but not
    # "...\system32_old\..."
    #
    # ORDER MATTERS: more specific patterns MUST come first. The matcher
    # returns on first hit. Suspicious + standard patterns are listed
    # BEFORE the broad "windows folder" / "users folder" catchalls so a
    # path under \Windows\Temp\ classifies as suspicious, not trusted.
    # Suspicious overrides user-app for the same reason (Temp under
    # AppData is suspicious, not user-app).
    ("\\appdata\\local\\temp\\", "User Temp folder", "suspicious"),
    ("\\users\\public\\", "Public user folder", "suspicious"),
    ("\\windows\\temp\\", "Windows Temp folder", "suspicious"),
    ("\\temp\\", "Temp folder", "suspicious"),
    ("\\windows\\system32\\", "Windows System32", "trusted"),
    ("\\windows\\syswow64\\", "Windows SysWOW64 (32-bit)", "trusted"),
    ("\\windows\\winsxs\\", "Windows side-by-side store", "trusted"),
    ("\\windows\\servicing\\", "Windows servicing folder", "trusted"),
    ("\\windows\\", "Windows folder", "trusted"),
    ("\\program files (x86)\\", "Program Files (x86)", "standard"),
    ("\\program files\\", "Program Files", "standard"),
    ("\\programdata\\", "ProgramData", "standard"),
    ("\\appdata\\local\\", "User AppData (Local)", "user-app"),
    ("\\appdata\\roaming\\", "User AppData (Roaming)", "user-app"),
    ("c:\\users\\", "User folder", "user-app"),
)


def _classify_path(path: str) -> dict:
    """Map an executable path to {label, severity}.

    Severity values inform the recommendation engine:
      - trusted    -> System-owned location, safe by default
      - standard   -> Normal install location (Program Files etc.)
      - user-app   -> Per-user install (legitimate but worth a glance)
      - suspicious -> Unusual location for a service/task binary
      - unknown    -> Couldn't classify (UNC paths, COM handlers, etc.)

    The substring match is case-insensitive; paths use double-backslashes
    to avoid matching mid-segment text (e.g. "Windows System32\\foo" must
    match "system32\\" not "system32" alone).
    """
    if not path or not isinstance(path, str):
        return {"label": "(empty)", "severity": "unknown"}
    p = path.lower()
    for pattern, label, severity in _PATH_CLASSIFICATIONS:
        if pattern in p:
            return {"label": label, "severity": severity}
    # Special case: COM handlers / well-known commands
    if p.strip() in ("com handler", "{", "}"):
        return {"label": "COM handler / shell", "severity": "trusted"}
    return {"label": "Unclassified location", "severity": "unknown"}


def _recent_windows_updates(window: timedelta = timedelta(days=7)) -> list:
    """Return Windows Updates installed within the past `window`.

    Uses Get-HotFix via PowerShell -- it's the simplest cross-version
    source. Returns an empty list on any failure (best-effort -- the
    investigator falls back to "no correlation data" rather than blocking
    the analysis).
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json -Compress",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if r.returncode != 0 or not (r.stdout or "").strip():
        return []
    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    cutoff = datetime.now() - window
    out: list[dict] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        installed = entry.get("InstalledOn")
        # PowerShell's ConvertTo-Json renders DateTime as either a string
        # or a {"value":"...","DateTime":"..."} object. Handle both.
        ts_str = ""
        if isinstance(installed, dict):
            ts_str = installed.get("DateTime") or installed.get("value") or ""
        elif isinstance(installed, str):
            ts_str = installed
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00").replace("/", "-"))
            ts = ts.replace(tzinfo=None) if ts.tzinfo else ts
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        out.append(
            {
                "id": entry.get("HotFixID") or "",
                "description": entry.get("Description") or "",
                "installed": ts.isoformat(timespec="seconds"),
            }
        )
    # Newest first -- the most recent update is the most likely cause.
    out.sort(key=lambda e: e["installed"], reverse=True)
    return out


# Sanitiser shared by every PowerShell-bound name. Strips anything outside
# a strict whitelist so a malicious / weird service / task name can't
# escape the single-quoted PS string it's interpolated into. Caller can
# still abort early if the sanitised result diverges from the input.
def _safe_ps_name(name: str, max_len: int = 256) -> str:
    if not isinstance(name, str):
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9_\-. \\/]", "", name)
    return cleaned[:max_len]


def _normalise_event_ts(value) -> str:
    """Best-effort ISO-8601 datetime from a PowerShell ConvertTo-Json TimeCreated."""
    if not value:
        return ""
    if isinstance(value, dict):
        value = value.get("DateTime") or value.get("value") or ""
    s = str(value).strip()
    if not s:
        return ""
    try:
        # PS ConvertTo-Json emits "/Date(1714233600000)/" sometimes too -- best
        # effort: pull the milliseconds out and format.
        m = re.match(r"/Date\((\d+)", s)
        if m:
            return datetime.fromtimestamp(int(m.group(1)) / 1000).isoformat(timespec="seconds")
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
        return dt.isoformat(timespec="seconds")
    except (ValueError, TypeError):
        return s


def _get_service_install_event(service_name: str) -> dict | None:
    """Look up the System log Event 7045 (service installed) for a given
    service name. Returns the install timestamp + image path + start type
    + account + installer-user, or None if no event matches.

    Event 7045 is logged by Service Control Manager every time a new
    service is registered. Properties (in order):
      [0] ServiceName  [1] ImagePath  [2] ServiceType
      [3] StartType    [4] AccountName

    The UserId on the event record points at the SID of the account that
    triggered the install. We resolve that SID to a friendly name when
    possible -- but we WRAP the resolve in try/catch because some SIDs
    (e.g. deleted accounts) can't be translated and would otherwise crash
    the whole pipeline.
    """
    safe = _safe_ps_name(service_name)
    if not safe:
        return None
    # PowerShell command: query last 200 events 7045, filter by service
    # name, take the most recent match. The escape-and-double for ' inside
    # a single-quoted PS string is `'`->`''`.
    safe_ps = safe.replace("'", "''")
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -MaxEvents 200 -ErrorAction SilentlyContinue |"
            f"Where-Object {{$_.Properties[0].Value -eq '{safe_ps}'}} |"
            "Sort-Object TimeCreated -Descending |"
            "Select-Object -First 1 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},"
            "@{N='ServiceName';E={$_.Properties[0].Value}},"
            "@{N='ImagePath';E={$_.Properties[1].Value}},"
            "@{N='ServiceType';E={$_.Properties[2].Value}},"
            "@{N='StartType';E={$_.Properties[3].Value}},"
            "@{N='AccountName';E={$_.Properties[4].Value}},"
            "@{N='InstalledBy';E={try{$_.UserId.Translate([System.Security.Principal.NTAccount]).Value}catch{''}}}|"
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not (r.stdout or "").strip():
        return None
    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return None
    return {
        "timestamp": _normalise_event_ts(data.get("TimeCreated")),
        "service_name": str(data.get("ServiceName", "")),
        "image_path": str(data.get("ImagePath", "")),
        "start_type": str(data.get("StartType", "")),
        "account_name": str(data.get("AccountName", "")),
        "installed_by": str(data.get("InstalledBy", "")),
    }


def _get_task_registration_event(task_path: str) -> dict | None:
    """Look up TaskScheduler/Operational Event 106 (task registered) for a
    given full task path (e.g. ``\\Microsoft\\Windows\\Foo\\Bar``).
    Returns timestamp + creator user, or None if not found.

    Event 106 is logged when a task is registered/created. The TaskName
    property holds the path; the registered user is in UserId.
    """
    safe = _safe_ps_name(task_path)
    if not safe:
        return None
    safe_ps = safe.replace("'", "''")
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';ID=106} "
            "-MaxEvents 500 -ErrorAction SilentlyContinue |"
            f"Where-Object {{$_.Properties[0].Value -eq '{safe_ps}'}} |"
            "Sort-Object TimeCreated -Descending |"
            "Select-Object -First 1 @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},"
            "@{N='TaskName';E={$_.Properties[0].Value}},"
            "@{N='UserName';E={$_.Properties[1].Value}}|"
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not (r.stdout or "").strip():
        return None
    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return None
    return {
        "timestamp": _normalise_event_ts(data.get("TimeCreated")),
        "task_name": str(data.get("TaskName", "")),
        "registered_by": str(data.get("UserName", "")),
    }


def _check_signature(image_path: str) -> dict:
    """Run Get-AuthenticodeSignature on a binary path. Returns:
        {"status": "Valid|NotSigned|HashMismatch|...", "signer": "<CN>",
         "valid": bool}

    Strips command-line args from image_path before checking (Windows
    services often store ``"C:\\foo.exe" -k arg``-style paths). Any
    failure (file missing, PowerShell error, network drive offline)
    returns {"status": "error", "signer": "", "valid": False} so the
    caller can treat it as "no signal" without special-casing.
    """
    if not isinstance(image_path, str) or not image_path.strip():
        return {"status": "no_path", "signer": "", "valid": False}
    p = image_path.strip()

    # Pull out the actual exe path: handle quoted ("C:\foo.exe") and
    # unquoted (C:\foo.exe -k arg) forms.
    if p.startswith('"'):
        end = p.find('"', 1)
        clean = p[1:end] if end > 0 else p[1:]
    else:
        clean = p.split(" ")[0]
    if not clean or len(clean) > 500 or "\n" in clean:
        return {"status": "invalid_path", "signer": "", "valid": False}
    if not (clean.lower().endswith(".exe") or clean.lower().endswith(".dll") or clean.lower().endswith(".sys")):
        return {"status": "not_pe", "signer": "", "valid": False}

    safe_ps = clean.replace("'", "''")
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$s=Get-AuthenticodeSignature -FilePath '{safe_ps}' -ErrorAction SilentlyContinue;"
            "if(!$s){@{Status='error';Signer=''}|ConvertTo-Json -Compress;exit};"
            "$signer=if($s.SignerCertificate){($s.SignerCertificate.Subject -replace '^CN=([^,]*).*$','$1')}else{''};"
            "@{Status=$s.Status.ToString();Signer=$signer}|ConvertTo-Json -Compress"
        ),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return {"status": "error", "signer": "", "valid": False}
    if r.returncode != 0 or not (r.stdout or "").strip():
        return {"status": "error", "signer": "", "valid": False}
    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"status": "error", "signer": "", "valid": False}
    status = str(data.get("Status", "Unknown")).strip()
    signer = str(data.get("Signer", "")).strip()
    return {"status": status, "signer": signer, "valid": status == "Valid"}


def _recent_software_installs(window: timedelta = timedelta(days=14)) -> list:
    """Read the Windows Uninstall registry hives for programs whose
    InstallDate falls within the window. Returns newest-first list of
    {name, publisher, install_date, source}.

    Scans three hives:
      - HKLM\\SOFTWARE\\...\\Uninstall            (64-bit + system)
      - HKLM\\SOFTWARE\\WOW6432Node\\...\\Uninstall (32-bit on 64-bit OS)
      - HKCU\\SOFTWARE\\...\\Uninstall            (per-user installs)

    InstallDate is YYYYMMDD format -- absent for some entries (Windows
    doesn't make it mandatory). We just skip those rather than guess.
    """
    try:
        import winreg
    except ImportError:
        return []

    cutoff = datetime.now() - window
    out: list[dict] = []
    hives = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-WOW64"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
    )
    for root, sub_path, src in hives:
        try:
            parent = winreg.OpenKey(root, sub_path)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(parent)[0]
            for i in range(count):
                try:
                    sub = winreg.EnumKey(parent, i)
                except OSError:
                    continue
                try:
                    k = winreg.OpenKey(parent, sub)
                except OSError:
                    continue
                try:

                    def _read(name, _k=k):
                        try:
                            return str(winreg.QueryValueEx(_k, name)[0])
                        except (OSError, FileNotFoundError):
                            return ""

                    name = _read("DisplayName")
                    install_date_str = _read("InstallDate")
                    if not name or not install_date_str:
                        continue
                    try:
                        dt = datetime.strptime(install_date_str.strip(), "%Y%m%d")
                    except (ValueError, TypeError):
                        continue
                    if dt < cutoff:
                        continue
                    out.append(
                        {
                            "name": name,
                            "publisher": _read("Publisher"),
                            "install_date": dt.isoformat(timespec="seconds"),
                            "source": src,
                        }
                    )
                finally:
                    winreg.CloseKey(k)
        finally:
            winreg.CloseKey(parent)

    out.sort(key=lambda e: e["install_date"], reverse=True)
    return out


def _correlate_install(image_path: str, signer: str, recent_installs: list) -> dict | None:
    """Pick the most-likely related software install from ``recent_installs``.

    Heuristics (highest priority first):
      1. Publisher matches the digital signer
      2. Software name appears in the image_path (e.g. "Adobe" in
         "C:\\Program Files\\Adobe\\Reader\\acrord.exe")
      3. Software's name OR publisher appears in the image_path (case-
         insensitive substring)

    Returns the matched install dict (with ``match_reason`` added) or None.
    """
    if not recent_installs:
        return None
    path_lc = (image_path or "").lower()
    signer_lc = (signer or "").lower()

    # Tier 1: publisher matches signer
    if signer_lc:
        for entry in recent_installs:
            pub = (entry.get("publisher") or "").lower()
            if pub and pub in signer_lc or (signer_lc and signer_lc in pub):
                return {**entry, "match_reason": "publisher matches binary signer"}

    # Tier 2: software name appears in image_path
    for entry in recent_installs:
        name = (entry.get("name") or "").lower()
        if name and len(name) >= 4 and name in path_lc:
            return {**entry, "match_reason": "software name appears in binary path"}

    # Tier 3: publisher appears in image_path
    for entry in recent_installs:
        pub = (entry.get("publisher") or "").lower()
        if pub and len(pub) >= 4 and pub in path_lc:
            return {**entry, "match_reason": "publisher name appears in binary path"}

    return None


def _infer_drift_cause(path_severity: str, recent_updates: list, kind: str) -> tuple[str, str, str]:
    """Combine path safety + update timing into a recommendation.

    Returns (inferred_cause, recommendation, explanation).
      - inferred_cause: "windows_update" | "software_install" | "user_action"
                       | "scheduled_task_run" | "needs_investigation" | "unknown"
      - recommendation: "likely_safe" | "review" | "investigate"
      - explanation: human-readable sentence(s) suitable for the UI

    Decision rules:
      - Suspicious path (Temp / Public / etc.) -> investigate, regardless
        of update history. This is the malware-signal path.
      - Trusted path + recent updates           -> likely_safe (probably WU)
      - Standard path + recent updates          -> review (probably software update)
      - Trusted path + no recent updates        -> likely_safe (user action)
      - User-app path                           -> review (per-user install)
      - Unknown                                 -> review
    """
    has_updates = bool(recent_updates)
    latest = recent_updates[0] if has_updates else None

    if path_severity == "suspicious":
        return (
            "needs_investigation",
            "investigate",
            (
                "The new path is in a location that's unusual for legitimate services or "
                "scheduled tasks (Temp / Public / similar). Verify the binary's "
                "digital signature and check what software installed it. If you didn't "
                "install anything matching this, treat as suspicious."
            ),
        )
    if path_severity == "trusted" and has_updates:
        return (
            "windows_update",
            "likely_safe",
            (
                f"Path is in a Windows-system location and Windows Update installed "
                f"{len(recent_updates)} update(s) in the last 7 days "
                f"(most recent: {latest['id']} on {latest['installed']}). "
                "This change is most likely a Windows Update side-effect -- safe to accept."
            ),
        )
    if path_severity == "standard" and has_updates:
        return (
            "windows_update",
            "review",
            (
                f"Path is in a normal install location and Windows Update installed "
                f"{len(recent_updates)} update(s) recently. Could be a driver/component "
                "update bundled with Windows Update. Quick sanity-check the binary "
                "(right-click → Properties → Digital Signatures) and accept if signed by a known vendor."
            ),
        )
    if path_severity == "trusted":
        return (
            "user_action",
            "likely_safe",
            (
                "Path is in a Windows-system location. No recent Windows Updates in the "
                "last 7 days, so this is most likely a user-initiated config change "
                "(toggling a service via services.msc, enabling a scheduled task, etc.)."
            ),
        )
    if path_severity == "user-app":
        return (
            "software_install",
            "review",
            (
                "Path is under a user folder -- common for per-user installs (Chrome, "
                "Discord, OneDrive, etc.). If you installed or updated software in this "
                "category recently, accept. Otherwise investigate."
            ),
        )
    if kind == "changed" and not has_updates:
        return (
            "scheduled_task_run",
            "likely_safe",
            (
                "Only context fields changed (e.g. last_run_time after a scheduled "
                "task ran). No recent Windows Updates. Most likely a normal task "
                "execution, not a config change."
            ),
        )
    return (
        "unknown",
        "review",
        "Couldn't infer a likely cause automatically. Verify the change manually.",
    )


def investigate_drift_entry(category: str, entry: dict) -> dict:
    """Analyze a single drift entry with multiple evidence sources.

    ``entry`` is a member of ``drift[category][added|removed|changed]``
    as returned by ``diff_snapshots``. Returns a dict the UI can render
    directly:
        {
            "kind":            "added" | "removed" | "changed",
            "key":             "<entry key>",
            "path_safety":     {"label": "...", "severity": "trusted|..."},
            "recent_updates":  [...],
            "install_event":   {timestamp, image_path, account, installed_by} | None,
            "signature":       {status, signer, valid},
            "recent_installs": [...],
            "matched_install": {name, publisher, install_date, match_reason} | None,
            "inferred_cause":  "windows_update|software_install|user_action|..."
            "recommendation":  "likely_safe|review|investigate",
            "explanation":     "...",
        }

    The deeper evidence (install_event, signature, recent_installs,
    matched_install) is most useful for ADDED entries -- "where did this
    come from" -- but we gather it for changed/removed too to give a
    complete picture. Each lookup is failure-tolerant: any subprocess
    error returns the empty/None state, so the investigation always
    completes even on a hostile environment.
    """
    # Detect the kind from the entry's shape.
    if entry.get("old") and entry.get("new"):
        kind = "changed"
    elif entry.get("old"):
        kind = "removed"
    else:
        kind = "added"

    # Pick the most-relevant binary path. For added/changed we want the
    # NEW value (the thing currently on disk). For removed we want the
    # OLD value (what was there). Both fall back to the flat-shape entry.
    source = entry.get("old") or entry if kind == "removed" else entry.get("new") or entry
    path = (source.get("image_path") or source.get("command") or "").strip()
    name = entry.get("name") or entry.get("key") or ""

    # ── Gather evidence ──
    path_safety = _classify_path(path)
    recent_updates = _recent_windows_updates()
    recent_installs = _recent_software_installs()

    # Install event: only meaningful for added entries (and useful as
    # confirmation for changed). Pick the right event source per category.
    install_event = None
    if kind in ("added", "changed"):
        if category == "services":
            install_event = _get_service_install_event(name)
        elif category == "tasks":
            # Tasks key is the full path; pass that to the event lookup.
            install_event = _get_task_registration_event(entry.get("key") or name)

    # Signature on the new binary -- skip for removed entries (the file
    # is presumably gone) and for empty paths.
    signature = (
        _check_signature(path)
        if kind != "removed" and path
        else {
            "status": "skipped",
            "signer": "",
            "valid": False,
        }
    )

    # Correlate against recent software installs.
    matched_install = _correlate_install(path, signature.get("signer", ""), recent_installs)

    # ── Combine into a recommendation ──
    inferred, recommendation, explanation = _infer_drift_cause_v2(
        kind=kind,
        path_safety=path_safety,
        recent_updates=recent_updates,
        install_event=install_event,
        signature=signature,
        matched_install=matched_install,
    )

    return {
        "kind": kind,
        "key": entry.get("key", ""),
        "path_safety": path_safety,
        "recent_updates": recent_updates[:5],
        "install_event": install_event,
        "signature": signature,
        "recent_installs": recent_installs[:5],
        "matched_install": matched_install,
        "inferred_cause": inferred,
        "recommendation": recommendation,
        "explanation": explanation,
    }


def _infer_drift_cause_v2(
    kind: str,
    path_safety: dict,
    recent_updates: list,
    install_event: dict | None,
    signature: dict,
    matched_install: dict | None,
) -> tuple[str, str, str]:
    """Decision engine v2 -- factors in event-log evidence + signature +
    software-install correlation on top of v1's path-severity check.

    Priority of evidence (strongest first):
      1. Suspicious path -> investigate (always wins; malware signal)
      2. Signed by trusted vendor + matched install -> likely_safe
         (we know who installed it and the publisher matches)
      3. Service install Event 7045 within last 14d + signed binary
         -> likely_safe (we have direct evidence + crypto verification)
      4. Trusted path + signed -> likely_safe
      5. Standard path + matched install -> likely_safe
      6. Standard path + signed binary + recent updates -> review
      7. Unsigned binary in non-trusted path -> investigate
      8. Path-only signals (v1 fallback)
    """
    severity = path_safety.get("severity", "unknown")
    sig_valid = bool(signature and signature.get("valid"))
    signer = (signature.get("signer") or "") if signature else ""
    has_install_event = install_event is not None

    # ── Always-investigate path (hard fail) ──
    if severity == "suspicious":
        details = []
        if sig_valid:
            details.append(f"binary signed by {signer}")
        else:
            details.append("binary unsigned or signature invalid")
        if matched_install:
            details.append(f"correlates with recent install of '{matched_install.get('name', '?')}'")
        if has_install_event:
            details.append(f"install event found at {install_event.get('timestamp', '?')}")
        return (
            "needs_investigation",
            "investigate",
            (
                f"Path is in {path_safety.get('label', 'a suspicious location')} -- unusual for legitimate "
                "services or scheduled tasks (Temp / Public / etc). "
                + ("; ".join(details) + ". " if details else "")
                + "Verify the source before accepting."
            ),
        )

    # ── Strong-positive paths ──
    if matched_install and sig_valid:
        return (
            "software_install",
            "likely_safe",
            (
                f"Binary is digitally signed by '{signer}' AND we found a recent install of "
                f"'{matched_install.get('name', '?')}' on {matched_install.get('install_date', '?')[:10]} "
                f"({matched_install.get('match_reason', 'matched')}). "
                "This change is almost certainly a known software install -- safe to accept."
            ),
        )

    if has_install_event and sig_valid:
        ev_ts = (install_event.get("timestamp") or "")[:19]
        installer = install_event.get("installed_by") or install_event.get("account_name") or "?"
        return (
            "software_install",
            "likely_safe",
            (
                f"Service was installed on {ev_ts} by '{installer}' (Windows Event 7045 captured "
                f"the install) AND the binary is signed by '{signer}'. "
                "Direct evidence + crypto verification -- safe to accept."
            ),
        )

    if has_install_event:
        ev_ts = (install_event.get("timestamp") or "")[:19]
        installer = install_event.get("installed_by") or install_event.get("account_name") or "?"
        return (
            "software_install",
            "review",
            (
                f"Found a Windows install event for this entry: registered {ev_ts} by '{installer}'. "
                "Binary is unsigned or signature couldn't be verified -- "
                "quick sanity-check the publisher before accepting."
            ),
        )

    if matched_install:
        return (
            "software_install",
            "review",
            (
                f"Recent install of '{matched_install.get('name', '?')}' "
                f"({matched_install.get('match_reason', 'name match')}) -- likely the source of this change. "
                "Binary signature couldn't be verified though, so quick sanity-check before accepting."
            ),
        )

    if severity == "trusted" and sig_valid:
        return (
            "software_install",
            "likely_safe",
            (
                f"Path is in {path_safety.get('label')} and binary is signed by '{signer}'. "
                "Signed Windows-system binary -- safe to accept."
            ),
        )

    # ── Fall back to path-only reasoning (v1 logic) ──
    has_updates = bool(recent_updates)
    latest = recent_updates[0] if has_updates else None

    if severity == "trusted" and has_updates:
        return (
            "windows_update",
            "likely_safe",
            (
                f"Path is in {path_safety.get('label')} and Windows Update installed "
                f"{len(recent_updates)} update(s) recently (most recent: {latest['id']}). "
                "Likely a Windows Update side-effect -- safe to accept."
            ),
        )

    if severity == "standard" and has_updates:
        sig_note = f" Binary signed by '{signer}'." if sig_valid else " Binary unsigned."
        return (
            "windows_update",
            "review",
            (
                f"Path is in {path_safety.get('label')} (normal install location) and Windows Update "
                f"installed {len(recent_updates)} update(s) recently.{sig_note} "
                "Quick sanity-check and accept if it matches the install."
            ),
        )

    if severity == "trusted":
        return (
            "user_action",
            "likely_safe",
            (
                f"Path is in {path_safety.get('label')}. No recent Windows Updates and no install "
                "event matched -- most likely a user-initiated config change."
            ),
        )

    if severity == "user-app":
        sig_note = f" Binary signed by '{signer}'." if sig_valid else ""
        return (
            "software_install",
            "review",
            (
                f"Path is in {path_safety.get('label')} -- common for per-user installs.{sig_note} "
                "If you installed/updated software in this category recently, accept."
            ),
        )

    if kind == "changed" and not has_updates:
        return (
            "scheduled_task_run",
            "likely_safe",
            (
                "Only context fields changed (e.g. last_run_time after a scheduled task ran). "
                "No recent Windows Updates and no install events. Most likely a normal task run."
            ),
        )

    # Unsigned binary in a non-trusted location with no other signals.
    if not sig_valid and severity not in ("trusted", "standard"):
        return (
            "needs_investigation",
            "investigate",
            (
                f"Binary is in {path_safety.get('label')} and is unsigned (or signature couldn't be "
                "verified). No recent install event or software install matches. Investigate the "
                "source before accepting."
            ),
        )

    return (
        "unknown",
        "review",
        "Couldn't infer a likely cause from the available evidence. Verify manually before accepting.",
    )
