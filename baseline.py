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
