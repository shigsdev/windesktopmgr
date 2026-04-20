"""metrics_history.py -- time-series sampler for the Trends dashboard (backlog #4).

Records a flat snapshot of key health metrics on every successful
``/api/dashboard/summary`` call (throttled to one sample per
``SAMPLE_INTERVAL``). Data is appended to ``metrics_history.json`` and
capped at ``MAX_HISTORY`` entries, so long-running tray instances do
not grow the file unbounded.

Storage shape (one entry per sample, list[dict]):

    {
        "timestamp": "2026-04-19T12:34:56",
        "metrics": {
            "concerns_critical":  0,
            "concerns_warning":   2,
            "cpu_percent":       23.5,
            "memory_percent":    67.2,
            "cpu_temp_c":        52,
            "disk_percent.C":    78,
            "disk_percent.D":    45
        }
    }

Per-drive metrics use a flat ``disk_percent.<letter>`` key so the
query API can return one series per metric without nested unpacking.

Public API:
    extract_metrics(summary)   -- pull a flat metric dict from a /summary response
    record_sample(summary, force=False)
                               -- append-throttled persistence
    get_series(metric, hours)  -- [(ts, value), ...] for one metric
    list_metrics()             -- sorted list of metric keys ever seen
    load_history()             -- raw on-disk list (mostly for tests)
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics_history.json")

# 4000 samples × 10-minute throttle ≈ 27 days of history at the default
# poll cadence. Bumping this is cheap (file stays well under 1 MB even at
# 4 k entries × ~250 B each), but 7-30 day windows cover every realistic
# trend question so we cap here to keep the read+rewrite step fast.
MAX_HISTORY = 4000

# Minimum gap between recorded samples. The dashboard summary endpoint
# can be hit many times per minute (manual refresh, NLQ, /api/selftest);
# without throttling the file would balloon and the trend signal would be
# drowned in identical adjacent samples.
SAMPLE_INTERVAL = timedelta(minutes=10)

# Default query window for get_series() and the /api/metrics/history
# route. 7 days is the natural unit for "is this trending in the wrong
# direction?" — long enough to see drift, short enough to fit on a
# sparkline without aliasing.
DEFAULT_WINDOW = timedelta(days=7)

_history_lock = threading.RLock()


# ── Metric extraction ──────────────────────────────────────────────


def extract_metrics(summary: dict) -> dict:
    """Pull a flat ``{metric_key: number}`` dict from a /summary response.

    Missing or malformed sections are skipped silently — the goal is to
    record whatever signal IS available rather than refuse to sample
    when one collector errored. Per-drive disk percents are flattened to
    ``disk_percent.<letter>`` keys so the query API can treat each
    drive as its own series.

    All values are coerced to ``float`` (or ``int`` for counts) so the
    on-disk JSON stays small and uniform.
    """
    if not isinstance(summary, dict):
        return {}

    metrics: dict = {}

    # Only emit concern counts when the caller actually passed a list. A
    # summary that omits "concerns" entirely is a missing signal, not a
    # "zero concerns" signal -- recording 0/0 in that case would lie to
    # the trend chart.
    concerns = summary.get("concerns")
    if isinstance(concerns, list):
        critical = sum(1 for c in concerns if isinstance(c, dict) and c.get("level") == "critical")
        warning = sum(1 for c in concerns if isinstance(c, dict) and c.get("level") == "warning")
        metrics["concerns_critical"] = critical
        metrics["concerns_warning"] = warning

    therm = summary.get("thermals") or {}
    if isinstance(therm, dict):
        cpu_pct = (therm.get("perf") or {}).get("CPUPct")
        if isinstance(cpu_pct, int | float):
            metrics["cpu_percent"] = float(cpu_pct)
        # Highest reported temperature across CPU + storage probes. A
        # single max value per sample is enough for trend detection;
        # per-zone breakdown is what the Thermals tab is for.
        temps = therm.get("temps") or []
        temp_values = [t.get("TempC") for t in temps if isinstance(t, dict)]
        temp_values = [v for v in temp_values if isinstance(v, int | float)]
        if temp_values:
            metrics["cpu_temp_c"] = float(max(temp_values))

    mem = summary.get("memory") or {}
    if isinstance(mem, dict):
        used = mem.get("used_mb")
        total = mem.get("total_mb")
        if isinstance(used, int | float) and isinstance(total, int | float) and total > 0:
            metrics["memory_percent"] = round(float(used) / float(total) * 100, 1)

    disk = summary.get("disk") or {}
    if isinstance(disk, dict):
        for d in disk.get("drives") or []:
            if not isinstance(d, dict):
                continue
            letter = d.get("Letter") or d.get("letter")
            pct = d.get("PctUsed")
            if pct is None:
                pct = d.get("pct_used")
            if letter and isinstance(pct, int | float):
                metrics[f"disk_percent.{str(letter).upper()[:1]}"] = float(pct)

    return metrics


# ── Persistence ────────────────────────────────────────────────────


def load_history() -> list:
    """Return the raw history list. Empty list on any read error."""
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
    """Append one entry, cap at MAX_HISTORY, atomic-write. Returns ok flag."""
    with _history_lock:
        history = load_history()
        history.append(entry)
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]
        tmp = HISTORY_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(history, f, separators=(",", ":"))
            os.replace(tmp, HISTORY_FILE)
            return True
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False


def _last_entry_age() -> timedelta | None:
    history = load_history()
    for entry in reversed(history):
        if not isinstance(entry, dict):
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        return datetime.now() - ts
    return None


# ── Recording ──────────────────────────────────────────────────────


def record_sample(summary: dict, force: bool = False) -> dict:
    """Persist one sample of metrics extracted from a /summary response.

    Throttled to one entry per ``SAMPLE_INTERVAL`` unless ``force=True``.
    If ``extract_metrics`` returns an empty dict (every collector errored)
    nothing is appended — recording an all-empty sample would just create
    a hole in every series.

    Always returns a dict so callers can treat the result uniformly:
        {"ok": bool, "skipped": bool, "metrics": dict}
    """
    if not force:
        age = _last_entry_age()
        if age is not None and age < SAMPLE_INTERVAL:
            return {"ok": True, "skipped": True, "metrics": {}}

    metrics = extract_metrics(summary)
    if not metrics:
        return {"ok": True, "skipped": True, "metrics": {}}

    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "metrics": metrics,
    }
    ok = _append_history(entry)
    return {"ok": ok, "skipped": False, "metrics": metrics}


# ── Querying ───────────────────────────────────────────────────────


def get_series(metric: str, window: timedelta = DEFAULT_WINDOW) -> list[dict]:
    """Return ``[{"ts": iso, "value": number}]`` for ``metric`` in ``window``.

    Entries lacking the requested metric (e.g. a sample taken before that
    drive existed) are skipped, not zero-filled — sparklines should show
    the data we have, not invent a baseline.
    """
    history = load_history()
    cutoff = datetime.now() - window
    out: list[dict] = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        m = entry.get("metrics") or {}
        if not isinstance(m, dict) or metric not in m:
            continue
        out.append({"ts": entry["timestamp"], "value": m[metric]})
    return out


def list_metrics() -> list[str]:
    """Return every metric key that has ever been recorded, sorted."""
    seen: set[str] = set()
    for entry in load_history():
        if not isinstance(entry, dict):
            continue
        m = entry.get("metrics") or {}
        if isinstance(m, dict):
            seen.update(m.keys())
    return sorted(seen)


def get_all_series(window: timedelta = DEFAULT_WINDOW) -> dict:
    """Return ``{metric: [{ts, value}, ...]}`` for every known metric.

    Single pass over history (vs N passes via ``get_series``) so the
    /api/metrics/history route stays O(samples) regardless of how many
    metrics the dashboard wants to render.
    """
    history = load_history()
    cutoff = datetime.now() - window
    out: dict[str, list[dict]] = {}
    for entry in history:
        if not isinstance(entry, dict):
            continue
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", ""))
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        m = entry.get("metrics") or {}
        if not isinstance(m, dict):
            continue
        for key, value in m.items():
            out.setdefault(key, []).append({"ts": entry["timestamp"], "value": value})
    return out
