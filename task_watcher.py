"""task_watcher.py -- Scheduled-task health observer.

Watches the logs of scheduled tasks this app owns (today: SystemHealthDiag)
and surfaces crash-loop / silent-failure patterns as dashboard concerns.

Motivation: on 2026-04-18 SystemHealthDiag was crashlooping on a
UnicodeEncodeError for days and the only way anyone noticed was because
the machine was crawling. The tray never knew.

Public API:
    MANAGED_TASKS                 -- list of (task_name, log_dir, log_prefix)
    analyze_task_logs(...)        -- log-only health summary
    get_schtask_info(task_name)   -- parses ``schtasks /query /v /fo CSV``
    get_task_health(task_spec)    -- combined view for a single task
    get_all_task_health()         -- for every managed task
    concerns_from_health(results) -- list of dashboard concern dicts
"""

from __future__ import annotations

import csv
import glob
import io
import os
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

# ── Configuration ──────────────────────────────────────────────────

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_DIR = os.path.join(REPO_ROOT, "Logs")

# (display_name, scheduled_task_name, log_dir, log_prefix)
MANAGED_TASKS: list[tuple[str, str, str, str]] = [
    ("System Health Diagnostic", "SystemHealthDiagnostic", DEFAULT_LOG_DIR, "SystemHealthDiag_"),
]

# Detection thresholds
CRASHLOOP_WINDOW = timedelta(hours=24)
CRASHLOOP_MIN_FAILURES = 3
STALE_SUCCESS_WINDOW = timedelta(hours=48)
RECENT_ACTIVITY_WINDOW = timedelta(hours=72)


# ── Data classes ───────────────────────────────────────────────────


@dataclass
class LogSummary:
    path: str
    timestamp: datetime | None
    ok: bool
    exception_signature: str | None  # e.g. "UnicodeEncodeError" or None
    size_bytes: int

    def as_dict(self) -> dict:
        return {
            "path": os.path.basename(self.path),
            "timestamp": self.timestamp.isoformat(timespec="seconds") if self.timestamp else None,
            "ok": self.ok,
            "exception_signature": self.exception_signature,
            "size_bytes": self.size_bytes,
        }


# ── Log parsing ────────────────────────────────────────────────────

# A Python traceback or ``[Class]Error:`` line marks a failure -- UNLESS the
# log also carries a success marker BEFORE the error (e.g. the 2026-04-14 -
# 18 SystemHealthDiag crashloop: it finished its real work, emailed the
# report, then hit a UnicodeEncodeError printing the final ✓/✗ tally. The
# run had actually succeeded; only the cleanup crashed). The success
# markers below are taken from the real SystemHealthDiag output.
_ERROR_PATTERNS = [
    re.compile(r"^Traceback \(most recent call last\)", re.MULTILINE),
    re.compile(r"^([A-Z][A-Za-z]+Error):", re.MULTILINE),
    re.compile(r"FATAL:", re.MULTILINE),
]
_SUCCESS_MARKERS = [
    re.compile(r"Report saved to:", re.IGNORECASE),
    re.compile(r"Email sent successfully", re.IGNORECASE),
    re.compile(r"Diagnostic complete", re.IGNORECASE),
    re.compile(r"All checks passed", re.IGNORECASE),
]
_EXCEPTION_TYPE_RE = re.compile(r"^([A-Z][A-Za-z]+Error)\b", re.MULTILINE)

# How many bytes at the tail to read — avoids loading multi-MB logs
_LOG_TAIL_BYTES = 16 * 1024

# Filename timestamp: e.g. "SystemHealthDiag_2026-04-18_15-26-07.log"
_TS_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})[_-](\d{2}[-.]\d{2}[-.]\d{2})")


def _read_range(path: str, start: int, nbytes: int) -> str:
    """Read ``nbytes`` bytes from ``start``, auto-detecting UTF-16 LE vs UTF-8.

    Returns '' on any read error.
    """
    try:
        with open(path, "rb") as f:
            head_bom = f.read(2)
            f.seek(start)
            raw = f.read(nbytes)
    except OSError:
        return ""

    if head_bom == b"\xff\xfe":
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _read_tail(path: str, nbytes: int = _LOG_TAIL_BYTES) -> str:
    """Read the last ``nbytes`` of a file, auto-detecting encoding."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
    except OSError:
        return ""
    return _read_range(path, max(0, size - nbytes), min(nbytes, size))


def _read_head(path: str, nbytes: int = _LOG_TAIL_BYTES) -> str:
    """Read the first ``nbytes`` of a file, auto-detecting encoding."""
    return _read_range(path, 0, nbytes)


def _timestamp_from_name(path: str) -> datetime | None:
    """Parse the date-time encoded in the filename. Returns None if not found."""
    name = os.path.basename(path)
    m = _TS_IN_NAME.search(name)
    if not m:
        return None
    date_part, time_part = m.group(1), m.group(2)
    # Normalise HH-MM-SS or HH.MM.SS to HH:MM:SS
    time_part = time_part.replace("-", ":").replace(".", ":")
    try:
        return datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_log(path: str) -> LogSummary:
    """Return a LogSummary describing one log file.

    A log is a FAILURE if a traceback / Error: pattern is present AND no
    success marker is found. If a success marker is present (e.g. 'Report
    saved to:' or 'Email sent successfully') the run is considered OK even
    if a trailing exception occurred during cleanup. The exception
    signature is still captured for observability.

    Success markers are searched in BOTH the head and the tail of the
    file -- SystemHealthDiag logs can be 50+ KB and the success line
    may live early in the run (before a cleanup crash that gets
    appended at the end). Audit finding 2026-04-19.
    """
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        pass

    tail = _read_tail(path)
    has_error = any(p.search(tail) for p in _ERROR_PATTERNS)
    # For small files the head overlaps the tail -- skip the duplicate read
    head = tail if size <= _LOG_TAIL_BYTES else _read_head(path)
    has_success_marker = any(p.search(head) or p.search(tail) for p in _SUCCESS_MARKERS)
    exc_match = _EXCEPTION_TYPE_RE.search(tail)
    exc_sig = exc_match.group(1) if exc_match else None

    # Success: either no error, OR the work completed before the error
    ok = (not has_error) or has_success_marker

    return LogSummary(
        path=path,
        timestamp=_timestamp_from_name(path),
        ok=ok,
        exception_signature=exc_sig,
        size_bytes=size,
    )


# ── Aggregation ────────────────────────────────────────────────────


def _list_logs(log_dir: str, prefix: str) -> list[str]:
    """All log files matching prefix in log_dir, newest first."""
    pattern = os.path.join(log_dir, f"{prefix}*.log")
    paths = glob.glob(pattern)
    paths.sort(key=lambda p: _timestamp_from_name(p) or datetime.min, reverse=True)
    return paths


def analyze_task_logs(
    log_dir: str,
    log_prefix: str,
    now: datetime | None = None,
) -> dict:
    """Analyse all logs for one task.

    Returns:
        {
            "log_count": int,
            "runs_in_24h": int,
            "failures_in_24h": int,
            "last_run": datetime | None,
            "last_success": datetime | None,
            "last_failure": datetime | None,
            "dominant_exception": str | None,
            "recent_logs": list[dict],           # last 10 summaries, newest first
            "crashloop_detected": bool,          # ≥ CRASHLOOP_MIN_FAILURES in 24h
            "success_stale": bool,               # no success in STALE_SUCCESS_WINDOW
            "inactive": bool,                    # no runs at all in RECENT_ACTIVITY_WINDOW
        }
    """
    now = now or datetime.now()
    crash_cutoff = now - CRASHLOOP_WINDOW
    stale_cutoff = now - STALE_SUCCESS_WINDOW
    active_cutoff = now - RECENT_ACTIVITY_WINDOW

    logs = _list_logs(log_dir, log_prefix)
    summaries = [parse_log(p) for p in logs]

    runs_in_24h = 0
    failures_in_24h = 0
    last_run = None
    last_success = None
    last_failure = None
    exc_counts: dict[str, int] = {}

    for s in summaries:
        if s.timestamp is None:
            continue
        if last_run is None or s.timestamp > last_run:
            last_run = s.timestamp
        if s.ok and (last_success is None or s.timestamp > last_success):
            last_success = s.timestamp
        if not s.ok and (last_failure is None or s.timestamp > last_failure):
            last_failure = s.timestamp
        if s.timestamp >= crash_cutoff:
            runs_in_24h += 1
            if not s.ok:
                failures_in_24h += 1
        if s.exception_signature:
            exc_counts[s.exception_signature] = exc_counts.get(s.exception_signature, 0) + 1

    dominant_exc = max(exc_counts.items(), key=lambda kv: kv[1])[0] if exc_counts else None

    return {
        "log_count": len(summaries),
        "runs_in_24h": runs_in_24h,
        "failures_in_24h": failures_in_24h,
        "last_run": last_run.isoformat(timespec="seconds") if last_run else None,
        "last_success": last_success.isoformat(timespec="seconds") if last_success else None,
        "last_failure": last_failure.isoformat(timespec="seconds") if last_failure else None,
        "dominant_exception": dominant_exc,
        "recent_logs": [s.as_dict() for s in summaries[:10]],
        "crashloop_detected": failures_in_24h >= CRASHLOOP_MIN_FAILURES,
        "success_stale": last_success is None or last_success < stale_cutoff,
        "inactive": last_run is None or last_run < active_cutoff,
    }


# ── schtasks query ─────────────────────────────────────────────────


# /v = verbose (includes last-run timestamp + return code), /fo CSV = stable parse format.
# quiet_timeout is a kwarg consumed by the headless subprocess wrapper in
# windesktopmgr.py; it degrades TimeoutExpired logs to DEBUG so this
# helper doesn't pollute the selftest log-error gate when it's called
# while the scheduler is unresponsive.
def get_schtask_info(task_name: str) -> dict:
    """Return {registered, last_run, last_result, status, next_run, error}.

    All fields may be None / absent. ``registered=False`` means the task
    was not found in Task Scheduler.
    """
    empty = {
        "registered": False,
        "last_run": None,
        "last_result": None,
        "status": None,
        "next_run": None,
        "error": None,
    }
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/tn", task_name, "/v", "/fo", "CSV"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {**empty, "error": str(e)}

    if r.returncode != 0:
        # schtasks returns 1 when the task isn't found; treat that as "not registered"
        return {**empty, "error": (r.stderr or "").strip() or None}

    try:
        reader = csv.DictReader(io.StringIO(r.stdout))
        row = next(reader, None)
    except csv.Error as e:
        return {**empty, "error": f"csv parse: {e}"}

    if not row:
        return {**empty, "error": "empty schtasks output"}

    last_run = row.get("Last Run Time") or None
    last_result_str = row.get("Last Result") or ""
    try:
        last_result = int(last_result_str) if last_result_str else None
    except ValueError:
        last_result = None

    return {
        "registered": True,
        "last_run": last_run if last_run and last_run != "N/A" else None,
        "last_result": last_result,
        "status": row.get("Status") or row.get("Scheduled Task State") or None,
        "next_run": row.get("Next Run Time") or None,
        "error": None,
    }


# ── Combined health + concerns ─────────────────────────────────────


def get_task_health(task_spec: tuple[str, str, str, str]) -> dict:
    """task_spec = (display_name, schtask_name, log_dir, log_prefix)."""
    display, schtask, log_dir, prefix = task_spec
    log = analyze_task_logs(log_dir, prefix)
    info = get_schtask_info(schtask)
    return {
        "display_name": display,
        "task_name": schtask,
        "log_summary": log,
        "schtasks": info,
    }


def get_all_task_health(tasks: Iterable[tuple[str, str, str, str]] | None = None) -> list[dict]:
    tasks = tasks if tasks is not None else MANAGED_TASKS
    return [get_task_health(t) for t in tasks]


def concerns_from_health(results: list[dict]) -> list[dict]:
    """Translate health results into dashboard concern dicts.

    One concern at most per task, with the most severe condition winning.
    Silent (no concern) when:
        * the task is not registered AND no logs exist -- the user simply
          hasn't set it up on this machine; nagging them is noise, not value
        * the task is healthy

    Concerns:
        * crashloop (>=3 failures in 24h regardless of registration) -> critical
        * registered but never succeeded in 48h -> warning
        * has old logs but not registered -> warning
    """
    concerns = []
    for r in results:
        display = r.get("display_name", "?")
        log = r.get("log_summary", {})
        info = r.get("schtasks", {})
        registered = info.get("registered", False)
        has_logs = log.get("log_count", 0) > 0

        # Crashloop always surfaces -- evidence is in the logs regardless
        # of whether the scheduler still has the task registered.
        if log.get("crashloop_detected"):
            fails = log.get("failures_in_24h", 0)
            exc = log.get("dominant_exception") or "(unknown)"
            concerns.append(
                {
                    "level": "critical",
                    "tab": "dashboard",
                    "icon": "⏱",
                    "title": f"{display}: crash loop ({fails} failures in 24h)",
                    "detail": f"Repeated exception: {exc}. Check Logs/ for details.",
                    "action": "Open Logs folder",
                    "action_fn": "openLogsFolder()",
                }
            )
            continue

        # "Had logs but task vanished from scheduler" -- the task WAS set
        # up, now it isn't. Worth a warning.
        if not registered and has_logs:
            concerns.append(
                {
                    "level": "warning",
                    "tab": "dashboard",
                    "icon": "⏱",
                    "title": f"{display}: scheduled task unregistered",
                    "detail": "The task has historical log files but is not currently registered with Task Scheduler.",
                    "action": "Re-register task",
                    "action_fn": "",
                }
            )
            continue

        # Stale-success warning only when the task is actually expected to run
        if registered and log.get("success_stale"):
            last_success = log.get("last_success") or "never"
            concerns.append(
                {
                    "level": "warning",
                    "tab": "dashboard",
                    "icon": "⏱",
                    "title": f"{display}: no successful run in 48h",
                    "detail": f"Last success: {last_success}. Task may be silently failing.",
                    "action": "View logs",
                    "action_fn": "openLogsFolder()",
                }
            )
    return concerns
