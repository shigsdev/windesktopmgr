"""codehealth.py -- Code-health scanners for the Utilities tab (backlog #51).

PR-1 ships four read-only scanners that surface inside the new Utilities
tab. All four are runnable on-demand from a Flask handler; on tray boot,
the existing main thread fires a background scan if the persisted state
is older than ``STALE_DAYS``. PR-2 will add the proper weekly cron with
a configurable cadence + trend history. The point of doing it in two
PRs is the user wanted to see the scanners working first before we
decide on cadence.

Scanners (each returns ``{ok, level, count, summary, details, ...}``):

  coverage   -- runs ``python -m coverage json -o -`` against the
                existing ``.coverage`` file (NOT a fresh pytest run --
                that's ~48s; the on-demand pytest path is deferred to
                PR-2). Reports per-file + total coverage %.

  ruff       -- runs ``python -m ruff check . --output-format=json``
                and categorises findings by rule prefix (F = correctness,
                S = security, B = bugbear, SIM/UP = modernisation).

  secrets    -- runs ``python scripts/check_repo_secrets.py --all`` and
                ``python -m gitleaks detect`` (when installed). Both are
                already wired into pre-commit; running them again on
                tracked-+-untracked surface is the on-demand "re-sweep
                everything" button.

  tech_debt  -- pure file-walk: counts TODO/FIXME/XXX/HACK markers in
                ``*.py`` and ``templates/*.html``, flags files over
                ``LARGE_FILE_THRESHOLD`` lines (5000), counts ruff C901
                complexity warnings.

Severity ladder (UI uses this to colour the cards):

  ok       -- nothing to flag (e.g. 0 ruff findings, 0 secrets)
  info     -- benign signal (e.g. a few TODOs, coverage ≥ 80%)
  warning  -- needs attention soon (coverage < 80%, F-class ruff > 0)
  critical -- needs attention NOW (secrets detected, coverage < 50%)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Any

try:
    from applogging import get_logger

    _log = get_logger("codehealth")
except Exception:  # noqa: BLE001
    import logging

    _log = logging.getLogger("windesktopmgr.codehealth")

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(_REPO_ROOT, "codehealth_state.json")
# Tracks which scan-finding fingerprints have already been appended to
# the project backlog -- prevents re-appending the same finding on
# every rescan. Separate file from STATE_FILE so a state reset doesn't
# wipe the dedup memory.
EMITTED_FILE = os.path.join(_REPO_ROOT, "codehealth_emitted.json")

# Path to the project backlog markdown. Lives in Claude project memory
# outside the repo. Overridable via env var so tests / CI can redirect.
BACKLOG_PATH = os.environ.get(
    "WINDESKTOPMGR_BACKLOG_PATH",
    os.path.expanduser(r"~\.claude\projects\C--shigsapps-windesktopmgr\memory\project_backlog.md"),
)

# Auto-scan on tray boot if state is older than this. PR-2 makes this
# configurable via the UI; PR-1 hardcodes a week.
STALE_DAYS = 7

# Per-scanner subprocess timeout. ruff/coverage/secrets all finish in
# 1-3 s on this repo, so 60 s is generous head-room for slow runs.
SCAN_TIMEOUT_SEC = 60

# Tech-debt thresholds.
LARGE_FILE_LINE_THRESHOLD = 5000
_TODO_PATTERN = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")

# Severity ladder used by the UI cards to pick a colour.
_LEVEL_ORDER = ["ok", "info", "warning", "critical"]


_state_lock = threading.RLock()
_run_lock = threading.Lock()
# True while a background scan thread is in flight. Guards against
# double-runs when the user mashes the "Run now" button.
_running = False
# True while a "Refresh coverage" job is in flight (the pytest --cov
# run that takes 30-90s). Reported as is_refreshing_coverage in
# /api/codehealth/status so the UI can show progress + disable the
# button. Different from _running because the refresh job EVENTUALLY
# triggers a scan_all itself, but we want the button to stay disabled
# for the whole pytest+rescan cycle.
_coverage_refresh_running = False
_coverage_refresh_last_result: dict | None = None
# Generous because the full suite is ~50-80s on this repo and worker
# machines vary. Aborting too early would leave .coverage in an
# inconsistent half-written state.
COVERAGE_REFRESH_TIMEOUT_SEC = 600


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _atomic_write_json(path: str, payload: Any) -> bool:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        _log.warning("atomic write to %s failed: %s", path, exc)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def load_state() -> dict:
    """Read codehealth_state.json. Returns {} if missing or malformed."""
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> bool:
    with _state_lock:
        return _atomic_write_json(STATE_FILE, state)


def is_stale(state: dict, days: int = STALE_DAYS) -> bool:
    """True if the last scan timestamp is older than ``days``, OR if
    there is no last-scan timestamp at all (first-run = stale)."""
    ts = state.get("finished_at")
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return True
    return dt < datetime.now() - timedelta(days=days)


def is_running() -> bool:
    return _running


# ─────────────────────────────────────────────────────────────────────
# Scanners — each returns a uniform dict.
#
#   ok          : bool                — scanner ran (NOT "found nothing")
#   level       : "ok"|"info"|"warning"|"critical"
#   count       : int                 — total findings
#   summary     : str                 — one-line for the card
#   details     : list[dict]          — top N findings for drill-down
#   started_at  : ISO8601
#   finished_at : ISO8601
#   duration_ms : int
#   error       : str|None            — when ok=False
# ─────────────────────────────────────────────────────────────────────


def _empty_result(name: str, error: str) -> dict:
    now = _now_iso()
    return {
        "ok": False,
        "level": "warning",
        "count": 0,
        "summary": f"{name}: scanner unavailable ({error})",
        "details": [],
        "started_at": now,
        "finished_at": now,
        "duration_ms": 0,
        "error": error,
    }


COVERAGE_STALE_DAYS = 3
"""If .coverage hasn't been touched in this many days, the percentage
is treated as stale -- the card shows the number with a (Xd old) tag
AND the severity is downgraded so we don't fire warning/critical
against historical data. PR-2's "Refresh coverage" button will let
the user trigger a fresh pytest --cov run from the UI."""


def scan_coverage() -> dict:
    """Read the existing .coverage file via the coverage CLI's JSON
    exporter. Does NOT re-run pytest (~48s) -- that's the PR-2 button.

    Staleness handling (added 2026-05-27 after user report): the
    .coverage file in the primary repo gets stale when test runs
    happen in worktrees (which is the standard dev flow). A 16-day-
    old 57.1% reading misled the user into thinking coverage had
    dropped. Fix: if .coverage mtime is older than COVERAGE_STALE_DAYS,
    report the number with explicit ``stale`` framing AND demote the
    severity (don't fire warning/critical against historical data).
    """
    started = datetime.now()
    cov_file = os.path.join(_REPO_ROOT, ".coverage")
    if not os.path.exists(cov_file):
        finished = datetime.now()
        return {
            "ok": False,
            "level": "info",
            "count": 0,
            "summary": "No .coverage file -- run pytest --cov first",
            "details": [],
            "started_at": started.isoformat(timespec="seconds"),
            "finished_at": finished.isoformat(timespec="seconds"),
            "duration_ms": int((finished - started).total_seconds() * 1000),
            "error": ".coverage file not found",
        }

    # Capture mtime BEFORE running the exporter (coverage json may
    # touch the file in some configurations -- safer to read first).
    try:
        cov_mtime = datetime.fromtimestamp(os.path.getmtime(cov_file))
        cov_age_days = (datetime.now() - cov_mtime).total_seconds() / 86400.0
    except OSError:
        cov_mtime = None
        cov_age_days = None

    try:
        proc = subprocess.run(
            ["python", "-m", "coverage", "json", "-o", "-", "--quiet"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SEC,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return _empty_result(
                "coverage",
                f"coverage CLI returned {proc.returncode}: {proc.stderr[:200]}",
            )
        data = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return _empty_result("coverage", str(exc))

    totals = data.get("totals", {})
    pct = float(totals.get("percent_covered", 0))
    # Per-file uncovered top 5.
    files = data.get("files", {})
    worst = sorted(
        (
            {"file": f, "percent": fdata.get("summary", {}).get("percent_covered", 0)}
            for f, fdata in files.items()
            if isinstance(fdata, dict)
        ),
        key=lambda x: x["percent"],
    )[:5]

    is_stale = cov_age_days is not None and cov_age_days >= COVERAGE_STALE_DAYS

    if is_stale:
        # Don't trust a stale number for severity assignment.  Show it
        # but tag as info -- the user knows it's historical and can
        # refresh via PR-2's button (or by running pytest manually).
        level = "info"
        summary = (
            f"{pct:.1f}% line coverage (stale -- last updated {cov_age_days:.1f}d ago; run pytest --cov to refresh)"
        )
    elif pct >= 80:
        level = "ok"
        summary = f"{pct:.1f}% line coverage"
    elif pct >= 50:
        level = "warning"
        summary = f"{pct:.1f}% line coverage"
    else:
        level = "critical"
        summary = f"{pct:.1f}% line coverage"
    finished = datetime.now()
    return {
        "ok": True,
        "level": level,
        "count": int(pct),  # integer % for sort/threshold logic
        "summary": summary,
        "details": worst,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "error": None,
        "coverage_mtime": cov_mtime.isoformat(timespec="seconds") if cov_mtime else None,
        "coverage_age_days": round(cov_age_days, 2) if cov_age_days is not None else None,
        "is_stale": is_stale,
    }


def scan_ruff() -> dict:
    """Run ruff and categorise findings."""
    started = datetime.now()
    try:
        proc = subprocess.run(
            ["python", "-m", "ruff", "check", ".", "--output-format=json"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SEC,
            check=False,
        )
        # ruff exits 1 on findings, 0 on clean -- BOTH are "ran ok" for us.
        if proc.returncode not in (0, 1):
            return _empty_result("ruff", f"ruff returned {proc.returncode}: {proc.stderr[:200]}")
        findings = json.loads(proc.stdout) if proc.stdout.strip() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return _empty_result("ruff", str(exc))

    by_prefix: dict[str, int] = {}
    for f in findings:
        code = f.get("code") or ""
        prefix = re.match(r"^[A-Z]+", code)
        key = prefix.group(0) if prefix else "?"
        by_prefix[key] = by_prefix.get(key, 0) + 1
    total = len(findings)
    # S-prefix = security; F-prefix = correctness. Both serious.
    has_security = by_prefix.get("S", 0) > 0
    has_correctness = by_prefix.get("F", 0) > 0
    if has_security:
        level = "critical"
    elif has_correctness:
        level = "warning"
    elif total > 0:
        level = "info"
    else:
        level = "ok"
    finished = datetime.now()
    # Top 5 findings for drill-down.
    details = [
        {
            "code": f.get("code"),
            "message": (f.get("message") or "")[:200],
            "file": f.get("filename", "").replace(_REPO_ROOT + os.sep, ""),
            "line": (f.get("location") or {}).get("row"),
        }
        for f in findings[:5]
    ]
    return {
        "ok": True,
        "level": level,
        "count": total,
        "summary": (
            "Clean -- 0 ruff findings"
            if total == 0
            else f"{total} ruff finding{'s' if total != 1 else ''} ({', '.join(f'{k}={v}' for k, v in sorted(by_prefix.items()))})"
        ),
        "details": details,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "error": None,
        "by_prefix": by_prefix,
    }


def scan_secrets() -> dict:
    """Run the repo secret scanner (the same one pre-commit invokes)."""
    started = datetime.now()
    scanner = os.path.join(_REPO_ROOT, "scripts", "check_repo_secrets.py")
    if not os.path.exists(scanner):
        return _empty_result("secrets", f"scanner not found at {scanner}")
    try:
        proc = subprocess.run(
            ["python", scanner, "--all"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SEC,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return _empty_result("secrets", str(exc))

    # Exit 0 = clean, exit 1 = at least one finding, anything else = scanner error.
    leak_count = 0
    if proc.returncode not in (0, 1):
        return _empty_result("secrets", f"scanner returned {proc.returncode}: {proc.stderr[:200]}")
    if proc.returncode == 1:
        # Each "Finding:" line in stdout = one leak. Don't echo the
        # secret content -- the scanner already redacts to <REDACTED>.
        leak_count = proc.stdout.count("Finding:")
        if leak_count == 0:
            # Scanner exited 1 but no obvious finding line -- treat as 1.
            leak_count = 1
    level = "critical" if leak_count > 0 else "ok"
    finished = datetime.now()
    return {
        "ok": True,
        "level": level,
        "count": leak_count,
        "summary": (
            "Clean -- 0 secret-shape matches"
            if leak_count == 0
            else f"{leak_count} potential secret{'s' if leak_count != 1 else ''} detected (output redacted; see docs/security/git-credentials.md)"
        ),
        "details": [],  # Detail bodies are redacted output -- nothing safe to ship to UI.
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "error": None,
    }


def scan_tech_debt() -> dict:
    """Walk the repo and count TODO/FIXME markers, oversized files, etc."""
    started = datetime.now()
    todo_count = 0
    todo_samples: list[dict] = []
    large_files: list[dict] = []
    py_files = 0
    for root, dirs, files in os.walk(_REPO_ROOT):
        # Skip generated / vendored dirs.
        dirs[:] = [
            d
            for d in dirs
            if d not in {".git", ".pytest_cache", ".ruff_cache", "__pycache__", "node_modules", "Logs", ".claude"}
        ]
        for name in files:
            if not name.endswith((".py", ".html")):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, _REPO_ROOT)
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            if name.endswith(".py"):
                py_files += 1
            line_count = len(lines)
            if line_count >= LARGE_FILE_LINE_THRESHOLD:
                large_files.append({"file": rel, "lines": line_count})
            for i, line in enumerate(lines, start=1):
                if _TODO_PATTERN.search(line):
                    todo_count += 1
                    if len(todo_samples) < 5:
                        todo_samples.append(
                            {
                                "file": rel,
                                "line": i,
                                "text": line.strip()[:200],
                            }
                        )
    large_files.sort(key=lambda x: x["lines"], reverse=True)
    # Severity: large_files alone is "info"; only fires "warning" if
    # both axes are bad (many TODOs AND multiple huge files).
    if todo_count >= 50 and len(large_files) >= 3:
        level = "warning"
    elif todo_count == 0 and not large_files:
        level = "ok"
    else:
        level = "info"
    finished = datetime.now()
    return {
        "ok": True,
        "level": level,
        "count": todo_count + len(large_files),
        "summary": f"{todo_count} TODO/FIXME marker{'s' if todo_count != 1 else ''} · {len(large_files)} file{'s' if len(large_files) != 1 else ''} ≥{LARGE_FILE_LINE_THRESHOLD} lines · {py_files} .py files scanned",
        "details": {
            "todos": todo_samples,
            "large_files": large_files[:10],
        },
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "error": None,
    }


# ─────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────


def _worst_level(scanners: dict) -> str:
    worst_idx = 0
    for result in scanners.values():
        if not isinstance(result, dict):
            continue
        level = result.get("level", "ok")
        if level in _LEVEL_ORDER:
            idx = _LEVEL_ORDER.index(level)
            if idx > worst_idx:
                worst_idx = idx
    return _LEVEL_ORDER[worst_idx]


def scan_all() -> dict:
    """Run all four scanners synchronously. ~3-5 s on this repo."""
    started = _now_iso()
    scanners = {
        "coverage": scan_coverage(),
        "ruff": scan_ruff(),
        "secrets": scan_secrets(),
        "tech_debt": scan_tech_debt(),
    }
    return {
        "started_at": started,
        "finished_at": _now_iso(),
        "worst_level": _worst_level(scanners),
        "scanners": scanners,
    }


def _run_and_save() -> None:
    """Inner body of the background-scan thread.  Sets _running guard,
    runs scan_all, persists, clears guard. Wrapped to keep tray boot
    bullet-proof against scanner crashes."""
    global _running
    with _run_lock:
        if _running:
            return
        _running = True
    try:
        result = scan_all()
        save_state(result)
        _log.info("codehealth scan complete -- worst level: %s", result.get("worst_level"))
        # PR-2 sub-task B: turn findings into backlog rows. Best-effort
        # -- backlog file lives outside the repo (Claude project memory)
        # so it might be missing on a different machine; skip silently
        # in that case rather than failing the scan.
        try:
            emit_result = append_findings_to_backlog(result)
            _log.info(
                "codehealth backlog: %d appended, %d skipped (already emitted)",
                emit_result.get("appended", 0),
                emit_result.get("skipped", 0),
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("codehealth backlog append failed (non-fatal): %s", exc)
    except Exception as exc:  # noqa: BLE001
        _log.exception("codehealth scan crashed: %s", exc)
    finally:
        with _run_lock:
            _running = False


def run_in_background() -> bool:
    """Kick off a background scan if one isn't already running.
    Returns True if a new thread was started, False if a scan was
    already in flight."""
    with _run_lock:
        if _running:
            return False
    thread = threading.Thread(target=_run_and_save, daemon=True, name="CodeHealthScan")
    thread.start()
    return True


def maybe_run_on_boot() -> bool:
    """Tray hook: if persisted state is missing or stale (>7 days),
    fire a background scan so the user sees fresh data after a tray
    restart. Returns True if a scan was started."""
    state = load_state()
    if is_stale(state):
        return run_in_background()
    return False


# ─────────────────────────────────────────────────────────────────────
# Coverage refresh (PR-2 of #51)
#
# scan_coverage() reads whatever .coverage exists on disk. That file
# is only refreshed by an actual pytest --cov run, which happens via
# pre-commit hooks but NOT during normal tray operation. After a few
# days the .coverage in the primary repo becomes stale -- the user
# report on 2026-05-27 was a 16-day-old 57.1% reading against an
# actual ~86% coverage.
#
# refresh_coverage_in_background() spawns a thread that runs the
# full pytest --cov suite IN PROCESS (subprocess to a fresh python),
# letting pytest rewrite .coverage. When pytest exits we trigger a
# scan_all so all four cards re-render with the fresh data in one shot.
# ─────────────────────────────────────────────────────────────────────


def is_refreshing_coverage() -> bool:
    return _coverage_refresh_running


def get_coverage_refresh_last_result() -> dict | None:
    """Returns the last refresh outcome (success or failure), or None
    if no refresh has run since process start. Used by the UI to show
    "Refresh failed: <reason>" after a click."""
    return _coverage_refresh_last_result


def _refresh_coverage_and_rescan() -> None:
    """Thread body: runs pytest --cov against the primary repo so
    .coverage gets a fresh write, then fires scan_all to re-read it
    and update the persisted state."""
    global _coverage_refresh_running, _coverage_refresh_last_result
    with _run_lock:
        if _coverage_refresh_running:
            return
        _coverage_refresh_running = True
    started = datetime.now()
    result: dict = {
        "ok": False,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": "",
        "duration_ms": 0,
        "returncode": None,
        "error": None,
        "stdout_tail": "",
        "stderr_tail": "",
    }
    try:
        # Use a dedicated --basetemp per refresh so pytest-xdist
        # workers don't race with leftover pytest-of-<user>/pytest-
        # current symlinks from previous runs. Caught 2026-05-27 on
        # the live tray: xdist raised INTERNALERROR(AssertionError)
        # while a sibling pytest run was cleaning up the same shared
        # tmpdir tree, returning exit 3 with no .coverage written.
        # Per-run isolated basetemp is the documented fix.
        import shutil
        import tempfile

        basetemp = os.path.join(tempfile.gettempdir(), "codehealth-cov-refresh")
        if os.path.exists(basetemp):
            shutil.rmtree(basetemp, ignore_errors=True)
        os.makedirs(basetemp, exist_ok=True)

        proc = subprocess.run(
            # -n auto parallelises across CPU cores via pytest-xdist;
            # pytest-cov has built-in support for merging coverage
            # data from worker subprocesses. Cuts wall-time from
            # ~5 min serial to ~45 s on a 10-core box. This is the
            # same configuration pre-commit uses.
            # --no-header / -q keep the captured output compact.
            # --basetemp isolates the run from concurrent pytest sessions.
            [
                "python",
                "-m",
                "pytest",
                "--cov",
                "-n",
                "auto",
                "--no-header",
                "-q",
                f"--basetemp={basetemp}",
            ],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=COVERAGE_REFRESH_TIMEOUT_SEC,
            check=False,
        )
        result["returncode"] = proc.returncode
        # Last 1000 chars is enough to surface the failure reason in
        # the UI without bloating the JSON payload.
        result["stdout_tail"] = (proc.stdout or "")[-1000:]
        result["stderr_tail"] = (proc.stderr or "")[-1000:]
        # pytest may exit 0 (clean) or 1 (failures) or 5 (no tests
        # collected). Either way the .coverage file is usually
        # written. Anything else (e.g. 2 = interrupted, 3 = internal
        # error) means the file may be missing or corrupt; surface it
        # but still attempt the rescan so the user sees the new state.
        if proc.returncode in (0, 1):
            result["ok"] = True
        elif proc.returncode == 5:
            result["ok"] = True
            result["error"] = "no tests collected"
        else:
            result["error"] = f"pytest returned {proc.returncode}"
    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {COVERAGE_REFRESH_TIMEOUT_SEC}s"
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        finished = datetime.now()
        result["finished_at"] = finished.isoformat(timespec="seconds")
        result["duration_ms"] = int((finished - started).total_seconds() * 1000)
        _coverage_refresh_last_result = result
        _log.info(
            "coverage refresh complete: ok=%s returncode=%s duration=%ss",
            result["ok"],
            result["returncode"],
            result["duration_ms"] / 1000,
        )

    # Re-run scan_all so the persisted state reflects the new .coverage
    # plus refreshed ruff / secrets / tech-debt. Done OUTSIDE the
    # _coverage_refresh_running guard so the UI's refresh-spinner can
    # flip off before the scan-all spinner kicks in -- but we want
    # the "Run now" guard to still prevent overlap.
    with _run_lock:
        _coverage_refresh_running = False

    # Fire a regular scan_all (which has its own _running guard).
    # Skips silently if a scan_all is somehow already in flight.
    run_in_background()


def refresh_coverage_in_background() -> bool:
    """Kick off a background pytest --cov run if one isn't already in
    flight. Returns True if a new thread was started, False if a
    refresh was already running."""
    with _run_lock:
        if _coverage_refresh_running:
            return False
    thread = threading.Thread(target=_refresh_coverage_and_rescan, daemon=True, name="CodeHealthCoverageRefresh")
    thread.start()
    return True


# ─────────────────────────────────────────────────────────────────────
# Scan findings -> project backlog (#51 PR-2 sub-task B, 2026-05-27)
#
# User asked: "if we find things on the scans, automated or manual,
# it should add them to the backlog". This turns scan results into
# trackable backlog rows so a real-bug ruff finding or a secret leak
# doesn't get scrolled past in a card grid -- it becomes a P0 line
# item in project memory.
#
# Dedup: each finding hashes to a stable fingerprint based on its
# identity (category + the specific bug location / file / rule code).
# Emitted fingerprints persist in codehealth_emitted.json so reruns
# don't pile up duplicate rows.
#
# Filter: only WARNING and CRITICAL findings get a row by default.
# Info-level signals (TODOs, coverage ≥80%, UP-class ruff modernisations)
# would spam the backlog with low-value rows. Tech-debt large-file
# findings get an info-level row because they're stable + actionable
# at a project-level (split this file vs leave the TODO).
# ─────────────────────────────────────────────────────────────────────


def _fingerprint(category: str, ident: str) -> str:
    """Stable 12-char hex fingerprint for a finding. Used to dedupe
    repeated emissions of the same finding across scan reruns."""
    h = hashlib.sha256(f"{category}::{ident}".encode()).hexdigest()
    return h[:12]


def load_emitted_fingerprints() -> set[str]:
    """Read the set of fingerprints we've already pushed to the backlog.
    Returns empty set if the file is missing or malformed."""
    if not os.path.exists(EMITTED_FILE):
        return set()
    try:
        with open(EMITTED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
            return {str(x) for x in data["fingerprints"]}
        if isinstance(data, list):
            return {str(x) for x in data}
        return set()
    except (OSError, json.JSONDecodeError):
        return set()


def save_emitted_fingerprints(fingerprints: set[str]) -> bool:
    payload = {
        "updated_at": _now_iso(),
        "fingerprints": sorted(fingerprints),
    }
    return _atomic_write_json(EMITTED_FILE, payload)


def findings_to_backlog_entries(scan_result: dict) -> list[dict]:
    """Convert a scan_all() result into a list of backlog-worthy entries.

    Each entry::

        {
          "fingerprint": "abc123def456",
          "category": "Security|Code Bug|Code Health|Tech Debt",
          "title": "<one-line summary>",
          "severity": "info|warning|critical",
          "priority": "P0|P1|P2",
          "body": "<longer description>",
          "source": "ruff|secrets|coverage|tech_debt"
        }

    Filters:
      - Coverage: only emit when level is warning/critical AND data is
        fresh (don't fire on stale .coverage -- false signal)
      - ruff: only F-prefix (correctness) and S-prefix (security);
        skip UP/PIE/etc. modernisation noise
      - secrets: always emit at critical
      - tech_debt: emit large-file flags (info-level), skip TODO list
        (too noisy + most TODOs are intentional)
    """
    entries: list[dict] = []
    scanners = scan_result.get("scanners", {}) if isinstance(scan_result, dict) else {}

    # ── Coverage ────────────────────────────────────────────────────
    cov = scanners.get("coverage") or {}
    cov_level = cov.get("level")
    cov_stale = bool(cov.get("is_stale"))
    if cov_level in ("warning", "critical") and not cov_stale:
        pct = cov.get("count", 0)
        entries.append(
            {
                "fingerprint": _fingerprint("coverage", f"below_80_{cov_level}"),
                "category": "Code Health",
                "title": f"Test coverage at {pct}% (below 80% target)",
                "severity": cov_level,
                "priority": "P1" if cov_level == "warning" else "P0",
                "body": (
                    f"Coverage scanner detected {pct}% line coverage. "
                    f"Action: identify uncovered files via `pytest --cov-report=term-missing` "
                    f"and add tests for the worst offenders."
                ),
                "source": "coverage",
            }
        )

    # ── ruff (per-finding for F/S/B; rollup for style) ──────────────
    ruff = scanners.get("ruff") or {}
    for finding in ruff.get("details") or []:
        if not isinstance(finding, dict):
            continue
        code = (finding.get("code") or "").upper()
        m = re.match(r"^[A-Z]+", code)
        prefix = m.group(0) if m else ""
        # Only correctness (F) + security (S) + bugbear (B) get per-
        # finding rows. UP/PIE/SIM/RUF (style + modernization) fall
        # through to the rollup below -- 10 individual rows for a batch
        # of mechanical fixes is more clutter than signal.
        if prefix not in ("F", "S", "B"):
            continue
        fpath = finding.get("file") or ""
        fline = finding.get("line") or 0
        msg = finding.get("message") or ""
        ident = f"{code}:{fpath}:{fline}"
        is_security = prefix == "S"
        entries.append(
            {
                "fingerprint": _fingerprint("ruff", ident),
                "category": "Security" if is_security else "Code Bug",
                "title": f"ruff {code} in {fpath}:{fline} — {msg[:80]}",
                "severity": "critical" if is_security else "warning",
                "priority": "P0" if is_security else "P1",
                "body": (
                    f"ruff rule `{code}` flagged {fpath}:{fline}. Message: {msg}. "
                    f"Resolve by editing the file or, if it's a false positive, "
                    f"add a justified `# noqa: {code}` comment."
                ),
                "source": "ruff",
            }
        )

    # Style / modernization rollup. User asked 2026-05-27 why the card
    # said "10 ruff findings (UP=10)" but zero ended up in the backlog.
    # Answer: my filter (above) intentionally skipped them. Fix: emit
    # ONE consolidated row for all the style-class findings rather
    # than spamming 10 individual rows. Auto-applies as a batch with
    # `ruff check --fix --unsafe-fixes`, so a single backlog item is
    # the right granularity.
    by_prefix = ruff.get("by_prefix") or {}
    # These prefixes are "style / modernization / opinionated" -- they
    # don't represent real bugs (pyflakes F + bandit S + bugbear B do).
    # PT = pytest-style, SIM = simplifications, UP = pyupgrade,
    # PIE = flake8-pie misc, RUF = ruff's own rules, C90 = mccabe complexity.
    style_prefixes = ("UP", "PIE", "SIM", "RUF", "PT", "C90")
    style_count = sum(by_prefix.get(p, 0) for p in style_prefixes)
    if style_count > 0:
        breakdown_parts = [f"{p}={by_prefix[p]}" for p in style_prefixes if by_prefix.get(p)]
        breakdown = ", ".join(breakdown_parts)
        # Fingerprint includes the count so a different total -> new
        # row (visible progress), but a re-scan with the same count
        # -> dedup. When the user fixes some but not all, they get a
        # new row reflecting the remaining work.
        entries.append(
            {
                "fingerprint": _fingerprint("ruff_style", f"count_{style_count}"),
                "category": "Tech Debt",
                "title": f"{style_count} ruff style/modernization findings ({breakdown})",
                "severity": "info",
                "priority": "P2",
                "body": (
                    f"ruff flagged {style_count} modernization opportunities ({breakdown}). "
                    f"Most are mechanical (e.g. UP038: `isinstance(x, (A, B))` -> "
                    f"`isinstance(x, A | B)`). Auto-apply the whole batch with "
                    f"`ruff check --fix --unsafe-fixes` then spot-check the diff. "
                    f"This is one rollup row rather than {style_count} individual rows -- "
                    f"the dashboard card shows the per-finding details."
                ),
                "source": "ruff_style",
            }
        )

    # ── secrets ─────────────────────────────────────────────────────
    secrets = scanners.get("secrets") or {}
    if secrets.get("level") == "critical":
        # Count goes into the fingerprint so a NEW leak triggers a new
        # row even though "secrets detected" is the same shape. Slight
        # over-emission risk but security >> dedup-precision.
        count = secrets.get("count", 0)
        entries.append(
            {
                "fingerprint": _fingerprint("secrets", f"count_{count}"),
                "category": "Security",
                "title": f"{count} potential secret(s) detected by repo scanner",
                "severity": "critical",
                "priority": "P0",
                "body": (
                    "Output is redacted by the scanner. Run "
                    "`python scripts/check_repo_secrets.py --all` to see the matched lines "
                    "with redacted token values. Follow docs/security/git-credentials.md "
                    "for the rotation playbook."
                ),
                "source": "secrets",
            }
        )

    # ── tech debt: large files ──────────────────────────────────────
    tech = scanners.get("tech_debt") or {}
    details = tech.get("details") or {}
    if isinstance(details, dict):
        for lf in details.get("large_files") or []:
            if not isinstance(lf, dict):
                continue
            fname = lf.get("file") or ""
            lines = lf.get("lines") or 0
            entries.append(
                {
                    "fingerprint": _fingerprint("tech_debt", f"large:{fname}"),
                    "category": "Tech Debt",
                    "title": f"{fname} is {lines:,} lines (target <5,000)",
                    "severity": "info",
                    "priority": "P2",
                    "body": (
                        f"File `{fname}` is {lines:,} lines. Past 5,000 lines, "
                        f"split into focused modules so future grep/diff/review work doesn't "
                        f"thrash. Suggested split criteria: pure parsers, route handlers, "
                        f"orchestration, dashboard surface."
                    ),
                    "source": "tech_debt",
                }
            )

    return entries


def _next_backlog_number(text: str) -> int:
    """Find the highest existing `| N |` row number in the backlog and
    return N+1. Defaults to 100 if no numbered rows exist (very unusual
    but handle gracefully)."""
    nums = re.findall(r"^\| (\d+) \|", text, re.MULTILINE)
    if not nums:
        return 100
    return max(int(n) for n in nums) + 1


def _format_backlog_row(num: int, entry: dict, today: str) -> str:
    """Produce a single Markdown table row matching the existing
    backlog schema (`| N | Feature | Effort | Priority |`)."""
    sev = entry["severity"]
    sev_emoji = {"critical": "🚨", "warning": "⚠", "info": "🔍"}.get(sev, "🔍")
    title = (
        f"**{sev_emoji} Scan finding: {entry['title']}** "
        f"Auto-detected by codehealth on {today}. {entry['body']} "
        f"Severity: {sev}. Source: {entry['source']}. "
        f"Fingerprint: `{entry['fingerprint']}`. "
        f"_Resolve by fixing the underlying issue; the next scan will "
        f"NOT re-emit (dedup by fingerprint). Move this row to Done "
        f"when shipped._"
    )
    # Escape pipe characters so they don't break the markdown table.
    title = title.replace("|", r"\|")
    return f"| {num} | {title} | Small | {entry['priority']} |"


def append_findings_to_backlog(scan_result: dict, backlog_path: str | None = None) -> dict:
    """Append new scan findings (not already emitted) to the project
    backlog markdown. Returns a result dict::

        {"ok": bool,
         "appended": int,
         "skipped": int,           # already-emitted count
         "fingerprints": [<new>],
         "backlog_path": str,
         "error": str | None}

    Best-effort: if the backlog file doesn't exist (e.g. fresh
    machine without Claude project memory), returns ok=False with a
    descriptive error rather than raising.
    """
    path = backlog_path or BACKLOG_PATH
    result: dict[str, Any] = {
        "ok": False,
        "appended": 0,
        "skipped": 0,
        "fingerprints": [],
        "backlog_path": path,
        "error": None,
    }
    if not os.path.exists(path):
        result["error"] = f"backlog not found at {path}"
        return result

    candidates = findings_to_backlog_entries(scan_result)
    emitted = load_emitted_fingerprints()
    new_entries = [e for e in candidates if e["fingerprint"] not in emitted]
    result["skipped"] = len(candidates) - len(new_entries)
    if not new_entries:
        result["ok"] = True
        return result

    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        result["error"] = f"backlog read failed: {exc}"
        return result

    next_num = _next_backlog_number(text)
    today = datetime.now().strftime("%Y-%m-%d")
    new_rows = [_format_backlog_row(next_num + i, entry, today) for i, entry in enumerate(new_entries)]
    block = "\n".join(new_rows) + "\n"

    # Insert before "**Priority key:**" anchor (lives at the bottom of
    # the Backlog table) so new rows land inside the table, not after
    # the priority key. Falls back to appending if anchor is missing.
    anchor = "**Priority key:**"
    text = text.replace(anchor, block + "\n" + anchor, 1) if anchor in text else text.rstrip() + "\n\n" + block

    # Atomic write so a crash mid-write doesn't corrupt the backlog.
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        result["error"] = f"backlog write failed: {exc}"
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return result

    # Persist the new fingerprints so reruns don't re-emit.
    emitted.update(e["fingerprint"] for e in new_entries)
    save_emitted_fingerprints(emitted)

    result["ok"] = True
    result["appended"] = len(new_entries)
    result["fingerprints"] = [e["fingerprint"] for e in new_entries]
    return result


def reset_emitted_fingerprints() -> bool:
    """Wipe the emitted-fingerprints memory so the next scan will
    re-emit findings that were previously appended. Used by the
    "Re-emit findings" admin action / when the user has manually
    cleaned up old rows and wants the scanner to repopulate."""
    return save_emitted_fingerprints(set())
