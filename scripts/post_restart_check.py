#!/usr/bin/env python3
"""post_restart_check.py -- Restart the running WinDesktopMgr app, wait for the
new instance to come up, then run /api/selftest and print pass/fail results.

Usage:
    python scripts/post_restart_check.py           # restart + verify
    python scripts/post_restart_check.py --no-restart  # verify only
    python scripts/post_restart_check.py --host http://localhost:5000

Exit codes:
    0 -- all checks passed
    1 -- one or more checks failed
    2 -- server did not come back up in time
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

DEFAULT_HOST = "http://localhost:5000"
HEARTBEAT_TIMEOUT_S = 45
HEARTBEAT_POLL_INTERVAL_S = 1.0
SELFTEST_TIMEOUT_S = 120


def _get_json(url: str, timeout: float = 5.0) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionResetError):
        return None


def _post(url: str, timeout: float = 5.0) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionResetError):
        return 0, None


def trigger_restart(host: str) -> bool:
    print(f"{BOLD}Restarting app{RESET} ... ", end="", flush=True)
    status, body = _post(f"{host}/api/restart", timeout=5)
    if status == 202 and body and body.get("ok"):
        print(f"{GREEN}scheduled{RESET}")
        return True
    print(f"{RED}FAILED{RESET} (status={status})")
    return False


def wait_for_heartbeat(host: str, timeout_s: int = HEARTBEAT_TIMEOUT_S) -> bool:
    print(f"{BOLD}Waiting for heartbeat{RESET} ", end="", flush=True)
    deadline = time.time() + timeout_s
    # Give the old process a moment to actually die before the first poll
    time.sleep(1.5)
    while time.time() < deadline:
        body = _get_json(f"{host}/api/health", timeout=2)
        if body and body.get("ok"):
            elapsed = timeout_s - (deadline - time.time())
            print(f" {GREEN}up{RESET} ({elapsed:.1f}s)")
            return True
        print(".", end="", flush=True)
        time.sleep(HEARTBEAT_POLL_INTERVAL_S)
    print(f" {RED}TIMEOUT{RESET} ({timeout_s}s)")
    return False


def run_selftest(host: str) -> dict | None:
    print(f"{BOLD}Running /api/selftest{RESET} ... ", end="", flush=True)
    start = time.time()
    body = _get_json(f"{host}/api/selftest", timeout=SELFTEST_TIMEOUT_S)
    elapsed = time.time() - start
    if not body:
        print(f"{RED}FAILED{RESET} (no response after {elapsed:.1f}s)")
        return None
    if body.get("ok"):
        print(f"{GREEN}all passed{RESET} ({elapsed:.1f}s)")
    else:
        print(f"{YELLOW}{body.get('failed', '?')} failed{RESET} ({elapsed:.1f}s)")
    return body


def print_results(body: dict) -> None:
    checks = body.get("checks", [])
    if not checks:
        return
    print()
    name_w = max((len(c["name"]) for c in checks), default=10)
    for c in checks:
        mark = f"{GREEN}PASS{RESET}" if c["ok"] else f"{RED}FAIL{RESET}"
        dur = f"{c['duration_ms']:>6} ms"
        line = f"  {mark}  {c['name']:<{name_w}}  {DIM}{dur}{RESET}"
        if not c["ok"] and c.get("error"):
            line += f"  {RED}{c['error']}{RESET}"
        print(line)
    print()
    total = body.get("total", len(checks))
    passed = body.get("passed", 0)
    failed = body.get("failed", 0)
    if body.get("ok"):
        print(f"  {GREEN}{BOLD}{passed}/{total} checks passed{RESET}")
    else:
        print(f"  {RED}{BOLD}{failed}/{total} checks failed{RESET}")


def check_dashboard(host: str) -> bool:
    """Verify /api/dashboard/summary returns a valid response.

    This is the endpoint the tray icon polls. If it hangs or 500s after
    restart, the tray icon goes red/grey even though selftest passes.
    """
    print(f"\n{BOLD}Checking dashboard/summary (tray icon path){RESET}")
    start = time.time()
    body = _get_json(f"{host}/api/dashboard/summary", timeout=60)
    elapsed = time.time() - start
    if not body:
        print(f"  {RED}FAILED{RESET}: no response after {elapsed:.1f}s")
        return False
    overall = body.get("overall", "unknown")
    total = body.get("total", 0)
    color = GREEN if overall == "ok" else (YELLOW if overall == "warning" else RED)
    print(f"  {color}overall={overall}{RESET}, {total} concern(s) ({elapsed:.1f}s)")
    if overall == "unknown" or "error" in str(body.get("concerns", [])).lower():
        print(f"  {YELLOW}WARNING{RESET}: dashboard returned unusual state")
    return True


IDLE_RATE_THRESHOLD = 2.0  # req/s to /api/scan/status while scan is idle
IDLE_SAMPLE_WINDOW_S = 3.0  # how long to sample
CPU_THRESHOLD_PCT = 25.0  # sustained CPU% on the tray pythonw
THREAD_THRESHOLD = 60  # thread count on the tray pythonw


def check_idle_poll_rate(host: str) -> bool:
    """Catch runaway /api/scan/status pollers (the 2026-04-18 CPU incident).

    Samples the log endpoint over a short window and flags if poll rate
    exceeds the threshold while no scan is active. A healthy idle tray
    should see 0 req/s on this path.
    """
    print(f"\n{BOLD}Checking idle poll rate (/api/scan/status){RESET}")
    from datetime import datetime, timedelta

    scan = _get_json(f"{host}/api/scan/status", timeout=5)
    if scan and scan.get("status") not in ("idle", "complete", None):
        print(f"  {DIM}skipped — scan in progress ({scan.get('status')}){RESET}")
        return True

    t0 = datetime.now()
    time.sleep(IDLE_SAMPLE_WINDOW_S)
    body = _get_json(f"{host}/api/logs?level=INFO&lines=1000", timeout=10)
    if body is None:
        print(f"  {YELLOW}skipped — could not fetch logs{RESET}")
        return True
    cutoff = t0 - timedelta(seconds=0.2)
    entries = body.get("entries", [])
    hits = 0
    for e in entries:
        msg = e.get("message", "") or ""
        if "GET /api/scan/status" not in msg:
            continue
        try:
            ts = datetime.fromisoformat(e.get("timestamp", "2000-01-01"))
        except ValueError:
            continue
        if ts >= cutoff:
            hits += 1
    rate = hits / IDLE_SAMPLE_WINDOW_S
    if rate > IDLE_RATE_THRESHOLD:
        print(
            f"  {RED}FAILED{RESET}: {rate:.1f} req/s (threshold {IDLE_RATE_THRESHOLD} r/s, {hits} hits in {IDLE_SAMPLE_WINDOW_S}s)"
        )
        print(f"    {DIM}possible poll-accumulator leak — check setInterval call sites in templates/index.html{RESET}")
        return False
    print(f"  {GREEN}{rate:.1f} req/s{RESET} ({hits} hits in {IDLE_SAMPLE_WINDOW_S}s)")
    return True


def check_tray_resource_budget(host: str) -> bool:
    """Catch CPU / thread leaks in the running tray (pythonw on port 5000)."""
    print(f"\n{BOLD}Checking tray CPU + thread budget{RESET}")
    try:
        import psutil
    except ImportError:
        print(f"  {DIM}skipped — psutil not installed{RESET}")
        return True

    port = 5000
    try:
        from urllib.parse import urlparse

        port = urlparse(host).port or 5000
    except Exception:
        pass

    tray = None
    for conn in psutil.net_connections(kind="tcp"):
        if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
            try:
                tray = psutil.Process(conn.pid)
                break
            except psutil.NoSuchProcess:
                continue
    if tray is None:
        print(f"  {YELLOW}skipped — no listener found on port {port}{RESET}")
        return True

    try:
        cpu = tray.cpu_percent(interval=2.0)
        threads = tray.num_threads()
    except psutil.NoSuchProcess:
        print(f"  {YELLOW}skipped — tray process exited during sample{RESET}")
        return True

    ok = True
    cpu_color = GREEN if cpu <= CPU_THRESHOLD_PCT else RED
    thr_color = GREEN if threads <= THREAD_THRESHOLD else RED
    print(
        f"  CPU: {cpu_color}{cpu:.1f}%{RESET} (budget {CPU_THRESHOLD_PCT}%)  threads: {thr_color}{threads}{RESET} (budget {THREAD_THRESHOLD})"
    )
    if cpu > CPU_THRESHOLD_PCT:
        print(f"    {DIM}sustained CPU on idle tray — likely a poll/refresh leak{RESET}")
        ok = False
    if threads > THREAD_THRESHOLD:
        print(f"    {DIM}excessive Flask worker threads — check for request floods{RESET}")
        ok = False
    return ok


def check_playwright_smoke() -> bool:
    """Run the frontend Playwright smoke suite against the live server.

    Opt-in: requires ``PLAYWRIGHT_SMOKE=1`` in the environment. When unset,
    this is a no-op that returns True (success). When set, pytest is
    invoked with ``-m playwright``; a non-zero exit fails the verify.

    Rationale: Playwright tests take 3-5 minutes (browser launch + 20
    tab-navigation assertions + network rate sampling). Running them on
    every verify would balloon wall time from 2 min to 7+ min. The
    explicit opt-in keeps the fast path fast while making the Playwright
    gate a deliberate choice before a release / milestone.
    """
    import os as _os

    if _os.environ.get("PLAYWRIGHT_SMOKE", "").strip() not in ("1", "true", "yes"):
        return True

    print(f"\n{BOLD}Running Playwright frontend smoke suite{RESET}")
    cmd = [sys.executable, "-m", "pytest", "tests/test_playwright_smoke.py", "-m", "playwright", "--no-cov", "-q"]
    import subprocess

    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
    elapsed = time.time() - start
    if result.returncode == 0:
        print(f"  {GREEN}passed{RESET} ({elapsed:.1f}s)")
        return True
    print(f"  {RED}FAILED{RESET} ({elapsed:.1f}s)")
    output = (result.stdout + result.stderr).strip()
    for line in output.splitlines()[-30:]:
        print(f"    {line}")
    return False


def check_logs(host: str, since: str | None = None) -> bool:
    """Fetch recent ERROR and WARNING log entries and report them.

    Args:
        host: Base URL of the running app.
        since: ISO timestamp — only report entries after this time.
               If None, reports all recent entries.

    Returns False if any ERROR-level entries are found after ``since``.
    """
    from datetime import datetime

    print(f"\n{BOLD}Checking logs for errors/warnings{RESET}")
    if since:
        print(f"  {DIM}(entries since {since}){RESET}")
    ok = True
    for level in ("ERROR", "WARNING"):
        body = _get_json(f"{host}/api/logs?level={level}&lines=200", timeout=10)
        if body is None:
            print(f"  {YELLOW}{level}{RESET}: could not fetch logs")
            continue
        entries = body.get("entries", [])
        # Filter to entries after the restart timestamp
        if since:
            cutoff = datetime.fromisoformat(since)
            entries = [e for e in entries if datetime.fromisoformat(e.get("timestamp", "2000-01-01")) >= cutoff]
        count = len(entries)
        if count == 0:
            print(f"  {GREEN}{level}{RESET}: 0 entries")
            continue
        color = RED if level == "ERROR" else YELLOW
        print(f"  {color}{level}{RESET}: {count} entries")
        for entry in entries[:5]:
            ts = entry.get("timestamp", "")
            msg = entry.get("message", str(entry))
            # Truncate long messages
            if len(msg) > 100:
                msg = msg[:97] + "..."
            print(f"    {DIM}{ts}  {msg}{RESET}")
        if count > 5:
            print(f"    {DIM}... and {count - 5} more{RESET}")
        if level == "ERROR":
            ok = False
    return ok


def main() -> int:
    from datetime import datetime

    parser = argparse.ArgumentParser(description="Restart + smoke-test WinDesktopMgr")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Base URL (default: %(default)s)")
    parser.add_argument("--no-restart", action="store_true", help="Skip restart, just run /api/selftest")
    args = parser.parse_args()

    # Record the time just before restart so we only check logs generated after
    restart_ts = datetime.now().isoformat(timespec="seconds")

    if not args.no_restart:
        if not trigger_restart(args.host):
            return 2
        if not wait_for_heartbeat(args.host):
            return 2

    body = run_selftest(args.host)
    if not body:
        return 2
    print_results(body)

    # Post-selftest dashboard summary check — verifies the tray icon path works
    dash_ok = check_dashboard(args.host)

    # Idle poll-rate check — catches runaway pollers (2026-04-18 incident)
    rate_ok = check_idle_poll_rate(args.host)

    # Tray CPU + thread budget — catches resource leaks in the running process
    budget_ok = check_tray_resource_budget(args.host)

    # Post-selftest log check — only entries since restart
    logs_ok = check_logs(args.host, since=restart_ts)
    selftest_ok = body.get("ok", False)

    # Playwright frontend smoke (backlog #26) — opt-in via PLAYWRIGHT_SMOKE=1
    playwright_ok = check_playwright_smoke()

    if selftest_ok and not dash_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but dashboard/summary failed{RESET}")
        return 1
    if selftest_ok and not rate_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but idle poll rate exceeded threshold{RESET}")
        return 1
    if selftest_ok and not budget_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but tray exceeded CPU/thread budget{RESET}")
        return 1
    if selftest_ok and not logs_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but log errors detected{RESET}")
        return 1
    if selftest_ok and not playwright_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but Playwright frontend smoke failed{RESET}")
        return 1
    return 0 if selftest_ok else 1


if __name__ == "__main__":
    sys.exit(main())
