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

    # Post-selftest log check — only entries since restart
    logs_ok = check_logs(args.host, since=restart_ts)
    selftest_ok = body.get("ok", False)

    if selftest_ok and not logs_ok:
        print(f"\n  {YELLOW}{BOLD}Selftest passed but log errors detected{RESET}")
        return 1
    return 0 if selftest_ok else 1


if __name__ == "__main__":
    sys.exit(main())
