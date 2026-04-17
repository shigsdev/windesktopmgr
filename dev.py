#!/usr/bin/env python3
"""
dev.py — Quick quality gate runner for WinDesktopMgr.

Usage:
    python dev.py                    # Run all checks (lint, format, test)
    python dev.py check              # Lint + format check only (fast, no tests)
    python dev.py fix                # Auto-fix lint + format issues
    python dev.py test               # Tests only
    python dev.py verify             # Restart running app + run /api/selftest
    python dev.py ship               # fix + test + verify (post-deploy smoke)
    python dev.py post-update-check  # Post-Windows-Update regression runner (#25)
"""

import subprocess
import sys
import time

TARGETS = [
    "windesktopmgr.py",
    "homenet.py",
    "tray.py",
    "SystemHealthDiag.py",
    "tests/",
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def run(label, cmd):
    """Run a command, print pass/fail, return success bool."""
    print(f"  {label} ... ", end="", flush=True)
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start
    if result.returncode == 0:
        print(f"{GREEN}passed{RESET} ({elapsed:.1f}s)")
        return True
    else:
        print(f"{RED}FAILED{RESET} ({elapsed:.1f}s)")
        output = (result.stdout + result.stderr).strip()
        if output:
            for line in output.splitlines()[:20]:
                print(f"    {line}")
        return False


def cmd_check():
    """Lint + format check (fast, no tests)."""
    print(f"\n{BOLD}Quality Check (lint + format){RESET}")
    ok = True
    ok &= run("ruff check", [sys.executable, "-m", "ruff", "check", *TARGETS])
    ok &= run("ruff format", [sys.executable, "-m", "ruff", "format", "--check", *TARGETS])
    return ok


def cmd_fix():
    """Auto-fix lint issues + reformat."""
    print(f"\n{BOLD}Auto-fix (lint + format){RESET}")
    ok = True
    ok &= run("ruff check --fix", [sys.executable, "-m", "ruff", "check", "--fix", *TARGETS])
    ok &= run("ruff format", [sys.executable, "-m", "ruff", "format", *TARGETS])
    return ok


def cmd_test():
    """Run full test suite."""
    print(f"\n{BOLD}Tests{RESET}")
    return run("pytest", [sys.executable, "-m", "pytest", "tests/", "-v"])


def cmd_all():
    """Run everything: fix → test."""
    ok = cmd_fix()
    ok &= cmd_test()
    return ok


def cmd_verify():
    """Restart the running app and run /api/selftest against it."""
    print(f"\n{BOLD}Verify (restart + selftest){RESET}")
    return run("post_restart_check", [sys.executable, "scripts/post_restart_check.py"])


def cmd_ship():
    """Full post-deploy smoke: fix → test → verify (assumes git push already done)."""
    ok = cmd_fix()
    ok &= cmd_test()
    if not ok:
        return False
    ok &= cmd_verify()
    return ok


def cmd_post_update_check():
    """
    Run the post-Windows-Update regression check (backlog #25).

    Delegates to ``post_update_check.main()`` so CLI flags (``--force``,
    ``--check-only``) pass through unchanged.
    """
    print(f"\n{BOLD}Post-Windows-Update regression check{RESET}")
    # Pass any extra argv after the subcommand straight through
    extra = sys.argv[2:]
    result = subprocess.run(
        [sys.executable, "-m", "post_update_check", *extra],
        cwd=str(__import__("pathlib").Path(__file__).resolve().parent),
    )
    return result.returncode == 0


def main():
    commands = {
        "check": cmd_check,
        "fix": cmd_fix,
        "test": cmd_test,
        "verify": cmd_verify,
        "ship": cmd_ship,
        "post-update-check": cmd_post_update_check,
    }

    arg = sys.argv[1] if len(sys.argv) > 1 else "all"

    if arg in commands:
        ok = commands[arg]()
    elif arg == "all":
        ok = cmd_all()
    else:
        print(f"Unknown command: {arg}")
        print("Usage: python dev.py [check|fix|test|all|verify|ship|post-update-check]")
        sys.exit(1)

    print()
    if ok:
        print(f"  {GREEN}{BOLD}All checks passed{RESET}")
    else:
        print(f"  {RED}{BOLD}Some checks failed{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
