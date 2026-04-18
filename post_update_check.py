"""
post_update_check.py — Post-Windows-Update automated regression testing (backlog #25).

When a Windows Update has been installed since the last check (detected via WMI
``Win32_QuickFixEngineering``), run the full test suite + live verification,
email the user a pass/fail report, and — if any regressions are detected —
prepend a ``[POST-UPDATE REGRESSION]`` entry at the top of
``project_backlog.md`` so the follow-up is visible on the next planning pass.

The goal is to catch Windows Update collateral damage — WMI schema shifts,
PowerShell output format drift, driver regressions, service state changes —
before the user notices at the dashboard.

Usage::

    python -m post_update_check                # full check (detect + run + notify)
    python -m post_update_check --force        # skip the "new update" guard
    python -m post_update_check --check-only   # print detection state and exit

Triggered automatically at tray startup when ``WDM_POST_UPDATE_CHECK=1`` is
set in the environment (see ``tray.py``).

Exit codes:
    0 — check completed (whether any updates were detected or not)
    1 — check ran but regressions were detected
    2 — fatal error (WMI unavailable, state file unreadable, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════════════════════

REPO_ROOT = Path(__file__).resolve().parent

# State file lives in %LOCALAPPDATA% so it survives repo re-clones but stays
# per-user.
_APPDATA = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
STATE_DIR = _APPDATA / "WinDesktopMgr"
STATE_FILE = STATE_DIR / "post_update_state.json"

# Backlog file lives in the user's Claude project memory so auto-entries land
# where the planning workflow already reads them.
BACKLOG_FILE = Path.home() / ".claude" / "projects" / "C--shigsapps-windesktopmgr" / "memory" / "project_backlog.md"

# SMTP — reuse the exact same credentials the daily SystemHealthDiag.py report
# uses. The config lives in ``diag_email_config.xml`` next to this file and is
# DPAPI-encrypted via PowerShell ``Export-Clixml`` / ``Get-Credential``.
# Run ``Setup-DiagSchedule.ps1`` once to populate it. If the file is missing,
# email is silently skipped (report still prints to stdout + lands on disk).
#
# Gmail SMTP matches what SystemHealthDiag sends through, so a Gmail app
# password in the CliXml works unchanged for this new channel.
CRED_FILE = REPO_ROOT / "diag_email_config.xml"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# How long to let pytest / dev.py verify run before force-killing.
PYTEST_TIMEOUT_S = 600  # 10 min — real test suite is ~3 min, leaves headroom
VERIFY_TIMEOUT_S = 300  # 5 min — dev.py verify is ~2.5 min


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS UPDATE DETECTION
# ══════════════════════════════════════════════════════════════════════════════


def get_latest_hotfix() -> dict | None:
    """
    Return the newest installed Windows hotfix as a dict, or ``None`` if no
    hotfixes are visible / WMI is unavailable.

    Output shape::

        {"HotFixID": "KB5041871", "InstalledOn": "2026-04-10T00:00:00"}

    Uses the ``wmi`` package (already in ``requirements.txt`` for Batch B) —
    no PowerShell subprocess.
    """
    try:
        import wmi

        conn = wmi.WMI()
        hotfixes = []
        for hf in conn.Win32_QuickFixEngineering():
            hfid = getattr(hf, "HotFixID", None) or ""
            installed_raw = getattr(hf, "InstalledOn", None) or ""
            if not hfid:
                continue
            # InstalledOn is typically "mm/dd/yyyy" or ISO; normalize to ISO.
            iso = _normalize_installed_date(installed_raw)
            hotfixes.append({"HotFixID": hfid, "InstalledOn": iso})
        if not hotfixes:
            return None
        # Sort by InstalledOn descending; ties by HotFixID descending (KB numbers
        # are monotonically increasing so higher KB => newer when dates tie).
        hotfixes.sort(key=lambda h: (h["InstalledOn"], h["HotFixID"]), reverse=True)
        return hotfixes[0]
    except Exception as e:
        print(f"[post_update_check] WMI hotfix query failed: {e}", file=sys.stderr)
        return None


def _normalize_installed_date(raw: str) -> str:
    """Normalize WMI ``InstalledOn`` strings to ISO-8601. Returns '' on failure."""
    if not raw:
        return ""
    raw = raw.strip()
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    # If we got here, assume raw is already ISO-ish — pass through.
    return raw


# ══════════════════════════════════════════════════════════════════════════════
# STATE FILE — records the last hotfix we've already tested against
# ══════════════════════════════════════════════════════════════════════════════


def load_state() -> dict:
    """Load the persisted post-update state, or return a fresh dict on miss."""
    try:
        if STATE_FILE.exists():
            with STATE_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[post_update_check] state load failed: {e}", file=sys.stderr)
    return {}


def save_state(state: dict) -> None:
    """Persist the post-update state, creating parent dirs if needed."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with STATE_FILE.open("w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[post_update_check] state save failed: {e}", file=sys.stderr)


def detect_new_update(state: dict | None = None) -> dict | None:
    """
    Return the newest hotfix dict iff it differs from the one last recorded in
    state. Returns ``None`` if no new update has landed.
    """
    latest = get_latest_hotfix()
    if not latest:
        return None
    if state is None:
        state = load_state()
    if state.get("last_hotfix_id") == latest["HotFixID"]:
        return None
    return latest


# ══════════════════════════════════════════════════════════════════════════════
# TEST / VERIFY RUNNERS — capture structured pass/fail + output excerpt
# ══════════════════════════════════════════════════════════════════════════════


def run_pytest() -> dict:
    """
    Run the full pytest suite with ``--tb=short -q``. Returns a dict with
    ``ok``, ``passed``, ``failed``, ``elapsed_s``, and ``excerpt``.

    Excerpt = the failure-relevant tail (pass/fail summary line +
    surrounding context). Encoded UTF-8 with ``errors='replace'`` so that
    a single non-cp1252 glyph (e.g. a ``—`` in a test name) can never
    truncate the capture and hide the pass/fail counts.
    """
    start = time.time()
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=PYTEST_TIMEOUT_S,
        )
        out = (r.stdout or "") + (r.stderr or "")
        excerpt = _extract_pytest_excerpt(out)
        passed, failed = _parse_pytest_counts(out)
        return {
            "ok": r.returncode == 0,
            "passed": passed,
            "failed": failed,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": excerpt,
            "returncode": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "passed": 0,
            "failed": -1,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": f"pytest exceeded {PYTEST_TIMEOUT_S}s timeout",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "ok": False,
            "passed": 0,
            "failed": -1,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": f"pytest invocation failed: {e}",
            "returncode": -1,
        }


def _parse_pytest_counts(output: str) -> tuple[int, int]:
    """Scrape 'N passed, M failed' from pytest's summary line. Safe fallbacks."""
    import re

    passed = failed = 0
    m = re.search(r"(\d+) passed", output)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", output)
    if m:
        failed = int(m.group(1))
    return passed, failed


def _extract_pytest_excerpt(output: str, max_lines: int = 40) -> str:
    """
    Return the failure-relevant tail of pytest output.

    Pytest's pass/fail summary ("1415 passed, 38 deselected in 147.94s") is the
    single most diagnostic line. When the coverage plugin is enabled (our repo
    config), that summary ends up *after* a ~180-line coverage report — so
    naively taking the last 40 lines pushes it off the top. Grab the summary
    line explicitly and pair it with the last ``max_lines`` so the email still
    shows whatever tracebacks / FAILED markers pytest emitted at the end.
    """
    import re

    lines = output.splitlines()
    tail = lines[-max_lines:]
    m = re.search(r"^=+ \d+ (?:passed|failed|error).*$", output, flags=re.MULTILINE)
    summary_line = m.group(0) if m else ""
    if summary_line and summary_line not in tail:
        return summary_line + "\n" + "\n".join(tail)
    return "\n".join(tail)


def run_verify() -> dict:
    """
    Run ``python dev.py verify`` — restart the running tray instance and
    execute the full live selftest. Returns ``{ok, elapsed_s, excerpt,
    returncode}``.
    """
    start = time.time()
    try:
        r = subprocess.run(
            [sys.executable, "dev.py", "verify"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=VERIFY_TIMEOUT_S,
        )
        out = (r.stdout or "") + (r.stderr or "")
        excerpt = "\n".join(out.splitlines()[-40:])
        return {
            "ok": r.returncode == 0,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": excerpt,
            "returncode": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": f"dev.py verify exceeded {VERIFY_TIMEOUT_S}s timeout",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "ok": False,
            "elapsed_s": round(time.time() - start, 1),
            "excerpt": f"dev.py verify invocation failed: {e}",
            "returncode": -1,
        }


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL NOTIFICATION
# ══════════════════════════════════════════════════════════════════════════════


def _load_email_config() -> dict | None:
    """
    Load the shared ``diag_email_config.xml`` credentials used by the daily
    SystemHealthDiag.py report.

    The XML is a PowerShell ``Export-Clixml`` blob — the password field is
    DPAPI-encrypted and tied to the current Windows user, so we decrypt it by
    shelling out to PowerShell (the only practical way without reimplementing
    DPAPI + CliXml parsing in Python).

    Returns ``{"FromEmail": str, "ToEmail": str, "Password": str}`` on success,
    or ``None`` if the file is missing / decryption fails / PS returns junk.
    """
    if not CRED_FILE.is_file():
        return None
    ps_cmd = (
        f"$cfg = Import-Clixml -Path '{CRED_FILE}'; "
        "@{"
        "FromEmail = $cfg.FromEmail; "
        "ToEmail = $cfg.ToEmail; "
        "Password = $cfg.Credential.GetNetworkCredential().Password"
        "} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode != 0 or not r.stdout.strip():
            print(
                f"[post_update_check] email config PS read failed: rc={r.returncode} stderr={r.stderr.strip()[:200]}",
                file=sys.stderr,
            )
            return None
        cfg = json.loads(r.stdout)
        if not cfg.get("FromEmail") or not cfg.get("Password"):
            return None
        return cfg
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as e:
        print(f"[post_update_check] email config load failed: {e}", file=sys.stderr)
        return None


def send_email(subject: str, body: str) -> bool:
    """
    Send the post-update report via Gmail SMTP using the same credentials as
    the daily SystemHealthDiag report. Returns ``False`` and logs a reason if
    the config file is missing / decryption fails / SMTP send fails — the
    report has already been printed to stdout by this point, so no info is lost.
    """
    cfg = _load_email_config()
    if not cfg:
        print(
            f"[post_update_check] no email config ({CRED_FILE}) — skipping email. "
            "Run Setup-DiagSchedule.ps1 to configure.",
            file=sys.stderr,
        )
        return False

    from_email = cfg["FromEmail"]
    to_email = cfg.get("ToEmail") or from_email
    password = cfg["Password"]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(from_email, password)
            smtp.send_message(msg)
        return True
    except (smtplib.SMTPException, socket.gaierror, TimeoutError, OSError) as e:
        print(f"[post_update_check] SMTP send failed: {e}", file=sys.stderr)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# BACKLOG AUTO-ENTRY
# ══════════════════════════════════════════════════════════════════════════════


def prepend_backlog_entry(hotfix: dict, pytest_result: dict, verify_result: dict) -> bool:
    """
    Prepend a ``[POST-UPDATE REGRESSION]`` entry to the top of the project
    backlog so the next planning pass sees it. Idempotent-safe: one call = one
    entry (does not dedupe across runs — regressions from different hotfixes
    are genuinely separate items).
    """
    try:
        if not BACKLOG_FILE.exists():
            print(
                f"[post_update_check] backlog file not found at {BACKLOG_FILE} — skipping auto-entry",
                file=sys.stderr,
            )
            return False

        existing = BACKLOG_FILE.read_text(encoding="utf-8")
        entry = _format_backlog_entry(hotfix, pytest_result, verify_result)
        # Prepend: insert directly after the file header (first blank line).
        lines = existing.splitlines(keepends=True)
        insert_at = 0
        for i, line in enumerate(lines):
            if i > 0 and line.strip() == "":
                insert_at = i + 1
                break
        new_content = "".join(lines[:insert_at]) + entry + "\n" + "".join(lines[insert_at:])
        BACKLOG_FILE.write_text(new_content, encoding="utf-8")
        return True
    except Exception as e:
        print(f"[post_update_check] backlog prepend failed: {e}", file=sys.stderr)
        return False


def _format_backlog_entry(hotfix: dict, pytest_result: dict, verify_result: dict) -> str:
    """Render a markdown snippet suitable for prepending to project_backlog.md."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    hfid = hotfix.get("HotFixID", "unknown")
    installed = hotfix.get("InstalledOn", "unknown")
    pytest_line = (
        f"pytest: {pytest_result.get('passed', 0)} passed, "
        f"{pytest_result.get('failed', 0)} failed "
        f"({pytest_result.get('elapsed_s', '?')}s)"
    )
    verify_line = (
        f"dev.py verify: {'OK' if verify_result.get('ok') else 'FAILED'} ({verify_result.get('elapsed_s', '?')}s)"
    )
    return (
        f"> **[POST-UPDATE REGRESSION] {ts}** — Hotfix `{hfid}` "
        f"(installed {installed}) broke the regression suite. "
        f"{pytest_line}; {verify_line}. "
        f"Investigate failing tests, root-cause the Windows-Update-side change "
        f"(WMI schema? PS output drift? driver regression?), and reply with a "
        f"fix + regression test.\n"
    )


# ══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTING
# ══════════════════════════════════════════════════════════════════════════════


def format_report(
    hotfix: dict | None,
    pytest_result: dict | None,
    verify_result: dict | None,
) -> tuple[str, str]:
    """
    Build a ``(subject, body)`` tuple for the email + stdout report.
    """
    if not hotfix:
        return (
            "WinDesktopMgr post-update check: no new updates",
            "No Windows Update has been installed since the last check.\n",
        )

    hfid = hotfix.get("HotFixID", "unknown")
    installed = hotfix.get("InstalledOn", "unknown")

    py_ok = (pytest_result or {}).get("ok", False)
    verify_ok = (verify_result or {}).get("ok", False)
    overall_ok = py_ok and verify_ok
    verdict = "ALL GREEN" if overall_ok else "REGRESSIONS DETECTED"

    subject = f"WinDesktopMgr post-update check ({hfid}): {verdict}"

    lines = [
        f"Hotfix detected: {hfid} (installed {installed})",
        f"Verdict:         {verdict}",
        "",
        "--- pytest -----------------------------------------",
    ]
    if pytest_result:
        lines.append(
            f"  {pytest_result.get('passed', 0)} passed, "
            f"{pytest_result.get('failed', 0)} failed "
            f"({pytest_result.get('elapsed_s', '?')}s)"
        )
        if not py_ok:
            lines.append("")
            lines.append("  Last lines of pytest output:")
            for line in (pytest_result.get("excerpt", "") or "").splitlines():
                lines.append(f"    {line}")
    else:
        lines.append("  (not run)")
    lines.append("")
    lines.append("--- dev.py verify ----------------------------------")
    if verify_result:
        lines.append(f"  {'OK' if verify_ok else 'FAILED'} ({verify_result.get('elapsed_s', '?')}s)")
        if not verify_ok:
            lines.append("")
            lines.append("  Last lines of verify output:")
            for line in (verify_result.get("excerpt", "") or "").splitlines():
                lines.append(f"    {line}")
    else:
        lines.append("  (not run)")
    lines.append("")
    if not overall_ok:
        lines.append(
            "A [POST-UPDATE REGRESSION] entry has been prepended to "
            "project_backlog.md so it appears at the top of the next "
            "planning pass."
        )
    return subject, "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════


def _safe_print(text: str) -> None:
    """
    Print ``text`` to stdout, tolerating the Windows console's default cp1252
    codec. If any character is outside cp1252, retry the print after encoding
    to ASCII with ``errors='replace'`` so we get a readable-ish fallback
    instead of an exception.

    Preserves the orchestrator invariant: report printing is best-effort, but
    state persistence and email send must never be gated on it succeeding.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            print(text.encode("ascii", errors="replace").decode("ascii"))
        except Exception:
            # If even the fallback fails, just give up on stdout — the report
            # already went to email + state file.
            pass


def run_post_update_check(*, force: bool = False) -> dict:
    """
    End-to-end flow:

    1. Detect a new Windows Update via ``Win32_QuickFixEngineering``.
    2. Run the full pytest suite + ``dev.py verify``.
    3. Persist state (so a mid-run crash doesn't cause the same hotfix to
       loop on every subsequent boot).
    4. Email the user a pass/fail report.
    5. Prepend a backlog entry if there are regressions.
    6. Print the report to stdout (best-effort — cp1252 console tolerated).

    The order matters: state + email must complete before the fragile
    stdout print so a Windows console encoding hiccup can't lose either.

    When ``force=True`` we skip step 1's "is this new?" guard (useful for
    manual reruns — e.g. ``dev.py post-update-check --force``).

    Returns a structured summary dict for programmatic callers (tests, tray).
    """
    state = load_state()
    hotfix = detect_new_update(state) if not force else get_latest_hotfix()

    if not hotfix:
        subject, body = format_report(None, None, None)
        _safe_print(body)
        return {"ran": False, "reason": "no new update", "subject": subject}

    print(f"[post_update_check] new hotfix detected: {hotfix['HotFixID']}")
    print("[post_update_check] running pytest ...")
    pytest_result = run_pytest()
    print(
        f"[post_update_check] pytest: ok={pytest_result['ok']} "
        f"passed={pytest_result['passed']} failed={pytest_result['failed']} "
        f"elapsed={pytest_result['elapsed_s']}s"
    )

    print("[post_update_check] running dev.py verify ...")
    verify_result = run_verify()
    print(f"[post_update_check] verify: ok={verify_result['ok']} elapsed={verify_result['elapsed_s']}s")

    overall_ok = pytest_result.get("ok") and verify_result.get("ok")
    subject, body = format_report(hotfix, pytest_result, verify_result)

    # Persist state FIRST — if anything downstream crashes (e.g. SMTP timeout
    # or cp1252 print error), the next run still skips this hotfix instead
    # of looping forever.
    state.update(
        {
            "last_hotfix_id": hotfix["HotFixID"],
            "last_installed_on": hotfix.get("InstalledOn", ""),
            "last_check_at": datetime.now(timezone.utc).isoformat(),
            "last_result": "all_passed" if overall_ok else "regressions",
        }
    )
    save_state(state)

    # Email next. This is the "outbound" signal the user cares about, so it
    # must run before the fragile stdout print.
    email_sent = send_email(subject, body)
    backlog_entry_added = False
    if not overall_ok:
        backlog_entry_added = prepend_backlog_entry(hotfix, pytest_result, verify_result)

    # Stdout print last — best-effort only, never blocks the outbound signal.
    _safe_print(body)

    return {
        "ran": True,
        "hotfix": hotfix,
        "pytest": pytest_result,
        "verify": verify_result,
        "overall_ok": overall_ok,
        "email_sent": email_sent,
        "backlog_entry_added": backlog_entry_added,
        "subject": subject,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run the test + verify suite even if no new update has been detected.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Print detection state (new update? which hotfix?) and exit.",
    )
    args = parser.parse_args(argv)

    if args.check_only:
        state = load_state()
        latest = get_latest_hotfix()
        new = detect_new_update(state)
        print(f"State file:       {STATE_FILE}")
        print(f"Last recorded:    {state.get('last_hotfix_id', 'none')}")
        print(f"Latest installed: {latest['HotFixID'] if latest else 'none'}")
        print(f"Needs run:        {'yes' if new else 'no'}")
        return 0

    try:
        result = run_post_update_check(force=args.force)
    except Exception as e:
        print(f"[post_update_check] fatal: {e}", file=sys.stderr)
        return 2

    if not result.get("ran"):
        return 0
    return 0 if result.get("overall_ok") else 1


if __name__ == "__main__":
    sys.exit(main())
