"""audit_common.py -- shared plumbing for the recurring code audits.

Five scheduled GitHub Actions workflows re-scan the repo on a timer, the
drift-over-time complement to the per-commit gates (ruff + pytest +
secret scan in pre-commit). The commit gates catch NEW problems as code is
written; these catch problems that appear in code nobody touched -- a CVE
published against a pinned package, a newer ruff rule, coverage sliding.
Ported from shigsdev/taskmanager's recurring audits.

  check_advisories.py       weekly   Mon  known CVEs in the pinned deps
  check_bug_patterns.py     weekly   Sun  code shapes that caused bugs here
  check_test_coverage.py    weekly   Fri  coverage drift vs the baseline
  check_tech_debt.py        weekly   Sat  TODOs, big/complex files, stale deps
  check_security_posture.py monthly  1st  secrets, Flask exposure, S-rules

Every script sends an email on EVERY run, clean or not, so a week with no
email means the audit itself stopped running. Exit codes: 0 clean, 1
findings, 2 internal error (a check crashed).

Each script is a list of ``(check_id, fn)`` pairs handed to ``run_audit``;
this module owns everything else (Finding shape, CLI flags, log output, the
email body, the Brevo send, and the GitHub job summary) so the five emails
stay consistent and the plumbing exists once. Stdlib only -- the scripts
must run on a bare CI runner.

Email needs three settings on the GitHub repo (same names taskmanager uses):
the ``BREVO_API_KEY`` Actions secret plus the ``DIGEST_FROM_EMAIL`` and
``DIGEST_TO_EMAIL`` Actions variables. Missing any one -> no email, the
run still logs and writes the job summary.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
SENDER_NAME = "WinDesktopMgr CI"
SUBJECT_PREFIX = "WinDesktopMgr"
RULE = "─" * 56


@dataclass(frozen=True)
class Finding:
    """One thing to review.

    ``path`` is repo-relative POSIX ("" when the finding is repo-wide) and
    ``line`` is 1-based (0 when the finding is about a whole file).
    """

    check_id: str
    detail: str
    path: str = ""
    line: int = 0

    @property
    def location(self) -> str:
        if not self.path:
            return ""
        return f"{self.path}:{self.line}" if self.line else self.path


Check = Callable[[], list[Finding]]


# ── Repo helpers ─────────────────────────────────────────────────────────────


def tracked_files(suffixes: Sequence[str] = ()) -> list[str]:
    """Repo-relative POSIX paths of every git-tracked file, optionally
    filtered by suffix. Untracked / ignored files (caches, the tray's JSON
    state, .coverage) are naturally excluded. ``[]`` if git is unavailable."""
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=False,
            cwd=PROJECT_ROOT,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    out = []
    for rel in proc.stdout.splitlines():
        if suffixes and not rel.endswith(tuple(suffixes)):
            continue
        if (PROJECT_ROOT / rel).is_file():
            out.append(rel)
    return out


def read_text(rel: str) -> str | None:
    """File contents, or None when unreadable / not UTF-8 (binary)."""
    try:
        return (PROJECT_ROOT / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def last_commit_date(rel: str) -> datetime.date | None:
    """Date of the last commit touching ``rel`` (needs full git history --
    the workflows check out with ``fetch-depth: 0``)."""
    try:
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", rel],
            capture_output=True,
            text=True,
            check=False,
            cwd=PROJECT_ROOT,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    stamp = proc.stdout.strip()
    if proc.returncode != 0 or not stamp:
        return None
    try:
        return datetime.date.fromisoformat(stamp[:10])
    except ValueError:
        return None


# ── Email body ───────────────────────────────────────────────────────────────


def render(
    *,
    today: str,
    tag: str,
    title: str,
    cadence: str,
    scope_blurb: str,
    per_check_counts: list[tuple[str, int]],
    findings: list[Finding],
    descriptions: dict[str, str],
    todo_steps: list[str],
    subject_extra: str = "",
    header_extra: list[str] | None = None,
) -> tuple[str, str]:
    """Build ``(subject, body)`` for one audit email.

    ``cadence`` is "weekly" or "monthly". The body opens with a WHAT THIS IS
    preamble (findings are advisories, not outages; a missing email is the
    real alarm), then one block per check that found something, then the
    numbered next steps.
    """
    total = len(findings)
    n_checks = len(per_check_counts)
    period = "week" if cadence == "weekly" else "month"
    whatis = (
        f"WHAT THIS IS — an automated {cadence} scan of the WinDesktopMgr repo "
        f"for {scope_blurb}. Findings are things to REVIEW, not outages: nothing "
        f"here means the app is broken. It emails EVERY {period} even when clean, "
        f"so a {period} with no email means the scan itself stopped running — "
        f"that silence is the thing to act on."
    )
    lines = [f"{title} — {today}", ""]
    lines += list(header_extra or [])

    if total == 0:
        subject = f"[{SUBJECT_PREFIX} {tag}] ✓ all clear ({n_checks} checks){subject_extra} — {today}"
        lines += [f"RESULT: ✓ all clear — 0 findings across {n_checks} checks.", "", whatis, "", "Checks run:"]
        lines += [f"  ✓ {label} — {descriptions.get(label, '')}" for label, _ in per_check_counts]
        lines += ["", "Full log: the GitHub Actions run that sent this email."]
        return subject, "\n".join(lines)

    noun = "issue" if total == 1 else "issues"
    n_hit = sum(1 for _, count in per_check_counts if count)
    subject = f"[{SUBJECT_PREFIX} {tag}] {total} {noun} to review{subject_extra} — {today}"
    lines += [f"RESULT: {total} {noun} to review, in {n_hit} of {n_checks} checks.", "", whatis, ""]
    for label, count in per_check_counts:
        if not count:
            continue
        lines += [RULE, f"{label} — {count} finding{'s' if count != 1 else ''}"]
        if descriptions.get(label):
            lines.append(descriptions[label])
        lines.append("")
        for f in (f for f in findings if f.check_id == label):
            if f.location:
                lines += [f"  {f.location}", f"      {f.detail}"]
            else:
                lines.append(f"  • {f.detail}")
        lines.append("")
    lines.append(RULE)
    clean = [label for label, count in per_check_counts if count == 0]
    if clean:
        lines += ["", "Clean this run: " + ", ".join(clean)]
    lines += ["", "WHAT TO DO:"]
    lines += [f"  {i}. {step}" for i, step in enumerate(todo_steps, start=1)]
    lines += ["", "Full log: the GitHub Actions run that sent this email."]
    return subject, "\n".join(lines)


# ── Delivery ─────────────────────────────────────────────────────────────────


def send_email(subject: str, body: str, *, log_tag: str) -> bool:
    """Send via Brevo. Best-effort: a missing setting or a failed send is
    logged and returns False, never raises -- an email outage must not turn
    a clean audit red."""
    api_key = os.environ.get("BREVO_API_KEY")
    from_addr = os.environ.get("DIGEST_FROM_EMAIL")
    to_addr = os.environ.get("DIGEST_TO_EMAIL")
    if not (api_key and from_addr and to_addr):
        sys.stderr.write(f"[{log_tag}] email not configured (BREVO_API_KEY / DIGEST_*_EMAIL); skipping\n")
        return False
    payload = {
        "sender": {"email": from_addr, "name": SENDER_NAME},
        "to": [{"email": to_addr}],
        "subject": subject,
        "textContent": body,
    }
    req = urllib.request.Request(
        BREVO_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"api-key": api_key, "accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            sys.stdout.write(f"[{log_tag}] email sent: HTTP {resp.status}\n")
            return True
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"[{log_tag}] email send failed: {exc}\n")
        return False


def write_step_summary(subject: str, body: str) -> None:
    """Append the report to the GitHub Actions job summary (the run page's
    Summary tab). No-op outside Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"### {subject}\n\n```text\n{body}\n```\n")
    except OSError:
        pass


# ── Driver ───────────────────────────────────────────────────────────────────


def build_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--no-email", action="store_true", help="log + job summary only; never send the email")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="exit 0 even when there are findings (internal errors still exit 2). "
        "Used by the pull_request trigger, which only proves the audit still runs.",
    )
    return parser


def run_audit(
    *,
    tag: str,
    title: str,
    cadence: str,
    scope_blurb: str,
    checks: Sequence[tuple[str, Check]],
    descriptions: dict[str, str],
    todo_steps: list[str],
    args: argparse.Namespace,
    subject_extra: str = "",
    header_extra: list[str] | None = None,
) -> int:
    """Run every check, log the results, then email + summarise.

    A check that raises is an internal error: the run stops with exit 2
    before any email goes out, so a broken audit can't masquerade as clean.
    """
    log_tag = f"{tag}-audit"
    # A piped Windows stdout is cp1252, which can't encode the subject's
    # "✓" -- without this, a local run crashes after the audit and exits 1.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    sys.stdout.write(f"[{log_tag}] starting {datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')}\n")
    findings: list[Finding] = []
    per_check_counts: list[tuple[str, int]] = []
    for label, fn in checks:
        try:
            found = fn()
        except Exception as exc:  # noqa: BLE001 -- any crash is an internal error, reported as exit 2
            sys.stderr.write(f"[{log_tag}] check {label!r} crashed: {type(exc).__name__}: {exc}\n")
            return 2
        sys.stdout.write(f"[{log_tag}] {label}: {len(found)} finding(s)\n")
        for f in found:
            sys.stdout.write(f"    {f.location or '(repo)'}  {f.detail}\n")
        findings += found
        per_check_counts.append((label, len(found)))

    subject, body = render(
        today=datetime.date.today().isoformat(),
        tag=tag,
        title=title,
        cadence=cadence,
        scope_blurb=scope_blurb,
        per_check_counts=per_check_counts,
        findings=findings,
        descriptions=descriptions,
        todo_steps=todo_steps,
        subject_extra=subject_extra,
        header_extra=header_extra,
    )
    write_step_summary(subject, body)
    if args.no_email:
        sys.stdout.write(f"[{log_tag}] --no-email: not sending\n")
    else:
        send_email(subject, body, log_tag=log_tag)
    sys.stdout.write(f"[{log_tag}] {subject}\n")
    if findings and not args.report_only:
        return 1
    return 0
