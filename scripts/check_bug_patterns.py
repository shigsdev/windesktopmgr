"""check_bug_patterns.py -- weekly scan for code shapes that caused bugs here.

The pre-commit gates catch NEW instances of a known-bad shape as code is
written. This catches OLD instances: code written before we learned a
pattern was dangerous, still sitting in files nobody has touched since.

  embedded-url-credentials
      ``https://user:token@host`` in any tracked file. The 2026 GitHub
      token leak shape (docs/security/git-credentials.md). The credential
      part is masked before it reaches the log or email.

  state-mutating-get-routes
      A Flask route declaring ``methods=[...]`` with GET next to
      POST/PUT/PATCH/DELETE. The tray serves localhost:5000, which any web
      page open in the browser can send a GET to (an <img> tag is enough),
      so a GET that changes state is a cross-site request forgery hole.

  subprocess-without-timeout
      ``subprocess.run`` / ``check_output`` / ``check_call`` / ``call`` in
      app code with no ``timeout=``. A PowerShell call that hangs without
      one hangs the request thread with it (CLAUDE.md: every PS call gets a
      timeout). Dev tooling (dev.py, scripts/) and tests are out of scope.

  relaunch-from-live-argv
      Relaunching the app from the LIVE ``sys.argv``. pysnmp's MIB loader
      rewrites ``sys.argv[0]`` at runtime, so a restart built from it runs
      a MIB file instead of the app (the PR #155 /api/restart bug). Use the
      argv captured at startup (``tray._ORIGINAL_ARGV``).

  unguarded-setinterval
      Re-runs ``scripts/lint_setinterval.py`` (also a pre-commit hook): a
      ``setInterval`` handle reassigned without ``clearInterval`` first
      stacks pollers on every click (the 2026-04-18 19% CPU incident).
      Weekly heartbeat in case the hook was bypassed.

Wired via ``.github/workflows/weekly-bug-pattern-scan.yml`` (Sundays).
See ``audit_common.py`` for exit codes and email settings.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys

from audit_common import PROJECT_ROOT, Finding, build_parser, read_text, run_audit, tracked_files

# This scan and its tests spell the patterns out on purpose.
_SELF = frozenset({"scripts/check_bug_patterns.py", "tests/test_recurring_audits.py"})

# ── embedded-url-credentials ─────────────────────────────────────────────────

_URL_CRED_RE = re.compile(r"https?://[^@\s/]+(?::[^@\s/]+)?@[^\s]")
_URL_CRED_MASK_RE = re.compile(r"(://[^:/\s@]+)(:[^@/\s]+)?@")

# Files that document or test the leak shape with fake credentials.
_URL_CRED_ALLOWLIST = _SELF | {
    "docs/security/git-credentials.md",
    "scripts/check_repo_secrets.py",
    "tests/test_check_repo_secrets.py",
    # Proxy-URL scrubber tests: the fake credentials are the input under test.
    "tests/test_diagnose_probes.py",
}


def check_embedded_url_credentials() -> list[Finding]:
    findings = []
    for rel in tracked_files():
        if rel in _URL_CRED_ALLOWLIST:
            continue
        text = read_text(rel)
        if text is None:
            continue
        for num, line in enumerate(text.splitlines(), start=1):
            if _URL_CRED_RE.search(line):
                masked = _URL_CRED_MASK_RE.sub(r"\1:****@", line.strip())
                findings.append(
                    Finding(
                        check_id="embedded-url-credentials",
                        path=rel,
                        line=num,
                        detail=f"{masked[:160]} — rotate that credential now; use the credential manager or an env var.",
                    )
                )
    return findings


# ── state-mutating-get-routes ────────────────────────────────────────────────

_ROUTE_METHODS_RE = re.compile(r"@\w+\.route\([^)]*methods\s*=\s*[\[(]([^\])]+)[\])]", re.IGNORECASE)
_MUTATING_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


def check_state_mutating_get_routes() -> list[Finding]:
    findings = []
    for rel in tracked_files((".py",)):
        if rel in _SELF:
            continue
        text = read_text(rel)
        if text is None:
            continue
        for num, line in enumerate(text.splitlines(), start=1):
            m = _ROUTE_METHODS_RE.search(line)
            if not m:
                continue
            verbs = {v.strip().strip("'\"").upper() for v in m.group(1).split(",") if v.strip()}
            mutating = sorted(verbs & _MUTATING_VERBS)
            if "GET" in verbs and mutating:
                findings.append(
                    Finding(
                        check_id="state-mutating-get-routes",
                        path=rel,
                        line=num,
                        detail=f"route accepts GET and {'/'.join(mutating)} — split the GET into its own "
                        "read-only handler so a web page can't trigger the change with a plain GET.",
                    )
                )
    return findings


# ── subprocess-without-timeout ───────────────────────────────────────────────

_BLOCKING_CALLS = {"run", "check_output", "check_call", "call"}


def _is_app_code(rel: str) -> bool:
    return rel.endswith(".py") and not rel.startswith(("tests/", "scripts/")) and rel != "dev.py"


def _calls_without_timeout(source: str) -> list[int]:
    """Line numbers of ``subprocess.<blocking>(...)`` calls lacking timeout=.
    A ``**kwargs`` splat might carry one, so those are given the benefit
    of the doubt."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        target = node.func.value
        if not (isinstance(target, ast.Name) and target.id == "subprocess" and node.func.attr in _BLOCKING_CALLS):
            continue
        keywords = {kw.arg for kw in node.keywords}
        if "timeout" not in keywords and None not in keywords:
            lines.append(node.lineno)
    return sorted(lines)


def check_subprocess_without_timeout() -> list[Finding]:
    findings = []
    for rel in tracked_files((".py",)):
        if not _is_app_code(rel):
            continue
        text = read_text(rel)
        if text is None:
            continue
        try:
            lines = _calls_without_timeout(text)
        except SyntaxError as exc:
            raise RuntimeError(f"{rel} does not parse: {exc}") from exc
        findings += [
            Finding(
                check_id="subprocess-without-timeout",
                path=rel,
                line=num,
                detail="subprocess call with no timeout= — a hung child process hangs the caller with it.",
            )
            for num in lines
        ]
    return findings


# ── relaunch-from-live-argv ──────────────────────────────────────────────────

# sys.executable and sys.argv on one line = building a relaunch command.
_LIVE_ARGV_RELAUNCH_RE = re.compile(r"sys\.executable.*\bsys\.argv\b|\bsys\.argv\b.*sys\.executable")


def check_relaunch_from_live_argv() -> list[Finding]:
    findings = []
    for rel in tracked_files((".py",)):
        if not _is_app_code(rel):
            continue
        text = read_text(rel)
        if text is None:
            continue
        for num, line in enumerate(text.splitlines(), start=1):
            code = line.split("#", 1)[0]
            if _LIVE_ARGV_RELAUNCH_RE.search(code):
                findings.append(
                    Finding(
                        check_id="relaunch-from-live-argv",
                        path=rel,
                        line=num,
                        detail="relaunch built from the live sys.argv — pysnmp rewrites sys.argv[0] at runtime; "
                        "use the argv captured at startup (tray._ORIGINAL_ARGV).",
                    )
                )
    return findings


# ── unguarded-setinterval ────────────────────────────────────────────────────


def check_unguarded_setinterval() -> list[Finding]:
    script = PROJECT_ROOT / "scripts" / "lint_setinterval.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
        timeout=120,
    )
    if proc.returncode == 0:
        return []
    if proc.returncode != 1:
        raise RuntimeError(f"lint_setinterval.py exit {proc.returncode}: {proc.stderr.strip()[:300]}")
    output = (proc.stdout + proc.stderr).strip()
    return [
        Finding(
            check_id="unguarded-setinterval",
            path="static/js/app.js",
            detail=f"lint_setinterval.py reported: {output[:1500]}",
        )
    ]


CHECKS = [
    ("embedded-url-credentials", check_embedded_url_credentials),
    ("state-mutating-get-routes", check_state_mutating_get_routes),
    ("subprocess-without-timeout", check_subprocess_without_timeout),
    ("relaunch-from-live-argv", check_relaunch_from_live_argv),
    ("unguarded-setinterval", check_unguarded_setinterval),
]

CHECK_DESCRIPTIONS = {
    "embedded-url-credentials": "A username or token baked into a URL in a committed file (secret-leak risk).",
    "state-mutating-get-routes": "A route that lets a plain GET change state — any web page could trigger it.",
    "subprocess-without-timeout": "An app subprocess call with no timeout — one hung PowerShell call hangs the app.",
    "relaunch-from-live-argv": "A restart built from sys.argv, which pysnmp rewrites at runtime (PR #155 bug).",
    "unguarded-setinterval": "A JS poller that can stack up on every click (the 2026-04-18 CPU incident).",
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser("Weekly bug-pattern scan.").parse_args(argv)
    return run_audit(
        tag="bug-pattern",
        title="Weekly bug-pattern scan",
        cadence="weekly",
        scope_blurb="code patterns that have caused bugs in this app before",
        checks=CHECKS,
        descriptions=CHECK_DESCRIPTIONS,
        todo_steps=[
            "Open each file:line above and fix it (the line under it says how).",
            "If one is a false positive, tune that check in scripts/check_bug_patterns.py.",
            "Re-run `python scripts/check_bug_patterns.py --no-email` to confirm it's clean.",
        ],
        args=args,
    )


if __name__ == "__main__":
    sys.exit(main())
