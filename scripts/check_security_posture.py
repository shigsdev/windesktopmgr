"""check_security_posture.py -- monthly security-posture audit.

The commit gates catch new secrets and new ruff S-rule hits as code is
written. This monthly sweep re-checks the whole tree for the slow-drift
cases those gates can't see:

  secrets-sweep
      Re-runs scripts/check_repo_secrets.py (the pre-commit secret
      scanner) over every tracked file and the git remote URLs, in case a
      commit went in with --no-verify. Its output is already redacted.

  flask-exposure
      ``app.run(...)`` with ``debug=True`` (the Werkzeug debugger runs any
      Python a page sends it) or a ``host=`` other than loopback (puts the
      dashboard -- process kill, remediation, restart -- on the LAN). The
      tray must stay bound to 127.0.0.1.

  ruff-security-rules
      The ruff ``S`` (bandit) results from a full run under the project's
      own config, with the LATEST ruff release rather than the version
      pre-commit pins: newer rules find issues in code nobody changed (how
      backlog #60's S508 SNMP finding appeared).

  new-security-suppressions
      ``# noqa: S...`` comments compared with the reviewed register in
      docs/audit/security-suppressions.json. A new suppression switches a
      security check off for that line; it should be a decision someone
      looked at, not a quiet way to get a commit through. After reviewing,
      record the current set with ``--write-baseline``.

Wired via ``.github/workflows/monthly-security-audit.yml`` (1st of the
month). See ``audit_common.py`` for exit codes and email settings.
"""

from __future__ import annotations

import ast
import datetime
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from audit_common import PROJECT_ROOT, Finding, build_parser, read_text, run_audit, tracked_files

SUPPRESSIONS_PATH = PROJECT_ROOT / "docs" / "audit" / "security-suppressions.json"
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_NOQA_S_RE = re.compile(r"#\s*noqa:\s*([A-Z0-9, ]+)")


def _app_python() -> list[str]:
    return [rel for rel in tracked_files((".py",)) if not rel.startswith("tests/")]


# ── secrets-sweep ────────────────────────────────────────────────────────────


def check_secrets_sweep() -> list[Finding]:
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "check_repo_secrets.py"), "--all"],
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
        timeout=300,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"check_repo_secrets.py exit {proc.returncode}: {proc.stderr.strip()[:300]}")
    return [
        Finding(check_id="secrets-sweep", detail=line.strip()[len("LEAK:") :].strip()[:300])
        for line in proc.stdout.splitlines()
        if line.startswith("LEAK:")
    ]


# ── flask-exposure ───────────────────────────────────────────────────────────


def _exposure_problems(source: str) -> list[tuple[int, str]]:
    """``(line, problem)`` for every ``<name>.run(...)`` call that turns on
    the debugger or binds a non-loopback host. Only ``*.run`` calls with a
    ``port=`` / ``host=`` / ``debug=`` keyword count, so ``subprocess.run``
    and friends are ignored."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run"):
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if not {"port", "host", "debug"} & kwargs.keys():
            continue
        debug = kwargs.get("debug")
        if debug is not None and not (isinstance(debug, ast.Constant) and debug.value is False):
            problems.append((node.lineno, "debug is not False — the Werkzeug debugger runs arbitrary Python"))
        host = kwargs.get("host")
        if host is not None and not (isinstance(host, ast.Constant) and host.value in _LOOPBACK_HOSTS):
            shown = host.value if isinstance(host, ast.Constant) else ast.unparse(host)
            problems.append(
                (node.lineno, f"host={shown!r} is not loopback — the dashboard would be reachable off this PC")
            )
    return problems


def check_flask_exposure() -> list[Finding]:
    findings = []
    for rel in _app_python():
        text = read_text(rel)
        if text is None:
            continue
        try:
            problems = _exposure_problems(text)
        except SyntaxError as exc:
            raise RuntimeError(f"{rel} does not parse: {exc}") from exc
        findings += [
            Finding(check_id="flask-exposure", path=rel, line=line, detail=problem) for line, problem in problems
        ]
    return findings


# ── ruff-security-rules ──────────────────────────────────────────────────────


def check_ruff_security_rules() -> list[Finding]:
    proc = subprocess.run(
        # The project config (pyproject.toml) already selects S with its
        # reviewed ignores; a CLI --select would discard those ignores.
        [sys.executable, "-m", "ruff", "check", ".", "--output-format", "json", "--exit-zero"],
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
        timeout=300,
    )
    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ruff exit {proc.returncode}, no JSON: {proc.stderr.strip()[:300]}") from exc
    findings = []
    for item in results:
        if not re.fullmatch(r"S\d+", item.get("code") or ""):
            continue
        path = Path(item.get("filename", "")).resolve()
        try:
            rel = path.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            rel = path.as_posix()
        findings.append(
            Finding(
                check_id="ruff-security-rules",
                path=rel,
                line=(item.get("location") or {}).get("row") or 0,
                detail=f"{item.get('code')}: {item.get('message')}",
            )
        )
    return findings


# ── new-security-suppressions ────────────────────────────────────────────────


def current_suppressions() -> Counter:
    """``Counter({"file.py S310": n})`` of S-rule noqa codes in app code."""
    counts: Counter = Counter()
    for rel in _app_python():
        for line in (read_text(rel) or "").splitlines():
            m = _NOQA_S_RE.search(line)
            if not m:
                continue
            for code in re.findall(r"S\d+", m.group(1)):
                counts[f"{rel} {code}"] += 1
    return counts


def write_suppressions_baseline(counts: Counter) -> None:
    SUPPRESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_doc": "Reviewed '# noqa: S...' suppressions (file + rule -> count) for "
        "scripts/check_security_posture.py. Refresh with "
        "`python scripts/check_security_posture.py --write-baseline` after reviewing a new one.",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "suppressions": dict(sorted(counts.items())),
    }
    SUPPRESSIONS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check_new_security_suppressions() -> list[Finding]:
    try:
        reviewed = json.loads(SUPPRESSIONS_PATH.read_text(encoding="utf-8"))["suppressions"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(f"{SUPPRESSIONS_PATH.name} unreadable — run --write-baseline: {exc}") from exc
    findings = []
    for key, count in sorted(current_suppressions().items()):
        known = int(reviewed.get(key, 0))
        if count > known:
            rel, code = key.rsplit(" ", 1)
            findings.append(
                Finding(
                    check_id="new-security-suppressions",
                    path=rel,
                    detail=f"{count - known} unreviewed '# noqa: {code}' (register has {known}, file has {count}). "
                    "Check each one is justified, then run --write-baseline.",
                )
            )
    return findings


CHECKS = [
    ("secrets-sweep", check_secrets_sweep),
    ("flask-exposure", check_flask_exposure),
    ("ruff-security-rules", check_ruff_security_rules),
    ("new-security-suppressions", check_new_security_suppressions),
]

CHECK_DESCRIPTIONS = {
    "secrets-sweep": "A token-shaped string or credentialed remote URL anywhere in the repo.",
    "flask-exposure": "The app started with the debugger on, or listening beyond this PC.",
    "ruff-security-rules": "A bandit-style security rule (ruff S) firing under the newest ruff release.",
    "new-security-suppressions": "A security check switched off with '# noqa: S…' that nobody has reviewed yet.",
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser("Monthly security-posture audit.")
    parser.add_argument("--write-baseline", action="store_true", help="record the current noqa set as reviewed")
    args = parser.parse_args(argv)
    if args.write_baseline:
        counts = current_suppressions()
        write_suppressions_baseline(counts)
        sys.stdout.write(f"[security-audit] register written: {sum(counts.values())} suppressions\n")
        return 0
    return run_audit(
        tag="security",
        title="Monthly security-posture audit",
        cadence="monthly",
        scope_blurb="leaked secrets, network exposure and security-rule drift",
        checks=CHECKS,
        descriptions=CHECK_DESCRIPTIONS,
        todo_steps=[
            "A secrets finding: rotate the credential FIRST, then remove it (docs/security/git-credentials.md).",
            "Fix or justify each ruff S finding; a justified one gets '# noqa: S… -- <reason>'.",
            "After reviewing new suppressions, run `python scripts/check_security_posture.py --write-baseline`.",
        ],
        args=args,
    )


if __name__ == "__main__":
    sys.exit(main())
