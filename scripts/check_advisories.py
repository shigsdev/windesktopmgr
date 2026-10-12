"""check_advisories.py -- weekly dependency-advisory (CVE) check.

Runs ``pip-audit`` against ``requirements.lock``, the exact versions the
app runs with (all 55 packages, transitive ones included). A CVE published
against a package we already pin never trips a commit gate -- nothing in
the repo changed -- so this weekly run is what notices it.

``--no-deps --disable-pip`` makes pip-audit look the pins up in the
vulnerability database without installing them, so the audit runs on a
Linux runner even though the lock holds Windows-only packages (pywin32,
wmi).

Wired via ``.github/workflows/weekly-advisory-check.yml`` (Mondays).
See ``audit_common.py`` for exit codes and email settings.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

from audit_common import PROJECT_ROOT, Finding, build_parser, run_audit

LOCK_FILE = "requirements.lock"

# Advisory IDs reviewed and judged not to apply, with the reason. Each one
# is passed to pip-audit as --ignore-vuln. Keep this short and explained.
IGNORED_VULNS: dict[str, str] = {}


def _pip_audit_cmd() -> list[str]:
    cmd = [sys.executable, "-m", "pip_audit", "-r", LOCK_FILE, "--no-deps", "--disable-pip", "--format", "json"]
    for vuln_id in sorted(IGNORED_VULNS):
        cmd += ["--ignore-vuln", vuln_id]
    return cmd


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def check_pip_advisories() -> list[Finding]:
    """One finding per vulnerable package, listing its advisory IDs and the
    lowest version that fixes all of them. Raises if pip-audit can't run or
    prints something that isn't its JSON report -- that's an internal error
    (exit 2), never a silent "clean"."""
    proc = subprocess.run(
        _pip_audit_cmd(),
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
        timeout=600,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"pip-audit exit {proc.returncode}, no JSON report: {proc.stderr.strip()[:300]}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"pip-audit returned unexpected JSON ({type(data).__name__})")

    findings = []
    for dep in data.get("dependencies") or []:
        vulns = dep.get("vulns") or []
        if not vulns:
            continue
        ids = [v.get("id") or "?" for v in vulns]
        # Each advisory lists the versions that fix it; the upgrade target is
        # the highest of the per-advisory minimums.
        minimums = [min(v["fix_versions"], key=_version_key) for v in vulns if v.get("fix_versions")]
        unfixed = len(vulns) - len(minimums)
        target = f"upgrade to >= {max(minimums, key=_version_key)}" if minimums else "no fixed version yet"
        if minimums and unfixed:
            target += f" ({unfixed} advisory(ies) not fixed in any release yet)"
        findings.append(
            Finding(
                check_id="pip-advisories",
                path=LOCK_FILE,
                detail=f"{dep.get('name')} {dep.get('version')} — {len(vulns)} advisory(ies): "
                f"{', '.join(ids)}. Fix: {target}.",
            )
        )
    return findings


CHECKS = [("pip-advisories", check_pip_advisories)]

CHECK_DESCRIPTIONS = {
    "pip-advisories": "A pinned package in requirements.lock has a published security advisory (CVE).",
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser("Weekly dependency-advisory check.").parse_args(argv)
    return run_audit(
        tag="advisory",
        title="Weekly dependency-advisory check",
        cadence="weekly",
        scope_blurb="published security advisories against the pinned Python packages",
        checks=CHECKS,
        descriptions=CHECK_DESCRIPTIONS,
        todo_steps=[
            "Raise the affected package's floor in requirements.txt to the fixed version.",
            "Regenerate the lock: `python scripts/lock_requirements.py`, then run the tests.",
            "If an advisory doesn't apply to how we use the package, add its ID to "
            "IGNORED_VULNS in scripts/check_advisories.py with the reason.",
        ],
        args=args,
    )


if __name__ == "__main__":
    sys.exit(main())
