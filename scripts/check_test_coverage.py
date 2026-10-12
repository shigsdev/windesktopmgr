"""check_test_coverage.py -- weekly test-coverage audit.

The commit gate only enforces the 80% overall floor, so coverage can slide
from 89% to 81% without anything going red. This runs the full suite and
compares against the committed baseline in docs/audit/coverage-baseline.json:

  overall-coverage-drift
      Overall coverage more than 1 percentage point below the baseline.

  per-file-coverage-drift
      Any file more than 5 points below its baseline. Catches one module
      losing its tests while the overall number barely moves. Files not in
      the baseline yet are skipped until the next --write-baseline.

  critical-path-floor
      Absolute minimums (not baseline-relative) for the modules where an
      untested change does real damage: the ones that kill processes,
      delete files, change system settings or run elevated.

Runs on a Windows runner: the suite imports wmi / pywin32. Test failures
don't stop the audit -- it only reads the coverage numbers; the commit gate
is what blocks failing tests.

After intentionally raising coverage, move the high-water mark up:

    python scripts/check_test_coverage.py --write-baseline

Wired via ``.github/workflows/weekly-coverage-audit.yml`` (Fridays).
See ``audit_common.py`` for exit codes and email settings.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from audit_common import PROJECT_ROOT, Finding, build_parser, run_audit

OVERALL_DRIFT_TOLERANCE_PP = 1.0
PER_FILE_DRIFT_TOLERANCE_PP = 5.0
BASELINE_PATH = PROJECT_ROOT / "docs" / "audit" / "coverage-baseline.json"

# Absolute floors, a few points under where each module sat when the audit
# was set up (2026-10-11, in brackets). Raise one when its coverage genuinely
# improves.
CRITICAL_PATH_FLOORS: dict[str, float] = {
    "remediation.py": 92.0,  # one-click fixes: winsock / TCP-IP resets, DISM+SFC, reboot (96.4%)
    "processes.py": 78.0,  # kill_process + the SAFE_PROCESSES kill guard (81.8%)
    "maintenance.py": 85.0,  # junk cleanup deletes files (89.9%)
    "backup.py": 84.0,  # backup jobs + the elevated helper hand-off (88.0%)
    "diagnose.py": 95.0,  # AI consent gate + what leaves the machine (99.9%)
}


def run_pytest_with_coverage() -> dict:
    """Run the unit suite with a JSON coverage report and return it parsed.
    Raises (-> exit 2) when no report was produced -- a crash before
    coverage could write, not a test failure."""
    with tempfile.TemporaryDirectory(prefix="cov-audit-") as tmp:
        report = Path(tmp) / "coverage.json"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-n", "auto", f"--cov-report=json:{report}", "-q"],
            capture_output=True,
            text=True,
            check=False,
            cwd=PROJECT_ROOT,
            timeout=1800,
        )
        tail = (proc.stdout or "").strip().splitlines()[-3:]
        sys.stdout.write(f"[coverage-audit] pytest exit {proc.returncode}: {' | '.join(tail)}\n")
        if not report.exists():
            raise RuntimeError(f"pytest produced no coverage report: {(proc.stderr or proc.stdout)[-500:]}")
        return json.loads(report.read_text(encoding="utf-8"))


def per_file_and_total(cov: dict) -> tuple[dict[str, float], float]:
    """``({posix_path: percent}, overall_percent)`` from a coverage JSON
    report. Paths are normalised to forward slashes so a baseline written
    on Windows matches on any runner."""
    per_file = {}
    for path, info in (cov.get("files") or {}).items():
        pct = ((info or {}).get("summary") or {}).get("percent_covered")
        if isinstance(pct, int | float):
            per_file[path.replace("\\", "/")] = float(pct)
    return per_file, float((cov.get("totals") or {}).get("percent_covered") or 0.0)


def read_baseline() -> dict | None:
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_baseline(overall: float, per_file: dict[str, float]) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_doc": "Coverage high-water mark for scripts/check_test_coverage.py. "
        "Regenerate with `python scripts/check_test_coverage.py --write-baseline` "
        "after intentionally raising coverage.",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "overall": round(overall, 2),
        "per_file": {path: round(pct, 2) for path, pct in sorted(per_file.items())},
    }
    BASELINE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check_overall_drift(overall: float, baseline: dict) -> list[Finding]:
    base = baseline.get("overall")
    if not isinstance(base, int | float) or base - overall <= OVERALL_DRIFT_TOLERANCE_PP:
        return []
    return [
        Finding(
            check_id="overall-coverage-drift",
            detail=f"overall coverage {overall:.1f}% is {base - overall:.1f} points below the {base:.1f}% "
            f"baseline (tolerance {OVERALL_DRIFT_TOLERANCE_PP:.0f}).",
        )
    ]


def check_per_file_drift(per_file: dict[str, float], baseline: dict) -> list[Finding]:
    findings = []
    for path, base in sorted((baseline.get("per_file") or {}).items()):
        current = per_file.get(path)
        if current is None or not isinstance(base, int | float):
            continue  # deleted / renamed since the baseline
        if base - current > PER_FILE_DRIFT_TOLERANCE_PP:
            findings.append(
                Finding(
                    check_id="per-file-coverage-drift",
                    path=path,
                    detail=f"{base:.1f}% -> {current:.1f}% ({base - current:.1f} points down; "
                    f"tolerance {PER_FILE_DRIFT_TOLERANCE_PP:.0f}).",
                )
            )
    return findings


def check_critical_path_floors(per_file: dict[str, float]) -> list[Finding]:
    findings = []
    for path, floor in CRITICAL_PATH_FLOORS.items():
        current = per_file.get(path)
        if current is None:
            findings.append(
                Finding(
                    check_id="critical-path-floor",
                    path=path,
                    detail="critical-path file missing from the coverage report — renamed or no longer measured? "
                    "Update CRITICAL_PATH_FLOORS.",
                )
            )
        elif current < floor:
            findings.append(
                Finding(
                    check_id="critical-path-floor",
                    path=path,
                    detail=f"{current:.1f}% covered, below its {floor:.0f}% floor.",
                )
            )
    return findings


CHECK_DESCRIPTIONS = {
    "overall-coverage-drift": f"Overall coverage fell more than {OVERALL_DRIFT_TOLERANCE_PP:.0f} point below the baseline.",
    "per-file-coverage-drift": f"One file's coverage fell more than {PER_FILE_DRIFT_TOLERANCE_PP:.0f} points below its baseline.",
    "critical-path-floor": "A module that kills processes, deletes files or changes the system is under its floor.",
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser("Weekly test-coverage audit.")
    parser.add_argument("--write-baseline", action="store_true", help="record current coverage as the new baseline")
    args = parser.parse_args(argv)

    try:
        per_file, overall = per_file_and_total(run_pytest_with_coverage())
    except (RuntimeError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        sys.stderr.write(f"[coverage-audit] could not measure coverage: {exc}\n")
        return 2
    if args.write_baseline:
        write_baseline(overall, per_file)
        sys.stdout.write(f"[coverage-audit] baseline written: {overall:.2f}% over {len(per_file)} files\n")
        return 0

    baseline = read_baseline()
    if baseline is None:
        sys.stderr.write(f"[coverage-audit] {BASELINE_PATH} missing or unreadable — run --write-baseline\n")
        return 2
    checks = [
        ("overall-coverage-drift", lambda: check_overall_drift(overall, baseline)),
        ("per-file-coverage-drift", lambda: check_per_file_drift(per_file, baseline)),
        ("critical-path-floor", lambda: check_critical_path_floors(per_file)),
    ]
    return run_audit(
        tag="coverage",
        title="Weekly test-coverage audit",
        cadence="weekly",
        scope_blurb="test-coverage drift against the committed baseline",
        checks=checks,
        descriptions=CHECK_DESCRIPTIONS,
        todo_steps=[
            "Add tests for the files above (pytest --cov shows the exact uncovered lines).",
            "If a drop is intentional (code removed), refresh the baseline: "
            "`python scripts/check_test_coverage.py --write-baseline`, and commit it.",
        ],
        args=args,
        subject_extra=f" ({overall:.1f}%)",
        header_extra=[f"Overall coverage: {overall:.1f}% (baseline {baseline.get('overall', '?')}%)", ""],
    )


if __name__ == "__main__":
    sys.exit(main())
