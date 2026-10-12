"""check_tech_debt.py -- weekly tech-debt audit.

Watches the slow code-quality drift no single commit causes:

  todo-fixme-accumulation
      TODO / FIXME / XXX / HACK markers in app source (tests and docs
      excluded). Flags any file holding more than 5, and the whole tree
      when it passes 25.

  large-files
      Source files (.py .js .html .css, minified bundles excluded) of 5,000+
      lines -- the same threshold as the Utilities tab's tech-debt card
      (codehealth.LARGE_FILE_LINE_THRESHOLD).

  complex-functions
      Functions whose ruff C901 (McCabe) complexity is above 30 -- the ones
      that are hard to change safely (backlog #71 tracks the current set).

  dependency-drift
      Packages we declare in requirements.txt whose locked version
      (requirements.lock) is a whole major version behind the latest
      release on PyPI. Catches "3 majors behind" before it becomes a
      forced migration. CVEs are the advisory check's job, not this one.

  stale-tests
      tests/test_*.py files with no commit in 180+ days. A test untouched
      for six months while its module changes may no longer test what it
      claims to.

  code-duplication
      Copy-pasted blocks of 30+ lines across .py / .js files, found with
      jscpd (run through npx; tests excluded). Skipped with a note when
      Node isn't installed locally; in CI a missing Node is an error.

Wired via ``.github/workflows/weekly-tech-debt-audit.yml`` (Saturdays).
See ``audit_common.py`` for exit codes and email settings.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from audit_common import PROJECT_ROOT, Finding, build_parser, last_commit_date, read_text, run_audit, tracked_files

# ── Policy ───────────────────────────────────────────────────────────────────

TODO_TOTAL_THRESHOLD = 25
TODO_PER_FILE_THRESHOLD = 5
# Keep in step with codehealth.LARGE_FILE_LINE_THRESHOLD (a test pins it).
LARGE_FILE_LINE_THRESHOLD = 5000
COMPLEXITY_THRESHOLD = 30
STALE_TEST_DAYS = 180
DUPLICATE_MIN_LINES = 30
JSCPD_VERSION = "5.4.1"

_SOURCE_SUFFIXES = (".py", ".js", ".html", ".css")
_MINIFIED_SUFFIXES = (".min.js", ".min.css")
_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
# Files that talk ABOUT the markers (scanners and their docs), not debt.
_TODO_SKIP = frozenset({"codehealth.py", "scripts/check_tech_debt.py", "architecture.html"})


def _app_source(rel: str) -> bool:
    return rel.endswith(_SOURCE_SUFFIXES) and not rel.endswith(_MINIFIED_SUFFIXES) and not rel.startswith("tests/")


# ── todo-fixme-accumulation ──────────────────────────────────────────────────


def check_todo_fixme_accumulation() -> list[Finding]:
    per_file: dict[str, int] = {}
    for rel in tracked_files(_SOURCE_SUFFIXES):
        if not _app_source(rel) or rel in _TODO_SKIP:
            continue
        text = read_text(rel)
        count = len(_TODO_RE.findall(text)) if text else 0
        if count:
            per_file[rel] = count
    ranked = sorted(per_file.items(), key=lambda kv: -kv[1])
    findings = [
        Finding(
            check_id="todo-fixme-accumulation",
            path=rel,
            detail=f"{count} TODO/FIXME markers in one file (limit {TODO_PER_FILE_THRESHOLD}) — a hotspot to clear.",
        )
        for rel, count in ranked
        if count > TODO_PER_FILE_THRESHOLD
    ]
    total = sum(per_file.values())
    if total > TODO_TOTAL_THRESHOLD:
        top = "; ".join(f"{rel} ({n})" for rel, n in ranked[:5])
        findings.append(
            Finding(
                check_id="todo-fixme-accumulation",
                detail=f"{total} TODO/FIXME markers across the tree (limit {TODO_TOTAL_THRESHOLD}). Top: {top}",
            )
        )
    return findings


# ── large-files ──────────────────────────────────────────────────────────────


def check_large_files() -> list[Finding]:
    sized = []
    for rel in tracked_files(_SOURCE_SUFFIXES):
        if not _app_source(rel):
            continue
        text = read_text(rel)
        lines = len(text.splitlines()) if text else 0
        if lines >= LARGE_FILE_LINE_THRESHOLD:
            sized.append((rel, lines))
    return [
        Finding(
            check_id="large-files",
            path=rel,
            detail=f"{lines:,} lines (limit {LARGE_FILE_LINE_THRESHOLD:,}) — split it along its feature seams.",
        )
        for rel, lines in sorted(sized, key=lambda item: -item[1])
    ]


# ── complex-functions ────────────────────────────────────────────────────────

_C901_RE = re.compile(r"`(?P<name>[^`]+)` is too complex \((?P<score>\d+) > \d+\)")


def check_complex_functions() -> list[Finding]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            ".",
            "--select",
            "C901",
            "--config",
            f"lint.mccabe.max-complexity={COMPLEXITY_THRESHOLD}",
            "--output-format",
            "json",
            "--exit-zero",
        ],
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
    scored = []
    for item in results:
        rel = Path(item.get("filename", "")).resolve()
        try:
            rel_str = rel.relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            rel_str = rel.as_posix()
        if rel_str.startswith("tests/"):
            continue
        m = _C901_RE.search(item.get("message", ""))
        name, score = (m.group("name"), int(m.group("score"))) if m else ("?", 0)
        scored.append(
            (
                score,
                Finding(
                    check_id="complex-functions",
                    path=rel_str,
                    line=(item.get("location") or {}).get("row") or 0,
                    detail=f"{name}() has complexity {score} (limit {COMPLEXITY_THRESHOLD}) — split it into smaller steps.",
                ),
            )
        )
    return [finding for _, finding in sorted(scored, key=lambda pair: -pair[0])]


# ── dependency-drift ─────────────────────────────────────────────────────────


def _canonical(name: str) -> str:
    """PEP 503 name: lowercase, runs of -_. become one '-'."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _declared_packages() -> list[str]:
    names = []
    for raw in (read_text("requirements.txt") or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            names.append(_canonical(re.split(r"[\[<>=!~;\s]", line, maxsplit=1)[0]))
    return names


def _locked_versions() -> dict[str, str]:
    pins = {}
    for raw in (read_text("requirements.lock") or "").splitlines():
        m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)", raw)
        if m:
            pins[_canonical(m.group(1))] = m.group(2)
    return pins


def _major(version: str) -> int | None:
    """Leading number of a dotted version. None for undotted schemes like
    pywin32's (311, 312), where every release bumps the only number."""
    m = re.match(r"v?(\d+)\.", version.strip())
    return int(m.group(1)) if m else None


def _pypi_latest(name: str) -> str:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as resp:
        return json.load(resp)["info"]["version"]


def check_dependency_drift() -> list[Finding]:
    locked = _locked_versions()
    findings = []
    for name in _declared_packages():
        current = locked.get(name)
        if not current:
            continue  # tests/test_requirements.py already fails on an unlocked declared package
        try:
            latest = _pypi_latest(name)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            raise RuntimeError(f"PyPI lookup for {name} failed: {exc}") from exc
        cur_major, new_major = _major(current), _major(latest)
        if cur_major is not None and new_major is not None and new_major > cur_major:
            findings.append(
                Finding(
                    check_id="dependency-drift",
                    path="requirements.lock",
                    detail=f"{name} locked at {current}, latest is {latest} "
                    f"({new_major - cur_major} major version(s) behind).",
                )
            )
    return findings


# ── stale-tests ──────────────────────────────────────────────────────────────


def check_stale_tests() -> list[Finding]:
    today = datetime.date.today()
    findings = []
    for rel in tracked_files((".py",)):
        if not re.fullmatch(r"tests/test_[^/]+\.py", rel):
            continue
        last = last_commit_date(rel)
        if last is None:
            continue
        age = (today - last).days
        if age > STALE_TEST_DAYS:
            findings.append(
                Finding(
                    check_id="stale-tests",
                    path=rel,
                    detail=f"last changed {last.isoformat()} ({age} days ago) — check it still tests "
                    "what its module does today.",
                )
            )
    return findings


# ── code-duplication ─────────────────────────────────────────────────────────


def _npx() -> str | None:
    return shutil.which("npx.cmd" if os.name == "nt" else "npx") or shutil.which("npx")


def check_code_duplication() -> list[Finding]:
    npx = _npx()
    if npx is None:
        if os.environ.get("GITHUB_ACTIONS"):
            raise RuntimeError("npx not found — the workflow must set up Node for jscpd")
        sys.stderr.write("[tech-debt-audit] npx not found; skipping code-duplication locally\n")
        return []
    with tempfile.TemporaryDirectory(prefix="jscpd-") as out_dir:
        proc = subprocess.run(
            [
                npx,
                "--yes",
                f"jscpd@{JSCPD_VERSION}",
                "--reporters",
                "json",
                "--silent",
                "--min-lines",
                str(DUPLICATE_MIN_LINES),
                "--format",
                "python,javascript",
                "--formats-exts",
                "python:py;javascript:js",
                "--ignore",
                "tests/**,**/*.min.js,.claude/**,node_modules/**,__pycache__/**",
                "--output",
                out_dir,
                ".",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=PROJECT_ROOT,
            timeout=600,
        )
        report = Path(out_dir) / "jscpd-report.json"
        if not report.exists():
            raise RuntimeError(f"jscpd exit {proc.returncode}, no report: {(proc.stderr or proc.stdout).strip()[:300]}")
        data = json.loads(report.read_text(encoding="utf-8"))

    findings = []
    for dup in data.get("duplicates") or []:
        lines = int(dup.get("lines") or 0)
        first, second = dup.get("firstFile") or {}, dup.get("secondFile") or {}
        a, b = (first.get("name") or "?").replace("\\", "/"), (second.get("name") or "?").replace("\\", "/")
        if lines < DUPLICATE_MIN_LINES or not (a.endswith((".py", ".js")) and b.endswith((".py", ".js"))):
            continue
        findings.append(
            Finding(
                check_id="code-duplication",
                path=a,
                line=int(first.get("start") or 0),
                detail=f"{lines}-line block duplicated at {b}:{second.get('start')} — move it into one shared helper.",
            )
        )
    return findings


CHECKS = [
    ("todo-fixme-accumulation", check_todo_fixme_accumulation),
    ("large-files", check_large_files),
    ("complex-functions", check_complex_functions),
    ("dependency-drift", check_dependency_drift),
    ("stale-tests", check_stale_tests),
    ("code-duplication", check_code_duplication),
]

CHECK_DESCRIPTIONS = {
    "todo-fixme-accumulation": "TODO/FIXME markers piling up in one file or across the app.",
    "large-files": f"Source files of {LARGE_FILE_LINE_THRESHOLD:,}+ lines — hard to review and to change safely.",
    "complex-functions": f"Functions with McCabe complexity over {COMPLEXITY_THRESHOLD} (too many branches to test).",
    "dependency-drift": "A package we declare is a whole major version behind its latest release.",
    "stale-tests": f"Test files nobody has changed in {STALE_TEST_DAYS}+ days.",
    "code-duplication": f"Copy-pasted blocks of {DUPLICATE_MIN_LINES}+ lines across .py/.js files.",
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser("Weekly tech-debt audit.").parse_args(argv)
    return run_audit(
        tag="tech-debt",
        title="Weekly tech-debt audit",
        cadence="weekly",
        scope_blurb="slow code-quality drift (markers, size, complexity, stale dependencies and tests)",
        checks=CHECKS,
        descriptions=CHECK_DESCRIPTIONS,
        todo_steps=[
            "Decide which items are worth a backlog row; most are 'fix when next touching that area'.",
            "For dependency drift, read the package's changelog before raising its floor in requirements.txt.",
            "Thresholds live at the top of scripts/check_tech_debt.py if one is too noisy.",
        ],
        args=args,
    )


if __name__ == "__main__":
    sys.exit(main())
