"""scripts/sop_report.py -- pre-fill the CLAUDE.md SOP Compliance Report (#59).

    python scripts/sop_report.py --title "Short description" [--commit SHA]
                                 [--backlog PATH] [--count-tests]

Reads the facts git can prove about ``--commit`` (default HEAD -- the squash
merge on main) and pre-marks those checklist lines; everything that needs
judgement or a run this script can't see (ruff, pytest, /code-review,
verify) stays ``[ ]`` for the author to fill in. Auto-detected:

  * files changed + docs-only fast path (CLAUDE.md "What counts as docs-only")
  * pushed / merged -- the commit is an ancestor of origin/main
  * tests touched alongside code (Phase 5)
  * architecture.html touched, or a Step-4 trigger it missed (new root /
    scripts / tests file) (Phase 9)
  * backlog row -- project_backlog.md mentions "PR #<n>" from the subject
  * optional ``--count-tests``: pytest --collect-only total

Read-only. Exit 0 always (it's a report, not a gate).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

DEFAULT_BACKLOG = os.path.join(
    os.path.expanduser("~"), ".claude", "projects", "C--shigsapps-windesktopmgr", "memory", "project_backlog.md"
)
_PR_RE = re.compile(r"\(#(\d+)\)\s*$")
_CODE_SUFFIXES = (".py", ".js", ".css", ".ps1", ".bat", ".toml", ".txt", ".cfg", ".yaml", ".yml", ".json", ".lock")

DONE, SKIP, TODO, MISS = "✅", "⏭️", "[ ]", "❌"


def _git(*args: str) -> str:
    out = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return out.stdout.strip() if out.returncode == 0 else ""


def is_docs_only(path: str) -> bool:
    """CLAUDE.md's docs-only rule: CLAUDE.md, architecture.html, *.md outside tests/."""
    p = path.replace("\\", "/")
    if p in ("CLAUDE.md", "architecture.html"):
        return True
    return p.endswith(".md") and not p.startswith("tests/")


def is_code(path: str) -> bool:
    p = path.replace("\\", "/")
    return not is_docs_only(p) and (p.endswith(_CODE_SUFFIXES) or p.startswith(("templates/", "static/")))


def arch_triggers(added: list[str]) -> list[str]:
    """Newly added files that are CLAUDE.md Step-4 triggers."""
    hits = []
    for path in added:
        parts = path.replace("\\", "/").split("/")
        if len(parts) == 1 or (parts[0] in ("scripts", "tests") and len(parts) == 2):
            hits.append(path)
    return hits


def collect(commit: str, backlog_path: str) -> dict:
    """Facts about ``commit`` from git + the backlog file."""
    subject = _git("log", "-1", "--format=%s", commit)
    status = _git("diff", "--name-status", f"{commit}^", commit)
    files, added = [], []
    for line in status.splitlines():
        cols = line.split("\t")
        if len(cols) >= 2:
            files.append(cols[-1])
            if cols[0].startswith("A"):
                added.append(cols[-1])
    pr_match = _PR_RE.search(subject)
    pr = pr_match.group(1) if pr_match else None
    backlog_hit = None
    if pr:
        try:
            with open(backlog_path, encoding="utf-8") as f:
                backlog_hit = f"PR #{pr}" in f.read()
        except OSError:
            backlog_hit = None
    merged = (
        subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"], capture_output=True).returncode
        == 0
    )
    return {
        "sha": _git("rev-parse", "--short", commit) or commit,
        "subject": subject,
        "pr": pr,
        "files": files,
        "added": added,
        "merged": merged,
        "backlog_hit": backlog_hit,
    }


def count_tests() -> int | None:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q", "--no-cov"],
        capture_output=True,
        text=True,
    )
    total = sum(int(m) for m in re.findall(r"^tests/\S+: (\d+)$", out.stdout, re.M))
    return total or None


def render(title: str, facts: dict, test_count: int | None = None) -> str:
    files = facts["files"]
    docs_only = bool(files) and all(is_docs_only(f) for f in files)
    code = [f for f in files if is_code(f)]
    tests_touched = any(f.replace("\\", "/").startswith("tests/") for f in files)
    arch_touched = "architecture.html" in files
    missed = [] if arch_touched else arch_triggers(facts["added"])
    docs_skip = f"{SKIP} Skipped (docs-only — no runtime code changed)"

    def gate(label: str) -> str:
        return f"  {docs_skip if docs_only else TODO} {label}"

    if docs_only:
        tests_line = f"{SKIP} Skipped (docs-only)"
    elif code and tests_touched:
        tests_line = f"{DONE} New/modified code has test coverage (tests/ changed)"
    elif code:
        tests_line = f"{MISS} Code changed but no tests/ file changed — add tests or justify"
    else:
        tests_line = f"{TODO} New/modified code has test coverage"

    if arch_touched:
        arch_line = f"{DONE} architecture.html updated"
    elif missed:
        arch_line = f"{MISS} architecture.html NOT updated but Step-4 trigger(s): {', '.join(missed)}"
    else:
        arch_line = f"{TODO} architecture.html — no trigger detected; mark it skipped with a reason"

    pr = facts["pr"]
    if facts["backlog_hit"]:
        backlog_line = f"{DONE} Backlog updated — mentions PR #{pr}"
    elif pr and facts["backlog_hit"] is False:
        backlog_line = f"{MISS} Backlog has no row mentioning PR #{pr}"
    else:
        backlog_line = f"{TODO} Backlog updated — dated Done row or ✅ SHIPPED annotation (not optional)"

    pushed = f"{DONE} Pushed to remote (merged to origin/main)" if facts["merged"] else f"{TODO} Pushed to remote"
    lines = [
        f"SOP Compliance Report — {title}",
        "──────────────────────────────────────────────────────",
        "Phase 1  Planning",
        f"  {TODO} Checked backlog",
        f"  {TODO} Scoped work",
        f"  {DONE} Identified affected files ({len(files)} changed)",
        "Phase 2  Git Workflow",
        f"  {TODO} Pulled latest main",
        f"  {TODO} Small logical commits",
        f"  {pushed}",
        "Phase 3  Coding Standards",
        f"  {TODO} Python first, PowerShell secondary",
        f"  {TODO} Boundary safety (escaping, validation)",
        f"  {TODO} Graceful fallbacks for external calls",
        "Phase 4  Quality Gates",
        gate("ruff check + format"),
        gate("pytest (all pass, ≥80% coverage)" + (f" — {test_count:,} tests collected" if test_count else "")),
        gate("/code-review (high-priority findings resolved or justified)"),
        f"  {TODO} pre-commit hooks passed",
        gate("python dev.py deploy (pull + restart + verify)"),
        "Phase 5  Tests",
        f"  {tests_line}",
        "Phase 9  Documentation",
        f"  {backlog_line}",
        f"  {arch_line}",
        "Phase 10 Post-Incident (bug fixes only)",
        f"  {TODO} Root cause + gap type documented",
        f"  {TODO} Regression test added",
        f"  {TODO} Prevention: line in commit message",
    ]
    body = "\n".join(lines)
    counts = {mark: body.count(mark) for mark in (DONE, SKIP, MISS, TODO)}
    lines += [
        f"Summary: {counts[DONE]} done, {counts[SKIP]} skipped, {counts[MISS]} not done, {counts[TODO]} to fill in",
        f"Commit(s): {facts['sha']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--title", required=True, help="Short description of the change")
    parser.add_argument("--commit", default="HEAD", help="Commit to report on (default HEAD)")
    parser.add_argument("--backlog", default=DEFAULT_BACKLOG, help="project_backlog.md path")
    parser.add_argument("--count-tests", action="store_true", help="Also run pytest --collect-only (~10 s)")
    args = parser.parse_args(argv)
    facts = collect(args.commit, args.backlog)
    report = render(args.title, facts, count_tests() if args.count_tests else None)
    sys.stdout.buffer.write((report + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
