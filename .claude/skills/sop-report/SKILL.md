---
name: sop-report
description: Generate the CLAUDE.md Phase 11 SOP Compliance Report at the end of a code change. Runs scripts/sop_report.py, which pre-marks everything git can prove (files changed, docs-only fast path, merged to origin/main, tests touched, architecture.html touched or a missed Step-4 trigger, backlog row mentioning the PR), then you fill the remaining [ ] lines from what you actually ran. Use when wrapping up any merged change, as the LAST thing printed.
---

# sop-report — pre-filled SOP Compliance Report

CLAUDE.md requires the SOP Compliance Report as the last thing printed for
every change. This skill removes the error-prone parts (miscounting, forgetting
whether architecture.html or the backlog was touched) by deriving them from git.

## Steps

1. After the PR is merged and deployed, run from the repo (any checkout):

   ```bash
   python scripts/sop_report.py --title "<short description of the change>" --commit <merged squash sha>
   ```

   Add `--count-tests` to include the `pytest --collect-only` total (~10 s).
   `--commit` defaults to HEAD; pass the squash-merge sha when HEAD is elsewhere.

2. Read the output. Lines it could prove are already marked:
   - ✅ done · ⏭️ skipped (docs-only fast path) · ❌ not done (with the reason)
   - `[ ]` = needs you: ruff, pytest, /code-review, pre-commit, deploy/verify,
     planning and coding-standard items, Phase 10 for bug fixes.

3. Replace every `[ ]` with ✅ / ⏭️ (reason) / ❌ (reason) from what you
   actually ran in this session — never mark ✅ for a gate you didn't run.
   Fix (don't just report) any ❌ the script found if it's in scope: e.g. add
   the backlog row, or update architecture.html for a missed trigger.

4. Recount the Summary line after filling in, and print the finished report
   as the LAST thing in your response.

## Notes

- Read-only; it never edits files or runs gates.
- The backlog check looks for `PR #<n>` (from the commit subject's `(#n)`) in
  `~/.claude/projects/C--shigsapps-windesktopmgr/memory/project_backlog.md`;
  override with `--backlog <path>`.
