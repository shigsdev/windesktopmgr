---
name: arch-update
description: Recompute architecture.html chip values (total test count, API endpoint count, repo line count, per-test-file subtitle counts) from live source-of-truth commands and apply targeted edits. Use when finishing a code change that touched tests / routes / source-file sizes, OR when the existing PostToolUse drift hook flags a mismatch. Replaces the manual sed-edit ritual that previously ran ~6 times per change.
disable-model-invocation: true
---

# arch-update — Refresh architecture.html chips from source of truth

Phase 9 of the CLAUDE.md workflow requires keeping `architecture.html`
chips in sync with reality. Historically this was a manual ritual: grep
for old values, count the new ones by hand, sed-replace across 4-6
locations. This skill automates the count + diff + edit.

**User-invokable only** (`disable-model-invocation: true`). Claude must
not auto-fire — it edits a checked-in file based on side-effect
computation, so the user owns the trigger.

## When to use

Run when any of these CLAUDE.md architecture triggers fired during a
change:

- Test count changed (added/removed/parametrized tests)
- A Flask route was added or removed
- A source file crossed a significant line-count threshold (~5% shift)
- The PostToolUse drift hook surfaced "TEST COUNT DRIFT: ..."
- You just realized the chips look stale

Skip when nothing relevant changed.

## What it updates

1. **Total test count chips** — every `<N> tests` token near the green
   coverage badge. Currently lives in ~4 places.
2. **API endpoint count chip** — `<N> API endpoints · localhost:5000`
3. **Total repo line count chip** — `<N> tests · ~<lines> lines`
4. **Per-test-file count subtitles** — `<N> tests · ...` inside the
   individual `test-chip` divs.

What it does NOT touch:

- Diagram body (positioning, arrows, colors)
- Module / route / file chips that don't exist yet
- The coverage % itself (computed separately via the codehealth
  Refresh-coverage button)

## Workflow

### 1. Compute current values

From the repo root:

```bash
# Total tests via pytest collection. --no-cov suppresses the coverage
# tail that otherwise hides the collection summary. The summary line
# looks like "2641/2751 tests collected (110 deselected) in 0.71s" --
# the first number is the post-deselect count we want.
TESTS=$(python -m pytest --collect-only --no-cov 2>&1 \
        | grep -oE '[0-9]+/[0-9]+ tests collected' \
        | head -1 | grep -oE '^[0-9]+')

# Total Flask routes (raw count -- see calibration note below).
ENDPOINTS=$(grep -rE "^@(app|[a-z_]+_bp)\.route" --include="*.py" . | wc -l)

# Approximate non-test runtime line count (raw count -- see
# calibration note below).
LINES=$(find . -type f \
        \( -name "*.py" -o -name "*.html" -o -name "*.js" -o -name "*.css" \) \
        -not -path "./.git/*" -not -path "./.claude/*" \
        -not -path "./.pytest_cache/*" -not -path "./.ruff_cache/*" \
        -not -path "./tests/*" \
        -exec wc -l {} + | tail -1 | awk '{print $1}')

echo "tests=$TESTS endpoints=$ENDPOINTS lines=$LINES"
```

**Calibration note (FIRST RUN ONLY)**: the original chips for
`endpoints` (77) and `lines` (~21,480) were hand-curated and the raw
counts above will be HIGHER. That doesn't mean the raw counts are
wrong -- it means the original chip used a stricter definition (e.g.
HTTP-method-distinct endpoints, or only top-level runtime modules).

On first run of this skill, do one of:

1. **Re-baseline the chips** to the raw counts above (recommended --
   the raw counts are reproducible and verifiable; the hand-curated
   semantics are lost). Update the chip values to the new raw numbers,
   note the baseline shift in the commit message.
2. **Apply the chip's filter manually** before computing -- e.g. only
   count `*.route("/api/*")` and only count `windesktopmgr.py`. Add the
   filter as a comment next to the chip so future runs use the same
   definition.

After calibration is settled, subsequent runs of the skill are just
"keep this stable number current."

### 2. Read existing chip values

Find the current values in architecture.html so you know what to
replace:

```bash
grep -nE '[0-9],?[0-9]+ tests' architecture.html | head -10
grep -nE '[0-9]+ API endpoints' architecture.html | head -3
grep -nE '~[0-9],?[0-9]+ lines' architecture.html | head -3
```

### 3. Apply targeted edits

Use the Edit tool (with `replace_all: true` for chips that appear
multiple times in the same file) to swap each old chip value with the
new one. Match the original formatting:

- `2,641 tests` (comma-formatted)
- `77 API endpoints`
- `~21,480 lines` (tilde + comma)

**Hard rule: idempotent.** If the current value already matches, NO-OP.
Don't write phantom diffs.

### 4. Per-file test count subtitles (optional second pass)

If individual test-chip subtitles look stale, recompute per file:

```bash
for f in tests/test_*.py; do
  base=$(basename "$f")
  count=$(pytest --collect-only -q "$f" 2>&1 | tail -1 | grep -oE '[0-9]+' | head -1)
  echo "$base $count"
done
```

Then update the test-chip `<div class="test-sub">N tests · ...</div>`
subtitles for any files that drifted.

### 5. Run the architecture drift test

Confirm the regression guard still passes:

```bash
pytest tests/test_architecture_html.py --no-cov
```

### 6. Report back

Print a summary of:

- Old → new for each chip changed
- Any chip that shifted by more than 10% (flag as "significant — verify
  this is the change you intended")
- Total edits applied

If `pytest` collection failed (e.g., import error in a test file),
abort and report the failure — do NOT apply chip edits against a
non-collectable suite.

### 7. Standard workflow takeover

After this skill returns, the caller picks up the normal Phase 4 →
Phase 5 → commit/push workflow. This skill never commits on its own.

## Caveats

- **pytest collection cost**: ~5-10s on this codebase. Acceptable but
  not instant. Don't invoke this in a tight loop.
- **Blueprint routes**: the endpoint grep won't catch routes registered
  via Flask blueprints with dynamic names. Spot-check expected.
- **Line-count semantics**: the `find` above EXCLUDES `tests/` to match
  the original "~21,480 lines" chip intent ("non-test runtime"). If the
  chip semantics ever change, update both the find command and the
  chip wording.
- **`.claude/skills/`**: this skill folder itself is excluded from the
  line count (it's not runtime code).
- **Multiple match risk**: `2,641 tests` appears 4 times in the file
  but `2,641` alone appears in other contexts. Always match the full
  chip phrase (`N tests`, `N API endpoints`), never just the number.

## Honest scope

This skill handles ~80% of architecture.html drift cases. The other
20% — new file chips, new module sections, route schema changes,
color-coded status changes — still require manual editing because the
skill won't invent new chips for files it doesn't know about.

If you find yourself manually editing architecture.html for the same
reason 3+ times, extend this skill rather than working around it.
