---
description: Refresh architecture.html chip values (test count, endpoint count, line count) from live source-of-truth commands and apply targeted edits. Replaces the manual sed-edit ritual.
allowed-tools: Bash, Read, Edit
---

You are running the `/arch-update` slash command. Goal: recompute the
chip values in `architecture.html` from source-of-truth commands and
apply idempotent edits.

Follow this workflow precisely. Do NOT skip steps. Do NOT auto-commit
— stop after step 5 and let the user pick up the normal workflow.

## Step 1 — Compute new values

Run from the repo root:

```bash
TESTS=$(python -m pytest --collect-only --no-cov 2>&1 \
        | grep -oE '[0-9]+/[0-9]+ tests collected' \
        | head -1 | grep -oE '^[0-9]+')

ENDPOINTS=$(grep -rE "^@(app|[a-z_]+_bp)\.route" --include="*.py" . | wc -l)

LINES=$(find . -type f \
        \( -name "*.py" -o -name "*.html" -o -name "*.js" -o -name "*.css" \) \
        -not -path "./.git/*" -not -path "./.claude/*" \
        -not -path "./.pytest_cache/*" -not -path "./.ruff_cache/*" \
        -not -path "./tests/*" \
        -exec wc -l {} + | tail -1 | awk '{print $1}')

echo "tests=$TESTS endpoints=$ENDPOINTS lines=$LINES"
```

If pytest collection FAILS (import error, etc.), abort and report. Do
NOT apply chip edits against a non-collectable suite.

## Step 2 — Read existing chip values

```bash
grep -nE '[0-9],?[0-9]+ tests' architecture.html | head -10
grep -nE '[0-9]+ API endpoints' architecture.html | head -3
grep -nE '~[0-9],?[0-9]+ lines' architecture.html | head -3
```

Capture the current values so you can compute the diff.

## Step 3 — Calibration check (FIRST-RUN PATH)

On first invocation, the endpoint and line counts will likely be
HIGHER than the hand-curated chips (e.g. 127 vs. 77 endpoints; 45k
vs. 21k lines). The original chips used a stricter definition that
wasn't captured in code.

Present the user with the diff and ask which path:

**Option A** (recommended) — re-baseline to raw counts. New numbers
are reproducible and auditable. Document the baseline shift in the
commit message.

**Option B** — keep the chip's stricter definition. Apply a filter
to the count commands and document the filter inline next to the
chip. Subsequent runs use the same filter.

Wait for the user's choice before applying any non-test-count edits.
(Test count is unambiguous — `pytest --collect-only` is the canonical
source, just apply the diff.)

## Step 4 — Apply targeted edits

Use the Edit tool with `replace_all: true` for chips that appear
multiple times in the same file. Match the full chip phrase, NEVER
just the number (the number may appear in other contexts).

Examples:
- `2,641 tests` → `<new>,<formatted> tests` (preserve comma)
- `77 API endpoints` → `<new> API endpoints`
- `~21,480 lines` → `~<new>,<formatted> lines`

**Hard rule: idempotent.** If the chip value already matches, NO-OP.

## Step 5 — Run the architecture drift test

```bash
python -m pytest tests/test_architecture_html.py --no-cov 2>&1 | tail -5
```

If the drift test now fails, REVERT the chip edits and report — the
drift test encodes constraints the chip values must satisfy.

## Step 6 — Report

Print a summary:

```
arch-update report
──────────────────
tests:     <old> → <new>  (Δ <signed>)
endpoints: <old> → <new>  (Δ <signed>)  [calibration: A | B | unchanged]
lines:     <old> → <new>  (Δ <signed>)  [calibration: A | B | unchanged]

Edits applied: <count>
test_architecture_html.py: <PASS|FAIL>

Next: user picks up the normal Phase 4 → commit/push workflow.
```

Then STOP. Do not commit. Do not push. The user owns the next step.

## Per-test-file subtitles (optional second pass)

If individual test-chip subtitles look stale (e.g. `test_baseline.py`
chip says "165 tests" but pytest collects 170 from that file), ask
the user whether to do a per-file refresh:

```bash
for f in tests/test_*.py; do
  base=$(basename "$f")
  count=$(python -m pytest --collect-only --no-cov "$f" 2>&1 \
          | grep -oE '[0-9]+/[0-9]+ tests collected' \
          | head -1 | grep -oE '^[0-9]+')
  echo "$base: $count"
done
```

Only run this if asked — it's slower and not always needed.

## Caveats

- pytest collection costs ~5-10s. Don't run in a tight loop.
- Blueprint routes with dynamic names may not match the grep pattern.
  Spot-check the endpoint count if it looks suspicious.
- Line semantics exclude `tests/` and `.claude/` to match the
  original chip's "non-test runtime" intent.
- The `.gitignore` ignores `.claude/*` but whitelists
  `.claude/skills/` and `.claude/commands/`. If you add new automation
  files, double-check they land in the tracked subtrees.
