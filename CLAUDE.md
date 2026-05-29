# WinDesktopMgr — Claude Code Guidelines

## ⚠️ MANDATORY WORKFLOW — Follow This Exact Order Every Change

**Every** code change (feature, bug fix, refactor) MUST follow this sequence.
No step may be skipped. No exceptions.

```
1. Code the change
2. ruff check + format       →  python -m ruff check . && python -m ruff format .
3. pytest                    →  python -m pytest tests/ -n auto   (parallel, ~48s)
3a. /code-review             →  invoke the code-review skill against the pending diff.
                                High-priority findings MUST be resolved or justified
                                in the commit message BEFORE step 5. (Plugin: code-
                                review@claude-plugins-official, installed 2026-05-28.)
3b. /code-simplifier         →  RECOMMENDED for refactor-heavy PRs (>200 LOC, dense
                                new logic, or "tidy up the surrounding code" intent).
                                Optional for small focused changes. Findings are
                                suggestions, not gates -- accept or reject per
                                judgement; document accepted simplifications in the
                                commit body. (Plugin: code-simplifier@claude-plugins-
                                official, installed 2026-05-28.)
4. Update architecture.html  →  REQUIRED if any of the triggers below apply
5. git commit + push branch  →  open PR, merge to main (pre-commit + pre-push hooks)
6. deploy + verify           →  pull main into the primary repo, restart the tray,
                                then `python dev.py verify` against the DEPLOYED code
7. Print SOP Compliance Report (Phase 11 checklist — see bottom of this file)
```

**Step 4 is NON-OPTIONAL when any of these triggers apply.** If you skip it,
the diagram rots and the checklist is a lie. Triggers:
- New or removed file in the repo root (e.g. `applogging.py`, `scripts/*`)
- New or removed Flask route in `windesktopmgr.py` or `homenet.py`
- New or removed external service, data source, cache file, or worker thread
- New or removed test file under `tests/`
- Line counts shifted by more than ~5% on any file chip already in the diagram
- New or removed tab in `templates/index.html`
- Test count or coverage percentage changed

**Shortcut**: when only the test-count / endpoint-count / line-count
chips need refreshing (the most common drift), invoke `/arch-update`
(slash command in `.claude/commands/arch-update.md`) instead of
editing chips by hand. The command computes new values from
source-of-truth commands (`pytest --collect-only`, route grep,
`find ... wc -l`), applies idempotent edits, and reports a diff.
Use the command first, then manually edit anything it doesn't cover
(new file chips, new module sections, color-coded status changes).

The matching skill at `.claude/skills/arch-update/SKILL.md` lets
Claude invoke the same workflow programmatically via the Skill tool;
the slash command is for interactive use from your Claude session.

**One-time setup**: if `/arch-update` returns "Unknown command",
restart your Claude session (or open a new one) so the project's
slash-command registry reloads.

If none of those triggers apply, mark Phase 9 `architecture.html` as ⏭️ Skipped
with a one-line reason in the SOP Compliance Report. Never silently skip.

**Step 6 is NON-OPTIONAL (for code changes).** The running tray re-execs from
the **primary repo** (`C:\shigsapps\windesktopmgr`), NOT the worktree — so the
deploy half of step 6 (pull `main` into the primary repo, then restart the
tray) is what actually makes a change live. `dev.py verify` then catches
mock-vs-reality drift, startup crashes, and PS output format regressions.
A green verify against a tray that re-execed *old* code is a false pass —
always confirm the primary repo was pulled before the restart. See the
Docs-Only Fast Path below for the one exception.

**Step 7 is NON-OPTIONAL.** The SOP Compliance Report must be the LAST thing
printed for every code change. See the template at the bottom of this file.

---

## 📝 Docs-Only Fast Path — Skip Testing When No Code Changed

If a change touches **only documentation files** and no runtime behavior,
Steps 2 (ruff), 3 (pytest), and 6 (deploy + verify) add no value and should
be explicitly skipped. Running them on a doc-only commit just wastes ~90
seconds per change and trains the habit of ignoring green output.

### What counts as docs-only

A change is docs-only if **every** modified file matches one of these:

- `CLAUDE.md`
- `architecture.html`
- `README.md`, `*.md` at the repo root
- `docs/**/*.md` or any other markdown outside `tests/`
- Files under `~/.claude/projects/*/memory/` (feedback_*.md, project_*.md, etc.)

If **any** of these are touched, it is NOT docs-only — run the full workflow:

- `*.py` (including tests, scripts, tools)
- `templates/index.html` or any other file under `templates/`
- `static/**` (JS, CSS, images that ship with the app)
- `pyproject.toml`, `requirements*.txt`, `.pre-commit-config.yaml`
- PowerShell scripts (`*.ps1`), batch files (`*.bat`)
- Anything the running Flask process or tray imports or reads at runtime

### Docs-only fast path workflow

```
1. Edit the docs
2. git commit + push         →  pre-commit hook still runs, but ruff/pytest
                                no-op when no .py files changed
3. Print SOP Compliance Report with Steps 2, 3, and 6 marked:
   ⏭️ Skipped (docs-only — no runtime code changed)
```

**Still mandatory on the fast path:**
- The SOP Compliance Report itself (Step 7). Skipping steps is fine;
  silently skipping is not.
- Any triggers from Step 4. A doc change that doesn't touch
  `architecture.html` when it should (e.g. adding a new SOP section that
  references the diagram) still needs the diagram update.
- Spell/link sanity check on the prose you just wrote.

**Never use the fast path for:**
- Changes that touch docstrings in `.py` files — those are code changes.
- "Refactors" that rename something in both code and docs — not docs-only.
- Anything where you're unsure. When in doubt, run the full workflow;
  the cost of a false negative (shipping a broken change) is much higher
  than the cost of a false positive (running tests on a doc tweak).

---

## 📓 Backlog Logging — Record Every Merged Change (MANDATORY)

`project_backlog.md` (in project memory:
`~/.claude/projects/C--shigsapps-windesktopmgr/memory/project_backlog.md`)
is the project's running record of what shipped. It only stays
trustworthy if **every** change updates it — a gap is how an entire
session's work goes unrecorded.

**On every change that merges to `main`:**

- **Planned feature** (has a numbered row in the `### Backlog` table) —
  annotate that row in place: prepend `✅ SHIPPED <date> (PR #NN)` plus a
  one-line result. Never delete the row.
- **Bug fix, tech-debt, or any unplanned change** — append one dated row
  to the `### Done` table:
  `| <date> | Bug Fix | <short title> (PR #NN) | <1-2 sentence summary> |`

There is no "if applicable" escape hatch — a bug fix is a change and gets
a row. This mirrors the architecture.html trigger rule: the record is
only worth keeping if it is never silently skipped. If a change genuinely
warrants no entry (e.g. a pure CLAUDE.md typo fix), mark Phase 9 `Backlog`
as ⏭️ Skipped with a one-line reason — never skip silently.

---

## Python First, PowerShell Secondary (MANDATORY)

Always prefer Python stdlib or pip packages over PowerShell/subprocess calls.
PowerShell is only acceptable when **no reasonable Python alternative exists**.

### Decision checklist — before writing `subprocess.run("powershell …")`

1. **Can Python do it?** — `os.scandir`, `psutil`, `wmi`, `winreg`, `ctypes`,
   `socket`, `platform`, `shutil.disk_usage`, `pathlib`, etc.
   → **Use Python.** Faster, testable, no PS startup cost.
2. **Is there a pip package?** — `wmi`, `pywin32`, `comtypes`, etc.
   → **Use the package** if it's already in `requirements.txt` or lightweight.
3. **Does it require a COM object, WMI class, or cmdlet with no Python binding?**
   → PowerShell is acceptable. Wrap it with the standard safety pattern
   (timeout, JSON output, fallback on error, input sanitisation).

### Why

| | Python | PowerShell |
|---|--------|-----------|
| **Startup** | 0 ms (in-process) | 200-500 ms (new process) |
| **Testability** | Mock stdlib, fast | Mock subprocess, fragile |
| **Error handling** | Try/except, typed | Parse stderr strings |
| **Parallelism** | ThreadPoolExecutor | RunspacePool (complex) |
| **Portability** | Cross-platform | Windows only |

### Examples of successful migrations

| Before (PowerShell) | After (Python) | Speedup |
|---------------------|---------------|---------|
| `robocopy /L` for disk analysis | `os.scandir()` + `ThreadPoolExecutor` | 6x |

---

## Quality Gates (MANDATORY)

Every code change — new feature, bug fix, or refactor — **must** pass all quality
gates before committing. No exceptions.

### 1. Tests with coverage

```bash
# Run tests with coverage (configured in pyproject.toml)
pytest tests/ -v               # serial, clearer output (~3m37s)
pytest tests/ -n auto          # parallel via xdist (~48s; pytest-cov merges per-worker)

# Coverage floor is 80% — builds fail below this
# Coverage report shows uncovered lines so you know what to test
```

### 2. Static analysis (ruff)

```bash
# Lint — catches dead code, undefined vars, security issues, hardcoded secrets
ruff check .

# Auto-fix safe issues
ruff check --fix .
```

### 3. Pre-commit hooks

Pre-commit runs ruff + pytest automatically on every `git commit`.
If either fails, the commit is blocked until the issue is fixed.

```bash
# Install hooks (one-time setup)
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

### 4. /code-review (added 2026-05-28)

After pytest passes and BEFORE committing, invoke the code-review skill
against the pending diff:

```
/code-review
```

(Plugin: `code-review@claude-plugins-official`, installed at user scope.)

The skill reads recently modified code with confidence-based filtering
and reports only high-priority issues — logic bugs, security
vulnerabilities, missed edge cases, broken patterns — that ruff and
pytest don't catch. Each finding MUST be either:

- **Resolved** in a follow-up commit on the same branch before merge, OR
- **Justified** inline (one-sentence reason in the commit body explaining
  why the finding is a false positive or an accepted trade-off).

NEVER merge a PR with unresolved + unjustified high-priority code-review
findings. The skill is the second pair of eyes that catches what pytest
green-checked through.

### 5. /code-simplifier (added 2026-05-28, OPTIONAL)

For refactor-heavy PRs (>200 LOC, dense new logic, or "tidy up the
surrounding code" intent), invoke after pytest passes:

```
/code-simplifier
```

(Plugin: `code-simplifier@claude-plugins-official`, installed at user
scope.)

The skill suggests clarity / consistency / maintainability improvements
WITHOUT changing functionality. Findings are SUGGESTIONS, not gates --
accept or reject per judgement. Accepted simplifications should be
documented in the commit body so the reviewer knows what changed and why.

Skip for small focused changes (<50 LOC, single function, bug fixes) --
the overhead-to-benefit ratio isn't there. Use for: new module / new
feature / cleanup PR / "this file got messy" follow-up.

### 6. What each tool catches

| Tool | Catches |
|------|---------|
| **pytest-cov** | Untested code paths, missing branch coverage |
| **ruff F** | Unused imports, undefined names, dead code |
| **ruff S** | Hardcoded passwords/secrets, injection risks |
| **ruff B** | Common bugs (mutable defaults, broad exceptions) |
| **ruff SIM** | Unnecessary complexity, duplicate code patterns |
| **ruff UP** | Python version upgrades (use modern syntax) |
| **/code-review** | Logic bugs, security gaps, edge cases, broken patterns ruff misses |
| **/code-simplifier** | Clarity / consistency / maintainability — suggestions, not gates |

---

## Testing Requirements (MANDATORY)

Every code change **must** include tests covering all new/modified branches.

---

### The Three Test Layers

#### 1. Flask Route Tests (`tests/test_routes.py`)
Every API endpoint needs tests for:
- `200 OK` with valid input
- Correct JSON structure in the response
- `400 / 422` for invalid or missing input
- `POST` endpoints reject missing required fields
- `DELETE` endpoints verify the right resource is removed

```python
# Example pattern
def test_endpoint_returns_200(self, client, mocker):
    mocker.patch("windesktopmgr.some_function", return_value={...})
    resp = client.get("/api/some/endpoint")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "expected_key" in data
```

#### 2. PowerShell / subprocess Tests (`tests/test_powershell.py`)
Every function that calls `subprocess.run` needs tests for:

| Scenario | What to assert |
|----------|---------------|
| **Happy path** | Realistic PS JSON output is parsed into the correct Python structure |
| **Single object** | PS returns `{}` instead of `[{}]` — must be normalised to a list |
| **Empty output** | `""` or `"  "` → safe fallback (empty list/dict, not an exception) |
| **Malformed JSON** | Garbage output → safe fallback (no `500`, no unhandled raise) |
| **Non-zero returncode** | `returncode=1` → error propagated in `{"ok": False, "error": ...}` |
| **Timeout** | `subprocess.TimeoutExpired` → safe fallback returned |
| **Command content** | The PS command string contains the required cmdlet / WMI class |
| **Input sanitisation** | User-supplied values injected into PS are sanitised (no injection) |

```python
# Example pattern
def test_function_happy_path(self, mocker):
    mock = mocker.patch("windesktopmgr.subprocess.run")
    mock.return_value.stdout = json.dumps([{...realistic data...}])
    mock.return_value.returncode = 0
    mock.return_value.stderr = ""
    result = wdm.some_function()
    assert result["key"] == expected_value

def test_function_timeout_returns_fallback(self, mocker):
    mocker.patch("windesktopmgr.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30))
    result = wdm.some_function()
    assert result == []   # or {} — whatever the safe fallback is
```

#### 3. Pure Python / Logic Tests (`tests/test_pure_functions.py`, `tests/test_summarizers.py`)
Every pure function and summarizer needs tests for:
- Normal input → expected output
- Edge cases (empty list, zero values, missing keys)
- Boundary conditions (thresholds, max/min values)
- All insight severity levels (`ok`, `info`, `warning`, `critical`)

```python
# Example pattern
def test_summarizer_critical_when_threshold_exceeded(self):
    data = {"some_value": 999}  # above threshold
    result = wdm.summarize_something(data)
    assert result["status"] == "critical"
    assert any(i["level"] == "critical" for i in result["insights"])
```

---

## Boundary Safety Rules (MANDATORY)

### Format Boundary Escaping
When user data crosses format boundaries, escape it:

| Source -> Target | Escaping method |
|-----------------|----------------|
| Python -> PowerShell | `re.sub(r"[^a-zA-Z0-9\-_. ]", "", value)` |
| Python -> XML/SOAP | `xml.sax.saxutils.escape(value)` |
| Python -> HTML | Jinja2 auto-escape or `markupsafe.escape()` |
| JS -> innerHTML | `esc(value)` shared helper |

### POST Route Validation Pattern
```python
data = request.get_json() or {}
name = data.get("name")
if not name:
    return jsonify({"ok": False, "error": "Missing required field: name"}), 400
```

### JavaScript Function Naming
Prefix all tab-specific functions with tab abbreviation to prevent global scope collisions:
`hn` = Home Network, `cred` = Credentials, `rem` = Remediation, `db` = Dashboard,
`drv` = Drivers, `bsod` = BSOD, `su` = Startup, `dk` = Disk, `net` = Network,
`upd` = Updates, `ev` = Events, `proc` = Processes, `th` = Thermals, `svc` = Services,
`hh` = Health History, `tl` = Timeline, `mem` = Memory, `bios` = BIOS, `si` = SysInfo.

---

## File Structure

```
tests/
├── conftest.py            # Shared fixtures — app, client, reset_globals, sample data
├── test_pure_functions.py # Pure Python helpers — no mocking needed
├── test_summarizers.py    # All summarize_*() functions
├── test_routes.py         # Flask API endpoints
└── test_powershell.py     # All subprocess.run / PowerShell call sites
```

---

## Fixtures — use these, don't re-invent them

| Fixture | What it gives you |
|---------|------------------|
| `client` | Flask test client (no real server) |
| `app` | The Flask app with `TESTING=True` |
| `reset_globals` | Auto-wipes all module-level caches before every test |
| `sample_crashes` | Two realistic BSOD crash dicts |
| `mock_subprocess_ok` | subprocess.run mocked to return `"[]"` with `returncode=0` |

---

## Installing test dependencies

```bash
pip install -r requirements-dev.txt

# One-time: install the Chromium binary for Playwright frontend smoke tests
python -m playwright install chromium
```

`requirements-dev.txt`:
```
pytest>=8.0
pytest-flask>=1.3
pytest-mock>=3.14
playwright>=1.47
pytest-playwright>=0.5
```

**Playwright frontend smoke tests (backlog #26)**
Opt-in suite that drives headless Chromium against a live server. Catches
JS regressions invisible to Python tests (missing handlers, console
errors, poll-accumulator leaks). Excluded from the default pytest run via
pyproject.toml's `-m "not integration and not playwright"`. To run:

```bash
# Make sure the tray (or dev server) is up on localhost:5000, then:
pytest -m playwright --no-cov

# Or wire into the verify gate:
PLAYWRIGHT_SMOKE=1 python dev.py verify
```

**Playwright MCP vs. pytest-playwright — division of labor (added 2026-05-28)**

The `playwright@claude-plugins-official` plugin registers Microsoft's
official Playwright MCP server (via `npx @playwright/mcp@latest`),
exposing `mcp__playwright__*` tools that let Claude drive a browser
interactively from a session. It is NOT a replacement for the pytest-
playwright suite. The two have orthogonal jobs:

| Need | Tool |
|------|------|
| Block bad code from merging | pytest-playwright (runs in CI / pre-push) |
| Parametrize over N inputs (e.g. 20 tabs in `TAB_IDS`) | pytest-playwright (`@pytest.mark.parametrize`) |
| Bisect "when did this start failing?" | pytest-playwright (git + pytest are deterministic) |
| Share fixtures with the rest of the test suite | pytest-playwright |
| Catch regressions when no human is watching | pytest-playwright |
| Pre-write exploration — find stable selectors before writing a test | Playwright MCP |
| Debug a failing pytest-playwright test interactively | Playwright MCP |
| One-off post-deploy "does this thing render?" smoke | Playwright MCP |
| Visual / layout / screenshot checks | Playwright MCP |

**Hard rule**: when you add a NEW user-visible feature, the regression
gate goes into `tests/test_playwright_smoke.py`. Drive the live tray
with the MCP plugin first if you want to explore the DOM before writing
the assertion -- but the asserted behaviour MUST land in the pytest
suite, not as a chat-driven manual check that disappears at session
end. The pytest-playwright suite has caught real bugs that an MCP-only
flow would have missed (PR #54 backup-tab visibility, PR #56 list-
editor persistence) because those bugs only surface on user actions
NOBODY was thinking to manually verify.

Use MCP for the "feels like" debugging that pytest assertions are bad
at (layout, color, animation timing). Use pytest-playwright for "is
this functional behavior still correct."

---

## Running tests

```bash
# All tests (serial — cleanest output, ~3m37s for 1,800+ tests)
pytest tests/ -v

# All tests in parallel (backlog #30, recommended for fast iteration)
# Distributes across CPU cores via pytest-xdist. ~48s on a 10-core box.
# Each worker is its own Python process so module globals + tmp_path
# files are per-worker isolated. Used by `python dev.py test` and the
# pre-commit pytest hook.
pytest tests/ -n auto

# Single file
pytest tests/test_powershell.py -v

# Single test class
pytest tests/test_powershell.py::TestGetDiskHealth -v

# Single test
pytest tests/test_powershell.py::TestGetDiskHealth::test_happy_path_returns_all_keys -v

# Stop on first failure
pytest tests/ -x

# Show print output (useful for debugging PS mock output)
pytest tests/ -v -s
```

**When `-n auto` is and isn't safe:**
- ✅ Default unit suite — every shared resource (history files, cache files,
  alert rules, baseline snapshots) is monkey-patched to `tmp_path`, which
  pytest-xdist isolates per worker. Module-level globals reset by the
  autouse `reset_globals` fixture are also per-process so workers don't
  step on each other.
- ❌ `-m integration` — real PowerShell / WMI / nvidia-smi / network probes.
  Rate limits, exclusive Windows resources, output ordering. Stays serial.
- ❌ `-m playwright` — drives a single live tray on `localhost:5000`. One
  browser, one server, can't fan out.

---

## Rules of thumb

- **Never** commit code that makes real PowerShell calls in tests
- **Always** mock `windesktopmgr.subprocess.run` — not `subprocess.run` globally
- **Always** test the fallback — if PS fails, the app must not crash
- **Always** include at least one command-content test per PS function to catch
  regressions in the actual PowerShell query being built
- **Keep tests fast** — all mocked, no I/O, no Windows dependency
- **One assert per concept** — clear failure messages beat multi-assert blobs

---

## Post-Push Live Verification (MANDATORY)

After every `git push`, run:

```bash
python dev.py verify
```

This command:
1. POSTs to `/api/restart` to restart the running tray instance
2. Polls `/api/health` until the new instance responds (45s budget)
3. Runs `/api/selftest` — 14 real PowerShell-backed health checks in parallel
4. Any failure means the push broke something mocked tests didn't catch

**What verify catches that mocked tests cannot:**
- PowerShell output format drift (real system output differs from mocks)
- File path regressions (e.g., hardcoded paths that don't exist on this machine)
- Startup crashes (missing import, syntax error only triggered at runtime)
- External service changes (NVIDIA API, router firmware, WMI schema)
- Dependency issues (missing package, wrong version)

---

## SOP Compliance Report — Phase 11 (MANDATORY)

At the end of **every** code change, print this checklist as the LAST thing in
the response. Mark each step: ✅ Done, ⏭️ Skipped (reason), or ❌ Not done (reason).

```
SOP Compliance Report — <short description of change>
──────────────────────────────────────────────────────
Phase 1  Planning
  [ ] Checked backlog
  [ ] Scoped work
  [ ] Identified affected files
Phase 2  Git Workflow
  [ ] Pulled latest main
  [ ] Small logical commits
  [ ] Pushed to remote
Phase 3  Coding Standards
  [ ] Python first, PowerShell secondary
  [ ] Boundary safety (escaping, validation)
  [ ] Graceful fallbacks for external calls
Phase 4  Quality Gates
  [ ] ruff check + format
  [ ] pytest (all pass, ≥80% coverage)
  [ ] /code-review (high-priority findings resolved or justified)
  [ ] pre-commit hooks passed
  [ ] python dev.py verify (post-restart live check)
Phase 5  Tests
  [ ] New/modified code has test coverage
Phase 9  Documentation
  [ ] Backlog updated — dated Done row or ✅ SHIPPED annotation (not optional)
  [ ] architecture.html updated (if applicable)
Phase 10 Post-Incident (bug fixes only)
  [ ] Root cause + gap type documented
  [ ] Regression test added
  [ ] Prevention: line in commit message
Summary: X done, Y skipped, Z not done
Commit(s): <hashes>
```

**Rules:**
- This checklist MUST be printed — it is not optional
- Never silently skip a step — always mark and explain
- ❌ Not done without justification means the change is incomplete
- For the full SOP details, see `feedback_github_sop.md` in project memory
