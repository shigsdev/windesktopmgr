# WinDesktopMgr — Claude Code Guidelines

## Quality Gates (MANDATORY)

Every code change — new feature, bug fix, or refactor — **must** pass all quality
gates before committing. No exceptions.

### 1. Tests with coverage

```bash
# Run tests with coverage (configured in pyproject.toml)
pytest tests/ -v

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

### 4. What each tool catches

| Tool | Catches |
|------|---------|
| **pytest-cov** | Untested code paths, missing branch coverage |
| **ruff F** | Unused imports, undefined names, dead code |
| **ruff S** | Hardcoded passwords/secrets, injection risks |
| **ruff B** | Common bugs (mutable defaults, broad exceptions) |
| **ruff SIM** | Unnecessary complexity, duplicate code patterns |
| **ruff UP** | Python version upgrades (use modern syntax) |

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
```

`requirements-dev.txt`:
```
pytest>=8.0
pytest-flask>=1.3
pytest-mock>=3.14
```

---

## Running tests

```bash
# All tests
pytest tests/ -v

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

---

## Rules of thumb

- **Never** commit code that makes real PowerShell calls in tests
- **Always** mock `windesktopmgr.subprocess.run` — not `subprocess.run` globally
- **Always** test the fallback — if PS fails, the app must not crash
- **Always** include at least one command-content test per PS function to catch
  regressions in the actual PowerShell query being built
- **Keep tests fast** — all mocked, no I/O, no Windows dependency
- **One assert per concept** — clear failure messages beat multi-assert blobs
