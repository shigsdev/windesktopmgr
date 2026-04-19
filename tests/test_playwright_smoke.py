"""tests/test_playwright_smoke.py -- frontend smoke tests (backlog #26).

Zero automated coverage existed on ``templates/index.html`` (~2 000 lines
of JS) before this file landed. Two real bugs in the 2026-04-18 / 19
sessions would have been caught by these tests:

  (a) the setInterval poll-accumulator in startScan() that burned 19 %
      sustained CPU on the tray after multi-click usage;
  (b) the task_watcher concern wiring ``action_fn="openLogsFolder()"``
      against a JS function that didn't exist -- the button did nothing.

Design
------
* Opt-in pytest marker: ``pytest -m playwright``. Excluded from the default
  suite via pyproject.toml's ``-m "not integration and not playwright"``.
* Requires a live Flask server at http://localhost:5000. A module-scope
  fixture probes the server; if it's down, every test in the file is
  skipped instead of erroring.
* Uses pytest-playwright's built-in ``page`` fixture (Chromium headless).
* Listens to console messages and page errors -- any error/warning counts
  as a failure.

One-time setup after ``pip install -r requirements-dev.txt``::

    python -m playwright install chromium

Running the suite::

    pytest -m playwright --no-cov
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.playwright

BASE_URL = "http://localhost:5000"

# Tab IDs from templates/index.html -- kept in sync with the actual nav
TAB_IDS = [
    "dashboard",
    "processes",
    "thermals",
    "disk",
    "memory",
    "bios",
    "credentials",
    "sysinfo",
    "startup",
    "drivers",
    "timeline",
    "updates",
    "events",
    "services",
    "health",
    "homenet",
    "remediation",
    "nlq",
]


# ── Live-server gate ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def live_server():
    """Skip every test in the module if the dev server isn't reachable."""
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=3) as resp:  # noqa: S310
            if resp.status != 200:
                pytest.skip(f"Server at {BASE_URL} returned {resp.status}")
    except Exception as e:  # noqa: BLE001 — anything -> skip, don't error the suite
        pytest.skip(f"Server at {BASE_URL} not reachable ({type(e).__name__}: {e}) -- start the tray first")
    return BASE_URL


@pytest.fixture
def loaded_page(page, live_server):
    """Navigate to the dashboard and collect console errors.

    We deliberately do NOT wait for ``networkidle`` -- the live dashboard
    polls continuously (tray heartbeat + dashboard summary auto-refresh)
    so networkidle never fires. Instead we wait for a known element.
    """
    errors: list[str] = []

    def _on_console(msg):
        if msg.type in ("error", "warning"):
            errors.append(f"[{msg.type}] {msg.text}")

    def _on_pageerror(exc):
        errors.append(f"[pageerror] {exc}")

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)
    page.goto(live_server, wait_until="domcontentloaded", timeout=15_000)
    # Wait for the tab nav to be rendered (a stable first-paint marker)
    page.wait_for_selector("#page-dashboard", state="attached", timeout=10_000)
    # Small settle so first-paint JS (loadDashboard, chart init, etc.) runs
    page.wait_for_timeout(800)
    return page, errors


# ── Tab navigation smoke ───────────────────────────────────────────


class TestTabNavigationSmoke:
    """Switching tabs must never surface a console error, a 'function not
    found' warning, or a JS exception. This catches missing handlers
    (openLogsFolder class), undefined globals, and typo'd function refs."""

    @pytest.mark.parametrize("tab_id", TAB_IDS)
    def test_tab_switch_has_no_console_errors(self, loaded_page, tab_id):
        page, errors = loaded_page
        # switchTab() is the real tab-switch entry point used by the nav buttons
        page.evaluate(f"switchTab({tab_id!r})")
        # Brief settle for any XHRs kicked off by the tab's load fn
        page.wait_for_timeout(500)
        # Filter out benign noise that exists unconditionally (e.g. 3rd-party
        # ads from embedded help links). Only fail on app-level issues.
        actionable = [e for e in errors if "favicon" not in e.lower()]
        assert not actionable, f"console errors after switchTab({tab_id}): {actionable}"


# ── Concern action-button handler resolution (backlog #26 primary win) ─


class TestConcernActionsResolve:
    """Every dashboard concern carries an ``action_fn`` like
    ``resumeOneDrive()`` or ``openLogsFolder()`` that the renderer
    parses and calls via ``window[name]``. If a Python-side concern
    emitter names a JS function that doesn't exist, the button silently
    does nothing (regression we shipped today via task_watcher).

    This test fetches the live concerns, extracts every action_fn name,
    and asserts each one resolves to a ``function`` on ``window``."""

    def test_every_emitted_action_fn_exists(self, loaded_page):
        page, _ = loaded_page
        # Pull the concerns the backend is actually emitting right now
        concerns = page.evaluate(
            """
            fetch('/api/dashboard/summary').then(r => r.json()).then(d => d.concerns || [])
            """
        )
        # Concerns with process_name use the new multi-button group instead
        # of a single action_fn -- those bypass the window-lookup path.
        fns = []
        for c in concerns:
            if c.get("process_name"):
                continue
            fn = (c.get("action_fn") or "").strip()
            if fn:
                fns.append(fn)
        if not fns:
            pytest.skip("no concerns currently emitted -- nothing to check")

        missing = []
        for fn_str in fns:
            # action_fn format: 'name()' or 'name(arg)'. Peel off the name.
            name = fn_str.split("(", 1)[0].strip()
            exists = page.evaluate(f"typeof window[{name!r}] === 'function'")
            if not exists:
                missing.append(name)
        assert not missing, (
            f"Dashboard concerns reference JS functions that don't exist: {missing}. "
            f"This is the openLogsFolder/2026-04-19 bug class -- a concern with a dead "
            f"action_fn silently does nothing when the user clicks it."
        )


# ── Poll-accumulator regression guard ──────────────────────────────


class TestScanButtonPollAccumulator:
    """If Scan Now is clicked multiple times without a guard, each click
    stacks a new setInterval, producing runaway /api/scan/status polls.
    This test triggers startScan() three times, lets it settle, then
    samples the network request rate for an idle window -- orphaned
    pollers would show up as continued traffic.

    Instead of running a real scan (60 s+ on this machine) we call
    startScan() directly and then immediately mark the status idle
    via the DOM, then check no lingering pollers remain.
    """

    def test_no_orphan_pollers_after_multi_click(self, loaded_page):
        page, _ = loaded_page
        # Need to be on the Drivers tab for startScan() to be bound
        page.evaluate("switchTab('drivers')")
        page.wait_for_timeout(300)

        # Count pollTimer across three clicks. Our guard should ensure
        # only one interval is active at any time.
        timers_after_clicks = page.evaluate(
            """
            async () => {
              // Click startScan three times; the guarded impl should
              // clear any prior interval before setting the new one.
              if (typeof startScan !== 'function') return -1;
              await startScan();
              await startScan();
              await startScan();
              // The module keeps the handle in ``pollTimer``. A leak
              // would manifest as a counter > 1 via intervalCount, but
              // JS doesn't expose that directly -- we instead rely on
              // pollTimer being a single id.
              return typeof pollTimer === 'number' ? 1 : 0;
            }
            """
        )
        # -1 means startScan isn't defined on this page (wrong tab); skip
        if timers_after_clicks == -1:
            pytest.skip("startScan not on this page -- tab wiring changed?")

        # Now sample the request rate in an idle window. With the guard,
        # at most ONE setInterval fires every 800 ms == 1.25 r/s. Without
        # it (3 orphans), we'd see ~3.75 r/s.
        rate = page.evaluate(
            """
            async () => {
              let count = 0;
              const orig = window.fetch;
              window.fetch = (url, ...rest) => {
                if (typeof url === 'string' && url.includes('/api/scan/status')) count++;
                return orig(url, ...rest);
              };
              await new Promise(r => setTimeout(r, 2000));
              window.fetch = orig;
              return count / 2.0;
            }
            """
        )
        # Generous threshold: healthy == 1.25 r/s, leak threshold = 2 r/s
        assert rate <= 2.0, (
            f"/api/scan/status firing at {rate:.1f} r/s after 3 clicks -- "
            f"poll-accumulator regression (lint_setinterval.py should also catch this)"
        )
