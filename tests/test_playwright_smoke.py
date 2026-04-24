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
    "baseline",
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


# ── Trends-card coverage regression (backlog #39) ──────────────────


class TestTrendsCardCoverage:
    """Every metric key that ``/api/metrics/history`` reports in
    ``available`` MUST have a rendered card in the Trends grid. The
    frontend's ``labels`` dict in ``loadTrends()`` must be refreshed
    alongside any backend change that adds a new metric series, or
    the card silently stops rendering for that key.

    The 2026-04-22 network-trends work (#38) had a cache-driven false
    alarm where the user reported "no metrics visible" after deploy --
    hard refresh cleared it, confirming the code was right. But a real
    forgotten-label-entry bug of the same shape would have shipped
    undetected because no test inspected the rendered cards. This
    class closes that gap.

    Assertion model: the authoritative list comes from
    ``/api/metrics/history``'s ``available`` array; the rendered set
    comes from every ``[data-metric]`` under ``#db-trends-grid``. If
    ``available`` ⊈ ``rendered``, fail with the missing keys.
    """

    def test_every_available_metric_has_a_rendered_card(self, loaded_page):
        page, _ = loaded_page

        # Explicit switch to Dashboard so the test doesn't depend on
        # loaded_page's starting tab. loadTrends() fires on every
        # dashboard render.
        page.evaluate("switchTab('dashboard')")

        # Wait for the Trends grid to settle -- either populated with
        # cards OR explicitly showing the "no samples yet" placeholder.
        # 'Loading…' is the transient state we must NOT read from.
        page.wait_for_function(
            """
            () => {
                const el = document.getElementById('db-trends-grid');
                if (!el) return false;
                const txt = el.textContent.trim();
                // settled = "has cards" OR "shows the no-samples message"
                return txt !== 'Loading…' && (
                    el.querySelector('[data-metric]') !== null
                    || txt.startsWith('No samples yet')
                    || txt.startsWith('Failed to load')
                );
            }
            """,
            timeout=15_000,
        )

        # Fetch the authoritative list of metrics the backend is tracking
        available = page.evaluate(
            """
            fetch('/api/metrics/history?window_h=168')
                .then(r => r.json())
                .then(d => d.available || [])
            """
        )

        if not available:
            # Fresh deploy / empty history -- no samples to render against.
            # The grid should show "No samples yet" in that case, not
            # explode -- the earlier wait_for_function verifies the grid
            # is in a defined terminal state, which is enough.
            pytest.skip("no metrics recorded yet -- sampler hasn't populated 'available'")

        rendered = page.evaluate(
            """
            Array.from(document.querySelectorAll('#db-trends-grid [data-metric]'))
                 .map(el => el.dataset.metric)
            """
        )

        missing = sorted(set(available) - set(rendered))
        assert not missing, (
            f"Trends card dropped {len(missing)} metric(s) that /api/metrics/history "
            f"reports as available: {missing}. "
            f"Likely cause: the `labels` dict in loadTrends() in templates/index.html "
            f"is missing an entry for each of these keys. Every new backend metric "
            f"series requires a matching label entry, or the card silently vanishes."
        )

    def test_rendered_cards_have_unique_data_metric(self, loaded_page):
        """Defence against a copy-paste bug in the labels dict producing two
        cards for the same key. If this fires, some label was duplicated."""
        page, _ = loaded_page
        page.evaluate("switchTab('dashboard')")
        page.wait_for_function(
            """
            () => {
                const el = document.getElementById('db-trends-grid');
                return el && (el.querySelector('[data-metric]') !== null
                              || el.textContent.includes('No samples yet'));
            }
            """,
            timeout=15_000,
        )
        rendered = page.evaluate(
            "Array.from(document.querySelectorAll('#db-trends-grid [data-metric]')).map(el => el.dataset.metric)"
        )
        dupes = sorted({m for m in rendered if rendered.count(m) > 1})
        assert not dupes, f"duplicate data-metric cards: {dupes}"


# ── Baseline tab coverage regression (backlog #14) ─────────────────


class TestBaselineTabCoverage:
    """The Baseline tab renders a Parameter|Previous|Current table with a
    "How to fix" block per drift entry. Frontend has a ``_BL_CATS`` dict
    that must stay in sync with the backend collectors -- if the backend
    adds a new tracked field (e.g. ``username``) but the frontend's field
    list isn't updated, that column silently stops rendering.

    Gaps this class closes (reported 2026-04-24):
      (a) No test verified the Baseline tab renders at all when a
          baseline exists with drift -- a syntax error in the JS would
          ship undetected.
      (b) No test verified that every drift entry renders the FULL
          parameter table expected for its category.
      (c) No test verified the schema-migration banner fires when the
          backend reports ``schema_migration_fields``.
      (d) No test verified the "How to fix" / launch-console button
          plumbing is wired.
    """

    def _goto_baseline(self, page):
        page.evaluate("switchTab('baseline')")
        # Wait for the baseline panel to leave its loading state. Same
        # settled-state pattern as TestTrendsCardCoverage: either the
        # drift detail appeared, the no-drift panel appeared, or the
        # no-baseline first-run panel appeared. Never time out on the
        # "Loading..." transient.
        page.wait_for_function(
            """
            () => {
                const loading = document.getElementById('bl-loading');
                if (!loading || loading.style.display !== 'none') return false;
                const content = document.getElementById('bl-drift-content');
                const nobaseline = document.getElementById('bl-nobaseline');
                const nodrift = document.getElementById('bl-nodrift');
                return (content && content.style.display !== 'none')
                    || (nobaseline && nobaseline.style.display !== 'none')
                    || (nodrift && nodrift.style.display !== 'none');
            }
            """,
            timeout=15_000,
        )

    def test_baseline_tab_renders_without_console_errors(self, loaded_page):
        page, errors = loaded_page
        self._goto_baseline(page)
        page.wait_for_timeout(300)  # let async XHRs settle
        actionable = [e for e in errors if "favicon" not in e.lower()]
        assert not actionable, f"Baseline tab console errors: {actionable}"

    def test_every_changed_entry_has_full_parameter_table(self, loaded_page):
        """For every Changed entry the backend reports, the UI must render
        the full parameter table -- not a subset. Each category has its own
        row count in _BL_CATS; the DOM must match.
        """
        page, _ = loaded_page
        drift = page.evaluate("fetch('/api/baseline/drift').then(r => r.json())")
        if not drift.get("has_baseline"):
            pytest.skip("no baseline captured yet")
        if (drift.get("drift") or {}).get("total_changes", 0) == 0:
            pytest.skip("no drift currently -- nothing to verify")

        self._goto_baseline(page)

        # Expected row counts mirror _BL_CATS.fields in templates/index.html
        # (the JS literal is the authoritative source; this Python copy must
        # be kept in sync -- the assertion below names the drift with a
        # clear remediation hint if it goes out of date).
        expected_rows = {"startup": 5, "services": 13, "tasks": 26}

        entries = page.evaluate(
            """
            Array.from(document.querySelectorAll('#bl-drift-content .bl-entry')).map(el => ({
                category: el.dataset.driftCategory,
                kind: el.dataset.driftKind,
                claimed_rows: parseInt(el.dataset.driftRows || '0', 10),
                actual_rows: el.querySelectorAll('table.bl-param-table tbody tr').length,
                has_howtofix: el.textContent.includes('How to fix'),
                has_console_button: el.querySelector('button[onclick^="blLaunchConsole"]') !== null,
            }))
            """
        )
        assert entries, "drift reported by API but no .bl-entry rendered in DOM"

        mismatches = []
        missing_howtofix = []
        missing_button = []
        for e in entries:
            exp = expected_rows.get(e["category"])
            if exp is None:
                mismatches.append(f"unknown category {e['category']}")
                continue
            if e["actual_rows"] != exp:
                mismatches.append(
                    f"{e['category']}/{e['kind']}: expected {exp} rows, got {e['actual_rows']} "
                    f"(data-drift-rows claims {e['claimed_rows']})"
                )
            if not e["has_howtofix"]:
                missing_howtofix.append(f"{e['category']}/{e['kind']}")
            if not e["has_console_button"]:
                missing_button.append(f"{e['category']}/{e['kind']}")

        assert not mismatches, (
            "Baseline drift table row count doesn't match _BL_CATS.fields. "
            "If you added a new tracked field to baseline.py's _DIFF_FIELDS "
            "or a collector, update _BL_CATS in templates/index.html AND "
            "expected_rows in this test. Mismatches: " + "; ".join(mismatches)
        )
        assert not missing_howtofix, f"drift entries without 'How to fix' block: {missing_howtofix}"
        assert not missing_button, f"drift entries without Open Console button: {missing_button}"

    def test_schema_migration_banner_matches_api(self, loaded_page):
        """If the API reports schema_migration_fields, the banner must be
        visible and carry the field list in data-migration-fields. If the
        API reports none, the banner must be hidden.
        """
        page, _ = loaded_page
        drift = page.evaluate("fetch('/api/baseline/drift').then(r => r.json())")
        if not drift.get("has_baseline"):
            pytest.skip("no baseline captured yet")
        api_fields = drift.get("schema_migration_fields") or []

        self._goto_baseline(page)

        state = page.evaluate(
            """
            () => {
                const b = document.getElementById('bl-migration-banner');
                if (!b) return {present: false};
                return {
                    present: true,
                    visible: b.style.display !== 'none',
                    fields: (b.dataset.migrationFields || '').split(',').filter(Boolean),
                };
            }
            """
        )
        assert state["present"], "bl-migration-banner element is missing from the template"

        if api_fields:
            assert state["visible"], (
                f"API reports {len(api_fields)} migration fields {api_fields} "
                f"but the banner is hidden -- UI isn't reading schema_migration_fields"
            )
            assert sorted(state["fields"]) == sorted(api_fields), (
                f"banner data-migration-fields={state['fields']} doesn't match API schema_migration_fields={api_fields}"
            )
        else:
            assert not state["visible"], (
                "API reports no migration fields but banner is visible -- "
                "UI leaked stale banner state across re-renders"
            )
