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


# ── Network Topology Diagram (#9) ──────────────────────────────────


class TestNetworkTopologyDiagram:
    """Backlog #9. The topology section is collapsed by default; clicking
    "Show diagram" lazy-fetches /api/homenet/topology and renders an
    inline SVG. The tests verify (a) the toggle wiring exists, (b) the
    rendered SVG includes the router + at least one infrastructure box,
    and (c) the API payload shape stays in sync with what the renderer
    consumes.
    """

    def _goto_homenet_and_show_topology(self, page):
        page.evaluate("switchTab('homenet')")
        # Wait for the homenet panel to render the topology toggle button.
        page.wait_for_selector("#hn-topo-toggle", state="attached", timeout=10_000)
        page.evaluate("hnTopoToggle()")
        # Wait until the SVG wrap is populated OR an error message appears.
        page.wait_for_function(
            """
            () => {
                const wrap = document.getElementById('hn-topo-svg-wrap');
                const err = document.getElementById('hn-topo-error');
                if (wrap && wrap.style.display !== 'none' && wrap.innerHTML.length) return true;
                if (err && err.style.display !== 'none') return true;
                return false;
            }
            """,
            timeout=15_000,
        )

    def test_topology_section_renders_without_console_errors(self, loaded_page):
        page, errors = loaded_page
        self._goto_homenet_and_show_topology(page)
        page.wait_for_timeout(300)
        actionable = [e for e in errors if "favicon" not in e.lower()]
        assert not actionable, f"Topology section console errors: {actionable}"

    def test_topology_payload_has_renderer_required_keys(self, loaded_page):
        """Drift-detect: the JS renderer reads router/switches/aps/devices
        /unmapped/stats. If the backend ever changes the shape, fail loud."""
        page, _ = loaded_page
        data = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        assert data.get("ok") is True, f"topology API not ok: {data}"
        for key in ("router", "switches", "aps", "devices", "unmapped", "stats"):
            assert key in data, (
                f"/api/homenet/topology missing '{key}' -- the renderer in "
                f"templates/index.html (hnTopoBuildSvg) reads this. If the "
                f"backend dropped it, the diagram silently breaks."
            )
        for sub in ("total", "wired_mapped", "wireless_mapped", "unmapped", "switch_available"):
            assert sub in data["stats"], f"stats payload missing '{sub}' -- breaks the stats line above the SVG"

    def test_topology_svg_contains_router_label(self, loaded_page):
        """The SVG must always render the router box (top-tier anchor) --
        even when no devices are in inventory."""
        page, _ = loaded_page
        self._goto_homenet_and_show_topology(page)
        svg_text = page.evaluate("document.getElementById('hn-topo-svg-wrap').textContent || ''")
        assert "Verizon" in svg_text or "Router" in svg_text, (
            f"Router label not found in topology SVG -- expected 'Verizon' or 'Router' "
            f"in the rendered output. SVG content was: {svg_text[:200]!r}"
        )

    # ── Visual-correctness regressions surfaced 2026-04-25 ────────────
    # Three bugs the user spotted that the structural tests above missed:
    #   - active devices rendered with grey dots ("MoCA bridge looks
    #     greyed out") because the connector line fused visually with
    #     the dot.
    #   - 6 devices showed raw MAC addresses because the label fallback
    #     never tried vendor name + suffix.
    #   - device rows weren't clickable for editing (no way to name an
    #     unnamed device from the diagram).
    # Each new test below would fail loudly if any of these regressed.

    def test_active_devices_render_with_active_dot(self, loaded_page):
        """Device circles carry data-active="true|false". Every device
        the API reports as active=True MUST have data-active="true" on
        its rendered circle. Catches the 2026-04-25 "MoCA bridge looks
        greyed out" bug class."""
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        active_macs = {m for m, d in (topology.get("devices") or {}).items() if d.get("active") is not False}
        if not active_macs:
            pytest.skip("no active devices in inventory -- nothing to verify")

        self._goto_homenet_and_show_topology(page)

        # Pull every rendered device circle's data-active flag, keyed by MAC.
        rendered = page.evaluate(
            """
            Array.from(document.querySelectorAll('#hn-topo-svg-wrap g[data-device-mac]')).map(g => ({
                mac: g.dataset.deviceMac,
                circleActive: g.previousElementSibling && g.previousElementSibling.tagName === 'circle'
                    ? g.previousElementSibling.dataset.active : null,
            }))
            """
        )
        rendered_actives = {r["mac"]: r["circleActive"] for r in rendered if r["mac"]}
        # Pick one active device that's actually rendered and assert its dot is "true"
        sample = next((m for m in active_macs if m in rendered_actives), None)
        if sample is None:
            pytest.skip("no active device made it into the rendered diagram")
        assert rendered_actives[sample] == "true", (
            f"Active device {sample} rendered with data-active={rendered_actives[sample]!r}; "
            f"expected 'true'. The 'greyed out MoCA bridge' regression class."
        )

    def test_no_device_rows_render_as_raw_macs(self, loaded_page):
        """Every rendered device row text MUST start with something other
        than a raw MAC address pattern (XX:XX:XX:...). The label fallback
        chain (friendly_name -> hostname -> vendor + suffix -> MAC) should
        only hit raw-MAC for devices with literally zero context. Catches
        the 2026-04-25 'I see just MAC addresses' bug."""
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        # Devices that have a vendor but no hostname/friendly are the
        # exact case that previously fell through to raw MAC.
        candidates = [
            m
            for m, d in (topology.get("devices") or {}).items()
            if not d.get("friendly_name") and not d.get("hostname") and (d.get("vendor") or "").strip()
        ]
        if not candidates:
            pytest.skip("no candidates for the vendor-fallback path in current inventory")

        self._goto_homenet_and_show_topology(page)
        names = page.evaluate(
            """
            Array.from(document.querySelectorAll('#hn-topo-svg-wrap g[data-device-mac]')).map(g => ({
                mac: g.dataset.deviceMac,
                name: g.dataset.deviceName,
            }))
            """
        )
        rendered = {n["mac"]: n["name"] for n in names if n["mac"]}
        import re

        raw_mac_re = re.compile(r"^[0-9A-F]{2}([:-][0-9A-F]{2}){5}$", re.I)
        bad = [m for m in candidates if m in rendered and raw_mac_re.match(rendered[m] or "")]
        assert not bad, (
            f"{len(bad)} device(s) with a known vendor still render as raw MAC: {bad[:3]}. "
            f"The vendor + suffix fallback in _hnTopoLabel() in templates/index.html isn't firing."
        )

    def test_device_rows_are_click_to_edit(self, loaded_page):
        """Every device row should carry an onclick that opens the edit
        modal -- without this the user can't name unnamed devices from
        the diagram."""
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        if not topology.get("devices"):
            pytest.skip("no devices in inventory -- nothing to verify")

        self._goto_homenet_and_show_topology(page)
        clickable = page.evaluate(
            """
            Array.from(document.querySelectorAll('#hn-topo-svg-wrap g[data-device-mac]')).filter(
                g => (g.getAttribute('onclick') || '').includes('openEditModal')
            ).length
            """
        )
        rendered_count = page.evaluate("document.querySelectorAll('#hn-topo-svg-wrap g[data-device-mac]').length")
        assert clickable > 0, "no device rows have openEditModal handler"
        # Every rendered row should be clickable -- not just some
        assert clickable == rendered_count, (
            f"{rendered_count - clickable} of {rendered_count} device rows are NOT click-to-edit; "
            f"the openEditModal onclick is missing on those rows."
        )

    def test_save_device_edit_auto_refreshes_topology(self, loaded_page):
        """User feedback 2026-04-25: "if i manually move a device to the
        TP-link switch it should automatically appear under that and not
        wait for a refresh." After saveDeviceEdit() POSTs successfully,
        the topology must re-fetch and re-render automatically while
        it's visible -- the user shouldn't have to click ↻ themselves.

        Test approach: pick a real device from the live inventory, change
        its wired_via via saveDeviceEdit() through the JS path, then
        immediately read back the rendered SVG row count and assert the
        diagram reflects the new bucketing without an explicit refresh
        call. We restore the original wired_via at the end so the test
        leaves the live inventory clean.
        """
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        # Pick a wired device that's in verizon_lan (the default bucket)
        # and that we can safely flip to wired_via=switch then back.
        candidate_mac = next(
            (m for m in topology.get("verizon_lan") or [] if topology["devices"].get(m, {}).get("network") == "wired"),
            None,
        )
        if not candidate_mac:
            pytest.skip("no wired-LAN device available to flip in this test")
        original = topology["devices"][candidate_mac].get("wired_via", "") or ""

        self._goto_homenet_and_show_topology(page)

        # Confirm initial state: device IS in verizon-lan column
        initial_in_verizon = page.evaluate(
            f"""
            (() => {{
                const verizonCol = document.querySelector('#hn-topo-svg-wrap');
                const rows = Array.from(verizonCol.querySelectorAll('g[data-device-mac]'));
                return rows.some(r => r.dataset.deviceMac === '{candidate_mac}');
            }})()
            """
        )
        assert initial_in_verizon, f"sanity: {candidate_mac} should be rendered in the diagram pre-flip"

        # Flip via the SAME JS path the user takes (saveDeviceEdit), then
        # wait for the auto-refresh to land. Direct fetch + manual call to
        # saveDeviceEdit through the modal is brittle; instead simulate by
        # POSTing directly to the route then calling the auto-refresh hook
        # exactly as saveDeviceEdit does. If the wiring is correct, the
        # diagram updates without an explicit hnTopoRefresh() call from
        # the test.
        try:
            # Pre-load the modal state (mirrors openEditModal -> saveDeviceEdit)
            page.evaluate(
                f"""
                async () => {{
                    document.getElementById('hn-edit-mac').value = '{candidate_mac}';
                    document.getElementById('hn-edit-name').value = '';
                    document.getElementById('hn-edit-category').value = '';
                    document.getElementById('hn-edit-location').value = '';
                    document.getElementById('hn-edit-notes').value = '';
                    document.getElementById('hn-edit-wired-via').value = 'switch';
                    await saveDeviceEdit();
                }}
                """
            )
            # Wait for the topology to re-render with the new bucketing.
            # The switch-forced device should leave verizon_lan and appear
            # under the TP-Link switch column instead.
            page.wait_for_function(
                f"""
                () => {{
                    const wrap = document.getElementById('hn-topo-svg-wrap');
                    if (!wrap) return false;
                    const rows = Array.from(wrap.querySelectorAll('g[data-device-mac]'));
                    const row = rows.find(r => r.dataset.deviceMac === '{candidate_mac}');
                    if (!row) return false;
                    // Confirm it's now under the switch (label contains 'port')
                    return row.textContent.toLowerCase().includes('port');
                }}
                """,
                timeout=10_000,
            )
        finally:
            # Restore original wired_via so we don't leave the inventory dirty
            page.evaluate(
                f"""
                fetch('/api/homenet/device/update', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{mac: '{candidate_mac}', wired_via: '{original}'}})
                }})
                """
            )


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
        expected_rows = {"startup": 5, "services": 13, "tasks": 27}

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

    def test_inventory_row_click_recovers_from_cache_miss(self, loaded_page):
        """Bug 2026-04-25: clicking an inventory row after loadBaseline()
        ran would surface "Item data missing from cache" because the cache
        was nulled out by the reload while the rendered DOM rows still
        referenced it. Fix: blToggleInventoryRow re-fetches the snapshot
        on cache miss and retries.

        This test simulates the failure mode by:
          1. Open the Baseline tab + expand the inventory section
          2. Forcibly null the inventory cache (mimics what loadBaseline did)
          3. Click an inventory row
          4. Assert the detail panel renders the parameter table (not the
             "Item data missing" error message)
        """
        page, _ = loaded_page
        drift = page.evaluate("fetch('/api/baseline/drift').then(r => r.json())")
        if not drift.get("has_baseline"):
            pytest.skip("no baseline captured yet -- can't exercise inventory rows")

        # Switch to Baseline tab and wait for it to settle
        page.evaluate("switchTab('baseline')")
        page.wait_for_function(
            """
            () => {
                const loading = document.getElementById('bl-loading');
                if (!loading || loading.style.display !== 'none') return false;
                return !!document.getElementById('bl-inv-toggle');
            }
            """,
            timeout=15_000,
        )

        # Expand inventory + wait for at least one row to render
        page.evaluate("blToggleInventory()")
        page.wait_for_function(
            "() => document.querySelectorAll('#bl-inv-body .bl-inv-row').length > 0",
            timeout=15_000,
        )

        # Reproduce the bug: null the cache to simulate what loadBaseline did
        page.evaluate("_blInventoryCache = null; _blInventoryDrift = null;")

        # Click the first inventory row
        page.evaluate(
            """
            () => {
                const row = document.querySelector('#bl-inv-body .bl-inv-row > div');
                if (row) row.click();
            }
            """
        )

        # The detail panel should populate -- either via re-fetch (success
        # path) or fail gracefully with the "no longer present" message.
        # The OLD failure mode would leave the "Item data missing from
        # cache" string in the panel; that's the regression we're guarding
        # against. Wait up to 8s for the re-fetch to settle.
        page.wait_for_function(
            """
            () => {
                const detail = document.querySelector('#bl-inv-body .bl-inv-row > div + div[id^="blinv-"]');
                if (!detail) return false;
                if (detail.style.display === 'none') return false;
                const txt = detail.textContent || '';
                // Settled = anything OTHER than the loading or stuck-cache-miss states
                return !txt.includes('Refreshing inventory') && !txt.includes('Item data missing from cache');
            }
            """,
            timeout=10_000,
        )

        # Final assertion: the OLD error string must NOT be present anywhere
        # in the inventory body
        bad = page.evaluate(
            """
            (() => {
                const body = document.getElementById('bl-inv-body');
                return (body && body.textContent || '').includes('Item data missing from cache');
            })()
            """
        )
        assert not bad, (
            "Inventory row click after cache miss surfaced 'Item data missing from cache' -- "
            "the auto-recovery re-fetch in blToggleInventoryRow isn't firing."
        )


# ── investigateProcess: Memory tab → Processes tab handoff ────────


class TestInvestigateProcessFromMemoryTab:
    """User reported 2026-04-28: clicking 🔍 Investigate next to a process
    on the Memory tab dropped them on the Processes tab with an empty
    filtered table even though the process exists.

    Two bugs combined:
      (a) The filter in renderProcesses only matched Name + Description,
          but investigateProcess set the search box to the numeric PID.
          PID "28008" never matches Name "ServiceShell.exe" -> 0 rows.
      (b) Hardcoded 150ms timeout fired the filter before
          /api/processes/list returned -> filtered an empty array.
    Both fixes guard each other; this test catches a regression of either.
    """

    def test_investigate_process_lands_on_filtered_match(self, loaded_page):
        """End-to-end: trigger investigateProcess from the dashboard like
        the Memory-tab button does, and confirm the user lands on a
        Processes tab with the matching row visible.

        We share data with the tab's loadProcesses() rather than doing our
        own /api/processes/list call -- that endpoint takes ~12s on a busy
        box, and TWO sequential fetches blow past any reasonable test
        timeout. So: switch to processes, wait for _processData, pick a
        target FROM the already-loaded data, switch away, and re-trigger
        investigateProcess to exercise the timing-race recovery path.
        """
        page, _ = loaded_page

        # Pre-load the Processes tab so _processData is populated. This
        # is the slow step; everything after it is local-only.
        page.evaluate("switchTab('processes')")
        page.wait_for_function(
            "() => _processData && (_processData.processes || []).length > 0",
            timeout=60_000,
        )
        target = page.evaluate(
            """
            (() => {
                const procs = (_processData.processes || []);
                return procs.find(p => (p.Name || '').toLowerCase().endsWith('.exe')) || null;
            })()
            """
        )
        if not target:
            pytest.skip("no .exe processes available to test investigation")

        # Switch away from the Processes tab so investigateProcess has to
        # navigate back -- exercising the switchTab->setTimeout->filter path.
        page.evaluate("switchTab('memory')")
        page.wait_for_timeout(500)

        # Trigger investigateProcess via the same JS path the Memory tab uses
        page.evaluate(f"investigateProcess({int(target['PID'])}, {target['Name']!r})")

        # Wait for the search to be applied and rows to be visible. Since
        # _processData is already populated from earlier, this should be
        # near-instant -- we're really testing the filter-matches-PID and
        # the search-box wiring, not the data fetch.
        page.wait_for_function(
            """
            () => {
                const tbody = document.getElementById('pr-tbody');
                if (!tbody) return false;
                const rows = tbody.querySelectorAll('tr');
                if (!rows.length) return false;
                const first = rows[0].textContent || '';
                return !first.includes('No processes match');
            }
            """,
            timeout=15_000,
        )

        # Confirm at least one row references the PID OR the name.
        match_found = page.evaluate(
            f"""
            (() => {{
                const tbody = document.getElementById('pr-tbody');
                if (!tbody) return false;
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const target_pid = {int(target["PID"])};
                const target_name = {target["Name"]!r}.toLowerCase();
                return rows.some(r => {{
                    const text = (r.textContent || '').toLowerCase();
                    return text.includes(String(target_pid)) || text.includes(target_name);
                }});
            }})()
            """
        )
        assert match_found, (
            f"investigateProcess({target['PID']}, {target['Name']!r}) didn't surface a matching row. "
            "Either renderProcesses filter regressed (drop PID match) or the timing-race fix in "
            "investigateProcess was reverted (filter applied before _processData populated)."
        )

    def test_renderProcesses_filter_matches_pid(self, loaded_page):
        """Direct unit-style check: setting the search box to a PID must
        match a process whose PID equals that number. Catches a filter
        regression independently of the investigateProcess timing path."""
        page, _ = loaded_page
        page.evaluate("switchTab('processes')")
        # Wait for data
        page.wait_for_function(
            "() => _processData && (_processData.processes || []).length > 0",
            timeout=60_000,
        )
        # Pick any PID
        pid = page.evaluate("(_processData.processes || [])[0].PID")
        if not pid:
            pytest.skip("no processes in _processData")
        # Set search to that PID and re-render
        page.evaluate(
            f"""
            document.getElementById('pr-search').value = '{pid}';
            renderProcesses();
            """
        )
        page.wait_for_timeout(200)
        rows = page.evaluate("document.getElementById('pr-tbody').querySelectorAll('tr').length")
        # At least one match -- the process whose PID we just searched for
        assert rows >= 1, f"PID search '{pid}' returned 0 rows -- filter doesn't accept PIDs"


# ── Trends drill-down modal regression (2026-04-28) ───────────────


class TestTrendsDrilldownModal:
    """User feature 2026-04-28: clicking a Trends sparkline card opens a
    full-size Chart.js drill-down with summary stats + time-axis + recent
    samples. Tests guard against:
      - Card no longer being clickable (onclick stripped)
      - Modal element missing or not opening
      - Chart canvas + Chart.js instance not constructed
      - Stats block missing one of the 8 expected metrics
      - Escape-to-close handler regressing
    """

    def _wait_for_trends_loaded(self, page):
        # loadTrends fires from loadDashboard which is the default tab.
        # Wait until at least one [data-metric] card is rendered.
        page.wait_for_function(
            "() => document.querySelectorAll('#db-trends-grid [data-metric]').length > 0",
            timeout=30_000,
        )

    def test_drilldown_modal_opens_on_card_click(self, loaded_page):
        page, _ = loaded_page
        self._wait_for_trends_loaded(page)
        # Click the first Trends card directly (its onclick attr fires
        # openTrendDrilldown). Real-user click path.
        page.evaluate("document.querySelectorAll('#db-trends-grid [data-metric]')[0].click()")
        page.wait_for_function(
            "() => document.getElementById('db-trends-modal').style.display === 'flex'",
            timeout=10_000,
        )
        # Confirm modal contents render: title + ≥4 stat blocks + chart canvas
        state = page.evaluate(
            """
            (() => ({
                title: document.getElementById('db-trends-modal-title').textContent,
                stat_blocks: document.getElementById('db-trends-modal-stats').children.length,
                chart_canvas: !!document.getElementById('db-trends-modal-chart'),
                chart_instance: typeof _trendsModalChart !== 'undefined' && _trendsModalChart !== null,
            }))()
            """
        )
        assert state["title"], "modal title is empty -- _trendsLabels lookup or DOM wiring broke"
        assert state["stat_blocks"] >= 4, f"expected ≥4 stat blocks (Now/Min/Max/Avg etc.), got {state['stat_blocks']}"
        assert state["chart_canvas"], "modal canvas element missing"
        assert state["chart_instance"], "Chart.js instance not constructed -- check date-fns adapter"

    def test_drilldown_modal_closes_on_escape(self, loaded_page):
        page, _ = loaded_page
        self._wait_for_trends_loaded(page)
        page.evaluate("openTrendDrilldown('cpu_percent')")
        page.wait_for_function(
            "() => document.getElementById('db-trends-modal').style.display === 'flex'",
            timeout=5_000,
        )
        page.keyboard.press("Escape")
        page.wait_for_function(
            "() => document.getElementById('db-trends-modal').style.display === 'none'",
            timeout=2_000,
        )

    def test_drilldown_window_buttons_re_render(self, loaded_page):
        """Clicking a different window-size button re-renders the chart
        with new data. Verify by capturing the chart's data.length before
        and after."""
        page, _ = loaded_page
        self._wait_for_trends_loaded(page)
        page.evaluate("openTrendDrilldown('cpu_percent')")
        page.wait_for_function(
            "() => typeof _trendsModalChart !== 'undefined' && _trendsModalChart !== null",
            timeout=10_000,
        )
        before = page.evaluate("(_trendsModalChart && _trendsModalChart.data.datasets[0].data.length) || 0")
        # Switch to the 24h window -- usually has fewer points than the 7d default
        page.evaluate("setTrendsModalWindow(24)")
        page.wait_for_timeout(800)  # let re-render settle
        after = page.evaluate("(_trendsModalChart && _trendsModalChart.data.datasets[0].data.length) || 0")
        # 24h should have <= 7d (in most environments fewer; in extreme edge
        # case where the user only has 24h of history they could match)
        assert after <= before, (
            f"24h window has {after} points, 7d had {before} -- the window button "
            "didn't re-fetch / didn't apply the cutoff filter"
        )

    def test_every_data_metric_card_has_onclick(self, loaded_page):
        """Defence against accidentally rendering a card without the
        onclick attribute -- which would make it appear interactive
        (cursor:pointer) but do nothing on click."""
        page, _ = loaded_page
        self._wait_for_trends_loaded(page)
        result = page.evaluate(
            """
            (() => {
                const cards = Array.from(document.querySelectorAll('#db-trends-grid [data-metric]'));
                const total = cards.length;
                const withClick = cards.filter(c => (c.getAttribute('onclick') || '').includes('openTrendDrilldown')).length;
                return {total, withClick};
            })()
            """
        )
        assert result["total"] > 0, "no Trends cards rendered"
        assert result["withClick"] == result["total"], (
            f"{result['total'] - result['withClick']} of {result['total']} Trends cards "
            "are missing the openTrendDrilldown onclick handler"
        )
