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

# Tab IDs from templates/index.html -- kept in sync with the actual nav.
# Adding a new tab? Add it here too so the parametrised smoke + the
# new-in-2026-05-25 visibility-after-switch test cover it.
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
    "backup",
    "utilities",
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

    @pytest.mark.parametrize("tab_id", TAB_IDS)
    def test_tab_switch_makes_target_page_visible(self, loaded_page, tab_id):
        """Added 2026-05-25 after the Backup-tab empty-viewport bug.

        Console-error-free wasn't enough -- the old switchTab had a
        hardcoded array of page IDs that the show/hide loop iterated.
        When the Backup tab landed (and "backup" wasn't in the array)
        clicking it ran loadBackup() cleanly but never UN-HID
        ``#page-backup``, leaving an empty viewport with zero JS errors.

        This test asserts the postcondition the show/hide loop is
        supposed to maintain: after ``switchTab(X)``, the
        ``#page-X`` div has a non-"none" display value AND every
        other ``#page-*`` div is hidden.
        """
        page, _errors = loaded_page
        page.evaluate(f"switchTab({tab_id!r})")
        page.wait_for_timeout(300)

        # Skip tabs whose page-X id intentionally doesn't exist (e.g.
        # NLQ uses a different DOM convention). The test gates on the
        # element being present in the page first.
        target_present = page.evaluate(f"!!document.getElementById('page-{tab_id}')")
        if not target_present:
            pytest.skip(f"no #page-{tab_id} div (tab uses different DOM)")

        target_display = page.evaluate(f"document.getElementById('page-{tab_id}').style.display")
        assert target_display != "none", (
            f"#page-{tab_id} is still display:none after switchTab({tab_id!r}) -- "
            f"the show/hide loop likely missed this tab id"
        )

        # Also verify ALL OTHER page-* divs are hidden. Catches the
        # opposite bug: "I switched to Backup but Dashboard is also
        # still visible".  Note: arrow functions don't have their own
        # `arguments` object, so we pass the target id via Playwright's
        # evaluate(fn, arg) parameter convention.
        visible_others = page.evaluate(
            """(targetId) => {
                return Array.from(document.querySelectorAll('[id^="page-"]'))
                    .filter(el => el.id !== 'page-' + targetId && el.style.display !== 'none')
                    .map(el => el.id);
            }""",
            tab_id,
        )
        assert visible_others == [], (
            f"after switchTab({tab_id!r}) these other pages were ALSO visible: {visible_others}"
        )


# ── Left instrument-rail navigation (redesign PR3) ─────────────────
#
# The top two-row tab bar was replaced by a fixed vertical rail. Items keep
# the .page-tab class + data-page value, so the parametrised switchTab smoke
# above (which drives switchTab directly) already covers show/hide for every
# tab. These guard the rail STRUCTURE and that CLICKING a rail item -- the
# user's real interaction, exercising the click handler not switchTab -- still
# navigates.


class TestLeftRailNav:
    def test_rail_renders_with_grouped_tabs(self, loaded_page):
        page, _ = loaded_page
        assert page.evaluate("!!document.querySelector('.rail')"), "left rail (.rail) not rendered"
        assert page.evaluate("!!document.querySelector('.rail-group')"), "rail group headings not rendered"
        pages = page.evaluate("Array.from(document.querySelectorAll('.rail .page-tab')).map(b => b.dataset.page)")
        assert len(pages) >= 20, f"expected the full tab set in the rail, got {len(pages)}: {pages}"
        # Spot-check a tab from each of the three groups survived the move.
        for key in ("dashboard", "thermals", "drivers", "baseline", "homenet", "architecture"):
            assert key in pages, f"rail missing nav item data-page={key!r}"

    def test_clicking_rail_item_navigates(self, loaded_page):
        """Clicking a rail button (not calling switchTab directly) must still
        activate it and show its page -- proves the click handler is wired to
        the new rail markup."""
        page, _ = loaded_page
        page.click(".rail .page-tab[data-page='architecture']")
        page.wait_for_timeout(400)
        active = page.evaluate("document.querySelector('.page-tab.active')?.dataset.page")
        assert active == "architecture", f"rail click didn't activate the item (active={active!r})"
        disp = page.evaluate("document.getElementById('page-architecture').style.display")
        assert disp != "none", "clicking the rail item didn't reveal #page-architecture"


# ── Backup tab Section 3 — exclusion-list editor persistence ──────
#
# Bug history: PR-1 of #46 wired the + button to call cc_addItem +
# cc_saveRules but the symmetric × button only called cc_removeItem.
# User clicked × to delete a rule, list visually updated, refreshed
# the page, and the deleted rule was back. Added 2026-05-25.


class TestCloudCopyListEditorPersists:
    """Section 3 exclusion-list editors -- both + and × must round-trip
    to the server. Visual update alone isn't enough; the rules file
    must reflect the change on the next page load."""

    def _open_backup_tab(self, page):
        page.evaluate("switchTab('backup')")
        # Give loadCloudCopy time to fetch + render.
        for _ in range(20):
            page.wait_for_timeout(300)
            ready = page.evaluate(
                "typeof _ccRules === 'object' && _ccRules !== null && Array.isArray(_ccRules.exclude_folders)"
            )
            if ready:
                break

    def _server_folders(self, page):
        return page.evaluate(
            """async () => {
                const r = await fetch('/api/cloudcopy/rules');
                const d = await r.json();
                return d.rules.exclude_folders;
            }"""
        )

    def test_add_via_plus_button_persists_to_server(self, loaded_page):
        page, _ = loaded_page
        self._open_backup_tab(page)
        marker = "PWTestAddViaPlus"
        # Make sure the marker doesn't already exist (test pollution).
        before = self._server_folders(page)
        assert marker not in before, "marker already on server -- previous test didn't clean up"

        page.locator("#cc-folders-add-input").fill(marker)
        page.evaluate(
            """() => {
                const inp = document.getElementById('cc-folders-add-input');
                inp.nextElementSibling.click();
            }"""
        )
        # cc_saveRules is async; give the PUT time to land.
        page.wait_for_timeout(800)

        after = self._server_folders(page)
        assert marker in after, f"+ click did not persist; server still has {after!r}"

        # Cleanup -- remove the marker we added.
        page.evaluate(
            f"""() => {{
                const ul = document.getElementById('cc-folders');
                const idx = _ccRules.exclude_folders.indexOf({marker!r});
                if (idx >= 0) {{
                    cc_removeItem('cc-folders', idx);
                }}
            }}"""
        )
        page.wait_for_timeout(800)

    def test_remove_via_x_button_persists_to_server(self, loaded_page):
        page, _ = loaded_page
        self._open_backup_tab(page)

        # First add a marker we can safely remove. This guarantees the
        # × test doesn't accidentally remove a real user rule.
        marker = "PWTestRemoveMe"
        page.locator("#cc-folders-add-input").fill(marker)
        page.evaluate(
            """() => {
                const inp = document.getElementById('cc-folders-add-input');
                inp.nextElementSibling.click();
            }"""
        )
        page.wait_for_timeout(800)
        # Sanity: marker is on the server.
        assert marker in self._server_folders(page)

        # Now click the × button next to the marker.
        page.evaluate(
            f"""() => {{
                const ul = document.getElementById('cc-folders');
                const lis = Array.from(ul.querySelectorAll('li'));
                const li = lis.find(el => el.textContent.includes({marker!r}));
                if (li) li.querySelector('button').click();
            }}"""
        )
        page.wait_for_timeout(800)

        server_after = self._server_folders(page)
        assert marker not in server_after, (
            f"× click did not persist; server still has marker in {server_after!r} -- "
            f"this is the bug the user reported 2026-05-25"
        )

    def test_enter_key_in_input_adds_and_persists(self, loaded_page):
        """Enter in the add-input is the natural keyboard UX. Equivalent
        to clicking +."""
        page, _ = loaded_page
        self._open_backup_tab(page)
        marker = "PWTestEnterKey"
        inp = page.locator("#cc-folders-add-input")
        inp.fill(marker)
        inp.press("Enter")
        page.wait_for_timeout(800)
        assert marker in self._server_folders(page), "Enter did not add"

        # Cleanup
        page.evaluate(
            f"""() => {{
                const idx = _ccRules.exclude_folders.indexOf({marker!r});
                if (idx >= 0) cc_removeItem('cc-folders', idx);
            }}"""
        )
        page.wait_for_timeout(800)

    def test_plus_with_empty_input_gives_visible_feedback(self, loaded_page):
        """User report 2026-05-25: clicking + with an empty input felt
        like 'the button does nothing.' Original code silently returned.
        Now an empty click must focus the input AND swap the placeholder
        to a hint AND flash the border red -- any of those three is
        enough to make the click feel responsive."""
        page, _ = loaded_page
        self._open_backup_tab(page)
        inp = page.locator("#cc-folders-add-input")
        inp.evaluate("el => el.blur()")  # start unfocused
        # Click + with empty input
        page.evaluate(
            """() => {
                const inp = document.getElementById('cc-folders-add-input');
                inp.value = '';
                inp.nextElementSibling.click();
            }"""
        )
        page.wait_for_timeout(200)
        # Visible feedback assertions: input focused + placeholder swapped.
        is_focused = page.evaluate("document.activeElement.id === 'cc-folders-add-input'")
        placeholder = page.evaluate("document.getElementById('cc-folders-add-input').placeholder")
        assert is_focused, "empty + click should focus the input so the user knows where to type"
        assert "type" in placeholder.lower() or "first" in placeholder.lower(), (
            f"empty + click should swap placeholder to a hint; got {placeholder!r}"
        )
        # Border color check is best-effort (browser CSS computed-value
        # quirks); the focus + placeholder change are the primary signal.
        # (Don't assert exact red value to avoid false positives.)

    def test_cluster_examine_modal_shows_real_data_at_24h_window(self, loaded_page):
        """End-to-end: open the Baseline tab, find a cluster in the
        timeline, click Examine, widen the window to 24h, and assert
        the modal contains REAL event-log data.

        Added 2026-05-25 after the user reported "the modal shows
        nothing" and asked "can you validate via testing that data
        shows up?"

        Why 24h: cluster timestamps mark when DRIFT WAS DETECTED, not
        when changes happened. On any actively-used Windows machine
        SOME event-log activity will exist in any 24h span -- so the
        24h window is the strongest "the pipeline works end-to-end"
        signal we can express in a tz-portable test.

        Skips if the timeline has no clusters (no drift history yet).
        """
        page, _errors = loaded_page

        # ── Step 1: open Baseline tab ──
        page.evaluate("switchTab('baseline')")
        page.wait_for_timeout(3000)

        # ── Step 2: find a cluster in the timeline ──
        # The cluster stash is populated by loadBaselineTimeline after
        # the drift fetch lands.
        cluster_count = 0
        for _ in range(20):
            page.wait_for_timeout(500)
            cluster_count = page.evaluate("(window._blClusterStash || []).filter(c => c.type === 'cluster').length")
            if cluster_count > 0:
                break
        if cluster_count == 0:
            pytest.skip("no clusters in baseline history -- can't end-to-end test the modal")

        # ── Step 3: click Examine on the first cluster ──
        page.evaluate("""() => {
            const stash = window._blClusterStash || [];
            const idx = stash.findIndex(c => c.type === 'cluster');
            bl_examineCluster(idx, 86400);  // open directly at 24h window
        }""")

        # The overlay appears INSTANTLY with a loading placeholder, then
        # the fetch resolves and the contents are replaced with the
        # rendered tables. Wait for the "Update history" section header
        # to appear -- it's only present in the final state, not the
        # loading placeholder, so this is a reliable readiness signal.
        # First-call Microsoft.Update.Session COM can take 5-10s on a
        # cold start; allow plenty of headroom (30s).
        for _ in range(60):  # 60 * 500ms = 30s
            page.wait_for_timeout(500)
            overlay_present = page.evaluate("!!document.getElementById('bl-examine-overlay')")
            if overlay_present:
                modal_text = page.evaluate("document.getElementById('bl-examine-overlay')?.innerText || ''")
                if "Update history" in modal_text:  # final state has all section headers
                    break

        # ── Step 4: assert modal opened with expected structure ──
        present = page.evaluate("!!document.getElementById('bl-examine-overlay')")
        assert present, "Examine modal didn't open"

        # All four source headers must be present in the rendered HTML.
        modal_html = page.evaluate("document.getElementById('bl-examine-overlay').innerHTML")
        assert "Update history" in modal_html, "modal missing Update history section"
        assert "Event Log" in modal_html, "modal missing Event Log section"
        assert "Hotfixes" in modal_html, "modal missing Hotfixes section"
        assert "BIOS audit" in modal_html, "modal missing BIOS audit section"

        # ── Step 5: assert at least one source returned REAL data ──
        # Count <tbody><tr> rows directly. Header-text counts like
        # "Update history (Microsoft.Update.Session) (N)" have nested
        # parens that confuse a naive regex, so we walk the DOM instead.
        # Placeholder "no entries" rows have a single <td> with colspan;
        # exclude them so the count reflects REAL data only.
        signal_counts = page.evaluate(
            """() => {
                const tables = Array.from(document.querySelectorAll('#bl-examine-overlay table'));
                return tables.map(t => {
                    const rows = Array.from(t.querySelectorAll('tbody tr'));
                    return rows.filter(r => {
                        const tds = r.querySelectorAll('td');
                        if (tds.length === 1 && tds[0].hasAttribute('colspan')) return false;
                        return true;
                    }).length;
                });
            }"""
        )
        total = sum(signal_counts)
        assert total > 0, (
            "Examine modal at 24h window found ZERO signals across all four sources. "
            "On any actively-used Windows machine SOMETHING should be in the System or "
            "Application event log within a 24-hour span. The pipeline is broken or the "
            "cluster timestamp is in the future. "
            f"counts: {signal_counts}"
        )

        # ── Step 6: verify the window-selector dropdown is present ──
        has_dropdown = page.evaluate("""!!document.querySelector("#bl-examine-overlay select")""")
        assert has_dropdown, "window-selector dropdown missing from modal"

        # ── Step 7: dismiss via Close button ──
        page.evaluate(
            """() => {
                document.querySelector('#bl-examine-overlay button').click();
            }"""
        )
        page.wait_for_timeout(300)
        still_present = page.evaluate("!!document.getElementById('bl-examine-overlay')")
        assert not still_present, "modal didn't close after clicking Close"

    def test_placeholder_survives_add(self, loaded_page):
        """User report 2026-05-25: 'folder name' placeholder vanished
        after the first add. Original cc_renderListEditor called with 2
        args set placeholder to empty string. After fix: placeholder
        only changes when explicitly supplied -- post-add renders leave
        it alone."""
        page, _ = loaded_page
        self._open_backup_tab(page)
        inp = page.locator("#cc-folders-add-input")

        # The initial placeholder is the example text set by loadCloudCopy.
        initial_placeholder = inp.evaluate("el => el.placeholder")
        assert "e.g." in initial_placeholder, (
            f"initial render should put an example placeholder; got {initial_placeholder!r}"
        )

        # Add an item, then check the placeholder hasn't been clobbered.
        marker = "PWTestPlaceholderSurvival"
        inp.fill(marker)
        page.evaluate("""() => document.getElementById('cc-folders-add-input').nextElementSibling.click()""")
        page.wait_for_timeout(800)
        after_add_placeholder = inp.evaluate("el => el.placeholder")
        assert after_add_placeholder == initial_placeholder, (
            f"placeholder was clobbered after add: {initial_placeholder!r} -> {after_add_placeholder!r}"
        )

        # Cleanup the marker.
        page.evaluate(
            f"""() => {{
                const idx = _ccRules.exclude_folders.indexOf({marker!r});
                if (idx >= 0) cc_removeItem('cc-folders', idx);
            }}"""
        )
        page.wait_for_timeout(800)


# ── Backup tab Section 2 — File History store-missing false alarm ─────
#
# Added 2026-06-16. A healthy ACL-protected store at a non-standard path
# made the card cry red "missing -- verify manually". The verdict now
# trusts a fresh catalog: when backups are current it reads a confident
# "healthy" and the store row shows a calm "ACL-protected" note instead of
# a red alarm. Gate: the DOM must reflect the API's health verdict, and a
# non-critical verdict must NOT render the scary red "missing".


class TestFileHistoryStoreAlarm:
    """When the API reports a non-critical File History verdict, the card
    must not render a red 'missing' store alarm, and the rendered health
    banner must match the API's reason string."""

    def test_card_reflects_api_health_without_false_missing_alarm(self, loaded_page):
        page, _ = loaded_page
        api = page.evaluate(
            """async () => {
                const r = await fetch('/api/backup/file-history');
                return await r.json();
            }"""
        )
        if not api.get("configured"):
            pytest.skip("File History not configured on this machine")

        page.evaluate("switchTab('backup')")
        # Wait for Section 2 to render the real health banner (the reason
        # text from the API), not the loading pill.
        reason = (api.get("health") or {}).get("reason", "")
        body = ""
        for _ in range(20):
            page.wait_for_timeout(300)
            body = page.evaluate("(document.getElementById('bk-sec2-body') || {}).textContent || ''")
            if reason and reason in body:
                break

        # The card's banner must show the SAME verdict the API computed.
        assert reason and reason in body, f"card banner doesn't match API health reason {reason!r}; body={body[:240]!r}"

        level = (api.get("health") or {}).get("level")
        store_confirmed = api.get("target_backup_store_exists") is True
        if level != "critical" and not store_confirmed:
            # The false-alarm scenario the fix targets: backups are fine but
            # the store folder isn't readable. The store row must show the
            # calm ACL note, NOT a bare red "missing".
            assert "acl-protected" in body.lower(), (
                f"non-critical + unconfirmed store should show the calm ACL note; body={body[:240]!r}"
            )


# ── Backup tab — scheduled auto-cleanup control (in-app retention) ────
#
# Added 2026-06-16: a weekly `fhmanagew -cleanup <N>` task that actually
# prunes old versions. Gate: the control renders and reflects the API
# (ON state vs the schedule-it form), not just "an element exists".


class TestCleanupScheduleControl:
    def test_schedule_control_reflects_api(self, loaded_page):
        page, _ = loaded_page
        api = page.evaluate(
            """async () => {
                const r = await fetch('/api/backup/fh-cleanup-schedule');
                return await r.json();
            }"""
        )
        fh = page.evaluate(
            """async () => {
                const r = await fetch('/api/backup/file-history');
                return await r.json();
            }"""
        )
        if not fh.get("configured"):
            pytest.skip("File History not configured on this machine")

        page.evaluate("switchTab('backup')")
        # Wait for the schedule control to populate. The status route shells
        # out to `schtasks /Query` (~2-3s warm, more on a cold tray), so give
        # it a generous budget to avoid a cold-restart flake.
        for _ in range(50):  # 50 * 300ms = 15s
            page.wait_for_timeout(300)
            ready = page.evaluate("(document.getElementById('bk-fh-schedule')||{}).textContent ? true : false")
            if ready:
                break

        body = page.evaluate("(document.getElementById('bk-fh-schedule')||{}).textContent || ''")
        assert body.strip(), "schedule control did not render"
        # The effective window must also surface in the Retention row so a
        # user who scheduled e.g. 180 days sees it there, not just below.
        ret_eff = page.evaluate("(document.getElementById('bk-ret-effective')||{}).textContent || ''")
        if api.get("enabled"):
            # ON state names the configured age + offers a Turn-off button.
            assert "auto-cleanup on" in body.lower()
            has_off = page.evaluate(
                "Array.from(document.querySelectorAll('#bk-fh-schedule button')).some(b => /turn off/i.test(b.textContent))"
            )
            assert has_off, "enabled schedule should offer a Turn-off button"
            assert "auto-cleanup" in ret_eff.lower() and "day" in ret_eff.lower(), (
                f"enabled schedule should surface the effective window in the Retention row; got {ret_eff!r}"
            )
        else:
            assert ret_eff.strip() == "", (
                f"disabled schedule should leave the Retention row's effective span empty; got {ret_eff!r}"
            )
            # OFF state shows the days input + a Schedule button.
            has_input = page.evaluate("!!document.getElementById('bk-sched-days')")
            has_btn = page.evaluate(
                "Array.from(document.querySelectorAll('#bk-fh-schedule button')).some(b => /schedule/i.test(b.textContent))"
            )
            assert has_input, "off-state schedule control should have a days input"
            assert has_btn, "off-state schedule control should have a Schedule button"


# ── Backup tab — File History storage breakdown panel ─────────────────
#
# Added 2026-06-29: an elevated scan that breaks down where File History
# space goes + flags reclaimable orphaned stores. Gate: the panel renders
# with a scan button, and when a cached scan exists it shows totals.


class TestStoragePanel:
    def test_storage_panel_renders_scan_control(self, loaded_page):
        page, _ = loaded_page
        fh = page.evaluate("async () => await (await fetch('/api/backup/file-history')).json()")
        if not fh.get("configured"):
            pytest.skip("File History not configured on this machine")

        page.evaluate("switchTab('backup')")
        body = ""
        for _ in range(20):
            page.wait_for_timeout(300)
            body = page.evaluate("(document.getElementById('bk-fh-storage')||{}).textContent || ''")
            if "storage usage" in body.lower():
                break

        assert "storage usage" in body.lower(), f"storage panel did not render; got {body[:160]!r}"
        # A scan button must be present (scan or re-scan, depending on cache).
        has_scan = page.evaluate(
            "Array.from(document.querySelectorAll('#bk-fh-storage button')).some(b => /scan/i.test(b.textContent))"
        )
        assert has_scan, "storage panel must offer a scan button"


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


# ── Dashboard hero gauges (redesign PR2) ───────────────────────────
#
# The instrument-cluster radial gauges render from the dashboard summary's
# `gauges` list. Same contract shape as TestTrendsCardCoverage: every gauge
# the API reports must render exactly one tile, in order. Per the
# visual-smoke-isn't-correctness lesson we assert the data-* attrs and the
# unavailable->"—" fallback, not just "a gauge exists".


class TestDashboardGauges:
    """One rendered tile per API gauge, in order; unavailable readings show
    "—" (missing sensor / no GPU), available ones show a number."""

    def _wait_gauges(self, page):
        page.evaluate("switchTab('dashboard')")
        # The summary fan-out is heavy/cold (bounded at 45s server-side), so
        # allow up to 45s for the first render; warm renders are instant.
        page.wait_for_function(
            "() => document.querySelectorAll('#db-gauges .db-gauge').length > 0",
            timeout=45_000,
        )

    def test_rendered_gauges_match_api(self, loaded_page):
        page, _errors = loaded_page
        self._wait_gauges(page)
        # Read the rendered tiles AND the API gauges in one evaluate so the 30s
        # dashboard re-render can't race between two separate reads.
        result = page.evaluate(
            """() => {
                const dom = Array.from(document.querySelectorAll('#db-gauges .db-gauge'))
                                 .map(t => t.dataset.gaugeKey);
                return fetch('/api/dashboard/summary')
                    .then(r => r.json())
                    .then(d => ({ api: (d.gauges || []).map(g => g.key), dom }));
            }"""
        )
        assert result["api"], "dashboard summary reported no gauges"
        assert result["dom"] == result["api"], (
            f"rendered gauge tiles {result['dom']} don't match the API's gauges {result['api']} -- "
            f"renderGauges() in app.js must emit one tile per gauge, in order"
        )

    def test_unavailable_gauge_shows_dash_not_zero(self, loaded_page):
        """A null reading (no CPU thermal provider, absent GPU) must render
        '—' with data-gauge-available=false -- never a bogus 0."""
        page, _errors = loaded_page
        self._wait_gauges(page)
        info = page.evaluate(
            """() => Array.from(document.querySelectorAll('#db-gauges .db-gauge')).map(t => ({
                key: t.dataset.gaugeKey,
                available: t.dataset.gaugeAvailable,
                num: ((t.querySelector('.dg-num') || {}).textContent || '').trim(),
            }))"""
        )
        assert info, "no gauge tiles rendered"
        for g in info:
            if g["available"] == "false":
                assert "—" in g["num"], f"unavailable gauge {g['key']} should show '—', got {g['num']!r}"
            else:
                assert any(c.isdigit() for c in g["num"]), (
                    f"available gauge {g['key']} should show a numeric reading, got {g['num']!r}"
                )

    def test_gauge_bar_fill_tracks_value(self, loaded_page):
        """Regression: each gauge is a horizontal bar whose fill width = the
        value %. --sweep must reach the .dg-fill that READS it (registered
        @property{inherits:false}); setting it on the tile would leave every
        fill at the initial 0 ('usage differs but the chart space is the same').
        The ring geometry was abandoned because its unfilled circular remainder
        read as a dark 'pre-filled' section -- a bar has only a small light
        track, so no remainder can look dark. Tiles still carry a state accent."""
        page, _ = loaded_page
        self._wait_gauges(page)
        info = page.evaluate(
            """() => Array.from(document.querySelectorAll('#db-gauges .db-gauge')).map(g => {
                const fill = g.querySelector('.dg-fill');
                return {
                    key: g.dataset.gaugeKey,
                    available: g.dataset.gaugeAvailable,
                    value: g.dataset.gaugeValue,
                    sweep: fill ? parseFloat(fill.style.getPropertyValue('--sweep')) : null,
                    accent: getComputedStyle(g).borderTopColor,
                    hasRing: !!g.querySelector('.dg-arc, .dg-ring'),
                };
            })"""
        )
        avail = [g for g in info if g["available"] == "true" and g["value"]]
        assert avail, "no available gauges to check"
        # Each available gauge's bar fill must be PROPORTIONAL to its value
        # (sweep% == value, since every gauge has max=100). This directly
        # catches the original bug (all fills stuck at the initial 0) without
        # false-failing when two sensors coincidentally read the same percent,
        # which a "fills must all differ" check would.
        for g in avail:
            expected = max(0.0, min(100.0, float(g["value"])))  # value clamped to the 0..max range
            assert g["sweep"] and g["sweep"] > 0, f"gauge {g['key']} bar not filled (sweep={g['sweep']})"
            assert abs(g["sweep"] - expected) < 1.0, (
                f"gauge {g['key']}: value={g['value']} but bar sweep={g['sweep']} (expected ~{expected})"
            )
        # Tile accent is a real state colour, not a transparent default.
        assert all(g["accent"] and "0, 0, 0, 0" not in g["accent"] for g in avail), (
            f"gauge tiles missing the state-colour accent: {[g['accent'] for g in avail]}"
        )
        # The circular ring geometry (the source of the dark-remainder look) is
        # gone -- no gauge should render a .dg-ring / .dg-arc any more.
        assert not any(g["hasRing"] for g in info), "a gauge still renders the old ring geometry (.dg-ring/.dg-arc)"


# ── Thermals tab redesign (PR4) ────────────────────────────────────


class TestThermalsRedesign:
    """Redesign PR4. The Thermals tab is a data-driven instrument cluster:
    a hero gauge row (reusing the dashboard renderer), a per-core grid OR a
    LibreHardwareMonitor install CTA, and one cooling-device card per fan.

    These assert behaviour that only surfaces on the user action of opening
    the tab -- the gauge fan-out, the cores-vs-CTA branch, and the fan
    cards -- per the visual-smoke-isn't-correctness memo (assert data-*
    attrs and the fallback branch, not just "an element exists")."""

    def _goto(self, page):
        page.evaluate("switchTab('thermals')")
        # Server bounds the thermals fan-out (perf + temps + gpu) similarly to
        # the dashboard summary; allow a cold first render.
        page.wait_for_function(
            "() => document.getElementById('th-content')"
            " && document.getElementById('th-content').style.display !== 'none'",
            timeout=45_000,
        )

    def test_hero_gauges_match_api(self, loaded_page):
        """One tile per API gauge, in order -- the tab reuses renderGauges()
        against /api/thermals/data's `gauges`, same contract as the dashboard."""
        page, _ = loaded_page
        self._goto(page)
        result = page.evaluate(
            """() => {
                const dom = Array.from(document.querySelectorAll('#th-gauge-row .db-gauge'))
                                 .map(t => t.dataset.gaugeKey);
                return fetch('/api/thermals/data')
                    .then(r => r.json())
                    .then(d => ({ api: (d.gauges || []).map(g => g.key), dom }));
            }"""
        )
        assert result["api"], "thermals endpoint reported no gauges"
        assert result["dom"] == result["api"], (
            f"rendered hero gauges {result['dom']} don't match the API's {result['api']}"
        )

    def test_unavailable_gauge_shows_dash(self, loaded_page):
        """A null reading (e.g. CPU temp with no thermal provider on this box)
        renders '—' with data-gauge-available=false, never a bogus 0."""
        page, _ = loaded_page
        self._goto(page)
        info = page.evaluate(
            """() => Array.from(document.querySelectorAll('#th-gauge-row .db-gauge')).map(t => ({
                key: t.dataset.gaugeKey,
                available: t.dataset.gaugeAvailable,
                num: ((t.querySelector('.dg-num') || {}).textContent || '').trim(),
            }))"""
        )
        assert info, "no hero gauge tiles rendered"
        for g in info:
            if g["available"] == "false":
                assert "—" in g["num"], f"unavailable gauge {g['key']} should show '—', got {g['num']!r}"

    def test_cores_grid_xor_install_cta(self, loaded_page):
        """Exactly one of the per-core grid / the LHM install CTA is shown,
        driven by whether the API returned 'CPU Core #N' sensors. On a box
        with no per-core provider the CTA shows; if LHM is installed the grid
        auto-populates instead. Never both, never neither."""
        page, _ = loaded_page
        self._goto(page)
        state = page.evaluate(
            """() => {
                const vis = id => {
                    const e = document.getElementById(id);
                    return !!e && getComputedStyle(e).display !== 'none';
                };
                return fetch('/api/thermals/data').then(r => r.json()).then(d => {
                    const temps = Array.isArray(d.temps) ? d.temps : [];
                    const cores = temps.filter(t => /core\\s*#?\\d+/i.test(String(t.Name || '')));
                    return {
                        hasCores: cores.length > 0,
                        gridShown: vis('th-cores-section'),
                        ctaShown: vis('th-cores-cta'),
                        coreCells: document.querySelectorAll('#th-cores .th-core').length,
                    };
                });
            }"""
        )
        assert state["gridShown"] != state["ctaShown"], (
            f"cores grid and CTA must be mutually exclusive, got grid={state['gridShown']} cta={state['ctaShown']}"
        )
        if state["hasCores"]:
            assert state["gridShown"], "API returned per-core sensors but the grid is hidden"
            assert state["coreCells"] > 0, "cores grid shown but no .th-core cells rendered"
        else:
            assert state["ctaShown"], "no per-core sensors but the install CTA is hidden"

    def test_install_cta_has_wired_action_button(self, loaded_page):
        """When the per-core CTA shows, it carries a real LHM installer action
        button (.th-cta-btn) whose label reflects the lhm/status state. Proves
        the in-app installer is wired, not just descriptive copy."""
        page, _ = loaded_page
        self._goto(page)
        # If LHM is already running on this box the CTA won't show -- skip then.
        state = page.evaluate(
            """() => {
                const cta = document.getElementById('th-cores-cta');
                const shown = !!cta && getComputedStyle(cta).display !== 'none';
                const btn = cta && cta.querySelector('.th-cta-btn');
                return {
                    shown,
                    label: btn ? btn.textContent.trim() : null,
                    hasStatus: !!(cta && cta.querySelector('.th-cta-status')),
                };
            }"""
        )
        if not state["shown"]:
            pytest.skip("LHM already running on this host -- CTA not shown")
        assert state["label"], "install CTA shown but no .th-cta-btn action button"
        assert any(w in state["label"] for w in ("Install", "Launch", "Refresh")), (
            f"CTA button label {state['label']!r} doesn't match an installer action"
        )
        assert state["hasStatus"], "CTA action row missing its .th-cta-status line"

    def test_lhm_autostart_toggle_renders_when_installed(self, loaded_page):
        """The optional 'auto-start at login' toggle appears once LHM is
        installed. The app-managed install dir is empty on this host, so we
        force the installed state and re-render to prove the toggle is wired
        (it lazily fetches /api/thermals/lhm/autostart to label itself)."""
        page, _ = loaded_page
        self._goto(page)
        state = page.evaluate(
            """async () => {
                if (typeof renderThermals !== 'function') return {skip: true};
                // _lhmStatus is a top-level `let` (lexical, not on window) -- assign
                // the binding directly so the renderer sees the forced state.
                _lhmStatus = {installed: true, running: false, version: 'v0.9.6'};
                renderThermals();
                await new Promise(r => setTimeout(r, 1500));  // let the autostart fetch resolve
                const cta = document.getElementById('th-cores-cta');
                if (!cta || getComputedStyle(cta).display === 'none') return {skip: true};
                const btns = Array.from(cta.querySelectorAll('.th-cta-btn')).map(b => b.textContent.trim());
                return {btns};
            }"""
        )
        if state.get("skip"):
            pytest.skip("thermals CTA not shown on this host (LHM running / no renderThermals)")
        joined = " ".join(state["btns"]).lower()
        assert "auto-start" in joined, f"auto-start toggle missing from CTA buttons: {state['btns']}"

    def test_per_core_cells_are_temperature_colour_banded(self, loaded_page):
        """Each per-core cell + sensor row carries a tband-* class matching its
        temperature, the legend renders all five bands, and the accent colour
        actually changes with the band (a cool cell is cyan; a warm/hot sensor
        is amber/orange) -- not just 'a class exists'."""
        page, _ = loaded_page
        self._goto(page)
        state = page.evaluate(
            """() => {
                const cells = Array.from(document.querySelectorAll('#th-cores .th-core'));
                if (!cells.length) return {skip: true};  // LHM not running -> no grid
                const bandOf = el => (el.className.match(/tband-(cool|normal|warm|hot|crit)/) || [])[1] || null;
                const allCellsBanded = cells.every(c => bandOf(c));
                const legend = document.querySelectorAll('#th-legend .th-leg-item').length;
                const cool = cells.find(c => bandOf(c) === 'cool');
                const coolColor = cool ? getComputedStyle(cool.querySelector('.th-core-temp')).color : null;
                const sensors = Array.from(document.querySelectorAll('#th-temps-grid .th-sensor'));
                const offCool = sensors.find(s => bandOf(s) && bandOf(s) !== 'cool');
                const offColor = offCool ? getComputedStyle(offCool.querySelector('.th-sensor-temp')).color : null;
                return {allCellsBanded, legend, coolColor, offColor};
            }"""
        )
        if state.get("skip"):
            pytest.skip("per-core grid not shown (LHM not running on this host)")
        assert state["allCellsBanded"], "some per-core cells have no tband-* class"
        assert state["legend"] == 5, f"legend should map all 5 bands, got {state['legend']}"
        # cool is cyan; any warmer band must render a different colour.
        if state["offColor"]:
            assert state["coolColor"] != state["offColor"], (
                f"colour didn't track the band: cool={state['coolColor']} off-cool={state['offColor']}"
            )

    def test_fan_cards_one_per_cooling_device(self, loaded_page):
        """One .th-fan card per fan from the API; active fans carry the
        spinning-blade class so the cooling state is visible at a glance."""
        page, _ = loaded_page
        self._goto(page)
        state = page.evaluate(
            """() => fetch('/api/thermals/data').then(r => r.json()).then(d => {
                const fans = Array.isArray(d.fans) ? d.fans : [];
                const sec = document.getElementById('th-fans-section');
                return {
                    apiFans: fans.length,
                    cards: document.querySelectorAll('#th-fans .th-fan').length,
                    spinning: document.querySelectorAll('#th-fans .th-fan-blade.spin').length,
                    secShown: !!sec && getComputedStyle(sec).display !== 'none',
                };
            })"""
        )
        if state["apiFans"]:
            assert state["secShown"], "API reported fans but the cooling-devices section is hidden"
            assert state["cards"] == state["apiFans"], (
                f"expected {state['apiFans']} fan cards, rendered {state['cards']}"
            )
        else:
            assert not state["secShown"], "no fans from API but the section is shown"


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

    # ── Structural coverage regressions ────────────────────────────────
    # User feedback 2026-05-08 ("shows one moca bridge"): the topology
    # diagram had collapsed all 5 auto-discovered MoCA bridges into a
    # single column, asymmetric with Orbi satellites which each get
    # their own column. The bug shipped because data tests asserted
    # backend correctness (build_topology returned 5 bridges) but no
    # test asserted the FRONTEND rendered N columns for N bridges.
    #
    # The lesson: visual smoke "X exists" tests miss structural bugs
    # like "wrong column count for the data we have." The test below
    # is a 1:1 contract guard between every multi-instance API category
    # and its rendered column set -- same pattern as TestTrendsCardCoverage
    # (#39) which guards every available metric → rendered card.

    def test_topology_column_count_matches_api_category_counts(self, loaded_page):
        """For every multi-instance infrastructure category in the API
        response (aps / switches / moca_bridges), the rendered SVG MUST
        contain that many columns of the matching kind. Catches the
        2026-05-08 'shows one moca bridge' bug class -- backend reported
        5 bridges, frontend rendered 1 column. Generalised so the same
        regression in any other category (Orbi APs, switches) fires too.
        """
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        if not topology.get("ok"):
            pytest.skip(f"topology API not ok: {topology}")

        # Map: API key -> expected column kinds in the SVG. A category
        # may map to multiple kinds (e.g. aps splits into base + satellite)
        # so the assertion is on combined count.
        # API key (list-of-MACs) -> set of valid SVG column kinds for it
        category_to_kinds = {
            "moca_bridges": {"moca"},
            "switches": {"switch"},
            "aps": {"ap_base", "ap_satellite"},
        }

        self._goto_homenet_and_show_topology(page)

        rendered_kinds = page.evaluate(
            """
            Array.from(document.querySelectorAll('#hn-topo-svg-wrap g[data-column-kind]'))
                 .map(g => g.dataset.columnKind)
            """
        )
        rendered_count_by_kind = {}
        for k in rendered_kinds:
            rendered_count_by_kind[k] = rendered_count_by_kind.get(k, 0) + 1

        misses = []
        for api_key, valid_kinds in category_to_kinds.items():
            api_items = topology.get(api_key) or []
            api_count = len(api_items)
            rendered_for_category = sum(rendered_count_by_kind.get(k, 0) for k in valid_kinds)
            if api_count != rendered_for_category:
                misses.append(
                    f"  {api_key}: API has {api_count}, SVG rendered {rendered_for_category} "
                    f"(kinds {sorted(valid_kinds)})"
                )

        assert not misses, (
            "Topology column-count mismatch -- the SVG isn't rendering one column per "
            "infrastructure item the backend reported.\n"
            + "\n".join(misses)
            + "\n\nThis catches the 2026-05-08 'shows one moca bridge' regression class: "
            "data tests pass because the backend is right, but the renderer in "
            "templates/index.html (hnTopoBuildSvg) collapses multiple items into one "
            "column. Each item in the multi-instance API categories should get its own "
            "<g data-column-kind=...> in the SVG."
        )

    def test_topology_columns_have_unique_data_column_id(self, loaded_page):
        """Defence against a copy-paste bug producing two columns with
        the same id (would hide one in the diagram). Same shape as
        TestTrendsCardCoverage.test_rendered_cards_have_unique_data_metric."""
        page, _ = loaded_page
        topology = page.evaluate("fetch('/api/homenet/topology').then(r => r.json())")
        if not topology.get("ok"):
            pytest.skip(f"topology API not ok: {topology}")

        self._goto_homenet_and_show_topology(page)
        ids = page.evaluate(
            """
            Array.from(document.querySelectorAll('#hn-topo-svg-wrap g[data-column-id]'))
                 .map(g => g.dataset.columnId)
                 .filter(s => s)
            """
        )
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        assert not dupes, f"duplicate data-column-id in topology SVG: {dupes}"

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
            # 35s, not 15s: the first baseline-drift call does a real
            # enumeration whose bounded worst-case is ~30s -- schtasks runs as a
            # subprocess with a 30s timeout, alongside the WMI service-enrichment
            # (8s bound) and startup scan (parallel). It's ~8s cold in isolation
            # but balloons under the resource contention of a full-suite run
            # (many concurrent tray operations). 35s covers the bounded ceiling
            # + contention headroom; every underlying call is still hang-bounded
            # so this widens headroom, never masks a hang. Warm calls ~3s.
            timeout=35_000,
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
            # 35s: same cold baseline-drift settle as _goto_baseline (see note there).
            timeout=35_000,
        )

        # Expand inventory + wait for at least one row to render
        page.evaluate("blToggleInventory()")
        page.wait_for_function(
            "() => document.querySelectorAll('#bl-inv-body .bl-inv-row').length > 0",
            timeout=25_000,
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
        # against. The cache-miss recovery re-fetches /api/baseline/snapshot,
        # i.e. a full bounded take_snapshot (~30s worst case), so allow 35s --
        # same rationale as the settle waits above (heavy under full-suite
        # contention; isolation runs settle in a couple seconds).
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
            timeout=35_000,
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


# ── Driver tab: NVIDIA card placement (2026-05-22) ─────────────────


class TestDriverTabNvidiaCard:
    """User feedback 2026-05-22: the NVIDIA GPU was rendered as a separate
    banner (``#drv-nvidia-card``) pinned above the driver grid. It should
    instead render as a normal card inside the ``#driver-grid`` matrix,
    alongside every other driver. ``drvLoadNvidiaStatus()`` now injects a
    driver-shaped entry into ``allDrivers`` and goes through the standard
    ``renderGrid()`` path.

    Guards against: the pinned banner coming back, and the NVIDIA card
    not landing in the grid at all.
    """

    def test_nvidia_renders_in_grid_not_pinned_banner(self, loaded_page):
        page, errors = loaded_page

        status = page.evaluate("fetch('/api/nvidia/status').then(r => r.json())")
        if not status.get("ok") or not status.get("has_nvidia"):
            pytest.skip("no NVIDIA GPU on this machine — nothing to render")

        # First switch to the Drivers tab triggers drvLoadNvidiaStatus().
        page.evaluate("switchTab('drivers')")
        page.wait_for_function(
            """
            () => {
                const grid = document.getElementById('driver-grid');
                if (!grid) return false;
                return Array.from(grid.querySelectorAll('.driver-card[data-driver-name]'))
                    .some(c => /nvidia/i.test(c.dataset.driverName));
            }
            """,
            timeout=20_000,
        )

        # 1. The old pinned-banner element must be gone entirely.
        assert page.evaluate("document.getElementById('drv-nvidia-card') === null"), (
            "#drv-nvidia-card still exists — the NVIDIA GPU should render inside "
            "#driver-grid as a normal card, not as a separate pinned banner"
        )

        # 2. The NVIDIA card must be a child of #driver-grid (the matrix).
        nv = page.evaluate(
            """
            (() => {
                const cards = Array.from(
                    document.querySelectorAll('#driver-grid .driver-card[data-driver-name]'));
                const card = cards.find(c => /nvidia/i.test(c.dataset.driverName));
                return card
                    ? {found: true, status: card.dataset.driverStatus, name: card.dataset.driverName}
                    : {found: false};
            })()
            """
        )
        assert nv["found"], "NVIDIA card is not inside #driver-grid — it must be in the matrix"
        assert nv["status"] in (
            "up_to_date",
            "update_available",
        ), f"NVIDIA grid card has unexpected data-driver-status {nv['status']!r}"

        actionable = [e for e in errors if "favicon" not in e.lower()]
        assert not actionable, f"console errors on the Drivers tab: {actionable}"


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


class TestCodeHealthCardDetails:
    """Utilities-tab code-health cards must expose their findings, not
    just a one-line summary. The 2026-05-30 bug: the Tech Debt card's
    'INFO' was a non-clickable severity pill, and the backend's rich
    ``details`` (the 14 TODOs + 4 oversized files, the lowest-coverage
    files, the ruff findings) were computed but never rendered -- so the
    card looked like it had a broken info button.

    The fix renders a ``<details data-scanner-details=...>`` disclosure
    on every card that HAS findings, with a count that matches the
    backend. A clean scanner (e.g. ruff with 0 findings) renders NO
    disclosure so the card stays compact.

    Assertion model: the authoritative findings come from
    ``/api/codehealth/status``; the rendered disclosures come from
    ``[data-scanner-details]`` under ``#util-ch-grid``. Each scanner's
    expected detail count is derived from its result shape (tech_debt
    is a dict of todos+large_files; coverage/ruff are lists; secrets is
    count-only).
    """

    def _goto_utilities(self, page):
        page.evaluate("switchTab('utilities')")
        # util_loadCodeHealth() renders the grid; wait for it to settle
        # to real cards (not the 'Loading…' placeholder).
        page.wait_for_function(
            """
            () => {
                const el = document.getElementById('util-ch-grid');
                if (!el) return false;
                return el.textContent.trim() !== 'Loading…'
                    && el.querySelector('[data-scanner]') !== null;
            }
            """,
            timeout=15_000,
        )

    def _expected_counts(self, page):
        """Per-scanner expected detail count, derived from the live API
        the same way the renderer does."""
        return page.evaluate(
            """
            fetch('/api/codehealth/status').then(r => r.json()).then(j => {
                const sc = (j.state && j.state.scanners) || {};
                const out = {};
                for (const [name, res] of Object.entries(sc)) {
                    const d = res.details;
                    let count = 0;
                    if (name === 'tech_debt' && d && !Array.isArray(d)) {
                        count = (d.large_files || []).length + (d.todos || []).length;
                    } else if ((name === 'coverage' || name === 'ruff') && Array.isArray(d)) {
                        count = d.length;
                    } else if (name === 'secrets') {
                        count = Number(res.count || 0);
                    }
                    out[name] = count;
                }
                return out;
            })
            """
        )

    def test_cards_with_findings_render_a_details_disclosure(self, loaded_page):
        page, _ = loaded_page
        self._goto_utilities(page)
        expected = self._expected_counts(page)

        # At least one scanner should have findings on a real repo
        # (tech_debt always has oversized files + TODOs here). If not,
        # skip rather than assert a vacuous truth.
        if not any(v > 0 for v in expected.values()):
            pytest.skip("no scanner reported findings -- nothing to expand")

        rendered = page.evaluate(
            """
            (() => {
                const out = {};
                document.querySelectorAll('#util-ch-grid [data-scanner-details]').forEach(el => {
                    out[el.getAttribute('data-scanner-details')] =
                        Number(el.getAttribute('data-detail-count'));
                });
                return out;
            })()
            """
        )

        # Every scanner with findings must have a disclosure whose count
        # matches the backend; every clean scanner must NOT have one.
        for name, exp in expected.items():
            if exp > 0:
                assert name in rendered, (
                    f"{name} has {exp} findings but renders no <details> disclosure "
                    f"(the original Tech-Debt bug). Rendered: {rendered}"
                )
                assert rendered[name] == exp, (
                    f"{name} disclosure shows {rendered[name]} details but backend reports {exp}"
                )
            else:
                assert name not in rendered, f"{name} is clean (0 findings) but still renders a details disclosure"

    def test_tech_debt_details_lists_oversized_files_and_todos(self, loaded_page):
        """The specific card from the bug report: expanding Tech Debt
        must surface the actual oversized-file names + line counts, not
        just the summary count."""
        page, _ = loaded_page
        self._goto_utilities(page)

        info = page.evaluate(
            """
            (() => {
                const card = document.querySelector('#util-ch-grid [data-scanner="tech_debt"]');
                if (!card) return {found: false};
                const det = card.querySelector('[data-scanner-details="tech_debt"]');
                if (!det) return {found: true, hasDetails: false};
                // Expand it (native <details>) and read the body text.
                det.open = true;
                return {found: true, hasDetails: true, text: det.textContent};
            })()
            """
        )
        assert info["found"], "tech_debt card not rendered on utilities tab"
        assert info["hasDetails"], "tech_debt card has no details disclosure -- the info button bug is back"
        # The body should name at least one oversized file with a line
        # count. windesktopmgr.py is always >5,000 lines on this repo.
        assert "windesktopmgr.py" in info["text"], (
            f"tech_debt details don't list the oversized files: {info['text'][:200]}"
        )
        assert "lines" in info["text"], "tech_debt details missing line-count labels"


# ── Logs tab exact-level filter (added 2026-06-08) ──────────────────────────


class TestLogsExactLevelFilter:
    """The log-level dropdown offers both 'minimum severity' (INFO+ = and above)
    AND 'this level only' (INFO only) options; logParseLevel() decodes the
    leading '=' into {level, exact}. Regression for the user report that INFO+
    'also shows warnings' (by design) -- exact gives an info-only view."""

    def test_dropdown_has_both_modes_and_parser_decodes_exact(self, loaded_page):
        page, _ = loaded_page
        page.evaluate("switchTab('logs')")
        page.wait_for_timeout(400)
        state = page.evaluate(
            """() => {
                const sel = document.getElementById('log-level');
                if (!sel || typeof logParseLevel !== 'function') return {skip: true};
                const opts = Array.from(sel.options).map(o => o.value);
                sel.value = '=WARNING';
                const exact = logParseLevel();
                sel.value = 'INFO';
                const min = logParseLevel();
                return {opts, exact, min};
            }"""
        )
        if state.get("skip"):
            pytest.skip("logs tab / logParseLevel not present")
        # Both the and-above and exact options exist.
        assert "INFO" in state["opts"], "minimum-severity INFO+ option missing"
        assert "=INFO" in state["opts"] and "=WARNING" in state["opts"], "exact-level options missing"
        # The parser decodes each correctly.
        assert state["exact"]["level"] == "WARNING" and state["exact"]["exact"] is True
        assert state["min"]["level"] == "INFO" and state["min"]["exact"] is False

    def test_exact_info_filter_returns_info_only(self, loaded_page):
        """End-to-end: the exact endpoint the dropdown hits returns only INFO."""
        page, _ = loaded_page
        levels = page.evaluate(
            """() => fetch('/api/logs?lines=500&level=INFO&exact=1')
                       .then(r => r.json())
                       .then(d => Array.from(new Set((d.entries||[]).map(e => e.level))))"""
        )
        # Live log is INFO-dominated; exact INFO must never include WARNING/ERROR.
        assert all(lv == "INFO" for lv in levels), f"exact INFO filter leaked other levels: {levels}"


class TestStorageTabSlotsAndSpaces:
    """Storage tab (renamed from Disk Health): every physical drive shows its
    slot + serial, and the Storage Spaces section appears iff the machine has a
    pool. Regression gate for PR #147."""

    def _open(self, page):
        page.evaluate("switchTab('disk')")
        for _ in range(25):
            page.wait_for_timeout(300)
            ready = page.evaluate(
                "!!document.getElementById('dk-content') && document.getElementById('dk-content').style.display !== 'none'"
            )
            if ready:
                break

    def test_physical_drive_rows_have_slot_and_serial_columns(self, loaded_page):
        page, _ = loaded_page
        self._open(page)
        # Wait for the physical-drives table to populate.
        for _ in range(20):
            page.wait_for_timeout(300)
            if page.evaluate("document.querySelectorAll('#dk-tbody tr').length"):
                break
        cols = page.evaluate(
            "document.querySelector('#dk-tbody tr') ? document.querySelector('#dk-tbody tr').children.length : 0"
        )
        assert cols == 8, f"expected 8 columns (incl. Serial + Physical slot), got {cols}"

    def test_spaces_section_visibility_tracks_has_spaces(self, loaded_page):
        page, _ = loaded_page
        self._open(page)
        page.wait_for_timeout(1200)  # let dkLoadSpaces fetch + render
        has_spaces = page.evaluate(
            "async () => { const r = await fetch('/api/storage/spaces'); const d = await r.json(); return !!d.has_spaces; }"
        )
        visible = page.evaluate("document.getElementById('dk-spaces-section').style.display !== 'none'")
        assert visible == has_spaces, f"spaces section visible={visible} but has_spaces={has_spaces}"

    def test_nas_section_visibility_tracks_configured(self, loaded_page):
        # The NAS section appears iff nas_config.json has a configured NAS. The
        # /api/storage/nas call does real SNMP, so poll for the render.
        page, _ = loaded_page
        self._open(page)
        configured = page.evaluate(
            "async () => { const r = await fetch('/api/storage/nas'); const d = await r.json(); return d.configured || 0; }"
        )
        visible = None
        for _ in range(24):
            page.wait_for_timeout(500)
            visible = page.evaluate("document.getElementById('dk-nas-section').style.display !== 'none'")
            if visible == (configured > 0):
                break
        assert visible == (configured > 0), f"nas section visible={visible} but configured={configured}"
