// Baseline tab (prefix bl) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// BASELINE / DRIFT TAB (backlog #14, prefix: bl)
// ══════════════════════════════════════════════════════════════════════════

// ── Cross-surface change timeline (backlog #44) ────────────────────────
// Loads independently from loadBaseline() so the timeline shows even
// when there's no current drift (history can have multi-category
// clusters from days ago that still warrant review). Cluster window
// is user-configurable via the <select> in the timeline panel.
function bl_reloadTimeline() { return loadBaselineTimeline(); }

// ── Cluster examine + accept-all (backlog #50) ────────────────────
//
// Each cluster rendered by loadBaselineTimeline is stashed on
// window._blClusterStash by index so the button handlers (which can
// only carry primitive args through onclick="...") can pick the full
// cluster object back up.

window._blClusterStash = [];

async function bl_examineCluster(idx, windowSeconds) {
  const cluster = (window._blClusterStash || [])[idx];
  if (!cluster) { alert("Cluster data not available -- refresh the timeline."); return; }
  // Default to ±15min instead of ±5min: the cluster TIMESTAMP marks
  // when drift was DETECTED, not when the changes actually happened.
  // Changes typically land 5-15 min before the drift check runs. ±5min
  // misses them; ±15min usually catches them. User can widen further
  // via the in-modal selector.
  const ws = Number(windowSeconds) || 900;
  const url = `/api/baseline/cluster-context?started_at=${encodeURIComponent(cluster.started_at)}&ended_at=${encodeURIComponent(cluster.ended_at)}&window=${ws}`;

  // Show the modal overlay IMMEDIATELY with a loading state so the
  // user (and the Playwright test) get instant feedback. The fetch
  // can take 5-10 s on the first call because Microsoft.Update.Session
  // is slow on a cold COM. Replace the modal contents after the fetch
  // resolves. Tear down any prior overlay so a second click doesn't
  // stack overlays.
  const old = document.getElementById("bl-examine-overlay");
  if (old) old.remove();
  const overlay = document.createElement("div");
  overlay.id = "bl-examine-overlay";
  overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px";
  overlay.onclick = e => { if (e.target === overlay) document.body.removeChild(overlay); };
  const modal = document.createElement("div");
  modal.style.cssText = "background:var(--card);border:1px solid var(--cyan);border-radius:10px;padding:20px;max-width:800px;width:100%;max-height:80vh;overflow-y:auto;color:var(--text)";
  modal.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div style="font-size:16px;font-weight:700;color:var(--text-bright)">🔍 What happened around ${escHtml(new Date(cluster.started_at).toLocaleString())}?</div>
      <button onclick="document.body.removeChild(document.getElementById('bl-examine-overlay'))" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 10px;border-radius:4px;cursor:pointer">Close</button>
    </div>
    <div style="padding:30px;text-align:center;color:var(--muted);font-size:12px">
      ⏳ Loading context (Microsoft.Update.Session can take ~5–10s on a cold COM)…
    </div>`;
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  // ESC dismiss
  const esc = ev => { if (ev.key === "Escape") { try { document.body.removeChild(overlay); } catch {} document.removeEventListener("keydown", esc); } };
  document.addEventListener("keydown", esc);

  let data;
  try {
    const r = await fetch(url);
    data = await r.json();
  } catch (e) {
    modal.innerHTML = `<div style="color:var(--red);padding:20px">Cluster examine failed: ${escHtml(e.message)}</div>`;
    return;
  }
  // If the overlay was dismissed mid-fetch, don't try to populate it.
  if (!document.getElementById("bl-examine-overlay")) return;
  if (!data.ok) {
    modal.innerHTML = `<div style="color:var(--red);padding:20px">Cluster examine refused: ${escHtml(data.error || "unknown")}</div>`;
    return;
  }

  // Build the final-state modal contents. The overlay + modal
  // shells were already created up-front (with a loading placeholder)
  // so the user sees instant feedback; now we replace the placeholder
  // with the rendered tables.
  const win = data.window || {};
  const wus = data.windows_updates || [];
  const biosChanges = data.bios_audit_changes || [];
  const wuHistory = data.update_history || [];
  const evtEntries = data.event_log_entries || [];
  const analysis = data.analysis || null;
  const totalSignals = wus.length + biosChanges.length + wuHistory.length + evtEntries.length;

  const wuRows = wus.length
    ? wus.map(u => `<tr><td style="padding:4px 8px;font-family:var(--font-mono);font-size:10px">${escHtml(u.installed_on)}</td><td style="padding:4px 8px;font-weight:600">${escHtml(u.hotfix_id)}</td><td style="padding:4px 8px;color:var(--muted);font-size:11px">${escHtml(u.description)}</td></tr>`).join("")
    : `<tr><td colspan="3" style="padding:8px;color:var(--muted);text-align:center;font-size:10px">(none in window — Get-HotFix only catches legacy hotfixes; check Update history below)</td></tr>`;
  const biosRows = biosChanges.length
    ? biosChanges.map(c => `<tr><td style="padding:4px 8px;font-family:var(--font-mono);font-size:10px">${escHtml(c.timestamp || "")}</td><td style="padding:4px 8px;font-size:11px">${escHtml((c.changes || []).map(x => x.field).join(", ") || "(no fields)")}</td></tr>`).join("")
    : `<tr><td colspan="2" style="padding:8px;color:var(--muted);text-align:center;font-size:10px">(none in window)</td></tr>`;
  const wuHistoryRows = wuHistory.length
    ? wuHistory.map(u => `<tr><td style="padding:4px 8px;font-family:var(--font-mono);font-size:10px">${escHtml(u.date)}</td><td style="padding:4px 8px;font-weight:600;font-size:11px">${escHtml(u.title)}</td><td style="padding:4px 8px;color:var(--muted);font-size:10px">${escHtml(u.result)}</td></tr>`).join("")
    : `<tr><td colspan="3" style="padding:8px;color:var(--muted);text-align:center;font-size:10px">(none in window — Microsoft.Update.Session.QueryHistory returned no events here)</td></tr>`;
  const evtRows = evtEntries.length
    ? evtEntries.map(e => `<tr><td style="padding:4px 8px;font-family:var(--font-mono);font-size:10px">${escHtml(e.time)}</td><td style="padding:4px 8px;font-size:10px;font-weight:600">${escHtml(e.channel)}</td><td style="padding:4px 8px;font-size:10px">${escHtml(String(e.event_id||""))}</td><td style="padding:4px 8px;font-size:10px;color:var(--muted)">${escHtml(e.provider)}</td><td style="padding:4px 8px;font-size:10px;color:var(--text);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(e.message)}">${escHtml(e.message)}</td></tr>`).join("")
    : `<tr><td colspan="5" style="padding:8px;color:var(--muted);text-align:center;font-size:10px">(none — Setup/Application/System logs returned no events in this window)</td></tr>`;

  const noSignalNote = totalSignals === 0
    ? `<div style="padding:12px 14px;background:var(--surface);border:1px solid var(--orange);border-left:4px solid var(--orange);border-radius:6px;font-size:11px;color:var(--text);margin-bottom:14px">
        <strong style="color:var(--orange)">No external signals correlate with this cluster.</strong>
        That doesn't mean nothing happened — it means the four sources I checked (Get-HotFix, BIOS audit, Update Session history, Event Log Setup/Application/System) all came back empty for this window.
        Likely causes: an app installer that doesn't log to Setup/Application channels (e.g. Click-to-Run Office, MSIX apps, portable installers), an admin push (Intune/SCCM), or a manual config change you made yourself.
        Drill into the individual events below by clicking through to the entry-history modal.
      </div>` : "";

  // Analysis banner — pattern-matched "likely cause" headline at the top
  // of the modal. Added 2026-05-28 after user report that they had to
  // widen the window to 4h and scroll through 20 events to find the
  // McAfee install + Windows Update activity by eye. The banner does
  // that pattern-matching automatically; for a stronger signal it
  // colours the left border green/orange/red by severity.
  let analysisBanner = "";
  if (analysis && analysis.has_signals) {
    const sigLevel = (analysis.signals[0] && analysis.signals[0].level) || "info";
    const borderColor = sigLevel === "critical" ? "var(--red)" : sigLevel === "warning" ? "var(--orange)" : "var(--cyan)";
    const otherSignalRows = (analysis.signals || []).slice(1, 6).map(s => {
      const lvlColor = s.level === "critical" ? "var(--red)" : s.level === "warning" ? "var(--orange)" : "var(--muted)";
      const ev = s.evidence || {};
      const ts = ev.time ? `<span style="font-family:var(--font-mono);font-size:10px;color:var(--muted)">${escHtml(ev.time)}</span> · ` : "";
      return `<div style="font-size:11px;padding:2px 0">${ts}<span style="color:${lvlColor};font-weight:600">[${escHtml(s.level)}]</span> ${escHtml(s.summary)}</div>`;
    }).join("");
    const noiseFooter = analysis.noise_filtered > 0
      ? `<div style="font-size:10px;color:var(--muted);margin-top:8px;padding-top:6px;border-top:1px solid var(--border)">${analysis.noise_filtered} benign event(s) filtered (time-sync, Bluetooth, config-monitor noise).</div>`
      : "";
    analysisBanner = `<div style="padding:12px 14px;background:var(--card);border:1px solid var(--border);border-left:4px solid ${borderColor};border-radius:6px;margin-bottom:14px">
        <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">🎯 ${escHtml(analysis.summary_line)}</div>
        ${otherSignalRows ? `<div style="margin-top:8px">${otherSignalRows}</div>` : ""}
        ${noiseFooter}
      </div>`;
  } else if (analysis && analysis.noise_filtered > 0 && totalSignals > 0) {
    // Events exist but they're all noise. Tell the user explicitly.
    analysisBanner = `<div style="padding:12px 14px;background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--muted);border-radius:6px;font-size:11px;color:var(--muted);margin-bottom:14px">
        🎯 ${escHtml(analysis.summary_line)}
      </div>`;
  }

  modal.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div style="font-size:16px;font-weight:700;color:var(--text-bright)">🔍 What happened around ${escHtml(new Date(cluster.started_at).toLocaleString())}?</div>
      <button onclick="document.body.removeChild(document.getElementById('bl-examine-overlay'))" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 10px;border-radius:4px;cursor:pointer">Close</button>
    </div>
    <div style="display:flex;align-items:center;gap:10px;font-size:11px;color:var(--muted);margin-bottom:10px;flex-wrap:wrap">
      <span>Cluster window: ${escHtml(win.started_at)} → ${escHtml(win.ended_at)}</span>
      <span>·</span>
      <span>look back ±</span>
      <select onchange="bl_examineCluster(${idx}, this.value)" style="background:var(--surface);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font-size:11px">
        <option value="300"${ws === 300 ? " selected" : ""}>5 min</option>
        <option value="900"${ws === 900 ? " selected" : ""}>15 min</option>
        <option value="3600"${ws === 3600 ? " selected" : ""}>1 hour</option>
        <option value="14400"${ws === 14400 ? " selected" : ""}>4 hours</option>
        <option value="86400"${ws === 86400 ? " selected" : ""}>24 hours</option>
      </select>
      <span style="color:var(--muted);font-size:10px">(probe: ${escHtml(win.expanded_started)} → ${escHtml(win.expanded_ended)})</span>
    </div>
    <div style="font-size:10px;color:var(--muted);margin-bottom:14px;padding:6px 10px;background:var(--surface);border-radius:4px;line-height:1.4">
      💡 The cluster timestamp marks when DRIFT was DETECTED (you opened the Baseline tab). The actual changes typically happen 5–15 minutes earlier. If the default 15-min window finds nothing, widen the look-back.
    </div>
    ${analysisBanner}
    ${noSignalNote}
    <div style="margin-bottom:16px">
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">📜 Update history (Microsoft.Update.Session) (${wuHistory.length})</div>
      <table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>${wuHistoryRows}</tbody></table>
    </div>
    <div style="margin-bottom:16px">
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">📋 Event Log (Setup/Application/System) (${evtEntries.length})</div>
      <table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>${evtRows}</tbody></table>
    </div>
    <div style="margin-bottom:16px">
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">🩹 Hotfixes (Get-HotFix legacy) (${wus.length})</div>
      <table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>${wuRows}</tbody></table>
    </div>
    <div>
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">🔩 BIOS audit changes (${biosChanges.length})</div>
      <table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>${biosRows}</tbody></table>
    </div>
    <div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--border);font-size:10px;color:var(--muted)">
      Best-effort context. Event Log queries are capped at 20 per channel + 6 s timeout. Drill into individual cluster events from the timeline row to see per-entry investigator output.
    </div>`;
  // No appendChild needed -- overlay + modal were attached up-front
  // with the loading placeholder, and innerHTML replacement updates
  // them in place.
}

async function bl_acceptCluster(idx) {
  const cluster = (window._blClusterStash || [])[idx];
  if (!cluster) { alert("Cluster data not available -- refresh the timeline."); return; }
  // Only what the accepted baseline does not already hold (bug 2026-10-10).
  const events = (cluster.events || []).filter(ev => ev.reconciled !== true).map(ev => ({
    category: ev.category,
    key: ev.key,
    kind: ev.kind,
    // current_value is omitted -- the slow-path accept_drift_entry call
    // re-snapshots to discover the value. Adds latency but keeps the
    // payload small + avoids stale-data bugs.
    current_value: null,
  }));
  if (!events.length) {
    alert((cluster.events || []).length
      ? "Everything in this cluster is already in your baseline -- refresh the timeline."
      : "Cluster has no events.");
    return;
  }
  const n = events.length;
  const expected = `ACCEPT ${n} CHANGES`;
  const typed = window.prompt(
    `Accept all ${n} changes in this cluster?\n\n` +
    `This absorbs every add/remove/change in the cluster into your baseline.\n` +
    `Useful when the cluster represents a known event (Windows Update install, app install).\n\n` +
    `To confirm, type exactly:\n    ${expected}`,
    ""
  );
  if (typed === null) return;
  if (typed !== expected) { alert(`Cancelled: confirmation didn't match "${expected}".`); return; }

  let result;
  try {
    const r = await fetch("/api/baseline/accept-cluster", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({events: events, confirm_token: expected}),
    });
    result = await r.json();
  } catch (e) {
    alert("Accept-cluster failed: " + e.message);
    return;
  }
  // Three-way breakdown (backlog #50, post-incident 2026-05-26):
  // - accepted   : baseline was actually written
  // - no_op      : desired end-state already matched (e.g. removal of
  //                a key that wasn't in baseline, or accept of a key
  //                already in baseline with same value). Idempotent
  //                success.
  // - failed     : true failure -- something needs the user's
  //                attention.
  const accepted = result.accepted || 0;
  const noOp = result.no_op || 0;
  const failed = result.failed || 0;
  const total = accepted + noOp + failed;
  let summary;
  if (failed === 0) {
    summary = noOp > 0
      ? `✅ All ${total} changes resolved.\n   ${accepted} written to baseline · ${noOp} already in desired state (no-op)`
      : `✅ Accepted all ${accepted} of ${total} changes.`;
  } else {
    summary = `Accepted ${accepted} of ${total}` +
      (noOp > 0 ? `, ${noOp} already in desired state` : "") +
      `, ${failed} truly failed.`;
  }
  if (failed > 0 && result.errors && result.errors.length) {
    alert(summary + "\n\nFirst errors:\n" + result.errors.slice(0, 5).map(e => `  ${e.category || ""}: ${e.error}`).join("\n"));
  } else {
    alert(summary);
  }
  // Reload the timeline so the cluster updates (or disappears if all accepted).
  loadBaseline();
}

async function loadBaselineTimeline() {
  // Reset the stash so stale entries from a previous render don't
  // accumulate indefinitely.
  window._blClusterStash = [];
  const section = document.getElementById("bl-timeline-section");
  const body = document.getElementById("bl-timeline-body");
  const subtitle = document.getElementById("bl-timeline-subtitle");
  const sel = document.getElementById("bl-timeline-window");
  if (!section || !body) return;
  const win = parseInt((sel && sel.value) || "300", 10) || 300;
  body.innerHTML = '<div style="color:var(--muted);padding:8px">Loading timeline…</div>';
  section.style.display = "block";
  let data;
  try {
    const r = await fetch("/api/baseline/timeline?window=" + win);
    data = await r.json();
  } catch (e) {
    body.innerHTML = `<div style="color:var(--red);padding:8px">Timeline fetch failed: ${escHtml(e.message)}</div>`;
    return;
  }
  const items = Array.isArray(data && data.timeline) ? data.timeline : [];
  if (!items.length) {
    body.innerHTML = '<div style="color:var(--muted);padding:8px">No baseline-drift history recorded yet. Once drift is detected on the Baseline tab, the timeline will populate.</div>';
    subtitle.textContent = `Cluster window: ${win} s · 0 items`;
    return;
  }
  // Severity → color mapping.
  const sevColor = { info: "var(--muted)", warning: "var(--orange)", critical: "var(--red)" };
  // Cluster + event counts for the subtitle.
  const clusters = items.filter(x => x.type === "cluster").length;
  const lone = items.filter(x => x.type === "event").length;
  // Clusters the accepted baseline already holds stay listed (the history)
  // but are no longer offered for accepting (bug 2026-10-10).
  const toReview = items.filter(x => x.reconciled !== true).length;
  subtitle.textContent = `Cluster window: ${win} s · ${clusters} cluster(s), ${lone} lone event(s) · ${toReview} to review`;
  // Render newest-first (API already returns that order).
  const html = items.map(it => {
    if (it.type === "cluster") {
      const done = it.reconciled === true;
      const open = Number.isFinite(it.open_count) ? it.open_count : (it.event_count || 0);
      const color = done ? sevColor.info : (sevColor[it.severity] || sevColor.info);
      const catLabel = (it.categories || []).join(", ");
      const span = it.span_seconds;
      const spanLabel = span >= 1 ? `${Math.round(span)} s` : "simultaneous";
      const headLine = `${it.event_count || 0} events across ${(it.categories || []).length} categories in ${spanLabel}`;
      const startedAt = it.started_at ? new Date(it.started_at).toLocaleString() : "—";
      const eventRows = (it.events || []).map(ev => `
        <div style="padding:4px 8px;border-left:2px solid ${color};margin:2px 0 2px 14px;font-size:11px;color:var(--text)">
          ${ev.reconciled === true && !done ? '<span style="color:var(--green)" title="Already in the baseline">✓</span> ' : ""}<span style="color:var(--muted);font-family:var(--font-mono);font-size:10px">${escHtml(ev.timestamp || "")}</span>
          &nbsp;·&nbsp;
          <span style="font-weight:600">${escHtml(ev.category || "")}</span>
          <span style="color:var(--muted)">${escHtml(ev.kind || "")}</span>
          : ${escHtml(ev.name || ev.key || "")}
          ${ev.delta && ev.delta.length ? `<span style="color:var(--muted);font-size:10px"> (${escHtml(ev.delta.join(", "))})</span>` : ""}
        </div>`).join("");
      // Stash the cluster on a global keyed by index so the Examine/Accept
      // button handlers can pick it back up. JSON.stringify would round-trip
      // but adds escaping nightmares for nested quotes; a global is simpler.
      const idx = window._blClusterStash.push(it) - 1;
      return `
        <div data-bl-cluster data-reconciled="${done ? "true" : "false"}" style="margin:8px 0;padding:8px 10px;background:var(--surface);border:1px solid ${color};border-left:4px solid ${color};border-radius:6px${done ? ";opacity:0.75" : ""}">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px">
            <div>
              <span style="font-weight:700;color:${color};text-transform:uppercase;font-size:10px">${escHtml(it.severity || "info")}</span>
              <span style="font-weight:600;color:var(--text-bright);margin-left:6px">Cluster · ${escHtml(headLine)}</span>
            </div>
            <div style="color:var(--muted);font-size:10px;font-family:var(--font-mono)">${escHtml(startedAt)}</div>
          </div>
          <div style="color:var(--muted);font-size:11px;margin-bottom:6px">Categories: ${escHtml(catLabel)}</div>
          <div style="display:flex;gap:6px;margin-bottom:6px">
            <button onclick="bl_examineCluster(${idx})" style="background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px">🔍 Examine</button>
            ${done
              ? '<span style="color:var(--green);border:1px solid var(--green);padding:3px 10px;border-radius:4px;font-size:11px" title="Your accepted baseline already includes every change in this cluster">✓ In baseline</span>'
              : `<button onclick="bl_acceptCluster(${idx})" style="background:var(--cyan);border:none;color:#000;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">✓ Accept all ${open}</button>`}
          </div>
          ${eventRows}
        </div>`;
    }
    // Lone event
    const ts = it.timestamp ? new Date(it.timestamp).toLocaleString() : "—";
    return `
      <div style="margin:4px 0;padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;display:flex;align-items:center;gap:10px">
        <span style="color:var(--muted);font-family:var(--font-mono);font-size:10px;min-width:140px">${escHtml(ts)}</span>
        <span style="font-weight:600;font-size:11px">${escHtml(it.category || "")}</span>
        <span style="color:var(--muted);font-size:11px">${escHtml(it.kind || "")}</span>
        <span style="font-size:11px;color:var(--text);flex:1">${escHtml(it.name || it.key || "")}</span>
        ${it.delta && it.delta.length ? `<span style="color:var(--muted);font-size:10px">(${escHtml(it.delta.join(", "))})</span>` : ""}
      </div>`;
  }).join("");
  body.innerHTML = html;
}


async function loadBaseline() {
  const loading    = document.getElementById("bl-loading");
  const nobaseline = document.getElementById("bl-nobaseline");
  const nodrift    = document.getElementById("bl-nodrift");
  const content    = document.getElementById("bl-drift-content");
  const acceptBtn  = document.getElementById("bl-accept-btn");
  if (!loading) return;
  // Kick off the timeline load in parallel with drift fetch. Timeline
  // is independent (reads history file, never blocks on snapshot).
  loadBaselineTimeline();

  loading.style.display    = "block";
  nobaseline.style.display = "none";
  nodrift.style.display    = "none";
  content.style.display    = "none";
  acceptBtn.style.display  = "none";
  const migBanner = document.getElementById("bl-migration-banner");
  if (migBanner) { migBanner.style.display = "none"; migBanner.removeAttribute("data-migration-fields"); }
  // Inventory cache invalidation. Two paths:
  //   - Inventory currently HIDDEN: just null the cache; next "Show inventory"
  //     click re-fetches lazily (the original behaviour).
  //   - Inventory currently VISIBLE: keep the cache populated through the
  //     reload so the user's open rows continue to work. Otherwise their
  //     click handlers would race against loadBaseline's null-then-refetch
  //     window and surface the "Item data missing from cache" error
  //     (reported 2026-04-25 -- happens whenever loadBaseline runs
  //     between the user opening the inventory and clicking a row, e.g.
  //     after a tab switch or auto-refresh).
  const invBody = document.getElementById("bl-inv-body");
  const invToggle = document.getElementById("bl-inv-toggle");
  const inventoryVisible = invBody && invBody.style.display !== "none";
  if (!inventoryVisible) {
    _blInventoryCache = null;
    _blInventoryDrift = null;
    if (invBody) invBody.style.display = "none";
    if (invToggle) invToggle.textContent = "Show inventory";
  }
  // If inventoryVisible, we'll refresh cache + re-render after the drift
  // fetch lands below (so the new banner / drift state can land first).

  let data;
  try {
    const r = await fetch("/api/baseline/drift");
    data = await r.json();
  } catch (e) {
    loading.innerHTML = `<div style="color:var(--red);padding:20px">Drift check failed: ${e.message}</div>`;
    return;
  }
  loading.style.display = "none";

  // First-run: no baseline exists yet. Show the capture prompt with a
  // preview of what we'd be capturing so the user knows the scale.
  if (!data.has_baseline) {
    const c = data.counts || {};
    document.getElementById("bl-initial-counts").textContent =
      `${c.startup || 0} startup items · ${c.services || 0} services · ${c.tasks || 0} scheduled tasks`;
    nobaseline.style.display = "block";
    return;
  }

  const drift = data.drift || {};
  const total = drift.total_changes || 0;

  // Always offer the re-accept button once a baseline exists so legit
  // changes (Windows Update, new app install) can be absorbed quickly.
  acceptBtn.style.display = "";
  // Bottom-mirrored Accept button (backlog #50) -- show/hide in sync
  // with the top one so a user who reads top-to-bottom finds the
  // action without scrolling back up.
  const bottomActions = document.getElementById("bl-bottom-actions");
  if (bottomActions) bottomActions.style.display = "";

  // Schema-migration banner: fires when the collector started tracking
  // a field after the baseline was captured. Without this, the user
  // sees "—" in the Previous column for rows like logon_mode and has
  // no idea why. The banner explains + nudges them to re-accept so
  // real drift detection resumes on those fields.
  const migFields = Array.isArray(data.schema_migration_fields) ? data.schema_migration_fields : [];
  if (migBanner && migFields.length) {
    migBanner.dataset.migrationFields = migFields.join(",");
    migBanner.style.display = "";
    migBanner.innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px">
        <div style="font-size:16px;line-height:1">🔄</div>
        <div style="flex:1">
          <div style="font-weight:700;color:var(--cyan);margin-bottom:4px">Tracking system upgraded</div>
          <div style="color:var(--text);margin-bottom:6px">
            ${migFields.length} new parameter${migFields.length !== 1 ? "s" : ""}
            (<code style="font-size:11px;background:var(--surface);padding:1px 4px;border-radius:3px">${escHtml(migFields.join(", "))}</code>)
            ${migFields.length !== 1 ? "are" : "is"} now tracked, but ${migFields.length !== 1 ? "they" : "it"} weren't part of your existing baseline — that's why the <strong>Previous</strong> column shows <strong>—</strong> for those rows.
          </div>
          <div style="color:var(--muted);font-size:11px">
            Click <strong>Accept current as baseline</strong> (top right) to capture these fields into the baseline so future changes are detected normally.
          </div>
        </div>
      </div>`;
  }

  if (total === 0) {
    nodrift.style.display = "";
    document.getElementById("bl-nodrift-detail").textContent =
      `Baseline: ${data.baseline_timestamp || "—"}  ·  Current: ${data.current_timestamp}`;
    return;
  }

  // Summary header
  const baselineTs = data.baseline_timestamp ? new Date(data.baseline_timestamp).toLocaleString() : "—";
  document.getElementById("bl-summary").innerHTML = `
    <div style="display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap">
      <div>
        <div data-bl-total style="font-size:14px;font-weight:700;color:var(--orange)">⚠ ${total} change${total!==1?"s":""} detected vs baseline</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Baseline accepted: ${escHtml(baselineTs)}</div>
      </div>
      <div style="font-size:11px;color:var(--muted)">
        Review each change below. Click "Accept current as baseline" to promote the current state once you've confirmed these are legitimate.
      </div>
    </div>`;

  // Render each category section. Each category has its own column plan:
  // the order of tracked fields shown in the Parameter|Previous|Current
  // table, and the subset of those that are "diff-critical" (highlighted
  // in orange when changed -- these mirror baseline.py's _DIFF_FIELDS).
  _blRenderCategory("bl-cat-startup",  "Startup Items",    "🚀", drift.startup,  _BL_CATS.startup);
  _blRenderCategory("bl-cat-services", "Windows Services", "⚙",  drift.services, _BL_CATS.services);
  _blRenderCategory("bl-cat-tasks",    "Scheduled Tasks",  "⏱",  drift.tasks,    _BL_CATS.tasks);

  content.style.display = "";

  // If the user had the Inventory section open before this reload, refresh
  // its cache + re-render so their open rows continue to work. Without this
  // the "Item data missing from cache" error fires on row clicks (the rows
  // were rendered against a snapshot that just got invalidated).
  if (inventoryVisible) {
    try {
      const [snap, drift2] = await Promise.all([
        fetch("/api/baseline/snapshot").then(r => r.json()),
        fetch("/api/baseline/drift").then(r => r.json()),
      ]);
      _blInventoryCache = snap.snapshot || snap;
      _blInventoryDrift = drift2.drift || {};
      blRenderInventory();
    } catch (e) {
      // Non-fatal -- the row click handler will retry the fetch on miss.
    }
  }
}

// Per-category field layout for the Parameter|Previous|Current table.
// ``fields`` is the ordered list of parameters shown as rows. ``critical``
// is the subset that baseline.py actually diffs on -- any difference here
// is real drift (the other fields are context the user wants to see).
// ``remediation`` is the guidance block shown below each drift entry:
//   console_label -- button text ("Open Task Scheduler")
//   console_hint  -- short one-liner under the button
//   steps         -- ordered list of manual steps for the user
const _BL_CATS = {
  startup: {
    fields:   ["name", "location", "type", "enabled", "command"],
    critical: ["command", "enabled"],
    remediation: {
      console_label: "Open Task Manager (Startup tab)",
      console_hint:  "Right-click the entry and choose Disable, or uninstall the originating app.",
      steps: [
        "Click the button above to open Task Manager.",
        "Switch to the Startup apps tab.",
        "Find the entry matching the Name shown in the table.",
        "If it's unexpected, select it and click Disable.",
        "If it's a legitimate change you want to keep, come back here and click 'Accept current as baseline' to absorb it.",
      ],
    },
  },
  services: {
    // Full set: psutil + WMI Win32_Service enrichment. 13 fields.
    fields: [
      "name", "display_name", "description",
      "status", "start_mode", "delayed_auto_start",
      "username", "image_path",
      "service_type", "error_control",
      "desktop_interact", "tag_id", "started",
    ],
    critical: ["start_mode", "image_path", "username", "service_type", "error_control", "delayed_auto_start", "desktop_interact"],
    remediation: {
      console_label: "Open services.msc",
      console_hint:  "Use the Services console to inspect, stop, or change startup type.",
      steps: [
        "Click the button above to open the Services console.",
        "Sort by Name and locate the service shown in the table.",
        "Double-click to inspect its Startup type, Log On account, and Path to executable.",
        "If a critical field (Startup type / Path / Log On As) was changed unexpectedly, revert it via the dialog.",
        "If the change is legitimate (Windows Update, new software install), come back here and click 'Accept current as baseline' to absorb it.",
      ],
    },
  },
  tasks: {
    // Full set: every schtasks /v column except redundant HostName/Status. 26 fields.
    fields: [
      // Identity
      "name", "path",
      // State
      "state", "author", "run_as", "logon_mode",
      // What it runs
      "image_path", "start_in", "comment",
      // When it runs
      "schedule", "schedule_type", "start_time", "start_date", "end_date",
      "days", "months",
      "repeat_every", "repeat_until_time", "repeat_until_duration", "repeat_stop_if_running",
      // Behaviour flags
      "idle_time", "power_management", "delete_if_not_rescheduled", "stop_if_runs_x_hours",
      // Run history
      "last_run_time", "last_result", "next_run_time",
    ],
    critical: ["state", "image_path", "run_as", "logon_mode", "start_in", "schedule_type"],
    remediation: {
      console_label: "Open Task Scheduler",
      console_hint:  "Navigate to the task's folder path and inspect Actions / Triggers / General.",
      steps: [
        "Click the button above to open Task Scheduler.",
        "In the left pane, navigate to the folder shown under 'path' (e.g. \\Microsoft\\Windows\\Printing).",
        "Right-click the task and choose Properties.",
        "Compare the task's Actions, Triggers, and General tabs against the Previous column above.",
        "To re-enable a disabled task: right-click -> Enable. To revert an edited task: re-open Properties and restore the original fields.",
        "If the change is legitimate, come back here and click 'Accept current as baseline' to absorb it.",
      ],
    },
  },
};

// Stable key for "what category does this element belong to" -- passed
// into _blRenderCategory so we can wire up the remediation block.
const _BL_CAT_KEYS = {
  "bl-cat-startup":  "startup",
  "bl-cat-services": "services",
  "bl-cat-tasks":    "tasks",
};

// Helper: render one drift category (added/removed/changed lists) into
// ``elId`` or hide the section if nothing changed for this category.
function _blRenderCategory(elId, label, icon, catDrift, cfg) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (!catDrift) { el.style.display = "none"; return; }
  const added   = catDrift.added   || [];
  const removed = catDrift.removed || [];
  const changed = catDrift.changed || [];
  if (added.length + removed.length + changed.length === 0) {
    el.style.display = "none";
    return;
  }
  el.style.display = "";

  let html = `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 18px">
      <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:10px">
        <div style="font-size:16px">${icon}</div>
        <div style="font-size:13px;font-weight:700;color:var(--text-bright)">${escHtml(label)}</div>
        <div data-bl-cat-counts style="font-size:10px;color:var(--muted);font-family:var(--font-mono)">
          +${added.length} added · -${removed.length} removed · ~${changed.length} changed
        </div>
      </div>`;

  const catKey = _BL_CAT_KEYS[elId] || "";

  if (added.length) {
    html += `<div style="margin:8px 0 4px;font-size:11px;color:var(--green);font-weight:700">＋ Added (${added.length})</div>`;
    // For added entries: Previous column is —, Current column carries the value.
    html += added.map(item =>
      _blRenderEntry(item, /*old*/ null, /*new*/ item, /*delta*/ null, cfg, catKey, "added", "var(--green)")
    ).join("");
  }
  if (removed.length) {
    html += `<div style="margin:10px 0 4px;font-size:11px;color:var(--red);font-weight:700">− Removed (${removed.length})</div>`;
    // For removed entries: Previous column carries the value, Current is —.
    html += removed.map(item =>
      _blRenderEntry(item, /*old*/ item, /*new*/ null, /*delta*/ null, cfg, catKey, "removed", "var(--red)")
    ).join("");
  }
  if (changed.length) {
    html += `<div style="margin:10px 0 4px;font-size:11px;color:var(--orange);font-weight:700">~ Changed (${changed.length})</div>`;
    html += changed.map(item =>
      _blRenderEntry(item, item.old || {}, item.new || {}, item.delta || [], cfg, catKey, "changed", "var(--orange)")
    ).join("");
  }

  html += `</div>`;
  el.innerHTML = html;
}

// Render one drift entry as a 3-column table: Parameter | Previous | Current.
//   old     -- object whose fields populate the Previous column (null => —)
//   new     -- object whose fields populate the Current column  (null => —)
//   delta   -- array of field names that changed (only for "changed" kind).
//              null for added/removed. Used to highlight diff-critical rows
//              where the value actually differs.
//   cfg     -- {fields, critical, remediation} for this category (see _BL_CATS).
//   catKey  -- category id ("startup"/"services"/"tasks") used by the
//              launch-console button to tell the backend which MMC to open.
//   kind    -- "added" | "removed" | "changed" — tunes the explainer prose.
function _blRenderEntry(header, oldObj, newObj, delta, cfg, catKey, kind, accent) {
  const title = escHtml(header.name || header.key || "");
  const subtitle = header.location || header.path || "";

  const deltaSet = new Set(delta || []);
  const critSet = new Set(cfg.critical || []);

  const rows = cfg.fields.map(f => {
    const oldVal = oldObj ? oldObj[f] : null;
    const newVal = newObj ? newObj[f] : null;
    // Treat undefined/null/"" all as "—" visually; differs() cares about
    // the raw pair so "" vs null don't light up as drift.
    const oldDisp = (oldObj == null || oldVal === undefined || oldVal === null || oldVal === "") ? "—" : String(oldVal);
    const newDisp = (newObj == null || newVal === undefined || newVal === null || newVal === "") ? "—" : String(newVal);

    // A row highlights in orange only when (a) this is a Changed entry,
    // (b) the field actually differs (backend's delta array says so), and
    // (c) it's one of the diff-critical fields. Context rows that happen
    // to carry different values (e.g. ``status`` flip) stay neutral.
    const isDiff = deltaSet.has(f);
    const isCrit = critSet.has(f);
    const rowBg   = isDiff ? "background:rgba(255,165,0,0.08)" : "";
    const paramColor = isCrit ? "color:var(--cyan)" : "color:var(--muted)";
    const prevColor = isDiff ? "color:var(--muted);text-decoration:line-through" : "color:var(--text)";
    const curColor  = isDiff ? "color:var(--orange);font-weight:700" : "color:var(--text)";

    return `<tr style="${rowBg}">
      <td style="padding:3px 8px;font-family:var(--font-mono);font-size:10px;${paramColor};white-space:nowrap;vertical-align:top">${escHtml(f)}</td>
      <td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;${prevColor};word-break:break-all;vertical-align:top">${escHtml(oldDisp)}</td>
      <td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;${curColor};word-break:break-all;vertical-align:top">${escHtml(newDisp)}</td>
    </tr>`;
  }).join("");

  // Remediation block -- "what to do about this drift" with a button that
  // opens the relevant Windows console. We show it on changed/added entries
  // where the user most likely wants to act; on removed entries the usual
  // remediation is "confirm the uninstall was intentional" so we soften the
  // wording but still offer the console as a verification jumping-off point.
  const rem = cfg.remediation || {};
  const kindExplainer = {
    added:   `<strong style="color:var(--green)">New entry</strong> appeared after the baseline was captured. If you installed software or enabled a feature recently this is expected; otherwise investigate.`,
    removed: `<strong style="color:var(--red)">Entry is gone</strong> since the baseline was captured. If you uninstalled something recently this is expected; otherwise it may have been tampered with.`,
    changed: `<strong style="color:var(--orange)">Tracked field(s) changed</strong> on an existing entry. Highlighted rows above show exactly what flipped. Verify the change is legitimate.`,
  }[kind] || "";
  const stepsHtml = (rem.steps || []).map(s => `<li style="margin:2px 0">${escHtml(s)}</li>`).join("");
  // Investigation panel: hidden until the user clicks "Why did this change?"
  // The panel id is built from the entry key (hashed for HTML safety) so each
  // drift entry has its own slot. Click handler fetches /api/baseline/
  // investigate, then renders path safety + recent updates + recommendation.
  const entryKey = header.key || header.mac || header.name || "";
  const investigateId = `bl-invest-${_blHashKey(entryKey + ":" + catKey)}`;
  const remediationHtml = `
    <div style="margin-top:8px;padding:8px 10px;background:var(--card);border:1px dashed var(--border);border-radius:4px;font-size:11px">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:4px">How to fix</div>
      <div style="color:var(--text);margin-bottom:6px">${kindExplainer}</div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0 6px">
        ${rem.console_label ? `<button onclick="blLaunchConsole('${escJsArg(catKey)}', this)" style="background:var(--cyan);border:none;color:#000;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">🔧 ${escHtml(rem.console_label)}</button>` : ""}
        <button onclick="blInvestigateDrift('${escJsArg(catKey)}', '${escJsArg(entryKey)}', '${investigateId}', this)" style="background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">🔍 Why did this change?</button>
        <button onclick="blAcceptThisChange(this)" title="Update the baseline for THIS entry only -- leaves all other drift untouched" style="background:var(--green);border:none;color:#000;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">✓ Accept this change</button>
        ${rem.console_hint ? `<span style="font-size:10px;color:var(--muted)">${escHtml(rem.console_hint)}</span>` : ""}
      </div>
      <div id="${investigateId}" class="bl-investigation" data-investigation-key="${escHtml(entryKey)}" style="display:none;margin:6px 0;padding:8px 10px;background:var(--surface);border-left:3px solid var(--cyan);border-radius:4px"></div>
      ${stepsHtml ? `<ol style="margin:4px 0 0 18px;padding:0;color:var(--text);font-size:11px;line-height:1.5">${stepsHtml}</ol>` : ""}
    </div>`;

  // data-drift-* attributes let Playwright tests introspect the rendered
  // drift entries without parsing visible text: category = startup/services/
  // tasks, kind = added/removed/changed, row-count = number of parameter
  // rows rendered (should equal _BL_CATS[cat].fields.length).
  //
  // data-drift-current-value carries the JSON-encoded "new" snapshot of
  // the entry so blAcceptThisChange() can fast-path the per-entry accept
  // without forcing the backend to re-snapshot the whole system. For
  // "removed" entries there's no current value (it's gone) so we skip it.
  const currentForAccept = (kind === "removed") ? null
    : (newObj && Object.keys(newObj).length ? newObj : (header.image_path !== undefined ? header : null));
  const cvAttr = currentForAccept
    ? ` data-drift-current-value="${escHtml(JSON.stringify(currentForAccept))}"`
    : "";
  return `<div class="bl-entry" data-drift-category="${escHtml(catKey)}" data-drift-kind="${escHtml(kind)}" data-drift-key="${escHtml(entryKey)}" data-drift-rows="${cfg.fields.length}"${cvAttr} style="padding:8px 10px;margin:4px 0;background:var(--surface);border-left:2px solid ${accent};border-radius:4px">
    <div onclick="openBaselineEntryDrilldown('${escJsArg(catKey)}', '${escJsArg(entryKey)}')" title="Click for full-screen detail (parameter table, investigation, history)" style="font-weight:600;font-size:12px;color:var(--text-bright);cursor:pointer;display:inline-flex;align-items:center;gap:6px" onmouseover="this.style.color='var(--cyan)'" onmouseout="this.style.color='var(--text-bright)'">${title} <span style="font-size:10px;color:var(--muted);font-weight:400">🔍</span></div>
    ${subtitle ? `<div style="font-size:10px;color:var(--muted);font-family:var(--font-mono);margin-bottom:4px">${escHtml(subtitle)}</div>` : ""}
    <table class="bl-param-table" style="width:100%;border-collapse:collapse;margin-top:4px">
      <thead>
        <tr style="border-bottom:1px solid var(--border)">
          <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Parameter</th>
          <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Previous</th>
          <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Current</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    ${remediationHtml}
  </div>`;
}

// Launch a Windows console (services.msc, taskschd.msc, taskmgr.exe) for the
// given drift category. Called from the "How to fix" block's button. Disables
// the button while the request is in flight so rapid double-click doesn't
// spawn two consoles.
async function blLaunchConsole(category, btn) {
  if (btn) { btn.disabled = true; const orig = btn.innerHTML; btn.innerHTML = "Opening..."; btn.dataset.orig = orig; }
  try {
    const r = await fetch("/api/baseline/launch_console", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({category}),
    });
    const data = await r.json();
    if (!data.ok) alert("Failed to open console: " + (data.error || "unknown"));
  } catch (e) {
    alert("Failed to open console: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig || btn.innerHTML; }
  }
}

// Per-entry baseline accept (user feedback 2026-04-28). Updates only THIS
// drift entry in the baseline -- leaves all other drift untouched.
//
// Performance update (2026-04-28 round 2): user reported "feels like a
// full rescan" because the backend was take_snapshot()-ing AND the UI
// was loadBaseline()-ing afterwards (two ~30s calls). Now:
//   - Reads kind + current_value from the entry's data-drift-* attrs
//     (the UI already has them from the drift response)
//   - Posts them to the backend, which fast-paths the baseline write
//     in ~10ms (no take_snapshot)
//   - Optimistically removes the entry div from the DOM and updates the
//     category counts INSTEAD of triggering a full loadBaseline reload
// User now sees the entry vanish in <100ms.
async function blAcceptThisChange(btn) {
  const entryEl = btn.closest(".bl-entry");
  if (!entryEl) return;
  const category = entryEl.dataset.driftCategory;
  const key = entryEl.dataset.driftKey;
  const kind = entryEl.dataset.driftKind;
  let currentValue = null;
  if (entryEl.dataset.driftCurrentValue) {
    try { currentValue = JSON.parse(entryEl.dataset.driftCurrentValue); }
    catch (e) { currentValue = null; }
  }

  // No confirm() prompt -- the user explicitly clicked ✓ Accept this change
  // on a specific drift entry, that's enough intent. The button changes
  // to "Accepting..." for visual feedback during the brief network call,
  // and the optimistic-removal animation makes the result obvious.
  // (Removed 2026-04-28: user feedback "no need to add an additional pop
  // up window" -- the global Accept-all button still has its confirm.)
  if (btn) { btn.disabled = true; const orig = btn.innerHTML; btn.innerHTML = "Accepting..."; btn.dataset.orig = orig; }
  try {
    const r = await fetch("/api/baseline/accept_entry", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({category, key, kind, current_value: currentValue}),
    });
    const data = await r.json();
    if (!data.ok) {
      alert("Accept failed: " + (data.error || "unknown"));
      return;
    }
    // Optimistic UI: fade + remove the entry without re-fetching everything.
    _blRemoveAcceptedEntry(entryEl, category);
  } catch (e) {
    alert("Accept failed: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig || btn.innerHTML; }
  }
}

// Optimistic removal: fade the just-accepted entry out of the DOM and
// decrement the category's count + the global "N changes detected" badge.
// Avoids a full loadBaseline() round-trip (~30s with snapshot calls).
function _blRemoveAcceptedEntry(entryEl, category) {
  if (!entryEl) return;
  // CSS fade-out then remove
  entryEl.style.transition = "opacity 0.25s ease, max-height 0.4s ease, padding 0.25s ease, margin 0.25s ease";
  entryEl.style.maxHeight = entryEl.offsetHeight + "px";
  // Force reflow so the transition starts from current height
  void entryEl.offsetHeight;
  entryEl.style.opacity = "0";
  entryEl.style.maxHeight = "0";
  entryEl.style.paddingTop = "0";
  entryEl.style.paddingBottom = "0";
  entryEl.style.marginTop = "0";
  entryEl.style.marginBottom = "0";
  entryEl.style.overflow = "hidden";
  setTimeout(() => {
    entryEl.remove();
    // Update the category card's sub-header counts if it's still on screen.
    // Cheap re-query: count remaining .bl-entry under each section, then
    // re-emit the "+N added · -N removed · ~N changed" line. If the
    // category has zero entries after this, hide the entire section.
    const section = document.getElementById(`bl-cat-${category}`);
    if (section) {
      const remaining = section.querySelectorAll(".bl-entry").length;
      if (remaining === 0) {
        section.style.display = "none";
      } else {
        const subEl = section.querySelector("[data-bl-cat-counts]");
        if (subEl) {
          const added = section.querySelectorAll(".bl-entry[data-drift-kind='added']").length;
          const removed = section.querySelectorAll(".bl-entry[data-drift-kind='removed']").length;
          const changed = section.querySelectorAll(".bl-entry[data-drift-kind='changed']").length;
          subEl.textContent = `+${added} added · -${removed} removed · ~${changed} changed`;
        }
      }
    }
    // Update the top "N change(s) detected vs baseline" badge if all
    // visible entries are gone.
    const allRemaining = document.querySelectorAll("#bl-drift-content .bl-entry").length;
    const summary = document.getElementById("bl-summary");
    if (allRemaining === 0) {
      // Switch to the "no drift" state without a full reload
      const content = document.getElementById("bl-drift-content");
      const nodrift = document.getElementById("bl-nodrift");
      if (content) content.style.display = "none";
      if (nodrift) nodrift.style.display = "";
    } else if (summary) {
      const badge = summary.querySelector("[data-bl-total]");
      if (badge) badge.textContent = `⚠ ${allRemaining} change${allRemaining !== 1 ? "s" : ""} detected vs baseline`;
    }
  }, 280);
}

// "Why did this change?" investigator. Fetches /api/baseline/investigate
// for the given drift entry and renders the result inline in the per-entry
// `panelId` div. Toggles the panel closed on a second click. Caches the
// fetch result in a data attribute so re-toggling is instant.
async function blInvestigateDrift(category, key, panelId, btn) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  // Toggle closed if already open
  if (panel.style.display !== "none") {
    panel.style.display = "none";
    if (btn) btn.innerHTML = "🔍 Why did this change?";
    return;
  }

  // Show panel + loading state
  panel.style.display = "";
  panel.innerHTML = `<div style="font-size:11px;color:var(--muted)">🔍 Investigating change…</div>`;
  if (btn) { btn.disabled = true; const orig = btn.innerHTML; btn.innerHTML = "Investigating..."; btn.dataset.orig = orig; }

  try {
    const r = await fetch("/api/baseline/investigate", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({category, key}),
    });
    const data = await r.json();
    if (!data.ok) {
      panel.innerHTML = `<div style="color:var(--red);font-size:11px">${escHtml(data.error || "investigation failed")}</div>`;
      return;
    }
    panel.innerHTML = _blRenderInvestigation(data.investigation);
  } catch (e) {
    panel.innerHTML = `<div style="color:var(--red);font-size:11px">Failed to investigate: ${escHtml(e.message)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = "🔍 Hide investigation";
    }
  }
}

// Render the investigation API response into a compact HTML report.
// Sections (most-actionable first):
//   - Recommendation badge + explanation
//   - Direct evidence: install event (Event 7045 / 106) -- when present,
//     this is the strongest signal (timestamp + installer-user)
//   - Digital signature status
//   - Matched recent software install (correlation)
//   - Path-safety classification
//   - Recent Windows Updates context
//   - Inferred cause label
function _blRenderInvestigation(inv) {
  if (!inv) return `<div style="color:var(--muted);font-size:11px">no investigation data</div>`;

  const sevColor = {
    "trusted": "var(--green)",
    "standard": "var(--cyan)",
    "user-app": "var(--yellow)",
    "suspicious": "var(--red)",
    "unknown": "var(--muted)",
  };
  const recColor = {
    "likely_safe": "var(--green)",
    "review": "var(--yellow)",
    "investigate": "var(--red)",
  };
  const recIcon = { "likely_safe": "✓", "review": "?", "investigate": "!" };

  const ps = inv.path_safety || {};
  const psColor = sevColor[ps.severity] || "var(--muted)";
  const recCol = recColor[inv.recommendation] || "var(--muted)";
  const recIc = recIcon[inv.recommendation] || "?";

  // ── Direct evidence: install event ──────────────────────────────
  let installEventHtml = "";
  if (inv.install_event) {
    const ev = inv.install_event;
    const ts = (ev.timestamp || "").replace("T", " ").slice(0, 19) || "(unknown time)";
    const installer = ev.installed_by || ev.account_name || "(unknown user)";
    const evImagePath = ev.image_path ? ` · <code style="font-size:10px">${escHtml(ev.image_path)}</code>` : "";
    installEventHtml = `
      <div style="margin-top:8px;padding:6px 8px;background:rgba(0,255,128,0.04);border-left:2px solid var(--green);border-radius:3px">
        <div style="font-size:9px;color:var(--green);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:3px">📋 Direct evidence — install event found</div>
        <div style="font-size:11px;color:var(--text)">Installed <strong>${escHtml(ts)}</strong> by <strong>${escHtml(installer)}</strong>${evImagePath}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px">Source: Windows Event Log (Event ${inv.kind === "added" && inv.key && inv.key.startsWith("\\") ? "106 / TaskScheduler" : "7045 / SCM"})</div>
      </div>`;
  }

  // ── Digital signature ──────────────────────────────────────────
  let sigHtml = "";
  if (inv.signature && inv.signature.status && inv.signature.status !== "skipped" && inv.signature.status !== "no_path" && inv.signature.status !== "not_pe") {
    const sig = inv.signature;
    const sigBg = sig.valid ? "var(--green)" : "var(--yellow)";
    const sigLabel = sig.valid ? "✓ Signed" : `⚠ ${escHtml(sig.status)}`;
    const signerLine = sig.signer
      ? `<span style="color:var(--text)">Signer: <strong>${escHtml(sig.signer)}</strong></span>`
      : `<span style="color:var(--muted)">No signer info</span>`;
    sigHtml = `
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px;font-size:11px">
        <span style="background:${sigBg};color:#000;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600">${sigLabel}</span>
        ${signerLine}
      </div>`;
  }

  // ── Matched software install ───────────────────────────────────
  let installMatchHtml = "";
  if (inv.matched_install) {
    const mi = inv.matched_install;
    installMatchHtml = `
      <div style="margin-top:8px;padding:6px 8px;background:rgba(0,200,255,0.04);border-left:2px solid var(--cyan);border-radius:3px">
        <div style="font-size:9px;color:var(--cyan);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:3px">🔗 Matched recent software install</div>
        <div style="font-size:11px;color:var(--text)">
          <strong>${escHtml(mi.name || "?")}</strong>
          ${mi.publisher ? ` <span style="color:var(--muted)">by ${escHtml(mi.publisher)}</span>` : ""}
          — installed ${escHtml((mi.install_date || "").slice(0, 10))}
        </div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px">Match reason: ${escHtml(mi.match_reason || "")}</div>
      </div>`;
  }

  // ── Recent Windows Updates context ─────────────────────────────
  let updatesHtml = "";
  if ((inv.recent_updates || []).length) {
    updatesHtml = `
      <div style="margin-top:8px">
        <div style="font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:3px">Recent Windows Updates (last 7d)</div>
        <ul style="margin:2px 0 0 16px;padding:0;font-size:11px;color:var(--text)">
          ${inv.recent_updates.slice(0, 3).map(u => `<li>${escHtml(u.id)} — ${escHtml((u.installed || "").slice(0, 10))}${u.description ? ` <span style="color:var(--muted)">(${escHtml(u.description)})</span>` : ""}</li>`).join("")}
        </ul>
      </div>`;
  }

  // ── Recent software installs (only if NO single match found) ───
  let recentInstallsHtml = "";
  if (!inv.matched_install && (inv.recent_installs || []).length) {
    const li = inv.recent_installs.slice(0, 3);
    recentInstallsHtml = `
      <div style="margin-top:8px">
        <div style="font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:3px">Recent software installs (last 14d)</div>
        <ul style="margin:2px 0 0 16px;padding:0;font-size:11px;color:var(--text)">
          ${li.map(s => `<li>${escHtml(s.name || "")}${s.publisher ? ` <span style="color:var(--muted)">by ${escHtml(s.publisher)}</span>` : ""} — ${escHtml((s.install_date || "").slice(0, 10))}</li>`).join("")}
        </ul>
      </div>`;
  }

  return `
    <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:6px">Why did this change?</div>
    <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px">
      <span style="background:${recCol};color:#000;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;flex-shrink:0">${recIc} ${escHtml((inv.recommendation || "review").replace("_", " "))}</span>
      <div style="font-size:11px;color:var(--text);line-height:1.5">${escHtml(inv.explanation || "")}</div>
    </div>
    ${installEventHtml}
    ${sigHtml}
    ${installMatchHtml}
    <div style="display:flex;align-items:center;gap:8px;font-size:11px;margin-top:8px">
      <span style="font-size:10px;color:var(--muted)">Path:</span>
      <span style="background:${psColor};color:#000;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600">${escHtml(ps.label || "unknown")}</span>
    </div>
    ${updatesHtml}
    ${recentInstallsHtml}
    <div style="margin-top:8px;font-size:10px;color:var(--muted)">
      Inferred cause: <strong>${escHtml((inv.inferred_cause || "unknown").replace(/_/g, " "))}</strong>
    </div>
  `;
}

// ── Per-entry drill-down modal (2026-04-28) ───────────────────────
//
// User feature request: same pattern as the Trends drill-down --
// click any drift entry's title to open a full-screen detail modal.
// Modal auto-loads investigation + historical drift events for the
// specific entry, so the user has everything they need to decide
// in one focused view rather than scrolling through cluttered inline
// renderings.

let _blEntryModalState = null;  // {category, key} for the currently-open entry

async function openBaselineEntryDrilldown(category, key) {
  _blEntryModalState = {category, key};
  const modal = document.getElementById("bl-entry-modal");
  if (!modal) return;

  // Find the source entry in the rendered DOM so we can re-use its data
  // attributes (category, kind, current_value) without an extra fetch.
  const sourceEl = document.querySelector(`.bl-entry[data-drift-category="${category}"][data-drift-key="${cssEsc(key)}"]`);
  const kind = sourceEl?.dataset?.driftKind || "";
  let currentValue = null;
  if (sourceEl?.dataset?.driftCurrentValue) {
    try { currentValue = JSON.parse(sourceEl.dataset.driftCurrentValue); }
    catch (e) { currentValue = null; }
  }

  // Title: human-readable name (last path segment for tasks) + category badge
  const cfg = _BL_CATS[category] || {fields: [], critical: []};
  const nameDisplay = key.includes("\\") ? key.split("\\").pop() : key;
  document.getElementById("bl-entry-modal-title").innerHTML =
    `${escHtml(nameDisplay)} <span style="font-size:11px;color:var(--muted);font-weight:400;margin-left:8px">[${escHtml(category)}/${escHtml(kind || "?")}]</span>`;
  document.getElementById("bl-entry-modal-sub").textContent = key;
  // Quick action buttons -- mirror the inline view's How-to-fix block
  const consoleLabel = (cfg.remediation || {}).console_label || "";
  document.getElementById("bl-entry-modal-actions").innerHTML = `
    ${consoleLabel ? `<button onclick="blLaunchConsole('${escJsArg(category)}', this)" style="background:var(--cyan);border:none;color:#000;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:700">🔧 ${escHtml(consoleLabel)}</button>` : ""}
    ${kind && kind !== "" ? `<button onclick="blAcceptThisChangeFromModal('${escJsArg(category)}', '${escJsArg(key)}', '${escJsArg(kind)}', this)" title="Update the baseline for THIS entry only" style="background:var(--green);border:none;color:#000;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:700">✓ Accept this change</button>` : ""}
    <button onclick="closeBaselineEntryDrilldown()" style="background:transparent;border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:5px;cursor:pointer;font-size:12px">Close</button>`;

  // Parameter table -- larger render than the inline view. Get old/new
  // dicts by walking the source entry's data again. For added/removed
  // we have only one side; for changed we have both.
  let oldDict = null;
  let newDict = null;
  if (kind === "changed") {
    // The source DOM has the table; we re-extract from data-drift-current-value
    // for "new" and from the matching API drift entry for "old".
    newDict = currentValue;
    // Fetch the drift state to get the old side. Cache for the modal session.
    try {
      const driftRsp = await fetch("/api/baseline/drift").then(r => r.json());
      const cat = (driftRsp.drift || {})[category] || {};
      const found = (cat.changed || []).find(e => e.key === key);
      if (found) oldDict = found.old || null;
    } catch (e) { /* non-fatal */ }
  } else if (kind === "added") {
    newDict = currentValue;
  } else if (kind === "removed") {
    // Similar: pull old from drift
    try {
      const driftRsp = await fetch("/api/baseline/drift").then(r => r.json());
      const cat = (driftRsp.drift || {})[category] || {};
      const found = (cat.removed || []).find(e => e.key === key);
      if (found) oldDict = found;
    } catch (e) { /* non-fatal */ }
  }
  document.getElementById("bl-entry-modal-params").innerHTML =
    _blRenderModalParamTable(cfg, kind, oldDict, newDict);

  // Show modal + register ESC + backdrop-click close
  modal.style.display = "flex";
  document.addEventListener("keydown", _blEntryModalEscHandler);
  modal.onclick = (e) => { if (e.target === modal) closeBaselineEntryDrilldown(); };

  // Auto-load investigation + history (parallel fetches)
  document.getElementById("bl-entry-modal-investigation").innerHTML =
    `<div style="color:var(--muted)">🔍 Investigating change…</div>`;
  document.getElementById("bl-entry-modal-history").innerHTML =
    `<div style="color:var(--muted)">Loading history…</div>`;
  Promise.all([
    fetch("/api/baseline/investigate", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({category, key}),
    }).then(r => r.json()).catch(e => ({ok: false, error: e.message})),
    fetch(`/api/baseline/entry-history?category=${encodeURIComponent(category)}&key=${encodeURIComponent(key)}`)
      .then(r => r.json()).catch(e => ({ok: false, error: e.message})),
  ]).then(([invRsp, histRsp]) => {
    // Investigation
    if (invRsp.ok && invRsp.investigation) {
      document.getElementById("bl-entry-modal-investigation").innerHTML =
        _blRenderInvestigation(invRsp.investigation);
    } else {
      document.getElementById("bl-entry-modal-investigation").innerHTML =
        `<div style="color:var(--red)">${escHtml(invRsp.error || "investigation unavailable")}</div>`;
    }
    // History
    document.getElementById("bl-entry-modal-history").innerHTML =
      _blRenderEntryHistory(histRsp);
  });
}

function closeBaselineEntryDrilldown() {
  const modal = document.getElementById("bl-entry-modal");
  if (modal) modal.style.display = "none";
  _blEntryModalState = null;
  document.removeEventListener("keydown", _blEntryModalEscHandler);
}

function _blEntryModalEscHandler(e) {
  if (e.key === "Escape") closeBaselineEntryDrilldown();
}

// CSS-escape a string for use in a [attr="value"] selector. Doubles
// backslashes (common in Windows task paths).
function cssEsc(s) {
  return String(s || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

// Render a larger Parameter | Previous | Current table for the modal.
// Same shape as the inline _blRenderEntry table but with bigger font
// and full-width layout.
function _blRenderModalParamTable(cfg, kind, oldDict, newDict) {
  const critSet = new Set(cfg.critical || []);
  const showBoth = (kind === "changed");
  const rows = (cfg.fields || []).map(f => {
    const oldVal = oldDict ? oldDict[f] : (kind === "added" ? null : undefined);
    const newVal = newDict ? newDict[f] : (kind === "removed" ? null : undefined);
    const oldDisp = (oldVal === undefined || oldVal === null || oldVal === "") ? "—" : String(oldVal);
    const newDisp = (newVal === undefined || newVal === null || newVal === "") ? "—" : String(newVal);
    const isCrit = critSet.has(f);
    const isDiff = showBoth && oldDisp !== newDisp;
    const rowBg = isDiff ? "background:rgba(255,165,0,0.10)" : "";
    const paramColor = isCrit ? "color:var(--cyan)" : "color:var(--muted)";
    if (showBoth) {
      const prevColor = isDiff ? "color:var(--muted);text-decoration:line-through" : "color:var(--text)";
      const curColor  = isDiff ? "color:var(--orange);font-weight:700" : "color:var(--text)";
      return `<tr style="${rowBg}">
        <td style="padding:5px 10px;font-family:var(--font-mono);font-size:11px;${paramColor};white-space:nowrap;vertical-align:top">${escHtml(f)}</td>
        <td style="padding:5px 10px;font-family:var(--font-mono);font-size:12px;${prevColor};word-break:break-all;vertical-align:top">${escHtml(oldDisp)}</td>
        <td style="padding:5px 10px;font-family:var(--font-mono);font-size:12px;${curColor};word-break:break-all;vertical-align:top">${escHtml(newDisp)}</td>
      </tr>`;
    }
    return `<tr>
      <td style="padding:5px 10px;font-family:var(--font-mono);font-size:11px;${paramColor};white-space:nowrap;vertical-align:top">${escHtml(f)}</td>
      <td style="padding:5px 10px;font-family:var(--font-mono);font-size:12px;color:var(--text);word-break:break-all;vertical-align:top">${kind === "removed" ? escHtml(oldDisp) : escHtml(newDisp)}</td>
    </tr>`;
  }).join("");
  const headers = showBoth
    ? `<tr style="border-bottom:1px solid var(--border)">
         <th style="text-align:left;padding:5px 10px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Parameter</th>
         <th style="text-align:left;padding:5px 10px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Previous</th>
         <th style="text-align:left;padding:5px 10px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Current</th>
       </tr>`
    : `<tr style="border-bottom:1px solid var(--border)">
         <th style="text-align:left;padding:5px 10px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Parameter</th>
         <th style="text-align:left;padding:5px 10px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">${kind === "removed" ? "Previous (was in baseline)" : "Current"}</th>
       </tr>`;
  return `<table style="width:100%;border-collapse:collapse"><thead>${headers}</thead><tbody>${rows}</tbody></table>`;
}

// Render the entry-history payload as a compact timeline. Each event
// shows: timestamp · kind badge · what changed (delta fields).
function _blRenderEntryHistory(rsp) {
  if (!rsp || !rsp.ok) {
    return `<div style="color:var(--red)">${escHtml((rsp && rsp.error) || "history unavailable")}</div>`;
  }
  const events = rsp.events || [];
  if (!events.length) {
    return `<div style="color:var(--muted);font-size:11px">
      No previous drift events for this entry. This is the first time it has differed from the baseline.
    </div>`;
  }
  const kindColor = {added: "var(--green)", removed: "var(--red)", changed: "var(--orange)"};
  const kindIcon = {added: "+", removed: "−", changed: "~"};
  const items = events.map(ev => {
    const ts = (ev.timestamp || "").replace("T", " ").slice(0, 19);
    const col = kindColor[ev.kind] || "var(--muted)";
    const icn = kindIcon[ev.kind] || "?";
    const delta = (ev.delta || []).join(", ") || "(no delta)";
    return `<div style="padding:6px 8px;margin:3px 0;border-left:2px solid ${col};background:rgba(255,255,255,0.02);border-radius:3px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="background:${col};color:#000;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">${icn} ${escHtml(ev.kind)}</span>
        <span style="color:var(--muted);font-family:var(--font-mono);font-size:11px">${escHtml(ts)}</span>
      </div>
      ${ev.kind === "changed" ? `<div style="font-size:10px;color:var(--text);margin-top:3px;font-family:var(--font-mono)">delta: ${escHtml(delta)}</div>` : ""}
    </div>`;
  }).join("");
  return `<div style="font-size:11px;color:var(--muted);margin-bottom:6px">
    ${events.length} previous event${events.length !== 1 ? "s" : ""} for this entry:
  </div>${items}`;
}

// Wrapper around blAcceptThisChange for the modal -- closes the modal
// after a successful accept since the entry is now gone from drift.
async function blAcceptThisChangeFromModal(category, key, kind, btn) {
  // Find the original entry row to reuse its current_value cache, then
  // call the same accept path the inline button uses.
  const sourceEl = document.querySelector(`.bl-entry[data-drift-category="${category}"][data-drift-key="${cssEsc(key)}"]`);
  if (!sourceEl) {
    alert("Couldn't find the source entry to accept.");
    return;
  }
  // Find the "✓ Accept this change" button on the source row and click it
  // to reuse the existing logic (data-attribute reads + optimistic remove).
  const inlineBtn = sourceEl.querySelector('button[onclick*="blAcceptThisChange"]');
  if (inlineBtn) {
    closeBaselineEntryDrilldown();
    inlineBtn.click();
  } else {
    alert("Couldn't find the inline Accept button to delegate to.");
  }
}


// ── Full-inventory browser (shows EVERY monitored item) ────────────────
//
// The drift detail only shows items that changed. Users want assurance
// that the whole inventory is being tracked. This browser fetches the
// current snapshot via /api/baseline/snapshot, groups items by category,
// and renders a collapsible list of every one. Clicking an item expands
// its full Parameter / Previous / Current table in-line so the user sees
// every tracked field for that item.

let _blInventoryCache = null;  // cached snapshot; cleared on loadBaseline re-entry
let _blInventoryDrift = null;  // pairs items with their drift state for the indicator dot

// Toggle the inventory body + lazy-load the snapshot the first time.
async function blToggleInventory() {
  const body = document.getElementById("bl-inv-body");
  const toggle = document.getElementById("bl-inv-toggle");
  if (!body || !toggle) return;
  const isHidden = body.style.display === "none";
  if (isHidden) {
    body.style.display = "";
    toggle.textContent = "Hide inventory";
    // Lazy fetch on first expand. Snapshot is ~600 items; keep it lean.
    if (!_blInventoryCache) {
      try {
        const [snap, drift] = await Promise.all([
          fetch("/api/baseline/snapshot").then(r => r.json()),
          fetch("/api/baseline/drift").then(r => r.json()),
        ]);
        _blInventoryCache = snap.snapshot || snap;
        _blInventoryDrift = drift.drift || {};
      } catch (e) {
        document.getElementById("bl-inv-startup").innerHTML =
          `<div style="color:var(--red);font-size:12px;padding:8px">Failed to load inventory: ${escHtml(e.message)}</div>`;
        return;
      }
    }
    blRenderInventory();
  } else {
    body.style.display = "none";
    toggle.textContent = "Show inventory";
  }
}

// Build the drift-state indicator for an item: added / removed / changed / clean.
// Returns a small colored dot with a tooltip string.
function _blItemDriftState(category, key) {
  const drift = (_blInventoryDrift && _blInventoryDrift[category]) || {};
  const added   = (drift.added   || []).some(e => e.key === key);
  const removed = (drift.removed || []).some(e => e.key === key);
  const changed = (drift.changed || []).some(e => e.key === key);
  if (added)   return {color: "var(--green)",  label: "Added",   kind: "added"};
  if (removed) return {color: "var(--red)",    label: "Removed", kind: "removed"};
  if (changed) return {color: "var(--orange)", label: "Changed", kind: "changed"};
  return {color: "var(--border)", label: "Matches baseline", kind: "clean"};
}

// Render the three category sections from the cached snapshot + drift.
// Filters by the search box contents (case-insensitive, matches the
// item name OR key).
function blRenderInventory() {
  if (!_blInventoryCache) return;
  const filterEl = document.getElementById("bl-inv-filter");
  const q = ((filterEl && filterEl.value) || "").toLowerCase().trim();

  const labels = {
    startup:  {title: "🚀 Startup Items",   icon: "🚀"},
    services: {title: "⚙ Windows Services", icon: "⚙"},
    tasks:    {title: "⏱ Scheduled Tasks",  icon: "⏱"},
  };

  for (const cat of ["startup", "services", "tasks"]) {
    const byKey = ((_blInventoryCache[cat] || {}).by_key) || {};
    const keys = Object.keys(byKey).sort((a, b) => a.localeCompare(b));
    const matchingKeys = q ? keys.filter(k => {
      const item = byKey[k];
      return k.toLowerCase().includes(q) ||
             (item.name || "").toLowerCase().includes(q) ||
             (item.display_name || "").toLowerCase().includes(q);
    }) : keys;

    const driftEntries = (_blInventoryDrift && _blInventoryDrift[cat]) || {};
    const driftCount = (driftEntries.added || []).length
                     + (driftEntries.removed || []).length
                     + (driftEntries.changed || []).length;

    const itemsHtml = matchingKeys.map(k => {
      const item = byKey[k];
      const ds = _blItemDriftState(cat, k);
      const name = item.name || k;
      const sub  = item.location || item.path || item.display_name || "";
      // Row: clickable summary; hidden detail panel toggled by click.
      // data-inv-key lets us find the detail panel on click without DOM query.
      const detailId = `blinv-${cat}-${_blHashKey(k)}`;
      return `
        <div class="bl-inv-row" data-inv-key="${escHtml(k)}" data-inv-category="${cat}" data-inv-kind="${ds.kind}">
          <div onclick="blToggleInventoryRow('${detailId}', this)" style="display:flex;align-items:center;gap:10px;padding:5px 10px;cursor:pointer;border-bottom:1px solid var(--border)" onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background=''">
            <span title="${escHtml(ds.label)}" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${ds.color};flex-shrink:0"></span>
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;color:var(--text-bright);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(name)}</div>
              ${sub ? `<div style="font-size:10px;color:var(--muted);font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(sub)}</div>` : ""}
            </div>
            <span style="font-size:10px;color:var(--muted);font-family:var(--font-mono)">${escHtml(ds.label)}</span>
          </div>
          <div id="${detailId}" style="display:none;padding:6px 10px"></div>
        </div>`;
    }).join("");

    const el = document.getElementById(`bl-inv-${cat}`);
    if (!el) continue;
    el.innerHTML = `
      <details open>
        <summary style="cursor:pointer;font-size:13px;font-weight:700;color:var(--text-bright);padding:6px 0;list-style:none">
          ${labels[cat].title}
          <span style="font-size:10px;color:var(--muted);font-weight:400;margin-left:8px">
            ${matchingKeys.length} of ${keys.length}${driftCount ? ` · <span style='color:var(--orange)'>${driftCount} drifted</span>` : ""}
          </span>
        </summary>
        <div style="border:1px solid var(--border);border-radius:6px;max-height:400px;overflow-y:auto;margin-top:6px">
          ${matchingKeys.length ? itemsHtml : `<div style="padding:10px;font-size:11px;color:var(--muted);text-align:center">No items match filter</div>`}
        </div>
      </details>`;
  }
}

// Simple hash for inventory-row detail IDs. We can't put the raw key
// into an HTML id (it may contain backslashes, colons, spaces). Using
// a hash collapses exotic characters to a safe suffix.
function _blHashKey(k) {
  let h = 0;
  for (let i = 0; i < k.length; i++) {
    h = ((h << 5) - h) + k.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h).toString(36);
}

// Click handler for an inventory row: expand/collapse its detail table.
// The detail table shows EVERY tracked field for that item, regardless
// of drift state. For drifted items we include both Previous and Current
// columns; for clean items Previous == Current so we render a single
// Value column for clarity.
async function blToggleInventoryRow(detailId, rowEl) {
  const detail = document.getElementById(detailId);
  if (!detail) return;
  if (detail.style.display !== "none") {
    detail.style.display = "none";
    return;
  }
  // Find the item data: category + key live on the parent .bl-inv-row.
  const rowContainer = rowEl.closest(".bl-inv-row");
  const category = rowContainer.dataset.invCategory;
  const key = rowContainer.dataset.invKey;
  const kind = rowContainer.dataset.invKind;
  let byKey = (((_blInventoryCache || {})[category] || {}).by_key) || {};
  let item = byKey[key];
  // Bug 2026-04-25: cache-miss showed "Item data missing from cache" with
  // no recovery path. Root cause: loadBaseline() unconditionally nulls
  // _blInventoryCache (e.g. after a tab switch or auto-refresh), but the
  // rendered DOM rows still reference the now-empty cache. Recover by
  // re-fetching the snapshot transparently and retrying. The user just
  // sees a brief delay instead of an unrecoverable error.
  if (!item) {
    try {
      detail.innerHTML = `<div style="color:var(--muted);font-size:11px">Refreshing inventory…</div>`;
      detail.style.display = "";
      const [snap, drift] = await Promise.all([
        fetch("/api/baseline/snapshot").then(r => r.json()),
        fetch("/api/baseline/drift").then(r => r.json()),
      ]);
      _blInventoryCache = snap.snapshot || snap;
      _blInventoryDrift = drift.drift || {};
      byKey = (((_blInventoryCache || {})[category] || {}).by_key) || {};
      item = byKey[key];
    } catch (e) {
      detail.innerHTML = `<div style="color:var(--red);font-size:11px">Failed to refresh inventory: ${escHtml(e.message)}</div>`;
      return;
    }
  }
  if (!item) {
    // Even after the re-fetch the item isn't there -- it really was
    // removed from the system since the last render (e.g. user
    // uninstalled a service). Tell them so they can re-render the
    // inventory list to drop the stale row.
    detail.innerHTML = `<div style="color:var(--orange);font-size:11px">This item is no longer present on the system. Click "Hide inventory" then "Show inventory" to refresh the list.</div>`;
    detail.style.display = "";
    return;
  }

  // For drifted items we also fetch the baseline-side values from the
  // drift payload so Previous column reflects the baseline, not the
  // current (which is always "item").
  let oldItem = null;
  if (kind === "changed") {
    const drift = (_blInventoryDrift && _blInventoryDrift[category]) || {};
    const match = (drift.changed || []).find(e => e.key === key);
    if (match) oldItem = match.old || null;
  } else if (kind === "removed") {
    const drift = (_blInventoryDrift && _blInventoryDrift[category]) || {};
    const match = (drift.removed || []).find(e => e.key === key);
    if (match) oldItem = match;  // removed entries carry the old value directly
  }

  const cfg = _BL_CATS[category];
  const critSet = new Set(cfg.critical || []);
  const isDrifted = kind !== "clean";
  const showBothCols = isDrifted && (oldItem !== null || kind === "added");

  const rows = cfg.fields.map(f => {
    const curVal = item[f];
    const oldVal = oldItem ? oldItem[f] : curVal;
    const curDisp = (curVal === undefined || curVal === null || curVal === "") ? "—" : String(curVal);
    const oldDisp = kind === "added" ? "—"
                  : (oldVal === undefined || oldVal === null || oldVal === "") ? "—" : String(oldVal);
    const isCrit = critSet.has(f);
    const changed = showBothCols && curDisp !== oldDisp;
    const paramCol = isCrit ? "color:var(--cyan)" : "color:var(--muted)";
    const rowBg = changed ? "background:rgba(255,165,0,0.08)" : "";
    if (showBothCols) {
      const prevColor = changed ? "color:var(--muted);text-decoration:line-through" : "color:var(--text)";
      const curColor  = changed ? "color:var(--orange);font-weight:700" : "color:var(--text)";
      return `<tr style="${rowBg}">
        <td style="padding:3px 8px;font-family:var(--font-mono);font-size:10px;${paramCol};white-space:nowrap;vertical-align:top">${escHtml(f)}</td>
        <td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;${prevColor};word-break:break-all;vertical-align:top">${escHtml(oldDisp)}</td>
        <td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;${curColor};word-break:break-all;vertical-align:top">${escHtml(curDisp)}</td>
      </tr>`;
    }
    return `<tr>
      <td style="padding:3px 8px;font-family:var(--font-mono);font-size:10px;${paramCol};white-space:nowrap;vertical-align:top">${escHtml(f)}</td>
      <td style="padding:3px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text);word-break:break-all;vertical-align:top">${escHtml(curDisp)}</td>
    </tr>`;
  }).join("");

  const headers = showBothCols
    ? `<tr style="border-bottom:1px solid var(--border)">
         <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase">Parameter</th>
         <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase">Previous</th>
         <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase">Current</th>
       </tr>`
    : `<tr style="border-bottom:1px solid var(--border)">
         <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase">Parameter</th>
         <th style="text-align:left;padding:3px 8px;font-size:9px;color:var(--muted);font-weight:600;text-transform:uppercase">Value</th>
       </tr>`;

  detail.innerHTML = `<table class="bl-inv-param-table" style="width:100%;border-collapse:collapse;background:var(--surface);border-radius:4px">
    <thead>${headers}</thead>
    <tbody>${rows}</tbody>
  </table>`;
  detail.style.display = "";
}

async function acceptBaseline() {
  const btn = document.getElementById("bl-accept-btn");
  const confirmed = confirm(
    "Accept the CURRENT system state as the new baseline?\n\n" +
    "After this, any future additions/removals/changes to startup items, " +
    "Windows services, or scheduled tasks will show up here as drift.\n\n" +
    "Only do this if the current state is what you want to consider 'known good.'"
  );
  if (!confirmed) return;

  if (btn) { btn.disabled = true; btn.textContent = "Capturing..."; }
  try {
    const r = await fetch("/api/baseline/accept", { method: "POST" });
    const data = await r.json();
    if (data.ok) {
      await loadBaseline();  // reload → should now show "No drift" state
    } else {
      alert("Baseline accept failed: " + (data.error || "unknown"));
    }
  } catch (e) {
    alert("Baseline accept failed: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Accept current as baseline"; }
  }
}



