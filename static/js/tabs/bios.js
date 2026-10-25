// BIOS tab (prefix bios) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// BIOS & FIRMWARE
// ══════════════════════════════════════════════════════════════════════════
async function loadBios() {
  try {
    document.getElementById("bios-loading").style.display = "block";
    document.getElementById("bios-content").style.display = "none";
    const r = await fetch("/api/bios/status");
    const d = await r.json();
    renderBios(d);
    fetchSummary("bios", d, "summary-bios");
    loadBiosAudit();  // refresh the audit trail alongside the status panel
  } catch(e) {
    console.error("Failed to load bios:", e);
  }
}

async function forceBiosPoll() {
  // Force-trigger a fresh BIOS audit poll right now (don't wait 15 min).
  // Bug fix 2026-05-14: after PR #36 cached bios_serial / vbs to fix
  // chronic timeouts, the user looked at the audit panel and still saw
  // 8 historical errors. They had no way to verify the fix worked
  // without waiting for the next 15-min cycle. This button hits the
  // /api/bios/audit/poll endpoint, forces a poll, and reports the
  // result inline so the user can SEE that the fix is working.
  const content = document.getElementById("bios-audit-content");
  const status = document.createElement("div");
  status.style.cssText = "margin:8px 0;padding:8px 12px;background:var(--surface);border-radius:6px;font-size:12px;color:var(--muted)";
  status.textContent = "⚡ Forcing a poll cycle…";
  if (content && content.parentElement) content.parentElement.insertBefore(status, content);
  try {
    const r = await fetch("/api/bios/audit/poll", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      const errs = d.errors_count || 0;
      const changes = d.changes_count || 0;
      const color = errs ? "var(--red)" : "var(--green)";
      const icon = errs ? "✗" : "✓";
      status.style.background = errs ? "#ff405018" : "#00d96820";
      status.style.color = color;
      status.innerHTML = `${icon} Poll completed at ${(d.snapshot_timestamp || "now")} — <strong>${errs} error${errs === 1 ? "" : "s"}, ${changes} change${changes === 1 ? "" : "s"}</strong>${errs === 0 ? " (cache fix working as intended)" : ""}`;
    } else {
      status.style.background = "#ff405018";
      status.style.color = "var(--red)";
      status.textContent = `✗ Poll failed: ${d.error || "unknown error"}`;
    }
  } catch (e) {
    status.style.background = "#ff405018";
    status.style.color = "var(--red)";
    status.textContent = `✗ Poll request failed: ${(e && e.message) || e}`;
  }
  // Also re-render the history so the user sees any new entry that landed
  loadBiosAudit();
  // Fade out the status banner after a few seconds so it doesn't clutter
  setTimeout(() => {
    if (status.parentElement) {
      status.style.transition = "opacity 0.6s";
      status.style.opacity = "0";
      setTimeout(() => status.remove(), 700);
    }
  }, 6000);
}

async function loadBiosAudit() {
  const content = document.getElementById("bios-audit-content");
  if (!content) return;
  // Synchronous visual feedback BEFORE the fetch so the user can tell
  // the click registered. Without this the UI looked frozen on the same
  // 3 baseline entries and the user reported "the refresh button does
  // nothing" (2026-05-14). The brief "Refreshing..." state confirms
  // the click was received and the fetch is in flight.
  const prevHtml = content.innerHTML;
  content.style.opacity = "0.6";
  content.style.transition = "opacity 0.15s";
  try {
    const r = await fetch("/api/bios/audit/history?limit=20");
    const d = await r.json();
    const esc = s => escHtml(s == null ? "—" : s);
    const fullHistory = (d.history || []).slice().reverse(); // newest first
    if (!fullHistory.length) {
      content.innerHTML = '<div style="color:var(--muted)">No snapshots yet — the baseline will be captured on the next polling cycle (up to 60 s).</div>';
      content.style.opacity = "1";
      return;
    }
    // 24-hour filter (bug fix 2026-05-14): user reported "error still
    // there" after the cache fix in PR #36 because 8 historical errors
    // from BEFORE the fix were still on screen, even though no new
    // errors had been added since the fix landed. By default we now
    // hide entries older than 24h so recent state isn't drowned by
    // historical noise. The "Show all history" checkbox restores the
    // full list. Hidden count is reported in the footer so nothing
    // disappears silently.
    const showAll = !!(document.getElementById("bios-audit-show-all") || {}).checked;
    const cutoffMs = Date.now() - 24 * 3600 * 1000;
    const history = showAll ? fullHistory : fullHistory.filter(e => {
      if (!e.timestamp) return true;  // unparseable -> show
      const t = new Date(e.timestamp).getTime();
      return isNaN(t) || t >= cutoffMs;
    });
    const hiddenCount = fullHistory.length - history.length;
    // Context chip renderer: "user" (gray) or "elevated" (purple)
    const ctxChip = ctx => {
      if (ctx === "elevated") {
        return '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#a855f722;border:1px solid #a855f766;color:var(--purple);font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-right:6px">ELEVATED</span>';
      }
      if (ctx === "user") {
        return '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#6b728033;border:1px solid #6b728066;color:var(--muted);font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-right:6px">USER</span>';
      }
      return '';
    };
    // Count entries by kind so we can report what the user is seeing
    // (and what was previously hidden -- error entries had been
    // silently dropped from the render). Bug fix 2026-05-14.
    const counts = {baseline: 0, change: 0, error: 0, other: 0};
    let html = '<div style="display:flex;flex-direction:column;gap:10px">';
    for (const entry of history) {
      const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "(no timestamp)";
      const chip = ctxChip(entry.context);
      if (entry.kind === "change") {
        counts.change++;
        const rows = (entry.changes || []).map(c =>
          `<div style="font-family:'JetBrains Mono',monospace;font-size:12px;padding:3px 0"><span style="color:var(--cyan)">${esc(c.field)}</span>: <span style="color:var(--muted);text-decoration:line-through">${esc(c.old)}</span> → <strong style="color:var(--orange)">${esc(c.new)}</strong></div>`
        ).join("");
        html += `<div style="background:var(--surface);border-left:3px solid var(--orange);padding:10px 14px;border-radius:6px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span>${chip}<span style="font-weight:600;color:var(--orange)">⚠ CHANGE</span></span><span style="font-size:11px;color:var(--muted)">${esc(ts)}</span></div>${rows}</div>`;
      } else if (entry.kind === "baseline") {
        counts.baseline++;
        const note = entry.note || "initial snapshot captured";
        html += `<div style="background:var(--surface);border-left:3px solid var(--cyan);padding:10px 14px;border-radius:6px"><div style="display:flex;justify-content:space-between;align-items:center"><span>${chip}<span style="font-weight:600;color:var(--cyan)">◆ BASELINE</span></span><span style="font-size:11px;color:var(--muted)">${esc(ts)}</span></div><div style="font-size:12px;color:var(--muted);margin-top:4px">${esc(note)}</div></div>`;
      } else if (entry.kind === "error") {
        // Bug fix 2026-05-14: error entries were silently dropped from
        // the render loop. User reported "refresh button does nothing"
        // because clicking re-fetched data but the rendered list never
        // changed -- on this user's machine 8 of 11 entries were errors
        // that vanished into the void. Render them as red-bar rows
        // alongside baselines + changes so the user knows the polling
        // cycle is actually running and which fields are failing.
        counts.error++;
        const errs = (entry.errors || []).map(e =>
          `<div style="font-family:'JetBrains Mono',monospace;font-size:12px;padding:3px 0"><span style="color:var(--cyan)">${esc(e.field)}</span>: <span style="color:var(--red)">${esc(e.error)}</span></div>`
        ).join("") || '<div style="font-size:12px;color:var(--muted)">(no error details)</div>';
        html += `<div style="background:var(--surface);border-left:3px solid var(--red);padding:10px 14px;border-radius:6px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span>${chip}<span style="font-weight:600;color:var(--red)">✗ ERROR</span></span><span style="font-size:11px;color:var(--muted)">${esc(ts)}</span></div>${errs}</div>`;
      } else {
        counts.other++;
      }
    }
    // Footer: timestamps + counts so the user can SEE that the refresh
    // ran even when no entries changed. Without this the UI rendered
    // the identical 3 baselines on every click -> "does nothing".
    const now = new Date().toLocaleTimeString();
    const summary = [];
    if (counts.baseline) summary.push(`<span style="color:var(--cyan)">${counts.baseline} baseline${counts.baseline === 1 ? "" : "s"}</span>`);
    if (counts.change) summary.push(`<span style="color:var(--orange)">${counts.change} change${counts.change === 1 ? "" : "s"}</span>`);
    if (counts.error) summary.push(`<span style="color:var(--red)">${counts.error} error${counts.error === 1 ? "" : "s"}</span>`);
    if (counts.other) summary.push(`<span style="color:var(--muted)">${counts.other} other</span>`);
    // If we filtered any entries, surface a small "N hidden, click to show"
    // hint so the user knows nothing was silently lost. Bug fix 2026-05-14.
    let hiddenLine = "";
    if (hiddenCount > 0 && !showAll) {
      hiddenLine = `<div style="margin-top:10px;padding:8px 12px;background:var(--surface);border-radius:6px;font-size:11px;color:var(--muted);text-align:center">${hiddenCount} older entr${hiddenCount === 1 ? "y" : "ies"} hidden (>24h old) — toggle "Show all history" above to see ${hiddenCount === 1 ? "it" : "them"}</div>`;
    }
    // Close the flex container BEFORE appending footer/hidden-line so
    // the DOM is well-formed regardless of which path we take.
    html += "</div>";
    // If the recent window is empty (cache fix is preventing new errors,
    // no real changes happening, no context shifts), replace the empty
    // entries container with a friendly "Polling healthy, nothing to
    // report" card instead of leaving a blank gap.
    if (!history.length) {
      html = `<div style="padding:16px;background:var(--surface);border-radius:8px;border-left:3px solid var(--green);text-align:center"><div style="color:var(--green);font-weight:600;margin-bottom:4px">✓ Polling healthy</div><div style="font-size:12px;color:var(--muted)">No baselines, changes, or errors in the last 24 hours. The polling loop is running silently because nothing has changed.</div></div>`;
    }
    html += `${hiddenLine}<div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px"><span>${summary.join(" · ") || "(no entries in window)"}</span><span>↻ Refreshed ${esc(now)}</span></div>`;
    content.innerHTML = html;
    content.style.opacity = "1";
  } catch (e) {
    console.error("Failed to load BIOS audit trail:", e);
    content.innerHTML = '<div style="color:var(--red)">Failed to load audit trail: ' + String(e && e.message || e) + '</div>';
    content.style.opacity = "1";
    // Restore previous content if we just emptied it on error
    if (prevHtml && content.innerHTML.startsWith('<div style="color:var(--red)')) {
      content.innerHTML += '<div style="margin-top:8px;font-size:11px;color:var(--muted)">(previous content preserved below)</div>' + prevHtml;
    }
  }
}

function renderBios(d) {
  const cur  = d.current || {};
  const upd  = d.update  || {};

  document.getElementById("bios-version").textContent = cur.BIOSVersion||"—";
  document.getElementById("bios-date").textContent    = cur.BIOSDateFormatted||"—";
  document.getElementById("bios-latest").textContent  = upd.latest_version||"—";

  const badge = document.getElementById("bios-update-badge");
  if (upd.update_available) {
    badge.innerHTML = `<span style="color:var(--red);font-weight:700">⚠ YES</span>`;
  } else if (upd.latest_version) {
    badge.innerHTML = `<span style="color:var(--cyan)">✓ No</span>`;
  } else {
    badge.innerHTML = `<span style="color:var(--muted)">Unknown</span>`;
  }

  document.getElementById("bios-current-detail").innerHTML = `
    <table style="width:100%;font-size:13px;border-collapse:collapse">
      ${[["Version",cur.BIOSVersion],["Date",cur.BIOSDateFormatted],
         ["Manufacturer",cur.Manufacturer],["Board",cur.BoardProduct],
         ["Board Mfr",cur.BoardMfr]].map(([k,v])=>
        `<tr style="border-bottom:1px solid var(--border)">
           <td style="padding:7px 10px;color:var(--muted)">${k}</td>
           <td style="padding:7px 10px;font-weight:600">${esc(v||"—")}</td>
         </tr>`).join("")}
    </table>`;

  const srcLabel = upd.source === "dell_api" ? "Dell API" : upd.source === "web_search_fallback" ? "Web search" : "—";
  document.getElementById("bios-update-detail").innerHTML = upd.update_available
    ? `<div style="background:#ff405018;border:1px solid var(--red);border-radius:8px;padding:16px;margin-bottom:14px">
         <div style="font-size:18px;font-weight:800;color:var(--red)">Update Available!</div>
         <div style="font-size:13px;margin-top:6px">Latest: <strong>${esc(upd.latest_version)}</strong> (${esc(upd.latest_date||"")})</div>
         <div style="font-size:12px;color:var(--muted);margin-top:4px">${esc(upd.release_notes||"")}</div>
         <a href="${esc(upd.download_url||"https://www.dell.com/support/home/en-us?app=drivers")}" target="_blank"
            style="display:inline-block;margin-top:12px;background:var(--red);color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700">
           ↓ Download BIOS Update
         </a>
       </div>`
    : `<div style="padding:12px;font-size:13px">
         ${upd.latest_version
           ? `<div style="color:var(--cyan);font-weight:700;font-size:15px;margin-bottom:8px">✓ BIOS is current</div>
              <div style="color:var(--muted)">Latest confirmed: ${esc(upd.latest_version)} · Source: ${srcLabel}</div>
              ${upd.release_notes ? `<div style="color:var(--muted);margin-top:6px;font-size:11px">${esc(upd.release_notes)}</div>` : ""}`
           : `<div style="color:var(--orange);font-weight:600;margin-bottom:10px">⚠ Could not auto-detect latest version</div>
              <div style="color:var(--muted);font-size:12px;margin-bottom:12px">
                Dell's update APIs are unreliable from Python. Your current BIOS is
                <strong style="color:var(--text)">${esc(upd.current_version||"unknown")}</strong>.
                ${upd.service_tag ? `Your service tag is <strong style="color:var(--cyan)">${esc(upd.service_tag)}</strong> — use the link below to go directly to your device's driver page.` : ""}
              </div>
              <a href="${esc(upd.download_url)}" target="_blank"
                 style="display:inline-block;background:#00d4ff22;border:1px solid var(--cyan);color:var(--cyan);padding:10px 18px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700;margin-bottom:10px">
                🔗 ${upd.service_tag ? "Open My Dell Driver Page →" : "Check Dell Support →"}
              </a>
              <div style="font-size:12px;color:var(--muted);margin-bottom:6px">On that page: filter by <strong>BIOS</strong> category and compare the version number shown to your current <strong>${esc(upd.current_version||"")}</strong>.</div>
              <div style="font-size:11px;color:var(--muted)">Or click ↺ Re-check Dell above to try the automatic check again.</div>`}
       </div>`;

  document.getElementById("bios-loading").style.display = "none";
  document.getElementById("bios-content").style.display = "";
}

async function clearBiosCache() {
  await fetch("/api/bios/cache/clear", { method: "POST" });
  loadBios();
}

