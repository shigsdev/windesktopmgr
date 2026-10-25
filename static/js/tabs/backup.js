// Backup tab (prefix bk / cc) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// BACKUP TAB — Sections 1+2 (PR-1 of backlog #47)
// Read-only inventory of Windows backups + File History; Sections 3 (#46)
// and 4 (#11) are placeholders until those ship.
// ══════════════════════════════════════════════════════════════════════════

function bk_humanBytes(n) {
  if (n === null || n === undefined || isNaN(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i === 0 ? 0 : 2) + " " + units[i];
}

function bk_pillStyle(level) {
  const map = {
    ok:       { bg: "rgba(46,204,113,0.15)", fg: "var(--green)",  border: "var(--green)" },
    info:     { bg: "var(--surface)",         fg: "var(--cyan)",   border: "var(--cyan)" },
    warning:  { bg: "rgba(243,156,18,0.15)",  fg: "var(--orange)", border: "var(--orange)" },
    critical: { bg: "rgba(231,76,60,0.18)",   fg: "var(--red)",    border: "var(--red)" }
  };
  return map[level] || map.info;
}

function bk_setStatusPill(elId, level, label) {
  const el = document.getElementById(elId);
  if (!el) return;
  const s = bk_pillStyle(level);
  el.style.background = s.bg;
  el.style.color = s.fg;
  el.style.borderColor = s.border;
  el.textContent = label;
}

// Backup and Restore (Windows 7) schedule strip: last successful run +
// scope. data-level carries the health level for the smoke test.
function bk_renderSchedule(wbs) {
  const el = document.getElementById("bk-wb-schedule");
  if (!el) return;
  if (!wbs) { el.innerHTML = ""; el.removeAttribute("data-level"); return; }
  const h = wbs.health || {};
  const lvl = h.level || "info";
  const s = bk_pillStyle(lvl);
  el.dataset.level = lvl;
  const last = wbs.last_success ? new Date(wbs.last_success).toLocaleString() : "never";
  const scope = !wbs.configured ? "—"
    : [wbs.includes_files ? "files" : null, wbs.system_image ? "system image" : null].filter(Boolean).join(" + ") || "nothing selected";
  el.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px">
      <strong style="color:var(--text-bright)">Backup and Restore (Windows 7) schedule</strong>
      <span style="font-size:10px;padding:2px 8px;border-radius:10px;background:${s.bg};color:${s.fg};border:1px solid ${s.border}">${escHtml(lvl.toUpperCase())}</span>
    </div>
    <div style="font-size:12px;margin-bottom:6px">${escHtml(h.reason || "")}</div>
    <div style="display:flex;gap:24px;flex-wrap:wrap;color:var(--muted);font-size:11px">
      <div>Last success: <strong style="color:var(--text-bright)">${escHtml(last)}</strong></div>
      <div>Backs up: <strong style="color:var(--text-bright)">${escHtml(scope)}</strong></div>
      <div>Target: <strong style="color:var(--text-bright)">${escHtml(wbs.target || "—")}</strong></div>
      ${wbs.running ? '<div style="color:var(--cyan)">⏳ backup running now</div>' : ""}
    </div>`;
}

// ── Elevated actions (PR-2 of #47) ─────────────────────────────────
// All three actions (scan / delete / fh-cleanup) follow the same
// pattern: POST to launch the helper -> store the session_id ->
// poll /api/backup/scan-status every 2s -> render the outcome and
// re-fetch the tab data once the helper exits.

async function bk_pollUntilDone(sessionId, statusEl, maxSeconds = 900) {
  // Helper for all three actions. Polls scan-status, updates a status
  // element with progress, returns the final result dict.
  const start = Date.now();
  let last = null;
  while (true) {
    const r = await fetch("/api/backup/scan-status?session_id=" + encodeURIComponent(sessionId));
    last = await r.json();
    if (last.state === "done") break;
    if (last.state === "missing") {
      if (statusEl) statusEl.textContent = "Status file missing -- did the helper crash?";
      break;
    }
    const elapsed = Math.round((Date.now() - start) / 1000);
    if (statusEl) statusEl.textContent = `Running... ${elapsed}s elapsed`;
    if (elapsed > maxSeconds) {
      if (statusEl) statusEl.textContent = `Timed out after ${maxSeconds}s (helper may still finish; refresh later)`;
      break;
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  // Best-effort cleanup of the result + request files.
  fetch("/api/backup/scan-cleanup", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({session_id: sessionId}),
  }).catch(() => {});
  return last;
}

function bk_showActionResult(label, result, ok) {
  // Lightweight inline banner above the section bodies. Auto-dismissing
  // toast would be nicer but a persistent banner is more honest -- the
  // user can see what happened until they click ↻ Refresh.
  const overall = document.getElementById("bk-overall");
  if (!overall) return;
  const colorBorder = ok ? "var(--green)" : "var(--red)";
  const icon = ok ? "✅" : "❌";
  overall.style.display = "block";
  overall.style.borderLeftColor = colorBorder;
  // Human-meaningful outcome (e.g. "nothing to remove" vs "versions
  // removed") -- without this the banner just said "completed" and the
  // user couldn't tell whether anything actually happened.
  const summaryLine = result.summary ? `<div style="font-size:12px;color:var(--text);margin-top:3px">${escHtml(result.summary)}</div>` : "";
  const errLine = result.error ? `<div style="color:var(--red);font-size:11px;margin-top:4px">Error: ${escHtml(result.error)}</div>` : "";
  const runLine = result.run && result.run.elapsed_seconds ? `<div style="color:var(--muted);font-size:10px;margin-top:2px">subprocess elapsed: ${result.run.elapsed_seconds}s, rc=${result.run.returncode}</div>` : "";
  overall.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">${icon}</span>
      <div style="flex:1">
        <div style="font-weight:700;font-size:12px;color:var(--text-bright)">${escHtml(label)}: ${ok ? "completed" : "failed"}</div>
        ${summaryLine}
        ${errLine}
        ${runLine}
      </div>
    </div>`;
  // Action buttons sit lower in the tab than this top banner -- bring the
  // result into view so it's never an off-screen no-op.
  overall.scrollIntoView({behavior: "smooth", block: "center"});
}

async function bk_scanCatalog() {
  // Launches the UAC prompt -> on Yes, polls the helper -> refreshes
  // the tab when done. No type-to-confirm needed: scan is read-only.
  const overall = document.getElementById("bk-overall");
  if (overall) {
    overall.style.display = "block";
    overall.style.borderLeftColor = "var(--cyan)";
    overall.innerHTML = `<div style="font-size:12px">⏳ Requesting elevation (UAC prompt should appear)... if denied, the scan won't start.</div>`;
  }
  let launch;
  try {
    const r = await fetch("/api/backup/scan", {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"});
    launch = await r.json();
  } catch (e) {
    bk_showActionResult("Scan", {error: e.message}, false);
    return;
  }
  if (!launch.ok) {
    bk_showActionResult("Scan", launch, false);
    return;
  }
  const status = await bk_pollUntilDone(launch.session_id);
  const result = (status && status.result) || {ok: false, error: "no result"};
  bk_showActionResult("Scan", result, !!result.ok);
  if (result.ok) loadBackup(true);
}

async function bk_deleteVersion(versionId) {
  // Type-to-confirm: user must paste the version_id back verbatim.
  // Same defense-in-depth as PR #22 router reboot.
  if (!versionId) return;
  const typed = window.prompt(
    `Delete WindowsImageBackup version ${versionId}?\n\n` +
    `This calls 'wbadmin delete backup -version:<id>' under UAC and is irreversible.\n` +
    `The most-recent version is protected by a server-side rail.\n\n` +
    `To confirm, type the version ID back verbatim:`,
    ""
  );
  if (typed === null) return;  // cancelled
  if (typed !== versionId) {
    alert(`Cancelled: typed value didn't match the version ID.`);
    return;
  }
  const overall = document.getElementById("bk-overall");
  if (overall) {
    overall.style.display = "block";
    overall.style.borderLeftColor = "var(--cyan)";
    overall.innerHTML = `<div style="font-size:12px">⏳ Deleting ${escHtml(versionId)} (UAC prompt should appear)...</div>`;
  }
  let launch;
  try {
    const r = await fetch("/api/backup/delete-version", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({version_id: versionId, confirm_token: versionId}),
    });
    launch = await r.json();
  } catch (e) {
    bk_showActionResult("Delete version", {error: e.message}, false);
    return;
  }
  if (!launch.ok) {
    bk_showActionResult("Delete version", launch, false);
    return;
  }
  const status = await bk_pollUntilDone(launch.session_id);
  const result = (status && status.result) || {ok: false, error: "no result"};
  bk_showActionResult(`Delete version ${versionId}`, result, !!result.ok);
  if (result.ok) loadBackup(true);
}

async function bk_fhCleanup() {
  const raw = window.prompt(
    "File History cleanup: delete versions older than N days.\n\n" +
    "Examples: 365 keeps the last year. 0 keeps only the newest version.\n" +
    "Calls 'fhmanagew.exe -cleanup <N>' under UAC.\n\n" +
    "Enter days (0-3650):",
    "365"
  );
  if (raw === null) return;
  const days = parseInt(raw.trim(), 10);
  if (isNaN(days) || days < 0 || days > 3650) {
    alert(`Invalid: must be 0-3650.`);
    return;
  }
  const confirm = window.prompt(
    `Confirm: this will delete File History versions older than ${days} days.\n\n` +
    `To proceed, type exactly: CLEANUP ${days}`,
    ""
  );
  if (confirm === null) return;
  const expected = `CLEANUP ${days}`;
  if (confirm !== expected) {
    alert(`Cancelled: confirmation didn't match "${expected}".`);
    return;
  }
  // Build the progress banner via DOM (not innerHTML) so we can hand the
  // live status line to bk_pollUntilDone -- without it the banner froze at
  // a static "Running..." and the user couldn't tell anything was happening.
  const overall = document.getElementById("bk-overall");
  let statusEl = null;
  if (overall) {
    overall.textContent = "";
    overall.style.display = "block";
    overall.style.borderLeftColor = "var(--cyan)";
    const wrap = document.createElement("div");
    wrap.style.fontSize = "12px";
    const head = document.createElement("div");
    head.textContent = `⏳ Cleaning up File History versions older than ${days} days — approve the UAC prompt…`;
    statusEl = document.createElement("div");
    statusEl.style.cssText = "color:var(--muted);font-size:11px;margin-top:3px";
    statusEl.textContent = "Waiting for the elevated helper to start…";
    wrap.appendChild(head);
    wrap.appendChild(statusEl);
    overall.appendChild(wrap);
    // The Cleanup button lives near the bottom of the section but this
    // banner is at the top -- scroll it into view so the user actually sees
    // the progress + result instead of clicking into apparent silence.
    overall.scrollIntoView({behavior: "smooth", block: "center"});
  }
  let launch;
  try {
    const r = await fetch("/api/backup/file-history-cleanup", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({days: days, confirm_token: expected}),
    });
    launch = await r.json();
  } catch (e) {
    bk_showActionResult("File History cleanup", {error: e.message}, false);
    return;
  }
  if (!launch.ok) {
    bk_showActionResult("File History cleanup", launch, false);
    return;
  }
  if (statusEl) statusEl.textContent = "Elevated helper started — running fhmanagew…";
  const status = await bk_pollUntilDone(launch.session_id, statusEl);
  const result = (status && status.result) || {ok: false, error: "no result"};
  bk_showActionResult(`File History cleanup (${days}d)`, result, !!result.ok);
  if (result.ok) loadBackup(true);
}

// ── Scheduled auto-cleanup (in-app retention) ───────────────────────
// Registers a WEEKLY `fhmanagew -cleanup <N>` task so versions older than
// N days are pruned automatically. Built with DOM methods + textContent
// (no innerHTML) -- the security hook blocks innerHTML, and these strings
// would otherwise need escaping.
async function bk_renderCleanupSchedule() {
  const el = document.getElementById("bk-fh-schedule");
  if (!el) return;
  el.textContent = "";
  let st;
  try {
    const r = await fetch("/api/backup/fh-cleanup-schedule");
    st = await r.json();
  } catch {
    return;
  }
  // Surface the EFFECTIVE app-managed window up in the Retention row, so a
  // user who scheduled e.g. 180 days sees it there (not just buried in this
  // control). The native "NO LIMIT" policy is shown alongside as secondary.
  const eff = document.getElementById("bk-ret-effective");
  if (eff) {
    if (st && st.enabled) {
      eff.textContent = `App auto-cleanup: keep ~${st.days != null ? st.days : "?"} days (${(st.schedule || "weekly").toLowerCase()}) · `;
      eff.style.cssText = "color:var(--green);font-weight:600";
    } else {
      eff.textContent = "";
    }
  }
  const wrap = document.createElement("div");
  wrap.style.cssText = "padding-top:8px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap";
  const label = document.createElement("div");
  label.style.cssText = "font-size:11px;color:var(--muted)";
  if (st && st.enabled) {
    label.style.color = "var(--green)";
    label.textContent = `⏱ Auto-cleanup ON — deletes versions older than ${st.days != null ? st.days : "?"} days, ${(st.schedule || "weekly").toLowerCase()}.`;
    const off = document.createElement("button");
    off.textContent = "Turn off";
    off.style.cssText = "background:transparent;border:1px solid var(--red);color:var(--red);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px";
    off.onclick = bk_removeCleanupSchedule;
    wrap.appendChild(label);
    wrap.appendChild(off);
  } else {
    label.textContent = "Auto-cleanup off. Schedule a weekly cleanup to keep ~the last N days of versions (this is what actually enforces a rolling window).";
    const grp = document.createElement("div");
    grp.style.cssText = "display:flex;align-items:center;gap:6px";
    const inp = document.createElement("input");
    inp.type = "number";
    inp.id = "bk-sched-days";
    inp.value = "180";
    inp.min = "0";
    inp.max = "3650";
    inp.style.cssText = "width:64px;background:var(--surface);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font-size:11px";
    const unit = document.createElement("span");
    unit.textContent = "days";
    unit.style.cssText = "font-size:11px;color:var(--muted)";
    const on = document.createElement("button");
    on.textContent = "⏱ Schedule weekly";
    on.style.cssText = "background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px";
    on.onclick = bk_setupCleanupSchedule;
    grp.appendChild(inp);
    grp.appendChild(unit);
    grp.appendChild(on);
    wrap.appendChild(label);
    wrap.appendChild(grp);
  }
  el.appendChild(wrap);
}

async function bk_setupCleanupSchedule() {
  const inp = document.getElementById("bk-sched-days");
  const days = parseInt(((inp && inp.value) || "").trim(), 10);
  if (isNaN(days) || days < 0 || days > 3650) {
    alert("Enter a number of days between 0 and 3650.");
    return;
  }
  if (!window.confirm(`Schedule a WEEKLY task that deletes File History versions older than ${days} days?\n\nA UAC prompt will appear (the task runs with admin rights so it can reach the protected backup store).`)) return;
  let res;
  try {
    const r = await fetch("/api/backup/fh-cleanup-schedule", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({days: days}),
    });
    res = await r.json();
  } catch (e) {
    bk_showActionResult("Schedule auto-cleanup", {error: e.message}, false);
    return;
  }
  bk_showActionResult(`Schedule weekly auto-cleanup (>${days}d)`, res, !!res.ok);
  // schtasks ran elevated in a separate process; re-query after the user has
  // had time to accept UAC so the control reflects the new task.
  setTimeout(bk_renderCleanupSchedule, 2500);
  setTimeout(bk_renderCleanupSchedule, 6000);
}

async function bk_removeCleanupSchedule() {
  if (!window.confirm("Turn off the scheduled File History auto-cleanup?\n\nA UAC prompt will appear.")) return;
  let res;
  try {
    const r = await fetch("/api/backup/fh-cleanup-schedule/remove", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: "{}",
    });
    res = await r.json();
  } catch (e) {
    bk_showActionResult("Remove auto-cleanup", {error: e.message}, false);
    return;
  }
  bk_showActionResult("Remove auto-cleanup", res, !!res.ok);
  setTimeout(bk_renderCleanupSchedule, 2500);
  setTimeout(bk_renderCleanupSchedule, 6000);
}

// ── File History storage breakdown (where is the space going) ───────
// DOM-built (no innerHTML). Shows total size, per-store cards (active vs
// stale orphaned/reclaimable), and per-source bars; the heavy scan runs
// elevated (the active store is ACL-restricted).
function bk_fmtGB(bytes) {
  const gb = (bytes || 0) / 1073741824;
  return gb >= 10 ? Math.round(gb) + " GB" : gb.toFixed(1) + " GB";
}

async function bk_renderStorage() {
  const el = document.getElementById("bk-fh-storage");
  if (!el) return;
  el.textContent = "";
  const mk = (tag, css, txt) => {
    const e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (txt != null) e.textContent = txt;
    return e;
  };
  let data;
  try {
    data = await (await fetch("/api/backup/fh-storage")).json();
  } catch {
    return;
  }

  const head = mk("div", "display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap");
  head.appendChild(mk("div", "font-size:12px;font-weight:600;color:var(--text-bright)", "Storage usage — where the space is going"));
  const scanBtn = mk("button", "background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px",
    data.has_cache ? "↻ Re-scan (UAC)" : "🔍 Scan storage usage (UAC)");
  scanBtn.onclick = bk_scanStorage;
  head.appendChild(scanBtn);
  el.appendChild(head);

  const status = mk("div", "font-size:11px;color:var(--muted);margin-top:4px");
  status.id = "bk-storage-status";
  el.appendChild(status);

  if (!data.has_cache) {
    status.textContent = "File History keeps every version of every changed file, so the store can grow very large. Scan to see exactly where the space is going — total size and which source folders fill it (one-time UAC prompt).";
    return;
  }

  status.textContent = `Total File History: ${bk_fmtGB(data.total_bytes)} across ${data.store_count} store(s). Scanned ${(data.scanned_at || "").replace("T", " ")}. This is a size report only — it doesn't recommend deleting anything.`;

  (data.stores || []).forEach((s) => {
    const card = mk("div", "margin-top:10px;padding:8px 10px;border:1px solid var(--border);border-radius:6px");
    const row = mk("div", "display:flex;align-items:center;gap:8px;flex-wrap:wrap");
    row.appendChild(mk("span", "font-size:9px;font-weight:700;letter-spacing:.06em;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:1px 5px", "FILE HISTORY STORE"));
    row.appendChild(mk("span", "font-size:13px;font-weight:700;color:var(--text-bright)", bk_fmtGB(s.size_bytes) + (s.capped ? "+ (scan capped)" : "")));
    row.appendChild(mk("span", "font-size:11px;color:var(--muted)", `${(s.file_count || 0).toLocaleString()} files`));
    card.appendChild(row);
    card.appendChild(mk("div", "margin-top:3px;font-size:10px;color:var(--ink-faint);word-break:break-all", s.path));
    // Per-source bars.
    (s.by_source || []).slice(0, 6).forEach((src) => {
      if (!src.size_bytes) return;
      const pct = s.size_bytes ? Math.max(2, Math.round((src.size_bytes / s.size_bytes) * 100)) : 0;
      const line = mk("div", "display:flex;align-items:center;gap:6px;margin-top:4px");
      line.appendChild(mk("span", "font-size:10px;color:var(--muted);width:60px;flex-shrink:0", src.name === "C" ? "C: drive" : src.name === "$OF" ? "OneDrive" : src.name));
      const track = mk("div", "flex:1;height:6px;background:rgba(255,255,255,.07);border-radius:4px;overflow:hidden");
      track.appendChild(mk("div", `width:${pct}%;height:100%;background:var(--cyan);border-radius:4px`));
      line.appendChild(track);
      line.appendChild(mk("span", "font-size:10px;color:var(--text);width:64px;text-align:right;flex-shrink:0", bk_fmtGB(src.size_bytes)));
      card.appendChild(line);
    });
    el.appendChild(card);
  });
}

async function bk_scanStorage() {
  const status = document.getElementById("bk-storage-status");
  if (status) status.textContent = "⏳ Requesting elevation (UAC prompt should appear)… then walking the drive — this can take a minute on a large store.";
  let launch;
  try {
    launch = await (await fetch("/api/backup/fh-storage-scan", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({})})).json();
  } catch (e) {
    if (status) status.textContent = "Scan failed to start: " + e.message;
    return;
  }
  if (!launch.ok) {
    if (status) status.textContent = "Scan failed to start: " + (launch.error || "unknown");
    return;
  }
  await bk_pollUntilDone(launch.session_id, status);
  bk_renderStorage();
}

async function bk_revealPath(path) {
  try {
    await fetch("/api/disk/open", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({path: path})});
  } catch (e) {
    alert("Could not open Explorer: " + e.message);
  }
}

async function loadBackup(preserveBanner = false) {
  // preserveBanner=true keeps whatever bk_showActionResult just wrote in
  // #bk-overall (the outcome of a scan/cleanup/delete) instead of clobbering
  // it with the overall-health summary -- otherwise the action result is
  // wiped within a second and the user can't tell what happened.
  const overall = document.getElementById("bk-overall");
  const s1body = document.getElementById("bk-sec1-body");
  const s2body = document.getElementById("bk-sec2-body");
  if (s1body) s1body.innerHTML = '<div style="color:var(--muted);padding:8px">Loading…</div>';
  if (s2body) s2body.innerHTML = '<div style="color:var(--muted);padding:8px">Loading…</div>';
  bk_setStatusPill("bk-sec1-status", "info", "loading…");
  bk_setStatusPill("bk-sec2-status", "info", "loading…");

  // 3 parallel fetches: summary (for overall banner) + Section 1 detail + Section 2 detail
  let summary, wb, fh;
  try {
    const [rS, rW, rF] = await Promise.all([
      fetch("/api/backup/summary"),
      fetch("/api/backup/windows-backups"),
      fetch("/api/backup/file-history"),
    ]);
    summary = await rS.json();
    wb = await rW.json();
    fh = await rF.json();
  } catch (e) {
    if (s1body) s1body.innerHTML = `<div style="color:var(--red);padding:8px">Fetch failed: ${escHtml(e.message)}</div>`;
    return;
  }

  // ── Overall banner ────────────────────────────────────────────────
  if (!preserveBanner && overall && summary && summary.overall_health) {
    const lvl = summary.overall_health.level || "info";
    const s = bk_pillStyle(lvl);
    overall.style.display = "block";
    overall.style.borderLeftColor = s.border;
    overall.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:18px">${lvl === "critical" ? "🚨" : (lvl === "warning" ? "⚠️" : (lvl === "ok" ? "✅" : "ℹ️"))}</span>
        <div style="flex:1">
          <div style="font-weight:700;color:${s.fg};text-transform:uppercase;font-size:10px;margin-bottom:2px">${escHtml(lvl)}</div>
          <div style="font-size:12px;color:var(--text)">${escHtml(summary.overall_health.reason || "")}</div>
        </div>
      </div>`;
  }

  bk_renderSchedule(summary && summary.windows_backup_schedule);

  // ── Section 1: Windows backups ───────────────────────────────────
  if (s1body) {
    // Header bar with the Scan-now button is always present (regardless
    // of cache state) so the user has a clear path to populate or refresh.
    const scanBar = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:0 0 10px 0;border-bottom:1px solid var(--border);margin-bottom:10px">
        <div style="font-size:11px;color:var(--muted)">Requires elevation (UAC prompt). Reads the catalogue + walks <code>WindowsImageBackup</code> for sizes.</div>
        <button onclick="bk_scanCatalog()" style="background:var(--cyan);border:none;color:#000;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:700">🔍 Scan now</button>
      </div>`;
    if (!wb.has_cache) {
      bk_setStatusPill("bk-sec1-status", "info", "not yet scanned");
      s1body.innerHTML = `
        ${scanBar}
        <div style="padding:10px 0;line-height:1.55">
          <p style="margin:0 0 8px 0">WindowsImageBackup catalogue reads require elevation, so we cache the catalogue to <code>backup_cache.json</code>. No scan has been run yet.</p>
          <p style="margin:0;color:var(--muted);font-size:11px">Click <strong>Scan now</strong> above to populate. Windows will prompt for permission; the elevated helper runs <code>wbadmin get versions</code> and writes the cache.</p>
        </div>`;
    } else {
      bk_setStatusPill("bk-sec1-status", wb.version_count > 0 ? "info" : "warning", `${wb.version_count} version(s)`);
      const total = bk_humanBytes(wb.total_size_bytes);
      const scannedAt = wb.scanned_at ? new Date(wb.scanned_at).toLocaleString() : "—";
      const ageH = wb.cache_age_seconds == null ? "" : ` (${Math.floor(wb.cache_age_seconds / 3600)}h ago)`;
      const versions = wb.versions || [];
      // Index 0 = newest = always disabled (safety: keep >=1 version).
      const rows = versions.map((v, i) => {
        const isNewest = i === 0;
        const disabledTip = isNewest ? 'title="Most-recent version cannot be deleted -- always keep at least one"' : "";
        const btn = isNewest
          ? `<span style="color:var(--muted);font-size:10px">🛡 keep</span>`
          : `<button onclick="bk_deleteVersion(${JSON.stringify(v.version_id || "").replace(/"/g, "&quot;")})" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px">🗑 Delete</button>`;
        return `
        <tr>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px">${escHtml(v.version_id || "")}</td>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">${escHtml(v.backup_time || "")}</td>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">${escHtml(v.target || "")}</td>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px;text-align:right">${bk_humanBytes(v.size_bytes)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">${escHtml(Array.isArray(v.can_recover) ? v.can_recover.join(", ") : (v.can_recover || ""))}</td>
          <td style="padding:6px 10px;border-bottom:1px solid var(--border);text-align:right" ${disabledTip}>${btn}</td>
        </tr>`;
      }).join("");
      s1body.innerHTML = `
        ${scanBar}
        <div style="display:flex;gap:24px;flex-wrap:wrap;padding:8px 0 12px 0;color:var(--muted);font-size:11px">
          <div><strong style="color:var(--text-bright)">${wb.version_count}</strong> version(s)</div>
          <div><strong style="color:var(--text-bright)">${total}</strong> total</div>
          <div>Last scan: <strong style="color:var(--text-bright)">${escHtml(scannedAt)}</strong>${escHtml(ageH)}</div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr style="text-align:left;color:var(--muted);font-weight:600">
            <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Version ID</th>
            <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Backup time</th>
            <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Target</th>
            <th style="padding:6px 10px;border-bottom:1px solid var(--border);text-align:right">Size</th>
            <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Can recover</th>
            <th style="padding:6px 10px;border-bottom:1px solid var(--border);text-align:right">Action</th>
          </tr></thead>
          <tbody>${rows || `<tr><td colspan="6" style="padding:14px;color:var(--muted);text-align:center">No versions catalogued.</td></tr>`}</tbody>
        </table>`;
    }
  }

  // ── Section 2: File History ───────────────────────────────────────
  if (s2body) {
    if (!fh.configured) {
      bk_setStatusPill("bk-sec2-status", "info", "not configured");
      s2body.innerHTML = `<div style="padding:10px 0;color:var(--muted)">File History is not configured on this machine. Configure it from Control Panel → System and Security → File History to enable.</div>`;
    } else {
      const cfg = fh.config || {};
      const target = cfg.target || {};
      const health = fh.health || {};
      bk_setStatusPill("bk-sec2-status", health.level || "info", (health.level || "info").toUpperCase());
      const enabled = cfg.enabled ? '<span style="color:var(--green);font-weight:600">ENABLED</span>' : '<span style="color:var(--muted)">DISABLED</span>';
      const targetExistsLabel = fh.target_path_exists === null
        ? "—"
        : (fh.target_path_exists ? '<span style="color:var(--green)">reachable</span>' : '<span style="color:var(--red)">unreachable</span>');
      // When backups are confirmed healthy (a fresh catalog), a store probe
      // that can't read the folder is NORMAL (ACL-protected store / non-
      // standard path) -- don't alarm the user with a red "missing". Only
      // show red "missing" when the verdict itself is critical.
      const storeConfirmed = fh.target_backup_store_exists === true;
      const storeHealthy = (health.level || "info") !== "critical";
      const storeExistsLabel = storeConfirmed
        ? '<span style="color:var(--green)">present</span>'
        : (storeHealthy
            ? '<span style="color:var(--muted)">not readable from tray (ACL-protected — normal)</span>'
            : '<span style="color:var(--red)">missing</span>');
      const catalogLabel = fh.catalog_exists
        ? `${bk_humanBytes(fh.catalog_size_bytes)} · last write ${fh.catalog_mtime || "—"} (${fh.catalog_age_days?.toFixed?.(1) || "?"} days ago)`
        : "(not present)";
      const stagingRatio = fh.staging_usage_ratio == null ? "" : ` (${(fh.staging_usage_ratio * 100).toFixed(1)}%)`;
      const folderCount = (cfg.user_folders || []).length + (cfg.libraries || []).reduce((sum, lib) => sum + (lib.folders || []).length, 0);
      const healthStyle = bk_pillStyle(health.level || "info");
      s2body.innerHTML = `
        <div style="padding:10px 0">
          <div style="padding:10px 14px;border-left:3px solid ${healthStyle.border};background:var(--surface);border-radius:6px;margin-bottom:12px">
            <div style="font-weight:600;color:${healthStyle.fg};margin-bottom:2px">${escHtml((health.level || "info").toUpperCase())}</div>
            <div style="font-size:12px;color:var(--text)">${escHtml(health.reason || "")}</div>
          </div>
          <div id="bk-fh-storage" style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)"></div>
          <div style="display:grid;grid-template-columns:140px 1fr;gap:6px 16px;font-size:12px">
            <div style="color:var(--muted)">Status</div><div>${enabled}</div>
            <div style="color:var(--muted)">Target</div><div>${escHtml(target.name || "—")} · <code>${escHtml(target.url || "")}</code> (${escHtml(target.drive_type || "—")})</div>
            <div style="color:var(--muted)">Target reachable</div><div>${targetExistsLabel}</div>
            <div style="color:var(--muted)">Backup store on target</div><div>${storeExistsLabel} (<code>${escHtml(target.backup_store_path || "")}</code>)</div>
            <div style="color:var(--muted)">Frequency</div><div>${cfg.frequency_seconds ? Math.round(cfg.frequency_seconds / 60) + " min" : "—"}</div>
            <div style="color:var(--muted)">Retention</div><div><span id="bk-ret-effective"></span>${escHtml(cfg.retention_policy || "—")}${cfg.retention_min_age_months ? ` · keep at least ${cfg.retention_min_age_months} mo` : ""} <span style="color:var(--ink-faint);font-size:10px">(File History's native policy — set in Control Panel → Advanced settings)</span></div>
            <div style="color:var(--muted)">Catalog</div><div>${catalogLabel}</div>
            <div style="color:var(--muted)">Staging</div><div>${bk_humanBytes(fh.staging_usage_bytes)} across ${fh.staging_file_count} file(s)${stagingRatio}</div>
            <div style="color:var(--muted)">Folders watched</div><div>${folderCount} folder(s) across ${(cfg.libraries || []).length} libraries + ${(cfg.user_folders || []).length} user folders</div>
          </div>
          <div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px">
            <div style="font-size:11px;color:var(--muted)">One-time delete of versions older than N days (<code>fhmanagew.exe -cleanup</code>, UAC). <strong>0</strong> = keep only newest. Does <strong>not</strong> change the retention policy above.</div>
            <button onclick="bk_fhCleanup()" style="background:transparent;border:1px solid var(--orange);color:var(--orange);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px">🧹 Cleanup old versions</button>
          </div>
          <div id="bk-fh-schedule" style="margin-top:4px"></div>
        </div>`;
      bk_renderCleanupSchedule();
      bk_renderStorage();
    }
  }

  // Section 3 -- OneDrive -> iCloud rule editor (backlog #46 PR-1).
  // Loads independently of sections 1+2; failures don't cascade.
  loadCloudCopy();

  // Also load the actions-history panel below (best-effort -- a slow
  // history fetch shouldn't block the section renders above).
  loadBackupActionsHistory();
}

// ── Section 3 — OneDrive -> iCloud replicator (backlog #46 PR-1) ─────
// Rule editor + preview only. No actual copying happens in PR-1; the
// Start button is stubbed with a "coming in PR-2" tooltip.

let _ccRules = null;  // Cache the current rules dict between edits.

function cc_renderListEditor(elId, items, placeholder) {
  // Renders a small editable list. The user adds items by typing in
  // an input + clicking +; removes via the × per row.
  const ul = document.getElementById(elId);
  if (!ul) return;
  ul.innerHTML = (items || []).map((s, i) => `
    <li style="display:flex;align-items:center;gap:6px;padding:3px 0;font-size:11px">
      <code style="flex:1;background:var(--surface);padding:2px 6px;border-radius:3px">${escHtml(s)}</code>
      <button onclick="cc_removeItem('${elId}', ${i})" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:0 6px;border-radius:3px;cursor:pointer;font-size:10px">×</button>
    </li>`).join("");
  // Bug-fix 2026-05-25: only set placeholder when the caller supplied
  // one (initial render from loadCloudCopy). Follow-up renders (after
  // add/remove) call us with 2 args, in which case we MUST leave the
  // input's placeholder alone -- otherwise the example text the user
  // relied on to learn what to type vanishes after the first add.
  if (placeholder !== undefined) {
    const adder = document.getElementById(elId + "-add-input");
    if (adder) adder.placeholder = placeholder;
  }
}

// elId -> rules-key mapping. Used by add/remove so the call sites don't
// have to repeat the rules-key.
const _CC_ELID_TO_KEY = {
  "cc-folders": "exclude_folders",
  "cc-extensions": "exclude_extensions",
  "cc-globs": "exclude_filename_globs",
};

function cc_addItem(elId, key) {
  const adder = document.getElementById(elId + "-add-input");
  if (!adder) return;
  // Bug-fix 2026-05-25 (second pass): visible feedback when the user
  // clicks + (or hits Enter) with an empty input. The original code
  // silently returned, which felt to the user like "the button does
  // nothing." Now we focus the input + briefly flash its border red +
  // swap the placeholder to an explicit "Type something first" hint.
  if (!adder.value.trim()) {
    adder.focus();
    adder.style.borderColor = "var(--red)";
    const originalPlaceholder = adder.placeholder;
    adder.placeholder = "Type a value first, then click +";
    setTimeout(() => {
      adder.style.borderColor = "";
      adder.placeholder = originalPlaceholder;
    }, 1800);
    return;
  }
  if (!_ccRules) return;
  _ccRules[key] = _ccRules[key] || [];
  _ccRules[key].push(adder.value.trim());
  adder.value = "";
  cc_renderListEditor(elId, _ccRules[key]);
  // Bug-fix 2026-05-25 (first pass): persist on EVERY add. The
  // original code relied on the call-site adding "; cc_saveRules();"
  // after each cc_addItem call, but the symmetric cc_removeItem never
  // did -- user clicked × and the deletion looked like it worked but
  // came back on reload. Centralising the save here lets cc_removeItem
  // mirror the contract.
  cc_saveRules();
}

function cc_removeItem(elId, idx) {
  const key = _CC_ELID_TO_KEY[elId];
  if (!key || !_ccRules) return;
  _ccRules[key].splice(idx, 1);
  cc_renderListEditor(elId, _ccRules[key]);
  // Bug-fix 2026-05-25: persist removals to the server. Original PR-1
  // code only updated _ccRules + the DOM without calling cc_saveRules,
  // so the next page reload brought the "deleted" item back. User
  // reported "the dropdown buttons for exclusions don't work" --
  // confirmed by a Playwright probe that showed the server's rules
  // were unchanged after a × click.
  cc_saveRules();
}

async function cc_saveRules() {
  if (!_ccRules) return;
  // Pull the personal-vault toggle from the DOM (it lives outside the
  // three list-editors).
  const pvToggle = document.getElementById("cc-include-vault");
  if (pvToggle) _ccRules.include_personal_vault = !!pvToggle.checked;
  const statusEl = document.getElementById("cc-save-status");
  if (statusEl) statusEl.textContent = "saving…";
  try {
    const r = await fetch("/api/cloudcopy/rules", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({rules: _ccRules}),
    });
    const data = await r.json();
    if (!data.ok) {
      if (statusEl) statusEl.textContent = "error: " + (data.error || "save failed");
      return;
    }
    if (statusEl) statusEl.textContent = "saved";
    setTimeout(() => { if (statusEl) statusEl.textContent = ""; }, 2500);
  } catch (e) {
    if (statusEl) statusEl.textContent = "error: " + e.message;
  }
}

async function cc_preview() {
  const out = document.getElementById("cc-preview-body");
  if (!out) return;
  out.innerHTML = '<div style="color:var(--muted);padding:8px">Walking OneDrive (this may take a few seconds)…</div>';
  // Save rules first so preview reflects what's on screen.
  await cc_saveRules();
  let data;
  try {
    const r = await fetch("/api/cloudcopy/preview");
    data = await r.json();
  } catch (e) {
    out.innerHTML = `<div style="color:var(--red);padding:8px">Preview failed: ${escHtml(e.message)}</div>`;
    return;
  }
  const incBytes = bk_humanBytes(data.included_bytes);
  const capNote = data.file_cap_hit ? ' <span style="color:var(--orange);font-size:10px">(walker stopped at 50,000 files — counts are lower bounds)</span>' : "";
  const includedSample = (data.included_sample || []).map(s =>
    `<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:10px"><span style="color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${escHtml(s.rel_path)}</span><span style="color:var(--muted);margin-left:8px">${bk_humanBytes(s.size)}</span></div>`
  ).join("") || '<div style="color:var(--muted);padding:4px">(none)</div>';
  const excludedSample = (data.excluded_sample || []).map(s =>
    `<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:10px"><span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${escHtml(s.rel_path)}</span><span style="color:var(--orange);margin-left:8px;font-size:9px">${escHtml(s.reason)}</span></div>`
  ).join("") || '<div style="color:var(--muted);padding:4px">(none)</div>';
  out.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:11px">
      <div>
        <div style="font-weight:600;color:var(--green);margin-bottom:6px">✅ Would copy: ${data.included_count.toLocaleString()} files · ${incBytes}${capNote}</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:4px">First ${(data.included_sample || []).length} sample paths:</div>
        <div style="max-height:200px;overflow-y:auto;border:1px solid var(--border);padding:6px;border-radius:4px;background:var(--surface)">${includedSample}</div>
      </div>
      <div>
        <div style="font-weight:600;color:var(--orange);margin-bottom:6px">⏭ Excluded: ${data.excluded_count.toLocaleString()} files</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:4px">First ${(data.excluded_sample || []).length} sample paths + reasons:</div>
        <div style="max-height:200px;overflow-y:auto;border:1px solid var(--border);padding:6px;border-radius:4px;background:var(--surface)">${excludedSample}</div>
      </div>
    </div>
    <div style="margin-top:10px;font-size:10px;color:var(--muted);font-family:var(--font-mono)">
      Source: ${escHtml(data.source_root)} → Destination: ${escHtml(data.destination_root)}<br>
      Walked at ${escHtml(data.walked_at)}
    </div>`;
}

// ── PR-2: copy engine + crash-safe resume ────────────────────────
//
// Start: prompt type-to-confirm -> POST /run -> poll /status every 2s
// Cancel: POST /cancel with session_id -> worker drains current file
// Resume: detected on tab load via /resume-state -> banner -> /resume
// Discard: banner -> /discard-crashed

let _ccActiveSession = null;
let _ccPollTimer = null;

function cc_humanBytes(n) {
  if (n === null || n === undefined || isNaN(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i === 0 ? 0 : 2) + " " + units[i];
}

function cc_setStartButton(enabled, label) {
  const btn = document.getElementById("cc-start-btn");
  if (!btn) return;
  btn.disabled = !enabled;
  btn.textContent = label || (enabled ? "▶ Start copy" : "⏳ Running…");
  btn.style.cursor = enabled ? "pointer" : "not-allowed";
  btn.style.background = enabled ? "var(--cyan)" : "var(--surface)";
  btn.style.color = enabled ? "#000" : "var(--muted)";
}

async function cc_startCopy() {
  // Save rules first so the session uses the current screen state.
  await cc_saveRules();
  const confirm = window.prompt(
    "Start the OneDrive → iCloud copy?\n\n" +
    "Source: " + (_ccRules?.source_root || "C:\\Users\\…\\OneDrive") + "\n" +
    "Destination: " + (_ccRules?.destination_root || "C:\\Users\\…\\iCloudDrive\\OneDrive-Mirror") + "\n\n" +
    "This is a long-running write operation. To confirm, type exactly:\n" +
    "    START CLOUD COPY",
    ""
  );
  if (confirm === null) return;
  if (confirm !== "START CLOUD COPY") { alert("Cancelled: confirmation didn't match."); return; }

  cc_setStartButton(false, "⏳ Starting…");
  let launch;
  try {
    const r = await fetch("/api/cloudcopy/run", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({confirm_token: "START CLOUD COPY"}),
    });
    launch = await r.json();
  } catch (e) {
    alert("Launch failed: " + e.message);
    cc_setStartButton(true);
    return;
  }
  if (!launch.ok) {
    alert("Launch refused: " + (launch.error || "unknown"));
    cc_setStartButton(true);
    return;
  }
  _ccActiveSession = launch.session_id;
  cc_startStatusPoll();
}

function cc_startStatusPoll() {
  if (_ccPollTimer) clearInterval(_ccPollTimer);
  _ccPollTimer = setInterval(cc_pollStatus, 2000);
  cc_pollStatus();
}

function cc_stopStatusPoll() {
  if (_ccPollTimer) clearInterval(_ccPollTimer);
  _ccPollTimer = null;
}

async function cc_pollStatus() {
  if (!_ccActiveSession) { cc_stopStatusPoll(); return; }
  const statusEl = document.getElementById("cc-run-status");
  if (!statusEl) { cc_stopStatusPoll(); return; }
  let data;
  try {
    const r = await fetch("/api/cloudcopy/status?session_id=" + encodeURIComponent(_ccActiveSession));
    data = await r.json();
  } catch (e) {
    statusEl.style.display = "block";
    statusEl.innerHTML = `<span style="color:var(--red)">Status fetch failed: ${escHtml(e.message)}</span>`;
    return;
  }

  if (data.state === "running" || data.state === "starting") {
    statusEl.style.display = "block";
    const pct = (data.percent || 0).toFixed(1);
    statusEl.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px">
        <div style="font-weight:700;color:var(--cyan)">⏳ Copying… ${pct}%</div>
        <button onclick="cc_cancelCopy()" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px">Cancel</button>
      </div>
      <div style="background:var(--surface);height:6px;border-radius:3px;overflow:hidden;margin-bottom:8px">
        <div style="background:var(--cyan);height:100%;width:${pct}%"></div>
      </div>
      <div style="font-size:11px;color:var(--muted);display:flex;gap:16px;flex-wrap:wrap">
        <span>📄 ${data.cursor || 0} / ${data.total || 0} files</span>
        <span>✅ ${data.files_completed || 0} copied</span>
        <span>⏭ ${data.files_skipped || 0} skipped (unchanged)</span>
        ${(data.files_failed || 0) > 0 ? `<span style="color:var(--red)">❌ ${data.files_failed} failed</span>` : ""}
        <span>💾 ${cc_humanBytes(data.bytes_copied)} copied</span>
      </div>`;
    return;
  }

  if (data.state === "finished") {
    cc_stopStatusPoll();
    _ccActiveSession = null;
    const h = data.history || {};
    const ok = h.status === "completed" || h.status === "completed_truncated";
    const color = ok ? "var(--green)" : (h.status === "cancelled" ? "var(--orange)" : "var(--red)");
    statusEl.style.display = "block";
    statusEl.style.borderLeftColor = color;
    statusEl.innerHTML = `
      <div style="font-weight:700;color:${color};margin-bottom:4px">${ok ? "✅" : (h.status === "cancelled" ? "⏸" : "❌")} Session ${escHtml(h.status || "ended")}</div>
      <div style="font-size:11px;color:var(--text)">
        ${h.files_completed_count || 0} copied, ${h.files_skipped_count || 0} skipped, ${h.files_failed_count || 0} failed · ${cc_humanBytes(h.bytes_copied)} written
        ${h.cap_hit ? ' · <span style="color:var(--orange)">50 GB session cap hit -- click Start again to continue</span>' : ""}
      </div>`;
    cc_setStartButton(true);
    return;
  }

  if (data.state === "missing") {
    cc_stopStatusPoll();
    _ccActiveSession = null;
    statusEl.style.display = "block";
    statusEl.innerHTML = `<span style="color:var(--orange)">Session not found (may have finished between polls).</span>`;
    cc_setStartButton(true);
    return;
  }
}

async function cc_cancelCopy() {
  if (!_ccActiveSession) return;
  if (!window.confirm("Cancel the copy? Files already copied stay; the in-progress file is rolled back.")) return;
  try {
    await fetch("/api/cloudcopy/cancel", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({session_id: _ccActiveSession}),
    });
  } catch (e) {
    alert("Cancel request failed: " + e.message);
  }
  // Don't stop polling -- the worker drains its current file then writes the
  // "cancelled" history row, and the next poll picks that up.
}

async function cc_renderResumeBanner() {
  const banner = document.getElementById("cc-resume-banner");
  if (!banner) return;
  let data;
  try {
    const r = await fetch("/api/cloudcopy/resume-state");
    data = await r.json();
  } catch {
    banner.style.display = "none";
    return;
  }
  if (!data.has_crashed) {
    banner.style.display = "none";
    return;
  }
  const s = data.state || {};
  const total = (s.plan || []).length;
  const cursor = s.cursor || 0;
  const pct = total ? ((cursor / total) * 100).toFixed(1) : 0;
  banner.style.display = "block";
  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px">
      <div style="font-size:18px">⚠️</div>
      <div style="flex:1">
        <div style="font-weight:700;color:var(--orange);margin-bottom:4px">Previous run crashed</div>
        <div style="color:var(--text);font-size:11px;margin-bottom:6px">
          Crashed at file ${cursor.toLocaleString()} / ${total.toLocaleString()} (${pct}%, ${cc_humanBytes(s.bytes_copied)} copied) · started ${escHtml(s.started_at || "—")}
        </div>
        <div style="color:var(--muted);font-size:10px;margin-bottom:8px">
          Resume continues from the same cursor using the same rule snapshot. Discard writes a "discarded" history entry + clears the state.
        </div>
        <div style="display:flex;gap:8px">
          <button onclick="cc_resume()" style="background:var(--cyan);border:none;color:#000;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">▶ Resume</button>
          <button onclick="cc_discard()" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px">Discard</button>
        </div>
      </div>
    </div>`;
}

async function cc_resume() {
  let data;
  try {
    const r = await fetch("/api/cloudcopy/resume", {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"});
    data = await r.json();
  } catch (e) {
    alert("Resume failed: " + e.message);
    return;
  }
  if (!data.ok) { alert("Resume refused: " + (data.error || "unknown")); return; }
  document.getElementById("cc-resume-banner").style.display = "none";
  _ccActiveSession = data.session_id;
  cc_setStartButton(false, "⏳ Resuming…");
  cc_startStatusPoll();
}

async function cc_discard() {
  if (!window.confirm("Discard the crashed session? This writes a 'discarded' history entry and clears the state file. The next Start begins from scratch.")) return;
  try {
    await fetch("/api/cloudcopy/discard-crashed", {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"});
  } catch (e) {
    alert("Discard failed: " + e.message);
    return;
  }
  document.getElementById("cc-resume-banner").style.display = "none";
}

async function loadCloudCopy() {
  const body = document.getElementById("bk-sec3-body");
  if (!body) return;
  body.innerHTML = '<div style="color:var(--muted);padding:8px">Loading rules…</div>';
  let data;
  try {
    const r = await fetch("/api/cloudcopy/rules");
    data = await r.json();
  } catch (e) {
    body.innerHTML = `<div style="color:var(--red);padding:8px">Failed: ${escHtml(e.message)}</div>`;
    return;
  }
  _ccRules = data.rules || {};
  bk_setStatusPill("bk-sec3-status", "info", "PR-1: rules + preview");

  // Top: a small explainer + the Start button (stubbed until PR-2).
  body.innerHTML = `
    <div style="padding:10px 0 14px 0;color:var(--text);font-size:12px;line-height:1.5">
      <div style="margin-bottom:6px">One-way replicator: pushes everything under <code>OneDrive</code> into <code>iCloudDrive/OneDrive-Mirror/</code>. Default = mirror everything; configure exclusion rules below to strike out what you don't want.</div>
      <div style="color:var(--muted);font-size:11px">Personal Vault is excluded by default (encrypted at rest by OneDrive; copying it sideways defeats the protection). Toggle below to override.</div>
    </div>

    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);margin-bottom:12px">
      <div style="font-size:11px;color:var(--muted)">
        <label style="cursor:pointer">
          <input type="checkbox" id="cc-include-vault" ${_ccRules.include_personal_vault ? "checked" : ""} onchange="cc_saveRules()" style="margin-right:6px">
          Include Personal Vault (NOT recommended — overrides default protection)
        </label>
      </div>
      <button onclick="cc_preview()" style="background:var(--cyan);border:none;color:#000;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:700">🔍 Preview what would be copied</button>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px">

      <div>
        <div style="font-size:12px;font-weight:700;color:var(--text-bright);margin-bottom:6px">Exclude folders</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:6px">Match by folder NAME (any depth, case-insensitive).</div>
        <ul id="cc-folders" style="list-style:none;padding:0;margin:0 0 6px 0;max-height:180px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;background:var(--surface);padding:6px"></ul>
        <div style="display:flex;gap:4px">
          <input id="cc-folders-add-input" type="text" placeholder="Backup Data" onkeydown="if(event.key==='Enter'){event.preventDefault();cc_addItem('cc-folders','exclude_folders');}" style="flex:1;padding:3px 6px;font-size:11px;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:3px">
          <button onclick="cc_addItem('cc-folders', 'exclude_folders')" style="background:var(--cyan);border:none;color:#000;padding:3px 10px;border-radius:3px;cursor:pointer;font-size:11px;font-weight:700">+</button>
        </div>
      </div>

      <div>
        <div style="font-size:12px;font-weight:700;color:var(--text-bright);margin-bottom:6px">Exclude extensions</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:6px">Must include the dot. Case-insensitive.</div>
        <ul id="cc-extensions" style="list-style:none;padding:0;margin:0 0 6px 0;max-height:180px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;background:var(--surface);padding:6px"></ul>
        <div style="display:flex;gap:4px">
          <input id="cc-extensions-add-input" type="text" placeholder=".iso" onkeydown="if(event.key==='Enter'){event.preventDefault();cc_addItem('cc-extensions','exclude_extensions');}" style="flex:1;padding:3px 6px;font-size:11px;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:3px">
          <button onclick="cc_addItem('cc-extensions', 'exclude_extensions')" style="background:var(--cyan);border:none;color:#000;padding:3px 10px;border-radius:3px;cursor:pointer;font-size:11px;font-weight:700">+</button>
        </div>
      </div>

      <div>
        <div style="font-size:12px;font-weight:700;color:var(--text-bright);margin-bottom:6px">Exclude filename globs</div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:6px">Use * and ? wildcards. Match filename only.</div>
        <ul id="cc-globs" style="list-style:none;padding:0;margin:0 0 6px 0;max-height:180px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;background:var(--surface);padding:6px"></ul>
        <div style="display:flex;gap:4px">
          <input id="cc-globs-add-input" type="text" placeholder="~$*" onkeydown="if(event.key==='Enter'){event.preventDefault();cc_addItem('cc-globs','exclude_filename_globs');}" style="flex:1;padding:3px 6px;font-size:11px;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:3px">
          <button onclick="cc_addItem('cc-globs', 'exclude_filename_globs')" style="background:var(--cyan);border:none;color:#000;padding:3px 10px;border-radius:3px;cursor:pointer;font-size:11px;font-weight:700">+</button>
        </div>
      </div>

    </div>

    <div id="cc-preview-body" style="margin-bottom:12px"></div>

    <!-- Resume banner (PR-2) -- only visible when a crashed session is detected.
         Populated by cc_renderResumeBanner() at the bottom of loadCloudCopy. -->
    <div id="cc-resume-banner" style="display:none;padding:10px 14px;background:var(--card);border:1px solid var(--orange);border-left:4px solid var(--orange);border-radius:8px;margin-bottom:12px;font-size:12px"></div>

    <!-- Live status (PR-2) -- only visible while a session is running. -->
    <div id="cc-run-status" style="display:none;padding:10px 14px;background:var(--card);border:1px solid var(--cyan);border-left:4px solid var(--cyan);border-radius:8px;margin-bottom:12px;font-size:12px"></div>

    <!-- Schedule status (PR-3 placeholder) -- DEFAULT OFF -->
    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 0;border-top:1px solid var(--border);font-size:11px;color:var(--muted)">
      <span>📅 Scheduled run: <strong style="color:var(--muted)">disabled by default</strong> · ${_ccRules.schedule_enabled ? "ENABLED at " + escHtml(_ccRules.schedule_time || "02:00") : "click below to enable"}</span>
      <button disabled title="Schedule toggle ships in #46 PR-3 (kept OFF by default per user spec)" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 10px;border-radius:4px;cursor:not-allowed;font-size:11px">Schedule (PR-3)</button>
    </div>

    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding-top:10px;border-top:1px solid var(--border)">
      <div style="font-size:10px;color:var(--muted)">Save status: <span id="cc-save-status"></span></div>
      <button id="cc-start-btn" onclick="cc_startCopy()" style="background:var(--cyan);border:none;color:#000;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:700">▶ Start copy</button>
    </div>`;

  // Initial-render placeholders show CONCRETE examples so the user has
  // something to imitate. (Original "folder name" / ".ext" / "glob
  // pattern" was too abstract -- user didn't realise they had to type
  // a value before clicking + and the empty click silently no-op'd.)
  cc_renderListEditor("cc-folders", _ccRules.exclude_folders || [], "e.g. Backup Data");
  cc_renderListEditor("cc-extensions", _ccRules.exclude_extensions || [], "e.g. .iso");
  cc_renderListEditor("cc-globs", _ccRules.exclude_filename_globs || [], "e.g. ~$*");

  // PR-2: check for an active session (resume-state route returns
  // active_session_id when a worker is running) OR a crashed session.
  try {
    const r = await fetch("/api/cloudcopy/resume-state");
    const rs = await r.json();
    if (rs.active_session_id) {
      // Pick up the in-flight session from a prior tab visit.
      _ccActiveSession = rs.active_session_id;
      cc_setStartButton(false, "⏳ Running…");
      cc_startStatusPoll();
    } else if (rs.has_crashed) {
      // Surface the resume banner.
      cc_renderResumeBanner();
    }
  } catch {
    // Resume-state probe is best-effort; not fatal if it fails.
  }
}

async function loadBackupActionsHistory() {
  // Renders into a dynamic panel appended below Section 4. Lazy-creates
  // the panel on first call so unrelated pages don't have to know about
  // it.
  let panel = document.getElementById("bk-actions-history");
  if (!panel) {
    const sec4 = document.getElementById("bk-sec4");
    if (!sec4) return;
    panel = document.createElement("details");
    panel.id = "bk-actions-history";
    panel.style.cssText = "margin-bottom:14px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:0";
    panel.open = false;
    panel.innerHTML = `
      <summary style="cursor:pointer;padding:12px 16px;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px">
        <span style="font-size:14px;font-weight:700;color:var(--text-bright)">📜 Actions history</span>
        <span style="font-size:10px;padding:2px 8px;border-radius:10px;background:var(--surface);color:var(--muted);border:1px solid var(--border)" id="bk-actions-count">loading…</span>
      </summary>
      <div id="bk-actions-body" style="padding:0 16px 16px 16px;font-size:11px"></div>`;
    sec4.parentNode.insertBefore(panel, sec4.nextSibling);
  }
  const body = document.getElementById("bk-actions-body");
  const count = document.getElementById("bk-actions-count");
  try {
    const r = await fetch("/api/backup/actions-history");
    const data = await r.json();
    const entries = data.entries || [];
    if (count) count.textContent = `${entries.length} entr${entries.length === 1 ? "y" : "ies"}`;
    if (!entries.length) {
      body.innerHTML = '<div style="color:var(--muted);padding:8px">No elevated actions recorded yet. Scan, delete, or cleanup operations will appear here once they run.</div>';
      return;
    }
    body.innerHTML = `
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="text-align:left;color:var(--muted);font-weight:600">
          <th style="padding:6px 10px;border-bottom:1px solid var(--border)">When</th>
          <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Action</th>
          <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Status</th>
          <th style="padding:6px 10px;border-bottom:1px solid var(--border);text-align:right">RC</th>
          <th style="padding:6px 10px;border-bottom:1px solid var(--border);text-align:right">Bytes freed</th>
          <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Notes</th>
        </tr></thead>
        <tbody>
          ${entries.map(e => {
            const statusColor = e.status === "completed" ? "var(--green)" : "var(--red)";
            const ended = e.ended_at ? new Date(e.ended_at).toLocaleString() : "—";
            const note = e.error ? escHtml(e.error) : escHtml((e.stderr_tail || "").slice(0, 200));
            return `<tr>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:10px">${escHtml(ended)}</td>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border)">${escHtml(e.action || "")}</td>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border);color:${statusColor};font-weight:600">${escHtml(e.status || "")}</td>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border);text-align:right">${e.returncode == null ? "—" : escHtml(String(e.returncode))}</td>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border);text-align:right">${e.bytes_freed_estimate ? bk_humanBytes(e.bytes_freed_estimate) : "—"}</td>
              <td style="padding:5px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px">${note}</td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>`;
  } catch (e) {
    if (body) body.innerHTML = `<div style="color:var(--red);padding:8px">Failed to load: ${escHtml(e.message)}</div>`;
  }
}

