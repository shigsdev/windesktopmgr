// Events tab (prefix ev) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// EVENT LOG VIEWER
// ══════════════════════════════════════════════════════════════════════════
async function queryEvents() {
  document.getElementById('ev-loading').style.display = 'block';
  document.getElementById('ev-tbody').innerHTML = '';
  const body = { log: document.getElementById('ev-log').value, level: document.getElementById('ev-level').value, search: document.getElementById('ev-search').value, max: 200 };
  const r = await fetch('/api/events/query', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
  const events = await r.json();
  document.getElementById('ev-loading').style.display = 'none';
  const lc = l => l==='Error'||l==='Critical'?'var(--red)':l==='Warning'?'var(--orange)':'var(--muted)';
  document.getElementById('ev-errors').textContent   = events.filter(e=>e.Level==='Error'||e.Level==='Critical').length;
  document.getElementById('ev-warnings').textContent = events.filter(e=>e.Level==='Warning').length;
  document.getElementById('ev-info').textContent     = events.filter(e=>e.Level==='Information').length;
  document.getElementById('ev-shown').textContent    = events.length;
  fetchSummary('events', {events: events}, 'summary-events');
  const rows = events.map(e=>{
    const d=new Date(e.Time);
    const ts=isNaN(d)?e.Time:d.toLocaleString('en-US',{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    return `<tr style="border-bottom:1px solid var(--border)"><td style="padding:5px 10px;white-space:nowrap;color:var(--muted);font-size:11px">${ts}</td><td style="padding:5px 10px;font-family:monospace">${e.Id}</td><td style="padding:5px 10px;color:${lc(e.Level)};font-weight:600">${esc(e.Level)}</td><td style="padding:5px 10px;color:var(--muted);font-size:11px">${esc(e.Source)}</td><td style="padding:5px 10px;font-size:11px;max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.Message)}">${esc(e.Message)}</td></tr>`;
  }).join('');
  document.getElementById('ev-tbody').innerHTML = rows||'<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--muted)">No events found</td></tr>';
}


// ── BSOD Stop Code Cache Manager ───────────────────────────────────────────
function toggleBsodCache() {
  var w = document.getElementById("bsod-cache-wrap");
  if (!w) return;
  var visible = w.style.display !== "none";
  w.style.display = visible ? "none" : "";
  if (!visible) loadBsodCache();
}

async function loadBsodCache() {
  try {
    var r = await fetch("/api/bsod/cache");
    var d = await r.json();
    var stats = document.getElementById("bsod-cache-stats");
    if (stats) stats.textContent =
      d.total_cached + " stop codes cached  |  " + d.queue_pending + " pending  |  " + d.in_flight + " in-flight";
    var src_color = function(s) {
      return s === "windows_bugcheck_table" ? "var(--cyan)"
           : s === "microsoft_learn"        ? "var(--orange)"
           : s === "static_kb"              ? "#8888aa"
           : "var(--muted)";
    };
    var rows = (d.entries||[]).map(function(e) {
      var date = e.fetched ? new Date(e.fetched).toLocaleDateString() : "";
      return "<tr style='border-bottom:1px solid var(--border)'>"
        + "<td style='padding:5px 10px;font-family:monospace;font-weight:700;color:var(--cyan)'>" + esc(e.code) + "</td>"
        + "<td style='padding:5px 10px'>" + esc(e.title) + "</td>"
        + "<td style='padding:5px 10px;color:" + src_color(e.source) + "'>" + esc(e.source) + "</td>"
        + "<td style='padding:5px 10px;color:var(--muted)'>" + date + "</td>"
        + "<td style='padding:5px 10px'><button onclick=\"deleteBsodCache('" + esc(e.code) + "')\" "
        + "style='background:transparent;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px'>Re-fetch</button></td>"
        + "</tr>";
    }).join("");
    var tbody = document.getElementById("bsod-cache-tbody");
    if (tbody) tbody.innerHTML = rows ||
      "<tr><td colspan='5' style='padding:12px;color:var(--muted)'>No learned stop codes yet. BSOD data will populate this automatically.</td></tr>";
  } catch(ex) { console.warn("loadBsodCache error:", ex); }
}

async function deleteBsodCache(code) {
  await fetch("/api/bsod/cache/delete/" + encodeURIComponent(code), { method: "DELETE" });
  loadBsodCache();
}

async function clearBsodCache() {
  if (!confirm("Clear all learned stop code lookups? The static knowledge base is kept.")) return;
  await fetch("/api/bsod/cache/clear", { method: "POST" });
  loadBsodCache();
}


// ── Event ID cache management (paired with /api/events/cache*) ─────────────
// Populates the "Event ID Knowledge Cache" section on the Events tab. These
// were missing and caused ``loadCacheStatus is not defined`` pageerrors --
// caught by the 2026-04-19 Playwright smoke suite (backlog #26).
async function loadCacheStatus() {
  try {
    const r = await fetch("/api/events/cache");
    const d = await r.json();
    const stats = document.getElementById("cache-stats");
    if (stats) {
      const total = (d.total_cached != null) ? d.total_cached : (d.entries ? d.entries.length : 0);
      const queue = (d.queue_pending != null) ? d.queue_pending : 0;
      const flight = (d.in_flight != null) ? d.in_flight : 0;
      stats.textContent = `${total} event IDs cached | ${queue} pending | ${flight} in-flight`;
    }
    const wrap = document.getElementById("cache-table-wrap");
    const tbody = document.getElementById("cache-tbody");
    const entries = d.entries || [];
    if (wrap) wrap.style.display = entries.length ? "" : "none";
    if (tbody) {
      tbody.innerHTML = entries.map(e => {
        const date = e.fetched ? new Date(e.fetched).toLocaleDateString() : "";
        const id = esc(e.id != null ? e.id : e.code);
        return `<tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 10px;font-family:monospace;font-weight:700;color:var(--cyan)">${id}</td>
          <td style="padding:5px 10px">${esc(e.title)}</td>
          <td style="padding:5px 10px;color:var(--muted)">${esc(e.source)}</td>
          <td style="padding:5px 10px;color:var(--muted)">${esc(date)}</td>
          <td style="padding:5px 10px"><button onclick="deleteEventCache('${id}')"
            style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px">Re-fetch</button></td>
        </tr>`;
      }).join("") || `<tr><td colspan="5" style="padding:12px;color:var(--muted)">No learned event IDs yet -- events will populate this automatically.</td></tr>`;
    }
  } catch(ex) { console.warn("loadCacheStatus error:", ex); }
}

async function deleteEventCache(eventId) {
  await fetch(`/api/events/cache/delete/${encodeURIComponent(eventId)}`, {method: "DELETE"});
  loadCacheStatus();
}

async function clearCache() {
  if (!confirm("Clear all learned event ID lookups? The static knowledge base is kept.")) return;
  await fetch("/api/events/cache/clear", {method: "POST"});
  loadCacheStatus();
}


// ── Bulk startup lookup ──────────────────────────────────────────────────────
async function lookupAllUnknowns() {
  if (!_startupData) return;

  const unknowns = _startupData.filter(i =>
    !i.info || i.info.source === "unknown" || !i.info.what ||
    i.info.what.includes("Could not determine")
  );

  if (unknowns.length === 0) {
    alert("No unknown items to look up — all startup entries are already identified.");
    return;
  }

  const btn      = document.getElementById("btn-lookup-all");
  const progress = document.getElementById("lookup-progress");
  btn.disabled   = true;
  btn.textContent = "Looking up…";
  progress.style.display = "";
  progress.textContent   = `Queuing ${unknowns.length} items…`;

  // Queue them all
  const r = await fetch("/api/startup/lookup-unknowns", {
    method:  "POST",
    headers: {"Content-Type": "application/json"},
    body:    JSON.stringify({ items: unknowns })
  });
  const d = await r.json();
  progress.textContent = `${d.queued} items queued for lookup…`;

  // Poll until queue drains, then refresh
  let attempts = 0;
  const maxAttempts = 60;   // 60 × 2s = 2 min max
  const poll = setInterval(async () => {
    attempts++;
    try {
      const sr   = await fetch("/api/startup/lookup-status");
      const sd   = await sr.json();
      const left = sd.queue_pending + sd.in_flight;
      progress.textContent = left > 0
        ? `Looking up… ${left} remaining (${sd.cached} cached so far)`
        : "All done! Refreshing…";

      if (left === 0 || attempts >= maxAttempts) {
        clearInterval(poll);
        btn.disabled    = false;
        btn.textContent = "🔍 Lookup All Unknowns";
        progress.style.display = "none";
        // Reload startup data with fresh info
        await loadStartup();
      }
    } catch(e) {
      clearInterval(poll);
      btn.disabled    = false;
      btn.textContent = "🔍 Lookup All Unknowns";
      progress.style.display = "none";
    }
  }, 2000);
}


function clearStartupFilters() {
  ["su-f-name","su-f-what","su-f-publisher","su-f-location",
   "su-f-status","su-f-rec","su-f-impact","su-f-suspicious"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  renderStartup();
}


