// Dashboard tab (prefix db) + deep links, trends, export report -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// DASHBOARD — aggregated health summary
// ══════════════════════════════════════════════════════════════════════════

// Helper: switch to another tab programmatically
function switchTab(page) {
  const btn = document.querySelector(`.page-tab[data-page="${page}"]`);
  if (btn) btn.click();
}

// ── Backlog #40: toast deep-link via URL hash ───────────────────────
// When the tray fires a Windows toast, the toast XML carries a
// launch="...#tab=X&concern=Y" attribute. Click -> Windows opens that
// URL in the default browser. The handlers below parse the fragment,
// switch to the right tab, and scroll/flash the relevant concern card.
//
// Mirror of tray.py's slugify_concern -- if you change one, change the
// other or the deep-link silently won't find its target.
function slugifyConcern(title) {
  return String(title || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// Parse window.location.hash into {tab, concern}. Tolerates either
// "?" or "#" prefix and either "&" or ";" separators just in case
// some browser mangles the URL en route from Windows -> default
// browser. Returns nulls for missing keys rather than empty strings
// so callers can use truthy checks.
function _parseHashFragment() {
  const raw = (window.location.hash || "").replace(/^#/, "");
  if (!raw) return {tab: null, concern: null};
  const out = {tab: null, concern: null};
  raw.split(/[&;]/).forEach(pair => {
    const eq = pair.indexOf("=");
    if (eq < 0) return;
    const k = pair.slice(0, eq);
    const v = decodeURIComponent(pair.slice(eq + 1));
    if (k === "tab") out.tab = v;
    else if (k === "concern") out.concern = v;
  });
  return out;
}

// Apply deep-link routing on page load and on hashchange. Tab switch
// happens unconditionally; concern highlight runs after the dashboard
// concerns finish rendering (the render loop calls applyConcernHashHighlight
// itself, so this function only needs to fire the tab switch).
function applyToastDeepLink() {
  const {tab} = _parseHashFragment();
  if (tab) {
    // switchTab is a no-op if the tab name is unknown (the querySelector
    // returns null); safe to call without validation.
    switchTab(tab);
  }
}

// Concern scroll + flash highlight. Called by applyToastDeepLink AND
// by the dashboard render loop -- whichever fires last "wins" and the
// concern gets highlighted. The double-call is intentional: deep-link
// hash may arrive before concerns are rendered (page load race) OR
// after (hashchange while dashboard already populated).
let _concernHighlightTimer = null;
function applyConcernHashHighlight() {
  const {concern} = _parseHashFragment();
  if (!concern) return;
  // Find the matching card. Selector matches the data-concern-slug
  // attribute we added to each concern row in the dashboard render.
  const card = document.querySelector(`.concern-card[data-concern-slug="${CSS.escape(concern)}"]`);
  if (!card) return;
  // Scroll into view -- "center" so the user sees context above + below
  card.scrollIntoView({behavior: "smooth", block: "center"});
  // Flash highlight via box-shadow + background tween. Clear any
  // previous flash timer so rapid hash changes don't leave the highlight
  // stuck on a stale card.
  if (_concernHighlightTimer) clearTimeout(_concernHighlightTimer);
  card.style.boxShadow = "0 0 0 3px var(--cyan), 0 0 24px var(--cyan)";
  _concernHighlightTimer = setTimeout(() => {
    card.style.boxShadow = "";
  }, 2500);
}

// Wire the listeners. DOMContentLoaded covers page load (the toast
// click typically opens a fresh tab); hashchange covers the case
// where the dashboard is already open and the user clicks a second
// toast. setTimeout(0) on load defers until the initial dashboard
// render has had a chance to populate concerns -- otherwise the
// concern selector finds nothing and the highlight no-ops silently.
window.addEventListener("DOMContentLoaded", () => setTimeout(applyToastDeepLink, 0));
window.addEventListener("hashchange", () => {
  applyToastDeepLink();
  // Concerns may already be rendered; try the highlight immediately
  // and let the next dashboard render pick it up if not.
  applyConcernHashHighlight();
});

const ALL_TABS = [
  { page:"drivers",      icon:"⟳", label:"Driver Manager" },
  { page:"bsod",         icon:"⚠", label:"BSOD Dashboard" },
  { page:"startup",      icon:"🚀", label:"Startup Manager" },
  { page:"disk",         icon:"💾", label:"Disk Health" },
  { page:"network",      icon:"🌐", label:"Network Monitor" },
  { page:"updates",      icon:"🔄", label:"Update History" },
  { page:"events",       icon:"📋", label:"Event Log" },
  { page:"processes",    icon:"⚡", label:"Processes" },
  { page:"thermals",     icon:"🌡", label:"Temps & Power" },
  { page:"services",     icon:"⚙", label:"Services" },
  { page:"health-history",icon:"📈",label:"Health History" },
  { page:"timeline",     icon:"⏱", label:"System Timeline" },
  { page:"memory",       icon:"🧠", label:"Memory Analysis" },
  { page:"bios",         icon:"🔩", label:"BIOS & Firmware" },
  { page:"credentials",  icon:"🔐", label:"Credentials & Network" },
  { page:"remediation",  icon:"🔧", label:"Remediation" },
  { page:"baseline",     icon:"📐", label:"Baseline / Drift" },
  { page:"backup",       icon:"📦", label:"Backup" },
  { page:"utilities",    icon:"🛠", label:"Utilities" },
  { page:"logs",         icon:"📜", label:"Application Logs" },
];

// A stale cached summary is served instantly while the server recomputes in
// the background (~5-15 s). Without a follow-up fetch the page kept showing
// the old numbers -- e.g. a CPU temp minutes old -- until a manual reload.
let _dbStaleTimer = null;

function dbScheduleStaleRefetch(d, attempt) {
  if (_dbStaleTimer) { clearTimeout(_dbStaleTimer); _dbStaleTimer = null; }
  if (!d || d.cache !== "stale" || attempt > 3) return;
  _dbStaleTimer = setTimeout(async () => {
    _dbStaleTimer = null;
    try {
      const fresh = await (await fetch("/api/dashboard/summary")).json();
      if (fresh.checked_at !== d.checked_at) renderDashboard(fresh);
      else dbScheduleStaleRefetch(d, attempt + 1);
    } catch (_e) { /* next manual load will retry */ }
  }, 8000);
}

async function loadDashboard() {
  document.getElementById("db-loading").style.display = "block";
  document.getElementById("db-content").style.display  = "none";

  try {
    const r = await fetch("/api/dashboard/summary");
    const d = await r.json();
    renderDashboard(d);
    dbScheduleStaleRefetch(d, 1);
  } catch(e) {
    document.getElementById("db-loading").innerHTML =
      `<div style="color:var(--red);padding:20px">Error loading dashboard: ${e.message}</div>`;
  }
}

// Instrument-cluster radial gauges (redesign PR2; reused by Thermals in PR4).
// Renders a `gauges` list into the given element `el` via DOM methods +
// textContent (no innerHTML -> XSS-proof). A null value renders an
// unavailable "—" dial (missing sensor / no GPU) rather than a bogus 0.
function renderGauges(el, gauges) {
  if (!el) return;
  el.textContent = "";
  if (!Array.isArray(gauges) || !gauges.length) { el.style.display = "none"; return; }
  el.style.display = "";

  // Thresholds per kind: [warn, crit]. Below warn is the "good" colour
  // (cyan for temps/mem, green for load/util); at/above each step escalates.
  const THRESH = { temp:[60,80], load:[60,85], util:[60,85], mem:[75,90] };
  const colVar = (kind, v) => {
    if (v === null || v === undefined) return "var(--muted)";
    const [warn, crit] = THRESH[kind] || [60, 85];
    if (v >= crit) return "var(--red)";
    if (v >= warn) return "var(--orange)";
    return (kind === "temp") ? "var(--cyan)" : "var(--green)";
  };
  const glowOf = {
    "var(--red)":"rgba(255,71,87,.30)", "var(--orange)":"rgba(255,112,67,.30)",
    "var(--cyan)":"rgba(0,212,255,.28)", "var(--green)":"rgba(0,229,160,.26)",
    "var(--muted)":"rgba(74,85,104,0)"
  };
  const mk = (cls, text) => {
    const d = document.createElement("div");
    d.className = cls;
    if (text != null) d.textContent = text;
    return d;
  };

  gauges.forEach(g => {
    const has = g.value !== null && g.value !== undefined;
    const max = g.max || 100;
    const sweep = has ? Math.max(0, Math.min(100, (g.value / max) * 100)) : 0;
    const col = colVar(g.kind, has ? g.value : null);
    const glow = glowOf[col] || "rgba(0,212,255,.28)";

    const tile = mk("db-gauge" + (has ? "" : " dg-unavail"));
    tile.setAttribute("data-gauge-key", g.key || "");
    tile.setAttribute("data-gauge-value", has ? String(g.value) : "");
    tile.setAttribute("data-gauge-available", String(has));
    // The state colour drives the top accent (--gcol), the number, and the bar
    // fill (--col) / its glow -- the whole tile reads its health at a glance.
    tile.style.setProperty("--gcol", col);
    tile.style.setProperty("--col", col);
    tile.style.setProperty("--glow", glow);
    tile.appendChild(mk("dg-lbl", g.label || ""));

    const num = mk("dg-num", has ? String(Math.round(g.value * 10) / 10) : "—");
    if (has && g.unit) {
      const em = document.createElement("em");
      em.textContent = g.unit;
      num.appendChild(em);
    }
    tile.appendChild(num);

    // Horizontal bar: light track + colour fill (width = value %). Replaces the
    // radial ring, whose unfilled circular remainder always read as a dark
    // "pre-filled" section on the near-black card. --sweep is set on the FILL
    // (it reads it; @property --sweep is inherits:false), not the tile.
    const bar = mk("dg-bar");
    const fill = mk("dg-fill");
    fill.style.setProperty("--sweep", sweep.toFixed(1));
    bar.appendChild(fill);
    tile.appendChild(bar);

    tile.appendChild(mk("dg-sub", g.sub || ""));
    el.appendChild(tile);
  });
}

function renderDashboard(d) {
  const concerns  = d.concerns  || [];
  const critical  = d.critical  || 0;
  const warnings  = d.warnings  || 0;
  const overall   = d.overall   || "ok";

  // Dynamic favicon (backlog #41): red dot overlay when critical > 0.
  // Cached state-toggle in _updateFavicon -- safe to call every render.
  _updateFavicon(critical);

  // ── Banner ────────────────────────────────────────────────────────────────
  const banner = document.getElementById("db-banner");
  const bannerColors = { critical:"#ff456018", warning:"#ff704318", ok:"#00e67610" };
  const bannerBorder = { critical:"var(--red)", warning:"var(--orange)", ok:"var(--green)" };
  banner.style.background   = bannerColors[overall] || bannerColors.ok;
  banner.style.borderColor  = bannerBorder[overall]  || bannerBorder.ok;

  const icons  = { critical:"🔴", warning:"🟡", ok:"🟢" };
  const titles = {
    critical: `${critical} critical issue${critical!==1?"s":""} require${critical===1?"s":""} attention`,
    warning:  `${warnings} warning${warnings!==1?"s":""} — review recommended`,
    ok:       "All systems healthy"
  };
  const subs = {
    critical: "Resolve critical items below to restore full system health.",
    warning:  "No critical issues — but some items are worth reviewing.",
    ok:       "No issues detected across all monitored areas."
  };
  document.getElementById("db-banner-icon").textContent  = icons[overall]  || "🟢";
  document.getElementById("db-banner-title").textContent = titles[overall] || titles.ok;
  document.getElementById("db-banner-sub").textContent   = subs[overall]   || subs.ok;
  document.getElementById("db-critical-count").textContent = critical;
  document.getElementById("db-warning-count").textContent  = warnings;

  // Checked at
  if (d.checked_at) {
    const dt = new Date(d.checked_at);
    document.getElementById("db-checked-at").textContent =
      "Last checked: " + dt.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
  }

  // ── Instrument-cluster hero gauges (redesign PR2) ───────────────────────────
  renderGauges(document.getElementById("db-gauges"), d.gauges || []);

  // ── Concern cards ─────────────────────────────────────────────────────────
  const levelColor  = l => l==="critical"?"var(--red)":l==="warning"?"var(--orange)":"var(--cyan)";
  const levelBg     = l => l==="critical"?"#ff456012":l==="warning"?"#ff704312":"#00d4ff10";
  const levelBorder = l => l==="critical"?"var(--red)":l==="warning"?"var(--orange)":"var(--cyan)";

  const concernsEl = document.getElementById("db-concerns");
  const allClearEl = document.getElementById("db-all-clear");

  if (concerns.length === 0) {
    concernsEl.innerHTML = "";
    allClearEl.style.display = "";
  } else {
    allClearEl.style.display = "none";
    // Per-concern action bar. Memory concerns (carrying process_name)
    // get a 3-button group: Kill / Investigate / Snooze. All other
    // concerns get the existing single-button behavior.
    function actionHTML(c, i) {
      const lvl = levelColor(c.level), bg = levelBg(c.level), bd = levelBorder(c.level);
      const btnBase = `padding:6px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:700;white-space:nowrap;background:${bg};border:1px solid ${bd};color:${lvl}`;
      if (c.process_name) {
        const pid = c.pid || 0;
        const pname = esc(c.process_name);
        return `<button data-mem-act="investigate" data-pid="${pid}" data-pname="${pname}" title="Filter Process Monitor to this PID" style="${btnBase}">🔍 Investigate</button>
                <button data-mem-act="kill" data-pid="${pid}" data-pname="${pname}" title="Kill this process (with confirmation)" style="${btnBase}">🔪 Kill</button>
                <button data-mem-act="snooze" data-pname="${pname}" title="Suppress this warning for 24 h" style="${btnBase}">⏳ Snooze 24h</button>`;
      }
      // Physical-disk health concerns carry a serial -> offer a Pause button
      // that temporarily excludes exactly this drive from alerts.
      if (c.disk_serial) {
        return `<button data-fn="${i}" style="${btnBase}">${esc(c.action||"View")} →</button>
                <button data-disk-snooze="${esc(c.disk_serial)}" title="Pause health alerts for this drive for 24 h (auto-resumes)" style="${btnBase}">⏸ Pause 24h</button>`;
      }
      return `<button data-fn="${i}" style="${btnBase}">${esc(c.action||"View")} →</button>`;
    }
    concernsEl.innerHTML = concerns.map((c, i) => `
      <div class="concern-card" data-concern-slug="${esc(slugifyConcern(c.title||""))}" style="display:flex;align-items:center;gap:14px;padding:14px 18px;
        background:${levelBg(c.level)};border:1px solid ${levelBorder(c.level)};
        border-left:4px solid ${levelBorder(c.level)};border-radius:8px;transition:box-shadow .3s,background .3s">
        <span style="font-size:22px;flex-shrink:0">${esc(c.icon||"•")}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;font-size:13px;color:${levelColor(c.level)}">${esc(c.title)}</div>
          <div style="font-size:12px;color:var(--muted);margin-top:3px;line-height:1.4">${esc(c.detail||"")}</div>
        </div>
        <div style="flex-shrink:0;display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
          <span style="font-size:10px;font-weight:700;text-transform:uppercase;
            color:${levelColor(c.level)};border:1px solid ${levelBorder(c.level)};
            padding:2px 8px;border-radius:10px;letter-spacing:.06em">${esc(c.level)}</span>
          ${actionHTML(c, i)}
        </div>
      </div>`).join("");

  // Backlog #40: after concerns render, check the URL hash to see if
  // a deep-link is asking us to scroll/highlight one. We re-run on
  // every render because the dashboard refreshes the concerns list
  // periodically; the highlight should reapply if the targeted
  // concern is still present.
  applyConcernHashHighlight();

  // Attach click handlers via delegation after innerHTML is set
  // Use window[] lookup instead of eval() to reliably call named functions
  _dashConcerns = concerns;
  concernsEl.querySelectorAll("button[data-fn]").forEach(btn => {
    const idx    = parseInt(btn.dataset.fn);
    const fnStr  = (_dashConcerns[idx] || {}).action_fn || "";
    if (!fnStr) return;
    btn.addEventListener("click", () => {
      // Parse "functionName(args)" — handles resumeBrokers(), switchTab('x'), fixFastStartup()
      const match = fnStr.match(/^([a-zA-Z_$][a-zA-Z0-9_$]*)\((.*)\)$/);
      if (match) {
        const name = match[1];
        const arg  = match[2].replace(/['"]/g, "").trim();
        const fn   = window[name];
        if (typeof fn === "function") {
          arg ? fn(arg) : fn();
        } else {
          console.warn("Dashboard: function not found:", name);
        }
      }
    });
  });
  // Memory concern action buttons (backlog #19)
  concernsEl.querySelectorAll("button[data-mem-act]").forEach(btn => {
    btn.addEventListener("click", () => {
      const act   = btn.dataset.memAct;
      const pid   = parseInt(btn.dataset.pid, 10) || 0;
      const pname = btn.dataset.pname || "";
      if (act === "investigate")  investigateProcess(pid, pname);
      else if (act === "kill")    killProcessFromConcern(pid, pname);
      else if (act === "snooze")  snoozeMemoryConcern(pname);
    });
  });
  // Disk-health "Pause 24h" buttons — snooze one drive by serial.
  concernsEl.querySelectorAll("button[data-disk-snooze]").forEach(btn => {
    btn.addEventListener("click", () => pauseDiskConcern(btn.dataset.diskSnooze, 24, btn));
  });
  }

  // Quick Fixes moved to the Utilities tab (backlog #51). Dashboard now
  // shows the deep-link card #db-quick-fixes-link instead. The actual
  // renderer lives in util_loadQuickFixes() further down.

  // ── Quick links grid ──────────────────────────────────────────────────────
  document.getElementById("db-quick-links").innerHTML = ALL_TABS.map(t =>
    `<button onclick="switchTab('${t.page}')"
      style="background:var(--card);border:1px solid var(--border);border-radius:8px;
      padding:10px 8px;cursor:pointer;text-align:center;transition:border-color .15s"
      onmouseover="this.style.borderColor='var(--cyan)'"
      onmouseout="this.style.borderColor='var(--border)'">
      <div style="font-size:16px;margin-bottom:4px">${t.icon}</div>
      <div style="font-size:10px;color:var(--muted);font-family:var(--font-mono);
        letter-spacing:.04em;line-height:1.3">${t.label}</div>
    </button>`
  ).join("");

  // ── Alert Rules (backlog #5) ──────────────────────────────────────────────
  loadAlertRules();

  // ── Trends sparklines (backlog #4) ────────────────────────────────────────
  loadTrends();

  document.getElementById("db-loading").style.display = "none";
  document.getElementById("db-content").style.display  = "";
}

// Trends card: fetch the last 7 days of metric samples and render one
// inline-SVG sparkline per metric. Backlog #4 — turns point-in-time
// snapshots into a "is this trending in the wrong direction?" signal.
// Module-level cache for the Trends drill-down modal. loadTrends populates
// this when it fetches /api/metrics/history; openTrendDrilldown reads it
// instead of re-fetching, so clicking a card opens instantly.
let _trendsRawSeries = {};   // {metric_key: [{ts, value}, ...]}
let _trendsLabels = {};      // {metric_key: {label, color, unit}}
let _trendsModalChart = null; // Chart.js instance (destroyed on close)

async function loadTrends() {
  const el = document.getElementById("db-trends-grid");
  if (!el) return;
  // Metric key → display label + colour. Order here is the render order.
  const labels = {
    "cpu_percent":                  {label: "CPU %",        color: "#00d4ff", unit: "%"},
    "memory_percent":               {label: "Memory %",     color: "#a78bfa", unit: "%"},
    "cpu_temp_c":                   {label: "CPU Temp",     color: "#ff7043", unit: "°C"},
    // GPU sparklines (backlog #37). Only render when the backend actually
    // reported GPU data -- a machine with no NVIDIA driver simply won't
    // have these series in the response, so the cards self-hide below.
    "gpu_utilization_pct":          {label: "GPU %",        color: "#76b900", unit: "%"},
    "gpu_vram_pct":                 {label: "GPU VRAM %",   color: "#4ade80", unit: "%"},
    "gpu_temp_c":                   {label: "GPU Temp",     color: "#f97316", unit: "°C"},
    // Network sparklines (backlog #38). in/out throughput + TCP latency
    // to Cloudflare DNS + active-connections count. Mbps keys have units
    // of "Mbps" for the now/avg row; connections is unitless integer.
    "net_throughput_mbps.in":       {label: "Net In",       color: "#38bdf8", unit: " Mbps"},
    "net_throughput_mbps.out":      {label: "Net Out",      color: "#0ea5e9", unit: " Mbps"},
    "net_latency_ms":               {label: "Net Latency",  color: "#c084fc", unit: " ms"},
    "net_connections_established":  {label: "TCP Conns",    color: "#60a5fa", unit: ""},
    "concerns_critical":            {label: "Critical",     color: "#ff4560", unit: ""},
    "concerns_warning":             {label: "Warnings",     color: "#ffd740", unit: ""},
  };
  try {
    const r = await fetch("/api/metrics/history?window_h=168");
    const d = await r.json();
    const series = d.metrics || {};
    const available = d.available || [];
    // Disk drives are dynamic (one metric per drive letter). Add them after
    // the fixed list so the layout stays consistent.
    available.filter(k => k.startsWith("disk_percent.")).sort().forEach(k => {
      const letter = k.split(".").pop();
      labels[k] = {label: `Disk ${letter}: %`, color: "#00e5a0", unit: "%"};
    });

    // Only render a card for metrics that have actually been recorded.
    // Prevents GPU sparklines (backlog #37) from appearing on machines
    // without an NVIDIA driver, and more generally suppresses "need ≥2
    // samples" ghost cards for metrics the collector never emitted.
    const availableSet = new Set(available);
    // Cache raw series + labels for the drill-down modal. Click handlers
    // reach back into these instead of re-fetching.
    _trendsRawSeries = series;
    _trendsLabels = labels;
    const cards = Object.entries(labels)
      .filter(([metric]) => availableSet.has(metric))
      .map(([metric, cfg]) => {
        const points = (series[metric] || []).map(p => Number(p.value)).filter(v => Number.isFinite(v));
        const n = points.length;
        const last = n ? points[n - 1] : null;
        const avg = n ? (points.reduce((a, b) => a + b, 0) / n) : null;
        // data-metric makes the Playwright regression test (backlog #39)
        // able to pair rendered cards with the API's ``available`` list
        // without parsing visible label text. Future additions to the
        // labels dict must preserve this attribute or the test fails.
        // Click anywhere on the card to open the drill-down modal.
        return `
          <div data-metric="${esc(metric)}" onclick="openTrendDrilldown('${escJsArg(metric)}')" style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 12px;cursor:pointer;transition:border-color 0.15s,transform 0.05s" onmouseover="this.style.borderColor='var(--cyan)'" onmouseout="this.style.borderColor='var(--border)'" title="Click to drill down (full chart, time axis, summary stats)">
            <div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px">
              <div style="font-size:11px;color:var(--text-bright);font-weight:600">${cfg.label}</div>
              <div style="font-size:10px;color:var(--muted);font-family:var(--font-mono)">n=${n} 🔍</div>
            </div>
            <div style="margin:4px 0">${trendSparkline(points, cfg.color)}</div>
            <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted);font-family:var(--font-mono);margin-top:4px">
              <span>now: ${last == null ? "—" : last.toFixed(1) + cfg.unit}</span>
              <span>avg: ${avg == null ? "—" : avg.toFixed(1) + cfg.unit}</span>
            </div>
          </div>`;
      });
    el.innerHTML = cards.join("");
    if (!Object.keys(series).length) {
      el.innerHTML = `<div style="grid-column:1/-1;color:var(--muted);font-size:11px;padding:12px">
        No samples yet — the dashboard records one snapshot every 10 minutes.
        Trends will fill in over time.</div>`;
    }
  } catch (ex) {
    console.warn("loadTrends failed:", ex);
    el.innerHTML = '<div style="color:var(--red);font-size:12px">Failed to load trend data.</div>';
  }
}

// ── Trends drill-down (2026-04-28) ─────────────────────────────────
//
// User feedback: "on the dashboard trends, you should be able to click on
// one of the graphs and then be able to look at a larger one and drill
// down." This modal opens on card click, renders a full-size Chart.js
// line chart with proper time-axis, and shows summary statistics
// (now/min/max/avg/median/p95) + a slope-based trend indicator.

// Currently-open metric. Used by setTrendsModalWindow to know what to
// re-fetch when the user picks a different time window.
let _trendsModalMetric = null;

// Compute summary stats over a values array. Returns null if empty.
function _trendStats(values) {
  if (!values || !values.length) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((a, b) => a + b, 0);
  const pct = (p) => sorted[Math.min(n - 1, Math.floor(p * n))];
  // Slope of the simple least-squares fit (positive=rising, negative=falling).
  // Used only for the directional badge -- magnitude is unitful so we
  // don't display it directly.
  const xs = values.map((_, i) => i);
  const xMean = xs.reduce((a, b) => a + b, 0) / n;
  const yMean = sum / n;
  let num = 0, den = 0;
  for (let i = 0; i < n; i++) {
    num += (xs[i] - xMean) * (values[i] - yMean);
    den += (xs[i] - xMean) ** 2;
  }
  const slope = den === 0 ? 0 : num / den;
  return {
    n: n,
    now: values[n - 1],
    min: sorted[0],
    max: sorted[n - 1],
    avg: sum / n,
    median: pct(0.5),
    p95: pct(0.95),
    slope: slope,
  };
}

// Open the drill-down modal for a given metric. If the global series
// cache (populated by loadTrends) has the data, use it instantly --
// otherwise re-fetch.
async function openTrendDrilldown(metric) {
  _trendsModalMetric = metric;
  const cfg = _trendsLabels[metric] || {label: metric, color: "#00d4ff", unit: ""};
  const modal = document.getElementById("db-trends-modal");
  if (!modal) return;
  document.getElementById("db-trends-modal-title").textContent = `${cfg.label} — Trend detail`;
  document.getElementById("db-trends-modal-sub").textContent = `Metric key: ${metric}`;
  modal.style.display = "flex";
  // Default to 7-day window on open
  _renderTrendModalChart(metric, 168, cfg);
  _highlightWindowButton(168);
  // ESC-to-close + click-on-backdrop-to-close
  document.addEventListener("keydown", _trendModalEscHandler);
  modal.onclick = (e) => { if (e.target === modal) closeTrendDrilldown(); };
}

function closeTrendDrilldown() {
  const modal = document.getElementById("db-trends-modal");
  if (modal) modal.style.display = "none";
  if (_trendsModalChart) { _trendsModalChart.destroy(); _trendsModalChart = null; }
  _trendsModalMetric = null;
  document.removeEventListener("keydown", _trendModalEscHandler);
}

function _trendModalEscHandler(e) {
  if (e.key === "Escape") closeTrendDrilldown();
}

// ── Export Report modal (backlog #15) ────────────────────────────────────
// Reads the user's format / scope / redact-PII choices and either:
//   📋 copies the rendered report to the clipboard (markdown only -- the
//       other formats are too large / not paste-friendly)
//   💾 downloads the report as a file (uses the route's attachment=1
//       Content-Disposition header)
//   🔗 opens the report in a new browser tab (HTML / JSON viewable
//       inline; markdown gets shown as plain text)
//
// Default redact_pii=ON because the cost of leaking a service tag in a
// public support post is real; the cost of toggling OFF for a personal
// record is one click.

function openExportModal() {
  const modal = document.getElementById("db-export-modal");
  if (!modal) return;
  modal.style.display = "flex";
  // Default redact ON every time the modal opens so the user is never
  // surprised by a previously-toggled-off state on a fresh export.
  const redactBox = document.getElementById("export-redact-pii");
  if (redactBox) redactBox.checked = true;
  const status = document.getElementById("export-status");
  if (status) status.textContent = "";
  document.addEventListener("keydown", _exportModalEscHandler);
}

function closeExportModal() {
  const modal = document.getElementById("db-export-modal");
  if (modal) modal.style.display = "none";
  document.removeEventListener("keydown", _exportModalEscHandler);
}

function _exportModalEscHandler(e) {
  if (e.key === "Escape") closeExportModal();
}

function _exportBuildUrl(forceAttachment) {
  // Read the current modal values + assemble the query string. Pulled
  // out so all three buttons (copy / download / open) build the same URL.
  const fmt = document.getElementById("export-format").value;
  const scope = document.getElementById("export-scope").value;
  const redact = document.getElementById("export-redact-pii").checked ? "1" : "0";
  const params = new URLSearchParams({format: fmt, scope: scope, redact_pii: redact});
  if (forceAttachment) params.set("attachment", "1");
  return "/api/report/export?" + params.toString();
}

function _exportSetStatus(msg, color) {
  const el = document.getElementById("export-status");
  if (el) {
    el.textContent = msg;
    el.style.color = color || "var(--muted)";
  }
}

async function exportReportCopy() {
  const btn = document.getElementById("export-copy-btn");
  if (btn) btn.disabled = true;
  _exportSetStatus("Generating…");
  try {
    const r = await fetch(_exportBuildUrl(false));
    if (!r.ok) {
      const err = await r.json().catch(() => ({error: r.statusText}));
      _exportSetStatus("Error: " + (err.error || r.statusText), "var(--red)");
      return;
    }
    const text = await r.text();
    // Modern Clipboard API requires HTTPS or localhost; localhost dashboard
    // runs on http://localhost:5000 which IS a secure context per spec.
    await navigator.clipboard.writeText(text);
    _exportSetStatus(`Copied ${text.length.toLocaleString()} characters to clipboard.`, "var(--green)");
  } catch (e) {
    _exportSetStatus("Copy failed: " + (e && e.message || e), "var(--red)");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function exportReportDownload() {
  // Use a transient anchor click so the browser handles the
  // attachment=1 Content-Disposition naturally. Avoids buffering the
  // whole report through fetch + blob just to trigger a save.
  const url = _exportBuildUrl(true);
  const a = document.createElement("a");
  a.href = url;
  // The Content-Disposition header drives the actual filename; this
  // attribute is just a fallback hint for browsers that ignore it.
  a.download = "windesktopmgr_report";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  _exportSetStatus("Download started.", "var(--green)");
}

function exportReportOpen() {
  // Open in a new tab for inline preview. HTML and JSON render
  // natively; markdown shows as plain text (which is fine for review).
  window.open(_exportBuildUrl(false), "_blank", "noopener,noreferrer");
  _exportSetStatus("Opened in new tab.", "var(--green)");
}

function _highlightWindowButton(hours) {
  document.querySelectorAll(".trends-win-btn").forEach(b => {
    const sel = String(b.dataset.trendsWindow) === String(hours);
    b.style.background = sel ? "var(--cyan)" : "transparent";
    b.style.color = sel ? "#000" : "var(--muted)";
    b.style.fontWeight = sel ? "700" : "400";
  });
}

async function setTrendsModalWindow(hours) {
  if (!_trendsModalMetric) return;
  const cfg = _trendsLabels[_trendsModalMetric] || {label: _trendsModalMetric, color: "#00d4ff", unit: ""};
  _highlightWindowButton(hours);
  await _renderTrendModalChart(_trendsModalMetric, hours, cfg);
}

// Render Chart.js line chart + stats + recent-samples table. For the
// 7-day window we use the cached series (loaded by loadTrends);
// for 24h/3d we slice the cache; for 30d we re-fetch /api/metrics/
// history with window_h=720 since the cache only holds 168h.
async function _renderTrendModalChart(metric, hours, cfg) {
  let series = _trendsRawSeries[metric] || [];
  const cutoffMs = Date.now() - hours * 3600 * 1000;
  if (hours > 168 || !series.length) {
    // Need a wider window than the cache holds -- fetch the metric directly
    try {
      const r = await fetch(`/api/metrics/history?metric=${encodeURIComponent(metric)}&window_h=${hours}`);
      const d = await r.json();
      series = d.series || [];
    } catch (e) {
      console.warn("Trend modal fetch failed:", e);
    }
  }
  // Filter to the requested window + parse values
  const filtered = series
    .map(p => ({ts: new Date(p.ts).getTime(), v: Number(p.value)}))
    .filter(p => Number.isFinite(p.v) && p.ts >= cutoffMs)
    .sort((a, b) => a.ts - b.ts);

  // Stats panel
  const values = filtered.map(p => p.v);
  const stats = _trendStats(values);
  const fmt = (x) => x == null ? "—" : x.toFixed(1) + (cfg.unit || "");
  const trendDir = stats == null ? "—"
                : Math.abs(stats.slope) < 0.001 ? "→ flat"
                : stats.slope > 0 ? "↑ rising" : "↓ falling";
  const trendColor = stats == null ? "var(--muted)"
                   : Math.abs(stats.slope) < 0.001 ? "var(--muted)"
                   : stats.slope > 0 ? "var(--orange)" : "var(--green)";
  const statBlock = (label, val, color = "var(--text)") =>
    `<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px 10px">
      <div style="font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">${label}</div>
      <div style="font-size:14px;font-weight:700;color:${color};font-family:var(--font-mono);margin-top:2px">${val}</div>
    </div>`;
  document.getElementById("db-trends-modal-stats").innerHTML = stats == null
    ? `<div style="color:var(--muted);font-size:11px;grid-column:1/-1">No samples in this window.</div>`
    : [
        statBlock("Now",    fmt(stats.now), cfg.color),
        statBlock("Min",    fmt(stats.min)),
        statBlock("Max",    fmt(stats.max), "var(--orange)"),
        statBlock("Avg",    fmt(stats.avg)),
        statBlock("Median", fmt(stats.median)),
        statBlock("P95",    fmt(stats.p95)),
        statBlock("Trend",  trendDir, trendColor),
        statBlock("Samples", String(stats.n), "var(--muted)"),
      ].join("");

  // Render Chart.js line chart with time-aware X axis (Chart.js parses
  // ISO timestamps if we tell it the parser format)
  if (_trendsModalChart) { _trendsModalChart.destroy(); _trendsModalChart = null; }
  const canvas = document.getElementById("db-trends-modal-chart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  _trendsModalChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: filtered.map(p => new Date(p.ts)),
      datasets: [{
        label: cfg.label,
        data: filtered.map(p => p.v),
        borderColor: cfg.color || "#00d4ff",
        backgroundColor: (cfg.color || "#00d4ff") + "22",
        fill: true,
        tension: 0.2,
        pointRadius: filtered.length > 200 ? 0 : 2,
        pointHoverRadius: 4,
        borderWidth: 1.5,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: {mode: "nearest", intersect: false, axis: "x"},
      plugins: {
        legend: {display: false},
        tooltip: {
          callbacks: {
            title: (items) => {
              const d = new Date(items[0].parsed.x);
              return d.toLocaleString();
            },
            label: (item) => `${cfg.label}: ${item.parsed.y.toFixed(2)}${cfg.unit || ""}`,
          },
        },
      },
      scales: {
        x: {
          type: "time",
          time: {
            unit: hours <= 24 ? "hour" : hours <= 72 ? "hour" : "day",
            displayFormats: {hour: "MMM d HH:mm", day: "MMM d"},
          },
          ticks: {color: "#aaa", font: {size: 10}, maxTicksLimit: 10},
          grid: {color: "rgba(255,255,255,0.05)"},
        },
        y: {
          ticks: {
            color: "#aaa",
            font: {size: 10},
            callback: (v) => v + (cfg.unit || ""),
          },
          grid: {color: "rgba(255,255,255,0.05)"},
        },
      },
    },
  });

  // Recent samples table (last 20)
  const recentEl = document.getElementById("db-trends-modal-recent");
  if (recentEl) {
    const rows = filtered.slice(-20).reverse().map(p => {
      const dt = new Date(p.ts).toLocaleString();
      return `<div style="display:flex;justify-content:space-between;padding:3px 8px;border-bottom:1px solid var(--border)">
        <span style="color:var(--muted)">${dt}</span>
        <span style="color:var(--text)">${p.v.toFixed(2)}${cfg.unit || ""}</span>
      </div>`;
    }).join("");
    recentEl.innerHTML = rows || `<div style="color:var(--muted);padding:8px">No samples</div>`;
  }
}

// Inline SVG sparkline: tiny line chart with no axes / labels. Returns a
// <svg> string ready to drop into innerHTML. No dependency on Chart.js
// or anything heavyweight — sparklines stay readable at this size.
function trendSparkline(values, color = "#00d4ff", w = 160, h = 32) {
  if (!values || values.length < 2) {
    return `<div style="color:var(--muted);font-size:10px;height:${h}px;display:flex;align-items:center">need ≥2 samples</div>`;
  }
  const min = Math.min(...values), max = Math.max(...values);
  const range = (max - min) || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * (w - 2) + 1;
    const y = h - 1 - ((v - min) / range) * (h - 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  // Polyline = the line itself. The two circle markers pin the start
  // and end so the user can see direction at a glance even on flat lines.
  const first = pts.split(" ")[0].split(",");
  const lastPt = pts.split(" ").slice(-1)[0].split(",");
  return `<svg width="100%" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="display:block">
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${first[0]}" cy="${first[1]}" r="2" fill="${color}" opacity="0.6"/>
    <circle cx="${lastPt[0]}" cy="${lastPt[1]}" r="2.5" fill="${color}"/>
  </svg>`;
}

// Alert rules card: list every rule with inline threshold / enable edits.
// Backlog #5 — the user should never have to edit Python to tune warning
// thresholds.
async function loadAlertRules() {
  const el = document.getElementById("db-alerts-rows");
  if (!el) return;
  try {
    const r = await fetch("/api/alerts/rules");
    const d = await r.json();
    const rules = d.rules || [];
    if (!rules.length) { el.innerHTML = '<div style="color:var(--muted);font-size:12px">No rules.</div>'; return; }
    const lvlColor = l => l === "critical" ? "var(--red)" : l === "warning" ? "var(--orange)" : "var(--cyan)";
    const unitFor = m => m === "temperature_c" ? "°C" : "%";
    el.innerHTML = rules.map(rule => `
      <div data-rule-id="${esc(rule.id)}" style="display:flex;align-items:center;gap:12px;padding:8px 12px;background:var(--card);border:1px solid var(--border);border-left:3px solid ${lvlColor(rule.level)};border-radius:6px">
        <span style="font-size:18px;flex-shrink:0">${esc(rule.icon || "⚠")}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;font-size:12px;color:var(--text-bright)">${esc(rule.name)}</div>
          <div style="font-size:10px;color:var(--muted);font-family:var(--font-mono)">${esc(rule.metric)} · <span style="color:${lvlColor(rule.level)}">${esc(rule.level.toUpperCase())}</span></div>
        </div>
        <label style="font-size:10px;color:var(--muted)">Threshold</label>
        <input type="number" step="1" min="0" max="110" value="${rule.threshold}"
               style="width:64px;padding:3px 6px;background:var(--bg);border:1px solid var(--border);color:var(--text-bright);border-radius:4px;font-family:var(--font-mono);font-size:11px"
               data-field="threshold">
        <span style="font-size:10px;color:var(--muted);margin-left:-6px">${unitFor(rule.metric)}</span>
        <label style="font-size:10px;color:var(--muted);display:flex;align-items:center;gap:4px;cursor:pointer">
          <input type="checkbox" ${rule.enabled ? "checked" : ""} data-field="enabled">
          enabled
        </label>
        <button data-action="save" style="background:transparent;border:1px solid var(--border);color:var(--cyan);padding:3px 10px;border-radius:4px;cursor:pointer;font-size:10px;font-weight:600">Save</button>
      </div>
    `).join("");
    el.querySelectorAll("div[data-rule-id]").forEach(row => {
      row.querySelector("button[data-action=save]").addEventListener("click", () =>
        saveAlertRule(row)
      );
    });
  } catch (ex) {
    console.warn("loadAlertRules failed:", ex);
    el.innerHTML = '<div style="color:var(--red);font-size:12px">Failed to load alert rules.</div>';
  }
}

async function saveAlertRule(rowEl) {
  const ruleId = rowEl.dataset.ruleId;
  const threshold = parseFloat(rowEl.querySelector("input[data-field=threshold]").value);
  const enabled = rowEl.querySelector("input[data-field=enabled]").checked;
  const btn = rowEl.querySelector("button[data-action=save]");
  const prev = btn.textContent;
  btn.disabled = true;
  btn.textContent = "…";
  try {
    const r = await fetch(`/api/alerts/rules/${encodeURIComponent(ruleId)}`, {
      method: "PATCH",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({threshold, enabled}),
    });
    const d = await r.json();
    if (d.ok) {
      btn.textContent = "✓ saved";
      // Reload the concerns list so the new threshold takes effect immediately
      if (typeof loadDashboard === "function") setTimeout(loadDashboard, 600);
      setTimeout(() => { btn.textContent = prev; btn.disabled = false; }, 1500);
    } else {
      btn.textContent = "✗ " + (d.error || "failed");
      setTimeout(() => { btn.textContent = prev; btn.disabled = false; }, 3000);
    }
  } catch (ex) {
    btn.textContent = "✗ network";
    setTimeout(() => { btn.textContent = prev; btn.disabled = false; }, 3000);
  }
}

// Auto-load dashboard when it's the active tab on startup
document.addEventListener("DOMContentLoaded", () => {
  // Retry dashboard load if server is still starting (e.g. after tray restart)
  function tryLoadDashboard(retries) {
    fetch("/api/dashboard/summary", {signal: AbortSignal.timeout(5000)})
      .then(() => loadDashboard())
      .catch(() => {
        if (retries > 0) setTimeout(() => tryLoadDashboard(retries - 1), 1000);
        else loadDashboard(); // final attempt even if server seems down
      });
  }
  setTimeout(() => tryLoadDashboard(3), 400);
});

