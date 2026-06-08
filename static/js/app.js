// ── Shared ─────────────────────────────────────────────────────────────────
const CAT_ICONS = { Display:"🖥", Audio:"🔊", Network:"🌐", Chipset:"⚙", Other:"📦" };

function escHtml(s) {
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Dynamic favicon (backlog #41) ────────────────────────────────
//
// Tab strip is crowded; users want to spot WinDesktopMgr at a glance
// AND know whether something needs attention. We do both:
//   - Static cyan-W favicon ships from /static/favicon.{svg,ico}
//   - When critical-concern count > 0, _updateFavicon() rebuilds the
//     icon as a canvas with a red badge in the upper-right corner
//     and swaps it in via a data: URI. Same trick Gmail uses for
//     unread-count badges.
// Cached so we don't redraw on every dashboard refresh -- the canvas
// only re-renders when the critical-count toggles between 0 and >0.
let _faviconLastCritical = null;
const _FAVICON_BASE_URL = "/static/favicon.svg";

function _updateFavicon(criticalCount) {
  const hasCritical = (criticalCount || 0) > 0;
  // Skip if state unchanged -- avoids canvas churn on every poll
  if (_faviconLastCritical === hasCritical) return;
  _faviconLastCritical = hasCritical;
  if (!hasCritical) {
    // No critical concerns -- restore the plain SVG icon
    _setFaviconHref(_FAVICON_BASE_URL);
    return;
  }
  // Render: load the SVG into an Image, draw onto a 32x32 canvas,
  // overlay a red circle in the upper-right, swap as data: URI.
  // No crossOrigin -- the SVG is same-origin (/static/), and setting
  // crossOrigin="anonymous" forced the browser to insist on CORS
  // headers it didn't actually need, leaving the image stuck in a
  // pending state and the favicon never swapping.
  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 32;
    canvas.height = 32;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, 32, 32);
    // Red badge dot, upper-right. Generous radius for visibility at
    // 16x16 favicon-strip scale.
    ctx.beginPath();
    ctx.arc(24, 8, 7, 0, 2 * Math.PI);
    ctx.fillStyle = "#ff4560";
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = "#0d1117";
    ctx.stroke();
    _setFaviconHref(canvas.toDataURL("image/png"));
  };
  img.onerror = () => {
    // SVG load failed -- fall back to the plain ICO so the user at
    // least sees the brand mark, just without the red overlay.
    _setFaviconHref("/static/favicon.ico");
  };
  img.src = _FAVICON_BASE_URL;
}

function _setFaviconHref(href) {
  // Find the SVG link tag; if absent, create one. We always set the
  // SVG link (browsers prefer it); the .ico link stays as an unchanged
  // fallback for old browsers. Setting both would force a flash on swap.
  let link = document.querySelector('link[rel="icon"][type="image/svg+xml"]');
  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    link.type = "image/svg+xml";
    document.head.appendChild(link);
  }
  link.href = href;
}

function fmtTs(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-US", {
      month:"short", day:"numeric", year:"numeric",
      hour:"2-digit", minute:"2-digit"
    });
  } catch { return ts; }
}

// ── Server Heartbeat ─────────────────────────────────────────────────────────
// Detects when Flask server is unavailable (e.g. during restart) and shows
// a reconnection banner instead of letting fetches hang silently.
//
// 2026-04-20 hardening: the original heartbeat used a 2-second fetch timeout
// and flipped ``_serverAlive`` on the first failure. A runaway polling loop
// in another tab saturated the browser's 6-connection-per-host cap, which
// meant /api/health couldn't even get a socket in 2s and the banner flashed
// up permanently even though the server was healthy. The new behaviour:
//
//  - 5-second fetch timeout, giving the browser time to recycle a socket
//  - ``keepalive:true`` so the probe has a shot at outliving pagehide
//  - ``cache:"no-store"`` so we don't get the ghost of a cached 200
//  - Requires THREE consecutive failures (~15 s) before claiming the
//    server is down. One blip no longer blames the server.
//  - Counter resets immediately on the next success.
let _serverAlive = true;
let _heartbeatId = null;
let _heartbeatFailures = 0;
const _HEARTBEAT_FAIL_THRESHOLD = 3;

function _startHeartbeat() {
  if (_heartbeatId) return;
  _heartbeatId = setInterval(_checkServer, 3000);
}

function _checkServer() {
  fetch("/api/health", {
    signal: AbortSignal.timeout(5000),
    keepalive: true,
    cache: "no-store",
  })
    .then(r => r.json())
    .then(() => {
      _heartbeatFailures = 0;
      if (!_serverAlive) {
        _serverAlive = true;
        _hideReconnectBanner();
        // Reload dashboard data after reconnect
        if (typeof loadDashboard === "function") setTimeout(loadDashboard, 500);
      }
    })
    .catch(() => {
      _heartbeatFailures++;
      if (_heartbeatFailures >= _HEARTBEAT_FAIL_THRESHOLD && _serverAlive) {
        _serverAlive = false;
        _showReconnectBanner();
      }
    });
}

function _showReconnectBanner() {
  let banner = document.getElementById("reconnect-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "reconnect-banner";
    banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:var(--orange,#f59e0b);color:#000;text-align:center;padding:8px;font-size:13px;font-family:var(--font-mono)";
    banner.textContent = "Server restarting — reconnecting...";
    document.body.prepend(banner);
  }
  banner.style.display = "block";
}

function _hideReconnectBanner() {
  const banner = document.getElementById("reconnect-banner");
  if (banner) banner.style.display = "none";
}

_startHeartbeat();

// ── NLQ (Natural Language Query) ────────────────────────────────────────────
function nlqAsk() {
  const input = document.getElementById("nlq-input");
  const panel = document.getElementById("nlq-panel");
  const content = document.getElementById("nlq-content");
  const btn = document.getElementById("nlq-send");
  const q = input.value.trim();
  if (!q) return;

  panel.classList.add("active");
  content.innerHTML = '<div class="nlq-loading"><div class="spinner"></div><span>Analyzing your system...</span></div>';
  btn.disabled = true;
  btn.textContent = "...";

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 60000);

  fetch("/api/nlq/ask", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({question: q}),
    signal: controller.signal,
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      content.innerHTML = `<div class="nlq-error">${esc(data.error)}</div>`;
      return;
    }
    let html = '<div class="nlq-answer">' + nlqMarkdown(data.answer) + '</div>';
    if (data.navigate_to) {
      html += `<div class="nlq-nav-hint">📍 <a onclick="switchTab('${data.navigate_to}')">Go to ${data.navigate_to} tab</a></div>`;
    }
    content.innerHTML = html;
  })
  .catch(err => {
    if (err.name === "AbortError") {
      content.innerHTML = '<div class="nlq-error">Request timed out — the server may be restarting. Please try again.</div>';
    } else {
      content.innerHTML = `<div class="nlq-error">Request failed: ${esc(err.message)}</div>`;
    }
  })
  .finally(() => {
    clearTimeout(timeoutId);
    btn.disabled = false;
    btn.textContent = "ASK";
  });
}

function nlqClose() {
  document.getElementById("nlq-panel").classList.remove("active");
}

// Enter key sends the question
document.getElementById("nlq-input").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); nlqAsk(); }
  if (e.key === "Escape") nlqClose();
});

// Simple markdown → HTML converter for NLQ responses
function nlqMarkdown(text) {
  if (!text) return "";
  let html = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    // Bold
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    // Inline code
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    // Headers
    .replace(/^#### (.+)$/gm, "<h4>$1</h4>")
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    // Unordered lists
    .replace(/^[*-] (.+)$/gm, "<li>$1</li>")
    // Ordered lists
    .replace(/^\d+\. (.+)$/gm, "<li>$1</li>")
    // Paragraphs (double newline)
    .replace(/\n\n/g, "</p><p>")
    // Single newlines (within paragraphs)
    .replace(/\n/g, "<br>");

  // Wrap consecutive <li> tags in <ul>
  html = html.replace(/((?:<li>.*?<\/li>(?:<br>)?)+)/g, "<ul>$1</ul>");
  html = html.replace(/<br><\/ul>/g, "</ul>").replace(/<ul><br>/g, "<ul>");

  return "<p>" + html + "</p>";
}

const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");

// ── Page switching ──────────────────────────────────────────────────────────
let bsodLoaded = false;
let timelineChart = null, errorChart = null, driverChart = null;

// Track which tabs have been loaded
const _tabLoaded = {};

document.querySelectorAll(".page-tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".page-tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    const page = btn.dataset.page;
    // Stop home network polling when leaving the tab
    if (page !== "homenet" && typeof _hnStopPolling === "function") _hnStopPolling();
    // Iterate the actual nav buttons (data-page attribute) rather than
    // a duplicated string array. The old approach silently broke when
    // a new tab landed in the markup but the dev forgot to update the
    // hardcoded list (caught 2026-05-25 on the Backup tab — clicking
    // it left an empty viewport because "backup" wasn't in the array).
    document.querySelectorAll(".page-tab").forEach(function(t) {
      var p = t.dataset.page;
      if (!p) return;
      var el = document.getElementById("page-" + p);
      if (el) el.style.display = (p === page) ? "" : "none";
    });
    if (page === "dashboard") {
      loadDashboard();
    } else if (page === "drivers") {
      if (!_tabLoaded["drivers"]) { _tabLoaded["drivers"] = true; drvLoadNvidiaStatus(); }
    } else if (page === "bsod") {
      if (!_tabLoaded["bsod"])    { _tabLoaded["bsod"]    = true; loadBsodData(false); }
    } else if (page === "startup") {
      if (!_tabLoaded["startup"]) { _tabLoaded["startup"] = true; loadStartup(); }
    } else if (page === "disk") {
      if (!_tabLoaded["disk"])    { _tabLoaded["disk"]    = true; loadDisk(); }
    } else if (page === "network") {
      if (!_tabLoaded["network"]) { _tabLoaded["network"] = true; loadNetwork(); }
    } else if (page === "updates") {
      if (!_tabLoaded["updates"]) { _tabLoaded["updates"] = true; loadUpdates(); }
    } else if (page === "events") {
      if (!_tabLoaded["events"])  { _tabLoaded["events"]  = true; queryEvents(); loadCacheStatus(); }
    } else if (page === "processes") {
      if (!_tabLoaded["processes"]) { _tabLoaded["processes"] = true; loadProcesses(); }
    } else if (page === "thermals") {
      if (!_tabLoaded["thermals"])  { _tabLoaded["thermals"]  = true; loadThermals(); }
    } else if (page === "services") {
      if (!_tabLoaded["services"])       { _tabLoaded["services"]       = true; loadServices(); }
    } else if (page === "health-history") {
      if (!_tabLoaded["health-history"]) { _tabLoaded["health-history"] = true; loadHealthHistory(); }
    } else if (page === "timeline") {
      if (!_tabLoaded["timeline"])       { _tabLoaded["timeline"]       = true; loadTimeline(); }
    } else if (page === "memory") {
      if (!_tabLoaded["memory"])         { _tabLoaded["memory"]         = true; loadMemory(); }
    } else if (page === "bios") {
      if (!_tabLoaded["bios"])           { _tabLoaded["bios"]           = true; loadBios(); loadBiosAudit(); }
    } else if (page === "credentials") {
      if (!_tabLoaded["credentials"])    { _tabLoaded["credentials"]    = true; loadCredentials(); }
    } else if (page === "sysinfo") {
      if (!_tabLoaded["sysinfo"])        { _tabLoaded["sysinfo"]        = true; loadSystemInfo(); }
    } else if (page === "remediation") {
      if (!_tabLoaded["remediation"])    { _tabLoaded["remediation"]    = true; loadRemediation(); }
    } else if (page === "homenet") {
      if (!_tabLoaded["homenet"])        { _tabLoaded["homenet"]        = true; loadHomeNet(); }
    } else if (page === "baseline") {
      // Force-reload baseline on every visit -- the drift list is only
      // useful if it's current, and the compute is slow enough that
      // caching across visits would serve stale data.
      loadBaseline();
    } else if (page === "backup") {
      // Force-reload on every visit -- File History health can change
      // when a drive is plugged/unplugged, and the call is fast (no
      // subprocess; pure user-space XML parse + a few stat() calls).
      loadBackup();
    } else if (page === "utilities") {
      // Force-reload on every visit -- both halves (Quick Fixes and
      // codehealth status) are cheap reads, and the user opening this
      // tab is the strongest signal they want fresh numbers.
      util_load();
    } else if (page === "logs") {
      if (!_tabLoaded["logs"])           { _tabLoaded["logs"]           = true; logLoad(); }
    } else if (page === "architecture") {
      if (!_tabLoaded["architecture"])   { _tabLoaded["architecture"]   = true; loadArchitecture(); }
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════
// DRIVER MANAGER
// ══════════════════════════════════════════════════════════════════════════
let allDrivers = [], activeTab = "All", pollTimer = null;

/** Load NVIDIA GPU status on tab open and render it as a normal card inside
 *  the driver grid — so the user sees GPU status immediately without running
 *  a full scan, but it sits in the same matrix as every other driver instead
 *  of as a separate banner pinned above the grid. A subsequent Run Scan
 *  replaces the grid with the full driver list (which already includes the
 *  NVIDIA GPU via run_scan), so there is never a duplicate NVIDIA card. */
async function drvLoadNvidiaStatus() {
  try {
    const r = await fetch("/api/nvidia/status");
    const data = await r.json();
    if (!data.ok || !data.has_nvidia) return;  // no NVIDIA GPU — keep the empty state
    // A scan may have started or finished while this request was in flight.
    // Never overwrite real scan results with the single-GPU preview.
    if (allDrivers.length) return;
    // Map the status payload onto the shape buildDriverCard() expects so the
    // GPU renders identically to a scanned driver entry, in the same grid.
    // (buildDriverCard escapes every field, so raw values are passed here.)
    allDrivers = [{
      name: data.Name || "NVIDIA GPU",
      version: data.InstalledVersion || "",
      date: "",
      category: "Display",
      manufacturer: "NVIDIA",
      status: data.UpdateAvailable === true ? "update_available" : "up_to_date",
      latest_version: data.LatestVersion || null,
      latest_date: null,
      download_url: data.UpdateAvailable === true ? "nvidia-app:" : "",
      low_priority: false,
      category_note: "",
    }];
    updateDriverStats();
    renderGrid();
  } catch(e) {
    console.error("Failed to load NVIDIA status:", e);
  }
}

document.getElementById("tabs").addEventListener("click", e => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll("#tabs .tab").forEach(t => t.classList.remove("active"));
  btn.classList.add("active");
  activeTab = btn.dataset.cat;
  renderGrid();
});

async function startScan() {
  try {
    const btn = document.getElementById("btn-scan");
    btn.disabled = true;
    btn.innerHTML = '<span class="icon">⟳</span> Scanning…';
    document.getElementById("progress-wrap").classList.add("visible");
    setProgress(0, "Initializing…");
    await fetch("/api/scan/start", { method:"POST" });
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    pollTimer = setInterval(pollStatus, 800);
  } catch(e) {
    console.error("Scan failed:", e);
    const btn = document.getElementById("btn-scan");
    if (btn) { btn.disabled = false; btn.textContent = "Scan Now"; }
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    setProgress(0, "Scan failed — server may be restarting");
  }
}

async function pollStatus() {
  try {
    const r = await fetch("/api/scan/status");
    const s = await r.json();
    setProgress(s.progress, s.message);
    if (s.status === "complete") {
      clearInterval(pollTimer);
      await loadDriverResults();
      finishScan();
    } else if (s.status === "idle") {
      clearInterval(pollTimer);
    }
  } catch(e) {
    console.error("Poll failed:", e);
    clearInterval(pollTimer);
    pollTimer = null;
    setProgress(0, "Connection lost — refresh to retry");
  }
}

async function loadDriverResults() {
  try {
    const r = await fetch("/api/scan/results");
    allDrivers = await r.json();
    updateDriverStats();
    renderGrid();
    fetchSummary('drivers', {results: allDrivers}, 'summary-drivers');
  } catch(e) {
    console.error("Failed to load driver results:", e);
  }
}

function finishScan() {
  const btn = document.getElementById("btn-scan");
  btn.disabled = false;
  btn.innerHTML = '<span class="icon">⟳</span> Re-Scan';
  document.getElementById("scan-time").textContent = "Last scan: " + new Date().toLocaleTimeString();
  setTimeout(() => document.getElementById("progress-wrap").classList.remove("visible"), 2000);
}

function setProgress(pct, msg) {
  document.getElementById("progress-fill").style.width = pct + "%";
  document.getElementById("progress-pct").textContent = pct + "%";
  document.getElementById("progress-msg").textContent = msg;
}

function updateDriverStats() {
  const updates = allDrivers.filter(d => d.status==="update_available").length;
  const importantUpdates = allDrivers.filter(d => d.status==="update_available" && !d.low_priority).length;
  const ok      = allDrivers.filter(d => d.status==="up_to_date").length;
  const unk     = allDrivers.filter(d => d.status==="unknown").length;
  document.getElementById("stat-total").textContent   = allDrivers.length;
  document.getElementById("stat-updates").textContent = updates;
  document.getElementById("stat-ok").textContent      = ok;
  document.getElementById("stat-unknown").textContent = unk;
}

function renderGrid() {
  const grid = document.getElementById("driver-grid");
  const filtered = activeTab === "All" ? allDrivers : allDrivers.filter(d => d.category===activeTab);
  if (!filtered.length) {
    grid.innerHTML = `<div class="empty-state">
      <div class="big-icon">🔍</div>
      <h3>No drivers found</h3>
      <p>${allDrivers.length ? "No drivers in this category." : "Run a scan to get started."}</p>
    </div>`;
    return;
  }
  grid.innerHTML = filtered.map((d, i) => buildDriverCard(d, i)).join("");
}

async function drvOpenNvidiaApp(e) {
  e.preventDefault();
  try {
    const r = await fetch("/api/launch/nvidia-app", {method:"POST"});
    const data = await r.json();
    if (data.launched) return; // App opened successfully
    // Not installed — open download page
    window.open(data.fallback_url || "https://www.nvidia.com/en-us/software/nvidia-app/", "_blank");
  } catch {
    window.open("https://www.nvidia.com/en-us/software/nvidia-app/", "_blank");
  }
}

function buildDriverCard(d, i) {
  const isLow   = d.low_priority && d.status === "update_available";
  const labels  = { update_available:"Update Available", up_to_date:"Up to Date", unknown:"Unknown" };
  const badge   = isLow
    ? `<div class="badge low-priority">Low Priority</div>`
    : `<div class="badge ${d.status}">${labels[d.status]||"Unknown"}</div>`;
  const isNvidiaApp = d.download_url && d.download_url.startsWith("nvidia-app:");
  const dlBtn = (!isLow && d.status==="update_available" && d.download_url)
    ? (isNvidiaApp
        ? `<a class="btn-dl" href="#" onclick="drvOpenNvidiaApp(event)">🟢 Update via NVIDIA App</a>`
        : `<a class="btn-dl" href="${escHtml(d.download_url)}" target="_blank">↓ Download Update</a>`)
    : "";
  const latestBlock = d.latest_version
    ? `<div class="meta-row">
         <span class="meta-label">Latest Version</span>
         <span class="meta-val${d.status==="update_available" && !isLow?" new":""}">${escHtml(d.latest_version)}</span>
       </div>` : "";
  const noteBlock = (isLow && d.category_note)
    ? `<div style="margin-top:10px;padding:8px 10px;background:#1a1a2a;border:1px solid #3a3a5a;
         border-radius:6px;font-size:10px;color:#7a7a9a;line-height:1.5">
         ℹ ${escHtml(d.category_note)}
       </div>` : "";
  return `
    <div class="driver-card ${d.status}${isLow?" low-priority":""}" data-driver-name="${escHtml(d.name)}" data-driver-status="${escHtml(d.status)}" style="animation-delay:${Math.min(i*18,400)}ms">
      <div class="card-top">
        <div class="card-name">${escHtml(d.name)}</div>
        ${badge}
      </div>
      <div class="card-meta">
        <div class="meta-row">
          <span class="meta-label">Installed Version</span>
          <span class="meta-val">${escHtml(d.version||"—")}</span>
        </div>
        ${latestBlock}
        <div class="meta-row">
          <span class="meta-label">Manufacturer</span>
          <span class="meta-val">${escHtml(d.manufacturer||"—")}</span>
        </div>
        <div class="meta-row">
          <span class="meta-label">Category</span>
          <span class="cat-tag"><span class="cat-icon">${CAT_ICONS[d.category]||"📦"}</span>${escHtml(d.category)}</span>
        </div>
      </div>
      ${noteBlock}
      ${dlBtn}
    </div>`;
}

// ══════════════════════════════════════════════════════════════════════════
// BSOD DASHBOARD
// ══════════════════════════════════════════════════════════════════════════

const CHART_COLORS = [
  "#ff7043","#00d4ff","#00e5a0","#a855f7","#ff4757",
  "#ffd700","#3d84ff","#ff69b4","#00bcd4","#8bc34a"
];

const CHART_DEFAULTS = {
  color: "#6b7a90",
  font: { family: "'JetBrains Mono', monospace", size: 11 },
};

Chart.defaults.color = CHART_DEFAULTS.color;
Chart.defaults.font  = CHART_DEFAULTS.font;

async function loadBsodData(forceRefresh = false) {
  if (forceRefresh) {
    document.getElementById("bsod-content").style.display = "none";
    document.getElementById("bsod-loading").style.display = "flex";
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
    if (errorChart)    { errorChart.destroy();    errorChart = null; }
    if (driverChart)   { driverChart.destroy();   driverChart = null; }
  }

  try {
    const r = await fetch("/api/bsod/data");
    const data = await r.json();
    renderBsodDashboard(data);
  fetchSummary('bsod', data, 'summary-bsod');
  loadBsodCache();
  } catch (e) {
    document.getElementById("bsod-loading").innerHTML =
      `<p style="color:var(--red)">Failed to load BSOD data. Is the Flask server running?</p>`;
  }
}

function renderBsodDashboard(data) {
  const s = data.summary;

  // Stats
  document.getElementById("b-total").textContent  = s.total_crashes;
  document.getElementById("b-month").textContent  = s.this_month;
  document.getElementById("b-common").textContent = s.most_common_error === "None" ? "None" : s.most_common_error;
  document.getElementById("b-uptime").textContent = s.avg_uptime_hours > 0
    ? s.avg_uptime_hours + "h" : "—";

  // Timeline chart
  const tlLabels = data.timeline.map(t => t.label);
  const tlData   = data.timeline.map(t => t.count);
  const maxVal   = Math.max(...tlData, 1);

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(document.getElementById("chart-timeline"), {
    type: "bar",
    data: {
      labels: tlLabels,
      datasets: [{
        label: "Crashes",
        data: tlData,
        backgroundColor: tlData.map(v =>
          v === 0 ? "rgba(28,37,53,.5)" :
          v >= maxVal * 0.8 ? "rgba(255,71,87,.7)" :
          "rgba(255,112,67,.6)"
        ),
        borderRadius: 4, borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(28,37,53,.8)" }, ticks: { maxRotation: 45 } },
        y: { grid: { color: "rgba(28,37,53,.8)" }, beginAtZero: true,
             ticks: { stepSize: 1, precision: 0 } }
      }
    }
  });

  // Error code chart
  if (errorChart) errorChart.destroy();
  if (data.error_codes.length) {
    errorChart = new Chart(document.getElementById("chart-errors"), {
      type: "doughnut",
      data: {
        labels: data.error_codes.map(e => e.code.replace(/_/g," ")),
        datasets: [{
          data: data.error_codes.map(e => e.count),
          backgroundColor: CHART_COLORS,
          borderColor: "#07090f", borderWidth: 2,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { boxWidth: 10, padding: 8, font: { size: 10 } }
          }
        }
      }
    });
  }

  // Faulty drivers chart
  if (driverChart) driverChart.destroy();
  if (data.faulty_drivers.length) {
    document.getElementById("no-drivers").style.display = "none";
    driverChart = new Chart(document.getElementById("chart-drivers"), {
      type: "bar",
      data: {
        labels: data.faulty_drivers.map(d => d.driver),
        datasets: [{
          label: "Crash count",
          data: data.faulty_drivers.map(d => d.count),
          backgroundColor: "rgba(168,85,247,.6)",
          borderRadius: 4, borderSkipped: false,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "rgba(28,37,53,.8)" }, ticks: { precision: 0 } },
          y: { grid: { display: false } }
        }
      }
    });
  } else {
    document.getElementById("no-drivers").style.display = "block";
    document.getElementById("chart-drivers").style.display = "none";
  }

  // Uptime periods
  const uptimeList = document.getElementById("uptime-list");
  const noUptime   = document.getElementById("no-uptime");
  if (data.uptime_periods.length) {
    noUptime.style.display = "none";
    const maxHours = Math.max(...data.uptime_periods.map(p => p.hours), 1);
    uptimeList.innerHTML = data.uptime_periods.slice().reverse().map(p => {
      const pct   = Math.round((p.hours / maxHours) * 100);
      const short = p.hours < 24;
      const label = p.hours >= 24
        ? Math.round(p.hours / 24) + "d"
        : Math.round(p.hours) + "h";
      return `
        <div class="uptime-row">
          <div class="uptime-bar-track">
            <div class="uptime-bar-fill${short?" short":""}" style="width:${pct}%"></div>
          </div>
          <div class="uptime-label${short?" short":""}">${label}</div>
        </div>`;
    }).join("");
  } else {
    noUptime.style.display = "block";
    uptimeList.style.display = "none";
  }

  // Recommendations
  document.getElementById("rec-list").innerHTML = data.recommendations.map((r, i) => `
    <div class="rec-card ${escHtml(r.priority)}" style="animation-delay:${i*60}ms">
      <div class="rec-header">
        <span class="rec-priority">${escHtml(r.priority)}</span>
        <span class="rec-title">${escHtml(r.title)}</span>
      </div>
      <div class="rec-detail">${escHtml(r.detail)}</div>
    </div>`).join("");

  // Crash log table
  const tbody   = document.getElementById("crash-tbody");
  const noCrash = document.getElementById("no-crashes");
  if (data.crashes.length) {
    noCrash.style.display = "none";
    tbody.innerHTML = data.crashes.map(c => `
      <tr>
        <td>${escHtml(fmtTs(c.timestamp))}</td>
        <td class="error-code-cell">${escHtml(c.error_code)}</td>
        <td><code style="font-size:11px;color:var(--text-dim)">${escHtml(c.stop_code||"—")}</code></td>
        <td class="driver-cell">${escHtml(c.faulty_driver||"—")}</td>
        <td><span class="src-badge ${escHtml(c.source)}">${escHtml(c.source.replace("_"," "))}</span></td>
      </tr>`).join("");
  } else {
    noCrash.style.display = "block";
    tbody.innerHTML = "";
  }

  // Show content
  document.getElementById("bsod-loading").style.display  = "none";
  document.getElementById("bsod-content").style.display  = "";
}




// ══════════════════════════════════════════════════════════════════════════
// SUMMARY BANNERS
// ══════════════════════════════════════════════════════════════════════════
function renderSummary(containerId, summary) {
  const el = document.getElementById(containerId);
  if (!el || !summary) return;
  const statusIcons = { ok: "✓", warning: "⚠", critical: "✕", info: "ℹ", idle: "·" };
  const s = summary.status || "info";
  const icon = statusIcons[s] || "·";
  const insightHtml = (summary.insights || []).map(ins => {
    const action = ins.action ? `<span class="insight-action">→ ${ins.action}</span>` : "";
    return `<div class="insight-row"><span class="insight-dot dot-${ins.level}">●</span><span>${ins.text}${action}</span></div>`;
  }).join("");
  const chipsHtml = (summary.actions || []).length
    ? `<div class="summary-actions">${(summary.actions||[]).map(a=>{
      if (a === "Open Windows Update") return `<a class="action-chip action-link" href="ms-settings:windowsupdate" target="_blank">${a}</a>`;
      if (a === "Update via NVIDIA App") return `<a class="action-chip action-link" href="#" onclick="drvOpenNvidiaApp(event)">${a}</a>`;
      return `<span class="action-chip">${a}</span>`;
    }).join("")}</div>` : "";
  el.className = `summary-banner loaded s-${s}`;
  el.innerHTML = `
    <div class="summary-headline">
      <span class="summary-badge badge-${s}">${icon} ${s}</span>
      ${summary.headline || ""}
    </div>
    <div class="summary-insights">${insightHtml}</div>
    ${chipsHtml}`;
}

// Backlog #29: ETag cache + 1-second identical-payload debounce on
// fetchSummary. The debounce stops runaway-tab fan-out (the
// 2026-04-20 flood pattern fired POST /api/summary/drivers ~100×/sec).
// The ETag cycle saves the response body bytes when the payload
// genuinely hasn't changed across legitimate refetches.
const _summaryEtags = new Map();      // tab -> last-seen ETag
const _summaryLastFetch = new Map();  // tab -> {payloadStr, ts}
const _summaryDebounceMs = 1000;

async function fetchSummary(tab, payload, containerId) {
  // 1) Identical-payload debounce. If the exact same JSON payload is
  //    fired again within _summaryDebounceMs, skip the network call
  //    entirely. Legitimate spaced refetches (e.g. after loadStartup's
  //    4s follow-up poll) are well outside this window.
  const payloadStr = JSON.stringify(payload);
  const now = Date.now();
  const last = _summaryLastFetch.get(tab);
  if (last && last.payloadStr === payloadStr && (now - last.ts) < _summaryDebounceMs) {
    return;
  }
  _summaryLastFetch.set(tab, { payloadStr, ts: now });

  try {
    const headers = {"Content-Type": "application/json"};
    // 2) Send last-seen ETag for this tab so the server can short-circuit
    //    to 304 if its computed response hasn't changed.
    const lastEtag = _summaryEtags.get(tab);
    if (lastEtag) headers["If-None-Match"] = lastEtag;

    const r = await fetch("/api/summary/" + tab, {
      method: "POST",
      headers: headers,
      body: payloadStr
    });
    // Capture the response's ETag for next round (server sets it on
    // both 200 and 304).
    const etag = r.headers.get("ETag");
    if (etag) _summaryEtags.set(tab, etag);

    // 304: response unchanged, skip the JSON parse + re-render.
    if (r.status === 304) return;

    const s = await r.json();
    renderSummary(containerId, s);
  } catch(e) { console.warn("Summary fetch failed:", e); }
}

// ══════════════════════════════════════════════════════════════════════════
// AUTO-LAUNCH
// ══════════════════════════════════════════════════════════════════════════
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => startScan(), 300);
  setTimeout(() => loadBsodData(false), 600);
});

// ══════════════════════════════════════════════════════════════════════════
// STARTUP MANAGER
// ══════════════════════════════════════════════════════════════════════════
let _startupData = null;
async function loadStartup() {
  try {
    document.getElementById('su-loading').style.display = 'block';
    document.getElementById('su-content').style.display = 'none';
    const r = await fetch('/api/startup/list');
    _startupData = await r.json();
    renderStartup();
    fetchSummary('startup', {items: _startupData}, 'summary-startup');
    // If any items are still pending lookup, refresh once after 4 seconds
    const pendingCount = _startupData.filter(i => !i.info).length;
    if (pendingCount > 0) {
      setTimeout(async () => {
        const r2 = await fetch('/api/startup/list');
        _startupData = await r2.json();
        renderStartup();
        fetchSummary('startup', {items: _startupData}, 'summary-startup');
      }, 4000);
    }
  } catch(e) {
    console.error("Failed to load startup:", e);
  }
}
function renderStartup() {
  if (!_startupData) return;
  // Read all active filters
  const fName       = (document.getElementById("su-f-name")      ?.value || "").toLowerCase().trim();
  const fWhat       = (document.getElementById("su-f-what")      ?.value || "").toLowerCase().trim();
  const fPublisher  = (document.getElementById("su-f-publisher")  ?.value || "").toLowerCase().trim();
  const fLocation   = (document.getElementById("su-f-location")   ?.value || "").toLowerCase();
  const fStatus     = (document.getElementById("su-f-status")     ?.value || "");
  const fRec        = (document.getElementById("su-f-rec")        ?.value || "");
  const fImpact     = (document.getElementById("su-f-impact")     ?.value || "");
  const fSuspicious = (document.getElementById("su-f-suspicious") ?.value || "");

  const items = _startupData.filter(i => {
    const info = i.info || {};
    if (fName      && !(i.Name||"").toLowerCase().includes(fName) &&
                      !(info.plain_name||"").toLowerCase().includes(fName)) return false;
    if (fWhat      && !(info.what||"").toLowerCase().includes(fWhat))       return false;
    if (fPublisher && !(info.publisher||"").toLowerCase().includes(fPublisher)) return false;
    if (fLocation  && !(i.Location||"").toLowerCase().includes(fLocation))  return false;
    if (fStatus === "enabled"  && !i.Enabled)  return false;
    if (fStatus === "disabled" &&  i.Enabled)  return false;
    if (fRec === "unknown") {
      if (info.recommendation && info.recommendation !== "unknown") return false;
      if (!info.recommendation && i.info) return false;
    } else if (fRec && info.recommendation !== fRec) return false;
    if (fImpact    && info.impact !== fImpact)                               return false;
    if (fSuspicious === "suspicious" && !i.suspicious) return false;
    if (fSuspicious === "clean"      &&  i.suspicious) return false;
    return true;
  });

  // Show filtered count
  const countEl = document.getElementById("su-filtered-count");
  if (countEl) {
    const active = [fName,fWhat,fPublisher,fLocation,fStatus,fRec,fImpact,fSuspicious].filter(Boolean).length;
    countEl.textContent = active > 0 ? `Showing ${items.length} of ${_startupData.length}` : "";
  }
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  document.getElementById("su-total").textContent      = _startupData.length;
  document.getElementById("su-enabled").textContent    = _startupData.filter(i => i.Enabled).length;
  document.getElementById("su-suspicious").textContent = _startupData.filter(i => i.suspicious).length;
  document.getElementById("su-tasks").textContent      = _startupData.filter(i => i.Type === "task").length;

  const recColors = { keep:"var(--cyan)", optional:"var(--orange)", disable:"var(--red)" };
  const recLabels = { keep:"&#10003; Keep", optional:"~ Optional", disable:"&#10005; Disable" };
  const impactColors = { low:"var(--cyan)", medium:"var(--orange)", high:"var(--red)", unknown:"var(--muted)" };

  const rows = items.map(item => {
    const info = item.info || null;
    const en   = item.Enabled;

    const dot = en
      ? "<span style='color:var(--cyan)'>&#9679; On</span>"
      : "<span style='color:var(--muted)'>&#9675; Off</span>";
    const toggleBtn = item.Type !== "folder"
      ? "<button onclick=\"doToggle(this,'" + esc(item.Name) + "','" + item.Type + "'," + (!en) + ")\"" +
        " style=\"margin-left:6px;background:" + (en?"#ff404022":"#00d4ff11") + ";border:1px solid " + (en?"var(--red)":"var(--cyan)") + ";" +
        "color:" + (en?"var(--red)":"var(--cyan)") + ";padding:2px 10px;border-radius:4px;cursor:pointer;font-size:11px\">" +
        (en?"Disable":"Enable") + "</button>"
      : "";

    const plainName = info
      ? "<div style='font-weight:700;font-size:13px'>" + esc(info.plain_name) + "</div>" +
        "<div style='color:var(--muted);font-size:11px'>" + esc(item.Name) + "</div>"
      : "<div style='font-weight:700;font-size:13px'>" + esc(item.Name) + "</div>" +
        "<div style='color:var(--muted);font-size:11px;font-style:italic'>Looking up&hellip;</div>";

    const srcTag = info && info.source && info.source !== "static_kb"
      ? " <span style='font-size:10px;color:#8a8aa0'>[" + esc(info.source) + "]</span>" : "";

    const detail = info
      ? "<div style='font-size:12px'>" + esc(info.what) + "</div>" +
        "<div style='font-size:11px;color:var(--muted);margin-top:2px'>" + esc(info.publisher) +
        (info.version ? " v" + esc(info.version) : "") + "</div>"
      : "<div style='font-family:monospace;font-size:11px;color:var(--muted)'>" +
        esc((item.Command||"").substring(0,70)) + ((item.Command||"").length>70?"&hellip;":"") + "</div>";

    const reason = info && info.reason
      ? "<div style='font-size:11px;color:var(--muted);margin-top:4px;font-style:italic'>" + esc(info.reason) + "</div>"
      : "";

    const rec = info ? info.recommendation : null;
    const recBadge = rec
      ? "<span style='font-size:11px;font-weight:700;color:" + (recColors[rec]||"var(--muted)") + "'>" +
        (recLabels[rec]||rec) + "</span>"
      : "";

    const impact = info ? info.impact : null;
    const impactEl = impact && impact !== "unknown"
      ? "<div style='font-size:10px;color:var(--muted);margin-top:3px'>Boot impact: " +
        "<span style='color:" + (impactColors[impact]||"var(--muted)") + "'>" + impact + "</span></div>"
      : "";

    const sus = item.suspicious
      ? "<div style='color:var(--red);font-weight:700;font-size:12px'>&#9888; Suspicious path</div>"
      : "";

    return "<tr style='border-bottom:1px solid var(--border);vertical-align:top'>"
      + "<td style='padding:10px 12px;white-space:nowrap;vertical-align:middle'>" + dot + toggleBtn + "</td>"
      + "<td style='padding:10px 12px'>" + plainName + srcTag + "</td>"
      + "<td style='padding:10px 12px;max-width:320px'>" + detail + reason + "</td>"
      + "<td style='padding:10px 12px;white-space:nowrap'>" + recBadge + impactEl + "</td>"
      + "<td style='padding:10px 12px;color:var(--muted);font-size:11px;white-space:nowrap'>" + esc(item.Location) + "</td>"
      + "<td style='padding:10px 12px'>" + sus + "</td>"
      + "</tr>";
  }).join("");

  document.getElementById("su-tbody").innerHTML = rows ||
    "<tr><td colspan='6' style='padding:24px;text-align:center;color:var(--muted)'>No entries found</td></tr>";
  document.getElementById("su-loading").style.display = "none";
  document.getElementById("su-content").style.display = "";
}
async function doToggle(btn, name, type, enable) {
  btn.disabled = true; btn.textContent = '...';
  const r = await fetch('/api/startup/toggle', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, type, enable}) });
  const d = await r.json();
  if (d.ok) loadStartup(); else { alert('Toggle failed: ' + (d.error||'Unknown error')); loadStartup(); }
}

// ══════════════════════════════════════════════════════════════════════════
// DISK HEALTH
// ══════════════════════════════════════════════════════════════════════════
async function loadDisk() {
  try {
    document.getElementById('dk-loading').style.display = 'block';
    document.getElementById('dk-content').style.display = 'none';
    const r = await fetch('/api/disk/data');
    const d = await r.json();
    const drives = Array.isArray(d.drives) ? d.drives : [];
    const physical = Array.isArray(d.physical) ? d.physical : [];
    const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    // Split by drive type. Default missing type to 'local' for backward compat
    // with cached payloads from the pre-Win32_LogicalDisk implementation.
    const dkType = dr => (dr.DriveTypeName || (dr.DriveType === 4 ? 'network' : dr.DriveType === 2 ? 'removable' : 'local'));
    const localDrives   = drives.filter(dr => dkType(dr) !== 'network');
    const networkDrives = drives.filter(dr => dkType(dr) === 'network');
    document.getElementById('dk-volumes').textContent  = localDrives.length
      + (networkDrives.length ? ` (+${networkDrives.length} net)` : '');
    document.getElementById('dk-physical').textContent = physical.length;
    // Total Space = local only — mapped NAS shares are not this machine's storage.
    const totalGB = localDrives.reduce((s,dr) => s+(dr.TotalGB||0), 0);
    document.getElementById('dk-total').textContent = totalGB.toFixed(1)+' GB';
    const issues = physical.filter(p => p.Health && p.Health.toLowerCase()!=='healthy').length;
    document.getElementById('dk-issues').textContent = issues||'0';
    const drvHtml = localDrives.map(dr => {
      const pct = dr.PctUsed||0;
      const col = pct>90?'var(--red)':pct>70?'var(--orange)':'var(--cyan)';
      const letter = esc(dr.Letter);
      const fsBadge = dr.FileSystem ? `<span style="font-size:10px;color:var(--muted);margin-left:6px">${esc(dr.FileSystem)}</span>` : '';
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px"><div style="font-size:28px;font-weight:800;color:${col}">${letter}:${fsBadge}</div><div style="color:var(--muted);font-size:12px;margin-bottom:12px">${esc(dr.Label||'Local Disk')}</div><div style="background:#ffffff11;border-radius:4px;height:8px;margin-bottom:10px"><div style="background:${col};height:100%;border-radius:4px;width:${pct}%"></div></div><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:12px"><span style="color:var(--muted)">${dr.UsedGB} GB used</span><span style="color:var(--muted)">${dr.FreeGB} GB free</span><span style="font-weight:700;color:${col}">${pct}%</span></div><button class="btn-action" style="width:100%;padding:8px;font-size:12px" onclick="dkAnalyzeOpen('${letter}')">🔍 Analyze Space</button></div>`;
    }).join('');
    document.getElementById('dk-drives').innerHTML = drvHtml || '<p style="color:var(--muted)">No local drives found</p>';
    // Network shares — render separately, no Analyze button (can't run os.scandir
    // over SMB without permission quirks), no red coloring (their fullness is a
    // NAS problem, not a local-disk problem), UNC path badge instead of label.
    const netHtml = networkDrives.map(dr => {
      const pct = dr.PctUsed||0;
      const letter = esc(dr.Letter);
      const unc = esc(dr.UNCPath || '');
      const label = esc(dr.Label || 'Network Share');
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;opacity:0.92"><div style="font-size:28px;font-weight:800;color:var(--muted)">${letter}: <span style="font-size:11px;color:var(--cyan);font-weight:600;vertical-align:middle">CIFS</span></div><div style="color:var(--muted);font-size:12px;margin-bottom:4px">${label}</div><div style="color:var(--cyan);font-size:11px;font-family:monospace;margin-bottom:10px;word-break:break-all">${unc}</div><div style="background:#ffffff11;border-radius:4px;height:8px;margin-bottom:10px"><div style="background:var(--muted);height:100%;border-radius:4px;width:${pct}%"></div></div><div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--muted)">${dr.UsedGB} GB used</span><span style="color:var(--muted)">${dr.FreeGB} GB free</span><span style="font-weight:700;color:var(--muted)">${pct}%</span></div></div>`;
    }).join('');
    document.getElementById('dk-network-drives').innerHTML = netHtml;
    document.getElementById('dk-network-section').style.display = networkDrives.length ? '' : 'none';
    const physRows = physical.map(p => {
      const hc = (p.Health||'').toLowerCase()==='healthy'?'var(--cyan)':'var(--red)';
      return `<tr style="border-bottom:1px solid var(--border)"><td style="padding:8px 12px;font-weight:600">${esc(p.Name)}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.MediaType)}</td><td style="padding:8px 12px">${p.SizeGB} GB</td><td style="padding:8px 12px;color:${hc}">${esc(p.Health)}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.Status)}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.BusType)}</td></tr>`;
    }).join('');
    document.getElementById('dk-tbody').innerHTML = physRows || '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--muted)">No disk info available</td></tr>';
    fetchSummary('disk', d, 'summary-disk');
    document.getElementById('dk-loading').style.display = 'none';
    document.getElementById('dk-content').style.display = '';
  } catch(e) {
    console.error("Failed to load disk:", e);
  }
}

// ── Disk Space Analyzer ───────────────────────────────────────────────────
let _dkAnalyzePath = null;
let _dkAnalyzeDrive = null;

// Escape a string for safe embedding as a JS single-quoted string literal
// inside an HTML attribute like onclick="fn('<value>')". Critically, this
// doubles backslashes so `C:\Users` survives the JS string-literal parser
// (otherwise `\U` is treated as an invalid escape and the backslash is lost).
function dkJsArg(s) {
  return String(s || '')
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;');
}

const _dkAnalyzeCache = new Map();

function dkAnalyzeOpen(letter) {
  _dkAnalyzeDrive = letter;
  _dkAnalyzeCache.clear();
  const root = letter + ':\\';
  document.getElementById('dk-analyze-modal').style.display = 'block';
  dkAnalyzeLoad(root);
  dkQuickWinsLoad(letter);
}

function dkAnalyzeClose() {
  document.getElementById('dk-analyze-modal').style.display = 'none';
  _dkAnalyzePath = null;
  _dkAnalyzeCache.clear();
}

function _dkRenderAnalyzeResult(d) {
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  const entries = d.entries || [];
  const total = d.total_bytes || 0;
  const cloudTotal = d.total_cloud_bytes || 0;
  const cloudSuffix = cloudTotal > 0
    ? ` — plus ${dkHuman(cloudTotal)} in cloud (iCloud/OneDrive/Dropbox, not using local disk)`
    : '';
  document.getElementById('dk-analyze-total').textContent =
    `Scanned total: ${dkHuman(total)} across ${entries.length} items${cloudSuffix}`;
  if (!entries.length) {
    document.getElementById('dk-analyze-tbody').innerHTML =
      '<tr><td colspan="4" style="padding:24px;text-align:center;color:var(--muted)">No items found</td></tr>';
    return;
  }
  const rows = entries.map(e => {
    const pct = e.pct || 0;
    const col = pct > 40 ? 'var(--red)' : pct > 15 ? 'var(--orange)' : 'var(--cyan)';
    const icon = e.type === 'dir' ? '📁' : '📄';
    const drillBtn = e.type === 'dir'
      ? `<button class="btn-action" style="padding:4px 10px;font-size:11px;margin-right:4px" onclick="dkAnalyzeLoad('${dkJsArg(e.path)}')">Drill in</button>`
      : '';
    const cloudBadge = (e.cloud_bytes && e.cloud_bytes > 0)
      ? `<span title="Cloud-only files (iCloud/OneDrive/Dropbox) — not on local disk" style="display:inline-block;margin-left:6px;padding:1px 6px;font-size:9px;background:#3b82f633;color:#93c5fd;border-radius:3px;font-weight:600">☁ ${esc(e.cloud_human)}</span>`
      : '';
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-family:monospace;font-size:12px">${icon} ${esc(e.name)}</td>
      <td style="padding:6px 10px;text-align:right;font-weight:600;color:${col}">${esc(e.size_human)}${cloudBadge}</td>
      <td style="padding:6px 10px;width:200px">
        <div style="background:#ffffff11;border-radius:3px;height:6px"><div style="background:${col};height:100%;border-radius:3px;width:${pct}%"></div></div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px">${pct}% • ${e.item_count||0} items</div>
      </td>
      <td style="padding:6px 10px">
        ${drillBtn}
        <button class="btn-action" style="padding:4px 10px;font-size:11px" onclick="dkOpenFolder('${dkJsArg(e.path)}')">Open</button>
      </td>
    </tr>`;
  }).join('');
  document.getElementById('dk-analyze-tbody').innerHTML = rows;
}

async function dkAnalyzeLoad(path) {
  _dkAnalyzePath = path;
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  document.getElementById('dk-analyze-error').style.display = 'none';
  document.getElementById('dk-analyze-tbody').innerHTML = '';
  document.getElementById('dk-analyze-total').textContent = '';
  // Breadcrumb
  const bc = document.getElementById('dk-analyze-breadcrumb');
  const segments = path.replace(/\\$/,'').split('\\');
  let bcHtml = '';
  let accum = '';
  segments.forEach((seg, i) => {
    if (i === 0) {
      accum = seg + '\\';
      bcHtml += `<a href="#" onclick="dkAnalyzeLoad('${dkJsArg(accum)}');return false" style="color:var(--cyan);text-decoration:none">${esc(seg)}\\</a>`;
    } else if (seg) {
      accum = accum + seg + '\\';
      bcHtml += ` / <a href="#" onclick="dkAnalyzeLoad('${dkJsArg(accum)}');return false" style="color:var(--cyan);text-decoration:none">${esc(seg)}</a>`;
    }
  });
  bc.innerHTML = bcHtml;

  // Check cache — instant back-navigation when drilling back up
  const cacheKey = path.replace(/\\+$/, '').toUpperCase();
  if (_dkAnalyzeCache.has(cacheKey)) {
    document.getElementById('dk-analyze-loading').style.display = 'none';
    _dkRenderAnalyzeResult(_dkAnalyzeCache.get(cacheKey));
    return;
  }

  const loadEl = document.getElementById('dk-analyze-loading');
  loadEl.textContent = 'Scanning — large folders with cloud files can take several minutes\u2026';
  loadEl.style.display = 'block';
  try {
    const _ac = new AbortController();
    const _tid = setTimeout(() => _ac.abort(), 660000);
    const r = await fetch('/api/disk/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path: path, top_n: 30}),
      signal: _ac.signal
    });
    clearTimeout(_tid);
    const d = await r.json();
    loadEl.style.display = 'none';
    if (!d.ok) {
      const err = document.getElementById('dk-analyze-error');
      err.textContent = 'Scan failed: ' + (d.error || 'unknown error');
      err.style.display = 'block';
      return;
    }
    _dkAnalyzeCache.set(cacheKey, d);
    _dkRenderAnalyzeResult(d);
  } catch(e) {
    console.error('analyze failed', e);
    loadEl.style.display = 'none';
    const err = document.getElementById('dk-analyze-error');
    if (e.name === 'AbortError') {
      err.textContent = 'Scan timed out — this folder is very large. Try drilling into a subfolder instead.';
    } else {
      err.textContent = 'Scan failed: ' + e.message + ' — try drilling into a smaller subfolder.';
    }
    err.style.display = 'block';
  }
}

async function dkQuickWinsLoad(letter) {
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  const loadingEl = document.getElementById('dk-quickwins-loading');
  const listEl = document.getElementById('dk-quickwins-list');
  loadingEl.style.display = 'block';
  listEl.innerHTML = '';
  try {
    const r = await fetch('/api/disk/quickwins?drive=' + encodeURIComponent(letter));
    const d = await r.json();
    loadingEl.style.display = 'none';
    if (!d.ok) {
      listEl.innerHTML = `<div style="color:var(--red);font-size:12px">Quick-wins failed: ${esc(d.error||'')}</div>`;
      return;
    }
    const groups = [
      {title: 'System', items: d.locations || []},
      {title: 'User profile', items: d.user_locations || []}
    ];
    let html = '';
    groups.forEach(g => {
      if (!g.items.length) return;
      html += `<div style="color:var(--muted);font-size:11px;margin:8px 0 4px;text-transform:uppercase">${esc(g.title)}</div>`;
      g.items.forEach(it => {
        if (!it.exists) return;
        const col = it.size_bytes > 1e9 ? 'var(--red)' : it.size_bytes > 1e8 ? 'var(--orange)' : 'var(--muted)';
        html += `<div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div style="font-weight:600;font-size:12px">${esc(it.label)}</div>
            <div style="font-weight:700;font-size:13px;color:${col}">${esc(it.size_human)}</div>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-top:2px;word-break:break-all">${esc(it.path)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">${esc(it.description)}</div>
          <div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">
            ${dkRenderQuickWinActions(it)}
          </div>
        </div>`;
      });
    });
    listEl.innerHTML = html || '<div style="color:var(--muted);font-size:12px">No quick-win locations found on this drive.</div>';
  } catch(e) {
    loadingEl.style.display = 'none';
    listEl.innerHTML = `<div style="color:var(--red);font-size:12px">Network error: ${esc(e.message)}</div>`;
  }
}

// Render the action buttons for a single quick-win item. Dispatches based on
// `action_kind` (open_folder | run_tool | info_only) returned by the backend.
// Items may also carry `extra_tools: [{tool, label}, ...]` for secondary
// tool buttons (e.g. Windows Installer offers PatchCleaner + Disk Cleanup).
function dkRenderQuickWinActions(it) {
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  const kind = it.action_kind || 'open_folder';
  const openBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px" onclick="dkOpenFolder('${dkJsArg(it.path)}')">📁 Open folder</button>`;
  const extraBtns = (it.extra_tools || []).map(x =>
    `<button class="btn-action" style="padding:3px 8px;font-size:10px" onclick="dkRunTool('${dkJsArg(x.tool)}','${dkJsArg(x.label)}')">🧹 ${esc(x.label)}</button>`
  ).join('');
  if (kind === 'run_tool') {
    const toolLabel = it.tool_label || it.tool || 'tool';
    const runBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px;background:var(--cyan);color:#000" onclick="dkRunTool('${dkJsArg(it.tool||'')}','${dkJsArg(toolLabel)}')">🧹 Launch ${esc(toolLabel)}</button>`;
    return runBtn + extraBtns + openBtn;
  }
  if (kind === 'info_only') {
    const cli = it.cli || '';
    const cliBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px;background:var(--orange);color:#000" onclick="dkShowCli('${dkJsArg(it.label)}','${dkJsArg(cli)}','${dkJsArg(it.description||'')}')">📋 Show command</button>`;
    return cliBtn + extraBtns + openBtn;
  }
  // default: open_folder
  return openBtn + extraBtns;
}

async function dkRunTool(tool, label) {
  if (!tool) { alert('No tool key provided'); return; }
  try {
    const r = await fetch('/api/disk/run-tool', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tool: tool})
    });
    const d = await r.json();
    if (!d.ok) {
      // Third-party tools may report an install_url when not yet installed
      if (d.install_url) {
        const go = confirm(
          (d.error || (label + ' is not installed')) +
          '\n\nOpen the download page?\n' + d.install_url
        );
        if (go) window.open(d.install_url, '_blank', 'noopener,noreferrer');
      } else {
        alert('Could not launch ' + (label || tool) + ': ' + (d.error || 'unknown error'));
      }
    }
  } catch(e) {
    alert('Network error: ' + e.message);
  }
}

// Show an admin command in a modal dialog with a Copy button. Used for
// info_only quick-wins (WinSxS / hiberfil / etc.) where the user must run
// the command themselves from an elevated prompt.
function dkShowCli(label, cli, desc) {
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  let modal = document.getElementById('dk-cli-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'dk-cli-modal';
    modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:10000;align-items:center;justify-content:center';
    modal.innerHTML = `
      <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;max-width:640px;width:90%;box-shadow:0 10px 40px rgba(0,0,0,0.5)">
        <div id="dk-cli-title" style="font-weight:700;font-size:14px;margin-bottom:6px;color:var(--cyan)"></div>
        <div id="dk-cli-desc" style="font-size:12px;color:var(--muted);margin-bottom:10px"></div>
        <pre id="dk-cli-cmd" style="background:#000;color:#0f0;padding:10px;border-radius:4px;overflow:auto;font-size:12px;font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-all"></pre>
        <div style="font-size:11px;color:var(--orange);margin-top:6px">⚠ Run this command in an <b>elevated</b> PowerShell or Command Prompt (Run as Administrator).</div>
        <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
          <button class="btn-action" onclick="dkCopyCli()">📋 Copy</button>
          <button class="btn-action" onclick="document.getElementById('dk-cli-modal').style.display='none'">Close</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById('dk-cli-title').textContent = label || 'Command';
  document.getElementById('dk-cli-desc').textContent = desc || '';
  document.getElementById('dk-cli-cmd').textContent = cli || '';
  modal.style.display = 'flex';
}

function dkCopyCli() {
  const cmd = document.getElementById('dk-cli-cmd').textContent || '';
  if (!cmd) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(
      () => { const b = event.target; const orig = b.textContent; b.textContent = '✓ Copied'; setTimeout(() => b.textContent = orig, 1500); },
      () => alert('Copy failed — select the command manually.')
    );
  } else {
    // Fallback: select the <pre> text
    const range = document.createRange();
    range.selectNodeContents(document.getElementById('dk-cli-cmd'));
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    alert('Command selected — press Ctrl+C to copy.');
  }
}

async function dkOpenFolder(path) {
  try {
    const r = await fetch('/api/disk/open', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path: path})
    });
    const d = await r.json();
    if (!d.ok) alert('Could not open: ' + (d.error || 'unknown error'));
  } catch(e) {
    alert('Network error: ' + e.message);
  }
}

function dkHuman(n) {
  if (!n) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < units.length-1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}

// ══════════════════════════════════════════════════════════════════════════
// NETWORK MONITOR
// ══════════════════════════════════════════════════════════════════════════
let _networkData = null;
async function loadNetwork() {
  try {
    document.getElementById('nw-loading').style.display = 'block';
    document.getElementById('nw-content').style.display = 'none';
    const r = await fetch('/api/network/data');
    _networkData = await r.json();
    renderNetwork();
    fetchSummary('network', _networkData, 'summary-network');
  } catch(e) {
    console.error("Failed to load network:", e);
  }
}
function renderNetwork() {
  if (!_networkData) return;
  const d = _networkData;
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
  document.getElementById('nw-established').textContent = d.total_connections||0;
  document.getElementById('nw-listening').textContent   = d.total_listening||0;
  document.getElementById('nw-procs').textContent       = (d.top_processes||[]).length;
  document.getElementById('nw-adapters').textContent    = (d.adapters||[]).filter(a=>(a.Status||'').toLowerCase()==='up').length;
  const procRows = (d.top_processes||[]).map(p=>`<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px 12px;font-weight:600">${esc(p.process)}</td><td style="padding:6px 12px;text-align:right;color:var(--cyan)">${p.connections}</td></tr>`).join('');
  document.getElementById('nw-proctable').innerHTML = procRows||'<tr><td colspan="2" style="padding:12px;color:var(--muted)">No connections</td></tr>';
  const adpRows = (d.adapters||[]).map(a=>{const sc=(a.Status||'').toLowerCase()==='up'?'var(--cyan)':'var(--muted)';return `<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px 12px;font-weight:600;color:${sc}">${esc(a.Name)}</td><td style="padding:6px 12px;text-align:right">${a.SentMB}</td><td style="padding:6px 12px;text-align:right">${a.ReceivedMB}</td><td style="padding:6px 12px;text-align:right;color:var(--muted)">${a.LinkSpeedMb} Mbps</td></tr>`;}).join('');
  document.getElementById('nw-adaptertable').innerHTML = adpRows||'<tr><td colspan="4" style="padding:12px;color:var(--muted)">No adapters</td></tr>';
  renderConnections();
  document.getElementById('nw-loading').style.display = 'none';
  document.getElementById('nw-content').style.display = '';
}
function renderConnections() {
  if (!_networkData) return;
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
  const q = (document.getElementById('nw-search').value||'').toLowerCase();
  const conns = (_networkData.established||[]).filter(c=>!q||(c.Process||'').toLowerCase().includes(q)||(c.RemoteAddress||'').includes(q));
  const rows = conns.slice(0,200).map(c=>`<tr style="border-bottom:1px solid var(--border)"><td style="padding:5px 10px;font-weight:600">${esc(c.Process)}</td><td style="padding:5px 10px;color:var(--muted)">${c.PID}</td><td style="padding:5px 10px">${c.LocalPort}</td><td style="padding:5px 10px;font-family:monospace;font-size:11px">${esc(c.RemoteAddress)}</td><td style="padding:5px 10px">${c.RemotePort}</td><td style="padding:5px 10px;color:var(--cyan)">${esc(c.State)}</td></tr>`).join('');
  document.getElementById('nw-contable').innerHTML = rows||'<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--muted)">No connections match filter</td></tr>';
}

// ══════════════════════════════════════════════════════════════════════════
// UPDATE HISTORY
// ══════════════════════════════════════════════════════════════════════════
let _updatesData = null;
async function loadUpdates() {
  try {
    document.getElementById('upd-loading').style.display = 'block';
    document.getElementById('upd-content').style.display = 'none';
    const r = await fetch('/api/updates/history');
    _updatesData = await r.json();
    renderUpdates();
    fetchSummary('updates', {items: _updatesData}, 'summary-updates');
  } catch(e) {
    console.error("Failed to load updates:", e);
  }
}
function renderUpdates() {
  if (!_updatesData) return;
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
  const q = (document.getElementById('upd-search').value||'').toLowerCase();
  const filter = document.getElementById('upd-filter').value;
  const now = new Date();
  const items = _updatesData.filter(u=>(!filter||(u.result||'').includes(filter))&&(!q||(u.Title||'').toLowerCase().includes(q)||(u.KB||'').toLowerCase().includes(q)));
  document.getElementById('upd-total').textContent = _updatesData.length;
  document.getElementById('upd-ok').textContent    = _updatesData.filter(u=>u.result==='Succeeded').length;
  document.getElementById('upd-fail').textContent  = _updatesData.filter(u=>u.result==='Failed'||u.result==='Aborted').length;
  const tm = _updatesData.filter(u=>{const d=new Date(u.Date);return d.getMonth()===now.getMonth()&&d.getFullYear()===now.getFullYear();}).length;
  document.getElementById('upd-month').textContent = tm;
  const rows = items.map(u=>{
    const d=new Date(u.Date);
    const ds=isNaN(d)?u.Date:d.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
    const rc=u.result==='Succeeded'?'var(--cyan)':u.result==='Failed'||u.result==='Aborted'?'var(--red)':'var(--muted)';
    return `<tr style="border-bottom:1px solid var(--border)"><td style="padding:8px 12px;white-space:nowrap;color:var(--muted)">${ds}</td><td style="padding:8px 12px;font-family:monospace;font-size:11px;color:var(--cyan)">${esc(u.KB)}</td><td style="padding:8px 12px">${esc(u.Title)}</td><td style="padding:8px 12px;color:var(--muted);font-size:11px">${esc(u.Categories)}</td><td style="padding:8px 12px;color:${rc};font-weight:600">${esc(u.result)}</td></tr>`;
  }).join('');
  document.getElementById('upd-tbody').innerHTML = rows||'<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--muted)">No updates match filter</td></tr>';
  document.getElementById('upd-loading').style.display = 'none';
  document.getElementById('upd-content').style.display = '';
}

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
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
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
    var esc = function(s) { return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;"); };
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
    const esc = s => String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;");
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


// ══════════════════════════════════════════════════════════════════════════
// PROCESS MONITOR
// ══════════════════════════════════════════════════════════════════════════
let _processData  = null;
let _prAutoTimer  = null;

async function loadProcesses() {
  try {
    document.getElementById("pr-loading").style.display = "block";
    document.getElementById("pr-content").style.display = "none";
    const r = await fetch("/api/processes/list");
    _processData = await r.json();
    renderProcesses();
    fetchSummary("processes", _processData, "summary-processes");
    const pendingProcs = (_processData.processes||[]).filter(p => !p.info).length;
    if (pendingProcs > 0) {
      setTimeout(async () => {
        const r2 = await fetch("/api/processes/list");
        _processData = await r2.json();
        renderProcesses();
        fetchSummary("processes", _processData, "summary-processes");
      }, 4000);
    }
  } catch(e) {
    console.error("Failed to load processes:", e);
  }
}

function renderProcesses() {
  if (!_processData) return;
  const esc   = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const q     = (document.getElementById("pr-search")?.value||"").toLowerCase();
  const flag  = document.getElementById("pr-filter-flag")?.value||"";
  const procs = (_processData.processes||[]).filter(p => {
    // Search across Name, Description, AND PID. Bug 2026-04-28: investigateProcess
    // dropped the user here with the PID in the search box, but the filter only
    // checked Name + Description -- so the table appeared empty (e.g. "28008"
    // doesn't match "ServiceShell.exe"). Adding PID + Path widens the match
    // to cover both the click-from-Memory-tab flow AND power-user lookups.
    if (q) {
      const hit = (p.Name||"").toLowerCase().includes(q)
               || (p.Description||"").toLowerCase().includes(q)
               || String(p.PID||"").includes(q)
               || (p.Path||"").toLowerCase().includes(q);
      if (!hit) return false;
    }
    if (flag === "flagged"   && !p.flag)  return false;
    if (flag === "unflagged" &&  p.flag)  return false;
    return true;
  });

  document.getElementById("pr-total").textContent   = _processData.total||0;
  document.getElementById("pr-ram").textContent     = (_processData.total_mem_mb||0).toFixed(0)+" MB";
  document.getElementById("pr-flagged").textContent = (_processData.flagged||[]).length;
  const countEl = document.getElementById("pr-count");
  if (countEl) countEl.textContent = q||flag ? `Showing ${procs.length} of ${(_processData.processes||[]).length}` : "";

  const flagBg    = f => f==="critical"?"#ff404012":f==="warning"?"#ff704312":"";
  const flagColor = f => f==="critical"?"var(--red)":f==="warning"?"var(--orange)":"var(--muted)";
  const flagLabel = f => f==="critical"?"● HIGH RAM":f==="warning"?"● Elevated":"";

  const rows = procs.map(p => {
    const info    = p.info || null;
    const plain   = info ? info.plain   : p.Name;
    const pub     = info ? info.publisher : "";
    const what    = info ? info.what    : null;
    const safeKill= info ? info.safe_kill : true;
    const srcTag  = info && info.source && info.source !== "static_kb"
      ? ` <span style="font-size:10px;color:#8a8aa0">[${esc(info.source)}]</span>` : "";
    const rowBg   = p.flag ? `background:${flagBg(p.flag)}` : "";

    // Name cell: plain name + raw name below + publisher
    const nameCell =
      `<div style="font-weight:700;font-size:12px">${esc(plain)}${srcTag}</div>` +
      `<div style="color:var(--muted);font-size:10px">${esc(p.Name)} · PID ${p.PID}</div>` +
      (pub && pub !== "Unknown" ? `<div style="color:#8a8aa0;font-size:10px">${esc(pub)}</div>` : "");

    // What it does cell
    const whatCell = what
      ? `<div style="font-size:11px;line-height:1.4">${esc(what.substring(0,120))}${what.length>120?"…":""}</div>`
      : (info === null
         ? `<div style="font-size:11px;color:var(--muted);font-style:italic">Looking up…</div>`
         : `<div style="font-size:11px;color:var(--muted)">${esc(p.Description||p.CmdLine||"—").substring(0,80)}</div>`);

    const memColor = p.MemMB>=1500?"var(--red)":p.MemMB>=500?"var(--orange)":"var(--text)";
    // CPUPct is the real current-load percentage (0-100, normalised across
    // cores). Fall back to the legacy CPU field (cumulative seconds) only
    // if the backend didn't populate CPUPct. Colour thresholds match
    // CPU_WARN_PCT (25%) and a pragmatic "hot" tier at 60%.
    const cpuPct  = (p.CPUPct != null) ? p.CPUPct : 0;
    const cpuSec  = p.CPUTime || p.CPU || 0;
    const cpuColor = cpuPct >= 60 ? "var(--red)" : cpuPct >= 25 ? "var(--orange)" : "var(--muted)";
    const cpuTitle = `Cumulative CPU time: ${cpuSec.toFixed(1)} s (since process started)`;

    const canKill  = p.PID && p.PID > 4 && safeKill !== false &&
                     !["system","idle"].includes((p.Name||"").toLowerCase());
    const killBtn  = canKill
      ? `<button onclick="killProc(${p.PID},'${esc(plain)}')"
           style="background:#ff404022;border:1px solid var(--red);color:var(--red);
           padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px">Kill</button>`
      : (safeKill === false
         ? `<span style="font-size:10px;color:var(--muted)">Protected</span>` : "");

    return `<tr style="border-bottom:1px solid var(--border);vertical-align:top;${rowBg}">
      <td style="padding:8px 10px">${nameCell}</td>
      <td style="padding:8px 10px;max-width:280px">${whatCell}</td>
      <td style="padding:8px 10px;text-align:right;color:var(--muted);vertical-align:middle">${p.PID}</td>
      <td style="padding:8px 10px;text-align:right;color:${memColor};font-weight:${p.MemMB>=500?"700":"400"};vertical-align:middle">${(p.MemMB||0).toFixed(0)}</td>
      <td style="padding:8px 10px;text-align:right;color:${cpuColor};vertical-align:middle" title="${cpuTitle}">${cpuPct.toFixed(1)}%</td>
      <td style="padding:8px 10px;text-align:right;color:var(--muted);vertical-align:middle">${p.Threads||0}</td>
      <td style="padding:8px 10px;color:${flagColor(p.flag)};font-size:11px;white-space:nowrap;vertical-align:middle;font-weight:700">${flagLabel(p.flag)}</td>
      <td style="padding:8px 10px;vertical-align:middle">${killBtn}</td>
    </tr>`;
  }).join("");

  document.getElementById("pr-tbody").innerHTML = rows ||
    "<tr><td colspan='8' style='padding:24px;text-align:center;color:var(--muted)'>No processes match filter</td></tr>";
  document.getElementById("pr-loading").style.display = "none";
  document.getElementById("pr-content").style.display = "";
}

async function killProc(pid, name) {
  if (!confirm(`Kill process "${name}" (PID ${pid})? Unsaved work in this process will be lost.`)) return;
  const r = await fetch("/api/processes/kill", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({pid})
  });
  const d = await r.json();
  if (d.ok) { loadProcesses(); }
  else { alert("Kill failed: " + (d.error||"Unknown error")); }
}

function togglePrAutoRefresh() {
  const btn = document.getElementById("pr-auto-btn");
  const lbl = document.getElementById("pr-refresh-lbl");
  if (_prAutoTimer) {
    clearInterval(_prAutoTimer);
    _prAutoTimer = null;
    btn.textContent = "▶ Auto-refresh (5s)";
    btn.style.borderColor = "var(--border)";
    btn.style.color = "var(--muted)";
    if (lbl) lbl.textContent = "Off";
  } else {
    _prAutoTimer = setInterval(loadProcesses, 5000);
    btn.textContent = "⏹ Stop Auto-refresh";
    btn.style.borderColor = "var(--cyan)";
    btn.style.color = "var(--cyan)";
    if (lbl) lbl.textContent = "5s";
  }
}

// ══════════════════════════════════════════════════════════════════════════
// TEMPERATURE & POWER
// ══════════════════════════════════════════════════════════════════════════
let _thermalsData = null;
let _thAutoTimer  = null;
let _lhmStatus    = null;

async function loadThermals() {
  try {
    const ld = document.getElementById("th-loading");
    if (ld) { ld.style.display = "block"; ld.textContent = "Loading thermal data…"; }
    document.getElementById("th-content").style.display = "none";
    const r = await fetch("/api/thermals/data");
    _thermalsData = await r.json();
    // LHM installer status drives the per-core CTA button (best effort —
    // the CTA still renders its copy if this fetch fails).
    try { _lhmStatus = await (await fetch("/api/thermals/lhm/status")).json(); }
    catch(_e) { _lhmStatus = null; }
    renderThermals();
    fetchSummary("thermals", _thermalsData, "summary-thermals");
  } catch(e) {
    console.error("Failed to load thermals:", e);
    // Surface the failure instead of leaving "Loading thermal data…" up
    // forever -- the 10s auto-refresh would otherwise spin silently.
    const ld = document.getElementById("th-loading");
    if (ld) { ld.style.display = "block"; ld.textContent = "Failed to load thermal data. Will retry on next refresh."; }
    document.getElementById("th-content").style.display = "none";
  }
}

// Thermals tab — instrument-cluster redesign (PR4). Built with DOM methods +
// textContent (no innerHTML -> XSS-proof). Renders hero radial gauges, a
// per-core temperature grid (auto-populates when LibreHardwareMonitor exposes
// "CPU Core #N" sensors; else an install CTA), cooling-device cards, and the
// detailed sensor list. Sections hide themselves when their data is absent.
function renderThermals() {
  if (!_thermalsData) return;
  const d = _thermalsData;
  const perf = d.perf || {};
  const temps = Array.isArray(d.temps) ? d.temps : [];
  const fans = Array.isArray(d.fans) ? d.fans : [];

  const cpu = perf.CPUPct || 0;
  const memU = perf.MemUsedMB || 0;
  const memT = perf.MemTotalMB || 1;
  const memP = Math.round(memU / memT * 100);

  const setText = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  setText("th-cpu", cpu + "%");
  setText("th-ram", memP + "%");
  setText("th-sensors", temps.length);
  const peak = temps.length ? Math.max(...temps.map(t => t.TempC || 0)) : null;
  setText("th-peak", peak !== null ? peak + "°C" : "—");

  // Hero radial gauges (reuse the dashboard renderer; same 5 readouts).
  renderGauges(document.getElementById("th-gauge-row"), d.gauges || []);

  const mk = (cls, text) => {
    const x = document.createElement("div");
    if (cls) x.className = cls;
    if (text != null) x.textContent = text;
    return x;
  };
  const isCore = t => /core\s*#?\d+/i.test(String(t.Name || ""));
  const tempColor = c => c >= 95 ? "var(--red)" : c >= 80 ? "var(--orange)" : c >= 65 ? "var(--cyan-hi)" : "var(--cyan)";

  // ── Per-core grid (LHM "CPU Core #N") OR install CTA ──
  const cores = temps.filter(isCore);
  const coresEl = document.getElementById("th-cores");
  coresEl.textContent = "";
  if (cores.length) {
    document.getElementById("th-cores-section").style.display = "";
    document.getElementById("th-cores-cta").style.display = "none";
    cores.forEach(t => {
      const c = t.TempC || 0;
      const cell = mk("th-core");
      cell.appendChild(mk("th-core-name", String(t.Name || "").replace(/cpu\s*/i, "")));
      cell.appendChild(mk("th-core-temp", c + "°"));
      const bar = mk("th-core-bar");
      bar.style.width = Math.max(0, Math.min(100, Math.round(c))) + "%";
      bar.style.background = tempColor(c);
      cell.appendChild(bar);
      coresEl.appendChild(cell);
    });
  } else {
    document.getElementById("th-cores-section").style.display = "none";
    const cta = document.getElementById("th-cores-cta");
    cta.style.display = "";
    cta.textContent = "";
    cta.appendChild(mk("th-cta-icon", "🌡"));
    const body = mk("th-cta-body");
    body.appendChild(mk("th-cta-title", "Per-core CPU temperatures need LibreHardwareMonitor"));
    body.appendChild(mk("th-cta-sub", d.note ||
      "LibreHardwareMonitor publishes per-core CPU temperatures over WMI while it runs (as Administrator). Install it below and the per-core grid + CPU-temp gauge populate automatically — no leaving the app."));
    thRenderLhmActions(body);
    cta.appendChild(body);
  }

  // ── Cooling-device cards ──
  const fansEl = document.getElementById("th-fans");
  fansEl.textContent = "";
  if (fans.length) {
    document.getElementById("th-fans-section").style.display = "";
    fans.forEach((f, i) => {
      const active = f.ActiveCooling !== false;
      const rpm = (f.DesiredSpeed != null && f.DesiredSpeed !== "") ? f.DesiredSpeed : null;
      const card = mk("th-fan" + (active ? "" : " th-fan-idle"));
      card.appendChild(mk("th-fan-name", (f.Name || "Fan") + (fans.length > 1 ? " " + (i + 1) : "")));
      const blade = mk("th-fan-blade" + (active ? " spin" : ""));
      blade.textContent = "✲";
      card.appendChild(blade);
      card.appendChild(mk("th-fan-val", rpm != null ? rpm + " rpm" : (active ? "Active" : "Idle")));
      fansEl.appendChild(card);
    });
  } else {
    document.getElementById("th-fans-section").style.display = "none";
  }

  // ── Detailed temperature-sensor list (non-core LHM/OHM sensors) ──
  const others = temps.filter(t => !isCore(t));
  const grid = document.getElementById("th-temps-grid");
  grid.textContent = "";
  if (others.length) {
    document.getElementById("th-sensors-section").style.display = "";
    others.forEach(t => {
      const c = t.TempC || 0;
      const col = tempColor(c);
      const row = mk("th-sensor");
      const top = mk("th-sensor-top");
      top.appendChild(mk("th-sensor-name", t.Name || ""));
      const val = mk("th-sensor-temp", c + "°C");
      val.style.color = col;
      top.appendChild(val);
      row.appendChild(top);
      const track = mk("th-sensor-track");
      const fill = mk("th-sensor-fill");
      fill.style.width = Math.min(100, Math.round((c - 20) / 80 * 100)) + "%";
      fill.style.background = col;
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(mk("th-sensor-meta", (t.Source || "") + " — " + (t.status || "")));
      grid.appendChild(row);
    });
  } else {
    document.getElementById("th-sensors-section").style.display = "none";
  }

  document.getElementById("th-loading").style.display = "none";
  document.getElementById("th-content").style.display = "";
}

// ── LibreHardwareMonitor in-app installer (per-core CTA) ──────────────────
// Built with DOM methods + textContent (no innerHTML). The button shown
// depends on _lhmStatus: Install -> Launch-as-admin -> (running, gauges fill).
function thRenderLhmActions(body) {
  const st = _lhmStatus || {};
  const row = document.createElement("div");
  row.className = "th-cta-actions";
  const status = document.createElement("div");
  status.className = "th-cta-status";
  if (st.running) {
    status.textContent = "LibreHardwareMonitor is running — refresh to pull per-core temps.";
    const btn = thMkCtaBtn("↺ Refresh now", () => loadThermals());
    row.appendChild(btn);
  } else if (st.installed) {
    const btn = thMkCtaBtn("⚡ Launch as admin", (b) => thLaunchLhm(b));
    row.appendChild(btn);
    status.textContent = "Installed. Launch it (you'll approve a Windows admin prompt) to publish per-core sensors.";
  } else {
    const btn = thMkCtaBtn("⬇ Install LibreHardwareMonitor", (b) => thInstallLhm(b));
    row.appendChild(btn);
    status.textContent = "One click downloads the verified " + (st.version || "v0.9.6") +
      " build (~6 MB, SHA256-checked) into your user folder. No admin needed to install.";
  }
  body.appendChild(row);
  body.appendChild(status);
}

function thMkCtaBtn(label, onClick) {
  const b = document.createElement("button");
  b.className = "th-cta-btn";
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", () => onClick(b));
  return b;
}

function thCtaError(msg) {
  const cta = document.getElementById("th-cores-cta");
  let err = document.getElementById("th-cta-err");
  if (!err) {
    err = document.createElement("div");
    err.id = "th-cta-err";
    err.className = "th-cta-err";
    cta.appendChild(err);
  }
  err.textContent = msg;
}

async function thInstallLhm(btn) {
  btn.disabled = true;
  btn.textContent = "Installing…";
  try {
    const d = await (await fetch("/api/thermals/lhm/install", {method: "POST"})).json();
    if (d.ok) {
      _lhmStatus = {installed: true, running: false, version: d.version};
      renderThermals();        // re-render → now shows the Launch button
    } else {
      btn.disabled = false;
      btn.textContent = "⬇ Install LibreHardwareMonitor";
      thCtaError(d.error || "Install failed.");
    }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "⬇ Install LibreHardwareMonitor";
    thCtaError("Install failed: " + e);
  }
}

async function thLaunchLhm(btn) {
  btn.disabled = true;
  btn.textContent = "Launching (approve the admin prompt)…";
  try {
    const d = await (await fetch("/api/thermals/lhm/launch", {method: "POST"})).json();
    if (d.ok) {
      btn.textContent = "Launched — reading sensors…";
      // Give LHM a few seconds to publish its WMI namespace, then reload.
      setTimeout(loadThermals, 6000);
    } else {
      btn.disabled = false;
      btn.textContent = "⚡ Launch as admin";
      thCtaError(d.error || "Launch failed.");
    }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "⚡ Launch as admin";
    thCtaError("Launch failed: " + e);
  }
}

function toggleThAutoRefresh() {
  const btn = document.getElementById("th-auto-btn");
  if (_thAutoTimer) {
    clearInterval(_thAutoTimer);
    _thAutoTimer = null;
    btn.textContent = "▶ Auto-refresh (10s)";
    btn.style.borderColor = "var(--border)";
    btn.style.color = "var(--muted)";
  } else {
    _thAutoTimer = setInterval(loadThermals, 10000);
    btn.textContent = "⏹ Stop Auto-refresh";
    btn.style.borderColor = "var(--cyan)";
    btn.style.color = "var(--cyan)";
  }
}

// ══════════════════════════════════════════════════════════════════════════
// WINDOWS SERVICES
// ══════════════════════════════════════════════════════════════════════════
let _servicesData = null;

async function loadServices() {
  try {
    document.getElementById("sv-loading").style.display = "block";
    document.getElementById("sv-content").style.display = "none";
    const r = await fetch("/api/services/list");
    _servicesData = await r.json();
    renderServices();
    fetchSummary("services", {services: _servicesData}, "summary-services");
    const unknown = _servicesData.filter(s => !s.info || s.info.source === "unknown").length;
    if (unknown > 0) {
      setTimeout(async () => {
        const r2 = await fetch("/api/services/list");
        _servicesData = await r2.json();
        renderServices();
      }, 4000);
    }
  } catch(e) {
    console.error("Failed to load services:", e);
  }
}

function renderServices() {
  if (!_servicesData) return;
  const esc     = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const fName   = (document.getElementById("sv-f-name")?.value||"").toLowerCase();
  const fWhat   = (document.getElementById("sv-f-what")?.value||"").toLowerCase();
  const fStatus = document.getElementById("sv-f-status")?.value||"";
  const fStart  = document.getElementById("sv-f-start")?.value||"";
  const fSafe   = document.getElementById("sv-f-safe")?.value||"";

  const svcs = _servicesData.filter(s => {
    const info = s.info||{};
    if (fName   && !(s.DisplayName||"").toLowerCase().includes(fName) &&
                   !(s.Name||"").toLowerCase().includes(fName) &&
                   !(info.plain||"").toLowerCase().includes(fName)) return false;
    if (fWhat   && !(info.what||"").toLowerCase().includes(fWhat))   return false;
    if (fStatus && s.Status !== fStatus)     return false;
    if (fStart  && s.StartMode !== fStart)   return false;
    if (fSafe === "safe"     && info.safe_stop === false) return false;
    if (fSafe === "critical" && info.safe_stop !== false) return false;
    return true;
  });

  document.getElementById("sv-total").textContent    = _servicesData.length;
  document.getElementById("sv-running").textContent  = _servicesData.filter(s=>s.Status==="Running").length;
  document.getElementById("sv-stopped").textContent  = _servicesData.filter(s=>s.Status==="Stopped").length;
  document.getElementById("sv-disabled").textContent = _servicesData.filter(s=>s.StartMode==="Disabled").length;

  const activeFilters = [fName,fWhat,fStatus,fStart,fSafe].filter(Boolean).length;
  const countEl = document.getElementById("sv-filter-count");
  if (countEl) countEl.textContent = activeFilters ? `Showing ${svcs.length} of ${_servicesData.length}` : "";

  const statusColor = s => s==="Running"?"var(--cyan)":s==="Stopped"?"var(--muted)":"var(--red)";
  const startColor  = s => s==="Auto"?"var(--cyan)":s==="Disabled"?"var(--red)":"var(--muted)";

  const rows = svcs.map(s => {
    const info     = s.info||null;
    const plainName = info ? info.plain : s.DisplayName;
    const whatText  = info ? info.what  : (s.Description||"Looking up…");
    const safeStop  = info ? info.safe_stop : null;
    const safeEl    = safeStop === false
      ? "<span style='color:var(--red);font-size:11px'>&#10005; Critical</span>"
      : safeStop === true
      ? "<span style='color:var(--cyan);font-size:11px'>&#10003; Safe</span>"
      : "<span style='color:var(--muted);font-size:11px'>Looking up…</span>";
    const srcTag = info && info.source && info.source !== "static_kb"
      ? ` <span style='font-size:10px;color:#8a8aa0'>[${esc(info.source)}]</span>` : "";

    const running  = s.Status === "Running";
    const disabled = s.StartMode === "Disabled";
    const isCrit   = info && info.safe_stop === false;

    const stopBtn = running && !isCrit
      ? `<button onclick="svcAction('${esc(s.Name)}','stop')"
           style="background:#ff404022;border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Stop</button>` : "";
    const startBtn = !running
      ? `<button onclick="svcAction('${esc(s.Name)}','start')"
           style="background:#00d4ff22;border:1px solid var(--cyan);color:var(--cyan);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Start</button>` : "";
    const disableBtn = !disabled && !isCrit
      ? `<button onclick="svcAction('${esc(s.Name)}','disable')"
           style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Disable</button>` : "";
    const enableBtn = disabled
      ? `<button onclick="svcAction('${esc(s.Name)}','enable')"
           style="background:#00d4ff22;border:1px solid var(--cyan);color:var(--cyan);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px">Enable</button>` : "";

    return `<tr style="border-bottom:1px solid var(--border);vertical-align:top">
      <td style="padding:8px 10px">
        <div style="font-weight:600;font-size:13px">${esc(plainName)}${srcTag}</div>
        <div style="color:var(--muted);font-size:11px">${esc(s.Name)}</div>
      </td>
      <td style="padding:8px 10px;font-size:12px;max-width:280px">
        <div>${esc((whatText||"").substring(0,120))}${(whatText||"").length>120?"…":""}</div>
        ${info && info.reason ? `<div style="color:var(--muted);font-size:11px;font-style:italic">${esc(info.reason)}</div>` : ""}
      </td>
      <td style="padding:8px 10px;color:${statusColor(s.Status)};font-weight:600;white-space:nowrap">${esc(s.Status)}</td>
      <td style="padding:8px 10px;color:${startColor(s.StartMode)};white-space:nowrap">${esc(s.StartMode)}</td>
      <td style="padding:8px 10px;white-space:nowrap">${safeEl}</td>
      <td style="padding:8px 10px;white-space:nowrap">${stopBtn}${startBtn}${disableBtn}${enableBtn}</td>
    </tr>`;
  }).join("");

  document.getElementById("sv-tbody").innerHTML = rows ||
    "<tr><td colspan='6' style='padding:24px;text-align:center;color:var(--muted)'>No services match filter</td></tr>";
  document.getElementById("sv-loading").style.display = "none";
  document.getElementById("sv-content").style.display = "";
}

async function svcAction(name, action) {
  const labels = {stop:"Stop", start:"Start", disable:"Disable", enable:"Enable"};
  if (!confirm(`${labels[action]} service "${name}"?`)) return;
  const r = await fetch("/api/services/toggle", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({name, action})
  });
  const d = await r.json();
  if (d.ok) loadServices();
  else alert(`Action failed: ${d.error||"Unknown error"}`);
}

async function lookupUnknownServices() {
  if (!_servicesData) return;
  const unknowns = _servicesData.filter(s => !s.info || s.info.source === "unknown");
  if (!unknowns.length) { alert("All services already identified."); return; }
  const btn  = document.getElementById("btn-svc-lookup");
  const prog = document.getElementById("sv-lookup-progress");
  btn.disabled = true; btn.textContent = "Looking up…";
  prog.style.display = "";
  prog.textContent = `Queuing ${unknowns.length} services…`;
  const r = await fetch("/api/services/lookup-unknowns", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({services: unknowns})
  });
  const d = await r.json();
  prog.textContent = `${d.queued} queued…`;
  let attempts = 0;
  const poll = setInterval(async () => {
    attempts++;
    const sr = await fetch("/api/services/lookup-status");
    const sd = await sr.json();
    const left = sd.queue_pending + sd.in_flight;
    prog.textContent = left > 0 ? `Looking up… ${left} remaining` : "Done! Refreshing…";
    if (left === 0 || attempts >= 60) {
      clearInterval(poll);
      btn.disabled = false; btn.textContent = "🔍 Lookup All Unknowns";
      prog.style.display = "none";
      loadServices();
    }
  }, 2000);
}

function clearServiceFilters() {
  ["sv-f-name","sv-f-what","sv-f-status","sv-f-start","sv-f-safe"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  renderServices();
}


async function lookupUnknownProcesses() {
  if (!_processData) return;
  const unknowns = (_processData.processes||[]).filter(p =>
    !p.info || p.info.source === "unknown");
  if (!unknowns.length) { alert("All processes already identified."); return; }
  const btn  = document.getElementById("btn-proc-lookup");
  const prog = document.getElementById("proc-lookup-progress");
  btn.disabled = true; btn.textContent = "Looking up…";
  prog.style.display = "";
  prog.textContent = `Queuing ${unknowns.length} processes…`;
  const r = await fetch("/api/processes/lookup-unknowns", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({processes: unknowns})
  });
  const d = await r.json();
  prog.textContent = `${d.queued} queued…`;
  let attempts = 0;
  const poll = setInterval(async () => {
    attempts++;
    const sr = await fetch("/api/processes/lookup-status");
    const sd = await sr.json();
    const left = sd.queue_pending + sd.in_flight;
    prog.textContent = left > 0 ? `Looking up… ${left} remaining` : "Done! Refreshing…";
    if (left === 0 || attempts >= 60) {
      clearInterval(poll);
      btn.disabled = false; btn.textContent = "🔍 Lookup All Unknowns";
      prog.style.display = "none";
      loadProcesses();
    }
  }, 2000);
}


// ══════════════════════════════════════════════════════════════════════════
// HEALTH HISTORY
// ══════════════════════════════════════════════════════════════════════════
let _hhChart = null;

async function loadHealthHistory() {
  try {
    document.getElementById("hh-loading").style.display = "block";
    document.getElementById("hh-content").style.display = "none";
    const r = await fetch("/api/health-history/data");
    const d = await r.json();
    renderHealthHistory(d);
    fetchSummary("health-history", d, "summary-health-history");
  } catch(e) {
    console.error("Failed to load health history:", e);
  }
}

function renderHealthHistory(d) {
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const reports = d.reports || [];
  document.getElementById("hh-total").textContent   = d.total || 0;
  document.getElementById("hh-avg").textContent     = d.avg_score != null ? d.avg_score + "/100" : "—";
  document.getElementById("hh-bsod").textContent    = reports.filter(r=>r.bsod_count>0).length;
  document.getElementById("hh-latest").textContent  = d.latest?.score != null ? d.latest.score + "/100" : "—";

  if (d.error) {
    document.getElementById("hh-loading").innerHTML =
      `<div style="color:var(--orange);padding:20px">${esc(d.error)}</div>`;
    return;
  }

  // Staleness warning banner
  const staleBanner = document.getElementById("hh-stale-banner");
  if (d.stale) {
    staleBanner.innerHTML = `<span style="color:var(--orange);font-weight:600">⚠ Reports are stale</span> — last report was ${d.stale_days} day(s) ago. Check that the SystemHealthDiag scheduled task is running.`;
    staleBanner.style.display = "block";
  } else {
    staleBanner.style.display = "none";
  }

  // Chart
  const labels = reports.map(r => r.date_label);
  const scores = reports.map(r => r.score);
  const bsods  = reports.map(r => r.bsod_count);
  if (_hhChart) _hhChart.destroy();
  const ctx = document.getElementById("hh-chart").getContext("2d");
  _hhChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Health Score", data: scores, borderColor: "#00d4ff", backgroundColor: "#00d4ff18",
          tension: 0.3, fill: true, pointRadius: 3, spanGaps: true },
        { label: "BSOD Events", data: bsods, borderColor: "#ff4560", backgroundColor: "transparent",
          tension: 0, yAxisID: "y2", pointRadius: 4, pointStyle: "triangle" }
      ]
    },
    options: {
      responsive: true, interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: "#aaa" } } },
      scales: {
        x:  { ticks: { color: "#666", maxTicksLimit: 20 }, grid: { color: "#ffffff08" } },
        y:  { min: 0, max: 100, ticks: { color: "#aaa" }, grid: { color: "#ffffff08" },
              title: { display: true, text: "Score", color: "#666" } },
        y2: { position: "right", min: 0, ticks: { color: "#ff4560", stepSize: 1 },
              grid: { display: false }, title: { display: true, text: "BSODs", color: "#ff4560" } }
      }
    }
  });

  // Table
  const statusColor = s => s==="critical"?"var(--red)":s==="warning"?"var(--orange)":"var(--cyan)";
  const rows = [...reports].reverse().map(r =>
    `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px">${esc(r.date_label)}</td>
      <td style="padding:6px 10px;text-align:center;font-weight:700;color:${r.score>=80?"var(--cyan)":r.score>=60?"var(--orange)":"var(--red)"}">${r.score!=null?r.score:"-"}</td>
      <td style="padding:6px 10px;text-align:center;color:${r.bsod_count>0?"var(--red)":"var(--muted)"}">${r.bsod_count||0}</td>
      <td style="padding:6px 10px;text-align:center;color:${r.whea_count>0?"var(--orange)":"var(--muted)"}">${r.whea_count||0}</td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${esc((r.sys_files||[]).slice(0,3).join(", "))}</td>
      <td style="padding:6px 10px;color:${statusColor(r.status)};font-size:11px;font-weight:700">${esc(r.status)}</td>
    </tr>`
  ).join("");
  document.getElementById("hh-tbody").innerHTML = rows ||
    `<tr><td colspan="6" style="padding:20px;color:var(--muted);text-align:center">No reports found in ${esc(d.report_dir||"")}</td></tr>`;

  document.getElementById("hh-loading").style.display = "none";
  document.getElementById("hh-content").style.display = "";
}

// ══════════════════════════════════════════════════════════════════════════
// SYSTEM TIMELINE
// ══════════════════════════════════════════════════════════════════════════
let _tlData = null;

async function loadTimeline() {
  try {
    document.getElementById("tl-loading").style.display = "block";
    document.getElementById("tl-content").style.display = "none";
    const days = document.getElementById("tl-days")?.value || 30;
    const r = await fetch(`/api/timeline/data?days=${days}`);
    _tlData = await r.json();
    renderTimeline();
    fetchSummary("timeline", _tlData, "summary-timeline");
  } catch(e) {
    console.error("Failed to load timeline:", e);
  }
}

function renderTimeline() {
  if (!_tlData) return;
  const esc    = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const filter = document.getElementById("tl-filter")?.value || "";
  const events = (_tlData.events||[]).filter(e => !filter || e.type === filter);

  document.getElementById("tl-crashes").textContent  = (_tlData.events||[]).filter(e=>e.type==="bsod").length;
  document.getElementById("tl-updates").textContent  = (_tlData.events||[]).filter(e=>e.type==="update"||e.type==="driver_install").length;
  document.getElementById("tl-near").textContent     = (_tlData.events||[]).filter(e=>e.crash_correlation?.classification==="likely_cause"||e.crash_correlation?.classification==="possible_cause").length;
  document.getElementById("tl-reboots").textContent  = (_tlData.events||[]).filter(e=>e.type==="reboot").length;
  const tlCredEl = document.getElementById("tl-credfails");
  if (tlCredEl) tlCredEl.textContent = (_tlData.events||[]).filter(e=>e.type==="cred_failure").length;

  const catColor = t => ({bsod:"var(--red)",update:"var(--cyan)",driver_install:"var(--orange)",
                          service_change:"#8888aa",reboot:"#6688aa",
                          cred_failure:"var(--orange)",cred_use:"#8888aa"})[t] || "var(--muted)";
  const catBg    = t => ({bsod:"#ff405018",update:"#00d4ff10",driver_install:"#ff704318",
                          service_change:"#88888810",reboot:"#66888810",
                          cred_failure:"#ff704318",cred_use:"#88888810"})[t] || "";

  // Group by date
  const byDate = {};
  events.forEach(e => {
    const d = new Date(e.ts).toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"});
    if (!byDate[d]) byDate[d] = [];
    byDate[d].push(e);
  });

  const html = Object.entries(byDate).map(([date, evts]) =>
    `<div style="margin-bottom:4px">
      <div style="font-size:11px;font-weight:700;color:var(--muted);padding:10px 12px 4px;letter-spacing:.08em;text-transform:uppercase">${esc(date)}</div>
      ${evts.map(e => {
        const time = new Date(e.ts).toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
        const corr = e.crash_correlation || {};
        const nearCrash = corr.has_correlation
          ? `<span style="margin-left:8px;font-size:10px;background:${corr.classification==='likely_cause'?'#ff405033':'#ff8c0033'};color:${corr.classification==='likely_cause'?'var(--red)':'var(--orange)'};padding:2px 7px;border-radius:10px;font-weight:700">${corr.classification==='likely_cause'?'🔴':'🟡'} ${corr.confidence}% — crash ${e.crash_gap_h}h later</span>` : "";
        return `<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border-left:3px solid ${catColor(e.type)};background:${catBg(e.type)};margin-bottom:2px">
          <span style="font-size:16px;flex-shrink:0">${esc(e.icon||"•")}</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600">${esc(e.title)}${nearCrash}</div>
            ${e.detail ? `<div style="font-size:11px;color:var(--muted)">${esc(e.detail)}</div>` : ""}
          </div>
          <div style="font-size:11px;color:var(--muted);white-space:nowrap;flex-shrink:0">${time}</div>
        </div>`;
      }).join("")}
    </div>`
  ).join("");

  document.getElementById("tl-events").innerHTML = html ||
    `<div style="padding:40px;text-align:center;color:var(--muted)">No events found for selected period / filter.</div>`;
  document.getElementById("tl-loading").style.display = "none";
  document.getElementById("tl-content").style.display = "";
}

// ══════════════════════════════════════════════════════════════════════════
// MEMORY ANALYSIS
// ══════════════════════════════════════════════════════════════════════════
let _memChart = null;

// System-process glossary (backlog #36). Fetched once per page load and
// cached; the Memory tab renderer looks up process names to decide whether
// to show an info icon and whether to hide the Kill button.
let _processGlossary = null;
async function _loadProcessGlossary() {
  if (_processGlossary !== null) return _processGlossary;
  try {
    const r = await fetch("/api/processes/glossary");
    const d = await r.json();
    _processGlossary = (d && d.glossary) ? d.glossary : {};
  } catch (e) {
    console.warn("Glossary fetch failed (non-fatal):", e);
    _processGlossary = {};  // empty -> no tooltips, no button hiding — safe fallback
  }
  return _processGlossary;
}

// Normalise psutil process names for glossary lookup: lowercase + strip .exe.
// The glossary keys are stored without the suffix; psutil returns names
// inconsistently (MemCompression has no .exe, csrss.exe does).
function _glossaryKey(name) {
  const s = String(name || "").toLowerCase();
  return s.endsWith(".exe") ? s.slice(0, -4) : s;
}

async function loadMemory() {
  try {
    document.getElementById("mem-loading").style.display = "block";
    document.getElementById("mem-content").style.display = "none";
    await _loadProcessGlossary();
    const r = await fetch("/api/memory/data");
    const d = await r.json();
    renderMemory(d);
    fetchSummary("memory", d, "summary-memory");
  } catch(e) {
    console.error("Failed to load memory:", e);
  }
}

function renderMemory(d) {
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const total = d.total_mb||32768, used = d.used_mb||0, free = d.free_mb||0;
  document.getElementById("mem-total").textContent  = (total/1024).toFixed(1) + " GB";
  document.getElementById("mem-used").textContent   = used.toLocaleString() + " MB";
  document.getElementById("mem-free").textContent   = free.toLocaleString() + " MB";
  document.getElementById("mem-mcafee").textContent = d.has_mcafee ? (d.mcafee_mb||0) + " MB" : "—";

  // Category chart
  const cats  = d.categories || {};
  const catNames = { security:"Security/AV", browser:"Browsers", microsoft:"Windows/System",
                     office:"Office", comms:"Comms", gpu_driver:"GPU Driver",
                     this_app:"This App", games:"Games", cloud:"Cloud Sync", other:"Other" };
  const catColors = ["#ff4560","#00d4ff","#4488ff","#ff7043","#aa44ff",
                     "#44ddaa","#ffaa00","#ff44aa","#44aaff","#888888"];
  const labels = [], values = [], colors = [];
  Object.entries(cats).forEach(([k,v],i) => {
    if (v > 10) { labels.push(catNames[k]||k); values.push(v); colors.push(catColors[i%catColors.length]); }
  });
  if (_memChart) _memChart.destroy();
  const ctx = document.getElementById("mem-chart").getContext("2d");
  _memChart = new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: "#1a1f2e", borderWidth: 2 }] },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "right", labels: { color: "#aaa", font: { size: 11 },
          generateLabels: (chart) => chart.data.labels.map((l,i) => ({
            text: `${l}: ${values[i].toLocaleString()} MB`,
            fillStyle: colors[i], strokeStyle: colors[i], lineWidth: 0,
            fontColor: "#ccc"
          }))
        }},
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw.toLocaleString()} MB` } }
      }
    }
  });

  // McAfee vs Defender comparison
  if (d.has_mcafee) {
    const saving = d.mcafee_saving_mb || 0;
    const mcMB   = d.mcafee_mb || 0;
    const defMB  = d.defender_baseline || 150;
    // Per-vendor breakdown so the total reconciles against the process
    // table — 2026-04-11 bug: user saw McAfee total != mc-fw-host row
    // and couldn't tell where the delta came from. This makes the math
    // auditable by showing every contributing process on hover.
    const mcProcs = d.mcafee_processes || [];
    const mcTooltip = mcProcs.length
      ? `Reconciliation (${mcProcs.length} McAfee processes):\n` +
        mcProcs.map(p => `  ${p.name}: ${p.mem.toLocaleString()} MB`).join("\n") +
        `\n  ─────\n  Total: ${mcMB.toLocaleString()} MB\n\n${d.accounting_note || ""}`
      : "";
    const mcBreakdownHTML = mcProcs.length
      ? `<div style="margin-top:6px;font-size:11px;color:var(--muted);font-family:var(--font-mono)">
          <details><summary style="cursor:pointer;color:var(--muted)">▸ Reconciliation (${mcProcs.length} processes)</summary>
            <div style="margin-top:6px;padding:8px 10px;background:#ffffff06;border-radius:4px">
              ${mcProcs.map(p => `<div style="display:flex;justify-content:space-between"><span>${esc(p.name)}</span><span>${p.mem.toLocaleString()} MB</span></div>`).join("")}
              <div style="margin-top:4px;padding-top:4px;border-top:1px dashed var(--border);display:flex;justify-content:space-between;font-weight:700">
                <span>Total</span><span>${mcMB.toLocaleString()} MB</span>
              </div>
              <div style="margin-top:6px;font-size:10px;color:var(--text-dim);line-height:1.4">${esc(d.accounting_note || "")}</div>
            </div>
          </details>
        </div>`
      : "";
    document.getElementById("mem-comparison").innerHTML = `
      <div style="margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:13px;font-weight:600">McAfee (current)</span>
          <span style="color:var(--red);font-weight:700" title="${esc(mcTooltip)}">${mcMB.toLocaleString()} MB</span>
        </div>
        <div style="background:#ffffff11;border-radius:4px;height:12px">
          <div style="background:var(--red);height:100%;border-radius:4px;width:${Math.min(100,mcMB/total*100*5).toFixed(0)}%"></div>
        </div>
        ${mcBreakdownHTML}
      </div>
      <div style="margin-bottom:20px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:13px;font-weight:600">Windows Defender (estimated)</span>
          <span style="color:var(--cyan);font-weight:700">~${defMB} MB</span>
        </div>
        <div style="background:#ffffff11;border-radius:4px;height:12px">
          <div style="background:var(--cyan);height:100%;border-radius:4px;width:${Math.min(100,defMB/total*100*5).toFixed(0)}%"></div>
        </div>
      </div>
      <div style="background:#00d4ff18;border:1px solid var(--cyan);border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--cyan)">${saving.toLocaleString()} MB</div>
        <div style="font-size:12px;color:var(--muted)">RAM you could recover by switching to Defender</div>
        <div style="font-size:11px;color:var(--muted);margin-top:4px">≈ ${(saving/1024).toFixed(1)} GB freed up</div>
      </div>`;
  } else {
    document.getElementById("mem-comparison").innerHTML =
      `<div style="color:var(--muted);font-size:13px;padding:12px">McAfee not detected — using Windows Defender or another AV.</div>`;
  }

  // 'Other' bucket audit (backlog #21). When unclassified processes cross
  // 5 % of total RAM, show the top 3 so we know what to add to the
  // vendor classifier.
  const auditEl = document.getElementById("mem-other-audit");
  if (auditEl) {
    const needsAudit = d.other_needs_audit;
    const otherTop = d.other_top_unclassified || [];
    if (needsAudit && otherTop.length) {
      const pct = d.other_pct || 0;
      const rowsHtml = otherTop.map(p =>
        `<div style="display:flex;justify-content:space-between;padding:4px 10px;font-family:var(--font-mono);font-size:12px"><span style="color:var(--text)">${esc(p.name)}</span><span style="color:var(--muted)">${p.mem.toLocaleString()} MB</span></div>`
      ).join("");
      auditEl.style.display = "";
      auditEl.innerHTML = `
        <div style="padding:14px 18px;background:var(--card);border:1px solid var(--border);border-left:4px solid var(--orange);border-radius:10px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div style="font-weight:700;font-size:13px;color:var(--orange)">⚠ 'Other' bucket is ${pct}% of RAM — classifier could use more entries</div>
            <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">audit</span>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-bottom:8px">
            Top unclassified processes (add to <code>MEM_CATEGORIES</code> in <code>windesktopmgr.py</code> so they bucket correctly):
          </div>
          ${rowsHtml}
        </div>`;
    } else {
      auditEl.style.display = "none";
      auditEl.innerHTML = "";
    }
  }

  // Top processes table (backlog #35 + #36 adds action buttons + glossary tooltips)
  const maxMem = (d.top_procs||[])[0]?.mem || 1;
  const catBadgeColor = c => ({security:"var(--red)",browser:"var(--cyan)",comms:"var(--orange)",
                               microsoft:"#4488ff",other:"#888"})[c] || "#888";
  const glossary = _processGlossary || {};
  // Action button style reused from the dashboard memory-concern buttons
  const actBtn = "padding:4px 8px;border-radius:5px;cursor:pointer;font-size:10px;font-weight:700;" +
                 "white-space:nowrap;background:transparent;border:1px solid var(--border);color:var(--muted);" +
                 "font-family:var(--font-mono)";
  const rows = (d.top_procs||[]).map(p => {
    const pid = p.pid || 0;
    const pname = esc(p.name);
    const key = _glossaryKey(p.name);
    const gloss = glossary[key];
    // Info icon: shown only when we have a glossary entry for this name.
    // Native title= tooltip is universally supported, accessible, and zero-JS.
    const infoIcon = gloss
      ? `<span title="${esc(gloss.title)} — ${esc(gloss.explanation)}" style="display:inline-block;margin-left:6px;cursor:help;color:var(--cyan);font-size:11px;user-select:none" aria-label="What is ${pname}?">ⓘ</span>`
      : "";
    // Protected processes show a 🛡 badge instead of Kill. Same tooltip
    // explains WHY it's protected so the user learns rather than being stonewalled.
    const protectedBadge = gloss && gloss.protected
      ? `<span title="Protected — ${esc(gloss.title)}: ${esc(gloss.explanation)}" style="font-size:10px;color:var(--muted);border:1px solid var(--border);padding:2px 8px;border-radius:5px;cursor:help">🛡 Protected</span>`
      : "";
    // When not protected, render the 3-button action group (Kill / Investigate / Snooze).
    // No PID -> no Investigate/Kill, just Snooze by name.
    const actions = gloss && gloss.protected
      ? protectedBadge
      : pid
        ? `<button data-mem-act="investigate" data-pid="${pid}" data-pname="${pname}" title="Filter Process Monitor to this PID" style="${actBtn}">🔍</button>
           <button data-mem-act="kill"        data-pid="${pid}" data-pname="${pname}" title="Kill this process (with confirmation)" style="${actBtn}">🔪</button>
           <button data-mem-act="snooze"                       data-pname="${pname}" title="Suppress this process's warnings for 24 h" style="${actBtn}">⏳</button>`
        : `<button data-mem-act="snooze" data-pname="${pname}" title="Suppress warnings for this process name (PID unknown)" style="${actBtn}">⏳</button>`;
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-weight:600">${pname}${infoIcon}</td>
      <td style="padding:6px 10px"><span style="font-size:10px;color:${catBadgeColor(p.category)};border:1px solid currentColor;padding:1px 6px;border-radius:8px">${esc(catNames[p.category]||p.category)}</span></td>
      <td style="padding:6px 10px;text-align:right;font-weight:700;color:${p.mem>1500?"var(--red)":p.mem>500?"var(--orange)":"var(--text)"}">${p.mem.toLocaleString()}</td>
      <td style="padding:6px 10px;width:200px">
        <div style="background:#ffffff11;border-radius:3px;height:6px">
          <div style="background:${p.mem>1500?"var(--red)":p.mem>500?"var(--orange)":"var(--cyan)"};height:100%;border-radius:3px;width:${Math.min(100,p.mem/maxMem*100).toFixed(0)}%"></div>
        </div>
      </td>
      <td style="padding:6px 10px;white-space:nowrap;text-align:right">${actions}</td>
    </tr>`;
  }).join("");
  const tbody = document.getElementById("mem-tbody");
  tbody.innerHTML = rows;
  // Wire the action buttons via the same helpers the dashboard concerns use
  // (backlog #19). Event delegation would also work, but per-button listeners
  // match the pattern in renderDashboard so the code stays consistent.
  tbody.querySelectorAll("button[data-mem-act]").forEach(btn => {
    btn.addEventListener("click", () => {
      const act   = btn.dataset.memAct;
      const pid   = parseInt(btn.dataset.pid, 10) || 0;
      const pname = btn.dataset.pname || "";
      if (act === "investigate") investigateProcess(pid, pname);
      else if (act === "kill")   killProcessFromConcern(pid, pname);
      else if (act === "snooze") snoozeMemoryConcern(pname);
    });
  });

  document.getElementById("mem-loading").style.display = "none";
  document.getElementById("mem-content").style.display = "";
}

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
    const esc = s => String(s == null ? "—" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;");
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
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const cur  = d.current || {};
  const upd  = d.update  || {};

  document.getElementById("bios-version").textContent = esc(cur.BIOSVersion||"—");
  document.getElementById("bios-date").textContent    = esc(cur.BIOSDateFormatted||"—");
  document.getElementById("bios-latest").textContent  = esc(upd.latest_version||"—");

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

// ══════════════════════════════════════════════════════════════════════════
// WARRANTY READINESS
// ══════════════════════════════════════════════════════════════════════════
async function loadWarrantyData() {
  const panel = document.getElementById("warranty-panel");
  const loading = document.getElementById("warranty-loading");
  const content = document.getElementById("warranty-content");
  loading.style.display = "block";
  content.style.display = "none";
  panel.style.display = "block";
  try {
    const r = await fetch("/api/warranty/data");
    const d = await r.json();
    if (d.status !== "ok") throw new Error(d.message || "Failed");
    renderWarranty(d.warranty);
  } catch (e) {
    loading.innerHTML = `<span style="color:var(--red)">Failed to load warranty data: ${e.message}</span>`;
  }
}

function renderWarranty(w) {
  const esc = s => String(s||"—").replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const grid = document.getElementById("warranty-grid");
  const statColor = (v, threshold=0) => v > threshold ? "var(--red)" : "var(--green)";

  const fields = [
    ["CPU Model", w.CPUModel, "var(--text)"],
    ["CPU ID", w.CPUSerial, "var(--cyan)"],
    ["Microcode", w.MicrocodeVersion, "var(--cyan)"],
    ["BIOS", `${w.BIOSVersion} (${w.BIOSDate})`, "var(--text)"],
    ["Dell Service Tag", w.DellServiceTag, "var(--cyan)"],
    ["Affected CPU", w.IsAffectedCPU ? "YES" : "No", w.IsAffectedCPU ? "var(--orange)" : "var(--green)"],
    ["BSODs (30 days)", w.BSODs30Days, statColor(w.BSODs30Days)],
    ["WHEA Errors", w.WHEAErrors, statColor(w.WHEAErrors)],
    ["Unexpected Shutdowns", w.UnexpectedShutdowns, statColor(w.UnexpectedShutdowns)],
  ];

  grid.innerHTML = fields.map(([label, value, color]) => `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px">
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px">${label}</div>
      <div style="font-size:13px;font-weight:600;color:${color};word-break:break-all">${esc(value)}</div>
    </div>`).join("");

  // Evidence summary
  const lines = [];
  lines.push(`System: ${w.Manufacturer} ${w.Model}`);
  lines.push(`CPU: ${w.CPUModel}`);
  lines.push(`CPU ID: ${w.CPUSerial}`);
  lines.push(`BIOS: ${w.BIOSVersion} (${w.BIOSDate})`);
  lines.push(`Microcode: ${w.MicrocodeVersion}`);
  if (w.DellServiceTag !== "N/A") lines.push(`Dell Service Tag: ${w.DellServiceTag}`);
  lines.push(`BSODs in last 30 days: ${w.BSODs30Days}`);
  lines.push(`WHEA hardware errors: ${w.WHEAErrors}`);
  lines.push(`Unexpected shutdowns: ${w.UnexpectedShutdowns}`);
  lines.push("");
  lines.push("This system exhibits symptoms consistent with the known Intel 13th/14th Gen");
  lines.push("desktop processor voltage instability issue (eTVB/SVID). Requesting warranty");
  lines.push("evaluation and potential CPU replacement under Intel's extended warranty program.");

  document.getElementById("warranty-evidence-text").textContent = lines.join("\n");

  // Links
  document.getElementById("warranty-intel-link").href = w.IntelWarrantyURL;
  document.getElementById("warranty-dell-link").href = w.DellSupportURL;
  if (w.DellServiceTag !== "N/A") {
    document.getElementById("warranty-dell-link").textContent = "🔗 Dell Support (Your Service Tag)";
  }

  document.getElementById("warranty-loading").style.display = "none";
  document.getElementById("warranty-content").style.display = "block";
}

// Auto-load warranty data when BIOS tab loads
const origLoadBios = loadBios;
loadBios = async function() {
  await origLoadBios();
  loadWarrantyData();
};


// ══════════════════════════════════════════════════════════════════════════
// CREDENTIALS & NETWORK HEALTH
// ══════════════════════════════════════════════════════════════════════════
let _credData = null;
let _dashConcerns = [];

async function loadCredentials() {
  try {
    document.getElementById("cr-loading").style.display = "block";
    document.getElementById("cr-content").style.display = "none";
    const r = await fetch("/api/credentials/health");
    _credData = await r.json();
    renderCredentials(_credData);
    fetchSummary("credentials", _credData, "summary-credentials");
  } catch(e) {
    console.error("Failed to load credentials:", e);
  }
}

function renderCredentials(d) {
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");

  // OneDrive stat cards
  const odStatusEl = document.getElementById("cr-od-status");
  const tokenAgeEl = document.getElementById("cr-token-age");
  if (d.msal_token_stale) {
    odStatusEl.innerHTML = `<span style="color:var(--red);font-weight:700">EXPIRED</span>`;
    tokenAgeEl.innerHTML = `<span style="color:var(--red)">${d.msal_token_age_h?.toFixed(0) || "?"}h old</span>`;
  } else if (d.onedrive_connected) {
    odStatusEl.innerHTML = `<span style="color:var(--cyan)">Connected</span>`;
    tokenAgeEl.innerHTML = d.msal_token_age_h != null
      ? `<span style="color:var(--cyan)">${d.msal_token_age_h.toFixed(0)}h ago</span>`
      : `<span style="color:var(--muted)">—</span>`;
  } else {
    odStatusEl.innerHTML = `<span style="color:var(--orange)">Not signed in</span>`;
    tokenAgeEl.innerHTML = `<span style="color:var(--muted)">—</span>`;
  }
  document.getElementById("cr-drives-down").textContent = (d.drives_down||[]).length;

  // OneDrive detail card
  const odCard = document.getElementById("cr-od-card");
  const odDetail = document.getElementById("cr-od-detail");
  if (d.onedrive_suspended) {
    odCard.style.borderColor = "var(--red)";
    odDetail.innerHTML = `
      <div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:14px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:8px">⚠ OneDrive is SUSPENDED by Windows</div>
        <div style="color:var(--muted);line-height:1.6;margin-bottom:10px">
          This is the confirmed root cause of your Word and Outlook sign-in errors.
          Windows suspended OneDrive to free memory (likely due to high RAM usage from other processes).
          When OneDrive is suspended it cannot refresh Microsoft 365 OAuth tokens.
        </div>
        <button onclick="resumeOneDrive()"
          style="background:var(--red);color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700">
          ▶ Resume OneDrive Now
        </button>
      </div>`;
  } else if (d.msal_token_stale) {
    odCard.style.borderColor = "var(--red)";
    odDetail.innerHTML = `
      <div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:14px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:8px">⚠ This is your Word / Outlook sign-in error</div>
        <div style="color:var(--muted);line-height:1.6;margin-bottom:10px">
          The Microsoft 365 authentication token in Windows is <strong style="color:var(--red)">${d.msal_token_age_h?.toFixed(0) || "?"} hours old</strong>.
          When this token expires, Word shows "Sign in Required — cached credentials have expired"
          and Outlook loses access to accounts using Modern Authentication (OAuth).
        </div>
        <div style="color:var(--text);font-weight:600;margin-bottom:6px">How to fix it:</div>
        <div style="color:var(--muted);line-height:1.8;font-size:11px">
          1. Click the OneDrive cloud icon in the taskbar system tray<br>
          2. Click Sign in and complete authentication<br>
          3. Open Word or Outlook — the sign-in prompt should clear automatically<br>
          4. If it persists: File &gt; Office Account &gt; Sign Out, then Sign In again
        </div>
      </div>`;
  } else if (!d.onedrive_connected) {
    odCard.style.borderColor = "var(--orange)";
    odDetail.innerHTML = `<div style="color:var(--orange);font-size:13px;padding:8px 0">
      OneDrive is not signed in. Office apps may show sign-in prompts.<br>
      <span style="color:var(--muted);font-size:11px">Click the OneDrive icon in the system tray to sign in.</span></div>`;
  } else {
    odCard.style.borderColor = "";
    const acct = d.onedrive_account ? `<div style="color:var(--muted);font-size:11px;margin-top:4px">${esc(d.onedrive_account)}</div>` : "";
    const age  = d.msal_token_age_h != null
      ? `<div style="color:var(--muted);font-size:11px;margin-top:4px">Token refreshed ${d.msal_token_age_h.toFixed(0)}h ago · ${d.msal_cache_files || 0} cache files · ${d.msal_cache_size_kb || 0} KB</div>`
      : "";
    const officeCreds = (d.office_creds||[]).length;
    odDetail.innerHTML = `
      <div style="color:var(--cyan);font-weight:700;font-size:13px;margin-bottom:4px">✓ Connected${d.onedrive_running ? " and running" : ""}</div>
      ${acct}${age}
      ${officeCreds ? `<div style="color:var(--muted);font-size:11px;margin-top:6px">${officeCreds} Office credential(s) in Credential Manager</div>` : ""}`;
  }

  const fastEl  = document.getElementById("cr-fast");
  const fastCard = document.getElementById("cr-fast-card");
  const fixBtn   = document.getElementById("cr-fix-btn");
  const fast = d.fast_startup;
  const fastDetailEl = document.getElementById("cr-fast-detail");
  if (fast === true) {
    fastEl.innerHTML = `<span style="color:var(--red);font-weight:700">ON</span>`;
    fastCard.style.borderColor = "var(--red)";
    fixBtn.style.display = "";
    fastDetailEl.innerHTML =
      `<div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:12px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:6px">⚠ Fast Startup is ON</div>
        <div style="color:var(--muted);line-height:1.5;margin-bottom:10px">
          Windows does not fully shut down. Network credentials and SMB connections are stored
          in a hibernation file and often fail to restore correctly on the next boot — the most
          common cause of NAS drive loss after reboot.
        </div>
        <span id="cr-fast-toggle-msg" style="font-size:11px;color:var(--muted);margin-left:10px"></span>
      </div>`;
    const actionsEl2 = document.getElementById("cr-fast-actions");
    if (actionsEl2) {
      actionsEl2.innerHTML = "";
      const btn2 = document.createElement("button");
      btn2.textContent = "⚡ Disable Fast Startup";
      btn2.style.cssText = "background:var(--red);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700";
      btn2.addEventListener("click", () => toggleFastStartup(false));
      actionsEl2.appendChild(btn2);
    }
  } else if (fast === false) {
    fastEl.innerHTML = `<span style="color:var(--cyan);font-weight:700">OFF</span>`;
    fastCard.style.borderColor = "";
    fastDetailEl.innerHTML =
      `<div style="color:var(--cyan);font-size:13px">✓ Fast Startup is disabled. Full shutdown/restart cycle is in effect.</div>
       <span id="cr-fast-toggle-msg" style="font-size:11px;color:var(--muted);display:block;margin-top:6px"></span>`;
    const actionsEl = document.getElementById("cr-fast-actions");
    if (actionsEl) {
      actionsEl.innerHTML = "";
      const btn = document.createElement("button");
      btn.textContent = "Enable Fast Startup";
      btn.style.cssText = "background:#00d4ff18;border:1px solid var(--cyan);color:var(--cyan);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600";
      btn.addEventListener("click", () => toggleFastStartup(true));
      actionsEl.appendChild(btn);
    }
  } else {
    fastEl.textContent = "—";
    fastDetailEl.innerHTML =
      `<div style="color:var(--muted);font-size:12px">Could not determine Fast Startup state.</div>`;
  }

  // SMB / CIFS / NFS drives
  const drives = d.drives || [];
  const protoBadge = p => {
    const col = p==="NFS"?"var(--purple)":p==="SMB/CIFS"?"var(--cyan)":"var(--muted)";
    return `<span style="font-size:9px;border:1px solid ${col};color:${col};padding:1px 5px;border-radius:4px;margin-left:6px">${esc(p)}</span>`;
  };
  const drivesHtml = drives.length ? `
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="color:var(--muted);border-bottom:1px solid var(--border)">
        <th style="padding:5px 8px;text-align:left">Drive</th>
        <th style="padding:5px 8px;text-align:left">Share Path</th>
        <th style="padding:5px 8px;text-align:left">Protocol</th>
        <th style="padding:5px 8px;text-align:center">Port</th>
        <th style="padding:5px 8px;text-align:left">Dialect</th>
        <th style="padding:5px 8px;text-align:left">Status</th>
      </tr></thead><tbody>` +
    drives.map(drv => {
      const ok      = drv.Reachable;
      const proto   = drv.Protocol || "SMB/CIFS";
      const port    = drv.Port || (proto === "NFS" ? 2049 : 445);
      const dialect = drv.Dialect || "";
      const portCol = proto==="NFS"?"var(--purple)":"var(--cyan)";
      const dialectLabel = dialect
        ? `<span style="font-size:10px;color:var(--cyan);border:1px solid #00d4ff33;padding:1px 6px;border-radius:4px">${esc(dialect)}</span>`
        : `<span style="font-size:10px;color:var(--muted)">—</span>`;
      return `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:6px 8px;font-weight:700">${esc(drv.Name)}:\</td>
        <td style="padding:6px 8px;color:var(--muted);font-size:11px">${esc(drv.DisplayRoot||drv.Root||"")}</td>
        <td style="padding:6px 8px">${protoBadge(proto)}</td>
        <td style="padding:6px 8px;text-align:center">
          <span style="font-size:11px;font-weight:700;color:${portCol}">${port}</span>
        </td>
        <td style="padding:6px 8px">${dialectLabel}</td>
        <td style="padding:6px 8px;color:${ok?"var(--cyan)":"var(--red)"};font-weight:700;white-space:nowrap">${ok?"✓ Reachable":"✗ UNREACHABLE"}</td>
      </tr>`;
    }).join("") + `</tbody></table>` :
    `<div style="color:var(--muted);font-size:12px">No mapped SMB/CIFS/NFS drives found.</div>`;
  document.getElementById("cr-drives-detail").innerHTML = drivesHtml;

  // Email credentials
  const emailCreds = d.email_creds || [];
  const emailHtml = emailCreds.length ? emailCreds.map(c =>
    `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
      <div style="font-size:12px;font-weight:600">${esc(c.Target||"")}</div>
      <div style="font-size:10px;color:var(--muted)">${esc(c.User||"")} &nbsp;·&nbsp; ${esc(c.Type||"")}</div>
    </div>`
  ).join("") :
  `<div style="color:var(--orange);font-size:12px;padding:10px 0">
    No email credentials found in Credential Manager.<br>
    <span style="color:var(--muted);font-size:11px">Outlook may be managing tokens separately via MSAL cache, or they were cleared on last reboot.</span>
  </div>`;
  document.getElementById("cr-email-detail").innerHTML = emailHtml;

  // Firewall rules
  const fw = d.fw_rules || [];
  const fwHtml = fw.length ? fw.slice(0,8).map(f =>
    `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px">
      <span style="color:var(--text)">${esc(f.DisplayName||"")}</span>
      <span style="color:${f.Action==="Block"?"var(--red)":f.Enabled?"var(--cyan)":"var(--muted)"};font-weight:700">${esc(f.Action||"")} ${f.Enabled?"":"(disabled)"}</span>
    </div>`
  ).join("") :
  `<div style="color:var(--muted);font-size:12px">No file sharing firewall rules found. McAfee may be managing these separately.</div>`;
  document.getElementById("cr-fw-detail").innerHTML = fwHtml;

  // All credentials table
  const creds = d.creds || [];
  const credRows = creds.map(c => {
    const isEmail = (d.email_creds||[]).some(e => e.Target === c.Target);
    const nasHosts = ["shigs78nas","shigs78nas2","nas","synology","qnap"];
    const isNas   = (d.nas_creds||[]).some(e => e.Target === c.Target) ||
                    nasHosts.some(h => (c.Target||"").toLowerCase().includes(h));
    const badge   = isEmail ? `<span style="font-size:9px;background:#00d4ff22;color:var(--cyan);padding:1px 6px;border-radius:8px;margin-left:6px">email</span>`
                  : isNas   ? `<span style="font-size:9px;background:#b388ff22;color:var(--purple);padding:1px 6px;border-radius:8px;margin-left:6px">NAS</span>`
                  : "";
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-size:12px">${esc(c.Target||"")}${badge}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--muted)">${esc(c.User||"")}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--muted)">${esc(c.Type||"")}</td>
    </tr>`;
  }).join("");
  document.getElementById("cr-creds-tbody").innerHTML = credRows ||
    `<tr><td colspan="3" style="padding:20px;color:var(--muted);text-align:center">No credentials stored in Windows Credential Manager</td></tr>`;

  document.getElementById("cr-loading").style.display = "none";
  document.getElementById("cr-content").style.display = "";
}

async function resumeOneDrive() {
  const btn    = document.getElementById("cr-resume-od-btn");
  const status = document.getElementById("cr-fix-status");
  if (btn) { btn.disabled = true; btn.textContent = "Resuming…"; }
  if (status) { status.style.display = ""; status.style.color = "var(--muted)"; status.textContent = "Resuming OneDrive…"; }
  try {
    const r = await fetch("/api/credentials/resume-onedrive", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      if (status) { status.style.color = "var(--cyan)"; status.textContent = d.message + " Refreshing in 3s…"; }
      setTimeout(() => { loadCredentials(); if (status) status.style.display = "none"; }, 3000);
    } else {
      if (status) { status.style.color = "var(--red)"; status.textContent = d.message || "Failed to resume OneDrive."; }
    }
  } catch(e) {
    if (status) { status.style.color = "var(--red)"; status.textContent = "Error: " + e.message; }
  }
  if (btn) { btn.disabled = false; btn.textContent = "▶ Resume OneDrive"; }
}

async function resumeBrokers() {
  const btn    = document.getElementById("cr-resume-btn");
  const status = document.getElementById("cr-fix-status");
  btn.disabled = true;
  btn.textContent = "Resuming…";
  status.style.display = "";
  status.style.color = "var(--muted)";
  status.textContent = "Resuming Microsoft auth broker processes…";
  try {
    const r = await fetch("/api/credentials/resume-brokers", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      status.style.color = "var(--cyan)";
      status.textContent = d.message + " Refreshing in 3s…";
      setTimeout(() => {
        loadCredentials();
        status.style.display = "none";
      }, 3000);
    } else {
      status.style.color = "var(--orange)";
      status.textContent = d.message || "No broker processes found to resume.";
    }
  } catch (e) {
    status.style.color = "var(--red)";
    status.textContent = "Error: " + e.message;
  }
  btn.disabled = false;
  btn.textContent = "▶ Resume Auth Brokers";
}

async function fixFastStartup() { await toggleFastStartup(false); }

// Used by task_watcher concerns (backlog #27) — pops the Windows Logs/
// folder in Explorer so the user can inspect the raw log files.
async function openLogsFolder() {
  try {
    const r = await fetch("/api/tasks/open-logs-folder", {method: "POST"});
    const d = await r.json();
    if (!d.ok) {
      alert(`Could not open Logs folder: ${d.error || "unknown error"}`);
    }
  } catch (e) {
    alert(`Could not open Logs folder: ${e.message}`);
  }
}

// ── Memory concern action handlers (backlog #19) ─────────────────────────
// Wired up by the dashboard concern renderer when a concern carries
// process_name metadata. Each handler reloads the dashboard so the concern
// state (killed / snoozed) is reflected immediately.

function investigateProcess(pid, name) {
  switchTab("processes");
  // Bug 2026-04-28: previous version used a fixed 150ms timeout AND set
  // the search box to the PID number. Two failure modes:
  //   (a) /api/processes/list takes >150ms (~1-2s on a busy box) so
  //       renderProcesses ran against an empty _processData -> blank table
  //   (b) The filter only matched Name/Description, so a numeric PID
  //       search like "28008" returned zero rows even after data loaded
  // Fix (b) is in renderProcesses (filter now also matches PID + Path).
  // Fix (a) is here: poll _processData up to 30s and apply the search
  // when it's actually available, so the user always lands on a populated
  // filtered view.
  //
  // The search defaults to the human-readable NAME (sans .exe) so the
  // search box reads "ServiceShell" not "28008" -- but the filter
  // accepts either, so power-users can paste a PID and it still works.
  let tries = 0;
  const maxTries = 300;  // 30s at 100ms tick
  const apply = () => {
    if (_processData && (_processData.processes || []).length) {
      const search = document.getElementById("pr-search");
      if (search) {
        const cleanName = (name || "").replace(/\.exe$/i, "");
        search.value = cleanName || (pid ? String(pid) : "");
        if (typeof renderProcesses === "function") renderProcesses();
      }
    } else if (++tries < maxTries) {
      setTimeout(apply, 100);
    }
  };
  setTimeout(apply, 100);
}

async function killProcessFromConcern(pid, name) {
  if (!pid) {
    alert(`Cannot kill "${name}" — no PID attached to this concern. Use the Process Monitor to kill manually.`);
    return;
  }
  if (!confirm(`Kill ${name} (PID ${pid})?\n\nAny unsaved work in that process will be lost.`)) return;
  try {
    const r = await fetch("/api/processes/kill", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({pid: pid}),
    });
    const d = await r.json();
    if (d.ok) {
      setTimeout(loadDashboard, 500);  // refresh — the concern should disappear
    } else {
      alert(`Failed to kill ${name}: ${d.error || "unknown error"}`);
    }
  } catch (e) {
    alert(`Failed to kill ${name}: ${e.message}`);
  }
}

async function snoozeMemoryConcern(name, hours) {
  if (!name) return;
  const h = parseInt(hours, 10) || 24;
  try {
    const r = await fetch("/api/memory/snooze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({process_name: name, hours: h}),
    });
    const d = await r.json();
    if (d.ok) {
      // Expiry in d.expires — reload to hide the concern
      setTimeout(loadDashboard, 200);
    } else {
      alert(`Failed to snooze ${name}: ${d.error || "unknown error"}`);
    }
  } catch (e) {
    alert(`Failed to snooze ${name}: ${e.message}`);
  }
}

async function toggleFastStartup(enable) {
  const btn = document.getElementById("cr-fast-toggle-btn");
  const msg = document.getElementById("cr-fast-toggle-msg");
  if (btn) { btn.disabled = true; btn.textContent = enable ? "Enabling…" : "Disabling…"; }
  if (msg) { msg.textContent = "Applying registry change…"; msg.style.color = "var(--muted)"; }
  try {
    const r = await fetch("/api/credentials/fix-fast-startup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enable })
    });
    const d = await r.json();
    if (d.ok) {
      if (msg) {
        msg.style.color = "var(--cyan)";
        msg.textContent = (enable ? "Fast Startup enabled." : "Fast Startup disabled.")
          + " Restart Windows to apply (use Restart, not Shut Down).";
      }
      setTimeout(() => loadCredentials(), 1500);
    } else {
      if (msg) { msg.style.color = "var(--red)"; msg.textContent = d.message || "Failed — try running as Administrator."; }
      if (btn) { btn.disabled = false; btn.textContent = enable ? "Enable Fast Startup" : "⚡ Disable Fast Startup"; }
    }
  } catch(e) {
    if (msg) { msg.style.color = "var(--red)"; msg.textContent = "Error: " + e.message; }
    if (btn) { btn.disabled = false; }
  }
}


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

async function loadDashboard() {
  document.getElementById("db-loading").style.display = "block";
  document.getElementById("db-content").style.display  = "none";

  try {
    const r = await fetch("/api/dashboard/summary");
    const d = await r.json();
    renderDashboard(d);
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

    const tile = mk("db-gauge");
    tile.setAttribute("data-gauge-key", g.key || "");
    tile.setAttribute("data-gauge-value", has ? String(g.value) : "");
    tile.setAttribute("data-gauge-available", String(has));
    tile.appendChild(mk("dg-lbl", g.label || ""));

    const ring = mk("dg-ring" + (has ? "" : " dg-unavail"));
    ring.style.setProperty("--sweep", sweep.toFixed(1));
    ring.style.setProperty("--col", col);
    ring.style.setProperty("--glow", glow);
    ring.appendChild(mk("dg-arc"));
    const core = mk("dg-core");
    const num = mk("dg-num", has ? String(Math.round(g.value * 10) / 10) : "—");
    if (has && g.unit) {
      const em = document.createElement("em");
      em.textContent = g.unit;
      num.appendChild(em);
    }
    core.appendChild(num);
    ring.appendChild(core);
    tile.appendChild(ring);
    tile.appendChild(mk("dg-sub", g.sub || ""));
    el.appendChild(tile);
  });
}

function renderDashboard(d) {
  const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;");
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
    "cpu_temp_c":                   {label: "Max Temp",     color: "#ff7043", unit: "°C"},
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
        const safeMetric = metric.replace(/"/g, '&quot;').replace(/'/g, "\\'");
        return `
          <div data-metric="${metric.replace(/"/g, '&quot;')}" onclick="openTrendDrilldown('${safeMetric}')" style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 12px;cursor:pointer;transition:border-color 0.15s,transform 0.05s" onmouseover="this.style.borderColor='var(--cyan)'" onmouseout="this.style.borderColor='var(--border)'" title="Click to drill down (full chart, time axis, summary stats)">
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
    const esc = s => String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;");
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

// ══════════════════════════════════════════════════════════════════════════
// SYSTEM INFO TAB
// ══════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════
// REMEDIATION ENGINE
// ══════════════════════════════════════════════════════════════════════════
let _remActions   = [];
let _remHistory   = [];
let _remHistFilt  = [];

const _remRiskColor = r => r==="high"?"var(--red)":r==="medium"?"var(--orange)":"var(--green)";
const _remRiskBg    = r => r==="high"?"#ff456012":r==="medium"?"#ff704312":"#00e67612";

async function loadRemediation() {
  document.getElementById("rem-actions-loading").style.display = "block";
  document.getElementById("rem-actions-grid").style.display    = "none";
  document.getElementById("rem-history-loading").style.display = "block";
  document.getElementById("rem-history-table").style.display   = "none";
  document.getElementById("rem-history-empty").style.display   = "none";
  try {
    const [ar, hr] = await Promise.all([
      fetch("/api/remediation/actions").then(r=>r.json()),
      fetch("/api/remediation/history").then(r=>r.json()),
    ]);
    _remActions  = Array.isArray(ar) ? ar : [];
    _remHistory  = Array.isArray(hr) ? hr : [];
    _remHistFilt = _remHistory.slice();
    renderRemActions();
    renderRemHistory();
  } catch(e) {
    document.getElementById("rem-actions-loading").innerHTML =
      `<span style="color:var(--red)">Error: ${esc(e.message)}</span>`;
  }
}

function renderRemActions() {
  const grid = document.getElementById("rem-actions-grid");
  grid.innerHTML = _remActions.map(a => `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 18px">
      <div style="display:flex;align-items:flex-start;gap:12px">
        <span style="font-size:24px;flex-shrink:0">${esc(a.icon)}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;font-size:13px;margin-bottom:4px">${esc(a.label)}</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.5;margin-bottom:10px">${esc(a.description)}</div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-size:9px;font-weight:700;text-transform:uppercase;
              color:${_remRiskColor(a.risk)};background:${_remRiskBg(a.risk)};
              border:1px solid ${_remRiskColor(a.risk)};padding:2px 8px;border-radius:8px">
              ${a.risk} risk</span>
            ${a.reboot ? '<span style="font-size:9px;color:var(--orange);font-weight:700">&#9888; Reboot required</span>' : ""}
            <button onclick="confirmRemediation('${esc(a.id)}')"
              style="margin-left:auto;background:var(--card);border:1px solid ${_remRiskColor(a.risk)};
              color:${_remRiskColor(a.risk)};padding:5px 14px;border-radius:6px;
              cursor:pointer;font-size:11px;font-weight:700;font-family:var(--font-mono)">
              Run &#8594;
            </button>
          </div>
        </div>
      </div>
    </div>`).join("");
  document.getElementById("rem-actions-loading").style.display = "none";
  grid.style.display = "grid";
}

function confirmRemediation(actionId) {
  const action = _remActions.find(a => a.id === actionId);
  if (!action) return;
  const riskUpper = action.risk.toUpperCase();
  const rebootNote = action.reboot
    ? "\n\nThis action REQUIRES a reboot to take full effect."
    : "";
  const msg = `Run: ${action.label}\n\nRisk level: ${riskUpper}\n${action.description}${rebootNote}\n\nProceed?`;
  if (!confirm(msg)) return;
  runRemediation(actionId);
}

async function runRemediation(actionId) {
  const action = _remActions.find(a => a.id === actionId);
  const label  = action ? action.label : actionId;
  document.querySelectorAll("#rem-actions-grid button, #db-qf-cards button").forEach(b => b.disabled = true);
  try {
    const r = await fetch("/api/remediation/run", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({action_id: actionId}),
    });
    const d = await r.json();
    if (d.ok) {
      const rebootNote = (action && action.reboot)
        ? `<br><button onclick="confirmRemediation('reboot_system')"
            style="margin-top:10px;background:#ff456015;border:1px solid var(--red);
            color:var(--red);padding:6px 16px;border-radius:6px;cursor:pointer;font-weight:700;font-family:var(--font-mono)">
            Reboot Now</button>`
        : "";
      showRemToast(`${esc(label)}: ${esc(d.message)}${rebootNote}`, "ok");
    } else {
      showRemToast(`${esc(label)} failed: ${esc(d.message)}`, "err");
    }
    fetch("/api/remediation/history").then(r=>r.json()).then(h=>{
      _remHistory  = Array.isArray(h) ? h : [];
      _remHistFilt = _remHistory.slice();
      renderRemHistory();
    });
  } catch(e) {
    showRemToast(`Error running ${esc(label)}: ${esc(e.message)}`, "err");
  } finally {
    document.querySelectorAll("#rem-actions-grid button, #db-qf-cards button").forEach(b => b.disabled = false);
  }
}

function runRemediationFromDashboard(actionId) {
  if (_remActions.length === 0) {
    fetch("/api/remediation/actions").then(r=>r.json()).then(a=>{
      _remActions = Array.isArray(a) ? a : [];
      confirmRemediation(actionId);
    });
  } else {
    confirmRemediation(actionId);
  }
}

function showRemToast(html, type) {
  let toast = document.getElementById("rem-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "rem-toast";
    toast.style.cssText =
      "position:fixed;bottom:24px;right:24px;z-index:9999;max-width:420px;padding:14px 18px;" +
      "border-radius:10px;font-size:13px;line-height:1.5;border:1px solid;font-family:var(--font-mono)";
    document.body.appendChild(toast);
  }
  toast.style.background  = type==="ok" ? "#00e67618" : "#ff456018";
  toast.style.borderColor = type==="ok" ? "var(--green)" : "var(--red)";
  toast.style.color       = type==="ok" ? "var(--green)" : "var(--red)";
  toast.innerHTML = html;
  toast.style.display = "block";
  if (toast._timer) clearTimeout(toast._timer);
  toast._timer = setTimeout(()=>{ toast.style.display="none"; }, 8000);
}

function renderRemHistory() {
  const tbody = document.getElementById("rem-history-tbody");
  const table = document.getElementById("rem-history-table");
  const empty = document.getElementById("rem-history-empty");
  document.getElementById("rem-history-loading").style.display = "none";
  if (!_remHistFilt.length) {
    table.style.display = "none";
    empty.style.display = "";
    return;
  }
  tbody.innerHTML = _remHistFilt.map(h => {
    const ts   = h.ts ? new Date(h.ts).toLocaleString() : "\u2014";
    const ok   = h.ok;
    const riskC = _remRiskColor(h.risk||"low");
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:8px 10px;font-size:11px;color:var(--muted);white-space:nowrap">${esc(ts)}</td>
      <td style="padding:8px 10px;font-weight:600">${esc(h.label||h.id)}</td>
      <td style="padding:8px 10px"><span style="font-size:9px;font-weight:700;text-transform:uppercase;
        color:${riskC};border:1px solid ${riskC};padding:1px 6px;border-radius:8px">${esc(h.risk||"")}</span></td>
      <td style="padding:8px 10px;color:${ok?"var(--green)":"var(--red)"};font-weight:700">${ok?"OK":"FAIL"}</td>
      <td style="padding:8px 10px;font-size:11px;color:var(--muted)">${esc(h.message||"")}</td>
    </tr>`;
  }).join("");
  table.style.display = "";
  empty.style.display = "none";
}

function filterRemHistory() {
  const q = (document.getElementById("rem-history-search").value||"").toLowerCase();
  _remHistFilt = q
    ? _remHistory.filter(h =>
        (h.label||"").toLowerCase().includes(q) ||
        (h.message||"").toLowerCase().includes(q) ||
        (h.risk||"").toLowerCase().includes(q) ||
        (h.id||"").toLowerCase().includes(q)
      )
    : _remHistory.slice();
  renderRemHistory();
}

// ── Home Network Management ──────────────────────────────────────────────
let _hnDevices = [];
let _hnDevicesFilt = [];
let _hnLightPollId = null;   // 60s ARP-only poll
let _hnFullPollId = null;    // 5min full scan poll
let _hnPollActive = false;   // true when tab is visible

function _hnStartPolling() {
  if (_hnPollActive) return;
  _hnPollActive = true;
  // Light poll every 60s (ARP only — fast)
  _hnLightPollId = setInterval(() => _hnLightPoll(), 60000);
  // Full scan every 5 min (ARP + routers)
  _hnFullPollId = setInterval(() => _hnFullPoll(), 300000);
}

function _hnStopPolling() {
  _hnPollActive = false;
  if (_hnLightPollId) { clearInterval(_hnLightPollId); _hnLightPollId = null; }
  if (_hnFullPollId)  { clearInterval(_hnFullPollId);  _hnFullPollId = null; }
}

async function _hnLightPoll() {
  // Only poll when the homenet tab is visible
  if (document.querySelector('.page-tab.active')?.dataset.page !== 'homenet') {
    _hnStopPolling();
    return;
  }
  try {
    const r = await fetch("/api/homenet/scan/light", {method: "POST"});
    const data = await r.json();
    if (data.ok) _hnUpdateUI(data);
  } catch(e) { console.error("light poll error:", e); }
}

async function _hnFullPoll() {
  if (document.querySelector('.page-tab.active')?.dataset.page !== 'homenet') {
    _hnStopPolling();
    return;
  }
  try {
    const btn = document.getElementById("hn-scan-btn");
    btn.textContent = "Auto-scanning…";
    const r = await fetch("/api/homenet/scan", {method: "POST"});
    const data = await r.json();
    if (data.errors && data.errors.length) {
      const errDiv = document.getElementById("hn-errors");
      errDiv.style.display = "block";
      errDiv.textContent = data.errors.join(" | ");
    }
    if (data.ok) _hnUpdateUI(data);
    btn.textContent = "🔍 Scan Network";
  } catch(e) {
    console.error("full poll error:", e);
    document.getElementById("hn-scan-btn").textContent = "🔍 Scan Network";
  }
}

function _hnUpdateUI(data) {
  _hnDevices = data.devices || [];
  document.getElementById("hn-total").textContent = data.device_count || 0;
  document.getElementById("hn-online").textContent = _hnDevices.filter(d => d.active).length;
  document.getElementById("hn-wired").textContent = _hnDevices.filter(d => d.network === "wired").length;
  document.getElementById("hn-wireless").textContent = _hnDevices.filter(d => d.network === "wireless").length;
  document.getElementById("hn-lastscan").textContent = data.last_scan
    ? new Date(data.last_scan).toLocaleString() : "Never";
  filterHomeNet(); // re-apply current filters
}

async function loadHomeNet() {
  document.getElementById("hn-devices-loading").style.display = "block";
  document.getElementById("hn-devices-table").style.display = "none";
  document.getElementById("hn-devices-empty").style.display = "none";

  // Load credentials
  try {
    const cr = await fetch("/api/homenet/credentials");
    const creds = await cr.json();
    renderHomeNetCredentials(creds);
  } catch(e) { console.error("creds load error:", e); }

  // Load inventory
  try {
    const r = await fetch("/api/homenet/inventory");
    const data = await r.json();
    _hnUpdateUI(data);
  } catch(e) {
    console.error("inventory load error:", e);
  }

  document.getElementById("hn-devices-loading").style.display = "none";

  // Start auto-polling
  _hnStartPolling();
}

function renderHomeNetCredentials(creds) {
  const grid = document.getElementById("hn-creds-grid");
  document.getElementById("hn-creds-loading").style.display = "none";
  grid.style.display = "grid";
  grid.innerHTML = creds.map(c => `
    <div style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-weight:600;font-size:13px">${esc(c.label)}</span>
        <span style="font-size:10px;padding:2px 8px;border-radius:10px;${
          c.configured
            ? 'background:var(--green-dim);color:var(--green)'
            : 'background:var(--red-dim);color:var(--red)'
        }">${c.configured ? 'Configured' : 'Not Set'}</span>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:6px">IP: ${esc(c.ip)}</div>
      ${c.configured
        ? `<div style="font-size:11px;margin-bottom:8px">User: <span style="color:var(--cyan)">${esc(c.username)}</span> &nbsp; Pass: <span style="color:var(--muted)">${esc(c.password_hint)}</span></div>
           <div style="display:flex;gap:6px">
             <button onclick="testCredentialDirect('${c.key}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--cyan);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Test</button>
             <button onclick="openCredModal('${c.key}','${esc(c.label)}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--orange);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Change</button>
             <button onclick="deleteCredential('${c.key}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--red);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Delete</button>
           </div>`
        : `<button onclick="openCredModal('${c.key}','${esc(c.label)}')" class="btn-action" style="padding:4px 12px;font-size:11px">Add Credentials</button>`
      }
    </div>
  `).join("");
}

function renderHomeNet() {
  const tbody = document.getElementById("hn-devices-tbody");
  const table = document.getElementById("hn-devices-table");
  const empty = document.getElementById("hn-devices-empty");

  if (!_hnDevicesFilt.length) {
    table.style.display = "none";
    empty.style.display = "block";
    return;
  }

  table.style.display = "table";
  empty.style.display = "none";

  // Sort: active first, then by IP
  const sorted = _hnDevicesFilt.slice().sort((a, b) => {
    if (a.active !== b.active) return b.active - a.active;
    const aOctets = (a.ip||"0.0.0.0").split(".").map(Number);
    const bOctets = (b.ip||"0.0.0.0").split(".").map(Number);
    for (let i = 0; i < 4; i++) { if (aOctets[i] !== bOctets[i]) return aOctets[i] - bOctets[i]; }
    return 0;
  });

  tbody.innerHTML = sorted.map(d => {
    const displayName = d.friendly_name || d.hostname || d.vendor || "Unknown";
    const netColor = d.network === "wired" ? "var(--orange)" : "var(--purple)";
    const netLabel = d.network === "wired" ? "Wired" : "WiFi";
    const statusDot = d.active
      ? '<span style="color:var(--green);font-size:14px">●</span>'
      : '<span style="color:var(--muted);font-size:14px">○</span>';
    const cat = d.category || '<span style="color:var(--muted)">—</span>';
    return `<tr style="border-bottom:1px solid var(--border)" class="hn-device-row"
               data-name="${esc(displayName).toLowerCase()}" data-ip="${esc(d.ip)}"
               data-mac="${esc(d.mac)}" data-vendor="${esc(d.vendor||'').toLowerCase()}"
               data-network="${d.network}" data-category="${(d.category||'').toLowerCase()}">
      <td style="padding:6px 10px">${statusDot}</td>
      <td style="padding:6px 10px;color:var(--text-bright)">${esc(displayName)}${d.friendly_name && d.hostname ? '<br><span style="font-size:10px;color:var(--muted)">'+esc(d.hostname)+'</span>' : ''}</td>
      <td style="padding:6px 10px;color:var(--cyan)">${esc(d.ip)}</td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${esc(d.mac)}</td>
      <td style="padding:6px 10px">${esc(d.vendor)}</td>
      <td style="padding:6px 10px"><span style="color:${netColor};font-size:11px;padding:1px 6px;border-radius:8px;border:1px solid ${netColor}">${netLabel}</span></td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${d.network === "wireless" && d.ssid ? esc(d.ssid) : '—'}</td>
      <td style="padding:6px 10px">${cat}</td>
      <td style="padding:6px 10px">
        <button onclick="openEditModal('${esc(d.mac)}')" style="padding:2px 8px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--cyan);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Edit</button>
      </td>
    </tr>`;
  }).join("");
}

// ── Network Topology Diagram (#9) ──────────────────────────────────────
//
// Renders a 3-tier hierarchical SVG: router (top) → infrastructure
// (switch + Orbi APs, middle) → devices (bottom, grouped under their
// uplink). Inline SVG -- no chart library, no canvas, just primitive
// <line> / <rect> / <circle> / <text> elements. Reads the cached
// inventory; doesn't trigger a fresh scan (the existing Scan button
// does that and the user clicks Refresh after to re-render).
//
// Category icon mapping mirrors the inventory table so a Phone in the
// list is also a Phone (📱) in the diagram.

const _HN_CAT_ICON = {
  "Computer": "💻", "Phone": "📱", "TV": "📺", "IoT": "💡",
  "Printer": "🖨", "Network": "🛜", "Storage": "💾", "Other": "📦",
};

let _hnTopoLoaded = false;

async function hnTopoToggle() {
  const body = document.getElementById("hn-topo-body");
  const btn = document.getElementById("hn-topo-toggle");
  if (!body || !btn) return;
  const isHidden = body.style.display === "none";
  if (isHidden) {
    body.style.display = "";
    btn.textContent = "📐 Hide diagram";
    if (!_hnTopoLoaded) {
      await hnTopoRefresh();
      _hnTopoLoaded = true;
    }
  } else {
    body.style.display = "none";
    btn.textContent = "📐 Show diagram";
  }
}

// Manually add a transparent device by MAC -- for MoCA bridges and other
// LAN-invisible gear (no IP, never in ARP). Uses two prompt() calls to keep
// the UX simple; a fancier modal could be added later.
async function hnTopoAddTransparent() {
  const mac = (prompt(
    "Add a transparent device by MAC address.\n\n" +
    "Use this for MoCA bridges that have no IP and don't show up in network scans " +
    "(common with Verizon-branded Askey FiOS extenders).\n\n" +
    "Enter the MAC address (printed on the back of the device, format AA:BB:CC:DD:EE:FF):"
  ) || "").trim();
  if (!mac) return;
  const friendly = (prompt("Friendly name (optional, e.g. 'Living Room MoCA'):") || "").trim();
  try {
    const r = await fetch("/api/homenet/device/add-manual", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ mac: mac, friendly_name: friendly, wired_via: "moca_bridge" }),
    });
    const data = await r.json();
    if (data.ok) {
      alert(`Added: ${data.device.mac} (${data.device.vendor || 'unknown vendor'})`);
      _hnTopoLoaded = false;
      await hnTopoRefresh();
      _hnTopoLoaded = true;
    } else {
      alert("Failed: " + (data.message || "unknown error"));
    }
  } catch (e) {
    alert("Failed to add device: " + e.message);
  }
}

async function hnTopoRefresh() {
  const loading = document.getElementById("hn-topo-loading");
  const errorEl = document.getElementById("hn-topo-error");
  const wrap = document.getElementById("hn-topo-svg-wrap");
  const legend = document.getElementById("hn-topo-legend");
  const stats = document.getElementById("hn-topo-stats");
  if (!loading) return;

  loading.style.display = "";
  errorEl.style.display = "none";
  wrap.style.display = "none";
  if (legend) legend.style.display = "none";

  let data;
  try {
    const r = await fetch("/api/homenet/topology");
    data = await r.json();
  } catch (e) {
    loading.style.display = "none";
    errorEl.style.display = "";
    errorEl.textContent = "Failed to fetch topology: " + e.message;
    return;
  }
  loading.style.display = "none";
  if (!data.ok) {
    errorEl.style.display = "";
    errorEl.textContent = "Topology API returned ok=false";
    return;
  }

  // Update the small stats line above the diagram
  const s = data.stats || {};
  if (stats) {
    const parts = [
      `${s.total || 0} devices`,
      `${s.wired_mapped || 0} on switch`,
      `${s.wireless_mapped || 0} wireless-mapped`,
    ];
    if (s.via_verizon_or_moca) parts.push(`${s.via_verizon_or_moca} Verizon-direct/MoCA`);
    if (s.moca_bridges) parts.push(`${s.moca_bridges} MoCA bridge${s.moca_bridges !== 1 ? "s" : ""}`);
    if (s.orbi_mesh_unknown_ap) parts.push(`${s.orbi_mesh_unknown_ap} unknown (Orbi firmware doesn't expose per-satellite mapping)`);
    if (s.unmapped) parts.push(`${s.unmapped} unmapped`);
    if (!s.switch_available) parts.push("⚠ switch unreachable — see Network Settings");
    // Hint: surface a one-line nudge if any satellite is still showing as
    // the "Orbi satellite (XXXX)" fallback. The RBRE960 firmware doesn't
    // expose satellite names via SOAP (every action returns ResponseCode
    // 404 -- not implemented on this firmware), so the user has to set
    // them manually via the inventory edit modal. The auto-synthesised
    // satellite entries land in the device table below with vendor=Netgear
    // + notes="Orbi satellite -- auto-added".
    const fallbackSats = (data.aps || []).filter(ap => /^Orbi satellite \([0-9A-F]{4}\)$/.test(ap.name));
    if (fallbackSats.length) {
      parts.push(`💡 ${fallbackSats.length} satellite${fallbackSats.length !== 1 ? "s" : ""} still using fallback name -- set "friendly_name" via the device table below`);
    }
    stats.textContent = parts.join(" · ");
  }

  wrap.style.display = "";
  if (legend) legend.style.display = "flex";
  // Bug fix 2026-05-12: openEditModal(mac) looks devices up in _hnDevices,
  // which is populated from /api/homenet/inventory. If the user opens
  // the topology section BEFORE the inventory poll has fired (timing
  // race on first tab activation), clicking a MoCA bridge / Orbi AP
  // header is a silent no-op. Backfill _hnDevices from the topology
  // payload's devices map so the clickable headers work immediately.
  if (!_hnDevices.length && data.devices && typeof data.devices === "object") {
    _hnDevices = Object.values(data.devices);
  }
  wrap.innerHTML = hnTopoBuildSvg(data);
}

// Build the SVG from a topology payload. Layout is hand-rolled because we
// only need three tiers and the math is trivial:
//   y=40   router
//   y=140  infra row (switch + each AP)
//   y=260+ device rows under each infra node
function hnTopoBuildSvg(t) {
  const PAD = 20;
  const ROW_H = 26;
  const NODE_W = 220;
  const ROUTER_Y = 40;
  const INFRA_Y = 130;
  const DEVICE_Y = 230;

  const devices = t.devices || {};

  // Build the infra columns: switch + every AP. Each column hosts a stack
  // of device boxes underneath. The column width adapts to the tallest
  // stack so the SVG never overflows the viewport.
  const columns = [];
  for (const sw of (t.switches || [])) {
    // For wired we group devices by port. A port may carry multiple MACs
    // (the Orbi base on its uplink port carries every wireless client) --
    // we collapse those into a "(N more)" pill rather than render them
    // here, since they show up under their AP elsewhere.
    const portRows = [];
    const ports = sw.ports || {};
    const sortedPorts = Object.keys(ports).map(Number).sort((a, b) => a - b);
    for (const p of sortedPorts) {
      const macs = ports[p] || [];
      const realDevs = macs.filter(m => devices[m] && !_hnIsInfra(devices[m]));
      const apsOnPort = macs.filter(m => devices[m] && _hnIsAp(devices[m]));
      if (!realDevs.length && !apsOnPort.length) continue;
      // Pick the most informative one to show; collapse the rest.
      for (const m of realDevs) {
        portRows.push({ mac: m, label: `port ${p}`, dev: devices[m] });
      }
      for (const m of apsOnPort) {
        portRows.push({ mac: m, label: `port ${p} (uplink)`, dev: devices[m], is_ap: true });
      }
    }
    columns.push({
      kind: "switch",
      id: sw.id,
      name: sw.name,
      sub: sw.available ? "" : (sw.error ? "switch unreachable" : "no MAC table"),
      rows: portRows,
    });
  }

  for (const ap of (t.aps || [])) {
    const rows = ap.clients.map(m => ({ mac: m, label: ap.is_base ? "via Orbi base" : "via satellite", dev: devices[m] || { mac: m } }));
    // Subtitle hints when the AP has no user-set friendly_name so the
    // user knows clicking the header opens the edit modal. The Orbi base
    // always has a friendly fallback ("Orbi RBRE960 (Base)") from
    // _INFRA_LABELS, so the hint only really fires for satellites.
    const apDev = devices[ap.mac] || {};
    const apFriendly = (apDev.friendly_name || "").trim();
    const apSub = apFriendly || ap.is_base
      ? `${ap.clients.length} client${ap.clients.length !== 1 ? "s" : ""}`
      : `✏ click header to name · ${ap.clients.length} client${ap.clients.length !== 1 ? "s" : ""}`;
    columns.push({
      kind: ap.is_base ? "ap_base" : "ap_satellite",
      id: ap.id,
      name: ap.name,
      sub: apSub,
      rows: rows,
      // Click the header → open the edit modal for this AP's MAC so the
      // user can set a friendly_name without hunting through the device
      // table.
      click_mac: ap.mac,
    });
  }

  // Two SEPARATE columns now (was one combined "Verizon-direct / MoCA"):
  //   - "Verizon LAN port"  → wired devices physically plugged into the
  //     Verizon CR1000A's 4 LAN ports
  //   - "via MoCA"           → wired devices reaching the LAN over coax,
  //     downstream of a MoCA bridge
  // These are distinct paths and the user (correctly) wanted them split.
  // Until per-device topology data from the Verizon API is wired up,
  // assignment is per-device user-set via the edit modal's Wired-via
  // dropdown. Devices with no wired_via set default to verizon_lan
  // (most common in typical home setups).
  if ((t.verizon_lan || []).length) {
    columns.push({
      kind: "verizon_lan",
      id: "verizon-lan",
      name: "Verizon LAN port",
      sub: `${t.verizon_lan.length} device${t.verizon_lan.length !== 1 ? "s" : ""} on Verizon LAN ports`,
      rows: t.verizon_lan.map(m => ({ mac: m, label: "Verizon LAN", dev: devices[m] || { mac: m } })),
    });
  }
  if ((t.via_moca || []).length) {
    columns.push({
      kind: "via_moca",
      id: "via-moca",
      name: "via MoCA (coax)",
      sub: `${t.via_moca.length} device${t.via_moca.length !== 1 ? "s" : ""} downstream of MoCA bridge`,
      rows: t.via_moca.map(m => ({ mac: m, label: "via MoCA", dev: devices[m] || { mac: m } })),
    });
  }

  // MoCA Bridges -- ONE COLUMN PER BRIDGE (user feedback 2026-05-08:
  // "shows one moca bridge" -- the previous layout crammed all bridges
  // into a single collapsed column, asymmetric with Orbi satellites
  // which each get their own column). Each bridge column:
  //   - title: friendly_name if set, else "<vendor> <last 4 of MAC>"
  //     (mirrors how Orbi satellite fallback names look)
  //   - sub: downstream device count
  //   - rows: the devices the user has marked behind_moca_bridge=<this>
  //
  // Degenerate case (zero bridges with downstream devices, which is
  // typical right after #42 auto-discovery): emit one column per
  // bridge anyway -- the empty columns act as a "click here to assign
  // devices" affordance, and the user can populate them via the
  // device-edit modal's "Behind MoCA bridge" dropdown. No fallback
  // to the old single-column layout because the user explicitly
  // asked for the per-bridge view.
  if ((t.moca_bridges || []).length) {
    const bridges = t.moca_bridges.slice(); // copy so sort doesn't mutate
    const childrenMap = t.moca_children || {};
    // Build per-bridge column metadata, sort alphabetically by display name
    // so the diagram is stable across scans regardless of MAC ordering.
    const bridgeColumns = bridges.map(bridgeMac => {
      const dev = devices[bridgeMac] || { mac: bridgeMac };
      const friendly = (dev.friendly_name || "").trim();
      const vendor = (dev.vendor || "Unknown").trim();
      // Last 4 hex chars of MAC (no colons) -- same compact fingerprint
      // the Orbi-satellite fallback uses, e.g. "Orbi satellite (73E1)".
      const macSuffix = bridgeMac.replace(/:/g, "").slice(-4).toUpperCase();
      const displayName = friendly || `${vendor} ${macSuffix}`;
      const kids = childrenMap[bridgeMac] || [];
      return { bridgeMac, dev, displayName, kids, hasFriendlyName: !!friendly };
    });
    bridgeColumns.sort((a, b) => a.displayName.localeCompare(b.displayName));
    for (const bc of bridgeColumns) {
      const rows = bc.kids.map(childMac => ({
        mac: childMac,
        label: "behind bridge",
        dev: devices[childMac] || { mac: childMac },
      }));
      // Subtitle hints the user that they can click to set a name. Only
      // shown when there's no friendly_name yet (otherwise the existing
      // downstream-device-count subtitle is more informative).
      let sub;
      if (!bc.hasFriendlyName) {
        sub = bc.kids.length
          ? `✏ click header to name · ${bc.kids.length} downstream`
          : "✏ click header to name";
      } else {
        sub = bc.kids.length
          ? `${bc.kids.length} downstream device${bc.kids.length !== 1 ? "s" : ""}`
          : "no downstream devices yet";
      }
      columns.push({
        kind: "moca",
        id: `moca-bridge-${bc.bridgeMac.replace(/:/g, "")}`,
        // Prefix with 📻 to mirror the Orbi 📡 visual hierarchy --
        // both are infrastructure tiers, so the icon-prefix tells you
        // "this is a hop, not a leaf device" at a glance.
        name: `📻 ${bc.displayName}`,
        sub,
        rows,
        // Carry the bridge-MAC through so the empty-state hint can
        // tell the user which bridge to assign devices to in the
        // edit modal, AND so the column header click handler can open
        // the device-edit modal for this bridge directly.
        bridge_mac: bc.bridgeMac,
        click_mac: bc.bridgeMac,
      });
    }
  }

  // "Unknown" column -- wireless devices the Orbi knows about but didn't
  // tell us which node they're on. Renamed from "Orbi mesh (AP unknown)"
  // to just "Unknown" per user request 2026-04-25 (the longer name was
  // confusing). Still honest UI for the Orbi SOAP-API limitation: they're
  // on the mesh somewhere, just not pinpointed to base/satellite.
  if ((t.orbi_mesh_unknown_ap || []).length) {
    // User feedback 2026-05-13: "I am assuming the unknown is one orbi
    // satellite and the unmapped is another" -- the previous column name
    // "Unknown" + same-shaped column visual encouraged that wrong mental
    // model. These are NOT separate satellites; they're failure-mode
    // buckets that happen to both contain wireless devices. Rename so the
    // difference is plain. Bug-source is the RBRE960 SOAP firmware quirk
    // (corrupted ConnAPMAC sentinel for satellite-connected clients).
    columns.push({
      kind: "orbi_mesh_unknown",
      id: "orbi-mesh-unknown",
      name: "Orbi mesh (satellite ?)",
      sub: `${t.orbi_mesh_unknown_ap.length} wireless · firmware didn't say WHICH satellite`,
      rows: t.orbi_mesh_unknown_ap.map(m => ({ mac: m, label: "wireless", dev: devices[m] || { mac: m } })),
    });
  }

  // Truly unmapped column on the right -- devices ARP saw but Orbi /
  // Verizon scans didn't return at all, so we have no AP info, no router
  // attestation, nothing. Distinct from "Orbi mesh (satellite ?)" above:
  // those came FROM the Orbi (it knows them, just won't say which AP);
  // these are ARP-only ghosts. Renamed 2026-05-13 to make the
  // distinction obvious.
  if ((t.unmapped || []).length) {
    columns.push({
      kind: "unmapped",
      id: "unmapped",
      name: "Unmapped (ARP-only)",
      sub: `${t.unmapped.length} device${t.unmapped.length !== 1 ? "s" : ""} · seen by ARP but not by Orbi/Verizon`,
      rows: t.unmapped.map(m => ({ mac: m, label: devices[m]?.network || "?", dev: devices[m] || { mac: m } })),
    });
  }

  // Per-column width is fixed; SVG width grows with column count.
  const COL_W = NODE_W + 30;
  const totalW = Math.max(800, PAD * 2 + COL_W * columns.length);
  const maxRows = Math.max(0, ...columns.map(c => c.rows.length));
  const totalH = DEVICE_Y + maxRows * ROW_H + 40;

  // Router box centered horizontally at the top
  const routerX = (totalW - NODE_W) / 2;
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalW} ${totalH}" style="width:${totalW}px;max-width:none;height:${totalH}px;font-family:var(--font-mono);font-size:11px">`;

  // ── Background grid for visual rhythm ─────────────────────────────
  svg += `<rect x="0" y="0" width="${totalW}" height="${totalH}" fill="none"/>`;

  // ── Tier 1: Router ────────────────────────────────────────────────
  svg += _hnSvgNode(routerX, ROUTER_Y, NODE_W, "🛜 " + (t.router?.name || "Router"), t.router?.ip || "", "var(--cyan)");

  // ── Tier 2: Infrastructure columns ─────────────────────────────────
  columns.forEach((col, i) => {
    const x = PAD + i * COL_W;
    const colorByKind = {
      switch: "var(--orange)",
      ap_base: "var(--purple)",
      ap_satellite: "var(--purple)",
      moca: "var(--cyan)",
      via_moca: "var(--cyan)",
      verizon_lan: "var(--yellow)",
      verizon_or_moca: "var(--yellow)",  // legacy kind, kept for safety
      orbi_mesh_unknown: "var(--purple)",
      unmapped: "var(--border)",
    };
    const iconByKind = { switch: "🔀", ap_base: "📡", ap_satellite: "📡", moca: "📻", via_moca: "🌀", verizon_lan: "🔌", verizon_or_moca: "🔌", orbi_mesh_unknown: "📶", unmapped: "❓" };
    const label = `${iconByKind[col.kind] || "•"} ${col.name}`;
    // data-column-kind / data-column-id make the column header
    // queryable from Playwright so the regression test for #42 follow-up
    // can assert "API says N MoCA bridges → SVG renders N moca columns"
    // without parsing visible label text. Mirrors the data-metric pattern
    // on Trends cards (#39).
    // When the column carries a click_mac (MoCA bridge / Orbi AP) wrap the
    // SVG node in a clickable <g> so the user can open the device-edit modal
    // for that MAC -- the primary entry point for setting friendly_name on
    // an infra node. Bug fix 2026-05-12: previously the only way to rename
    // a MoCA bridge was to scroll the device table and find it; topology
    // headers were inert. Cursor:pointer + a tooltip make the affordance
    // discoverable.
    const headerExtra = col.click_mac
      ? ` style="cursor:pointer" onclick="openEditModal('${_esc(col.click_mac).replace(/'/g, '')}')" data-click-mac="${_esc(col.click_mac)}"`
      : "";
    svg += `<g data-column-kind="${_esc(col.kind || '')}" data-column-id="${_esc(col.id || '')}"${headerExtra}>`;
    if (col.click_mac) {
      // Tooltip mirrors what the device-edit modal does so the user knows
      // what clicking the header will do.
      svg += `<title>Click to edit this ${col.kind === "moca" ? "MoCA bridge" : "Orbi AP"} (set a friendly name, location, notes)</title>`;
    }
    svg += _hnSvgNode(x, INFRA_Y, NODE_W, label, col.sub || "", colorByKind[col.kind] || "var(--muted)");
    svg += `</g>`;

    // Connector router → infra. Skip for "unmapped" only -- everything
    // else (switch, APs, MoCA bridges, Verizon-direct/MoCA bucket) does
    // ultimately route through the Verizon, so a line is correct.
    if (col.kind !== "unmapped") {
      svg += `<line x1="${routerX + NODE_W / 2}" y1="${ROUTER_Y + 50}" x2="${x + NODE_W / 2}" y2="${INFRA_Y}" stroke="var(--border)" stroke-width="1.2"/>`;
    }

    // ── Tier 3: device rows under this column ──────────────────────
    col.rows.forEach((r, rIdx) => {
      const y = DEVICE_Y + rIdx * ROW_H;
      const dev = r.dev || {};
      const cat = (dev.category || "Other");
      const icon = _HN_CAT_ICON[cat] || _HN_CAT_ICON.Other;
      const name = _hnTopoLabel(dev, r.mac);
      const isOnline = dev.active !== false;
      const isChild = !!r.is_child;
      // Children of MoCA bridges are indented to convey the parent->child
      // hierarchy. Non-child rows continue at the default x offset.
      const indentX = isChild ? 16 : 0;
      // Connector infra → device. Stops 6 px before the dot's outer edge
      // so the dot reads as a distinct circle, not as the line's terminus.
      svg += `<line x1="${x + NODE_W / 2}" y1="${INFRA_Y + 50}" x2="${x + 18 + indentX}" y2="${y + ROW_H / 2}" stroke="var(--border)" stroke-width="0.8" opacity="${isChild ? "0.25" : "0.4"}"/>`;
      // Status dot -- bigger (r=5 was 4) + a stroke so it pops over the
      // connector line. Active=green, inactive=hollow grey ring. Children
      // get a smaller dot to convey hierarchy at a glance.
      const dotFill = isOnline ? "var(--green)" : "var(--bg)";
      const dotStroke = isOnline ? "var(--green)" : "var(--muted)";
      const dotR = isChild ? 4 : 5;
      svg += `<circle cx="${x + 8 + indentX}" cy="${y + ROW_H / 2}" r="${dotR}" fill="${dotFill}" stroke="${dotStroke}" stroke-width="1.5" data-active="${isOnline}"/>`;
      // Device row -- clickable, opens the edit modal.
      const safeMac = (dev.mac || r.mac || "").replace(/'/g, "");
      const opacity = isOnline ? "1" : "0.55";
      const childTreeMark = isChild ? "└ " : "";
      const tooltip = `${name}\n${dev.mac || r.mac}\n${dev.ip || "no IP"}\n${r.label}\n(click to edit)`;
      svg += `<g opacity="${opacity}" style="cursor:pointer" onclick="openEditModal('${safeMac}')" data-device-mac="${_esc(dev.mac || r.mac || "")}" data-device-name="${_esc(name)}" data-is-child="${isChild}"><title>${_esc(tooltip)}</title>`;
      svg += `<text x="${x + 20 + indentX}" y="${y + ROW_H / 2 + 4}" fill="var(--text)" font-size="11">${childTreeMark}${icon} ${_truncate(_esc(name), 22 - (isChild ? 2 : 0))}</text>`;
      svg += `<text x="${x + NODE_W - 6}" y="${y + ROW_H / 2 + 4}" fill="var(--muted)" font-size="9" text-anchor="end">${_esc(r.label)}</text>`;
      svg += `</g>`;
    });
  });

  svg += "</svg>";
  return svg;
}

// Pick the most-informative human-readable label for a device row.
//
// Fallback chain:
//   1. friendly_name set by the user (always wins -- it's their explicit choice)
//   2. hostname from DNS / mDNS / router-side label
//   3. vendor from IEEE OUI lookup + last 4 hex of MAC
//      ("Microsoft 4100" beats "00:15:5D:62:A8:93" for skim-readability)
//   4. raw MAC -- last resort, only if literally nothing else is available
//
// Bug 2026-04-25: prior chain dropped to raw MAC for 6 of 76 devices in
// the user's inventory because both friendly_name AND hostname were empty
// (Hyper-V vNICs, randomized phone MACs, mDNS-shy IoT). Now the vendor +
// suffix step gives them readable identities.
function _hnTopoLabel(dev, fallbackMac) {
  const friendly = (dev.friendly_name || "").trim();
  if (friendly) return friendly;
  const hostname = (dev.hostname || "").trim();
  if (hostname) {
    // Strip the boring ".mynetworksettings.com" suffix that shows on every
    // Verizon-DHCP'd device -- it adds noise and truncates real names.
    return hostname.replace(/\.mynetworksettings\.com$/i, "");
  }
  const mac = (dev.mac || fallbackMac || "").toUpperCase();
  const vendor = (dev.vendor || "").trim();
  if (vendor && mac) {
    // Take the first word of the vendor (e.g. "Microsoft Corporation" -> "Microsoft")
    // and append the last 4 hex chars for uniqueness.
    const shortVendor = vendor.split(/[\s,]/)[0];
    const suffix = mac.replace(/:/g, "").slice(-4);
    return `${shortVendor} ${suffix}`;
  }
  return mac || "(unknown)";
}

function _hnSvgNode(x, y, w, label, sub, color) {
  return `
    <g>
      <rect x="${x}" y="${y}" width="${w}" height="50" rx="6" fill="var(--card)" stroke="${color}" stroke-width="1.5"/>
      <text x="${x + w / 2}" y="${y + 20}" fill="var(--text-bright)" font-size="12" font-weight="700" text-anchor="middle">${_esc(label)}</text>
      ${sub ? `<text x="${x + w / 2}" y="${y + 38}" fill="var(--muted)" font-size="10" text-anchor="middle">${_esc(sub)}</text>` : ""}
    </g>`;
}

function _hnIsInfra(dev) {
  if (!dev) return false;
  const ip = dev.ip || "";
  if (ip === "192.168.1.1" || ip === "10.0.0.1") return true;
  return (dev.mac || "").toUpperCase() === "DC:62:79:F3:52:5C";
}

function _hnIsAp(dev) {
  if (!dev) return false;
  return (dev.ip || "") === "10.0.0.1";
}

function _esc(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function _truncate(s, n) {
  if (!s || s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

function filterHomeNet() {
  const q = (document.getElementById("hn-search").value || "").toLowerCase();
  const net = document.getElementById("hn-filter-network").value;
  const cat = document.getElementById("hn-filter-category").value.toLowerCase();
  _hnDevicesFilt = _hnDevices.filter(d => {
    if (net && d.network !== net) return false;
    if (cat && (d.category || "").toLowerCase() !== cat) return false;
    if (q) {
      const hay = [d.friendly_name, d.hostname, d.ip, d.mac, d.vendor, d.category, d.notes]
        .filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  renderHomeNet();
}

// ── Remote reboot (backlog #16) ──────────────────────────────────────────
// Type-to-confirm flow:
//   1. User clicks one of the Reboot buttons -> hnOpenRebootConfirm()
//      sets up the modal with the device's display name + key
//   2. User types the device key in the input -> hnRebootConfirmInputChanged()
//      enables the Reboot button only when text matches
//   3. User clicks Reboot -> hnFireReboot() POSTs to /api/homenet/reboot/<device>
//      with confirm=<key> in the body. Backend has its own type-to-confirm
//      guard as defense-in-depth.
//   4. For SOAP (Orbi): backend confirms reboot fired
//      For deep-link (Verizon, TP-Link): backend returns the URL; UI
//      opens it in a new tab so user finishes in the device's admin.
let _hnRebootDevice = null;  // currently-selected device key

function hnOpenRebootConfirm(deviceKey, displayName) {
  _hnRebootDevice = deviceKey;
  document.getElementById("hn-reboot-modal-device").textContent = displayName;
  document.getElementById("hn-reboot-confirm-required").textContent = deviceKey;
  // Mode-specific copy so the user knows what to expect after confirm.
  // SOAP (Orbi) is real one-click; deep-link routes through the device's
  // own admin UI for the actual trigger.
  const modeNote = document.getElementById("hn-reboot-modal-mode-note");
  if (modeNote) {
    modeNote.textContent = deviceKey === "orbi"
      ? "Reboot fires immediately via SOAP."
      : "Opens the device's admin UI to its reboot page; you click Reboot there.";
  }
  const input = document.getElementById("hn-reboot-confirm-input");
  if (input) {
    input.value = "";
    input.placeholder = `type "${deviceKey}" to enable`;
    setTimeout(() => input.focus(), 0);
  }
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = ".4";
    btn.style.cursor = "not-allowed";
  }
  const status = document.getElementById("hn-reboot-status");
  if (status) status.textContent = "";
  document.getElementById("hn-reboot-modal").style.display = "flex";
  document.addEventListener("keydown", _hnRebootEscHandler);
}

function _hnRebootEscHandler(e) {
  if (e.key === "Escape") hnCloseRebootConfirm();
}

function hnCloseRebootConfirm() {
  document.getElementById("hn-reboot-modal").style.display = "none";
  document.removeEventListener("keydown", _hnRebootEscHandler);
  _hnRebootDevice = null;
}

function hnRebootConfirmInputChanged() {
  const input = document.getElementById("hn-reboot-confirm-input");
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (!input || !btn || !_hnRebootDevice) return;
  const matches = input.value.trim().toLowerCase() === _hnRebootDevice;
  btn.disabled = !matches;
  btn.style.opacity = matches ? "1" : ".4";
  btn.style.cursor = matches ? "pointer" : "not-allowed";
}

async function hnFireReboot() {
  if (!_hnRebootDevice) return;
  const device = _hnRebootDevice;
  const status = document.getElementById("hn-reboot-status");
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (btn) btn.disabled = true;
  if (status) {
    status.textContent = "Sending reboot…";
    status.style.color = "var(--muted)";
  }
  // Bug fix 2026-05-12: open the popup window SYNCHRONOUSLY, inside the
  // user-gesture stack of the click that called us. If we wait until
  // after `await fetch(...)` to call window.open, modern browsers
  // (Chrome / Edge / Firefox) treat it as a non-gesture popup and
  // silently block it -- the user clicks Reboot and "nothing happens".
  // For SOAP-mode (Orbi) we close the popup once we know the response
  // didn't need a deep-link. `noopener,noreferrer` is dropped here so
  // we keep a handle on the popup; we re-apply the equivalent isolation
  // by setting the popup's opener to null after navigating.
  let popup = null;
  try {
    popup = window.open("about:blank", "_blank");
  } catch (_) {
    popup = null;
  }
  try {
    const r = await fetch(`/api/homenet/reboot/${encodeURIComponent(device)}`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      // Server-side type-to-confirm guard mirrors the UI guard --
      // defense-in-depth so a stray POST from elsewhere can't fire reboot.
      body: JSON.stringify({confirm: device}),
    });
    const data = await r.json();
    if (!r.ok || !data.ok) {
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = "Failed: " + (data.error || r.statusText);
        status.style.color = "var(--red)";
      }
      if (btn) btn.disabled = false;
      return;
    }
    if (data.mode === "deep-link" && data.url) {
      // Navigate the placeholder window we pre-opened in the user-gesture
      // stack. Fallback to a fresh window.open if the placeholder was
      // blocked (some hardened popup-blockers reject even about:blank).
      if (popup) {
        try { popup.opener = null; } catch (_) {}
        try { popup.location.href = data.url; }
        catch (_) { window.open(data.url, "_blank", "noopener,noreferrer"); }
      } else {
        window.open(data.url, "_blank", "noopener,noreferrer");
      }
      if (status) {
        status.textContent = "Opened admin UI -- click Reboot there to finish.";
        status.style.color = "var(--green)";
      }
    } else if (data.mode === "reboot-fired") {
      // SOAP path doesn't need a deep-link; close the placeholder.
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = data.message || "Reboot triggered.";
        status.style.color = "var(--green)";
      }
    } else {
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = "Unknown response mode: " + (data.mode || "?");
        status.style.color = "var(--orange)";
      }
    }
    // Auto-close after a short delay so the user sees the success message
    setTimeout(() => hnCloseRebootConfirm(), 2500);
  } catch (e) {
    if (popup) { try { popup.close(); } catch (_) {} }
    if (status) {
      status.textContent = "Error: " + (e && e.message || e);
      status.style.color = "var(--red)";
    }
    if (btn) btn.disabled = false;
  }
}

// ── Router config backups (new feature 2026-05-09) ───────────────────────
// Two flows depending on vendor:
//   * Orbi  -> POST /api/homenet/backup/orbi runs the SOAP-based real
//              backup, saves to backups/orbi/, response carries the
//              saved path. On failure (older firmware path didn't work)
//              the response includes a fallback_url so we can offer the
//              deep-link as a one-click recovery.
//   * Verizon -> POST returns mode='deep-link' + url. We open the admin
//                Save/Restore page in a new tab; user clicks Save there.
// Both flows refresh the saved-backups list afterwards so the user sees
// their new file appear (Orbi case) or knows to drop the downloaded
// file into backups/verizon/ themselves.

async function hnLoadBackupList() {
  const container = document.getElementById("hn-backup-history");
  if (!container) return;
  try {
    const r = await fetch("/api/homenet/backup/list");
    const d = await r.json();
    if (!d.ok) {
      container.innerHTML = `<div style="color:var(--red);font-size:11px">Error loading backups: ${esc(d.error || "unknown")}</div>`;
      return;
    }
    const renderVendor = (vendor, label) => {
      const list = (d.backups && d.backups[vendor]) || [];
      if (!list.length) {
        return `<div style="margin-bottom:8px"><strong style="color:var(--cyan);font-size:11px">${esc(label)}</strong> <span style="color:var(--muted);font-size:11px">— no backups yet</span></div>`;
      }
      const rows = list.slice(0, 15).map(b => {
        const kb = (b.bytes / 1024).toFixed(1);
        return `<tr>
          <td style="padding:3px 8px;color:var(--text);font-family:var(--font-mono);font-size:11px">${esc(b.filename)}</td>
          <td style="padding:3px 8px;color:var(--muted);font-size:11px;text-align:right">${kb} KB</td>
          <td style="padding:3px 8px;color:var(--muted);font-size:11px">${esc(b.age_human)}</td>
        </tr>`;
      }).join("");
      const overflow = list.length > 15 ? `<tr><td colspan="3" style="padding:3px 8px;color:var(--muted);font-size:11px;font-style:italic">… and ${list.length - 15} more</td></tr>` : "";
      return `<div style="margin-bottom:14px">
        <strong style="color:var(--cyan);font-size:11px">${esc(label)} <span style="color:var(--muted);font-weight:400">(${list.length} saved, max ${d.max_per_router || 50})</span></strong>
        <table style="width:100%;border-collapse:collapse;margin-top:4px">${rows}${overflow}</table>
      </div>`;
    };
    container.innerHTML = renderVendor("orbi", "Orbi RBRE960") + renderVendor("verizon", "Verizon CR1000A");
    // Render backup-staleness health (reverted scheduler 2026-05-11; backups
    // are manual now). Best-effort: health-fetch failure shouldn't break the
    // backup-list display.
    try {
      const hr = await fetch("/api/homenet/backup/health");
      const hd = await hr.json();
      const block = document.getElementById("hn-backup-scheduler-status");
      if (block) {
        const fmt = (v, stale, threshold) => {
          if (v === null || v === undefined) return `<span style="color:var(--red)">never backed up</span>`;
          const color = stale ? "var(--orange)" : "var(--green)";
          const ageStr = v < 1 ? `${(v * 24).toFixed(0)}h` : `${v.toFixed(1)}d`;
          return `<span style="color:${color}">${esc(ageStr)} old (stale at ${esc(String(threshold))}d)</span>`;
        };
        const orbiThresh = hd.orbi_stale_threshold_days || 30;
        const verizonThresh = hd.verizon_stale_threshold_days || 30;
        block.style.display = "block";
        block.innerHTML = `
          <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:baseline">
            <span style="color:var(--cyan);font-weight:600">🗄 Backups are manual</span>
            <span><strong>Orbi:</strong> ${fmt(hd.orbi_age_days, hd.orbi_stale, orbiThresh)}</span>
            <span><strong>Verizon:</strong> ${fmt(hd.verizon_age_days, hd.verizon_stale, verizonThresh)}</span>
          </div>
          <div style="color:var(--muted);margin-top:4px">Click the Backup buttons below to open each router's admin Save/Restore page in a new tab. Both vendors require manual interaction -- Orbi RBRE960 rejects the documented SOAP backup endpoint, and Verizon's SPA needs browser-side auth.</div>
        `;
      }
    } catch (e) {
      // Don't bubble -- the main backup-list rendering above is what matters
    }
    // Show the actual resolved BACKUPS_DIR so the user knows where files
    // land. Defaults to ~/OneDrive/WinDesktopMgr/backup; overridable via
    // WINDESKTOPMGR_BACKUP_DIR env var.
    const helper = document.getElementById("hn-backup-helper-text");
    if (helper && d.backup_dir) {
      helper.innerHTML = `
        Backups saved to <code>${esc(d.backup_dir)}</code> (capped at ${d.max_per_router || 50} files per router; oldest pruned automatically).
        For Verizon, the admin Save/Restore page opens in a new tab; your browser downloads the file. To track Verizon backups in this list, drop the downloaded files into the <code>verizon/</code> subfolder manually.
        Override the location by setting the <code>WINDESKTOPMGR_BACKUP_DIR</code> environment variable before starting WinDesktopMgr.
      `;
    }
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-size:11px">Error: ${esc(e && e.message || e)}</div>`;
  }
}

async function hnRunBackup(vendor, displayName) {
  const status = document.getElementById("hn-backup-status");
  const btn = document.getElementById(`hn-backup-${vendor}-btn`);
  const setStatus = (msg, color) => {
    if (status) {
      status.textContent = msg;
      status.style.color = color || "var(--muted)";
    }
  };
  if (btn) btn.disabled = true;
  setStatus(`Backing up ${displayName}…`);
  try {
    const r = await fetch(`/api/homenet/backup/${encodeURIComponent(vendor)}`, {method: "POST"});
    const d = await r.json();
    if (d.mode === "downloaded" && d.ok) {
      const kb = ((d.bytes || 0) / 1024).toFixed(1);
      setStatus(`✓ Saved ${esc(d.filename)} (${kb} KB) to backups/${vendor}/`, "var(--green)");
      hnLoadBackupList();
    } else if (d.mode === "deep-link" && d.url) {
      window.open(d.url, "_blank", "noopener,noreferrer");
      setStatus("✓ Opened admin UI -- click Save in the Verizon admin to download the config file.", "var(--green)");
    } else if (d.mode === "needs-fallback" && d.fallback_url) {
      const wantsFallback = confirm(
        `Orbi API backup failed:\n\n${d.error}\n\nOpen the Orbi admin in a new tab to download manually?`
      );
      if (wantsFallback) {
        window.open(d.fallback_url, "_blank", "noopener,noreferrer");
        setStatus("Opened Orbi admin -- find the Backup option in Settings.", "var(--orange)");
      } else {
        setStatus(`Backup cancelled. ${d.error}`, "var(--orange)");
      }
    } else {
      setStatus(`Backup failed: ${esc(d.error || "unknown error")}`, "var(--red)");
    }
  } catch (e) {
    setStatus(`Network error: ${esc(e && e.message || e)}`, "var(--red)");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function homenetScan() {
  const btn = document.getElementById("hn-scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  document.getElementById("hn-errors").style.display = "none";
  try {
    const r = await fetch("/api/homenet/scan", {method: "POST"});
    const data = await r.json();
    if (data.errors && data.errors.length) {
      const errDiv = document.getElementById("hn-errors");
      errDiv.style.display = "block";
      errDiv.textContent = data.errors.join(" | ");
    }
    _hnUpdateUI(data);
  } catch(e) {
    console.error("scan error:", e);
    document.getElementById("hn-errors").style.display = "block";
    document.getElementById("hn-errors").textContent = "Scan failed: " + e.message;
  }
  btn.disabled = false;
  btn.textContent = "🔍 Scan Network";
}

async function homenetResolveNames() {
  const btn = document.getElementById("hn-resolve-btn");
  btn.disabled = true;
  btn.textContent = "Resolving…";
  try {
    const r = await fetch("/api/homenet/resolve-names", {method: "POST"});
    const data = await r.json();
    if (data.ok) {
      _hnUpdateUI(data);
      const msg = data.resolved > 0
        ? `Resolved ${data.resolved} new name(s). ${data.total_named}/${data.total_devices} devices named.`
        : `No new names found. ${data.total_named}/${data.total_devices} devices already named.`;
      alert(msg);
    }
  } catch(e) {
    console.error("resolve error:", e);
    alert("Name resolution failed: " + e.message);
  }
  btn.disabled = false;
  btn.textContent = "🏷 Resolve Names";
}

// ── Credential management ───
function openCredModal(key, label) {
  document.getElementById("hn-cred-key").value = key;
  document.getElementById("hn-cred-title").textContent = "Credentials — " + label;
  const userLabel = document.querySelector('label[for="hn-cred-user"]') || document.getElementById("hn-cred-user").previousElementSibling;
  const passLabel = document.querySelector('label[for="hn-cred-pass"]') || document.getElementById("hn-cred-pass").previousElementSibling;
  // Show/hide Orbi SSID field
  const ssidRow = document.getElementById("hn-cred-ssid-row");
  // Toggle the TP-Link SNMP help block: visible only for tplink_switch.
  const tplinkHelp = document.getElementById("hn-cred-tplink-help");
  if (tplinkHelp) tplinkHelp.style.display = (key === "tplink_switch") ? "" : "none";
  if (key === "tplink_switch") {
    // For SNMP: username = switch IP, password = community string
    document.getElementById("hn-cred-user").value = "auto";
    document.getElementById("hn-cred-user").placeholder = "Switch IP or 'auto' (finds via MAC)";
    document.getElementById("hn-cred-pass").placeholder = "SNMP community string (default: public)";
    if (userLabel) userLabel.textContent = "Switch IP Address";
    if (passLabel) passLabel.textContent = "SNMP Community String";
    if (ssidRow) ssidRow.style.display = "none";
  } else if (key === "orbi") {
    document.getElementById("hn-cred-user").value = "admin";
    document.getElementById("hn-cred-user").placeholder = "";
    document.getElementById("hn-cred-pass").placeholder = "";
    if (userLabel) userLabel.textContent = "Username";
    if (passLabel) passLabel.textContent = "Password";
    if (ssidRow) ssidRow.style.display = "block";
    document.getElementById("hn-cred-ssid").value = "";
  } else {
    document.getElementById("hn-cred-user").value = "admin";
    document.getElementById("hn-cred-user").placeholder = "";
    document.getElementById("hn-cred-pass").placeholder = "";
    if (userLabel) userLabel.textContent = "Username";
    if (passLabel) passLabel.textContent = "Password";
    if (ssidRow) ssidRow.style.display = "none";
  }
  document.getElementById("hn-cred-pass").value = "";
  document.getElementById("hn-cred-status").style.display = "none";
  document.getElementById("hn-cred-modal").style.display = "flex";
}

function closeCredModal() {
  document.getElementById("hn-cred-modal").style.display = "none";
}

async function saveCredential() {
  const key = document.getElementById("hn-cred-key").value;
  const user = document.getElementById("hn-cred-user").value;
  const pass = document.getElementById("hn-cred-pass").value;
  if (!pass) { alert("Password is required"); return; }
  const payload = {device_key: key, username: user, password: pass};
  if (key === "orbi") {
    const ssid = document.getElementById("hn-cred-ssid").value.trim();
    if (ssid) payload.orbi_ssid = ssid;
  }
  const r = await fetch("/api/homenet/credentials/save", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  const data = await r.json();
  if (data.ok) {
    closeCredModal();
    loadHomeNet();
  } else {
    const s = document.getElementById("hn-cred-status");
    s.style.display = "block";
    s.style.background = "var(--red-dim)";
    s.style.color = "var(--red)";
    s.textContent = data.message;
  }
}

async function testCredential() {
  const key = document.getElementById("hn-cred-key").value;
  // Save first, then test
  const user = document.getElementById("hn-cred-user").value;
  const pass = document.getElementById("hn-cred-pass").value;
  if (!pass) { alert("Password is required"); return; }
  await fetch("/api/homenet/credentials/save", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key, username: user, password: pass})
  });
  const s = document.getElementById("hn-cred-status");
  s.style.display = "block";
  s.style.background = "var(--cyan-dim)";
  s.style.color = "var(--cyan)";
  s.textContent = "Testing connection…";
  const r = await fetch("/api/homenet/credentials/test", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  const data = await r.json();
  s.style.background = data.ok ? "var(--green-dim)" : "var(--red-dim)";
  s.style.color = data.ok ? "var(--green)" : "var(--red)";
  s.textContent = data.message;
}

async function testCredentialDirect(key) {
  const r = await fetch("/api/homenet/credentials/test", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  const data = await r.json();
  alert(data.ok ? "✓ " + data.message : "✗ " + data.message);
}

async function deleteCredential(key) {
  if (!confirm("Delete stored credentials for this device?")) return;
  await fetch("/api/homenet/credentials/delete", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  loadHomeNet();
}

// ── Device edit modal ───
function openEditModal(mac) {
  const dev = _hnDevices.find(d => d.mac === mac);
  if (!dev) return;
  document.getElementById("hn-edit-mac").value = mac;
  document.getElementById("hn-edit-title").textContent = "Edit — " + (dev.friendly_name || dev.hostname || dev.ip);
  document.getElementById("hn-edit-name").value = dev.friendly_name || "";
  document.getElementById("hn-edit-category").value = dev.category || "";
  document.getElementById("hn-edit-location").value = dev.location || "";
  document.getElementById("hn-edit-notes").value = dev.notes || "";
  // DNS Hostname (#7): always populated from the inventory's router-sourced
  // value. Falls back to "(none yet)" when no router has reported it -- happens
  // for ARP-only devices and manually-added entries. Status line clears on
  // every open so leftover messages from a previous edit don't confuse.
  const dnsEl = document.getElementById("hn-edit-dns-hostname");
  if (dnsEl) dnsEl.value = dev.dns_hostname || "(none yet — click 🔄 to pull)";
  const dnsStatus = document.getElementById("hn-edit-dns-status");
  if (dnsStatus) dnsStatus.textContent = "";
  // wired_via: only meaningful for wired devices. The dropdown is always
  // visible to keep modal layout stable, but for wireless devices the
  // value is ignored by the topology classifier.
  const viaEl = document.getElementById("hn-edit-wired-via");
  if (viaEl) viaEl.value = dev.wired_via || "";
  // behind_moca_bridge dropdown: rebuild every open so newly-added bridges
  // surface without page reload. Filters out the device being edited (a
  // bridge can't be its own parent).
  const behindEl = document.getElementById("hn-edit-behind-moca");
  if (behindEl) {
    const bridges = _hnDevices.filter(d => {
      const isBridge = (d.wired_via || "").toLowerCase() === "moca_bridge"
        || _isMocaVendor(d.vendor || "");
      return isBridge && d.mac !== mac;  // exclude self
    });
    // Sort by friendly_name/hostname for predictable ordering
    bridges.sort((a, b) => {
      const na = (a.friendly_name || a.hostname || a.mac || "").toLowerCase();
      const nb = (b.friendly_name || b.hostname || b.mac || "").toLowerCase();
      return na.localeCompare(nb);
    });
    behindEl.innerHTML = '<option value="">— Not behind any bridge —</option>'
      + bridges.map(b => {
          const label = (b.friendly_name || b.hostname || b.mac);
          return `<option value="${esc(b.mac)}">📻 ${esc(label)}</option>`;
        }).join("");
    behindEl.value = dev.behind_moca_bridge || "";
  }
  // Via Orbi satellite dropdown: list every device the user has attested
  // as wired_via='orbi_satellite' (2026-05-13 manual-attestation path,
  // see homenet.py). Excludes self so a satellite can't be its own parent.
  const viaSatEl = document.getElementById("hn-edit-via-orbi-satellite");
  if (viaSatEl) {
    const sats = _hnDevices.filter(d =>
      (d.wired_via || "").toLowerCase() === "orbi_satellite" && d.mac !== mac
    );
    sats.sort((a, b) => {
      const na = (a.friendly_name || a.hostname || a.mac || "").toLowerCase();
      const nb = (b.friendly_name || b.hostname || b.mac || "").toLowerCase();
      return na.localeCompare(nb);
    });
    viaSatEl.innerHTML = '<option value="">— Not on a satellite (base or unknown) —</option>'
      + sats.map(s => {
          const label = (s.friendly_name || s.hostname || s.mac);
          return `<option value="${esc(s.mac)}">📡 ${esc(label)}</option>`;
        }).join("");
    viaSatEl.value = dev.via_orbi_satellite || "";
  }
  document.getElementById("hn-edit-modal").style.display = "flex";
}

// Mirror of homenet.py _ETHERNET_MOCA_BRIDGE_VENDORS -- kept in sync manually.
// Used by the edit modal's "Behind MoCA bridge" parent dropdown to filter
// devices that could plausibly be bridges. Bug 2026-05-12: Commscope/Arris
// removed because they're Verizon FiOS STBs (MoCA endpoints, not bridges).
// A user who really has a Commscope/Arris bridge can still tag it
// explicitly via wired_via=moca_bridge in the same modal -- once tagged,
// the dropdown picks it up via the wired_via check, not vendor.
function _isMocaVendor(vendor) {
  const v = (vendor || "").toLowerCase();
  if (!v) return false;
  return ["actiontec", "askey", "gocoax", "hitron",
          "motorola mobility", "screenbeam", "westell"]
         .some(p => v.includes(p));
}

function closeEditModal() {
  document.getElementById("hn-edit-modal").style.display = "none";
}

// ── DNS hostname helpers (#7, Path A) ───
// Pick the right router admin URL for a given device. Wireless devices
// (10.x IPs) live in the Orbi admin; everything else in the Verizon admin.
// Both pages list connected devices -- the user can scroll/Ctrl-F for the
// MAC and rename in-place. We can't deep-link to a specific row because
// neither admin UI supports MAC-anchored routes.
function _routerAdminUrlForDevice(dev) {
  if (!dev) return null;
  const ip = String(dev.ip || "");
  // Orbi RBRE960 admin is HTTPS on 10.0.0.1 with a self-signed cert. The
  // /DEV_devices.htm page is the connected-devices view in stock firmware.
  if (ip.startsWith("10.")) return "https://10.0.0.1/DEV_devices.htm";
  // Verizon CR1000A is the default. Hash-route /#/devices opens the
  // Connected Devices view in the Vue SPA.
  return "http://192.168.1.1/#/devices";
}

function openRouterAdminForDevice() {
  const mac = document.getElementById("hn-edit-mac").value;
  const dev = _hnDevices.find(d => d.mac === mac);
  if (!dev) return;
  const url = _routerAdminUrlForDevice(dev);
  if (!url) {
    alert("No router admin URL for this device.");
    return;
  }
  // window.open with no opener so the admin page can't tamper with our tab.
  // The user is leaving WinDesktopMgr to rename the device in the router,
  // then returns to click 🔄 to pull the new name back.
  const w = window.open(url, "_blank", "noopener,noreferrer");
  const status = document.getElementById("hn-edit-dns-status");
  if (status) {
    if (w) {
      status.textContent = `Opened ${url} -- after renaming, click 🔄 to refresh`;
      status.style.color = "var(--cyan)";
    } else {
      // Pop-up blocked. Hand the user the URL so they can copy-paste.
      status.textContent = `Pop-up blocked. Open: ${url}`;
      status.style.color = "var(--warning, #ffc107)";
    }
  }
}

async function pullDnsHostnameFromRouter() {
  const mac = document.getElementById("hn-edit-mac").value;
  if (!mac) return;
  const status = document.getElementById("hn-edit-dns-status");
  const dnsEl  = document.getElementById("hn-edit-dns-hostname");
  const btn    = document.getElementById("hn-edit-dns-pull");
  if (status) {
    status.textContent = "Pulling from routers…";
    status.style.color = "var(--muted)";
  }
  if (btn) btn.disabled = true;
  try {
    const r = await fetch("/api/homenet/device/rescan-hostname", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({mac: mac})
    });
    const data = await r.json();
    if (data.ok && data.dns_hostname) {
      if (dnsEl) dnsEl.value = data.dns_hostname;
      if (status) {
        const src = data.source ? ` (from ${data.source})` : "";
        status.textContent = `Pulled "${data.dns_hostname}"${src}`;
        status.style.color = "var(--success, #28a745)";
      }
      // Refresh the inventory cache so the device table reflects the new
      // name without forcing the user to close and reopen the tab.
      const idx = _hnDevices.findIndex(d => d.mac === mac);
      if (idx >= 0) {
        _hnDevices[idx].dns_hostname = data.dns_hostname;
        _hnDevices[idx].hostname = data.dns_hostname;
      }
    } else {
      if (status) {
        status.textContent = data.message || "No router-side hostname found";
        status.style.color = "var(--warning, #ffc107)";
      }
    }
  } catch (e) {
    if (status) {
      status.textContent = "Error: " + (e && e.message || e);
      status.style.color = "var(--danger, #dc3545)";
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function saveDeviceEdit() {
  const mac = document.getElementById("hn-edit-mac").value;
  const r = await fetch("/api/homenet/device/update", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mac: mac,
      friendly_name: document.getElementById("hn-edit-name").value,
      category: document.getElementById("hn-edit-category").value,
      location: document.getElementById("hn-edit-location").value,
      notes: document.getElementById("hn-edit-notes").value,
      wired_via: document.getElementById("hn-edit-wired-via").value,
      behind_moca_bridge: document.getElementById("hn-edit-behind-moca").value,
      via_orbi_satellite: (document.getElementById("hn-edit-via-orbi-satellite") || {}).value || ""
    })
  });
  const data = await r.json();
  if (data.ok) {
    closeEditModal();
    _tabLoaded["homenet"] = false;
    loadHomeNet();
    // Auto-refresh the topology if it's currently visible. User feedback
    // 2026-04-25: "if i manually move a device to the TP-link switch it
    // should automatically appear under that and not wait for a refresh."
    // Same for satellite naming, wired_via=moca, friendly_name changes,
    // etc. -- any inventory edit can affect the topology so we
    // unconditionally re-render when the user has the diagram open.
    const topoBody = document.getElementById("hn-topo-body");
    if (topoBody && topoBody.style.display !== "none") {
      _hnTopoLoaded = false;
      hnTopoRefresh().then(() => { _hnTopoLoaded = true; });
    }
  } else {
    alert("Save failed: " + data.message);
  }
}

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
  const events = (cluster.events || []).map(ev => ({
    category: ev.category,
    key: ev.key,
    kind: ev.kind,
    // current_value is omitted -- the slow-path accept_drift_entry call
    // re-snapshots to discover the value. Adds latency but keeps the
    // payload small + avoids stale-data bugs.
    current_value: null,
  }));
  if (!events.length) { alert("Cluster has no events."); return; }
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
  subtitle.textContent = `Cluster window: ${win} s · ${clusters} cluster(s), ${lone} lone event(s)`;
  // Render newest-first (API already returns that order).
  const html = items.map(it => {
    if (it.type === "cluster") {
      const color = sevColor[it.severity] || sevColor.info;
      const catLabel = (it.categories || []).join(", ");
      const span = it.span_seconds;
      const spanLabel = span >= 1 ? `${Math.round(span)} s` : "simultaneous";
      const headLine = `${it.event_count || 0} events across ${(it.categories || []).length} categories in ${spanLabel}`;
      const startedAt = it.started_at ? new Date(it.started_at).toLocaleString() : "—";
      const eventRows = (it.events || []).map(ev => `
        <div style="padding:4px 8px;border-left:2px solid ${color};margin:2px 0 2px 14px;font-size:11px;color:var(--text)">
          <span style="color:var(--muted);font-family:var(--font-mono);font-size:10px">${escHtml(ev.timestamp || "")}</span>
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
        <div style="margin:8px 0;padding:8px 10px;background:var(--surface);border:1px solid ${color};border-left:4px solid ${color};border-radius:6px">
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
            <button onclick="bl_acceptCluster(${idx})" style="background:var(--cyan);border:none;color:#000;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">✓ Accept all ${it.event_count || 0}</button>
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
  const errLine = result.error ? `<div style="color:var(--red);font-size:11px;margin-top:4px">Error: ${escHtml(result.error)}</div>` : "";
  const runLine = result.run && result.run.elapsed_seconds ? `<div style="color:var(--muted);font-size:10px;margin-top:2px">subprocess elapsed: ${result.run.elapsed_seconds}s, rc=${result.run.returncode}</div>` : "";
  overall.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">${icon}</span>
      <div style="flex:1">
        <div style="font-weight:700;font-size:12px;color:var(--text-bright)">${escHtml(label)}: ${ok ? "completed" : "failed"}</div>
        ${errLine}
        ${runLine}
      </div>
    </div>`;
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
  if (result.ok) loadBackup();
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
  if (result.ok) loadBackup();
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
  const overall = document.getElementById("bk-overall");
  if (overall) {
    overall.style.display = "block";
    overall.style.borderLeftColor = "var(--cyan)";
    overall.innerHTML = `<div style="font-size:12px">⏳ Running fhmanagew -cleanup ${days} (UAC prompt should appear)...</div>`;
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
  const status = await bk_pollUntilDone(launch.session_id);
  const result = (status && status.result) || {ok: false, error: "no result"};
  bk_showActionResult(`File History cleanup (${days}d)`, result, !!result.ok);
  if (result.ok) loadBackup();
}

async function loadBackup() {
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
  if (overall && summary && summary.overall_health) {
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
      const storeExistsLabel = fh.target_backup_store_exists === null
        ? "—"
        : (fh.target_backup_store_exists ? '<span style="color:var(--green)">present</span>' : '<span style="color:var(--red)">missing</span>');
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
          <div style="display:grid;grid-template-columns:140px 1fr;gap:6px 16px;font-size:12px">
            <div style="color:var(--muted)">Status</div><div>${enabled}</div>
            <div style="color:var(--muted)">Target</div><div>${escHtml(target.name || "—")} · <code>${escHtml(target.url || "")}</code> (${escHtml(target.drive_type || "—")})</div>
            <div style="color:var(--muted)">Target reachable</div><div>${targetExistsLabel}</div>
            <div style="color:var(--muted)">Backup store on target</div><div>${storeExistsLabel} (<code>${escHtml(target.backup_store_path || "")}</code>)</div>
            <div style="color:var(--muted)">Frequency</div><div>${cfg.frequency_seconds ? Math.round(cfg.frequency_seconds / 60) + " min" : "—"}</div>
            <div style="color:var(--muted)">Retention</div><div>${escHtml(cfg.retention_policy || "—")}${cfg.retention_min_age_months ? ` · keep at least ${cfg.retention_min_age_months} mo` : ""}</div>
            <div style="color:var(--muted)">Catalog</div><div>${catalogLabel}</div>
            <div style="color:var(--muted)">Staging</div><div>${bk_humanBytes(fh.staging_usage_bytes)} across ${fh.staging_file_count} file(s)${stagingRatio}</div>
            <div style="color:var(--muted)">Folders watched</div><div>${folderCount} folder(s) across ${(cfg.libraries || []).length} libraries + ${(cfg.user_folders || []).length} user folders</div>
          </div>
          <div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px">
            <div style="font-size:11px;color:var(--muted)">Cleanup runs <code>fhmanagew.exe -cleanup &lt;days&gt;</code> under UAC. <strong>0</strong> = keep only newest.</div>
            <button onclick="bk_fhCleanup()" style="background:transparent;border:1px solid var(--orange);color:var(--orange);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:11px">🧹 Cleanup old versions</button>
          </div>
        </div>`;
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

// ══════════════════════════════════════════════════════════════════════════
// UTILITIES TAB (backlog #51) — Quick Fixes + code-health scans
//
// All function names prefixed `util_*` to keep out of global-scope
// collisions (see the tab-prefix convention in CLAUDE.md).
// ══════════════════════════════════════════════════════════════════════════

let _utilPollTimer = null;

async function util_load() {
  await Promise.all([
    util_loadQuickFixes(),
    util_loadCodeHealth(),
  ]);
}

async function util_loadQuickFixes() {
  // Mirror of the original Dashboard renderer (removed from
  // loadDashboard above; this is now the single source of truth).
  const target = document.getElementById("util-qf-cards");
  if (!target) return;
  try {
    const r = await fetch("/api/remediation/actions");
    const actions = await r.json();
    const rc = r=>r==="high"?"var(--red)":r==="medium"?"var(--orange)":"var(--green)";
    const rb = r=>r==="high"?"rgba(255,71,87,.22)":r==="medium"?"rgba(255,112,67,.22)":"rgba(0,229,160,.22)";
    target.innerHTML = (actions || []).map(a=>`
      <button onclick="runRemediationFromDashboard('${esc(a.id)}')"
        style="background:var(--card);border:1px solid var(--border);border-radius:8px;
        padding:10px 8px;cursor:pointer;text-align:center;transition:border-color .15s;position:relative"
        onmouseover="this.style.borderColor='${rc(a.risk)}'"
        onmouseout="this.style.borderColor='var(--border)'" title="${esc(a.description)}">
        <div style="font-size:16px;margin-bottom:4px">${esc(a.icon)}</div>
        <div style="font-size:11px;color:var(--text-bright);font-family:var(--font-mono);font-weight:500;line-height:1.3;margin-bottom:6px">${esc(a.label)}</div>
        <span style="font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;
          color:${rc(a.risk)};background:${rb(a.risk)};
          border:1px solid ${rc(a.risk)};padding:2px 7px;border-radius:8px">${a.risk}</span>
      </button>`).join("");
  } catch {
    target.innerHTML = `<div style="color:var(--muted);padding:10px;grid-column:1/-1">Quick Fixes unavailable.</div>`;
  }
}

function util_levelColor(level) {
  return level === "critical" ? "var(--red)"
       : level === "warning"  ? "var(--orange)"
       : level === "info"     ? "var(--cyan)"
       : "var(--green)";
}

function util_renderScannerCard(name, label, icon, result, opts) {
  const status = result.ok ? result.summary : (result.error || "Scanner unavailable");
  const color = util_levelColor(result.level || "ok");
  const dur = result.duration_ms != null ? `${(result.duration_ms / 1000).toFixed(1)}s` : "—";
  const ts = result.finished_at ? new Date(result.finished_at).toLocaleString() : "never";
  // Per-card extra controls. PR-2 of #51 ships a Refresh button for
  // the coverage card so the user can trigger a fresh pytest --cov
  // run from the UI when .coverage gets stale (the 2026-05-27 bug).
  const extraControl = (opts && opts.extraControl) || "";
  const detailsBlock = util_renderScannerDetails(name, result);
  return `
    <div data-scanner="${esc(name)}" style="background:var(--card);border:1px solid var(--border);border-left:3px solid ${color};
                border-radius:8px;padding:14px 16px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:18px">${icon}</span>
        <div style="flex:1;font-size:12px;font-weight:700;color:var(--text-bright)">${esc(label)}</div>
        <span style="font-size:9px;text-transform:uppercase;font-weight:800;letter-spacing:.04em;
                     color:${color};border:1px solid ${color};padding:2px 7px;border-radius:8px">${esc(result.level || "?")}</span>
      </div>
      <div style="font-size:12px;color:var(--text);line-height:1.4;margin-bottom:6px">${esc(status)}</div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:10px;color:var(--muted);font-family:var(--font-mono)">
        <span>${esc(ts)} · ${esc(dur)}</span>
        ${extraControl}
      </div>
      ${detailsBlock}
    </div>`;
}

function util_renderScannerDetails(name, result) {
  // Build the expandable "ⓘ N details" disclosure for a scanner card.
  // Each scanner stores its findings in result.details with a DIFFERENT
  // shape, so we branch per scanner:
  //   coverage  -> list of {file, percent}     (lowest-coverage files)
  //   ruff      -> list of {code, message, file, line}  (top findings)
  //   secrets   -> always [] (redacted); we surface a count-only note
  //   tech_debt -> DICT {todos:[{file,line,text}], large_files:[{file,lines}]}
  // Returns "" when there's nothing useful to show (clean scanner), so
  // the card stays compact. Native <details> = no JS state to wire and
  // it survives the poll re-render cleanly (collapsed default).
  const d = result.details;
  const rows = [];
  let count = 0;

  if (name === "tech_debt" && d && !Array.isArray(d)) {
    const large = d.large_files || [];
    const todos = d.todos || [];
    count = large.length + todos.length;
    if (large.length) {
      rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Oversized files (≥5,000 lines)</div>`);
      large.forEach(f => rows.push(
        `<div>${esc(f.file || "?")} · <span style="color:var(--orange)">${Number(f.lines || 0).toLocaleString()} lines</span></div>`
      ));
    }
    if (todos.length) {
      rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:8px 0 2px">TODO / FIXME markers</div>`);
      todos.forEach(t => rows.push(
        `<div>${esc(t.file || "?")}:${esc(String(t.line ?? ""))} · <span style="color:var(--muted)">${esc((t.text || "").slice(0, 90))}</span></div>`
      ));
    }
  } else if (name === "coverage" && Array.isArray(d) && d.length) {
    count = d.length;
    rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Lowest-coverage files</div>`);
    d.forEach(f => rows.push(
      `<div>${esc(f.file || "?")} · <span style="color:${Number(f.percent || 0) < 50 ? 'var(--red)' : 'var(--orange)'}">${Number(f.percent || 0).toFixed(1)}%</span></div>`
    ));
  } else if (name === "ruff" && Array.isArray(d) && d.length) {
    count = d.length;
    rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Top findings</div>`);
    d.forEach(f => rows.push(
      `<div><span style="color:var(--orange)">${esc(f.code || "?")}</span> ${esc(f.file || "")}:${esc(String(f.line ?? ""))} · <span style="color:var(--muted)">${esc((f.message || "").slice(0, 90))}</span></div>`
    ));
  } else if (name === "secrets" && Number(result.count || 0) > 0) {
    count = Number(result.count);
    rows.push(`<div style="color:var(--muted)">${count} potential match${count !== 1 ? 'es' : ''} — output redacted for security. See docs/security/git-credentials.md.</div>`);
  }

  if (!rows.length) return "";
  return `
      <details data-scanner-details="${esc(name)}" data-detail-count="${count}" style="margin-top:8px">
        <summary style="cursor:pointer;color:var(--cyan);font-size:10px;font-family:var(--font-mono);user-select:none;list-style:none">ⓘ ${count} detail${count !== 1 ? 's' : ''}</summary>
        <div style="margin-top:6px;font-size:11px;color:var(--text);line-height:1.5;font-family:var(--font-mono);max-height:240px;overflow:auto;word-break:break-word">
          ${rows.join("")}
        </div>
      </details>`;
}

async function util_loadCodeHealth(opts) {
  const fromPoll = opts && opts.fromPoll;
  const lastSpan = document.getElementById("util-last-scan");
  const grid     = document.getElementById("util-ch-grid");
  const empty    = document.getElementById("util-ch-empty");
  const btn      = document.getElementById("util-scan-btn");
  if (!grid) return;
  let payload;
  try {
    const r = await fetch("/api/codehealth/status");
    payload = await r.json();
  } catch (e) {
    grid.innerHTML = `<div style="color:var(--red);grid-column:1/-1;padding:10px">Failed to load: ${esc(e.message)}</div>`;
    return;
  }
  const state    = payload.state || {};
  const scanners = state.scanners || {};
  const running  = payload.is_running;
  const refreshingCov = payload.is_refreshing_coverage;
  const stale    = payload.is_stale;
  const finished = state.finished_at;
  const hasResults = scanners && Object.keys(scanners).length > 0;

  // Header line + Scan-now button state.
  // Either a scan OR a coverage refresh keeps the spinner running.
  // A coverage refresh ends with an automatic scan_all so the
  // running flag flips through both phases.
  const anyInFlight = running || refreshingCov;
  if (anyInFlight) {
    if (lastSpan) {
      lastSpan.textContent = refreshingCov
        ? "Running pytest --cov (~60s)…"
        : "Scan in progress…";
    }
    if (btn) { btn.disabled = true; btn.textContent = refreshingCov ? "Refreshing coverage…" : "Scanning…"; }
    // Auto-poll every 1.5s while in flight.
    if (!_utilPollTimer) {
      _utilPollTimer = setInterval(() => util_loadCodeHealth({fromPoll: true}), 1500);
    }
  } else {
    if (lastSpan) {
      if (!finished) {
        lastSpan.textContent = "Never scanned";
      } else {
        const ts = new Date(finished).toLocaleString();
        const tag = stale ? " (stale)" : "";
        lastSpan.textContent = `Last scan: ${ts}${tag}`;
        lastSpan.style.color = stale ? "var(--orange)" : "var(--muted)";
      }
    }
    if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
    if (_utilPollTimer) { clearInterval(_utilPollTimer); _utilPollTimer = null; }
  }

  // Surface the last refresh error inline if it failed (the user
  // clicked Refresh and pytest blew up). Done above the cards.
  const refLast = payload.coverage_refresh_last_result;
  let refreshErrorBanner = "";
  if (refLast && !refLast.ok && !refreshingCov) {
    const tail = (refLast.stderr_tail || refLast.stdout_tail || "").slice(-300);
    refreshErrorBanner = `<div style="grid-column:1/-1;background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.4);
                          border-radius:6px;padding:8px 12px;margin-bottom:8px;font-size:11px;color:var(--text)">
        ⚠ Last coverage refresh failed: ${esc(refLast.error || "pytest returned " + refLast.returncode)}
        ${tail ? `<details style="margin-top:6px"><summary style="cursor:pointer;color:var(--muted)">tail</summary>
          <pre style="font-size:10px;color:var(--muted);white-space:pre-wrap;margin:4px 0 0">${esc(tail)}</pre></details>` : ""}
      </div>`;
  }

  if (!hasResults) {
    grid.style.display = "none";
    if (empty) empty.style.display = anyInFlight ? "none" : "";
    return;
  }
  grid.style.display = "grid";
  if (empty) empty.style.display = "none";

  // Card label + icon per scanner. Cards are rendered by iterating the
  // API's scanner_names (extensible: a new backend scanner auto-renders
  // here, falling back to a humanised label + 🔧 if it's not in the map).
  const SCANNER_META = {
    coverage:  ["Test Coverage",     "🧪"],
    ruff:      ["Code Bugs (ruff)",  "🪲"],
    secrets:   ["Security / Secrets","🔒"],
    tech_debt: ["Tech Debt",         "🧹"],
  };
  // Drive the card order off the registry the API reports; fall back to
  // whatever keys the scan result carries (older state without the field).
  const order = (payload.scanner_names && payload.scanner_names.length)
    ? payload.scanner_names
    : Object.keys(scanners);
  const runningScanner = payload.running_scanner;

  const cards = order.map(name => {
    const [label, icon] = SCANNER_META[name] || [util_humanise(name), "🔧"];
    let extraControl;
    if (name === "coverage") {
      // Coverage's per-card action is the expensive pytest --cov refresh
      // (re-reading the same .coverage yields the same number), kept on
      // its own endpoint. (PR-2 of #51, fixes the 2026-05-27 stale bug.)
      extraControl = refreshingCov
        ? `<span style="color:var(--cyan)">refreshing…</span>`
        : `<button onclick="util_refreshCoverage()"
                    style="background:transparent;border:1px solid var(--border);color:var(--cyan);
                           padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:var(--font-mono)"
                    title="Re-runs pytest --cov to refresh the .coverage file (~60s)">↻ Refresh</button>`;
    } else {
      // Cheap scanners get a per-card "↻ Run" that re-runs only this
      // scanner. Disabled (shows "running…") while any scan is in flight;
      // the card whose scanner is active gets the explicit spinner.
      extraControl = (runningScanner === name)
        ? `<span style="color:var(--cyan)">running…</span>`
        : `<button onclick="util_runScanner('${name}')" ${anyInFlight ? "disabled" : ""}
                    style="background:transparent;border:1px solid var(--border);
                           color:${anyInFlight ? "var(--muted)" : "var(--cyan)"};
                           padding:2px 8px;border-radius:4px;cursor:${anyInFlight ? "default" : "pointer"};
                           font-size:10px;font-family:var(--font-mono)"
                    title="Re-run just this scanner">↻ Run</button>`;
    }
    return [name, label, icon, scanners[name] || {}, {extraControl}];
  });
  grid.innerHTML = refreshErrorBanner + cards.map(([_, label, icon, r, opts]) =>
    util_renderScannerCard(_, label, icon, r, opts)
  ).join("");
}

function util_copyCmd(cmd, btn) {
  // Copy a slash command to clipboard. Both code-review and code-
  // simplifier are Claude Code skills -- the tray can't invoke them,
  // so the right UX is "make it one click to paste into a Claude
  // session" rather than a button that does nothing useful.
  //
  // Unified promise chain handles BOTH error paths (code-review
  // finding 2026-05-28): synchronous TypeError when
  // navigator.clipboard is undefined on an older browser AND async
  // rejections from writeText (permission denied / unfocused doc).
  // The previous try/catch only caught the sync case.
  Promise.resolve()
    .then(() => navigator.clipboard.writeText(cmd))
    .then(() => {
      const orig = btn.textContent;
      btn.textContent = "✓ Copied";
      btn.style.color = "var(--green)";
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.color = "var(--muted)";
      }, 1500);
    })
    .catch(e => {
      alert("Couldn't copy to clipboard: " + (e && e.message ? e.message : e));
    });
}

async function util_resetEmitted() {
  // Clears the dedup memory so the next scan re-emits all current
  // findings to the project backlog. Useful after the user has
  // hand-pruned the auto-generated rows or wants a "rebuild from
  // scratch" run.
  if (!confirm("Reset emitted-findings memory? The next scan will re-append every current finding to the project backlog (deduped against the same memory, so reruns after that won't re-add)." )) {
    return;
  }
  try {
    const r = await fetch("/api/codehealth/reset-emitted", {method:"POST"});
    if (!r.ok) {
      alert("Reset failed: " + r.status);
      return;
    }
    alert("✅ Emitted-findings memory cleared. Click ▶ Scan now to re-emit.");
  } catch (e) {
    alert("Reset failed: " + e.message);
  }
}

async function util_refreshCoverage() {
  // Re-runs pytest --cov against the primary repo so .coverage gets
  // freshened. The backend kicks off a thread; we poll status until
  // is_refreshing_coverage flips back to false, then the new % shows up.
  try {
    const r = await fetch("/api/codehealth/refresh-coverage", {method:"POST"});
    if (r.status === 409) {
      // Already running — just (re)start the poll.
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {
      const data = await r.json().catch(()=>({}));
      alert("Coverage refresh failed to start: " + (data.error || r.status));
      return;
    }
    // Re-render immediately so the spinner state shows; poll picks up
    // the rest.
    await util_loadCodeHealth();
  } catch (e) {
    alert("Coverage refresh failed to start: " + e.message);
  }
}

function util_humanise(name) {
  // "tech_debt" -> "Tech Debt". Fallback label for scanners not in
  // SCANNER_META (so a future backend scanner still renders a card).
  return String(name).replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

async function util_runScanner(name) {
  // Re-run a single scanner via POST /api/codehealth/run/<name>. Leaves
  // the other cards untouched. The status poll flips the per-card
  // spinner + the global button back when is_running clears.
  try {
    const r = await fetch("/api/codehealth/run/" + encodeURIComponent(name), {method:"POST"});
    if (r.status === 409) {            // a scan is already in flight
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {                       // 404 unknown scanner / other
      const data = await r.json().catch(()=>({}));
      alert("Couldn't run " + name + ": " + (data.error || r.status));
      return;
    }
    await util_loadCodeHealth();        // render spinner state; poll does the rest
  } catch (e) {
    alert("Couldn't run " + name + ": " + e.message);
  }
}

async function util_runScan() {
  const btn = document.getElementById("util-scan-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
  try {
    const r = await fetch("/api/codehealth/run", {method:"POST"});
    if (r.status === 409) {
      // Already running — just (re)start the poll.
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {
      const data = await r.json().catch(()=>({}));
      alert("Scan failed to start: " + (data.error || r.status));
      if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
      return;
    }
    // Kick off polling; util_loadCodeHealth flips the button back when
    // is_running flips back to false.
    await util_loadCodeHealth();
  } catch (e) {
    alert("Scan failed to start: " + e.message);
    if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
  }
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
  const safeKey = entryKey.replace(/'/g, "\\'").replace(/\\/g, "\\\\");
  const remediationHtml = `
    <div style="margin-top:8px;padding:8px 10px;background:var(--card);border:1px dashed var(--border);border-radius:4px;font-size:11px">
      <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:700;margin-bottom:4px">How to fix</div>
      <div style="color:var(--text);margin-bottom:6px">${kindExplainer}</div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0 6px">
        ${rem.console_label ? `<button onclick="blLaunchConsole('${escHtml(catKey)}', this)" style="background:var(--cyan);border:none;color:#000;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">🔧 ${escHtml(rem.console_label)}</button>` : ""}
        <button onclick="blInvestigateDrift('${escHtml(catKey)}', '${escHtml(safeKey)}', '${investigateId}', this)" style="background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:700">🔍 Why did this change?</button>
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
    <div onclick="openBaselineEntryDrilldown('${escHtml(catKey)}', '${escHtml(safeKey)}')" title="Click for full-screen detail (parameter table, investigation, history)" style="font-weight:600;font-size:12px;color:var(--text-bright);cursor:pointer;display:inline-flex;align-items:center;gap:6px" onmouseover="this.style.color='var(--cyan)'" onmouseout="this.style.color='var(--text-bright)'">${title} <span style="font-size:10px;color:var(--muted);font-weight:400">🔍</span></div>
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
  const safeKey = key.replace(/'/g, "\\'").replace(/\\/g, "\\\\");
  document.getElementById("bl-entry-modal-actions").innerHTML = `
    ${consoleLabel ? `<button onclick="blLaunchConsole('${escHtml(category)}', this)" style="background:var(--cyan);border:none;color:#000;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:700">🔧 ${escHtml(consoleLabel)}</button>` : ""}
    ${kind && kind !== "" ? `<button onclick="blAcceptThisChangeFromModal('${escHtml(category)}', '${escHtml(safeKey)}', '${escHtml(kind)}', this)" title="Update the baseline for THIS entry only" style="background:var(--green);border:none;color:#000;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:700">✓ Accept this change</button>` : ""}
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

// Local HTML-escape helper for the Baseline tab. Uses the same pattern
// as other tabs -- keeps dependency-free from window.esc helpers that
// may or may not be in scope here.
function escHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}


// ══════════════════════════════════════════════════════════════════════════
// LOGS TAB (prefix: log)
// ══════════════════════════════════════════════════════════════════════════
async function logLoad() {
  const container = document.getElementById("log-container");
  const summary = document.getElementById("log-summary");
  const level = document.getElementById("log-level").value;
  const lines = document.getElementById("log-lines").value;
  container.textContent = "Loading...";
  summary.textContent = "";
  try {
    const params = new URLSearchParams({ lines: lines });
    if (level) params.set("level", level);
    const ctrl = new AbortController();
    const timeoutId = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch("/api/logs?" + params.toString(), { signal: ctrl.signal });
    clearTimeout(timeoutId);
    const data = await resp.json();
    if (!data.ok || !data.entries) {
      container.textContent = "No log entries found.";
      return;
    }
    summary.textContent = `${data.count} entries (newest first, ${level || "all levels"})`;
    logRender(data.entries);
  } catch (e) {
    container.textContent = "Failed to load logs: " + (e && e.message ? e.message : e);
  }
}

function logDownload(fmt) {
  // Downloads always pull the full tail (max 20000), filtered by current level
  const level = document.getElementById("log-level").value;
  const params = new URLSearchParams({ format: fmt, lines: "20000" });
  if (level) params.set("level", level);
  window.location.href = "/api/logs/download?" + params.toString();
}

function logRender(entries) {
  const container = document.getElementById("log-container");
  if (!entries.length) { container.textContent = "No matching entries."; return; }
  const colors = {
    DEBUG: "#888",
    INFO: "#7ac6ff",
    WARNING: "#ffcc66",
    ERROR: "#ff6b6b",
    CRITICAL: "#ff3030",
  };
  const html = entries.map(e => {
    const color = colors[e.level] || "#ccc";
    const thread = e.thread ? `<span style="color:#555">[${esc(e.thread)}]</span> ` : "";
    const source = e.source ? `<span style="color:#5a7a9a">${esc(e.source)}</span> ` : "";
    return `<div style="margin-bottom:2px">`
         + `<span style="color:#666">${esc(e.timestamp)}</span> `
         + `<span style="color:${color};font-weight:600">${esc(e.level.padEnd(8))}</span> `
         + thread
         + `<span style="color:#9fb3c8">${esc(e.logger)}</span> `
         + source
         + `<span>${esc(e.message)}</span></div>`;
  }).join("");
  container.innerHTML = html;
}

function loadArchitecture() {
  const iframe = document.getElementById("arch-iframe");
  iframe.src = "/architecture.html";
  // Auto-resize iframe to fit content
  iframe.onload = function() {
    try {
      const h = iframe.contentDocument.documentElement.scrollHeight;
      iframe.style.height = (h + 40) + "px";
    } catch(e) {
      iframe.style.height = "2400px";
    }
  };
}

// ── System Info: Upgrade Opportunities (#43) ───
// Pure rendering function -- takes a list of opportunity records from
// summarize_upgrades() and emits cards into #si-upgrade-panel. Empty list
// hides the whole panel so the section title doesn't sit above an empty
// container. Severity controls the left-border colour:
//   ok      -> green   (informational, no action needed)
//   info    -> cyan    (an opportunity worth considering)
//   warning -> orange  (something suboptimal you can fix for free,
//                       e.g. running in single-channel mode)
//
// Optional fields rendered when present:
//   compat   -- list of {label,value} -- shown as a definition list
//               under detail. The "approved spec" answer to "what can
//               I actually buy that fits my board?"
//   caveats  -- list of strings -- shown as orange-bullet warnings
//               below detail (the "verify before spending money" notes)
//   links    -- list of {label,url} -- rendered as small link buttons
//               next to the action footer (e.g. OEM support page using
//               the Service Tag we already collected)
function siRenderUpgradePanel(opportunities) {
  const panel = document.getElementById("si-upgrade-panel");
  const body  = document.getElementById("si-upgrade-cards");
  if (!panel || !body) return;
  if (!opportunities || !opportunities.length) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "block";
  const sevColor = sev =>
    sev === "warning" ? "var(--orange)" :
    sev === "ok"      ? "var(--green)"  :
                        "var(--cyan)";
  const sevIcon = sev =>
    sev === "warning" ? "⚠" :
    sev === "ok"      ? "✓" :
                        "↑";
  const catIcon = cat =>
    cat === "memory"  ? "🧠" :
    cat === "cpu"     ? "⚡" :
    cat === "gpu"     ? "🎮" :
    cat === "nic"     ? "🌐" :
    cat === "pcie"    ? "🔧" :
    cat === "storage" ? "💾" : "🚀";
  body.innerHTML = opportunities.map(o => {
    const color = sevColor(o.severity);
    // Compat block -- definition list of approved specs (#43 follow-up
    // 2026-05-02). Two columns: cyan label, normal value. Mono font
    // keeps PartNumbers / JEDEC strings legible.
    const compatHtml = (o.compat && o.compat.length)
      ? `<div style="margin-top:8px;padding:8px 10px;background:var(--bg);border-radius:4px;font-size:11px;font-family:var(--font-mono);line-height:1.6">
          <div style="font-size:10px;color:var(--cyan);font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">Approved spec</div>
          ${o.compat.map(c => `
            <div style="display:flex;gap:8px;align-items:flex-start">
              <span style="color:var(--cyan);min-width:120px;flex-shrink:0">${esc(c.label||'')}</span>
              <span style="color:var(--text)">${esc(c.value||'')}</span>
            </div>
          `).join("")}
        </div>`
      : '';
    // Caveats -- orange ⚠ bullets so they read as "things to verify"
    // not as part of the recommendation. Renders one bullet per caveat.
    const caveatsHtml = (o.caveats && o.caveats.length)
      ? `<div style="margin-top:8px;font-size:11px;color:var(--text);line-height:1.5">
          ${o.caveats.map(c => `
            <div style="display:flex;gap:6px;align-items:flex-start;margin-top:3px">
              <span style="color:var(--orange);flex-shrink:0">⚠</span>
              <span>${esc(c)}</span>
            </div>
          `).join("")}
        </div>`
      : '';
    // Links -- shown to the right of the action so the click target is
    // visually obvious. target=_blank + rel=noopener so the OEM page
    // can't tamper with our tab.
    const linksHtml = (o.links && o.links.length)
      ? o.links.map(l =>
          `<a href="${esc(l.url||'')}" target="_blank" rel="noopener noreferrer"
              style="display:inline-block;margin-left:8px;padding:3px 10px;background:var(--cyan);color:#0d1117;border-radius:4px;font-size:11px;font-weight:600;text-decoration:none">🔗 ${esc(l.label||'')}</a>`
        ).join("")
      : '';
    return `
      <div class="upgrade-card" data-category="${esc(o.category||'')}" data-severity="${esc(o.severity||'')}"
           style="background:var(--surface);border:1px solid var(--border);border-left:4px solid ${color};
                  border-radius:8px;padding:14px 16px;margin-bottom:10px">
        <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px">
          <span style="font-size:20px">${catIcon(o.category)}</span>
          <div style="flex:1">
            <div style="font-weight:700;color:${color};font-size:14px;margin-bottom:2px">
              <span style="margin-right:6px">${sevIcon(o.severity)}</span>${esc(o.headline||'')}
            </div>
            ${o.detail ? `<div style="font-size:12px;color:var(--text);white-space:pre-wrap;line-height:1.5">${esc(o.detail)}</div>` : ''}
            ${compatHtml}
            ${caveatsHtml}
          </div>
        </div>
        ${(o.action || linksHtml) ? `<div style="margin-top:8px;padding:6px 10px;background:var(--bg);border-radius:4px;font-size:11px;color:var(--muted);font-family:var(--font-mono);display:flex;align-items:center;flex-wrap:wrap;gap:6px"><span style="flex:1"><span style="color:var(--cyan);font-weight:600">→ Action:</span> ${esc(o.action||'')}</span>${linksHtml}</div>` : ''}
      </div>
    `;
  }).join("");
}

async function loadSystemInfo() {
  document.getElementById("si-loading").style.display = "block";
  document.getElementById("si-content").style.display = "none";
  const staleBanner = document.getElementById("si-stale-banner");
  if (staleBanner) staleBanner.style.display = "none";
  try {
    const r = await fetch("/api/sysinfo/data");
    const j = await r.json();
    // Show stale/connectivity banner
    if (j.stale) {
      if (staleBanner) {
        staleBanner.style.display = "flex";
        staleBanner.querySelector(".stale-msg").textContent =
          "Data may be incomplete \u2014 " + (j.error || "collection issue");
        staleBanner.querySelector(".stale-time").textContent =
          "Attempted: " + new Date(j.collected_at).toLocaleString();
      }
    }
    // Show collected_at timestamp
    if (j.collected_at) {
      const tsEl = document.getElementById("si-collected-at");
      if (tsEl) tsEl.textContent = "Collected: " + new Date(j.collected_at).toLocaleString();
    }
    if (j.status === "ok" || j.status === "partial") {
      if (j.data && Object.keys(j.data).length > 0) {
        renderSystemInfo(j.data, j.upgrades);
        fetchSummary("sysinfo", j.data, "summary-sysinfo");
      } else {
        document.getElementById("si-loading").textContent = "No data returned.";
        return;
      }
    } else {
      document.getElementById("si-loading").textContent = "Error: " + (j.message || j.error || "Unknown");
      return;
    }
  } catch(e) {
    document.getElementById("si-loading").textContent = "Failed to load system info.";
    return;
  }
  document.getElementById("si-loading").style.display = "none";
  document.getElementById("si-content").style.display = "";
}

function renderSystemInfo(d, upgrades) {
  const comp = d.Computer || {};
  const os = d.OS || {};
  const cpu = d.CPU || {};
  const bios = d.BIOS || {};
  const bb = d.Baseboard || {};
  const gpus = d.GPU || [];
  const nics = d.Network || [];
  const nicHw = d.NetworkHardware || [];
  const ram = d.Memory || [];
  const memArrays = d.MemoryArray || [];
  const disks = d.Disks || [];
  const vols = d.Volumes || [];
  const sound = d.Sound || [];
  const usb = d.USBControllers || [];
  const slots = d.PCIeSlots || [];

  // Upgrade Opportunities panel (#43). Computed server-side by
  // summarize_upgrades() and shipped on the same response. Uses the
  // shared esc helper and `siRenderUpgradePanel` so the rendering can
  // be tested independently. Empty opportunities -> hide the panel
  // entirely so we don't waste vertical space when there's nothing
  // actionable to surface.
  siRenderUpgradePanel((upgrades && upgrades.opportunities) || []);

  // Stat cards
  document.getElementById("si-hostname").textContent = comp.Name || "\u2014";
  document.getElementById("si-os").textContent = (os.Name || "\u2014").replace("Microsoft ", "");
  document.getElementById("si-cpu-short").textContent = (cpu.Name || "\u2014").replace("Intel(R) Core(TM) ", "").replace(" Processor", "");
  document.getElementById("si-ram").textContent = (comp.TotalRAM_GB || 0) + " GB";
  document.getElementById("si-uptime").textContent = os.Uptime || "\u2014";
  document.getElementById("si-build").textContent = os.Build || "\u2014";

  // Computer section
  const compRows = [
    ["Computer Name", comp.Name], ["Domain / Workgroup", comp.Domain],
    ["Manufacturer", comp.Manufacturer], ["Model", comp.Model],
    ["System Type", comp.SystemType], ["Total RAM", comp.TotalRAM_GB + " GB"],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-comp-tbody").innerHTML = compRows;

  // OS section
  const osRows = [
    ["OS Name", os.Name], ["Version", os.Version], ["Build", os.Build],
    ["Architecture", os.Architecture], ["Install Date", os.InstallDate],
    ["Last Boot", os.LastBoot], ["Uptime", os.Uptime],
    ["Windows Directory", os.WindowsDir], ["System Drive", os.SystemDrive],
    ["Locale", os.Locale], ["Time Zone", os.TimeZone],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-os-tbody").innerHTML = osRows;

  // CPU section
  const cpuRows = [
    ["Processor", cpu.Name], ["Cores", cpu.Cores], ["Logical Processors", cpu.LogicalProcs],
    ["Max Clock", cpu.MaxClockMHz + " MHz"], ["Current Clock", cpu.CurrentClockMHz + " MHz"],
    ["Socket", cpu.SocketDesignation], ["L2 Cache", (cpu.L2CacheKB ? cpu.L2CacheKB + " KB" : "\u2014")],
    ["L3 Cache", (cpu.L3CacheKB ? Math.round(cpu.L3CacheKB/1024) + " MB" : "\u2014")],
    ["Architecture", cpu.Architecture], ["Processor ID", cpu.ProcessorId],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-cpu-tbody").innerHTML = cpuRows;

  // BIOS + Baseboard section
  const biosRows = [
    ["BIOS Version", bios.Version], ["BIOS Date", bios.ReleaseDate],
    ["BIOS Manufacturer", bios.Manufacturer], ["Serial Number (Service Tag)", bios.SerialNumber],
    ["Baseboard", bb.Manufacturer + " " + bb.Product],
    ["Baseboard Version", bb.Version], ["Baseboard Serial", bb.SerialNumber],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-bios-tbody").innerHTML = biosRows;

  // GPU section (expanded with manufacturer + PNP ID)
  const gpuHtml = gpus.map(g => {
    const vram = g.AdapterRAM ? Math.round(g.AdapterRAM / 1073741824) + " GB" : "\u2014";
    return [
      ["GPU", g.Name], ["Manufacturer", g.AdapterCompatibility], ["Driver Version", g.DriverVersion],
      ["Video RAM", vram], ["Refresh Rate", (g.CurrentRefreshRate||"\u2014") + " Hz"],
      ["Resolution", g.VideoModeDescription], ["PNP Device ID", g.PNPDeviceID],
    ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  }).join('<tr><td colspan="2" style="border-top:1px solid var(--border)"></td></tr>');
  document.getElementById("si-gpu-tbody").innerHTML = gpuHtml || '<tr><td colspan="2" style="color:var(--muted)">No GPU detected</td></tr>';

  // Memory modules (expanded with type, form factor, clock, locator)
  const ramHtml = ram.map(m => {
    const gb = m.Capacity ? (m.Capacity / 1073741824).toFixed(0) + " GB" : "\u2014";
    return `<tr><td>${m.BankLabel||'\u2014'}</td><td>${m.DeviceLocator||'\u2014'}</td><td>${gb}</td><td>${m.MemoryType||'\u2014'}</td><td>${m.FormFactor||'\u2014'}</td><td>${m.ConfiguredClockSpeed||m.Speed||'\u2014'} MHz</td><td>${m.Manufacturer||'\u2014'}</td><td><code>${(m.PartNumber||'').trim()}</code></td></tr>`;
  }).join("");
  document.getElementById("si-ram-tbody").innerHTML = ramHtml || '<tr><td colspan="8" style="color:var(--muted)">No data</td></tr>';

  // Memory Array board-limits header (#43). Sums slots + max capacity
  // across arrays (typically 1 on desktops; can be >1 on workstation /
  // server boards). Renders nothing if WMI didn't return MemoryArray
  // data -- some VMs and OEM-locked firmware suppress it.
  const memHdr = document.getElementById("si-ram-board-header");
  if (memHdr) {
    if (memArrays.length) {
      const totalSlots = memArrays.reduce((a, x) => a + (x.MemoryDevices || 0), 0);
      const maxGB = memArrays.reduce((a, x) => a + (x.MaxCapacityGB || 0), 0);
      const usedSlots = ram.filter(m => (m.Capacity || 0) > 0).length;
      const installedGB = ram.reduce((a, m) => a + (m.Capacity || 0), 0) / 1073741824;
      const headroomGB = Math.max(0, maxGB - installedGB);
      const ec = memArrays.find(a => a.MemoryErrorCorrection)?.MemoryErrorCorrection || "";
      memHdr.innerHTML = `
        <span style="color:var(--cyan)">Slots used:</span> <strong>${usedSlots} of ${totalSlots}</strong>
        &nbsp;\u00b7&nbsp;
        <span style="color:var(--cyan)">Max board capacity:</span> <strong>${maxGB.toFixed(0)} GB</strong>
        &nbsp;\u00b7&nbsp;
        <span style="color:var(--cyan)">Headroom:</span> <strong style="color:${headroomGB > 0 ? 'var(--green)' : 'var(--muted)'}">+${headroomGB.toFixed(1)} GB</strong>
        ${ec ? `&nbsp;\u00b7&nbsp;<span style="color:var(--cyan)">ECC:</span> ${ec}` : ''}
      `;
      memHdr.style.display = "block";
    } else {
      memHdr.style.display = "none";
    }
  }

  // Network adapters (IP config)
  const nicHtml = nics.map(n => {
    const dns = Array.isArray(n.DNSServerSearchOrder) ? n.DNSServerSearchOrder.join(", ") : (n.DNSServerSearchOrder||"\u2014");
    return `<tr><td>${n.Description||'\u2014'}</td><td><code>${n.MACAddress||'\u2014'}</code></td><td>${n.IPAddress||'\u2014'}</td><td>${n.DHCPEnabled ? 'Yes ('+n.DHCPServer+')' : 'Static'}</td><td style="font-size:11px">${dns}</td></tr>`;
  }).join("");
  document.getElementById("si-nic-tbody").innerHTML = nicHtml || '<tr><td colspan="5" style="color:var(--muted)">No active adapters</td></tr>';

  // Network hardware (manufacturer details)
  const nicHwHtml = nicHw.map(n => {
    const speed = n.Speed ? (n.Speed >= 1e9 ? (n.Speed/1e9).toFixed(0) + " Gbps" : (n.Speed/1e6).toFixed(0) + " Mbps") : "\u2014";
    return `<tr><td>${n.Name||'\u2014'}</td><td>${n.Manufacturer||'\u2014'}</td><td>${n.NetConnectionID||'\u2014'}</td><td>${speed}</td><td>${n.AdapterType||'\u2014'}</td><td><code>${n.MACAddress||'\u2014'}</code></td></tr>`;
  }).join("");
  document.getElementById("si-nichw-tbody").innerHTML = nicHwHtml || '<tr><td colspan="6" style="color:var(--muted)">No adapters</td></tr>';

  // Sound devices
  const soundHtml = sound.map(s => {
    const statusCol = (s.Status||"").toLowerCase() === "ok" ? "var(--green)" : "var(--orange)";
    return `<tr><td>${s.Name||'\u2014'}</td><td>${s.Manufacturer||'\u2014'}</td><td style="color:${statusCol}">${s.Status||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-sound-tbody").innerHTML = soundHtml || '<tr><td colspan="3" style="color:var(--muted)">No sound devices</td></tr>';

  // USB controllers
  const usbHtml = usb.map(u => {
    const statusCol = (u.Status||"").toLowerCase() === "ok" ? "var(--green)" : "var(--orange)";
    return `<tr><td>${u.Name||'\u2014'}</td><td>${u.Manufacturer||'\u2014'}</td><td style="color:${statusCol}">${u.Status||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-usb-tbody").innerHTML = usbHtml || '<tr><td colspan="3" style="color:var(--muted)">No USB controllers</td></tr>';

  // PCIe slots
  const slotHtml = slots.map(s => {
    const usageCol = s.CurrentUsage === "In Use" ? "var(--green)" : s.CurrentUsage === "Available" ? "var(--muted)" : "var(--orange)";
    return `<tr><td>${s.SlotDesignation||'\u2014'}</td><td style="color:${usageCol}">${s.CurrentUsage||'\u2014'}</td><td>${s.Status||'\u2014'}</td><td style="font-size:11px">${s.Description||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-pcie-tbody").innerHTML = slotHtml || '<tr><td colspan="4" style="color:var(--muted)">No slot data</td></tr>';

  // PCIe slot summary header (#43) -- matches the Memory header style
  // so the upgrade-relevant numbers are visible at a glance without
  // scanning the row count.
  const pcieHdr = document.getElementById("si-pcie-summary-header");
  if (pcieHdr) {
    if (slots.length) {
      const free = slots.filter(s => (s.CurrentUsage || "").toLowerCase() === "available").length;
      pcieHdr.innerHTML = `
        <span style="color:var(--cyan)">Free slots:</span>
        <strong style="color:${free > 0 ? 'var(--green)' : 'var(--muted)'}">${free} of ${slots.length}</strong>
        ${free > 0 ? '&nbsp;\u00b7&nbsp;<span style="color:var(--muted)">Capacity for: GPU, NIC, capture card, NVMe carrier, HBA</span>' : ''}
      `;
      pcieHdr.style.display = "block";
    } else {
      pcieHdr.style.display = "none";
    }
  }

  // Disks
  const diskHtml = disks.map(dk => {
    const sizeGB = dk.Size ? (dk.Size / 1073741824).toFixed(1) + " GB" : "\u2014";
    return `<tr><td>${dk.Model||'\u2014'}</td><td>${sizeGB}</td><td>${dk.InterfaceType||'\u2014'}</td><td>${dk.MediaType||'\u2014'}</td><td>${dk.Partitions||'\u2014'}</td><td style="font-size:10px"><code>${(dk.SerialNumber||'').trim()}</code></td></tr>`;
  }).join("");
  document.getElementById("si-disk-tbody").innerHTML = diskHtml || '<tr><td colspan="6" style="color:var(--muted)">No disks</td></tr>';

  // Volumes
  const volHtml = vols.map(v => {
    const pctFree = v.SizeGB ? ((v.FreeGB / v.SizeGB) * 100).toFixed(1) : 0;
    const col = pctFree < 10 ? "var(--red)" : pctFree < 20 ? "var(--orange)" : "var(--green)";
    return `<tr><td><strong>${v.DeviceID||'\u2014'}</strong></td><td>${v.VolumeName||''}</td><td>${v.FileSystem||'\u2014'}</td><td>${v.SizeGB||'\u2014'} GB</td><td>${v.FreeGB||'\u2014'} GB</td><td style="color:${col};font-weight:600">${pctFree}%</td></tr>`;
  }).join("");
  document.getElementById("si-vol-tbody").innerHTML = volHtml || '<tr><td colspan="6" style="color:var(--muted)">No volumes</td></tr>';
}
