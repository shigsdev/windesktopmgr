// ── Shared ─────────────────────────────────────────────────────────────────
const CAT_ICONS = { Display:"🖥", Audio:"🔊", Network:"🌐", Chipset:"⚙", Other:"📦" };

// The one HTML escaper (tech-debt #67): text AND attribute values, all five
// HTML-special characters. null/undefined -> "", 0 -> "0". esc() and _esc()
// are the same function -- never add a private copy in a tab section.
function escHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Text inside an inline handler's quoted JS string:
//   onclick="fn('${escJsArg(name)}')"
// The browser turns &#39; back into ' before it runs the handler, so HTML
// escaping alone lets a quote end the string; JS-escape first, then HTML.
function escJsArg(s) {
  return escHtml(String(s == null ? "" : s)
    .replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, '\\"')
    .replace(/\r/g, "\\r").replace(/\n/g, "\\n")
    .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029"));
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
let _assetsVersion = null;  // front-end bundle version; reload the page when it changes (a deploy)
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
    .then((data) => {
      _heartbeatFailures = 0;
      // Auto-reload when a deploy changes the front-end bundle, so the open
      // page stops running a stale stylesheet/script (it otherwise only
      // refreshes DATA, never the assets). First reading just records the
      // baseline; a later change triggers one reload.
      if (data && data.assets) {
        if (_assetsVersion === null) {
          _assetsVersion = data.assets;
        } else if (data.assets !== _assetsVersion) {
          // A deploy changed the bundle -> reload to drop the stale CSS/JS.
          // (No loop: the reloaded page re-baselines against the now-stable
          // post-deploy version on its first heartbeat.)
          window.location.reload();
          return;
        }
      }
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
  // Up to 5 model rounds (Opus 5.5 always thinks) plus tool calls: 60 s was too tight.
  const timeoutId = setTimeout(() => controller.abort(), 150000);

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
      html += `<div class="nlq-nav-hint">📍 <a onclick="switchTab('${escJsArg(data.navigate_to)}')">Go to ${esc(data.navigate_to)} tab</a></div>`;
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

const esc = escHtml;

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
    // Same for the Temps & Power auto-refresh: it only polls while visible.
    if (page !== "thermals") thStopAutoRefresh();
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
      // Always fresh on entry: a temperature snapshot from a previous visit is
      // misleading (it kept showing a reading taken mid dashboard refresh).
      _tabLoaded["thermals"] = true;
      loadThermals();
      thStartAutoRefresh();
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
    } else if (page === "maintenance") {
      if (!_tabLoaded["maintenance"]) { _tabLoaded["maintenance"] = true; mnt_scan(); mnt_system(); }
    } else if (page === "docs") {
      // Reload on EVERY visit, like baseline/backup/utilities. The page
      // promises live values, and the documented workflow is: open this tab ->
      // shut down -> swap the drive -> boot -> come back here to run the
      // script. A one-shot load would still flag the replaced drive as
      // "REMOVE THIS ONE". Cheap now that the topology is cached server-side.
      doc_load();
    } else if (page === "diagnose") {
      // Reload history on EVERY visit, and resume a session left running
      // (a reload must not strand a payload preview waiting for an answer).
      dx_load();
    } else if (page === "logs") {
      if (!_tabLoaded["logs"])           { _tabLoaded["logs"]           = true; logLoad(); }
    } else if (page === "architecture") {
      if (!_tabLoaded["architecture"])   { _tabLoaded["architecture"]   = true; loadArchitecture(); }
    }
  });
});

