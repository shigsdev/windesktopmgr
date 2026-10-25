// Drivers tab (prefix drv) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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

