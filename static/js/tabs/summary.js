// Shared summary banners + auto-launch -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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

