// Logs tab (prefix log) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// LOGS TAB (prefix: log)
// ══════════════════════════════════════════════════════════════════════════
// Translate the dropdown value into {level, exact, label}. A leading "=" marks
// an exact-level option (e.g. "=INFO" -> INFO only); otherwise it's a minimum
// severity ("INFO" -> INFO and above). "" -> all levels.
function logParseLevel() {
  const raw = document.getElementById("log-level").value;
  if (!raw) return { level: "", exact: false, label: "all levels" };
  if (raw.startsWith("=")) {
    const lvl = raw.slice(1);
    return { level: lvl, exact: true, label: lvl + " only" };
  }
  return { level: raw, exact: false, label: raw + " and above" };
}


async function logLoad() {
  const container = document.getElementById("log-container");
  const summary = document.getElementById("log-summary");
  const sel = logParseLevel();
  const lines = document.getElementById("log-lines").value;
  container.textContent = "Loading...";
  summary.textContent = "";
  try {
    const params = new URLSearchParams({ lines: lines });
    if (sel.level) { params.set("level", sel.level); if (sel.exact) params.set("exact", "1"); }
    const ctrl = new AbortController();
    const timeoutId = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch("/api/logs?" + params.toString(), { signal: ctrl.signal });
    clearTimeout(timeoutId);
    const data = await resp.json();
    if (!data.ok || !data.entries) {
      container.textContent = "No log entries found.";
      return;
    }
    summary.textContent = `${data.count} entries (newest first, ${sel.label})`;
    logRender(data.entries);
  } catch (e) {
    container.textContent = "Failed to load logs: " + (e && e.message ? e.message : e);
  }
}

function logDownload(fmt) {
  // Downloads always pull the full tail (max 20000), filtered by current level
  const sel = logParseLevel();
  const params = new URLSearchParams({ format: fmt, lines: "20000" });
  if (sel.level) { params.set("level", sel.level); if (sel.exact) params.set("exact", "1"); }
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
