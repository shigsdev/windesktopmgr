// Services tab (prefix svc) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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
      ? `<button onclick="svcAction('${escJsArg(s.Name)}','stop')"
           style="background:#ff404022;border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Stop</button>` : "";
    const startBtn = !running
      ? `<button onclick="svcAction('${escJsArg(s.Name)}','start')"
           style="background:#00d4ff22;border:1px solid var(--cyan);color:var(--cyan);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Start</button>` : "";
    const disableBtn = !disabled && !isCrit
      ? `<button onclick="svcAction('${escJsArg(s.Name)}','disable')"
           style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;margin-right:4px">Disable</button>` : "";
    const enableBtn = disabled
      ? `<button onclick="svcAction('${escJsArg(s.Name)}','enable')"
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


