// Processes tab (prefix proc) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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
      ? `<button onclick="killProc(${p.PID},'${escJsArg(plain)}')"
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

// Shared elevated-kill fallback (proc_ = Processes tab). When /api/processes/kill
// returns can_elevate, offer a UAC-elevated taskkill retry that succeeds for
// SYSTEM / other-user / higher-integrity processes. When it returns a protected
// (anti-tamper) reason, just show the honest message — elevation won't help.
async function proc_elevatedKill(pid, name, onSuccess) {
  try {
    const r = await fetch("/api/processes/kill-elevated", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({pid}),
    });
    const d = await r.json();
    if (d.ok) { onSuccess(); }
    else { alert(`Elevated kill of ${name} failed: ${d.error || "unknown error"}`); }
  } catch (e) {
    alert(`Elevated kill of ${name} failed: ${e.message}`);
  }
}

function proc_handleKillFailure(d, pid, name, onSuccess) {
  if (d.can_elevate) {
    if (confirm(`${d.error}\n\nRetry killing ${name} (PID ${pid}) as administrator? A Windows UAC prompt will appear.`)) {
      proc_elevatedKill(pid, name, onSuccess);
    }
  } else {
    // protected / anti-tamper (or any non-elevatable failure) — honest message
    alert(`Cannot kill ${name}: ${d.error || "unknown error"}`);
  }
}

async function killProc(pid, name) {
  if (!confirm(`Kill process "${name}" (PID ${pid})? Unsaved work in this process will be lost.`)) return;
  const r = await fetch("/api/processes/kill", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({pid})
  });
  const d = await r.json();
  if (d.ok) { loadProcesses(); }
  else { proc_handleKillFailure(d, pid, name, loadProcesses); }
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

