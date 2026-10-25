// Timeline tab (prefix tl) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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

