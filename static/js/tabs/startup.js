// Startup tab (prefix su) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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

