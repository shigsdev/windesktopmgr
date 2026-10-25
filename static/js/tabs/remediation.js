// Remediation (prefix rem) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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
            <button onclick="confirmRemediation('${escJsArg(a.id)}')"
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

