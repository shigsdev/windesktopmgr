// Network tab (prefix net) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
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
  const q = (document.getElementById('nw-search').value||'').toLowerCase();
  const conns = (_networkData.established||[]).filter(c=>!q||(c.Process||'').toLowerCase().includes(q)||(c.RemoteAddress||'').includes(q));
  const rows = conns.slice(0,200).map(c=>`<tr style="border-bottom:1px solid var(--border)"><td style="padding:5px 10px;font-weight:600">${esc(c.Process)}</td><td style="padding:5px 10px;color:var(--muted)">${c.PID}</td><td style="padding:5px 10px">${c.LocalPort}</td><td style="padding:5px 10px;font-family:monospace;font-size:11px">${esc(c.RemoteAddress)}</td><td style="padding:5px 10px">${c.RemotePort}</td><td style="padding:5px 10px;color:var(--cyan)">${esc(c.State)}</td></tr>`).join('');
  document.getElementById('nw-contable').innerHTML = rows||'<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--muted)">No connections match filter</td></tr>';
}

