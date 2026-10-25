// Updates tab (prefix upd) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// UPDATE HISTORY
// ══════════════════════════════════════════════════════════════════════════
let _updatesData = null;
async function loadUpdates() {
  try {
    document.getElementById('upd-loading').style.display = 'block';
    document.getElementById('upd-content').style.display = 'none';
    const r = await fetch('/api/updates/history');
    _updatesData = await r.json();
    renderUpdates();
    fetchSummary('updates', {items: _updatesData}, 'summary-updates');
  } catch(e) {
    console.error("Failed to load updates:", e);
  }
}
function renderUpdates() {
  if (!_updatesData) return;
  const q = (document.getElementById('upd-search').value||'').toLowerCase();
  const filter = document.getElementById('upd-filter').value;
  const now = new Date();
  const items = _updatesData.filter(u=>(!filter||(u.result||'').includes(filter))&&(!q||(u.Title||'').toLowerCase().includes(q)||(u.KB||'').toLowerCase().includes(q)));
  document.getElementById('upd-total').textContent = _updatesData.length;
  document.getElementById('upd-ok').textContent    = _updatesData.filter(u=>u.result==='Succeeded').length;
  document.getElementById('upd-fail').textContent  = _updatesData.filter(u=>u.result==='Failed'||u.result==='Aborted').length;
  const tm = _updatesData.filter(u=>{const d=new Date(u.Date);return d.getMonth()===now.getMonth()&&d.getFullYear()===now.getFullYear();}).length;
  document.getElementById('upd-month').textContent = tm;
  const rows = items.map(u=>{
    const d=new Date(u.Date);
    const ds=isNaN(d)?u.Date:d.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
    const rc=u.result==='Succeeded'?'var(--cyan)':u.result==='Failed'||u.result==='Aborted'?'var(--red)':'var(--muted)';
    return `<tr style="border-bottom:1px solid var(--border)"><td style="padding:8px 12px;white-space:nowrap;color:var(--muted)">${ds}</td><td style="padding:8px 12px;font-family:monospace;font-size:11px;color:var(--cyan)">${esc(u.KB)}</td><td style="padding:8px 12px">${esc(u.Title)}</td><td style="padding:8px 12px;color:var(--muted);font-size:11px">${esc(u.Categories)}</td><td style="padding:8px 12px;color:${rc};font-weight:600">${esc(u.result)}</td></tr>`;
  }).join('');
  document.getElementById('upd-tbody').innerHTML = rows||'<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--muted)">No updates match filter</td></tr>';
  document.getElementById('upd-loading').style.display = 'none';
  document.getElementById('upd-content').style.display = '';
}

