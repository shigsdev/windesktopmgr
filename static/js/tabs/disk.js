// Disk / Storage tab (prefix dk) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// DISK HEALTH
// ══════════════════════════════════════════════════════════════════════════
async function loadDisk() {
  try {
    document.getElementById('dk-loading').style.display = 'block';
    document.getElementById('dk-content').style.display = 'none';
    const r = await fetch('/api/disk/data');
    const d = await r.json();
    const drives = Array.isArray(d.drives) ? d.drives : [];
    const physical = Array.isArray(d.physical) ? d.physical : [];
    // Split by drive type. Default missing type to 'local' for backward compat
    // with cached payloads from the pre-Win32_LogicalDisk implementation.
    const dkType = dr => (dr.DriveTypeName || (dr.DriveType === 4 ? 'network' : dr.DriveType === 2 ? 'removable' : 'local'));
    const localDrives   = drives.filter(dr => dkType(dr) !== 'network');
    const networkDrives = drives.filter(dr => dkType(dr) === 'network');
    document.getElementById('dk-volumes').textContent  = localDrives.length
      + (networkDrives.length ? ` (+${networkDrives.length} net)` : '');
    document.getElementById('dk-physical').textContent = physical.length;
    // Total Space = local only — mapped NAS shares are not this machine's storage.
    const totalGB = localDrives.reduce((s,dr) => s+(dr.TotalGB||0), 0);
    document.getElementById('dk-total').textContent = totalGB.toFixed(1)+' GB';
    const issues = physical.filter(p => p.Health && p.Health.toLowerCase()!=='healthy').length;
    document.getElementById('dk-issues').textContent = issues||'0';
    const drvHtml = localDrives.map(dr => {
      const pct = dr.PctUsed||0;
      const col = pct>90?'var(--red)':pct>70?'var(--orange)':'var(--cyan)';
      const letter = esc(dr.Letter);
      const fsBadge = dr.FileSystem ? `<span style="font-size:10px;color:var(--muted);margin-left:6px">${esc(dr.FileSystem)}</span>` : '';
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px"><div style="font-size:28px;font-weight:800;color:${col}">${letter}:${fsBadge}</div><div style="color:var(--muted);font-size:12px;margin-bottom:12px">${esc(dr.Label||'Local Disk')}</div><div style="background:#ffffff11;border-radius:4px;height:8px;margin-bottom:10px"><div style="background:${col};height:100%;border-radius:4px;width:${pct}%"></div></div><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:12px"><span style="color:var(--muted)">${dr.UsedGB} GB used</span><span style="color:var(--muted)">${dr.FreeGB} GB free</span><span style="font-weight:700;color:${col}">${pct}%</span></div><button class="btn-action" style="width:100%;padding:8px;font-size:12px" onclick="dkAnalyzeOpen('${letter}')">🔍 Analyze Space</button></div>`;
    }).join('');
    document.getElementById('dk-drives').innerHTML = drvHtml || '<p style="color:var(--muted)">No local drives found</p>';
    // Network shares — render separately, no Analyze button (can't run os.scandir
    // over SMB without permission quirks), no red coloring (their fullness is a
    // NAS problem, not a local-disk problem), UNC path badge instead of label.
    const netHtml = networkDrives.map(dr => {
      const pct = dr.PctUsed||0;
      const letter = esc(dr.Letter);
      const unc = esc(dr.UNCPath || '');
      const label = esc(dr.Label || 'Network Share');
      return `<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;opacity:0.92"><div style="font-size:28px;font-weight:800;color:var(--muted)">${letter}: <span style="font-size:11px;color:var(--cyan);font-weight:600;vertical-align:middle">CIFS</span></div><div style="color:var(--muted);font-size:12px;margin-bottom:4px">${label}</div><div style="color:var(--cyan);font-size:11px;font-family:monospace;margin-bottom:10px;word-break:break-all">${unc}</div><div style="background:#ffffff11;border-radius:4px;height:8px;margin-bottom:10px"><div style="background:var(--muted);height:100%;border-radius:4px;width:${pct}%"></div></div><div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--muted)">${dr.UsedGB} GB used</span><span style="color:var(--muted)">${dr.FreeGB} GB free</span><span style="font-weight:700;color:var(--muted)">${pct}%</span></div></div>`;
    }).join('');
    document.getElementById('dk-network-drives').innerHTML = netHtml;
    document.getElementById('dk-network-section').style.display = networkDrives.length ? '' : 'none';
    let dkSnoozes = {};
    try { const sr = await fetch('/api/disk/snoozes'); const sd = await sr.json(); dkSnoozes = (sd && sd.snoozes) || {}; } catch(e) {}
    const _snKey = s => String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'');
    const physRows = physical.map(p => {
      const bad = (p.Health||'').toLowerCase() && (p.Health||'').toLowerCase()!=='healthy';
      const paused = !!dkSnoozes[_snKey(p.SerialNumber)];
      const hc = bad ? 'var(--red)' : 'var(--cyan)';
      const li = p.LocationInfo || {};
      const serial = esc(p.SerialNumber||'').replace(/\.$/,'') || '<span style="color:var(--muted)">—</span>';
      const slotTxt = esc(li.slot || (li.integrated ? 'Integrated' : '') || '—');
      const busTxt = (li.bus!==null && li.bus!==undefined) ? ` · bus ${li.bus}` : '';
      const hint = esc(li.hint||'');
      const slotCell = hint
        ? `<span title="${hint}" style="border-bottom:1px dotted var(--muted);cursor:help">${slotTxt}${busTxt}</span>`
        : `${slotTxt}${busTxt}`;
      // Paused drive: don't scream red, show a resume link. Unhealthy + not
      // paused: red row + a pause link. Healthy: nothing extra.
      const pausedTag = paused
        ? ` <span style="color:var(--muted);font-size:11px" title="health alerts paused">⏸ paused · <a href="#" onclick="resumeDiskDrive('${dkJsArg(p.SerialNumber)}');return false" style="color:var(--cyan)">resume</a></span>`
        : (bad ? ` <a href="#" onclick="pauseDiskConcern('${dkJsArg(p.SerialNumber)}');return false" title="Pause health alerts for this drive for 24 h" style="color:var(--muted);font-size:11px">⏸ pause</a>` : '');
      const rowBg = (bad && !paused) ? 'background:#ff555511;' : '';
      return `<tr style="border-bottom:1px solid var(--border);${rowBg}"><td style="padding:8px 12px;font-weight:600">${esc(p.Name)}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.MediaType)}</td><td style="padding:8px 12px">${p.SizeGB} GB</td><td style="padding:8px 12px;color:${paused?'var(--muted)':hc};font-weight:${(bad&&!paused)?'700':'400'}">${esc(p.Health)}${pausedTag}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.Status)}</td><td style="padding:8px 12px;color:var(--muted)">${esc(p.BusType)}</td><td style="padding:8px 12px;color:var(--muted);font-family:monospace;font-size:11px">${serial}</td><td style="padding:8px 12px;color:var(--muted)">${slotCell}</td></tr>`;
    }).join('');
    document.getElementById('dk-tbody').innerHTML = physRows || '<tr><td colspan="8" style="padding:24px;text-align:center;color:var(--muted)">No disk info available</td></tr>';
    dkLoadSpaces();
    dkLoadNas();
    dkLoadTopology();
    fetchSummary('disk', d, 'summary-disk');
    document.getElementById('dk-loading').style.display = 'none';
    document.getElementById('dk-content').style.display = '';
  } catch(e) {
    console.error("Failed to load disk:", e);
  }
}

// Storage Spaces (software-RAID pools). Rendered only when the machine has a
// non-primordial pool. Windows raises no alert when a pool degrades, so this
// section is the user-facing surface for lost redundancy + a stalled repair.
async function dkLoadSpaces() {
  try {
    const r = await fetch('/api/storage/spaces');
    const ss = await r.json();
    const sec = document.getElementById('dk-spaces-section');
    if (!ss || !ss.has_spaces) { sec.style.display = 'none'; return; }
    const degraded = (h,o) => {
      h=(h||'').toLowerCase(); o=(o||'').toLowerCase();
      return h==='warning'||h==='unhealthy'||/degraded|incomplete|unhealthy|detached/.test(o);
    };
    const badge = (h,o) => {
      const col = degraded(h,o)?'var(--red)':'var(--cyan)';
      return `<span style="color:${col};font-weight:700">${esc(h||o||'—')}</span>`;
    };
    let html = '';
    (ss.virtual_disks||[]).forEach(vd => {
      const bad = degraded(vd.Health, vd.Operational);
      html += `<div style="background:var(--card);border:1px solid ${bad?'var(--red)':'var(--border)'};border-radius:10px;padding:16px;margin-bottom:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-weight:700;font-size:15px">🗄 ${esc(vd.Name)} <span style="font-size:12px;color:var(--muted);font-weight:400">· ${esc(vd.Resiliency)} · ${vd.SizeGB} GB</span></div>${badge(vd.Health, vd.Operational)}</div>${bad?'<div style="color:var(--red);font-size:12px">⚠ Running WITHOUT redundancy — a member drive dropped. Another failure would lose the volume.</div>':''}</div>`;
    });
    (ss.repair_jobs||[]).forEach(j => {
      const suspended = (j.State||'').toLowerCase()==='suspended';
      html += `<div style="font-size:12px;color:${suspended?'var(--orange)':'var(--muted)'};margin-bottom:8px">🛠 Repair <b>${esc(j.Name)}</b>: ${esc(j.State)}${(j.Pct||j.Pct===0)&&j.State&&j.State.toLowerCase()==='running'?` (${j.Pct}%)`:''}${suspended?' — stalled; usually not enough free pool space to rebuild':''}</div>`;
    });
    if ((ss.members||[]).length) {
      html += `<table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px"><thead><tr style="color:var(--muted);text-align:left;border-bottom:1px solid var(--border)"><th style="padding:6px 10px">Member drive</th><th style="padding:6px 10px">Health</th><th style="padding:6px 10px">Serial</th><th style="padding:6px 10px">Physical slot</th></tr></thead><tbody>`;
      ss.members.forEach(m => {
        const bad = degraded(m.Health, m.Operational);
        const li = m.LocationInfo||{};
        const slot = esc(li.slot || (li.integrated?'Integrated':'') || '—');
        const bus = (li.bus!==null&&li.bus!==undefined)?` · bus ${li.bus}`:'';
        const serial = esc(m.Serial||'').replace(/\.$/,'')||'—';
        html += `<tr style="border-bottom:1px solid var(--border);${bad?'background:#ff555511':''}"><td style="padding:6px 10px">${esc(m.Name)}</td><td style="padding:6px 10px;color:${bad?'var(--red)':'var(--cyan)'}">${esc(m.Health||m.Operational)}</td><td style="padding:6px 10px;font-family:monospace;font-size:11px;color:var(--muted)">${serial}</td><td style="padding:6px 10px;color:var(--muted)"><span title="${esc(li.hint||'')}" style="border-bottom:1px dotted var(--muted);cursor:help">${slot}${bus}</span></td></tr>`;
      });
      html += `</tbody></table><div style="font-size:11px;color:var(--muted);margin-top:6px">A drive that has fully dropped out of the pool no longer appears here — check the Physical Drives table below for its Warning / IO-Error status and slot.</div>`;
    }
    document.getElementById('dk-spaces').innerHTML = html;
    sec.style.display = '';
  } catch(e) { console.error('Failed to load storage spaces:', e); }
}

// Physical card view (dk = Storage tab). Draws the add-in PCIe M.2 card's
// drives starting at the metal bracket, in the order checked by hand
// (physical_order from disk.build_pcie_card_topology), highlighting a
// failed/retired drive for a hardware swap, and lists the onboard M.2 drives
// as "do not touch". Each row says how far it sits from the bracket and whether
// that was checked or assumed, then leads with the serial printed on the drive
// label; the EUI Windows uses is shown last.
// Built with DOM APIs + textContent (no innerHTML) so the live drive
// model/serial strings can't inject markup. Shown only when the
// machine actually has an add-in card (has_card).
// sectionId/hostId are parameters so the Docs tab can render the SAME live
// diagram instead of shipping a screenshot that goes stale the moment a drive
// is swapped -- which is exactly the drive swap this diagram exists to guide.
async function dkLoadTopology(sectionId, hostId, prefetched) {
  const SVGNS = 'http://www.w3.org/2000/svg';
  const sec = document.getElementById(sectionId || 'dk-card-section');
  const host = document.getElementById(hostId || 'dk-card');
  if (!sec || !host) return;
  try {
    // prefetched lets a caller that already has the payload skip a second
    // request. The Docs tab needs the same data twice (diagram + drive-state
    // line), and the browser caps concurrent connections per host, so the
    // duplicate fetch queued behind the dashboard's own polling and the
    // diagram sat blank for a minute while the state line rendered instantly.
    const t = prefetched || await fetch('/api/storage/pcie-topology').then(r => r.json());
    if (!t || !t.ok || !t.has_card) { sec.style.display = 'none'; return; }
    while (host.firstChild) host.removeChild(host.firstChild);

    const flagColor = f => f === 'retired' ? '#ff4d4f' : (f === 'unhealthy' ? '#ffd740' : '#8b949e');
    // Drawn starting at the metal bracket, in the order checked by hand
    // (physical_order). Windows' bus order ran the OTHER way on this card, and
    // drawing it top-down beside the bracket got a healthy drive pulled on
    // 2026-10-08. Older payloads without physical_order fall back to bus order.
    const drives = t.physical_order || t.card_drives || [];
    const rowH = 88, top = 74, W = 700, H = top + drives.length * rowH + 12;
    const svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('width', '100%');
    const rect = (x, y, w, h, o = {}) => {
      const e = document.createElementNS(SVGNS, 'rect');
      e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('width', w); e.setAttribute('height', h);
      e.setAttribute('rx', o.rx || 6);
      if (o.fill) e.setAttribute('fill', o.fill);
      if (o.stroke) { e.setAttribute('stroke', o.stroke); e.setAttribute('stroke-width', o.sw || 1.5); }
      svg.appendChild(e); return e;
    };
    const text = (x, y, s, o = {}) => {
      const e = document.createElementNS(SVGNS, 'text');
      e.setAttribute('x', x); e.setAttribute('y', y);
      e.setAttribute('fill', o.fill || '#e6edf3'); e.setAttribute('font-size', o.size || 13);
      if (o.weight) e.setAttribute('font-weight', o.weight);
      if (o.mono) e.setAttribute('font-family', 'ui-monospace,Consolas,monospace');
      e.textContent = s; svg.appendChild(e); return e;
    };
    // Bracket across the top (the end of the card at the back of the PC), the
    // card body below it, sockets running away from the bracket.
    rect(30, 10, W - 60, 26, {rx: 4, fill: '#2a3440', stroke: '#4b5a6b'});
    text(46, 28, 'METAL BRACKET  ·  back of the PC, where the cables plug in', {fill: '#c9d1d9', size: 12, weight: '700'});
    rect(40, 36, W - 80, H - 40, {rx: 10, fill: '#11161d', stroke: '#30363d', sw: 2});
    // card_switch already reads as a full noun ("ASMedia ASM2812", "PCIe
    // switch", "Broadcom/PLX PCIe switch") — don't append "switch" or fallbacks
    // double it ("PCIe switch switch").
    const cardLabel = t.card_switch ? `PCIe M.2 carrier card · ${t.card_switch}` : 'PCIe M.2 carrier card';
    text(56, 60, cardLabel, {fill: '#8b949e', size: 12});
    const placedCount = drives.filter(d => d.position).length;
    const where = d => {
      if (!d.position) return 'POSITION UNKNOWN — find it by the label';
      const n = d.position;
      const pos = n === 1 ? 'NEAREST THE BRACKET'
        : (n === placedCount ? 'FARTHEST FROM THE BRACKET'
          : `${n}${n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'} FROM THE BRACKET`);
      return `${pos}  ${d.position_checked ? '(checked by hand 2026-10-08)' : '(assumed)'}`;
    };
    drives.forEach((d, i) => {
      const y = top + i * rowH;
      const failed = d.flag !== 'ok';
      rect(60, y, W - 120, rowH - 12, failed ? {fill: '#2d1416', stroke: '#ff4d4f', sw: 2.5} : {fill: '#0d1117', stroke: '#30363d'});
      const c = flagColor(d.flag);
      const tag = failed ? (d.retired ? '✖ RETIRED — REMOVE THE DRIVE WITH THIS LABEL' : '⚠ unhealthy — check this drive') : '✓ healthy';
      text(76, y + 18, where(d), {fill: '#d29922', size: 11, weight: '700'});
      // Label serial first: it is the only thing printed on the drive.
      const lbl = d.label_serial ? `label S/N ${d.label_serial}` : 'label S/N not reported — match by model';
      text(76, y + 38, `${lbl}    ${tag}`, {fill: c, size: 13, mono: true, weight: '700'});
      text(76, y + 57, `${d.model || ''}${d.size_gb ? ' · ' + Math.round(d.size_gb) + ' GB' : ''}`, {size: 13});
      const slotTxt = d.slot ? ` · ${d.slot}` : '';
      const busTxt = (d.bus !== null && d.bus !== undefined) ? ` · bus ${d.bus}` : '';
      text(76, y + 73, `Windows #${d.socket}${slotTxt}${busTxt} · ID ${d.serial || ('…' + (d.serial_short || '????'))} (not on label)`, {fill: '#8b949e', size: 11, mono: true});
    });
    // Drawn order (bracket first), for tests.
    svg.setAttribute('data-dk-order', drives.map(d => d.label_serial || d.serial_short || '').join(','));
    // The failed drive's label serial, for tests and the Docs state line.
    svg.setAttribute('data-dk-failed-label', t.failed_label_serial || '');
    host.appendChild(svg);

    const note = document.createElement('div');
    note.style.cssText = 'font-size:11px;color:var(--muted);margin-top:6px';
    note.textContent = [t.order_basis, t.note].filter(Boolean).join(' ');
    host.appendChild(note);

    // Drives that dropped off the bus entirely (dead / already pulled) but are
    // still known to a pool — the real swap scenario. Show them so the view
    // never looks all-healthy while a drive is actually gone.
    if ((t.missing || []).length) {
      const mv = document.createElement('div');
      mv.style.cssText = 'font-size:12px;color:#ff4d4f;margin-top:10px;font-weight:700';
      mv.textContent = 'Pulled or dropped (pool member Windows can no longer reach):';
      host.appendChild(mv);
      t.missing.forEach(d => {
        const line = document.createElement('div');
        line.style.cssText = 'font-size:12px;color:#ff4d4f';
        const lbl = d.label_serial ? `label S/N ${d.label_serial}` : `ID ${d.serial || ('…' + (d.serial_short || '????'))}`;
        const why = String(d.usage || '').toLowerCase() === 'retired'
          ? 'failed drive, removed (expected)'
          : 'HOLDS DATA — put it back';
        line.textContent = `✖ ${d.model || ''} · ${lbl} · ${why}`;
        host.appendChild(line);
      });
    }

    if ((t.onboard || []).length) {
      const ob = document.createElement('div');
      ob.style.cssText = 'font-size:12px;color:var(--muted);margin-top:10px';
      const h = document.createElement('div');
      h.style.cssText = 'font-weight:700;margin-bottom:2px';
      h.textContent = 'Not on the card (motherboard M.2 / SATA — do not remove for this swap):';
      ob.appendChild(h);
      t.onboard.forEach(d => {
        const bad = d.flag && d.flag !== 'ok';
        const line = document.createElement('div');
        if (bad) line.style.cssText = 'color:#ff4d4f;font-weight:700';
        const tag = bad ? (d.retired ? '  ✖ RETIRED — but this one is NOT on the card' : '  ⚠ unhealthy — NOT on the card') : '';
        const lbl = d.label_serial ? `label S/N ${d.label_serial}` : `ID ${d.serial || ('…' + (d.serial_short || '????'))}`;
        line.textContent = `• ${d.model || ''} · ${lbl}${tag}`;
        ob.appendChild(line);
      });
      host.appendChild(ob);
    }
    sec.style.display = '';
  } catch (e) { console.error('Failed to load PCIe topology:', e); sec.style.display = 'none'; }
}

// NAS storage (QNAP over SNMP). Rendered only when nas_config.json is filled in
// (configured > 0). Each NAS: disks (bay/model/capacity/temp/health) + volumes
// (name/pool/fs/size/used%/status) + fans. Unhealthy rows tinted red.
async function dkLoadNas() {
  try {
    const r = await fetch('/api/storage/nas');
    const nd = await r.json();
    const sec = document.getElementById('dk-nas-section');
    if (!nd || !nd.configured) { sec.style.display = 'none'; return; }
    let html = '';
    (nd.nas||[]).forEach(n => {
      const online = !!n.reachable;
      const sub = online ? `· ${esc(n.model)} · fw ${esc(n.firmware)}` : '';
      const badge = online
        ? '<span style="color:var(--cyan);font-weight:700">online</span>'
        : '<span style="color:var(--orange);font-weight:700">unreachable</span>';
      const hdr = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><div style="font-weight:700;font-size:15px">🗄 ${esc(n.name)} <span style="font-size:12px;color:var(--muted);font-weight:400">${sub}</span></div>${badge}</div>`;
      if (!online) {
        html += `<div style="background:var(--card);border:1px solid var(--orange);border-radius:10px;padding:16px;margin-bottom:16px">${hdr}<div style="color:var(--orange);font-size:12px">${esc(n.error||'Could not reach this NAS over SNMP.')}</div></div>`;
        return;
      }
      // Compact system stats row (CPU / RAM / temps) under the header.
      const stat = (label, val) => (val!==null && val!==undefined && val!=='') ? `<span style="color:var(--muted)">${label} <b style="color:var(--fg)">${esc(val)}</b></span>` : '';
      const stats = `<div style="display:flex;gap:18px;flex-wrap:wrap;font-size:11px;margin:-2px 0 12px">
        ${stat('CPU', n.cpu)}
        ${n.mem_used_pct!=null ? stat('RAM', n.mem_used_pct + '% of ' + (n.mem_total_gb!=null?Math.round(n.mem_total_gb):'?') + ' GB') : ''}
        ${n.sys_temp_c!=null ? stat('System', n.sys_temp_c + '°C') : ''}
        ${n.cpu_temp_c!=null ? stat('CPU temp', n.cpu_temp_c + '°C') : ''}
      </div>`;
      let disks = `<div style="font-size:11px;color:var(--muted);margin-bottom:4px">Disks (${(n.disks||[]).length})</div><table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:12px"><thead><tr style="color:var(--muted);text-align:left;border-bottom:1px solid var(--border)"><th style="padding:5px 10px">Bay</th><th style="padding:5px 10px">Model</th><th style="padding:5px 10px">Capacity</th><th style="padding:5px 10px">Temp</th><th style="padding:5px 10px">Health</th></tr></thead><tbody>`;
      (n.disks||[]).forEach(d => {
        const bad = !d.healthy;
        disks += `<tr style="border-bottom:1px solid var(--border);${bad?'background:#ff555511':''}"><td style="padding:5px 10px;font-weight:600">${esc(d.bay)}</td><td style="padding:5px 10px">${esc(d.model)}</td><td style="padding:5px 10px">${esc(d.capacity)}</td><td style="padding:5px 10px;color:var(--muted)">${d.temp_c!=null?esc(d.temp_c)+'°C':'—'}</td><td style="padding:5px 10px;color:${bad?'var(--red)':'var(--cyan)'};font-weight:${bad?'700':'400'}">${esc(d.health)}</td></tr>`;
      });
      disks += `</tbody></table>`;
      let vols = `<div style="font-size:11px;color:var(--muted);margin-bottom:4px">Volumes (${(n.volumes||[]).length})</div><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="color:var(--muted);text-align:left;border-bottom:1px solid var(--border)"><th style="padding:5px 10px">Volume</th><th style="padding:5px 10px">Pool</th><th style="padding:5px 10px">FS</th><th style="padding:5px 10px">Size</th><th style="padding:5px 10px">Used</th><th style="padding:5px 10px">Status</th></tr></thead><tbody>`;
      (n.volumes||[]).forEach(v => {
        const bad = !v.healthy;
        const pct = v.pct_used;
        const pc = (pct!=null && pct>=90) ? 'var(--red)' : (pct!=null && pct>=75) ? 'var(--orange)' : 'var(--muted)';
        vols += `<tr style="border-bottom:1px solid var(--border);${bad?'background:#ff555511':''}"><td style="padding:5px 10px;font-weight:600">${esc(v.name)}</td><td style="padding:5px 10px;color:var(--muted)">${esc(v.pool)}</td><td style="padding:5px 10px;color:var(--muted)">${esc(v.fs)}</td><td style="padding:5px 10px">${esc(v.total)} <span style="color:var(--muted)">(${esc(v.free)} free)</span></td><td style="padding:5px 10px;color:${pc}">${pct!=null?pct+'%':'—'}</td><td style="padding:5px 10px;color:${bad?'var(--red)':'var(--cyan)'}">${esc(v.status)}</td></tr>`;
      });
      vols += `</tbody></table>`;
      const fans = (n.fans||[]).length ? `<div style="font-size:11px;color:var(--muted);margin-top:10px">Fans: ${(n.fans||[]).map(f=>esc(f.name)+' '+esc(f.speed)).join(' · ')}</div>` : '';
      html += `<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px">${hdr}${stats}${disks}${vols}${fans}</div>`;
    });
    document.getElementById('dk-nas').innerHTML = html;
    sec.style.display = '';
  } catch(e) { console.error('Failed to load NAS storage:', e); }
}

// ── Disk Space Analyzer ───────────────────────────────────────────────────
let _dkAnalyzePath = null;
let _dkAnalyzeDrive = null;

// Storage tab's name for escJsArg (kept for its call sites).
function dkJsArg(s) {
  return escJsArg(s);
}

const _dkAnalyzeCache = new Map();

function dkAnalyzeOpen(letter) {
  _dkAnalyzeDrive = letter;
  _dkAnalyzeCache.clear();
  const root = letter + ':\\';
  document.getElementById('dk-analyze-modal').style.display = 'block';
  dkAnalyzeLoad(root);
  dkQuickWinsLoad(letter);
}

function dkAnalyzeClose() {
  document.getElementById('dk-analyze-modal').style.display = 'none';
  _dkAnalyzePath = null;
  _dkAnalyzeCache.clear();
}

function _dkRenderAnalyzeResult(d) {
  const entries = d.entries || [];
  const total = d.total_bytes || 0;
  const cloudTotal = d.total_cloud_bytes || 0;
  const cloudSuffix = cloudTotal > 0
    ? ` — plus ${dkHuman(cloudTotal)} in cloud (iCloud/OneDrive/Dropbox, not using local disk)`
    : '';
  document.getElementById('dk-analyze-total').textContent =
    `Scanned total: ${dkHuman(total)} across ${entries.length} items${cloudSuffix}`;
  if (!entries.length) {
    document.getElementById('dk-analyze-tbody').innerHTML =
      '<tr><td colspan="4" style="padding:24px;text-align:center;color:var(--muted)">No items found</td></tr>';
    return;
  }
  const rows = entries.map(e => {
    const pct = e.pct || 0;
    const col = pct > 40 ? 'var(--red)' : pct > 15 ? 'var(--orange)' : 'var(--cyan)';
    const icon = e.type === 'dir' ? '📁' : '📄';
    const drillBtn = e.type === 'dir'
      ? `<button class="btn-action" style="padding:4px 10px;font-size:11px;margin-right:4px" onclick="dkAnalyzeLoad('${dkJsArg(e.path)}')">Drill in</button>`
      : '';
    const cloudBadge = (e.cloud_bytes && e.cloud_bytes > 0)
      ? `<span title="Cloud-only files (iCloud/OneDrive/Dropbox) — not on local disk" style="display:inline-block;margin-left:6px;padding:1px 6px;font-size:9px;background:#3b82f633;color:#93c5fd;border-radius:3px;font-weight:600">☁ ${esc(e.cloud_human)}</span>`
      : '';
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-family:monospace;font-size:12px">${icon} ${esc(e.name)}</td>
      <td style="padding:6px 10px;text-align:right;font-weight:600;color:${col}">${esc(e.size_human)}${cloudBadge}</td>
      <td style="padding:6px 10px;width:200px">
        <div style="background:#ffffff11;border-radius:3px;height:6px"><div style="background:${col};height:100%;border-radius:3px;width:${pct}%"></div></div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px">${pct}% • ${e.item_count||0} items</div>
      </td>
      <td style="padding:6px 10px">
        ${drillBtn}
        <button class="btn-action" style="padding:4px 10px;font-size:11px" onclick="dkOpenFolder('${dkJsArg(e.path)}')">Open</button>
      </td>
    </tr>`;
  }).join('');
  document.getElementById('dk-analyze-tbody').innerHTML = rows;
}

async function dkAnalyzeLoad(path) {
  _dkAnalyzePath = path;
  document.getElementById('dk-analyze-error').style.display = 'none';
  document.getElementById('dk-analyze-tbody').innerHTML = '';
  document.getElementById('dk-analyze-total').textContent = '';
  // Breadcrumb
  const bc = document.getElementById('dk-analyze-breadcrumb');
  const segments = path.replace(/\\$/,'').split('\\');
  let bcHtml = '';
  let accum = '';
  segments.forEach((seg, i) => {
    if (i === 0) {
      accum = seg + '\\';
      bcHtml += `<a href="#" onclick="dkAnalyzeLoad('${dkJsArg(accum)}');return false" style="color:var(--cyan);text-decoration:none">${esc(seg)}\\</a>`;
    } else if (seg) {
      accum = accum + seg + '\\';
      bcHtml += ` / <a href="#" onclick="dkAnalyzeLoad('${dkJsArg(accum)}');return false" style="color:var(--cyan);text-decoration:none">${esc(seg)}</a>`;
    }
  });
  bc.innerHTML = bcHtml;

  // Check cache — instant back-navigation when drilling back up
  const cacheKey = path.replace(/\\+$/, '').toUpperCase();
  if (_dkAnalyzeCache.has(cacheKey)) {
    document.getElementById('dk-analyze-loading').style.display = 'none';
    _dkRenderAnalyzeResult(_dkAnalyzeCache.get(cacheKey));
    return;
  }

  const loadEl = document.getElementById('dk-analyze-loading');
  loadEl.textContent = 'Scanning — large folders with cloud files can take several minutes\u2026';
  loadEl.style.display = 'block';
  try {
    const _ac = new AbortController();
    const _tid = setTimeout(() => _ac.abort(), 660000);
    const r = await fetch('/api/disk/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path: path, top_n: 30}),
      signal: _ac.signal
    });
    clearTimeout(_tid);
    const d = await r.json();
    loadEl.style.display = 'none';
    if (!d.ok) {
      const err = document.getElementById('dk-analyze-error');
      err.textContent = 'Scan failed: ' + (d.error || 'unknown error');
      err.style.display = 'block';
      return;
    }
    _dkAnalyzeCache.set(cacheKey, d);
    _dkRenderAnalyzeResult(d);
  } catch(e) {
    console.error('analyze failed', e);
    loadEl.style.display = 'none';
    const err = document.getElementById('dk-analyze-error');
    if (e.name === 'AbortError') {
      err.textContent = 'Scan timed out — this folder is very large. Try drilling into a subfolder instead.';
    } else {
      err.textContent = 'Scan failed: ' + e.message + ' — try drilling into a smaller subfolder.';
    }
    err.style.display = 'block';
  }
}

async function dkQuickWinsLoad(letter) {
  const loadingEl = document.getElementById('dk-quickwins-loading');
  const listEl = document.getElementById('dk-quickwins-list');
  loadingEl.style.display = 'block';
  listEl.innerHTML = '';
  try {
    const r = await fetch('/api/disk/quickwins?drive=' + encodeURIComponent(letter));
    const d = await r.json();
    loadingEl.style.display = 'none';
    if (!d.ok) {
      listEl.innerHTML = `<div style="color:var(--red);font-size:12px">Quick-wins failed: ${esc(d.error||'')}</div>`;
      return;
    }
    const groups = [
      {title: 'System', items: d.locations || []},
      {title: 'User profile', items: d.user_locations || []}
    ];
    let html = '';
    groups.forEach(g => {
      if (!g.items.length) return;
      html += `<div style="color:var(--muted);font-size:11px;margin:8px 0 4px;text-transform:uppercase">${esc(g.title)}</div>`;
      g.items.forEach(it => {
        if (!it.exists) return;
        const col = it.size_bytes > 1e9 ? 'var(--red)' : it.size_bytes > 1e8 ? 'var(--orange)' : 'var(--muted)';
        html += `<div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div style="font-weight:600;font-size:12px">${esc(it.label)}</div>
            <div style="font-weight:700;font-size:13px;color:${col}">${esc(it.size_human)}</div>
          </div>
          <div style="font-size:10px;color:var(--muted);margin-top:2px;word-break:break-all">${esc(it.path)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px">${esc(it.description)}</div>
          <div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">
            ${dkRenderQuickWinActions(it)}
          </div>
        </div>`;
      });
    });
    listEl.innerHTML = html || '<div style="color:var(--muted);font-size:12px">No quick-win locations found on this drive.</div>';
  } catch(e) {
    loadingEl.style.display = 'none';
    listEl.innerHTML = `<div style="color:var(--red);font-size:12px">Network error: ${esc(e.message)}</div>`;
  }
}

// Render the action buttons for a single quick-win item. Dispatches based on
// `action_kind` (open_folder | run_tool | info_only) returned by the backend.
// Items may also carry `extra_tools: [{tool, label}, ...]` for secondary
// tool buttons (e.g. Windows Installer offers PatchCleaner + Disk Cleanup).
function dkRenderQuickWinActions(it) {
  const kind = it.action_kind || 'open_folder';
  const openBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px" onclick="dkOpenFolder('${dkJsArg(it.path)}')">📁 Open folder</button>`;
  const extraBtns = (it.extra_tools || []).map(x =>
    `<button class="btn-action" style="padding:3px 8px;font-size:10px" onclick="dkRunTool('${dkJsArg(x.tool)}','${dkJsArg(x.label)}')">🧹 ${esc(x.label)}</button>`
  ).join('');
  if (kind === 'run_tool') {
    const toolLabel = it.tool_label || it.tool || 'tool';
    const runBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px;background:var(--cyan);color:#000" onclick="dkRunTool('${dkJsArg(it.tool||'')}','${dkJsArg(toolLabel)}')">🧹 Launch ${esc(toolLabel)}</button>`;
    return runBtn + extraBtns + openBtn;
  }
  if (kind === 'info_only') {
    const cli = it.cli || '';
    const cliBtn = `<button class="btn-action" style="padding:3px 8px;font-size:10px;background:var(--orange);color:#000" onclick="dkShowCli('${dkJsArg(it.label)}','${dkJsArg(cli)}','${dkJsArg(it.description||'')}')">📋 Show command</button>`;
    return cliBtn + extraBtns + openBtn;
  }
  // default: open_folder
  return openBtn + extraBtns;
}

async function dkRunTool(tool, label) {
  if (!tool) { alert('No tool key provided'); return; }
  try {
    const r = await fetch('/api/disk/run-tool', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tool: tool})
    });
    const d = await r.json();
    if (!d.ok) {
      // Third-party tools may report an install_url when not yet installed
      if (d.install_url) {
        const go = confirm(
          (d.error || (label + ' is not installed')) +
          '\n\nOpen the download page?\n' + d.install_url
        );
        if (go) window.open(d.install_url, '_blank', 'noopener,noreferrer');
      } else {
        alert('Could not launch ' + (label || tool) + ': ' + (d.error || 'unknown error'));
      }
    }
  } catch(e) {
    alert('Network error: ' + e.message);
  }
}

// Show an admin command in a modal dialog with a Copy button. Used for
// info_only quick-wins (WinSxS / hiberfil / etc.) where the user must run
// the command themselves from an elevated prompt.
function dkShowCli(label, cli, desc) {
  let modal = document.getElementById('dk-cli-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'dk-cli-modal';
    modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:10000;align-items:center;justify-content:center';
    modal.innerHTML = `
      <div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;max-width:640px;width:90%;box-shadow:0 10px 40px rgba(0,0,0,0.5)">
        <div id="dk-cli-title" style="font-weight:700;font-size:14px;margin-bottom:6px;color:var(--cyan)"></div>
        <div id="dk-cli-desc" style="font-size:12px;color:var(--muted);margin-bottom:10px"></div>
        <pre id="dk-cli-cmd" style="background:#000;color:#0f0;padding:10px;border-radius:4px;overflow:auto;font-size:12px;font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-all"></pre>
        <div style="font-size:11px;color:var(--orange);margin-top:6px">⚠ Run this command in an <b>elevated</b> PowerShell or Command Prompt (Run as Administrator).</div>
        <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
          <button class="btn-action" onclick="dkCopyCli()">📋 Copy</button>
          <button class="btn-action" onclick="document.getElementById('dk-cli-modal').style.display='none'">Close</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById('dk-cli-title').textContent = label || 'Command';
  document.getElementById('dk-cli-desc').textContent = desc || '';
  document.getElementById('dk-cli-cmd').textContent = cli || '';
  modal.style.display = 'flex';
}

function dkCopyCli() {
  const cmd = document.getElementById('dk-cli-cmd').textContent || '';
  if (!cmd) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(
      () => { const b = event.target; const orig = b.textContent; b.textContent = '✓ Copied'; setTimeout(() => b.textContent = orig, 1500); },
      () => alert('Copy failed — select the command manually.')
    );
  } else {
    // Fallback: select the <pre> text
    const range = document.createRange();
    range.selectNodeContents(document.getElementById('dk-cli-cmd'));
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    alert('Command selected — press Ctrl+C to copy.');
  }
}

async function dkOpenFolder(path) {
  try {
    const r = await fetch('/api/disk/open', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path: path})
    });
    const d = await r.json();
    if (!d.ok) alert('Could not open: ' + (d.error || 'unknown error'));
  } catch(e) {
    alert('Network error: ' + e.message);
  }
}

function dkHuman(n) {
  if (!n) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < units.length-1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}

