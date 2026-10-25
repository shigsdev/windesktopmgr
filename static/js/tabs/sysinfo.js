// System Info tab (prefix si) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ── System Info: Upgrade Opportunities (#43) ───
// Pure rendering function -- takes a list of opportunity records from
// summarize_upgrades() and emits cards into #si-upgrade-panel. Empty list
// hides the whole panel so the section title doesn't sit above an empty
// container. Severity controls the left-border colour:
//   ok      -> green   (informational, no action needed)
//   info    -> cyan    (an opportunity worth considering)
//   warning -> orange  (something suboptimal you can fix for free,
//                       e.g. running in single-channel mode)
//
// Optional fields rendered when present:
//   compat   -- list of {label,value} -- shown as a definition list
//               under detail. The "approved spec" answer to "what can
//               I actually buy that fits my board?"
//   caveats  -- list of strings -- shown as orange-bullet warnings
//               below detail (the "verify before spending money" notes)
//   links    -- list of {label,url} -- rendered as small link buttons
//               next to the action footer (e.g. OEM support page using
//               the Service Tag we already collected)
function siRenderUpgradePanel(opportunities) {
  const panel = document.getElementById("si-upgrade-panel");
  const body  = document.getElementById("si-upgrade-cards");
  if (!panel || !body) return;
  if (!opportunities || !opportunities.length) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "block";
  const sevColor = sev =>
    sev === "warning" ? "var(--orange)" :
    sev === "ok"      ? "var(--green)"  :
                        "var(--cyan)";
  const sevIcon = sev =>
    sev === "warning" ? "⚠" :
    sev === "ok"      ? "✓" :
                        "↑";
  const catIcon = cat =>
    cat === "memory"  ? "🧠" :
    cat === "cpu"     ? "⚡" :
    cat === "gpu"     ? "🎮" :
    cat === "nic"     ? "🌐" :
    cat === "pcie"    ? "🔧" :
    cat === "storage" ? "💾" : "🚀";
  body.innerHTML = opportunities.map(o => {
    const color = sevColor(o.severity);
    // Compat block -- definition list of approved specs (#43 follow-up
    // 2026-05-02). Two columns: cyan label, normal value. Mono font
    // keeps PartNumbers / JEDEC strings legible.
    const compatHtml = (o.compat && o.compat.length)
      ? `<div style="margin-top:8px;padding:8px 10px;background:var(--bg);border-radius:4px;font-size:11px;font-family:var(--font-mono);line-height:1.6">
          <div style="font-size:10px;color:var(--cyan);font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">Approved spec</div>
          ${o.compat.map(c => `
            <div style="display:flex;gap:8px;align-items:flex-start">
              <span style="color:var(--cyan);min-width:120px;flex-shrink:0">${esc(c.label||'')}</span>
              <span style="color:var(--text)">${esc(c.value||'')}</span>
            </div>
          `).join("")}
        </div>`
      : '';
    // Caveats -- orange ⚠ bullets so they read as "things to verify"
    // not as part of the recommendation. Renders one bullet per caveat.
    const caveatsHtml = (o.caveats && o.caveats.length)
      ? `<div style="margin-top:8px;font-size:11px;color:var(--text);line-height:1.5">
          ${o.caveats.map(c => `
            <div style="display:flex;gap:6px;align-items:flex-start;margin-top:3px">
              <span style="color:var(--orange);flex-shrink:0">⚠</span>
              <span>${esc(c)}</span>
            </div>
          `).join("")}
        </div>`
      : '';
    // Links -- shown to the right of the action so the click target is
    // visually obvious. target=_blank + rel=noopener so the OEM page
    // can't tamper with our tab.
    const linksHtml = (o.links && o.links.length)
      ? o.links.map(l =>
          `<a href="${esc(l.url||'')}" target="_blank" rel="noopener noreferrer"
              style="display:inline-block;margin-left:8px;padding:3px 10px;background:var(--cyan);color:#0d1117;border-radius:4px;font-size:11px;font-weight:600;text-decoration:none">🔗 ${esc(l.label||'')}</a>`
        ).join("")
      : '';
    return `
      <div class="upgrade-card" data-category="${esc(o.category||'')}" data-severity="${esc(o.severity||'')}"
           style="background:var(--surface);border:1px solid var(--border);border-left:4px solid ${color};
                  border-radius:8px;padding:14px 16px;margin-bottom:10px">
        <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px">
          <span style="font-size:20px">${catIcon(o.category)}</span>
          <div style="flex:1">
            <div style="font-weight:700;color:${color};font-size:14px;margin-bottom:2px">
              <span style="margin-right:6px">${sevIcon(o.severity)}</span>${esc(o.headline||'')}
            </div>
            ${o.detail ? `<div style="font-size:12px;color:var(--text);white-space:pre-wrap;line-height:1.5">${esc(o.detail)}</div>` : ''}
            ${compatHtml}
            ${caveatsHtml}
          </div>
        </div>
        ${(o.action || linksHtml) ? `<div style="margin-top:8px;padding:6px 10px;background:var(--bg);border-radius:4px;font-size:11px;color:var(--muted);font-family:var(--font-mono);display:flex;align-items:center;flex-wrap:wrap;gap:6px"><span style="flex:1"><span style="color:var(--cyan);font-weight:600">→ Action:</span> ${esc(o.action||'')}</span>${linksHtml}</div>` : ''}
      </div>
    `;
  }).join("");
}

async function loadSystemInfo() {
  document.getElementById("si-loading").style.display = "block";
  document.getElementById("si-content").style.display = "none";
  const staleBanner = document.getElementById("si-stale-banner");
  if (staleBanner) staleBanner.style.display = "none";
  try {
    const r = await fetch("/api/sysinfo/data");
    const j = await r.json();
    // Show stale/connectivity banner
    if (j.stale) {
      if (staleBanner) {
        staleBanner.style.display = "flex";
        staleBanner.querySelector(".stale-msg").textContent =
          "Data may be incomplete \u2014 " + (j.error || "collection issue");
        staleBanner.querySelector(".stale-time").textContent =
          "Attempted: " + new Date(j.collected_at).toLocaleString();
      }
    }
    // Show collected_at timestamp
    if (j.collected_at) {
      const tsEl = document.getElementById("si-collected-at");
      if (tsEl) tsEl.textContent = "Collected: " + new Date(j.collected_at).toLocaleString();
    }
    if (j.status === "ok" || j.status === "partial") {
      if (j.data && Object.keys(j.data).length > 0) {
        renderSystemInfo(j.data, j.upgrades);
        fetchSummary("sysinfo", j.data, "summary-sysinfo");
      } else {
        document.getElementById("si-loading").textContent = "No data returned.";
        return;
      }
    } else {
      document.getElementById("si-loading").textContent = "Error: " + (j.message || j.error || "Unknown");
      return;
    }
  } catch(e) {
    document.getElementById("si-loading").textContent = "Failed to load system info.";
    return;
  }
  document.getElementById("si-loading").style.display = "none";
  document.getElementById("si-content").style.display = "";
}

function renderSystemInfo(d, upgrades) {
  const comp = d.Computer || {};
  const os = d.OS || {};
  const cpu = d.CPU || {};
  const bios = d.BIOS || {};
  const bb = d.Baseboard || {};
  const gpus = d.GPU || [];
  const nics = d.Network || [];
  const nicHw = d.NetworkHardware || [];
  const ram = d.Memory || [];
  const memArrays = d.MemoryArray || [];
  const disks = d.Disks || [];
  const vols = d.Volumes || [];
  const sound = d.Sound || [];
  const usb = d.USBControllers || [];
  const slots = d.PCIeSlots || [];

  // Upgrade Opportunities panel (#43). Computed server-side by
  // summarize_upgrades() and shipped on the same response. Uses the
  // shared esc helper and `siRenderUpgradePanel` so the rendering can
  // be tested independently. Empty opportunities -> hide the panel
  // entirely so we don't waste vertical space when there's nothing
  // actionable to surface.
  siRenderUpgradePanel((upgrades && upgrades.opportunities) || []);

  // Stat cards
  document.getElementById("si-hostname").textContent = comp.Name || "\u2014";
  document.getElementById("si-os").textContent = (os.Name || "\u2014").replace("Microsoft ", "");
  document.getElementById("si-cpu-short").textContent = (cpu.Name || "\u2014").replace("Intel(R) Core(TM) ", "").replace(" Processor", "");
  document.getElementById("si-ram").textContent = (comp.TotalRAM_GB || 0) + " GB";
  document.getElementById("si-uptime").textContent = os.Uptime || "\u2014";
  document.getElementById("si-build").textContent = os.Build || "\u2014";

  // Computer section
  const compRows = [
    ["Computer Name", comp.Name], ["Domain / Workgroup", comp.Domain],
    ["Manufacturer", comp.Manufacturer], ["Model", comp.Model],
    ["System Type", comp.SystemType], ["Total RAM", comp.TotalRAM_GB + " GB"],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-comp-tbody").innerHTML = compRows;

  // OS section
  const osRows = [
    ["OS Name", os.Name], ["Version", os.Version], ["Build", os.Build],
    ["Architecture", os.Architecture], ["Install Date", os.InstallDate],
    ["Last Boot", os.LastBoot], ["Uptime", os.Uptime],
    ["Windows Directory", os.WindowsDir], ["System Drive", os.SystemDrive],
    ["Locale", os.Locale], ["Time Zone", os.TimeZone],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-os-tbody").innerHTML = osRows;

  // CPU section
  const cpuRows = [
    ["Processor", cpu.Name], ["Cores", cpu.Cores], ["Logical Processors", cpu.LogicalProcs],
    ["Max Clock", cpu.MaxClockMHz + " MHz"], ["Current Clock", cpu.CurrentClockMHz + " MHz"],
    ["Socket", cpu.SocketDesignation], ["L2 Cache", (cpu.L2CacheKB ? cpu.L2CacheKB + " KB" : "\u2014")],
    ["L3 Cache", (cpu.L3CacheKB ? Math.round(cpu.L3CacheKB/1024) + " MB" : "\u2014")],
    ["Architecture", cpu.Architecture], ["Processor ID", cpu.ProcessorId],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-cpu-tbody").innerHTML = cpuRows;

  // BIOS + Baseboard section
  const biosRows = [
    ["BIOS Version", bios.Version], ["BIOS Date", bios.ReleaseDate],
    ["BIOS Manufacturer", bios.Manufacturer], ["Serial Number (Service Tag)", bios.SerialNumber],
    ["Baseboard", bb.Manufacturer + " " + bb.Product],
    ["Baseboard Version", bb.Version], ["Baseboard Serial", bb.SerialNumber],
  ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  document.getElementById("si-bios-tbody").innerHTML = biosRows;

  // GPU section (expanded with manufacturer + PNP ID)
  const gpuHtml = gpus.map(g => {
    const vram = g.AdapterRAM ? Math.round(g.AdapterRAM / 1073741824) + " GB" : "\u2014";
    return [
      ["GPU", g.Name], ["Manufacturer", g.AdapterCompatibility], ["Driver Version", g.DriverVersion],
      ["Video RAM", vram], ["Refresh Rate", (g.CurrentRefreshRate||"\u2014") + " Hz"],
      ["Resolution", g.VideoModeDescription], ["PNP Device ID", g.PNPDeviceID],
    ].map(([k,v]) => `<tr><td style="color:var(--cyan);width:200px">${k}</td><td>${v||'\u2014'}</td></tr>`).join("");
  }).join('<tr><td colspan="2" style="border-top:1px solid var(--border)"></td></tr>');
  document.getElementById("si-gpu-tbody").innerHTML = gpuHtml || '<tr><td colspan="2" style="color:var(--muted)">No GPU detected</td></tr>';

  // Memory modules (expanded with type, form factor, clock, locator)
  const ramHtml = ram.map(m => {
    const gb = m.Capacity ? (m.Capacity / 1073741824).toFixed(0) + " GB" : "\u2014";
    return `<tr><td>${m.BankLabel||'\u2014'}</td><td>${m.DeviceLocator||'\u2014'}</td><td>${gb}</td><td>${m.MemoryType||'\u2014'}</td><td>${m.FormFactor||'\u2014'}</td><td>${m.ConfiguredClockSpeed||m.Speed||'\u2014'} MHz</td><td>${m.Manufacturer||'\u2014'}</td><td><code>${(m.PartNumber||'').trim()}</code></td></tr>`;
  }).join("");
  document.getElementById("si-ram-tbody").innerHTML = ramHtml || '<tr><td colspan="8" style="color:var(--muted)">No data</td></tr>';

  // Memory Array board-limits header (#43). Sums slots + max capacity
  // across arrays (typically 1 on desktops; can be >1 on workstation /
  // server boards). Renders nothing if WMI didn't return MemoryArray
  // data -- some VMs and OEM-locked firmware suppress it.
  const memHdr = document.getElementById("si-ram-board-header");
  if (memHdr) {
    if (memArrays.length) {
      const totalSlots = memArrays.reduce((a, x) => a + (x.MemoryDevices || 0), 0);
      const maxGB = memArrays.reduce((a, x) => a + (x.MaxCapacityGB || 0), 0);
      const usedSlots = ram.filter(m => (m.Capacity || 0) > 0).length;
      const installedGB = ram.reduce((a, m) => a + (m.Capacity || 0), 0) / 1073741824;
      const headroomGB = Math.max(0, maxGB - installedGB);
      const ec = memArrays.find(a => a.MemoryErrorCorrection)?.MemoryErrorCorrection || "";
      memHdr.innerHTML = `
        <span style="color:var(--cyan)">Slots used:</span> <strong>${usedSlots} of ${totalSlots}</strong>
        &nbsp;\u00b7&nbsp;
        <span style="color:var(--cyan)">Max board capacity:</span> <strong>${maxGB.toFixed(0)} GB</strong>
        &nbsp;\u00b7&nbsp;
        <span style="color:var(--cyan)">Headroom:</span> <strong style="color:${headroomGB > 0 ? 'var(--green)' : 'var(--muted)'}">+${headroomGB.toFixed(1)} GB</strong>
        ${ec ? `&nbsp;\u00b7&nbsp;<span style="color:var(--cyan)">ECC:</span> ${ec}` : ''}
      `;
      memHdr.style.display = "block";
    } else {
      memHdr.style.display = "none";
    }
  }

  // Network adapters (IP config)
  const nicHtml = nics.map(n => {
    const dns = Array.isArray(n.DNSServerSearchOrder) ? n.DNSServerSearchOrder.join(", ") : (n.DNSServerSearchOrder||"\u2014");
    return `<tr><td>${n.Description||'\u2014'}</td><td><code>${n.MACAddress||'\u2014'}</code></td><td>${n.IPAddress||'\u2014'}</td><td>${n.DHCPEnabled ? 'Yes ('+n.DHCPServer+')' : 'Static'}</td><td style="font-size:11px">${dns}</td></tr>`;
  }).join("");
  document.getElementById("si-nic-tbody").innerHTML = nicHtml || '<tr><td colspan="5" style="color:var(--muted)">No active adapters</td></tr>';

  // Network hardware (manufacturer details)
  const nicHwHtml = nicHw.map(n => {
    const speed = n.Speed ? (n.Speed >= 1e9 ? (n.Speed/1e9).toFixed(0) + " Gbps" : (n.Speed/1e6).toFixed(0) + " Mbps") : "\u2014";
    return `<tr><td>${n.Name||'\u2014'}</td><td>${n.Manufacturer||'\u2014'}</td><td>${n.NetConnectionID||'\u2014'}</td><td>${speed}</td><td>${n.AdapterType||'\u2014'}</td><td><code>${n.MACAddress||'\u2014'}</code></td></tr>`;
  }).join("");
  document.getElementById("si-nichw-tbody").innerHTML = nicHwHtml || '<tr><td colspan="6" style="color:var(--muted)">No adapters</td></tr>';

  // Sound devices
  const soundHtml = sound.map(s => {
    const statusCol = (s.Status||"").toLowerCase() === "ok" ? "var(--green)" : "var(--orange)";
    return `<tr><td>${s.Name||'\u2014'}</td><td>${s.Manufacturer||'\u2014'}</td><td style="color:${statusCol}">${s.Status||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-sound-tbody").innerHTML = soundHtml || '<tr><td colspan="3" style="color:var(--muted)">No sound devices</td></tr>';

  // USB controllers
  const usbHtml = usb.map(u => {
    const statusCol = (u.Status||"").toLowerCase() === "ok" ? "var(--green)" : "var(--orange)";
    return `<tr><td>${u.Name||'\u2014'}</td><td>${u.Manufacturer||'\u2014'}</td><td style="color:${statusCol}">${u.Status||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-usb-tbody").innerHTML = usbHtml || '<tr><td colspan="3" style="color:var(--muted)">No USB controllers</td></tr>';

  // PCIe slots
  const slotHtml = slots.map(s => {
    const usageCol = s.CurrentUsage === "In Use" ? "var(--green)" : s.CurrentUsage === "Available" ? "var(--muted)" : "var(--orange)";
    return `<tr><td>${s.SlotDesignation||'\u2014'}</td><td style="color:${usageCol}">${s.CurrentUsage||'\u2014'}</td><td>${s.Status||'\u2014'}</td><td style="font-size:11px">${s.Description||'\u2014'}</td></tr>`;
  }).join("");
  document.getElementById("si-pcie-tbody").innerHTML = slotHtml || '<tr><td colspan="4" style="color:var(--muted)">No slot data</td></tr>';

  // PCIe slot summary header (#43) -- matches the Memory header style
  // so the upgrade-relevant numbers are visible at a glance without
  // scanning the row count.
  const pcieHdr = document.getElementById("si-pcie-summary-header");
  if (pcieHdr) {
    if (slots.length) {
      const free = slots.filter(s => (s.CurrentUsage || "").toLowerCase() === "available").length;
      pcieHdr.innerHTML = `
        <span style="color:var(--cyan)">Free slots:</span>
        <strong style="color:${free > 0 ? 'var(--green)' : 'var(--muted)'}">${free} of ${slots.length}</strong>
        ${free > 0 ? '&nbsp;\u00b7&nbsp;<span style="color:var(--muted)">Capacity for: GPU, NIC, capture card, NVMe carrier, HBA</span>' : ''}
      `;
      pcieHdr.style.display = "block";
    } else {
      pcieHdr.style.display = "none";
    }
  }

  // Disks
  const diskHtml = disks.map(dk => {
    const sizeGB = dk.Size ? (dk.Size / 1073741824).toFixed(1) + " GB" : "\u2014";
    return `<tr><td>${dk.Model||'\u2014'}</td><td>${sizeGB}</td><td>${dk.InterfaceType||'\u2014'}</td><td>${dk.MediaType||'\u2014'}</td><td>${dk.Partitions||'\u2014'}</td><td style="font-size:10px"><code>${(dk.SerialNumber||'').trim()}</code></td></tr>`;
  }).join("");
  document.getElementById("si-disk-tbody").innerHTML = diskHtml || '<tr><td colspan="6" style="color:var(--muted)">No disks</td></tr>';

  // Volumes
  const volHtml = vols.map(v => {
    const pctFree = v.SizeGB ? ((v.FreeGB / v.SizeGB) * 100).toFixed(1) : 0;
    const col = pctFree < 10 ? "var(--red)" : pctFree < 20 ? "var(--orange)" : "var(--green)";
    return `<tr><td><strong>${v.DeviceID||'\u2014'}</strong></td><td>${v.VolumeName||''}</td><td>${v.FileSystem||'\u2014'}</td><td>${v.SizeGB||'\u2014'} GB</td><td>${v.FreeGB||'\u2014'} GB</td><td style="color:${col};font-weight:600">${pctFree}%</td></tr>`;
  }).join("");
  document.getElementById("si-vol-tbody").innerHTML = volHtml || '<tr><td colspan="6" style="color:var(--muted)">No volumes</td></tr>';
}
