// Home Network tab (prefix hn) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ── Home Network Management ──────────────────────────────────────────────
let _hnDevices = [];
let _hnDevicesFilt = [];
let _hnLightPollId = null;   // 60s ARP-only poll
let _hnFullPollId = null;    // 5min full scan poll
let _hnPollActive = false;   // true when tab is visible

function _hnStartPolling() {
  if (_hnPollActive) return;
  _hnPollActive = true;
  // Light poll every 60s (ARP only — fast)
  _hnLightPollId = setInterval(() => _hnLightPoll(), 60000);
  // Full scan every 5 min (ARP + routers)
  _hnFullPollId = setInterval(() => _hnFullPoll(), 300000);
}

function _hnStopPolling() {
  _hnPollActive = false;
  if (_hnLightPollId) { clearInterval(_hnLightPollId); _hnLightPollId = null; }
  if (_hnFullPollId)  { clearInterval(_hnFullPollId);  _hnFullPollId = null; }
}

async function _hnLightPoll() {
  // Only poll when the homenet tab is visible
  if (document.querySelector('.page-tab.active')?.dataset.page !== 'homenet') {
    _hnStopPolling();
    return;
  }
  try {
    const r = await fetch("/api/homenet/scan/light", {method: "POST"});
    const data = await r.json();
    if (data.ok) _hnUpdateUI(data);
  } catch(e) { console.error("light poll error:", e); }
}

async function _hnFullPoll() {
  if (document.querySelector('.page-tab.active')?.dataset.page !== 'homenet') {
    _hnStopPolling();
    return;
  }
  try {
    const btn = document.getElementById("hn-scan-btn");
    btn.textContent = "Auto-scanning…";
    const r = await fetch("/api/homenet/scan", {method: "POST"});
    const data = await r.json();
    if (data.errors && data.errors.length) {
      const errDiv = document.getElementById("hn-errors");
      errDiv.style.display = "block";
      errDiv.textContent = data.errors.join(" | ");
    }
    if (data.ok) _hnUpdateUI(data);
    btn.textContent = "🔍 Scan Network";
  } catch(e) {
    console.error("full poll error:", e);
    document.getElementById("hn-scan-btn").textContent = "🔍 Scan Network";
  }
}

function _hnUpdateUI(data) {
  _hnDevices = data.devices || [];
  document.getElementById("hn-total").textContent = data.device_count || 0;
  document.getElementById("hn-online").textContent = _hnDevices.filter(d => d.active).length;
  document.getElementById("hn-wired").textContent = _hnDevices.filter(d => d.network === "wired").length;
  document.getElementById("hn-wireless").textContent = _hnDevices.filter(d => d.network === "wireless").length;
  document.getElementById("hn-lastscan").textContent = data.last_scan
    ? new Date(data.last_scan).toLocaleString() : "Never";
  filterHomeNet(); // re-apply current filters
}

async function loadHomeNet() {
  document.getElementById("hn-devices-loading").style.display = "block";
  document.getElementById("hn-devices-table").style.display = "none";
  document.getElementById("hn-devices-empty").style.display = "none";

  // Load credentials
  try {
    const cr = await fetch("/api/homenet/credentials");
    const creds = await cr.json();
    renderHomeNetCredentials(creds);
  } catch(e) { console.error("creds load error:", e); }

  // Load inventory
  try {
    const r = await fetch("/api/homenet/inventory");
    const data = await r.json();
    _hnUpdateUI(data);
  } catch(e) {
    console.error("inventory load error:", e);
  }

  document.getElementById("hn-devices-loading").style.display = "none";

  // Start auto-polling
  _hnStartPolling();
}

function renderHomeNetCredentials(creds) {
  const grid = document.getElementById("hn-creds-grid");
  document.getElementById("hn-creds-loading").style.display = "none";
  grid.style.display = "grid";
  grid.innerHTML = creds.map(c => `
    <div style="padding:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-weight:600;font-size:13px">${esc(c.label)}</span>
        <span style="font-size:10px;padding:2px 8px;border-radius:10px;${
          c.configured
            ? 'background:var(--green-dim);color:var(--green)'
            : 'background:var(--red-dim);color:var(--red)'
        }">${c.configured ? 'Configured' : 'Not Set'}</span>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:6px">IP: ${esc(c.ip)}</div>
      ${c.configured
        ? `<div style="font-size:11px;margin-bottom:8px">User: <span style="color:var(--cyan)">${esc(c.username)}</span> &nbsp; Pass: <span style="color:var(--muted)">${esc(c.password_hint)}</span></div>
           <div style="display:flex;gap:6px">
             <button onclick="testCredentialDirect('${c.key}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--cyan);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Test</button>
             <button onclick="openCredModal('${c.key}','${escJsArg(c.label)}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--orange);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Change</button>
             <button onclick="deleteCredential('${c.key}')" style="padding:3px 10px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--red);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Delete</button>
           </div>`
        : `<button onclick="openCredModal('${c.key}','${escJsArg(c.label)}')" class="btn-action" style="padding:4px 12px;font-size:11px">Add Credentials</button>`
      }
    </div>
  `).join("");
}

function renderHomeNet() {
  const tbody = document.getElementById("hn-devices-tbody");
  const table = document.getElementById("hn-devices-table");
  const empty = document.getElementById("hn-devices-empty");

  if (!_hnDevicesFilt.length) {
    table.style.display = "none";
    empty.style.display = "block";
    return;
  }

  table.style.display = "table";
  empty.style.display = "none";

  // Sort: active first, then by IP
  const sorted = _hnDevicesFilt.slice().sort((a, b) => {
    if (a.active !== b.active) return b.active - a.active;
    const aOctets = (a.ip||"0.0.0.0").split(".").map(Number);
    const bOctets = (b.ip||"0.0.0.0").split(".").map(Number);
    for (let i = 0; i < 4; i++) { if (aOctets[i] !== bOctets[i]) return aOctets[i] - bOctets[i]; }
    return 0;
  });

  tbody.innerHTML = sorted.map(d => {
    const displayName = d.friendly_name || d.hostname || d.vendor || "Unknown";
    const netColor = d.network === "wired" ? "var(--orange)" : "var(--purple)";
    const netLabel = d.network === "wired" ? "Wired" : "WiFi";
    const statusDot = d.active
      ? '<span style="color:var(--green);font-size:14px">●</span>'
      : '<span style="color:var(--muted);font-size:14px">○</span>';
    const cat = d.category || '<span style="color:var(--muted)">—</span>';
    return `<tr style="border-bottom:1px solid var(--border)" class="hn-device-row"
               data-name="${esc(displayName).toLowerCase()}" data-ip="${esc(d.ip)}"
               data-mac="${esc(d.mac)}" data-vendor="${esc(d.vendor||'').toLowerCase()}"
               data-network="${d.network}" data-category="${(d.category||'').toLowerCase()}">
      <td style="padding:6px 10px">${statusDot}</td>
      <td style="padding:6px 10px;color:var(--text-bright)">${esc(displayName)}${d.friendly_name && d.hostname ? '<br><span style="font-size:10px;color:var(--muted)">'+esc(d.hostname)+'</span>' : ''}</td>
      <td style="padding:6px 10px;color:var(--cyan)">${esc(d.ip)}</td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${esc(d.mac)}</td>
      <td style="padding:6px 10px">${esc(d.vendor)}</td>
      <td style="padding:6px 10px"><span style="color:${netColor};font-size:11px;padding:1px 6px;border-radius:8px;border:1px solid ${netColor}">${netLabel}</span></td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${d.network === "wireless" && d.ssid ? esc(d.ssid) : '—'}</td>
      <td style="padding:6px 10px">${cat}</td>
      <td style="padding:6px 10px">
        <button onclick="openEditModal('${escJsArg(d.mac)}')" style="padding:2px 8px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--cyan);cursor:pointer;font-size:11px;font-family:var(--font-mono)">Edit</button>
      </td>
    </tr>`;
  }).join("");
}

// ── Network Topology Diagram (#9) ──────────────────────────────────────
//
// Renders a 3-tier hierarchical SVG: router (top) → infrastructure
// (switch + Orbi APs, middle) → devices (bottom, grouped under their
// uplink). Inline SVG -- no chart library, no canvas, just primitive
// <line> / <rect> / <circle> / <text> elements. Reads the cached
// inventory; doesn't trigger a fresh scan (the existing Scan button
// does that and the user clicks Refresh after to re-render).
//
// Category icon mapping mirrors the inventory table so a Phone in the
// list is also a Phone (📱) in the diagram.

const _HN_CAT_ICON = {
  "Computer": "💻", "Phone": "📱", "TV": "📺", "IoT": "💡",
  "Printer": "🖨", "Network": "🛜", "Storage": "💾", "Other": "📦",
};

let _hnTopoLoaded = false;

async function hnTopoToggle() {
  const body = document.getElementById("hn-topo-body");
  const btn = document.getElementById("hn-topo-toggle");
  if (!body || !btn) return;
  const isHidden = body.style.display === "none";
  if (isHidden) {
    body.style.display = "";
    btn.textContent = "📐 Hide diagram";
    if (!_hnTopoLoaded) {
      await hnTopoRefresh();
      _hnTopoLoaded = true;
    }
  } else {
    body.style.display = "none";
    btn.textContent = "📐 Show diagram";
  }
}

// Manually add a transparent device by MAC -- for MoCA bridges and other
// LAN-invisible gear (no IP, never in ARP). Uses two prompt() calls to keep
// the UX simple; a fancier modal could be added later.
async function hnTopoAddTransparent() {
  const mac = (prompt(
    "Add a transparent device by MAC address.\n\n" +
    "Use this for MoCA bridges that have no IP and don't show up in network scans " +
    "(common with Verizon-branded Askey FiOS extenders).\n\n" +
    "Enter the MAC address (printed on the back of the device, format AA:BB:CC:DD:EE:FF):"
  ) || "").trim();
  if (!mac) return;
  const friendly = (prompt("Friendly name (optional, e.g. 'Living Room MoCA'):") || "").trim();
  try {
    const r = await fetch("/api/homenet/device/add-manual", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ mac: mac, friendly_name: friendly, wired_via: "moca_bridge" }),
    });
    const data = await r.json();
    if (data.ok) {
      alert(`Added: ${data.device.mac} (${data.device.vendor || 'unknown vendor'})`);
      _hnTopoLoaded = false;
      await hnTopoRefresh();
      _hnTopoLoaded = true;
    } else {
      alert("Failed: " + (data.message || "unknown error"));
    }
  } catch (e) {
    alert("Failed to add device: " + e.message);
  }
}

async function hnTopoRefresh() {
  const loading = document.getElementById("hn-topo-loading");
  const errorEl = document.getElementById("hn-topo-error");
  const wrap = document.getElementById("hn-topo-svg-wrap");
  const legend = document.getElementById("hn-topo-legend");
  const stats = document.getElementById("hn-topo-stats");
  if (!loading) return;

  loading.style.display = "";
  errorEl.style.display = "none";
  wrap.style.display = "none";
  if (legend) legend.style.display = "none";

  let data;
  try {
    const r = await fetch("/api/homenet/topology");
    data = await r.json();
  } catch (e) {
    loading.style.display = "none";
    errorEl.style.display = "";
    errorEl.textContent = "Failed to fetch topology: " + e.message;
    return;
  }
  loading.style.display = "none";
  if (!data.ok) {
    errorEl.style.display = "";
    errorEl.textContent = "Topology API returned ok=false";
    return;
  }

  // Update the small stats line above the diagram
  const s = data.stats || {};
  if (stats) {
    const parts = [
      `${s.total || 0} devices`,
      `${s.wired_mapped || 0} on switch`,
      `${s.wireless_mapped || 0} wireless-mapped`,
    ];
    if (s.via_verizon_or_moca) parts.push(`${s.via_verizon_or_moca} Verizon-direct/MoCA`);
    if (s.moca_bridges) parts.push(`${s.moca_bridges} MoCA bridge${s.moca_bridges !== 1 ? "s" : ""}`);
    if (s.orbi_mesh_unknown_ap) parts.push(`${s.orbi_mesh_unknown_ap} unknown (Orbi firmware doesn't expose per-satellite mapping)`);
    if (s.unmapped) parts.push(`${s.unmapped} unmapped`);
    if (!s.switch_available) parts.push("⚠ switch unreachable — see Network Settings");
    // Hint: surface a one-line nudge if any satellite is still showing as
    // the "Orbi satellite (XXXX)" fallback. The RBRE960 firmware doesn't
    // expose satellite names via SOAP (every action returns ResponseCode
    // 404 -- not implemented on this firmware), so the user has to set
    // them manually via the inventory edit modal. The auto-synthesised
    // satellite entries land in the device table below with vendor=Netgear
    // + notes="Orbi satellite -- auto-added".
    const fallbackSats = (data.aps || []).filter(ap => /^Orbi satellite \([0-9A-F]{4}\)$/.test(ap.name));
    if (fallbackSats.length) {
      parts.push(`💡 ${fallbackSats.length} satellite${fallbackSats.length !== 1 ? "s" : ""} still using fallback name -- set "friendly_name" via the device table below`);
    }
    stats.textContent = parts.join(" · ");
  }

  wrap.style.display = "";
  if (legend) legend.style.display = "flex";
  // Bug fix 2026-05-12: openEditModal(mac) looks devices up in _hnDevices,
  // which is populated from /api/homenet/inventory. If the user opens
  // the topology section BEFORE the inventory poll has fired (timing
  // race on first tab activation), clicking a MoCA bridge / Orbi AP
  // header is a silent no-op. Backfill _hnDevices from the topology
  // payload's devices map so the clickable headers work immediately.
  if (!_hnDevices.length && data.devices && typeof data.devices === "object") {
    _hnDevices = Object.values(data.devices);
  }
  wrap.innerHTML = hnTopoBuildSvg(data);
}

// Build the SVG from a topology payload. Layout is hand-rolled because we
// only need three tiers and the math is trivial:
//   y=40   router
//   y=140  infra row (switch + each AP)
//   y=260+ device rows under each infra node
function hnTopoBuildSvg(t) {
  const PAD = 20;
  const ROW_H = 26;
  const NODE_W = 220;
  const ROUTER_Y = 40;
  const INFRA_Y = 130;
  const DEVICE_Y = 230;

  const devices = t.devices || {};

  // Build the infra columns: switch + every AP. Each column hosts a stack
  // of device boxes underneath. The column width adapts to the tallest
  // stack so the SVG never overflows the viewport.
  const columns = [];
  for (const sw of (t.switches || [])) {
    // For wired we group devices by port. A port may carry multiple MACs
    // (the Orbi base on its uplink port carries every wireless client) --
    // we collapse those into a "(N more)" pill rather than render them
    // here, since they show up under their AP elsewhere.
    const portRows = [];
    const ports = sw.ports || {};
    const sortedPorts = Object.keys(ports).map(Number).sort((a, b) => a - b);
    for (const p of sortedPorts) {
      const macs = ports[p] || [];
      const realDevs = macs.filter(m => devices[m] && !_hnIsInfra(devices[m]));
      const apsOnPort = macs.filter(m => devices[m] && _hnIsAp(devices[m]));
      if (!realDevs.length && !apsOnPort.length) continue;
      // Pick the most informative one to show; collapse the rest.
      for (const m of realDevs) {
        portRows.push({ mac: m, label: `port ${p}`, dev: devices[m] });
      }
      for (const m of apsOnPort) {
        portRows.push({ mac: m, label: `port ${p} (uplink)`, dev: devices[m], is_ap: true });
      }
    }
    columns.push({
      kind: "switch",
      id: sw.id,
      name: sw.name,
      sub: sw.available ? "" : (sw.error ? "switch unreachable" : "no MAC table"),
      rows: portRows,
    });
  }

  for (const ap of (t.aps || [])) {
    const rows = ap.clients.map(m => ({ mac: m, label: ap.is_base ? "via Orbi base" : "via satellite", dev: devices[m] || { mac: m } }));
    // Subtitle hints when the AP has no user-set friendly_name so the
    // user knows clicking the header opens the edit modal. The Orbi base
    // always has a friendly fallback ("Orbi RBRE960 (Base)") from
    // _INFRA_LABELS, so the hint only really fires for satellites.
    const apDev = devices[ap.mac] || {};
    const apFriendly = (apDev.friendly_name || "").trim();
    const apSub = apFriendly || ap.is_base
      ? `${ap.clients.length} client${ap.clients.length !== 1 ? "s" : ""}`
      : `✏ click header to name · ${ap.clients.length} client${ap.clients.length !== 1 ? "s" : ""}`;
    columns.push({
      kind: ap.is_base ? "ap_base" : "ap_satellite",
      id: ap.id,
      name: ap.name,
      sub: apSub,
      rows: rows,
      // Click the header → open the edit modal for this AP's MAC so the
      // user can set a friendly_name without hunting through the device
      // table.
      click_mac: ap.mac,
    });
  }

  // Two SEPARATE columns now (was one combined "Verizon-direct / MoCA"):
  //   - "Verizon LAN port"  → wired devices physically plugged into the
  //     Verizon CR1000A's 4 LAN ports
  //   - "via MoCA"           → wired devices reaching the LAN over coax,
  //     downstream of a MoCA bridge
  // These are distinct paths and the user (correctly) wanted them split.
  // Until per-device topology data from the Verizon API is wired up,
  // assignment is per-device user-set via the edit modal's Wired-via
  // dropdown. Devices with no wired_via set default to verizon_lan
  // (most common in typical home setups).
  if ((t.verizon_lan || []).length) {
    columns.push({
      kind: "verizon_lan",
      id: "verizon-lan",
      name: "Verizon LAN port",
      sub: `${t.verizon_lan.length} device${t.verizon_lan.length !== 1 ? "s" : ""} on Verizon LAN ports`,
      rows: t.verizon_lan.map(m => ({ mac: m, label: "Verizon LAN", dev: devices[m] || { mac: m } })),
    });
  }
  if ((t.via_moca || []).length) {
    columns.push({
      kind: "via_moca",
      id: "via-moca",
      name: "via MoCA (coax)",
      sub: `${t.via_moca.length} device${t.via_moca.length !== 1 ? "s" : ""} downstream of MoCA bridge`,
      rows: t.via_moca.map(m => ({ mac: m, label: "via MoCA", dev: devices[m] || { mac: m } })),
    });
  }

  // MoCA Bridges -- ONE COLUMN PER BRIDGE (user feedback 2026-05-08:
  // "shows one moca bridge" -- the previous layout crammed all bridges
  // into a single collapsed column, asymmetric with Orbi satellites
  // which each get their own column). Each bridge column:
  //   - title: friendly_name if set, else "<vendor> <last 4 of MAC>"
  //     (mirrors how Orbi satellite fallback names look)
  //   - sub: downstream device count
  //   - rows: the devices the user has marked behind_moca_bridge=<this>
  //
  // Degenerate case (zero bridges with downstream devices, which is
  // typical right after #42 auto-discovery): emit one column per
  // bridge anyway -- the empty columns act as a "click here to assign
  // devices" affordance, and the user can populate them via the
  // device-edit modal's "Behind MoCA bridge" dropdown. No fallback
  // to the old single-column layout because the user explicitly
  // asked for the per-bridge view.
  if ((t.moca_bridges || []).length) {
    const bridges = t.moca_bridges.slice(); // copy so sort doesn't mutate
    const childrenMap = t.moca_children || {};
    // Build per-bridge column metadata, sort alphabetically by display name
    // so the diagram is stable across scans regardless of MAC ordering.
    const bridgeColumns = bridges.map(bridgeMac => {
      const dev = devices[bridgeMac] || { mac: bridgeMac };
      const friendly = (dev.friendly_name || "").trim();
      const vendor = (dev.vendor || "Unknown").trim();
      // Last 4 hex chars of MAC (no colons) -- same compact fingerprint
      // the Orbi-satellite fallback uses, e.g. "Orbi satellite (73E1)".
      const macSuffix = bridgeMac.replace(/:/g, "").slice(-4).toUpperCase();
      const displayName = friendly || `${vendor} ${macSuffix}`;
      const kids = childrenMap[bridgeMac] || [];
      return { bridgeMac, dev, displayName, kids, hasFriendlyName: !!friendly };
    });
    bridgeColumns.sort((a, b) => a.displayName.localeCompare(b.displayName));
    for (const bc of bridgeColumns) {
      const rows = bc.kids.map(childMac => ({
        mac: childMac,
        label: "behind bridge",
        dev: devices[childMac] || { mac: childMac },
      }));
      // Subtitle hints the user that they can click to set a name. Only
      // shown when there's no friendly_name yet (otherwise the existing
      // downstream-device-count subtitle is more informative).
      let sub;
      if (!bc.hasFriendlyName) {
        sub = bc.kids.length
          ? `✏ click header to name · ${bc.kids.length} downstream`
          : "✏ click header to name";
      } else {
        sub = bc.kids.length
          ? `${bc.kids.length} downstream device${bc.kids.length !== 1 ? "s" : ""}`
          : "no downstream devices yet";
      }
      columns.push({
        kind: "moca",
        id: `moca-bridge-${bc.bridgeMac.replace(/:/g, "")}`,
        // Prefix with 📻 to mirror the Orbi 📡 visual hierarchy --
        // both are infrastructure tiers, so the icon-prefix tells you
        // "this is a hop, not a leaf device" at a glance.
        name: `📻 ${bc.displayName}`,
        sub,
        rows,
        // Carry the bridge-MAC through so the empty-state hint can
        // tell the user which bridge to assign devices to in the
        // edit modal, AND so the column header click handler can open
        // the device-edit modal for this bridge directly.
        bridge_mac: bc.bridgeMac,
        click_mac: bc.bridgeMac,
      });
    }
  }

  // "Unknown" column -- wireless devices the Orbi knows about but didn't
  // tell us which node they're on. Renamed from "Orbi mesh (AP unknown)"
  // to just "Unknown" per user request 2026-04-25 (the longer name was
  // confusing). Still honest UI for the Orbi SOAP-API limitation: they're
  // on the mesh somewhere, just not pinpointed to base/satellite.
  if ((t.orbi_mesh_unknown_ap || []).length) {
    // User feedback 2026-05-13: "I am assuming the unknown is one orbi
    // satellite and the unmapped is another" -- the previous column name
    // "Unknown" + same-shaped column visual encouraged that wrong mental
    // model. These are NOT separate satellites; they're failure-mode
    // buckets that happen to both contain wireless devices. Rename so the
    // difference is plain. Bug-source is the RBRE960 SOAP firmware quirk
    // (corrupted ConnAPMAC sentinel for satellite-connected clients).
    columns.push({
      kind: "orbi_mesh_unknown",
      id: "orbi-mesh-unknown",
      name: "Orbi mesh (satellite ?)",
      sub: `${t.orbi_mesh_unknown_ap.length} wireless · firmware didn't say WHICH satellite`,
      rows: t.orbi_mesh_unknown_ap.map(m => ({ mac: m, label: "wireless", dev: devices[m] || { mac: m } })),
    });
  }

  // Truly unmapped column on the right -- devices ARP saw but Orbi /
  // Verizon scans didn't return at all, so we have no AP info, no router
  // attestation, nothing. Distinct from "Orbi mesh (satellite ?)" above:
  // those came FROM the Orbi (it knows them, just won't say which AP);
  // these are ARP-only ghosts. Renamed 2026-05-13 to make the
  // distinction obvious.
  if ((t.unmapped || []).length) {
    columns.push({
      kind: "unmapped",
      id: "unmapped",
      name: "Unmapped (ARP-only)",
      sub: `${t.unmapped.length} device${t.unmapped.length !== 1 ? "s" : ""} · seen by ARP but not by Orbi/Verizon`,
      rows: t.unmapped.map(m => ({ mac: m, label: devices[m]?.network || "?", dev: devices[m] || { mac: m } })),
    });
  }

  // Per-column width is fixed; SVG width grows with column count.
  const COL_W = NODE_W + 30;
  const totalW = Math.max(800, PAD * 2 + COL_W * columns.length);
  const maxRows = Math.max(0, ...columns.map(c => c.rows.length));
  const totalH = DEVICE_Y + maxRows * ROW_H + 40;

  // Router box centered horizontally at the top
  const routerX = (totalW - NODE_W) / 2;
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalW} ${totalH}" style="width:${totalW}px;max-width:none;height:${totalH}px;font-family:var(--font-mono);font-size:11px">`;

  // ── Background grid for visual rhythm ─────────────────────────────
  svg += `<rect x="0" y="0" width="${totalW}" height="${totalH}" fill="none"/>`;

  // ── Tier 1: Router ────────────────────────────────────────────────
  svg += _hnSvgNode(routerX, ROUTER_Y, NODE_W, "🛜 " + (t.router?.name || "Router"), t.router?.ip || "", "var(--cyan)");

  // ── Tier 2: Infrastructure columns ─────────────────────────────────
  columns.forEach((col, i) => {
    const x = PAD + i * COL_W;
    const colorByKind = {
      switch: "var(--orange)",
      ap_base: "var(--purple)",
      ap_satellite: "var(--purple)",
      moca: "var(--cyan)",
      via_moca: "var(--cyan)",
      verizon_lan: "var(--yellow)",
      verizon_or_moca: "var(--yellow)",  // legacy kind, kept for safety
      orbi_mesh_unknown: "var(--purple)",
      unmapped: "var(--border)",
    };
    const iconByKind = { switch: "🔀", ap_base: "📡", ap_satellite: "📡", moca: "📻", via_moca: "🌀", verizon_lan: "🔌", verizon_or_moca: "🔌", orbi_mesh_unknown: "📶", unmapped: "❓" };
    const label = `${iconByKind[col.kind] || "•"} ${col.name}`;
    // data-column-kind / data-column-id make the column header
    // queryable from Playwright so the regression test for #42 follow-up
    // can assert "API says N MoCA bridges → SVG renders N moca columns"
    // without parsing visible label text. Mirrors the data-metric pattern
    // on Trends cards (#39).
    // When the column carries a click_mac (MoCA bridge / Orbi AP) wrap the
    // SVG node in a clickable <g> so the user can open the device-edit modal
    // for that MAC -- the primary entry point for setting friendly_name on
    // an infra node. Bug fix 2026-05-12: previously the only way to rename
    // a MoCA bridge was to scroll the device table and find it; topology
    // headers were inert. Cursor:pointer + a tooltip make the affordance
    // discoverable.
    const headerExtra = col.click_mac
      ? ` style="cursor:pointer" onclick="openEditModal('${escJsArg(col.click_mac)}')" data-click-mac="${_esc(col.click_mac)}"`
      : "";
    svg += `<g data-column-kind="${_esc(col.kind || '')}" data-column-id="${_esc(col.id || '')}"${headerExtra}>`;
    if (col.click_mac) {
      // Tooltip mirrors what the device-edit modal does so the user knows
      // what clicking the header will do.
      svg += `<title>Click to edit this ${col.kind === "moca" ? "MoCA bridge" : "Orbi AP"} (set a friendly name, location, notes)</title>`;
    }
    svg += _hnSvgNode(x, INFRA_Y, NODE_W, label, col.sub || "", colorByKind[col.kind] || "var(--muted)");
    svg += `</g>`;

    // Connector router → infra. Skip for "unmapped" only -- everything
    // else (switch, APs, MoCA bridges, Verizon-direct/MoCA bucket) does
    // ultimately route through the Verizon, so a line is correct.
    if (col.kind !== "unmapped") {
      svg += `<line x1="${routerX + NODE_W / 2}" y1="${ROUTER_Y + 50}" x2="${x + NODE_W / 2}" y2="${INFRA_Y}" stroke="var(--border)" stroke-width="1.2"/>`;
    }

    // ── Tier 3: device rows under this column ──────────────────────
    col.rows.forEach((r, rIdx) => {
      const y = DEVICE_Y + rIdx * ROW_H;
      const dev = r.dev || {};
      const cat = (dev.category || "Other");
      const icon = _HN_CAT_ICON[cat] || _HN_CAT_ICON.Other;
      const name = _hnTopoLabel(dev, r.mac);
      const isOnline = dev.active !== false;
      const isChild = !!r.is_child;
      // Children of MoCA bridges are indented to convey the parent->child
      // hierarchy. Non-child rows continue at the default x offset.
      const indentX = isChild ? 16 : 0;
      // Connector infra → device. Stops 6 px before the dot's outer edge
      // so the dot reads as a distinct circle, not as the line's terminus.
      svg += `<line x1="${x + NODE_W / 2}" y1="${INFRA_Y + 50}" x2="${x + 18 + indentX}" y2="${y + ROW_H / 2}" stroke="var(--border)" stroke-width="0.8" opacity="${isChild ? "0.25" : "0.4"}"/>`;
      // Status dot -- bigger (r=5 was 4) + a stroke so it pops over the
      // connector line. Active=green, inactive=hollow grey ring. Children
      // get a smaller dot to convey hierarchy at a glance.
      const dotFill = isOnline ? "var(--green)" : "var(--bg)";
      const dotStroke = isOnline ? "var(--green)" : "var(--muted)";
      const dotR = isChild ? 4 : 5;
      svg += `<circle cx="${x + 8 + indentX}" cy="${y + ROW_H / 2}" r="${dotR}" fill="${dotFill}" stroke="${dotStroke}" stroke-width="1.5" data-active="${isOnline}"/>`;
      // Device row -- clickable, opens the edit modal.
      const safeMac = (dev.mac || r.mac || "").replace(/'/g, "");
      const opacity = isOnline ? "1" : "0.55";
      const childTreeMark = isChild ? "└ " : "";
      const tooltip = `${name}\n${dev.mac || r.mac}\n${dev.ip || "no IP"}\n${r.label}\n(click to edit)`;
      svg += `<g opacity="${opacity}" style="cursor:pointer" onclick="openEditModal('${safeMac}')" data-device-mac="${_esc(dev.mac || r.mac || "")}" data-device-name="${_esc(name)}" data-is-child="${isChild}"><title>${_esc(tooltip)}</title>`;
      svg += `<text x="${x + 20 + indentX}" y="${y + ROW_H / 2 + 4}" fill="var(--text)" font-size="11">${childTreeMark}${icon} ${_truncate(_esc(name), 22 - (isChild ? 2 : 0))}</text>`;
      svg += `<text x="${x + NODE_W - 6}" y="${y + ROW_H / 2 + 4}" fill="var(--muted)" font-size="9" text-anchor="end">${_esc(r.label)}</text>`;
      svg += `</g>`;
    });
  });

  svg += "</svg>";
  return svg;
}

// Pick the most-informative human-readable label for a device row.
//
// Fallback chain:
//   1. friendly_name set by the user (always wins -- it's their explicit choice)
//   2. hostname from DNS / mDNS / router-side label
//   3. vendor from IEEE OUI lookup + last 4 hex of MAC
//      ("Microsoft 4100" beats "00:15:5D:62:A8:93" for skim-readability)
//   4. raw MAC -- last resort, only if literally nothing else is available
//
// Bug 2026-04-25: prior chain dropped to raw MAC for 6 of 76 devices in
// the user's inventory because both friendly_name AND hostname were empty
// (Hyper-V vNICs, randomized phone MACs, mDNS-shy IoT). Now the vendor +
// suffix step gives them readable identities.
function _hnTopoLabel(dev, fallbackMac) {
  const friendly = (dev.friendly_name || "").trim();
  if (friendly) return friendly;
  const hostname = (dev.hostname || "").trim();
  if (hostname) {
    // Strip the boring ".mynetworksettings.com" suffix that shows on every
    // Verizon-DHCP'd device -- it adds noise and truncates real names.
    return hostname.replace(/\.mynetworksettings\.com$/i, "");
  }
  const mac = (dev.mac || fallbackMac || "").toUpperCase();
  const vendor = (dev.vendor || "").trim();
  if (vendor && mac) {
    // Take the first word of the vendor (e.g. "Microsoft Corporation" -> "Microsoft")
    // and append the last 4 hex chars for uniqueness.
    const shortVendor = vendor.split(/[\s,]/)[0];
    const suffix = mac.replace(/:/g, "").slice(-4);
    return `${shortVendor} ${suffix}`;
  }
  return mac || "(unknown)";
}

function _hnSvgNode(x, y, w, label, sub, color) {
  return `
    <g>
      <rect x="${x}" y="${y}" width="${w}" height="50" rx="6" fill="var(--card)" stroke="${color}" stroke-width="1.5"/>
      <text x="${x + w / 2}" y="${y + 20}" fill="var(--text-bright)" font-size="12" font-weight="700" text-anchor="middle">${_esc(label)}</text>
      ${sub ? `<text x="${x + w / 2}" y="${y + 38}" fill="var(--muted)" font-size="10" text-anchor="middle">${_esc(sub)}</text>` : ""}
    </g>`;
}

function _hnIsInfra(dev) {
  if (!dev) return false;
  const ip = dev.ip || "";
  if (ip === "192.168.1.1" || ip === "10.0.0.1") return true;
  return (dev.mac || "").toUpperCase() === "DC:62:79:F3:52:5C";
}

function _hnIsAp(dev) {
  if (!dev) return false;
  return (dev.ip || "") === "10.0.0.1";
}

function _esc(s) { return escHtml(s); }

function _truncate(s, n) {
  if (!s || s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

function filterHomeNet() {
  const q = (document.getElementById("hn-search").value || "").toLowerCase();
  const net = document.getElementById("hn-filter-network").value;
  const cat = document.getElementById("hn-filter-category").value.toLowerCase();
  _hnDevicesFilt = _hnDevices.filter(d => {
    if (net && d.network !== net) return false;
    if (cat && (d.category || "").toLowerCase() !== cat) return false;
    if (q) {
      const hay = [d.friendly_name, d.hostname, d.ip, d.mac, d.vendor, d.category, d.notes]
        .filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  renderHomeNet();
}

// ── Remote reboot (backlog #16) ──────────────────────────────────────────
// Type-to-confirm flow:
//   1. User clicks one of the Reboot buttons -> hnOpenRebootConfirm()
//      sets up the modal with the device's display name + key
//   2. User types the device key in the input -> hnRebootConfirmInputChanged()
//      enables the Reboot button only when text matches
//   3. User clicks Reboot -> hnFireReboot() POSTs to /api/homenet/reboot/<device>
//      with confirm=<key> in the body. Backend has its own type-to-confirm
//      guard as defense-in-depth.
//   4. For SOAP (Orbi): backend confirms reboot fired
//      For deep-link (Verizon, TP-Link): backend returns the URL; UI
//      opens it in a new tab so user finishes in the device's admin.
let _hnRebootDevice = null;  // currently-selected device key

function hnOpenRebootConfirm(deviceKey, displayName) {
  _hnRebootDevice = deviceKey;
  document.getElementById("hn-reboot-modal-device").textContent = displayName;
  document.getElementById("hn-reboot-confirm-required").textContent = deviceKey;
  // Mode-specific copy so the user knows what to expect after confirm.
  // SOAP (Orbi) is real one-click; deep-link routes through the device's
  // own admin UI for the actual trigger.
  const modeNote = document.getElementById("hn-reboot-modal-mode-note");
  if (modeNote) {
    modeNote.textContent = deviceKey === "orbi"
      ? "Reboot fires immediately via SOAP."
      : "Opens the device's admin UI to its reboot page; you click Reboot there.";
  }
  const input = document.getElementById("hn-reboot-confirm-input");
  if (input) {
    input.value = "";
    input.placeholder = `type "${deviceKey}" to enable`;
    setTimeout(() => input.focus(), 0);
  }
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = ".4";
    btn.style.cursor = "not-allowed";
  }
  const status = document.getElementById("hn-reboot-status");
  if (status) status.textContent = "";
  document.getElementById("hn-reboot-modal").style.display = "flex";
  document.addEventListener("keydown", _hnRebootEscHandler);
}

function _hnRebootEscHandler(e) {
  if (e.key === "Escape") hnCloseRebootConfirm();
}

function hnCloseRebootConfirm() {
  document.getElementById("hn-reboot-modal").style.display = "none";
  document.removeEventListener("keydown", _hnRebootEscHandler);
  _hnRebootDevice = null;
}

function hnRebootConfirmInputChanged() {
  const input = document.getElementById("hn-reboot-confirm-input");
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (!input || !btn || !_hnRebootDevice) return;
  const matches = input.value.trim().toLowerCase() === _hnRebootDevice;
  btn.disabled = !matches;
  btn.style.opacity = matches ? "1" : ".4";
  btn.style.cursor = matches ? "pointer" : "not-allowed";
}

async function hnFireReboot() {
  if (!_hnRebootDevice) return;
  const device = _hnRebootDevice;
  const status = document.getElementById("hn-reboot-status");
  const btn = document.getElementById("hn-reboot-fire-btn");
  if (btn) btn.disabled = true;
  if (status) {
    status.textContent = "Sending reboot…";
    status.style.color = "var(--muted)";
  }
  // Bug fix 2026-05-12: open the popup window SYNCHRONOUSLY, inside the
  // user-gesture stack of the click that called us. If we wait until
  // after `await fetch(...)` to call window.open, modern browsers
  // (Chrome / Edge / Firefox) treat it as a non-gesture popup and
  // silently block it -- the user clicks Reboot and "nothing happens".
  // For SOAP-mode (Orbi) we close the popup once we know the response
  // didn't need a deep-link. `noopener,noreferrer` is dropped here so
  // we keep a handle on the popup; we re-apply the equivalent isolation
  // by setting the popup's opener to null after navigating.
  let popup = null;
  try {
    popup = window.open("about:blank", "_blank");
  } catch (_) {
    popup = null;
  }
  try {
    const r = await fetch(`/api/homenet/reboot/${encodeURIComponent(device)}`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      // Server-side type-to-confirm guard mirrors the UI guard --
      // defense-in-depth so a stray POST from elsewhere can't fire reboot.
      body: JSON.stringify({confirm: device}),
    });
    const data = await r.json();
    if (!r.ok || !data.ok) {
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = "Failed: " + (data.error || r.statusText);
        status.style.color = "var(--red)";
      }
      if (btn) btn.disabled = false;
      return;
    }
    if (data.mode === "deep-link" && data.url) {
      // Navigate the placeholder window we pre-opened in the user-gesture
      // stack. Fallback to a fresh window.open if the placeholder was
      // blocked (some hardened popup-blockers reject even about:blank).
      if (popup) {
        try { popup.opener = null; } catch (_) {}
        try { popup.location.href = data.url; }
        catch (_) { window.open(data.url, "_blank", "noopener,noreferrer"); }
      } else {
        window.open(data.url, "_blank", "noopener,noreferrer");
      }
      if (status) {
        status.textContent = "Opened admin UI -- click Reboot there to finish.";
        status.style.color = "var(--green)";
      }
    } else if (data.mode === "reboot-fired") {
      // SOAP path doesn't need a deep-link; close the placeholder.
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = data.message || "Reboot triggered.";
        status.style.color = "var(--green)";
      }
    } else {
      if (popup) { try { popup.close(); } catch (_) {} }
      if (status) {
        status.textContent = "Unknown response mode: " + (data.mode || "?");
        status.style.color = "var(--orange)";
      }
    }
    // Auto-close after a short delay so the user sees the success message
    setTimeout(() => hnCloseRebootConfirm(), 2500);
  } catch (e) {
    if (popup) { try { popup.close(); } catch (_) {} }
    if (status) {
      status.textContent = "Error: " + (e && e.message || e);
      status.style.color = "var(--red)";
    }
    if (btn) btn.disabled = false;
  }
}

// ── Router config backups (new feature 2026-05-09) ───────────────────────
// Two flows depending on vendor:
//   * Orbi  -> POST /api/homenet/backup/orbi runs the SOAP-based real
//              backup, saves to backups/orbi/, response carries the
//              saved path. On failure (older firmware path didn't work)
//              the response includes a fallback_url so we can offer the
//              deep-link as a one-click recovery.
//   * Verizon -> POST returns mode='deep-link' + url. We open the admin
//                Save/Restore page in a new tab; user clicks Save there.
// Both flows refresh the saved-backups list afterwards so the user sees
// their new file appear (Orbi case) or knows to drop the downloaded
// file into backups/verizon/ themselves.

async function hnLoadBackupList() {
  const container = document.getElementById("hn-backup-history");
  if (!container) return;
  try {
    const r = await fetch("/api/homenet/backup/list");
    const d = await r.json();
    if (!d.ok) {
      container.innerHTML = `<div style="color:var(--red);font-size:11px">Error loading backups: ${esc(d.error || "unknown")}</div>`;
      return;
    }
    const renderVendor = (vendor, label) => {
      const list = (d.backups && d.backups[vendor]) || [];
      if (!list.length) {
        return `<div style="margin-bottom:8px"><strong style="color:var(--cyan);font-size:11px">${esc(label)}</strong> <span style="color:var(--muted);font-size:11px">— no backups yet</span></div>`;
      }
      const rows = list.slice(0, 15).map(b => {
        const kb = (b.bytes / 1024).toFixed(1);
        return `<tr>
          <td style="padding:3px 8px;color:var(--text);font-family:var(--font-mono);font-size:11px">${esc(b.filename)}</td>
          <td style="padding:3px 8px;color:var(--muted);font-size:11px;text-align:right">${kb} KB</td>
          <td style="padding:3px 8px;color:var(--muted);font-size:11px">${esc(b.age_human)}</td>
        </tr>`;
      }).join("");
      const overflow = list.length > 15 ? `<tr><td colspan="3" style="padding:3px 8px;color:var(--muted);font-size:11px;font-style:italic">… and ${list.length - 15} more</td></tr>` : "";
      return `<div style="margin-bottom:14px">
        <strong style="color:var(--cyan);font-size:11px">${esc(label)} <span style="color:var(--muted);font-weight:400">(${list.length} saved, max ${d.max_per_router || 50})</span></strong>
        <table style="width:100%;border-collapse:collapse;margin-top:4px">${rows}${overflow}</table>
      </div>`;
    };
    container.innerHTML = renderVendor("orbi", "Orbi RBRE960") + renderVendor("verizon", "Verizon CR1000A");
    // Render backup-staleness health (reverted scheduler 2026-05-11; backups
    // are manual now). Best-effort: health-fetch failure shouldn't break the
    // backup-list display.
    try {
      const hr = await fetch("/api/homenet/backup/health");
      const hd = await hr.json();
      const block = document.getElementById("hn-backup-scheduler-status");
      if (block) {
        const fmt = (v, stale, threshold) => {
          if (v === null || v === undefined) return `<span style="color:var(--red)">never backed up</span>`;
          const color = stale ? "var(--orange)" : "var(--green)";
          const ageStr = v < 1 ? `${(v * 24).toFixed(0)}h` : `${v.toFixed(1)}d`;
          return `<span style="color:${color}">${esc(ageStr)} old (stale at ${esc(String(threshold))}d)</span>`;
        };
        const orbiThresh = hd.orbi_stale_threshold_days || 30;
        const verizonThresh = hd.verizon_stale_threshold_days || 30;
        block.style.display = "block";
        block.innerHTML = `
          <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:baseline">
            <span style="color:var(--cyan);font-weight:600">🗄 Backups are manual</span>
            <span><strong>Orbi:</strong> ${fmt(hd.orbi_age_days, hd.orbi_stale, orbiThresh)}</span>
            <span><strong>Verizon:</strong> ${fmt(hd.verizon_age_days, hd.verizon_stale, verizonThresh)}</span>
          </div>
          <div style="color:var(--muted);margin-top:4px">Click the Backup buttons below to open each router's admin Save/Restore page in a new tab. Both vendors require manual interaction -- Orbi RBRE960 rejects the documented SOAP backup endpoint, and Verizon's SPA needs browser-side auth.</div>
        `;
      }
    } catch (e) {
      // Don't bubble -- the main backup-list rendering above is what matters
    }
    // Show the actual resolved BACKUPS_DIR so the user knows where files
    // land. Defaults to ~/OneDrive/WinDesktopMgr/backup; overridable via
    // WINDESKTOPMGR_BACKUP_DIR env var.
    const helper = document.getElementById("hn-backup-helper-text");
    if (helper && d.backup_dir) {
      helper.innerHTML = `
        Backups saved to <code>${esc(d.backup_dir)}</code> (capped at ${d.max_per_router || 50} files per router; oldest pruned automatically).
        For Verizon, the admin Save/Restore page opens in a new tab; your browser downloads the file. To track Verizon backups in this list, drop the downloaded files into the <code>verizon/</code> subfolder manually.
        Override the location by setting the <code>WINDESKTOPMGR_BACKUP_DIR</code> environment variable before starting WinDesktopMgr.
      `;
    }
  } catch (e) {
    container.innerHTML = `<div style="color:var(--red);font-size:11px">Error: ${esc(e && e.message || e)}</div>`;
  }
}

async function hnRunBackup(vendor, displayName) {
  const status = document.getElementById("hn-backup-status");
  const btn = document.getElementById(`hn-backup-${vendor}-btn`);
  const setStatus = (msg, color) => {
    if (status) {
      status.textContent = msg;
      status.style.color = color || "var(--muted)";
    }
  };
  if (btn) btn.disabled = true;
  setStatus(`Backing up ${displayName}…`);
  try {
    const r = await fetch(`/api/homenet/backup/${encodeURIComponent(vendor)}`, {method: "POST"});
    const d = await r.json();
    if (d.mode === "downloaded" && d.ok) {
      const kb = ((d.bytes || 0) / 1024).toFixed(1);
      setStatus(`✓ Saved ${esc(d.filename)} (${kb} KB) to backups/${vendor}/`, "var(--green)");
      hnLoadBackupList();
    } else if (d.mode === "deep-link" && d.url) {
      window.open(d.url, "_blank", "noopener,noreferrer");
      setStatus("✓ Opened admin UI -- click Save in the Verizon admin to download the config file.", "var(--green)");
    } else if (d.mode === "needs-fallback" && d.fallback_url) {
      const wantsFallback = confirm(
        `Orbi API backup failed:\n\n${d.error}\n\nOpen the Orbi admin in a new tab to download manually?`
      );
      if (wantsFallback) {
        window.open(d.fallback_url, "_blank", "noopener,noreferrer");
        setStatus("Opened Orbi admin -- find the Backup option in Settings.", "var(--orange)");
      } else {
        setStatus(`Backup cancelled. ${d.error}`, "var(--orange)");
      }
    } else {
      setStatus(`Backup failed: ${esc(d.error || "unknown error")}`, "var(--red)");
    }
  } catch (e) {
    setStatus(`Network error: ${esc(e && e.message || e)}`, "var(--red)");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function homenetScan() {
  const btn = document.getElementById("hn-scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  document.getElementById("hn-errors").style.display = "none";
  try {
    const r = await fetch("/api/homenet/scan", {method: "POST"});
    const data = await r.json();
    if (data.errors && data.errors.length) {
      const errDiv = document.getElementById("hn-errors");
      errDiv.style.display = "block";
      errDiv.textContent = data.errors.join(" | ");
    }
    _hnUpdateUI(data);
  } catch(e) {
    console.error("scan error:", e);
    document.getElementById("hn-errors").style.display = "block";
    document.getElementById("hn-errors").textContent = "Scan failed: " + e.message;
  }
  btn.disabled = false;
  btn.textContent = "🔍 Scan Network";
}

async function homenetResolveNames() {
  const btn = document.getElementById("hn-resolve-btn");
  btn.disabled = true;
  btn.textContent = "Resolving…";
  try {
    const r = await fetch("/api/homenet/resolve-names", {method: "POST"});
    const data = await r.json();
    if (data.ok) {
      _hnUpdateUI(data);
      const msg = data.resolved > 0
        ? `Resolved ${data.resolved} new name(s). ${data.total_named}/${data.total_devices} devices named.`
        : `No new names found. ${data.total_named}/${data.total_devices} devices already named.`;
      alert(msg);
    }
  } catch(e) {
    console.error("resolve error:", e);
    alert("Name resolution failed: " + e.message);
  }
  btn.disabled = false;
  btn.textContent = "🏷 Resolve Names";
}

// ── Credential management ───
function openCredModal(key, label) {
  document.getElementById("hn-cred-key").value = key;
  document.getElementById("hn-cred-title").textContent = "Credentials — " + label;
  const userLabel = document.querySelector('label[for="hn-cred-user"]') || document.getElementById("hn-cred-user").previousElementSibling;
  const passLabel = document.querySelector('label[for="hn-cred-pass"]') || document.getElementById("hn-cred-pass").previousElementSibling;
  // Show/hide Orbi SSID field
  const ssidRow = document.getElementById("hn-cred-ssid-row");
  // Toggle the TP-Link SNMP help block: visible only for tplink_switch.
  const tplinkHelp = document.getElementById("hn-cred-tplink-help");
  if (tplinkHelp) tplinkHelp.style.display = (key === "tplink_switch") ? "" : "none";
  if (key === "tplink_switch") {
    // For SNMP: username = switch IP, password = community string
    document.getElementById("hn-cred-user").value = "auto";
    document.getElementById("hn-cred-user").placeholder = "Switch IP or 'auto' (finds via MAC)";
    document.getElementById("hn-cred-pass").placeholder = "SNMP community string (default: public)";
    if (userLabel) userLabel.textContent = "Switch IP Address";
    if (passLabel) passLabel.textContent = "SNMP Community String";
    if (ssidRow) ssidRow.style.display = "none";
  } else if (key === "orbi") {
    document.getElementById("hn-cred-user").value = "admin";
    document.getElementById("hn-cred-user").placeholder = "";
    document.getElementById("hn-cred-pass").placeholder = "";
    if (userLabel) userLabel.textContent = "Username";
    if (passLabel) passLabel.textContent = "Password";
    if (ssidRow) ssidRow.style.display = "block";
    document.getElementById("hn-cred-ssid").value = "";
  } else {
    document.getElementById("hn-cred-user").value = "admin";
    document.getElementById("hn-cred-user").placeholder = "";
    document.getElementById("hn-cred-pass").placeholder = "";
    if (userLabel) userLabel.textContent = "Username";
    if (passLabel) passLabel.textContent = "Password";
    if (ssidRow) ssidRow.style.display = "none";
  }
  document.getElementById("hn-cred-pass").value = "";
  document.getElementById("hn-cred-status").style.display = "none";
  document.getElementById("hn-cred-modal").style.display = "flex";
}

function closeCredModal() {
  document.getElementById("hn-cred-modal").style.display = "none";
}

async function saveCredential() {
  const key = document.getElementById("hn-cred-key").value;
  const user = document.getElementById("hn-cred-user").value;
  const pass = document.getElementById("hn-cred-pass").value;
  if (!pass) { alert("Password is required"); return; }
  const payload = {device_key: key, username: user, password: pass};
  if (key === "orbi") {
    const ssid = document.getElementById("hn-cred-ssid").value.trim();
    if (ssid) payload.orbi_ssid = ssid;
  }
  const r = await fetch("/api/homenet/credentials/save", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  const data = await r.json();
  if (data.ok) {
    closeCredModal();
    loadHomeNet();
  } else {
    const s = document.getElementById("hn-cred-status");
    s.style.display = "block";
    s.style.background = "var(--red-dim)";
    s.style.color = "var(--red)";
    s.textContent = data.message;
  }
}

async function testCredential() {
  const key = document.getElementById("hn-cred-key").value;
  // Save first, then test
  const user = document.getElementById("hn-cred-user").value;
  const pass = document.getElementById("hn-cred-pass").value;
  if (!pass) { alert("Password is required"); return; }
  await fetch("/api/homenet/credentials/save", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key, username: user, password: pass})
  });
  const s = document.getElementById("hn-cred-status");
  s.style.display = "block";
  s.style.background = "var(--cyan-dim)";
  s.style.color = "var(--cyan)";
  s.textContent = "Testing connection…";
  const r = await fetch("/api/homenet/credentials/test", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  const data = await r.json();
  s.style.background = data.ok ? "var(--green-dim)" : "var(--red-dim)";
  s.style.color = data.ok ? "var(--green)" : "var(--red)";
  s.textContent = data.message;
}

async function testCredentialDirect(key) {
  const r = await fetch("/api/homenet/credentials/test", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  const data = await r.json();
  alert(data.ok ? "✓ " + data.message : "✗ " + data.message);
}

async function deleteCredential(key) {
  if (!confirm("Delete stored credentials for this device?")) return;
  await fetch("/api/homenet/credentials/delete", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_key: key})
  });
  loadHomeNet();
}

// ── Device edit modal ───
function openEditModal(mac) {
  const dev = _hnDevices.find(d => d.mac === mac);
  if (!dev) return;
  document.getElementById("hn-edit-mac").value = mac;
  document.getElementById("hn-edit-title").textContent = "Edit — " + (dev.friendly_name || dev.hostname || dev.ip);
  document.getElementById("hn-edit-name").value = dev.friendly_name || "";
  document.getElementById("hn-edit-category").value = dev.category || "";
  document.getElementById("hn-edit-location").value = dev.location || "";
  document.getElementById("hn-edit-notes").value = dev.notes || "";
  // DNS Hostname (#7): always populated from the inventory's router-sourced
  // value. Falls back to "(none yet)" when no router has reported it -- happens
  // for ARP-only devices and manually-added entries. Status line clears on
  // every open so leftover messages from a previous edit don't confuse.
  const dnsEl = document.getElementById("hn-edit-dns-hostname");
  if (dnsEl) dnsEl.value = dev.dns_hostname || "(none yet — click 🔄 to pull)";
  const dnsStatus = document.getElementById("hn-edit-dns-status");
  if (dnsStatus) dnsStatus.textContent = "";
  // wired_via: only meaningful for wired devices. The dropdown is always
  // visible to keep modal layout stable, but for wireless devices the
  // value is ignored by the topology classifier.
  const viaEl = document.getElementById("hn-edit-wired-via");
  if (viaEl) viaEl.value = dev.wired_via || "";
  // behind_moca_bridge dropdown: rebuild every open so newly-added bridges
  // surface without page reload. Filters out the device being edited (a
  // bridge can't be its own parent).
  const behindEl = document.getElementById("hn-edit-behind-moca");
  if (behindEl) {
    const bridges = _hnDevices.filter(d => {
      const isBridge = (d.wired_via || "").toLowerCase() === "moca_bridge"
        || _isMocaVendor(d.vendor || "");
      return isBridge && d.mac !== mac;  // exclude self
    });
    // Sort by friendly_name/hostname for predictable ordering
    bridges.sort((a, b) => {
      const na = (a.friendly_name || a.hostname || a.mac || "").toLowerCase();
      const nb = (b.friendly_name || b.hostname || b.mac || "").toLowerCase();
      return na.localeCompare(nb);
    });
    behindEl.innerHTML = '<option value="">— Not behind any bridge —</option>'
      + bridges.map(b => {
          const label = (b.friendly_name || b.hostname || b.mac);
          return `<option value="${esc(b.mac)}">📻 ${esc(label)}</option>`;
        }).join("");
    behindEl.value = dev.behind_moca_bridge || "";
  }
  // Via Orbi satellite dropdown: list every device the user has attested
  // as wired_via='orbi_satellite' (2026-05-13 manual-attestation path,
  // see homenet.py). Excludes self so a satellite can't be its own parent.
  const viaSatEl = document.getElementById("hn-edit-via-orbi-satellite");
  if (viaSatEl) {
    const sats = _hnDevices.filter(d =>
      (d.wired_via || "").toLowerCase() === "orbi_satellite" && d.mac !== mac
    );
    sats.sort((a, b) => {
      const na = (a.friendly_name || a.hostname || a.mac || "").toLowerCase();
      const nb = (b.friendly_name || b.hostname || b.mac || "").toLowerCase();
      return na.localeCompare(nb);
    });
    viaSatEl.innerHTML = '<option value="">— Not on a satellite (base or unknown) —</option>'
      + sats.map(s => {
          const label = (s.friendly_name || s.hostname || s.mac);
          return `<option value="${esc(s.mac)}">📡 ${esc(label)}</option>`;
        }).join("");
    viaSatEl.value = dev.via_orbi_satellite || "";
  }
  document.getElementById("hn-edit-modal").style.display = "flex";
}

// Mirror of homenet.py _ETHERNET_MOCA_BRIDGE_VENDORS -- kept in sync manually.
// Used by the edit modal's "Behind MoCA bridge" parent dropdown to filter
// devices that could plausibly be bridges. Bug 2026-05-12: Commscope/Arris
// removed because they're Verizon FiOS STBs (MoCA endpoints, not bridges).
// A user who really has a Commscope/Arris bridge can still tag it
// explicitly via wired_via=moca_bridge in the same modal -- once tagged,
// the dropdown picks it up via the wired_via check, not vendor.
function _isMocaVendor(vendor) {
  const v = (vendor || "").toLowerCase();
  if (!v) return false;
  return ["actiontec", "askey", "gocoax", "hitron",
          "motorola mobility", "screenbeam", "westell"]
         .some(p => v.includes(p));
}

function closeEditModal() {
  document.getElementById("hn-edit-modal").style.display = "none";
}

// ── DNS hostname helpers (#7, Path A) ───
// Pick the right router admin URL for a given device. Wireless devices
// (10.x IPs) live in the Orbi admin; everything else in the Verizon admin.
// Both pages list connected devices -- the user can scroll/Ctrl-F for the
// MAC and rename in-place. We can't deep-link to a specific row because
// neither admin UI supports MAC-anchored routes.
function _routerAdminUrlForDevice(dev) {
  if (!dev) return null;
  const ip = String(dev.ip || "");
  // Orbi RBRE960 admin is HTTPS on 10.0.0.1 with a self-signed cert. The
  // /DEV_devices.htm page is the connected-devices view in stock firmware.
  if (ip.startsWith("10.")) return "https://10.0.0.1/DEV_devices.htm";
  // Verizon CR1000A is the default. Hash-route /#/devices opens the
  // Connected Devices view in the Vue SPA.
  return "http://192.168.1.1/#/devices";
}

function openRouterAdminForDevice() {
  const mac = document.getElementById("hn-edit-mac").value;
  const dev = _hnDevices.find(d => d.mac === mac);
  if (!dev) return;
  const url = _routerAdminUrlForDevice(dev);
  if (!url) {
    alert("No router admin URL for this device.");
    return;
  }
  // window.open with no opener so the admin page can't tamper with our tab.
  // The user is leaving WinDesktopMgr to rename the device in the router,
  // then returns to click 🔄 to pull the new name back.
  const w = window.open(url, "_blank", "noopener,noreferrer");
  const status = document.getElementById("hn-edit-dns-status");
  if (status) {
    if (w) {
      status.textContent = `Opened ${url} -- after renaming, click 🔄 to refresh`;
      status.style.color = "var(--cyan)";
    } else {
      // Pop-up blocked. Hand the user the URL so they can copy-paste.
      status.textContent = `Pop-up blocked. Open: ${url}`;
      status.style.color = "var(--warning, #ffc107)";
    }
  }
}

async function pullDnsHostnameFromRouter() {
  const mac = document.getElementById("hn-edit-mac").value;
  if (!mac) return;
  const status = document.getElementById("hn-edit-dns-status");
  const dnsEl  = document.getElementById("hn-edit-dns-hostname");
  const btn    = document.getElementById("hn-edit-dns-pull");
  if (status) {
    status.textContent = "Pulling from routers…";
    status.style.color = "var(--muted)";
  }
  if (btn) btn.disabled = true;
  try {
    const r = await fetch("/api/homenet/device/rescan-hostname", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({mac: mac})
    });
    const data = await r.json();
    if (data.ok && data.dns_hostname) {
      if (dnsEl) dnsEl.value = data.dns_hostname;
      if (status) {
        const src = data.source ? ` (from ${data.source})` : "";
        status.textContent = `Pulled "${data.dns_hostname}"${src}`;
        status.style.color = "var(--success, #28a745)";
      }
      // Refresh the inventory cache so the device table reflects the new
      // name without forcing the user to close and reopen the tab.
      const idx = _hnDevices.findIndex(d => d.mac === mac);
      if (idx >= 0) {
        _hnDevices[idx].dns_hostname = data.dns_hostname;
        _hnDevices[idx].hostname = data.dns_hostname;
      }
    } else {
      if (status) {
        status.textContent = data.message || "No router-side hostname found";
        status.style.color = "var(--warning, #ffc107)";
      }
    }
  } catch (e) {
    if (status) {
      status.textContent = "Error: " + (e && e.message || e);
      status.style.color = "var(--danger, #dc3545)";
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function saveDeviceEdit() {
  const mac = document.getElementById("hn-edit-mac").value;
  const r = await fetch("/api/homenet/device/update", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mac: mac,
      friendly_name: document.getElementById("hn-edit-name").value,
      category: document.getElementById("hn-edit-category").value,
      location: document.getElementById("hn-edit-location").value,
      notes: document.getElementById("hn-edit-notes").value,
      wired_via: document.getElementById("hn-edit-wired-via").value,
      behind_moca_bridge: document.getElementById("hn-edit-behind-moca").value,
      via_orbi_satellite: (document.getElementById("hn-edit-via-orbi-satellite") || {}).value || ""
    })
  });
  const data = await r.json();
  if (data.ok) {
    closeEditModal();
    _tabLoaded["homenet"] = false;
    loadHomeNet();
    // Auto-refresh the topology if it's currently visible. User feedback
    // 2026-04-25: "if i manually move a device to the TP-link switch it
    // should automatically appear under that and not wait for a refresh."
    // Same for satellite naming, wired_via=moca, friendly_name changes,
    // etc. -- any inventory edit can affect the topology so we
    // unconditionally re-render when the user has the diagram open.
    const topoBody = document.getElementById("hn-topo-body");
    if (topoBody && topoBody.style.display !== "none") {
      _hnTopoLoaded = false;
      hnTopoRefresh().then(() => { _hnTopoLoaded = true; });
    }
  } else {
    alert("Save failed: " + data.message);
  }
}

