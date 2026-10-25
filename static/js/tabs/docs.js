// Documentation tab (prefix doc) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ── Documentation tab (doc) ─────────────────────────────────────────────────
// Procedures for this machine. Everything factual is read live rather than
// written into the page: a swap guide whose "which drive failed" is a
// screenshot is wrong the moment you act on it.

function doc_el(tag, css, text) {
  const e = document.createElement(tag);
  if (css) e.style.cssText = css;
  if (text !== undefined) e.textContent = text;
  return e;
}

function doc_copy(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const was = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = was; }, 1200);
  }).catch(() => alert("Copy failed. The command is:\n\n" + text));
}

function doc_cmdRow(label, cmd) {
  const wrap = doc_el("div", "margin-bottom:10px");
  wrap.appendChild(doc_el("div", "font-size:11px;color:var(--muted);margin-bottom:4px", label));
  const row = doc_el("div", "display:flex;align-items:center;gap:8px;flex-wrap:wrap");
  const code = doc_el("code",
    "flex:1;min-width:260px;font-size:11px;color:var(--cyan);background:var(--bg);padding:6px 9px;border-radius:5px;word-break:break-all", cmd);
  row.appendChild(code);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "Copy";
  btn.style.cssText = "padding:4px 12px;font-size:11px;border-radius:5px;background:transparent;color:var(--cyan);border:1px solid var(--cyan);cursor:pointer;white-space:nowrap";
  btn.onclick = () => doc_copy(cmd, btn);
  row.appendChild(btn);
  wrap.appendChild(row);
  return wrap;
}

// The exact commands from scripts/repair_storage_pool.ps1's own header, so the
// page and the script cannot drift apart.
const DOC_REPAIR_CMDS = [
  ["1. Preview — shows the plan, changes nothing",
   "powershell -ExecutionPolicy Bypass -File C:\\shigsapps\\windesktopmgr\\scripts\\repair_storage_pool.ps1 -Preview"],
  ["2. Run it for real — leave the window open, this takes hours",
   "powershell -ExecutionPolicy Bypass -File C:\\shigsapps\\windesktopmgr\\scripts\\repair_storage_pool.ps1"],
];

function doc_renderCommands() {
  const host = document.getElementById("doc-cmds");
  if (!host) return;
  while (host.firstChild) host.removeChild(host.firstChild);
  DOC_REPAIR_CMDS.forEach(([label, cmd]) => host.appendChild(doc_cmdRow(label, cmd)));
}

// Drive state for the procedure header.
//
// Reads the PCIe topology rather than /api/storage/spaces: the topology
// endpoint is cached (~0.3s warm) while the spaces call is an uncached
// PowerShell round-trip that took 8-70s, which left this line stuck on
// "Reading pool state…" long after the diagram had rendered. The topology
// response already carries the retired flag, serial and socket, so the second
// call bought nothing.
async function doc_loadPoolState(prefetched) {
  const host = document.getElementById("doc-pool-state");
  if (!host) return;
  try {
    const t = prefetched || await fetch("/api/storage/pcie-topology").then(r => r.json());
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!t || !t.ok) {
      host.appendChild(doc_el("div", "font-size:12px;color:var(--muted)", "Could not read drive state."));
      return;
    }
    const drives = t.card_drives || [];
    const retired = drives.filter(d => d.retired || d.flag === "retired");
    const unhealthy = drives.filter(d => !d.retired && d.flag === "unhealthy");
    // A missing RETIRED drive is the expected result of a correct swap (its
    // pool entry stays until the script removes it). A missing drive that is
    // NOT retired holds data -- it was pulled by mistake and must go back.
    const missing = t.missing || [];
    const isRetired = d => String(d.usage || "").toLowerCase() === "retired";
    const lostData = missing.filter(d => !isRetired(d));
    const removedFailed = missing.filter(isRetired);

    const line = doc_el("div", "display:flex;align-items:center;gap:10px;flex-wrap:wrap");
    line.appendChild(doc_el("span", "font-size:12px;font-weight:700", "Current drive state:"));
    if (lostData.length) {
      line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--red)",
        `${lostData.length} data drive${lostData.length === 1 ? "" : "s"} not detected — put it back before running the script`));
    } else if (retired.length) {
      line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--amber)",
        `${retired.length} drive${retired.length === 1 ? "" : "s"} retired — this procedure applies`));
    } else if (unhealthy.length) {
      line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--amber)",
        `${unhealthy.length} drive${unhealthy.length === 1 ? "" : "s"} reporting a warning`));
    } else if (removedFailed.length) {
      line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--green)",
        "Failed drive removed — ready for Step 3"));
    } else if (drives.length) {
      line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--green)",
        `All ${drives.length} card drives healthy — reference only, nothing to do`));
    } else {
      line.appendChild(doc_el("span", "font-size:12px;color:var(--muted)", "no add-in card drives reported"));
    }
    host.appendChild(line);

    // The label serial + model are what the user can actually check; the
    // distance from the bracket (from physical_order) is a where-to-look hint,
    // marked "probably" unless that socket was checked by hand.
    const placed = drives.filter(d => d.position).length;
    const nearBracket = d => {
      if (!d.position) return "";
      const n = d.position;
      const pos = n === 1 ? "nearest the bracket"
        : (n === placed ? "farthest from the bracket" : `${n}${n === 2 ? "nd" : n === 3 ? "rd" : "th"} from the bracket`);
      return ` · ${d.position_checked ? "" : "probably "}${pos}`;
    };
    retired.concat(unhealthy).forEach(d => {
      const lbl = d.label_serial ? `label S/N ${d.label_serial}` : `Windows ID ${d.serial || "unknown"} (label serial not reported)`;
      host.appendChild(doc_el("div", "font-size:12px;font-weight:700;color:var(--amber);margin-top:6px",
        `Remove: ${d.model || "unknown drive"} · ${lbl}${nearBracket(d)} · ${d.usage || d.health || ""}`.trim()));
    });
    lostData.forEach(d => {
      const lbl = d.label_serial ? `label S/N ${d.label_serial}` : `Windows ID ${d.serial || "unknown"}`;
      host.appendChild(doc_el("div", "font-size:12px;font-weight:700;color:var(--red);margin-top:6px",
        `Put back (holds data, not detected): ${d.model || "unknown drive"} · ${lbl}`));
    });
    removedFailed.forEach(d => {
      const lbl = d.label_serial ? `label S/N ${d.label_serial}` : `Windows ID ${d.serial || "unknown"}`;
      host.appendChild(doc_el("div", "font-size:11px;color:var(--muted);margin-top:6px",
        `Removed failed drive (expected; the script deletes its pool entry): ${d.model || "unknown drive"} · ${lbl}`));
    });
    if (t.note) {
      host.appendChild(doc_el("div", "font-size:11px;color:var(--muted);margin-top:6px", t.note));
    }
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(doc_el("div", "font-size:12px;color:var(--muted)",
      "Could not read drive state: " + e.message));
  }
}

// Stylesheet for the exported document. The export builds a STANDALONE page in
// an isolated iframe rather than printing the app page, because printing the
// app page came out blank: the shell's layout (fixed rail, scroll container,
// per-tab display toggling) fights @media print, and every fix there is a
// guess about the user's browser. A clean clone has no shell to fight.
//
// The page is built with inline styles referencing theme variables, so the
// variables are re-pointed to a light print palette instead of restyling every
// element. The card diagram keeps its own colours -- the red retired socket is
// the entire point of the diagram.
const DOC_EXPORT_CSS = `
  :root {
    --bg:#ffffff; --card:#ffffff; --border:#cccccc; --text:#111111;
    --fg:#111111; --muted:#444444; --cyan:#0b5fa5; --green:#1a7f37;
    --amber:#8a6100; --red:#b3261e;
    --font-head: 'Chakra Petch', system-ui, sans-serif;
  }
  @page { margin: 14mm; }
  html, body { background:#fff; color:#111; margin:0; }
  body {
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    font-size: 12px; line-height: 1.5;
  }
  #page-docs { display:block !important; max-width:100%; }
  code {
    background:#f2f2f2 !important; color:#0b5fa5 !important;
    border:1px solid #ddd; border-radius:4px; padding:2px 5px;
    font-family: ui-monospace, 'JetBrains Mono', monospace;
    word-break: break-all;
  }
  svg { max-width:100% !important; height:auto !important; }
  /* Keep the diagram's own fills so the retired-socket highlight survives. */
  svg, svg * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
  /* Do not split a step across pages if it can be helped. */
  #page-docs > div > div { break-inside: avoid; page-break-inside: avoid; }
  h2 { font-size: 20px; margin: 0 0 4px; }
  h3 { font-size: 15px; }
`;

async function doc_exportPdf(btn) {
  const src = document.getElementById("page-docs");
  if (!src) return;
  if (btn) { btn.disabled = true; btn.textContent = "Preparing…"; }
  // Wait for the live reads before cloning. Exporting mid-load would bake
  // "Reading the card layout…" into the PDF in place of the failed drive's
  // socket and serial — and carrying that to the machine is the whole point
  // of the export. Same mistake the on-screen placeholder already avoids.
  try {
    await _docReady;
  } catch (e) {
    console.error("doc: load failed before export", e);
  }

  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.setAttribute("title", "Print preview");
  frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;opacity:0";
  document.body.appendChild(frame);

  const cleanup = () => {
    if (frame.parentNode) frame.parentNode.removeChild(frame);
    if (btn) { btn.disabled = false; btn.textContent = "↓ Export PDF"; }
  };

  try {
    const d = frame.contentDocument;
    // Assembled with createElement / appendChild only, so a live drive model or
    // serial string can never inject markup into the export.
    d.title = "WinDesktopMgr — SSD replacement procedure";
    const style = d.createElement("style");
    style.textContent = DOC_EXPORT_CSS;
    d.head.appendChild(style);

    const clone = d.importNode(src, true);
    clone.style.display = "block";
    // Buttons and anything marked no-print are interactive chrome, not content.
    clone.querySelectorAll("button, .no-print").forEach(n => n.remove());
    // A placeholder that is hidden on screen (e.g. the "no add-in card" note
    // once the diagram rendered) would otherwise print as a blank gap.
    clone.querySelectorAll("[style*='display:none'], [style*='display: none']").forEach(n => {
      if (!n.querySelector("svg")) n.remove();
    });
    d.body.appendChild(clone);

    const w = frame.contentWindow;
    w.addEventListener("afterprint", cleanup, {once: true});
    // Give the cloned SVG and fonts a beat to lay out before printing.
    setTimeout(() => {
      try {
        w.focus();
        w.print();
      } catch (e) {
        cleanup();
        alert("Could not open the print dialog: " + e.message);
      }
    }, 250);
    // Safety net: some browsers never fire afterprint.
    setTimeout(cleanup, 120000);
  } catch (e) {
    cleanup();
    alert("Could not build the export: " + e.message);
  }
}

// Secure Boot state for the Docs procedure. Only the ELEVATED BIOS audit can
// read it (bios_audit._ELEVATED_ONLY_FIELDS). That check runs daily but only
// APPENDS history when something changes, so the newest elevated entry is the
// current value and its timestamp is when it last changed -- not when it was
// last checked. msinfo32 is the instant answer after a change.
function doc_secureBootFrom(history) {
  for (let i = history.length - 1; i >= 0; i--) {
    const e = history[i] || {};
    const snap = e.snapshot || {};
    const ctx = e.context || snap.context;
    if (ctx === "elevated" && typeof snap.secure_boot === "string" && snap.secure_boot) {
      return {state: snap.secure_boot, when: e.timestamp || snap.timestamp || ""};
    }
  }
  return null;
}

async function doc_loadSecureBoot() {
  const host = document.getElementById("doc-sb-state");
  if (!host) return;
  let sb = null;
  let failed = false;
  try {
    const d = await fetch("/api/bios/audit/history?limit=200").then(r => r.json());
    sb = doc_secureBootFrom(Array.isArray(d && d.history) ? d.history : []);
  } catch (e) {
    console.error("doc: secure boot read failed", e);
    failed = true;
  }
  while (host.firstChild) host.removeChild(host.firstChild);
  host.dataset.sbState = sb ? sb.state : "unknown";
  const line = doc_el("div", "display:flex;align-items:center;gap:10px;flex-wrap:wrap");
  line.appendChild(doc_el("span", "font-size:12px;font-weight:700", "Secure Boot:"));
  if (!sb) {
    line.appendChild(doc_el("span", "font-size:12px;color:var(--muted)",
      failed ? "could not read the BIOS audit" : "not recorded yet — check with msinfo32 (Step 3)"));
  } else if (sb.state.toLowerCase() === "enabled") {
    line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--green)", "On — nothing to do"));
  } else if (sb.state.toLowerCase() === "unsupported") {
    // Confirm-SecureBootUEFI fails on a Legacy-mode boot; Step 2 says not to
    // change that, so this must not read as "follow the steps".
    line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--amber)",
      "not available — Windows may be starting in Legacy mode. Check BIOS Mode in msinfo32 (Step 3) before changing anything."));
  } else {
    line.appendChild(doc_el("span", "font-size:12px;font-weight:700;color:var(--amber)",
      `${sb.state} — follow the steps below`));
  }
  host.appendChild(line);
  if (sb && sb.when) {
    host.appendChild(doc_el("div", "font-size:11px;color:var(--muted);margin-top:4px",
      `Recorded ${sb.when.replace("T", " ")}, when it last changed. The app re-checks daily and only records changes, so turning it on shows up here within a day; msinfo32 shows it immediately.`));
  }
}

// Tracks the in-flight page load so the export can wait for real data instead
// of capturing the "Reading the card layout…" placeholder.
let _docReady = null;

function doc_load() {
  _docReady = _doc_loadInner();
  return _docReady;
}

async function _doc_loadInner() {
  doc_renderCommands();
  // Reuse the Storage tab's live card diagram rather than a screenshot.
  const empty = document.getElementById("doc-card-empty");
  // Reading the PCIe topology walks the PnP tree and can take up to a minute.
  // Until it returns we must NOT show "no add-in card detected" -- that is a
  // factual claim about the hardware, and showing it while still looking would
  // tell someone mid-swap that the card they are holding does not exist. Set
  // BEFORE the fetch: set after it, the stale text (the template's, or the
  // previous visit's verdict) stayed up for the whole wait.
  if (empty) {
    empty.textContent = "Reading the card layout from the PCIe bus… this can take up to a minute.";
    empty.style.display = "";
  }
  // ONE request, shared by the diagram and the drive-state line.
  let topo = null;
  try {
    topo = await fetch("/api/storage/pcie-topology").then(r => r.json());
  } catch (e) {
    console.error("doc: topology fetch failed", e);
  }
  const poolDone = doc_loadPoolState(topo);
  const sbDone = doc_loadSecureBoot();
  try {
    await dkLoadTopology("doc-card-section", "doc-card", topo);
    const sec = document.getElementById("doc-card-section");
    const shown = sec && sec.style.display !== "none";
    if (empty) {
      if (shown) {
        empty.style.display = "none";
      } else {
        empty.textContent = "No add-in card detected on this machine.";
        empty.style.display = "";
      }
    }
  } catch (e) {
    console.error("doc: card diagram failed", e);
    if (empty) empty.textContent = "Could not read the card layout: " + e.message;
  }
  await poolDone;
  await sbDone;
}

