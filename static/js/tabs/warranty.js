// Warranty readiness -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// WARRANTY READINESS
// ══════════════════════════════════════════════════════════════════════════
async function loadWarrantyData() {
  const panel = document.getElementById("warranty-panel");
  const loading = document.getElementById("warranty-loading");
  const content = document.getElementById("warranty-content");
  loading.style.display = "block";
  content.style.display = "none";
  panel.style.display = "block";
  try {
    const r = await fetch("/api/warranty/data");
    const d = await r.json();
    if (d.status !== "ok") throw new Error(d.message || "Failed");
    renderWarranty(d.warranty);
  } catch (e) {
    loading.innerHTML = `<span style="color:var(--red)">Failed to load warranty data: ${e.message}</span>`;
  }
}

function renderWarranty(w) {
  const esc = s => escHtml(s || "—");
  const grid = document.getElementById("warranty-grid");
  const statColor = (v, threshold=0) => v > threshold ? "var(--red)" : "var(--green)";

  const fields = [
    ["CPU Model", w.CPUModel, "var(--text)"],
    ["CPU ID", w.CPUSerial, "var(--cyan)"],
    ["Microcode", w.MicrocodeVersion, "var(--cyan)"],
    ["BIOS", `${w.BIOSVersion} (${w.BIOSDate})`, "var(--text)"],
    ["Dell Service Tag", w.DellServiceTag, "var(--cyan)"],
    ["Affected CPU", w.IsAffectedCPU ? "YES" : "No", w.IsAffectedCPU ? "var(--orange)" : "var(--green)"],
    ["BSODs (30 days)", w.BSODs30Days, statColor(w.BSODs30Days)],
    ["WHEA Errors", w.WHEAErrors, statColor(w.WHEAErrors)],
    ["Unexpected Shutdowns", w.UnexpectedShutdowns, statColor(w.UnexpectedShutdowns)],
  ];

  grid.innerHTML = fields.map(([label, value, color]) => `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px">
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px">${label}</div>
      <div style="font-size:13px;font-weight:600;color:${color};word-break:break-all">${esc(value)}</div>
    </div>`).join("");

  // Evidence summary
  const lines = [];
  lines.push(`System: ${w.Manufacturer} ${w.Model}`);
  lines.push(`CPU: ${w.CPUModel}`);
  lines.push(`CPU ID: ${w.CPUSerial}`);
  lines.push(`BIOS: ${w.BIOSVersion} (${w.BIOSDate})`);
  lines.push(`Microcode: ${w.MicrocodeVersion}`);
  if (w.DellServiceTag !== "N/A") lines.push(`Dell Service Tag: ${w.DellServiceTag}`);
  lines.push(`BSODs in last 30 days: ${w.BSODs30Days}`);
  lines.push(`WHEA hardware errors: ${w.WHEAErrors}`);
  lines.push(`Unexpected shutdowns: ${w.UnexpectedShutdowns}`);
  lines.push("");
  lines.push("This system exhibits symptoms consistent with the known Intel 13th/14th Gen");
  lines.push("desktop processor voltage instability issue (eTVB/SVID). Requesting warranty");
  lines.push("evaluation and potential CPU replacement under Intel's extended warranty program.");

  document.getElementById("warranty-evidence-text").textContent = lines.join("\n");

  // Links
  document.getElementById("warranty-intel-link").href = w.IntelWarrantyURL;
  document.getElementById("warranty-dell-link").href = w.DellSupportURL;
  if (w.DellServiceTag !== "N/A") {
    document.getElementById("warranty-dell-link").textContent = "🔗 Dell Support (Your Service Tag)";
  }

  document.getElementById("warranty-loading").style.display = "none";
  document.getElementById("warranty-content").style.display = "block";
}

// Auto-load warranty data when BIOS tab loads
const origLoadBios = loadBios;
loadBios = async function() {
  await origLoadBios();
  loadWarrantyData();
};


