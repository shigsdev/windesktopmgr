// Memory tab (prefix mem) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// MEMORY ANALYSIS
// ══════════════════════════════════════════════════════════════════════════
let _memChart = null;

// System-process glossary (backlog #36). Fetched once per page load and
// cached; the Memory tab renderer looks up process names to decide whether
// to show an info icon and whether to hide the Kill button.
let _processGlossary = null;
async function _loadProcessGlossary() {
  if (_processGlossary !== null) return _processGlossary;
  try {
    const r = await fetch("/api/processes/glossary");
    const d = await r.json();
    _processGlossary = (d && d.glossary) ? d.glossary : {};
  } catch (e) {
    console.warn("Glossary fetch failed (non-fatal):", e);
    _processGlossary = {};  // empty -> no tooltips, no button hiding — safe fallback
  }
  return _processGlossary;
}

// Normalise psutil process names for glossary lookup: lowercase + strip .exe.
// The glossary keys are stored without the suffix; psutil returns names
// inconsistently (MemCompression has no .exe, csrss.exe does).
function _glossaryKey(name) {
  const s = String(name || "").toLowerCase();
  return s.endsWith(".exe") ? s.slice(0, -4) : s;
}

async function loadMemory() {
  try {
    document.getElementById("mem-loading").style.display = "block";
    document.getElementById("mem-content").style.display = "none";
    await _loadProcessGlossary();
    const r = await fetch("/api/memory/data");
    const d = await r.json();
    renderMemory(d);
    fetchSummary("memory", d, "summary-memory");
  } catch(e) {
    console.error("Failed to load memory:", e);
  }
}

function renderMemory(d) {
  const total = d.total_mb||32768, used = d.used_mb||0, free = d.free_mb||0;
  document.getElementById("mem-total").textContent  = (total/1024).toFixed(1) + " GB";
  document.getElementById("mem-used").textContent   = used.toLocaleString() + " MB";
  document.getElementById("mem-free").textContent   = free.toLocaleString() + " MB";
  document.getElementById("mem-mcafee").textContent = d.has_mcafee ? (d.mcafee_mb||0) + " MB" : "—";

  // Category chart
  const cats  = d.categories || {};
  const catNames = { security:"Security/AV", browser:"Browsers", microsoft:"Windows/System",
                     office:"Office", comms:"Comms", gpu_driver:"GPU Driver",
                     this_app:"This App", games:"Games", cloud:"Cloud Sync", other:"Other" };
  const catColors = ["#ff4560","#00d4ff","#4488ff","#ff7043","#aa44ff",
                     "#44ddaa","#ffaa00","#ff44aa","#44aaff","#888888"];
  const labels = [], values = [], colors = [];
  Object.entries(cats).forEach(([k,v],i) => {
    if (v > 10) { labels.push(catNames[k]||k); values.push(v); colors.push(catColors[i%catColors.length]); }
  });
  if (_memChart) _memChart.destroy();
  const ctx = document.getElementById("mem-chart").getContext("2d");
  _memChart = new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: "#1a1f2e", borderWidth: 2 }] },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "right", labels: { color: "#aaa", font: { size: 11 },
          generateLabels: (chart) => chart.data.labels.map((l,i) => ({
            text: `${l}: ${values[i].toLocaleString()} MB`,
            fillStyle: colors[i], strokeStyle: colors[i], lineWidth: 0,
            fontColor: "#ccc"
          }))
        }},
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw.toLocaleString()} MB` } }
      }
    }
  });

  // McAfee vs Defender comparison
  if (d.has_mcafee) {
    const saving = d.mcafee_saving_mb || 0;
    const mcMB   = d.mcafee_mb || 0;
    const defMB  = d.defender_baseline || 150;
    // Per-vendor breakdown so the total reconciles against the process
    // table — 2026-04-11 bug: user saw McAfee total != mc-fw-host row
    // and couldn't tell where the delta came from. This makes the math
    // auditable by showing every contributing process on hover.
    const mcProcs = d.mcafee_processes || [];
    const mcTooltip = mcProcs.length
      ? `Reconciliation (${mcProcs.length} McAfee processes):\n` +
        mcProcs.map(p => `  ${p.name}: ${p.mem.toLocaleString()} MB`).join("\n") +
        `\n  ─────\n  Total: ${mcMB.toLocaleString()} MB\n\n${d.accounting_note || ""}`
      : "";
    const mcBreakdownHTML = mcProcs.length
      ? `<div style="margin-top:6px;font-size:11px;color:var(--muted);font-family:var(--font-mono)">
          <details><summary style="cursor:pointer;color:var(--muted)">▸ Reconciliation (${mcProcs.length} processes)</summary>
            <div style="margin-top:6px;padding:8px 10px;background:#ffffff06;border-radius:4px">
              ${mcProcs.map(p => `<div style="display:flex;justify-content:space-between"><span>${esc(p.name)}</span><span>${p.mem.toLocaleString()} MB</span></div>`).join("")}
              <div style="margin-top:4px;padding-top:4px;border-top:1px dashed var(--border);display:flex;justify-content:space-between;font-weight:700">
                <span>Total</span><span>${mcMB.toLocaleString()} MB</span>
              </div>
              <div style="margin-top:6px;font-size:10px;color:var(--text-dim);line-height:1.4">${esc(d.accounting_note || "")}</div>
            </div>
          </details>
        </div>`
      : "";
    document.getElementById("mem-comparison").innerHTML = `
      <div style="margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:13px;font-weight:600">McAfee (current)</span>
          <span style="color:var(--red);font-weight:700" title="${esc(mcTooltip)}">${mcMB.toLocaleString()} MB</span>
        </div>
        <div style="background:#ffffff11;border-radius:4px;height:12px">
          <div style="background:var(--red);height:100%;border-radius:4px;width:${Math.min(100,mcMB/total*100*5).toFixed(0)}%"></div>
        </div>
        ${mcBreakdownHTML}
      </div>
      <div style="margin-bottom:20px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:13px;font-weight:600">Windows Defender (estimated)</span>
          <span style="color:var(--cyan);font-weight:700">~${defMB} MB</span>
        </div>
        <div style="background:#ffffff11;border-radius:4px;height:12px">
          <div style="background:var(--cyan);height:100%;border-radius:4px;width:${Math.min(100,defMB/total*100*5).toFixed(0)}%"></div>
        </div>
      </div>
      <div style="background:#00d4ff18;border:1px solid var(--cyan);border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:800;color:var(--cyan)">${saving.toLocaleString()} MB</div>
        <div style="font-size:12px;color:var(--muted)">RAM you could recover by switching to Defender</div>
        <div style="font-size:11px;color:var(--muted);margin-top:4px">≈ ${(saving/1024).toFixed(1)} GB freed up</div>
      </div>`;
  } else {
    document.getElementById("mem-comparison").innerHTML =
      `<div style="color:var(--muted);font-size:13px;padding:12px">McAfee not detected — using Windows Defender or another AV.</div>`;
  }

  // 'Other' bucket audit (backlog #21). When unclassified processes cross
  // 5 % of total RAM, show the top 3 so we know what to add to the
  // vendor classifier.
  const auditEl = document.getElementById("mem-other-audit");
  if (auditEl) {
    const needsAudit = d.other_needs_audit;
    const otherTop = d.other_top_unclassified || [];
    if (needsAudit && otherTop.length) {
      const pct = d.other_pct || 0;
      const rowsHtml = otherTop.map(p =>
        `<div style="display:flex;justify-content:space-between;padding:4px 10px;font-family:var(--font-mono);font-size:12px"><span style="color:var(--text)">${esc(p.name)}</span><span style="color:var(--muted)">${p.mem.toLocaleString()} MB</span></div>`
      ).join("");
      auditEl.style.display = "";
      auditEl.innerHTML = `
        <div style="padding:14px 18px;background:var(--card);border:1px solid var(--border);border-left:4px solid var(--orange);border-radius:10px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div style="font-weight:700;font-size:13px;color:var(--orange)">⚠ 'Other' bucket is ${pct}% of RAM — classifier could use more entries</div>
            <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">audit</span>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-bottom:8px">
            Top unclassified processes (add to <code>MEM_CATEGORIES</code> in <code>windesktopmgr.py</code> so they bucket correctly):
          </div>
          ${rowsHtml}
        </div>`;
    } else {
      auditEl.style.display = "none";
      auditEl.innerHTML = "";
    }
  }

  // Top processes table (backlog #35 + #36 adds action buttons + glossary tooltips)
  const maxMem = (d.top_procs||[])[0]?.mem || 1;
  const catBadgeColor = c => ({security:"var(--red)",browser:"var(--cyan)",comms:"var(--orange)",
                               microsoft:"#4488ff",other:"#888"})[c] || "#888";
  const glossary = _processGlossary || {};
  // Action button style reused from the dashboard memory-concern buttons
  const actBtn = "padding:4px 8px;border-radius:5px;cursor:pointer;font-size:10px;font-weight:700;" +
                 "white-space:nowrap;background:transparent;border:1px solid var(--border);color:var(--muted);" +
                 "font-family:var(--font-mono)";
  const rows = (d.top_procs||[]).map(p => {
    const pid = p.pid || 0;
    const pname = esc(p.name);
    const key = _glossaryKey(p.name);
    const gloss = glossary[key];
    // Info icon: shown only when we have a glossary entry for this name.
    // Native title= tooltip is universally supported, accessible, and zero-JS.
    const infoIcon = gloss
      ? `<span title="${esc(gloss.title)} — ${esc(gloss.explanation)}" style="display:inline-block;margin-left:6px;cursor:help;color:var(--cyan);font-size:11px;user-select:none" aria-label="What is ${pname}?">ⓘ</span>`
      : "";
    // Protected processes show a 🛡 badge instead of Kill. Same tooltip
    // explains WHY it's protected so the user learns rather than being stonewalled.
    const protectedBadge = gloss && gloss.protected
      ? `<span title="Protected — ${esc(gloss.title)}: ${esc(gloss.explanation)}" style="font-size:10px;color:var(--muted);border:1px solid var(--border);padding:2px 8px;border-radius:5px;cursor:help">🛡 Protected</span>`
      : "";
    // When not protected, render the 3-button action group (Kill / Investigate / Snooze).
    // No PID -> no Investigate/Kill, just Snooze by name.
    const actions = gloss && gloss.protected
      ? protectedBadge
      : pid
        ? `<button data-mem-act="investigate" data-pid="${pid}" data-pname="${pname}" title="Filter Process Monitor to this PID" style="${actBtn}">🔍</button>
           <button data-mem-act="kill"        data-pid="${pid}" data-pname="${pname}" title="Kill this process (with confirmation)" style="${actBtn}">🔪</button>
           <button data-mem-act="snooze"                       data-pname="${pname}" title="Suppress this process's warnings for 24 h" style="${actBtn}">⏳</button>`
        : `<button data-mem-act="snooze" data-pname="${pname}" title="Suppress warnings for this process name (PID unknown)" style="${actBtn}">⏳</button>`;
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-weight:600">${pname}${infoIcon}</td>
      <td style="padding:6px 10px"><span style="font-size:10px;color:${catBadgeColor(p.category)};border:1px solid currentColor;padding:1px 6px;border-radius:8px">${esc(catNames[p.category]||p.category)}</span></td>
      <td style="padding:6px 10px;text-align:right;font-weight:700;color:${p.mem>1500?"var(--red)":p.mem>500?"var(--orange)":"var(--text)"}">${p.mem.toLocaleString()}</td>
      <td style="padding:6px 10px;width:200px">
        <div style="background:#ffffff11;border-radius:3px;height:6px">
          <div style="background:${p.mem>1500?"var(--red)":p.mem>500?"var(--orange)":"var(--cyan)"};height:100%;border-radius:3px;width:${Math.min(100,p.mem/maxMem*100).toFixed(0)}%"></div>
        </div>
      </td>
      <td style="padding:6px 10px;white-space:nowrap;text-align:right">${actions}</td>
    </tr>`;
  }).join("");
  const tbody = document.getElementById("mem-tbody");
  tbody.innerHTML = rows;
  // Wire the action buttons via the same helpers the dashboard concerns use
  // (backlog #19). Event delegation would also work, but per-button listeners
  // match the pattern in renderDashboard so the code stays consistent.
  tbody.querySelectorAll("button[data-mem-act]").forEach(btn => {
    btn.addEventListener("click", () => {
      const act   = btn.dataset.memAct;
      const pid   = parseInt(btn.dataset.pid, 10) || 0;
      const pname = btn.dataset.pname || "";
      if (act === "investigate") investigateProcess(pid, pname);
      else if (act === "kill")   killProcessFromConcern(pid, pname);
      else if (act === "snooze") snoozeMemoryConcern(pname);
    });
  });

  document.getElementById("mem-loading").style.display = "none";
  document.getElementById("mem-content").style.display = "";
}

