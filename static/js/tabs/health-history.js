// Health History tab (prefix hh) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// HEALTH HISTORY
// ══════════════════════════════════════════════════════════════════════════
let _hhChart = null;

async function loadHealthHistory() {
  try {
    document.getElementById("hh-loading").style.display = "block";
    document.getElementById("hh-content").style.display = "none";
    const r = await fetch("/api/health-history/data");
    const d = await r.json();
    renderHealthHistory(d);
    fetchSummary("health-history", d, "summary-health-history");
  } catch(e) {
    console.error("Failed to load health history:", e);
  }
}

function renderHealthHistory(d) {
  const reports = d.reports || [];
  document.getElementById("hh-total").textContent   = d.total || 0;
  document.getElementById("hh-avg").textContent     = d.avg_score != null ? d.avg_score + "/100" : "—";
  document.getElementById("hh-bsod").textContent    = reports.filter(r=>r.bsod_count>0).length;
  document.getElementById("hh-latest").textContent  = d.latest?.score != null ? d.latest.score + "/100" : "—";

  if (d.error) {
    document.getElementById("hh-loading").innerHTML =
      `<div style="color:var(--orange);padding:20px">${esc(d.error)}</div>`;
    return;
  }

  // Staleness warning banner
  const staleBanner = document.getElementById("hh-stale-banner");
  if (d.stale) {
    staleBanner.innerHTML = `<span style="color:var(--orange);font-weight:600">⚠ Reports are stale</span> — last report was ${d.stale_days} day(s) ago. Check that the SystemHealthDiag scheduled task is running.`;
    staleBanner.style.display = "block";
  } else {
    staleBanner.style.display = "none";
  }

  // Chart
  const labels = reports.map(r => r.date_label);
  const scores = reports.map(r => r.score);
  const bsods  = reports.map(r => r.bsod_count);
  if (_hhChart) _hhChart.destroy();
  const ctx = document.getElementById("hh-chart").getContext("2d");
  _hhChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Health Score", data: scores, borderColor: "#00d4ff", backgroundColor: "#00d4ff18",
          tension: 0.3, fill: true, pointRadius: 3, spanGaps: true },
        { label: "BSOD Events", data: bsods, borderColor: "#ff4560", backgroundColor: "transparent",
          tension: 0, yAxisID: "y2", pointRadius: 4, pointStyle: "triangle" }
      ]
    },
    options: {
      responsive: true, interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { color: "#aaa" } } },
      scales: {
        x:  { ticks: { color: "#666", maxTicksLimit: 20 }, grid: { color: "#ffffff08" } },
        y:  { min: 0, max: 100, ticks: { color: "#aaa" }, grid: { color: "#ffffff08" },
              title: { display: true, text: "Score", color: "#666" } },
        y2: { position: "right", min: 0, ticks: { color: "#ff4560", stepSize: 1 },
              grid: { display: false }, title: { display: true, text: "BSODs", color: "#ff4560" } }
      }
    }
  });

  // Table
  const statusColor = s => s==="critical"?"var(--red)":s==="warning"?"var(--orange)":"var(--cyan)";
  const rows = [...reports].reverse().map(r =>
    `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px">${esc(r.date_label)}</td>
      <td style="padding:6px 10px;text-align:center;font-weight:700;color:${r.score>=80?"var(--cyan)":r.score>=60?"var(--orange)":"var(--red)"}">${r.score!=null?r.score:"-"}</td>
      <td style="padding:6px 10px;text-align:center;color:${r.bsod_count>0?"var(--red)":"var(--muted)"}">${r.bsod_count||0}</td>
      <td style="padding:6px 10px;text-align:center;color:${r.whea_count>0?"var(--orange)":"var(--muted)"}">${r.whea_count||0}</td>
      <td style="padding:6px 10px;font-size:11px;color:var(--muted)">${esc((r.sys_files||[]).slice(0,3).join(", "))}</td>
      <td style="padding:6px 10px;color:${statusColor(r.status)};font-size:11px;font-weight:700">${esc(r.status)}</td>
    </tr>`
  ).join("");
  document.getElementById("hh-tbody").innerHTML = rows ||
    `<tr><td colspan="6" style="padding:20px;color:var(--muted);text-align:center">No reports found in ${esc(d.report_dir||"")}</td></tr>`;

  document.getElementById("hh-loading").style.display = "none";
  document.getElementById("hh-content").style.display = "";
}

