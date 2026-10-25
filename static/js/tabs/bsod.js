// BSOD tab (prefix bsod) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// BSOD DASHBOARD
// ══════════════════════════════════════════════════════════════════════════

const CHART_COLORS = [
  "#ff7043","#00d4ff","#00e5a0","#a855f7","#ff4757",
  "#ffd700","#3d84ff","#ff69b4","#00bcd4","#8bc34a"
];

const CHART_DEFAULTS = {
  color: "#6b7a90",
  font: { family: "'JetBrains Mono', monospace", size: 11 },
};

Chart.defaults.color = CHART_DEFAULTS.color;
Chart.defaults.font  = CHART_DEFAULTS.font;

async function loadBsodData(forceRefresh = false) {
  if (forceRefresh) {
    document.getElementById("bsod-content").style.display = "none";
    document.getElementById("bsod-loading").style.display = "flex";
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
    if (errorChart)    { errorChart.destroy();    errorChart = null; }
    if (driverChart)   { driverChart.destroy();   driverChart = null; }
  }

  try {
    const r = await fetch("/api/bsod/data");
    const data = await r.json();
    renderBsodDashboard(data);
  fetchSummary('bsod', data, 'summary-bsod');
  loadBsodCache();
  } catch (e) {
    document.getElementById("bsod-loading").innerHTML =
      `<p style="color:var(--red)">Failed to load BSOD data. Is the Flask server running?</p>`;
  }
}

function renderBsodDashboard(data) {
  const s = data.summary;

  // Stats
  document.getElementById("b-total").textContent  = s.total_crashes;
  document.getElementById("b-month").textContent  = s.this_month;
  document.getElementById("b-common").textContent = s.most_common_error === "None" ? "None" : s.most_common_error;
  document.getElementById("b-uptime").textContent = s.avg_uptime_hours > 0
    ? s.avg_uptime_hours + "h" : "—";

  // Timeline chart
  const tlLabels = data.timeline.map(t => t.label);
  const tlData   = data.timeline.map(t => t.count);
  const maxVal   = Math.max(...tlData, 1);

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(document.getElementById("chart-timeline"), {
    type: "bar",
    data: {
      labels: tlLabels,
      datasets: [{
        label: "Crashes",
        data: tlData,
        backgroundColor: tlData.map(v =>
          v === 0 ? "rgba(28,37,53,.5)" :
          v >= maxVal * 0.8 ? "rgba(255,71,87,.7)" :
          "rgba(255,112,67,.6)"
        ),
        borderRadius: 4, borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(28,37,53,.8)" }, ticks: { maxRotation: 45 } },
        y: { grid: { color: "rgba(28,37,53,.8)" }, beginAtZero: true,
             ticks: { stepSize: 1, precision: 0 } }
      }
    }
  });

  // Error code chart
  if (errorChart) errorChart.destroy();
  if (data.error_codes.length) {
    errorChart = new Chart(document.getElementById("chart-errors"), {
      type: "doughnut",
      data: {
        labels: data.error_codes.map(e => e.code.replace(/_/g," ")),
        datasets: [{
          data: data.error_codes.map(e => e.count),
          backgroundColor: CHART_COLORS,
          borderColor: "#07090f", borderWidth: 2,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { boxWidth: 10, padding: 8, font: { size: 10 } }
          }
        }
      }
    });
  }

  // Faulty drivers chart
  if (driverChart) driverChart.destroy();
  if (data.faulty_drivers.length) {
    document.getElementById("no-drivers").style.display = "none";
    driverChart = new Chart(document.getElementById("chart-drivers"), {
      type: "bar",
      data: {
        labels: data.faulty_drivers.map(d => d.driver),
        datasets: [{
          label: "Crash count",
          data: data.faulty_drivers.map(d => d.count),
          backgroundColor: "rgba(168,85,247,.6)",
          borderRadius: 4, borderSkipped: false,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "rgba(28,37,53,.8)" }, ticks: { precision: 0 } },
          y: { grid: { display: false } }
        }
      }
    });
  } else {
    document.getElementById("no-drivers").style.display = "block";
    document.getElementById("chart-drivers").style.display = "none";
  }

  // Uptime periods
  const uptimeList = document.getElementById("uptime-list");
  const noUptime   = document.getElementById("no-uptime");
  if (data.uptime_periods.length) {
    noUptime.style.display = "none";
    const maxHours = Math.max(...data.uptime_periods.map(p => p.hours), 1);
    uptimeList.innerHTML = data.uptime_periods.slice().reverse().map(p => {
      const pct   = Math.round((p.hours / maxHours) * 100);
      const short = p.hours < 24;
      const label = p.hours >= 24
        ? Math.round(p.hours / 24) + "d"
        : Math.round(p.hours) + "h";
      return `
        <div class="uptime-row">
          <div class="uptime-bar-track">
            <div class="uptime-bar-fill${short?" short":""}" style="width:${pct}%"></div>
          </div>
          <div class="uptime-label${short?" short":""}">${label}</div>
        </div>`;
    }).join("");
  } else {
    noUptime.style.display = "block";
    uptimeList.style.display = "none";
  }

  // Recommendations
  document.getElementById("rec-list").innerHTML = data.recommendations.map((r, i) => `
    <div class="rec-card ${escHtml(r.priority)}" style="animation-delay:${i*60}ms">
      <div class="rec-header">
        <span class="rec-priority">${escHtml(r.priority)}</span>
        <span class="rec-title">${escHtml(r.title)}</span>
      </div>
      <div class="rec-detail">${escHtml(r.detail)}</div>
    </div>`).join("");

  // Crash log table
  const tbody   = document.getElementById("crash-tbody");
  const noCrash = document.getElementById("no-crashes");
  if (data.crashes.length) {
    noCrash.style.display = "none";
    tbody.innerHTML = data.crashes.map(c => `
      <tr>
        <td>${escHtml(fmtTs(c.timestamp))}</td>
        <td class="error-code-cell">${escHtml(c.error_code)}</td>
        <td><code style="font-size:11px;color:var(--text-dim)">${escHtml(c.stop_code||"—")}</code></td>
        <td class="driver-cell">${escHtml(c.faulty_driver||"—")}</td>
        <td><span class="src-badge ${escHtml(c.source)}">${escHtml(c.source.replace("_"," "))}</span></td>
      </tr>`).join("");
  } else {
    noCrash.style.display = "block";
    tbody.innerHTML = "";
  }

  // Show content
  document.getElementById("bsod-loading").style.display  = "none";
  document.getElementById("bsod-content").style.display  = "";
}




