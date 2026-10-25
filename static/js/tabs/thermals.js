// Thermals tab (prefix th) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// TEMPERATURE & POWER
// ══════════════════════════════════════════════════════════════════════════
let _thermalsData = null;
let _thAutoTimer  = null;
let _lhmStatus    = null;

async function loadThermals(opts) {
  // Auto-refresh passes {silent:true}: keep the current readings on screen
  // while the next sample loads instead of flashing "Loading…" every 10 s.
  const silent = !!(opts && opts.silent) && _thermalsData !== null;
  try {
    const ld = document.getElementById("th-loading");
    if (!silent) {
      if (ld) { ld.style.display = "block"; ld.textContent = "Loading thermal data…"; }
      document.getElementById("th-content").style.display = "none";
    }
    const r = await fetch("/api/thermals/data");
    _thermalsData = await r.json();
    const upd = document.getElementById("th-updated");
    if (upd) upd.textContent = "updated " + new Date().toLocaleTimeString();
    // LHM installer status drives the per-core CTA button (best effort —
    // the CTA still renders its copy if this fetch fails).
    try { _lhmStatus = await (await fetch("/api/thermals/lhm/status")).json(); }
    catch(_e) { _lhmStatus = null; }
    renderThermals();
    fetchSummary("thermals", _thermalsData, "summary-thermals");
  } catch(e) {
    console.error("Failed to load thermals:", e);
    // Surface the failure instead of leaving "Loading thermal data…" up
    // forever -- the 10s auto-refresh would otherwise spin silently.
    const ld = document.getElementById("th-loading");
    if (ld) { ld.style.display = "block"; ld.textContent = "Failed to load thermal data. Will retry on next refresh."; }
    document.getElementById("th-content").style.display = "none";
  }
}

// Thermals tab — instrument-cluster redesign (PR4). Built with DOM methods +
// textContent (no innerHTML -> XSS-proof). Renders hero radial gauges, a
// per-core temperature grid (auto-populates when LibreHardwareMonitor exposes
// "CPU Core #N" sensors; else an install CTA), cooling-device cards, and the
// detailed sensor list. Sections hide themselves when their data is absent.
function renderThermals() {
  if (!_thermalsData) return;
  const d = _thermalsData;
  const perf = d.perf || {};
  const temps = Array.isArray(d.temps) ? d.temps : [];
  const fans = Array.isArray(d.fans) ? d.fans : [];

  const cpu = perf.CPUPct || 0;
  const memU = perf.MemUsedMB || 0;
  const memT = perf.MemTotalMB || 1;
  const memP = Math.round(memU / memT * 100);

  const setText = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  setText("th-cpu", cpu + "%");
  setText("th-ram", memP + "%");
  setText("th-sensors", temps.length);
  const peak = temps.length ? Math.max(...temps.map(t => t.TempC || 0)) : null;
  setText("th-peak", peak !== null ? peak + "°C" : "—");

  // Hero radial gauges (reuse the dashboard renderer; same 5 readouts).
  renderGauges(document.getElementById("th-gauge-row"), d.gauges || []);
  thRenderKernel(d.kernel_cpu);

  const mk = (cls, text) => {
    const x = document.createElement("div");
    if (cls) x.className = cls;
    if (text != null) x.textContent = text;
    return x;
  };
  const isCore = t => /core\s*#?\d+/i.test(String(t.Name || ""));
  // Temperature bands -> a CSS class (tband-*) used to colour-code every
  // thermal panel consistently (cells, sensor rows, legend). The class drives
  // both the accent colour and the readout colour via CSS, so JS stays simple.
  const tempBand = c =>
    c >= 95 ? "crit" : c >= 85 ? "hot" : c >= 70 ? "warm" : c >= 50 ? "normal" : "cool";

  // Legend so the colours are self-explanatory.
  const legendEl = document.getElementById("th-legend");
  if (legendEl) {
    legendEl.textContent = "";
    [["cool", "< 50°"], ["normal", "50–69°"], ["warm", "70–84°"], ["hot", "85–94°"], ["crit", "≥ 95°"]]
      .forEach(([band, label]) => {
        const item = mk("th-leg-item");
        const sw = mk("th-leg-sw tband-" + band);
        item.appendChild(sw);
        item.appendChild(mk("th-leg-label", label));
        legendEl.appendChild(item);
      });
  }

  // ── Per-core grid (LHM "CPU Core #N") OR install CTA ──
  const cores = temps.filter(isCore);
  const coresEl = document.getElementById("th-cores");
  coresEl.textContent = "";
  if (cores.length) {
    document.getElementById("th-cores-section").style.display = "";
    document.getElementById("th-cores-cta").style.display = "none";
    cores.forEach(t => {
      const c = t.TempC || 0;
      const cell = mk("th-core tband-" + tempBand(c));
      cell.appendChild(mk("th-core-name", String(t.Name || "").replace(/cpu\s*/i, "")));
      cell.appendChild(mk("th-core-temp", c + "°"));
      const bar = mk("th-core-bar");
      bar.style.width = Math.max(0, Math.min(100, Math.round(c))) + "%";
      cell.appendChild(bar);
      coresEl.appendChild(cell);
    });
  } else {
    document.getElementById("th-cores-section").style.display = "none";
    const cta = document.getElementById("th-cores-cta");
    cta.style.display = "";
    cta.textContent = "";
    cta.appendChild(mk("th-cta-icon", "🌡"));
    const body = mk("th-cta-body");
    body.appendChild(mk("th-cta-title", "Per-core CPU temperatures need LibreHardwareMonitor"));
    body.appendChild(mk("th-cta-sub", d.note ||
      "LibreHardwareMonitor reads per-core CPU temperatures while it runs (as Administrator) and serves them to this app over a local-only connection. Install it below and the per-core grid + CPU-temp gauge populate automatically — no leaving the app."));
    thRenderLhmActions(body);
    cta.appendChild(body);
  }

  // ── Cooling-device cards ──
  const fansEl = document.getElementById("th-fans");
  fansEl.textContent = "";
  if (fans.length) {
    document.getElementById("th-fans-section").style.display = "";
    fans.forEach((f, i) => {
      const active = f.ActiveCooling !== false;
      const rpm = (f.DesiredSpeed != null && f.DesiredSpeed !== "") ? f.DesiredSpeed : null;
      const card = mk("th-fan" + (active ? "" : " th-fan-idle"));
      card.appendChild(mk("th-fan-name", (f.Name || "Fan") + (fans.length > 1 ? " " + (i + 1) : "")));
      const blade = mk("th-fan-blade" + (active ? " spin" : ""));
      blade.textContent = "✲";
      card.appendChild(blade);
      card.appendChild(mk("th-fan-val", rpm != null ? rpm + " rpm" : (active ? "Active" : "Idle")));
      fansEl.appendChild(card);
    });
  } else {
    document.getElementById("th-fans-section").style.display = "none";
  }

  // ── Detailed temperature-sensor list (non-core LHM/OHM sensors) ──
  const others = temps.filter(t => !isCore(t));
  const grid = document.getElementById("th-temps-grid");
  grid.textContent = "";
  if (others.length) {
    document.getElementById("th-sensors-section").style.display = "";
    others.forEach(t => {
      const c = t.TempC || 0;
      const row = mk("th-sensor tband-" + tempBand(c));
      const top = mk("th-sensor-top");
      top.appendChild(mk("th-sensor-name", t.Name || ""));
      top.appendChild(mk("th-sensor-temp", c + "°C"));
      row.appendChild(top);
      const track = mk("th-sensor-track");
      const fill = mk("th-sensor-fill");
      fill.style.width = Math.min(100, Math.round((c - 20) / 80 * 100)) + "%";
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(mk("th-sensor-meta", (t.Source || "") + " — " + (t.status || "")));
      grid.appendChild(row);
    });
  } else {
    document.getElementById("th-sensors-section").style.display = "none";
  }

  document.getElementById("th-loading").style.display = "none";
  document.getElementById("th-content").style.display = "";
}

// Kernel driver load line (#75). textContent only. data-state drives the
// Playwright gate: "stuck" when a driver thread is pinning a core.
function thRenderKernel(k) {
  const el = document.getElementById("th-kernel");
  if (!el) return;
  el.textContent = "";
  const label = document.createElement("strong");
  label.textContent = "Kernel driver load: ";
  el.appendChild(label);
  const msg = document.createElement("span");
  if (!k || !k.available) {
    el.dataset.state = "na";
    el.style.borderColor = "var(--border)";
    msg.textContent = (k && k.warming_up)
      ? "measuring — needs two samples about 20 s apart"
      : "unavailable" + (k && k.reason ? " (" + k.reason + ")" : "");
    msg.style.color = "var(--muted)";
  } else if (k.stuck && k.stuck.length) {
    const s = k.stuck[0];
    el.dataset.state = "stuck";
    el.style.borderColor = "var(--orange)";
    msg.textContent = "a driver thread is pinning a core — " + s.pct + "% of a core for " +
      Math.round(s.minutes) + " min. It heats the fastest cores at low load — click Identify driver below to name it.";
    msg.style.color = "var(--orange)";
  } else {
    el.dataset.state = "ok";
    el.style.borderColor = "var(--border)";
    const b = k.busiest ? k.busiest.pct : 0;
    msg.textContent = "busiest thread " + b + "% of a core · all System threads " + k.total_pct +
      "% · normal (alerts above 50% sustained)";
  }
  el.appendChild(msg);
}

// "Identify driver" (#75 PR 2). POST launches the UAC-elevated helper (the
// request blocks until the prompt is answered), then poll the status route
// until the helper's result lands (~10 s sample). textContent only.
let _thIdentifyBusy = false;
async function thIdentifyDriver() {
  if (_thIdentifyBusy) return;
  const out = document.getElementById("th-kernel-identify-result");
  const btn = document.getElementById("th-kernel-identify");
  if (!out) return;
  const say = (state, text, color) => {
    out.dataset.state = state;
    out.textContent = text;
    out.style.color = color || "var(--muted)";
  };
  _thIdentifyBusy = true;
  if (btn) btn.disabled = true;
  try {
    say("prompt", "Approve the Windows admin prompt to continue…");
    const r = await fetch("/api/thermals/kernel/identify", { method: "POST" });
    const launch = await r.json();
    if (!launch.ok) { say("error", "Not identified: " + (launch.error || "launch failed"), "var(--orange)"); return; }
    say("running", "Watching the System process for about 10 seconds…");
    for (let i = 0; i < 45; i++) {
      await new Promise(res => setTimeout(res, 2000));
      const s = await (await fetch("/api/thermals/kernel/identify/status?session_id=" + encodeURIComponent(launch.session_id))).json();
      if (s.state === "pending") continue;
      if (s.state !== "done") { say("error", "Not identified: " + (s.error || "unknown error"), "var(--orange)"); return; }
      thRenderIdentify(out, s.result || {});
      return;
    }
    say("error", "The helper didn't report back within 90 seconds.", "var(--orange)");
  } catch (e) {
    say("error", "Not identified: " + e.message, "var(--orange)");
  } finally {
    _thIdentifyBusy = false;
    if (btn) btn.disabled = false;
  }
}

function thRenderIdentify(out, res) {
  out.textContent = "";
  out.style.color = "var(--text)";
  if (!res.ok) {
    out.dataset.state = "error";
    out.style.color = "var(--orange)";
    out.textContent = "Not identified: " + (res.error || "the helper failed");
    return;
  }
  out.dataset.state = "done";
  const head = document.createElement("div");
  head.style.color = "var(--muted)";
  head.textContent = "System-process CPU by driver over " + res.sampled_s + " s" +
    (res.note ? " — " + res.note : "") + ":";
  out.appendChild(head);
  const rows = Array.isArray(res.rows) ? res.rows : [];
  if (!rows.length) {
    const none = document.createElement("div");
    none.textContent = "No kernel thread used measurable CPU — nothing is pinning a core right now.";
    out.appendChild(none);
  }
  rows.forEach(row => {
    const line = document.createElement("div");
    line.className = "th-kernel-driver-row";
    line.dataset.driver = row.driver;
    const name = document.createElement("strong");
    name.textContent = row.driver;
    line.appendChild(name);
    line.appendChild(document.createTextNode(
      " — " + row.pct + "% of a core (" + row.threads + " thread" + (row.threads === 1 ? "" : "s") + ")"));
    if (row.hint) {
      const hint = document.createElement("span");
      hint.style.color = row.pct > 50 ? "var(--orange)" : "var(--muted)";
      hint.textContent = " → " + row.hint;
      line.appendChild(hint);
    }
    out.appendChild(line);
  });
}

// ── LibreHardwareMonitor in-app installer (per-core CTA) ──────────────────
// Built with DOM methods + textContent (no innerHTML). The button shown
// depends on _lhmStatus: Install -> Launch-as-admin -> (running, gauges fill).
function thRenderLhmActions(body) {
  const st = _lhmStatus || {};
  const row = document.createElement("div");
  row.className = "th-cta-actions";
  const status = document.createElement("div");
  status.className = "th-cta-status";
  if (st.running) {
    status.textContent = "LibreHardwareMonitor is running — refresh to pull per-core temps.";
    const btn = thMkCtaBtn("↺ Refresh now", () => loadThermals());
    row.appendChild(btn);
  } else if (st.installed) {
    const btn = thMkCtaBtn("⚡ Launch as admin", (b) => thLaunchLhm(b));
    row.appendChild(btn);
    status.textContent = "Installed. Launch it (you'll approve a Windows admin prompt) to publish per-core sensors.";
  } else {
    const btn = thMkCtaBtn("⬇ Install LibreHardwareMonitor", (b) => thInstallLhm(b));
    row.appendChild(btn);
    status.textContent = "One click downloads the verified " + (st.version || "v0.9.6") +
      " build (~6 MB, SHA256-checked) into your user folder. No admin needed to install.";
  }
  body.appendChild(row);
  body.appendChild(status);
  // Once LHM is installed, offer the optional always-on auto-start (elevated
  // at-logon task). Lazily fetches its current state to label the toggle.
  if (st.installed) thRenderLhmAutostart(body);
}

// Optional "launch LHM elevated at every login" toggle. Built with DOM methods.
function thRenderLhmAutostart(body) {
  const wrap = document.createElement("div");
  wrap.className = "th-cta-actions";
  wrap.style.marginTop = "8px";
  const note = document.createElement("div");
  note.className = "th-cta-status";
  note.textContent = "Checking auto-start…";
  const btn = thMkCtaBtn("…", () => {});
  btn.disabled = true;
  wrap.appendChild(btn);
  body.appendChild(wrap);
  body.appendChild(note);

  const paint = (enabled) => {
    btn.disabled = false;
    if (enabled) {
      btn.textContent = "✓ Auto-start on — turn off";
      btn.onclick = null;
      btn.addEventListener("click", () => thToggleLhmAutostart(btn, note, true), {once: true});
      note.textContent = "LibreHardwareMonitor launches elevated at every login, so the gauges always work.";
    } else {
      btn.textContent = "⤴ Set up auto-start at login";
      btn.onclick = null;
      btn.addEventListener("click", () => thToggleLhmAutostart(btn, note, false), {once: true});
      note.textContent = "Optional: make Windows launch LHM elevated automatically at login (one admin prompt) so you never re-launch it.";
    }
  };

  fetch("/api/thermals/lhm/autostart")
    .then((r) => r.json())
    .then((d) => paint(!!d.enabled))
    .catch(() => { note.textContent = "Could not check auto-start state."; btn.style.display = "none"; });
}

async function thToggleLhmAutostart(btn, note, currentlyOn) {
  btn.disabled = true;
  btn.textContent = currentlyOn ? "Removing (approve the admin prompt)…" : "Setting up (approve the admin prompt)…";
  const url = currentlyOn ? "/api/thermals/lhm/autostart/remove" : "/api/thermals/lhm/autostart";
  try {
    const d = await (await fetch(url, {method: "POST"})).json();
    if (d.ok) {
      // schtasks ran elevated; re-query the real state to confirm.
      setTimeout(async () => {
        try {
          const s = await (await fetch("/api/thermals/lhm/autostart")).json();
          btn.disabled = false;
          // Re-render the whole CTA so the toggle reflects the new state.
          renderThermals();
          void s;
        } catch (_e) { btn.disabled = false; }
      }, 1500);
    } else {
      btn.disabled = false;
      btn.textContent = currentlyOn ? "✓ Auto-start on — turn off" : "⤴ Set up auto-start at login";
      thCtaError(d.error || "Auto-start change failed.");
    }
  } catch (e) {
    btn.disabled = false;
    thCtaError("Auto-start change failed: " + e);
  }
}

function thMkCtaBtn(label, onClick) {
  const b = document.createElement("button");
  b.className = "th-cta-btn";
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", () => onClick(b));
  return b;
}

function thCtaError(msg) {
  const cta = document.getElementById("th-cores-cta");
  let err = document.getElementById("th-cta-err");
  if (!err) {
    err = document.createElement("div");
    err.id = "th-cta-err";
    err.className = "th-cta-err";
    cta.appendChild(err);
  }
  err.textContent = msg;
}

async function thInstallLhm(btn) {
  btn.disabled = true;
  btn.textContent = "Installing…";
  try {
    const d = await (await fetch("/api/thermals/lhm/install", {method: "POST"})).json();
    if (d.ok) {
      _lhmStatus = {installed: true, running: false, version: d.version};
      renderThermals();        // re-render → now shows the Launch button
    } else {
      btn.disabled = false;
      btn.textContent = "⬇ Install LibreHardwareMonitor";
      thCtaError(d.error || "Install failed.");
    }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "⬇ Install LibreHardwareMonitor";
    thCtaError("Install failed: " + e);
  }
}

async function thLaunchLhm(btn) {
  btn.disabled = true;
  btn.textContent = "Launching (approve the admin prompt)…";
  try {
    const d = await (await fetch("/api/thermals/lhm/launch", {method: "POST"})).json();
    if (d.ok) {
      btn.textContent = "Launched — reading sensors…";
      // Give LHM a few seconds to start its HTTP server, then reload.
      setTimeout(loadThermals, 6000);
    } else {
      btn.disabled = false;
      btn.textContent = "⚡ Launch as admin";
      thCtaError(d.error || "Launch failed.");
    }
  } catch(e) {
    btn.disabled = false;
    btn.textContent = "⚡ Launch as admin";
    thCtaError("Launch failed: " + e);
  }
}

// Auto-refresh is ON whenever the tab is open (a one-off snapshot of a CPU
// whose favored cores swing 30 C in a second reads as "stuck hot") and OFF
// when the tab is left, so it never polls in the background.
function thStartAutoRefresh() {
  if (_thAutoTimer) return;
  _thAutoTimer = setInterval(() => loadThermals({silent: true}), 10000);
  const btn = document.getElementById("th-auto-btn");
  if (btn) {
    btn.textContent = "⏹ Stop Auto-refresh";
    btn.style.borderColor = "var(--cyan)";
    btn.style.color = "var(--cyan)";
  }
}

function thStopAutoRefresh() {
  if (_thAutoTimer) {
    clearInterval(_thAutoTimer);
    _thAutoTimer = null;
  }
  const btn = document.getElementById("th-auto-btn");
  if (btn) {
    btn.textContent = "▶ Auto-refresh (10s)";
    btn.style.borderColor = "var(--border)";
    btn.style.color = "var(--muted)";
  }
}

function toggleThAutoRefresh() {
  if (_thAutoTimer) thStopAutoRefresh();
  else thStartAutoRefresh();
}

