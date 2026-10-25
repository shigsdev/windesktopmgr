// Utilities tab (prefix util) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// UTILITIES TAB (backlog #51) — Quick Fixes + code-health scans
//
// All function names prefixed `util_*` to keep out of global-scope
// collisions (see the tab-prefix convention in CLAUDE.md).
// ══════════════════════════════════════════════════════════════════════════

let _utilPollTimer = null;

async function util_load() {
  await Promise.all([
    util_loadQuickFixes(),
    util_loadCodeHealth(),
  ]);
}

async function util_loadQuickFixes() {
  // Mirror of the original Dashboard renderer (removed from
  // loadDashboard above; this is now the single source of truth).
  const target = document.getElementById("util-qf-cards");
  if (!target) return;
  try {
    const r = await fetch("/api/remediation/actions");
    const actions = await r.json();
    const rc = r=>r==="high"?"var(--red)":r==="medium"?"var(--orange)":"var(--green)";
    const rb = r=>r==="high"?"rgba(255,71,87,.22)":r==="medium"?"rgba(255,112,67,.22)":"rgba(0,229,160,.22)";
    target.innerHTML = (actions || []).map(a=>`
      <button onclick="runRemediationFromDashboard('${escJsArg(a.id)}')"
        style="background:var(--card);border:1px solid var(--border);border-radius:8px;
        padding:10px 8px;cursor:pointer;text-align:center;transition:border-color .15s;position:relative"
        onmouseover="this.style.borderColor='${rc(a.risk)}'"
        onmouseout="this.style.borderColor='var(--border)'" title="${esc(a.description)}">
        <div style="font-size:16px;margin-bottom:4px">${esc(a.icon)}</div>
        <div style="font-size:11px;color:var(--text-bright);font-family:var(--font-mono);font-weight:500;line-height:1.3;margin-bottom:6px">${esc(a.label)}</div>
        <span style="font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;
          color:${rc(a.risk)};background:${rb(a.risk)};
          border:1px solid ${rc(a.risk)};padding:2px 7px;border-radius:8px">${a.risk}</span>
      </button>`).join("");
  } catch {
    target.innerHTML = `<div style="color:var(--muted);padding:10px;grid-column:1/-1">Quick Fixes unavailable.</div>`;
  }
}

function util_levelColor(level) {
  return level === "critical" ? "var(--red)"
       : level === "warning"  ? "var(--orange)"
       : level === "info"     ? "var(--cyan)"
       : "var(--green)";
}

function util_renderScannerCard(name, label, icon, result, opts) {
  const status = result.ok ? result.summary : (result.error || "Scanner unavailable");
  const color = util_levelColor(result.level || "ok");
  const dur = result.duration_ms != null ? `${(result.duration_ms / 1000).toFixed(1)}s` : "—";
  const ts = result.finished_at ? new Date(result.finished_at).toLocaleString() : "never";
  // Per-card extra controls. PR-2 of #51 ships a Refresh button for
  // the coverage card so the user can trigger a fresh pytest --cov
  // run from the UI when .coverage gets stale (the 2026-05-27 bug).
  const extraControl = (opts && opts.extraControl) || "";
  const detailsBlock = util_renderScannerDetails(name, result);
  return `
    <div data-scanner="${esc(name)}" style="background:var(--card);border:1px solid var(--border);border-left:3px solid ${color};
                border-radius:8px;padding:14px 16px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:18px">${icon}</span>
        <div style="flex:1;font-size:12px;font-weight:700;color:var(--text-bright)">${esc(label)}</div>
        <span style="font-size:9px;text-transform:uppercase;font-weight:800;letter-spacing:.04em;
                     color:${color};border:1px solid ${color};padding:2px 7px;border-radius:8px">${esc(result.level || "?")}</span>
      </div>
      <div style="font-size:12px;color:var(--text);line-height:1.4;margin-bottom:6px">${esc(status)}</div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:10px;color:var(--muted);font-family:var(--font-mono)">
        <span>${esc(ts)} · ${esc(dur)}</span>
        ${extraControl}
      </div>
      ${detailsBlock}
    </div>`;
}

function util_renderScannerDetails(name, result) {
  // Build the expandable "ⓘ N details" disclosure for a scanner card.
  // Each scanner stores its findings in result.details with a DIFFERENT
  // shape, so we branch per scanner:
  //   coverage  -> list of {file, percent}     (lowest-coverage files)
  //   ruff      -> list of {code, message, file, line}  (top findings)
  //   secrets   -> always [] (redacted); we surface a count-only note
  //   tech_debt -> DICT {todos:[{file,line,text}], large_files:[{file,lines}]}
  // Returns "" when there's nothing useful to show (clean scanner), so
  // the card stays compact. Native <details> = no JS state to wire and
  // it survives the poll re-render cleanly (collapsed default).
  const d = result.details;
  const rows = [];
  let count = 0;

  if (name === "tech_debt" && d && !Array.isArray(d)) {
    const large = d.large_files || [];
    const todos = d.todos || [];
    count = large.length + todos.length;
    if (large.length) {
      rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Oversized files (≥5,000 lines)</div>`);
      large.forEach(f => rows.push(
        `<div>${esc(f.file || "?")} · <span style="color:var(--orange)">${Number(f.lines || 0).toLocaleString()} lines</span></div>`
      ));
    }
    if (todos.length) {
      rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:8px 0 2px">TODO / FIXME markers</div>`);
      todos.forEach(t => rows.push(
        `<div>${esc(t.file || "?")}:${esc(String(t.line ?? ""))} · <span style="color:var(--muted)">${esc((t.text || "").slice(0, 90))}</span></div>`
      ));
    }
  } else if (name === "coverage" && Array.isArray(d) && d.length) {
    count = d.length;
    rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Lowest-coverage files</div>`);
    d.forEach(f => rows.push(
      `<div>${esc(f.file || "?")} · <span style="color:${Number(f.percent || 0) < 50 ? 'var(--red)' : 'var(--orange)'}">${Number(f.percent || 0).toFixed(1)}%</span></div>`
    ));
  } else if (name === "ruff" && Array.isArray(d) && d.length) {
    count = d.length;
    rows.push(`<div style="color:var(--text-bright);font-weight:600;margin:2px 0">Top findings</div>`);
    d.forEach(f => rows.push(
      `<div><span style="color:var(--orange)">${esc(f.code || "?")}</span> ${esc(f.file || "")}:${esc(String(f.line ?? ""))} · <span style="color:var(--muted)">${esc((f.message || "").slice(0, 90))}</span></div>`
    ));
  } else if (name === "secrets" && Number(result.count || 0) > 0) {
    count = Number(result.count);
    rows.push(`<div style="color:var(--muted)">${count} potential match${count !== 1 ? 'es' : ''} — output redacted for security. See docs/security/git-credentials.md.</div>`);
  }

  if (!rows.length) return "";
  return `
      <details data-scanner-details="${esc(name)}" data-detail-count="${count}" style="margin-top:8px">
        <summary style="cursor:pointer;color:var(--cyan);font-size:10px;font-family:var(--font-mono);user-select:none;list-style:none">ⓘ ${count} detail${count !== 1 ? 's' : ''}</summary>
        <div style="margin-top:6px;font-size:11px;color:var(--text);line-height:1.5;font-family:var(--font-mono);max-height:240px;overflow:auto;word-break:break-word">
          ${rows.join("")}
        </div>
      </details>`;
}

async function util_loadCodeHealth(opts) {
  const fromPoll = opts && opts.fromPoll;
  const lastSpan = document.getElementById("util-last-scan");
  const grid     = document.getElementById("util-ch-grid");
  const empty    = document.getElementById("util-ch-empty");
  const btn      = document.getElementById("util-scan-btn");
  if (!grid) return;
  let payload;
  try {
    const r = await fetch("/api/codehealth/status");
    payload = await r.json();
  } catch (e) {
    grid.innerHTML = `<div style="color:var(--red);grid-column:1/-1;padding:10px">Failed to load: ${esc(e.message)}</div>`;
    return;
  }
  const state    = payload.state || {};
  const scanners = state.scanners || {};
  const running  = payload.is_running;
  const refreshingCov = payload.is_refreshing_coverage;
  const stale    = payload.is_stale;
  const finished = state.finished_at;
  const hasResults = scanners && Object.keys(scanners).length > 0;

  // Header line + Scan-now button state.
  // Either a scan OR a coverage refresh keeps the spinner running.
  // A coverage refresh ends with an automatic scan_all so the
  // running flag flips through both phases.
  const anyInFlight = running || refreshingCov;
  if (anyInFlight) {
    if (lastSpan) {
      lastSpan.textContent = refreshingCov
        ? "Running pytest --cov (~60s)…"
        : "Scan in progress…";
    }
    if (btn) { btn.disabled = true; btn.textContent = refreshingCov ? "Refreshing coverage…" : "Scanning…"; }
    // Auto-poll every 1.5s while in flight.
    if (!_utilPollTimer) {
      _utilPollTimer = setInterval(() => util_loadCodeHealth({fromPoll: true}), 1500);
    }
  } else {
    if (lastSpan) {
      if (!finished) {
        lastSpan.textContent = "Never scanned";
      } else {
        const ts = new Date(finished).toLocaleString();
        const tag = stale ? " (stale)" : "";
        lastSpan.textContent = `Last scan: ${ts}${tag}`;
        lastSpan.style.color = stale ? "var(--orange)" : "var(--muted)";
      }
    }
    if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
    if (_utilPollTimer) { clearInterval(_utilPollTimer); _utilPollTimer = null; }
  }

  // Surface the last refresh error inline if it failed (the user
  // clicked Refresh and pytest blew up). Done above the cards.
  const refLast = payload.coverage_refresh_last_result;
  let refreshErrorBanner = "";
  if (refLast && !refLast.ok && !refreshingCov) {
    const tail = (refLast.stderr_tail || refLast.stdout_tail || "").slice(-300);
    refreshErrorBanner = `<div style="grid-column:1/-1;background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.4);
                          border-radius:6px;padding:8px 12px;margin-bottom:8px;font-size:11px;color:var(--text)">
        ⚠ Last coverage refresh failed: ${esc(refLast.error || "pytest returned " + refLast.returncode)}
        ${tail ? `<details style="margin-top:6px"><summary style="cursor:pointer;color:var(--muted)">tail</summary>
          <pre style="font-size:10px;color:var(--muted);white-space:pre-wrap;margin:4px 0 0">${esc(tail)}</pre></details>` : ""}
      </div>`;
  }

  if (!hasResults) {
    grid.style.display = "none";
    if (empty) empty.style.display = anyInFlight ? "none" : "";
    return;
  }
  grid.style.display = "grid";
  if (empty) empty.style.display = "none";

  // Card label + icon per scanner. Cards are rendered by iterating the
  // API's scanner_names (extensible: a new backend scanner auto-renders
  // here, falling back to a humanised label + 🔧 if it's not in the map).
  const SCANNER_META = {
    coverage:  ["Test Coverage",     "🧪"],
    ruff:      ["Code Bugs (ruff)",  "🪲"],
    secrets:   ["Security / Secrets","🔒"],
    tech_debt: ["Tech Debt",         "🧹"],
  };
  // Drive the card order off the registry the API reports; fall back to
  // whatever keys the scan result carries (older state without the field).
  const order = (payload.scanner_names && payload.scanner_names.length)
    ? payload.scanner_names
    : Object.keys(scanners);
  const runningScanner = payload.running_scanner;

  const cards = order.map(name => {
    const [label, icon] = SCANNER_META[name] || [util_humanise(name), "🔧"];
    let extraControl;
    if (name === "coverage") {
      // Coverage's per-card action is the expensive pytest --cov refresh
      // (re-reading the same .coverage yields the same number), kept on
      // its own endpoint. (PR-2 of #51, fixes the 2026-05-27 stale bug.)
      extraControl = refreshingCov
        ? `<span style="color:var(--cyan)">refreshing…</span>`
        : `<button onclick="util_refreshCoverage()"
                    style="background:transparent;border:1px solid var(--border);color:var(--cyan);
                           padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:var(--font-mono)"
                    title="Re-runs pytest --cov to refresh the .coverage file (~60s)">↻ Refresh</button>`;
    } else {
      // Cheap scanners get a per-card "↻ Run" that re-runs only this
      // scanner. Disabled (shows "running…") while any scan is in flight;
      // the card whose scanner is active gets the explicit spinner.
      extraControl = (runningScanner === name)
        ? `<span style="color:var(--cyan)">running…</span>`
        : `<button onclick="util_runScanner('${name}')" ${anyInFlight ? "disabled" : ""}
                    style="background:transparent;border:1px solid var(--border);
                           color:${anyInFlight ? "var(--muted)" : "var(--cyan)"};
                           padding:2px 8px;border-radius:4px;cursor:${anyInFlight ? "default" : "pointer"};
                           font-size:10px;font-family:var(--font-mono)"
                    title="Re-run just this scanner">↻ Run</button>`;
    }
    return [name, label, icon, scanners[name] || {}, {extraControl}];
  });
  grid.innerHTML = refreshErrorBanner + cards.map(([_, label, icon, r, opts]) =>
    util_renderScannerCard(_, label, icon, r, opts)
  ).join("");
}

function util_copyCmd(cmd, btn) {
  // Copy a slash command to clipboard. Both code-review and code-
  // simplifier are Claude Code skills -- the tray can't invoke them,
  // so the right UX is "make it one click to paste into a Claude
  // session" rather than a button that does nothing useful.
  //
  // Unified promise chain handles BOTH error paths (code-review
  // finding 2026-05-28): synchronous TypeError when
  // navigator.clipboard is undefined on an older browser AND async
  // rejections from writeText (permission denied / unfocused doc).
  // The previous try/catch only caught the sync case.
  Promise.resolve()
    .then(() => navigator.clipboard.writeText(cmd))
    .then(() => {
      const orig = btn.textContent;
      btn.textContent = "✓ Copied";
      btn.style.color = "var(--green)";
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.color = "var(--muted)";
      }, 1500);
    })
    .catch(e => {
      alert("Couldn't copy to clipboard: " + (e && e.message ? e.message : e));
    });
}

async function util_resetEmitted() {
  // Clears the dedup memory so the next scan re-emits all current
  // findings to the project backlog. Useful after the user has
  // hand-pruned the auto-generated rows or wants a "rebuild from
  // scratch" run.
  if (!confirm("Reset emitted-findings memory? The next scan will re-append every current finding to the project backlog (deduped against the same memory, so reruns after that won't re-add)." )) {
    return;
  }
  try {
    const r = await fetch("/api/codehealth/reset-emitted", {method:"POST"});
    if (!r.ok) {
      alert("Reset failed: " + r.status);
      return;
    }
    alert("✅ Emitted-findings memory cleared. Click ▶ Scan now to re-emit.");
  } catch (e) {
    alert("Reset failed: " + e.message);
  }
}

async function util_refreshCoverage() {
  // Re-runs pytest --cov against the primary repo so .coverage gets
  // freshened. The backend kicks off a thread; we poll status until
  // is_refreshing_coverage flips back to false, then the new % shows up.
  try {
    const r = await fetch("/api/codehealth/refresh-coverage", {method:"POST"});
    if (r.status === 409) {
      // Already running — just (re)start the poll.
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {
      const data = await r.json().catch(()=>({}));
      alert("Coverage refresh failed to start: " + (data.error || r.status));
      return;
    }
    // Re-render immediately so the spinner state shows; poll picks up
    // the rest.
    await util_loadCodeHealth();
  } catch (e) {
    alert("Coverage refresh failed to start: " + e.message);
  }
}

function util_humanise(name) {
  // "tech_debt" -> "Tech Debt". Fallback label for scanners not in
  // SCANNER_META (so a future backend scanner still renders a card).
  return String(name).replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

async function util_runScanner(name) {
  // Re-run a single scanner via POST /api/codehealth/run/<name>. Leaves
  // the other cards untouched. The status poll flips the per-card
  // spinner + the global button back when is_running clears.
  try {
    const r = await fetch("/api/codehealth/run/" + encodeURIComponent(name), {method:"POST"});
    if (r.status === 409) {            // a scan is already in flight
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {                       // 404 unknown scanner / other
      const data = await r.json().catch(()=>({}));
      alert("Couldn't run " + name + ": " + (data.error || r.status));
      return;
    }
    await util_loadCodeHealth();        // render spinner state; poll does the rest
  } catch (e) {
    alert("Couldn't run " + name + ": " + e.message);
  }
}

async function util_runScan() {
  const btn = document.getElementById("util-scan-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
  try {
    const r = await fetch("/api/codehealth/run", {method:"POST"});
    if (r.status === 409) {
      // Already running — just (re)start the poll.
      await util_loadCodeHealth();
      return;
    }
    if (!r.ok) {
      const data = await r.json().catch(()=>({}));
      alert("Scan failed to start: " + (data.error || r.status));
      if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
      return;
    }
    // Kick off polling; util_loadCodeHealth flips the button back when
    // is_running flips back to false.
    await util_loadCodeHealth();
  } catch (e) {
    alert("Scan failed to start: " + e.message);
    if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
  }
}
