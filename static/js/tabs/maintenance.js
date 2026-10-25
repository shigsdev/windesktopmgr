// Cleanup tab (prefix mnt) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// MAINTENANCE / CLEANUP (mnt = Cleanup tab)
// Scan is read-only; clean acts only on whitelisted category KEYS. DOM-built
// (no innerHTML) since it renders live filesystem paths/sizes.
// ══════════════════════════════════════════════════════════════════════════
function mnt_el(tag, css, text) {
  const e = document.createElement(tag);
  if (css) e.style.cssText = css;
  if (text !== undefined) e.textContent = text;
  return e;
}

// The scan runs in a background thread server-side (a full %TEMP% walk can take
// ~a minute), so we poll: fetch returns status 'running' until the result is
// ready, then 'done'. force=true asks the server for a fresh scan.
async function mnt_scan(force) {
  const host = document.getElementById("mnt-junk");
  const totalEl = document.getElementById("mnt-total");
  const btn = document.getElementById("mnt-scan-btn");
  if (!host) return;
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  while (host.firstChild) host.removeChild(host.firstChild);
  const progress = mnt_el("div", "color:var(--muted);font-size:13px;padding:12px", "Scanning…");
  host.appendChild(progress);
  try {
    // Shares mnt_poll with the space scans so all three behave identically.
    const d = await mnt_poll("/api/maintenance/junk/scan", force,
      s => { progress.textContent = `Scanning… (${s}s)`; });
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!d || !d.ok || d.status === "running") {
      const p = mnt_pollProblem(d);
      host.appendChild(mnt_el("div", `color:${p.color};padding:12px`, p.text));
      return;
    }
    if (totalEl) totalEl.textContent = `${d.total_human} reclaimable`;

    (d.categories || []).forEach(c => {
      const row = mnt_el("label", "display:flex;align-items:center;gap:12px;padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer");
      const cb = document.createElement("input");
      cb.type = "checkbox"; cb.value = c.key; cb.className = "mnt-cb";
      // Pre-check only non-empty, non-irreversible categories. The Recycle Bin
      // (default_off) empties permanently, so the user must opt in explicitly.
      cb.checked = c.bytes > 0 && !c.default_off;
      cb.disabled = c.bytes === 0 && c.count === 0;
      row.appendChild(cb);
      const mid = mnt_el("div", "flex:1;min-width:0");
      mid.appendChild(mnt_el("div", "font-weight:600;font-size:13px", c.label));
      mid.appendChild(mnt_el("div", "font-size:11px;color:var(--muted)", c.description));
      row.appendChild(mid);
      const size = mnt_el("div", `font-family:monospace;font-size:13px;white-space:nowrap;color:${c.bytes > 0 ? "var(--fg)" : "var(--muted)"}`,
        `${c.human}${c.count ? " · " + c.count + " item" + (c.count === 1 ? "" : "s") : ""}`);
      row.appendChild(size);
      host.appendChild(row);
    });

    const bar = mnt_el("div", "display:flex;align-items:center;gap:12px;padding:12px");
    const clean = document.createElement("button");
    clean.type = "button"; clean.textContent = "🧹 Clean selected";
    clean.style.cssText = "padding:8px 16px;font-size:12px;border-radius:6px;background:transparent;color:var(--cyan);border:1px solid var(--cyan);cursor:pointer";
    clean.onclick = mnt_clean;
    bar.appendChild(clean);
    bar.appendChild(mnt_el("span", "font-size:11px;color:var(--muted)", "Safe, regenerated files are removed permanently; nothing outside these categories is touched."));
    host.appendChild(bar);
    const res = mnt_el("div", "font-size:12px;padding:0 12px");
    res.id = "mnt-result";
    host.appendChild(res);
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(mnt_el("div", "color:var(--red);padding:12px", "Scan error: " + e.message));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "▶ Scan now"; }
  }
}

async function mnt_clean() {
  const keys = [...document.querySelectorAll(".mnt-cb:checked")].map(cb => cb.value);
  if (!keys.length) { alert("Select at least one category to clean."); return; }
  const labels = [...document.querySelectorAll(".mnt-cb:checked")].map(cb => cb.closest("label").querySelector("div div").textContent);
  if (!confirm(`Clean these ${keys.length} categories?\n\n• ${labels.join("\n• ")}\n\nSafe, regenerated files are removed permanently.`)) return;
  const res = document.getElementById("mnt-result");
  if (res) res.textContent = "Cleaning…";
  try {
    const r = await fetch("/api/maintenance/junk/clean", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({keys}),
    });
    const d = await r.json();
    if (!d.ok) { if (res) { res.textContent = "Clean failed: " + (d.error || "unknown"); res.style.color = "var(--red)"; } return; }
    if (res) { res.textContent = `Freed ${d.total_human}.`; res.style.color = "var(--cyan)"; }
    setTimeout(() => mnt_scan(true), 600);  // force a fresh scan so freed space is reflected
  } catch (e) {
    if (res) { res.textContent = "Clean error: " + e.message; res.style.color = "var(--red)"; }
  }
}

async function mnt_diskCleanup() {
  try {
    const r = await fetch("/api/disk/run-tool", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({tool: "cleanmgr"}),
    });
    const d = await r.json();
    if (!d.ok) alert("Could not launch Disk Cleanup: " + (d.error || "unknown error"));
  } catch (e) { alert("Could not launch Disk Cleanup: " + e.message); }
}

// ── Tier 3: system maintenance (read-only status + hand-offs) ───────────────
// Nothing here runs a repair. SFC / DISM / Optimize-Volume all need admin, and
// the app never spawns an elevated repair — it reports what it can read as a
// normal user and hands the actual work to Windows' own tools.

function mnt_statusRow(label, valueText, color, detail) {
  const row = mnt_el("div", "display:flex;align-items:flex-start;gap:12px;padding:9px 12px;border-bottom:1px solid var(--border)");
  const mid = mnt_el("div", "flex:1;min-width:0");
  mid.appendChild(mnt_el("div", "font-weight:600;font-size:12px", label));
  if (detail) mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted)", detail));
  row.appendChild(mid);
  row.appendChild(mnt_el("div", `font-size:12px;font-weight:600;white-space:nowrap;color:${color}`, valueText));
  return row;
}

async function mnt_runTool(tool, label) {
  try {
    const r = await fetch("/api/disk/run-tool", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({tool}),
    });
    const d = await r.json();
    if (!d.ok) alert(`Could not launch ${label}: ` + (d.error || "unknown error"));
  } catch (e) { alert(`Could not launch ${label}: ` + e.message); }
}

function mnt_copyCommand(cli, btn) {
  navigator.clipboard.writeText(cli).then(() => {
    const was = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = was; }, 1200);
  }).catch(() => alert("Copy failed. The command is: " + cli));
}

async function mnt_system() {
  const host = document.getElementById("mnt-system");
  if (!host) return;
  while (host.firstChild) host.removeChild(host.firstChild);
  host.appendChild(mnt_el("div", "color:var(--muted);font-size:12px;padding:12px", "Reading system status…"));
  try {
    const d = await fetch("/api/maintenance/system/status").then(r => r.json());
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!d || !d.ok) {
      host.appendChild(mnt_el("div", "color:var(--red);font-size:12px;padding:12px",
        "Could not read system status" + (d && d.error ? ": " + d.error : ".")));
      return;
    }

    // TRIM
    const t = d.trim || {};
    if (t.known) {
      const on = t.enabled === true;
      const names = (t.filesystems || []).map(f => f.filesystem).join(", ");
      mnt_appendRow(host, "SSD TRIM", on ? "Enabled" : (t.enabled === false ? "DISABLED" : "Unknown"),
        on ? "var(--green)" : (t.enabled === false ? "var(--red)" : "var(--muted)"),
        on ? `Windows is sending TRIM to your SSDs (${names}) — this keeps write speed up.`
           : `TRIM is not being sent (${names}). SSDs slow down over time without it.`);
    } else {
      mnt_appendRow(host, "SSD TRIM", "Unknown", "var(--muted)", t.detail || "");
    }

    // Drive optimization schedule
    const o = d.optimize || {};
    if (o.known) {
      const bad = o.stale || !o.succeeded || !o.enabled;
      let value, detail;
      if (!o.enabled) {
        value = "Disabled"; detail = "Windows' scheduled drive optimization is turned off.";
      } else if (!o.succeeded) {
        value = "Last run failed"; detail = `Scheduled optimization returned ${o.result_hex}.`;
      } else if (o.stale) {
        value = `${o.days_ago}d ago`; detail = `Last optimization was over ${o.stale_after_days} days ago — the weekly schedule may not be running.`;
      } else {
        value = o.days_ago === 0 ? "Today" : `${o.days_ago}d ago`;
        detail = `Windows optimized your drives on schedule (last result ${o.result_hex}).`;
      }
      mnt_appendRow(host, "Drive optimization", value, bad ? "var(--amber)" : "var(--green)", detail);
    } else {
      mnt_appendRow(host, "Drive optimization", "Unknown", "var(--muted)", o.detail || "");
    }

    // Pending reboot
    const rb = d.reboot || {};
    const strong = (rb.signals || []).filter(s => s.set && s.strong).map(s => s.label);
    const soft = (rb.signals || []).filter(s => s.set && !s.strong).map(s => s.label);
    if (rb.required) {
      mnt_appendRow(host, "Pending reboot", "Restart needed", "var(--amber)",
        "Windows is holding a restart: " + strong.join(", ") + ".");
    } else if (rb.soft_only) {
      // Deliberately NOT an alarm: PendingFileRenameOperations is set on plenty
      // of healthy machines, so it is reported as context, not a warning.
      mnt_appendRow(host, "Pending reboot", "Not required", "var(--green)",
        "No servicing or update restart is pending. (" + soft.join(", ") + " — normal, not a problem.)");
    } else {
      mnt_appendRow(host, "Pending reboot", "Not required", "var(--green)", "Nothing is waiting on a restart.");
    }

    // Hand-offs — Windows owns these repairs
    const tools = mnt_el("div", "padding:10px 12px");
    tools.appendChild(mnt_el("div", "font-size:11px;color:var(--muted);margin-bottom:8px",
      "These repairs need administrator rights, so they are handed to Windows rather than run by the app."));
    (d.tools || []).forEach(tool => {
      const row = mnt_el("div", "display:flex;align-items:flex-start;gap:10px;padding:7px 0");
      const mid = mnt_el("div", "flex:1;min-width:0");
      mid.appendChild(mnt_el("div", "font-weight:600;font-size:12px", tool.label));
      mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted)", tool.description));
      if (tool.kind === "command") {
        mid.appendChild(mnt_el("code", "display:inline-block;margin-top:4px;font-size:11px;color:var(--cyan);background:var(--bg);padding:2px 6px;border-radius:4px", tool.cli));
      }
      row.appendChild(mid);
      const btn = document.createElement("button");
      btn.type = "button";
      btn.style.cssText = "padding:5px 12px;font-size:11px;border-radius:6px;background:transparent;color:var(--cyan);border:1px solid var(--cyan);cursor:pointer;white-space:nowrap";
      if (tool.kind === "launch") {
        btn.textContent = "Open";
        btn.onclick = () => mnt_runTool(tool.tool, tool.label);
      } else {
        btn.textContent = "Copy";
        btn.onclick = () => mnt_copyCommand(tool.cli, btn);
      }
      row.appendChild(btn);
      tools.appendChild(row);
    });
    host.appendChild(tools);
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(mnt_el("div", "color:var(--red);font-size:12px;padding:12px", "System status error: " + e.message));
  }
}


// ── Tier 4: registry report (read-only) ─────────────────────────────────────
// There is deliberately no "fix" or "clean" button here. The report shows what
// is broken and can back the keys up; removing a registry entry stays a
// decision the user makes deliberately, in regedit.

function mnt_regFinding(f) {
  const row = mnt_el("div", "display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border)");
  const mid = mnt_el("div", "flex:1;min-width:0");
  const head = mnt_el("div", "display:flex;align-items:center;gap:8px;flex-wrap:wrap");
  head.appendChild(mnt_el("span", "font-weight:600;font-size:12px", f.name || "(unnamed)"));
  head.appendChild(mnt_el("span", "font-size:10px;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:1px 5px", f.hive));
  head.appendChild(mnt_el("span",
    `font-size:10px;border-radius:4px;padding:1px 5px;border:1px solid var(--amber);color:var(--amber)`,
    f.issue === "empty" ? "launches nothing" : "target missing"));
  mid.appendChild(head);
  mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted);margin-top:2px", f.detail || ""));
  if (f.target) mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted);word-break:break-all;margin-top:2px", f.target));
  mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted);word-break:break-all;opacity:.75", f.hive + "\\" + f.key));
  row.appendChild(mid);
  return row;
}

async function mnt_regBackup(btn) {
  const host = document.getElementById("mnt-registry-backup");
  const keys = window._mntRegKeys || [];
  if (btn) { btn.disabled = true; btn.textContent = "Backing up…"; }
  try {
    const r = await fetch("/api/maintenance/registry/backup", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({keys}),
    });
    const d = await r.json();
    if (host) {
      while (host.firstChild) host.removeChild(host.firstChild);
      host.appendChild(mnt_el("div", `font-size:11px;color:${d.ok ? "var(--green)" : "var(--red)"}`,
        d.ok ? `Backed up ${d.count} key(s) (${d.human}) to ${d.dir}`
             : "Backup failed: " + (d.error || "unknown error")));
    }
  } catch (e) {
    if (host) host.textContent = "Backup error: " + e.message;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Back up these keys"; }
  }
}

async function mnt_registry(force) {
  const host = document.getElementById("mnt-registry");
  const btn = document.getElementById("mnt-registry-btn");
  if (!host) return;
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  while (host.firstChild) host.removeChild(host.firstChild);
  const progress = mnt_el("div", "color:var(--muted);font-size:12px;padding:12px", "Scanning…");
  host.appendChild(progress);
  try {
    const d = await mnt_poll("/api/maintenance/registry/scan", force,
      s => { progress.textContent = `Scanning… (${s}s)`; });
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!d || !d.ok || d.status === "running") {
      const p = mnt_pollProblem(d);
      host.appendChild(mnt_el("div", `color:${p.color};font-size:12px;padding:10px 12px`, p.text));
      return;
    }

    // Headline. "0 problems" is a real, useful result here, not a failure to
    // find something — say so plainly instead of padding the list.
    const clean = d.total === 0;
    const headline = mnt_el("div", `padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;color:${clean ? "var(--green)" : "var(--amber)"}`,
      clean ? `No broken registry entries found (${d.checked.toLocaleString()} checked)`
            : `${d.total} broken entr${d.total === 1 ? "y" : "ies"} found (${d.checked.toLocaleString()} checked)`);
    host.appendChild(headline);
    host.appendChild(mnt_el("div", "font-size:11px;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)", d.note || ""));

    const keys = [];
    (d.categories || []).forEach(c => {
      const row = mnt_el("div", "padding:8px 12px;border-bottom:1px solid var(--border)");
      const line = mnt_el("div", "display:flex;align-items:center;gap:10px");
      const mid = mnt_el("div", "flex:1;min-width:0");
      mid.appendChild(mnt_el("div", "font-weight:600;font-size:12px", c.label));
      mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted)", c.description || ""));
      line.appendChild(mid);
      let tail = `${c.checked.toLocaleString()} checked`;
      if (c.unverified) tail += ` · ${c.unverified} unverified`;
      line.appendChild(mnt_el("div", "font-size:10px;color:var(--muted);white-space:nowrap", tail));
      line.appendChild(mnt_el("div",
        `font-size:12px;font-weight:600;white-space:nowrap;color:${c.count ? "var(--amber)" : "var(--green)"}`,
        c.count ? String(c.count) : "0"));
      row.appendChild(line);
      if (c.error) row.appendChild(mnt_el("div", "font-size:10px;color:var(--red);margin-top:4px", "Could not read: " + c.error));
      host.appendChild(row);
      (c.findings || []).forEach(f => { host.appendChild(mnt_regFinding(f)); if (!keys.includes(f.key)) keys.push(f.key); });
    });
    window._mntRegKeys = keys;

    const bar = mnt_el("div", "padding:10px 12px");
    if (keys.length) {
      const backup = document.createElement("button");
      backup.type = "button"; backup.textContent = "Back up these keys";
      backup.style.cssText = "padding:6px 14px;font-size:12px;border-radius:6px;background:transparent;color:var(--cyan);border:1px solid var(--cyan);cursor:pointer";
      backup.onclick = () => mnt_regBackup(backup);
      bar.appendChild(backup);
      bar.appendChild(mnt_el("div", "font-size:11px;color:var(--muted);margin-top:6px",
        "Saves a .reg file per key so you can restore it if you remove an entry by hand. Nothing here edits the registry."));
    } else {
      bar.appendChild(mnt_el("div", "font-size:11px;color:var(--muted)",
        "Nothing to back up — no broken entries were found."));
    }
    const result = mnt_el("div", "margin-top:6px");
    result.id = "mnt-registry-backup";
    bar.appendChild(result);
    host.appendChild(bar);
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(mnt_el("div", "color:var(--red);font-size:12px;padding:12px", "Registry scan error: " + e.message));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Scan registry"; }
  }
}

function mnt_appendRow(host, label, value, color, detail) {
  host.appendChild(mnt_statusRow(label, value, color, detail));
}

// ── Tier 2: space analysis (read-only) ──────────────────────────────────────
// Shared poll driver for the background scans. The server returns
// {status:'running'} until the worker finishes, so every space scan polls the
// same way; onTick reports elapsed seconds so the UI can show progress.
async function mnt_poll(url, force, onTick, maxPolls) {
  const t0 = Date.now();
  let u = url + (url.includes("?") ? "&" : "?") + (force ? "refresh=1" : "");
  let d = null;
  for (let i = 0; i < (maxPolls || 260); i++) {
    const r = await fetch(u);
    d = await r.json();
    if (!d || d.status !== "running") break;
    if (onTick) onTick(Math.round((Date.now() - t0) / 1000));
    // Snappy at first, then easier on a scan that is clearly going to take a
    // while. 20x1.5s + 240x3s gives a ~12 min ceiling: a cold %TEMP% walk on a
    // busy machine really can run past three minutes, and giving up on it was
    // reported to the user as a failure.
    await new Promise(res => setTimeout(res, i < 20 ? 1500 : 3000));
    u = url;  // later polls read the in-flight scan; never re-force
  }
  return d;
}

// A scan we stopped waiting for has NOT failed. Saying "timed out" when the
// worker is still happily running (and will cache its result) is a lie that
// trains people to distrust the tab — so the two cases read differently.
function mnt_pollProblem(d) {
  if (!d) return {text: "No response from the scanner.", color: "var(--red)"};
  if (d.status === "running") {
    return {
      text: "Still scanning in the background — this folder is unusually large. It will finish on its own; click the scan button again in a moment to pick up the result.",
      color: "var(--amber)",
    };
  }
  return {text: "Scan failed: " + (d.error || "unknown error"), color: "var(--red)"};
}

function mnt_spaceRoot() {
  const el = document.getElementById("mnt-space-root");
  return (el && el.value.trim()) || "";
}

// Truncation is reported honestly rather than silently: a capped walk is a
// partial answer and the user needs to know before concluding anything.
function mnt_truncNote(d) {
  if (!d.truncated) return null;
  return mnt_el("div", "font-size:11px;color:var(--amber);padding:6px 12px",
    `Stopped early after ${(d.scanned || 0).toLocaleString()} files (size/time cap) — results are partial. Scan a narrower folder for a complete answer.`);
}

function mnt_openFolder(path) {
  fetch("/api/disk/open", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({path}),
  }).then(r => r.json()).then(d => { if (!d.ok) alert("Could not open: " + (d.error || "unknown")); })
    .catch(e => alert("Could not open: " + e.message));
}

function mnt_fileRow(f, extra) {
  const row = mnt_el("div", "display:flex;align-items:center;gap:12px;padding:8px 12px;border-bottom:1px solid var(--border)");
  const mid = mnt_el("div", "flex:1;min-width:0");
  mid.appendChild(mnt_el("div", "font-weight:600;font-size:12px;word-break:break-all", f.name));
  mid.appendChild(mnt_el("div", "font-size:10px;color:var(--muted);word-break:break-all", f.dir || ""));
  row.appendChild(mid);
  if (extra) row.appendChild(extra);
  row.appendChild(mnt_el("div", "font-family:monospace;font-size:12px;white-space:nowrap", f.human));
  const open = document.createElement("button");
  open.type = "button"; open.textContent = "Open";
  open.style.cssText = "padding:3px 10px;font-size:11px;border-radius:5px;background:transparent;color:var(--cyan);border:1px solid var(--cyan);cursor:pointer";
  open.onclick = () => mnt_openFolder(f.dir || f.path);
  row.appendChild(open);
  return row;
}

async function mnt_bigFiles(force) {
  const host = document.getElementById("mnt-bigfiles");
  const btn = document.getElementById("mnt-bigfiles-btn");
  if (!host) return;
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  while (host.firstChild) host.removeChild(host.firstChild);
  const progress = mnt_el("div", "color:var(--muted);font-size:12px;padding:10px 12px", "Scanning…");
  host.appendChild(progress);
  try {
    const root = mnt_spaceRoot();
    const url = "/api/maintenance/space/large-files" + (root ? "?root=" + encodeURIComponent(root) : "");
    const d = await mnt_poll(url, force, s => { progress.textContent = `Scanning… (${s}s)`; });
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!d || !d.ok || d.status === "running") {
      const p = mnt_pollProblem(d);
      host.appendChild(mnt_el("div", `color:${p.color};font-size:12px;padding:10px 12px`, p.text));
      return;
    }
    const head = mnt_el("div", "font-size:11px;color:var(--muted);padding:6px 12px",
      `${d.files.length} file${d.files.length === 1 ? "" : "s"} over ${d.min_human} · ${d.total_human} total · walked ${(d.scanned || 0).toLocaleString()} files in ${d.root}`);
    host.appendChild(head);
    const note = mnt_truncNote(d);
    if (note) host.appendChild(note);
    if (!d.files.length) {
      host.appendChild(mnt_el("div", "font-size:12px;color:var(--muted);padding:10px 12px",
        `Nothing over ${d.min_human} here.`));
      return;
    }
    d.files.forEach(f => host.appendChild(mnt_fileRow(f, null)));
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(mnt_el("div", "color:var(--red);font-size:12px;padding:10px 12px", "Scan error: " + e.message));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Find big files"; }
  }
}

async function mnt_dupes(force) {
  const host = document.getElementById("mnt-dupes");
  const btn = document.getElementById("mnt-dupes-btn");
  if (!host) return;
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  while (host.firstChild) host.removeChild(host.firstChild);
  const progress = mnt_el("div", "color:var(--muted);font-size:12px;padding:10px 12px", "Scanning…");
  host.appendChild(progress);
  try {
    const root = mnt_spaceRoot();
    const url = "/api/maintenance/space/duplicates" + (root ? "?root=" + encodeURIComponent(root) : "");
    const d = await mnt_poll(url, force, s => { progress.textContent = `Hashing… (${s}s)`; });
    while (host.firstChild) host.removeChild(host.firstChild);
    if (!d || !d.ok || d.status === "running") {
      const p = mnt_pollProblem(d);
      host.appendChild(mnt_el("div", `color:${p.color};font-size:12px;padding:10px 12px`, p.text));
      return;
    }
    const shown = (d.groups || []).length;
    host.appendChild(mnt_el("div", "font-size:11px;color:var(--muted);padding:6px 12px",
      `${d.group_count} duplicate set${d.group_count === 1 ? "" : "s"}${shown < d.group_count ? ` (showing ${shown})` : ""} · ${d.total_wasted_human} wasted · files over ${d.min_human} in ${d.root}`));
    const note = mnt_truncNote(d);
    if (note) host.appendChild(note);
    if (!shown) {
      host.appendChild(mnt_el("div", "font-size:12px;color:var(--muted);padding:10px 12px", "No duplicates found."));
      return;
    }
    d.groups.forEach(g => {
      const wrap = mnt_el("div", "border-bottom:1px solid var(--border);padding:6px 0");
      wrap.appendChild(mnt_el("div", "font-size:11px;color:var(--amber);padding:4px 12px",
        `${g.count} copies × ${g.human} — ${g.wasted_human} wasted`));
      g.files.forEach((f, i) => {
        // The first copy is labelled as the one to keep; the app never deletes
        // here, so this is guidance for the user, not an action.
        const tag = mnt_el("span",
          `font-size:10px;padding:2px 6px;border-radius:4px;white-space:nowrap;border:1px solid ${i === 0 ? "var(--green)" : "var(--border)"};color:${i === 0 ? "var(--green)" : "var(--muted)"}`,
          i === 0 ? "keep" : "copy");
        wrap.appendChild(mnt_fileRow(f, tag));
      });
      host.appendChild(wrap);
    });
  } catch (e) {
    while (host.firstChild) host.removeChild(host.firstChild);
    host.appendChild(mnt_el("div", "color:var(--red);font-size:12px;padding:10px 12px", "Scan error: " + e.message));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Find duplicates"; }
  }
}


