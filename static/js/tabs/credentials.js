// Credentials tab (prefix cred) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// CREDENTIALS & NETWORK HEALTH
// ══════════════════════════════════════════════════════════════════════════
let _credData = null;
let _dashConcerns = [];

async function loadCredentials() {
  try {
    document.getElementById("cr-loading").style.display = "block";
    document.getElementById("cr-content").style.display = "none";
    const r = await fetch("/api/credentials/health");
    _credData = await r.json();
    renderCredentials(_credData);
    fetchSummary("credentials", _credData, "summary-credentials");
  } catch(e) {
    console.error("Failed to load credentials:", e);
  }
}

function renderCredentials(d) {

  // OneDrive stat cards
  const odStatusEl = document.getElementById("cr-od-status");
  const tokenAgeEl = document.getElementById("cr-token-age");
  if (d.msal_token_stale) {
    odStatusEl.innerHTML = `<span style="color:var(--red);font-weight:700">EXPIRED</span>`;
    tokenAgeEl.innerHTML = `<span style="color:var(--red)">${d.msal_token_age_h?.toFixed(0) || "?"}h old</span>`;
  } else if (d.onedrive_connected) {
    odStatusEl.innerHTML = `<span style="color:var(--cyan)">Connected</span>`;
    tokenAgeEl.innerHTML = d.msal_token_age_h != null
      ? `<span style="color:var(--cyan)">${d.msal_token_age_h.toFixed(0)}h ago</span>`
      : `<span style="color:var(--muted)">—</span>`;
  } else {
    odStatusEl.innerHTML = `<span style="color:var(--orange)">Not signed in</span>`;
    tokenAgeEl.innerHTML = `<span style="color:var(--muted)">—</span>`;
  }
  document.getElementById("cr-drives-down").textContent = (d.drives_down||[]).length;

  // OneDrive detail card
  const odCard = document.getElementById("cr-od-card");
  const odDetail = document.getElementById("cr-od-detail");
  if (d.onedrive_suspended) {
    odCard.style.borderColor = "var(--red)";
    odDetail.innerHTML = `
      <div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:14px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:8px">⚠ OneDrive is SUSPENDED by Windows</div>
        <div style="color:var(--muted);line-height:1.6;margin-bottom:10px">
          This is the confirmed root cause of your Word and Outlook sign-in errors.
          Windows suspended OneDrive to free memory (likely due to high RAM usage from other processes).
          When OneDrive is suspended it cannot refresh Microsoft 365 OAuth tokens.
        </div>
        <button onclick="resumeOneDrive()"
          style="background:var(--red);color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700">
          ▶ Resume OneDrive Now
        </button>
      </div>`;
  } else if (d.msal_token_stale) {
    odCard.style.borderColor = "var(--red)";
    odDetail.innerHTML = `
      <div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:14px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:8px">⚠ This is your Word / Outlook sign-in error</div>
        <div style="color:var(--muted);line-height:1.6;margin-bottom:10px">
          The Microsoft 365 authentication token in Windows is <strong style="color:var(--red)">${d.msal_token_age_h?.toFixed(0) || "?"} hours old</strong>.
          When this token expires, Word shows "Sign in Required — cached credentials have expired"
          and Outlook loses access to accounts using Modern Authentication (OAuth).
        </div>
        <div style="color:var(--text);font-weight:600;margin-bottom:6px">How to fix it:</div>
        <div style="color:var(--muted);line-height:1.8;font-size:11px">
          1. Click the OneDrive cloud icon in the taskbar system tray<br>
          2. Click Sign in and complete authentication<br>
          3. Open Word or Outlook — the sign-in prompt should clear automatically<br>
          4. If it persists: File &gt; Office Account &gt; Sign Out, then Sign In again
        </div>
      </div>`;
  } else if (!d.onedrive_connected) {
    odCard.style.borderColor = "var(--orange)";
    odDetail.innerHTML = `<div style="color:var(--orange);font-size:13px;padding:8px 0">
      OneDrive is not signed in. Office apps may show sign-in prompts.<br>
      <span style="color:var(--muted);font-size:11px">Click the OneDrive icon in the system tray to sign in.</span></div>`;
  } else {
    odCard.style.borderColor = "";
    const acct = d.onedrive_account ? `<div style="color:var(--muted);font-size:11px;margin-top:4px">${esc(d.onedrive_account)}</div>` : "";
    const age  = d.msal_token_age_h != null
      ? `<div style="color:var(--muted);font-size:11px;margin-top:4px">Token refreshed ${d.msal_token_age_h.toFixed(0)}h ago · ${d.msal_cache_files || 0} cache files · ${d.msal_cache_size_kb || 0} KB</div>`
      : "";
    const officeCreds = (d.office_creds||[]).length;
    odDetail.innerHTML = `
      <div style="color:var(--cyan);font-weight:700;font-size:13px;margin-bottom:4px">✓ Connected${d.onedrive_running ? " and running" : ""}</div>
      ${acct}${age}
      ${officeCreds ? `<div style="color:var(--muted);font-size:11px;margin-top:6px">${officeCreds} Office credential(s) in Credential Manager</div>` : ""}`;
  }

  const fastEl  = document.getElementById("cr-fast");
  const fastCard = document.getElementById("cr-fast-card");
  const fixBtn   = document.getElementById("cr-fix-btn");
  const fast = d.fast_startup;
  const fastDetailEl = document.getElementById("cr-fast-detail");
  if (fast === true) {
    fastEl.innerHTML = `<span style="color:var(--red);font-weight:700">ON</span>`;
    fastCard.style.borderColor = "var(--red)";
    fixBtn.style.display = "";
    fastDetailEl.innerHTML =
      `<div style="background:#ff456018;border:1px solid var(--red);border-radius:8px;padding:12px;font-size:12px">
        <div style="color:var(--red);font-weight:700;margin-bottom:6px">⚠ Fast Startup is ON</div>
        <div style="color:var(--muted);line-height:1.5;margin-bottom:10px">
          Windows does not fully shut down. Network credentials and SMB connections are stored
          in a hibernation file and often fail to restore correctly on the next boot — the most
          common cause of NAS drive loss after reboot.
        </div>
        <span id="cr-fast-toggle-msg" style="font-size:11px;color:var(--muted);margin-left:10px"></span>
      </div>`;
    const actionsEl2 = document.getElementById("cr-fast-actions");
    if (actionsEl2) {
      actionsEl2.innerHTML = "";
      const btn2 = document.createElement("button");
      btn2.textContent = "⚡ Disable Fast Startup";
      btn2.style.cssText = "background:var(--red);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700";
      btn2.addEventListener("click", () => toggleFastStartup(false));
      actionsEl2.appendChild(btn2);
    }
  } else if (fast === false) {
    fastEl.innerHTML = `<span style="color:var(--cyan);font-weight:700">OFF</span>`;
    fastCard.style.borderColor = "";
    fastDetailEl.innerHTML =
      `<div style="color:var(--cyan);font-size:13px">✓ Fast Startup is disabled. Full shutdown/restart cycle is in effect.</div>
       <span id="cr-fast-toggle-msg" style="font-size:11px;color:var(--muted);display:block;margin-top:6px"></span>`;
    const actionsEl = document.getElementById("cr-fast-actions");
    if (actionsEl) {
      actionsEl.innerHTML = "";
      const btn = document.createElement("button");
      btn.textContent = "Enable Fast Startup";
      btn.style.cssText = "background:#00d4ff18;border:1px solid var(--cyan);color:var(--cyan);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600";
      btn.addEventListener("click", () => toggleFastStartup(true));
      actionsEl.appendChild(btn);
    }
  } else {
    fastEl.textContent = "—";
    fastDetailEl.innerHTML =
      `<div style="color:var(--muted);font-size:12px">Could not determine Fast Startup state.</div>`;
  }

  // SMB / CIFS / NFS drives
  const drives = d.drives || [];
  const protoBadge = p => {
    const col = p==="NFS"?"var(--purple)":p==="SMB/CIFS"?"var(--cyan)":"var(--muted)";
    return `<span style="font-size:9px;border:1px solid ${col};color:${col};padding:1px 5px;border-radius:4px;margin-left:6px">${esc(p)}</span>`;
  };
  const drivesHtml = drives.length ? `
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="color:var(--muted);border-bottom:1px solid var(--border)">
        <th style="padding:5px 8px;text-align:left">Drive</th>
        <th style="padding:5px 8px;text-align:left">Share Path</th>
        <th style="padding:5px 8px;text-align:left">Protocol</th>
        <th style="padding:5px 8px;text-align:center">Port</th>
        <th style="padding:5px 8px;text-align:left">Dialect</th>
        <th style="padding:5px 8px;text-align:left">Status</th>
      </tr></thead><tbody>` +
    drives.map(drv => {
      const ok      = drv.Reachable;
      const proto   = drv.Protocol || "SMB/CIFS";
      const port    = drv.Port || (proto === "NFS" ? 2049 : 445);
      const dialect = drv.Dialect || "";
      const portCol = proto==="NFS"?"var(--purple)":"var(--cyan)";
      const dialectLabel = dialect
        ? `<span style="font-size:10px;color:var(--cyan);border:1px solid #00d4ff33;padding:1px 6px;border-radius:4px">${esc(dialect)}</span>`
        : `<span style="font-size:10px;color:var(--muted)">—</span>`;
      return `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:6px 8px;font-weight:700">${esc(drv.Name)}:\</td>
        <td style="padding:6px 8px;color:var(--muted);font-size:11px">${esc(drv.DisplayRoot||drv.Root||"")}</td>
        <td style="padding:6px 8px">${protoBadge(proto)}</td>
        <td style="padding:6px 8px;text-align:center">
          <span style="font-size:11px;font-weight:700;color:${portCol}">${port}</span>
        </td>
        <td style="padding:6px 8px">${dialectLabel}</td>
        <td style="padding:6px 8px;color:${ok?"var(--cyan)":"var(--red)"};font-weight:700;white-space:nowrap">${ok?"✓ Reachable":"✗ UNREACHABLE"}</td>
      </tr>`;
    }).join("") + `</tbody></table>` :
    `<div style="color:var(--muted);font-size:12px">No mapped SMB/CIFS/NFS drives found.</div>`;
  document.getElementById("cr-drives-detail").innerHTML = drivesHtml;

  // Email credentials
  const emailCreds = d.email_creds || [];
  const emailHtml = emailCreds.length ? emailCreds.map(c =>
    `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
      <div style="font-size:12px;font-weight:600">${esc(c.Target||"")}</div>
      <div style="font-size:10px;color:var(--muted)">${esc(c.User||"")} &nbsp;·&nbsp; ${esc(c.Type||"")}</div>
    </div>`
  ).join("") :
  `<div style="color:var(--orange);font-size:12px;padding:10px 0">
    No email credentials found in Credential Manager.<br>
    <span style="color:var(--muted);font-size:11px">Outlook may be managing tokens separately via MSAL cache, or they were cleared on last reboot.</span>
  </div>`;
  document.getElementById("cr-email-detail").innerHTML = emailHtml;

  // Firewall rules
  const fw = d.fw_rules || [];
  const fwHtml = fw.length ? fw.slice(0,8).map(f =>
    `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px">
      <span style="color:var(--text)">${esc(f.DisplayName||"")}</span>
      <span style="color:${f.Action==="Block"?"var(--red)":f.Enabled?"var(--cyan)":"var(--muted)"};font-weight:700">${esc(f.Action||"")} ${f.Enabled?"":"(disabled)"}</span>
    </div>`
  ).join("") :
  `<div style="color:var(--muted);font-size:12px">No file sharing firewall rules found. McAfee may be managing these separately.</div>`;
  document.getElementById("cr-fw-detail").innerHTML = fwHtml;

  // All credentials table
  const creds = d.creds || [];
  const credRows = creds.map(c => {
    const isEmail = (d.email_creds||[]).some(e => e.Target === c.Target);
    const nasHosts = ["shigs78nas","shigs78nas2","nas","synology","qnap"];
    const isNas   = (d.nas_creds||[]).some(e => e.Target === c.Target) ||
                    nasHosts.some(h => (c.Target||"").toLowerCase().includes(h));
    const badge   = isEmail ? `<span style="font-size:9px;background:#00d4ff22;color:var(--cyan);padding:1px 6px;border-radius:8px;margin-left:6px">email</span>`
                  : isNas   ? `<span style="font-size:9px;background:#b388ff22;color:var(--purple);padding:1px 6px;border-radius:8px;margin-left:6px">NAS</span>`
                  : "";
    return `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:6px 10px;font-size:12px">${esc(c.Target||"")}${badge}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--muted)">${esc(c.User||"")}</td>
      <td style="padding:6px 10px;font-size:12px;color:var(--muted)">${esc(c.Type||"")}</td>
    </tr>`;
  }).join("");
  document.getElementById("cr-creds-tbody").innerHTML = credRows ||
    `<tr><td colspan="3" style="padding:20px;color:var(--muted);text-align:center">No credentials stored in Windows Credential Manager</td></tr>`;

  document.getElementById("cr-loading").style.display = "none";
  document.getElementById("cr-content").style.display = "";
}

async function resumeOneDrive() {
  const btn    = document.getElementById("cr-resume-od-btn");
  const status = document.getElementById("cr-fix-status");
  if (btn) { btn.disabled = true; btn.textContent = "Resuming…"; }
  if (status) { status.style.display = ""; status.style.color = "var(--muted)"; status.textContent = "Resuming OneDrive…"; }
  try {
    const r = await fetch("/api/credentials/resume-onedrive", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      if (status) { status.style.color = "var(--cyan)"; status.textContent = d.message + " Refreshing in 3s…"; }
      setTimeout(() => { loadCredentials(); if (status) status.style.display = "none"; }, 3000);
    } else {
      if (status) { status.style.color = "var(--red)"; status.textContent = d.message || "Failed to resume OneDrive."; }
    }
  } catch(e) {
    if (status) { status.style.color = "var(--red)"; status.textContent = "Error: " + e.message; }
  }
  if (btn) { btn.disabled = false; btn.textContent = "▶ Resume OneDrive"; }
}

async function resumeBrokers() {
  const btn    = document.getElementById("cr-resume-btn");
  const status = document.getElementById("cr-fix-status");
  btn.disabled = true;
  btn.textContent = "Resuming…";
  status.style.display = "";
  status.style.color = "var(--muted)";
  status.textContent = "Resuming Microsoft auth broker processes…";
  try {
    const r = await fetch("/api/credentials/resume-brokers", { method: "POST" });
    const d = await r.json();
    if (d.ok) {
      status.style.color = "var(--cyan)";
      status.textContent = d.message + " Refreshing in 3s…";
      setTimeout(() => {
        loadCredentials();
        status.style.display = "none";
      }, 3000);
    } else {
      status.style.color = "var(--orange)";
      status.textContent = d.message || "No broker processes found to resume.";
    }
  } catch (e) {
    status.style.color = "var(--red)";
    status.textContent = "Error: " + e.message;
  }
  btn.disabled = false;
  btn.textContent = "▶ Resume Auth Brokers";
}

async function fixFastStartup() { await toggleFastStartup(false); }

// Used by task_watcher concerns (backlog #27) — pops the Windows Logs/
// folder in Explorer so the user can inspect the raw log files.
async function openLogsFolder() {
  try {
    const r = await fetch("/api/tasks/open-logs-folder", {method: "POST"});
    const d = await r.json();
    if (!d.ok) {
      alert(`Could not open Logs folder: ${d.error || "unknown error"}`);
    }
  } catch (e) {
    alert(`Could not open Logs folder: ${e.message}`);
  }
}

// ── Memory concern action handlers (backlog #19) ─────────────────────────
// Wired up by the dashboard concern renderer when a concern carries
// process_name metadata. Each handler reloads the dashboard so the concern
// state (killed / snoozed) is reflected immediately.

function investigateProcess(pid, name) {
  switchTab("processes");
  // Bug 2026-04-28: previous version used a fixed 150ms timeout AND set
  // the search box to the PID number. Two failure modes:
  //   (a) /api/processes/list takes >150ms (~1-2s on a busy box) so
  //       renderProcesses ran against an empty _processData -> blank table
  //   (b) The filter only matched Name/Description, so a numeric PID
  //       search like "28008" returned zero rows even after data loaded
  // Fix (b) is in renderProcesses (filter now also matches PID + Path).
  // Fix (a) is here: poll _processData up to 30s and apply the search
  // when it's actually available, so the user always lands on a populated
  // filtered view.
  //
  // The search defaults to the human-readable NAME (sans .exe) so the
  // search box reads "ServiceShell" not "28008" -- but the filter
  // accepts either, so power-users can paste a PID and it still works.
  let tries = 0;
  const maxTries = 300;  // 30s at 100ms tick
  const apply = () => {
    if (_processData && (_processData.processes || []).length) {
      const search = document.getElementById("pr-search");
      if (search) {
        const cleanName = (name || "").replace(/\.exe$/i, "");
        search.value = cleanName || (pid ? String(pid) : "");
        if (typeof renderProcesses === "function") renderProcesses();
      }
    } else if (++tries < maxTries) {
      setTimeout(apply, 100);
    }
  };
  setTimeout(apply, 100);
}

async function killProcessFromConcern(pid, name) {
  if (!pid) {
    alert(`Cannot kill "${name}" — no PID attached to this concern. Use the Process Monitor to kill manually.`);
    return;
  }
  if (!confirm(`Kill ${name} (PID ${pid})?\n\nAny unsaved work in that process will be lost.`)) return;
  try {
    const r = await fetch("/api/processes/kill", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({pid: pid}),
    });
    const d = await r.json();
    if (d.ok) {
      setTimeout(loadDashboard, 500);  // refresh — the concern should disappear
    } else {
      // Offer elevated retry (SYSTEM/other-user procs) or honest message
      // (anti-tamper security software) instead of a bare "Access is denied".
      proc_handleKillFailure(d, pid, name, () => setTimeout(loadDashboard, 500));
    }
  } catch (e) {
    alert(`Failed to kill ${name}: ${e.message}`);
  }
}

async function snoozeMemoryConcern(name, hours) {
  if (!name) return;
  const h = parseInt(hours, 10) || 24;
  try {
    const r = await fetch("/api/memory/snooze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({process_name: name, hours: h}),
    });
    const d = await r.json();
    if (d.ok) {
      // Expiry in d.expires — reload to hide the concern
      setTimeout(loadDashboard, 200);
    } else {
      alert(`Failed to snooze ${name}: ${d.error || "unknown error"}`);
    }
  } catch (e) {
    alert(`Failed to snooze ${name}: ${e.message}`);
  }
}

// Pause / resume dashboard health alerts for one physical drive (by serial).
// Used by the "⏸ Pause 24h" button on a disk-health concern and the "resume"
// link the Storage tab shows on a paused drive.
async function pauseDiskConcern(serial, hours, btnEl) {
  if (!serial) return;
  const h = parseInt(hours, 10) || 24;
  try {
    const r = await fetch("/api/disk/snooze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({serial: serial, hours: h}),
    });
    const d = await r.json();
    if (d.ok) {
      // Optimistic feedback: fade the concern card immediately so the click is
      // visibly acknowledged. The backend already cleared the dashboard cache,
      // so the reload recomputes fresh and drops the concern for real.
      if (btnEl && btnEl.closest) {
        const card = btnEl.closest(".concern-card");
        if (card) { card.style.transition = "opacity .3s"; card.style.opacity = "0.35"; }
      }
      setTimeout(loadDashboard, 300);
    } else {
      alert(`Failed to pause drive: ${d.error || "unknown error"}`);
    }
  } catch (e) { alert(`Failed to pause drive: ${e.message}`); }
}

async function resumeDiskDrive(serial) {
  if (!serial) return;
  try {
    await fetch("/api/disk/snooze", {
      method: "DELETE",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({serial: serial}),
    });
    loadDisk();
    if (typeof loadDashboard === "function") setTimeout(loadDashboard, 200);
  } catch (e) { alert(`Failed to resume drive: ${e.message}`); }
}

async function toggleFastStartup(enable) {
  const btn = document.getElementById("cr-fast-toggle-btn");
  const msg = document.getElementById("cr-fast-toggle-msg");
  if (btn) { btn.disabled = true; btn.textContent = enable ? "Enabling…" : "Disabling…"; }
  if (msg) { msg.textContent = "Applying registry change…"; msg.style.color = "var(--muted)"; }
  try {
    const r = await fetch("/api/credentials/fix-fast-startup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enable })
    });
    const d = await r.json();
    if (d.ok) {
      if (msg) {
        msg.style.color = "var(--cyan)";
        msg.textContent = (enable ? "Fast Startup enabled." : "Fast Startup disabled.")
          + " Restart Windows to apply (use Restart, not Shut Down).";
      }
      setTimeout(() => loadCredentials(), 1500);
    } else {
      if (msg) { msg.style.color = "var(--red)"; msg.textContent = d.message || "Failed — try running as Administrator."; }
      if (btn) { btn.disabled = false; btn.textContent = enable ? "Enable Fast Startup" : "⚡ Disable Fast Startup"; }
    }
  } catch(e) {
    if (msg) { msg.style.color = "var(--red)"; msg.textContent = "Error: " + e.message; }
    if (btn) { btn.disabled = false; }
  }
}


