// Diagnose tab (prefix dx) -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
// ══════════════════════════════════════════════════════════════════════════
// DIAGNOSE (dx_) -- symptom -> read-only probes -> payload preview -> verdict
// ══════════════════════════════════════════════════════════════════════════
// Backend: diagnose.py (/api/diagnose/*). The flow is: dx_start() posts the
// symptom; the server either asks for a missing slot (awaiting_slots, no
// session) or starts a session that dx_poll() follows. When the engine wants
// to send the evidence to the model it parks in awaiting_consent with the
// exact text; nothing is sent until dx_consent(true).
// Every interpolated value goes through escHtml().
const _DX_TERMINAL = ["done", "evidence_only", "error"];
const _DX_POLL_MS = 1000;
const _DX_MAX_POLL_FAILS = 5;
const _DX_BANNERS = {
  no_api_key: "No ANTHROPIC_API_KEY is set, so there's no AI verdict. The probe results below are still complete.",
  sdk_missing: "The anthropic package isn't installed, so there's no AI verdict. The probe results below are still complete.",
  declined: "You chose not to send the evidence.",
  consent_timeout: "No answer to the send prompt, so nothing was sent.",
  model_error: "The model didn't return a usable answer.",
  call_cap: "AI call limit reached until the app restarts.",
  superseded: "A newer diagnosis replaced this one before anything was sent.",
};
const _DX_LOCUS = {
  local: "Cause is on this PC",
  external_cause: "Nothing to fix on this PC",
  unknown: "Cause not pinned down",
};

let _dxPollTimer = null;       // the ONE poll timer; cleared before every re-arm
let _dxSid = null;             // session being followed (null = none)
let _dxPollFails = 0;
let _dxPreviewKey = null;      // "<sid>:<round>" of the preview now on screen
let _dxAnsweredKey = null;     // preview key already answered (blocks double posts)
let _dxAutoKey = null;         // preview key armed for auto-consent next poll
let _dxClasses = null;         // /api/diagnose/classes, fetched once
let _dxActions = [];           // registry entries behind the rendered buttons
let _dxStarting = false;

function dx_el(id) { return document.getElementById(id); }

function dx_store(key, value) {
  try {
    if (value === null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, value);
  } catch (e) { /* storage blocked: the tab just won't survive a reload */ }
}

function dx_stored(key) {
  try { return sessionStorage.getItem(key); } catch (e) { return null; }
}

function dx_noask() { return dx_stored("dx_noask") === "1"; }

function dx_setNoAsk(on) { dx_store("dx_noask", on ? "1" : null); }

function dx_show(id, on) {
  const e = dx_el(id);
  if (e) e.style.display = on ? "" : "none";
}

function dx_say(text) {
  const e = dx_el("dx-msg");
  if (!e) return;
  e.innerHTML = escHtml(text);
  e.style.display = text ? "" : "none";
}

function dx_load() {
  dx_loadClasses();
  dx_loadHistory();
  // A reload (or a trip to another tab and back) must not strand a preview
  // that is waiting on an answer: pick the stored session up again.
  const sid = dx_stored("dx_sid");
  if (sid && sid !== _dxSid) {
    _dxSid = sid;
    _dxPollFails = 0;
    dx_poll(sid);
  }
}

async function dx_loadClasses() {
  if (_dxClasses) return _dxClasses;
  try {
    const r = await fetch("/api/diagnose/classes");
    const list = await r.json();
    _dxClasses = Array.isArray(list) ? list : [];
  } catch (e) {
    console.error("dx: classes fetch failed", e);
    return [];
  }
  const sel = dx_el("dx-class");
  if (sel) {
    sel.innerHTML = '<option value="">Choose one&hellip;</option>' +
      _dxClasses.map(c => `<option value="${escHtml(c.key)}">${escHtml(c.label)}</option>`).join("");
    // Only ask for a detail once a class that uses it is picked.
    sel.addEventListener("change", () => {
      dx_show("dx-host-row", dx_classNeedsHost(sel.value));
      dx_show("dx-app-row", dx_classHasOptional(sel.value, "app_name"));
      dx_show("dx-drive-row", dx_classHasOptional(sel.value, "drive"));
    });
  }
  return _dxClasses;
}

function dx_classHasOptional(key, slot) {
  const c = (_dxClasses || []).find(x => x.key === key);
  return !!(c && Array.isArray(c.optional_slots) && c.optional_slots.includes(slot));
}

function dx_classNeedsHost(key) {
  const c = (_dxClasses || []).find(x => x.key === key);
  return !!(c && Array.isArray(c.slots) && c.slots.includes("target_host"));
}

// What to say when the engine could not place the symptom. It must name what
// Diagnose CAN look into: "Pick one below" over a one-item list (network only)
// asked a user reporting a crash to name a website. Built with DOM nodes and
// textContent so the class labels can't inject markup.
function dx_fillUnclassified(box, classes) {
  while (box.firstChild) box.removeChild(box.firstChild);
  const add = (tag, txt) => { const n = document.createElement(tag); n.textContent = txt; box.appendChild(n); return n; };
  if (!classes.length) {
    // The classes fetch failed; don't claim Diagnose covers nothing.
    box.textContent = "I couldn't load the list of problems Diagnose can check. Try again in a moment.";
    return;
  }
  box.appendChild(document.createTextNode("This doesn't look like a problem Diagnose can check yet. It currently covers: "));
  add("b", classes.map(c => c.label).join(", "));
  box.appendChild(document.createTextNode(". If it is one of those, pick it below."));
  // The crash pointer is only true while no crash class exists. The planned
  // crash bundle (backlog #63 PR 2) registers as "crashes", which retires it.
  if (classes.some(c => c.key === "crashes")) return;
  box.appendChild(document.createElement("br"));
  box.appendChild(document.createTextNode("For a crash, freeze or unexpected restart, look at the "));
  const link = (page, txt) => {
    const b = add("button", txt);
    b.type = "button";
    b.className = "dx-link";
    b.dataset.goto = page;
    b.addEventListener("click", () => {
      const tab = document.querySelector(`[data-page="${page}"]`);
      if (tab) tab.click();
    });
  };
  link("bsod", "Blue Screens");
  box.appendChild(document.createTextNode(" and "));
  link("events", "Event Log");
  box.appendChild(document.createTextNode(" tabs."));
}

async function dx_loadHistory() {
  try {
    const r = await fetch("/api/diagnose/history");
    const list = await r.json();
    dx_renderHistory(Array.isArray(list) ? list : []);
  } catch (e) {
    console.error("dx: history fetch failed", e);
    dx_renderHistory([]);
  }
}

// Forget the session being followed (terminal state, or it no longer exists).
function dx_forget() {
  if (_dxPollTimer) { clearTimeout(_dxPollTimer); _dxPollTimer = null; }
  _dxSid = null;
  _dxPollFails = 0;
  dx_store("dx_sid", null);
}

function dx_resetView() {
  dx_say("");
  dx_show("dx-progress", false);
  dx_show("dx-preview", false);
  dx_show("dx-result", false);
  dx_show("dx-evidence", false);
  // A new diagnosis starts collapsed; dx_renderResult re-opens it where needed.
  const ev = dx_el("dx-evidence");
  if (ev) ev.open = false;
  _dxPreviewKey = null;
  _dxAutoKey = null;
}

// The slots the engine asked for. Only the rows that are needed are shown.
async function dx_showAsk(res) {
  const need = Array.isArray(res.need) ? res.need : [];
  const wantClass = need.includes("symptom_class");
  const wantHost = need.includes("target_host");
  const classes = wantClass ? await dx_loadClasses() : [];
  const ask = dx_el("dx-ask");
  if (ask) {
    if (wantClass) dx_fillUnclassified(ask, classes);
    else ask.textContent = "Which site or host is affected? I won't guess; name it below.";
    ask.style.display = "";
  }
  dx_show("dx-class-row", wantClass);
  // When the class is unknown the site box waits until a class needing one is picked.
  const sel = dx_el("dx-class");
  dx_show("dx-host-row", wantHost || (wantClass && !!sel && dx_classNeedsHost(sel.value)));
  dx_show("dx-app-row", wantClass && !!sel && dx_classHasOptional(sel.value, "app_name"));
  dx_show("dx-drive-row", wantClass && !!sel && dx_classHasOptional(sel.value, "drive"));
  const chips = dx_el("dx-candidates");
  if (chips) {
    const cands = Array.isArray(res.candidates) ? res.candidates : [];
    chips.innerHTML = cands.map(c =>
      `<button type="button" class="dx-chip" data-host="${escHtml(c)}">${escHtml(c)}</button>`).join("");
    chips.querySelectorAll(".dx-chip").forEach(b => b.addEventListener("click", () => {
      const host = dx_el("dx-host");
      host.value = b.dataset.host;
      host.focus();
    }));
  }
}

function dx_clearAsk() {
  dx_show("dx-ask", false);
  dx_show("dx-class-row", false);
  dx_show("dx-host-row", false);
  dx_show("dx-app-row", false);
  const host = dx_el("dx-host");
  if (host) host.value = "";
  const appBox = dx_el("dx-app");
  if (appBox) appBox.value = "";
  const sel = dx_el("dx-class");
  if (sel) sel.value = "";
  const chips = dx_el("dx-candidates");
  if (chips) chips.innerHTML = "";
}

async function dx_start() {
  if (_dxStarting) return;
  const symptom = (dx_el("dx-symptom").value || "").trim();
  if (!symptom) { dx_say("Describe the problem first."); return; }
  const body = {symptom};
  // Omit what is empty: the server must never see "" or null for a slot.
  const host = (dx_el("dx-host").value || "").trim();
  if (host) body.slots = {target_host: host};
  // The optional app name is sent only while its box is showing.
  const appRow = dx_el("dx-app-row");
  const appName = (dx_el("dx-app").value || "").trim();
  if (appName && appRow && appRow.style.display !== "none") body.slots = {...(body.slots || {}), app_name: appName};
  // Likewise the optional drive, only while the storage class's box is showing.
  const driveRow = dx_el("dx-drive-row");
  const drive = (dx_el("dx-drive").value || "").trim();
  if (drive && driveRow && driveRow.style.display !== "none") body.slots = {...(body.slots || {}), drive};
  const classRow = dx_el("dx-class-row");
  const cls = dx_el("dx-class").value;
  if (cls && classRow && classRow.style.display !== "none") body.symptom_class = cls;

  _dxStarting = true;
  dx_el("dx-run").disabled = true;
  // The session being followed is replaced only once a new session_id
  // arrives: a 429 or an awaiting_slots answer must not strand a parked preview.
  dx_say("");
  try {
    const r = await fetch("/api/diagnose/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    let d = {};
    try { d = await r.json(); } catch (e) { d = {}; }
    if (r.status === 429) {
      dx_say("Two diagnoses are already running; wait for one to finish.");
    } else if (r.status === 400) {
      dx_say(d.error || "That request was not accepted.");
    } else if (!r.ok || !d.ok) {
      dx_say(d.error || ("Could not start the diagnosis (HTTP " + r.status + ")."));
    } else if (d.state === "awaiting_slots") {
      await dx_showAsk(d);
    } else if (d.session_id) {
      dx_forget();
      dx_resetView();
      dx_clearAsk();
      _dxSid = d.session_id;
      dx_store("dx_sid", d.session_id);
      dx_poll(d.session_id);
    }
  } catch (e) {
    dx_say("Could not reach the app: " + e.message);
  } finally {
    _dxStarting = false;
    dx_el("dx-run").disabled = false;
  }
}

function dx_progressText(status) {
  if (status.state === "interpreting") return "Waiting for the AI to read the results…";
  if (status.round > 0) return "Running the extra checks the AI asked for (round " + status.round + ")…";
  return "Running read-only checks on this PC…";
}

async function dx_poll(sid) {
  if (_dxPollTimer) { clearTimeout(_dxPollTimer); _dxPollTimer = null; }
  if (sid !== _dxSid) return;
  let status = null;
  let http = 0;
  try {
    const r = await fetch("/api/diagnose/status/" + encodeURIComponent(sid));
    http = r.status;
    status = await r.json();
  } catch (e) {
    status = null;
  }
  if (sid !== _dxSid) return;   // a newer diagnosis took over while we waited
  if (http === 404 || http === 400) {
    dx_forget();
    dx_show("dx-progress", false);
    dx_show("dx-preview", false);
    dx_say("That diagnosis is no longer available (the app may have restarted). Run it again.");
    return;
  }
  if (!status || !status.ok) {
    _dxPollFails += 1;
    if (_dxPollFails >= _DX_MAX_POLL_FAILS) {
      dx_forget();
      dx_show("dx-progress", false);
      dx_say("Lost contact with the app while the diagnosis was running.");
      return;
    }
    _dxPollTimer = setTimeout(() => dx_poll(sid), _DX_POLL_MS);
    return;
  }
  _dxPollFails = 0;

  if (_DX_TERMINAL.includes(status.state)) {
    dx_forget();
    dx_show("dx-progress", false);
    dx_show("dx-preview", false);
    dx_renderResult(status);
    dx_loadHistory();
    return;
  }

  if (status.state === "awaiting_consent" && status.preview) {
    dx_show("dx-progress", false);
    const key = sid + ":" + status.round;
    if (_dxPreviewKey !== key) {
      _dxPreviewKey = key;
      dx_renderPreview(status.preview);
      // "Don't ask again": the text is shown now and answered on the next
      // poll, so there is always one cycle where the user can see it.
      if (dx_noask()) _dxAutoKey = key;
    } else if (_dxAutoKey === key && dx_noask() && _dxAnsweredKey !== key) {
      dx_consent(true);
    }
  } else if (status.state !== "awaiting_consent") {
    dx_show("dx-preview", false);
    const prog = dx_el("dx-progress");
    prog.innerHTML = '<span class="dx-spin"></span>' + escHtml(dx_progressText(status));
    prog.style.display = "";
    dx_renderEvidence(status.evidence, false);
  }
  _dxPollTimer = setTimeout(() => dx_poll(sid), _DX_POLL_MS);
}

function dx_renderPreview(text) {
  dx_el("dx-preview-text").innerHTML = escHtml(text);
  dx_el("dx-noask").checked = dx_noask();
  dx_show("dx-preview", true);
}

async function dx_consent(approved) {
  const sid = _dxSid;
  if (!sid || !_dxPreviewKey || _dxAnsweredKey === _dxPreviewKey) return;
  const key = _dxPreviewKey;
  _dxAnsweredKey = key;
  const shown = dx_el("dx-preview-text").textContent;
  dx_show("dx-preview", false);
  const body = {session_id: sid, approved: approved === true, auto_followups: approved === true && dx_noask()};
  try {
    const r = await fetch("/api/diagnose/consent", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    if (!r.ok && r.status !== 409) {
      // 409 = already answered / not waiting: the poll shows the truth.
      // Anything else means the answer didn't land, so let the user retry.
      _dxAnsweredKey = null;
      dx_renderPreview(shown);
      dx_say("Could not record your answer (HTTP " + r.status + "). Try again.");
    }
  } catch (e) {
    _dxAnsweredKey = null;
    dx_renderPreview(shown);
    dx_say("Could not reach the app: " + e.message);
  }
}

// ── Rendering (pure: status object in, DOM out) ────────────────────────────
function dx_renderEvidence(evidence, open) {
  const box = dx_el("dx-evidence");
  const list = Array.isArray(evidence) ? evidence : [];
  if (!list.length) { box.style.display = "none"; return; }
  dx_el("dx-evidence-summary").innerHTML = escHtml("Evidence (" + list.length + (list.length === 1 ? " check)" : " checks)"));
  dx_el("dx-evidence-body").innerHTML = list.map(ev => {
    const ok = ev.ok === true;
    const ms = Math.round(Number(ev.elapsed_ms) || 0);
    const detail = ok
      ? `<pre>${escHtml(JSON.stringify(ev.data, null, 2))}</pre>`
      : `<div class="dx-ev-err">${escHtml(ev.error || "failed")}</div>`;
    return `<div class="dx-ev" data-key="${escHtml(ev.key)}">
      <div class="dx-ev-head"><b>${escHtml(ev.label || ev.key)}</b>
        <span class="${ok ? "dx-ev-ok" : "dx-ev-bad"}">${ok ? "ok" : "failed"}</span>
        <span class="dx-ev-ms">${ms} ms</span></div>${detail}</div>`;
  }).join("");
  box.style.display = "";
  if (open) box.open = true;
}

function dx_verdictHtml(v, status) {
  const label = v.source === "rules" ? "Rule-based finding" : "AI verdict";
  const conf = v.status === "confident" ? "Confident" : "Likely";
  const locus = _DX_LOCUS[v.locus] || _DX_LOCUS.unknown;
  const refs = (Array.isArray(v.evidence_refs) ? v.evidence_refs : [])
    .map(k => `<span class="dx-ref">${escHtml(k)}</span>`).join("");
  let html = `<div class="dx-verdict" data-locus="${escHtml(v.locus)}">
    <div class="dx-verdict-tags"><span class="dx-tag">${escHtml(label)}</span>
      <span class="dx-tag dx-tag-${escHtml(v.status)}">${escHtml(conf)}</span>
      <span class="dx-tag dx-tag-locus">${escHtml(locus)}</span></div>
    <div class="dx-headline">${escHtml(v.headline)}</div>
    <div class="dx-reasoning">${escHtml(v.reasoning)}</div>`;
  if (v.overridden_model_locus) {
    html += `<div class="dx-note">${escHtml("The AI suggested a different cause (" + v.overridden_model_locus + "); the DNS measurements show otherwise, so the measured finding is shown.")}</div>`;
  }
  if (v.locus === "external_cause") {
    html += `<div class="dx-nofix"><b>Nothing to fix on this PC</b>
      <div>${escHtml(v.no_local_fix_reason)}</div></div>`;
  } else if (Array.isArray(status.actions) && status.actions.length) {
    html += '<div class="dx-actions-title">Suggested fixes (nothing runs until you confirm)</div><div class="dx-actions">' +
      status.actions.map(a => `<button type="button" class="dx-action" data-action="${escHtml(a.id)}"
        title="${escHtml(a.description)}">${escHtml(a.icon)} ${escHtml(a.label)}
        <span class="dx-risk dx-risk-${escHtml(a.risk)}">${escHtml(a.risk)} risk</span></button>`).join("") +
      '</div><div id="dx-action-msg" class="dx-msg" style="display:none"></div>';
  }
  html += dx_stepsHtml(v);
  if (refs) html += `<div class="dx-refs">Based on: ${refs}</div>`;
  return html + "</div>";
}

// "Steps you can take": advice text only. Unlike the fix buttons above,
// nothing here runs; the user follows the steps themselves.
function dx_stepsHtml(v) {
  const steps = v && Array.isArray(v.manual_steps) ? v.manual_steps.filter(s => typeof s === "string" && s) : [];
  if (!steps.length) return "";
  return `<div class="dx-steps" data-dx-steps="${steps.length}"><div class="dx-steps-title">Steps you can take</div>
    <ol>${steps.map(s => `<li>${escHtml(s)}</li>`).join("")}</ol></div>`;
}

function dx_renderResult(status) {
  const box = dx_el("dx-result");
  const state = status.state;
  // evidence_only shows the deterministic rule finding; done shows the verdict.
  const v = state === "done" ? status.verdict : status.rule_verdict;
  const conclusive = !!v && (v.status === "confident" || v.status === "likely");
  // A conclusive external_cause must never offer a fix, whatever the server sent.
  _dxActions = conclusive && v.locus !== "external_cause" && Array.isArray(status.actions) ? status.actions : [];
  let html = "";
  // With no AI verdict the evidence is the main content, so show it open.
  let evidenceOpen = state === "evidence_only";

  if (state === "error") {
    html = `<div class="dx-error">${escHtml(status.error || "The diagnosis failed.")}</div>`;
  } else {
    if (state === "evidence_only") {
      const why = _DX_BANNERS[status.reason] || "No AI verdict was produced.";
      html += `<div class="dx-evidence-only">${escHtml(why)}</div>`;
    }
    if (conclusive) {
      html += dx_verdictHtml(v, {actions: _dxActions});
    } else if (state === "done") {
      evidenceOpen = true;
      html += `<div class="dx-inconclusive"><div class="dx-headline">Couldn't determine this</div>
        <div class="dx-reasoning">${escHtml(v && v.reasoning ? v.reasoning : "The checks did not point to a single cause.")}</div>
        ${dx_stepsHtml(v)}
        <div class="dx-sub">The evidence is below. Nothing was changed on this PC.</div></div>`;
    }
  }

  box.innerHTML = html;
  box.dataset.state = state || "";
  box.dataset.status = v && v.status ? v.status : "";
  box.dataset.locus = v && v.locus ? v.locus : "";
  box.style.display = "";
  box.querySelectorAll("button[data-action]").forEach(b =>
    b.addEventListener("click", () => dx_runAction(b.dataset.action)));
  dx_renderEvidence(status.evidence, evidenceOpen);
}

async function dx_runAction(key) {
  const a = _dxActions.find(x => x.id === key);
  if (!a) return;
  const reboot = a.reboot ? "\n\nThis action REQUIRES a reboot to take full effect." : "";
  if (!confirm("Run: " + a.label + "\n\nRisk level: " + String(a.risk).toUpperCase() + "\n" + a.description + reboot + "\n\nProceed?")) return;
  const out = dx_el("dx-action-msg");
  const say = (text) => { if (out) { out.innerHTML = escHtml(text); out.style.display = ""; } };
  document.querySelectorAll("#dx-result button[data-action]").forEach(b => { b.disabled = true; });
  try {
    const r = await fetch("/api/remediation/run", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action_id: key}),
    });
    const d = await r.json();
    say(a.label + (d.ok ? ": " : " failed: ") + (d.message || ""));
  } catch (e) {
    say("Error running " + a.label + ": " + e.message);
  } finally {
    document.querySelectorAll("#dx-result button[data-action]").forEach(b => { b.disabled = false; });
  }
}

function dx_renderHistory(list) {
  const box = dx_el("dx-history");
  const rows = (Array.isArray(list) ? list : []).slice(0, 10);
  if (!rows.length) {
    box.innerHTML = '<div class="dx-sub">No diagnoses yet.</div>';
    return;
  }
  box.innerHTML = rows.map((e, i) => {
    const v = e.verdict || {};
    const when = e.ts ? new Date(e.ts).toLocaleString() : "";
    const outcome = e.state === "done" ? (v.locus || "done") : (e.state || "") + (e.reason ? " / " + e.reason : "");
    const headline = v.headline || (e.symptom || "");
    const sent = Array.isArray(e.sent) ? e.sent : [];
    const sentHtml = sent.length
      ? sent.map(t => `<pre>${escHtml(t)}</pre>`).join("")
      : '<div class="dx-sub">Nothing was sent off this PC.</div>';
    return `<div class="dx-hist" data-idx="${i}">
      <button type="button" class="dx-hist-head" aria-expanded="false">
        <span class="dx-hist-when">${escHtml(when)}</span>
        <span class="dx-hist-host">${escHtml(e.target_host || "—")}</span>
        <span class="dx-hist-state">${escHtml(outcome)}</span>
        <span class="dx-hist-headline">${escHtml(headline)}</span>
      </button>
      <div class="dx-hist-body" style="display:none">
        <div class="dx-sub">${e.model ? "What was sent to " + escHtml(e.model) + ":" : "What was sent:"}</div>${sentHtml}
      </div></div>`;
  }).join("");
  box.querySelectorAll(".dx-hist-head").forEach(h => h.addEventListener("click", () => {
    const body = h.nextElementSibling;
    const open = body.style.display === "none";
    body.style.display = open ? "" : "none";
    h.setAttribute("aria-expanded", open ? "true" : "false");
  }));
}
