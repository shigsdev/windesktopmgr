"""Baseline tab routes -- drift detection, accept, timeline, investigate.

Moved out of windesktopmgr.py verbatim (tech-debt #73). The drift logic
itself lives in baseline.py; these are the thin Flask wrappers.
"""

import os
from datetime import timedelta

from flask import Blueprint, jsonify, request

baseline_bp = Blueprint("baseline", __name__)


# ── Baseline / drift detection (backlog #14) ────────────────────────


@baseline_bp.route("/api/baseline/drift")
def baseline_drift_route():
    """Return the current drift vs the accepted baseline.

    This is the heavy call (~5 s total: 287 ms services + 3 s schtasks +
    ~2 s startup-via-PS) and is the primary source for the Baseline UI
    tab. Records an entry in the drift history if drift > 0 AND a
    baseline exists, so recent_drift() can power a dashboard concern
    without the user having to open the tab first.
    """
    import baseline

    return jsonify(baseline.record_drift_if_any())


@baseline_bp.route("/api/baseline/snapshot")
def baseline_snapshot_route():
    """Return a live snapshot of the current state (no diff, no history)."""
    import baseline

    return jsonify({"ok": True, "snapshot": baseline.take_snapshot()})


@baseline_bp.route("/api/baseline/accept", methods=["POST"])
def baseline_accept_route():
    """Promote the current system state to the accepted baseline.

    Idempotent: re-accepting after legitimate changes (Windows Update
    installed new services, user added a startup item they like) is
    the expected way to clear drift.
    """
    import baseline

    result = baseline.accept_current_as_baseline()
    status = 200 if result.get("ok") else 500
    return jsonify(result), status


@baseline_bp.route("/api/baseline/history")
def baseline_history_route():
    """Return recent drift-detection history entries (default 24h window)."""
    import baseline

    try:
        hours = int(request.args.get("hours", "24"))
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(hours, 720))  # clamp 1h..30d
    entries = baseline.recent_drift(window=timedelta(hours=hours))
    return jsonify({"ok": True, "hours": hours, "entries": entries})


@baseline_bp.route("/api/baseline/entry-history")
def baseline_entry_history_route():
    """Return every historical drift event for a specific (category, key) pair.

    Used by the per-entry drill-down modal (2026-04-28) to show whether a
    drifted service / task / startup item has drifted before -- a
    recurring pattern often signals legit churn (Windows Update touching
    the same binary every patch Tuesday).

    Query params:
      - category: services | tasks | startup
      - key:      the entry key (full task path, service name, etc.)
      - hours:    optional cutoff (defaults to all history, capped at 30d)
    """
    import baseline

    category = (request.args.get("category") or "").lower().strip()
    key = (request.args.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category and key required"}), 400

    window: timedelta | None = None
    raw_hours = request.args.get("hours")
    if raw_hours is not None:
        try:
            hours = max(1, min(int(raw_hours), 720))
            window = timedelta(hours=hours)
        except (TypeError, ValueError):
            window = None

    events = baseline.entry_drift_history(category, key, window=window)
    return jsonify({"ok": True, "category": category, "key": key, "events": events})


# ── Baseline cluster examine + accept-all (backlog #50) ──────────────


@baseline_bp.route("/api/baseline/cluster-context", methods=["GET"])
def baseline_cluster_context_route():
    """Gather contextual signals (Windows Updates + BIOS audit) inside
    a cluster's time window. Powers the Examine modal on the cross-
    surface timeline (#44).

    Query params:
      - started_at: ISO timestamp of the cluster's first event
      - ended_at:   ISO timestamp of the cluster's last event
      - window:     seconds to expand the window on each side
                    (default 300 = 5min)
    """
    import baseline

    started_at = (request.args.get("started_at") or "").strip()
    ended_at = (request.args.get("ended_at") or "").strip()
    if not started_at or not ended_at:
        return jsonify({"ok": False, "error": "started_at and ended_at required"}), 400
    try:
        window = int(request.args.get("window", "300"))
    except (TypeError, ValueError):
        window = 300
    window = max(0, min(window, 86400))  # 0..24h
    result = baseline.gather_cluster_context(started_at, ended_at, window_seconds=window)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@baseline_bp.route("/api/baseline/accept-cluster", methods=["POST"])
def baseline_accept_cluster_route():
    """Bulk-accept every change in a cluster.

    Body::
        {
          "events": [
            {"category": "startup|services|tasks",
             "key": "...",
             "kind": "added|removed|changed",
             "current_value": {...} | null},
            ...
          ],
          "confirm_token": "ACCEPT N CHANGES"
        }

    The confirm_token must equal the literal string ``"ACCEPT <N>
    CHANGES"`` where N matches ``len(events)`` exactly. Mirrors the
    PR #22 router-reboot type-to-confirm guard so a stray POST can't
    flip a baseline by mistake.
    """
    import baseline

    data = request.get_json() or {}
    events = data.get("events")
    confirm = (data.get("confirm_token") or "").strip()
    if not isinstance(events, list):
        return jsonify({"ok": False, "error": "events list required"}), 400
    expected = f"ACCEPT {len(events)} CHANGES"
    if confirm != expected:
        return jsonify({"ok": False, "error": f"confirm_token must equal {expected!r}"}), 400
    result = baseline.accept_cluster_events(events)
    status = 200 if result.get("ok") else 207  # 207 Multi-Status when partial-success
    return jsonify(result), status


@baseline_bp.route("/api/baseline/timeline")
def baseline_timeline_route():
    """Unified cross-surface change timeline (backlog #44).

    Flattens the per-category drift history into one chronologically-sorted
    stream of change events and clusters multi-category bursts within the
    requested window. Lone events and same-category bursts stay
    ungrouped. Cluster severity scales with the number of categories
    touched — a single burst that hits startup + services + tasks is the
    canonical install / malware fingerprint.

    Query params:
      - window: seconds, default 300 (5 min). Clamped to [10, 86400].

    Response::

        {"ok": true, "window_seconds": <int>, "timeline": [<items>, ...]}

    Items are either ``{"type": "event", ...}`` or
    ``{"type": "cluster", "events": [...], "categories": [...], ...}``.
    Newest first. See ``baseline.correlate_drift_events`` for the
    exact item shape.
    """
    import baseline

    try:
        window = int(request.args.get("window", "300"))
    except (TypeError, ValueError):
        window = 300
    # Clamp: <10 s is finer than the timestamp resolution (`isoformat`
    # rounded to seconds), >24 h is pointless — anything that far apart
    # isn't correlated.
    window = max(10, min(window, 86400))
    history = baseline.load_history()
    timeline = baseline.correlate_drift_events(history, window_seconds=window)
    # Say which changes the accepted baseline already holds, so the tab
    # stops offering to accept them again (bug 2026-10-10).
    baseline.annotate_reconciled(timeline, history, baseline.load_baseline(), baseline.load_accept_watermark())
    return jsonify({"ok": True, "window_seconds": window, "timeline": timeline})


# Maps a drift category to the Windows console that edits it. No user
# input reaches the command line -- the category is validated against
# this whitelist, so there's no injection surface.
_BASELINE_CONSOLES = {
    "services": "services.msc",
    "tasks": "taskschd.msc",
    # Task Manager's Startup tab is the user-friendly way to toggle
    # startup items; msconfig is the deep-cut alternative.
    "startup": "taskmgr.exe",
}


@baseline_bp.route("/api/baseline/launch_console", methods=["POST"])
def baseline_launch_console_route():
    """Open the native Windows console for a drift category.

    Called by the "Open Task Scheduler" / "Open services.msc" / "Open
    Task Manager" buttons in the Baseline tab's remediation block. Lets
    the user jump straight from "here's what drifted" to "the place to
    fix it" without hunting through Start menu.
    """
    data = request.get_json(silent=True) or {}
    category = (data.get("category") or "").lower().strip()
    if category not in _BASELINE_CONSOLES:
        return jsonify({"ok": False, "error": f"unknown category: {category}"}), 400

    console = _BASELINE_CONSOLES[category]
    try:
        # os.startfile is the Windows shell-execute equivalent -- the right
        # tool to "open this MMC snap-in as if the user double-clicked it".
        # Services/tasks snap-ins are .msc files (MMC); taskmgr.exe is a
        # direct executable launch. Both work via startfile.
        if not hasattr(os, "startfile"):
            return jsonify({"ok": False, "error": "os.startfile unavailable (non-Windows host)"}), 500
        os.startfile(console)  # noqa: S606  # deliberate: fixed console path, no user input
        return jsonify({"ok": True, "launched": console, "category": category})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e), "launched": console}), 500


@baseline_bp.route("/api/baseline/accept_entry", methods=["POST"])
def baseline_accept_entry_route():
    """Accept a SINGLE drift entry into the baseline (not the whole snapshot).

    User feedback 2026-04-28: the existing /api/baseline/accept is all-
    or-nothing. This route takes one (category, key) pair and updates
    only that entry in the baseline, so the user can absorb individual
    changes without committing to "everything that's drifted is fine."

    Body shape: ``{"category": "services|tasks|startup", "key": "..."}``
    Returns: ``{"ok": bool, "kind": "added|removed|changed",
                "error": str|None, "baseline_timestamp": str|None}``
    """
    import baseline

    body = request.get_json(silent=True) or {}
    category = (body.get("category") or "").lower().strip()
    key = (body.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category (startup|services|tasks) and key required"}), 400

    # Optional fast-path inputs from the UI: kind ("added"|"removed"|
    # "changed") + current_value (the new dict for added/changed). When
    # provided, baseline.accept_drift_entry skips its expensive
    # take_snapshot() call and applies the change in a few ms instead
    # of the 5-30s a full snapshot takes.
    raw_kind = body.get("kind")
    kind = raw_kind.lower().strip() if isinstance(raw_kind, str) else None
    if kind not in (None, "added", "removed", "changed"):
        kind = None  # fall back to slow path on garbage rather than 400ing
    raw_value = body.get("current_value")
    current_value = raw_value if isinstance(raw_value, dict) else None

    result = baseline.accept_drift_entry(category, key, kind=kind, current_value=current_value)
    if result.get("ok"):
        return jsonify(result), 200
    err = (result.get("error") or "").lower()
    if "not found" in err:
        return jsonify(result), 404
    return jsonify(result), 500


@baseline_bp.route("/api/baseline/investigate", methods=["POST"])
def baseline_investigate_route():
    """Analyze a single drift entry to help the user decide whether to accept.

    Body shape:
        {"category": "services|tasks|startup",
         "key":      "<entry key from drift.<category>.<kind>[].key>",
         "kind":     "added|removed|changed"  (optional -- inferred from drift state)}

    Returns:
        {"ok": True, "investigation": {path_safety, recent_updates, inferred_cause,
                                       recommendation, explanation, ...}}
    """
    import baseline

    body = request.get_json(silent=True) or {}
    category = (body.get("category") or "").lower().strip()
    key = (body.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category (startup|services|tasks) and key required"}), 400

    # Recompute current drift to find the entry by category + key.
    result = baseline.compute_drift()
    drift_cat = (result.get("drift") or {}).get(category) or {}
    entry = None
    for kind in ("changed", "added", "removed"):
        for e in drift_cat.get(kind) or []:
            if e.get("key") == key:
                entry = e
                break
        if entry:
            break

    if not entry:
        return (
            jsonify({"ok": False, "error": f"no current drift entry for category={category} key={key}"}),
            404,
        )

    investigation = baseline.investigate_drift_entry(category, entry)
    return jsonify({"ok": True, "investigation": investigation})
