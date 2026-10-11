"""Backup tab routes -- Windows backups, File History, OneDrive -> iCloud copy.

Moved out of windesktopmgr.py verbatim (tech-debt #73). The logic lives
in backup.py and cloudcopy.py; these are the thin Flask wrappers.
"""

from flask import Blueprint, jsonify, request

backup_bp = Blueprint("backup", __name__)


# ── Backup tab (backlog #47) ─────────────────────────────────────────


@backup_bp.route("/api/backup/windows-backups")
def backup_windows_backups_route():
    """Section 1: WindowsImageBackup inventory.

    Returns the cached catalog from `backup_cache.json` (populated by
    the elevated helper in PR-2) or a `has_cache=False` placeholder if
    no scan has been run yet. PR-1 is read-only -- the cache is either
    pre-seeded manually or via the future Scan-with-UAC endpoint.
    """
    import backup

    return jsonify(backup.load_windows_backup_cache())


@backup_bp.route("/api/backup/file-history")
def backup_file_history_route():
    """Section 2: File History live state.

    Reads Config1.xml under %LOCALAPPDATA% (no elevation needed) and
    probes the configured target drive + backup-store folder + catalog
    freshness + staging area for health signals. The most common silent
    failure is "configured + enabled but the target backup-store folder
    on the target drive is missing" -- bubbles up as a critical health
    verdict.
    """
    import backup

    return jsonify(backup.get_file_history_state())


@backup_bp.route("/api/backup/summary")
def backup_summary_route():
    """Combined health summary across Sections 1 + 2.

    Used by the Backup tab's status header AND by the dashboard
    concern fan-out (so the dashboard doesn't have to parse two
    separate endpoints).
    """
    import backup

    return jsonify(backup.summarize_backup())


# ── Backup tab — elevated actions (PR-2 of #47) ─────────────────────


@backup_bp.route("/api/backup/scan", methods=["POST"])
def backup_scan_route():
    """Launch the elevated catalog scan via ShellExecuteW("runas").

    Returns ``{ok: True, session_id: "<hex>"}`` once the UAC prompt has
    been accepted and the helper is running; the UI then polls
    ``/api/backup/scan-status`` until the helper writes a result file.

    Refuses cleanly when the UAC prompt is declined or the helper can't
    be located.
    """
    import backup

    result = backup.request_elevated_action("scan_catalog", {})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@backup_bp.route("/api/backup/scan-status")
def backup_scan_status_route():
    """Poll endpoint -- returns ``{state: pending|done|missing}``."""
    import backup

    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"state": "missing", "error": "session_id required"}), 400
    return jsonify(backup.get_scan_status(session_id))


@backup_bp.route("/api/backup/scan-cleanup", methods=["POST"])
def backup_scan_cleanup_route():
    """Tray housekeeping: drop the request/result files for a finished
    session. The UI calls this after rendering the result so a future
    poll doesn't pick up stale state."""
    import backup

    data = request.get_json() or {}
    session_id = (data.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"ok": False, "error": "session_id required"}), 400
    backup.cleanup_session_files(session_id)
    return jsonify({"ok": True})


@backup_bp.route("/api/backup/delete-version", methods=["POST"])
def backup_delete_version_route():
    """Delete a specific WindowsImageBackup version via the elevated
    helper. Requires a TYPE-TO-CONFIRM body field that exactly matches
    the version_id -- mirrors the PR #22 router-reboot guard so a stray
    POST can't trigger an irreversible delete.

    Body::
        {"version_id": "05/24/2026-04:00", "confirm_token": "05/24/2026-04:00"}
    """
    import backup

    data = request.get_json() or {}
    version_id = (data.get("version_id") or "").strip()
    confirm = (data.get("confirm_token") or "").strip()
    if not version_id:
        return jsonify({"ok": False, "error": "version_id required"}), 400
    if confirm != version_id:
        return jsonify({"ok": False, "error": "confirm_token must equal version_id (defense-in-depth)"}), 400

    # Validate against the current cached catalog BEFORE we even spawn
    # the UAC prompt -- saves the user a click if the request is bad.
    cache = backup.load_windows_backup_cache()
    ok, err = backup.validate_delete_version_request(version_id, cache.get("versions") or [])
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    result = backup.request_elevated_action("delete_version", {"version_id": version_id})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@backup_bp.route("/api/backup/file-history-cleanup", methods=["POST"])
def backup_fh_cleanup_route():
    """Run ``fhmanagew.exe -cleanup <days>`` via the elevated helper.

    Body::
        {"days": 90, "confirm_token": "CLEANUP 90"}

    The confirm_token convention is the literal string "CLEANUP <days>"
    so a stray POST with default ``days=0`` (which would WIPE all but
    the newest version) can't fire without an explicit match.
    """
    import backup

    data = request.get_json() or {}
    days = data.get("days")
    # Reject bool before int() (int(True) == 1 would defeat the validator's
    # bool guard).
    if isinstance(days, bool):
        return jsonify({"ok": False, "error": "days must be an integer"}), 400
    try:
        days = int(days)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "days must be an integer"}), 400
    confirm = (data.get("confirm_token") or "").strip()
    expected = f"CLEANUP {days}"
    if confirm != expected:
        return jsonify({"ok": False, "error": f"confirm_token must equal {expected!r}"}), 400

    ok, err = backup.validate_fh_cleanup_request(days)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    result = backup.request_elevated_action("fh_cleanup", {"days": days})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@backup_bp.route("/api/backup/fh-cleanup-schedule")
def backup_fh_cleanup_schedule_status_route():
    """Status of the recurring File History auto-cleanup task (no elevation)."""
    import backup

    return jsonify({"ok": True, **backup.fh_cleanup_schedule_status()})


@backup_bp.route("/api/backup/fh-cleanup-schedule", methods=["POST"])
def backup_fh_cleanup_schedule_setup_route():
    """Register the WEEKLY auto-cleanup task (UAC prompt via schtasks).

    Body: ``{"days": 180}`` -- delete versions older than this each run.
    """
    import backup

    data = request.get_json() or {}
    days = data.get("days")
    # Reject bool BEFORE int() -- int(True) is 1, which would slip past the
    # validator's bool guard and silently schedule "-cleanup 1" (prune
    # everything older than 1 day).
    if isinstance(days, bool):
        return jsonify({"ok": False, "error": "days must be an integer"}), 400
    try:
        days = int(days)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "days must be an integer"}), 400

    ok, err = backup.validate_fh_cleanup_request(days)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    result = backup.setup_fh_cleanup_schedule(days)
    return jsonify(result), (200 if result.get("ok") else 502)


@backup_bp.route("/api/backup/fh-cleanup-schedule/remove", methods=["POST"])
def backup_fh_cleanup_schedule_remove_route():
    """Remove the recurring File History auto-cleanup task (UAC prompt)."""
    import backup

    result = backup.remove_fh_cleanup_schedule()
    return jsonify(result), (200 if result.get("ok") else 502)


@backup_bp.route("/api/backup/fh-storage")
def backup_fh_storage_route():
    """Last File History storage breakdown (cached; written by the elevated
    scan). ``has_cache=False`` until the first scan runs."""
    import backup

    return jsonify({"ok": True, **backup.load_fh_storage_cache()})


@backup_bp.route("/api/backup/fh-storage-scan", methods=["POST"])
def backup_fh_storage_scan_route():
    """Launch the elevated File History storage scan (UAC). The active store
    is ACL-restricted, so this walks the target drive elevated and caches the
    per-store / per-source size breakdown. Returns a session_id to poll like
    the other elevated actions."""
    import backup

    fh = backup.get_file_history_state()
    target = (fh.get("config") or {}).get("target") or {}
    target_url = target.get("url") or ""
    if not target_url:
        return jsonify({"ok": False, "error": "File History is not configured (no target drive)"}), 400

    result = backup.request_elevated_action(
        "fh_storage_scan",
        {"target_url": target_url, "store_rel_path": target.get("backup_store_path") or ""},
    )
    return jsonify(result), (200 if result.get("ok") else 502)


@backup_bp.route("/api/backup/actions-history")
def backup_actions_history_route():
    """Return the append-only audit log of elevated actions."""
    import backup

    return jsonify({"ok": True, "entries": backup.load_actions_history()})


# ── Backup tab Section 3 — OneDrive -> iCloud replicator (PR-1 of #46) ──


@backup_bp.route("/api/cloudcopy/rules", methods=["GET"])
def cloudcopy_get_rules_route():
    """Return the user-configured exclusion rules, or DEFAULT_RULES if
    none have been saved yet. Always shape-complete so the UI never has
    to null-check."""
    import cloudcopy

    return jsonify({"ok": True, "rules": cloudcopy.load_rules()})


@backup_bp.route("/api/cloudcopy/rules", methods=["PUT"])
def cloudcopy_put_rules_route():
    """Persist a user-edited rule set.

    Body: ``{"rules": {...}}`` -- shape must match DEFAULT_RULES.
    Returns ``{ok, error}`` -- 400 on validation failure, 500 on disk error.
    """
    import cloudcopy

    data = request.get_json() or {}
    incoming = data.get("rules")
    if not isinstance(incoming, dict):
        return jsonify({"ok": False, "error": "body must be {rules: {...}}"}), 400
    ok, err = cloudcopy.validate_rules(incoming)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    ok, err = cloudcopy.save_rules(incoming)
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


@backup_bp.route("/api/cloudcopy/preview", methods=["GET"])
def cloudcopy_preview_route():
    """Walk the OneDrive source root with the current rules and return
    counts + samples of what would be copied. Read-only -- no files
    are touched.

    Optional query params:
      sample_size: default 50, capped at 200
    """
    import cloudcopy

    try:
        sample = int(request.args.get("sample_size", "50"))
    except (TypeError, ValueError):
        sample = 50
    sample = max(1, min(sample, 200))
    return jsonify(cloudcopy.preview(sample_size=sample))


@backup_bp.route("/api/cloudcopy/history", methods=["GET"])
def cloudcopy_history_route():
    """Return past copy-session history. Empty in PR-1; PR-2's copy
    engine starts recording entries."""
    import cloudcopy

    return jsonify({"ok": True, "entries": cloudcopy.load_history()})


@backup_bp.route("/api/cloudcopy/resume-state", methods=["GET"])
def cloudcopy_resume_state_route():
    """Return the in-progress session state if a crashed session is
    detected, else ``{has_crashed: False}``. PR-2 wires this to the
    per-file commit log -- the user sees a "Resume previous run?"
    banner after a tray restart."""
    import cloudcopy

    state = cloudcopy.load_resume_state()
    active = cloudcopy.get_active_session_id()
    # If a session is currently active, the state file belongs to it
    # (not to a crashed run). Distinguish so the UI doesn't show a
    # spurious "Resume" banner during a normal in-progress copy.
    if not state or (active and active == state.get("session_id")):
        return jsonify({"ok": True, "has_crashed": False, "active_session_id": active})
    return jsonify({"ok": True, "has_crashed": True, "state": state, "active_session_id": active})


# PR-2: actual copy engine routes.


@backup_bp.route("/api/cloudcopy/run", methods=["POST"])
def cloudcopy_run_route():
    """Start a new copy session.

    Body::
        {"confirm_token": "START CLOUD COPY"}

    Type-to-confirm gate (mirrors PR #22 router-reboot pattern). The
    literal string "START CLOUD COPY" must match exactly so a stray
    POST can't trigger a long-running write operation.

    Returns ``{ok: true, session_id: "<hex>"}`` on launch, or 400/409
    with an error string on validation / concurrency failure.
    """
    import cloudcopy

    data = request.get_json() or {}
    confirm = (data.get("confirm_token") or "").strip()
    if confirm != "START CLOUD COPY":
        return jsonify({"ok": False, "error": "confirm_token must equal 'START CLOUD COPY'"}), 400
    result = cloudcopy.start_copy_session()
    if not result.get("ok"):
        # 409 Conflict for "another session is active"; 400 for everything else.
        status = 409 if "active" in (result.get("error") or "") else 400
        return jsonify(result), status
    return jsonify(result)


@backup_bp.route("/api/cloudcopy/status", methods=["GET"])
def cloudcopy_status_route():
    """Live progress for the active session (or its history row if it
    just finished)."""
    import cloudcopy

    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"state": "missing", "error": "session_id required"}), 400
    return jsonify(cloudcopy.get_status(session_id))


@backup_bp.route("/api/cloudcopy/cancel", methods=["POST"])
def cloudcopy_cancel_route():
    """Co-operative cancel of the active session. Worker drains its
    in-progress file then exits cleanly with a 'cancelled' history
    entry."""
    import cloudcopy

    data = request.get_json() or {}
    session_id = (data.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"ok": False, "error": "session_id required"}), 400
    accepted = cloudcopy.request_cancel(session_id)
    if not accepted:
        return jsonify({"ok": False, "error": "session id does not match active session"}), 404
    return jsonify({"ok": True})


@backup_bp.route("/api/cloudcopy/resume", methods=["POST"])
def cloudcopy_resume_route():
    """Continue a crashed session from its last-committed cursor. Re-
    validates source + destination + rules-hash before resuming so the
    rest of the session honours the same rule snapshot the original
    used."""
    import cloudcopy

    result = cloudcopy.resume_crashed_session()
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@backup_bp.route("/api/cloudcopy/discard-crashed", methods=["POST"])
def cloudcopy_discard_route():
    """Write a 'discarded' history entry + clear the orphan state
    file. User chose Discard on the crashed-session banner."""
    import cloudcopy

    result = cloudcopy.discard_crashed_session()
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)
