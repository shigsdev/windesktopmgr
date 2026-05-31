"""System change-timeline for WinDesktopMgr (#54 PR I).

get_system_timeline() correlates events from multiple sources into one
chronological timeline: BSODs (Event Log 41/1001/6008 + health reports),
Windows Updates, driver installs, service state changes (7036), reboots
(6013), credential-failure events (4625/4648). _correlate_crashes_with_updates
links each crash to a recent update within a time window (via
_get_update_domain / _get_crash_domain heuristics). summarize_timeline()
folds the timeline into the dashboard insight/action shape.

The shared event-log query helpers (_query_event_log_xpath, _build_evt_xpath),
get_update_history, and parse_event live in windesktopmgr.py and are
lazy-imported inside get_system_timeline (breaks the import cycle + keeps
the windesktopmgr-namespace test patches effective). The Flask route,
/api/selftest globals() lookup, get_summary dispatch, and NLQ dispatch
call the re-exported bindings.

_insight / _parse_ts are duplicated locally (disk.py / bsod.py precedent).
"""

import re
from datetime import datetime, timedelta, timezone


def _parse_ts(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _insight(level: str, text: str, action: str = "") -> dict:
    return {"level": level, "text": text, "action": action}


# ─── Crash correlation domain mappings ────────────────────────────────────────
# Stop codes that are inherently driver-related
DRIVER_RELATED_STOP_CODES = {
    "VIDEO_TDR_FAILURE",
    "VIDEO_TDR_TIMEOUT_DETECTED",
    "VIDEO_SCHEDULER_INTERNAL_ERROR",
    "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "DRIVER_POWER_STATE_FAILURE",
    "DRIVER_OVERRAN_STACK_BUFFER",
    "THREAD_STUCK_IN_DEVICE_DRIVER",
    "KMODE_EXCEPTION_NOT_HANDLED",
    "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "IRQL_NOT_LESS_OR_EQUAL",
    "WDF_VIOLATION",
    "NDIS_INTERNAL_ERROR",
}

# Map faulty .sys file to a broad domain for semantic matching
_DRIVER_DOMAIN = {
    "nvlddmkm.sys": "nvidia",
    "nvwgf2umx.sys": "nvidia",
    "dxgmms2.sys": "gpu",
    "atikmdag.sys": "amd_gpu",
    "igdkmd64.sys": "intel_gpu",
    "tcpip.sys": "network",
    "ndis.sys": "network",
    "e1d65x64.sys": "network",
    "intelppm.sys": "intel_cpu",
    "storport.sys": "storage",
    "iastora.sys": "storage",
    "hidclass.sys": "usb",
    "wdf01000.sys": "usb",
    "klif.sys": "security",
    "mfehidk.sys": "security",
    "aswsnx.sys": "security",
}

# Extract a domain from update title keywords
_UPDATE_DOMAIN_KEYWORDS = {
    "nvidia": "nvidia",
    "geforce": "nvidia",
    "radeon": "amd_gpu",
    "amd": "amd_gpu",
    "intel": "intel_cpu",
    "realtek": "network",
    "network": "network",
    "wi-fi": "network",
    "usb": "usb",
    "storage": "storage",
    "nvme": "storage",
    "defender": "security",
    "mcafee": "security",
}


def get_system_timeline(days: int = 30) -> list:
    """
    Correlate events from multiple sources into a single chronological timeline.
    Sources: BSODs (Event Log + health reports), Windows Updates, driver installs,
             service state changes (Event Log 7036), system reboots (Event Log 6013).
    """
    # Shared event-log + Windows-Update + bsod-parse helpers live in
    # windesktopmgr; lazy-import here to break the cycle and keep
    # mocker.patch("windesktopmgr.X") effective (#54 PR I).
    from windesktopmgr import (
        _build_evt_xpath,
        _query_event_log_xpath,
        get_update_history,
        parse_event,
    )

    events = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # ── 1. BSODs from Event Log ───────────────────────────────────────────────
    try:
        raw_bsod = _query_event_log_xpath(
            "System",
            _build_evt_xpath(ids=[41, 1001, 6008]),
            max_events=300,  # 100 per ID × 3 IDs, matching the legacy PS loop cap
            timeout_s=20.0,
        )
        bsod_evts = [
            {
                "EventId": e["Id"],
                "TimeCreated": e["TimeCreated"],
                "Message": (e["Message"] or "")[:200],
            }
            for e in raw_bsod
        ]
        for e in bsod_evts:
            ts = _parse_ts(e.get("TimeCreated", ""))
            if ts < cutoff:
                continue
            eid = e.get("EventId", 0)
            msg = e.get("Message", "")
            code = re.search(r"0x[0-9a-fA-F]{4,8}", msg)
            # Parse structured crash data for correlation
            parsed = parse_event(e)
            stop_code = parsed.get("stop_code") if parsed else None
            error_name = parsed.get("error_code", "") if parsed else ""
            faulty_drv = parsed.get("faulty_driver") if parsed else None
            events.append(
                {
                    "ts": ts.isoformat(),
                    "type": "bsod",
                    "category": "crash",
                    "title": "System Crash / Unexpected Shutdown",
                    "detail": (
                        f"Stop code: {code.group()}"
                        if code
                        else ("Kernel power loss" if eid == 41 else "Windows Error Reporting crash")
                    ),
                    "severity": "critical",
                    "icon": "💀",
                    "stop_code": stop_code,
                    "error_name": error_name,
                    "faulty_driver": faulty_drv,
                }
            )
    except Exception as e:
        print(f"[Timeline] BSOD query error: {e}")

    # ── 2. Windows Updates ────────────────────────────────────────────────────
    # Reuse get_update_history() — already an in-process win32com QueryHistory
    # (backlog #28). The old PowerShell here was a duplicate of that COM call;
    # filter the shared history to succeeded installs (ResultCode == 2).
    try:
        for u in get_update_history():
            if u.get("ResultCode") != 2:
                continue
            ts = _parse_ts(u.get("Date", ""))
            if ts < cutoff:
                continue
            title = u.get("Title", "Update")
            is_driver = any(w in title.lower() for w in ("driver", "firmware", "bios"))
            events.append(
                {
                    "ts": ts.isoformat(),
                    "type": "driver_install" if is_driver else "update",
                    "category": "update",
                    "title": title[:80],
                    "detail": u.get("KB", ""),
                    "severity": "info",
                    "icon": "🔧" if is_driver else "🔄",
                }
            )
    except Exception as e:
        print(f"[Timeline] Update query error: {e}")

    # ── 3. Service start/stop events (Event ID 7036) ─────────────────────────
    try:
        raw_svc = _query_event_log_xpath(
            "System",
            _build_evt_xpath(ids=[7036]),
            max_events=200,
            timeout_s=15.0,
        )
        svc_list = [{"Time": e["TimeCreated"], "Message": e["Message"]} for e in raw_svc]
        for s in svc_list:
            ts = _parse_ts(s.get("Time", ""))
            if ts < cutoff:
                continue
            msg = s.get("Message", "")
            # Only include security/AV/driver-related services
            if not any(
                w in msg.lower()
                for w in ("defender", "antivirus", "firewall", "driver", "update", "mcafee", "intel", "nvidia", "dell")
            ):
                continue
            events.append(
                {
                    "ts": ts.isoformat(),
                    "type": "service_change",
                    "category": "service",
                    "title": msg[:80] if msg else "Service state change",
                    "detail": "",
                    "severity": "info",
                    "icon": "⚙",
                }
            )
    except Exception as e:
        print(f"[Timeline] Service query error: {e}")

    # ── 4. System reboots (Event ID 6013 = uptime logged at boot) ────────────
    try:
        raw_boot = _query_event_log_xpath(
            "System",
            _build_evt_xpath(ids=[6013]),
            max_events=30,
            timeout_s=10.0,
        )
        boot_list = [{"Time": e["TimeCreated"], "Message": e["Message"]} for e in raw_boot]
        for b in boot_list:
            ts = _parse_ts(b.get("Time", ""))
            if ts < cutoff:
                continue
            events.append(
                {
                    "ts": ts.isoformat(),
                    "type": "reboot",
                    "category": "reboot",
                    "title": "System started / rebooted",
                    "detail": "",
                    "severity": "info",
                    "icon": "🔁",
                }
            )
    except Exception as e:
        print(f"[Timeline] Boot query error: {e}")

    # ── 5. Credential loss events (Security log 4625 failed logon, 4648 explicit cred) ──
    try:
        raw_cred = _query_event_log_xpath(
            "Security",
            _build_evt_xpath(ids=[4625, 4648]),
            max_events=100,
            timeout_s=15.0,
        )
        # Replicate legacy filter: always keep 4625, keep 4648 only if the
        # message references one of the known credential-loss signatures.
        _cred_msg_re = re.compile(
            r"SMB|network|NAS|OUTLOOK|IMAP|SMTP|MicrosoftOffice|MicrosoftEdge",
            re.IGNORECASE,
        )
        cred_evts = [
            {
                "Id": e["Id"],
                "Time": e["TimeCreated"],
                "Message": (e["Message"] or "")[:120],
            }
            for e in raw_cred
            if e["Id"] == 4625 or _cred_msg_re.search(e["Message"] or "")
        ]
        for ce in cred_evts:
            ts = _parse_ts(ce.get("Time", ""))
            if ts < cutoff:
                continue
            eid = ce.get("Id", 0)
            events.append(
                {
                    "ts": ts.isoformat(),
                    "type": "cred_failure" if eid == 4625 else "cred_use",
                    "category": "credential",
                    "title": "Credential failure / logon rejected"
                    if eid == 4625
                    else "Explicit credential use detected",
                    "detail": ce.get("Message", "")[:80],
                    "severity": "warning" if eid == 4625 else "info",
                    "icon": "🔐",
                }
            )
    except Exception as e:
        print(f"[Timeline] Cred events error: {e}")

    # ── Sort and correlate ────────────────────────────────────────────────────
    events.sort(key=lambda e: e["ts"], reverse=True)
    events = _correlate_crashes_with_updates(events)
    return events


def _get_update_domain(title: str) -> str | None:
    """Extract a domain tag from an update title (e.g. 'NVIDIA' -> 'nvidia')."""
    lower = title.lower()
    for keyword, domain in _UPDATE_DOMAIN_KEYWORDS.items():
        if keyword in lower:
            return domain
    return None


def _get_crash_domain(faulty_driver: str | None) -> str | None:
    """Map a faulty .sys file to a domain tag."""
    if not faulty_driver:
        return None
    return _DRIVER_DOMAIN.get(faulty_driver.lower())


def _correlate_crashes_with_updates(events: list) -> list:
    """Smart crash-update correlation with confidence scoring.

    Instead of naive abs(time difference), this:
    1. Only links updates BEFORE crashes (causation direction)
    2. Checks if the crash pattern is pre-existing (existed before update)
    3. Matches driver domains (e.g. NVIDIA update → nvlddmkm.sys crash)
    4. Assigns a confidence score (0-100) and classification
    """
    crashes = [e for e in events if e["type"] == "bsod"]
    updates = [e for e in events if e["type"] in ("update", "driver_install")]

    if not crashes or not updates:
        for ev in events:
            if ev["type"] in ("update", "driver_install"):
                ev["near_crash"] = False
                ev["crash_correlation"] = {"has_correlation": False}
        return events

    # Build a map of stop codes → sorted timestamps (oldest first) for pre-existing check
    code_history: dict[str, list[datetime]] = {}
    for c in crashes:
        code = c.get("error_name") or c.get("stop_code") or "UNKNOWN"
        ts = _parse_ts(c["ts"])
        code_history.setdefault(code, []).append(ts)
    for v in code_history.values():
        v.sort()

    # Score each update against crashes
    for ev in events:
        if ev["type"] not in ("update", "driver_install"):
            continue
        ev_ts = _parse_ts(ev["ts"])
        update_domain = _get_update_domain(ev.get("title", ""))
        best_score = 0
        matched_crashes = []
        reasoning = []

        for c in crashes:
            crash_ts = _parse_ts(c["ts"])
            delta_h = (crash_ts - ev_ts).total_seconds() / 3600

            # Only consider crashes AFTER the update (cause → effect)
            if delta_h <= 0 or delta_h > 24:
                continue

            score = 0
            reasons = []

            # ── Time proximity ────────────────────────────────────
            if delta_h <= 2:
                score += 30
                reasons.append(f"Crash {delta_h:.1f}h after update (very close)")
            elif delta_h <= 6:
                score += 20
                reasons.append(f"Crash {delta_h:.1f}h after update")
            else:
                score += 10
                reasons.append(f"Crash {delta_h:.1f}h after update (loose)")

            # ── Update type ───────────────────────────────────────
            if ev["type"] == "driver_install":
                score += 15
                reasons.append("Update is a driver/firmware install")

            # ── Driver-related stop code ──────────────────────────
            error_name = c.get("error_name", "")
            if error_name in DRIVER_RELATED_STOP_CODES:
                score += 10
                reasons.append(f"Stop code {error_name} is driver-related")

            # ── Domain match ──────────────────────────────────────
            crash_domain = _get_crash_domain(c.get("faulty_driver"))
            if update_domain and crash_domain and update_domain == crash_domain:
                score += 25
                reasons.append(f"Domain match: {update_domain} update → {c.get('faulty_driver', '?')} crash")

            # ── Faulty driver in update title ─────────────────────
            faulty = c.get("faulty_driver", "")
            if faulty and faulty.lower().replace(".sys", "") in ev.get("title", "").lower():
                score += 20
                reasons.append(f"Faulty driver {faulty} mentioned in update title")

            # ── Pre-existing pattern check ────────────────────────
            code_key = error_name or c.get("stop_code") or "UNKNOWN"
            code_times = code_history.get(code_key, [])
            pre_existing = [t for t in code_times if t < ev_ts]
            if pre_existing:
                score -= 20
                reasons.append(f"Same crash pattern existed before update ({len(pre_existing)} prior occurrence(s))")
            else:
                score += 15
                reasons.append("First time this crash pattern appeared after update")

            # ── Cluster bonus ─────────────────────────────────────
            post_same_code = [t for t in code_times if 0 < (t - ev_ts).total_seconds() / 3600 <= 24]
            if len(post_same_code) >= 2:
                score += 10
                reasons.append(f"{len(post_same_code)} crashes with same code within 24h")

            score = max(5, min(100, score))

            matched_crashes.append(
                {
                    "ts": c["ts"],
                    "stop_code": c.get("error_name") or c.get("stop_code", ""),
                    "faulty_driver": c.get("faulty_driver"),
                    "hours_after_update": round(delta_h, 1),
                    "confidence": score,
                }
            )
            if score > best_score:
                best_score = score
                reasoning = reasons

        # Classify
        if best_score >= 70:
            classification = "likely_cause"
        elif best_score >= 40:
            classification = "possible_cause"
        elif best_score > 0:
            classification = "coincidental"
        else:
            classification = None

        has_corr = best_score > 0 and len(matched_crashes) > 0
        ev["near_crash"] = has_corr and classification in ("likely_cause", "possible_cause")
        if has_corr and matched_crashes:
            ev["crash_gap_h"] = matched_crashes[0]["hours_after_update"]
        ev["crash_correlation"] = {
            "has_correlation": has_corr,
            "confidence": best_score if has_corr else 0,
            "classification": classification,
            "matched_crashes": sorted(matched_crashes, key=lambda x: -x["confidence"])[:5],
            "reasoning": reasoning,
        }

    # Ensure non-update events have the field
    for ev in events:
        if "crash_correlation" not in ev:
            ev["crash_correlation"] = {"has_correlation": False}
        if "near_crash" not in ev:
            ev["near_crash"] = False

    return events


def summarize_timeline(events: list) -> dict:
    if not events:
        return {"status": "ok", "headline": "No timeline events found.", "insights": [], "actions": []}
    insights, actions = [], []
    crashes = [e for e in events if e["type"] == "bsod"]
    updates = [e for e in events if e["type"] in ("update", "driver_install")]
    cred_fails = [e for e in events if e["type"] == "cred_failure"]

    # Confidence-based correlation groups
    correlated = [e for e in updates if e.get("crash_correlation", {}).get("has_correlation")]
    likely = [e for e in correlated if e["crash_correlation"]["classification"] == "likely_cause"]
    possible = [e for e in correlated if e["crash_correlation"]["classification"] == "possible_cause"]

    if likely:
        for u in likely[:3]:
            corr = u["crash_correlation"]
            top_crash = corr["matched_crashes"][0] if corr["matched_crashes"] else {}
            stop = top_crash.get("stop_code", "unknown crash")
            gap = top_crash.get("hours_after_update", "?")
            insights.append(
                _insight(
                    "critical",
                    f"{u['title'][:50]} → {stop} {gap}h later (confidence {corr['confidence']}%).",
                    corr["reasoning"][0] if corr["reasoning"] else "Consider rolling back this update.",
                )
            )
        actions.append("Review and consider rolling back flagged updates")
    if possible:
        titles = ", ".join(e["title"][:35] for e in possible[:2])
        insights.append(
            _insight(
                "warning",
                f"{len(possible)} update(s) with suspicious crash timing: {titles}.",
                "Investigate these updates — they may or may not be related.",
            )
        )
    if crashes:
        insights.append(
            _insight("warning" if len(crashes) < 5 else "critical", f"{len(crashes)} crash(es) in the selected period.")
        )
    driver_installs = [e for e in events if e["type"] == "driver_install"]
    if driver_installs:
        insights.append(_insight("info", f"{len(driver_installs)} driver/firmware change(s) in the period."))
    if cred_fails:
        insights.append(
            _insight(
                "warning",
                f"{len(cred_fails)} credential failure event(s) detected. "
                "These may relate to Outlook disconnections and SMB drive loss after reboot.",
                "Check the Credentials & Network Health tab for diagnosis.",
            )
        )
    if not crashes and not likely and not possible:
        insights.append(_insight("ok", "No crashes detected and no suspicious update timing."))
    status = "critical" if likely else "warning" if (possible or crashes) else "ok"
    headline = (
        f"{len(likely)} update(s) likely caused crashes!"
        if likely
        else f"{len(possible)} update(s) may be related to crashes"
        if possible
        else f"{len(crashes)} crash(es), {len(updates)} update(s) in period"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}
