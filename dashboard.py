"""Dashboard concerns aggregation for WinDesktopMgr (backlog #54 PR E).

Fans out across every health collector (thermals, memory, BIOS,
credentials, disk, drivers, GPU, network) plus best-effort cross-surface
signals (alerts, scheduled-task health, baseline drift, backup health,
BIOS audit trail, router-config staleness) and folds them into a single
ranked ``concerns`` list for the dashboard card.

Caching: the synchronous fan-out (~seconds) is computed once and cached
for ``_DASHBOARD_CACHE_TTL``. Within the window the cached payload is
served instantly; once stale, the cached payload is still served while a
single-flight background thread recomputes (see
``_trigger_dashboard_refresh_async``). The Flask route lives in
windesktopmgr.py and calls these helpers via the re-exported bindings.

The 8 primary collectors are resolved from the ``windesktopmgr`` namespace
at call time (lazy import inside ``_compute_dashboard_summary``) -- this
both breaks the import cycle and keeps ``mocker.patch("windesktopmgr.X")``
effective for the dashboard route tests.

Exception: the per-process memory-snooze cross-check reaches DIRECTLY into
the ``processes`` module (``processes._load_memory_snoozes()``,
``processes.MEM_CRIT_MB``, ``processes.SAFE_PROCESSES``) via the top-level
``import processes`` -- NOT through the windesktopmgr namespace. Tests that
need to stub those must patch ``processes.X``, not ``windesktopmgr.X``.
"""

import json
import threading
from datetime import datetime, timedelta, timezone

import processes

# ── Dashboard summary cache ──────────────────────────────────────────────────
# Caching rationale (moved verbatim from windesktopmgr.py): the TTL is
# short (30 s) -- long enough that a dashboard refresh click, a tray
# status poll, and a Playwright smoke pass during the same window all
# share one computation; short enough that truly new state (e.g. a
# remediation action that just ran) is visible on the next refresh.
_dashboard_state: dict = {"data": None, "ts": None}
_dashboard_cache_lock = threading.Lock()
_dashboard_refresh_lock = threading.Lock()
_DASHBOARD_CACHE_TTL = timedelta(seconds=30)


def _build_gauges(results: dict) -> list:
    """Compact radial-gauge readouts for the dashboard hero row.

    Built from the fan-out ``results`` (no extra collection). Each gauge is
    ``{key, label, value, unit, max, kind, sub}`` where ``value`` is a number
    or ``None`` -- ``None`` renders as an unavailable ("—") gauge so a missing
    sensor (no CPU thermal provider) or absent GPU degrades gracefully rather
    than showing a bogus 0. ``kind`` drives the frontend colour thresholds
    (temp/load/util/mem). Defensive against collector error dicts.
    """

    def _num(v):
        return v if isinstance(v, int | float) and not isinstance(v, bool) else None

    therm = results.get("thermals") if isinstance(results.get("thermals"), dict) else {}
    perf = therm.get("perf") if isinstance(therm.get("perf"), dict) else {}
    temps = therm.get("temps") if isinstance(therm.get("temps"), list) else []
    gpu = results.get("gpu") if isinstance(results.get("gpu"), dict) else {}

    # CPU temp: hottest CPU sensor. With LHM merged in, `temps` also carries
    # GPU/storage/board sensors, so restrict to CPU ones (by LHM SensorId
    # /intelcpu//amdcpu/, else by name) before taking the max -- otherwise a hot
    # GPU/NVMe reading would masquerade as the CPU temp. Fall back to any sensor
    # when none is identifiable (e.g. a bare WMI thermal zone).
    def _is_cpu_temp(t: dict) -> bool:
        sid = (t.get("SensorId") or "").lower()
        if sid:
            return "cpu" in sid
        return any(k in (t.get("Name") or "").lower() for k in ("cpu", "core", "package"))

    cpu_vals = [_num(t.get("TempC")) for t in temps if isinstance(t, dict) and _is_cpu_temp(t)]
    cpu_vals = [v for v in cpu_vals if v is not None]
    all_vals = [_num(t.get("TempC")) for t in temps if isinstance(t, dict)]
    all_vals = [v for v in all_vals if v is not None]
    pick = cpu_vals or all_vals
    cpu_temp = round(max(pick), 1) if pick else None

    cpu_pct = _num(perf.get("CPUPct"))
    # Memory here comes from the thermals perf snapshot (psutil), NOT the
    # dedicated `memory` collector that powers the memory concerns -- the
    # gauge just mirrors the one-shot reading the fan-out already gathered.
    mem_used = _num(perf.get("MemUsedMB")) or 0
    mem_total = _num(perf.get("MemTotalMB")) or 0
    mem_pct = round(mem_used / mem_total * 100, 1) if mem_total else None

    gpu_ok = bool(gpu.get("available"))
    gpu_temp = _num(gpu.get("temp_c")) if gpu_ok else None
    gpu_util = _num(gpu.get("utilization_pct")) if gpu_ok else None
    vram_used = _num(gpu.get("vram_used_mb")) if gpu_ok else None
    gpu_name = (gpu.get("name") or "").strip() if gpu_ok else ""

    return [
        {"key": "cpu_load", "label": "CPU Load", "value": cpu_pct, "unit": "%", "max": 100, "kind": "load", "sub": ""},
        {
            "key": "cpu_temp",
            "label": "CPU Temp",
            "value": cpu_temp,
            "unit": "°C",
            "max": 100,
            "kind": "temp",
            "sub": "" if cpu_temp is not None else "no sensor",
        },
        {
            "key": "gpu_temp",
            "label": "GPU Core",
            "value": gpu_temp,
            "unit": "°C",
            "max": 100,
            "kind": "temp",
            "sub": (gpu_name[:18] if gpu_name else "") if gpu_ok else "no GPU",
        },
        {
            "key": "gpu_util",
            "label": "GPU Util",
            "value": gpu_util,
            "unit": "%",
            "max": 100,
            "kind": "util",
            "sub": (f"{round(vram_used / 1024, 1)} GB VRAM" if (gpu_ok and vram_used) else "") if gpu_ok else "no GPU",
        },
        {
            "key": "memory",
            "label": "Memory",
            "value": mem_pct,
            "unit": "%",
            "max": 100,
            "kind": "mem",
            "sub": (f"{round(mem_used / 1024, 1)} / {round(mem_total / 1024, 1)} GB" if mem_total else ""),
        },
    ]


def _compute_dashboard_summary() -> dict:
    """Synchronous fan-out over every dashboard collector.

    Returns the full response dict (not a Flask Response) so the route
    handler and the background refresher can share one implementation.
    """
    import concurrent.futures

    # Collectors are resolved from the windesktopmgr namespace at call
    # time so existing `mocker.patch("windesktopmgr.get_*")` test hooks
    # keep intercepting the fan-out after the extraction (PR E, #54).
    import windesktopmgr as wdm

    results = {}

    def run(name, fn):
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = {"error": str(e)}

    checks = {
        "thermals": wdm.get_thermals,
        "memory": wdm.get_memory_analysis,
        "bios": wdm.get_bios_status,
        "credentials": wdm.get_credentials_network_health,
        "disk": wdm.get_disk_health,
        "drivers": wdm.get_driver_health,
        "gpu": wdm.get_gpu_metrics,
        "network": wdm.get_network_metrics,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(fn): name for name, fn in checks.items()}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=45):
                name = futs[fut]
                try:
                    results[name] = fut.result()
                except Exception as e:
                    results[name] = {"error": str(e)}
        except TimeoutError:
            # Some checks didn't finish — collect whatever did complete
            for fut, name in futs.items():
                if name not in results:
                    if fut.done():
                        try:
                            results[name] = fut.result()
                        except Exception as e:
                            results[name] = {"error": str(e)}
                    else:
                        results[name] = {"error": "timed out"}

    # ── Pull key signals from each area ──────────────────────────────────────
    concerns = []

    # Credentials / Auth
    cred = results.get("credentials", {})
    if cred.get("onedrive_suspended"):
        concerns.append(
            {
                "level": "critical",
                "tab": "credentials",
                "icon": "☁",
                "title": "OneDrive is SUSPENDED — confirmed cause of Word/Outlook sign-in errors",
                "detail": "Windows suspended OneDrive to free memory. OAuth tokens cannot refresh until it is resumed.",
                "action": "Resume OneDrive",
                "action_fn": "resumeOneDrive()",
            }
        )
    # Note: ms_account_suspended reflects McAfee's idle UWP RulesEngine task — not an auth issue
    # Only flag if it's a genuine Microsoft auth process (not McAfee AppX background tasks)
    if cred.get("msal_token_stale"):
        age = cred.get("msal_token_age_h", 0)
        concerns.append(
            {
                "level": "critical",
                "tab": "credentials",
                "icon": "🔑",
                "title": f"Microsoft 365 token expired ({age:.0f}h old)",
                "detail": "Sign in to OneDrive to refresh tokens for all Office apps.",
                "action": "View Credentials tab",
                "action_fn": "switchTab('credentials')",
            }
        )
    if cred.get("fast_startup"):
        concerns.append(
            {
                "level": "warning",
                "tab": "credentials",
                "icon": "⚡",
                "title": "Fast Startup is enabled",
                "detail": "Causes SMB credential loss and NAS disconnection on every reboot.",
                "action": "Disable Fast Startup",
                "action_fn": "fixFastStartup()",
            }
        )
    drives_down = cred.get("drives_down", [])
    if drives_down:
        concerns.append(
            {
                "level": "critical",
                "tab": "credentials",
                "icon": "💾",
                "title": f"{len(drives_down)} NAS drive(s) unreachable",
                "detail": ", ".join(f"{d.get('Name', '?')}: {d.get('DisplayRoot', '')}" for d in drives_down[:3]),
                "action": "View Credentials tab",
                "action_fn": "switchTab('credentials')",
            }
        )

    # Thermals
    therm = results.get("thermals", {})
    crit_temps = [t for t in therm.get("temps", []) if t.get("status") == "critical"]
    warn_temps = [t for t in therm.get("temps", []) if t.get("status") == "warning"]
    cpu_pct = therm.get("perf", {}).get("CPUPct", 0)
    if crit_temps:
        concerns.append(
            {
                "level": "critical",
                "tab": "thermals",
                "icon": "🌡",
                "title": f"Critical temperature: {crit_temps[0].get('TempC')}°C ({crit_temps[0].get('Name', '')})",
                "detail": "Immediate risk of thermal throttling or damage.",
                "action": "View Temps & Power",
                "action_fn": "switchTab('thermals')",
            }
        )
    elif warn_temps:
        concerns.append(
            {
                "level": "warning",
                "tab": "thermals",
                "icon": "🌡",
                "title": f"Elevated temperature: {warn_temps[0].get('TempC')}°C ({warn_temps[0].get('Name', '')})",
                "detail": "Monitor under load — may contribute to instability.",
                "action": "View Temps & Power",
                "action_fn": "switchTab('thermals')",
            }
        )
    # Hoist mem/mem_pct OUT of the try/except so downstream code (per-process
    # memory concerns loop at line ~8605) can't hit NameError if the alerts
    # block is ever refactored. Audit finding (2026-04-19 security review).
    mem = results.get("memory", {})
    mem_pct = round(mem.get("used_mb", 0) / max(mem.get("total_mb", 1), 1) * 100, 1)

    # CPU + Memory system pressure concerns now flow through alerts.py
    # (backlog #5) so the user can tune thresholds without editing code.
    # Per-drive disk percents also join the rule-driven stream.
    try:
        import alerts

        metric_points: list[alerts.MetricPoint] = []
        if cpu_pct:
            metric_points.append(alerts.MetricPoint(metric="cpu_percent", value=float(cpu_pct), label=""))
        if mem_pct:
            metric_points.append(
                alerts.MetricPoint(
                    metric="memory_percent",
                    value=float(mem_pct),
                    label=f"{mem.get('used_mb', 0):,.0f} MB used",
                )
            )
        # Per-drive disk usage (drive letters A..Z)
        for d in (results.get("disk") or {}).get("drives", []):
            pct = d.get("PctUsed") or d.get("pct_used")
            letter = d.get("Letter") or d.get("letter") or ""
            if pct is not None and letter:
                metric_points.append(alerts.MetricPoint(metric="disk_percent", value=float(pct), label=f"{letter}:"))
        concerns.extend(alerts.evaluate_rules(metric_points))
    except Exception:  # noqa: BLE001 — alerts engine is best-effort
        # Fallback to legacy hardcoded thresholds so the dashboard is never
        # silent about real pressure even if the rules engine is broken.
        if cpu_pct >= 80:
            concerns.append(
                {
                    "level": "warning",
                    "tab": "thermals",
                    "icon": "💻",
                    "title": f"CPU at {cpu_pct}% utilisation",
                    "detail": "Check Processes tab for what is driving high CPU.",
                    "action": "View Processes",
                    "action_fn": "switchTab('processes')",
                }
            )
        if mem_pct > 90:
            concerns.append(
                {
                    "level": "critical",
                    "tab": "memory",
                    "icon": "🧠",
                    "title": f"RAM at {mem_pct}% ({mem.get('used_mb', 0):,.0f} MB used)",
                    "detail": "Very little memory available — system may be unstable.",
                    "action": "View Memory Analysis",
                    "action_fn": "switchTab('memory')",
                }
            )
        # Disk fullness fallback (audit finding: previously silent in the
        # fallback path, so a broken alerts.py would stop surfacing
        # drive-full warnings). Mirrors the default disk_warning / disk_critical
        # thresholds (85 / 95 %) from alerts.DEFAULT_RULES.
        for d in (results.get("disk") or {}).get("drives", []):
            pct = d.get("PctUsed") or d.get("pct_used") or 0
            letter = d.get("Letter") or d.get("letter") or ""
            free_gb = d.get("FreeGB") or 0
            if not letter or pct < 85:
                continue
            level = "critical" if pct >= 95 else "warning"
            concerns.append(
                {
                    "level": level,
                    "tab": "disk",
                    "icon": "💾",
                    "title": f"Drive {letter} is {pct}% full ({free_gb:.1f} GB free)",
                    "detail": "Disk space is running low. Consider freeing up space.",
                    "action": "View Disk Health",
                    "action_fn": "switchTab('disk')",
                }
            )

    # Memory — per-process hogs (backlog #19). Each concern carries
    # pid/process_name/mem_mb so the frontend can render inline action
    # buttons (Kill / Investigate / Snooze 24h). Snoozed processes are
    # filtered here so the user's dismissal actually suppresses the
    # warning for the snooze window.
    try:
        snoozes = processes._load_memory_snoozes()
    except Exception:  # noqa: BLE001
        snoozes = {}
    for p in mem.get("top_procs", [])[:8]:
        name = p.get("name") or ""
        mb = p.get("mem") or 0
        pid = p.get("pid")
        if not name or mb < processes.MEM_CRIT_MB:
            continue
        if name.lower() in snoozes:
            continue
        # Skip well-known system-critical processes that have no business
        # being killed from the dashboard (kernel-adjacent, AV, etc.)
        if (name + ".exe").lower() in processes.SAFE_PROCESSES:
            continue
        concerns.append(
            {
                "level": "critical" if mb >= 2 * processes.MEM_CRIT_MB else "warning",
                "tab": "processes",
                "icon": "🧠",
                "title": f"{name} using {mb:,.0f} MB RAM",
                "detail": "High memory use. Use the actions below to investigate or kill.",
                "action": "View in Process Monitor",
                "action_fn": f"investigateProcess({int(pid) if pid else 0}, {json.dumps(name)})",
                # Extra metadata consumed by the frontend concern renderer to
                # draw Kill / Investigate / Snooze buttons:
                "process_name": name,
                "pid": int(pid) if pid else None,
                "mem_mb": mb,
            }
        )

    # BIOS
    bios = results.get("bios", {})
    if bios.get("update", {}).get("update_available"):
        latest = bios.get("update", {}).get("latest_version", "")
        concerns.append(
            {
                "level": "critical",
                "tab": "bios",
                "icon": "🔩",
                "title": f"BIOS update available: {latest}",
                "detail": "Install to get latest microcode patches for your i9-14900K.",
                "action": "View BIOS & Firmware",
                "action_fn": "switchTab('bios')",
            }
        )
    elif bios.get("update", {}).get("confirmed_current"):
        pass  # BIOS confirmed current — no concern needed

    # Scheduled-task health concerns (crashloops, stale successes, missing tasks)
    try:
        import task_watcher

        task_results = task_watcher.get_all_task_health()
        concerns.extend(task_watcher.concerns_from_health(task_results))
    except Exception:  # noqa: BLE001
        pass  # best-effort — never break dashboard

    # Baseline drift concerns (backlog #14). Reads the drift history file
    # (fast), NOT the live compute_drift() call (~5 s: too slow for the
    # dashboard fan-out). The history is appended by /api/baseline/drift
    # whenever the user opens the Baseline tab, which is also the place
    # they act on it. Concern fires at "info" level because drift is
    # often benign (Windows Update installed a service); critical only
    # if the user has explicitly marked something suspicious.
    try:
        import baseline

        # drop_accepted() excludes drift the user already reconciled via
        # "accept current as baseline" -- without it, cleared drift keeps
        # showing as open on the dashboard for up to 24h (bug 2026-06-03).
        drift_entries = baseline.drop_accepted(baseline.recent_drift())
        if drift_entries:
            latest = drift_entries[-1]
            total = latest.get("total_changes", 0)
            breakdown = latest.get("drift", {})
            parts = []
            for cat in ("startup", "services", "tasks"):
                cat_d = breakdown.get(cat) or {}
                a = len(cat_d.get("added", []))
                r = len(cat_d.get("removed", []))
                c = len(cat_d.get("changed", []))
                if a + r + c:
                    parts.append(f"{cat}: +{a}/-{r}/~{c}")
            detail = "; ".join(parts) if parts else f"{total} change(s) vs baseline"
            concerns.append(
                {
                    "level": "info",
                    "tab": "baseline",
                    "icon": "📐",
                    "title": f"System baseline drift detected ({total} change(s) in 24h)",
                    "detail": detail,
                    "action": "Review baseline drift",
                    "action_fn": "switchTab('baseline')",
                }
            )

        # Backlog #44 cross-surface correlation concern. Distinct from
        # the info-level "drift detected" concern above — that one fires
        # on ANY drift; this one fires on the security-relevant pattern
        # where the most-recent cluster touched ≥3 categories within
        # 60 s. That's the canonical install / malware fingerprint and
        # warrants warning-level attention even if the underlying drift
        # count is small.
        history_all = baseline.drop_accepted(baseline.load_history())
        alert = baseline.correlation_alert(history_all, window_seconds=60, min_categories=3)
        if alert:
            cat_label = ", ".join(alert["categories"])
            span = alert["span_seconds"]
            span_label = f"{int(span)} s" if span >= 1 else "simultaneously"
            concerns.append(
                {
                    "level": "warning",
                    "tab": "baseline",
                    "icon": "🚨",
                    "title": f"Cross-surface baseline drift cluster ({alert['event_count']} events, {span_label})",
                    "detail": f"Touched {len(alert['categories'])} categories: {cat_label}. Review the Change Timeline.",
                    "action": "Review change timeline",
                    "action_fn": "switchTab('baseline')",
                }
            )
    except Exception:  # noqa: BLE001 -- baseline is best-effort
        pass

    # Backup health concerns (backlog #47). Fires when File History is
    # configured + enabled but the target backup store is unreachable
    # (silent-failure mode that wastes the user's mental "I'm backed up"
    # reassurance) or when the WindowsImageBackup catalog is empty.
    # Best-effort: NEVER block dashboard rendering on this.
    try:
        import backup as backup_mod

        backup_summary = backup_mod.summarize_backup()
        overall = backup_summary.get("overall_health") or {}
        level = overall.get("level", "info")
        if level in ("warning", "critical"):
            fh = backup_summary.get("file_history") or {}
            wb = backup_summary.get("windows_backups") or {}
            # Detail line shows both surfaces so the user sees the full
            # picture from the concern card without opening the tab.
            fh_label = fh.get("health", {}).get("reason", "")
            wb_label = wb.get("health", {}).get("reason", "")
            detail_parts = []
            if fh_label and (fh.get("health", {}).get("level") in ("warning", "critical")):
                detail_parts.append(f"File History: {fh_label}")
            if wb_label and (wb.get("health", {}).get("level") in ("warning", "critical")):
                detail_parts.append(f"WindowsImageBackup: {wb_label}")
            concerns.append(
                {
                    "level": level,
                    "tab": "backup",
                    "icon": "📦",
                    "title": (
                        "Backup health: critical -- target unreachable or store missing"
                        if level == "critical"
                        else "Backup health: warning"
                    ),
                    "detail": " · ".join(detail_parts) or overall.get("reason", ""),
                    "action": "Review backups",
                    "action_fn": "switchTab('backup')",
                }
            )
    except Exception:  # noqa: BLE001 -- backup health is best-effort
        pass

    # BIOS audit-trail concerns: logged changes + collection errors in the last 24h
    try:
        import bios_audit

        bios_changes = bios_audit.recent_changes()
        if bios_changes:
            latest = bios_changes[-1]
            fields = [c["field"] for c in latest.get("changes", [])[:3]]
            fields_label = ", ".join(fields) if fields else "(details)"
            extra = len(latest.get("changes", [])) - 3
            if extra > 0:
                fields_label += f" (+{extra} more)"
            concerns.append(
                {
                    "level": "info",
                    "tab": "bios",
                    "icon": "📋",
                    "title": f"BIOS/firmware setting change detected ({len(bios_changes)} in 24h)",
                    "detail": f"Fields: {fields_label}",
                    "action": "View BIOS audit trail",
                    "action_fn": "switchTab('bios')",
                }
            )
        # Collection errors: PowerShell/WMI calls that failed during a
        # BIOS snapshot. Surfaced so the user sees "we couldn't read
        # field X" rather than a silent gap followed by a fake "change".
        bios_errors = bios_audit.recent_errors()
        if bios_errors:
            err_fields = sorted(
                {e.get("field", "?") for entry in bios_errors for e in entry.get("errors", []) if isinstance(e, dict)}
            )
            sample = ", ".join(err_fields[:4])
            if len(err_fields) > 4:
                sample += f" (+{len(err_fields) - 4} more)"
            concerns.append(
                {
                    "level": "warning",
                    "tab": "logs",
                    "icon": "⚠",
                    "title": f"BIOS audit collection errors ({len(bios_errors)} cycle(s) in 24h)",
                    "detail": f"Failed fields: {sample}. Open the Logs tab for PowerShell/WMI error details.",
                    "action": "View Logs",
                    "action_fn": "switchTab('logs')",
                }
            )
    except Exception:  # noqa: BLE001
        pass  # audit trail is best-effort — never break dashboard

    # Disk usage is now driven by alerts.py (backlog #5) — see the
    # per-drive points appended in the CPU/memory block above. Thresholds
    # are user-configurable via /api/alerts/rules.

    # Driver health
    drv = results.get("drivers", {})
    prob_drivers = drv.get("problematic_drivers", [])
    old_drivers = drv.get("old_drivers", [])
    nv = drv.get("nvidia")
    if prob_drivers:
        names = ", ".join(d.get("DeviceName", "?")[:30] for d in prob_drivers[:3])
        concerns.append(
            {
                "level": "critical",
                "tab": "drivers",
                "icon": "⚠",
                "title": f"{len(prob_drivers)} device(s) with driver errors",
                "detail": names,
                "action": "View Driver Manager",
                "action_fn": "switchTab('drivers')",
            }
        )
    if len(old_drivers) > 3:
        concerns.append(
            {
                "level": "info",
                "tab": "drivers",
                "icon": "📦",
                "title": f"{len(old_drivers)} third-party drivers are over 2 years old",
                "detail": "Age alone is not actionable — check Driver Manager tab for actual available updates.",
                "action": "View Driver Manager",
                "action_fn": "switchTab('drivers')",
            }
        )

    # NVIDIA GPU driver update
    if nv and nv.get("UpdateAvailable"):
        installed = nv.get("InstalledVersion", "?")
        latest = nv.get("LatestVersion", "?")
        gpu_name = nv.get("Name", "NVIDIA GPU")
        concerns.append(
            {
                "level": "warning",
                "tab": "drivers",
                "icon": "🎮",
                "title": f"NVIDIA driver update available: {installed} → {latest}",
                "detail": f"{gpu_name}. Open NVIDIA App or Windows Update to install.",
                "action": "View Driver Manager",
                "action_fn": "switchTab('drivers')",
            }
        )

    # Sort by level
    level_order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    concerns.sort(key=lambda c: level_order.get(c.get("level", "info"), 2))

    # Router config backup staleness. Both vendors require manual backups
    # via their admin Save/Restore page (Orbi RBRE960 firmware rejects the
    # documented SOAP backup endpoint; Verizon CR1000A's SPA needs browser
    # interaction). The dashboard surfaces an info-level concern when the
    # newest file in backups/<vendor>/ crosses the staleness threshold so
    # the user knows it's time to re-run the manual backup. Best-effort --
    # import failure mustn't kill the dashboard.
    try:
        from homenet import get_backup_health

        bh = get_backup_health()
        if bh.get("verizon_stale"):
            age = bh.get("verizon_age_days")
            age_msg = "never backed up" if age is None else f"{age:.0f} days old"
            concerns.append(
                {
                    "level": "info",
                    "tab": "homenet",
                    "icon": "🗄",
                    "title": f"Verizon CR1000A config backup is stale ({age_msg})",
                    "detail": (
                        f"Last backup: {age_msg}. Verizon backups are manual -- "
                        "click Backup → Verizon on the Home Network tab to open "
                        "the admin Save/Restore page, then drop the downloaded "
                        "file into backups/verizon/ to track it here."
                    ),
                    "action": "Open Home Network tab",
                    "action_fn": "switchTab('homenet')",
                }
            )
        if bh.get("orbi_stale"):
            age = bh.get("orbi_age_days")
            age_msg = "never backed up" if age is None else f"{age:.0f} days old"
            concerns.append(
                {
                    "level": "info",
                    "tab": "homenet",
                    "icon": "🗄",
                    "title": f"Orbi RBRE960 config backup is stale ({age_msg})",
                    "detail": (
                        f"Last backup: {age_msg}. Orbi backups are manual -- the "
                        "RBRE960 firmware rejects the documented SOAP endpoint, "
                        "so click Backup → Orbi on the Home Network tab to open "
                        "the admin Save/Restore page, then drop the file into "
                        "backups/orbi/."
                    ),
                    "action": "Open Home Network tab",
                    "action_fn": "switchTab('homenet')",
                }
            )
    except Exception:  # noqa: BLE001 -- never let backup-status break the dashboard
        pass

    # Orbi mesh-unknown bucket (bug 2026-05-12). When the RBRE960 firmware
    # emits corrupted ConnAPMAC values for satellite-connected clients, the
    # topology builder can't tell which Orbi node those clients belong to
    # and they all collapse into the "Orbi mesh (AP unknown)" column. The
    # parser captures a sample to ~/homenet_orbi_debug.xml so we can debug,
    # but the user needs to know WHY their satellite columns disappeared.
    # Surface as INFO when the unknown bucket dominates wireless mappings.
    #
    # NOTE 2026-05-13: removed the "Orbi reporting N wireless devices with
    # unknown AP" dashboard concern. The Orbi RBRE960 firmware emits a
    # corrupted ConnAPMAC sentinel for satellite-connected clients -- this
    # is a STATIC fact about the user's hardware, not an actionable issue.
    # Surfacing it as a dashboard concern that re-fires every poll was
    # nagging without action. Moved to the topology stats line + the
    # Unknown column subtitle where it's contextual. The raw response
    # sample at ~/homenet_orbi_debug.xml is still captured by the parser
    # on first occurrence per process for anyone investigating the
    # firmware quirk further. User feedback 2026-05-13: "I still see this
    # error... are you checking post-deploy?".

    overall = (
        "critical"
        if any(c["level"] == "critical" for c in concerns)
        else "warning"
        if any(c["level"] == "warning" for c in concerns)
        else "ok"
    )

    # Trend sampler (backlog #4). Best-effort, throttled internally to one
    # sample per SAMPLE_INTERVAL — must never break the dashboard response.
    try:
        import metrics_history

        metrics_history.record_sample(
            {
                "concerns": concerns,
                "thermals": results.get("thermals") or {},
                "memory": results.get("memory") or {},
                "disk": results.get("disk") or {},
                "gpu": results.get("gpu") or {},
                "network": results.get("network") or {},
            }
        )
    except Exception:  # noqa: BLE001
        pass

    return {
        "concerns": concerns,
        "total": len(concerns),
        "critical": sum(1 for c in concerns if c["level"] == "critical"),
        "warnings": sum(1 for c in concerns if c["level"] == "warning"),
        "overall": overall,
        "gauges": _build_gauges(results),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _trigger_dashboard_refresh_async():
    """Kick off a background cache refresh if one isn't already running.

    Single-flight: the refresh_lock is acquired non-blocking. If it's
    already held, a refresh is in progress and we don't start a second
    one -- the stale cache is served in the meantime, and the in-flight
    refresh will land shortly.
    """
    if not _dashboard_refresh_lock.acquire(blocking=False):
        return

    def _refresh():
        try:
            data = _compute_dashboard_summary()
            with _dashboard_cache_lock:
                _dashboard_state["data"] = data
                _dashboard_state["ts"] = datetime.now()
        except Exception:  # noqa: BLE001 — a refresh crash must never take the cache down
            pass
        finally:
            _dashboard_refresh_lock.release()

    threading.Thread(target=_refresh, name="DashboardRefresh", daemon=True).start()


def _dashboard_cache_clear() -> None:
    """Test hook: drop the cached summary so the next request recomputes."""
    with _dashboard_cache_lock:
        _dashboard_state["data"] = None
        _dashboard_state["ts"] = None
