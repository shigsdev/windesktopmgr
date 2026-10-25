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
import re
import threading
from datetime import datetime, timedelta, timezone

import metrics_history
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


def _cpu_core_average(cpu_temps: list, num) -> float | None:
    """Average CPU core temperature from the CPU sensor list.

    Prefers LibreHardwareMonitor's own ``Core Average`` sensor; otherwise the
    mean of per-core readings (names like ``P-Core #3`` / ``Core #3``). None
    when there are no per-core sensors (e.g. a bare WMI thermal zone), so the
    gauge doesn't present a single zone reading as an "average".
    """
    for t in cpu_temps:
        if (t.get("Name") or "").strip().lower() == "core average":
            v = num(t.get("TempC"))
            if v is not None:
                return v
    cores = [num(t.get("TempC")) for t in cpu_temps if re.search(r"\bcore #\d+\b", (t.get("Name") or "").lower())]
    cores = [v for v in cores if v is not None]
    return sum(cores) / len(cores) if cores else None


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
    # GPU/storage/board sensors; metrics_history.hottest_cpu_temp keeps only
    # CPU ones (shared with the cpu_temp_c trend series so both name the same
    # number) and falls back to a bare WMI thermal zone, never a GPU/NVMe one.
    cpu_max = metrics_history.hottest_cpu_temp(temps)
    cpu_temp = round(cpu_max, 1) if cpu_max is not None else None
    # The value is the hottest sensor at that instant -- on a hybrid CPU the
    # favored P-cores swing 30 C within a second of any work, so the sub-line
    # adds the far steadier core average (LHM's "Core Average" sensor, else
    # the mean of the per-core readings) to keep a spike in perspective.
    cpu_avg = _cpu_core_average(
        [t for t in temps if isinstance(t, dict) and metrics_history.is_cpu_temp_sensor(t)], _num
    )
    if cpu_temp is None:
        cpu_temp_sub = "no sensor"
    elif cpu_avg is not None:
        cpu_temp_sub = f"hottest core · avg {round(cpu_avg)}°"
    else:
        cpu_temp_sub = ""

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
            "sub": cpu_temp_sub,
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


def _format_operational_status(status) -> str:
    """Normalise a physical disk's OperationalStatus into a display string.

    ``Get-PhysicalDisk`` surfaces OperationalStatus as a scalar ("OK"), a
    JSON array (``["IO Error", "OK"]`` when a disk is throwing errors), or
    a wrapped object (``{"value": ["IO Error", "OK"], "Count": 2}``)
    depending on how PowerShell serialised it. Flatten any of those into a
    comma-joined string; return "" for empty / None.
    """
    if status is None:
        return ""
    if isinstance(status, dict):
        status = status.get("value", "")
    if isinstance(status, list | tuple):
        parts = [str(s).strip() for s in status if str(s).strip()]
        return ", ".join(parts)
    return str(status).strip()


def _parse_bios_date(s: str) -> datetime | None:
    """Parse a 'YYYY-MM-DD' BIOS date to a datetime, or None if unknown /
    unparseable (so callers raise no concern rather than a false one)."""
    if not s or s == "Unknown":
        return None
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def hardware_advisory_concerns(warranty: dict) -> list[dict]:
    """Dashboard concerns from get_warranty_data() — Intel 13th/14th-gen
    microcode/BIOS degradation risk + WHEA hardware errors.

    Parity with the daily report (SystemHealthDiag.check_intel_cpu /
    check_events) so the dashboard and the emailed report agree. Returns []
    when nothing is wrong OR the data is unavailable/unparseable — never a
    false alarm on missing data.
    """
    if not warranty or warranty.get("error"):
        return []
    concerns: list[dict] = []

    # Intel 13th/14th-gen degradation: an AFFECTED CPU on a BIOS that predates
    # Intel's microcode fix (0x129, Aug 2024) is at eTVB/SVID voltage-
    # degradation risk. Only fires for an affected CPU with an OLD, PARSEABLE
    # BIOS date — unknown/recent date raises nothing.
    if warranty.get("IsAffectedCPU"):
        bios_dt = _parse_bios_date(warranty.get("BIOSDate", ""))
        cpu = warranty.get("CPUModel") or "your CPU"
        shown = warranty.get("BIOSDate", "")
        if bios_dt is not None and bios_dt < datetime(2024, 8, 1):
            concerns.append(
                {
                    "level": "critical",
                    "tab": "bios",
                    "icon": "🔩",
                    "title": f"Intel microcode risk — BIOS predates the fix ({shown})",
                    "detail": (
                        f"{cpu} is a 13th/14th-gen part affected by the eTVB/SVID voltage-degradation issue, "
                        "and this BIOS is older than Intel's August-2024 microcode fix (0x129). "
                        "Update the BIOS as soon as possible — the degradation can be permanent."
                    ),
                    "action": "View BIOS & Firmware",
                    "action_fn": "switchTab('bios')",
                }
            )
        elif bios_dt is not None and bios_dt < datetime(2024, 12, 1):
            concerns.append(
                {
                    "level": "warning",
                    "tab": "bios",
                    "icon": "🔩",
                    "title": f"Intel microcode — verify latest BIOS ({shown})",
                    "detail": (
                        f"{cpu} is affected by the 13th/14th-gen voltage issue. This BIOS is post-fix but may "
                        "not carry the newest microcode — confirm you are on the latest Dell BIOS."
                    ),
                    "action": "View BIOS & Firmware",
                    "action_fn": "switchTab('bios')",
                }
            )

    # WHEA (hardware error) events: a fault in the last 7 days is ACTIVE
    # (critical); older-but-within-30-days is a warning (may be resolved).
    # Mirrors SystemHealthDiag.check_events.
    recent = warranty.get("WHEAErrorsRecent7Days") or 0
    older = warranty.get("WHEAErrors30Days") or 0
    if recent > 0:
        concerns.append(
            {
                "level": "critical",
                "tab": "sysinfo",
                "icon": "🩺",
                "title": f"{recent} hardware error(s) (WHEA) in the last 7 days",
                "detail": (
                    "Windows logged Machine-Check / PCIe / memory hardware errors recently — an ACTIVE fault, "
                    "most likely CPU, RAM, or motherboard. Back up important data and investigate."
                ),
                "action": "View System Info",
                "action_fn": "switchTab('sysinfo')",
            }
        )
    elif older > 0:
        concerns.append(
            {
                "level": "warning",
                "tab": "sysinfo",
                "icon": "🩺",
                "title": f"{older} hardware error(s) (WHEA) in the last 30 days",
                "detail": (
                    "Windows logged hardware (WHEA) errors in the past month but none in the last week — "
                    "possibly resolved, but worth watching."
                ),
                "action": "View System Info",
                "action_fn": "switchTab('sysinfo')",
            }
        )

    return concerns


def _storage_degraded(health: str, operational: str) -> bool:
    """True when a Storage Spaces pool/virtual-disk is not fully healthy."""
    h = str(health or "").strip().lower()
    o = str(operational or "").strip().lower()
    if h in ("warning", "unhealthy"):
        return True
    return any(k in o for k in ("degraded", "incomplete", "unhealthy", "detached"))


def storage_pool_concerns(data: dict) -> list[dict]:
    """Storage Spaces pool / virtual-disk health -> dashboard concerns.

    Windows Storage Spaces raises NO alert of its own when a pool degrades (a
    member drive dropping just silently flips it to Degraded), so this is the
    only place the app surfaces lost redundancy. A degraded space is CRITICAL:
    it's running without the parity/mirror protection it was built for, and one
    more drive failure loses the volume. Also flags a stalled (Suspended)
    repair. Returns [] when everything is healthy or there are no Spaces.
    """
    if not data or not data.get("has_spaces"):
        return []
    concerns: list[dict] = []

    degraded_vds = [
        vd for vd in data.get("virtual_disks", []) if _storage_degraded(vd.get("Health"), vd.get("Operational"))
    ]
    for vd in degraded_vds:
        name = vd.get("Name") or "Storage Space"
        state = vd.get("Health") or vd.get("Operational") or "Degraded"
        resil = vd.get("Resiliency") or "?"
        concerns.append(
            {
                "level": "critical",
                "tab": "disk",
                "icon": "🗄",
                "title": f"Storage Space '{name}' is {state} — redundancy lost",
                "detail": (
                    f"This {resil} space dropped a member drive and is running WITHOUT redundancy. "
                    "Another drive failure would lose the whole volume. Open the Storage tab to find the "
                    "failed drive (by slot + serial) and repair or replace it."
                ),
                "action": "View Storage",
                "action_fn": "switchTab('disk')",
            }
        )

    # Pool degraded with no matching virtual disk (rare) — still surface it.
    if not degraded_vds:
        for p in data.get("pools", []):
            if _storage_degraded(p.get("Health"), p.get("Operational")):
                concerns.append(
                    {
                        "level": "critical",
                        "tab": "disk",
                        "icon": "🗄",
                        "title": f"Storage pool '{p.get('Name', 'pool')}' is {p.get('Health') or 'Degraded'}",
                        "detail": "A Storage Spaces pool is degraded — a member drive has dropped. Investigate on the Storage tab.",
                        "action": "View Storage",
                        "action_fn": "switchTab('disk')",
                    }
                )

    # A repair that exists but is Suspended means the array is NOT self-healing
    # (often: not enough free pool space to rebuild). Worth a warning even while
    # the degraded-critical above fires.
    for j in data.get("repair_jobs", []):
        if str(j.get("State") or "").strip().lower() == "suspended":
            concerns.append(
                {
                    "level": "warning",
                    "tab": "disk",
                    "icon": "🛠",
                    "title": "Storage Spaces repair is stalled (Suspended)",
                    "detail": (
                        "A repair job is suspended, so the pool is not rebuilding on its own — usually because "
                        "there isn't enough free pool space to absorb the lost drive. Add/replace a drive or free "
                        "space, then repair."
                    ),
                    "action": "View Storage",
                    "action_fn": "switchTab('disk')",
                }
            )
            break

    return concerns


def _mem_cfg_concern(level: str, title: str, detail: str) -> dict:
    return {
        "level": level,
        "tab": "sysinfo",
        "icon": "🧠",
        "title": title,
        "detail": detail,
        "action": "View System Info",
        "action_fn": "switchTab('sysinfo')",
    }


def memory_config_concerns(cfg: dict) -> list[dict]:
    """RAM speed/capacity mismatch + above-spec XMP -> dashboard warnings.

    Parity with SystemHealthDiag.check_memory. All warning-level (config
    issues, not live failures). Returns [] when the config is clean OR the
    data is unavailable — never a false alarm on missing data. Needs >=2
    sticks with valid readings to compare.
    """
    if not cfg or cfg.get("error"):
        return []
    sticks = cfg.get("sticks", [])
    speeds = [s.get("speed_mhz") for s in sticks if s.get("speed_mhz")]
    caps = [s.get("capacity_gb") for s in sticks if s.get("capacity_gb")]
    concerns: list[dict] = []

    if len(set(speeds)) > 1:
        shown = ", ".join(f"{s} MHz" for s in sorted(set(speeds)))
        concerns.append(
            _mem_cfg_concern(
                "warning",
                "RAM sticks run at different speeds",
                f"Configured speeds differ ({shown}) — mismatched RAM runs at the slowest common speed and can "
                "reduce stability.",
            )
        )
    if len(set(caps)) > 1:
        shown = ", ".join(f"{c} GB" for c in sorted(set(caps)))
        concerns.append(
            _mem_cfg_concern(
                "warning",
                "RAM sticks have different capacities",
                f"Capacities differ ({shown}) — mixed-size RAM can drop you out of dual-channel and reduce stability.",
            )
        )
    if speeds and max(speeds) > 5600:
        concerns.append(
            _mem_cfg_concern(
                "warning",
                f"RAM running above Intel spec ({max(speeds)} MHz)",
                "Configured above Intel's official 5600 MHz DDR5 spec for 13th/14th-gen (an XMP/EXPO profile). "
                "Usually fine, but a common instability source — if you see random crashes, try disabling XMP in BIOS.",
            )
        )
    return concerns


def _collect_dashboard_results(wdm) -> dict:
    """Run every dashboard collector: thermals first and alone, the rest in
    parallel with a 45 s budget. A collector that raises or times out reads
    as ``{"error": ...}``."""
    import concurrent.futures

    results = {}

    def run(name, fn):
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = {"error": str(e)}

    # Thermals run FIRST and alone. The other collectors below spawn
    # PowerShell / WMI work that pushes the CPU to ~40% load and ~200 W for
    # several seconds; sampled in parallel, the CPU-temp and CPU-load gauges
    # were measuring the dashboard's own refresh (86-91 C on an idle 14900K
    # whose cores sat at ~50 C) and then showing that for minutes.
    run("thermals", wdm.get_thermals)

    checks = {
        "memory": wdm.get_memory_analysis,
        "bios": wdm.get_bios_status,
        "credentials": wdm.get_credentials_network_health,
        "disk": wdm.get_disk_health,
        "drivers": wdm.get_driver_health,
        "gpu": wdm.get_gpu_metrics,
        "network": wdm.get_network_metrics,
        "network_health": wdm.get_network_health,
        "warranty": wdm.get_warranty_data,
        "memory_config": wdm.get_memory_config,
        "storage_spaces": wdm.get_storage_spaces,
        "nas_storage": wdm.get_nas_storage,
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
    return results


def _best_effort(build, *args) -> list[dict]:
    """``build(*args)`` or ``[]`` if it raises: an optional source must never
    break the dashboard."""
    try:
        return list(build(*args) or [])
    except Exception:  # noqa: BLE001 -- best-effort by design
        return []


def _credential_concerns(results: dict) -> list[dict]:
    concerns = []
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
    return concerns


def _thermal_concerns(therm: dict) -> list[dict]:
    concerns = []
    crit_temps = [t for t in therm.get("temps", []) if t.get("status") == "critical"]
    warn_temps = [t for t in therm.get("temps", []) if t.get("status") == "warning"]
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
    # A kernel driver pinning a core (#75) -- sampled by get_thermals().
    try:
        import kernel_cpu

        kernel_concern = kernel_cpu.stuck_concern(therm.get("kernel_cpu"))
        if kernel_concern:
            concerns.append(kernel_concern)
    except Exception:  # noqa: BLE001 -- best-effort, never block the dashboard
        pass
    return concerns


def _pressure_concerns(results: dict, cpu_pct, mem: dict, mem_pct: float) -> list[dict]:
    """CPU, memory and per-drive fullness through the user-tunable alerts.py
    rules (backlog #5), with the legacy hardcoded thresholds as the fallback
    so the dashboard is never silent about real pressure."""
    concerns = []
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
    return concerns


def _physical_disk_concerns(results: dict) -> list[dict]:
    """Physical-disk SMART/health status.

    The drive loops in _pressure_concerns only cover logical-volume
    *fullness* (disk_percent); a physical disk reporting a non-Healthy
    HealthStatus (Warning / Unhealthy / an "IO Error" OperationalStatus)
    never reached the dashboard concerns feed before this block, so a failing
    disk showed up in the daily health report
    (SystemHealthDiag.check_disk_health) and on the Disk tab
    (disk.summarize_disk) but was silently absent from the dashboard. Mirror
    those two surfaces: any non-Healthy physical disk is a critical,
    data-loss-risk concern. (Bug: dashboard/daily-report disagreement,
    2026-07-04.) A drive the user has explicitly PAUSED (e.g. a known-failing
    one mid-replacement) is suppressed here so it stops nagging — but only
    that drive, by serial, and only until the snooze expires.
    """
    concerns = []
    try:
        import disk as _disk_mod

        _disk_snoozes = _disk_mod._load_disk_snoozes()
    except Exception:  # noqa: BLE001
        _disk_mod = None
        _disk_snoozes = {}
    for p in (results.get("disk") or {}).get("physical", []):
        health = str(p.get("Health") or "").strip()
        if health.lower() in ("", "healthy"):
            continue
        serial = str(p.get("SerialNumber") or "")
        if _disk_mod is not None and _disk_mod.is_disk_snoozed(serial, _disk_snoozes):
            continue
        name = p.get("Name") or "Unknown disk"
        op = _format_operational_status(p.get("Status"))
        detail = "Back up important data now and investigate — a disk in this state can lose data."
        if op and op.lower() not in ("ok", "healthy"):
            detail = f"Operational status: {op}. " + detail
        concerns.append(
            {
                "level": "critical",
                "tab": "disk",
                "icon": "💾",
                "title": f"Disk '{name}' reports {health} health",
                "detail": detail,
                "action": "View Storage",
                "action_fn": "switchTab('disk')",
                # Serial lets the dashboard render a "Pause 24h" button that
                # snoozes exactly this drive.
                "disk_serial": serial,
            }
        )
    return concerns


def _network_health_concerns(results: dict) -> list[dict]:
    """Internet reachability / DNS / adapter status. Parity with the daily
    health report (SystemHealthDiag.check_network_health), which flags
    internet-down / DNS-fail / no-active-adapter as critical. The `network`
    collector only samples throughput/latency for the Trends card and can't
    answer "is the internet usable?"; `network_health` is the dedicated
    reachability probe."""
    import network as _network_mod

    nh = results.get("network_health") or {}
    if nh and not nh.get("error"):
        return _network_mod.network_health_concerns(nh)
    return []


def _nas_concerns(results: dict) -> list[dict]:
    """NAS storage (QNAP over SNMP) — unhealthy NAS disk / not-Ready volume /
    unreachable NAS. Only active when nas_config.json is filled in."""
    import nas as _nas_mod

    return _nas_mod.nas_storage_concerns(results.get("nas_storage") or {})


def _process_memory_concerns(mem: dict) -> list[dict]:
    """Per-process memory hogs (backlog #19). Each concern carries
    pid/process_name/mem_mb so the frontend can render inline action buttons
    (Kill / Investigate / Snooze 24h). Snoozed processes are filtered here so
    the user's dismissal actually suppresses the warning for the snooze
    window."""
    concerns = []
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
    return concerns


def _bios_update_concerns(results: dict) -> list[dict]:
    bios = results.get("bios", {})
    if bios.get("update", {}).get("update_available"):
        latest = bios.get("update", {}).get("latest_version", "")
        return [
            {
                "level": "critical",
                "tab": "bios",
                "icon": "🔩",
                "title": f"BIOS update available: {latest}",
                "detail": "Install to get latest microcode patches for your i9-14900K.",
                "action": "View BIOS & Firmware",
                "action_fn": "switchTab('bios')",
            }
        ]
    return []  # no update, or BIOS confirmed current -- no concern needed


def _task_concerns() -> list[dict]:
    """Scheduled-task health concerns (crashloops, stale successes, missing tasks)."""
    import task_watcher

    return task_watcher.concerns_from_health(task_watcher.get_all_task_health())


def _baseline_concerns() -> list[dict]:
    """Baseline drift concerns (backlog #14).

    Reads the drift history file (fast), NOT the live compute_drift() call
    (~5 s: too slow for the dashboard fan-out). The history is appended by
    /api/baseline/drift whenever the user opens the Baseline tab, which is
    also the place they act on it. Concern fires at "info" level because
    drift is often benign (Windows Update installed a service); critical
    only if the user has explicitly marked something suspicious.
    """
    import baseline

    concerns = []
    # drop_reconciled() removes every change that no longer needs review
    # -- cleared by "accept current as baseline", accepted one entry or
    # cluster at a time, or undone on the PC -- by the same rule as the
    # Baseline tab timeline. Without it, settled drift kept showing as
    # open on the dashboard for up to 24h (bugs 2026-06-03, 2026-10-10).
    history = baseline.load_history()
    drift_entries = baseline.drop_reconciled(baseline.recent_drift(), history)
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

    try:
        concerns += _baseline_cluster_concerns(baseline, history)
    except Exception:  # noqa: BLE001 -- keep the drift concern already found
        pass
    return concerns


def _baseline_cluster_concerns(baseline, history: list) -> list[dict]:
    # Backlog #44 cross-surface correlation concern. Distinct from the
    # info-level "drift detected" concern in _baseline_concerns — that one fires on ANY
    # drift; this one fires on the security-relevant pattern where the
    # most-recent cluster touched ≥3 categories within 60 s. That's the
    # canonical install / malware fingerprint and warrants warning-level
    # attention even if the underlying drift count is small.
    history_all = baseline.drop_reconciled(history, history)
    alert = baseline.correlation_alert(history_all, window_seconds=60, min_categories=3)
    if alert:
        cat_label = ", ".join(alert["categories"])
        span = alert["span_seconds"]
        span_label = f"{int(span)} s" if span >= 1 else "simultaneously"
        return [
            {
                "level": "warning",
                "tab": "baseline",
                "icon": "🚨",
                "title": f"Cross-surface baseline drift cluster ({alert['event_count']} events, {span_label})",
                "detail": f"Touched {len(alert['categories'])} categories: {cat_label}. Review the Change Timeline.",
                "action": "Review change timeline",
                "action_fn": "switchTab('baseline')",
            }
        ]
    return []


def _backup_concerns() -> list[dict]:
    """Backup health concerns (backlog #47). Fires when File History is
    configured + enabled but the target backup store is unreachable
    (silent-failure mode that wastes the user's mental "I'm backed up"
    reassurance), when the WindowsImageBackup catalog is empty, or when the
    Backup and Restore schedule's last success is stale."""
    import backup as backup_mod

    backup_summary = backup_mod.summarize_backup()
    overall = backup_summary.get("overall_health") or {}
    level = overall.get("level", "info")
    if level not in ("warning", "critical"):
        return []
    # Detail line shows every failing surface so the user sees the
    # full picture from the concern card without opening the tab.
    detail_parts = []
    for key, label in (
        ("file_history", "File History"),
        ("windows_backups", "WindowsImageBackup"),
        ("windows_backup_schedule", "Backup and Restore"),
    ):
        health = (backup_summary.get(key) or {}).get("health") or {}
        if health.get("reason") and health.get("level") in ("warning", "critical"):
            detail_parts.append(f"{label}: {health['reason']}")
    return [
        {
            "level": level,
            "tab": "backup",
            "icon": "📦",
            "title": (
                "Backup health: critical -- backups are not being saved or are out of date"
                if level == "critical"
                else "Backup health: warning"
            ),
            "detail": " · ".join(detail_parts) or overall.get("reason", ""),
            "action": "Review backups",
            "action_fn": "switchTab('backup')",
        }
    ]


def _bios_audit_concerns() -> list[dict]:
    """BIOS audit-trail concerns: logged changes + collection errors in the last 24h."""
    import bios_audit

    concerns = []
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
    try:
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
    except Exception:  # noqa: BLE001 -- keep the change concern already found
        pass
    return concerns


def _driver_concerns(results: dict) -> list[dict]:
    """Device errors, very old third-party drivers, and an NVIDIA driver update."""
    concerns = []
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
    return concerns


def _router_backup_concerns() -> list[dict]:
    """Router config backup staleness.

    Both vendors require manual backups via their admin Save/Restore page
    (Orbi RBRE960 firmware rejects the documented SOAP backup endpoint;
    Verizon CR1000A's SPA needs browser interaction). The dashboard surfaces
    an info-level concern when the newest file in backups/<vendor>/ crosses
    the staleness threshold so the user knows it's time to re-run the manual
    backup.

    (The "Orbi reporting N wireless devices with unknown AP" concern was
    removed 2026-05-13: the RBRE960 firmware's corrupted ConnAPMAC sentinel
    is a static hardware fact, not an actionable issue, so it lives on the
    topology stats line and the Unknown column subtitle instead.)
    """
    from homenet import get_backup_health

    concerns = []
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
    try:
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
    except Exception:  # noqa: BLE001 -- keep the Verizon concern already found
        pass
    return concerns


def _record_trend_sample(concerns: list[dict], results: dict) -> None:
    """Trend sampler (backlog #4). Best-effort, throttled internally to one
    sample per SAMPLE_INTERVAL — must never break the dashboard response."""
    try:
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


_LEVEL_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def _compute_dashboard_summary() -> dict:
    """Synchronous fan-out over every dashboard collector.

    Returns the full response dict (not a Flask Response) so the route
    handler and the background refresher can share one implementation.
    Each area's concerns come from its own helper above; the order they are
    gathered in is the order equal-level concerns are shown in.
    """
    # Collectors are resolved from the windesktopmgr namespace at call
    # time so existing `mocker.patch("windesktopmgr.get_*")` test hooks
    # keep intercepting the fan-out after the extraction (PR E, #54).
    import windesktopmgr as wdm

    results = _collect_dashboard_results(wdm)

    therm = results.get("thermals", {})
    cpu_pct = therm.get("perf", {}).get("CPUPct", 0)
    # mem / mem_pct are shared by the pressure and per-process concerns.
    mem = results.get("memory", {})
    mem_pct = round(mem.get("used_mb", 0) / max(mem.get("total_mb", 1), 1) * 100, 1)

    concerns = [
        *_credential_concerns(results),
        *_thermal_concerns(therm),
        *_pressure_concerns(results, cpu_pct, mem, mem_pct),
        *_physical_disk_concerns(results),
        # Parity with the daily report: network reachability, Intel CPU /
        # WHEA advisories, RAM config, Storage Spaces pool, NAS. Each reads
        # the same collector its tab uses, so the surfaces can't disagree.
        *_best_effort(_network_health_concerns, results),
        *_best_effort(hardware_advisory_concerns, results.get("warranty") or {}),
        *_best_effort(memory_config_concerns, results.get("memory_config") or {}),
        *_best_effort(storage_pool_concerns, results.get("storage_spaces") or {}),
        *_best_effort(_nas_concerns, results),
        *_process_memory_concerns(mem),
        *_bios_update_concerns(results),
        *_best_effort(_task_concerns),
        *_best_effort(_baseline_concerns),
        *_best_effort(_backup_concerns),
        *_best_effort(_bios_audit_concerns),
        *_driver_concerns(results),
    ]
    concerns.sort(key=lambda c: _LEVEL_ORDER.get(c.get("level", "info"), 2))
    # Router backups are appended after the sort (info level, always last).
    concerns += _best_effort(_router_backup_concerns)

    overall = (
        "critical"
        if any(c["level"] == "critical" for c in concerns)
        else "warning"
        if any(c["level"] == "warning" for c in concerns)
        else "ok"
    )
    _record_trend_sample(concerns, results)

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
