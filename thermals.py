"""Temperature, power & fan telemetry for WinDesktopMgr (#54 PR G).

get_thermals() reads CPU thermal zones (MSAcpi_ThermalZoneTemperature),
optional OpenHardwareMonitor / LibreHardwareMonitor per-sensor temps, and
Win32_Fan speeds via the in-process `wmi` package, plus CPU/memory/battery
via psutil -- no PowerShell subprocess. summarize_thermals() folds the
reading into the dashboard insight/action shape using the TEMP_WARN_C /
TEMP_CRIT_C thresholds.

WMI/psutil/pythoncom are imported here but are the SAME module objects the
test suite patches as `windesktopmgr.wmi.WMI` / `windesktopmgr.pythoncom.*`
(module-attribute patches, shared across importers), so those mocks keep
working after the move. The Flask route, /api/selftest globals() lookup,
get_summary dispatch, NLQ dispatch, and the dashboard fan-out call the
re-exported bindings in windesktopmgr.py.

_insight is duplicated locally (disk.py / bsod.py precedent).
"""

import psutil
import pythoncom
import wmi

TEMP_WARN_C = 80
TEMP_CRIT_C = 95


def _insight(level: str, text: str, action: str = "") -> dict:
    return {"level": level, "text": text, "action": action}


def get_thermals() -> dict:
    """CPU temperatures, utilisation, and fan speeds — fully in-process
    (backlog #28 close-out): thermal zones + OHM/LHM sensors via the ``wmi``
    package, CPU/memory/battery via ``psutil``. No PowerShell subprocess.
    """

    # The three WMI enumerations below are blocking COM calls that hang
    # forever when Winmgmt is wedged, so run them bounded (see
    # bounded_wmi_query). On timeout/error we degrade to empty temps+fans and
    # fall through to the psutil perf block + the standard "no sensors" note.
    def _wmi_work():
        temps: list = []
        fans: list = []
        pythoncom.CoInitialize()
        # CPU temps — MSAcpi_ThermalZoneTemperature lives in root\wmi and
        # reports decikelvin (value / 10 - 273.15 = Celsius). InstanceName
        # is trimmed the same way the old PS -replace pair did.
        try:
            for z in wmi.WMI(namespace="root\\wmi").MSAcpi_ThermalZoneTemperature():
                inst = z.InstanceName or ""
                name = inst.split("_")[-1].split("\\")[0] if inst else "ThermalZone"
                temps.append(
                    {
                        "Name": name,
                        "TempC": round(z.CurrentTemperature / 10 - 273.15, 1),
                        "Source": "WMI_ThermalZone",
                    }
                )
        except Exception:  # noqa: BLE001 — no thermal-zone provider
            pass
        # Rich per-sensor temps — only present when OpenHardwareMonitor /
        # LibreHardwareMonitor is running and has registered its WMI provider.
        for ns, label in (
            ("root\\OpenHardwareMonitor", "OpenHardwareMonitor"),
            ("root\\LibreHardwareMonitor", "LibreHardwareMonitor"),
        ):
            try:
                for s in wmi.WMI(namespace=ns).Sensor():
                    if s.SensorType == "Temperature":
                        temps.append({"Name": s.Name, "TempC": round(s.Value, 1), "Source": label})
            except Exception:  # noqa: BLE001 — namespace absent (tool not running)
                pass
        # Fan speeds — Win32_Fan; almost always empty on consumer hardware.
        try:
            for f in wmi.WMI().Win32_Fan():
                fans.append({"Name": f.Name, "ActiveCooling": f.ActiveCooling, "DesiredSpeed": f.DesiredSpeed})
        except Exception:  # noqa: BLE001
            pass
        return temps, fans

    from windesktopmgr import bounded_wmi_query  # lazy: wdm-resident, breaks import cycle

    temps, fans = bounded_wmi_query(_wmi_work, timeout_s=8.0, fallback=([], []), label="thermals WMI")

    # LibreHardwareMonitor rich sensors. LHM has NO WMI provider (only the
    # OpenHardwareMonitor namespace above ever answers WMI) -- it exposes its
    # per-core CPU + GPU + board temps only through its HTTP server, which the
    # in-app installer enables. Read it over loopback and merge. Best-effort:
    # an empty list (LHM not running) just leaves the WMI/psutil data as-is.
    try:
        import lhm  # noqa: PLC0415 -- lazy: optional sibling

        lhm_temps = lhm.get_lhm_temps()
        if lhm_temps:
            # LHM is authoritative when present; drop the coarse WMI thermal
            # zone(s) so the per-core grid + sensor list aren't duplicated.
            temps = [t for t in temps if t.get("Source") not in ("WMI_ThermalZone",)] + lhm_temps
    except Exception:  # noqa: BLE001 -- never let LHM read break the core reading
        pass

    # CPU utilisation / memory / battery via psutil — no WMI, no subprocess.
    try:
        vm = psutil.virtual_memory()
        battery = None
        b = psutil.sensors_battery()
        if b is not None:
            # Match the old Win32_Battery shape: Status 2 = on AC, 1 = discharging.
            battery = {"Status": 2 if b.power_plugged else 1, "Charge": round(b.percent)}
        perf = {
            "CPUPct": round(psutil.cpu_percent(interval=0.3), 1),
            "MemUsedMB": round((vm.total - vm.available) / (1024 * 1024)),
            "MemTotalMB": round(vm.total / (1024 * 1024)),
            "Battery": battery,
        }
    except Exception:  # noqa: BLE001
        perf = {}

    # Annotate temperatures with status thresholds.
    for t in temps:
        c = t.get("TempC", 0)
        t["status"] = "critical" if c >= TEMP_CRIT_C else "warning" if c >= TEMP_WARN_C else "ok"

    has_rich = any(t.get("Source") in ("OpenHardwareMonitor", "LibreHardwareMonitor") for t in temps)
    return {
        "temps": temps,
        "perf": perf,
        "fans": fans,
        "has_rich": has_rich,
        "note": ""
        if has_rich
        else (
            "Install LibreHardwareMonitor for detailed CPU/GPU per-core temperatures, "
            "then launch it as Administrator so it can read the sensors and serve them to this app."
        ),
    }


def summarize_thermals(data: dict) -> dict:
    temps = data.get("temps", [])
    perf = data.get("perf", {})
    insights = []
    actions = []
    cpu_pct = perf.get("CPUPct", 0)
    mem_used = perf.get("MemUsedMB", 0)
    mem_tot = perf.get("MemTotalMB", 1)

    critical_temps = [t for t in temps if t.get("status") == "critical"]
    warn_temps = [t for t in temps if t.get("status") == "warning"]

    if critical_temps:
        insights.append(
            _insight(
                "critical",
                "CRITICAL temperatures detected: " + ", ".join(f"{t['Name']} {t['TempC']}°C" for t in critical_temps),
                "Shut down immediately and check cooling. Clean dust from heatsink and case fans.",
            )
        )
        actions.append("Check cooling immediately")
    elif warn_temps:
        insights.append(
            _insight(
                "warning",
                "Elevated temperatures: " + ", ".join(f"{t['Name']} {t['TempC']}°C" for t in warn_temps),
                "Monitor under load. Consider reapplying thermal paste if temps persist.",
            )
        )
    elif temps:
        insights.append(
            _insight("ok", "All temperatures normal: " + ", ".join(f"{t['Name']} {t['TempC']}°C" for t in temps[:4]))
        )

    if cpu_pct >= 90:
        insights.append(
            _insight(
                "warning",
                f"CPU at {cpu_pct}% — sustained high utilisation.",
                "Check the Processes tab to identify what is driving high CPU. "
                "This may be normal during heavy tasks (video encoding, backups) but worth checking if unexpected.",
            )
        )
    elif cpu_pct >= 60:
        insights.append(_insight("info", f"CPU at {cpu_pct}% utilisation — moderately busy."))
    else:
        insights.append(_insight("ok", f"CPU at {cpu_pct}% utilisation — normal."))

    if mem_tot > 0:
        mem_pct = round(mem_used / mem_tot * 100, 1)
        level = "critical" if mem_pct > 90 else "warning" if mem_pct > 75 else "ok"
        insights.append(_insight(level, f"RAM: {mem_used:,} MB used of {mem_tot:,} MB ({mem_pct}%)."))

    if not data.get("has_rich") and not temps:
        insights.append(
            _insight(
                "info",
                "No temperature sensors detected via WMI. Install LibreHardwareMonitor for detailed CPU/GPU temps.",
                "Download from librehardwaremonitor.org — run as Administrator once to register.",
            )
        )

    status = "critical" if critical_temps or cpu_pct >= 90 else "warning" if warn_temps or cpu_pct >= 60 else "ok"
    headline = (
        "🌡 Critical temps detected — check cooling!"
        if critical_temps
        else f"CPU {cpu_pct}% | RAM {round(mem_used / mem_tot * 100) if mem_tot else 0}%"
        + (" | ⚠ High temps" if warn_temps else "")
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}
