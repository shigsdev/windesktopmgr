"""
sysinfo.py — System Information & Upgrade-analysis module for WinDesktopMgr.

Owns the System Info tab:

* ``collect_sysinfo`` — the comprehensive hardware/OS inventory collector
  (WMI: OS, CPU, BIOS, baseboard, GPU, NICs, RAM sticks + arrays, disks,
  volumes, sound, USB, PCIe slots) plus the derived upgrade opportunities.
  Extracted verbatim from the old inline ``/api/sysinfo/data`` route body;
  windesktopmgr keeps a thin route wrapper that jsonify()s this.
* ``summarize_sysinfo`` — the System Info tab insight summary.
* Hardware upgrade analyser (backlog #43): chipset inference + max-RAM table,
  JEDEC/voltage specs, Crucial/OEM advisor URLs, PCIe-slot blocking, and
  ``summarize_upgrades``.
* The sysinfo-only WMI decode maps (_ff_map / _mem_type_map / _arch_map /
  _slot_usage_map / _mem_ec_map / _mem_loc_map).

Extracted from windesktopmgr.py (backlog #54 PR D, fourth production-file
extraction after bsod.py / events.py / processes.py). No behaviour changes:
every block is a verbatim relocation (the route body is wrapped as a
function returning the same payload dict the route used to jsonify()).

Circular-import note: ``collect_sysinfo`` lazy-imports the shared WMI helpers
(``_wmi_conn`` / ``_wmi_date_to_str``) from windesktopmgr at call time — those
have ~18 callers that stay in windesktopmgr. The lazy import breaks the cycle
and keeps ``mocker.patch("windesktopmgr._wmi_conn")`` effective.
"""

from __future__ import annotations

import locale
import time
from datetime import datetime, timezone


def _insight(level: str, text: str, action: str = "") -> dict:
    """Insight dict constructor — local copy of the windesktopmgr helper
    (the disk.py / bsod.py / events.py / processes.py extraction pattern)."""
    return {"level": level, "text": text, "action": action}


_ff_map = {8: "DIMM", 12: "SODIMM", 0: "Unknown"}
_mem_type_map = {20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM", 24: "DDR3", 26: "DDR4", 34: "DDR5", 0: "Unknown"}
_arch_map = {0: "x86", 5: "ARM", 9: "x64", 12: "ARM64"}
_slot_usage_map = {1: "Other", 2: "Unknown", 3: "Available", 4: "In Use"}
# Win32_PhysicalMemoryArray.MemoryErrorCorrection codes (DMTF / SMBIOS)
_mem_ec_map = {
    1: "Other",
    2: "Unknown",
    3: "None",
    4: "Parity",
    5: "Single-bit ECC",
    6: "Multi-bit ECC",
    7: "CRC",
}
# Win32_PhysicalMemoryArray.Location codes (where the array physically sits)
_mem_loc_map = {
    1: "Other",
    2: "Unknown",
    3: "System Board",
    4: "ISA Add-on Card",
    5: "EISA Add-on Card",
    6: "PCI Add-on Card",
    7: "MCA Add-on Card",
    8: "PCMCIA Add-on Card",
    9: "Proprietary Add-on Card",
    10: "NuBus",
}


def collect_sysinfo() -> dict:
    """Collect comprehensive system information for the System Info tab.

    Extracted from the old inline /api/sysinfo/data route body (#54 PR D).
    Returns the same payload dict the route used to jsonify().
    """
    # Lazy import breaks the windesktopmgr <-> sysinfo cycle and keeps
    # mocker.patch("windesktopmgr._wmi_conn") effective.
    from windesktopmgr import _wmi_conn, _wmi_date_to_str

    collected_at = datetime.now(timezone.utc).isoformat()
    stale = False
    error_detail = None

    # All the WMI enumerations below are blocking COM calls that hang forever
    # when Winmgmt is wedged, so build the inventory inside a bounded worker
    # (see bounded_wmi_query). On timeout/fault we get None back and mark the
    # payload stale -- same signal the old try/except produced.
    def _wmi_work():
        data = {}
        c = _wmi_conn()
        os_obj = c.Win32_OperatingSystem()[0]
        cs_obj = c.Win32_ComputerSystem()[0]
        cpu_obj = c.Win32_Processor()[0]
        bios_obj = c.Win32_BIOS()[0]
        bb_obj = c.Win32_BaseBoard()[0]

        # Parse OS dates
        install_date = _wmi_date_to_str(os_obj.InstallDate or "")
        last_boot_raw = os_obj.LastBootUpTime or ""
        last_boot = _wmi_date_to_str(last_boot_raw, "%Y-%m-%d %H:%M:%S")

        # Uptime calculation
        uptime_str = ""
        if last_boot_raw and len(last_boot_raw) >= 14:
            try:
                boot_dt = datetime.strptime(last_boot_raw[:14], "%Y%m%d%H%M%S")
                delta = datetime.now() - boot_dt
                days = delta.days
                hours, rem = divmod(delta.seconds, 3600)
                minutes, seconds = divmod(rem, 60)
                uptime_str = f"{days:02d}.{hours:02d}:{minutes:02d}:{seconds:02d}"
            except Exception:
                pass

        # TimeZone — use Python stdlib
        local_tz_name = time.tzname[time.daylight] if time.daylight else time.tzname[0]
        utc_offset = -time.timezone if not time.daylight else -time.altzone
        tz_hours = utc_offset // 3600
        tz_sign = "+" if tz_hours >= 0 else ""
        tz_display = f"(UTC{tz_sign}{tz_hours:02d}:00) {local_tz_name}"
        tz_id = local_tz_name

        # Locale — use Python stdlib
        try:
            locale_name = locale.getlocale()[0] or "Unknown"
        except Exception:
            locale_name = "Unknown"

        # Computer
        total_ram_bytes = int(cs_obj.TotalPhysicalMemory or 0)
        data["Computer"] = {
            "Name": cs_obj.Name or "",
            "Domain": cs_obj.Domain or "",
            "Manufacturer": cs_obj.Manufacturer or "",
            "Model": cs_obj.Model or "",
            "SystemType": cs_obj.SystemType or "",
            "TotalRAM_GB": round(total_ram_bytes / (1024**3), 1) if total_ram_bytes else 0,
        }

        # OS
        data["OS"] = {
            "Name": os_obj.Caption or "",
            "Version": os_obj.Version or "",
            "Build": os_obj.BuildNumber or "",
            "Architecture": os_obj.OSArchitecture or "",
            "InstallDate": install_date,
            "LastBoot": last_boot,
            "Uptime": uptime_str,
            "WindowsDir": os_obj.WindowsDirectory or "",
            "SystemDrive": os_obj.SystemDrive or "",
            "Locale": locale_name,
            "TimeZone": tz_display,
            "TimeZoneId": tz_id,
        }

        # CPU
        arch_code = int(cpu_obj.Architecture) if cpu_obj.Architecture is not None else -1
        data["CPU"] = {
            "Name": (cpu_obj.Name or "").strip(),
            "Cores": int(cpu_obj.NumberOfCores or 0),
            "LogicalProcs": int(cpu_obj.NumberOfLogicalProcessors or 0),
            "MaxClockMHz": int(cpu_obj.MaxClockSpeed or 0),
            "CurrentClockMHz": int(cpu_obj.CurrentClockSpeed or 0),
            "SocketDesignation": cpu_obj.SocketDesignation or "",
            "L2CacheKB": int(cpu_obj.L2CacheSize or 0),
            "L3CacheKB": int(cpu_obj.L3CacheSize or 0),
            "ProcessorId": cpu_obj.ProcessorId or "",
            "Architecture": _arch_map.get(arch_code, str(arch_code)),
        }

        # BIOS
        bios_release = bios_obj.ReleaseDate or ""
        data["BIOS"] = {
            "Version": bios_obj.SMBIOSBIOSVersion or "",
            "ReleaseDate": _wmi_date_to_str(bios_release) if bios_release else "Unknown",
            "Manufacturer": bios_obj.Manufacturer or "",
            "SerialNumber": bios_obj.SerialNumber or "",
        }

        # Baseboard
        data["Baseboard"] = {
            "Manufacturer": bb_obj.Manufacturer or "",
            "Product": bb_obj.Product or "",
            "Version": bb_obj.Version or "",
            "SerialNumber": bb_obj.SerialNumber or "",
        }

        # GPU
        gpus = []
        for g in c.Win32_VideoController():
            gpus.append(
                {
                    "Name": g.Name or "",
                    "DriverVersion": g.DriverVersion or "",
                    "DriverDate": _wmi_date_to_str(g.DriverDate or "") if g.DriverDate else "",
                    "AdapterRAM": int(g.AdapterRAM or 0),
                    "VideoProcessor": g.VideoProcessor or "",
                    "CurrentRefreshRate": int(g.CurrentRefreshRate or 0),
                    "VideoModeDescription": g.VideoModeDescription or "",
                    "AdapterCompatibility": g.AdapterCompatibility or "",
                    "PNPDeviceID": g.PNPDeviceID or "",
                }
            )
        data["GPU"] = gpus

        # Network (IP-enabled adapters)
        nics = []
        for n in c.Win32_NetworkAdapterConfiguration():
            if not n.IPEnabled:
                continue
            ip_addrs = n.IPAddress
            ip_str = ", ".join(ip_addrs) if ip_addrs else ""
            dns = n.DNSServerSearchOrder
            nics.append(
                {
                    "Description": n.Description or "",
                    "MACAddress": n.MACAddress or "",
                    "IPAddress": ip_str,
                    "DHCPEnabled": bool(n.DHCPEnabled),
                    "DHCPServer": n.DHCPServer or "",
                    "DNSServerSearchOrder": list(dns) if dns else [],
                }
            )
        data["Network"] = nics

        # NetworkHardware
        nic_hw = []
        for n in c.Win32_NetworkAdapter():
            if n.NetConnectionID is None:
                continue
            nic_hw.append(
                {
                    "Name": n.Name or "",
                    "Manufacturer": n.Manufacturer or "",
                    "ProductName": n.ProductName or "",
                    "NetConnectionID": n.NetConnectionID or "",
                    "Speed": n.Speed or "",
                    "AdapterType": n.AdapterType or "",
                    "MACAddress": n.MACAddress or "",
                }
            )
        data["NetworkHardware"] = nic_hw

        # Memory
        ram_sticks = []
        for m in c.Win32_PhysicalMemory():
            ff_code = int(m.FormFactor) if m.FormFactor is not None else 0
            mt_code = int(m.SMBIOSMemoryType) if m.SMBIOSMemoryType is not None else 0
            ram_sticks.append(
                {
                    "BankLabel": m.BankLabel or "",
                    "Capacity": int(m.Capacity or 0),
                    "Speed": int(m.Speed or 0),
                    "Manufacturer": m.Manufacturer or "",
                    "PartNumber": (m.PartNumber or "").strip(),
                    "ConfiguredClockSpeed": int(m.ConfiguredClockSpeed or 0),
                    "FormFactor": _ff_map.get(ff_code, str(ff_code)),
                    "MemoryType": _mem_type_map.get(mt_code, str(mt_code)),
                    "DataWidth": int(m.DataWidth or 0),
                    "DeviceLocator": m.DeviceLocator or "",
                }
            )
        data["Memory"] = ram_sticks

        # MemoryArray (backlog #43, hardware upgrade analyser).
        # Win32_PhysicalMemoryArray exposes the *board's* limits -- max
        # capacity it can hold and how many DIMM slots it has. Without this,
        # we can only show "you have N DIMMs" -- with it, we can answer
        # "you have N of M DIMMs and X GB of headroom". On most modern
        # systems there's exactly one array (the main memory complex);
        # rare server boards expose multiple arrays which we list separately
        # so the upgrade summariser can decide which array a new DIMM goes in.
        # MaxCapacity caveat: Dell/HP firmware sometimes caps this to the
        # originally-shipped config rather than the chipset's true max --
        # we surface the WMI value as-is and let summarize_upgrades flag it
        # with a "verify against board manual" note.
        mem_arrays = []
        for a in c.Win32_PhysicalMemoryArray():
            # MaxCapacity is in KB on most systems but spec allows it to be
            # signalled via MaxCapacityEx (uint64) when the value exceeds
            # 2 TB. Prefer Ex when present and non-zero.
            max_kb = 0
            try:
                ex = int(a.MaxCapacityEx or 0)
                max_kb = ex if ex > 0 else int(a.MaxCapacity or 0)
            except (AttributeError, ValueError, TypeError):
                # MaxCapacityEx isn't on every WMI provider -- swallow and
                # fall back to MaxCapacity. The .get-style access on a WMI
                # COM object raises rather than returning None.
                try:
                    max_kb = int(a.MaxCapacity or 0)
                except (ValueError, TypeError):
                    max_kb = 0
            ec_code = int(a.MemoryErrorCorrection) if a.MemoryErrorCorrection is not None else 0
            mem_arrays.append(
                {
                    "MaxCapacityGB": round(max_kb / (1024 * 1024), 1) if max_kb else 0,
                    "MemoryDevices": int(a.MemoryDevices or 0),
                    "MemoryErrorCorrection": _mem_ec_map.get(ec_code, str(ec_code)),
                    "Location": _mem_loc_map.get(int(a.Location) if a.Location is not None else 0, "Unknown"),
                }
            )
        data["MemoryArray"] = mem_arrays

        # Disks
        disks = []
        for d in c.Win32_DiskDrive():
            disks.append(
                {
                    "Model": d.Model or "",
                    "Size": int(d.Size or 0),
                    "InterfaceType": d.InterfaceType or "",
                    "MediaType": d.MediaType or "",
                    "SerialNumber": (d.SerialNumber or "").strip(),
                    "Partitions": int(d.Partitions or 0),
                }
            )
        data["Disks"] = disks

        # Volumes (local fixed disks)
        volumes = []
        for v in c.Win32_LogicalDisk(DriveType=3):
            size_bytes = int(v.Size or 0)
            free_bytes = int(v.FreeSpace or 0)
            volumes.append(
                {
                    "DeviceID": v.DeviceID or "",
                    "VolumeName": v.VolumeName or "",
                    "FileSystem": v.FileSystem or "",
                    "SizeGB": round(size_bytes / (1024**3), 1) if size_bytes else 0,
                    "FreeGB": round(free_bytes / (1024**3), 1) if free_bytes else 0,
                }
            )
        data["Volumes"] = volumes

        # Sound
        sounds = []
        for s in c.Win32_SoundDevice():
            sounds.append(
                {
                    "Name": s.Name or "",
                    "Manufacturer": s.Manufacturer or "",
                    "Status": s.Status or "",
                }
            )
        data["Sound"] = sounds

        # USB Controllers
        usb_ctrls = []
        for u in c.Win32_USBController():
            usb_ctrls.append(
                {
                    "Name": u.Name or "",
                    "Manufacturer": u.Manufacturer or "",
                    "Status": u.Status or "",
                }
            )
        data["USBControllers"] = usb_ctrls

        # PCIe Slots
        slots = []
        for sl in c.Win32_SystemSlot():
            usage_code = int(sl.CurrentUsage) if sl.CurrentUsage is not None else 2
            slots.append(
                {
                    "SlotDesignation": sl.SlotDesignation or "",
                    "CurrentUsage": _slot_usage_map.get(usage_code, str(usage_code)),
                    "Status": sl.Status or "",
                    "Description": sl.Description or "",
                }
            )
        data["PCIeSlots"] = slots
        return data

    from windesktopmgr import bounded_wmi_query  # lazy: wdm-resident, breaks import cycle

    data = bounded_wmi_query(_wmi_work, timeout_s=15.0, fallback=None, label="sysinfo WMI")
    if data is None:
        # Timed out or COM-faulted -- mark stale like the old except did.
        data = {}
        stale = True
        error_detail = "WMI/SCM unavailable (timed out or faulted)"

    # Upgrade opportunities (#43). Computed from the inventory we just
    # collected so the UI gets one round-trip's worth of data instead of
    # two. Empty list when sysinfo collection failed -- callers shouldn't
    # have to special-case that.
    try:
        upgrades = summarize_upgrades(data)
    except Exception:
        # Defensive: a bug in the synthesiser must NEVER take down the
        # /api/sysinfo/data route. The hardware inventory is the
        # primary value here; upgrades is a derived bonus.
        upgrades = {"opportunities": []}

    return {
        "status": "partial" if stale else "ok",
        "data": data,
        "collected_at": collected_at,
        "stale": stale,
        "error": error_detail,
        "upgrades": upgrades,
    }


def summarize_sysinfo(data: dict) -> dict:
    """Summarize system info for the summary banner."""
    insights = []
    actions = []
    status = "ok"

    # Handle empty / stale data
    if not data or all(not data.get(k) for k in ("Computer", "OS", "CPU")):
        return {
            "status": "warning",
            "headline": "System info unavailable",
            "insights": [
                {
                    "level": "warning",
                    "text": "Data collection failed or returned empty",
                    "detail": "PowerShell/WMI may not be responding.",
                }
            ],
            "actions": ["Refresh the System Info tab or check PowerShell connectivity"],
        }

    comp = data.get("Computer", {})
    os_info = data.get("OS", {})
    cpu = data.get("CPU", {})

    # Uptime check
    uptime_str = os_info.get("Uptime", "")
    if uptime_str:
        try:
            days = int(uptime_str.split(".")[0])
            if days > 14:
                status = "warning"
                insights.append(
                    {
                        "level": "warning",
                        "text": f"System uptime is {days} days",
                        "detail": "Consider rebooting periodically for stability and updates.",
                    }
                )
                actions.append("Reboot the system to apply pending updates and clear memory leaks")
            elif days > 7:
                insights.append(
                    {
                        "level": "info",
                        "text": f"System uptime is {days} days",
                        "detail": "Moderate uptime — fine for most workloads.",
                    }
                )
        except (ValueError, IndexError):
            pass

    # RAM check
    ram_gb = comp.get("TotalRAM_GB", 0)
    if ram_gb and ram_gb < 16:
        status = "warning"
        insights.append(
            {
                "level": "warning",
                "text": f"Only {ram_gb} GB RAM installed",
                "detail": "16 GB is recommended minimum for modern workloads.",
            }
        )
    elif ram_gb:
        insights.append({"level": "ok", "text": f"{ram_gb} GB RAM installed", "detail": ""})

    # Memory type insight
    mem_sticks = data.get("Memory", [])
    if mem_sticks:
        mem_types = set(m.get("MemoryType", "") for m in mem_sticks if m.get("MemoryType"))
        mem_type_str = ", ".join(sorted(mem_types)) if mem_types else "Unknown"
        speeds = [m.get("ConfiguredClockSpeed", 0) for m in mem_sticks if m.get("ConfiguredClockSpeed")]
        speed_str = f" @ {max(speeds)} MHz" if speeds else ""
        if "DDR5" in mem_types:
            insights.append(
                {
                    "level": "ok",
                    "text": f"{mem_type_str}{speed_str} — {len(mem_sticks)} DIMM(s)",
                    "detail": "Latest generation memory",
                }
            )
        elif "DDR4" in mem_types:
            insights.append(
                {
                    "level": "info",
                    "text": f"{mem_type_str}{speed_str} — {len(mem_sticks)} DIMM(s)",
                    "detail": "Previous generation — still widely supported",
                }
            )
        else:
            insights.append(
                {
                    "level": "info",
                    "text": f"Memory: {mem_type_str}{speed_str} — {len(mem_sticks)} DIMM(s)",
                    "detail": "",
                }
            )

    # CPU info
    cpu_name = cpu.get("Name", "Unknown")
    cores = cpu.get("Cores", 0)
    logical = cpu.get("LogicalProcs", 0)
    if cpu_name != "Unknown":
        insights.append(
            {"level": "ok", "text": f"{cpu_name}", "detail": f"{cores} cores / {logical} logical processors"}
        )

    # GPU info with manufacturer
    gpus = data.get("GPU", [])
    for gpu in gpus:
        gpu_name = gpu.get("Name", "Unknown GPU")
        gpu_mfr = gpu.get("AdapterCompatibility", "")
        vram = gpu.get("AdapterRAM", 0)
        vram_str = f" — {round(vram / (1024**3), 1)} GB VRAM" if vram and vram > 0 else ""
        prefix = f"{gpu_mfr} " if gpu_mfr and gpu_mfr not in gpu_name else ""
        insights.append(
            {
                "level": "ok",
                "text": f"{prefix}{gpu_name}{vram_str}",
                "detail": f"Driver: {gpu.get('DriverVersion', 'N/A')}",
            }
        )

    # OS info
    os_name = os_info.get("Name", "")
    if os_name:
        insights.append(
            {
                "level": "ok",
                "text": os_name,
                "detail": f"Build {os_info.get('Build', '')} — installed {os_info.get('InstallDate', '')}",
            }
        )

    # Sound devices
    sound = data.get("Sound", [])
    if sound:
        names = [s.get("Name", "?") for s in sound[:3]]
        insights.append({"level": "ok", "text": f"{len(sound)} audio device(s)", "detail": ", ".join(names)})

    # NIC hardware
    nic_hw = data.get("NetworkHardware", [])
    if nic_hw:
        nic_names = [n.get("Manufacturer", n.get("Name", "?")) for n in nic_hw[:3]]
        insights.append({"level": "ok", "text": f"{len(nic_hw)} network adapter(s)", "detail": ", ".join(nic_names)})

    headline = f"{comp.get('Manufacturer', '')} {comp.get('Model', '')} — {cpu_name}".strip()

    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ── Upgrade-analyser helpers (#43 follow-up) ──────────────────────────────────
# Pure helpers used by summarize_upgrades. Pulled out so each piece is
# independently testable and so the summariser body stays readable as it
# grows past the original three categories.


def _jedec_spec(mem_type: str, speed_mts: int) -> str:
    """Return the JEDEC marketing string for a DRAM type+speed.

    DDR5-5600 → "DDR5-5600 PC5-44800"  (speed × 8 = bandwidth in MB/s)
    DDR4-3200 → "DDR4-3200 PC4-25600"

    JEDEC's PCx- designation encodes peak transfer bandwidth in MB/s,
    which is what most module retailers print on the label. Surfacing
    both forms lets users match either the speed-MT/s or the PC-bandwidth
    string, depending on which the seller chose.
    """
    if not mem_type or not speed_mts:
        return ""
    # PC4 / PC5 generation prefix derived from DDR generation digit.
    # Anything older than DDR3 is rare enough we don't bother.
    gen_map = {"DDR3": "PC3", "DDR4": "PC4", "DDR5": "PC5"}
    prefix = gen_map.get(mem_type)
    if not prefix:
        return f"{mem_type}-{speed_mts}"
    bandwidth_mbs = speed_mts * 8
    return f"{mem_type}-{speed_mts} {prefix}-{bandwidth_mbs}"


def _mem_voltage(mem_type: str) -> str:
    """Nominal DIMM voltage for a memory generation. Helps users avoid
    accidentally buying high-voltage XMP/EXPO kits when their board only
    supports JEDEC voltages (or vice versa).
    """
    return {"DDR3": "1.5 V (1.35 V low-voltage variants)", "DDR4": "1.2 V (1.35 V XMP)", "DDR5": "1.1 V"}.get(
        mem_type, ""
    )


# Static chipset → max-RAM lookup. Two reasons we need this on top of
# WMI's Win32_PhysicalMemoryArray.MaxCapacity:
#   1. OEM firmware (Dell, HP) often reports a lower MaxCapacity than the
#      chipset can technically handle, because the BIOS hardcodes the
#      "validated" config rather than the chipset spec ceiling.
#   2. The user explicitly asked: "I would expect that the code will
#      check these things for me instead of me having to go check"
#      (re: the "verify against your board's QVL" caveat).
#
# Sources: Intel ARK (ark.intel.com) and AMD product pages, accurate as
# of 2026-05. Numbers are GB. Update when a new chipset generation
# launches; missing entries fall back to "WMI value is the only source".
_CHIPSET_MAX_RAM_GB = {
    # Intel 600/700-series desktop (12th/13th/14th gen Core)
    "Z790": 192,
    "H770": 192,
    "B760": 192,
    "H710": 64,
    "Z690": 128,
    "H670": 128,
    "B660": 128,
    "H610": 64,
    # AMD AM5 (Ryzen 7000/8000/9000)
    "X870E": 256,
    "X870": 256,
    "B850": 256,
    "B840": 256,
    "X670E": 256,
    "X670": 256,
    "B650E": 256,
    "B650": 256,
    "A620": 192,
    # AMD AM4 (Ryzen 1000-5000) -- DDR4 era, lower ceilings
    "X570": 128,
    "B550": 128,
    "A520": 128,
    "X470": 64,
    "B450": 64,
    # Intel 500-series desktop (10th/11th gen)
    "Z590": 128,
    "H570": 128,
    "B560": 128,
    "H510": 64,
}


def _infer_chipset(cpu_name: str, mem_type: str) -> str | None:
    """Best-effort chipset inference from CPU model + memory type.

    WMI doesn't expose the chipset directly on most consumer hardware
    (Win32_BaseBoard.Product is the board *model*, not the chipset).
    We infer from the CPU generation + memory generation:

      Intel 12th-14th gen + DDR5 → Z790 (or H770/B760, but Z790 is the
        most common in pre-built towers; the user can ignore the
        chipset name and trust the GB figure since they're all 192).
      Intel 12th-14th gen + DDR4 → Z690-class (128 GB DDR4 max)
      AMD Ryzen 7000-9000 → X670E-class (256 GB DDR5 max)
      AMD Ryzen 1000-5000 → X570-class (128 GB DDR4 max)

    Returns the chipset *family label* (which keys into _CHIPSET_MAX_RAM_GB),
    or None when we can't infer with confidence (Apple Silicon, ARM, etc.).
    """
    name = (cpu_name or "").lower()
    mt = (mem_type or "").upper()

    # Intel: parse the generation digit from "Core(TM) iN-XXNNN..."
    # e.g. i9-14900K -> "14" -> 14th gen. K-suffix -> Z-series likely.
    intel = "intel" in name and "core" in name
    if intel:
        import re as _re

        m = _re.search(r"i\d-(\d{2})\d{3}", name)
        gen = int(m.group(1)) if m else None
        if gen is not None:
            if gen >= 12 and "DDR5" in mt:
                return "Z790"
            if gen >= 12 and "DDR4" in mt:
                return "Z690"
            if 10 <= gen < 12:
                return "Z590"

    # AMD Ryzen: "Ryzen 9 7950X" -> generation 7000-series. Lookahead
    # for non-digit (or string end) instead of \b because the X / X3D /
    # G suffixes are word characters that defeat the trailing \b.
    if "ryzen" in name:
        import re as _re

        m = _re.search(r"\b([3-9])\d{3}(?=\D|$)", name)
        if m:
            gen = int(m.group(1))
            if gen >= 7 and "DDR5" in mt:
                return "X670E"
            if 1 <= gen <= 5:
                return "X570"

    return None


def _crucial_advisor_url(baseboard: dict) -> tuple[str, str] | None:
    """Deep-link to Crucial's compatibility tool for the user's machine.

    Crucial Memory Advisor is the de-facto industry standard for "what
    RAM works in this exact machine?" -- they've maintained it since
    the 90s and their compatibility data is more reliable than scraping
    OEM QVL pages. URL pattern verified against live crucial.com:

        https://www.crucial.com/compatible-upgrade-for/{vendor}/{model}

    where {vendor} is e.g. "dell" and {model} is the marketing name with
    spaces → hyphens, lowercased. We have BaseBoard.Product but that's
    typically the internal board ID (e.g. "0WN7Y6") not the marketing
    model. ComputerSystem.Model is closer ("XPS 8960", "OptiPlex 7080")
    -- caller passes that in via the baseboard dict already.

    Returns (label, url) or None when we can't synthesise a high-
    confidence URL.
    """
    mfr = (baseboard.get("Manufacturer") or "").lower()
    # Computer model rather than baseboard product -- caller passes
    # data["Computer"]["Model"] in here for accuracy.
    model = (baseboard.get("Model") or baseboard.get("Product") or "").strip()
    if not model:
        return None
    # Slugify: lowercase, replace whitespace with hyphens, strip non-
    # alnum-hyphen chars. Crucial accepts this format.
    import re as _re

    slug = _re.sub(r"[^a-z0-9\-]", "", _re.sub(r"\s+", "-", model.lower()))
    if not slug:
        return None
    if "dell" in mfr:
        return (
            "Crucial Memory Advisor (compatible RAM SKUs for this model)",
            f"https://www.crucial.com/compatible-upgrade-for/dell/{slug}",
        )
    # Other OEMs use the same URL pattern but we haven't validated
    # against live HP / Lenovo pages yet, so be conservative.
    return None


def _oem_support_url(bios: dict, baseboard: dict) -> tuple[str, str] | None:
    """Build a deep-link to the OEM's support page for this exact machine.

    Dell pattern (verified against live www.dell.com):
        https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers
    Service tag comes from Win32_BIOS.SerialNumber on Dell hardware.

    Other OEMs (HP, Lenovo) use different URL schemes and we don't have
    a sample machine to validate against right now -- returning None
    keeps the UI honest ("Verify with your board's manual") rather than
    handing the user a 404. If we add a Lenovo / HP machine later, this
    is the one place to extend.

    Returns a (label, url) tuple or None. Label is what the UI shows on
    the link button.
    """
    mfr = ((bios.get("Manufacturer") or "") + " " + (baseboard.get("Manufacturer") or "")).lower()
    serial = (bios.get("SerialNumber") or "").strip()
    if "dell" in mfr and serial and serial != "0":
        return (
            "Dell support page (this machine)",
            f"https://www.dell.com/support/home/en-us/product-support/servicetag/{serial}/drivers",
        )
    return None


def _slot_numeric_index(designation: str) -> int | None:
    """Extract the trailing numeric suffix from a slot designation.

    SLOT1 → 1   PCIEX16_2 → 2   PCI Express x4-3 → 3
    Returns None when no recognisable suffix is present (e.g. "M.2 WLAN").
    Used by _estimate_gpu_blocked_slots to walk slots in physical order.
    """
    import re as _re

    m = _re.search(r"(\d+)\s*$", designation or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except (ValueError, TypeError):
        return None


def _estimate_gpu_blocked_slots(slots: list, gpus: list) -> list[str]:
    """Find PCIe slots likely physically blocked by the GPU's cooler.

    User feedback 2026-05-02: "for the PCIe slots - for the GPU card,
    I believe it is physically covering one of the slots so we should
    validate that we have that many." Discrete GPUs are typically
    dual-slot (sometimes 2.5- or 3-slot) -- the cooler shroud extends
    below the card and physically blocks the next slot down even though
    that slot reports CurrentUsage=Available to WMI (no electrical
    connection ≠ physically usable).

    Heuristic (deliberately conservative):
      1. We need at least one discrete GPU (gpus list non-empty AND not
         all entries look like integrated graphics).
      2. We find the lowest-numbered "In Use" PCIe slot whose designation
         starts with SLOT or PCIEX (the typical x16 GPU home).
      3. The next sequential numeric slot, if it exists and is
         "Available", is flagged as potentially blocked.

    This will under-report on triple-slot GPUs (they block 2 slots, we
    only flag 1) and may over-report when the GPU is a single-slot
    workstation card. Both are acceptable failure modes -- the UI
    surfaces it as a *caveat* ("verify with the side panel off"), not
    a hard claim, so the user makes the final call.

    Returns the list of slot designations to flag.
    """
    if not slots or not gpus:
        return []

    # Filter out integrated graphics. Any GPU whose name or AdapterCompatibility
    # mentions "Intel HD/UHD/Iris" or "AMD Radeon Graphics" (no Vega/RX prefix)
    # is integrated -- doesn't occupy a PCIe slot.
    discrete = []
    for g in gpus:
        name = (g.get("Name") or "").lower()
        compat = (g.get("AdapterCompatibility") or "").lower()
        is_integrated = ("intel" in compat and any(t in name for t in ("hd graphics", "uhd graphics", "iris"))) or (
            compat == "advanced micro devices"
            and "radeon graphics" in name
            and not any(t in name for t in ("rx ", "vega"))
        )
        if not is_integrated:
            discrete.append(g)
    if not discrete:
        return []

    # Find the GPU's likely home slot: lowest-numbered "In Use" slot whose
    # designation looks like a PCIe slot (SLOT/PCIEX prefix).
    pcie_slot_designations = []
    for s in slots:
        desg = (s.get("SlotDesignation") or "").upper()
        if not desg.startswith(("SLOT", "PCIEX", "PCI EXPRESS")):
            continue
        idx = _slot_numeric_index(desg)
        if idx is None:
            continue
        pcie_slot_designations.append((idx, s))
    pcie_slot_designations.sort(key=lambda t: t[0])

    in_use_indices = [idx for idx, s in pcie_slot_designations if (s.get("CurrentUsage") or "").lower() == "in use"]
    if not in_use_indices:
        return []
    gpu_home_idx = min(in_use_indices)

    # Flag the slot directly after the GPU's home if it's Available.
    blocked = []
    for idx, s in pcie_slot_designations:
        if idx == gpu_home_idx + 1 and (s.get("CurrentUsage") or "").lower() == "available":
            blocked.append(s.get("SlotDesignation") or "")
    return [b for b in blocked if b]


def summarize_upgrades(data: dict) -> dict:
    """Walk the system-info inventory and surface upgrade opportunities.

    Backlog #43 (hardware upgrade analyser). Six categories:

    * **memory** -- compares populated DIMMs against board capacity
      (Win32_PhysicalMemoryArray.MaxCapacity + .MemoryDevices). Reports
      free slots, RAM headroom, and -- when only one DIMM is installed --
      a single-channel-mode warning since dual-channel doubles bandwidth
      and is free if you've already got a second matching stick lying
      around. Each opportunity carries `compat` (JEDEC spec, voltage,
      reference PartNumber) and an OEM support `links` entry when the
      board manufacturer is recognised.
    * **cpu** -- always emitted when SocketDesignation is non-empty,
      since "is this CPU upgradeable?" is a question the inventory CAN
      answer (the socket family is the gate). Carries the socket
      designation as `compat`; the user / OEM page tells them which
      specific CPUs are supported (BIOS revision matters).
    * **gpu** -- when a free PCIe x16 slot exists, flag GPU upgrade
      capacity. Caveats include PSU wattage (which we can't detect
      from software) and physical case clearance.
    * **nic** -- two flavours: (a) Wi-Fi when an M.2 WLAN slot is
      Available, (b) wired when a free PCIe x1+ slot exists.
    * **pcie** -- the catch-all for "you have N free slots". Subtracts
      slots likely physically blocked by the GPU's cooler (heuristic
      via _estimate_gpu_blocked_slots) and surfaces those as a caveat
      so the headline count matches reality, not WMI's electrical
      view. Each slot's `compat` carries the gen + lane width parsed
      from the WMI Description.
    * **storage** -- counts physical disks by interface type. Doesn't
      attempt to enumerate empty SATA/M.2 ports (Win32 has no clean
      surface for that), but DOES surface "you have N spinning-rust
      drives" as a candidate for SSD migration.

    Each opportunity has a stable shape so the UI can render them
    uniformly:
        category   -- "memory" | "cpu" | "gpu" | "nic" | "pcie" | "storage"
        severity   -- "ok" | "info" | "warning"
        headline   -- one-line summary (shown bold on the card)
        detail     -- multi-line context
        action     -- imperative next step (shown as the card's CTA)
        compat     -- list of {"label","value"} structured spec rows
                      (optional; UI renders as a definition list)
        caveats    -- list of strings (optional; UI renders as warning
                      lines below detail)
        links      -- list of {"label","url"} pairs (optional; UI renders
                      as small link buttons next to action)

    The function is pure -- no I/O, no globals -- so it's trivially
    testable. Empty/missing data returns ``{"opportunities": []}`` rather
    than raising, so a partial sysinfo collection (WMI flake) still
    renders a clean panel instead of a JS error.
    """
    opportunities = []
    bios = data.get("BIOS", {}) or {}
    baseboard = data.get("Baseboard", {}) or {}
    computer = data.get("Computer", {}) or {}
    cpu = data.get("CPU", {}) or {}
    oem_link = _oem_support_url(bios, baseboard)
    # Crucial Advisor wants the user-friendly machine model, which lives
    # on Win32_ComputerSystem.Model not Win32_BaseBoard.Product. Pass it
    # through the baseboard dict shape that _crucial_advisor_url expects.
    crucial_link = _crucial_advisor_url(
        {"Manufacturer": baseboard.get("Manufacturer", ""), "Model": computer.get("Model", "")}
    )

    # ── Memory ────────────────────────────────────────────────────────
    mem_sticks = data.get("Memory", []) or []
    mem_arrays = data.get("MemoryArray", []) or []
    installed_bytes = sum(int(m.get("Capacity") or 0) for m in mem_sticks)
    installed_gb = round(installed_bytes / (1024**3), 1) if installed_bytes else 0
    populated_slots = len([m for m in mem_sticks if int(m.get("Capacity") or 0) > 0])
    total_slots = sum(int(a.get("MemoryDevices") or 0) for a in mem_arrays)
    max_capacity_gb = sum(float(a.get("MaxCapacityGB") or 0) for a in mem_arrays)
    free_slots = max(0, total_slots - populated_slots) if total_slots else 0
    headroom_gb = round(max_capacity_gb - installed_gb, 1) if max_capacity_gb else 0

    mem_types = sorted({m.get("MemoryType", "") for m in mem_sticks if m.get("MemoryType")})
    mem_type_str = "/".join(mem_types) if mem_types else "Unknown type"
    primary_mem_type = mem_types[0] if mem_types else ""
    speeds = [int(m.get("ConfiguredClockSpeed") or 0) for m in mem_sticks if m.get("ConfiguredClockSpeed")]
    primary_speed = max(speeds) if speeds else 0
    speed_str = f"-{primary_speed}" if primary_speed else ""
    form_factors = sorted({m.get("FormFactor", "") for m in mem_sticks if m.get("FormFactor")})
    form_str = "/".join(form_factors) if form_factors else ""
    part_numbers = sorted(
        {(m.get("PartNumber") or "").strip() for m in mem_sticks if (m.get("PartNumber") or "").strip()}
    )
    ec_str = ""
    if mem_arrays:
        ec_str = (mem_arrays[0].get("MemoryErrorCorrection") or "").strip()

    largest_stick_gb = 0
    if mem_sticks:
        biggest = max((int(m.get("Capacity") or 0) for m in mem_sticks), default=0)
        largest_stick_gb = round(biggest / (1024**3), 1) if biggest else 0

    # Per-slot max -- the constraint the user actually has to respect
    # when buying sticks. If the board reports 64 GB max with 2 slots,
    # each slot tops out at 32 GB. User feedback 2026-05-02: "I would
    # expect that the code will check these things for me instead of me
    # having to go check" -- so we compute and surface this directly
    # rather than punting to the user with "verify against the QVL".
    per_slot_max_gb = 0
    if total_slots and max_capacity_gb:
        per_slot_max_gb = round(max_capacity_gb / total_slots, 1)

    # Chipset cross-check. WMI's MaxCapacity is the *board's* value (often
    # capped by Dell/HP firmware to the validated config). The chipset
    # itself usually supports much more. Surfacing both numbers tells the
    # user when their board is the bottleneck vs when they're already at
    # the chipset ceiling.
    chipset = _infer_chipset(cpu.get("Name", ""), primary_mem_type)
    chipset_max_gb = _CHIPSET_MAX_RAM_GB.get(chipset, 0) if chipset else 0
    chipset_exceeds_board = chipset_max_gb and max_capacity_gb and chipset_max_gb > max_capacity_gb

    # Build the structured `compat` block once -- used by every memory
    # opportunity so the user gets the same exact-spec guidance whether
    # the recommendation is "add sticks" or "replace sticks".
    def _mem_compat() -> list:
        rows = []
        if primary_mem_type:
            jedec = _jedec_spec(primary_mem_type, primary_speed)
            if jedec:
                rows.append({"label": "JEDEC spec", "value": jedec})
        if form_str:
            rows.append({"label": "Form factor", "value": form_str})
        if primary_mem_type:
            v = _mem_voltage(primary_mem_type)
            if v:
                rows.append({"label": "Voltage", "value": v})
        if ec_str:
            rows.append({"label": "ECC", "value": ec_str})
        if part_numbers:
            rows.append({"label": "Reference part #", "value": ", ".join(part_numbers)})
        if largest_stick_gb:
            rows.append({"label": "Per-stick capacity (matched)", "value": f"{int(largest_stick_gb)} GB"})
        # New (#43 follow-up #2): expose what the code checked rather
        # than hand-waving "verify against the QVL".
        if total_slots:
            rows.append({"label": "Board DIMM slots", "value": f"{populated_slots} populated / {total_slots} total"})
        if per_slot_max_gb:
            rows.append(
                {"label": "Max stick size (per slot)", "value": f"{per_slot_max_gb:g} GB (= board max ÷ slot count)"}
            )
        if chipset and chipset_max_gb:
            note = (
                f"{chipset_max_gb} GB"
                if not chipset_exceeds_board
                else f"{chipset_max_gb} GB (chipset supports more than the board reports -- slot-count cap likely)"
            )
            rows.append({"label": f"Chipset ceiling ({chipset})", "value": note})
        return rows

    def _mem_caveats() -> list:
        """Caveats that explain what we DID check -- and call out the
        remaining unknowns -- rather than punting everything to the QVL."""
        notes = []
        # Always-true caveat about XMP/EXPO since we can't detect XMP profiles
        if primary_mem_type in ("DDR4", "DDR5"):
            notes.append(
                "XMP/EXPO profiles run at higher voltages (1.35-1.4 V) than JEDEC. "
                "Auto-detection only -- XMP capability is a board feature, not surfaced via WMI."
            )
        # If chipset detection succeeded but board caps lower, explain why
        if chipset_exceeds_board:
            notes.append(
                f"Your board reports {max_capacity_gb:g} GB max but the {chipset} chipset itself "
                f"supports {chipset_max_gb} GB. The lower number is usually a slot-count cap "
                f"({total_slots} slots × {per_slot_max_gb:g} GB per slot = {max_capacity_gb:g} GB), "
                "not a Dell/HP firmware lockout. To exceed it you'd need a different board, not just bigger sticks."
            )
        # Crucial pre-filtered SKU list is the closest thing to a "QVL
        # check" we can offer programmatically -- surface it as the
        # action item rather than handing the user a generic "verify the QVL".
        if crucial_link:
            notes.append(
                "The Crucial Memory Advisor link below shows specific module SKUs Crucial has "
                "validated against your model -- treat that as the authoritative compatibility list."
            )
        return notes

    def _oem_link_list() -> list:
        # Memory opportunities get TWO links: the Dell support page (full
        # product docs) and the Crucial Advisor (the actual SKU list).
        # Crucial first since it directly answers "what RAM can I buy?"
        links = []
        if crucial_link:
            links.append({"label": crucial_link[0], "url": crucial_link[1]})
        if oem_link:
            links.append({"label": oem_link[0], "url": oem_link[1]})
        return links

    def _oem_link_list_only() -> list:
        """For non-memory opportunities (CPU, NIC) where the OEM support
        page is the right destination but Crucial is irrelevant."""
        return [{"label": oem_link[0], "url": oem_link[1]}] if oem_link else []

    if total_slots and free_slots > 0 and headroom_gb > 0:
        spec = f"{mem_type_str}{speed_str} {form_str}".strip()
        suggest_size = f"{int(largest_stick_gb)} GB" if largest_stick_gb else "16 GB"
        opportunities.append(
            {
                "category": "memory",
                "severity": "info",
                "headline": (
                    f"Add up to {headroom_gb:g} GB more RAM "
                    f"({free_slots} of {total_slots} DIMM slot{'s' if free_slots != 1 else ''} free)"
                ),
                "detail": (
                    f"You have {installed_gb:g} GB across {populated_slots} of {total_slots} slots. "
                    f"Board reports max capacity {max_capacity_gb:g} GB. "
                    f"Match your existing {spec} sticks "
                    f"(suggested: {free_slots} × {suggest_size})."
                ),
                "action": f"Buy {free_slots} × {suggest_size} {spec} matching your existing PartNumber",
                "compat": _mem_compat(),
                "caveats": _mem_caveats(),
                "links": _oem_link_list(),
            }
        )
    elif total_slots and free_slots == 0 and headroom_gb > 0:
        opportunities.append(
            {
                "category": "memory",
                "severity": "info",
                "headline": f"Up to {headroom_gb:g} GB more RAM possible (requires replacing existing sticks)",
                "detail": (
                    f"All {total_slots} DIMM slots are populated with {installed_gb:g} GB. "
                    f"Board reports max capacity {max_capacity_gb:g} GB, so further "
                    "expansion means swapping existing sticks for higher-density modules. "
                    f"Per-slot ceiling is {per_slot_max_gb:g} GB -- buy modules of that capacity."
                    if per_slot_max_gb
                    else (
                        f"All {total_slots} DIMM slots are populated with {installed_gb:g} GB. "
                        f"Board reports max capacity {max_capacity_gb:g} GB, so further "
                        "expansion means swapping existing sticks for higher-density modules."
                    )
                ),
                "action": f"Replace existing sticks with higher-density {mem_type_str} modules",
                "compat": _mem_compat(),
                "caveats": _mem_caveats(),
                "links": _oem_link_list(),
            }
        )
    elif total_slots and populated_slots == total_slots:
        opportunities.append(
            {
                "category": "memory",
                "severity": "ok",
                "headline": "Memory fully populated",
                "detail": f"All {total_slots} DIMM slots populated; {installed_gb:g} GB at the board's reported max.",
                "action": "",
                "compat": _mem_compat(),
            }
        )

    if populated_slots == 1 and total_slots >= 2:
        opportunities.append(
            {
                "category": "memory",
                "severity": "warning",
                "headline": "Running in single-channel mode",
                "detail": (
                    "Only 1 DIMM is populated. Adding a second matching stick "
                    "(same capacity, speed, and ideally same PartNumber) enables "
                    "dual-channel mode -- roughly 2× memory bandwidth at zero CPU cost. "
                    "Most noticeable on integrated graphics, video editing, and "
                    "memory-heavy workloads."
                ),
                "action": f"Add 1 matching DIMM to bring the system to dual-channel ({installed_gb:g} GB → {installed_gb * 2:g} GB)",
                "compat": _mem_compat(),
                "links": _oem_link_list(),
            }
        )

    # ── CPU ───────────────────────────────────────────────────────────
    # Always emit when SocketDesignation is non-empty: "is this socket
    # upgradeable" is a question the inventory CAN answer (the socket
    # family is the gate). The OEM page lists the specific CPUs supported
    # at each BIOS revision, which is too dynamic to bake in here.
    cpu = data.get("CPU", {}) or {}
    socket = (cpu.get("SocketDesignation") or "").strip()
    if socket:
        cpu_compat = [{"label": "Socket", "value": socket}]
        if cpu.get("Architecture"):
            cpu_compat.append({"label": "Architecture", "value": cpu["Architecture"]})
        if cpu.get("Cores") and cpu.get("LogicalProcs"):
            cpu_compat.append(
                {
                    "label": "Current",
                    "value": f"{cpu.get('Name', '').strip()} -- {cpu['Cores']} cores / {cpu['LogicalProcs']} threads",
                }
            )
        opportunities.append(
            {
                "category": "cpu",
                "severity": "info",
                "headline": f"CPU is socketed ({socket}) -- upgrade possible within socket family",
                "detail": (
                    "Desktop CPUs in a standard socket can typically be swapped without "
                    "replacing the board, as long as the new chip is on the same socket "
                    "AND your board's chipset/BIOS supports it. The OEM CPU support list "
                    "is the authoritative source for what your specific board accepts at "
                    "what BIOS revision -- a BIOS update is sometimes required before a "
                    "newer CPU will POST."
                ),
                "action": f"Pick a CPU in the {socket} family from your board's CPU support list",
                "compat": cpu_compat,
                "caveats": [
                    "BIOS update may be required before a newer-generation CPU will POST.",
                    "Cooler compatibility -- some sockets use a different mounting pattern across generations.",
                    "Power delivery -- a high-TDP chip may exceed what your board's VRM can sustain.",
                ],
                "links": _oem_link_list_only(),
            }
        )

    # ── PCIe (with GPU-blocked-slot heuristic) ────────────────────────
    pcie_slots = data.get("PCIeSlots", []) or []
    gpus = data.get("GPU", []) or []
    free_pcie = [s for s in pcie_slots if (s.get("CurrentUsage") or "").lower() == "available"]
    blocked_designations = _estimate_gpu_blocked_slots(pcie_slots, gpus)

    # WLAN and M.2-SSD slots are NOT general-purpose PCIe slots. WLAN
    # slots are E-key 2230 sockets that only accept Wi-Fi modules; M.2
    # SSD slots are M-key 2280 sockets that only accept NVMe drives.
    # Both are reported as Win32_SystemSlot rows on most boards but
    # neither will accept a typical expansion card (NIC, capture card,
    # GPU, HBA). Live-verify on real hardware (2026-05-02) caught the
    # regression where M.2 WLAN was being surfaced as "1 of 6 PCIe slots
    # physically usable" -- misleading. WLAN gets its own NIC-Wi-Fi
    # opportunity; M.2 SSD upgrades get tracked under storage. The
    # catch-all PCIe + wired-NIC paths exclude both.
    def _is_wlan_slot(s: dict) -> bool:
        desg = (s.get("SlotDesignation") or "").upper()
        return any(tok in desg for tok in ("WLAN", "WI-FI", "WIFI"))

    def _is_storage_only_slot(s: dict) -> bool:
        desg = (s.get("SlotDesignation") or "").upper()
        # M.2 PCIe SSD slots, M.2 NVMe slots, etc.
        return "M.2" in desg and any(tok in desg for tok in ("SSD", "NVME", "STORAGE"))

    truly_free = [
        s
        for s in free_pcie
        if s.get("SlotDesignation") not in blocked_designations
        and not _is_wlan_slot(s)
        and not _is_storage_only_slot(s)
    ]
    general_pcie_slots = [s for s in pcie_slots if not _is_wlan_slot(s) and not _is_storage_only_slot(s)]
    if general_pcie_slots and truly_free:
        slot_compat = []
        for s in truly_free:
            desg = s.get("SlotDesignation", "?")
            desc = s.get("Description", "")
            slot_compat.append({"label": desg, "value": desc or "PCIe slot"})

        caveats = []
        if blocked_designations:
            caveats.append(
                f"Slot{'s' if len(blocked_designations) != 1 else ''} "
                f"{', '.join(blocked_designations)} report{'s' if len(blocked_designations) == 1 else ''} "
                "Available to WMI but may be physically blocked by the GPU's cooler "
                "(typical for dual-slot discrete cards). Verify with the side panel off."
            )
        opportunities.append(
            {
                "category": "pcie",
                "severity": "info",
                "headline": (
                    f"{len(truly_free)} of {len(general_pcie_slots)} general PCIe slot{'s' if len(general_pcie_slots) != 1 else ''} "
                    f"physically usable"
                    + (f" ({len(blocked_designations)} likely blocked by GPU)" if blocked_designations else "")
                ),
                "detail": (
                    "Match the card's lane requirement (x1 / x4 / x16) to a slot of equal "
                    "or greater width. Slot generation (PCIe 3.0 / 4.0 / 5.0) caps the "
                    "card's bandwidth -- a PCIe 5.0 card in a PCIe 3.0 slot still works, "
                    "just at lower throughput. M.2 WLAN and M.2 SSD slots are tracked "
                    "separately under NIC and storage."
                ),
                "action": "Pick the right slot for the card's lane width and generation",
                "compat": slot_compat,
                "caveats": caveats,
            }
        )

    # ── GPU upgrade ───────────────────────────────────────────────────
    # Surface a GPU-upgrade opportunity when there's at least one truly-
    # free PCIe slot wide enough for a discrete GPU (x16 designation
    # match). We don't try to estimate PSU headroom from software --
    # called out as a caveat instead.
    x16_free = [s for s in truly_free if "X16" in (s.get("SlotDesignation") or "").upper().replace(" ", "")]
    # Some boards (especially Dell OEM) use SLOTn instead of PCIEX16_n.
    # Fall back to "the lowest-numbered truly-free slot whose Description
    # mentions x16" when no explicit PCIEX16 designation matches.
    if not x16_free and truly_free:
        x16_free = [s for s in truly_free if "X16" in (s.get("Description") or "").upper().replace(" ", "")]
    if x16_free and gpus:
        current_gpu = next(
            (g.get("Name", "") for g in gpus if (g.get("AdapterCompatibility") or "").lower() not in ("intel", "")), ""
        )
        if not current_gpu:
            current_gpu = gpus[0].get("Name", "")
        opportunities.append(
            {
                "category": "gpu",
                "severity": "info",
                "headline": f"GPU upgrade slot available ({len(x16_free)} free x16-class slot{'s' if len(x16_free) != 1 else ''})",
                "detail": (
                    f"Current GPU: {current_gpu or 'unknown'}. A free x16 slot can host a "
                    "newer discrete card. Two constraints WinDesktopMgr can't measure: "
                    "PSU wattage and physical case clearance. A modern high-end GPU draws "
                    "300-450 W and is 300-340 mm long, often 3 slots tall."
                ),
                "action": "Pick a card matching your PSU headroom + case length / height clearance",
                "compat": [
                    {"label": s.get("SlotDesignation", "?"), "value": s.get("Description") or "x16 slot"}
                    for s in x16_free
                ],
                "caveats": [
                    "PSU wattage isn't visible to WMI -- check the label on the side of your PSU and add up the new GPU's TGP + ~150 W headroom for CPU/board/drives.",
                    "Case clearance: measure from the back of the case to the front fan / drive cage to confirm card length fits.",
                    "Power connectors: 12VHPWR (16-pin) vs 8-pin EPS -- newer cards often need an adapter or a PSU with native 12VHPWR.",
                ],
            }
        )

    # ── NIC upgrades (Wi-Fi via M.2 WLAN, wired via free PCIe) ────────
    # Wi-Fi: if a slot is designated WLAN/Wi-Fi/WiFi and is Available,
    # surface a Wi-Fi 7 upgrade opportunity (most M.2 WLAN slots are
    # E-key 2230 -- fits Wi-Fi 6E and Wi-Fi 7 modules).
    wlan_slots = [
        s
        for s in pcie_slots
        if any(tok in (s.get("SlotDesignation") or "").upper() for tok in ("WLAN", "WI-FI", "WIFI"))
    ]
    free_wlan = [s for s in wlan_slots if (s.get("CurrentUsage") or "").lower() == "available"]
    if free_wlan:
        opportunities.append(
            {
                "category": "nic",
                "severity": "info",
                "headline": "M.2 WLAN slot empty -- Wi-Fi 7 module compatible",
                "detail": (
                    "An M.2 E-key 2230 WLAN slot is available. Modern modules "
                    "(Intel BE200, Qualcomm FastConnect 7800) drop in for Wi-Fi 7 "
                    "(802.11be) plus Bluetooth 5.4 if your motherboard has CNVio / CNVi "
                    "support and you can route the antenna cables to external connectors."
                ),
                "action": "Buy an M.2 2230 E-key Wi-Fi 7 module + verify antenna routing",
                "compat": [
                    {"label": s.get("SlotDesignation", "?"), "value": s.get("Description") or "M.2 WLAN slot"}
                    for s in free_wlan
                ],
                "caveats": [
                    "Some OEM boards lock the WLAN slot to a vendor whitelist via BIOS.",
                    "Wi-Fi 7 needs Windows 11 24H2+ for full feature support.",
                ],
                "links": _oem_link_list_only(),
            }
        )

    # Wired NIC: 10 GbE / 2.5 GbE upgrade is possible whenever any free
    # PCIe slot of x1 or wider exists. Don't fire when *only* a x16 slot
    # is free -- that's covered by the GPU opportunity, no need to
    # double-recommend the same slot for two different cards.
    non_x16_free = [s for s in truly_free if "X16" not in (s.get("SlotDesignation") or "").upper().replace(" ", "")]
    if non_x16_free:
        opportunities.append(
            {
                "category": "nic",
                "severity": "info",
                "headline": f"Free PCIe slot{'s' if len(non_x16_free) != 1 else ''} for a 2.5 GbE / 10 GbE NIC",
                "detail": (
                    "10 GbE NICs (Intel X550-T2, Aquantia AQC107) fit in any x4+ slot. "
                    "2.5 GbE NICs are widely available in x1 form factors. Worth doing "
                    "if you've got 2.5 GbE+ on your switch / NAS and your motherboard's "
                    "built-in NIC tops out at 1 GbE."
                ),
                "action": "Buy a NIC matching your switch's max negotiated speed",
                "compat": [
                    {"label": s.get("SlotDesignation", "?"), "value": s.get("Description") or "PCIe slot"}
                    for s in non_x16_free
                ],
                "caveats": [
                    "Cabling: 10 GbE over copper requires Cat6a or Cat7; Cat5e tops out at ~5 Gbps.",
                    "10 GbE NICs run hot -- verify case airflow over the slot area.",
                ],
            }
        )

    # ── Storage ───────────────────────────────────────────────────────
    disks = data.get("Disks", []) or []
    if disks:
        spinning = []
        for d in disks:
            model = (d.get("Model") or "").upper()
            iface = (d.get("InterfaceType") or "").upper()
            looks_ssd = any(tok in model for tok in ("SSD", "NVME", "M.2"))
            looks_hdd = (iface in ("IDE", "ATAPI") or "WD" in model[:4] or "SEAGATE" in model) and not looks_ssd
            if looks_hdd:
                spinning.append(d)
        if spinning:
            sizes_gb = [round(int(d.get("Size") or 0) / (1024**3)) for d in spinning]
            opportunities.append(
                {
                    "category": "storage",
                    "severity": "info",
                    "headline": f"{len(spinning)} spinning-disk drive{'s' if len(spinning) != 1 else ''} could be migrated to SSD",
                    "detail": (
                        f"Drives that look like HDDs (sizes: {', '.join(str(s) + ' GB' for s in sizes_gb)}). "
                        "SSDs are dramatically faster on random I/O (boot, app launch, indexing) "
                        "and cheaper per GB than they were two years ago. "
                        "If the HDD holds bulk media you don't read often, leave it; "
                        "if it holds OS / apps / active project files, migrate."
                    ),
                    "action": "Replace the OS/active-files HDD with an SSD; keep HDDs for bulk storage",
                    "compat": [
                        {
                            "label": "Form factor options",
                            "value": 'M.2 2280 NVMe (fastest, fewest cables) > 2.5" SATA SSD (drop-in HDD replacement)',
                        },
                    ],
                    "caveats": [
                        "M.2 NVMe needs an empty M.2 slot on the board (verify in System Info > PCIe Slots).",
                        "Cloning the OS drive: use Macrium Reflect Free or the SSD vendor's migration tool; full image, then physically swap.",
                    ],
                }
            )

    return {"opportunities": opportunities}
