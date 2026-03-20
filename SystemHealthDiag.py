#!/usr/bin/env python3
"""
Deep System Health Diagnostic Tool for Windows 11
Designed for Dell XPS 8960 / Intel i9-14900K

Requires: Run as Administrator
Usage: python SystemHealthDiag.py

No extra packages required - uses only Python standard library + PowerShell subprocess calls.
"""

import ctypes
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
import time
import winreg
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape as he
from pathlib import Path

# ============================================================
# CONSTANTS
# ============================================================
REPORT_FOLDER = r"C:\shigsapps\windesktopmgr\System Health Reports"
SCRIPT_DIR = r"C:\shigsapps\windesktopmgr"
CRED_FILE = os.path.join(SCRIPT_DIR, "diag_email_config.xml")

BUGCHECK_LOOKUP = {
    "0x0000009C": "MACHINE_CHECK_EXCEPTION - Hardware failure detected by CPU. Common with degraded Intel 13th/14th gen CPUs.",
    "0x00000124": "WHEA_UNCORRECTABLE_ERROR - Hardware error (often CPU or memory). Strongly associated with Intel voltage degradation.",
    "0x0000003B": "SYSTEM_SERVICE_EXCEPTION - Kernel-mode driver or service fault. Check recently updated drivers.",
    "0x0000000A": "IRQL_NOT_LESS_OR_EQUAL - Driver using improper memory address. Often GPU or network driver.",
    "0x0000001E": "KMODE_EXCEPTION_NOT_HANDLED - Kernel-mode program generated an exception. Check drivers.",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA - Invalid memory referenced. Can be RAM, driver, or disk issue.",
    "0x0000001A": "MEMORY_MANAGEMENT - Serious memory management error. Run memtest86.",
    "0x000000D1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL - Driver accessed pageable memory at wrong IRQL.",
    "0x00000116": "VIDEO_TDR_TIMEOUT_DETECTED - GPU driver took too long. Update or rollback GPU driver.",
    "0x00000119": "VIDEO_SCHEDULER_INTERNAL_ERROR - GPU scheduling failure. GPU driver or hardware issue.",
    "0x0000007E": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - System thread threw unhandled exception.",
    "0x000000EF": "CRITICAL_PROCESS_DIED - Critical system process terminated. Possible file corruption or driver conflict.",
    "0x000000C5": "DRIVER_CORRUPTED_EXPOOL - Driver corrupted pool memory. Faulty driver identified.",
    "0x0000009F": "DRIVER_POWER_STATE_FAILURE - Driver in inconsistent power state. Common during sleep/wake.",
    "0x00000133": "DPC_WATCHDOG_VIOLATION - DPC routine ran too long. Driver performance issue.",
    "0x00000139": "KERNEL_SECURITY_CHECK_FAILURE - Kernel detected data corruption. Can be driver or hardware.",
    "0x00000019": "BAD_POOL_HEADER - Pool header corrupted. Memory or driver issue.",
    "0x000000FC": "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY - Code tried to execute from non-executable memory.",
    "0x00000101": "CLOCK_WATCHDOG_TIMEOUT - Processor not processing interrupts. Common with Intel 13/14th gen issue.",
    "0x00000154": "UNEXPECTED_STORE_EXCEPTION - Store component threw unexpected exception. Possible disk or memory.",
}
HW_CODES = {"0x0000009C", "0x00000124", "0x00000101", "0x0000001A", "0x00000050"}


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def is_admin():
    """Check if the current process has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def safe_truncate(text, max_len=300):
    """Truncate text to max_len, replacing newlines with spaces."""
    if not text:
        return ""
    clean = text.replace("\r\n", " ").replace("\n", " ")
    return clean[:max_len] if len(clean) > max_len else clean


def ps(cmd, as_json=False):
    """Run a PowerShell command and return output."""
    full_cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd]
    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace"
        )
        output = result.stdout.strip()
        if as_json and output:
            return json.loads(output)
        return output
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return [] if as_json else ""


def ps_events(log_name, provider=None, event_id=None, level=None, max_events=20):
    """Query Windows Event Log via PowerShell and return list of dicts."""
    filters = [f"LogName='{log_name}'"]
    if provider:
        filters.append(f"ProviderName='{provider}'")
    if event_id is not None:
        filters.append(f"Id={event_id}")
    if level is not None:
        filters.append(f"Level={level}")
    ht = "@{" + "; ".join(filters) + "}"
    cmd = (
        f"Get-WinEvent -FilterHashtable {ht} -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
        f"Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message | "
        f"ForEach-Object {{ @{{ "
        f"  Date = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
        f"  EventID = $_.Id; "
        f"  Source = $_.ProviderName; "
        f"  Level = if ($_.LevelDisplayName) {{ $_.LevelDisplayName }} else {{ 'Unknown' }}; "
        f"  Message = if ($_.Message) {{ $_.Message.Substring(0, [Math]::Min($_.Message.Length, 400)) -replace \"`r`n\", ' ' }} else {{ '' }} "
        f"}} }} | ConvertTo-Json -Depth 3"
    )
    result = ps(cmd, as_json=True)
    if isinstance(result, dict):
        return [result]
    return result if isinstance(result, list) else []


def cprint(msg, color="cyan"):
    """Print colored console output."""
    colors = {
        "cyan": "\033[96m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "red": "\033[91m",
        "gray": "\033[90m",
        "reset": "\033[0m",
    }
    print(f"{colors.get(color, '')}{msg}{colors['reset']}")


def normalize_list(data, key):
    """Normalize PS output: wrap single dict in list, default to empty list."""
    val = data.get(key, []) or []
    if isinstance(val, dict):
        return [val]
    return val


# ============================================================
# DATA COLLECTION FUNCTIONS (Sections 1-10)
# ============================================================
def collect_system_info():
    """Section 1: Collect system information via WMI."""
    cprint("[1/10] Collecting System Information...", "yellow")
    sys_info_cmd = """
$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$CPU = Get-CimInstance Win32_Processor
$BIOS = Get-CimInstance Win32_BIOS
$BB = Get-CimInstance Win32_BaseBoard
@{
    ComputerName = $CS.Name
    Manufacturer = $CS.Manufacturer
    Model = $CS.Model
    OSName = $OS.Caption
    OSVersion = $OS.Version
    OSBuild = $OS.BuildNumber
    InstallDate = $OS.InstallDate.ToString('yyyy-MM-dd')
    LastBoot = $OS.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
    Uptime = ((Get-Date) - $OS.LastBootUpTime).ToString('dd\\.hh\\:mm\\:ss')
    CPUName = $CPU.Name.Trim()
    CPUCores = $CPU.NumberOfCores
    CPULogical = $CPU.NumberOfLogicalProcessors
    CPUMaxClock = "$($CPU.MaxClockSpeed) MHz"
    CPUCurrentClock = "$($CPU.CurrentClockSpeed) MHz"
    BIOSVersion = $BIOS.SMBIOSBIOSVersion
    BIOSDate = $BIOS.ReleaseDate.ToString('yyyy-MM-dd')
    Baseboard = "$($BB.Manufacturer) $($BB.Product) v$($BB.Version)"
    TotalRAM_GB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 1)
} | ConvertTo-Json
"""
    return ps(sys_info_cmd, as_json=True) or {}


def check_intel_cpu(sys_info):
    """Section 2: Check Intel 13th/14th Gen CPU microcode and known issues.

    Returns:
        tuple: (intel_check dict, critical list, warnings list, info list)
    """
    cprint("[2/10] Checking Intel CPU Microcode & Known Issues...", "yellow")

    critical = []
    warnings = []
    info = []

    intel_check = {
        "IsAffectedCPU": False,
        "CPUFamily": "Unknown",
        "MicrocodeVersion": "Unknown",
        "Recommendation": "",
        "Details": "",
        "BIOSDate": sys_info.get("BIOSDate", ""),
    }

    cpu_name = sys_info.get("CPUName", "")
    if re.search(r"i[579]-1[34]\d{3}", cpu_name):
        intel_check["IsAffectedCPU"] = True
        if "i9-14900" in cpu_name:
            intel_check["CPUFamily"] = "Intel 14th Gen Core i9 (Raptor Lake Refresh)"
        elif "i7-14700" in cpu_name:
            intel_check["CPUFamily"] = "Intel 14th Gen Core i7 (Raptor Lake Refresh)"
        elif "i9-13900" in cpu_name:
            intel_check["CPUFamily"] = "Intel 13th Gen Core i9 (Raptor Lake)"
        else:
            intel_check["CPUFamily"] = "Intel 13th/14th Gen (Potentially Affected)"

        # Read microcode from registry
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            mcu_raw, _ = winreg.QueryValueEx(key, "Update Revision")
            winreg.CloseKey(key)
            if isinstance(mcu_raw, bytes):
                intel_check["MicrocodeVersion"] = "0x" + mcu_raw.hex().upper()
            else:
                intel_check["MicrocodeVersion"] = str(mcu_raw)
        except Exception:
            intel_check["MicrocodeVersion"] = "Unable to read"

        bios_date_str = sys_info.get("BIOSDate", "2020-01-01")
        try:
            bios_date = datetime.strptime(bios_date_str, "%Y-%m-%d")
        except:
            bios_date = datetime(2020, 1, 1)

        if bios_date < datetime(2024, 8, 1):
            critical.append(
                f"INTEL CPU VULNERABILITY: Your BIOS date ({bios_date_str}) predates the Intel microcode fix (August 2024). Your i9-14900K may be experiencing eTVB/SVID voltage instability causing BSODs and potential permanent CPU degradation. IMMEDIATE BIOS UPDATE REQUIRED."
            )
            intel_check["Recommendation"] = (
                "CRITICAL: Update BIOS immediately to get Intel microcode 0x129 or later. Check Dell support for XPS 8960 BIOS updates."
            )
        elif bios_date < datetime(2024, 12, 1):
            warnings.append(
                "INTEL CPU: BIOS has been updated since initial Intel fix but may not have the latest microcode. Verify you have the newest Dell BIOS for XPS 8960."
            )
            intel_check["Recommendation"] = (
                "Check for latest Dell BIOS update for XPS 8960 to ensure newest Intel microcode."
            )
        else:
            info.append(
                f"INTEL CPU: BIOS date ({bios_date_str}) is recent and likely includes the Intel microcode fix. However, if the CPU was already degraded before the fix, damage may be irreversible."
            )
            intel_check["Recommendation"] = (
                "BIOS appears up to date. If BSODs persist, the CPU may have already sustained degradation. Intel extended their warranty by 2 years for affected 13th/14th Gen CPUs. Visit warranty.intel.com to check status and submit a replacement claim."
            )

        intel_check["Details"] = (
            "Intel acknowledged that 13th/14th Gen desktop processors (i5/i7/i9) had an elevated operating voltage issue causing instability and permanent degradation. Root causes: eTVB (Enhanced Thermal Velocity Boost) and SVID (Serial VID) algorithms requesting excessive voltage. Intel released microcode 0x129 in August 2024 to mitigate this. CPUs already damaged may need replacement under Intel extended warranty."
        )
    else:
        intel_check["Details"] = "CPU does not appear to be in the affected Intel 13th/14th Gen desktop family."
        info.append("CPU is not in the known affected Intel 13th/14th Gen range.")

    return intel_check, critical, warnings, info


def analyze_bsod():
    """Section 3: Analyze BSOD minidump files.

    Returns:
        tuple: (bsod_data dict, critical list, warnings list, info list)
    """
    cprint("[3/10] Analyzing BSOD Minidump Files...", "yellow")

    critical = []
    warnings = []
    info = []

    minidump_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Minidump")
    bsod_data = {
        "MinidumpFiles": [],
        "BugCheckCodes": [],
        "RecentCrashes": 0,
        "CrashSummary": [],
        "UnexpectedShutdowns": 0,
        "UnexpectedShutdownDetails": [],
    }

    if os.path.isdir(minidump_path):
        dmp_files = sorted(Path(minidump_path).glob("*.dmp"), key=lambda f: f.stat().st_mtime, reverse=True)[:20]
        thirty_days_ago = datetime.now() - timedelta(days=30)
        for f in dmp_files:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            bsod_data["MinidumpFiles"].append(
                {
                    "FileName": f.name,
                    "Date": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    "SizeKB": round(f.stat().st_size / 1024, 1),
                }
            )
            if mtime > thirty_days_ago:
                bsod_data["RecentCrashes"] += 1

        if bsod_data["RecentCrashes"] > 5:
            critical.append(
                f"HIGH CRASH FREQUENCY: {bsod_data['RecentCrashes']} BSOD minidumps in the last 30 days. This indicates a serious ongoing issue."
            )
        elif bsod_data["RecentCrashes"] > 0:
            warnings.append(f"{bsod_data['RecentCrashes']} BSOD minidump(s) found in the last 30 days.")
    else:
        info.append("No minidump directory found. Minidumps may be disabled or cleared.")

    # BugCheck events (WER)
    wer_events = ps_events(
        "System", provider="Microsoft-Windows-WER-SystemErrorReporting", event_id=1001, max_events=20
    )
    for ev in wer_events:
        msg = safe_truncate(ev.get("Message", ""), 300)
        bc_match = re.search(r"bug check.*?(0x[0-9A-Fa-f]+)", msg, re.IGNORECASE)
        code = bc_match.group(1) if bc_match else ""
        bsod_data["CrashSummary"].append({"Date": ev.get("Date", ""), "BugCheckCode": code, "Message": msg})
        if code and code not in bsod_data["BugCheckCodes"]:
            bsod_data["BugCheckCodes"].append(code)

    # Kernel-Power unexpected shutdowns
    kp_events = ps_events("System", provider="Microsoft-Windows-Kernel-Power", event_id=41, max_events=20)
    bsod_data["UnexpectedShutdowns"] = len(kp_events)
    bsod_data["UnexpectedShutdownDetails"] = [
        {"Date": e.get("Date", ""), "Message": safe_truncate(e.get("Message", ""), 300)} for e in kp_events[:10]
    ]

    if bsod_data["UnexpectedShutdowns"] > 5:
        critical.append(
            f"{bsod_data['UnexpectedShutdowns']} unexpected shutdowns (Kernel-Power 41) detected. Combined with BSODs, this points to a hardware or power delivery issue."
        )

    return bsod_data, critical, warnings, info


def scan_event_logs():
    """Section 4: Scan Windows Event Logs.

    Returns:
        tuple: (event_data dict, critical list, warnings list, info list)
    """
    cprint("[4/10] Scanning Windows Event Logs...", "yellow")

    critical = []
    warnings = []
    info = []

    event_data = {"SystemCritical": [], "SystemErrors": [], "WHEAErrors": []}
    event_data["SystemCritical"] = ps_events("System", level=1, max_events=30)
    event_data["SystemErrors"] = ps_events("System", level=2, max_events=50)

    # WHEA
    whea_events = ps_events("System", provider="Microsoft-Windows-WHEA-Logger", max_events=50)
    event_data["WHEAErrors"] = whea_events

    if len(whea_events) > 0:
        critical.append(
            f"{len(whea_events)} WHEA (hardware error) events found. This strongly indicates a hardware problem - likely CPU, RAM, or motherboard. With an i9-14900K, this is a hallmark of the Intel voltage degradation issue."
        )

    return event_data, critical, warnings, info


def analyze_drivers():
    """Section 5: Analyze installed drivers.

    Returns:
        tuple: (driver_data dict, critical list, warnings list, info list)
    """
    cprint("[5/10] Analyzing Installed Drivers...", "yellow")

    critical = []
    warnings = []
    info = []

    driver_cmd = """
$ms = @('Microsoft','Microsoft Windows','Microsoft Corporation')
$all = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverVersion }
$tp = @(); $old = @()
foreach ($d in $all) {
    $isMS = $false; foreach ($p in $ms) { if ($d.DriverProviderName -like "*$p*") { $isMS=$true; break } }
    if (-not $isMS -and $d.DriverProviderName) {
        $dt = if ($d.DriverDate) { $d.DriverDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
        $entry = @{DeviceName=$d.DeviceName;Provider=$d.DriverProviderName;Version=$d.DriverVersion;Date=$dt;IsSigned=$d.IsSigned}
        $tp += $entry
        if ($d.DriverDate -and $d.DriverDate -lt (Get-Date).AddYears(-2)) { $old += $entry }
    }
}
$prob = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | ForEach-Object {
    @{DeviceName=$_.Name;ErrorCode=$_.ConfigManagerErrorCode;Status=$_.Status}
})
@{Total=$all.Count;ThirdParty=$tp;Old=$old;Problematic=$prob} | ConvertTo-Json -Depth 4
"""
    driver_data_raw = ps(driver_cmd, as_json=True) or {}
    driver_data = {
        "TotalDrivers": driver_data_raw.get("Total", 0),
        "ThirdPartyDrivers": normalize_list(driver_data_raw, "ThirdParty"),
        "OldDrivers": normalize_list(driver_data_raw, "Old"),
        "ProblematicDrivers": normalize_list(driver_data_raw, "Problematic"),
    }

    if len(driver_data["ProblematicDrivers"]) > 0:
        warnings.append(
            f"{len(driver_data['ProblematicDrivers'])} device(s) reporting driver errors. These could contribute to system instability."
        )
    if len(driver_data["OldDrivers"]) > 3:
        warnings.append(
            f"{len(driver_data['OldDrivers'])} third-party drivers are over 2 years old. Outdated drivers can cause BSODs."
        )

    return driver_data, critical, warnings, info


def check_disk_health():
    """Section 6: Check disk health.

    Returns:
        tuple: (disk_data dict, critical list, warnings list, info list)
    """
    cprint("[6/10] Checking Disk Health...", "yellow")

    critical = []
    warnings = []
    info = []

    disk_cmd = """
$disks = @(); $vols = @()
foreach ($pd in Get-PhysicalDisk -EA SilentlyContinue) {
    $r = $null; try { $r = Get-PhysicalDisk -UniqueId $pd.UniqueId | Get-StorageReliabilityCounter -EA Stop } catch {}
    $disks += @{
        FriendlyName=$pd.FriendlyName; MediaType="$($pd.MediaType)"; Size_GB=[math]::Round($pd.Size/1GB,1)
        HealthStatus="$($pd.HealthStatus)"; BusType="$($pd.BusType)"
        Wear=if($r -and $r.Wear){"$($r.Wear)%"}else{"N/A"}
        Temperature=if($r -and $r.Temperature){"$($r.Temperature)C"}else{"N/A"}
        ReadErrors=if($r -and $r.ReadErrorsTotal){$r.ReadErrorsTotal}else{0}
        WriteErrors=if($r -and $r.WriteErrorsTotal){$r.WriteErrorsTotal}else{0}
        PowerOnHours=if($r -and $r.PowerOnHours){$r.PowerOnHours}else{"N/A"}
    }
}
foreach ($v in Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }) {
    $pct = if($v.Size -gt 0){[math]::Round(($v.SizeRemaining/$v.Size)*100,1)}else{0}
    $vols += @{DriveLetter="$($v.DriveLetter):";Label="$($v.FileSystemLabel)";FileSystem="$($v.FileSystem)";Size_GB=[math]::Round($v.Size/1GB,1);Free_GB=[math]::Round($v.SizeRemaining/1GB,1);PercentFree=$pct;Health="$($v.HealthStatus)"}
}
@{Disks=$disks;Volumes=$vols} | ConvertTo-Json -Depth 4
"""
    disk_raw = ps(disk_cmd, as_json=True) or {}
    disk_data = {
        "Disks": normalize_list(disk_raw, "Disks"),
        "Volumes": normalize_list(disk_raw, "Volumes"),
    }

    for d in disk_data["Disks"]:
        if d.get("HealthStatus") != "Healthy":
            critical.append(
                f"DISK UNHEALTHY: {d.get('FriendlyName')} reports status '{d.get('HealthStatus')}'. Data loss risk - back up immediately."
            )
        if d.get("ReadErrors", 0) > 0 or d.get("WriteErrors", 0) > 0:
            warnings.append(
                f"Disk '{d.get('FriendlyName')}' has read/write errors (Read: {d.get('ReadErrors')}, Write: {d.get('WriteErrors')})."
            )

    for v in disk_data["Volumes"]:
        if str(v.get("DriveLetter", "")).startswith("C") and v.get("PercentFree", 100) < 10:
            warnings.append(f"C: drive is critically low on space ({v.get('PercentFree')}% free).")

    return disk_data, critical, warnings, info


def analyze_memory():
    """Section 7: Analyze memory (RAM) configuration.

    Returns:
        tuple: (mem_data dict, critical list, warnings list, info list)
    """
    cprint("[7/10] Analyzing Memory Configuration...", "yellow")

    critical = []
    warnings = []
    info = []

    mem_cmd = """
$sticks = @(); $speeds = @(); $sizes = @()
foreach ($s in Get-CimInstance Win32_PhysicalMemory) {
    $sticks += @{DeviceLocator="$($s.DeviceLocator)";Capacity_GB=[math]::Round($s.Capacity/1GB,1);Speed_MHz=$s.ConfiguredClockSpeed;Manufacturer="$($s.Manufacturer)";PartNumber=("$($s.PartNumber)" -replace '\\s+',' ').Trim()}
    $speeds += $s.ConfiguredClockSpeed; $sizes += $s.Capacity
}
$cs = Get-CimInstance Win32_ComputerSystem
@{Sticks=$sticks;TotalGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1);Speeds=$speeds;Sizes=$sizes} | ConvertTo-Json -Depth 4
"""
    mem_raw = ps(mem_cmd, as_json=True) or {}
    mem_data = {
        "Sticks": normalize_list(mem_raw, "Sticks"),
        "TotalGB": mem_raw.get("TotalGB", 0),
        "XMPWarning": False,
        "MismatchWarning": False,
    }

    speeds = mem_raw.get("Speeds", []) or []
    if isinstance(speeds, (int, float)):
        speeds = [speeds]
    sizes = mem_raw.get("Sizes", []) or []
    if isinstance(sizes, (int, float)):
        sizes = [sizes]

    if len(set(speeds)) > 1:
        mem_data["MismatchWarning"] = True
        warnings.append(f"RAM sticks are running at different speeds: {', '.join(str(s) for s in speeds)} MHz.")
    if len(set(sizes)) > 1:
        warnings.append("RAM sticks have different capacities. Mismatched RAM can reduce stability.")
    if speeds and speeds[0] > 5600:
        mem_data["XMPWarning"] = True
        warnings.append(
            f"RAM speed ({speeds[0]} MHz) exceeds Intel official spec for 14th Gen (5600 MHz DDR5). Try disabling XMP in BIOS."
        )

    return mem_data, critical, warnings, info


def check_thermals():
    """Section 8: Check thermal and power status.

    Returns:
        tuple: (thermal_data dict, critical list, warnings list, info list)
    """
    cprint("[8/10] Checking Thermal & Power Status...", "yellow")

    critical = []
    warnings = []
    info = []

    thermal_cmd = """
$pp = powercfg /getactivescheme 2>$null
$plan = if ($pp) { ($pp -replace 'Power Scheme GUID:\\s*\\S+\\s*\\(', '' -replace '\\)$', '').Trim() } else { 'Unknown' }
$perf = 'N/A'; $throttle = $false
try { $p = Get-Counter '\\Processor Information(_Total)\\% Processor Performance' -SampleInterval 1 -MaxSamples 1 -EA Stop; $perf = [math]::Round($p.CounterSamples[0].CookedValue, 1); if ($perf -lt 80) { $throttle = $true } } catch {}
$temps = @()
try { foreach ($tz in Get-CimInstance -Namespace root\\WMI -ClassName MSAcpi_ThermalZoneTemperature -EA Stop) {
    $c = [math]::Round(($tz.CurrentTemperature/10)-273.15,1); $f = [math]::Round(($c*9/5)+32,1)
    $temps += @{Zone=$tz.InstanceName;TempC=$c;TempF=$f}
}} catch { $temps += @{Zone='N/A';TempC='WMI unavailable';TempF='Install HWiNFO64'} }
@{PowerPlan=$plan;CPUPerformancePct=$perf;CPUThrottling=$throttle;Temperatures=$temps} | ConvertTo-Json -Depth 3
"""
    thermal_data = ps(thermal_cmd, as_json=True) or {}
    if not isinstance(thermal_data.get("Temperatures"), list):
        thermal_data["Temperatures"] = (
            [thermal_data.get("Temperatures", {})] if thermal_data.get("Temperatures") else []
        )

    for t in thermal_data.get("Temperatures", []):
        tc = t.get("TempC", 0)
        if isinstance(tc, (int, float)):
            if tc > 90:
                critical.append(f"CPU temperature at {tc}C - CRITICALLY HIGH. Check CPU cooler.")
            elif tc > 80:
                warnings.append(f"CPU temperature at {tc}C - elevated. Monitor cooling performance.")

    if thermal_data.get("CPUThrottling"):
        warnings.append(
            f"CPU performance counter at {thermal_data.get('CPUPerformancePct')}%. CPU may be thermal throttling."
        )

    return thermal_data, critical, warnings, info


def check_updates():
    """Section 9: Check system integrity and updates.

    Returns:
        tuple: (update_history list, critical list, warnings list, info list)
    """
    cprint("[9/10] Checking System Integrity & Updates...", "yellow")

    critical = []
    warnings = []
    info = []

    update_cmd = """
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $sr = $s.CreateUpdateSearcher()
    $hc = $sr.GetTotalHistoryCount()
    $h = $sr.QueryHistory(0, [Math]::Min($hc, 15))
    $results = @($h | ForEach-Object {
        $r = switch ($_.ResultCode) { 2{'Succeeded'} 3{'Succeeded with Errors'} 4{'Failed'} 5{'Aborted'} default{'In Progress'} }
        @{Title="$($_.Title)";Date=if($_.Date){$_.Date.ToString('yyyy-MM-dd')}else{'Unknown'};Result=$r}
    })
    $results | ConvertTo-Json -Depth 3
} catch { '[]' }
"""
    update_history = ps(update_cmd, as_json=True) or []
    if isinstance(update_history, dict):
        update_history = [update_history]

    failed_updates = [u for u in update_history if u.get("Result") == "Failed"]
    if len(failed_updates) > 0:
        warnings.append(f"{len(failed_updates)} Windows Updates have failed recently.")

    return update_history, critical, warnings, info


def collect_reliability():
    """Section 10: Collect reliability data (app crashes and hangs).

    Returns:
        tuple: (app_crashes list, app_hangs list)
    """
    cprint("[10/10] Collecting Reliability Data...", "yellow")
    app_crashes = ps_events("Application", provider="Application Error", event_id=1000, max_events=20)
    app_hangs = ps_events("Application", provider="Application Hang", event_id=1002, max_events=20)
    return app_crashes, app_hangs


# ============================================================
# WARRANTY READINESS DATA
# ============================================================
def collect_warranty_data(sys_info, intel_check, bsod_data, event_data):
    """Collect all data needed for Intel/Dell warranty claims.

    Returns:
        dict: Warranty-ready data with CPU serial, service tag, and evidence summary.
    """
    cprint("Collecting warranty readiness data...", "gray")

    warranty = {
        "CPUModel": sys_info.get("CPUName", "Unknown"),
        "CPUFamily": intel_check.get("CPUFamily", "Unknown"),
        "IsAffectedCPU": intel_check.get("IsAffectedCPU", False),
        "MicrocodeVersion": intel_check.get("MicrocodeVersion", "Unknown"),
        "BIOSVersion": sys_info.get("BIOSVersion", "Unknown"),
        "BIOSDate": sys_info.get("BIOSDate", "Unknown"),
        "CPUSerial": "Unable to read",
        "DellServiceTag": "N/A",
        "SystemManufacturer": sys_info.get("Manufacturer", "Unknown"),
        "SystemModel": sys_info.get("Model", "Unknown"),
        "BSODCount30Days": bsod_data.get("RecentCrashes", 0),
        "UnexpectedShutdowns": bsod_data.get("UnexpectedShutdowns", 0),
        "BugCheckCodes": bsod_data.get("BugCheckCodes", []),
        "WHEAErrorCount": len(event_data.get("WHEAErrors", [])),
        "IntelWarrantyURL": "https://warranty.intel.com",
        "DellSupportURL": "https://www.dell.com/support",
    }

    # Read CPU ProcessorId (CPUID — closest to serial available via WMI)
    cpu_id_cmd = """
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
@{
    ProcessorId = $cpu.ProcessorId
    UniqueId = if ($cpu.UniqueId) { $cpu.UniqueId } else { 'N/A' }
    SerialNumber = if ($cpu.SerialNumber) { $cpu.SerialNumber } else { 'N/A' }
} | ConvertTo-Json
"""
    cpu_id = ps(cpu_id_cmd, as_json=True) or {}
    warranty["CPUSerial"] = cpu_id.get("ProcessorId", "Unable to read")
    if cpu_id.get("SerialNumber", "N/A") not in ("N/A", "", "To Be Filled By O.E.M."):
        warranty["CPUSerial"] = cpu_id["SerialNumber"]

    # Read Dell Service Tag via WMI
    tag_cmd = "(Get-CimInstance Win32_BIOS).SerialNumber"
    tag = ps(tag_cmd)
    if tag and tag not in ("", "To Be Filled By O.E.M.", "Default string"):
        warranty["DellServiceTag"] = tag
        warranty["DellSupportURL"] = f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}"

    # Build evidence summary (copy-pasteable for warranty claim)
    evidence_lines = []
    evidence_lines.append(f"System: {warranty['SystemManufacturer']} {warranty['SystemModel']}")
    evidence_lines.append(f"CPU: {warranty['CPUModel']}")
    evidence_lines.append(f"CPU ID: {warranty['CPUSerial']}")
    evidence_lines.append(f"BIOS: {warranty['BIOSVersion']} ({warranty['BIOSDate']})")
    evidence_lines.append(f"Microcode: {warranty['MicrocodeVersion']}")
    evidence_lines.append(f"BSODs in last 30 days: {warranty['BSODCount30Days']}")
    evidence_lines.append(f"Unexpected shutdowns: {warranty['UnexpectedShutdowns']}")
    evidence_lines.append(f"WHEA hardware errors: {warranty['WHEAErrorCount']}")
    if warranty["BugCheckCodes"]:
        codes_str = ", ".join(warranty["BugCheckCodes"])
        evidence_lines.append(f"Bug check codes: {codes_str}")
        hw_codes_found = [c for c in warranty["BugCheckCodes"] if c in HW_CODES]
        if hw_codes_found:
            evidence_lines.append(f"Hardware-related codes: {', '.join(hw_codes_found)}")
    if warranty["DellServiceTag"] != "N/A":
        evidence_lines.append(f"Dell Service Tag: {warranty['DellServiceTag']}")
    evidence_lines.append("")
    evidence_lines.append("This system exhibits symptoms consistent with the known Intel 13th/14th Gen")
    evidence_lines.append("desktop processor voltage instability issue (eTVB/SVID). Requesting warranty")
    evidence_lines.append("evaluation and potential CPU replacement under Intel's extended warranty program.")

    warranty["EvidenceSummary"] = "\n".join(evidence_lines)

    return warranty


def build_warranty_section(warranty):
    """Build the Warranty Ready HTML section for the report.

    Returns:
        str: HTML for the warranty section, or empty string if CPU is not affected.
    """
    if not warranty.get("IsAffectedCPU"):
        return ""

    has_issues = (
        warranty["BSODCount30Days"] > 0 or warranty["WHEAErrorCount"] > 0 or warranty["UnexpectedShutdowns"] > 0
    )

    border_class = "intel-critical" if has_issues else "intel-warn"

    html = f"""<div class="section"><div class="section-header"><div class="section-icon">&#x1F4CB;</div><h2>Warranty Claim — Ready to File</h2></div><div class="section-body">
    <div class="intel-box {border_class}">
    <h3>{"⚠️ Evidence Supports Warranty Claim" if has_issues else "ℹ️ Warranty Information"}</h3>
    <p class="help-text" style="margin-bottom:1rem">All data below is auto-collected from your system. Copy the evidence summary and paste it into your warranty claim.</p>

    <div class="intel-grid" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr));">
        <div><span class="stat-label">CPU Model</span><span class="stat-val">{he(warranty["CPUModel"])}</span></div>
        <div><span class="stat-label">CPU ID / Serial</span><span class="stat-val"><code>{he(warranty["CPUSerial"])}</code></span></div>
        <div><span class="stat-label">Microcode</span><span class="stat-val"><code>{he(warranty["MicrocodeVersion"])}</code></span></div>
        <div><span class="stat-label">BIOS Version</span><span class="stat-val">{he(warranty["BIOSVersion"])} ({he(warranty["BIOSDate"])})</span></div>
        <div><span class="stat-label">Dell Service Tag</span><span class="stat-val"><code>{he(warranty["DellServiceTag"])}</code></span></div>
        <div><span class="stat-label">BSODs (30 days)</span><span class="stat-val" style="color:{"var(--red)" if warranty["BSODCount30Days"] > 0 else "var(--green)"};">{warranty["BSODCount30Days"]}</span></div>
        <div><span class="stat-label">WHEA Errors</span><span class="stat-val" style="color:{"var(--red)" if warranty["WHEAErrorCount"] > 0 else "var(--green)"};">{warranty["WHEAErrorCount"]}</span></div>
        <div><span class="stat-label">Unexpected Shutdowns</span><span class="stat-val" style="color:{"var(--red)" if warranty["UnexpectedShutdowns"] > 0 else "var(--green)"};">{warranty["UnexpectedShutdowns"]}</span></div>
    </div>"""

    if warranty["BugCheckCodes"]:
        codes_html = " ".join(
            f'<span class="badge {"badge-crit" if c in HW_CODES else "badge-warn"}">{c}</span>'
            for c in warranty["BugCheckCodes"]
        )
        html += f'<div style="margin-top:1rem;"><span class="stat-label">Bug Check Codes</span><div style="margin-top:.4rem;display:flex;flex-wrap:wrap;gap:.4rem;">{codes_html}</div></div>'

    # Copy-pasteable evidence
    html += f"""
    <div style="margin-top:1.5rem;">
        <h4 style="color:var(--text-bright);font-size:.9rem;margin-bottom:.5rem;">📋 Evidence Summary (copy &amp; paste into warranty claim)</h4>
        <pre style="background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:8px;padding:1rem;font-family:var(--mono);font-size:.78rem;color:var(--text);line-height:1.7;white-space:pre-wrap;cursor:text;user-select:all;">{he(warranty["EvidenceSummary"])}</pre>
    </div>

    <div style="margin-top:1.5rem;display:flex;gap:1rem;flex-wrap:wrap;">
        <a href="{warranty["IntelWarrantyURL"]}" target="_blank" style="display:inline-flex;align-items:center;gap:.5rem;padding:.6rem 1.2rem;background:var(--accent);color:var(--bg);border-radius:6px;text-decoration:none;font-weight:600;font-size:.85rem;">🔗 Intel Warranty Portal</a>
        <a href="{warranty["DellSupportURL"]}" target="_blank" style="display:inline-flex;align-items:center;gap:.5rem;padding:.6rem 1.2rem;background:var(--orange);color:var(--bg);border-radius:6px;text-decoration:none;font-weight:600;font-size:.85rem;">🔗 Dell Support{" (Your Service Tag)" if warranty["DellServiceTag"] != "N/A" else ""}</a>
    </div>
    </div></div></div>"""

    return html


# ============================================================
# SCORE CALCULATION
# ============================================================
def calculate_score(critical, warnings):
    """Calculate health score from findings.

    Returns:
        tuple: (score int, score_label str, score_color str)
    """
    score = max(0, min(100, 100 - len(critical) * 20 - len(warnings) * 5))
    score_label = "Good" if score >= 80 else "Fair" if score >= 60 else "Poor" if score >= 40 else "Critical"
    score_color = "#22c55e" if score >= 80 else "#eab308" if score >= 60 else "#f97316" if score >= 40 else "#ef4444"
    return score, score_label, score_color


# ============================================================
# HTML REPORT BUILDERS
# ============================================================
def build_table(headers, rows, row_class_fn=None):
    """Build an HTML table from headers and rows."""
    h = "<thead><tr>" + "".join(f"<th>{he(h)}</th>" for h in headers) + "</tr></thead><tbody>"
    for r in rows:
        cls = row_class_fn(r) if row_class_fn else ""
        h += f"<tr{cls}>" + "".join(f"<td>{he(str(c))}</td>" for c in r) + "</tr>"
    return h + "</tbody>"


def build_findings(critical, warnings, info):
    """Build the Key Findings HTML section."""
    html = ""
    for label, items, css in [
        ("Critical Issues", critical, "findings-critical"),
        ("Warnings", warnings, "findings-warning"),
        ("Informational", info, "findings-info"),
    ]:
        if items:
            icon = "&#9888;" if "Critical" in label or "Warn" in label else "&#8505;"
            html += f'<div class="findings-group {css}"><h3>{label}</h3>'
            for item in items:
                html += f'<div class="finding-item"><span class="finding-icon">{icon}</span><p>{he(item)}</p></div>'
            html += "</div>"
    return html


def build_bugcheck_section(bsod_data):
    """Build the Bug Check Codes HTML section."""
    if not bsod_data["BugCheckCodes"]:
        return ""
    html = '<div class="subsection"><h3>Bug Check Codes Found</h3><div class="code-grid">'
    for code in bsod_data["BugCheckCodes"]:
        desc = BUGCHECK_LOOKUP.get(code, "Unknown bug check code. Analyze minidump with WinDbg for details.")
        badge = ("badge-crit", "HARDWARE") if code in HW_CODES else ("badge-warn", "SOFTWARE")
        html += f'<div class="code-card"><div class="code-header"><span class="bc-code">{code}</span><span class="badge {badge[0]}">{badge[1]}</span></div><p>{he(desc)}</p></div>'
    return html + "</div></div>"


def build_event_table(events, max_items=15, err_class=False):
    """Build an event log HTML table."""
    if not events:
        return ""
    html = '<div class="table-wrap"><table><thead><tr><th>Date</th><th>Source</th><th>ID</th><th>Message</th></tr></thead><tbody>'
    for e in events[:max_items]:
        cls = ' class="err-row"' if err_class else ""
        html += f'<tr{cls}><td class="nowrap">{he(str(e.get("Date", "")))}</td><td>{he(str(e.get("Source", "")))}</td><td>{he(str(e.get("EventID", "")))}</td><td class="msg-cell">{he(safe_truncate(str(e.get("Message", "")), 400))}</td></tr>'
    return html + "</tbody></table></div>"


def build_intel_section(intel_check, critical):
    """Build the Intel CPU Stability Analysis HTML section."""
    if not intel_check["IsAffectedCPU"]:
        return ""
    border = "intel-critical" if any("INTEL CPU VULNERABILITY" in c for c in critical) else "intel-warn"
    html = '<div class="section"><div class="section-header"><div class="section-icon">&#x1F4A1;</div><h2>Intel CPU Stability Analysis</h2></div><div class="section-body">'
    html += f'<div class="intel-box {border}"><h3>Intel 13th/14th Gen Instability Check</h3><div class="intel-grid">'
    for lbl, val in [
        ("CPU Family", intel_check["CPUFamily"]),
        ("Microcode", f"<code>{he(intel_check['MicrocodeVersion'])}</code>"),
        ("BIOS Date", intel_check["BIOSDate"]),
    ]:
        html += f'<div><span class="stat-label">{lbl}</span><span class="stat-val">{val}</span></div>'
    html += f'</div><div class="intel-detail"><strong>Background:</strong> {he(intel_check["Details"])}</div>'
    html += f'<div class="intel-rec"><strong>Recommendation:</strong> {he(intel_check["Recommendation"])}</div>'
    html += '<div style="margin-top:1rem;padding:1rem;background:rgba(0,0,0,0.25);border-radius:8px;border:1px solid rgba(255,255,255,0.1);">'
    html += (
        '<h4 style="color:var(--text-bright);font-size:0.9rem;margin-bottom:0.6rem;">How to Check Intel Warranty</h4>'
    )
    html += '<ol style="padding-left:1.2rem;font-size:0.82rem;color:var(--text);line-height:1.9;">'
    for step in [
        "Go to <strong>warranty.intel.com</strong> and sign in or create an account",
        "Click <strong>Check Warranty Status</strong> -- enter CPU ATPO/batch number",
        "No batch number? Download Intel <strong>Processor Diagnostic Tool</strong>",
        "Click <strong>Submit a Warranty Request</strong>",
        "Select issue type: <strong>System instability / BSOD</strong>",
        "Mention WHEA errors, bug check codes, and daily BSOD frequency",
        "Intel typically cross-ships replacement CPUs",
        "<strong>Alternative:</strong> Contact Dell Support -- they may handle it under Dell warranty",
    ]:
        html += f"<li>{step}</li>"
    html += "</ol></div></div></div></div>"
    return html


def build_disk_cards(disk_data):
    """Build disk health card HTML."""
    html = '<div class="disk-cards">'
    for d in disk_data["Disks"]:
        sc = "status-ok" if d.get("HealthStatus") == "Healthy" else "status-bad"
        html += f'<div class="disk-card"><div class="disk-card-header"><span class="disk-name">{he(str(d.get("FriendlyName", "")))}</span><span class="badge {sc}">{he(str(d.get("HealthStatus", "")))}</span></div><div class="disk-stats">'
        for lbl, val in [
            ("Type", d.get("MediaType")),
            ("Size", f"{d.get('Size_GB')} GB"),
            ("Bus", d.get("BusType")),
            ("Wear", d.get("Wear")),
            ("Temp", d.get("Temperature")),
            ("Power On", f"{d.get('PowerOnHours')} hrs"),
            ("Read Errors", d.get("ReadErrors")),
            ("Write Errors", d.get("WriteErrors")),
        ]:
            html += (
                f'<div><span class="stat-label">{lbl}</span><span class="stat-val">{he(str(val or "N/A"))}</span></div>'
            )
        html += "</div></div>"
    return html + "</div>"


def sys_grid(items):
    """Build a system info grid HTML component."""
    html = '<div class="sys-grid">'
    for lbl, val in items:
        html += f'<div class="sys-item"><span class="stat-label">{lbl}</span><span class="stat-val">{he(str(val))}</span></div>'
    return html + "</div>"


# ============================================================
# CSS (same dark theme as before)
# ============================================================
CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{--bg:#0a0a0f;--bg-card:#12121a;--bg-card-alt:#181825;--border:#2a2a3a;--border-light:#3a3a4f;--text:#e4e4ef;--text-dim:#8888a0;--text-bright:#fff;--accent:#6c8aff;--accent-glow:rgba(108,138,255,.15);--red:#ff4d6a;--red-bg:rgba(255,77,106,.08);--red-border:rgba(255,77,106,.25);--orange:#ff9f43;--orange-bg:rgba(255,159,67,.08);--orange-border:rgba(255,159,67,.25);--green:#22c55e;--green-bg:rgba(34,197,94,.08);--green-border:rgba(34,197,94,.25);--blue-bg:rgba(108,138,255,.08);--blue-border:rgba(108,138,255,.25);--font:'DM Sans',-apple-system,sans-serif;--mono:'JetBrains Mono',monospace}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}.container{max-width:1200px;margin:0 auto;padding:2rem 1.5rem 4rem}.header{text-align:center;padding:3rem 0 2rem;border-bottom:1px solid var(--border);margin-bottom:2.5rem}.header h1{font-size:2rem;font-weight:700;color:var(--text-bright);letter-spacing:-.5px;margin-bottom:.5rem}.header .subtitle{color:var(--text-dim);font-size:.95rem}.header .sys-badge{display:inline-block;margin-top:1rem;padding:.4rem 1rem;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;font-family:var(--mono);font-size:.8rem;color:var(--accent)}.score-section{display:flex;align-items:center;gap:2rem;padding:2rem;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;margin-bottom:2rem}.score-ring{position:relative;width:120px;height:120px;flex-shrink:0}.score-ring svg{transform:rotate(-90deg)}.score-ring .score-num{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:2rem;font-weight:700;color:var(--text-bright)}.score-ring .score-label{position:absolute;top:68%;left:50%;transform:translate(-50%,0);font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim)}.score-details h2{font-size:1.3rem;color:var(--text-bright);margin-bottom:.3rem}.score-details p{color:var(--text-dim);font-size:.9rem}.score-counts{display:flex;gap:1rem;margin-top:.8rem}.score-counts span{font-size:.8rem;padding:.25rem .6rem;border-radius:4px;font-weight:600}.cnt-crit{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}.cnt-warn{background:var(--orange-bg);color:var(--orange);border:1px solid var(--orange-border)}.cnt-info{background:var(--blue-bg);color:var(--accent);border:1px solid var(--blue-border)}
.section{margin-bottom:2rem;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden}.section-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem}.section-header h2{font-size:1.1rem;font-weight:600;color:var(--text-bright)}.section-icon{width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:var(--accent-glow);border-radius:8px;font-size:1rem}.section-body{padding:1.5rem}.subsection{margin-bottom:1.5rem}.subsection:last-child{margin-bottom:0}.subsection h3{font-size:.95rem;font-weight:600;color:var(--text-bright);margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.sys-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.75rem}.sys-item{display:flex;justify-content:space-between;padding:.6rem .8rem;background:var(--bg-card-alt);border-radius:6px;border:1px solid var(--border)}.stat-label{font-size:.8rem;color:var(--text-dim)}.stat-val{font-size:.85rem;color:var(--text-bright);font-weight:500}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.82rem}th{text-align:left;padding:.6rem .75rem;background:var(--bg-card-alt);color:var(--text-dim);font-weight:600;text-transform:uppercase;font-size:.7rem;letter-spacing:.5px;border-bottom:1px solid var(--border)}td{padding:.5rem .75rem;border-bottom:1px solid var(--border);color:var(--text);vertical-align:top}tr:hover td{background:rgba(108,138,255,.03)}.err-row td{background:var(--red-bg)}.warn-row td{background:var(--orange-bg)}.nowrap{white-space:nowrap}.msg-cell{max-width:500px;word-break:break-word;font-size:.78rem;color:var(--text-dim)}code{font-family:var(--mono);font-size:.8rem;background:var(--bg-card-alt);padding:.1rem .4rem;border-radius:3px;color:var(--accent)}
.badge{display:inline-block;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;padding:.2rem .5rem;border-radius:4px}.badge-crit{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}.badge-warn{background:var(--orange-bg);color:var(--orange);border:1px solid var(--orange-border)}.badge-ok,.status-ok{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}.status-bad{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}.code-grid{display:grid;gap:.75rem}.code-card{padding:1rem;background:var(--bg-card-alt);border:1px solid var(--border);border-radius:8px}.code-header{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}.bc-code{font-family:var(--mono);font-size:1.1rem;font-weight:700;color:var(--text-bright)}.code-card p{font-size:.85rem;color:var(--text-dim);line-height:1.5}
.intel-box{padding:1.5rem;border-radius:10px;margin-bottom:1.5rem}.intel-critical{background:var(--red-bg);border:2px solid var(--red-border)}.intel-warn{background:var(--orange-bg);border:2px solid var(--orange-border)}.intel-box h3{font-size:1.1rem;color:var(--text-bright);margin-bottom:1rem}.intel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem;margin-bottom:1rem}.intel-grid>div{display:flex;flex-direction:column;gap:.2rem;padding:.6rem;background:rgba(0,0,0,.2);border-radius:6px}.intel-detail,.intel-rec{font-size:.85rem;color:var(--text);margin-top:.75rem;line-height:1.6}.intel-rec{color:var(--text-bright)}
.disk-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem;margin-bottom:1rem}.disk-card{background:var(--bg-card-alt);border:1px solid var(--border);border-radius:8px;padding:1rem}.disk-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem}.disk-name{font-weight:600;color:var(--text-bright)}.disk-stats{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}.disk-stats>div{display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid var(--border)}.thermal-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem}.thermal-card{display:flex;flex-direction:column;gap:.3rem;padding:.8rem;background:var(--bg-card-alt);border:1px solid var(--border);border-radius:6px}
.findings-group{padding:1.25rem;border-radius:10px;margin-bottom:1rem}.findings-critical{background:var(--red-bg);border:1px solid var(--red-border)}.findings-warning{background:var(--orange-bg);border:1px solid var(--orange-border)}.findings-info{background:var(--blue-bg);border:1px solid var(--blue-border)}.findings-group h3{font-size:.95rem;margin-bottom:.75rem;color:var(--text-bright)}.finding-item{display:flex;gap:.75rem;align-items:flex-start;margin-bottom:.6rem}.finding-item:last-child{margin-bottom:0}.finding-icon{font-size:1.1rem;flex-shrink:0}.finding-item p{font-size:.85rem;line-height:1.5}.alert-inline{background:var(--red-bg);border:1px solid var(--red-border);padding:.75rem 1rem;border-radius:6px;font-size:.85rem;margin-bottom:.75rem;color:var(--text)}
.actions-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem}.action-card{padding:1.25rem;background:var(--bg-card-alt);border:1px solid var(--border);border-radius:8px}.action-card.action-priority{border-color:var(--red-border);background:var(--red-bg)}.action-num{width:28px;height:28px;display:flex;align-items:center;justify-content:center;background:var(--accent);color:var(--bg);font-weight:700;font-size:.8rem;border-radius:50%;margin-bottom:.75rem}.action-priority .action-num{background:var(--red)}.action-card h4{font-size:.95rem;color:var(--text-bright);margin-bottom:.5rem}.action-card p{font-size:.82rem;color:var(--text-dim);line-height:1.5}.action-card code{font-size:.75rem}
details{margin-top:.5rem}summary{cursor:pointer;font-size:.85rem;color:var(--accent);font-weight:500;padding:.4rem 0}summary:hover{text-decoration:underline}.help-text{font-size:.82rem;color:var(--text-dim);margin-bottom:.75rem}.footer{text-align:center;padding:2rem 0;border-top:1px solid var(--border);margin-top:2rem;color:var(--text-dim);font-size:.8rem}
@media print{body{background:#fff;color:#111}.section{border:1px solid #ccc;break-inside:avoid}}@media(max-width:600px){.container{padding:1rem}.score-section{flex-direction:column;text-align:center}.sys-grid{grid-template-columns:1fr}.actions-grid{grid-template-columns:1fr}}
"""


def build_html_report(
    sys_info,
    intel_check,
    bsod_data,
    event_data,
    driver_data,
    disk_data,
    mem_data,
    thermal_data,
    update_history,
    app_crashes,
    app_hangs,
    critical,
    warnings,
    info,
    score,
    score_label,
    score_color,
    warranty=None,
):
    """Assemble the full HTML diagnostic report.

    Returns:
        str: Complete HTML document.
    """
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    svg_dash = round(326.7 * score / 100, 1)
    si = sys_info  # shorthand

    # Crash table
    crash_html = ""
    if bsod_data["CrashSummary"]:
        crash_html = '<div class="subsection"><h3>Recent BSOD Events</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Bug Check</th><th>Details</th></tr></thead><tbody>'
        for c in bsod_data["CrashSummary"][:15]:
            crash_html += f'<tr><td class="nowrap">{he(c["Date"])}</td><td><code>{he(c["BugCheckCode"])}</code></td><td class="msg-cell">{he(c["Message"])}</td></tr>'
        crash_html += "</tbody></table></div></div>"

    # Minidump table
    minidump_html = ""
    if bsod_data["MinidumpFiles"]:
        minidump_html = '<div class="subsection"><h3>Minidump Files</h3><p class="help-text">Analyze with <strong>WinDbg</strong> (Microsoft Store): <code>.symfix; .reload; !analyze -v</code></p><div class="table-wrap"><table><thead><tr><th>File</th><th>Date</th><th>Size</th></tr></thead><tbody>'
        for m in bsod_data["MinidumpFiles"]:
            minidump_html += f'<tr><td><code>{he(m["FileName"])}</code></td><td class="nowrap">{he(m["Date"])}</td><td>{m["SizeKB"]} KB</td></tr>'
        minidump_html += "</tbody></table></div></div>"

    # Kernel-Power
    kp_html = ""
    if bsod_data["UnexpectedShutdowns"] > 0:
        kp_html = f'<div class="subsection"><h3>Unexpected Shutdowns - Kernel-Power 41</h3><p>{bsod_data["UnexpectedShutdowns"]} events found -- system lost power or crashed without clean shutdown.</p><div class="table-wrap"><table><thead><tr><th>Date</th><th>Details</th></tr></thead><tbody>'
        for kp in bsod_data["UnexpectedShutdownDetails"]:
            kp_html += f'<tr><td class="nowrap">{he(kp["Date"])}</td><td class="msg-cell">{he(kp["Message"])}</td></tr>'
        kp_html += "</tbody></table></div></div>"

    # WHEA
    whea_html = ""
    if event_data["WHEAErrors"]:
        whea_html = (
            '<div class="subsection"><h3>WHEA Hardware Errors</h3><p class="alert-inline"><strong>WHEA errors are strong indicators of hardware failure.</strong> With an Intel 13th/14th Gen CPU, these often signal voltage-induced CPU degradation.</p>'
            + build_event_table(event_data["WHEAErrors"], 20, True)
            + "</div>"
        )

    # System critical
    sys_crit_html = (
        f'<div class="subsection"><h3>System Critical Events</h3>{build_event_table(event_data["SystemCritical"], 15, True)}</div>'
        if event_data["SystemCritical"]
        else ""
    )

    # System errors (collapsible)
    sys_err_html = ""
    if event_data["SystemErrors"]:
        cnt = len(event_data["SystemErrors"])
        sys_err_html = f'<div class="subsection"><h3>System Errors - Last 50</h3><details><summary>Click to expand - {cnt} events</summary>{build_event_table(event_data["SystemErrors"])}</details></div>'

    # Driver tables
    drv_prob_html = ""
    if driver_data["ProblematicDrivers"]:
        drv_prob_html = '<div class="subsection"><h3>Devices with Errors</h3><div class="table-wrap"><table><thead><tr><th>Device</th><th>Error Code</th><th>Status</th></tr></thead><tbody>'
        for d in driver_data["ProblematicDrivers"]:
            drv_prob_html += f'<tr class="err-row"><td>{he(str(d.get("DeviceName", "")))}</td><td>{he(str(d.get("ErrorCode", "")))}</td><td>{he(str(d.get("Status", "")))}</td></tr>'
        drv_prob_html += "</tbody></table></div></div>"

    drv_3p_html = ""
    if driver_data["ThirdPartyDrivers"]:
        cnt = len(driver_data["ThirdPartyDrivers"])
        drv_3p_html = f'<div class="subsection"><h3>Third-Party Drivers - {cnt}</h3><details><summary>Click to expand</summary><div class="table-wrap"><table><thead><tr><th>Device</th><th>Provider</th><th>Version</th><th>Date</th><th>Signed</th></tr></thead><tbody>'
        for d in sorted(driver_data["ThirdPartyDrivers"], key=lambda x: str(x.get("Date", "")), reverse=True):
            sbadge = (
                '<span class="badge badge-ok">Yes</span>'
                if d.get("IsSigned")
                else '<span class="badge badge-crit">NO</span>'
            )
            drv_3p_html += f"<tr><td>{he(str(d.get('DeviceName', '')))}</td><td>{he(str(d.get('Provider', '')))}</td><td><code>{he(str(d.get('Version', '')))}</code></td><td>{he(str(d.get('Date', '')))}</td><td>{sbadge}</td></tr>"
        drv_3p_html += "</tbody></table></div></details></div>"

    # Volume table
    vol_html = '<div class="table-wrap"><table><thead><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size</th><th>Free</th><th>% Free</th><th>Health</th></tr></thead><tbody>'
    for v in disk_data["Volumes"]:
        pf = v.get("PercentFree", 100)
        cls = ' class="err-row"' if pf < 10 else (' class="warn-row"' if pf < 20 else "")
        vol_html += f"<tr{cls}><td><strong>{he(str(v.get('DriveLetter', '')))}</strong></td><td>{he(str(v.get('Label', '')))}</td><td>{he(str(v.get('FileSystem', '')))}</td><td>{v.get('Size_GB', 0)} GB</td><td>{v.get('Free_GB', 0)} GB</td><td>{pf}%</td><td>{he(str(v.get('Health', '')))}</td></tr>"
    vol_html += "</tbody></table></div>"

    # Memory table
    mem_html = '<div class="table-wrap"><table><thead><tr><th>Slot</th><th>Size</th><th>Speed</th><th>Manufacturer</th><th>Part Number</th></tr></thead><tbody>'
    for s in mem_data["Sticks"]:
        mem_html += f"<tr><td>{he(str(s.get('DeviceLocator', '')))}</td><td>{s.get('Capacity_GB', 0)} GB</td><td>{s.get('Speed_MHz', 0)} MHz</td><td>{he(str(s.get('Manufacturer', '')))}</td><td><code>{he(str(s.get('PartNumber', '')))}</code></td></tr>"
    mem_html += "</tbody></table></div>"

    # Thermal
    thermal_html = '<div class="thermal-grid">'
    thermal_html += f'<div class="thermal-card"><span class="stat-label">Power Plan</span><span class="stat-val">{he(str(thermal_data.get("PowerPlan", "")))}</span></div>'
    thermal_html += f'<div class="thermal-card"><span class="stat-label">CPU Performance</span><span class="stat-val">{he(str(thermal_data.get("CPUPerformancePct", "N/A")))}%</span></div>'
    for t in thermal_data.get("Temperatures", []):
        thermal_html += f'<div class="thermal-card"><span class="stat-label">{he(str(t.get("Zone", "")))}</span><span class="stat-val">{t.get("TempC", "")}C / {t.get("TempF", "")}F</span></div>'
    thermal_html += "</div>"

    # Updates table
    update_html = ""
    if update_history:
        update_html = '<div class="subsection"><h3>Recent Windows Updates</h3><div class="table-wrap"><table><thead><tr><th>Date</th><th>Result</th><th>Update</th></tr></thead><tbody>'
        for u in update_history:
            cls = ' class="err-row"' if u.get("Result") == "Failed" else ""
            update_html += f'<tr{cls}><td class="nowrap">{he(str(u.get("Date", "")))}</td><td>{he(str(u.get("Result", "")))}</td><td>{he(str(u.get("Title", "")))}</td></tr>'
        update_html += "</tbody></table></div></div>"

    # App crashes
    app_crash_html = ""
    if app_crashes:
        app_crash_html = f'<div class="subsection"><h3>Application Crashes - {len(app_crashes)}</h3><details><summary>Click to expand</summary><div class="table-wrap"><table><thead><tr><th>Date</th><th>Details</th></tr></thead><tbody>'
        for ac in app_crashes:
            app_crash_html += f'<tr><td class="nowrap">{he(str(ac.get("Date", "")))}</td><td class="msg-cell">{he(safe_truncate(str(ac.get("Message", "")), 400))}</td></tr>'
        app_crash_html += "</tbody></table></div></details></div>"

    # Assemble final HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>System Health Report</title>
<style>{CSS}</style></head>
<body><div class="container">
    <div class="header">
        <h1>&#x1F6E1; System Health Diagnostic Report</h1>
        <div class="subtitle">Generated {report_date}</div>
        <div class="sys-badge">{he(si.get("Manufacturer", ""))} {he(si.get("Model", ""))} | {
        he(si.get("CPUName", ""))
    } | {si.get("TotalRAM_GB", "")} GB RAM</div>
    </div>

    <div class="score-section">
        <div class="score-ring">
            <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8"/>
                <circle cx="60" cy="60" r="52" fill="none" stroke="{score_color}" stroke-width="8" stroke-dasharray="{
        svg_dash
    } 326.7" stroke-linecap="round"/>
            </svg>
            <div class="score-num">{score}</div>
            <div class="score-label">{score_label}</div>
        </div>
        <div class="score-details">
            <h2>Overall System Health</h2>
            <p>Based on analysis of event logs, drivers, hardware status, BSOD history, and Intel CPU microcode.</p>
            <div class="score-counts">
                <span class="cnt-crit">{len(critical)} Critical</span>
                <span class="cnt-warn">{len(warnings)} Warnings</span>
                <span class="cnt-info">{len(info)} Info</span>
            </div>
        </div>
    </div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F50D;</div><h2>Key Findings</h2></div><div class="section-body">{
        build_findings(critical, warnings, info)
    }</div></div>

    {build_intel_section(intel_check, critical)}

    {build_warranty_section(warranty) if warranty else ""}

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F4A5;</div><h2>BSOD / Crash Analysis</h2></div><div class="section-body">
        <div class="subsection">{
        sys_grid(
            [
                ("Minidump Files", len(bsod_data["MinidumpFiles"])),
                ("Crashes - 30 days", bsod_data["RecentCrashes"]),
                ("Unexpected Shutdowns", bsod_data["UnexpectedShutdowns"]),
                ("Bug Check Codes", f"{len(bsod_data['BugCheckCodes'])} unique"),
            ]
        )
    }</div>
        {build_bugcheck_section(bsod_data)}{crash_html}{kp_html}{minidump_html}
    </div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F4CB;</div><h2>Event Log Analysis</h2></div><div class="section-body">{
        whea_html
    }{sys_crit_html}{sys_err_html}</div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x2699;</div><h2>Driver Analysis</h2></div><div class="section-body">
        <div class="subsection">{
        sys_grid(
            [
                ("Total Drivers", driver_data["TotalDrivers"]),
                ("Third-Party", len(driver_data["ThirdPartyDrivers"])),
                ("With Errors", len(driver_data["ProblematicDrivers"])),
                ("Outdated - 2yr+", len(driver_data["OldDrivers"])),
            ]
        )
    }</div>
        {drv_prob_html}{drv_3p_html}
    </div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F4BE;</div><h2>Disk Health</h2></div><div class="section-body">{
        build_disk_cards(disk_data)
    }<div class="subsection"><h3>Volumes</h3>{vol_html}</div></div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F9E0;</div><h2>Memory - RAM</h2></div><div class="section-body">
        <div class="subsection">{
        sys_grid(
            [
                ("Total RAM", f"{mem_data['TotalGB']} GB"),
                ("Sticks Installed", len(mem_data["Sticks"])),
                ("Speed Mismatch", "YES" if mem_data["MismatchWarning"] else "No"),
                ("XMP Concern", "YES - High Speed" if mem_data["XMPWarning"] else "No"),
            ]
        )
    }</div>
        <div class="subsection"><h3>Installed Modules</h3>{mem_html}</div>
    </div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F321;</div><h2>Thermal and Power</h2></div><div class="section-body">{
        thermal_html
    }</div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F4BB;</div><h2>System Information</h2></div><div class="section-body">{
        sys_grid(
            [
                ("Computer", si.get("ComputerName", "")),
                ("Model", f"{si.get('Manufacturer', '')} {si.get('Model', '')}"),
                ("OS", si.get("OSName", "")),
                ("OS Build", f"{si.get('OSVersion', '')} / {si.get('OSBuild', '')}"),
                ("CPU", si.get("CPUName", "")),
                ("Cores / Threads", f"{si.get('CPUCores', '')} / {si.get('CPULogical', '')}"),
                ("Max Clock", si.get("CPUMaxClock", "")),
                ("BIOS", f"{si.get('BIOSVersion', '')} / {si.get('BIOSDate', '')}"),
                ("Baseboard", si.get("Baseboard", "")),
                ("RAM", f"{si.get('TotalRAM_GB', '')} GB"),
                ("Last Boot", si.get("LastBoot", "")),
                ("Uptime", si.get("Uptime", "")),
            ]
        )
    }</div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F504;</div><h2>Windows Updates and Integrity</h2></div><div class="section-body">
        {update_html}
        <div class="subsection"><h3>Recommended Integrity Checks</h3><p class="help-text">Run these in an <strong>Administrator PowerShell</strong>:</p>
        <div style="background:var(--bg-card-alt);padding:1rem;border-radius:6px;border:1px solid var(--border);font-family:var(--mono);font-size:.82rem;line-height:1.8">sfc /scannow<br>DISM /Online /Cleanup-Image /RestoreHealth<br>chkdsk C: /f /r <span style="color:var(--text-dim)">(requires reboot)</span></div></div>
    </div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F4CA;</div><h2>Application Reliability</h2></div><div class="section-body">
        {sys_grid([("App Crashes", len(app_crashes)), ("App Hangs", len(app_hangs))])}
        {app_crash_html}
    </div></div>

    <div class="section"><div class="section-header"><div class="section-icon">&#x1F6E0;</div><h2>Recommended Actions</h2></div><div class="section-body">
        <p class="help-text" style="margin-bottom:1rem">Prioritized steps to resolve BSOD issues. <strong>Red-highlighted steps are highest priority.</strong></p>
        <div class="actions-grid">
            <div class="action-card action-priority"><div class="action-num">1</div><h4>Update Dell BIOS</h4><p>Visit <strong>dell.com/support</strong>, enter Service Tag, download and install the latest BIOS for XPS 8960.</p></div>
            <div class="action-card action-priority"><div class="action-num">2</div><h4>Check Intel Warranty</h4><p>If BSODs persist, visit <strong>warranty.intel.com</strong> -- Intel extended warranty for affected 13th/14th Gen CPUs.</p></div>
            <div class="action-card"><div class="action-num">3</div><h4>Run Memory Diagnostics</h4><p>Windows Memory Diagnostic or <strong>MemTest86</strong> (free) overnight.</p></div>
            <div class="action-card"><div class="action-num">4</div><h4>Disable XMP in BIOS</h4><p>If RAM exceeds 5600 MHz, disable XMP/EXPO and test at JEDEC defaults.</p></div>
            <div class="action-card"><div class="action-num">5</div><h4>Run SFC and DISM</h4><p><code>sfc /scannow</code> then <code>DISM /Online /Cleanup-Image /RestoreHealth</code></p></div>
            <div class="action-card"><div class="action-num">6</div><h4>Update All Drivers</h4><p>Visit <strong>dell.com/support</strong> -- chipset, GPU, and network drivers.</p></div>
            <div class="action-card"><div class="action-num">7</div><h4>Analyze Minidumps</h4><p>Install <strong>WinDbg</strong>, run <code>!analyze -v</code> on .dmp files.</p></div>
            <div class="action-card"><div class="action-num">8</div><h4>Monitor Temperatures</h4><p>Install <strong>HWiNFO64</strong>. i9-14900K should stay below 95C.</p></div>
        </div>
    </div></div>

    <div class="footer">System Health Diagnostic Tool (Python) | {report_date} | {he(si.get("ComputerName", ""))}</div>
</div></body></html>"""

    return html


# ============================================================
# PDF CONVERSION
# ============================================================
def convert_to_pdf(report_path):
    """Convert HTML report to PDF using Edge headless.

    Returns:
        str or None: Path to PDF file, or None if conversion failed.
    """
    pdf_path = report_path.replace(".html", ".pdf")

    edge_paths = [
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    edge_path = next((p for p in edge_paths if os.path.isfile(p)), None)

    if not edge_path:
        cprint("Microsoft Edge not found -- skipping PDF conversion", "yellow")
        return None

    cprint("Converting report to PDF...", "cyan")
    cprint(f"  Edge: {edge_path}", "gray")

    from urllib.parse import quote

    file_uri = "file:///" + quote(report_path.replace("\\", "/"), safe=":/")
    cprint(f"  URI: {file_uri}", "gray")

    attempts = [
        [
            edge_path,
            "--headless=new",
            "--disable-gpu",
            f"--print-to-pdf={pdf_path}",
            "--print-to-pdf-no-header",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=5000",
            file_uri,
        ],
        [
            edge_path,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            f"--print-to-pdf={pdf_path}",
            "--print-to-pdf-no-header",
            file_uri,
        ],
    ]

    for i, cmd_args in enumerate(attempts):
        if os.path.isfile(pdf_path):
            try:
                os.remove(pdf_path)
            except:
                pass

        try:
            result = subprocess.run(cmd_args, timeout=30, capture_output=True, text=True)
            if result.stderr:
                cprint(f"  Attempt {i + 1} stderr: {result.stderr[:200]}", "gray")
        except subprocess.TimeoutExpired:
            cprint(f"  Attempt {i + 1} timed out", "gray")
            continue
        except Exception as e:
            cprint(f"  Attempt {i + 1} error: {e}", "gray")
            continue

        time.sleep(2)

        if os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0:
            pdf_size = round(os.path.getsize(pdf_path) / 1024)
            cprint(f"  PDF created: {pdf_path} ({pdf_size} KB)", "green")
            return pdf_path
        else:
            cprint(f"  Attempt {i + 1} did not produce a PDF", "gray")

    cprint("  PDF conversion failed -- HTML report is still available", "yellow")
    cprint("  You can manually print to PDF from your browser (Ctrl+P)", "gray")
    return None


# ============================================================
# EMAIL REPORT
# ============================================================
def email_list_html(items, color):
    """Build an HTML list of findings for the email body."""
    if not items:
        return '<li style="color:#388e3c;">None found</li>'
    return "".join(f'<li style="margin-bottom:6px;color:{color};">{he(i)}</li>' for i in items)


def send_email_report(
    report_path,
    pdf_path,
    sys_info,
    bsod_data,
    event_data,
    driver_data,
    critical,
    warnings,
    score,
    score_label,
    timestamp,
):
    """Send the diagnostic report via email.

    Returns:
        bool: True if email sent successfully, False otherwise.
    """
    if not os.path.isfile(CRED_FILE):
        cprint("No email configuration found -- skipping email.", "gray")
        cprint("Run Setup-DiagSchedule.ps1 to configure daily email reports.", "gray")
        return False

    cprint("Sending report via email...", "cyan")

    try:
        email_cmd = f"""
$cfg = Import-Clixml -Path '{CRED_FILE}'
@{{
    FromEmail = $cfg.FromEmail
    ToEmail = $cfg.ToEmail
    Password = $cfg.Credential.GetNetworkCredential().Password
}} | ConvertTo-Json
"""
        email_cfg = ps(email_cmd, as_json=True)
        if not email_cfg:
            cprint("  Failed to read email config", "red")
            return False

        from_email = email_cfg["FromEmail"]
        to_email = email_cfg["ToEmail"]
        password = email_cfg["Password"]

        score_tag = "[OK]" if score >= 80 else "[WARN]" if score >= 60 else "[POOR]" if score >= 40 else "[CRITICAL]"
        score_bar_color = (
            "#4caf50" if score >= 80 else "#ff9800" if score >= 60 else "#ff5722" if score >= 40 else "#f44336"
        )

        si = sys_info
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        bc_email = ""
        if bsod_data["BugCheckCodes"]:
            bc_email = '<tr><td colspan="2" style="padding:12px 16px;background:#fff3f3;"><strong style="color:#d32f2f;">Bug Check Codes:</strong><ul style="margin:8px 0 0;padding-left:20px;">'
            for code in bsod_data["BugCheckCodes"]:
                desc = BUGCHECK_LOOKUP.get(code, "Unknown")
                bc_email += f'<li style="margin-bottom:4px;"><strong>{code}</strong> -- {he(desc)}</li>'
            bc_email += "</ul></td></tr>"

        email_body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:640px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">
    <div style="background:#1a1a2e;padding:24px;text-align:center;">
        <h1 style="margin:0;color:#fff;font-size:20px;">System Health Report</h1>
        <p style="margin:6px 0 0;color:#8888aa;font-size:13px;">{he(si.get("Manufacturer", ""))} {he(si.get("Model", ""))} | {he(si.get("CPUName", ""))} | {report_date}</p>
    </div>
    <div style="padding:20px 24px;text-align:center;border-bottom:1px solid #eee;">
        <div style="font-size:48px;font-weight:700;color:{score_bar_color};">{score}<span style="font-size:20px;color:#999;">/100</span></div>
        <div style="font-size:14px;color:#666;text-transform:uppercase;letter-spacing:1px;">{score_label}</div>
        <div style="margin:12px auto 0;max-width:300px;height:8px;background:#e0e0e0;border-radius:4px;overflow:hidden;"><div style="width:{score}%;height:100%;background:{score_bar_color};border-radius:4px;"></div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;">
        <tr style="background:#fafafa;"><td style="padding:10px 16px;border-bottom:1px solid #eee;width:50%;font-size:13px;"><span style="color:#999;">Critical Issues</span><br><strong style="font-size:18px;color:#d32f2f;">{len(critical)}</strong></td><td style="padding:10px 16px;border-bottom:1px solid #eee;width:50%;font-size:13px;"><span style="color:#999;">Warnings</span><br><strong style="font-size:18px;color:#e65100;">{len(warnings)}</strong></td></tr>
        <tr style="background:#fafafa;"><td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">BSODs (30 days)</span><br><strong style="font-size:18px;color:#d32f2f;">{bsod_data["RecentCrashes"]}</strong></td><td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">Unexpected Shutdowns</span><br><strong style="font-size:18px;color:#e65100;">{bsod_data["UnexpectedShutdowns"]}</strong></td></tr>
        <tr style="background:#fafafa;"><td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">WHEA Errors</span><br><strong style="font-size:18px;color:#d32f2f;">{len(event_data["WHEAErrors"])}</strong></td><td style="padding:10px 16px;border-bottom:1px solid #eee;font-size:13px;"><span style="color:#999;">Problem Drivers</span><br><strong style="font-size:18px;color:#e65100;">{len(driver_data["ProblematicDrivers"])}</strong></td></tr>
        {bc_email}
    </table>
    <div style="padding:16px 24px;border-bottom:1px solid #eee;"><h2 style="margin:0 0 10px;font-size:15px;color:#d32f2f;">&#9888; Critical Issues</h2><ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;">{email_list_html(critical, "#d32f2f")}</ul></div>
    <div style="padding:16px 24px;border-bottom:1px solid #eee;"><h2 style="margin:0 0 10px;font-size:15px;color:#e65100;">&#9888; Warnings</h2><ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.6;">{email_list_html(warnings, "#e65100")}</ul></div>
    <div style="padding:16px 24px;background:#fafafa;text-align:center;">
        <p style="margin:0;font-size:12px;color:#999;">Full HTML and PDF reports attached.</p>
        <p style="margin:6px 0 0;font-size:11px;color:#bbb;">System Health Diagnostic Tool | {he(si.get("ComputerName", ""))}</p>
    </div>
</div></body></html>"""

        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = f"{score_tag} System Health: {score}/100 ({score_label}) - {timestamp}"
        msg.attach(MIMEText(email_body, "html"))

        for filepath in [pdf_path, report_path]:
            if filepath and os.path.isfile(filepath):
                with open(filepath, "rb") as af:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(af.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(filepath)}")
                    msg.attach(part)

        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(from_email, password)
            server.send_message(msg)

        cprint(f"  Email sent successfully to {to_email}", "green")
        return True
    except Exception as e:
        cprint(f"  EMAIL FAILED: {e}", "red")
        return False


# ============================================================
# MAIN ENTRY POINT
# ============================================================
def run_windesktopmgr_tests():
    """Run WinDesktopMgr integration tests and return results."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-m", "integration", "-q", "--no-header", "--no-cov", "--tb=line"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=project_dir,
        )
        output = r.stdout + r.stderr
        # Parse "X passed" and "Y failed" from pytest output
        import re as _re

        passed_m = _re.search(r"(\d+) passed", output)
        failed_m = _re.search(r"(\d+) failed", output)
        passed_count = int(passed_m.group(1)) if passed_m else 0
        failed_count = int(failed_m.group(1)) if failed_m else 0
        return {
            "passed": r.returncode == 0,
            "total": passed_count + failed_count,
            "failed": failed_count,
            "output": output,
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "total": 0, "failed": 0, "output": "Integration tests timed out after 120s"}
    except Exception as e:
        return {"passed": False, "total": 0, "failed": 0, "output": str(e)}


def main():
    """Run the full diagnostic and generate report."""
    # Admin check
    if not is_admin():
        print("\n  ERROR: This script must be run as Administrator.")
        print("  Right-click your terminal -> Run as Administrator\n")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    report_path = os.path.join(REPORT_FOLDER, f"SystemHealthReport_{timestamp}.html")

    # Aggregated findings
    all_critical = []
    all_warnings = []
    all_info = []

    print()
    cprint("========================================================", "cyan")
    cprint("  DEEP SYSTEM HEALTH DIAGNOSTIC TOOL (Python)", "cyan")
    cprint(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "cyan")
    cprint("========================================================", "cyan")
    print()
    cprint(f"Report will be saved to: {report_path}", "gray")
    print()

    # Section 1: System Info
    sys_info = collect_system_info()

    # Section 2: Intel CPU Check
    intel_check, crit, warn, inf = check_intel_cpu(sys_info)
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 3: BSOD Analysis
    bsod_data, crit, warn, inf = analyze_bsod()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 4: Event Logs
    event_data, crit, warn, inf = scan_event_logs()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 5: Drivers
    driver_data, crit, warn, inf = analyze_drivers()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 6: Disk Health
    disk_data, crit, warn, inf = check_disk_health()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 7: Memory
    mem_data, crit, warn, inf = analyze_memory()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 8: Thermals
    thermal_data, crit, warn, inf = check_thermals()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 9: Updates
    update_history, crit, warn, inf = check_updates()
    all_critical.extend(crit)
    all_warnings.extend(warn)
    all_info.extend(inf)

    # Section 10: Reliability
    app_crashes, app_hangs = collect_reliability()

    # Warranty readiness data
    warranty = collect_warranty_data(sys_info, intel_check, bsod_data, event_data)

    # Score
    score, score_label, score_color = calculate_score(all_critical, all_warnings)

    # Build HTML report
    print()
    cprint("Generating HTML Report...", "cyan")
    html = build_html_report(
        sys_info,
        intel_check,
        bsod_data,
        event_data,
        driver_data,
        disk_data,
        mem_data,
        thermal_data,
        update_history,
        app_crashes,
        app_hangs,
        all_critical,
        all_warnings,
        all_info,
        score,
        score_label,
        score_color,
        warranty=warranty,
    )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print()
    cprint("========================================================", "green")
    cprint("  HTML REPORT SAVED", "green")
    cprint(f"  {report_path}", "green")
    cprint("========================================================", "green")

    # PDF conversion
    print()
    pdf_path = convert_to_pdf(report_path)

    # Email
    print()
    send_email_report(
        report_path,
        pdf_path,
        sys_info,
        bsod_data,
        event_data,
        driver_data,
        all_critical,
        all_warnings,
        score,
        score_label,
        timestamp,
    )

    # Open report
    try:
        os.startfile(report_path)
    except:
        pass

    # Section 11: WinDesktopMgr Integration Tests
    print()
    cprint("Running WinDesktopMgr integration tests...", "cyan")
    test_result = run_windesktopmgr_tests()
    if test_result["passed"]:
        cprint(f"  ✓ All {test_result['total']} integration tests passed", "green")
    else:
        cprint(f"  ✗ {test_result['failed']} of {test_result['total']} tests failed", "red")
        all_warnings.append(f"WinDesktopMgr integration tests: {test_result['failed']} failure(s)")
        for line in test_result["output"].splitlines()[-10:]:
            if "FAILED" in line or "ERROR" in line:
                cprint(f"    {line.strip()}", "red")

    # Summary
    print()
    cprint("QUICK SUMMARY:", "yellow")
    cprint(f"  Health Score: {score} / 100 ({score_label})", "green" if score >= 60 else "red")
    cprint(f"  Critical Issues: {len(all_critical)}", "red" if all_critical else "green")
    cprint(f"  Warnings: {len(all_warnings)}", "yellow" if all_warnings else "green")
    cprint(
        f"  BSOD Minidumps (30d): {bsod_data['RecentCrashes']}", "red" if bsod_data["RecentCrashes"] > 0 else "green"
    )
    print()


if __name__ == "__main__":
    main()
