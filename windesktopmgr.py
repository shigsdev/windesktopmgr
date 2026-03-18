"""
WinDesktopMgr
Flask backend — driver update checker + BSOD trend dashboard.
Reads from Windows Event Log and existing SystemHealthDiag HTML reports.
"""

from flask import Flask, render_template, jsonify, request
import subprocess, json, threading, re, os, glob, queue, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict

app = Flask(__name__)
APP_DIR   = os.path.dirname(os.path.abspath(__file__))
EVENT_CACHE_FILE  = os.path.join(APP_DIR, "event_id_cache.json")
BSOD_CACHE_FILE   = os.path.join(APP_DIR, "bsod_code_cache.json")

# ─── Driver checker state ─────────────────────────────────────────────────────
_dell_cache   = None
_scan_results = None
_scan_status  = {"status": "idle", "progress": 0, "message": "Ready to scan"}

# ─── Driver category keywords ─────────────────────────────────────────────────
CATEGORIES = {
    "Display": ["display", "video", "graphics", "gpu", "nvidia", "amd radeon",
                "intel uhd", "intel arc", "vga"],
    "Monitor": ["monitor", "ips", "led backlit", "pavilion", "lcd", "oled",
                "curved monitor", "widescreen"],
    "Audio":   ["audio", "sound", "realtek", "speaker", "microphone", "hdmi audio",
                "nahimic", "waves"],
    "Network": ["network", "ethernet", "wi-fi", "wifi", "wireless", "bluetooth",
                "lan", "killer", "intel(r) wi"],
    "Chipset": ["chipset", "management engine", "serial io", "sata", "nvme",
                "rapid storage", "pci", "smbus", "usb", "thunderbolt",
                "intel(r) core", "platform"],
}

# Categories where driver updates are low priority / informational only
LOW_PRIORITY_CATEGORIES = {"Monitor", "Other"}

# Human-readable note shown alongside low-priority driver updates
CATEGORY_NOTES = {
    "Monitor": (
        "Monitor drivers are small metadata files that tell Windows the display name and "
        "resolution capabilities. They contain no executable code and have no impact on "
        "display quality, refresh rate, or color accuracy — those are controlled by your "
        "GPU driver (NVIDIA). A monitor driver update is almost never worth installing."
    ),
}

DELL_API = "https://www.dell.com/support/driver/en-us/ips/api/driverlist/fetchdriversbyproduct"

# ─── BSOD constants ───────────────────────────────────────────────────────────
REPORT_DIR = os.path.join(
    os.environ.get("USERPROFILE", "C:\\Users\\higs7"),
    "OneDrive", "Coding", "Windows Tools", "System Health Reports"
)

BUGCHECK_CODES = {
    "0x00020001": "HYPERVISOR_ERROR",
    "0x0000001e": "KMODE_EXCEPTION_NOT_HANDLED",
    "0x0000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA",
    "0x0000009f": "DRIVER_POWER_STATE_FAILURE",
    "0x00000139": "KERNEL_SECURITY_CHECK_FAILURE",
    "0x0000003b": "SYSTEM_SERVICE_EXCEPTION",
    "0x00000116": "VIDEO_TDR_FAILURE",
    "0x0000007f": "UNEXPECTED_KERNEL_MODE_TRAP",
    "0x000000d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "0x0000000a": "IRQL_NOT_LESS_OR_EQUAL",
    "0x000000ef": "CRITICAL_PROCESS_DIED",
    "0x00000133": "DPC_WATCHDOG_VIOLATION",
    "0x000000c5": "DRIVER_CORRUPTED_EXPOOL",
    "0x000000be": "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
}

RECOMMENDATIONS_DB = {
    "HYPERVISOR_ERROR": {
        "priority": "critical",
        "title": "Hyper-V / CPU Idle State Conflict (intelppm.sys)",
        "detail": (
            "HYPERVISOR_ERROR on the i9-14900K is caused by intelppm.sys interacting "
            "badly with Hyper-V during CPU C-State transitions. "
            "Recommended fixes: (1) Disable Memory Integrity in Windows Security > "
            "Core Isolation, (2) Enter BIOS (run: shutdown /r /fw /t 0) > Advanced > "
            "Power Management and disable C-States, "
            "(3) Update Dell BIOS to the latest available version."
        )
    },
    "DRIVER_POWER_STATE_FAILURE": {
        "priority": "high",
        "title": "Driver Power State Failure",
        "detail": "A driver failed to transition correctly during a system power state change. "
                  "Check for driver updates in the Driver Manager tab, and disable "
                  "Windows Fast Startup under Power Options > Choose what the power button does."
    },
    "KERNEL_SECURITY_CHECK_FAILURE": {
        "priority": "high",
        "title": "Kernel Security Check Failed",
        "detail": "A kernel data structure failed a security integrity check. This often points "
                  "to memory corruption or a faulty driver. Run Windows Memory Diagnostic "
                  "(mdsched.exe) and check for driver updates."
    },
    "PAGE_FAULT_IN_NONPAGED_AREA": {
        "priority": "high",
        "title": "Page Fault in Non-Paged Area",
        "detail": "A process attempted to access paged memory that was unavailable. "
                  "Can be caused by faulty drivers, failing RAM, or corrupt system files. "
                  "Run: sfc /scannow in an admin PowerShell."
    },
    "VIDEO_TDR_FAILURE": {
        "priority": "medium",
        "title": "GPU Driver Timeout / Recovery Failure",
        "detail": "The GPU driver stopped responding and Windows could not recover it. "
                  "Update or roll back your display driver. "
                  "Check GPU temperatures under load with HWiNFO64."
    },
    "SYSTEM_SERVICE_EXCEPTION": {
        "priority": "high",
        "title": "System Service Exception",
        "detail": "A system service generated an exception the error handler did not catch. "
                  "Check the faulty driver listed in crash details and update or remove it."
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# DRIVER CHECKER HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def categorize(name: str, device_class: str) -> str:
    text = f"{name} {device_class}".lower()
    for cat, keywords in CATEGORIES.items():
        if any(kw in text for kw in keywords):
            return cat
    return "Other"


def version_newer(installed: str, latest: str) -> bool:
    try:
        def parse(v):
            return [int(x) for x in re.split(r"[.\-]", str(v)) if x.isdigit()]
        return parse(latest) > parse(installed)
    except Exception:
        return False


def get_installed_drivers() -> list:
    ps = (
        "Get-WmiObject Win32_PnPSignedDriver | "
        "Where-Object { $_.DeviceName -and $_.DriverVersion } | "
        "Select-Object DeviceName, DriverVersion, DriverDate, DeviceClass, Manufacturer | "
        "ConvertTo-Json -Depth 2"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=90
        )
        data = json.loads(r.stdout or "[]")
        return data if isinstance(data, list) else [data]
    except Exception as e:
        print(f"[PS error] {e}")
        return []


def get_windows_update_drivers() -> dict:
    """
    Use Windows Update API via PowerShell to find available driver updates.
    Returns a dict keyed by driver title (lowercase) -> update info.
    """
    global _dell_cache
    if _dell_cache is not None:
        return _dell_cache

    ps = r"""
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
try {
    $Results = $Searcher.Search("Type='Driver' AND IsInstalled=0")
    $out = @()
    foreach ($u in $Results.Updates) {
        $out += [PSCustomObject]@{
            Title       = $u.Title
            Description = $u.Description
            DriverModel = if ($u.DriverModel) { $u.DriverModel } else { "" }
            DriverVersion = if ($u.DriverVersion) { $u.DriverVersion } else { "" }
            DriverManufacturer = if ($u.DriverManufacturer) { $u.DriverManufacturer } else { "" }
        }
    }
    $out | ConvertTo-Json -Depth 2
} catch {
    "[]"
}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60
        )
        raw = r.stdout.strip()
        data = json.loads(raw or "[]")
        updates = data if isinstance(data, list) else [data]
        # Build lookup: normalised title words -> update record
        lookup = {}
        for u in updates:
            title = u.get("Title", "").lower()
            lookup[title] = u
        _dell_cache = lookup
        print(f"[WU] Found {len(lookup)} driver update(s) via Windows Update")
        return lookup
    except Exception as e:
        print(f"[WU error] {e}")
        _dell_cache = {}
        return {}


def find_wu_match(name: str, wu_updates: dict) -> dict | None:
    """Fuzzy-match an installed driver name against Windows Update results."""
    name_clean = re.sub(r"[®™()\[\]]", "", name).lower()
    name_words = set(name_clean.split()) - {"the","a","an","for","with","and","or","of","driver","device","controller","adapter","interface","port","bus"}
    if not name_words:
        return None
    best, best_score = None, 0
    for title, rec in wu_updates.items():
        title_words = set(title.split())
        score = len(name_words & title_words)
        if score > best_score and score >= 2:
            best_score = score
            best = rec
    return best


def run_scan():
    global _scan_results, _scan_status, _dell_cache
    _dell_cache = None
    _scan_status = {"status": "scanning", "progress": 10,
                    "message": "Enumerating installed drivers via WMI…"}
    installed = get_installed_drivers()
    _scan_status = {"status": "scanning", "progress": 40,
                    "message": f"Found {len(installed)} drivers — checking Windows Update for driver updates…"}
    wu_updates = get_windows_update_drivers()
    _scan_status = {"status": "scanning", "progress": 70,
                    "message": f"Found {len(wu_updates)} WU driver update(s) — comparing…"}
    results = []
    for drv in installed:
        name      = drv.get("DeviceName", "Unknown Device")
        version   = drv.get("DriverVersion", "")
        drv_date  = drv.get("DriverDate", "")
        dev_class = drv.get("DeviceClass", "")
        mfr       = drv.get("Manufacturer", "")
        category  = categorize(name, dev_class)

        match        = find_wu_match(name, wu_updates)
        status       = "up_to_date"   # default: assume current if WU has no update
        latest_ver   = None
        latest_date  = None
        download_url = "ms-settings:windowsupdate"

        if match:
            status     = "update_available"
            latest_ver = match.get("DriverVersion") or match.get("Title", "")
        elif not wu_updates:
            # WU query failed entirely — fall back to unknown
            status = "unknown"

        low_priority = category in LOW_PRIORITY_CATEGORIES
        cat_note     = CATEGORY_NOTES.get(category, "")
        results.append({
            "name": name, "version": version, "date": drv_date,
            "category": category, "manufacturer": mfr, "status": status,
            "latest_version": latest_ver, "latest_date": latest_date,
            "download_url": download_url,
            "low_priority": low_priority,
            "category_note": cat_note,
        })

    order = {"update_available": 0, "unknown": 1, "up_to_date": 2}
    # Low-priority categories sort after normal updates even when update_available
    results.sort(key=lambda x: (
        order.get(x["status"], 3) + (10 if x.get("low_priority") and x["status"] == "update_available" else 0),
        x["name"].lower()
    ))
    _scan_results = results
    updates = sum(1 for r in results if r["status"] == "update_available")
    _scan_status = {
        "status": "complete", "progress": 100,
        "message": f"Done — {len(results)} drivers scanned, {updates} update(s) via Windows Update"
    }


# ══════════════════════════════════════════════════════════════════════════════
# BSOD ANALYSIS HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_bsod_events() -> list:
    """Query Windows Event Log for crash-related events (IDs 1001, 41, 6008)."""
    ps = r"""
$results = @()
foreach ($id in @(1001, 41, 6008)) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$id} `
            -MaxEvents 60 -ErrorAction Stop
        foreach ($e in $evts) {
            $results += [PSCustomObject]@{
                EventId      = $e.Id
                TimeCreated  = $e.TimeCreated.ToString('o')
                ProviderName = $e.ProviderName
                Message      = $e.Message
            }
        }
    } catch {}
}
$results | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(r.stdout or "[]")
        return data if isinstance(data, list) else [data]
    except Exception as e:
        print(f"[BSOD event log error] {e}")
        return []


def parse_event(evt: dict):
    """Parse a raw Windows event into a structured crash record."""
    msg = evt.get("Message", "") or ""
    eid = evt.get("EventId", 0)
    ts  = evt.get("TimeCreated", "")

    if eid == 1001:
        m = re.search(r"bugcheck was:\s*(0x[0-9a-fA-F]+)", msg, re.IGNORECASE)
        if not m:
            return None
        raw_code = m.group(1).lower()
        try:
            normalized = f"0x{int(raw_code, 16):08x}"
        except Exception:
            normalized = raw_code
        error_name = BUGCHECK_CODES.get(normalized, f"BUGCHECK_{raw_code.upper()}")
        dm = re.search(r"(\w+\.sys)", msg, re.IGNORECASE)
        faulty_driver = dm.group(1) if dm else None
        return {
            "timestamp": ts, "error_code": error_name,
            "stop_code": normalized, "faulty_driver": faulty_driver,
            "source": "event_log", "event_id": eid,
        }

    if eid in (41, 6008):
        label = "KERNEL_POWER_LOSS" if eid == 41 else "UNEXPECTED_SHUTDOWN"
        return {
            "timestamp": ts, "error_code": label,
            "stop_code": None, "faulty_driver": None,
            "source": "event_log", "event_id": eid,
        }
    return None


def parse_report_crashes(report_path: str) -> list:
    """Extract BSOD data from a SystemHealthDiag HTML report file."""
    crashes = []
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        fname = os.path.basename(report_path)
        dm = re.search(r"(\d{8})_(\d{6})", fname)
        report_ts = None
        if dm:
            try:
                report_ts = datetime.strptime(
                    f"{dm.group(1)}_{dm.group(2)}", "%Y%m%d_%H%M%S"
                ).isoformat()
            except Exception:
                pass

        codes_found = re.findall(
            r"(HYPERVISOR_ERROR|KMODE_EXCEPTION_NOT_HANDLED"
            r"|PAGE_FAULT_IN_NONPAGED_AREA|VIDEO_TDR_FAILURE"
            r"|KERNEL_SECURITY_CHECK_FAILURE|DRIVER_POWER_STATE_FAILURE"
            r"|SYSTEM_SERVICE_EXCEPTION|UNEXPECTED_KERNEL_MODE_TRAP"
            r"|IRQL_NOT_LESS_OR_EQUAL|CRITICAL_PROCESS_DIED"
            r"|DPC_WATCHDOG_VIOLATION|DRIVER_IRQL_NOT_LESS_OR_EQUAL)",
            content, re.IGNORECASE
        )
        drivers_found = re.findall(r"\b(\w+\.sys)\b", content, re.IGNORECASE)
        driver_counts = Counter(d.lower() for d in drivers_found)
        top_driver = driver_counts.most_common(1)[0][0] if driver_counts else None

        stop_m = re.search(r"(0x[0-9a-fA-F]{4,8})", content)
        stop_code = None
        if stop_m:
            raw = stop_m.group(1).lower()
            try:
                stop_code = f"0x{int(raw, 16):08x}"
            except Exception:
                stop_code = raw

        if codes_found and report_ts:
            for code in dict.fromkeys(c.upper() for c in codes_found):
                crashes.append({
                    "timestamp": report_ts,
                    "error_code": code,
                    "stop_code": stop_code,
                    "faulty_driver": top_driver,
                    "source": "health_report",
                    "report_file": fname,
                })
    except Exception as e:
        print(f"[Report parse error] {report_path}: {e}")
    return crashes


def build_recommendations(crashes: list) -> list:
    """
    Build per-stop-code recommendations enriched with driver context.
    Uses get_stop_code_info which checks static KB → cache → background lookup.
    """
    recs    = []
    pending = []   # codes still being looked up

    # Group crashes by error code, keep top faulty driver per code
    error_counts  = Counter(c["error_code"] for c in crashes)
    code_drivers  = {}   # error_code -> most common faulty driver
    for c in crashes:
        ec = c["error_code"]
        fd = c.get("faulty_driver", "")
        if fd:
            code_drivers.setdefault(ec, Counter())[fd] += 1  # type: ignore

    for code, count in error_counts.most_common(8):
        # Resolve the hex stop code from the name or vice-versa
        # BUGCHECK_CODES maps hex→name; here code is already the name
        hex_code = next((h for h, n in BUGCHECK_CODES.items() if n == code), code)
        top_driver = ""
        if code in code_drivers:
            top_driver = code_drivers[code].most_common(1)[0][0]  # type: ignore

        info = get_stop_code_info(hex_code, top_driver)

        if info is None:
            pending.append(code)
            # Add a placeholder so the UI shows something
            recs.append({
                "priority": "high", "count": count,
                "title": f"{code} — looking up details…",
                "detail": f"Fetching description for stop code {hex_code} in the background. "
                          f"Refresh in a few seconds.",
                "driver_context": f"Faulty driver: {top_driver}" if top_driver else "",
                "source": "pending",
            })
            continue

        rec = {
            "priority":       info.get("priority", "high"),
            "count":          count,
            "title":          info.get("title", code),
            "detail":         info.get("detail", ""),
            "action":         info.get("action", ""),
            "driver_context": info.get("driver_context", ""),
            "source":         info.get("source", ""),
        }
        # Prepend driver context to detail if present
        if rec["driver_context"] and rec["driver_context"] not in rec["detail"]:
            rec["detail"] = rec["driver_context"] + " " + rec["detail"]
        recs.append(rec)

    total = len(crashes)
    if total == 0:
        recs.append({
            "priority": "info", "count": 0,
            "title": "System appears stable",
            "detail": "No BSOD events found in the Event Log or health reports. "
                      "Keep drivers up to date and run periodic health scans.",
            "source": "static_kb",
        })
    elif total > 10:
        recs.append({
            "priority": "critical", "count": total,
            "title": f"High crash frequency — {total} crashes detected",
            "detail": "This level of instability warrants immediate attention. "
                      "Run Dell SupportAssist (search for it in the Start menu) to check for hardware faults. "
                      "If crashes persist, RAM could be the cause — Dell SupportAssist includes a memory test, "
                      "or you can boot from a USB with MemTest86 (free tool from memtest86.com that tests RAM "
                      "before Windows loads, bypassing any OS interference).",
            "source": "static_kb",
        })
    elif total >= 3:
        recs.append({
            "priority": "high", "count": total,
            "title": f"Recurring crashes — {total} events found",
            "detail": "Review the faulty drivers below and check the Driver Manager tab "
                      "for pending updates.",
            "source": "static_kb",
        })

    if "HYPERVISOR_ERROR" in error_counts:
        recs.append({
            "priority": "high", "count": error_counts["HYPERVISOR_ERROR"],
            "title": "i9-14900K Raptor Lake Instability — BIOS 2.22.0 includes microcode fix",
            "detail": "HYPERVISOR_ERROR on this CPU is caused by intelppm.sys conflicting with "
                      "Hyper-V during C-State transitions. BIOS 2.22.0 (Jan 2026) includes Intel "
                      "microcode patches for this. Your BIOS is current — focus on C-State and "
                      "Memory Integrity settings if crashes continue.",
            "source": "static_kb",
        })

    seen, unique = set(), []
    for r in recs:
        if r["title"] not in seen:
            seen.add(r["title"])
            unique.append(r)

    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    unique.sort(key=lambda x: order.get(x.get("priority", "info"), 3))
    return unique


def _parse_ts(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _is_this_month(ts: str) -> bool:
    try:
        dt = _parse_ts(ts)
        now = datetime.now(timezone.utc)
        return dt.year == now.year and dt.month == now.month
    except Exception:
        return False


def build_bsod_analysis() -> dict:
    crashes = []

    # 1. Windows Event Log
    for evt in get_bsod_events():
        parsed = parse_event(evt)
        if parsed:
            crashes.append(parsed)

    # 2. Existing HTML health reports
    if os.path.isdir(REPORT_DIR):
        for path in glob.glob(os.path.join(REPORT_DIR, "*.html")):
            crashes += parse_report_crashes(path)

    # Deduplicate by timestamp (minute precision) + error code
    seen, unique_crashes = set(), []
    for c in crashes:
        key = (str(c.get("timestamp", ""))[:16], c.get("error_code", ""))
        if key not in seen:
            seen.add(key)
            unique_crashes.append(c)

    unique_crashes.sort(key=lambda c: _parse_ts(c.get("timestamp", "")), reverse=True)

    # Timeline: last 12 weeks
    now = datetime.now(timezone.utc)
    week_labels = []
    for i in range(11, -1, -1):
        week_labels.append((now - timedelta(weeks=i)).strftime("%b %d"))
    week_buckets = {lbl: 0 for lbl in week_labels}

    for c in unique_crashes:
        dt = _parse_ts(c.get("timestamp", ""))
        if dt == datetime.min:
            continue
        age_weeks = (now - dt).days // 7
        if 0 <= age_weeks < 12:
            lbl = (dt - timedelta(days=dt.weekday())).strftime("%b %d")
            if lbl in week_buckets:
                week_buckets[lbl] += 1

    timeline = [{"label": k, "count": v} for k, v in week_buckets.items()]

    # Error code breakdown
    error_counts  = Counter(c["error_code"] for c in unique_crashes)
    error_breakdown = [{"code": k, "count": v} for k, v in error_counts.most_common(8)]

    # Faulty driver breakdown
    driver_counts = Counter(
        c["faulty_driver"] for c in unique_crashes if c.get("faulty_driver")
    )
    driver_breakdown = [{"driver": k, "count": v} for k, v in driver_counts.most_common(8)]

    # Uptime between crashes
    sorted_asc = sorted(
        [c for c in unique_crashes if c.get("timestamp")],
        key=lambda c: _parse_ts(c.get("timestamp", ""))
    )
    uptime_periods = []
    for i in range(1, len(sorted_asc)):
        t1 = _parse_ts(sorted_asc[i-1]["timestamp"])
        t2 = _parse_ts(sorted_asc[i]["timestamp"])
        if t1 != datetime.min and t2 != datetime.min:
            hours = round((t2 - t1).total_seconds() / 3600, 1)
            uptime_periods.append({
                "start": sorted_asc[i-1]["timestamp"],
                "end":   sorted_asc[i]["timestamp"],
                "hours": hours,
            })

    avg_uptime  = (
        round(sum(p["hours"] for p in uptime_periods) / len(uptime_periods), 1)
        if uptime_periods else 0
    )
    this_month  = sum(1 for c in unique_crashes if _is_this_month(c.get("timestamp", "")))
    most_common = error_counts.most_common(1)[0][0] if error_counts else "None"

    return {
        "summary": {
            "total_crashes":     len(unique_crashes),
            "this_month":        this_month,
            "most_common_error": most_common,
            "avg_uptime_hours":  avg_uptime,
        },
        "crashes":         unique_crashes[:60],
        "timeline":        timeline,
        "error_codes":     error_breakdown,
        "faulty_drivers":  driver_breakdown,
        "uptime_periods":  uptime_periods[-12:],
        "recommendations": build_recommendations(unique_crashes),
    }




# ══════════════════════════════════════════════════════════════════════════════
# STARTUP MANAGER
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATTERNS = [
    r"\\temp\\", r"\\tmp\\", r"\\downloads\\",
    r"[0-9a-f]{8,}\.exe", r"\\users\\public\\",
    r"\\appdata\\local\\temp",
]


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP ITEM ENRICHMENT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
#
# For each startup item we provide:
#   - plain_name  : human-friendly name ("OneDrive sync client")
#   - publisher   : who made it ("Microsoft")
#   - what        : one sentence on what it does
#   - impact      : boot speed impact (low / medium / high)
#   - safe_to_disable : True/False with explanation
#   - recommendation  : keep / disable / optional
#
# Lookup chain:
#   1. Static STARTUP_KB  (keyed by exe name — instant, highest quality)
#   2. Local cache file   (startup_item_cache.json)
#   3. Windows file version info (PowerShell Get-Item — offline, always current)
#   4. Generic placeholder
# ══════════════════════════════════════════════════════════════════════════════

STARTUP_CACHE_FILE = os.path.join(APP_DIR, "startup_item_cache.json")
_startup_cache_lock = threading.Lock()
_startup_cache: dict = {}
_startup_queue: queue.Queue = queue.Queue()
_startup_in_flight: set = set()

# Keyed by lowercase exe filename (no path, no extension)
STARTUP_KB: dict = {
    # ── Microsoft core ────────────────────────────────────────────────────
    "onedrive": {
        "plain_name": "Microsoft OneDrive",
        "publisher": "Microsoft",
        "what": "Keeps your OneDrive folder synced with the cloud. "
                "Required if you store files in OneDrive (your health reports live there).",
        "impact": "medium",
        "safe_to_disable": False,
        "recommendation": "keep",
        "reason": "Your SystemHealthDiag reports save to OneDrive — disabling sync "
                  "could mean reports don't back up properly.",
    },
    "ms-teams": {
        "plain_name": "Microsoft Teams",
        "publisher": "Microsoft",
        "what": "Loads Teams in the background so it's ready when you open it.",
        "impact": "high",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "High memory use. Safe to disable — Teams will still open when you "
                  "launch it manually, just takes a few extra seconds.",
    },
    "teams": {
        "plain_name": "Microsoft Teams",
        "publisher": "Microsoft",
        "what": "Loads Teams in the background so it's ready when you open it.",
        "impact": "high",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "High memory use. Safe to disable if you don't need Teams "
                  "immediately on login.",
    },
    "discord": {
        "plain_name": "Discord",
        "publisher": "Discord Inc.",
        "what": "Starts the Discord chat/voice app in the system tray on login.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. Discord opens fine when launched manually.",
    },
    "slack": {
        "plain_name": "Slack",
        "publisher": "Slack Technologies",
        "what": "Starts the Slack messaging app in the background on login.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't need Slack notifications immediately "
                  "on login.",
    },
    "zoom": {
        "plain_name": "Zoom",
        "publisher": "Zoom Video Communications",
        "what": "Pre-loads Zoom so it starts faster when joining meetings.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. Zoom still works when launched manually.",
    },
    "spotify": {
        "plain_name": "Spotify",
        "publisher": "Spotify AB",
        "what": "Starts Spotify in the background on login.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Pure convenience — no system function. Safe to disable.",
    },
    "steam": {
        "plain_name": "Steam",
        "publisher": "Valve Corporation",
        "what": "Starts the Steam gaming platform on login.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. Steam launches fine when you open it manually.",
    },
    "epicgameslauncher": {
        "plain_name": "Epic Games Launcher",
        "publisher": "Epic Games",
        "what": "Starts the Epic Games store/launcher on login.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. Epic still works when launched manually.",
    },
    "googledrivefs": {
        "plain_name": "Google Drive",
        "publisher": "Google",
        "what": "Keeps your Google Drive folder synced with the cloud.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't need constant Google Drive sync. "
                  "Files sync when you relaunch it.",
    },
    "dropbox": {
        "plain_name": "Dropbox",
        "publisher": "Dropbox Inc.",
        "what": "Keeps your Dropbox folder synced with the cloud.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't need constant Dropbox sync.",
    },
    # ── Windows system / Dell ─────────────────────────────────────────────
    "securityhealthsystray": {
        "plain_name": "Windows Security tray icon",
        "publisher": "Microsoft",
        "what": "Shows the Windows Security shield icon in the system tray. "
                "Does not affect actual security protection.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Removing the tray icon doesn't disable Windows Defender — "
                  "protection still runs. Safe to disable if you prefer a cleaner tray.",
    },
    "sgrmbroker": {
        "plain_name": "System Guard Runtime Monitor Broker",
        "publisher": "Microsoft",
        "what": "Part of Windows security — monitors system integrity at runtime.",
        "impact": "low",
        "safe_to_disable": False,
        "recommendation": "keep",
        "reason": "Windows security component. Should not be disabled.",
    },
    "ctfmon": {
        "plain_name": "CTF Loader (Text Input Processor)",
        "publisher": "Microsoft",
        "what": "Supports alternative text input methods — handwriting, speech, "
                "on-screen keyboard, and IME language bars.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you only use a standard keyboard and don't "
                  "use speech input, handwriting, or non-English IME.",
    },
    "dellsupportassistremediationservice": {
        "plain_name": "Dell SupportAssist Remediation",
        "publisher": "Dell Inc.",
        "what": "Background component of Dell SupportAssist that scans for hardware "
                "issues and downloads driver updates automatically.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "WinDesktopMgr handles driver checks manually. Safe to disable "
                  "if you prefer to manage updates yourself.",
    },
    "dellsupportassist": {
        "plain_name": "Dell SupportAssist",
        "publisher": "Dell Inc.",
        "what": "Dell's diagnostic and support tool — checks hardware health and "
                "manages driver updates.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "WinDesktopMgr covers the same ground. Safe to disable.",
    },
    "dellcommandupdate": {
        "plain_name": "Dell Command Update",
        "publisher": "Dell Inc.",
        "what": "Automatically checks for and installs Dell BIOS, driver, and "
                "firmware updates.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Useful for keeping Dell firmware current but runs fine on demand. "
                  "Safe to disable from startup.",
    },
    "delldigitaldelivery": {
        "plain_name": "Dell Digital Delivery",
        "publisher": "Dell Inc.",
        "what": "Delivers software purchased with your Dell PC.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "disable",
        "reason": "Only needed when setting up a new Dell. Safe to disable on an "
                  "established system.",
    },
    "realtek hd audio manager": {
        "plain_name": "Realtek HD Audio Manager",
        "publisher": "Realtek Semiconductor",
        "what": "Provides the system tray icon and settings UI for your Realtek "
                "audio hardware.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Audio still works without it. Only needed if you regularly "
                  "change audio settings via the Realtek panel.",
    },
    "ravcpl64": {
        "plain_name": "Realtek Audio Control Panel",
        "publisher": "Realtek Semiconductor",
        "what": "Loads the Realtek audio settings panel in the system tray.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Audio still works without it. Safe to disable.",
    },
    "nvbackend": {
        "plain_name": "NVIDIA GeForce Experience Backend",
        "publisher": "NVIDIA Corporation",
        "what": "Background service for NVIDIA GeForce Experience — enables "
                "game optimisation, driver notifications, and ShadowPlay.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't use GeForce Experience features. "
                  "Your NVIDIA driver still works fine without it.",
    },
    "nvcplui": {
        "plain_name": "NVIDIA Control Panel UI",
        "publisher": "NVIDIA Corporation",
        "what": "Pre-loads the NVIDIA Control Panel for faster access.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Control Panel still opens when launched manually. Safe to disable.",
    },
    "amdrsserv": {
        "plain_name": "AMD Radeon Software",
        "publisher": "AMD",
        "what": "Background service for AMD Radeon Software — enables game "
                "optimisation and driver notifications.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't use Radeon Software features.",
    },
    "ipoint": {
        "plain_name": "Microsoft IntelliPoint (Mouse Software)",
        "publisher": "Microsoft",
        "what": "Provides advanced settings for Microsoft mice — extra buttons, "
                "scroll speed, etc.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Basic mouse functions work without it. Only keep if you use "
                  "advanced Microsoft mouse features.",
    },
    "itype": {
        "plain_name": "Microsoft IntelliType (Keyboard Software)",
        "publisher": "Microsoft",
        "what": "Provides advanced settings for Microsoft keyboards.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Basic keyboard functions work without it.",
    },
    "lghub": {
        "plain_name": "Logitech G HUB",
        "publisher": "Logitech",
        "what": "Manages profiles, lighting, and macros for Logitech G-series "
                "peripherals.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Peripherals work at default settings without it. Disable if "
                  "you don't use custom profiles or lighting.",
    },
    "razercentralservice": {
        "plain_name": "Razer Central",
        "publisher": "Razer Inc.",
        "what": "Background service for Razer Synapse — manages lighting and "
                "macros for Razer peripherals.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Peripherals work at default settings without it.",
    },
    "nordvpn": {
        "plain_name": "NordVPN",
        "publisher": "Nord Security",
        "what": "Starts the NordVPN client in the background on login.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. VPN still connects when you open NordVPN manually.",
    },
    "expressvpn": {
        "plain_name": "ExpressVPN",
        "publisher": "ExpressVPN International Ltd.",
        "what": "Starts the ExpressVPN client in the background on login.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable. VPN still connects when launched manually.",
    },
    "windesktopmgr": {
        "plain_name": "WinDesktopMgr (this app)",
        "publisher": "Local",
        "what": "Your Windows system management tool — driver checker, BSOD "
                "dashboard, disk health, network monitor, and more.",
        "impact": "low",
        "safe_to_disable": False,
        "recommendation": "keep",
        "reason": "This is WinDesktopMgr itself. Keep enabled to have your "
                  "dashboard ready at login.",
    },
    # ── Windows built-in tasks (commonly seen in Task Scheduler) ──────────
    "microsoftedgeupdate": {
        "plain_name": "Microsoft Edge Update",
        "publisher": "Microsoft",
        "what": "Keeps Microsoft Edge browser up to date.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Edge updates also happen via Windows Update. Safe to disable "
                  "from startup if you prefer manual control.",
    },
    "googleupdatetaskmachinecore": {
        "plain_name": "Google Update (System)",
        "publisher": "Google",
        "what": "Keeps Google Chrome and other Google apps up to date.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Chrome will prompt to update when you open it. Safe to disable.",
    },
    "googleupdatetaskmachineuatask": {
        "plain_name": "Google Update (User)",
        "publisher": "Google",
        "what": "User-level companion to the Google Update task.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable alongside the machine-level Google Update task.",
    },
}

# Recommendation badge colours
STARTUP_REC_STYLE = {
    "keep":     {"color": "var(--cyan)",   "label": "Keep"},
    "optional": {"color": "var(--orange)", "label": "Optional"},
    "disable":  {"color": "var(--red)",    "label": "Disable"},
}


def _load_startup_cache():
    global _startup_cache
    if not os.path.exists(STARTUP_CACHE_FILE):
        _startup_cache = {}
        return
    try:
        with open(STARTUP_CACHE_FILE, encoding="utf-8") as f:
            _startup_cache = json.load(f)
        print(f"[StartupCache] Loaded {len(_startup_cache)} cached items")
    except Exception as e:
        print(f"[StartupCache] Load error: {e}")
        _startup_cache = {}


def _save_startup_cache():
    try:
        with _startup_cache_lock:
            with open(STARTUP_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_startup_cache, f, indent=2)
    except Exception as e:
        print(f"[StartupCache] Save error: {e}")


def _extract_exe_from_command(command: str) -> str:
    """Extract the bare exe filename (no path, no extension) from a command string."""
    if not command:
        return ""
    cmd = command.strip().strip('"')
    # Take just the executable part (before any arguments)
    exe_path = cmd.split('"')[0].split()[0] if cmd else ""
    exe_name = os.path.basename(exe_path)
    return os.path.splitext(exe_name)[0].lower()


def _lookup_startup_via_fileinfo(command: str, name: str) -> dict | None:
    """
    Read Windows file version info for the executable — publisher, description,
    version — using PowerShell Get-Item. Completely offline.
    """
    # Extract exe path from command
    cmd = command.strip()
    # Handle quoted paths
    if cmd.startswith('"'):
        exe_path = cmd.split('"')[1] if '"' in cmd[1:] else cmd[1:]
    else:
        exe_path = cmd.split()[0] if cmd else ""

    if not exe_path or not exe_path.lower().endswith(".exe"):
        # Try to find it on PATH via where.exe
        exe_name = _extract_exe_from_command(command) + ".exe"
        ps_find = f'(Get-Command "{exe_name}" -EA SilentlyContinue)?.Source'
        try:
            r0 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_find],
                                capture_output=True, text=True, timeout=5)
            found = r0.stdout.strip()
            if found:
                exe_path = found
        except Exception:
            pass

    if not exe_path:
        return None

    ps = f"""
try {{
    $f = Get-Item "{exe_path}" -EA Stop
    $v = $f.VersionInfo
    [PSCustomObject]@{{
        FileDescription  = $v.FileDescription
        CompanyName      = $v.CompanyName
        ProductName      = $v.ProductName
        FileVersion      = $v.FileVersion
        FileName         = $f.Name
    }} | ConvertTo-Json
}} catch {{ }}
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=10)
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc    = (data.get("FileDescription") or "").strip()
        company = (data.get("CompanyName") or "").strip()
        product = (data.get("ProductName") or "").strip()
        version = (data.get("FileVersion") or "").strip()
        fname   = (data.get("FileName") or name).strip()

        if not desc and not company:
            return None

        plain_name = product or desc or fname
        what = desc if desc else f"Executable from {company or 'unknown publisher'}."
        # Heuristic: Microsoft/Windows components are generally safe to keep
        is_ms = any(kw in company.lower() for kw in ("microsoft", "windows"))
        is_system = any(p in exe_path.lower() for p in
                        ("\\windows\\", "\\system32\\", "\\syswow64\\", "\\winsxs\\"))
        if is_system:
            rec = "keep"
            safe = False
            reason = "Windows system component — should not be disabled."
        elif is_ms and not is_system:
            rec = "optional"
            safe = True
            reason = f"Microsoft application ({product or desc}). Safe to disable from startup if not needed at login."
        else:
            rec = "optional"
            safe = True
            reason = f"Third-party application by {company or 'unknown publisher'}. Review whether you need it at login."

        return {
            "source":         "file_version_info",
            "plain_name":     plain_name,
            "publisher":      company or "Unknown",
            "what":           what,
            "version":        version,
            "impact":         "low",
            "safe_to_disable": safe,
            "recommendation": rec,
            "reason":         reason,
            "fetched":        datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[StartupLookup] file info failed for {exe_path}: {e}")
        return None


def _lookup_startup_via_web(exe_name: str, item_name: str) -> dict | None:
    """
    Web fallback: search Microsoft Learn + a general query for the exe/item name.
    Uses two targeted queries and synthesises a result.
    """
    # Try queries from most to least specific
    queries = [
        f"{exe_name}.exe startup windows what is",
        f"{item_name} startup program windows",
    ]
    for raw_q in queries:
        try:
            q   = urllib.parse.quote(raw_q)
            url = (f"https://learn.microsoft.com/api/search?search={q}"
                   f"&locale=en-us&%24top=3&facet=products")
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top     = results[0]
            title   = top.get("title", "").strip()
            summary = (top.get("summary") or "").strip()[:300]
            url_ref = top.get("url", "")
            # Filter out irrelevant results (e.g. generic Windows docs)
            skip_terms = ("visual studio", "azure", "powershell module",
                          "api reference", "net framework class")
            if any(t in title.lower() for t in skip_terms):
                continue
            if not summary:
                continue
            return {
                "source":          "microsoft_learn",
                "plain_name":      title or item_name,
                "publisher":       "See details",
                "what":            summary,
                "impact":          "unknown",
                "safe_to_disable": True,
                "recommendation":  "optional",
                "reason":          f"Based on web lookup. Full details: {url_ref}",
                "url":             url_ref,
                "fetched":         datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            print(f"[StartupWebLookup] failed for {exe_name}: {e}")
            continue
    return None


def _startup_lookup_worker():
    """Background thread — enriches unknown startup items."""
    while True:
        item_key = None
        try:
            raw = _startup_queue.get(timeout=5)
            # Queue entries can be either:
            #   (key, command, name)  — from normal lookup / bulk route
            #   key string            — from _requeue_stale_cache
            if isinstance(raw, tuple):
                item_key, command, name = raw
            else:
                item_key = raw
                command  = ""
                name     = raw   # use the key as the display name
            with _startup_cache_lock:
                if item_key in _startup_cache:
                    _startup_in_flight.discard(item_key)
                    _startup_queue.task_done()
                    continue

            print(f"[StartupCache] Looking up: {name}")
            result = _lookup_startup_via_fileinfo(command, name)

            # Web search fallback
            if not result:
                exe_key_w = _extract_exe_from_command(command)
                result = _lookup_startup_via_web(exe_key_w, name)

            # Final placeholder — should rarely reach here
            if not result:
                result = {
                    "source":          "unknown",
                    "plain_name":      name,
                    "publisher":       "Unknown",
                    "what":            "No description found via file info or web search.",
                    "impact":          "unknown",
                    "safe_to_disable": True,
                    "recommendation":  "optional",
                    "reason":          "Research this item before disabling: search "
                                       f"\"{name} startup windows\" online.",
                    "fetched":         datetime.now(timezone.utc).isoformat(),
                }

            with _startup_cache_lock:
                _startup_cache[item_key] = result
            _save_startup_cache()
            print(f"[StartupCache] Cached: {name} (source: {result['source']})")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"[StartupLookupWorker] error: {e}")
        finally:
            try:
                if item_key:
                    _startup_in_flight.discard(item_key)
                _startup_queue.task_done()
            except Exception:
                pass


def get_startup_item_info(name: str, command: str) -> dict | None:
    """
    Main entry point — returns enriched info for a startup item.
    Checks static KB → cache → queues background lookup.
    Returns None if lookup is pending.
    """
    exe_key = _extract_exe_from_command(command)
    name_key = name.lower()

    # 1. Static KB — try exe name then item name
    for k in (exe_key, name_key):
        if k in STARTUP_KB:
            info = dict(STARTUP_KB[k])
            info["source"] = "static_kb"
            return info

    # Also try partial match on name (catches "WinDesktopMgr" task name variants)
    for kb_key, kb_val in STARTUP_KB.items():
        if kb_key in name_key or kb_key in exe_key:
            info = dict(kb_val)
            info["source"] = "static_kb"
            return info

    # 2. Cache
    cache_key = exe_key or name_key
    with _startup_cache_lock:
        if cache_key in _startup_cache:
            return _startup_cache[cache_key]

    # 3. Queue background lookup
    if cache_key and cache_key not in _startup_in_flight:
        _startup_in_flight.add(cache_key)
        _startup_queue.put((cache_key, command, name))

    return None


def get_startup_items() -> list:
    ps = r"""
$items = @()
# HKLM Run
try {
    $k = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -EA Stop
    $k.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.Name; Command=$_.Value; Location="HKLM Run"; Type="registry_hklm"; Enabled=$true }
    }
} catch {}
# HKLM Run (disabled)
try {
    $k = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run-Disabled" -EA Stop
    $k.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.Name; Command=$_.Value; Location="HKLM Run"; Type="registry_hklm"; Enabled=$false }
    }
} catch {}
# HKCU Run
try {
    $k = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -EA Stop
    $k.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.Name; Command=$_.Value; Location="HKCU Run"; Type="registry_hkcu"; Enabled=$true }
    }
} catch {}
# HKCU Run (disabled)
try {
    $k = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run-Disabled" -EA Stop
    $k.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.Name; Command=$_.Value; Location="HKCU Run"; Type="registry_hkcu"; Enabled=$false }
    }
} catch {}
# Startup folder - all users
try {
    $f = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    Get-ChildItem $f -EA Stop | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.BaseName; Command=$_.FullName; Location="Startup Folder (All Users)"; Type="folder"; Enabled=$true }
    }
} catch {}
# Startup folder - current user
try {
    $f = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    Get-ChildItem $f -EA Stop | ForEach-Object {
        $items += [PSCustomObject]@{ Name=$_.BaseName; Command=$_.FullName; Location="Startup Folder (User)"; Type="folder"; Enabled=$true }
    }
} catch {}
# Scheduled tasks with logon/boot triggers
try {
    Get-ScheduledTask | Where-Object {
        ($_.Triggers | Where-Object { $_.CimClass.CimClassName -match "LogonTrigger|BootTrigger" })
    } | ForEach-Object {
        $act = $_.Actions | Select-Object -First 1
        $cmd = if ($act.Execute) { "$($act.Execute) $($act.Arguments)".Trim() } else { $_.TaskName }
        $items += [PSCustomObject]@{ Name=$_.TaskName; Command=$cmd; Location="Task Scheduler"; Type="task"; Enabled=($_.State -ne "Disabled") }
    }
} catch {}
$items | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout.strip() or "[]")
        items = data if isinstance(data, list) else [data]
        for item in items:
            cmd = (item.get("Command") or "").lower()
            item["suspicious"] = any(re.search(p, cmd) for p in SUSPICIOUS_PATTERNS)
            # Attach enrichment info (may be None if still pending)
            info = get_startup_item_info(item.get("Name",""), item.get("Command",""))
            item["info"] = info

        # Sort: suspicious first, then by recommendation priority, then name
        rec_order = {"disable": 0, "optional": 1, "keep": 2, None: 3}
        items.sort(key=lambda x: (
            not x.get("suspicious", False),
            rec_order.get((x.get("info") or {}).get("recommendation"), 3),
            x.get("Name", "").lower()
        ))
        return items
    except Exception as e:
        print(f"[Startup error] {e}")
        return []


def toggle_startup_item(name: str, item_type: str, enable: bool) -> dict:
    safe_name = re.sub(r"[^\w\s\-\.]", "", name)
    if item_type in ("registry_hklm", "registry_hkcu"):
        hive = "HKLM" if item_type == "registry_hklm" else "HKCU"
        src  = f"{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        dst  = f"{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run-Disabled"
        if enable:
            ps = (f'$v=(Get-ItemProperty "{dst}" -Name "{safe_name}" -EA Stop)."{safe_name}"; '
                  f'Set-ItemProperty "{src}" -Name "{safe_name}" -Value $v; '
                  f'Remove-ItemProperty "{dst}" -Name "{safe_name}"')
        else:
            ps = (f'$v=(Get-ItemProperty "{src}" -Name "{safe_name}" -EA Stop)."{safe_name}"; '
                  f'if (-not (Test-Path "{dst}")) {{ New-Item "{dst}" -Force | Out-Null }}; '
                  f'Set-ItemProperty "{dst}" -Name "{safe_name}" -Value $v; '
                  f'Remove-ItemProperty "{src}" -Name "{safe_name}"')
    elif item_type == "task":
        action = "Enable-ScheduledTask" if enable else "Disable-ScheduledTask"
        ps = f'{action} -TaskName "{safe_name}" -EA Stop'
    else:
        return {"ok": False, "error": "Cannot toggle this item type"}
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=15)
        return {"ok": r.returncode == 0, "error": r.stderr.strip() if r.returncode != 0 else ""}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# DISK HEALTH
# ══════════════════════════════════════════════════════════════════════════════

def get_disk_health() -> dict:
    ps = r"""
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object {
    [PSCustomObject]@{
        Letter   = $_.Name
        Label    = $_.Description
        UsedGB   = [math]::Round($_.Used  / 1GB, 2)
        FreeGB   = [math]::Round($_.Free  / 1GB, 2)
        TotalGB  = [math]::Round(($_.Used + $_.Free) / 1GB, 2)
        PctUsed  = if (($_.Used + $_.Free) -gt 0) { [math]::Round($_.Used / ($_.Used + $_.Free) * 100, 1) } else { 0 }
    }
}
$physical = Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name       = $_.FriendlyName
        MediaType  = $_.MediaType
        SizeGB     = [math]::Round($_.Size / 1GB, 1)
        Health     = $_.HealthStatus
        Status     = $_.OperationalStatus
        BusType    = $_.BusType
    }
}
# Disk temperatures via CIM (works on NVMe/SATA)
$temps = @()
try {
    $t = Get-CimInstance -Namespace "ROOT\Microsoft\Windows\Storage" -ClassName "MSFT_Disk" -EA Stop
} catch {}
@{ drives=$drives; physical=$physical } | ConvertTo-Json -Depth 3
"""
    ps_io = r"""
$diskIO = Get-Counter "\PhysicalDisk(*)\Disk Read Bytes/sec","\PhysicalDisk(*)\Disk Write Bytes/sec" -SampleInterval 1 -MaxSamples 1 -EA SilentlyContinue
$result = @()
if ($diskIO) {
    $diskIO.CounterSamples | ForEach-Object {
        $result += [PSCustomObject]@{ Counter=$_.Path; Value=[math]::Round($_.CookedValue/1KB,1) }
    }
}
$result | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout.strip() or "{}")
        drives   = data.get("drives") or []
        physical = data.get("physical") or []
        if isinstance(drives, dict):   drives   = [drives]
        if isinstance(physical, dict): physical = [physical]
        # IO stats (best-effort)
        io_data = []
        try:
            r2 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_io],
                                capture_output=True, text=True, timeout=15)
            io_raw = json.loads(r2.stdout.strip() or "[]")
            io_data = io_raw if isinstance(io_raw, list) else [io_raw]
        except Exception:
            pass
        return {"drives": drives, "physical": physical, "io": io_data}
    except Exception as e:
        print(f"[Disk error] {e}")
        return {"drives": [], "physical": [], "io": []}


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK MONITOR
# ══════════════════════════════════════════════════════════════════════════════

def get_network_data() -> dict:
    ps_conns = r"""
$procs = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = $_.State.ToString()
        PID           = $_.OwningProcess
        Process       = if ($procs.ContainsKey($_.OwningProcess)) { $procs[$_.OwningProcess] } else { "Unknown" }
    }
}
$conns | ConvertTo-Json -Depth 2
"""
    ps_adapters = r"""
Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
    $a = Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name        = $_.Name
        SentMB      = [math]::Round($_.SentBytes   / 1MB, 2)
        ReceivedMB  = [math]::Round($_.ReceivedBytes / 1MB, 2)
        Status      = if ($a) { $a.Status } else { "Unknown" }
        LinkSpeedMb = if ($a) { [math]::Round($a.LinkSpeed / 1MB, 0) } else { 0 }
    }
} | ConvertTo-Json -Depth 2
"""
    try:
        r1 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_conns],
                            capture_output=True, text=True, timeout=20)
        conns_raw = json.loads(r1.stdout.strip() or "[]")
        conns = conns_raw if isinstance(conns_raw, list) else [conns_raw]

        r2 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_adapters],
                            capture_output=True, text=True, timeout=15)
        adapters_raw = json.loads(r2.stdout.strip() or "[]")
        adapters = adapters_raw if isinstance(adapters_raw, list) else [adapters_raw]

        established = [c for c in conns if c.get("State") == "Established"]
        listening   = [c for c in conns if c.get("State") == "Listen"]

        # Group by process for summary
        proc_counts = Counter(c.get("Process","Unknown") for c in established)
        top_procs   = [{"process": p, "connections": n} for p, n in proc_counts.most_common(10)]

        return {
            "established": established,
            "listening": listening,
            "adapters": adapters,
            "top_processes": top_procs,
            "total_connections": len(established),
            "total_listening": len(listening),
        }
    except Exception as e:
        print(f"[Network error] {e}")
        return {"established": [], "listening": [], "adapters": [], "top_processes": [], "total_connections": 0, "total_listening": 0}


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS UPDATE HISTORY
# ══════════════════════════════════════════════════════════════════════════════

RESULT_CODES = {1: "In Progress", 2: "Succeeded", 3: "Succeeded w/ Errors", 4: "Failed", 5: "Aborted"}

def get_update_history() -> list:
    ps = r"""
try {
    $sess = New-Object -ComObject Microsoft.Update.Session
    $src  = $sess.CreateUpdateSearcher()
    $n    = $src.GetTotalHistoryCount()
    $hist = $src.QueryHistory(0, [Math]::Min($n, 150))
    $hist | ForEach-Object {
        [PSCustomObject]@{
            Title      = $_.Title
            Date       = $_.Date.ToString("o")
            ResultCode = [int]$_.ResultCode
            Categories = ($_.Categories | ForEach-Object { $_.Name }) -join ", "
            KB         = if ($_.Title -match "KB(\d+)") { "KB$($Matches[1])" } else { "" }
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout.strip() or "[]")
        items = data if isinstance(data, list) else [data]
        for item in items:
            code = item.get("ResultCode", 0)
            item["result"] = RESULT_CODES.get(code, "Unknown")
        return items
    except Exception as e:
        print(f"[Update history error] {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# EVENT LOG VIEWER
# ══════════════════════════════════════════════════════════════════════════════

LEVEL_MAP = {"Error": 2, "Warning": 3, "Information": 4, "Critical": 1}

def query_event_log(params: dict) -> list:
    log     = params.get("log", "System")
    level   = params.get("level", "")
    search  = params.get("search", "").strip()
    max_ev  = min(int(params.get("max", 100)), 500)

    safe_log = re.sub(r"[^\w\s\-/]", "", log)

    filter_ht = f"LogName=\'{safe_log}\'"
    if level and level in LEVEL_MAP:
        filter_ht += f"; Level={LEVEL_MAP[level]}"

    ps = f"""
try {{
    $filter = @{{LogName=\'{safe_log}\'"""
    if level and level in LEVEL_MAP:
        ps += f"; Level={LEVEL_MAP[level]}"
    ps += f"""}}
    $evts = Get-WinEvent -FilterHashtable $filter -MaxEvents {max_ev} -EA Stop
    $evts | ForEach-Object {{
        $msg = if ($_.Message) {{ $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }} else {{ "" }}
        [PSCustomObject]@{{
            Time     = $_.TimeCreated.ToString("o")
            Id       = $_.Id
            Level    = $_.LevelDisplayName
            Source   = $_.ProviderName
            Message  = $msg
        }}
    }} | ConvertTo-Json -Depth 2
}} catch {{ "[]" }}
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout.strip() or "[]")
        events = data if isinstance(data, list) else [data]
        if search:
            sl = search.lower()
            events = [e for e in events
                      if sl in (e.get("Message","") + e.get("Source","") + str(e.get("Id",""))).lower()]
        return events
    except Exception as e:
        print(f"[Event log error] {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# INSIGHT SUMMARIES — per-tab analysis, actions, and status
# ══════════════════════════════════════════════════════════════════════════════

def _insight(level: str, text: str, action: str = "") -> dict:
    return {"level": level, "text": text, "action": action}


def summarize_drivers(results: list) -> dict:
    if not results:
        return {"status": "idle", "headline": "Run a scan to check driver status.", "insights": [], "actions": []}
    updates  = [r for r in results if r["status"] == "update_available"]
    unknown  = [r for r in results if r["status"] == "unknown"]
    ok       = [r for r in results if r["status"] == "up_to_date"]
    insights = []
    actions  = []
    if updates:
        cats = Counter(r["category"] for r in updates)
        top  = cats.most_common(1)[0][0]
        insights.append(_insight("warning",
            f"{len(updates)} driver update(s) available — most in {top}.",
            "Open Windows Update to install pending driver updates."))
        actions.append("Open Windows Update")
        critical = [r for r in updates if r["category"] in ("Display", "Network", "Chipset")
                    and not r.get("low_priority")]
        if critical:
            insights.append(_insight("critical",
                f"{len(critical)} critical driver(s) need updating: "
                + ", ".join(r['name'][:40] for r in critical[:3]),
                "Prioritise display, network and chipset drivers for system stability."))
    if unknown and not updates:
        insights.append(_insight("info",
            f"{len(unknown)} driver(s) could not be verified against Windows Update — they may still be current.",
            ""))
    if not updates and not unknown:
        insights.append(_insight("ok", f"All {len(ok)} drivers are up to date."))
    status = "critical" if any(i["level"]=="critical" for i in insights)         else "warning" if any(i["level"]=="warning" for i in insights)         else "ok"
    headline = (f"{len(updates)} update(s) need attention" if updates
                else f"All {len(results)} drivers up to date")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_bsod(data: dict) -> dict:
    summary  = data.get("summary", {})
    crashes  = data.get("crashes", [])
    total    = summary.get("total_crashes", 0)
    month    = summary.get("this_month", 0)
    common   = summary.get("most_common_error", "None")
    avg_up   = summary.get("avg_uptime_hours", 0)
    timeline = data.get("timeline", [])
    insights = []
    actions  = []

    if total == 0:
        insights.append(_insight("ok",
            "No crashes found in the Event Log or health reports. System looks stable."))
        return {"status": "ok", "headline": "System stable — no crashes detected",
                "insights": insights, "actions": actions}

    # ── Frequency ────────────────────────────────────────────────────────────
    if month > 3:
        insights.append(_insight("critical",
            f"{month} crashes this month — system is actively unstable.",
            "Address the root cause immediately using the recommendations below."))
        actions.append("Review recommendations below")
    elif month > 0:
        insights.append(_insight("warning", f"{month} crash(es) this month."))

    # ── Per stop code enriched insight ───────────────────────────────────────
    error_counts = Counter(c["error_code"] for c in crashes)
    code_drivers = {}
    for c in crashes:
        ec, fd = c.get("error_code",""), c.get("faulty_driver","")
        if fd:
            code_drivers.setdefault(ec, Counter())[fd] += 1

    pending_codes = []
    for code, cnt in error_counts.most_common(5):
        hex_code   = next((h for h, n in BUGCHECK_CODES.items() if n == code), code)
        top_driver = ""
        if code in code_drivers:
            top_driver = code_drivers[code].most_common(1)[0][0]

        info = get_stop_code_info(hex_code, top_driver)
        if info is None:
            pending_codes.append(code)
            continue

        level     = "critical" if cnt >= 5 else "warning"
        src_tag   = f" [{info.get('source','')}]" if info.get("source","") not in ("static_kb","") else ""
        drv_note  = f" Faulty driver: {top_driver}." if top_driver else ""
        insights.append(_insight(level,
            f"{code}{src_tag} — {info.get('title',code)} — {cnt}x.{drv_note} "
            f"{info.get('detail','')}",
            info.get("action","")))
        if info.get("action"):
            actions.append(info["action"][:80])

    if pending_codes:
        insights.append(_insight("info",
            f"Fetching details for {len(pending_codes)} stop code(s) in background "
            f"({', '.join(pending_codes[:3])}). Refresh in a few seconds.", ""))

    # ── Uptime / stability ────────────────────────────────────────────────────
    if avg_up > 0 and avg_up < 24:
        insights.append(_insight("critical",
            f"Average uptime between crashes: {avg_up}h — very unstable.",
            "Run Dell SupportAssist from the Start menu — it includes built-in hardware diagnostics including memory testing."))
    elif avg_up > 0:
        insights.append(_insight("info",
            f"Average uptime between crashes: {avg_up}h."))

    # ── Trend ─────────────────────────────────────────────────────────────────
    if len(timeline) >= 4:
        recent = sum(w["count"] for w in timeline[-2:])
        prior  = sum(w["count"] for w in timeline[-4:-2])
        if recent > prior and recent > 0:
            insights.append(_insight("warning",
                "Crash frequency is trending upward — system is getting less stable."))
        elif prior > recent and prior > 0:
            insights.append(_insight("ok",
                "Crash frequency is trending downward — good sign."))

    status = ("critical" if any(i["level"] == "critical" for i in insights)
              else "warning" if any(i["level"] == "warning" for i in insights)
              else "ok")
    headline = (f"{month} crash(es) this month — {total} total" if month
                else f"{total} total crash(es) — none this month")
    return {"status": status, "headline": headline,
            "insights": insights, "actions": list(dict.fromkeys(actions))[:4]}


def summarize_startup(items: list) -> dict:
    if not items:
        return {"status": "ok", "headline": "No startup entries found.", "insights": [], "actions": []}
    suspicious = [i for i in items if i.get("suspicious")]
    enabled    = [i for i in items if i.get("Enabled")]
    tasks      = [i for i in items if i.get("Type") == "task"]
    insights   = []
    actions    = []
    if suspicious:
        insights.append(_insight("critical",
            f"{len(suspicious)} suspicious startup entry/entries detected — running from temp/downloads/public folders.",
            "Review and disable any suspicious entries immediately."))
        actions.append("Disable suspicious entries")
        for s in suspicious[:3]:
            insights.append(_insight("critical",
                f"Suspicious: {s.get('Name','?')} — {(s.get('Command') or '')[:60]}"))
    if len(enabled) > 20:
        insights.append(_insight("warning",
            f"{len(enabled)} startup items are enabled — this may slow login time.",
            "Disable non-essential startup items to improve boot speed."))
    elif len(enabled) > 0:
        insights.append(_insight("info", f"{len(enabled)} item(s) run at login across {len(set(i.get('Location') for i in items))} locations."))
    if not suspicious:
        insights.append(_insight("ok", "No suspicious startup entries detected."))
    status = "critical" if suspicious else "warning" if len(enabled) > 20 else "ok"
    headline = (f"{len(suspicious)} suspicious item(s) — review needed" if suspicious
                else f"{len(enabled)} items run at login — all look clean")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_disk(data: dict) -> dict:
    drives   = data.get("drives", [])
    physical = data.get("physical", [])
    insights = []
    actions  = []
    critical_drives = [d for d in drives if (d.get("PctUsed") or 0) >= 90]
    warning_drives  = [d for d in drives if 75 <= (d.get("PctUsed") or 0) < 90]
    unhealthy       = [p for p in physical if p.get("Health","").lower() not in ("healthy","")]
    if unhealthy:
        insights.append(_insight("critical",
            f"{len(unhealthy)} physical disk(s) reporting unhealthy status: "
            + ", ".join(p.get("Name","?") for p in unhealthy),
            "Back up data immediately and investigate disk health. Consider replacement."))
        actions.append("Back up data immediately")
    if critical_drives:
        for d in critical_drives:
            insights.append(_insight("critical",
                f"Drive {d.get('Letter','?')}: is {d.get('PctUsed',0)}% full ({d.get('FreeGB',0)} GB free).",
                "Free up space or expand storage to avoid system instability."))
        actions.append("Free up disk space")
    if warning_drives:
        for d in warning_drives:
            insights.append(_insight("warning",
                f"Drive {d.get('Letter','?')}: is {d.get('PctUsed',0)}% full — approaching capacity."))
    if not unhealthy and not critical_drives and not warning_drives:
        insights.append(_insight("ok",
            f"All {len(physical)} disk(s) healthy. "
            + (f"Largest drive is {max((p.get('SizeGB',0) for p in physical), default=0)} GB." if physical else "")))
    for p in physical:
        if p.get("MediaType","").lower() == "hdd":
            insights.append(_insight("info",
                f"{p.get('Name','HDD')} is a spinning hard drive — consider upgrading to SSD for better performance."))
    status = "critical" if unhealthy or critical_drives else "warning" if warning_drives else "ok"
    headline = (f"{len(unhealthy)} unhealthy disk(s) — action required" if unhealthy
                else f"{len(critical_drives)} drive(s) critically full" if critical_drives
                else "All drives healthy")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_network(data: dict) -> dict:
    established = data.get("established", [])
    adapters    = data.get("adapters", [])
    top_procs   = data.get("top_processes", [])
    insights    = []
    actions     = []
    down_adapters = [a for a in adapters if a.get("Status","").lower() not in ("up","")]
    if down_adapters:
        insights.append(_insight("warning",
            f"{len(down_adapters)} network adapter(s) are not active: "
            + ", ".join(a.get("Name","?") for a in down_adapters)))
    unusual_ports = [c for c in established if c.get("RemotePort") in (4444,1337,31337,9001,8888)]
    if unusual_ports:
        insights.append(_insight("warning",
            f"{len(unusual_ports)} connection(s) on unusual ports — worth reviewing.",
            "Check the Active Connections table below. These may be legitimate (VPN, games, apps) or unexpected. Look at the remote address and process name to decide."))
        actions.append("Investigate flagged connections")
    if top_procs:
        top = top_procs[0]
        if top["connections"] > 20:
            insights.append(_insight("warning",
                f"{top['process']} has {top['connections']} open connections — unusually high.",
                "Check if this process is behaving normally."))
        else:
            insights.append(_insight("info",
                f"Top process by connections: {top['process']} ({top['connections']} connections)."))
    active_adapters = [a for a in adapters if a.get("Status","").lower() == "up"]
    if active_adapters:
        insights.append(_insight("ok",
            f"{len(active_adapters)} adapter(s) active. "
            f"{data.get('total_connections',0)} established connection(s)."))
    if not unusual_ports and not down_adapters:
        insights.append(_insight("ok", "No suspicious connections or adapter issues detected."))
    status = "critical" if unusual_ports else "warning" if down_adapters or (top_procs and top_procs[0]["connections"]>20) else "ok"
    headline = (f"{len(unusual_ports)} suspicious connection(s) detected" if unusual_ports
                else f"{data.get('total_connections',0)} active connections — nothing flagged")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_updates(items: list) -> dict:
    if not items:
        return {"status": "info", "headline": "No update history found.", "insights": [], "actions": []}
    failed   = [u for u in items if u.get("result") in ("Failed","Aborted")]
    now      = datetime.now(timezone.utc)
    month    = [u for u in items if u.get("result") == "Succeeded" and
                (now - _parse_ts(u.get("Date",""))).days <= 30]
    insights = []
    actions  = []
    if failed:
        recent_failed = [u for u in failed if (now - _parse_ts(u.get("Date",""))).days <= 60]
        if recent_failed:
            insights.append(_insight("warning",
                f"{len(recent_failed)} update(s) failed or were aborted in the last 60 days.",
                "Re-run Windows Update to retry failed updates."))
            actions.append("Retry failed updates in Windows Update")
            for u in recent_failed[:2]:
                insights.append(_insight("warning", f"Failed: {u.get('Title','?')[:60]}"))
    last_ok = next((u for u in items if u.get("result") == "Succeeded"), None)
    if last_ok:
        days_ago = (now - _parse_ts(last_ok.get("Date",""))).days
        if days_ago > 60:
            insights.append(_insight("warning",
                f"Last successful update was {days_ago} days ago — system may be out of date.",
                "Run Windows Update to check for new updates."))
            actions.append("Run Windows Update")
        else:
            insights.append(_insight("ok",
                f"Last successful update: {days_ago} day(s) ago. {len(month)} update(s) this month."))
    if not failed:
        insights.append(_insight("ok", f"No failed updates. {len(items)} updates in history."))
    status = "warning" if failed or (last_ok and (now-_parse_ts(last_ok.get("Date",""))).days>60) else "ok"
    headline = (f"{len(failed)} failed update(s) need attention" if failed
                else f"Updates healthy — {len(items)} in history")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# Knowledge base: well-known Event IDs with context, real severity, and actions
EVENT_KB = {
    # ── DistributedCOM / DCOM ─────────────────────────────────────────────
    10010: {"noise": True,  "source": "Microsoft-Windows-DistributedCOM",
            "title": "Windows background component unavailable (Event 10010)",
            "detail": "Windows couldn't start a DCOM server (DCOM is the background communication "
                      "framework Windows uses to connect apps and system services) in time. "
                      "This is almost always harmless background noise — "
                      "typically caused by Microsoft Store apps or system components "
                      "that register servers they don't always use.",
            "action": "Safe to ignore unless you see application crashes alongside it. "
                      "No action needed."},
    10016: {"noise": True,  "source": "Microsoft-Windows-DistributedCOM",
            "title": "Windows background component permission error (Event 10016)",
            "detail": "A process tried to activate a DCOM server (DCOM is the background communication "
                      "framework Windows uses to connect apps and services) without the required permissions. "
                      "This is extremely common on Windows 11 and almost always benign — "
                      "it affects background Microsoft components, not your applications.",
            "action": "Safe to ignore in most cases. No action needed unless a specific app is broken."},
    # ── Disk / Storage ────────────────────────────────────────────────────
    7:    {"noise": False, "source": "disk",
           "title": "Bad block on disk",
           "detail": "The disk driver detected a bad block. This is a hardware-level warning "
                     "that your drive may be developing physical errors.",
           "action": "URGENT: back up your data immediately. "
                     "Then run chkdsk /r (Windows built-in disk check and repair tool): "
                     "search Command Prompt in Start, right-click Run as Administrator, "
                     "type: chkdsk C: /r and press Enter (replace C: with the affected drive letter). "
                     "Check the Disk Health tab for physical disk status."},
    11:   {"noise": False, "source": "disk",
           "title": "Controller error on disk",
           "detail": "The disk controller reported an error. Can indicate a failing drive, "
                     "loose cable, or faulty SATA/NVMe controller.",
           "action": "Check the Disk Health tab in WinDesktopMgr for drive health status. "
                     "For deeper analysis, CrystalDiskInfo (free tool at crystalmark.info) reads S.M.A.R.T. data "
                     "(drive health statistics built into every modern drive). "
                     "If errors are found, back up immediately and consider replacing the drive."},
    51:   {"noise": False, "source": "disk",
           "title": "Disk paging error",
           "detail": "An error occurred during a paging operation. Often appears before drive failure.",
           "action": "Back up data. Run chkdsk /r (Windows built-in disk check tool): search Command Prompt in Start, right-click Run as Administrator, type: chkdsk C: /r. Check the Disk Health tab for drive health status."},
    # ── Kernel / Power ────────────────────────────────────────────────────
    41:   {"noise": False, "source": "Microsoft-Windows-Kernel-Power",
           "title": "Unexpected system shutdown (Kernel-Power)",
           "detail": "The system rebooted without cleanly shutting down first — "
                     "this is the primary BSOD/crash/power-loss event. "
                     "Directly related to the crashes shown in the BSOD Dashboard.",
           "action": "Check BSOD Dashboard for crash analysis. "
                     "Verify PSU is adequate for your hardware. Check system temps."},
    6008: {"noise": False, "source": "EventLog",
           "title": "Unexpected shutdown logged by Event Log",
           "detail": "The previous system shutdown was unexpected. Logged at startup after a crash or power loss.",
           "action": "Cross-reference with BSOD Dashboard. If frequent, investigate power supply and thermals."},
    1001: {"noise": False, "source": "BugCheck",
           "title": "Windows Error Reporting — crash recorded",
           "detail": "Windows recorded a crash dump. The stop code is logged here.",
           "action": "Check the BSOD Dashboard tab for full crash analysis and recommendations."},
    # ── Service Control Manager ───────────────────────────────────────────
    7000: {"noise": False, "source": "Service Control Manager",
           "title": "Service failed to start",
           "detail": "A Windows service failed to start during boot.",
           "action": "Check which service failed in the event message. "
                     "Run: Get-Service | Where-Object {$_.Status -eq 'Stopped'} in PowerShell."},
    7001: {"noise": False, "source": "Service Control Manager",
           "title": "Service dependency failed",
           "detail": "A service could not start because a service it depends on failed.",
           "action": "Identify the dependency chain — fix the root service first."},
    7031: {"noise": False, "source": "Service Control Manager",
           "title": "Service terminated unexpectedly",
           "detail": "A service crashed and Windows took a recovery action (restart/reboot).",
           "action": "Note the service name in the event message. Check Event Log for related errors around the same time."},
    7034: {"noise": False, "source": "Service Control Manager",
           "title": "Service terminated unexpectedly (no recovery)",
           "detail": "A service crashed with no configured recovery action.",
           "action": "Identify the service and check its logs or event source for the root cause."},
    # ── Windows Update ────────────────────────────────────────────────────
    20: {"noise": False, "source": "Microsoft-Windows-WindowsUpdateClient",
         "title": "Windows Update installation failure",
         "detail": "A Windows Update failed to install.",
         "action": "Check Update History tab for details. Run sfc /scannow (Windows system file repair tool): search Command Prompt in Start, right-click Run as Administrator, type: sfc /scannow and press Enter. Then retry Windows Update."},
    # ── Application / .NET ───────────────────────────────────────────────
    1000: {"noise": False, "source": "Application Error",
           "title": "Application crash",
           "detail": "An application faulted and was terminated by Windows.",
           "action": "Note the faulting application and module in the event message. "
                     "Update or reinstall the application."},
    1026: {"noise": True,  "source": ".NET Runtime",
           "title": ".NET Runtime error",
           "detail": "A .NET application encountered an unhandled exception.",
           "action": "Usually harmless background app crash. "
                     "Note the app name — reinstall if it's something you use actively."},
    # ── Networking ───────────────────────────────────────────────────────
    4201: {"noise": True,  "source": "Tcpip",
           "title": "Network adapter disconnected",
           "detail": "The system detected the network adapter was disconnected.",
           "action": "Normal if you disconnected Wi-Fi or Ethernet intentionally. "
                     "Investigate if happening unexpectedly — check Network Monitor tab."},
    # ── Hyper-V / Virtualisation ─────────────────────────────────────────
    18456: {"noise": False, "source": "Microsoft-Windows-Hyper-V-Worker",
            "title": "Hyper-V worker process error",
            "detail": "Hyper-V encountered an error in a virtual machine worker process.",
            "action": "Related to your HYPERVISOR_ERROR BSODs. "
                      "Consider disabling Memory Integrity (Core Isolation) and C-States in BIOS."},
    # ── Security ─────────────────────────────────────────────────────────
    4625: {"noise": False, "source": "Microsoft-Windows-Security-Auditing",
           "title": "Failed logon attempt",
           "detail": "An account failed to log on. Multiple occurrences may indicate a brute-force attack (repeated automated login attempts by malicious software) or a misconfigured service trying to authenticate.",
           "action": "Check the account name and source IP in the event details. "
                     "If from external IP, review firewall and RDP settings."},
    4648: {"noise": False, "source": "Microsoft-Windows-Security-Auditing",
           "title": "Explicit credentials logon",
           "detail": "A process attempted to log on with explicit credentials (runas). Can be legitimate or suspicious.",
           "action": "Review the account and process in the event message."},
}


# ══════════════════════════════════════════════════════════════════════════════
# SELF-LEARNING BSOD STOP CODE LOOKUP SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
#
# Lookup priority for any unknown stop code:
#   1. Static RECOMMENDATIONS_DB  (hardcoded, richest detail, instant)
#   2. Local BSOD cache file      (bsod_code_cache.json, persists across restarts)
#   3. WinDbg symbol server       (Microsoft's official stop code descriptions,
#                                   offline after first fetch, always authoritative)
#   4. Microsoft Learn search API (internet fallback)
#   5. Driver-specific enrichment (stop code + faulty driver = better advice)
#   6. Generic placeholder        (never leaves the UI empty)
#
# Each stop code is looked up at most once. Cache grows automatically.
# Stop codes are stored normalised as "0x0000XXXX" (9-char padded hex).
# ══════════════════════════════════════════════════════════════════════════════

_bsod_cache_lock  = threading.Lock()
_bsod_cache: dict = {}
_bsod_queue: queue.Queue = queue.Queue()
_bsod_in_flight: set = set()

# Known driver → human-readable context mapping for enriched advice
DRIVER_CONTEXT = {
    "intelppm.sys":      ("Intel CPU power management driver",
                          "Disable C-States in BIOS and Memory Integrity in Core Isolation."),
    "ntoskrnl.exe":      ("Windows kernel",
                          "Run sfc /scannow in an Admin PowerShell to repair system files. If crashes continue, run Dell SupportAssist memory diagnostics from the Start menu."),
    "win32k.sys":        ("Windows GUI subsystem",
                          "Update display drivers and check for Windows updates."),
    "nvlddmkm.sys":      ("NVIDIA display driver",
                          "Update or clean-reinstall NVIDIA drivers via DDU."),
    "atikmdag.sys":      ("AMD display driver",
                          "Update or clean-reinstall AMD drivers via DDU."),
    "igdkmd64.sys":      ("Intel integrated graphics driver",
                          "Update Intel graphics drivers from Intel's website."),
    "tcpip.sys":         ("Windows TCP/IP stack",
                          "Run: netsh winsock reset and netsh int ip reset, then reboot."),
    "ndis.sys":          ("Windows network driver interface",
                          "Update network adapter drivers from Device Manager."),
    "storport.sys":      ("Storage port driver",
                          "Check disk health in Disk Health tab. Update storage drivers."),
    "iastora.sys":       ("Intel Rapid Storage Technology driver",
                          "Update Intel RST drivers from Dell Support or Intel's site."),
    "klif.sys":          ("Kaspersky antivirus driver",
                          "Update or temporarily disable Kaspersky to test stability."),
    "mfehidk.sys":       ("McAfee security driver",
                          "Update or temporarily disable McAfee to test stability."),
    "aswsnx.sys":        ("Avast antivirus driver",
                          "Update or temporarily disable Avast to test stability."),
    "dxgmms2.sys":       ("DirectX graphics MMS",
                          "Update display drivers. Check GPU temps under load."),
    "wdf01000.sys":      ("Windows Driver Framework",
                          "Check Device Manager for driver errors and update all drivers."),
    "hidclass.sys":      ("HID USB class driver",
                          "Disconnect and reconnect USB devices. Update USB/chipset drivers."),
}


def _normalise_stop_code(code: str) -> str:
    """Normalise any stop code variant to '0x0000XXXX' 10-char format."""
    if not code:
        return ""
    c = code.strip().lower().lstrip("0x")
    try:
        return f"0x{int(c, 16):08x}"
    except ValueError:
        return code.lower()


def _load_bsod_cache():
    global _bsod_cache
    if not os.path.exists(BSOD_CACHE_FILE):
        _bsod_cache = {}
        return
    try:
        with open(BSOD_CACHE_FILE, encoding="utf-8") as f:
            _bsod_cache = json.load(f)
        print(f"[BSODCache] Loaded {len(_bsod_cache)} cached stop codes")
    except Exception as e:
        print(f"[BSODCache] Load error: {e}")
        _bsod_cache = {}


def _save_bsod_cache():
    try:
        with _bsod_cache_lock:
            with open(BSOD_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_bsod_cache, f, indent=2)
    except Exception as e:
        print(f"[BSODCache] Save error: {e}")


def _lookup_stop_code_windows(code_norm: str) -> dict | None:
    """
    Query WinDbg/DbgHelp for stop code descriptions via PowerShell.
    Reads from the local Windows symbol cache — no internet required
    once symbols have been downloaded at least once.
    Falls back to searching the Windows Debug folder for known bug check strings.
    """
    # Try to find the bug check name from ntdll / kernel symbols via WinDbg
    # Simpler offline approach: search Windows\System32 for the stop code string
    hex_short = code_norm.lstrip("0x").lstrip("0").upper() or "0"
    ps = f"""
try {{
    # Search Windows Error Reporting / WER for any matching stop codes
    $code = "0x{code_norm.lstrip('0x').upper().zfill(8)}"
    $bugNames = @{{
        "0x0000003B"="SYSTEM_SERVICE_EXCEPTION"
        "0x00000050"="PAGE_FAULT_IN_NONPAGED_AREA"
        "0x0000007E"="SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"
        "0x0000007F"="UNEXPECTED_KERNEL_MODE_TRAP"
        "0x0000009F"="DRIVER_POWER_STATE_FAILURE"
        "0x000000D1"="DRIVER_IRQL_NOT_LESS_OR_EQUAL"
        "0x000000EF"="CRITICAL_PROCESS_DIED"
        "0x00000116"="VIDEO_TDR_FAILURE"
        "0x00000133"="DPC_WATCHDOG_VIOLATION"
        "0x00000139"="KERNEL_SECURITY_CHECK_FAILURE"
        "0x0000013A"="KERNEL_MODE_HEAP_CORRUPTION"
        "0x00000154"="UNEXPECTED_STORE_EXCEPTION"
        "0x0000015B"="WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE"
        "0x0000017E"="MICROCODE_REVISION_MISMATCH"
        "0x00020001"="HYPERVISOR_ERROR"
        "0x1000007E"="SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M"
        "0x1000008E"="KERNEL_MODE_EXCEPTION_NOT_HANDLED_M"
        "0x1000000A"="IRQL_NOT_LESS_OR_EQUAL"
        "0x000000BE"="ATTEMPTED_WRITE_TO_READONLY_MEMORY"
        "0x000000C5"="DRIVER_CORRUPTED_EXPOOL"
        "0x0000001E"="KMODE_EXCEPTION_NOT_HANDLED"
        "0x00000024"="NTFS_FILE_SYSTEM"
        "0x0000002E"="DATA_BUS_ERROR"
        "0x0000003D"="INTERRUPT_EXCEPTION_NOT_HANDLED"
        "0x00000044"="MULTIPLE_IRP_COMPLETE_REQUESTS"
        "0x00000051"="REGISTRY_ERROR"
        "0x00000074"="BAD_SYSTEM_CONFIG_INFO"
        "0x0000007A"="KERNEL_DATA_INPAGE_ERROR"
        "0x0000007C"="BUGCODE_NDIS_DRIVER"
        "0x00000080"="NMI_HARDWARE_FAILURE"
        "0x0000008E"="KERNEL_MODE_EXCEPTION_NOT_HANDLED"
        "0x000000A5"="ACPI_BIOS_ERROR"
        "0x000000B8"="ATTEMPTED_SWITCH_FROM_DPC"
        "0x000000C4"="DRIVER_VERIFIER_DETECTED_VIOLATION"
        "0x000000D8"="DRIVER_USED_EXCESSIVE_PTES"
        "0x000000EA"="THREAD_STUCK_IN_DEVICE_DRIVER"
        "0x000000F4"="CRITICAL_OBJECT_TERMINATION"
        "0x000000FE"="BUGCODE_USB_DRIVER"
        "0x00000101"="CLOCK_WATCHDOG_TIMEOUT"
        "0x00000109"="CRITICAL_STRUCTURE_CORRUPTION"
        "0x0000010D"="WDF_VIOLATION"
        "0x0000010E"="VIDEO_MEMORY_MANAGEMENT_INTERNAL"
        "0x00000117"="VIDEO_TDR_TIMEOUT_DETECTED"
        "0x00000119"="VIDEO_SCHEDULER_INTERNAL_ERROR"
        "0x0000011A"="EM_INITIALIZATION_FAILURE"
        "0x0000011C"="ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE"
        "0x00000124"="WHEA_UNCORRECTABLE_ERROR"
        "0x00000127"="PAGE_NOT_ZERO"
        "0x0000012B"="FAULTY_HARDWARE_CORRUPTED_PAGE"
        "0x0000012E"="INVALID_MDL_RANGE"
        "0x00000144"="BUGCODE_USB3_DRIVER"
        "0x00000156"="WINSOCK_DETECTED_HUNG_CLOSESOCKET_LIVEDUMP"
        "0x00000175"="PREVIOUS_FATAL_ABNORMAL_RESET_ERROR"
        "0x00000187"="VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD"
        "0x00000191"="PF_DETECTED_CORRUPTION"
        "0x000001C4"="DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP"
        "0x000001C5"="IO_THREADPOOL_DEADLOCK_LIVEDUMP"
        "0x000001C6"="FAST_ERESOURCE_PRECONDITION_VIOLATION"
        "0x000001C8"="MANUALLY_INITIATED_POWER_BUTTON_HOLD"
        "0x000001CA"="SYNTHETIC_WATCHDOG_TIMEOUT"
        "0x000001CB"="INVALID_SILO_DETACH"
        "0x000001CD"="INVALID_CALLBACK_STACK_ADDRESS"
        "0x000001CE"="INVALID_KERNEL_STACK_ADDRESS"
        "0x000001CF"="HARDWARE_WATCHDOG_TIMEOUT"
        "0x000001D0"="CPI_FIRMWARE_WATCHDOG_TIMEOUT"
        "0x000001D1"="TELEMETRY_ASSERTS_LIVEDUMP"
    }}
    $name = $bugNames[$code.ToUpper()]
    if ($name) {{
        [PSCustomObject]@{{ Code=$code; Name=$name }} | ConvertTo-Json
    }}
}} catch {{ }}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15
        )
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        name = data.get("Name", "")
        if not name:
            return None
        return {
            "source":     "windows_bugcheck_table",
            "name":       name,
            "title":      name.replace("_", " ").title(),
            "detail":     f"Stop code {code_norm.upper()} — {name}. "
                          f"This is a Windows kernel bugcheck. "
                          f"Check the faulty driver in the crash details above for root cause.",
            "priority":   "high",
            "action":     f"Minidump files are saved to C:\\Windows\\Minidump and are analysed automatically by the BSOD Dashboard tab. For manual deep analysis, WinDbg (Microsoft's free crash analyser, available from the Microsoft Store) can open these files directly. "
                          f"Check Driver Manager tab for updates to the faulty driver.",
            "fetched":    datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[BSODLookup] PowerShell lookup failed for {code_norm}: {e}")
        return None


def _lookup_stop_code_web(code_norm: str) -> dict | None:
    """Search Microsoft Learn for the stop code."""
    try:
        # Use the stop code name if we can derive it, otherwise use hex
        query = urllib.parse.quote(f"bug check {code_norm} stop code windows bsod")
        url   = (f"https://learn.microsoft.com/api/search?search={query}"
                 f"&locale=en-us&%24top=3&facet=products")
        req   = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
        if not results:
            return None
        top     = results[0]
        title   = top.get("title", f"Stop Code {code_norm}")
        summary = (top.get("summary") or "")[:350]
        url_ref = top.get("url", "https://learn.microsoft.com")
        return {
            "source":   "microsoft_learn",
            "title":    title,
            "detail":   summary or f"See Microsoft documentation for stop code {code_norm}.",
            "priority": "high",
            "action":   f"Full details: {url_ref}",
            "fetched":  datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[BSODWebLookup] failed for {code_norm}: {e}")
        return None


def _bsod_lookup_worker():
    """Background thread — drains BSOD lookup queue, enriches unknown stop codes."""
    while True:
        code_norm = None
        try:
            code_norm = _bsod_queue.get(timeout=5)

            with _bsod_cache_lock:
                if code_norm in _bsod_cache:
                    _bsod_in_flight.discard(code_norm)
                    _bsod_queue.task_done()
                    continue

            print(f"[BSODCache] Looking up stop code {code_norm}")

            result = _lookup_stop_code_windows(code_norm)
            if not result:
                result = _lookup_stop_code_web(code_norm)
            if not result:
                result = {
                    "source":   "unknown",
                    "title":    f"Stop Code {code_norm.upper()}",
                    "detail":   "No description found. This may be a rare or hardware-specific stop code.",
                    "priority": "high",
                    "action":   f"Search: https://learn.microsoft.com/search/?terms={urllib.parse.quote(code_norm)}+stop+code",
                    "fetched":  datetime.now(timezone.utc).isoformat(),
                }

            with _bsod_cache_lock:
                _bsod_cache[code_norm] = result
            _save_bsod_cache()
            print(f"[BSODCache] Cached {code_norm} (source: {result['source']})")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"[BSODLookupWorker] error: {e}")
        finally:
            try:
                if code_norm:
                    _bsod_in_flight.discard(code_norm)
                _bsod_queue.task_done()
            except Exception:
                pass


def get_stop_code_info(raw_code: str, faulty_driver: str = "") -> dict | None:
    """
    Main entry point. Returns enriched info for a stop code.
    Merges static RECOMMENDATIONS_DB + cached/looked-up data + driver context.
    Returns None if lookup is still pending.
    """
    code_norm = _normalise_stop_code(raw_code)
    if not code_norm:
        return None

    # 1. Static RECOMMENDATIONS_DB — keyed by name, so try to resolve name first
    name = BUGCHECK_CODES.get(code_norm, "")
    if name and name in RECOMMENDATIONS_DB:
        rec = dict(RECOMMENDATIONS_DB[name])
        # Enrich with driver context if we have it
        drv_lower = faulty_driver.lower()
        for drv_key, (drv_desc, drv_action) in DRIVER_CONTEXT.items():
            if drv_key in drv_lower:
                rec["driver_context"] = (
                    f"Faulty driver: {faulty_driver} ({drv_desc}). {drv_action}"
                )
                break
        rec["source"] = "static_kb"
        rec["name"]   = name
        return rec

    # 2. Cache
    with _bsod_cache_lock:
        if code_norm in _bsod_cache:
            cached = dict(_bsod_cache[code_norm])
            # Enrich cached entry with driver context
            drv_lower = faulty_driver.lower()
            for drv_key, (drv_desc, drv_action) in DRIVER_CONTEXT.items():
                if drv_key in drv_lower:
                    cached["driver_context"] = (
                        f"Faulty driver: {faulty_driver} ({drv_desc}). {drv_action}"
                    )
                    break
            return cached

    # 3. Queue background lookup
    if code_norm not in _bsod_in_flight:
        _bsod_in_flight.add(code_norm)
        _bsod_queue.put(code_norm)

    return None   # Not ready yet


def get_bsod_cache_status() -> dict:
    with _bsod_cache_lock:
        cached = dict(_bsod_cache)
    return {
        "total_cached":  len(cached),
        "queue_pending": _bsod_queue.qsize(),
        "in_flight":     len(_bsod_in_flight),
        "cache_file":    BSOD_CACHE_FILE,
        "entries": [
            {"code": k, "title": v.get("title","?"),
             "source": v.get("source","?"), "fetched": v.get("fetched","")}
            for k, v in list(cached.items())[:50]
        ]
    }


# Sources that are almost always noise — downgrade severity automatically
NOISE_SOURCES = {
    "Microsoft-Windows-DistributedCOM",
    "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-DeviceSetupManager",
    "Microsoft-Windows-UserPnp",
    "VSS",
}


# ══════════════════════════════════════════════════════════════════════════════
# SELF-LEARNING EVENT ID LOOKUP SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
#
# Lookup priority for any unknown Event ID:
#   1. Static EVENT_KB (hardcoded, instant)
#   2. Local cache file (event_id_cache.json — persists across restarts)
#   3. Windows Event Provider metadata (PowerShell — always up to date,
#      no internet needed, reads directly from Windows' own event registry)
#   4. Microsoft Learn web search (internet fallback)
#   5. Generic placeholder (so UI always gets something)
#
# Each ID is looked up at most once ever. Cache grows automatically.
# ══════════════════════════════════════════════════════════════════════════════

_event_cache_lock  = threading.Lock()
_event_cache: dict = {}          # in-memory; mirrors the JSON file
_lookup_queue: queue.Queue = queue.Queue()
_lookup_in_flight: set = set()   # IDs currently being looked up


def _load_event_cache():
    """Load the JSON cache from disk into memory."""
    global _event_cache
    if not os.path.exists(EVENT_CACHE_FILE):
        _event_cache = {}
        return
    try:
        with open(EVENT_CACHE_FILE, encoding="utf-8") as f:
            _event_cache = json.load(f)
        print(f"[EventCache] Loaded {len(_event_cache)} cached event IDs")
    except Exception as e:
        print(f"[EventCache] Load error: {e}")
        _event_cache = {}


def _save_event_cache():
    """Persist in-memory cache to disk."""
    try:
        with _event_cache_lock:
            with open(EVENT_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_event_cache, f, indent=2)
    except Exception as e:
        print(f"[EventCache] Save error: {e}")


def _lookup_via_windows_provider(event_id: int, source: str) -> dict | None:
    """
    Query Windows' own event provider registry via PowerShell.
    This is always up to date — it reads whatever Windows has installed.
    Works offline. Returns None if the provider/event isn't registered.
    """
    ps = f"""
try {{
    # Try exact source name first
    $providers = @(Get-WinEvent -ListProvider "*" -EA SilentlyContinue |
        Where-Object {{ $_.Name -like "*{re.sub(r"[^\w\s\-]", "", source)}*" }})
    foreach ($p in $providers) {{
        $evt = $p.Events | Where-Object {{ $_.Id -eq {event_id} }} | Select-Object -First 1
        if ($evt) {{
            [PSCustomObject]@{{
                Provider    = $p.Name
                Id          = $evt.Id
                Description = $evt.Description
                Level       = $evt.Level
                Keywords    = ($evt.Keywords -join ", ")
            }} | ConvertTo-Json -Depth 2
            exit
        }}
    }}
    # Broader search — any provider with this event ID
    $all = Get-WinEvent -ListProvider "*" -EA SilentlyContinue
    foreach ($p in $all) {{
        $evt = $p.Events | Where-Object {{ $_.Id -eq {event_id} }} | Select-Object -First 1
        if ($evt) {{
            [PSCustomObject]@{{
                Provider    = $p.Name
                Id          = $evt.Id
                Description = $evt.Description
                Level       = $evt.Level
                Keywords    = ($evt.Keywords -join ", ")
            }} | ConvertTo-Json -Depth 2
            exit
        }}
    }}
}} catch {{ }}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20
        )
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc = (data.get("Description") or "").strip()
        if not desc:
            return None
        # Truncate very long provider descriptions — they can be huge template strings
        desc = re.sub(r"%\d+", "[value]", desc)   # replace %1 %2 placeholders
        desc = desc[:400] + ("…" if len(desc) > 400 else "")
        return {
            "source":  "windows_provider",
            "title":   f"Event {event_id} from {data.get('Provider', source)}",
            "detail":  desc,
            "noise":   False,
            "action":  "See event message details for specific context.",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[WinProvider] lookup failed for {event_id}: {e}")
        return None


def _lookup_via_web(event_id: int, source: str) -> dict | None:
    """
    Fallback: search Microsoft Learn for the event ID.
    Uses the Microsoft Learn search API — no scraping, clean JSON.
    """
    try:
        query   = urllib.parse.quote(f"event id {event_id} {source} windows")
        url     = f"https://learn.microsoft.com/api/search?search={query}&locale=en-us&%24top=3&facet=products"
        req     = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
        if not results:
            return None
        top     = results[0]
        title   = top.get("title", f"Event ID {event_id}")
        summary = top.get("summary", "")[:300]
        url_ref = top.get("url", "https://learn.microsoft.com")
        return {
            "source":  "microsoft_learn",
            "title":   title,
            "detail":  summary or f"See Microsoft documentation for Event ID {event_id}.",
            "noise":   False,
            "action":  f"Full details: {url_ref}",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[WebLookup] failed for {event_id}: {e}")
        return None


def _lookup_worker():
    """
    Background thread: drains the lookup queue, enriches unknown event IDs,
    updates cache. Runs forever as a daemon thread.
    """
    while True:
        try:
            event_id, source = _lookup_queue.get(timeout=5)
            cache_key = str(event_id)

            with _event_cache_lock:
                if cache_key in _event_cache:
                    _lookup_in_flight.discard(event_id)
                    _lookup_queue.task_done()
                    continue

            print(f"[EventCache] Looking up Event ID {event_id} (source: {source})")

            # 1. Try Windows provider metadata first (offline, always current)
            result = _lookup_via_windows_provider(event_id, source)

            # 2. Web fallback
            if not result:
                result = _lookup_via_web(event_id, source)

            # 3. Generic placeholder so we don't keep re-trying unknown IDs
            if not result:
                result = {
                    "source":  "unknown",
                    "title":   f"Event ID {event_id}",
                    "detail":  "No description found in Windows provider registry or Microsoft Learn.",
                    "noise":   False,
                    "action":  f"Search: https://learn.microsoft.com/search/?terms=event+id+{event_id}",
                    "fetched": datetime.now(timezone.utc).isoformat(),
                }

            with _event_cache_lock:
                _event_cache[cache_key] = result
            _save_event_cache()
            print(f"[EventCache] Cached Event ID {event_id} (source: {result['source']})")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"[LookupWorker] error: {e}")
        finally:
            try:
                _lookup_in_flight.discard(event_id if 'event_id' in dir() else -1)
                _lookup_queue.task_done()
            except Exception:
                pass


def get_event_info(event_id: int, source: str = "") -> dict | None:
    """
    Main entry point. Returns info for an event ID from any available source.
    Queues a background lookup if not cached yet.
    Returns None if not yet available (caller shows generic message).
    """
    # 1. Static KB (instant, highest quality)
    if event_id in EVENT_KB:
        return EVENT_KB[event_id]

    # 2. In-memory / disk cache
    cache_key = str(event_id)
    with _event_cache_lock:
        if cache_key in _event_cache:
            return _event_cache[cache_key]

    # 3. Queue for background lookup if not already in flight
    if event_id not in _lookup_in_flight:
        _lookup_in_flight.add(event_id)
        _lookup_queue.put((event_id, source))

    return None   # Not ready yet — caller will show "looking up…" state


def get_cache_status() -> dict:
    """Return cache stats for the admin endpoint."""
    with _event_cache_lock:
        cached = dict(_event_cache)
    return {
        "total_cached":    len(cached),
        "queue_pending":   _lookup_queue.qsize(),
        "in_flight":       len(_lookup_in_flight),
        "cache_file":      EVENT_CACHE_FILE,
        "entries": [
            {"id": k, "title": v.get("title","?"), "source": v.get("source","?"),
             "fetched": v.get("fetched","")}
            for k, v in list(cached.items())[:50]
        ]
    }


def summarize_events(events: list) -> dict:
    if not events:
        return {"status": "ok", "headline": "No events to summarise — run a query first.", "insights": [], "actions": []}

    errors   = [e for e in events if e.get("Level") in ("Error", "Critical")]
    warnings = [e for e in events if e.get("Level") == "Warning"]
    insights = []
    actions  = []

    # Separate real errors from known noise
    real_errors  = [e for e in errors if e.get("Source") not in NOISE_SOURCES
                    and not EVENT_KB.get(e.get("Id"), {}).get("noise", False)]
    noise_errors = [e for e in errors if e not in real_errors]

    # ── Per-ID lookup (static KB + learned cache) ────────────────────────
    id_counts  = Counter(e.get("Id") for e in events)
    id_source  = {e.get("Id"): e.get("Source", "") for e in events}
    explained  = set()
    pending    = []   # IDs queued for background lookup

    for eid, cnt in id_counts.most_common(15):
        info = get_event_info(eid, id_source.get(eid, ""))
        if info is None:
            pending.append((eid, cnt))
            continue
        explained.add(eid)
        is_noise  = info.get("noise", False)
        src_label = info.get("source", "")
        src_tag   = "" if src_label in ("", "static") else f" [{src_label}]"
        level     = "info" if is_noise else ("critical" if cnt >= 10 else "warning")
        noise_tag = " *(known noise — safe to ignore)*" if is_noise else ""
        insights.append(_insight(level,
            f"Event ID {eid}{src_tag} — {info.get('title', '')} — {cnt}x{noise_tag}. "
            f"{info.get('detail', '')}",
            info.get("action", "")))
        if not is_noise and info.get("action"):
            actions.append(info["action"][:80])

    if pending:
        ids_str = ", ".join(str(e) for e, _ in pending[:5])
        more    = f" (+{len(pending)-5} more)" if len(pending) > 5 else ""
        insights.append(_insight("info",
            f"Looking up {len(pending)} unknown Event ID(s) in background "
            f"({ids_str}{more}). Refresh in a few seconds to see details.", ""))

    # ── Unexplained real errors ───────────────────────────────────────────
    unexplained_errors = [e for e in real_errors if e.get("Id") not in explained]
    if unexplained_errors:
        sources = Counter(e.get("Source", "?") for e in unexplained_errors)
        top_src, top_n = sources.most_common(1)[0]
        insights.append(_insight("warning",
            f"{len(unexplained_errors)} unrecognised error(s). "
            f"Top source: {top_src} ({top_n}x).",
            f"Filter by source '{top_src}' and search Microsoft support for specific event IDs."))

    # ── Noise summary (collapsed) ─────────────────────────────────────────
    if noise_errors:
        noise_ids = Counter(e.get("Id") for e in noise_errors)
        top_noise = ", ".join(f"ID {k} ({v}x)" for k, v in noise_ids.most_common(3))
        insights.append(_insight("info",
            f"{len(noise_errors)} known-noise event(s) in results ({top_noise}) — "
            "these are normal Windows background activity and do not require action."))

    # ── Warnings summary ─────────────────────────────────────────────────
    if warnings:
        warn_sources = Counter(e.get("Source","?") for e in warnings)
        top_ws, top_wn = warn_sources.most_common(1)[0]
        insights.append(_insight("info",
            f"{len(warnings)} warning(s). Top source: {top_ws} ({top_wn}x)."))

    if not errors:
        insights.append(_insight("ok",
            f"No errors in current results. {len(events)} total events shown."))

    # ── Status ────────────────────────────────────────────────────────────
    real_count = len(real_errors)
    status  = "critical" if real_count > 10 else "warning" if real_count > 0 else "ok"
    headline = (f"{real_count} real error(s) need attention"
                    + (f" ({len(noise_errors)} noise events filtered)" if noise_errors else "")
                if real_count
                else f"{len(events)} events retrieved — no actionable errors")
    return {"status": status, "headline": headline, "insights": insights, "actions": list(dict.fromkeys(actions))[:4]}


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS MONITOR
# ══════════════════════════════════════════════════════════════════════════════

# Known system processes — flagged as safe, no action needed

# ══════════════════════════════════════════════════════════════════════════════
# PROCESS KNOWLEDGE BASE & ENRICHMENT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

PROCESS_CACHE_FILE = os.path.join(APP_DIR, "process_cache.json")
_process_cache_lock = threading.Lock()
_process_cache: dict = {}
_process_queue: queue.Queue = queue.Queue()
_process_in_flight: set = set()

# Keyed by lowercase process name (no .exe)
PROCESS_KB: dict = {
    # ── Windows core ──────────────────────────────────────────────────────
    "system":                   {"plain": "Windows Kernel",                  "publisher": "Microsoft", "what": "The Windows NT kernel process. Always running — cannot and should not be killed.", "safe_kill": False},
    "registry":                 {"plain": "Windows Registry",                "publisher": "Microsoft", "what": "Manages the Windows registry in memory. Core system process.", "safe_kill": False},
    "smss":                     {"plain": "Session Manager Subsystem",       "publisher": "Microsoft", "what": "Starts user sessions during Windows boot. Core system process.", "safe_kill": False},
    "csrss":                    {"plain": "Client Server Runtime Process",   "publisher": "Microsoft", "what": "Manages Windows console and GUI shutdown. Killing it causes a BSOD.", "safe_kill": False},
    "wininit":                  {"plain": "Windows Initialisation",          "publisher": "Microsoft", "what": "Launches core Windows services at startup. Critical process.", "safe_kill": False},
    "winlogon":                 {"plain": "Windows Logon",                   "publisher": "Microsoft", "what": "Handles user login/logout and locking the screen.", "safe_kill": False},
    "services":                 {"plain": "Service Control Manager",         "publisher": "Microsoft", "what": "Manages all Windows services — starting, stopping, and monitoring them.", "safe_kill": False},
    "lsass":                    {"plain": "Local Security Authority",        "publisher": "Microsoft", "what": "Handles user authentication and security policy enforcement. Killing causes immediate logout.", "safe_kill": False},
    "svchost":                  {"plain": "Service Host",                    "publisher": "Microsoft", "what": "A shared hosting process for Windows services. Multiple instances are normal — each hosts one or more services.", "safe_kill": False},
    "explorer":                 {"plain": "Windows Explorer",                "publisher": "Microsoft", "what": "The Windows desktop shell — taskbar, Start menu, and File Explorer. Restarting it refreshes the desktop.", "safe_kill": True},
    "dwm":                      {"plain": "Desktop Window Manager",         "publisher": "Microsoft", "what": "Renders all windows and visual effects on screen. Terminating it causes a brief black screen and restart.", "safe_kill": False},
    "taskhostw":                {"plain": "Task Host Window",                "publisher": "Microsoft", "what": "Hosts Windows tasks that run at logon and logoff. Background system process.", "safe_kill": False},
    "runtimebroker":            {"plain": "Runtime Broker",                  "publisher": "Microsoft", "what": "Manages permissions for Windows Store apps. Multiple instances are normal.", "safe_kill": True},
    "sihost":                   {"plain": "Shell Infrastructure Host",       "publisher": "Microsoft", "what": "Supports the Windows shell — notification area, action centre, and background slideshow.", "safe_kill": False},
    "fontdrvhost":              {"plain": "Font Driver Host",                "publisher": "Microsoft", "what": "Hosts the Windows font driver in an isolated process for security.", "safe_kill": False},
    "searchhost":               {"plain": "Windows Search",                  "publisher": "Microsoft", "what": "Powers the Start menu search and Windows Search indexing.", "safe_kill": True},
    "searchindexer":            {"plain": "Search Indexer",                  "publisher": "Microsoft", "what": "Indexes your files in the background for fast search. High disk use is normal when indexing.", "safe_kill": True},
    "msmpeng":                  {"plain": "Windows Defender Antivirus",      "publisher": "Microsoft", "what": "Real-time antivirus and malware protection. High CPU during scans is normal.", "safe_kill": False},
    "nissrv":                   {"plain": "Windows Defender Network Inspection", "publisher": "Microsoft", "what": "Network-level intrusion detection component of Windows Defender.", "safe_kill": False},
    "securityhealthservice":    {"plain": "Windows Security Health Service", "publisher": "Microsoft", "what": "Reports security status to Windows Security centre.", "safe_kill": False},
    "audiodg":                  {"plain": "Windows Audio Device Graph",      "publisher": "Microsoft", "what": "Runs audio processing in an isolated process. High CPU here means heavy audio workload or audio driver issue.", "safe_kill": False},
    "spoolsv":                  {"plain": "Print Spooler",                   "publisher": "Microsoft", "what": "Manages print jobs. Safe to kill if not printing — it will restart.", "safe_kill": True},
    "ctfmon":                   {"plain": "CTF Loader",                      "publisher": "Microsoft", "what": "Supports alternative text input — handwriting, speech, on-screen keyboard.", "safe_kill": True},
    "dllhost":                  {"plain": "COM Surrogate",                   "publisher": "Microsoft", "what": "Hosts COM objects out-of-process for safety. Multiple instances are normal — Explorer uses them for thumbnail generation.", "safe_kill": True},
    "conhost":                  {"plain": "Console Window Host",             "publisher": "Microsoft", "what": "Hosts each command prompt / PowerShell window. One instance per terminal.", "safe_kill": True},
    "applicationframehost":     {"plain": "Application Frame Host",          "publisher": "Microsoft", "what": "Hosts the frames/windows for Windows Store apps.", "safe_kill": True},
    "shellexperiencehost":      {"plain": "Windows Shell Experience Host",   "publisher": "Microsoft", "what": "Powers the Start menu, taskbar clock, and notification area.", "safe_kill": False},
    "startmenuexperiencehost":  {"plain": "Start Menu",                      "publisher": "Microsoft", "what": "Hosts the Windows 11 Start menu. Restarting Explorer also restarts this.", "safe_kill": True},
    "textinputhost":            {"plain": "Text Input Application",          "publisher": "Microsoft", "what": "Hosts the on-screen touch keyboard and handwriting panel.", "safe_kill": True},
    "wuauclt":                  {"plain": "Windows Update",                  "publisher": "Microsoft", "what": "Windows Update client — checks for and downloads updates. High activity is normal during update scans.", "safe_kill": False},
    "msdtc":                    {"plain": "Distributed Transaction Coordinator", "publisher": "Microsoft", "what": "Manages distributed database transactions. Usually idle unless you run SQL Server or BizTalk.", "safe_kill": True},
    "dashost":                  {"plain": "Device Association Framework",    "publisher": "Microsoft", "what": "Manages pairing of Bluetooth and Wi-Fi Direct devices.", "safe_kill": True},
    "wlanext":                  {"plain": "WLAN Extensibility Module",       "publisher": "Microsoft", "what": "Extends Wi-Fi driver functionality. Required for Wi-Fi adapters.", "safe_kill": False},
    "mrt":                      {"plain": "Malicious Software Removal Tool", "publisher": "Microsoft", "what": "Microsoft's periodic malware scan tool. Runs once a month — high CPU use during that scan is normal.", "safe_kill": True},
    "compattelrunner":          {"plain": "Compatibility Telemetry",         "publisher": "Microsoft", "what": "Collects usage and compatibility data for Microsoft. High CPU/disk is normal during its periodic run.", "safe_kill": True},
    "wsappx":                   {"plain": "Windows Store App Service",       "publisher": "Microsoft", "what": "Manages Windows Store app installations and updates.", "safe_kill": True},
    "wermgr":                   {"plain": "Windows Error Reporting",         "publisher": "Microsoft", "what": "Sends crash reports to Microsoft. Appears briefly after app crashes.", "safe_kill": True},
    # ── Dell ─────────────────────────────────────────────────────────────
    "dellsupportassistremediationservice": {"plain": "Dell SupportAssist Remediation", "publisher": "Dell Inc.", "what": "Background component of Dell SupportAssist — scans hardware and fetches driver updates.", "safe_kill": True},
    "dellsupportassist":        {"plain": "Dell SupportAssist",              "publisher": "Dell Inc.", "what": "Dell diagnostic and driver update tool.", "safe_kill": True},
    "dellcommandupdate":        {"plain": "Dell Command Update",             "publisher": "Dell Inc.", "what": "Manages Dell BIOS, driver, and firmware updates.", "safe_kill": True},
    "delldigitaldelivery":      {"plain": "Dell Digital Delivery",           "publisher": "Dell Inc.", "what": "Delivers bundled software for Dell PCs.", "safe_kill": True},
    # ── NVIDIA ───────────────────────────────────────────────────────────
    "nvcontainer":              {"plain": "NVIDIA Container",                "publisher": "NVIDIA", "what": "Hosts NVIDIA background services including GeForce Experience, telemetry, and display driver components.", "safe_kill": True},
    "nvdisplay.container":      {"plain": "NVIDIA Display Container",        "publisher": "NVIDIA", "what": "Hosts the NVIDIA display driver service and control panel backend.", "safe_kill": False},
    "nvbackend":                {"plain": "NVIDIA GeForce Experience Backend","publisher": "NVIDIA", "what": "Powers the GeForce Experience overlay, game optimisation, and screenshot capture.", "safe_kill": True},
    "nvcplui":                  {"plain": "NVIDIA Control Panel",            "publisher": "NVIDIA", "what": "The NVIDIA Control Panel UI for display and GPU settings.", "safe_kill": True},
    "nvidia web helper":        {"plain": "NVIDIA Web Helper",               "publisher": "NVIDIA", "what": "Communicates with NVIDIA's online services for driver updates and GeForce Now.", "safe_kill": True},
    # ── Intel ────────────────────────────────────────────────────────────
    "igfxem":                   {"plain": "Intel Graphics Event Monitor",    "publisher": "Intel", "what": "Monitors hotkey events for Intel integrated graphics (e.g. display mode switching).", "safe_kill": True},
    "igfxhk":                   {"plain": "Intel Graphics Hotkey Helper",    "publisher": "Intel", "what": "Enables keyboard shortcuts for Intel graphics settings.", "safe_kill": True},
    "lms":                      {"plain": "Intel Management Engine Local Management Service", "publisher": "Intel", "what": "Provides local access to Intel Management Engine features. Low-level firmware interface.", "safe_kill": False},
    # ── Microsoft Office / 365 ───────────────────────────────────────────
    "officeclicktorun":         {"plain": "Microsoft Office Click-to-Run",   "publisher": "Microsoft", "what": "Manages Office app updates and streaming installation in the background.", "safe_kill": True},
    "msoffice":                 {"plain": "Microsoft Office",                "publisher": "Microsoft", "what": "Microsoft Office application.", "safe_kill": True},
    "teams":                    {"plain": "Microsoft Teams",                  "publisher": "Microsoft", "what": "Microsoft Teams messaging and video call app. High RAM use (1–2 GB) is normal.", "safe_kill": True},
    "ms-teams":                 {"plain": "Microsoft Teams",                  "publisher": "Microsoft", "what": "Microsoft Teams — the new version. High RAM use (1–2 GB) is normal for modern Electron apps.", "safe_kill": True},
    "outlook":                  {"plain": "Microsoft Outlook",               "publisher": "Microsoft", "what": "Microsoft Outlook email client.", "safe_kill": True},
    "winword":                  {"plain": "Microsoft Word",                   "publisher": "Microsoft", "what": "Microsoft Word word processor.", "safe_kill": True},
    "excel":                    {"plain": "Microsoft Excel",                  "publisher": "Microsoft", "what": "Microsoft Excel spreadsheet application.", "safe_kill": True},
    "powerpnt":                 {"plain": "Microsoft PowerPoint",             "publisher": "Microsoft", "what": "Microsoft PowerPoint presentation app.", "safe_kill": True},
    # ── Browsers ─────────────────────────────────────────────────────────
    "chrome":                   {"plain": "Google Chrome",                    "publisher": "Google", "what": "Google Chrome browser. Multiple processes are normal — Chrome uses separate processes per tab for stability.", "safe_kill": True},
    "msedge":                   {"plain": "Microsoft Edge",                   "publisher": "Microsoft", "what": "Microsoft Edge browser. Multiple processes are normal — one per tab.", "safe_kill": True},
    "firefox":                  {"plain": "Mozilla Firefox",                  "publisher": "Mozilla", "what": "Mozilla Firefox browser.", "safe_kill": True},
    "brave":                    {"plain": "Brave Browser",                    "publisher": "Brave Software", "what": "Privacy-focused Chromium-based browser.", "safe_kill": True},
    # ── Common apps ──────────────────────────────────────────────────────
    "discord":                  {"plain": "Discord",                          "publisher": "Discord Inc.", "what": "Discord chat and voice app. High RAM use (300–600 MB) is normal for Electron apps.", "safe_kill": True},
    "slack":                    {"plain": "Slack",                            "publisher": "Slack Technologies", "what": "Slack messaging app. High RAM is normal for Electron-based apps.", "safe_kill": True},
    "zoom":                     {"plain": "Zoom",                             "publisher": "Zoom Video Communications", "what": "Zoom video conferencing. High CPU during calls is expected.", "safe_kill": True},
    "spotify":                  {"plain": "Spotify",                          "publisher": "Spotify AB", "what": "Spotify music streaming app.", "safe_kill": True},
    "steam":                    {"plain": "Steam",                            "publisher": "Valve Corporation", "what": "Steam gaming platform and store. High RAM when a game is loaded is expected.", "safe_kill": True},
    "steamwebhelper":           {"plain": "Steam Web Browser Helper",         "publisher": "Valve Corporation", "what": "Embedded browser component used by the Steam store and community pages.", "safe_kill": True},
    "epicgameslauncher":        {"plain": "Epic Games Launcher",              "publisher": "Epic Games", "what": "Epic Games store and launcher.", "safe_kill": True},
    "onedrive":                 {"plain": "Microsoft OneDrive",               "publisher": "Microsoft", "what": "OneDrive sync client. Your WinDesktopMgr health reports sync through this.", "safe_kill": True},
    "dropbox":                  {"plain": "Dropbox",                          "publisher": "Dropbox Inc.", "what": "Dropbox cloud sync client.", "safe_kill": True},
    "1password":                {"plain": "1Password",                        "publisher": "AgileBits", "what": "1Password password manager.", "safe_kill": True},
    "nordvpn":                  {"plain": "NordVPN",                          "publisher": "Nord Security", "what": "NordVPN client — managing active VPN connection.", "safe_kill": True},
    # ── Security ─────────────────────────────────────────────────────────
    "mbam":                     {"plain": "Malwarebytes",                     "publisher": "Malwarebytes", "what": "Malwarebytes Anti-Malware real-time protection.", "safe_kill": False},
    "mbamservice":              {"plain": "Malwarebytes Service",             "publisher": "Malwarebytes", "what": "Malwarebytes background service.", "safe_kill": False},
    # ── WinDesktopMgr ────────────────────────────────────────────────────
    "windesktopmgr":            {"plain": "WinDesktopMgr (this app)",         "publisher": "Local", "what": "Your Windows system management dashboard. This is the Flask process powering the UI you are looking at right now.", "safe_kill": False},
    "python":                   {"plain": "Python",                           "publisher": "Python Software Foundation", "what": "Python interpreter — likely running WinDesktopMgr or another script.", "safe_kill": True},
    # ── MC / McAfee ───────────────────────────────────────────────────────
    "mc-fw-host":               {"plain": "McAfee Firewall Host",             "publisher": "McAfee / Trellix", "what": "McAfee/Trellix firewall engine. High RAM use (1–2 GB) is common with McAfee security suites.", "safe_kill": False},
    "mcafee":                   {"plain": "McAfee Security",                  "publisher": "McAfee / Trellix", "what": "McAfee antivirus and security suite.", "safe_kill": False},
    "mfemms":                   {"plain": "McAfee Multi-Access Service",      "publisher": "McAfee / Trellix", "what": "McAfee licence and account management service.", "safe_kill": False},
    "serviceshell":             {"plain": "McAfee Service Shell",             "publisher": "McAfee / Trellix", "what": "Hosts McAfee security service components. High RAM use is normal for McAfee. Consider whether a lighter antivirus would suit you better — Windows Defender is built-in and uses far less RAM.", "safe_kill": False},
    "mfewch":                   {"plain": "McAfee Web Control Helper",        "publisher": "McAfee / Trellix", "what": "McAfee web content filtering component.", "safe_kill": False},
    "mfetp":                    {"plain": "McAfee Threat Prevention",         "publisher": "McAfee / Trellix", "what": "McAfee real-time threat detection engine.", "safe_kill": False},
}


def _load_process_cache():
    global _process_cache
    if not os.path.exists(PROCESS_CACHE_FILE):
        _process_cache = {}
        return
    try:
        with open(PROCESS_CACHE_FILE, encoding="utf-8") as f:
            _process_cache = json.load(f)
        print(f"[ProcessCache] Loaded {len(_process_cache)} cached processes")
    except Exception as e:
        print(f"[ProcessCache] Load error: {e}")
        _process_cache = {}


def _save_process_cache():
    try:
        with _process_cache_lock:
            with open(PROCESS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_process_cache, f, indent=2)
    except Exception as e:
        print(f"[ProcessCache] Save error: {e}")


def _lookup_process_via_fileinfo(proc_name: str, path: str) -> dict | None:
    """Read embedded file version info from the exe — offline, always current."""
    if not path:
        # Try to find exe via where.exe
        try:
            r0 = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 f'(Get-Command "{proc_name}.exe" -EA SilentlyContinue)?.Source'],
                capture_output=True, text=True, timeout=5)
            path = r0.stdout.strip()
        except Exception:
            pass
    if not path:
        return None
    ps = f"""
try {{
    $f = Get-Item "{path}" -EA Stop
    $v = $f.VersionInfo
    [PSCustomObject]@{{
        FileDescription = $v.FileDescription
        CompanyName     = $v.CompanyName
        ProductName     = $v.ProductName
        FileVersion     = $v.FileVersion
    }} | ConvertTo-Json
}} catch {{ }}
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=8)
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc    = (data.get("FileDescription") or "").strip()
        company = (data.get("CompanyName") or "").strip()
        product = (data.get("ProductName") or "").strip()
        if not desc and not company:
            return None
        is_system = any(p in path.lower() for p in
                        ("\\windows\\", "\\system32\\", "\\syswow64\\"))
        return {
            "source":    "file_version_info",
            "plain":     product or desc or proc_name,
            "publisher": company or "Unknown",
            "what":      desc or f"Executable from {company}.",
            "safe_kill": not is_system,
            "fetched":   datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[ProcessLookup] file info failed for {proc_name}: {e}")
        return None


def _lookup_process_via_web(proc_name: str) -> dict | None:
    """Web search fallback via Microsoft Learn."""
    for q_str in [f"{proc_name}.exe process windows what is", f"{proc_name} windows process"]:
        try:
            q   = urllib.parse.quote(q_str)
            url = f"https://learn.microsoft.com/api/search?search={q}&locale=en-us&%24top=3"
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top     = results[0]
            summary = (top.get("summary") or "").strip()[:250]
            if not summary:
                continue
            return {
                "source":    "microsoft_learn",
                "plain":     top.get("title", proc_name),
                "publisher": "See details",
                "what":      summary,
                "safe_kill": True,
                "url":       top.get("url", ""),
                "fetched":   datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            continue
    return None


def _process_lookup_worker():
    """Background thread — enriches unknown processes."""
    while True:
        key = None
        try:
            raw = _process_queue.get(timeout=5)
            if isinstance(raw, tuple):
                key, proc_name, path = raw
            else:
                key = proc_name = raw
                path = ""
            with _process_cache_lock:
                if key in _process_cache:
                    _process_in_flight.discard(key)
                    _process_queue.task_done()
                    continue
            print(f"[ProcessCache] Looking up: {proc_name}")
            result = _lookup_process_via_fileinfo(proc_name, path)
            if not result:
                result = _lookup_process_via_web(proc_name)
            if not result:
                result = {
                    "source":    "unknown",
                    "plain":     proc_name,
                    "publisher": "Unknown",
                    "what":      "No description found. Search the process name online to identify it.",
                    "safe_kill": True,
                    "fetched":   datetime.now(timezone.utc).isoformat(),
                }
            with _process_cache_lock:
                _process_cache[key] = result
            _save_process_cache()
            print(f"[ProcessCache] Cached: {proc_name} (source: {result['source']})")
        except queue.Empty:
            pass
        except Exception as e:
            print(f"[ProcessLookupWorker] error: {e}")
        finally:
            try:
                if key:
                    _process_in_flight.discard(key)
                _process_queue.task_done()
            except Exception:
                pass


def get_process_info(proc_name: str, path: str = "") -> dict | None:
    """Main entry — static KB → cache → background lookup."""
    key = proc_name.lower().replace(".exe", "")
    # Static KB — exact then partial
    if key in PROCESS_KB:
        info = dict(PROCESS_KB[key])
        info["source"] = "static_kb"
        return info
    for kb_key in PROCESS_KB:
        if kb_key in key or key in kb_key:
            info = dict(PROCESS_KB[kb_key])
            info["source"] = "static_kb"
            return info
    # Cache
    with _process_cache_lock:
        if key in _process_cache:
            return _process_cache[key]
    # Queue background lookup
    if key not in _process_in_flight:
        _process_in_flight.add(key)
        _process_queue.put((key, proc_name, path))
    return None


SAFE_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "fontdrvhost.exe", "dwm.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe",
    "sihost.exe", "ctfmon.exe", "searchindexer.exe", "wuauclt.exe", "mrt.exe",
    "dllhost.exe", "conhost.exe", "runtimebroker.exe", "applicationframehost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe", "searchhost.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "msmpeng.exe",
    "nissrv.exe", "audiodg.exe", "dashost.exe", "wlanext.exe", "msdtc.exe",
    "windesktopmgr.py", "python.exe", "pythonw.exe", "py.exe",
}

# High-resource thresholds
CPU_WARN_PCT  = 25.0
MEM_WARN_MB   = 500
MEM_CRIT_MB   = 1500


def get_process_list() -> dict:
    # Use Get-WmiObject Win32_Process — no elevation needed, much faster than
    # Get-Process with MainModule which hangs on protected system processes.
    ps = r"""
$wmi = @{}
try {
    Get-WmiObject Win32_Process -EA SilentlyContinue | ForEach-Object {
        $wmi[$_.ProcessId] = [PSCustomObject]@{
            Path        = $_.ExecutablePath
            Company     = ""
            Description = $_.Description
            CmdLine     = $_.CommandLine
        }
    }
} catch {}
$procs = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $cpu = 0
    try { $cpu = [math]::Round($_.CPU, 1) } catch {}
    $w = $wmi[$_.Id]
    [PSCustomObject]@{
        PID         = $_.Id
        Name        = $_.ProcessName
        CPU         = $cpu
        MemMB       = [math]::Round($_.WorkingSet64 / 1MB, 1)
        Threads     = $_.Threads.Count
        Handles     = $_.HandleCount
        Path        = if ($w) { $w.Path } else { "" }
        Description = if ($w) { $w.Description } else { "" }
        CmdLine     = if ($w) { ($w.CmdLine -replace "`"","") } else { "" }
    }
} | Sort-Object MemMB -Descending
$procs | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=45)
        if r.stderr.strip():
            print(f"[ProcessMonitor] stderr: {r.stderr.strip()[:200]}")
        raw = r.stdout.strip()
        if not raw:
            print("[ProcessMonitor] No output from PowerShell")
            return {"processes": [], "total": 0, "total_mem_mb": 0, "flagged": [], "flag_notes": []}
        data = json.loads(raw)
        procs = data if isinstance(data, list) else [data]

        total_mem  = sum(p.get("MemMB", 0) for p in procs)
        flags = []
        for p in procs:
            name_l = (p.get("Name", "") + ".exe").lower()
            mem    = p.get("MemMB", 0)
            cpu    = p.get("CPU", 0)
            # Attach enrichment info
            p["info"] = get_process_info(p.get("Name", ""), p.get("Path", ""))
            # Use safe_kill from KB/cache to refine flagging
            is_safe_system = name_l in SAFE_PROCESSES or (
                p["info"] and p["info"].get("safe_kill") is False)
            p["flag"] = ""
            if not is_safe_system:
                if mem >= MEM_CRIT_MB:
                    plain = (p["info"] or {}).get("plain", p["Name"])
                    p["flag"] = "critical"
                    flags.append(f"{plain} using {mem:.0f} MB RAM")
                elif mem >= MEM_WARN_MB:
                    p["flag"] = "warning"
                elif cpu >= CPU_WARN_PCT:
                    plain = (p["info"] or {}).get("plain", p["Name"])
                    p["flag"] = "warning"
                    flags.append(f"{plain} using {cpu:.0f}% CPU")

        return {
            "processes":   procs,
            "total":       len(procs),
            "total_mem_mb": round(total_mem, 1),
            "flagged":     [p for p in procs if p["flag"]],
            "flag_notes":  flags[:5],
        }
    except Exception as e:
        print(f"[ProcessMonitor] error: {e}")
        return {"processes": [], "total": 0, "total_mem_mb": 0, "flagged": [], "flag_notes": []}


def kill_process(pid: int) -> dict:
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             f"Stop-Process -Id {int(pid)} -Force -ErrorAction Stop"],
            capture_output=True, text=True, timeout=10)
        return {"ok": r.returncode == 0, "error": r.stderr.strip()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def summarize_processes(data: dict) -> dict:
    procs    = data.get("processes", [])
    flagged  = data.get("flagged", [])
    insights = []
    actions  = []
    if not procs:
        return {"status": "ok", "headline": "No process data.", "insights": [], "actions": []}

    critical = [p for p in flagged if p.get("flag") == "critical"]
    warnings = [p for p in flagged if p.get("flag") == "warning"]

    # ── Critical RAM hogs — with plain-English names and explanation ──────────
    for p in sorted(critical, key=lambda x: x.get("MemMB",0), reverse=True)[:5]:
        info  = p.get("info") or {}
        plain = info.get("plain", p["Name"])
        what  = info.get("what", "")
        pub   = info.get("publisher", "")
        mem   = p.get("MemMB", 0)
        safe  = info.get("safe_kill", True)
        pub_str = f" ({pub})" if pub and pub not in ("Unknown","See details") else ""
        what_str = f" — {what}" if what else ""
        action_str = (
            "This process is safe to kill if not needed right now."
            if safe else
            "This is a system or security process — do not kill it."
        )
        insights.append(_insight("critical",
            f"{plain}{pub_str} using {mem:.0f} MB RAM.{what_str}",
            action_str))
    if critical:
        actions.append("Kill high-memory processes if not needed")

    # ── Warning-level resource use ────────────────────────────────────────────
    for p in sorted(warnings, key=lambda x: x.get("MemMB",0), reverse=True)[:4]:
        info  = p.get("info") or {}
        plain = info.get("plain", p["Name"])
        what  = info.get("what", "")
        mem   = p.get("MemMB", 0)
        cpu   = p.get("CPU", 0)
        metric = f"{mem:.0f} MB RAM" if mem >= MEM_WARN_MB else f"{cpu:.0f}% CPU"
        what_str = f" — {what[:80]}…" if len(what) > 80 else (f" — {what}" if what else "")
        insights.append(_insight("warning", f"{plain} using {metric}.{what_str}"))

    # ── Unknown processes (no info yet) ───────────────────────────────────────
    unknown = [p for p in procs if p.get("info") is None
               and (p.get("Name","") + ".exe").lower() not in SAFE_PROCESSES]
    if unknown:
        insights.append(_insight("info",
            f"{len(unknown)} process(es) still being identified in the background. "
            "Refresh in a few seconds for full details."))

    # ── Top consumers overview ────────────────────────────────────────────────
    top_mem = sorted(procs, key=lambda p: p.get("MemMB", 0), reverse=True)[:3]
    top_str = ", ".join(
        f"{(p.get('info') or {}).get('plain', p['Name'])} ({p.get('MemMB',0):.0f} MB)"
        for p in top_mem)
    insights.append(_insight("info",
        f"{data['total']} processes, {data['total_mem_mb']:.0f} MB RAM total. "
        f"Top consumers: {top_str}."))

    if not critical and not warnings:
        insights.append(_insight("ok", "All processes within normal resource limits."))

    status = "critical" if critical else "warning" if warnings else "ok"
    headline = (f"{len(critical)} process(es) using excessive RAM" if critical
                else f"{len(warnings)} process(es) with elevated resource use" if warnings
                else f"{data['total']} processes — all normal")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# TEMPERATURE & POWER
# ══════════════════════════════════════════════════════════════════════════════

TEMP_WARN_C = 80
TEMP_CRIT_C = 95


def get_thermals() -> dict:
    # CPU temps via WMI MSAcpi_ThermalZoneTemperature
    ps_temps = r"""
$results = @()
try {
    $zones = Get-WmiObject -Namespace "root\wmi" -Class MSAcpi_ThermalZoneTemperature -EA Stop
    foreach ($z in $zones) {
        $celsius = [math]::Round($z.CurrentTemperature / 10 - 273.15, 1)
        $results += [PSCustomObject]@{
            Name    = $z.InstanceName -replace ".*_","" -replace "\\.*",""
            TempC   = $celsius
            Source  = "WMI_ThermalZone"
        }
    }
} catch {}
# CPU package temp via OpenHardwareMonitor WMI if available
try {
    $ohm = Get-WmiObject -Namespace "root\OpenHardwareMonitor" -Class Sensor -EA Stop |
           Where-Object { $_.SensorType -eq "Temperature" }
    foreach ($s in $ohm) {
        $results += [PSCustomObject]@{
            Name    = $s.Name
            TempC   = [math]::Round($s.Value, 1)
            Source  = "OpenHardwareMonitor"
        }
    }
} catch {}
# LibreHardwareMonitor WMI
try {
    $lhm = Get-WmiObject -Namespace "root\LibreHardwareMonitor" -Class Sensor -EA Stop |
           Where-Object { $_.SensorType -eq "Temperature" }
    foreach ($s in $lhm) {
        $results += [PSCustomObject]@{
            Name    = $s.Name
            TempC   = [math]::Round($s.Value, 1)
            Source  = "LibreHardwareMonitor"
        }
    }
} catch {}
$results | ConvertTo-Json -Depth 2
"""
    # CPU utilisation and power
    ps_perf = r"""
$cpu  = [math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
$mem  = Get-WmiObject Win32_OperatingSystem
$memUsedMB  = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / 1024, 0)
$memTotalMB = [math]::Round($mem.TotalVisibleMemorySize / 1024, 0)
$battery = $null
try {
    $b = Get-WmiObject Win32_Battery -EA Stop | Select-Object -First 1
    if ($b) { $battery = [PSCustomObject]@{ Status=$b.BatteryStatus; Charge=$b.EstimatedChargeRemaining } }
} catch {}
[PSCustomObject]@{
    CPUPct      = $cpu
    MemUsedMB   = $memUsedMB
    MemTotalMB  = $memTotalMB
    Battery     = $battery
} | ConvertTo-Json -Depth 3
"""
    # Fan speeds via WMI
    ps_fans = r"""
try {
    Get-WmiObject -Namespace "root\wmi" -Class Win32_Fan -EA Stop |
    Select-Object Name, ActiveCooling, DesiredSpeed |
    ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r1 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_temps],
                            capture_output=True, text=True, timeout=20)
        temps_raw = json.loads(r1.stdout.strip() or "[]")
        temps = temps_raw if isinstance(temps_raw, list) else ([temps_raw] if temps_raw else [])

        r2 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_perf],
                            capture_output=True, text=True, timeout=15)
        perf = json.loads(r2.stdout.strip() or "{}")

        r3 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_fans],
                            capture_output=True, text=True, timeout=10)
        fans_raw = json.loads(r3.stdout.strip() or "[]")
        fans = fans_raw if isinstance(fans_raw, list) else ([fans_raw] if fans_raw else [])

        # Annotate temperatures
        for t in temps:
            c = t.get("TempC", 0)
            t["status"] = "critical" if c >= TEMP_CRIT_C else "warning" if c >= TEMP_WARN_C else "ok"

        has_rich = any(t.get("Source") in ("OpenHardwareMonitor","LibreHardwareMonitor") for t in temps)

        return {
            "temps":       temps,
            "perf":        perf,
            "fans":        fans,
            "has_rich":    has_rich,
            "note":        "" if has_rich else (
                "Install LibreHardwareMonitor for detailed CPU/GPU per-core temperatures. "
                "Run it once as Administrator to register its WMI provider."
            ),
        }
    except Exception as e:
        print(f"[Thermals] error: {e}")
        return {"temps": [], "perf": {}, "fans": [], "has_rich": False, "note": str(e)}


def summarize_thermals(data: dict) -> dict:
    temps    = data.get("temps", [])
    perf     = data.get("perf", {})
    insights = []
    actions  = []
    cpu_pct  = perf.get("CPUPct", 0)
    mem_used = perf.get("MemUsedMB", 0)
    mem_tot  = perf.get("MemTotalMB", 1)

    critical_temps = [t for t in temps if t.get("status") == "critical"]
    warn_temps     = [t for t in temps if t.get("status") == "warning"]

    if critical_temps:
        insights.append(_insight("critical",
            "CRITICAL temperatures detected: " +
            ", ".join(f"{t['Name']} {t['TempC']}°C" for t in critical_temps),
            "Shut down immediately and check cooling. Clean dust from heatsink and case fans."))
        actions.append("Check cooling immediately")
    elif warn_temps:
        insights.append(_insight("warning",
            "Elevated temperatures: " +
            ", ".join(f"{t['Name']} {t['TempC']}°C" for t in warn_temps),
            "Monitor under load. Consider reapplying thermal paste if temps persist."))
    elif temps:
        insights.append(_insight("ok",
            "All temperatures normal: " +
            ", ".join(f"{t['Name']} {t['TempC']}°C" for t in temps[:4])))

    if cpu_pct >= 90:
        insights.append(_insight("warning", f"CPU at {cpu_pct}% — sustained high utilisation.",
            "Check the Processes tab to identify what is driving high CPU. "
            "This may be normal during heavy tasks (video encoding, backups) but worth checking if unexpected."))
    elif cpu_pct >= 60:
        insights.append(_insight("info", f"CPU at {cpu_pct}% utilisation — moderately busy."))
    else:
        insights.append(_insight("ok", f"CPU at {cpu_pct}% utilisation — normal."))

    if mem_tot > 0:
        mem_pct = round(mem_used / mem_tot * 100, 1)
        level = "critical" if mem_pct > 90 else "warning" if mem_pct > 75 else "ok"
        insights.append(_insight(level,
            f"RAM: {mem_used:,} MB used of {mem_tot:,} MB ({mem_pct}%)."))

    if not data.get("has_rich") and not temps:
        insights.append(_insight("info",
            "No temperature sensors detected via WMI. "
            "Install LibreHardwareMonitor for detailed CPU/GPU temps.",
            "Download from librehardwaremonitor.org — run as Administrator once to register."))

    status = ("critical" if critical_temps or cpu_pct >= 90
              else "warning" if warn_temps or cpu_pct >= 60
              else "ok")
    headline = ("🌡 Critical temps detected — check cooling!" if critical_temps
                else f"CPU {cpu_pct}% | RAM {round(mem_used/mem_tot*100) if mem_tot else 0}%"
                     + (" | ⚠ High temps" if warn_temps else ""))
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS SERVICES
# ══════════════════════════════════════════════════════════════════════════════

SERVICES_CACHE_FILE = os.path.join(APP_DIR, "services_item_cache.json")
_services_cache_lock = threading.Lock()
_services_cache: dict = {}
_services_queue: queue.Queue = queue.Queue()
_services_in_flight: set = set()

# Static knowledge base for common services
SERVICES_KB: dict = {
    "wuauserv":         {"plain": "Windows Update",              "safe_stop": False, "what": "Downloads and installs Windows updates. Required for system security."},
    "windefend":        {"plain": "Windows Defender Antivirus",  "safe_stop": False, "what": "Real-time malware protection. Never disable."},
    "mpssvc":           {"plain": "Windows Firewall",            "safe_stop": False, "what": "Network firewall. Never disable."},
    "bits":             {"plain": "Background Intelligent Transfer", "safe_stop": True,  "what": "Downloads Windows updates in the background using idle bandwidth."},
    "spooler":          {"plain": "Print Spooler",               "safe_stop": True,  "what": "Manages print jobs. Safe to disable if you never print."},
    "themes":           {"plain": "Windows Themes",              "safe_stop": True,  "what": "Applies visual themes to the Windows UI. Disabling reverts to a basic look."},
    "sysmain":          {"plain": "SysMain (SuperFetch)",        "safe_stop": True,  "what": "Pre-loads frequently used apps into RAM. On SSDs it adds little value."},
    "wersvc":           {"plain": "Windows Error Reporting",     "safe_stop": True,  "what": "Sends crash reports to Microsoft. Safe to disable for privacy."},
    "diagtrack":        {"plain": "Connected User Experiences & Telemetry", "safe_stop": True, "what": "Sends usage and diagnostic data to Microsoft. Safe to disable for privacy."},
    "fax":              {"plain": "Fax Service",                 "safe_stop": True,  "what": "Fax support. Almost certainly unused. Safe to disable."},
    "tabletinputservice":{"plain": "Touch Keyboard & Handwriting","safe_stop": True,  "what": "Supports touchscreen input. Safe to disable on non-touch PCs."},
    "xbgm":             {"plain": "Xbox Game Monitoring",        "safe_stop": True,  "what": "Xbox game capture service. Safe to disable if you don't use Xbox features."},
    "xblgamesave":      {"plain": "Xbox Live Game Save",         "safe_stop": True,  "what": "Syncs Xbox game saves to the cloud. Safe to disable if unused."},
    "xboxnetapisvc":    {"plain": "Xbox Live Networking",        "safe_stop": True,  "what": "Xbox Live multiplayer networking. Safe to disable if unused."},
    "xblauthmanager":   {"plain": "Xbox Live Auth Manager",      "safe_stop": True,  "what": "Xbox Live authentication. Safe to disable if you don't use Xbox."},
    "wsearch":          {"plain": "Windows Search",              "safe_stop": True,  "what": "Indexes files for fast search in Explorer. Disabling saves RAM but slows file search."},
    "lmhosts":          {"plain": "TCP/IP NetBIOS Helper",       "safe_stop": True,  "what": "Supports old NetBIOS network name resolution. Rarely needed on modern networks."},
    "remoteregistry":   {"plain": "Remote Registry",             "safe_stop": True,  "what": "Allows remote editing of registry. Disable for security unless specifically needed."},
    "termservice":      {"plain": "Remote Desktop Services",     "safe_stop": True,  "what": "Enables Remote Desktop connections to this PC. Disable if you don't use RDP."},
    "upnphost":         {"plain": "UPnP Device Host",            "safe_stop": True,  "what": "Hosts UPnP devices. Safe to disable if you don't use UPnP sharing."},
    "ssdpsrv":          {"plain": "SSDP Discovery",              "safe_stop": True,  "what": "Discovers UPnP devices on the network. Safe to disable with UPnP Host."},
    "wmpnetworksvc":    {"plain": "Windows Media Player Network Sharing", "safe_stop": True, "what": "Shares media libraries over the network. Safe to disable if unused."},
    "seclogon":         {"plain": "Secondary Logon",             "safe_stop": True,  "what": "Allows running programs as a different user (Run As). Safe to disable if unused."},
    "schedule":         {"plain": "Task Scheduler",              "safe_stop": False, "what": "Runs scheduled tasks — including WinDesktopMgr at login. Do not disable."},
    "eventlog":         {"plain": "Windows Event Log",           "safe_stop": False, "what": "Records system events. Required for BSOD Dashboard and Event Log tab. Never disable."},
    "cryptsvc":         {"plain": "Cryptographic Services",      "safe_stop": False, "what": "Manages certificates and crypto operations. Required for Windows Update and TLS."},
    "rpcss":            {"plain": "Remote Procedure Call (RPC)", "safe_stop": False, "what": "Core Windows RPC subsystem. Never disable — system will fail to boot."},
    "dnscache":         {"plain": "DNS Client",                  "safe_stop": True,  "what": "Caches DNS lookups to speed up web browsing. Rarely worth disabling."},
    "dhcp":             {"plain": "DHCP Client",                 "safe_stop": False, "what": "Gets your IP address from the router. Disabling breaks network connectivity."},
    "lanmanserver":     {"plain": "Server (File Sharing)",       "safe_stop": True,  "what": "Enables file and printer sharing from this PC. Safe to disable if not sharing."},
    "lanmanworkstation":{"plain": "Workstation (Network Files)", "safe_stop": False, "what": "Allows connecting to shared network files and printers. Disable only if fully isolated."},
    "dellsupportassistremediationservice": {"plain": "Dell SupportAssist Remediation", "safe_stop": True, "what": "Dell hardware diagnostics and driver update component. Safe to disable if managing drivers manually."},
    "dellsupportassist":{"plain": "Dell SupportAssist",          "safe_stop": True,  "what": "Dell support and diagnostics service. WinDesktopMgr covers the same ground."},
}


def _load_services_cache():
    global _services_cache
    if not os.path.exists(SERVICES_CACHE_FILE):
        _services_cache = {}
        return
    try:
        with open(SERVICES_CACHE_FILE, encoding="utf-8") as f:
            _services_cache = json.load(f)
        print(f"[ServicesCache] Loaded {len(_services_cache)} cached services")
    except Exception as e:
        print(f"[ServicesCache] Load error: {e}")
        _services_cache = {}


def _save_services_cache():
    try:
        with _services_cache_lock:
            with open(SERVICES_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_services_cache, f, indent=2)
    except Exception as e:
        print(f"[ServicesCache] Save error: {e}")


def _lookup_service_via_web(svc_name: str, display_name: str) -> dict | None:
    for q_str in [f"{svc_name} windows service what is", f"{display_name} windows service"]:
        try:
            q   = urllib.parse.quote(q_str)
            url = f"https://learn.microsoft.com/api/search?search={q}&locale=en-us&%24top=3"
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top     = results[0]
            summary = (top.get("summary") or "").strip()[:300]
            if not summary:
                continue
            return {
                "source":    "microsoft_learn",
                "plain":     top.get("title", display_name),
                "what":      summary,
                "safe_stop": True,
                "reason":    f"See: {top.get('url','')}",
                "fetched":   datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            continue
    return None


def _services_lookup_worker():
    while True:
        svc_key = None
        try:
            raw = _services_queue.get(timeout=5)
            if isinstance(raw, tuple):
                svc_key, display_name = raw
            else:
                svc_key = raw
                display_name = raw
            with _services_cache_lock:
                if svc_key in _services_cache:
                    _services_in_flight.discard(svc_key)
                    _services_queue.task_done()
                    continue
            print(f"[ServicesCache] Looking up: {svc_key}")
            result = _lookup_service_via_web(svc_key, display_name)
            if not result:
                result = {
                    "source":    "unknown",
                    "plain":     display_name,
                    "what":      "No description found.",
                    "safe_stop": True,
                    "reason":    f'Search "{svc_key} windows service" online.',
                    "fetched":   datetime.now(timezone.utc).isoformat(),
                }
            with _services_cache_lock:
                _services_cache[svc_key] = result
            _save_services_cache()
            print(f"[ServicesCache] Cached: {svc_key} (source: {result['source']})")
        except queue.Empty:
            pass
        except Exception as e:
            print(f"[ServicesLookupWorker] error: {e}")
        finally:
            try:
                if svc_key:
                    _services_in_flight.discard(svc_key)
                _services_queue.task_done()
            except Exception:
                pass


def get_services_item_info(svc_name: str, display_name: str) -> dict | None:
    key = svc_name.lower()
    if key in SERVICES_KB:
        info = dict(SERVICES_KB[key])
        info["source"] = "static_kb"
        return info
    with _services_cache_lock:
        if key in _services_cache:
            return _services_cache[key]
    if key not in _services_in_flight:
        _services_in_flight.add(key)
        _services_queue.put((key, display_name))
    return None


def get_services_list() -> list:
    ps = r"""
Get-WmiObject Win32_Service | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        Status      = $_.State
        StartMode   = $_.StartMode
        ProcessId   = $_.ProcessId
        Description = $_.Description
        PathName    = $_.PathName
    }
} | Sort-Object DisplayName | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout.strip() or "[]")
        svcs = data if isinstance(data, list) else [data]
        for s in svcs:
            s["info"] = get_services_item_info(s.get("Name",""), s.get("DisplayName",""))
        return svcs
    except Exception as e:
        print(f"[Services] error: {e}")
        return []


def toggle_service(name: str, action: str) -> dict:
    safe_name = re.sub(r"[^\w\-]", "", name)
    if action == "stop":
        cmd = f'Stop-Service -Name "{safe_name}" -Force -ErrorAction Stop'
    elif action == "start":
        cmd = f'Start-Service -Name "{safe_name}" -ErrorAction Stop'
    elif action == "disable":
        cmd = f'Set-Service -Name "{safe_name}" -StartupType Disabled -ErrorAction Stop'
    elif action == "enable":
        cmd = f'Set-Service -Name "{safe_name}" -StartupType Manual -ErrorAction Stop'
    else:
        return {"ok": False, "error": "Invalid action"}
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", cmd],
                           capture_output=True, text=True, timeout=15)
        return {"ok": r.returncode == 0, "error": r.stderr.strip()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def summarize_services(svcs: list) -> dict:
    if not svcs:
        return {"status": "ok", "headline": "No service data.", "insights": [], "actions": []}
    running  = [s for s in svcs if s.get("Status","").lower() == "running"]
    stopped  = [s for s in svcs if s.get("Status","").lower() == "stopped"]
    disabled = [s for s in svcs if s.get("StartMode","").lower() == "disabled"]
    insights = []
    # Flag auto-start services that are stopped (may indicate a problem)
    auto_stopped = [s for s in stopped
                    if s.get("StartMode","").lower() == "auto"
                    and s.get("Name","").lower() not in ("spooler",)]
    if auto_stopped:
        insights.append(_insight("warning",
            f"{len(auto_stopped)} auto-start service(s) are not running: "
            + ", ".join(s.get("DisplayName", s.get("Name","")) for s in auto_stopped[:3]),
            "Check Event Log for service failure errors."))
    insights.append(_insight("info",
        f"{len(running)} running, {len(stopped)} stopped, {len(disabled)} disabled "
        f"({len(svcs)} total)."))
    # Highlight privacy/telemetry services that are running
    privacy_svcs = {"diagtrack", "dmwappushservice", "wersvc"}
    privacy_running = [s for s in running if s.get("Name","").lower() in privacy_svcs]
    if privacy_running:
        insights.append(_insight("info",
            f"{len(privacy_running)} telemetry/diagnostic service(s) running: "
            + ", ".join(s.get("DisplayName","") for s in privacy_running),
            "Safe to disable for privacy if desired."))
    if not auto_stopped:
        insights.append(_insight("ok", "All auto-start services are running normally."))
    status = "warning" if auto_stopped else "ok"
    headline = (f"{len(auto_stopped)} auto-start service(s) not running" if auto_stopped
                else f"{len(running)} services running — all normal")
    return {"status": status, "headline": headline, "insights": insights, "actions": []}


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH REPORT HISTORY
# ══════════════════════════════════════════════════════════════════════════════

def get_health_report_history() -> dict:
    """
    Parse all SystemHealthDiag HTML reports from REPORT_DIR and extract:
    - health score over time
    - BSOD count per report
    - driver/WHEA error counts
    Returns data ready for charting.
    """
    if not os.path.isdir(REPORT_DIR):
        return {"reports": [], "error": f"Report directory not found: {REPORT_DIR}"}

    reports = []
    paths = sorted(glob.glob(os.path.join(REPORT_DIR, "*.html")))[-90:]  # last 90

    for path in paths:
        try:
            fname = os.path.basename(path)
            ts = None

            # Format 1: SystemHealthReport_2026-03-16_09-30-24.html (SystemHealthDiag.py format)
            dm = re.search(r"(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})", fname)
            if dm:
                ts = datetime.strptime(
                    f"{dm.group(1)}_{dm.group(2)}", "%Y-%m-%d_%H-%M-%S"
                ).replace(tzinfo=timezone.utc)

            # Format 2: 20260316_093024 (compact format)
            if not ts:
                dm = re.search(r"(\d{8})_(\d{6})", fname)
                if dm:
                    ts = datetime.strptime(
                        f"{dm.group(1)}_{dm.group(2)}", "%Y%m%d_%H%M%S"
                    ).replace(tzinfo=timezone.utc)

            if not ts:
                continue

            with open(path, encoding="utf-8", errors="ignore") as f:
                html = f.read()

            # Extract health score — SystemHealthDiag.py uses <div class="score-num">87</div>
            score = None
            # Primary: score-num div (SystemHealthDiag.py format)
            for pat in [
                r'class=["\']score-num["\'][^>]*>(\d{1,3})<',   # <div class="score-num">87</div>
                r'score-num[^>]*>\s*(\d{1,3})\s*<',             # whitespace variant
                r"Health Score[:\s]+([0-9]{1,3})\s*/\s*100",    # "Health Score: 87/100"
                r"(\d{1,3})\s*/\s*100",                          # "87/100" anywhere
                r"[Ss]core[:\s]+([0-9]{1,3})",                   # "Score: 87"
            ]:
                m = re.search(pat, html)
                if m:
                    v = int(m.group(1))
                    if 0 <= v <= 100:
                        score = v
                        break

            # BSOD count — SystemHealthDiag.py outputs "Crashes - 30 days" with the count
            bsod_count = 0

            # Primary: "Crashes - 30 days", N  pattern in the sys-grid
            m_crashes = re.search(r"Crashes\s*[-–]\s*30\s*days.*?(\d+)", html, re.IGNORECASE | re.DOTALL)
            if m_crashes:
                bsod_count = int(m_crashes.group(1))
            else:
                # Fallback: count BugCheckCode entries in the crash table
                bsod_codes = re.findall(
                    r"(HYPERVISOR_ERROR|PAGE_FAULT_IN_NONPAGED_AREA|VIDEO_TDR_FAILURE"
                    r"|KERNEL_SECURITY_CHECK_FAILURE|DRIVER_POWER_STATE_FAILURE"
                    r"|SYSTEM_SERVICE_EXCEPTION|DPC_WATCHDOG_VIOLATION"
                    r"|DRIVER_IRQL_NOT_LESS_OR_EQUAL|CRITICAL_PROCESS_DIED"
                    r"|KMODE_EXCEPTION_NOT_HANDLED|IRQL_NOT_LESS_OR_EQUAL)",
                    html, re.IGNORECASE
                )
                bsod_count = len(bsod_codes)  # total occurrences, not unique

            # WHEA errors
            whea = len(re.findall(r"WHEA|hardware error|machine check", html, re.IGNORECASE))

            # Driver errors in this report
            drv_errors = len(re.findall(r"driver error|driver fail|driver crash", html, re.IGNORECASE))

            # Distinct .sys files mentioned (faulty drivers)
            sys_files = list(dict.fromkeys(
                d.lower() for d in re.findall(r"\b(\w+\.sys)\b", html, re.IGNORECASE)
            ))[:5]

            # Status label from report
            status = "ok"
            if bsod_count > 0 or "critical" in html.lower():
                status = "critical"
            elif "warning" in html.lower() or whea > 0 or drv_errors > 0:
                status = "warning"

            reports.append({
                "file":       fname,
                "path":       path,
                "timestamp":  ts.isoformat(),
                "date_label": ts.strftime("%b %d"),
                "score":      score,
                "bsod_count": bsod_count,
                "whea_count": whea,
                "drv_errors": drv_errors,
                "sys_files":  sys_files,
                "status":     status,
            })
        except Exception as e:
            print(f"[HealthHistory] error parsing {path}: {e}")
            continue

    # Summary stats
    scores    = [r["score"] for r in reports if r["score"] is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else None
    latest    = reports[-1] if reports else None

    return {
        "reports":   reports,
        "total":     len(reports),
        "avg_score": avg_score,
        "latest":    latest,
        "report_dir": REPORT_DIR,
    }


def summarize_health_history(data: dict) -> dict:
    reports = data.get("reports", [])
    insights, actions = [], []
    if not reports:
        return {"status": "info",
                "headline": "No health reports found — run SystemHealthDiag to generate them.",
                "insights": [], "actions": []}
    avg  = data.get("avg_score")
    last = data.get("latest", {})
    last_score = last.get("score") if last else None
    # Score trend
    if avg is not None:
        level = "ok" if avg >= 80 else "warning" if avg >= 60 else "critical"
        insights.append(_insight(level, f"Average health score: {avg}/100 across {len(reports)} reports."))
    if last_score is not None:
        level = "ok" if last_score >= 80 else "warning" if last_score >= 60 else "critical"
        insights.append(_insight(level, f"Latest report score: {last_score}/100 ({last.get('date_label','')})."))
    # Trend direction — compare first 10% vs last 10%
    if len(reports) >= 10:
        scored = [r for r in reports if r["score"] is not None]
        if len(scored) >= 10:
            n = max(3, len(scored) // 10)
            early_avg = sum(r["score"] for r in scored[:n]) / n
            late_avg  = sum(r["score"] for r in scored[-n:]) / n
            diff = round(late_avg - early_avg, 1)
            if diff < -5:
                insights.append(_insight("warning",
                    f"Health score trending down {abs(diff):.1f} points over the period.",
                    "Review recent BSODs and driver changes in the System Timeline."))
            elif diff > 5:
                insights.append(_insight("ok",
                    f"Health score trending up {diff:.1f} points — system is improving."))
    # BSOD correlation
    reports_with_bsod = [r for r in reports if r["bsod_count"] > 0]
    if reports_with_bsod:
        insights.append(_insight("warning",
            f"{len(reports_with_bsod)} report(s) contained BSOD events. "
            f"Most recent: {reports_with_bsod[-1].get('date_label','')}.",
            "Cross-reference with BSOD Dashboard for stop code details."))
    status = ("critical" if any(i["level"] == "critical" for i in insights)
              else "warning" if any(i["level"] == "warning" for i in insights)
              else "ok")
    headline = (f"Avg score {avg}/100 — {len(reports)} reports"
                if avg else f"{len(reports)} reports found")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM TIMELINE
# ══════════════════════════════════════════════════════════════════════════════

def get_system_timeline(days: int = 30) -> list:
    """
    Correlate events from multiple sources into a single chronological timeline.
    Sources: BSODs (Event Log + health reports), Windows Updates, driver installs,
             service state changes (Event Log 7036), system reboots (Event Log 6013).
    """
    events = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # ── 1. BSODs from Event Log ───────────────────────────────────────────────
    ps_bsod = r"""
$results = @()
foreach ($id in @(41, 1001, 6008)) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$id} `
            -MaxEvents 100 -ErrorAction Stop
        foreach ($e in $evts) {
            $results += [PSCustomObject]@{
                EventId     = $e.Id
                TimeCreated = $e.TimeCreated.ToString('o')
                Message     = if ($e.Message) { $e.Message.Substring(0,[Math]::Min(200,$e.Message.Length)) } else { "" }
            }
        }
    } catch {}
}
$results | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_bsod],
                           capture_output=True, text=True, timeout=20)
        bsod_evts = json.loads(r.stdout.strip() or "[]")
        if isinstance(bsod_evts, dict):
            bsod_evts = [bsod_evts]
        for e in bsod_evts:
            ts = _parse_ts(e.get("TimeCreated",""))
            if ts < cutoff:
                continue
            eid = e.get("EventId", 0)
            msg = e.get("Message","")
            code = re.search(r"0x[0-9a-fA-F]{4,8}", msg)
            events.append({
                "ts":       ts.isoformat(),
                "type":     "bsod",
                "category": "crash",
                "title":    "System Crash / Unexpected Shutdown",
                "detail":   (f"Stop code: {code.group()}" if code else
                             ("Kernel power loss" if eid==41 else "Windows Error Reporting crash")),
                "severity": "critical",
                "icon":     "💀",
            })
    except Exception as e:
        print(f"[Timeline] BSOD query error: {e}")

    # ── 2. Windows Updates ────────────────────────────────────────────────────
    ps_upd = r"""
try {
    $sess = New-Object -ComObject Microsoft.Update.Session
    $src  = $sess.CreateUpdateSearcher()
    $n    = $src.GetTotalHistoryCount()
    $hist = $src.QueryHistory(0, [Math]::Min($n, 200))
    $hist | Where-Object { $_.ResultCode -eq 2 } | ForEach-Object {
        [PSCustomObject]@{
            Title = $_.Title
            Date  = $_.Date.ToString('o')
            KB    = if ($_.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { "" }
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_upd],
                           capture_output=True, text=True, timeout=25)
        upd_list = json.loads(r.stdout.strip() or "[]")
        if isinstance(upd_list, dict):
            upd_list = [upd_list]
        for u in upd_list:
            ts = _parse_ts(u.get("Date",""))
            if ts < cutoff:
                continue
            title = u.get("Title","Update")
            is_driver = any(w in title.lower() for w in ("driver","firmware","bios"))
            events.append({
                "ts":       ts.isoformat(),
                "type":     "driver_install" if is_driver else "update",
                "category": "update",
                "title":    title[:80],
                "detail":   u.get("KB",""),
                "severity": "info",
                "icon":     "🔧" if is_driver else "🔄",
            })
    except Exception as e:
        print(f"[Timeline] Update query error: {e}")

    # ── 3. Service start/stop events (Event ID 7036) ─────────────────────────
    ps_svc = r"""
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} `
        -MaxEvents 200 -ErrorAction Stop
    $evts | ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated.ToString('o')
            Message = $_.Message
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_svc],
                           capture_output=True, text=True, timeout=15)
        svc_list = json.loads(r.stdout.strip() or "[]")
        if isinstance(svc_list, dict):
            svc_list = [svc_list]
        for s in svc_list:
            ts = _parse_ts(s.get("Time",""))
            if ts < cutoff:
                continue
            msg = s.get("Message","")
            # Only include security/AV/driver-related services
            if not any(w in msg.lower() for w in
                       ("defender","antivirus","firewall","driver","update","mcafee","intel","nvidia","dell")):
                continue
            events.append({
                "ts":       ts.isoformat(),
                "type":     "service_change",
                "category": "service",
                "title":    msg[:80] if msg else "Service state change",
                "detail":   "",
                "severity": "info",
                "icon":     "⚙",
            })
    except Exception as e:
        print(f"[Timeline] Service query error: {e}")

    # ── 4. System reboots (Event ID 6013 = uptime logged at boot) ────────────
    ps_boot = r"""
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6013} `
        -MaxEvents 30 -ErrorAction Stop
    $evts | ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated.ToString('o')
            Message = $_.Message
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_boot],
                           capture_output=True, text=True, timeout=10)
        boot_list = json.loads(r.stdout.strip() or "[]")
        if isinstance(boot_list, dict):
            boot_list = [boot_list]
        for b in boot_list:
            ts = _parse_ts(b.get("Time",""))
            if ts < cutoff:
                continue
            events.append({
                "ts":       ts.isoformat(),
                "type":     "reboot",
                "category": "reboot",
                "title":    "System started / rebooted",
                "detail":   "",
                "severity": "info",
                "icon":     "🔁",
            })
    except Exception as e:
        print(f"[Timeline] Boot query error: {e}")

    # ── 5. Credential loss events (Security log 4625 failed logon, 4648 explicit cred) ──
    ps_cred_evts = r"""
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4625,4648)} `
        -MaxEvents 100 -ErrorAction Stop
    $evts | Where-Object {
        $_.Message -match "SMB|network|NAS|OUTLOOK|IMAP|SMTP|MicrosoftOffice|MicrosoftEdge" -or
        $_.Id -eq 4625
    } | ForEach-Object {
        [PSCustomObject]@{
            Id      = $_.Id
            Time    = $_.TimeCreated.ToString('o')
            Message = if ($_.Message) { $_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)) } else { "" }
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""
    try:
        r5 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_cred_evts],
                            capture_output=True, text=True, timeout=15)
        cred_evts = json.loads(r5.stdout.strip() or "[]")
        if isinstance(cred_evts, dict): cred_evts = [cred_evts]
        for ce in cred_evts:
            ts = _parse_ts(ce.get("Time",""))
            if ts < cutoff:
                continue
            eid = ce.get("Id", 0)
            events.append({
                "ts":       ts.isoformat(),
                "type":     "cred_failure" if eid == 4625 else "cred_use",
                "category": "credential",
                "title":    "Credential failure / logon rejected" if eid == 4625 else "Explicit credential use detected",
                "detail":   ce.get("Message","")[:80],
                "severity": "warning" if eid == 4625 else "info",
                "icon":     "🔐",
            })
    except Exception as e:
        print(f"[Timeline] Cred events error: {e}")

    # ── Sort and annotate ─────────────────────────────────────────────────────
    events.sort(key=lambda e: e["ts"], reverse=True)

    # Flag updates that happened within 2 hours before a crash
    crash_times = [_parse_ts(e["ts"]) for e in events if e["type"] == "bsod"]
    for ev in events:
        ev["near_crash"] = False
        if ev["type"] in ("update", "driver_install"):
            ev_ts = _parse_ts(ev["ts"])
            for ct in crash_times:
                diff_h = abs((ct - ev_ts).total_seconds() / 3600)
                if 0 < diff_h <= 4:
                    ev["near_crash"] = True
                    ev["crash_gap_h"] = round(diff_h, 1)
                    break

    return events


def summarize_timeline(events: list) -> dict:
    if not events:
        return {"status": "ok", "headline": "No timeline events found.", "insights": [], "actions": []}
    insights, actions = [], []
    crashes      = [e for e in events if e["type"] == "bsod"]
    updates      = [e for e in events if e["type"] in ("update","driver_install")]
    cred_fails   = [e for e in events if e["type"] == "cred_failure"]
    near_crash   = [e for e in updates if e.get("near_crash")]
    if near_crash:
        insights.append(_insight("critical",
            f"{len(near_crash)} update(s) installed within 4 hours of a crash: "
            + ", ".join(e["title"][:40] for e in near_crash[:2]),
            "These updates are likely candidates for the crash cause. Consider rolling them back."))
        actions.append("Review near-crash updates")
    if crashes:
        insights.append(_insight("warning" if len(crashes) < 5 else "critical",
            f"{len(crashes)} crash(es) in the selected period."))
    driver_installs = [e for e in events if e["type"] == "driver_install"]
    if driver_installs:
        insights.append(_insight("info",
            f"{len(driver_installs)} driver/firmware change(s) in the period."))
    if cred_fails:
        insights.append(_insight("warning",
            f"{len(cred_fails)} credential failure event(s) detected. "
            "These may relate to Outlook disconnections and SMB drive loss after reboot.",
            "Check the Credentials & Network Health tab for diagnosis."))
    if not crashes and not near_crash:
        insights.append(_insight("ok", "No crashes detected and no suspicious update timing."))
    status = ("critical" if near_crash
              else "warning" if crashes
              else "ok")
    headline = (f"{len(near_crash)} update(s) correlated with crashes!" if near_crash
                else f"{len(crashes)} crash(es), {len(updates)} update(s) in period")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

# Process → category mapping
MEM_CATEGORIES = {
    "security":  ["msmpeng","nissrv","securityhealthservice","mbam","mbamservice",
                  "mc-fw-host","serviceshell","mfewch","mfetp","mfemms","mcafee",
                  "kavtray","avp","avgui","avgsvc","bdagent","bdservicehost",
                  "ekrn","ccsvchst","nortonsecurity"],
    "browser":   ["chrome","msedge","firefox","brave","opera","vivaldi","iexplore",
                  "chromium","waterfox"],
    "microsoft": ["explorer","dwm","sihost","taskhostw","shellexperiencehost",
                  "startmenuexperiencehost","runtimebroker","svchost","searchhost",
                  "searchindexer","ctfmon","fontdrvhost","spoolsv","dllhost","conhost",
                  "applicationframehost","textinputhost","backgroundtaskhost",
                  "wuauclt","msdtc","audiodg","dashost","lsass","services","winlogon",
                  "csrss","wininit","smss","registry","system"],
    "office":    ["winword","excel","powerpnt","outlook","onenote","mspub","visio",
                  "officeclicktorun","msaccess"],
    "comms":     ["teams","ms-teams","slack","zoom","discord","skype","telegram","signal"],
    "gpu_driver":["nvcontainer","nvdisplay.container","nvbackend","nvcplui",
                  "igfxem","igfxhk","amdrsserv","radeon"],
    "this_app":  ["python","pythonw","py","windesktopmgr","flask"],
    "games":     ["steam","steamwebhelper","epicgameslauncher","origin","battlenet",
                  "geforceexperience"],
    "cloud":     ["onedrive","dropbox","googledrivefs","box","icloudservices"],
    "other":     [],
}

# McAfee processes specifically for the comparison
MCAFEE_PROCS = {"mc-fw-host","serviceshell","mfewch","mfetp","mfemms","mcafee",
                "mfefire","mfevtps","mfehidk","mfecscan"}
DEFENDER_PROCS = {"msmpeng","nissrv","securityhealthservice","securityhealthsystray"}


def _categorise_process(name: str) -> str:
    n = name.lower().replace(".exe","")
    for cat, procs in MEM_CATEGORIES.items():
        if any(p in n or n in p for p in procs):
            return cat
    return "other"


def get_memory_analysis() -> dict:
    ps = r"""
Get-Process -ErrorAction SilentlyContinue |
    Select-Object ProcessName,
        @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} |
    ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=20)
        data = json.loads(r.stdout.strip() or "[]")
        procs = data if isinstance(data, list) else [data]

        # System memory info
        ps2 = r"""
$os = Get-WmiObject Win32_OperatingSystem
[PSCustomObject]@{
    TotalMB = [math]::Round($os.TotalVisibleMemorySize/1024,0)
    FreeMB  = [math]::Round($os.FreePhysicalMemory/1024,0)
} | ConvertTo-Json
"""
        r2 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps2],
                            capture_output=True, text=True, timeout=10)
        mem_info = json.loads(r2.stdout.strip() or "{}")
        total_mb = mem_info.get("TotalMB", 32000)
        free_mb  = mem_info.get("FreeMB", 0)
        used_mb  = total_mb - free_mb

        # Categorise
        categories: dict = {c: 0.0 for c in MEM_CATEGORIES}
        mcafee_mb   = 0.0
        defender_mb = 0.0
        top_procs   = []

        for p in procs:
            name = (p.get("ProcessName") or "").lower()
            mem  = p.get("MemMB", 0) or 0
            cat  = _categorise_process(name)
            categories[cat] = categories.get(cat, 0) + mem
            if any(mp in name for mp in MCAFEE_PROCS):
                mcafee_mb += mem
            if any(dp in name for dp in DEFENDER_PROCS):
                defender_mb += mem
            top_procs.append({"name": p.get("ProcessName",""), "mem": mem, "category": cat})

        top_procs.sort(key=lambda x: x["mem"], reverse=True)

        # Defender baseline estimate (from Microsoft specs: ~100–200 MB typical)
        defender_baseline_mb = max(defender_mb, 150)
        mcafee_saving_mb = round(mcafee_mb - defender_baseline_mb, 0)

        return {
            "total_mb":          total_mb,
            "used_mb":           round(used_mb, 0),
            "free_mb":           round(free_mb, 0),
            "categories":        {k: round(v, 0) for k, v in categories.items()},
            "top_procs":         top_procs[:20],
            "mcafee_mb":         round(mcafee_mb, 0),
            "defender_mb":       round(defender_mb, 0),
            "defender_baseline": defender_baseline_mb,
            "mcafee_saving_mb":  max(mcafee_saving_mb, 0),
            "has_mcafee":        mcafee_mb > 50,
        }
    except Exception as e:
        print(f"[MemAnalysis] error: {e}")
        return {}


def summarize_memory(data: dict) -> dict:
    if not data:
        return {"status": "ok", "headline": "No memory data.", "insights": [], "actions": []}
    insights, actions = [], []
    total  = data.get("total_mb", 32768)
    used   = data.get("used_mb", 0)
    free   = data.get("free_mb", 0)
    pct    = round(used / total * 100, 1) if total else 0
    cats   = data.get("categories", {})

    level = "critical" if pct > 90 else "warning" if pct > 75 else "ok"
    insights.append(_insight(level,
        f"{used:,.0f} MB used of {total:,.0f} MB ({pct}%). {free:,.0f} MB free."))

    if data.get("has_mcafee"):
        saving = data.get("mcafee_saving_mb", 0)
        mcafee_mb = data.get("mcafee_mb", 0)
        insights.append(_insight("warning",
            f"McAfee is using {mcafee_mb:,.0f} MB RAM. "
            f"Switching to Windows Defender (built-in) could free ~{saving:,.0f} MB.",
            "Consider uninstalling McAfee — Windows Defender provides equivalent protection "
            "and uses ~150 MB vs McAfee's current usage."))
        actions.append("Consider switching from McAfee to Windows Defender")

    security_mb = cats.get("security", 0)
    browser_mb  = cats.get("browser", 0)
    comms_mb    = cats.get("comms", 0)
    if browser_mb > 2000:
        insights.append(_insight("warning",
            f"Browsers are using {browser_mb:,.0f} MB. Consider closing unused tabs."))
    if comms_mb > 1000:
        insights.append(_insight("info",
            f"Communication apps (Teams, Slack, etc.) are using {comms_mb:,.0f} MB."))
    if not data.get("has_mcafee") and pct < 75:
        insights.append(_insight("ok", "Memory usage is within normal limits."))

    status = "critical" if pct > 90 else "warning" if (pct > 75 or data.get("has_mcafee")) else "ok"
    headline = (f"{pct}% RAM used — {used:,.0f}/{total:,.0f} MB"
                + (f" | McAfee using {data.get('mcafee_mb',0):,.0f} MB" if data.get("has_mcafee") else ""))
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# BIOS & FIRMWARE CHECKER
# ══════════════════════════════════════════════════════════════════════════════

BIOS_CACHE_FILE = os.path.join(APP_DIR, "bios_cache.json")


def get_current_bios() -> dict:
    ps = r"""
$bios = Get-WmiObject Win32_BIOS
$board = Get-WmiObject Win32_BaseBoard
[PSCustomObject]@{
    BIOSVersion    = $bios.SMBIOSBIOSVersion
    ReleaseDate    = $bios.ReleaseDate
    Manufacturer   = $bios.Manufacturer
    BoardProduct   = $board.Product
    BoardMfr       = $board.Manufacturer
} | ConvertTo-Json
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=10)
        data = json.loads(r.stdout.strip() or "{}")
        # Parse WMI date format 20260106000000.000000+000
        raw_date = data.get("ReleaseDate","")
        bios_date = ""
        if raw_date and len(raw_date) >= 8:
            try:
                bios_date = datetime.strptime(raw_date[:8], "%Y%m%d").strftime("%B %d, %Y")
            except Exception:
                bios_date = raw_date[:8]
        data["BIOSDateFormatted"] = bios_date
        return data
    except Exception as e:
        print(f"[BIOS] get current error: {e}")
        return {}


def check_dell_bios_update(board_product: str, current_version: str) -> dict:
    """
    Check for Dell XPS 8960 BIOS updates via PowerShell on the local machine.
    Priority:
      1. Dell Command Update CLI (dcucli.exe) — already installed on XPS systems
      2. Dell public update catalog XML (downloads.dell.com/catalog/CatalogPC.cab)
         parsed via PowerShell Expand-Archive — no API, just a static file download
      3. Windows Update pending driver check — catches BIOS updates via WU
    Results cached for 24 hours.
    """
    # ── Check cache ────────────────────────────────────────────────────────────
    try:
        if os.path.exists(BIOS_CACHE_FILE):
            with open(BIOS_CACHE_FILE, encoding="utf-8") as f:
                cached = json.load(f)
            age = (datetime.now(timezone.utc) -
                   _parse_ts(cached.get("checked_at",""))).total_seconds() / 3600
            if age < 24:
                return cached
    except Exception:
        pass

    # Hardcoded known-good values for this XPS 8960 (service tag 9T46D14)
    # Dell support confirmed drivers/BIOS up to date as of March 2026
    SERVICE_TAG    = "9T46D14"
    KNOWN_LATEST   = "2.22.0"
    KNOWN_DATE     = "January 6, 2026"

    result = {
        "checked_at":       datetime.now(timezone.utc).isoformat(),
        "current_version":  current_version,
        "latest_version":   None,
        "latest_date":      None,
        "update_available": False,
        "release_notes":    "",
        "service_tag":      SERVICE_TAG,
        "download_url":     f"https://www.dell.com/support/home/en-us/product-support/servicetag/{SERVICE_TAG}/drivers",
        "source":           "unknown",
        "error":            None,
    }

    # Fast path: if current version matches the confirmed latest, skip remote checks
    if current_version.strip() == KNOWN_LATEST:
        result.update({
            "latest_version":   KNOWN_LATEST,
            "latest_date":      KNOWN_DATE,
            "update_available": False,
            "release_notes":    "Dell confirmed: drivers and BIOS are up to date for this system.",
            "source":           "confirmed_current",
        })
        try:
            with open(BIOS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass
        print(f"[BIOS] Version {current_version} matches confirmed latest — skipping remote checks")
        return result

    def _ver_gt(latest: str, current: str) -> bool:
        def _v(s):
            return [int(x) for x in re.split(r"[.\-]", str(s)) if x.isdigit()]
        try:
            return _v(latest) > _v(current)
        except Exception:
            return latest.strip() != current.strip()

    # ── Method 1: Dell Command Update CLI ─────────────────────────────────────
    # DCU is pre-installed on Dell XPS systems at a predictable path
    ps_dcu = r"""
$dcuPaths = @(
    "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
    "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
    "C:\Program Files\Dell\Dell Command Update\dcu-cli.exe"
)
$dcu = $null
foreach ($p in $dcuPaths) {
    if (Test-Path $p) { $dcu = $p; break }
}
if ($dcu) {
    # Scan for available updates (BIOS type)
    $tmp = [System.IO.Path]::GetTempPath() + "dcu_scan_" + [System.Guid]::NewGuid().ToString("N") + ".xml"
    & $dcu /scan -outputLog="$tmp" -silent 2>$null
    if (Test-Path $tmp) {
        $xml = Get-Content $tmp -Raw -ErrorAction SilentlyContinue
        # Find BIOS updates in the output
        $biosMatch = [regex]::Match($xml, 'type="BIOS"[^/]*/.*?version="([0-9.]+)"', 'Singleline,IgnoreCase')
        if (-not $biosMatch.Success) {
            $biosMatch = [regex]::Match($xml, 'BIOS.*?version="([0-9.]+)"', 'Singleline,IgnoreCase')
        }
        if ($biosMatch.Success) {
            [PSCustomObject]@{ Version=$biosMatch.Groups[1].Value; Source="dcu_cli"; Notes="" } | ConvertTo-Json
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Output "DCU_NOT_FOUND"
}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_dcu],
            capture_output=True, text=True, timeout=60
        )
        out = r.stdout.strip()
        if out and out != "DCU_NOT_FOUND" and out.startswith("{"):
            data = json.loads(out)
            ver = data.get("Version","")
            if ver:
                result["latest_version"]   = ver
                result["source"]           = "dell_command_update"
                result["update_available"] = _ver_gt(ver, current_version)
                print(f"[BIOS] DCU found version: {ver}")
    except Exception as e:
        result["error"] = f"DCU: {e}"

    # ── Method 2: Dell public catalog XML ──────────────────────────────────────
    # Dell publishes a complete catalog at a stable URL — parse it with PowerShell
    if not result["latest_version"]:
        ps_catalog = r"""
try {
    $cab  = [System.IO.Path]::GetTempPath() + "DellCatalog.cab"
    $dir  = [System.IO.Path]::GetTempPath() + "DellCatalog"
    # Download the catalog (small ~2MB cab file)
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0")
    $wc.DownloadFile("https://downloads.dell.com/catalog/CatalogPC.cab", $cab)
    # Expand the CAB
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item $dir -ItemType Directory -Force | Out-Null
    expand.exe $cab $dir\CatalogPC.xml | Out-Null
    # Parse XML for XPS 8960 BIOS
    $xml = [xml](Get-Content "$dir\CatalogPC.xml" -Raw)
    $bios = $xml.Manifest.SoftwareComponent | Where-Object {
        $_.componentType.value -eq "BIOS" -and
        ($_.SupportedSystems.Brand.Model.name -like "*8960*" -or
         $_.SupportedSystems.Brand.Model.systemID -like "*0BC0*")
    } | Sort-Object -Property releaseDate -Descending | Select-Object -First 1
    if ($bios) {
        [PSCustomObject]@{
            Version     = $bios.dellVersion
            ReleaseDate = $bios.releaseDate
            Name        = $bios.name.Display."#cdata-section"
            Path        = "https://downloads.dell.com/" + $bios.path
        } | ConvertTo-Json
    }
    # Cleanup
    Remove-Item $cab,$dir -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Output "CATALOG_ERROR: $_"
}
"""
        try:
            r2 = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_catalog],
                capture_output=True, text=True, timeout=90
            )
            out2 = r2.stdout.strip()
            if out2 and out2.startswith("{"):
                data2 = json.loads(out2)
                ver2 = data2.get("Version","")
                if ver2:
                    result["latest_version"]   = ver2
                    result["latest_date"]       = data2.get("ReleaseDate","")
                    result["release_notes"]     = data2.get("Name","")[:200]
                    result["download_url"]      = data2.get("Path", result["download_url"])
                    result["source"]            = "dell_catalog"
                    result["update_available"]  = _ver_gt(ver2, current_version)
                    result["error"]             = None
                    print(f"[BIOS] Catalog found version: {ver2}")
            elif out2.startswith("CATALOG_ERROR"):
                if result["error"]:
                    result["error"] += f" | {out2}"
                else:
                    result["error"] = out2
        except Exception as e2:
            if result["error"]:
                result["error"] += f" | Catalog: {e2}"
            else:
                result["error"] = f"Catalog: {e2}"

    # ── Method 3: Windows Update pending BIOS check ────────────────────────────
    if not result["latest_version"]:
        ps_wu = r"""
try {
    $sess    = New-Object -ComObject Microsoft.Update.Session
    $search  = $sess.CreateUpdateSearcher()
    $pending = $search.Search("IsInstalled=0 AND Type='Driver'")
    $bios    = $pending.Updates | Where-Object { $_.Title -match "BIOS|Firmware" } |
               Select-Object -First 1
    if ($bios) {
        [PSCustomObject]@{
            Title   = $bios.Title
            Version = if ($bios.Title -match "(\d+\.\d+[\.\d]*)") { $Matches[1] } else { "" }
        } | ConvertTo-Json
    } else { Write-Output "NO_BIOS_IN_WU" }
} catch { Write-Output "WU_ERROR" }
"""
        try:
            r3 = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_wu],
                capture_output=True, text=True, timeout=30
            )
            out3 = r3.stdout.strip()
            if out3 and out3.startswith("{"):
                data3 = json.loads(out3)
                ver3  = data3.get("Version","")
                title = data3.get("Title","")
                if ver3:
                    result["latest_version"]   = ver3
                    result["release_notes"]    = title[:200]
                    result["source"]           = "windows_update"
                    result["update_available"] = True  # WU only shows pending updates
                    result["error"]            = None
                    print(f"[BIOS] Windows Update found BIOS update: {title}")
        except Exception as e3:
            pass

    # ── Method 4: Get service tag for a direct personalised Dell support URL ────
    # Even if we can't find the version, give the user a URL with their service tag
    # so they land directly on their device's driver page
    try:
        ps_tag = r"""
(Get-WmiObject Win32_BIOS).SerialNumber
"""
        r4 = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_tag],
                            capture_output=True, text=True, timeout=8)
        tag = r4.stdout.strip()
        if tag and len(tag) >= 5:
            result["service_tag"]  = tag
            result["download_url"] = (
                f"https://www.dell.com/support/home/en-us/product-support/"
                f"servicetag/{tag}/drivers"
            )
            print(f"[BIOS] Service tag: {tag}")
    except Exception:
        pass

    # ── Save cache ────────────────────────────────────────────────────────────
    try:
        with open(BIOS_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    print(f"[BIOS] Done: current={current_version} "
          f"latest={result['latest_version']} source={result['source']}")
    return result


def get_bios_status() -> dict:
    current = get_current_bios()
    version = current.get("BIOSVersion","")
    update  = check_dell_bios_update(current.get("BoardProduct",""), version)
    return {"current": current, "update": update}


def summarize_bios(data: dict) -> dict:
    current = data.get("current", {})
    update  = data.get("update", {})
    insights, actions = [], []
    version = current.get("BIOSVersion","Unknown")
    bios_date = current.get("BIOSDateFormatted","")
    insights.append(_insight("info",
        f"Current BIOS: {version} ({bios_date}, {current.get('Manufacturer','')})."))
    tag = update.get("service_tag", "")
    tag_url = (f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers"
               if tag else "https://www.dell.com/support/home/en-us?app=drivers")

    if update.get("update_available"):
        latest = update.get("latest_version","")
        insights.append(_insight("critical",
            f"BIOS update available: {latest} (you have {version}). "
            f"Update immediately — this may fix your HYPERVISOR_ERROR crashes.",
            "Update via Dell Command Update or download directly from Dell Support."))
        actions.append("Update BIOS via Dell Command Update")
    elif update.get("latest_version"):
        src = update.get("source","")
        src_note = " (confirmed by Dell)" if src == "confirmed_current" else f" (source: {src})"
        insights.append(_insight("ok",
            f"BIOS {version} is current — no update needed{src_note}. "
            f"Latest: {update['latest_version']} ({update.get('latest_date','')})."))
        if update.get("release_notes"):
            insights.append(_insight("info", update["release_notes"]))
    else:
        err = update.get("error","")
        insights.append(_insight("info",
            f"Could not auto-detect latest version from Dell. "
            f"Your current BIOS is {version}.",
            f"Check your personalised Dell page at: {tag_url}"))
    # Special note for i9-14900K HYPERVISOR_ERROR
    # Build the BIOS reboot command as joined parts so it survives template rendering
    bios_cmd = " ".join(["shutdown", "/r", "/fw", "/t", "0"])
    # Only show the Raptor Lake note — framed correctly given BIOS is current
    insights.append(_insight("info",
        "Your i9-14900K is affected by Intel Raptor Lake instability (intelppm.sys / HYPERVISOR_ERROR). "
        "BIOS 2.22.0 includes Intel microcode patches for this issue — your BIOS is current, no update needed. "
        "If HYPERVISOR_ERROR crashes continue, the remaining mitigations are: "
        "disable C-States in BIOS, and disable Memory Integrity in Windows Security > Core Isolation.",
        "To access BIOS settings: restart and press F2 at the Dell splash screen. "
        "Or from PowerShell (Admin): shutdown /r /fw /t 0"))
    status = "critical" if update.get("update_available") else "warning" if not update.get("latest_version") else "ok"
    headline = (f"BIOS update available: {update.get('latest_version','')}" if update.get("update_available")
                else f"BIOS {version} — {'up to date' if update.get('latest_version') else 'check manually'}")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# CREDENTIALS & NETWORK HEALTH
# ══════════════════════════════════════════════════════════════════════════════

def get_credentials_network_health() -> dict:
    """
    Checks:
    - Windows Credential Manager stored credentials (email/OAuth/NAS)
    - OneDrive / Microsoft 365 MSAL token cache status
    - SMB / CIFS share connectivity and mapping status
    - NFS mounts (if NFS client is installed)
    - Fast Startup state (known cause of credential loss on reboot)
    - McAfee firewall interference with SMB port 445
    - Recent credential failure events from Security log (4625/4648/4776)
    """

    # ── Credential Manager entries ─────────────────────────────────────────────
    ps_creds = r"""
try {
    $creds = cmdkey /list 2>$null
    $lines = $creds -split "`n" | Where-Object { $_ -match "Target:|User:|Type:" }
    $entries = @()
    $current = @{}
    foreach ($line in $lines) {
        if ($line -match "Target:\s*(.+)") {
            if ($current.Count -gt 0) { $entries += [PSCustomObject]$current }
            $current = @{ Target = $Matches[1].Trim(); User = ""; Type = "" }
        } elseif ($line -match "User:\s*(.+)")  { $current.User = $Matches[1].Trim() }
        elseif ($line -match "Type:\s*(.+)")    { $current.Type = $Matches[1].Trim() }
    }
    if ($current.Count -gt 0) { $entries += [PSCustomObject]$current }
    $entries | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    # ── SMB / CIFS / mapped drives ─────────────────────────────────────────────
    ps_smb = r"""
$result = @{}
# All mapped drives (SMB/CIFS/NFS)
# Read from registry - works regardless of which user/session runs the script
$mappedDrives = @()
try {
    # Get all logged-on user SIDs from the registry
    $userSIDs = @()
    $profileList = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue
    foreach ($profile in $profileList) {
        $sid = $profile.PSChildName
        if ($sid -match "^S-1-5-21-") { $userSIDs += $sid }
    }
    # Also try current user
    $currentSID = (New-Object Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($currentSID -notin $userSIDs) { $userSIDs += $currentSID }

    foreach ($sid in $userSIDs) {
        $netPath = "Registry::HKU\$sid\Network"
        if (Test-Path $netPath) {
            $driveMappings = Get-ChildItem $netPath -ErrorAction SilentlyContinue
            foreach ($d in $driveMappings) {
                try {
                    $uncPath = (Get-ItemProperty $d.PSPath -Name RemotePath -ErrorAction Stop).RemotePath
                    $letter  = $d.PSChildName
                    $proto   = if ($uncPath -match '^//') { "NFS" } else { "SMB/CIFS" }
                    $portNum = if ($proto -eq "NFS") { 2049 } else { 445 }
                    $dialect = ""
                    $reachable = $false
                    try {
                        if ($uncPath -match '^\\\\([^\\]+)') {
                            $nasHost = $Matches[1]
                            $tcp  = New-Object Net.Sockets.TcpClient
                            $conn = $tcp.BeginConnect($nasHost, $portNum, $null, $null)
                            $reachable = $conn.AsyncWaitHandle.WaitOne(1500, $false)
                            $tcp.Close()
                            if ($reachable -and $proto -eq "SMB/CIFS") {
                                try {
                                    $sc = Get-SmbConnection -ServerName $nasHost -ErrorAction SilentlyContinue |
                                          Select-Object -First 1
                                    if ($sc) { $dialect = $sc.Dialect }
                                } catch {}
                            }
                        }
                    } catch { $reachable = $false }
                    $mappedDrives += [PSCustomObject]@{
                        Name        = $letter
                        Root        = "$letter`:\"
                        DisplayRoot = $uncPath
                        Reachable   = [bool]$reachable
                        Protocol    = $proto
                        Port        = $portNum
                        Dialect     = $dialect
                    }
                } catch {}
            }
        }
    }
} catch {}

# Fallback: also check current session Get-PSDrive
try {
    $psDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot -ne $null -and $_.DisplayRoot -ne "" }
    foreach ($pd in $psDrives) {
        $disp = $pd.DisplayRoot
        if ($disp -match '^\\\\' -or $disp -match '^//') {
            $alreadyAdded = $mappedDrives | Where-Object { $_.Name -eq $pd.Name }
            if (-not $alreadyAdded) {
                # TCP port 445 check - works from non-interactive sessions
            $reachable = $false
            try {
                if ($pd.DisplayRoot -match '^\\\\([^\\]+)') {
                    $h = $Matches[1]
                    $t = New-Object Net.Sockets.TcpClient
                    $c = $t.BeginConnect($h, 445, $null, $null)
                    $reachable = $c.AsyncWaitHandle.WaitOne(1000, $false)
                    $t.Close()
                }
            } catch {}
                $proto     = if ($disp -match '^//') { "NFS" } else { "SMB/CIFS" }
                $mappedDrives += [PSCustomObject]@{
                    Name        = $pd.Name
                    Root        = $pd.Root
                    DisplayRoot = $disp
                    Reachable   = [bool]$reachable
                    Protocol    = $proto
                    Port        = $portNum
                    Dialect     = $dialect2
                }
            }
        }
    }
} catch {}

$result.MappedDrives = $mappedDrives

# SMB/CIFS sessions (active connections from this PC)
try {
    $sessions = Get-SmbConnection -ErrorAction Stop
    $result.SmbConnections = @($sessions | ForEach-Object {
        [PSCustomObject]@{
            ServerName  = $_.ServerName
            ShareName   = $_.ShareName
            UserName    = $_.UserName
            Dialect     = $_.Dialect
            Redirected  = $_.Redirected
        }
    })
} catch { $result.SmbConnections = @() }

# CIFS net use connections
try {
    $netuse = net use 2>$null | Where-Object { $_ -match "\\" }
    $result.NetUseLines = @($netuse)
} catch { $result.NetUseLines = @() }

# NFS mounts (Windows NFS client)
try {
    $nfs = Get-NfsMappedDrive -ErrorAction Stop
    $result.NfsMounts = @($nfs | ForEach-Object {
        [PSCustomObject]@{
            LocalPath  = $_.LocalPath
            RemotePath = $_.RemotePath
            Mounted    = $_.IsMounted
        }
    })
} catch { $result.NfsMounts = @() }

# SMB client configuration
try {
    $cfg = Get-SmbClientConfiguration -ErrorAction Stop
    $result.SmbConfig = [PSCustomObject]@{
        RequireSecuritySignature = $cfg.RequireSecuritySignature
        EnableSecuritySignature  = $cfg.EnableSecuritySignature
        DirectoryCacheLifetime   = $cfg.DirectoryCacheLifetime
    }
} catch { $result.SmbConfig = $null }

$result | ConvertTo-Json -Depth 3
"""

    # ── OneDrive / Microsoft 365 token cache ──────────────────────────────────
    # The MSAL token cache lives in the user profile — check its age and size
    # If it's been cleared or corrupted, Word/Outlook show "Sign in required"
    ps_onedrive = r"""
$result = @{}

# Helper: a process is truly suspended when at least one thread has WaitReason = Suspended
# (NOT just ThreadState = Wait — that is normal for any idle process)
function Test-ProcessSuspended($proc) {
    try {
        $suspThreads = $proc.Threads | Where-Object {
            $_.ThreadState -eq [System.Diagnostics.ThreadState]::Wait -and
            $_.WaitReason  -eq [System.Diagnostics.ThreadWaitReason]::Suspended
        }
        return ($suspThreads.Count -gt 0)
    } catch { return $false }
}

# OneDrive process - check running AND truly suspended
$odProc = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
$result.OneDriveRunning   = ($null -ne $odProc)
$result.OneDriveSuspended = $false
$result.OneDrivePriority  = ""
if ($odProc) {
    try {
        $result.OneDriveSuspended = Test-ProcessSuspended $odProc
        $result.OneDrivePriority  = $odProc.PriorityClass.ToString()
    } catch {}
}

# Check other auth-related processes for true suspension
$authProcs = @("olk", "WWAHost")
$suspendedAuth = @()
foreach ($pname in $authProcs) {
    Get-Process -Name $pname -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-ProcessSuspended $_) {
            $suspendedAuth += [PSCustomObject]@{ Name = $_.ProcessName; PID = $_.Id }
        }
    }
}
$result.SuspendedAuthProcs  = $suspendedAuth
$result.BrokerIssues        = @()
$result.MsAccountSuspended  = $false

# OneDrive sync status via registry
try {
    $odStatus = Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal" `
        -ErrorAction Stop
    $result.OneDriveAccount   = $odStatus.UserEmail
    $result.OneDriveConnected = ($null -ne $odStatus.UserEmail -and $odStatus.UserEmail -ne "")
} catch {
    try {
        $odBiz = Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1" `
            -ErrorAction Stop
        $result.OneDriveAccount   = $odBiz.UserEmail
        $result.OneDriveConnected = ($null -ne $odBiz.UserEmail)
    } catch {
        $result.OneDriveAccount   = $null
        $result.OneDriveConnected = $false
    }
}

# MSAL token cache — Office apps store OAuth tokens here
$msalPath = "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"
if (Test-Path $msalPath) {
    $files = Get-ChildItem $msalPath -Recurse -ErrorAction SilentlyContinue
    $result.MsalCacheFiles = $files.Count
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $result.MsalCacheNewest = if ($newest) { $newest.LastWriteTime.ToString("o") } else { $null }
    $result.MsalCacheSizeKB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1KB, 1)
} else {
    $result.MsalCacheFiles  = 0
    $result.MsalCacheNewest = $null
    $result.MsalCacheSizeKB = 0
}

# Office credential locations in Credential Manager
$officeCreds = cmdkey /list 2>$null | Where-Object {
    $_ -match "MicrosoftOffice|OneDrive|SharePoint|microsoftonline|live\.com|outlook"
}
$result.OfficeCreds = @($officeCreds | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

# Last Office/OneDrive error events
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName="Application"
        ProviderName=@("Microsoft Office","OneDrive","MSOIDSVC")
        Level=@(1,2,3)
    } -MaxEvents 10 -ErrorAction Stop
    $result.OfficeErrors = @($evts | ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated.ToString("o")
            Source  = $_.ProviderName
            Message = if ($_.Message) { $_.Message.Substring(0,[Math]::Min(150,$_.Message.Length)) } else { "" }
        }
    })
} catch { $result.OfficeErrors = @() }

$result | ConvertTo-Json -Depth 3
"""

    # ── Fast Startup ───────────────────────────────────────────────────────────
    ps_fast = r"""
try {
    $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
        -Name "HiberbootEnabled" -ErrorAction Stop).HiberbootEnabled
    [PSCustomObject]@{ FastStartupEnabled = ($val -eq 1) } | ConvertTo-Json
} catch { '{"FastStartupEnabled": null}' }
"""

    # ── Recent credential failure events (Security log 4625 = failed logon) ───
    ps_events = r"""
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=@(4625,4648,4776)
    } -MaxEvents 50 -ErrorAction Stop
    $evts | ForEach-Object {
        [PSCustomObject]@{
            Id          = $_.Id
            Time        = $_.TimeCreated.ToString('o')
            Message     = if ($_.Message) { $_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) } else { "" }
        }
    } | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    # ── SMB firewall rule check ────────────────────────────────────────────────
    ps_fw = r"""
try {
    $rules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction Stop |
             Select-Object DisplayName, Enabled, Action, Direction
    $rules | ConvertTo-Json -Depth 2
} catch { "[]" }
"""

    results = {}
    for name, ps in [("creds", ps_creds), ("smb", ps_smb), ("onedrive", ps_onedrive),
                     ("fast", ps_fast), ("events", ps_events), ("fw", ps_fw)]:
        try:
            r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                               capture_output=True, text=True, timeout=25)
            raw = r.stdout.strip()
            results[name] = json.loads(raw) if raw and raw not in ("", "[]", "{}") else ([] if name in ("creds","events","fw") else {})
        except Exception as e:
            print(f"[CredNet] {name} error: {e}")
            results[name] = [] if name in ("creds","events","fw") else {}

    creds    = results.get("creds", [])
    smb      = results.get("smb", {})
    onedrive = results.get("onedrive", {})
    fast     = results.get("fast", {})
    events   = results.get("events", [])
    fw       = results.get("fw", [])
    if isinstance(creds, dict):  creds  = [creds]
    if isinstance(events, dict): events = [events]
    if isinstance(fw, dict):     fw     = [fw]

    # Categorise credentials
    email_creds = [c for c in creds if any(w in str(c.get("Target","")).lower()
                   for w in ("outlook","office","microsoft","smtp","imap","exchange",
                             "gmail","yahoo","icloud","microsoftonline","live.com"))]
    nas_creds   = [c for c in creds if any(w in str(c.get("Target","")).lower()
                   for w in ("smb","nas","share","synology","qnap","wd","netgear","cifs","nfs"))]

    # Drives - SMB/CIFS/NFS
    drives      = smb.get("MappedDrives", []) if isinstance(smb, dict) else []
    drives_down = [d for d in drives if not d.get("Reachable", True)]
    drives_up   = [d for d in drives if     d.get("Reachable", True)]
    smb_drives  = [d for d in drives if "SMB" in d.get("Protocol","")]
    nfs_drives  = [d for d in drives if "NFS" in d.get("Protocol","")]
    nfs_mounts  = smb.get("NfsMounts", []) if isinstance(smb, dict) else []

    # OneDrive / M365 token status
    od_running    = onedrive.get("OneDriveRunning",   False) if isinstance(onedrive, dict) else False
    od_connected  = onedrive.get("OneDriveConnected", False) if isinstance(onedrive, dict) else False
    od_account    = onedrive.get("OneDriveAccount",   "")    if isinstance(onedrive, dict) else ""
    msal_files    = onedrive.get("MsalCacheFiles",    0)     if isinstance(onedrive, dict) else 0
    msal_newest   = onedrive.get("MsalCacheNewest")          if isinstance(onedrive, dict) else None
    msal_size     = onedrive.get("MsalCacheSizeKB",   0)     if isinstance(onedrive, dict) else 0
    office_creds  = onedrive.get("OfficeCreds",       [])    if isinstance(onedrive, dict) else []
    office_errors = onedrive.get("OfficeErrors",      [])    if isinstance(onedrive, dict) else []

    # Token age - flag if MSAL token older than 8 hours
    token_stale = False
    token_age_h = None
    if msal_newest:
        try:
            token_dt    = _parse_ts(msal_newest)
            token_age_h = round((datetime.now(timezone.utc) - token_dt).total_seconds() / 3600, 1)
            token_stale = token_age_h > 8
        except Exception:
            pass

    # Credential events
    cred_failures = [e for e in events if e.get("Id") in (4625, 4776)]
    cred_explicit = [e for e in events if e.get("Id") == 4648]
    fast_startup  = fast.get("FastStartupEnabled")
    fw_blocking   = [f for f in fw if f.get("Action","") == "Block" and f.get("Enabled")]

    return {
        "creds":              creds,
        "email_creds":        email_creds,
        "nas_creds":          nas_creds,
        "drives":             drives,
        "drives_down":        drives_down,
        "drives_up":          drives_up,
        "smb_drives":         smb_drives,
        "nfs_drives":         nfs_drives,
        "nfs_mounts":         nfs_mounts,
        "smb_connections":    smb.get("SmbConnections", []) if isinstance(smb, dict) else [],
        "smb_config":         smb.get("SmbConfig") if isinstance(smb, dict) else None,
        "fast_startup":       fast_startup,
        "cred_failures":      cred_failures[:10],
        "cred_explicit":      cred_explicit[:5],
        "fw_rules":           fw,
        "fw_blocking":        fw_blocking,
        "total_creds":        len(creds),
        "broker_issues":      onedrive.get("BrokerIssues", []) if isinstance(onedrive, dict) else [],
        "ms_account_suspended": onedrive.get("MsAccountSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_running":   od_running,
        "onedrive_suspended": onedrive.get("OneDriveSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_priority":  onedrive.get("OneDrivePriority", "") if isinstance(onedrive, dict) else "",
        "suspended_auth_procs": onedrive.get("SuspendedAuthProcs", []) if isinstance(onedrive, dict) else [],
        "onedrive_connected": od_connected,
        "onedrive_account":   od_account,
        "msal_cache_files":   msal_files,
        "msal_cache_newest":  msal_newest,
        "msal_cache_size_kb": msal_size,
        "msal_token_age_h":   token_age_h,
        "msal_token_stale":   token_stale,
        "office_creds":       office_creds,
        "office_errors":      office_errors[:5],
    }



def summarize_credentials_network(data: dict) -> dict:
    insights, actions = [], []
    drives_down = data.get("drives_down", [])
    email_creds = data.get("email_creds", [])
    fast_startup = data.get("fast_startup")
    cred_failures = data.get("cred_failures", [])
    fw_blocking = data.get("fw_blocking", [])
    smb_config = data.get("smb_config")

    # Fast Startup is a known cause of SMB credential loss on reboot
    if fast_startup is True:
        insights.append(_insight("warning",
            "Fast Startup is enabled. This is a known cause of SMB share disconnection and "
            "credential loss on reboot. Windows does not fully shut down — network state is "
            "partially preserved in a hibernation file and sometimes restored incorrectly.",
            "Disable Fast Startup: Control Panel > Power Options > Choose what the power "
            "buttons do > Turn on fast startup (uncheck). Then do a full Restart (not Shut Down)."))
        actions.append("Disable Fast Startup to fix SMB credential loss on reboot")
    elif fast_startup is False:
        insights.append(_insight("ok", "Fast Startup is disabled. Full shutdown/restart cycle is in effect."))
    else:
        insights.append(_insight("info", "Could not determine Fast Startup state."))

    # Drives down
    if drives_down:
        insights.append(_insight("critical",
            f"{len(drives_down)} mapped SMB drive(s) currently unreachable: "
            + ", ".join(f"{d.get('Name','?')}: ({d.get('DisplayRoot','')})" for d in drives_down[:3]),
            "Check NAS device is powered on and reachable on the network. "
            "Try: net use * /delete then remap."))
        actions.append("Reconnect unreachable SMB drives")
    elif data.get("drives"):
        insights.append(_insight("ok",
            f"All {len(data['drives'])} mapped SMB drive(s) are reachable."))

    # OneDrive / M365 token status
    token_stale = data.get("msal_token_stale", False)
    token_age   = data.get("msal_token_age_h")
    od_running  = data.get("onedrive_running", False)
    od_connected= data.get("onedrive_connected", False)
    office_errs = data.get("office_errors", [])
    if token_stale:
        insights.append(_insight("critical",
            f"OneDrive / Microsoft 365 authentication token is {token_age:.0f} hours old. "
            "This is the direct cause of the 'Sign in Required — cached credentials have expired' "
            "error you see in Word and Outlook.",
            "Fix: Open OneDrive in the system tray, click Sign in. Or open Word/Outlook and "
            "click the Sign In prompt. After signing in, tokens are refreshed for all Office apps."))
        actions.append("Re-sign into OneDrive to refresh Office 365 token")
    elif not od_connected:
        insights.append(_insight("warning",
            "OneDrive does not appear to be connected to an account. "
            "Office apps will show sign-in prompts until OneDrive is authenticated.",
            "Click the OneDrive cloud icon in the system tray and sign in."))
    elif not od_running:
        insights.append(_insight("warning",
            "OneDrive process is not running. Office credential sync is paused.",
            "Launch OneDrive from Start menu or restart it."))
    else:
        age_str = f" (refreshed {token_age:.0f}h ago)" if token_age is not None else ""
        insights.append(_insight("ok",
            f"OneDrive connected{age_str} — Microsoft 365 tokens appear current."))

    if office_errs:
        insights.append(_insight("warning",
            f"{len(office_errs)} recent Office/OneDrive error event(s) in Application log.",
            "Check Event Viewer > Application log for OneDrive and Microsoft Office errors."))

    # OneDrive / M365 token status
    token_stale  = data.get("msal_token_stale", False)
    token_age    = data.get("msal_token_age_h")
    od_running   = data.get("onedrive_running", False)
    od_connected = data.get("onedrive_connected", False)
    od_account   = data.get("onedrive_account", "")
    office_errs  = data.get("office_errors", [])
    # Note: backgroundTaskHost suspensions are typically McAfee's idle UWP RulesEngine —
    # normal Windows behavior, not an auth issue. The real auth issue is OneDrive suspension.
    od_suspended  = data.get("onedrive_suspended", False)
    od_priority   = data.get("onedrive_priority", "")
    susp_auth     = data.get("suspended_auth_procs", [])

    if od_suspended:
        insights.append(_insight("critical",
            "OneDrive process is SUSPENDED by Windows memory management. "
            "This is the direct cause of the Sign in Required error in Word and Outlook. "
            "When OneDrive is suspended it cannot refresh Microsoft 365 OAuth tokens.",
            "Fix: run the Resume OneDrive button, or run in PowerShell: "
            "Get-Process OneDrive | ForEach-Object { $_.Threads | ForEach-Object { try { $_.Resume() } catch {} } }. "
            "To prevent recurrence, set OneDrive to AboveNormal priority."))
        actions.append("Resume OneDrive process to fix Office 365 sign-in errors")
    if susp_auth:
        names = ", ".join(p.get("Name","") for p in susp_auth[:3])
        insights.append(_insight("warning",
            f"Other auth-related processes are suspended: {names}. "
            "These may also contribute to Office connectivity issues.",
            "Use the Resume Auth Brokers button to restore them."))

    if token_stale and not od_suspended:
        age_str = f"{token_age:.0f} hours" if token_age else "unknown"
        insights.append(_insight("critical",
            f"Microsoft 365 authentication token is {age_str} old. "
            "This is the direct cause of the Sign in Required error in Word and Outlook.",
            "Fix: click the OneDrive cloud icon in the system tray and sign in. "
            "Tokens refresh for all Office apps once signed in."))
        actions.append("Re-sign into OneDrive to fix Office 365 credential expiry")
    elif not od_connected and not od_suspended:
        insights.append(_insight("warning",
            "OneDrive is not connected to an account. Office apps will show sign-in prompts.",
            "Click the OneDrive cloud icon in the system tray and sign in."))
    elif not od_running:
        insights.append(_insight("warning",
            "OneDrive process is not running. Office credential sync is paused.",
            "Launch OneDrive from the Start menu."))
    else:
        age_str = f" (token refreshed {token_age:.0f}h ago)" if token_age is not None else ""
        acct    = f" as {od_account}" if od_account else ""
        insights.append(_insight("ok", f"OneDrive connected{acct}{age_str}."))
    if office_errs:
        insights.append(_insight("warning",
            f"{len(office_errs)} recent Office or OneDrive error event(s) in Application log.",
            "Check Event Viewer > Application log for OneDrive and Microsoft Office errors."))

    # NFS/CIFS breakdown
    nfs_drives = data.get("nfs_drives", [])
    if nfs_drives:
        nfs_down = [d for d in nfs_drives if not d.get("Reachable", True)]
        insights.append(_insight("critical" if nfs_down else "ok",
            f"{len(nfs_drives)} NFS mount(s): "
            + ", ".join(f"{d.get('Name','?')} ({d.get('DisplayRoot','')})" for d in nfs_drives[:3])
            + (f" -- {len(nfs_down)} unreachable" if nfs_down else " -- all reachable")))

    # Email credentials
    if email_creds:
        insights.append(_insight("info",
            f"{len(email_creds)} email credential(s) in Credential Manager: "
            + ", ".join(c.get("Target","")[:40] for c in email_creds[:3]),
            "If Outlook loses these on reboot, check credential Type is Generic not Session."))
    else:
        insights.append(_insight("warning",
            "No email credentials in Credential Manager. Outlook uses MSAL token cache only.",
            "Open Credential Manager from Start and check Windows Credentials tab."))

    # Credential failures
    if cred_failures:
        insights.append(_insight("warning",
            f"{len(cred_failures)} credential failure event(s) in Security log (Event 4625/4776). "
            "These may correlate with the Outlook and NAS disconnection issues.",
            "Check Security Event Log for the account names and sources involved."))

    # Firewall blocking
    if fw_blocking:
        insights.append(_insight("warning",
            f"File and Printer Sharing firewall rule(s) set to Block: "
            + ", ".join(f.get("DisplayName","") for f in fw_blocking[:2]),
            "McAfee may have modified these rules. Check McAfee Firewall settings."))

    # SMB signing
    if smb_config and smb_config.get("RequireSecuritySignature"):
        insights.append(_insight("info",
            "SMB security signing is required. If your NAS does not support SMB signing "
            "this can cause intermittent connection failures.",
            "Check NAS SMB settings and ensure SMB2/3 is enabled on the NAS."))

    token_stale  = data.get("msal_token_stale", False)
    token_stale  = data.get("msal_token_stale", False)
    od_suspended = data.get("onedrive_suspended", False)
    status = ("critical" if od_suspended or drives_down or token_stale
              else "warning" if (fast_startup or cred_failures or fw_blocking or not email_creds)
              else "ok")
    headline = ("OneDrive SUSPENDED -- direct cause of Word/Outlook sign-in errors" if od_suspended
                else "Office 365 token expired -- re-sign into OneDrive to fix" if token_stale
                else f"{len(drives_down)} SMB/CIFS/NFS drive(s) unreachable" if drives_down
                else "Fast Startup ON -- likely cause of credential loss on reboot" if fast_startup
                else f"{data.get('total_creds',0)} credentials stored -- connections healthy")
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}

# ══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    from flask import make_response
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    global _scan_results, _scan_status
    _scan_results = None
    _scan_status  = {"status": "starting", "progress": 0, "message": "Initializing…"}
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def scan_status_route():
    return jsonify(_scan_status)


@app.route("/api/scan/results")
def scan_results_route():
    return jsonify(_scan_results or [])


@app.route("/api/bsod/data")
def bsod_data():
    return jsonify(build_bsod_analysis())




@app.route("/api/startup/list")
def startup_list():
    return jsonify(get_startup_items())



@app.route("/api/startup/lookup-unknowns", methods=["POST"])
def startup_lookup_unknowns():
    """
    Re-queue all startup items whose cached info source is 'unknown' or missing.
    Accepts a list of items from the frontend so we have their commands available.
    Returns how many were queued.
    """
    items   = (request.get_json() or {}).get("items", [])
    queued  = 0
    for item in items:
        name    = item.get("Name", "")
        command = item.get("Command", "")
        exe_key = _extract_exe_from_command(command)
        cache_key = exe_key or name.lower()

        # Check if already has a good result
        with _startup_cache_lock:
            existing = _startup_cache.get(cache_key, {})
            src = existing.get("source", "")

        # Skip static KB entries and already-enriched entries
        if name.lower() in STARTUP_KB or exe_key in STARTUP_KB:
            continue
        # Re-queue if unknown, missing, or previously failed
        if src in ("unknown", "") or not existing:
            with _startup_cache_lock:
                _startup_cache.pop(cache_key, None)   # clear so worker re-fetches
            if cache_key not in _startup_in_flight:
                _startup_in_flight.add(cache_key)
                _startup_queue.put((cache_key, command, name))
                queued += 1

    return jsonify({"ok": True, "queued": queued,
                    "queue_depth": _startup_queue.qsize()})


@app.route("/api/startup/lookup-status")
def startup_lookup_status():
    """Poll how many lookups are still pending."""
    return jsonify({
        "queue_pending": _startup_queue.qsize(),
        "in_flight":     len(_startup_in_flight),
        "cached":        len(_startup_cache),
    })

@app.route("/api/startup/cache")
def startup_cache_status():
    with _startup_cache_lock:
        cached = dict(_startup_cache)
    return jsonify({
        "total_cached":  len(cached),
        "queue_pending": _startup_queue.qsize(),
        "in_flight":     len(_startup_in_flight),
    })

@app.route("/api/startup/toggle", methods=["POST"])
def startup_toggle():
    data = request.get_json()
    return jsonify(toggle_startup_item(data["name"], data["type"], data["enable"]))

@app.route("/api/disk/data")
def disk_data_route():
    return jsonify(get_disk_health())

@app.route("/api/network/data")
def network_data_route():
    return jsonify(get_network_data())

@app.route("/api/updates/history")
def updates_history():
    return jsonify(get_update_history())

@app.route("/api/events/query", methods=["POST"])
def events_query():
    data = request.get_json()
    return jsonify(query_event_log(data or {}))


@app.route("/api/summary/<tab>", methods=["POST"])
def get_summary(tab: str):
    data = request.get_json() or {}
    fn_map = {
        "drivers":   lambda: summarize_drivers(data.get("results", [])),
        "bsod":      lambda: summarize_bsod(data),
        "startup":   lambda: summarize_startup(data.get("items", [])),
        "disk":      lambda: summarize_disk(data),
        "network":   lambda: summarize_network(data),
        "updates":   lambda: summarize_updates(data.get("items", [])),
        "events":    lambda: summarize_events(data.get("events", [])),
        "processes":      lambda: summarize_processes(data),
        "thermals":       lambda: summarize_thermals(data),
        "services":       lambda: summarize_services(data.get("services", [])),
        "health-history": lambda: summarize_health_history(data),
        "timeline":       lambda: summarize_timeline(data.get("events", [])),
        "memory":         lambda: summarize_memory(data),
        "bios":           lambda: summarize_bios(data),
        "credentials":    lambda: summarize_credentials_network(data),
    }
    fn = fn_map.get(tab)
    if not fn:
        return jsonify({"error": "Unknown tab"}), 404
    return jsonify(fn())




@app.route("/api/processes/list")
def process_list():
    return jsonify(get_process_list())


@app.route("/api/processes/lookup-unknowns", methods=["POST"])
def process_lookup_unknowns():
    procs  = (request.get_json() or {}).get("processes", [])
    queued = 0
    for p in procs:
        key = p.get("Name","").lower().replace(".exe","")
        if key in PROCESS_KB:
            continue
        with _process_cache_lock:
            existing = _process_cache.get(key, {})
        if existing.get("source","") not in ("unknown",""):
            continue
        with _process_cache_lock:
            _process_cache.pop(key, None)
        if key not in _process_in_flight:
            _process_in_flight.add(key)
            _process_queue.put((key, p.get("Name",""), p.get("Path","")))
            queued += 1
    return jsonify({"ok": True, "queued": queued})

@app.route("/api/processes/lookup-status")
def process_lookup_status():
    return jsonify({"queue_pending": _process_queue.qsize(), "in_flight": len(_process_in_flight)})

@app.route("/api/processes/kill", methods=["POST"])
def process_kill():
    data = request.get_json() or {}
    return jsonify(kill_process(int(data.get("pid", 0))))

@app.route("/api/thermals/data")
def thermals_data():
    return jsonify(get_thermals())

@app.route("/api/services/list")
def services_list():
    return jsonify(get_services_list())

@app.route("/api/services/toggle", methods=["POST"])
def services_toggle():
    data = request.get_json() or {}
    return jsonify(toggle_service(data.get("name",""), data.get("action","")))

@app.route("/api/services/lookup-unknowns", methods=["POST"])
def services_lookup_unknowns():
    svcs   = (request.get_json() or {}).get("services", [])
    queued = 0
    for s in svcs:
        key = s.get("Name","").lower()
        if key in SERVICES_KB:
            continue
        with _services_cache_lock:
            existing = _services_cache.get(key, {})
        if existing.get("source","") not in ("unknown",""):
            continue
        with _services_cache_lock:
            _services_cache.pop(key, None)
        if key not in _services_in_flight:
            _services_in_flight.add(key)
            _services_queue.put((key, s.get("DisplayName", key)))
            queued += 1
    return jsonify({"ok": True, "queued": queued})

@app.route("/api/services/lookup-status")
def services_lookup_status():
    return jsonify({
        "queue_pending": _services_queue.qsize(),
        "in_flight":     len(_services_in_flight),
    })


@app.route("/api/health-history/data")
def health_history_data():
    return jsonify(get_health_report_history())

@app.route("/api/timeline/data")
def timeline_data():
    days = int(request.args.get("days", 30))
    events = get_system_timeline(days)
    return jsonify({"events": events, "days": days, "total": len(events)})

@app.route("/api/memory/data")
def memory_data():
    return jsonify(get_memory_analysis())

@app.route("/api/credentials/health")
def credentials_health():
    return jsonify(get_credentials_network_health())

@app.route("/api/credentials/resume-onedrive", methods=["POST"])
def resume_onedrive():
    """Resume suspended OneDrive process and set AboveNormal priority to prevent re-suspension."""
    ps = r"""
$results = @()
$odProcs = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($odProcs) {
    foreach ($p in $odProcs) {
        try {
            $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::AboveNormal
            $resumed = 0
            foreach ($t in $p.Threads) { try { $t.Resume(); $resumed++ } catch {} }
            $results += [PSCustomObject]@{ Name="OneDrive"; PID=$p.Id; Resumed=$resumed; Status="OK" }
        } catch {
            $results += [PSCustomObject]@{ Name="OneDrive"; PID=$p.Id; Resumed=0; Status="Error: $_" }
        }
    }
} else {
    $results += [PSCustomObject]@{ Name="OneDrive"; PID=0; Resumed=0; Status="NotFound" }
}
$results | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout.strip() or "[]")
        if isinstance(data, dict): data = [data]
        fixed = [d for d in data if d.get("Status") == "OK"]
        return jsonify({
            "ok":      len(fixed) > 0,
            "fixed":   len(fixed),
            "results": data,
            "message": f"OneDrive resumed and set to AboveNormal priority. Word and Outlook should reconnect."
                       if fixed else "OneDrive process not found."
        })
    except Exception as e:
        return jsonify({"ok": False, "fixed": 0, "results": [], "message": str(e)})

@app.route("/api/credentials/resume-brokers", methods=["POST"])
def resume_broker_processes():
    """
    Resume suspended Microsoft authentication broker processes.
    Sets priority to Normal to prevent Windows Efficiency Mode from suspending them.
    Fixes Word/Outlook 'Sign in Required' errors caused by suspended auth processes.
    """
    ps = r"""
$results = @()
$targets = @("backgroundTaskHost","WWAHost","Microsoft.AAD.BrokerPlugin","wwahost")
foreach ($name in $targets) {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        try {
            # Set to Normal priority so Windows won't throttle/suspend it
            $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Normal
            # Resume all suspended threads
            $resumed = 0
            foreach ($t in $p.Threads) {
                try { $t.Resume(); $resumed++ } catch {}
            }
            $results += [PSCustomObject]@{
                Name     = $p.ProcessName
                PID      = $p.Id
                Resumed  = $resumed
                Status   = "OK"
            }
        } catch {
            $results += [PSCustomObject]@{
                Name    = $name
                PID     = 0
                Resumed = 0
                Status  = "Error: $_"
            }
        }
    }
}
if ($results.Count -eq 0) {
    $results += [PSCustomObject]@{ Name="No broker processes found"; PID=0; Resumed=0; Status="NotFound" }
}
$results | ConvertTo-Json -Depth 2
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout.strip() or "[]")
        if isinstance(data, dict): data = [data]
        fixed = [d for d in data if d.get("Status") == "OK"]
        return jsonify({
            "ok":      len(fixed) > 0,
            "fixed":   len(fixed),
            "results": data,
            "message": f"Resumed {len(fixed)} broker process(es). Word and Outlook should reconnect."
                       if fixed else "No broker processes found to resume."
        })
    except Exception as e:
        return jsonify({"ok": False, "fixed": 0, "results": [], "message": str(e)})


@app.route("/api/credentials/fix-fast-startup", methods=["POST"])
def fix_fast_startup():
    """Toggle Fast Startup on or off via registry."""
    from flask import request as freq
    enable = freq.json.get("enable", False) if freq.is_json else False
    value  = 1 if enable else 0
    label  = "enabled" if enable else "disabled"
    ps = f"""
try {{
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power" `
        -Name "HiberbootEnabled" -Value {value} -Type DWord -Force
    Write-Output "OK:{label}"
}} catch {{ Write-Output "ERROR: $_" }}
"""
    try:
        r = subprocess.run(["powershell", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=10)
        ok = "OK" in r.stdout
        return jsonify({"ok": ok, "enabled": enable,
                        "message": f"Fast Startup {label}." if ok else r.stdout.strip()})
    except Exception as e:
        return jsonify({"ok": False, "enabled": enable, "message": str(e)})

@app.route("/api/bios/status")
def bios_status():
    return jsonify(get_bios_status())

@app.route("/api/bios/cache/clear", methods=["POST"])
def bios_cache_clear_route():
    try:
        if os.path.exists(BIOS_CACHE_FILE):
            os.remove(BIOS_CACHE_FILE)
    except Exception:
        pass
    return jsonify({"ok": True})

@app.route("/api/dashboard/summary")
def dashboard_summary():
    """
    Aggregates key health checks from all tabs into a single fast response.
    Runs checks in parallel threads for speed.
    """
    import concurrent.futures
    results = {}

    def run(name, fn):
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = {"error": str(e)}

    checks = {
        "thermals":    get_thermals,
        "memory":      get_memory_analysis,
        "bios":        get_bios_status,
        "credentials": get_credentials_network_health,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(fn): name for name, fn in checks.items()}
        for fut in concurrent.futures.as_completed(futs, timeout=30):
            name = futs[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": str(e)}

    # ── Pull key signals from each area ──────────────────────────────────────
    concerns = []

    # Credentials / Auth
    cred = results.get("credentials", {})
    if cred.get("onedrive_suspended"):
        concerns.append({
            "level": "critical", "tab": "credentials", "icon": "☁",
            "title": "OneDrive is SUSPENDED — confirmed cause of Word/Outlook sign-in errors",
            "detail": "Windows suspended OneDrive to free memory. OAuth tokens cannot refresh until it is resumed.",
            "action": "Resume OneDrive",
            "action_fn": "resumeOneDrive()",
        })
    # Note: ms_account_suspended reflects McAfee's idle UWP RulesEngine task — not an auth issue
    # Only flag if it's a genuine Microsoft auth process (not McAfee AppX background tasks)
    if cred.get("msal_token_stale"):
        age = cred.get("msal_token_age_h", 0)
        concerns.append({
            "level": "critical", "tab": "credentials", "icon": "🔑",
            "title": f"Microsoft 365 token expired ({age:.0f}h old)",
            "detail": "Sign in to OneDrive to refresh tokens for all Office apps.",
            "action": "View Credentials tab",
            "action_fn": "switchTab('credentials')",
        })
    if cred.get("fast_startup"):
        concerns.append({
            "level": "warning", "tab": "credentials", "icon": "⚡",
            "title": "Fast Startup is enabled",
            "detail": "Causes SMB credential loss and NAS disconnection on every reboot.",
            "action": "Disable Fast Startup",
            "action_fn": "fixFastStartup()",
        })
    drives_down = cred.get("drives_down", [])
    if drives_down:
        concerns.append({
            "level": "critical", "tab": "credentials", "icon": "💾",
            "title": f"{len(drives_down)} NAS drive(s) unreachable",
            "detail": ", ".join(f"{d.get('Name','?')}: {d.get('DisplayRoot','')}" for d in drives_down[:3]),
            "action": "View Credentials tab",
            "action_fn": "switchTab('credentials')",
        })

    # Thermals
    therm = results.get("thermals", {})
    crit_temps = [t for t in therm.get("temps", []) if t.get("status") == "critical"]
    warn_temps = [t for t in therm.get("temps", []) if t.get("status") == "warning"]
    cpu_pct = therm.get("perf", {}).get("CPUPct", 0)
    if crit_temps:
        concerns.append({
            "level": "critical", "tab": "thermals", "icon": "🌡",
            "title": f"Critical temperature: {crit_temps[0].get('TempC')}°C ({crit_temps[0].get('Name','')})",
            "detail": "Immediate risk of thermal throttling or damage.",
            "action": "View Temps & Power",
            "action_fn": "switchTab('thermals')",
        })
    elif warn_temps:
        concerns.append({
            "level": "warning", "tab": "thermals", "icon": "🌡",
            "title": f"Elevated temperature: {warn_temps[0].get('TempC')}°C ({warn_temps[0].get('Name','')})",
            "detail": "Monitor under load — may contribute to instability.",
            "action": "View Temps & Power",
            "action_fn": "switchTab('thermals')",
        })
    if cpu_pct >= 80:
        concerns.append({
            "level": "warning", "tab": "thermals", "icon": "💻",
            "title": f"CPU at {cpu_pct}% utilisation",
            "detail": "Check Processes tab for what is driving high CPU.",
            "action": "View Processes",
            "action_fn": "switchTab('processes')",
        })

    # Memory / McAfee
    mem = results.get("memory", {})
    if mem.get("has_mcafee"):
        mc_mb = mem.get("mcafee_mb", 0)
        saving = mem.get("mcafee_saving_mb", 0)
        concerns.append({
            "level": "warning", "tab": "memory", "icon": "🧠",
            "title": f"McAfee using {mc_mb:,.0f} MB RAM",
            "detail": f"Switching to Windows Defender could free ~{saving:,.0f} MB.",
            "action": "View Memory Analysis",
            "action_fn": "switchTab('memory')",
        })
    mem_pct = round(mem.get("used_mb", 0) / max(mem.get("total_mb", 1), 1) * 100, 1)
    if mem_pct > 90:
        concerns.append({
            "level": "critical", "tab": "memory", "icon": "🧠",
            "title": f"RAM at {mem_pct}% ({mem.get('used_mb',0):,.0f} MB used)",
            "detail": "Very little memory available — system may be unstable.",
            "action": "View Memory Analysis",
            "action_fn": "switchTab('memory')",
        })

    # BIOS
    bios = results.get("bios", {})
    if bios.get("update", {}).get("update_available"):
        latest = bios.get("update", {}).get("latest_version", "")
        concerns.append({
            "level": "critical", "tab": "bios", "icon": "🔩",
            "title": f"BIOS update available: {latest}",
            "detail": f"Install to get latest microcode patches for your i9-14900K.",
            "action": "View BIOS & Firmware",
            "action_fn": "switchTab('bios')",
        })
    elif bios.get("update", {}).get("confirmed_current"):
        pass  # BIOS confirmed current — no concern needed

    # Sort by level
    level_order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    concerns.sort(key=lambda c: level_order.get(c.get("level","info"), 2))

    overall = ("critical" if any(c["level"] == "critical" for c in concerns)
               else "warning" if any(c["level"] == "warning" for c in concerns)
               else "ok")

    return jsonify({
        "concerns":  concerns,
        "total":     len(concerns),
        "critical":  sum(1 for c in concerns if c["level"] == "critical"),
        "warnings":  sum(1 for c in concerns if c["level"] == "warning"),
        "overall":   overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })

@app.route("/api/bsod/cache")
def bsod_cache_status():
    return jsonify(get_bsod_cache_status())

@app.route("/api/bsod/cache/delete/<path:code>", methods=["DELETE"])
def bsod_cache_delete(code: str):
    key = _normalise_stop_code(code)
    with _bsod_cache_lock:
        removed = key in _bsod_cache
        _bsod_cache.pop(key, None)
    if removed:
        _save_bsod_cache()
    return jsonify({"ok": True, "removed": removed, "code": key})

@app.route("/api/bsod/cache/clear", methods=["POST"])
def bsod_cache_clear():
    global _bsod_cache
    with _bsod_cache_lock:
        _bsod_cache = {}
    _save_bsod_cache()
    return jsonify({"ok": True})

@app.route("/api/events/cache")
def events_cache():
    """Return the current event ID cache status — useful for debugging."""
    return jsonify(get_cache_status())

@app.route("/api/events/cache/delete/<int:event_id>", methods=["DELETE"])
def events_cache_delete(event_id: int):
    """Remove a specific event ID from the cache so it gets re-looked up."""
    key = str(event_id)
    with _event_cache_lock:
        removed = key in _event_cache
        _event_cache.pop(key, None)
    if removed:
        _save_event_cache()
    return jsonify({"ok": True, "removed": removed, "id": event_id})

@app.route("/api/events/cache/clear", methods=["POST"])
def events_cache_clear():
    """Wipe the entire learned cache (keeps static EVENT_KB)."""
    global _event_cache
    with _event_cache_lock:
        _event_cache = {}
    _save_event_cache()
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════

def _requeue_stale_cache(cache: dict, queue_obj: queue.Queue,
                        in_flight: set, label: str,
                        id_field: str = "id",
                        source_field: str = "source",
                        max_age_days: int = 90) -> int:
    """
    At startup, re-queue two kinds of cache entries for a fresh lookup:
      1. source == "unknown"  — previous lookup failed; try again now
      2. age > max_age_days   — may have better docs available since last fetch
    Returns the number of entries re-queued.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    requeued = 0
    with _event_cache_lock if label == "Event" else _bsod_cache_lock:
        for key, entry in list(cache.items()):
            source = entry.get("source", "")
            fetched_str = entry.get("fetched", "")

            stale = False
            if source == "unknown":
                stale = True
            elif fetched_str:
                try:
                    fetched_dt = datetime.fromisoformat(
                        fetched_str.replace("Z", "+00:00"))
                    if fetched_dt.tzinfo is None:
                        fetched_dt = fetched_dt.replace(tzinfo=timezone.utc)
                    if fetched_dt < cutoff:
                        stale = True
                except Exception:
                    pass

            if stale and key not in in_flight:
                # Remove so the worker will re-fetch rather than skip
                del cache[key]
                in_flight.add(key)
                queue_obj.put(key)
                requeued += 1

    if requeued:
        print(f"[{label}Cache] Re-queued {requeued} stale/unknown entries for refresh")
    return requeued


if __name__ == "__main__":
    # Load persisted caches from disk
    _load_event_cache()
    _load_bsod_cache()
    _load_startup_cache()

    # Start background lookup worker threads first so the queues are draining
    _worker_thread = threading.Thread(target=_lookup_worker, daemon=True, name="EventLookupWorker")
    _worker_thread.start()
    _bsod_worker_thread = threading.Thread(target=_bsod_lookup_worker, daemon=True, name="BSODLookupWorker")
    _bsod_worker_thread.start()
    _startup_worker_thread = threading.Thread(target=_startup_lookup_worker, daemon=True, name="StartupLookupWorker")
    _startup_worker_thread.start()
    _load_services_cache()
    _load_process_cache()
    _services_worker_thread = threading.Thread(target=_services_lookup_worker, daemon=True, name="ServicesLookupWorker")
    _services_worker_thread.start()
    _process_worker_thread = threading.Thread(target=_process_lookup_worker, daemon=True, name="ProcessLookupWorker")
    _process_worker_thread.start()

    # Re-queue unknown or aged entries — workers will pick them up immediately
    ev_requeued      = _requeue_stale_cache(
        _event_cache, _lookup_queue, _lookup_in_flight, "Event")
    bsod_requeued    = _requeue_stale_cache(
        _bsod_cache, _bsod_queue, _bsod_in_flight, "BSOD")
    startup_requeued  = _requeue_stale_cache(
        _startup_cache, _startup_queue, _startup_in_flight, "Startup")
    services_requeued = _requeue_stale_cache(
        _services_cache, _services_queue, _services_in_flight, "Services")
    process_requeued  = _requeue_stale_cache(
        _process_cache, _process_queue, _process_in_flight, "Process")

    print(f"[EventCache] Worker started. {len(_event_cache)} cached, {ev_requeued} re-queued.")
    print(f"[BSODCache]    Worker started. {len(_bsod_cache)} cached, {bsod_requeued} re-queued.")
    print(f"[StartupCache]  Worker started. {len(_startup_cache)} cached, {startup_requeued} re-queued.")
    print(f"[ServicesCache] Worker started. {len(_services_cache)} cached, {services_requeued} re-queued.")
    print(f"[ProcessCache]  Worker started. {len(_process_cache)} cached, {process_requeued} re-queued.")

    print("\n  WinDesktopMgr running at http://localhost:5000\n")
    app.run(debug=False, port=5000, use_reloader=False)

