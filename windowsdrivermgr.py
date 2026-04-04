"""
WindowsDriverMgr
Flask backend — driver update checker + BSOD trend dashboard.
Reads from Windows Event Log and existing SystemHealthDiag HTML reports.
"""

import glob
import json
import os
import re
import subprocess
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template

app = Flask(__name__)

# ─── Driver checker state ─────────────────────────────────────────────────────
_dell_cache = None
_scan_results = None
_scan_status = {"status": "idle", "progress": 0, "message": "Ready to scan"}

# ─── Driver category keywords ─────────────────────────────────────────────────
CATEGORIES = {
    "Display": ["display", "video", "graphics", "gpu", "nvidia", "amd radeon", "intel uhd", "intel arc", "vga"],
    "Audio": ["audio", "sound", "realtek", "speaker", "microphone", "hdmi audio", "nahimic", "waves"],
    "Network": ["network", "ethernet", "wi-fi", "wifi", "wireless", "bluetooth", "lan", "killer", "intel(r) wi"],
    "Chipset": [
        "chipset",
        "management engine",
        "serial io",
        "sata",
        "nvme",
        "rapid storage",
        "pci",
        "smbus",
        "usb",
        "thunderbolt",
        "intel(r) core",
        "platform",
    ],
}

DELL_API = "https://www.dell.com/support/driver/en-us/ips/api/driverlist/fetchdriversbyproduct"

# ─── BSOD constants ───────────────────────────────────────────────────────────
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "System Health Reports")

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
        ),
    },
    "DRIVER_POWER_STATE_FAILURE": {
        "priority": "high",
        "title": "Driver Power State Failure",
        "detail": "A driver failed to transition correctly during a system power state change. "
        "Check for driver updates in the Driver Manager tab, and disable "
        "Windows Fast Startup under Power Options > Choose what the power button does.",
    },
    "KERNEL_SECURITY_CHECK_FAILURE": {
        "priority": "high",
        "title": "Kernel Security Check Failed",
        "detail": "A kernel data structure failed a security integrity check. This often points "
        "to memory corruption or a faulty driver. Run Windows Memory Diagnostic "
        "(mdsched.exe) and check for driver updates.",
    },
    "PAGE_FAULT_IN_NONPAGED_AREA": {
        "priority": "high",
        "title": "Page Fault in Non-Paged Area",
        "detail": "A process attempted to access paged memory that was unavailable. "
        "Can be caused by faulty drivers, failing RAM, or corrupt system files. "
        "Run: sfc /scannow in an admin PowerShell.",
    },
    "VIDEO_TDR_FAILURE": {
        "priority": "medium",
        "title": "GPU Driver Timeout / Recovery Failure",
        "detail": "The GPU driver stopped responding and Windows could not recover it. "
        "Update or roll back your display driver. "
        "Check GPU temperatures under load with HWiNFO64.",
    },
    "SYSTEM_SERVICE_EXCEPTION": {
        "priority": "high",
        "title": "System Service Exception",
        "detail": "A system service generated an exception the error handler did not catch. "
        "Check the faulty driver listed in crash details and update or remove it.",
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
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=90
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
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=60
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
    name_words = set(name_clean.split()) - {
        "the",
        "a",
        "an",
        "for",
        "with",
        "and",
        "or",
        "of",
        "driver",
        "device",
        "controller",
        "adapter",
        "interface",
        "port",
        "bus",
    }
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
    _scan_status = {"status": "scanning", "progress": 10, "message": "Enumerating installed drivers via WMI…"}
    installed = get_installed_drivers()
    _scan_status = {
        "status": "scanning",
        "progress": 40,
        "message": f"Found {len(installed)} drivers — checking Windows Update for driver updates…",
    }
    wu_updates = get_windows_update_drivers()
    _scan_status = {
        "status": "scanning",
        "progress": 70,
        "message": f"Found {len(wu_updates)} WU driver update(s) — comparing…",
    }
    results = []
    for drv in installed:
        name = drv.get("DeviceName", "Unknown Device")
        version = drv.get("DriverVersion", "")
        drv_date = drv.get("DriverDate", "")
        dev_class = drv.get("DeviceClass", "")
        mfr = drv.get("Manufacturer", "")
        category = categorize(name, dev_class)

        match = find_wu_match(name, wu_updates)
        status = "up_to_date"  # default: assume current if WU has no update
        latest_ver = None
        latest_date = None
        download_url = "ms-settings:windowsupdate"

        if match:
            status = "update_available"
            latest_ver = match.get("DriverVersion") or match.get("Title", "")
        elif not wu_updates:
            # WU query failed entirely — fall back to unknown
            status = "unknown"

        results.append(
            {
                "name": name,
                "version": version,
                "date": drv_date,
                "category": category,
                "manufacturer": mfr,
                "status": status,
                "latest_version": latest_ver,
                "latest_date": latest_date,
                "download_url": download_url,
            }
        )

    order = {"update_available": 0, "unknown": 1, "up_to_date": 2}
    results.sort(key=lambda x: (order.get(x["status"], 3), x["name"].lower()))
    _scan_results = results
    updates = sum(1 for r in results if r["status"] == "update_available")
    _scan_status = {
        "status": "complete",
        "progress": 100,
        "message": f"Done — {len(results)} drivers scanned, {updates} update(s) via Windows Update",
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
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=30
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
    ts = evt.get("TimeCreated", "")

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
            "timestamp": ts,
            "error_code": error_name,
            "stop_code": normalized,
            "faulty_driver": faulty_driver,
            "source": "event_log",
            "event_id": eid,
        }

    if eid in (41, 6008):
        label = "KERNEL_POWER_LOSS" if eid == 41 else "UNEXPECTED_SHUTDOWN"
        return {
            "timestamp": ts,
            "error_code": label,
            "stop_code": None,
            "faulty_driver": None,
            "source": "event_log",
            "event_id": eid,
        }
    return None


def parse_report_crashes(report_path: str) -> list:
    """Extract BSOD data from a SystemHealthDiag HTML report file."""
    crashes = []
    try:
        with open(report_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        fname = os.path.basename(report_path)
        dm = re.search(r"(\d{8})_(\d{6})", fname)
        report_ts = None
        if dm:
            try:
                report_ts = datetime.strptime(f"{dm.group(1)}_{dm.group(2)}", "%Y%m%d_%H%M%S").isoformat()
            except Exception:
                pass

        codes_found = re.findall(
            r"(HYPERVISOR_ERROR|KMODE_EXCEPTION_NOT_HANDLED"
            r"|PAGE_FAULT_IN_NONPAGED_AREA|VIDEO_TDR_FAILURE"
            r"|KERNEL_SECURITY_CHECK_FAILURE|DRIVER_POWER_STATE_FAILURE"
            r"|SYSTEM_SERVICE_EXCEPTION|UNEXPECTED_KERNEL_MODE_TRAP"
            r"|IRQL_NOT_LESS_OR_EQUAL|CRITICAL_PROCESS_DIED"
            r"|DPC_WATCHDOG_VIOLATION|DRIVER_IRQL_NOT_LESS_OR_EQUAL)",
            content,
            re.IGNORECASE,
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
                crashes.append(
                    {
                        "timestamp": report_ts,
                        "error_code": code,
                        "stop_code": stop_code,
                        "faulty_driver": top_driver,
                        "source": "health_report",
                        "report_file": fname,
                    }
                )
    except Exception as e:
        print(f"[Report parse error] {report_path}: {e}")
    return crashes


def build_recommendations(crashes: list) -> list:
    recs = []
    error_counts = Counter(c["error_code"] for c in crashes)

    for code, count in error_counts.most_common(6):
        if code in RECOMMENDATIONS_DB:
            rec = dict(RECOMMENDATIONS_DB[code])
            rec["count"] = count
            recs.append(rec)

    total = len(crashes)
    if total == 0:
        recs.append(
            {
                "priority": "info",
                "count": 0,
                "title": "System appears stable",
                "detail": "No BSOD events found in the Event Log or health reports. "
                "Keep drivers up to date and run periodic health scans.",
            }
        )
    elif total > 10:
        recs.append(
            {
                "priority": "critical",
                "count": total,
                "title": f"High crash frequency — {total} crashes detected",
                "detail": "This level of instability warrants immediate attention. "
                "Run Dell SupportAssist diagnostics and consider hardware testing (memtest86).",
            }
        )
    elif total >= 3:
        recs.append(
            {
                "priority": "high",
                "count": total,
                "title": f"Recurring crashes — {total} events found",
                "detail": "Review the faulty drivers below and check the Driver Manager tab for pending updates.",
            }
        )

    if "HYPERVISOR_ERROR" in error_counts:
        recs.append(
            {
                "priority": "high",
                "count": error_counts["HYPERVISOR_ERROR"],
                "title": "Verify BIOS Version for i9-14900K Stability",
                "detail": "BIOS updates for the XPS 8960 include CPU microcode patches that address "
                "Raptor Lake stability issues. Current BIOS: 2.22.0 (Jan 2026). "
                "Check Dell Support for newer releases.",
            }
        )

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
    error_counts = Counter(c["error_code"] for c in unique_crashes)
    error_breakdown = [{"code": k, "count": v} for k, v in error_counts.most_common(8)]

    # Faulty driver breakdown
    driver_counts = Counter(c["faulty_driver"] for c in unique_crashes if c.get("faulty_driver"))
    driver_breakdown = [{"driver": k, "count": v} for k, v in driver_counts.most_common(8)]

    # Uptime between crashes
    sorted_asc = sorted(
        [c for c in unique_crashes if c.get("timestamp")], key=lambda c: _parse_ts(c.get("timestamp", ""))
    )
    uptime_periods = []
    for i in range(1, len(sorted_asc)):
        t1 = _parse_ts(sorted_asc[i - 1]["timestamp"])
        t2 = _parse_ts(sorted_asc[i]["timestamp"])
        if t1 != datetime.min and t2 != datetime.min:
            hours = round((t2 - t1).total_seconds() / 3600, 1)
            uptime_periods.append(
                {
                    "start": sorted_asc[i - 1]["timestamp"],
                    "end": sorted_asc[i]["timestamp"],
                    "hours": hours,
                }
            )

    avg_uptime = round(sum(p["hours"] for p in uptime_periods) / len(uptime_periods), 1) if uptime_periods else 0
    this_month = sum(1 for c in unique_crashes if _is_this_month(c.get("timestamp", "")))
    most_common = error_counts.most_common(1)[0][0] if error_counts else "None"

    return {
        "summary": {
            "total_crashes": len(unique_crashes),
            "this_month": this_month,
            "most_common_error": most_common,
            "avg_uptime_hours": avg_uptime,
        },
        "crashes": unique_crashes[:60],
        "timeline": timeline,
        "error_codes": error_breakdown,
        "faulty_drivers": driver_breakdown,
        "uptime_periods": uptime_periods[-12:],
        "recommendations": build_recommendations(unique_crashes),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    global _scan_results, _scan_status
    _scan_results = None
    _scan_status = {"status": "starting", "progress": 0, "message": "Initializing…"}
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


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  WindowsDriverMgr running at http://localhost:5000\n")
    app.run(debug=False, port=5000, use_reloader=False)
