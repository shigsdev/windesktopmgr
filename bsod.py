"""
bsod.py — BSOD / crash-analysis module for WinDesktopMgr.

Owns the full Blue-Screen-of-Death subsystem:

* Crash collection — Windows Event Log (IDs 1001/41/6008) + SystemHealthDiag
  HTML report parsing.
* Crash analysis — dedup, 12-week timeline, error-code / faulty-driver
  breakdowns, uptime-between-crashes, and the dashboard summary.
* Self-learning stop-code lookup — static KB → on-disk cache → Windows
  bugcheck table → Microsoft Learn search, drained by a background worker.

Extracted from windesktopmgr.py (backlog #54, production-file split — the
first prod blueprint extraction after the disk/homenet/remediation/nlq
modules). No behaviour changes: every function is a verbatim relocation.

Circular-import note: ``get_bsod_events`` lazy-imports the shared event-log
helpers from windesktopmgr at call time. windesktopmgr imports the public
BSOD symbols from this module at top level; doing the event-log import lazily
breaks the cycle AND keeps ``mocker.patch("windesktopmgr._query_event_log_xpath")``
effective (the name is resolved per-call, after the patch is applied).
"""

from __future__ import annotations

import glob
import json
import os
import queue
import re
import threading
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BSOD_CACHE_FILE = os.path.join(APP_DIR, "bsod_code_cache.json")
REPORT_DIR = os.path.join(APP_DIR, "System Health Reports")


# ══════════════════════════════════════════════════════════════════════════════
# LOCAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# _parse_ts / _is_this_month / _insight are duplicated from windesktopmgr (the
# disk.py extraction pattern). _parse_ts has 20+ non-BSOD callers that keep the
# windesktopmgr copy; duplicating the trivial body here avoids a circular import.


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


def _insight(level: str, text: str, action: str = "") -> dict:
    """Insight dict constructor — local copy of the windesktopmgr helper."""
    return {"level": level, "text": text, "action": action}


# ══════════════════════════════════════════════════════════════════════════════
# BSOD CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

BUGCHECK_CODES = {
    "0x0000000a": "IRQL_NOT_LESS_OR_EQUAL",
    "0x0000001e": "KMODE_EXCEPTION_NOT_HANDLED",
    "0x00000024": "NTFS_FILE_SYSTEM",
    "0x0000002e": "DATA_BUS_ERROR",
    "0x0000003b": "SYSTEM_SERVICE_EXCEPTION",
    "0x0000003d": "INTERRUPT_EXCEPTION_NOT_HANDLED",
    "0x00000044": "MULTIPLE_IRP_COMPLETE_REQUESTS",
    "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA",
    "0x00000051": "REGISTRY_ERROR",
    "0x00000074": "BAD_SYSTEM_CONFIG_INFO",
    "0x0000007a": "KERNEL_DATA_INPAGE_ERROR",
    "0x0000007c": "BUGCODE_NDIS_DRIVER",
    "0x0000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "0x0000007f": "UNEXPECTED_KERNEL_MODE_TRAP",
    "0x00000080": "NMI_HARDWARE_FAILURE",
    "0x0000008e": "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    "0x0000009f": "DRIVER_POWER_STATE_FAILURE",
    "0x000000a5": "ACPI_BIOS_ERROR",
    "0x000000b8": "ATTEMPTED_SWITCH_FROM_DPC",
    "0x000000be": "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    "0x000000c4": "DRIVER_VERIFIER_DETECTED_VIOLATION",
    "0x000000c5": "DRIVER_CORRUPTED_EXPOOL",
    "0x000000d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "0x000000d8": "DRIVER_USED_EXCESSIVE_PTES",
    "0x000000ea": "THREAD_STUCK_IN_DEVICE_DRIVER",
    "0x000000ef": "CRITICAL_PROCESS_DIED",
    "0x000000f4": "CRITICAL_OBJECT_TERMINATION",
    "0x000000fe": "BUGCODE_USB_DRIVER",
    "0x00000101": "CLOCK_WATCHDOG_TIMEOUT",
    "0x00000109": "CRITICAL_STRUCTURE_CORRUPTION",
    "0x0000010d": "WDF_VIOLATION",
    "0x0000010e": "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
    "0x00000116": "VIDEO_TDR_FAILURE",
    "0x00000117": "VIDEO_TDR_TIMEOUT_DETECTED",
    "0x00000119": "VIDEO_SCHEDULER_INTERNAL_ERROR",
    "0x0000011a": "EM_INITIALIZATION_FAILURE",
    "0x0000011c": "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE",
    "0x00000124": "WHEA_UNCORRECTABLE_ERROR",
    "0x00000127": "PAGE_NOT_ZERO",
    "0x0000012b": "FAULTY_HARDWARE_CORRUPTED_PAGE",
    "0x0000012e": "INVALID_MDL_RANGE",
    "0x00000133": "DPC_WATCHDOG_VIOLATION",
    "0x00000139": "KERNEL_SECURITY_CHECK_FAILURE",
    "0x0000013a": "KERNEL_MODE_HEAP_CORRUPTION",
    "0x00000144": "BUGCODE_USB3_DRIVER",
    "0x00000154": "UNEXPECTED_STORE_EXCEPTION",
    "0x00000156": "WINSOCK_DETECTED_HUNG_CLOSESOCKET_LIVEDUMP",
    "0x0000015b": "WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE",
    "0x00000175": "PREVIOUS_FATAL_ABNORMAL_RESET_ERROR",
    "0x0000017e": "MICROCODE_REVISION_MISMATCH",
    "0x00000187": "VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD",
    "0x00000191": "PF_DETECTED_CORRUPTION",
    "0x000001c4": "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP",
    "0x000001c5": "IO_THREADPOOL_DEADLOCK_LIVEDUMP",
    "0x000001c6": "FAST_ERESOURCE_PRECONDITION_VIOLATION",
    "0x000001c8": "MANUALLY_INITIATED_POWER_BUTTON_HOLD",
    "0x000001ca": "SYNTHETIC_WATCHDOG_TIMEOUT",
    "0x000001cb": "INVALID_SILO_DETACH",
    "0x000001cd": "INVALID_CALLBACK_STACK_ADDRESS",
    "0x000001ce": "INVALID_KERNEL_STACK_ADDRESS",
    "0x000001cf": "HARDWARE_WATCHDOG_TIMEOUT",
    "0x000001d0": "CPI_FIRMWARE_WATCHDOG_TIMEOUT",
    "0x000001d1": "TELEMETRY_ASSERTS_LIVEDUMP",
    "0x00020001": "HYPERVISOR_ERROR",
    "0x1000000a": "IRQL_NOT_LESS_OR_EQUAL",
    "0x1000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
    "0x1000008e": "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
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

# Known driver → human-readable context mapping for enriched advice
DRIVER_CONTEXT = {
    "intelppm.sys": (
        "Intel CPU power management driver",
        "Disable C-States in BIOS and Memory Integrity in Core Isolation.",
    ),
    "ntoskrnl.exe": (
        "Windows kernel",
        "Run sfc /scannow in an Admin PowerShell to repair system files. If crashes continue, run Dell SupportAssist memory diagnostics from the Start menu.",
    ),
    "win32k.sys": ("Windows GUI subsystem", "Update display drivers and check for Windows updates."),
    "nvlddmkm.sys": ("NVIDIA display driver", "Update or clean-reinstall NVIDIA drivers via DDU."),
    "atikmdag.sys": ("AMD display driver", "Update or clean-reinstall AMD drivers via DDU."),
    "igdkmd64.sys": ("Intel integrated graphics driver", "Update Intel graphics drivers from Intel's website."),
    "tcpip.sys": ("Windows TCP/IP stack", "Run: netsh winsock reset and netsh int ip reset, then reboot."),
    "ndis.sys": ("Windows network driver interface", "Update network adapter drivers from Device Manager."),
    "storport.sys": ("Storage port driver", "Check disk health in Disk Health tab. Update storage drivers."),
    "iastora.sys": (
        "Intel Rapid Storage Technology driver",
        "Update Intel RST drivers from Dell Support or Intel's site.",
    ),
    "klif.sys": ("Kaspersky antivirus driver", "Update or temporarily disable Kaspersky to test stability."),
    "mfehidk.sys": ("McAfee security driver", "Update or temporarily disable McAfee to test stability."),
    "aswsnx.sys": ("Avast antivirus driver", "Update or temporarily disable Avast to test stability."),
    "dxgmms2.sys": ("DirectX graphics MMS", "Update display drivers. Check GPU temps under load."),
    "wdf01000.sys": ("Windows Driver Framework", "Check Device Manager for driver errors and update all drivers."),
    "hidclass.sys": ("HID USB class driver", "Disconnect and reconnect USB devices. Update USB/chipset drivers."),
}


# ══════════════════════════════════════════════════════════════════════════════
# BSOD ANALYSIS HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def get_bsod_events() -> list:
    """Query Windows Event Log for crash-related events (IDs 1001, 41, 6008)."""
    # Lazy import breaks the windesktopmgr <-> bsod cycle and keeps
    # mocker.patch("windesktopmgr._query_event_log_xpath") effective.
    from windesktopmgr import _build_evt_xpath, _query_event_log_xpath

    try:
        rows = _query_event_log_xpath(
            "System",
            _build_evt_xpath(ids=[1001, 41, 6008]),
            max_events=180,  # 60 per ID × 3 IDs, matching the legacy PS loop cap
            timeout_s=30.0,
        )
        # Map helper output → legacy PS key names expected by parse_event() consumers
        return [
            {
                "EventId": e["Id"],
                "TimeCreated": e["TimeCreated"],
                "ProviderName": e["ProviderName"],
                "Message": e["Message"],
            }
            for e in rows
        ]
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
    """
    Build per-stop-code recommendations enriched with driver context.
    Uses get_stop_code_info which checks static KB → cache → background lookup.
    """
    recs = []
    pending = []  # codes still being looked up

    # Group crashes by error code, keep top faulty driver per code
    error_counts = Counter(c["error_code"] for c in crashes)
    code_drivers = {}  # error_code -> most common faulty driver
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
            recs.append(
                {
                    "priority": "high",
                    "count": count,
                    "title": f"{code} — looking up details…",
                    "detail": f"Fetching description for stop code {hex_code} in the background. "
                    f"Refresh in a few seconds.",
                    "driver_context": f"Faulty driver: {top_driver}" if top_driver else "",
                    "source": "pending",
                }
            )
            continue

        rec = {
            "priority": info.get("priority", "high"),
            "count": count,
            "title": info.get("title", code),
            "detail": info.get("detail", ""),
            "action": info.get("action", ""),
            "driver_context": info.get("driver_context", ""),
            "source": info.get("source", ""),
        }
        # Prepend driver context to detail if present
        if rec["driver_context"] and rec["driver_context"] not in rec["detail"]:
            rec["detail"] = rec["driver_context"] + " " + rec["detail"]
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
                "source": "static_kb",
            }
        )
    elif total > 10:
        recs.append(
            {
                "priority": "critical",
                "count": total,
                "title": f"High crash frequency — {total} crashes detected",
                "detail": "This level of instability warrants immediate attention. "
                "Run Dell SupportAssist (search for it in the Start menu) to check for hardware faults. "
                "If crashes persist, RAM could be the cause — Dell SupportAssist includes a memory test, "
                "or you can boot from a USB with MemTest86 (free tool from memtest86.com that tests RAM "
                "before Windows loads, bypassing any OS interference).",
                "source": "static_kb",
            }
        )
    elif total >= 3:
        recs.append(
            {
                "priority": "high",
                "count": total,
                "title": f"Recurring crashes — {total} events found",
                "detail": "Review the faulty drivers below and check the Driver Manager tab for pending updates.",
                "source": "static_kb",
            }
        )

    if "HYPERVISOR_ERROR" in error_counts:
        recs.append(
            {
                "priority": "high",
                "count": error_counts["HYPERVISOR_ERROR"],
                "title": "i9-14900K Raptor Lake Instability — BIOS 2.22.0 includes microcode fix",
                "detail": "HYPERVISOR_ERROR on this CPU is caused by intelppm.sys conflicting with "
                "Hyper-V during C-State transitions. BIOS 2.22.0 (Jan 2026) includes Intel "
                "microcode patches for this. Your BIOS is current — focus on C-State and "
                "Memory Integrity settings if crashes continue.",
                "source": "static_kb",
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


def summarize_bsod(data: dict) -> dict:
    summary = data.get("summary", {})
    crashes = data.get("crashes", [])
    total = summary.get("total_crashes", 0)
    month = summary.get("this_month", 0)
    avg_up = summary.get("avg_uptime_hours", 0)
    timeline = data.get("timeline", [])
    insights = []
    actions = []

    if total == 0:
        insights.append(_insight("ok", "No crashes found in the Event Log or health reports. System looks stable."))
        return {
            "status": "ok",
            "headline": "System stable — no crashes detected",
            "insights": insights,
            "actions": actions,
        }

    # ── Frequency ────────────────────────────────────────────────────────────
    if month > 3:
        insights.append(
            _insight(
                "critical",
                f"{month} crashes this month — system is actively unstable.",
                "Address the root cause immediately using the recommendations below.",
            )
        )
        actions.append("Review recommendations below")
    elif month > 0:
        insights.append(_insight("warning", f"{month} crash(es) this month."))

    # ── Per stop code enriched insight ───────────────────────────────────────
    error_counts = Counter(c["error_code"] for c in crashes)
    code_drivers = {}
    for c in crashes:
        ec, fd = c.get("error_code", ""), c.get("faulty_driver", "")
        if fd:
            code_drivers.setdefault(ec, Counter())[fd] += 1

    pending_codes = []
    for code, cnt in error_counts.most_common(5):
        hex_code = next((h for h, n in BUGCHECK_CODES.items() if n == code), code)
        top_driver = ""
        if code in code_drivers:
            top_driver = code_drivers[code].most_common(1)[0][0]

        info = get_stop_code_info(hex_code, top_driver)
        if info is None:
            pending_codes.append(code)
            continue

        level = "critical" if cnt >= 5 else "warning"
        src_tag = f" [{info.get('source', '')}]" if info.get("source", "") not in ("static_kb", "") else ""
        drv_note = f" Faulty driver: {top_driver}." if top_driver else ""
        insights.append(
            _insight(
                level,
                f"{code}{src_tag} — {info.get('title', code)} — {cnt}x.{drv_note} {info.get('detail', '')}",
                info.get("action", ""),
            )
        )
        if info.get("action"):
            actions.append(info["action"][:80])

    if pending_codes:
        insights.append(
            _insight(
                "info",
                f"Fetching details for {len(pending_codes)} stop code(s) in background "
                f"({', '.join(pending_codes[:3])}). Refresh in a few seconds.",
                "",
            )
        )

    # ── Uptime / stability ────────────────────────────────────────────────────
    if avg_up > 0 and avg_up < 24:
        insights.append(
            _insight(
                "critical",
                f"Average uptime between crashes: {avg_up}h — very unstable.",
                "Run Dell SupportAssist from the Start menu — it includes built-in hardware diagnostics including memory testing.",
            )
        )
    elif avg_up > 0:
        insights.append(_insight("info", f"Average uptime between crashes: {avg_up}h."))

    # ── Trend ─────────────────────────────────────────────────────────────────
    if len(timeline) >= 4:
        recent = sum(w["count"] for w in timeline[-2:])
        prior = sum(w["count"] for w in timeline[-4:-2])
        if recent > prior and recent > 0:
            insights.append(_insight("warning", "Crash frequency is trending upward — system is getting less stable."))
        elif prior > recent and prior > 0:
            insights.append(_insight("ok", "Crash frequency is trending downward — good sign."))

    status = (
        "critical"
        if any(i["level"] == "critical" for i in insights)
        else "warning"
        if any(i["level"] == "warning" for i in insights)
        else "ok"
    )
    headline = (
        f"{month} crash(es) this month — {total} total" if month else f"{total} total crash(es) — none this month"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": list(dict.fromkeys(actions))[:4]}


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

_bsod_cache_lock = threading.Lock()
_bsod_cache: dict = {}
_bsod_queue: queue.Queue = queue.Queue()
_bsod_in_flight: set = set()


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
    """Look up a stop code name from the BUGCHECK_CODES dict (no subprocess needed)."""
    name = BUGCHECK_CODES.get(code_norm.lower())
    if name:
        return {
            "source": "windows_bugcheck_table",
            "name": name,
            "title": name.replace("_", " ").title(),
            "detail": f"Stop code {code_norm.upper()} — {name}. "
            f"This is a Windows kernel bugcheck. "
            f"Check the faulty driver in the crash details above for root cause.",
            "priority": "high",
            "action": "Minidump files are saved to C:\\Windows\\Minidump and are analysed automatically by the BSOD Dashboard tab. For manual deep analysis, WinDbg (Microsoft's free crash analyser, available from the Microsoft Store) can open these files directly. "
            "Check Driver Manager tab for updates to the faulty driver.",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    return None


def _lookup_stop_code_web(code_norm: str) -> dict | None:
    """Search Microsoft Learn for the stop code."""
    try:
        # Use the stop code name if we can derive it, otherwise use hex
        query = urllib.parse.quote(f"bug check {code_norm} stop code windows bsod")
        url = f"https://learn.microsoft.com/api/search?search={query}&locale=en-us&%24top=3&facet=products"
        req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
        if not results:
            return None
        top = results[0]
        title = top.get("title", f"Stop Code {code_norm}")
        summary = (top.get("summary") or "")[:350]
        url_ref = top.get("url", "https://learn.microsoft.com")
        return {
            "source": "microsoft_learn",
            "title": title,
            "detail": summary or f"See Microsoft documentation for stop code {code_norm}.",
            "priority": "high",
            "action": f"Full details: {url_ref}",
            "fetched": datetime.now(timezone.utc).isoformat(),
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
                    "source": "unknown",
                    "title": f"Stop Code {code_norm.upper()}",
                    "detail": "No description found. This may be a rare or hardware-specific stop code.",
                    "priority": "high",
                    "action": f"Search: https://learn.microsoft.com/search/?terms={urllib.parse.quote(code_norm)}+stop+code",
                    "fetched": datetime.now(timezone.utc).isoformat(),
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
                    with _bsod_cache_lock:
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
                rec["driver_context"] = f"Faulty driver: {faulty_driver} ({drv_desc}). {drv_action}"
                break
        rec["source"] = "static_kb"
        rec["name"] = name
        return rec

    # 2. Cache
    with _bsod_cache_lock:
        if code_norm in _bsod_cache:
            cached = dict(_bsod_cache[code_norm])
            # Enrich cached entry with driver context
            drv_lower = faulty_driver.lower()
            for drv_key, (drv_desc, drv_action) in DRIVER_CONTEXT.items():
                if drv_key in drv_lower:
                    cached["driver_context"] = f"Faulty driver: {faulty_driver} ({drv_desc}). {drv_action}"
                    break
            return cached

    # 3. Queue background lookup
    with _bsod_cache_lock:
        if code_norm not in _bsod_in_flight:
            _bsod_in_flight.add(code_norm)
            _bsod_queue.put(code_norm)

    return None  # Not ready yet


def get_bsod_cache_status() -> dict:
    with _bsod_cache_lock:
        cached = dict(_bsod_cache)
    return {
        "total_cached": len(cached),
        "queue_pending": _bsod_queue.qsize(),
        "in_flight": len(_bsod_in_flight),
        "cache_file": BSOD_CACHE_FILE,
        "entries": [
            {"code": k, "title": v.get("title", "?"), "source": v.get("source", "?"), "fetched": v.get("fetched", "")}
            for k, v in list(cached.items())[:50]
        ],
    }


def delete_cached_code(code: str) -> dict:
    """Remove a single stop code from the cache (backs DELETE /api/bsod/cache/delete)."""
    key = _normalise_stop_code(code)
    with _bsod_cache_lock:
        removed = key in _bsod_cache
        _bsod_cache.pop(key, None)
    if removed:
        _save_bsod_cache()
    return {"ok": True, "removed": removed, "code": key}


def clear_cache() -> dict:
    """Empty the entire stop-code cache (backs POST /api/bsod/cache/clear)."""
    with _bsod_cache_lock:
        _bsod_cache.clear()
    _save_bsod_cache()
    return {"ok": True}
