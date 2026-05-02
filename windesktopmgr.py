"""
WinDesktopMgr
Flask backend — driver update checker + BSOD trend dashboard.
Reads from Windows Event Log and existing SystemHealthDiag HTML reports.
"""

import glob
import json
import locale
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import winreg
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone

import psutil
import pythoncom
import win32api
import win32evtlog
import win32service
import win32serviceutil
import wmi
from flask import Flask, jsonify, make_response, render_template, request, send_from_directory

from applogging import get_logger
from disk import disk_bp, get_disk_health, summarize_disk
from homenet import homenet_bp, homenet_get_inventory
from nlq import nlq_bp
from nlq import register_tool_dispatch as _nlq_register_tool_dispatch
from remediation import (
    _nlq_get_remediation_history,
    _nlq_run_remediation,
    remediation_bp,
)

_ps_log = get_logger("ps")

# ─── Headless mode: suppress console windows for subprocess calls ─────────────
# When running via tray.py (pythonw.exe), PowerShell subprocess calls would
# flash console windows. This flag is set by tray.py before start_server().
HEADLESS_MODE = False

_original_subprocess_run = subprocess.run


def _summarize_cmd(args) -> str:
    """Return a short string describing the subprocess command for logging."""
    try:
        text = " ".join(str(a) for a in args) if isinstance(args, (list, tuple)) else str(args)
    except Exception:  # noqa: BLE001
        return "<unprintable cmd>"
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > 200:
        text = text[:197] + "..."
    return text


def _caller_info(depth: int = 3) -> str:
    """Return 'file:line (func)' for the Python frame that invoked subprocess.run.

    depth=3 skips _caller_info, _headless_subprocess_run, and subprocess.run.
    Used to label PS log entries with the actual call site inside windesktopmgr.
    """
    try:
        frame = sys._getframe(depth)
        filename = os.path.basename(frame.f_code.co_filename)
        return f"{filename}:{frame.f_lineno} ({frame.f_code.co_name})"
    except Exception:  # noqa: BLE001
        return "?"


def _headless_subprocess_run(*args, **kwargs):
    """Wrapper that adds CREATE_NO_WINDOW flag when in headless/tray mode
    and logs every subprocess call via the windesktopmgr.ps logger.

    Logged fields per call:
        caller   -- file:line (function) that invoked subprocess.run
        cmd      -- short summary of the command (max 200 chars)
        timeout  -- the kwarg timeout if set
        rc       -- process returncode
        elapsed  -- wall-clock duration in ms
        bytes    -- stdout size on success
        stderr   -- first 200 chars of stderr on failure
    """
    if HEADLESS_MODE and os.name == "nt" and "creationflags" not in kwargs:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    # Opt-in: callers that legitimately expect timeouts (e.g. nbtstat on a
    # wireless device that's asleep) can pass quiet_timeout=True to downgrade
    # the TIMEOUT log from ERROR to DEBUG — keeps the selftest log-error
    # gate meaningful instead of noisy.
    quiet_timeout = kwargs.pop("quiet_timeout", False)

    cmd = args[0] if args else kwargs.get("args", "")
    cmd_summary = _summarize_cmd(cmd)
    timeout = kwargs.get("timeout", "-")
    caller = _caller_info()
    start = time.time()
    try:
        result = _original_subprocess_run(*args, **kwargs)
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.time() - start) * 1000)
        log_fn = _ps_log.debug if quiet_timeout else _ps_log.error
        log_fn(
            "TIMEOUT after=%dms limit=%ss caller=%s cmd=%s",
            elapsed_ms,
            timeout,
            caller,
            cmd_summary,
        )
        raise
    except Exception as e:  # noqa: BLE001
        elapsed_ms = int((time.time() - start) * 1000)
        _ps_log.error(
            "EXCEPTION after=%dms caller=%s cmd=%s exc=%s: %s",
            elapsed_ms,
            caller,
            cmd_summary,
            type(e).__name__,
            e,
        )
        raise

    elapsed_ms = int((time.time() - start) * 1000)
    rc = getattr(result, "returncode", 0)
    stdout = getattr(result, "stdout", "") or ""
    stdout_bytes = len(stdout.encode("utf-8", errors="replace")) if isinstance(stdout, str) else len(stdout or b"")

    if rc == 0:
        _ps_log.debug(
            "rc=0 elapsed=%dms bytes=%d caller=%s cmd=%s",
            elapsed_ms,
            stdout_bytes,
            caller,
            cmd_summary,
        )
    else:
        stderr = getattr(result, "stderr", "") or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stderr_snip = stderr.strip().replace("\n", " ")[:200]
        _ps_log.warning(
            "rc=%s elapsed=%dms bytes=%d caller=%s cmd=%s stderr=%s",
            rc,
            elapsed_ms,
            stdout_bytes,
            caller,
            cmd_summary,
            stderr_snip or "<empty>",
        )
    return result


subprocess.run = _headless_subprocess_run

app = Flask(__name__)
APP_DIR = os.path.dirname(os.path.abspath(__file__))
EVENT_CACHE_FILE = os.path.join(APP_DIR, "event_id_cache.json")
BSOD_CACHE_FILE = os.path.join(APP_DIR, "bsod_code_cache.json")

# ─── Driver checker state ─────────────────────────────────────────────────────
_dell_cache = None
_scan_results = None
_scan_status = {"status": "idle", "progress": 0, "message": "Ready to scan"}

# ─── Driver category keywords ─────────────────────────────────────────────────
CATEGORIES = {
    "Display": ["display", "video", "graphics", "gpu", "nvidia", "amd radeon", "intel uhd", "intel arc", "vga"],
    "Monitor": ["monitor", "ips", "led backlit", "pavilion", "lcd", "oled", "curved monitor", "widescreen"],
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


# ─── BSOD constants ───────────────────────────────────────────────────────────
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "System Health Reports")

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


# ── WMI helpers ───────────────────────────────────────────────────────────────
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


def _wmi_date_to_str(wmi_date: str, fmt: str = "%Y-%m-%d") -> str:
    """Parse WMI datetime (20260621000000.000000+000) to formatted string."""
    if not wmi_date or len(wmi_date) < 8:
        return "Unknown"
    try:
        return datetime.strptime(wmi_date[:14], "%Y%m%d%H%M%S").strftime(fmt)
    except Exception:
        return wmi_date[:8]


def _wmi_conn():
    """Create a WMI connection with COM initialized for the current thread.

    Flask runs requests in worker threads where COM is not initialized.
    wmi.WMI() uses COM under the hood (win32com.client.GetObject) and will
    deadlock or fail if CoInitialize hasn't been called on the thread.
    """
    pythoncom.CoInitialize()
    return wmi.WMI()


def get_installed_drivers() -> list:
    try:
        c = _wmi_conn()
        result = []
        for d in c.Win32_PnPSignedDriver():
            if d.DeviceName and d.DriverVersion:
                result.append(
                    {
                        "DeviceName": d.DeviceName,
                        "DriverVersion": d.DriverVersion,
                        "DriverDate": d.DriverDate or "",
                        "DeviceClass": d.DeviceClass or "",
                        "Manufacturer": d.Manufacturer or "",
                    }
                )
        return result
    except Exception as e:
        print(f"[WMI error] {e}")
        return []


def get_driver_health() -> dict:
    """Lightweight driver health check for the dashboard.

    Returns dict with:
        old_drivers: list of 3rd-party drivers >2 years old
        problematic_drivers: list of devices with ConfigManager errors
        nvidia: dict with GPU driver info and update state (or None)
    """
    _ms_providers = ("Microsoft", "Microsoft Windows", "Microsoft Corporation")
    cutoff = datetime.now() - timedelta(days=730)  # ~2 years
    old = []
    prob = []
    try:
        c = _wmi_conn()
        for d in c.Win32_PnPSignedDriver():
            if not d.DriverVersion:
                continue
            provider = d.DriverProviderName or ""
            if any(ms in provider for ms in _ms_providers):
                continue
            if not provider:
                continue
            raw_date = d.DriverDate or ""
            if raw_date and len(raw_date) >= 8:
                try:
                    drv_dt = datetime.strptime(raw_date[:8], "%Y%m%d")
                    if drv_dt < cutoff:
                        old.append(
                            {
                                "DeviceName": d.DeviceName or "",
                                "Provider": provider,
                                "Version": d.DriverVersion,
                                "Date": drv_dt.strftime("%Y-%m-%d"),
                            }
                        )
                except Exception:
                    pass

        for ent in c.Win32_PnPEntity():
            err_code = ent.ConfigManagerErrorCode
            if err_code is not None and err_code != 0:
                prob.append(
                    {
                        "DeviceName": ent.Name or "",
                        "ErrorCode": int(err_code),
                        "Status": ent.Status or "",
                    }
                )
    except Exception as e:
        print(f"[DriverHealth] {e}")

    # NVIDIA update check via Python (API + fallback) — no extra PS overhead
    nvidia = get_nvidia_update_info()
    return {"old_drivers": old, "problematic_drivers": prob, "nvidia": nvidia}


def _win_to_nvidia_version(win_ver: str) -> str:
    """Convert Windows driver version to NVIDIA short format.

    Windows: 32.0.15.9174  →  NVIDIA: 591.74
    Formula: concatenate parts[2]+parts[3], drop first char, insert dot before last 2.
    """
    parts = win_ver.split(".")
    if len(parts) < 4:
        return win_ver
    raw = parts[2] + parts[3]  # e.g. "159174"
    if len(raw) < 3:
        return win_ver
    raw = raw[1:]  # drop first char → "59174"
    return raw[:-2] + "." + raw[-2:]  # "591.74"


def _get_nvidia_gpu_info() -> dict | None:
    """Detect NVIDIA GPU name and installed driver version via nvidia-smi or WMI.

    Returns dict with 'name', 'installed', 'win_ver' or None if no NVIDIA GPU.
    """
    gpu_name = ""
    nv_short = ""
    win_ver = ""

    # Try nvidia-smi first for accurate name + NVIDIA short version
    nvsmi_path = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "nvidia-smi.exe")
    try:
        if os.path.exists(nvsmi_path):
            r = subprocess.run(
                [nvsmi_path, "--query-gpu=name,driver_version", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                fields = r.stdout.strip().split(",")
                if len(fields) >= 2:
                    gpu_name = fields[0].strip()
                    nv_short = fields[1].strip()
    except Exception:
        pass

    # Get Windows driver version from WMI
    try:
        c = _wmi_conn()
        for vc in c.Win32_VideoController():
            if vc.Name and "NVIDIA" in vc.Name.upper():
                win_ver = vc.DriverVersion or ""
                if not gpu_name:
                    gpu_name = vc.Name
                break
    except Exception:
        pass

    if not gpu_name:
        return None

    # If nvidia-smi didn't give us the short version, derive it from Windows version
    if not nv_short and win_ver:
        nv_short = _win_to_nvidia_version(win_ver)

    return {"name": gpu_name, "installed": nv_short, "win_ver": win_ver}


def _gpu_metrics_blank(error: str | None = None) -> dict:
    """Shared empty-result factory so every exit path returns the same shape."""
    return {
        "available": False,
        "source": None,
        "name": "",
        "utilization_pct": None,
        "vram_memctrl_pct": None,
        "vram_used_mb": None,
        "vram_total_mb": None,
        "vram_pct": None,
        "temp_c": None,
        "power_w": None,
        "error": error,
    }


def get_gpu_metrics() -> dict:
    """Collect runtime GPU metrics for the Trends card (backlog #37).

    Python-first: uses the ``pynvml`` package (the official NVIDIA Python
    binding for NVML -- what ``nvidia-smi`` itself is built on). In-process
    C calls, no subprocess fork, ~50 ms on first init and microseconds
    thereafter -- vs the 200-500 ms cold start of shelling out to
    ``nvidia-smi.exe``. Falls through to an empty ``available=False`` dict
    on import failure, NVML-init failure, or no GPU present -- the
    dashboard fan-out treats an empty result as "no GPU signal to
    display" rather than an error.

    Requires the ``nvidia-ml-py`` pip package (import name ``pynvml``).
    Added to ``requirements.txt`` alongside this function.

    Returns:
        {
            "available": bool,
            "source": "pynvml" | None,
            "name": str,
            "utilization_pct":      float | None,  # 0-100 current load
            "vram_memctrl_pct":     float | None,  # memory controller
                                                    # throughput (NOT
                                                    # vram-used-%)
            "vram_used_mb":         float | None,
            "vram_total_mb":        float | None,
            "vram_pct":             float | None,  # computed: used/total
            "temp_c":               float | None,
            "power_w":              float | None,
            "error":                str | None,    # populated on failure
        }
    """
    try:
        import pynvml
    except ImportError as e:
        return _gpu_metrics_blank(f"pynvml not installed: {e}")

    try:
        pynvml.nvmlInit()
    except pynvml.NVMLError as e:
        # Most common causes: no NVIDIA driver, driver/library version
        # mismatch, no GPU in the machine. Surface the NVML error text so
        # the dashboard concern is actionable.
        return _gpu_metrics_blank(f"NVML init failed: {e}")

    try:
        count = pynvml.nvmlDeviceGetCount()
        if count == 0:
            return _gpu_metrics_blank("no NVIDIA GPU detected")

        # First card only -- multi-GPU rigs get the primary for now; a
        # follow-up could surface each card as its own series.
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)

        # Name: pynvml 12+ returns str; older versions return bytes.
        raw_name = pynvml.nvmlDeviceGetName(handle)
        name = raw_name.decode("utf-8", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)

        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)

        # Power is optional -- lower-tier cards / passthrough VMs can
        # return NVML_ERROR_NOT_SUPPORTED. Treat as "no signal" (None),
        # not an error for the whole collector.
        try:
            power_w: float | None = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
        except pynvml.NVMLError:
            power_w = None

        vram_used_mb = round(mem.used / (1024 * 1024), 1)
        vram_total_mb = round(mem.total / (1024 * 1024), 1)
        vram_pct = round(mem.used / mem.total * 100, 1) if mem.total else None

        return {
            "available": True,
            "source": "pynvml",
            "name": name,
            "utilization_pct": float(util.gpu),
            "vram_memctrl_pct": float(util.memory),
            "vram_used_mb": vram_used_mb,
            "vram_total_mb": vram_total_mb,
            "vram_pct": vram_pct,
            "temp_c": float(temp),
            "power_w": round(power_w, 1) if power_w is not None else None,
            "error": None,
        }
    except pynvml.NVMLError as e:
        return _gpu_metrics_blank(f"NVML query failed: {e}")
    except Exception as e:  # noqa: BLE001 -- defensive; pynvml surprises are survivable
        return _gpu_metrics_blank(f"unexpected GPU collector error: {type(e).__name__}: {e}")
    finally:
        # Best-effort -- if shutdown fails the next init will still work
        # (NVML is reference-counted internally).
        try:
            pynvml.nvmlShutdown()
        except Exception:  # noqa: BLE001
            pass


# Known GPU product family IDs for the NVIDIA driver lookup API.
# Resolved via https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=<series>
# Series 127 = GeForce RTX 40 Series (Desktop)
_NVIDIA_PFID_MAP: dict[str, int] = {
    "NVIDIA GeForce RTX 4090": 995,
    "NVIDIA GeForce RTX 4080 SUPER": 1041,
    "NVIDIA GeForce RTX 4080": 996,
    "NVIDIA GeForce RTX 4070 Ti SUPER": 1040,
    "NVIDIA GeForce RTX 4070 Ti": 1001,
    "NVIDIA GeForce RTX 4070 SUPER": 1039,
    "NVIDIA GeForce RTX 4070": 1015,
    "NVIDIA GeForce RTX 4060 Ti": 1022,
    "NVIDIA GeForce RTX 4060": 1023,
}

# NVIDIA AjaxDriverService API endpoint
_NVIDIA_DRIVER_API = "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php"


def _detect_nvidia_driver_branch() -> bool:
    """Detect whether the user is on Studio/CRD or Game Ready driver branch.

    Checks NVIDIA App's SHIM.json for IsCRD flag, falls back to True (Studio)
    since that's the safer default — offering Game Ready to a Studio user is wrong.

    Returns True for Studio/CRD, False for Game Ready.
    """
    try:
        import glob
        import os

        pattern = os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "NVIDIA Corporation",
            "NVIDIA app",
            "NvBackend",
            "SHIM.json",
        )
        matches = glob.glob(pattern)
        if matches:
            with open(matches[0]) as f:
                data = json.load(f)
            return data.get("IsCRD", True)
    except Exception:
        pass
    # Default to Studio — safer than offering Game Ready to Studio users
    return True


def _query_nvidia_api(pfid: int, *, studio: bool = True) -> dict | None:
    """Query NVIDIA's public driver API for the latest available driver.

    Args:
        pfid: Product Family ID (e.g. 1022 for RTX 4060 Ti)
        studio: True for Studio/CRD driver, False for Game Ready

    Returns dict with 'version', 'url', 'date', 'name' or None on failure.
    """
    params = {
        "func": "DriverManualLookup",
        "pfid": str(pfid),
        "osID": "57",  # Windows 10/11 64-bit
        "languageCode": "1033",
        "beta": "0",
        "isWHQL": "1",
        "dltype": "-1",
        "dch": "1",
        "upCRD": "1" if studio else "0",
        "qnf": "0",
        "sort1": "0",
        "numberOfResults": "1",
    }
    try:
        import urllib.parse
        import urllib.request

        url = _NVIDIA_DRIVER_API + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        if data.get("Success") != "1" or not data.get("IDS"):
            return None
        info = data["IDS"][0].get("downloadInfo", {})
        if info.get("Success") != "1":
            return None
        import urllib.parse as up

        return {
            "version": info.get("Version", ""),
            "url": up.unquote(info.get("DetailsURL", "")),
            "date": info.get("ReleaseDateTime", ""),
            "name": up.unquote(info.get("Name", "")),
        }
    except Exception as e:
        print(f"[NVIDIA API] {e}")
        return None


def get_nvidia_update_info() -> dict | None:
    """Check for NVIDIA GPU and pending driver updates.

    Detection priority:
    1. NVIDIA public API (real-time, works even if update not downloaded)
    2. Installer2 Cache registry (downloaded-but-not-installed)
    3. Windows Update (pending NVIDIA driver)

    Returns dict with InstalledVersion, LatestVersion, UpdateAvailable, Name
    or None if no NVIDIA GPU found.
    """
    gpu = _get_nvidia_gpu_info()
    if not gpu:
        return None

    installed = gpu["installed"]
    name = gpu["name"]
    latest = ""
    source = "none"

    # Detect driver branch (Studio/CRD vs Game Ready) from NVIDIA App data
    is_studio = _detect_nvidia_driver_branch()

    # Method 1: NVIDIA public API — real-time latest version check
    pfid = _NVIDIA_PFID_MAP.get(name)
    if pfid:
        api_result = _query_nvidia_api(pfid, studio=is_studio)
        # Do NOT fall back to the other branch — Game Ready 595.97 is not
        # a valid "update" for a Studio 595.79 user (different driver branches).
        if api_result and api_result.get("version"):
            latest = api_result["version"]
            source = "nvidia_api"

    # Method 2: Installer2 Cache (offline fallback) — pure Python via winreg
    if not latest:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\NVIDIA Corporation\Installer2\Cache",
            )
            max_ver = 0
            i = 0
            while True:
                try:
                    name_val, _val, _typ = winreg.EnumValue(key, i)
                    if name_val.startswith("Display.Driver/"):
                        ver_str = name_val.split("/")[1].replace(".", "")
                        try:
                            ver_num = int(ver_str)
                            if ver_num > max_ver:
                                max_ver = ver_num
                        except ValueError:
                            pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            if max_ver > 0:
                s = str(max_ver)
                cached_ver = s[:-2] + "." + s[-2:]
                if cached_ver != installed:
                    latest = cached_ver
                    source = "installer2_cache"
        except FileNotFoundError:
            pass
        except Exception:
            pass

    update_available = bool(latest and latest != installed)
    return {
        "Name": name,
        "InstalledVersion": installed,
        "WindowsVersion": gpu["win_ver"],
        "LatestVersion": latest,
        "UpdateAvailable": update_available,
        "UpdateSource": source,
    }


def get_windows_update_drivers() -> dict | None:
    """
    Use Windows Update API via PowerShell to find available driver updates.
    Returns a dict keyed by driver title (lowercase) -> update info, or None on failure.
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
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=120
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
    except subprocess.TimeoutExpired:
        print("[WU error] Windows Update driver search timed out (120s)")
        _dell_cache = {}
        return {}
    except Exception as e:
        print(f"[WU error] {e}")
        _dell_cache = None
        return None


def find_wu_match(name: str, wu_updates: dict | None) -> dict | None:
    """Fuzzy-match an installed driver name against Windows Update results."""
    if not wu_updates:
        return None
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
        "progress": 60,
        "message": f"Found {len(wu_updates or {})} WU driver update(s) — checking NVIDIA App…",
    }
    nvidia_info = get_nvidia_update_info()
    _scan_status = {
        "status": "scanning",
        "progress": 75,
        "message": "Comparing installed drivers against available updates…",
    }
    results = []
    for drv in installed:
        name = drv.get("DeviceName", "Unknown Device")
        version = drv.get("DriverVersion", "")
        drv_date = drv.get("DriverDate", "")
        dev_class = drv.get("DeviceClass", "")
        mfr = drv.get("Manufacturer", "")
        category = categorize(name, dev_class)

        is_nvidia = "nvidia" in name.lower()
        # GPU driver has a 4-part Windows version like 32.0.15.9579;
        # companion drivers (HD Audio, Virtual Audio) have different schemes.
        is_nvidia_gpu = (
            is_nvidia
            and len(version.split(".")) == 4
            and version.split(".")[0].isdigit()
            and int(version.split(".")[0]) >= 20
        )
        match = find_wu_match(name, wu_updates)
        status = "up_to_date"  # default: assume current if WU has no update
        latest_ver = None
        latest_date = None
        download_url = "ms-settings:windowsupdate"

        if is_nvidia and nvidia_info:
            # NVIDIA API is authoritative for all NVIDIA drivers. The entire
            # driver package (GPU + HD Audio + Virtual Audio) ships together,
            # so if the GPU driver is current, companion drivers are too.
            # WU doesn't distinguish Studio vs Game Ready, so skip WU for NVIDIA.
            if nvidia_info.get("UpdateAvailable"):
                status = "update_available"
                # Only show GPU version comparison for the GPU driver itself
                if is_nvidia_gpu:
                    latest_ver = nvidia_info.get("LatestVersion", "")
                download_url = "nvidia-app:"
            else:
                status = "up_to_date"
            # Convert version to NVIDIA short format only for GPU drivers
            if is_nvidia_gpu and version:
                nv_ver = _win_to_nvidia_version(version)
                if nv_ver != version:
                    version = nv_ver
        elif match:
            status = "update_available"
            latest_ver = match.get("DriverVersion") or match.get("Title", "")
        elif wu_updates is None:
            # WU query failed entirely — fall back to unknown
            status = "unknown"

        low_priority = category in LOW_PRIORITY_CATEGORIES
        cat_note = CATEGORY_NOTES.get(category, "")
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
                "low_priority": low_priority,
                "category_note": cat_note,
            }
        )

    order = {"update_available": 0, "unknown": 1, "up_to_date": 2}
    # Low-priority categories sort after normal updates even when update_available
    results.sort(
        key=lambda x: (
            order.get(x["status"], 3) + (10 if x.get("low_priority") and x["status"] == "update_available" else 0),
            x["name"].lower(),
        )
    )
    _scan_results = results
    updates = sum(1 for r in results if r["status"] == "update_available")
    _scan_status = {
        "status": "complete",
        "progress": 100,
        "message": f"Done — {len(results)} drivers scanned, {updates} update(s) via Windows Update",
    }


# ══════════════════════════════════════════════════════════════════════════════
# EVENT LOG QUERY HELPER (win32evtlog — replaces Get-WinEvent PS calls)
# ══════════════════════════════════════════════════════════════════════════════

_EVT_NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _build_evt_xpath(
    ids: list[int] | None = None,
    providers: list[str] | None = None,
    levels: list[int] | None = None,
) -> str:
    """
    Build an XPath filter for EvtQuery that selects by EventID / Provider / Level.
    Equivalent to the PowerShell ``-FilterHashtable`` fields ``Id=``, ``ProviderName=``,
    ``Level=``.
    """
    parts: list[str] = []
    if ids:
        id_part = " or ".join(f"EventID={int(i)}" for i in ids)
        parts.append(f"({id_part})")
    if providers:
        # XPath @Name attribute match on the Provider element
        prov_part = " or ".join(f"@Name='{p}'" for p in providers)
        parts.append(f"Provider[{prov_part}]")
    if levels:
        lvl_part = " or ".join(f"Level={int(lv)}" for lv in levels)
        parts.append(f"({lvl_part})")
    if not parts:
        return "*"
    return f"*[System[{' and '.join(parts)}]]"


def _query_event_log_xpath(
    log_name: str,
    xpath: str,
    max_events: int = 100,
    timeout_s: float = 20.0,
) -> list[dict]:
    """
    Query a Windows Event Log via pywin32 ``win32evtlog.EvtQuery`` + XPath filter.

    Drop-in replacement for ``Get-WinEvent -FilterHashtable`` PowerShell calls.
    Returns a list of dicts with keys matching the PS-era output shape:
    ``{"Id": int, "TimeCreated": str (ISO8601), "ProviderName": str,
        "Level": int, "Message": str}``

    Runs the query in a worker thread so it can be bounded by ``timeout_s``.
    Any failure (bad XPath, access denied, timeout) returns ``[]`` so callers
    can treat event-log errors as "no events" rather than crashing.
    """
    import concurrent.futures

    def _do_query() -> list[dict]:
        out: list[dict] = []
        try:
            h = win32evtlog.EvtQuery(
                log_name,
                win32evtlog.EvtQueryReverseDirection | win32evtlog.EvtQueryChannelPath,
                xpath,
            )
        except Exception as e:
            print(f"[_query_event_log_xpath] EvtQuery({log_name}) failed: {e}")
            return out

        remaining = max(1, int(max_events))
        while remaining > 0:
            batch_size = min(remaining, 100)
            try:
                batch = win32evtlog.EvtNext(h, batch_size)
            except Exception as e:
                print(f"[_query_event_log_xpath] EvtNext failed: {e}")
                break
            if not batch:
                break
            for evt in batch:
                try:
                    xml_str = win32evtlog.EvtFormatMessage(None, evt, win32evtlog.EvtFormatMessageXml)
                    # S314 suppression: the XML source is Windows Event Log
                    # Service serialisation (win32evtlog.EvtFormatMessage), not
                    # user-controlled input — no DTDs or external entities are
                    # possible. defusedxml is not required here.
                    root = ET.fromstring(xml_str)  # noqa: S314
                    eid_el = root.find(".//e:EventID", _EVT_NAMESPACE)
                    ts_el = root.find(".//e:TimeCreated", _EVT_NAMESPACE)
                    prov_el = root.find(".//e:Provider", _EVT_NAMESPACE)
                    level_el = root.find(".//e:Level", _EVT_NAMESPACE)
                    try:
                        eid = int((eid_el.text if eid_el is not None else "0") or "0")
                    except (TypeError, ValueError):
                        eid = 0
                    ts = ts_el.get("SystemTime", "") if ts_el is not None else ""
                    provider = prov_el.get("Name", "") if prov_el is not None else ""
                    try:
                        level = int(level_el.text) if level_el is not None and level_el.text else 0
                    except (TypeError, ValueError):
                        level = 0

                    # Render human-readable message via publisher metadata.
                    # Some providers are missing their message DLL — fall back to empty.
                    msg = ""
                    if provider:
                        try:
                            pub_meta = win32evtlog.EvtOpenPublisherMetadata(provider, None)
                            msg = win32evtlog.EvtFormatMessage(pub_meta, evt, win32evtlog.EvtFormatMessageEvent) or ""
                        except Exception:
                            msg = ""

                    out.append(
                        {
                            "Id": eid,
                            "TimeCreated": ts,
                            "ProviderName": provider,
                            "Level": level,
                            "Message": msg,
                        }
                    )
                except Exception:
                    # Skip malformed events rather than aborting the whole query
                    continue
            remaining -= len(batch)
        return out

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(_do_query)
        try:
            return future.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError:
            print(f"[_query_event_log_xpath] timeout after {timeout_s}s on {log_name}")
            return []
        except Exception as e:
            print(f"[_query_event_log_xpath] worker error on {log_name}: {e}")
            return []


# ══════════════════════════════════════════════════════════════════════════════
# BSOD ANALYSIS HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def get_bsod_events() -> list:
    """Query Windows Event Log for crash-related events (IDs 1001, 41, 6008)."""
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
# STARTUP MANAGER
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATTERNS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\downloads\\",
    r"[0-9a-f]{8,}\.exe",
    r"\\users\\public\\",
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
        "reason": "High memory use. Safe to disable if you don't need Teams immediately on login.",
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
        "reason": "Safe to disable if you don't need Slack notifications immediately on login.",
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
        "reason": "Safe to disable if you don't need constant Google Drive sync. Files sync when you relaunch it.",
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
        "what": "Dell's diagnostic and support tool — checks hardware health and manages driver updates.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "WinDesktopMgr covers the same ground. Safe to disable.",
    },
    "dellcommandupdate": {
        "plain_name": "Dell Command Update",
        "publisher": "Dell Inc.",
        "what": "Automatically checks for and installs Dell BIOS, driver, and firmware updates.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Useful for keeping Dell firmware current but runs fine on demand. Safe to disable from startup.",
    },
    "delldigitaldelivery": {
        "plain_name": "Dell Digital Delivery",
        "publisher": "Dell Inc.",
        "what": "Delivers software purchased with your Dell PC.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "disable",
        "reason": "Only needed when setting up a new Dell. Safe to disable on an established system.",
    },
    "realtek hd audio manager": {
        "plain_name": "Realtek HD Audio Manager",
        "publisher": "Realtek Semiconductor",
        "what": "Provides the system tray icon and settings UI for your Realtek audio hardware.",
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
        "what": "Background service for AMD Radeon Software — enables game optimisation and driver notifications.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Safe to disable if you don't use Radeon Software features.",
    },
    "ipoint": {
        "plain_name": "Microsoft IntelliPoint (Mouse Software)",
        "publisher": "Microsoft",
        "what": "Provides advanced settings for Microsoft mice — extra buttons, scroll speed, etc.",
        "impact": "low",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Basic mouse functions work without it. Only keep if you use advanced Microsoft mouse features.",
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
        "what": "Manages profiles, lighting, and macros for Logitech G-series peripherals.",
        "impact": "medium",
        "safe_to_disable": True,
        "recommendation": "optional",
        "reason": "Peripherals work at default settings without it. Disable if "
        "you don't use custom profiles or lighting.",
    },
    "razercentralservice": {
        "plain_name": "Razer Central",
        "publisher": "Razer Inc.",
        "what": "Background service for Razer Synapse — manages lighting and macros for Razer peripherals.",
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
        "reason": "This is WinDesktopMgr itself. Keep enabled to have your dashboard ready at login.",
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
    "keep": {"color": "var(--cyan)", "label": "Keep"},
    "optional": {"color": "var(--orange)", "label": "Optional"},
    "disable": {"color": "var(--red)", "label": "Disable"},
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
        # Try to find it on PATH via Get-Command (PS 5.1-compatible — no ?. operator)
        base = _extract_exe_from_command(command)
        if base:
            exe_name = base + ".exe"
            safe_name = re.sub(r"[^a-zA-Z0-9\-_. ]", "", exe_name)
            # Explicit `exit 0` is critical: Get-Command leaves $? = $false when
            # the exe is missing, even with -EA SilentlyContinue, and PowerShell
            # exits with code 1. That produced a warning for every unknown process.
            ps_find = (
                f'$ErrorActionPreference="SilentlyContinue"; '
                f'$c = Get-Command "{safe_name}" -EA SilentlyContinue; '
                f"if ($c) {{ $c.Source }}; exit 0"
            )
            try:
                r0 = subprocess.run(
                    ["powershell", "-NonInteractive", "-Command", ps_find],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                found = r0.stdout.strip()
                if found:
                    exe_path = found
            except Exception:  # noqa: BLE001
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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=10
        )
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc = (data.get("FileDescription") or "").strip()
        company = (data.get("CompanyName") or "").strip()
        product = (data.get("ProductName") or "").strip()
        version = (data.get("FileVersion") or "").strip()
        fname = (data.get("FileName") or name).strip()

        if not desc and not company:
            return None

        plain_name = product or desc or fname
        what = desc if desc else f"Executable from {company or 'unknown publisher'}."
        # Heuristic: Microsoft/Windows components are generally safe to keep
        is_ms = any(kw in company.lower() for kw in ("microsoft", "windows"))
        is_system = any(p in exe_path.lower() for p in ("\\windows\\", "\\system32\\", "\\syswow64\\", "\\winsxs\\"))
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
            reason = (
                f"Third-party application by {company or 'unknown publisher'}. Review whether you need it at login."
            )

        return {
            "source": "file_version_info",
            "plain_name": plain_name,
            "publisher": company or "Unknown",
            "what": what,
            "version": version,
            "impact": "low",
            "safe_to_disable": safe,
            "recommendation": rec,
            "reason": reason,
            "fetched": datetime.now(timezone.utc).isoformat(),
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
            q = urllib.parse.quote(raw_q)
            url = f"https://learn.microsoft.com/api/search?search={q}&locale=en-us&%24top=3&facet=products"
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top = results[0]
            title = top.get("title", "").strip()
            summary = (top.get("summary") or "").strip()[:300]
            url_ref = top.get("url", "")
            # Filter out irrelevant results (e.g. generic Windows docs)
            skip_terms = ("visual studio", "azure", "powershell module", "api reference", "net framework class")
            if any(t in title.lower() for t in skip_terms):
                continue
            if not summary:
                continue
            return {
                "source": "microsoft_learn",
                "plain_name": title or item_name,
                "publisher": "See details",
                "what": summary,
                "impact": "unknown",
                "safe_to_disable": True,
                "recommendation": "optional",
                "reason": f"Based on web lookup. Full details: {url_ref}",
                "url": url_ref,
                "fetched": datetime.now(timezone.utc).isoformat(),
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
                command = ""
                name = raw  # use the key as the display name
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
                    "source": "unknown",
                    "plain_name": name,
                    "publisher": "Unknown",
                    "what": "No description found via file info or web search.",
                    "impact": "unknown",
                    "safe_to_disable": True,
                    "recommendation": "optional",
                    "reason": f'Research this item before disabling: search "{name} startup windows" online.',
                    "fetched": datetime.now(timezone.utc).isoformat(),
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
                    with _startup_cache_lock:
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
    with _startup_cache_lock:
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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=30
        )
        data = json.loads(r.stdout.strip() or "[]")
        items = data if isinstance(data, list) else [data]
        for item in items:
            cmd = (item.get("Command") or "").lower()
            item["suspicious"] = any(re.search(p, cmd) for p in SUSPICIOUS_PATTERNS)
            # Attach enrichment info (may be None if still pending)
            info = get_startup_item_info(item.get("Name", ""), item.get("Command", ""))
            item["info"] = info

        # Sort: suspicious first, then by recommendation priority, then name
        rec_order = {"disable": 0, "optional": 1, "keep": 2, None: 3}
        items.sort(
            key=lambda x: (
                not x.get("suspicious", False),
                rec_order.get((x.get("info") or {}).get("recommendation"), 3),
                x.get("Name", "").lower(),
            )
        )
        return items
    except Exception as e:
        print(f"[Startup error] {e}")
        return []


def toggle_startup_item(name: str, item_type: str, enable: bool) -> dict:
    safe_name = re.sub(r"[^a-zA-Z0-9\-_. ]", "", name).strip()
    if item_type in ("registry_hklm", "registry_hkcu"):
        hive = "HKLM" if item_type == "registry_hklm" else "HKCU"
        src = f"{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        dst = f"{hive}:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run-Disabled"
        if enable:
            ps = (
                f'$v=(Get-ItemProperty "{dst}" -Name "{safe_name}" -EA Stop)."{safe_name}"; '
                f'Set-ItemProperty "{src}" -Name "{safe_name}" -Value $v; '
                f'Remove-ItemProperty "{dst}" -Name "{safe_name}"'
            )
        else:
            ps = (
                f'$v=(Get-ItemProperty "{src}" -Name "{safe_name}" -EA Stop)."{safe_name}"; '
                f'if (-not (Test-Path "{dst}")) {{ New-Item "{dst}" -Force | Out-Null }}; '
                f'Set-ItemProperty "{dst}" -Name "{safe_name}" -Value $v; '
                f'Remove-ItemProperty "{src}" -Name "{safe_name}"'
            )
    elif item_type == "task":
        action = "Enable-ScheduledTask" if enable else "Disable-ScheduledTask"
        ps = f'{action} -TaskName "{safe_name}" -EA Stop'
    else:
        return {"ok": False, "error": "Cannot toggle this item type"}
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=15
        )
        return {"ok": r.returncode == 0, "error": r.stderr.strip() if r.returncode != 0 else ""}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# DISK HEALTH — moved to disk.py (backlog #22 blueprint extraction)
# ══════════════════════════════════════════════════════════════════════════════
#
# Disk enumeration, path analyzer, quick-wins, WinSxS sizing, and cleanup-tool
# launcher all live in disk.py and are re-imported at the top of this file so
# that globals()-based lookups (selftest), NLQ dispatch, dashboard aggregation,
# and test patches still resolve through the windesktopmgr namespace.


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK MONITOR
# ══════════════════════════════════════════════════════════════════════════════


def get_network_data() -> dict:
    """Enumerate TCP connections + adapter stats using psutil (no PowerShell).

    Replaces ``Get-NetTCPConnection`` + ``Get-NetAdapterStatistics`` +
    ``Get-NetAdapter`` (backlog #24 batch A, sites #22 + #23). The output
    shape is preserved exactly so the /api/network route and JS renderer
    don't change:

    - ``State`` values are mapped from psutil's ``ESTABLISHED``/``LISTEN``
      constants back to PowerShell's ``Established``/``Listen`` title-case
      so existing filters keep working.
    - ``LinkSpeedMb`` comes from ``net_if_stats().speed`` (already Mbps).
    - ``SentMB`` / ``ReceivedMB`` come from ``net_io_counters(pernic=True)``.
    - Process names are resolved per-PID via ``Process(pid).name()``.
    """
    try:
        # Build pid -> name map once to avoid per-conn Process() lookups.
        pid_names: dict[int, str] = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[proc.info["pid"]] = proc.info.get("name") or "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Map psutil status constants → the title-case strings the UI expects.
        _state_map = {
            psutil.CONN_ESTABLISHED: "Established",
            psutil.CONN_LISTEN: "Listen",
            psutil.CONN_SYN_SENT: "SynSent",
            psutil.CONN_SYN_RECV: "SynReceived",
            psutil.CONN_FIN_WAIT1: "FinWait1",
            psutil.CONN_FIN_WAIT2: "FinWait2",
            psutil.CONN_TIME_WAIT: "TimeWait",
            psutil.CONN_CLOSE: "Closed",
            psutil.CONN_CLOSE_WAIT: "CloseWait",
            psutil.CONN_LAST_ACK: "LastAck",
            psutil.CONN_CLOSING: "Closing",
            psutil.CONN_NONE: "None",
        }

        conns: list[dict] = []
        try:
            raw_conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            # net_connections needs admin on Windows for system-wide visibility.
            # Fall back to empty list (same as PS pipeline when RPC is denied).
            raw_conns = []
        for c in raw_conns:
            laddr = c.laddr
            raddr = c.raddr
            pid = c.pid or 0
            conns.append(
                {
                    "LocalAddress": laddr.ip if laddr else "",
                    "LocalPort": laddr.port if laddr else 0,
                    "RemoteAddress": raddr.ip if raddr else "",
                    "RemotePort": raddr.port if raddr else 0,
                    "State": _state_map.get(c.status, c.status),
                    "PID": pid,
                    "Process": pid_names.get(pid, "Unknown"),
                }
            )

        # Adapters: combine net_io_counters (bytes) + net_if_stats (speed/up).
        try:
            io_counters = psutil.net_io_counters(pernic=True)
        except Exception:
            io_counters = {}
        try:
            if_stats = psutil.net_if_stats()
        except Exception:
            if_stats = {}

        adapters: list[dict] = []
        for name, counters in io_counters.items():
            stats = if_stats.get(name)
            adapters.append(
                {
                    "Name": name,
                    "SentMB": round(counters.bytes_sent / (1024 * 1024), 2),
                    "ReceivedMB": round(counters.bytes_recv / (1024 * 1024), 2),
                    "Status": ("Up" if (stats and stats.isup) else "Down") if stats else "Unknown",
                    # psutil speed is already in Mbps — match the PS output directly.
                    "LinkSpeedMb": int(stats.speed) if stats and stats.speed else 0,
                }
            )

        established = [c for c in conns if c.get("State") == "Established"]
        listening = [c for c in conns if c.get("State") == "Listen"]

        # Group by process for summary
        proc_counts = Counter(c.get("Process", "Unknown") for c in established)
        top_procs = [{"process": p, "connections": n} for p, n in proc_counts.most_common(10)]

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
        return {
            "established": [],
            "listening": [],
            "adapters": [],
            "top_processes": [],
            "total_connections": 0,
            "total_listening": 0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK METRICS — Trends dashboard (backlog #38)
#
# Lightweight time-series metrics for the Trends sparklines, separate from
# get_network_data() which powers the full Network Monitor tab (connection
# table + per-adapter detail). Four numbers per sample:
#
#   throughput_in_mbps       — sum of all non-loopback adapters
#   throughput_out_mbps      — same
#   latency_ms               — single TCP-connect probe to Cloudflare DNS
#   connections_established  — count of ESTABLISHED TCP connections
#
# Python-first: psutil + stdlib socket. No subprocess anywhere.
# ══════════════════════════════════════════════════════════════════════════════

# Throughput needs a baseline to compute Mbps (same pattern as the Processes
# tab CPU % fix -- see _last_cpu_samples). Dict layout:
#   {"total": (bytes_sent_cumulative, bytes_recv_cumulative, wall_clock_ts)}
# Only one key ("total") because the Trends card shows aggregate throughput
# across every non-loopback NIC, not per-adapter. Per-NIC breakdown would
# add N sparklines for marginal value on a home rig.
_last_net_samples: dict[str, tuple[float, float, float]] = {}
_net_samples_lock = threading.Lock()

# External target for the TCP-connect latency probe. Cloudflare DNS: 1.1.1.1
# on port 53 is widely open (not firewalled the way ICMP often is), has
# predictable sub-50 ms RTT from most places, and doesn't require admin
# privileges for a raw-socket ping. Changing this target would shift every
# recorded historic latency sample upward/downward, so pin it here.
_LATENCY_PROBE_TARGET: tuple[str, int] = ("1.1.1.1", 53)
_LATENCY_PROBE_TIMEOUT_S: float = 2.0


def _measure_tcp_latency(
    target: tuple[str, int] = _LATENCY_PROBE_TARGET, timeout: float = _LATENCY_PROBE_TIMEOUT_S
) -> float | None:
    """Return round-trip milliseconds of a TCP connect to ``target``.

    Returns ``None`` on any failure (DNS fail, connection refused, timeout,
    no route to host, firewall drop). Callers treat None as "no signal"
    rather than "zero latency" -- recording 0 ms for a failed probe would
    lie to the trend chart.

    Uses ``socket.create_connection`` which does DNS + TCP handshake in one
    call. Measured in ``time.perf_counter()`` for monotonic accuracy even
    across NTP adjustments.
    """
    import socket

    try:
        t0 = time.perf_counter()
        with socket.create_connection(target, timeout=timeout):
            return round((time.perf_counter() - t0) * 1000.0, 1)
    except (OSError, TimeoutError, socket.gaierror):
        # socket.timeout is an alias for TimeoutError in Py 3.10+; listed
        # explicitly via TimeoutError to satisfy ruff UP041. socket.gaierror
        # is a distinct subclass of OSError for DNS-resolution failures.
        return None


def _is_loopback_adapter(name: str) -> bool:
    """True for Windows / Linux loopback NIC names.

    Windows usually calls it "Loopback Pseudo-Interface 1" but can vary by
    locale / virtualisation stack. Matching the substring ``loopback`` is
    generous enough to catch every variant I've seen and strict enough to
    avoid false positives -- real user-facing NICs don't include the word.
    """
    n = name.lower()
    return "loopback" in n or n == "lo"


def get_network_metrics() -> dict:
    """Sample lightweight network metrics for the Trends card (backlog #38).

    Fields:
        available                — always True (collector never errors
                                    fatally; individual fields degrade to
                                    None / 0 as noted)
        source                   — "psutil+socket"
        throughput_in_mbps       — Mbps averaged across all non-loopback
                                    NICs between the previous call and now.
                                    0 on the very first call (no baseline).
        throughput_out_mbps      — same, upload direction.
        latency_ms               — TCP-connect RTT to Cloudflare DNS; None
                                    on probe failure.
        connections_established  — count of ESTABLISHED TCP connections;
                                    None when psutil can't enumerate
                                    (AccessDenied without admin on some
                                    setups).
        latency_target           — "host:port" the probe hit, for display.
        error                    — None in the happy path; populated only
                                    if the counter read itself blew up.

    Thread safety: ``_net_samples_lock`` is held for the minimum window
    (copy prev, write new) so parallel dashboard_summary calls don't race
    on the rate calculation.
    """
    result = {
        "available": True,
        "source": "psutil+socket",
        "throughput_in_mbps": 0.0,
        "throughput_out_mbps": 0.0,
        "latency_ms": None,
        "latency_target": f"{_LATENCY_PROBE_TARGET[0]}:{_LATENCY_PROBE_TARGET[1]}",
        "connections_established": None,
        "error": None,
    }

    now = time.time()

    # ── Aggregate counters across all non-loopback NICs ──────────────
    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception as e:  # noqa: BLE001 -- psutil can surface OS-specific surprises
        result["error"] = f"net_io_counters failed: {type(e).__name__}: {e}"
        return result

    total_sent = 0
    total_recv = 0
    for name, c in (counters or {}).items():
        if _is_loopback_adapter(name):
            continue
        total_sent += c.bytes_sent
        total_recv += c.bytes_recv

    with _net_samples_lock:
        prev = _last_net_samples.get("total")
        _last_net_samples["total"] = (float(total_sent), float(total_recv), now)

    if prev is not None:
        prev_sent, prev_recv, prev_ts = prev
        dt = now - prev_ts
        # Guard dt>0 against clock skew / zero-interval rapid calls; guard
        # delta>=0 against counter rollover or NIC reset (which would
        # produce a negative delta -- treat as "no reliable rate" not a
        # negative Mbps).
        if dt > 0:
            d_sent = max(0.0, float(total_sent) - prev_sent)
            d_recv = max(0.0, float(total_recv) - prev_recv)
            # Mbps = bytes/s * 8 bits/byte / 1_000_000 bits/Mb
            result["throughput_out_mbps"] = round(d_sent * 8.0 / 1_000_000.0 / dt, 3)
            result["throughput_in_mbps"] = round(d_recv * 8.0 / 1_000_000.0 / dt, 3)

    # ── Latency probe (TCP connect to Cloudflare DNS) ─────────────────
    result["latency_ms"] = _measure_tcp_latency()

    # ── Active connection count ───────────────────────────────────────
    # psutil.net_connections(kind='tcp') can raise AccessDenied on some
    # configurations (non-admin user enumerating other users' sockets).
    # Fall back to kind='inet4' which is often more permissive; if that
    # also fails, leave the field None so the extractor skips it.
    try:
        conns = psutil.net_connections(kind="tcp")
        result["connections_established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
    except (psutil.AccessDenied, PermissionError):
        try:
            conns = psutil.net_connections(kind="inet4")
            result["connections_established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
        except Exception:  # noqa: BLE001
            result["connections_established"] = None
    except Exception:  # noqa: BLE001
        result["connections_established"] = None

    return result


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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=30
        )
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


_LEVEL_DISPLAY = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}


def query_event_log(params: dict) -> list:
    log = params.get("log", "System")
    level = params.get("level", "")
    search = params.get("search", "").strip()
    max_ev = min(int(params.get("max", 100)), 500)

    safe_log = re.sub(r"[^\w\s\-/]", "", log)

    levels = [LEVEL_MAP[level]] if level and level in LEVEL_MAP else None
    xpath = _build_evt_xpath(levels=levels)

    try:
        rows = _query_event_log_xpath(safe_log, xpath, max_events=max_ev, timeout_s=30.0)
        events = [
            {
                "Time": e["TimeCreated"],
                "Id": e["Id"],
                "Level": _LEVEL_DISPLAY.get(e["Level"], ""),
                "Source": e["ProviderName"],
                # Preserve the legacy 300-char truncation for UI display parity
                "Message": (e["Message"] or "")[:300],
            }
            for e in rows
        ]
        if search:
            sl = search.lower()
            events = [
                e for e in events if sl in (e.get("Message", "") + e.get("Source", "") + str(e.get("Id", ""))).lower()
            ]
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
    updates = [r for r in results if r["status"] == "update_available"]
    unknown = [r for r in results if r["status"] == "unknown"]
    ok = [r for r in results if r["status"] == "up_to_date"]
    insights = []
    actions = []
    if updates:
        cats = Counter(r["category"] for r in updates)
        top = cats.most_common(1)[0][0]
        nvidia_updates = [r for r in updates if r.get("download_url", "").startswith("nvidia-app:")]
        wu_updates_list = [r for r in updates if not r.get("download_url", "").startswith("nvidia-app:")]
        # Build context-aware advice
        if nvidia_updates and wu_updates_list:
            advice = f"{len(nvidia_updates)} via NVIDIA App, {len(wu_updates_list)} via Windows Update."
            actions.append("Update via NVIDIA App")
            actions.append("Open Windows Update")
        elif nvidia_updates:
            advice = "Open NVIDIA App to install the latest driver."
            actions.append("Update via NVIDIA App")
        else:
            advice = "Open Windows Update to install pending driver updates."
            actions.append("Open Windows Update")
        insights.append(
            _insight(
                "warning",
                f"{len(updates)} driver update(s) available — most in {top}.",
                advice,
            )
        )
        critical = [
            r for r in updates if r["category"] in ("Display", "Network", "Chipset") and not r.get("low_priority")
        ]
        if critical:
            insights.append(
                _insight(
                    "critical",
                    f"{len(critical)} critical driver(s) need updating: "
                    + ", ".join(r["name"][:40] for r in critical[:3]),
                    "Prioritise display, network and chipset drivers for system stability.",
                )
            )
    if unknown and not updates:
        insights.append(
            _insight(
                "info",
                f"{len(unknown)} driver(s) could not be verified against Windows Update — they may still be current.",
                "",
            )
        )
    if not updates and not unknown:
        insights.append(_insight("ok", f"All {len(ok)} drivers are up to date."))
    status = (
        "critical"
        if any(i["level"] == "critical" for i in insights)
        else "warning"
        if any(i["level"] == "warning" for i in insights)
        else "ok"
    )
    if updates:
        headline = f"{len(updates)} update(s) need attention"
    elif unknown and not ok:
        headline = f"{len(unknown)} driver(s) could not be verified"
    elif unknown:
        headline = f"{len(ok)} driver(s) verified, {len(unknown)} unknown"
    else:
        headline = f"All {len(results)} drivers up to date"
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


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


def summarize_startup(items: list) -> dict:
    if not items:
        return {"status": "ok", "headline": "No startup entries found.", "insights": [], "actions": []}
    suspicious = [i for i in items if i.get("suspicious")]
    enabled = [i for i in items if i.get("Enabled")]
    insights = []
    actions = []
    if suspicious:
        insights.append(
            _insight(
                "critical",
                f"{len(suspicious)} suspicious startup entry/entries detected — running from temp/downloads/public folders.",
                "Review and disable any suspicious entries immediately.",
            )
        )
        actions.append("Disable suspicious entries")
        for s in suspicious[:3]:
            insights.append(_insight("critical", f"Suspicious: {s.get('Name', '?')} — {(s.get('Command') or '')[:60]}"))
    if len(enabled) > 20:
        insights.append(
            _insight(
                "warning",
                f"{len(enabled)} startup items are enabled — this may slow login time.",
                "Disable non-essential startup items to improve boot speed.",
            )
        )
    elif len(enabled) > 0:
        insights.append(
            _insight(
                "info",
                f"{len(enabled)} item(s) run at login across {len(set(i.get('Location') for i in items))} locations.",
            )
        )
    if not suspicious:
        insights.append(_insight("ok", "No suspicious startup entries detected."))
    status = "critical" if suspicious else "warning" if len(enabled) > 20 else "ok"
    headline = (
        f"{len(suspicious)} suspicious item(s) — review needed"
        if suspicious
        else f"{len(enabled)} items run at login — all look clean"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_network(data: dict) -> dict:
    established = data.get("established", [])
    adapters = data.get("adapters", [])
    top_procs = data.get("top_processes", [])
    insights = []
    actions = []
    down_adapters = [a for a in adapters if a.get("Status", "").lower() not in ("up", "")]
    if down_adapters:
        insights.append(
            _insight(
                "warning",
                f"{len(down_adapters)} network adapter(s) are not active: "
                + ", ".join(a.get("Name", "?") for a in down_adapters),
            )
        )
    unusual_ports = [c for c in established if c.get("RemotePort") in (4444, 1337, 31337, 9001, 8888)]
    if unusual_ports:
        insights.append(
            _insight(
                "warning",
                f"{len(unusual_ports)} connection(s) on unusual ports — worth reviewing.",
                "Check the Active Connections table below. These may be legitimate (VPN, games, apps) or unexpected. Look at the remote address and process name to decide.",
            )
        )
        actions.append("Investigate flagged connections")
    if top_procs:
        top = top_procs[0]
        if top["connections"] > 20:
            insights.append(
                _insight(
                    "warning",
                    f"{top['process']} has {top['connections']} open connections — unusually high.",
                    "Check if this process is behaving normally.",
                )
            )
        else:
            insights.append(
                _insight("info", f"Top process by connections: {top['process']} ({top['connections']} connections).")
            )
    active_adapters = [a for a in adapters if a.get("Status", "").lower() == "up"]
    if active_adapters:
        insights.append(
            _insight(
                "ok",
                f"{len(active_adapters)} adapter(s) active. "
                f"{data.get('total_connections', 0)} established connection(s).",
            )
        )
    if not unusual_ports and not down_adapters:
        insights.append(_insight("ok", "No suspicious connections or adapter issues detected."))
    status = (
        "critical"
        if unusual_ports
        else "warning"
        if down_adapters or (top_procs and top_procs[0]["connections"] > 20)
        else "ok"
    )
    headline = (
        f"{len(unusual_ports)} suspicious connection(s) detected"
        if unusual_ports
        else f"{data.get('total_connections', 0)} active connections — nothing flagged"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


def summarize_updates(items: list) -> dict:
    if not items:
        return {"status": "info", "headline": "No update history found.", "insights": [], "actions": []}
    failed = [u for u in items if u.get("result") in ("Failed", "Aborted")]
    now = datetime.now(timezone.utc)
    month = [u for u in items if u.get("result") == "Succeeded" and (now - _parse_ts(u.get("Date", ""))).days <= 30]
    insights = []
    actions = []
    if failed:
        recent_failed = [u for u in failed if (now - _parse_ts(u.get("Date", ""))).days <= 60]
        if recent_failed:
            insights.append(
                _insight(
                    "warning",
                    f"{len(recent_failed)} update(s) failed or were aborted in the last 60 days.",
                    "Re-run Windows Update to retry failed updates.",
                )
            )
            actions.append("Retry failed updates in Windows Update")
            for u in recent_failed[:2]:
                insights.append(_insight("warning", f"Failed: {u.get('Title', '?')[:60]}"))
    last_ok = next((u for u in items if u.get("result") == "Succeeded"), None)
    if last_ok:
        days_ago = (now - _parse_ts(last_ok.get("Date", ""))).days
        if days_ago > 60:
            insights.append(
                _insight(
                    "warning",
                    f"Last successful update was {days_ago} days ago — system may be out of date.",
                    "Run Windows Update to check for new updates.",
                )
            )
            actions.append("Run Windows Update")
        else:
            insights.append(
                _insight("ok", f"Last successful update: {days_ago} day(s) ago. {len(month)} update(s) this month.")
            )
    if not failed:
        insights.append(_insight("ok", f"No failed updates. {len(items)} updates in history."))
    status = "warning" if failed or (last_ok and (now - _parse_ts(last_ok.get("Date", ""))).days > 60) else "ok"
    headline = (
        f"{len(failed)} failed update(s) need attention" if failed else f"Updates healthy — {len(items)} in history"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# Knowledge base: well-known Event IDs with context, real severity, and actions
EVENT_KB = {
    # ── DistributedCOM / DCOM ─────────────────────────────────────────────
    10010: {
        "noise": True,
        "source": "Microsoft-Windows-DistributedCOM",
        "title": "Windows background component unavailable (Event 10010)",
        "detail": "Windows couldn't start a DCOM server (DCOM is the background communication "
        "framework Windows uses to connect apps and system services) in time. "
        "This is almost always harmless background noise — "
        "typically caused by Microsoft Store apps or system components "
        "that register servers they don't always use.",
        "action": "Safe to ignore unless you see application crashes alongside it. No action needed.",
    },
    10016: {
        "noise": True,
        "source": "Microsoft-Windows-DistributedCOM",
        "title": "Windows background component permission error (Event 10016)",
        "detail": "A process tried to activate a DCOM server (DCOM is the background communication "
        "framework Windows uses to connect apps and services) without the required permissions. "
        "This is extremely common on Windows 11 and almost always benign — "
        "it affects background Microsoft components, not your applications.",
        "action": "Safe to ignore in most cases. No action needed unless a specific app is broken.",
    },
    # ── Disk / Storage ────────────────────────────────────────────────────
    7: {
        "noise": False,
        "source": "disk",
        "title": "Bad block on disk",
        "detail": "The disk driver detected a bad block. This is a hardware-level warning "
        "that your drive may be developing physical errors.",
        "action": "URGENT: back up your data immediately. "
        "Then run chkdsk /r (Windows built-in disk check and repair tool): "
        "search Command Prompt in Start, right-click Run as Administrator, "
        "type: chkdsk C: /r and press Enter (replace C: with the affected drive letter). "
        "Check the Disk Health tab for physical disk status.",
    },
    11: {
        "noise": False,
        "source": "disk",
        "title": "Controller error on disk",
        "detail": "The disk controller reported an error. Can indicate a failing drive, "
        "loose cable, or faulty SATA/NVMe controller.",
        "action": "Check the Disk Health tab in WinDesktopMgr for drive health status. "
        "For deeper analysis, CrystalDiskInfo (free tool at crystalmark.info) reads S.M.A.R.T. data "
        "(drive health statistics built into every modern drive). "
        "If errors are found, back up immediately and consider replacing the drive.",
    },
    51: {
        "noise": False,
        "source": "disk",
        "title": "Disk paging error",
        "detail": "An error occurred during a paging operation. Often appears before drive failure.",
        "action": "Back up data. Run chkdsk /r (Windows built-in disk check tool): search Command Prompt in Start, right-click Run as Administrator, type: chkdsk C: /r. Check the Disk Health tab for drive health status.",
    },
    # ── Kernel / Power ────────────────────────────────────────────────────
    41: {
        "noise": False,
        "source": "Microsoft-Windows-Kernel-Power",
        "title": "Unexpected system shutdown (Kernel-Power)",
        "detail": "The system rebooted without cleanly shutting down first — "
        "this is the primary BSOD/crash/power-loss event. "
        "Directly related to the crashes shown in the BSOD Dashboard.",
        "action": "Check BSOD Dashboard for crash analysis. "
        "Verify PSU is adequate for your hardware. Check system temps.",
    },
    6008: {
        "noise": False,
        "source": "EventLog",
        "title": "Unexpected shutdown logged by Event Log",
        "detail": "The previous system shutdown was unexpected. Logged at startup after a crash or power loss.",
        "action": "Cross-reference with BSOD Dashboard. If frequent, investigate power supply and thermals.",
    },
    1001: {
        "noise": False,
        "source": "BugCheck",
        "title": "Windows Error Reporting — crash recorded",
        "detail": "Windows recorded a crash dump. The stop code is logged here.",
        "action": "Check the BSOD Dashboard tab for full crash analysis and recommendations.",
    },
    # ── Service Control Manager ───────────────────────────────────────────
    7000: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service failed to start",
        "detail": "A Windows service failed to start during boot.",
        "action": "Check which service failed in the event message. "
        "Run: Get-Service | Where-Object {$_.Status -eq 'Stopped'} in PowerShell.",
    },
    7001: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service dependency failed",
        "detail": "A service could not start because a service it depends on failed.",
        "action": "Identify the dependency chain — fix the root service first.",
    },
    7031: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service terminated unexpectedly",
        "detail": "A service crashed and Windows took a recovery action (restart/reboot).",
        "action": "Note the service name in the event message. Check Event Log for related errors around the same time.",
    },
    7034: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service terminated unexpectedly (no recovery)",
        "detail": "A service crashed with no configured recovery action.",
        "action": "Identify the service and check its logs or event source for the root cause.",
    },
    # ── Windows Update ────────────────────────────────────────────────────
    20: {
        "noise": False,
        "source": "Microsoft-Windows-WindowsUpdateClient",
        "title": "Windows Update installation failure",
        "detail": "A Windows Update failed to install.",
        "action": "Check Update History tab for details. Run sfc /scannow (Windows system file repair tool): search Command Prompt in Start, right-click Run as Administrator, type: sfc /scannow and press Enter. Then retry Windows Update.",
    },
    # ── Application / .NET ───────────────────────────────────────────────
    1000: {
        "noise": False,
        "source": "Application Error",
        "title": "Application crash",
        "detail": "An application faulted and was terminated by Windows.",
        "action": "Note the faulting application and module in the event message. Update or reinstall the application.",
    },
    1026: {
        "noise": True,
        "source": ".NET Runtime",
        "title": ".NET Runtime error",
        "detail": "A .NET application encountered an unhandled exception.",
        "action": "Usually harmless background app crash. "
        "Note the app name — reinstall if it's something you use actively.",
    },
    # ── Networking ───────────────────────────────────────────────────────
    4201: {
        "noise": True,
        "source": "Tcpip",
        "title": "Network adapter disconnected",
        "detail": "The system detected the network adapter was disconnected.",
        "action": "Normal if you disconnected Wi-Fi or Ethernet intentionally. "
        "Investigate if happening unexpectedly — check Network Monitor tab.",
    },
    # ── Hyper-V / Virtualisation ─────────────────────────────────────────
    18456: {
        "noise": False,
        "source": "Microsoft-Windows-Hyper-V-Worker",
        "title": "Hyper-V worker process error",
        "detail": "Hyper-V encountered an error in a virtual machine worker process.",
        "action": "Related to your HYPERVISOR_ERROR BSODs. "
        "Consider disabling Memory Integrity (Core Isolation) and C-States in BIOS.",
    },
    # ── Security ─────────────────────────────────────────────────────────
    4625: {
        "noise": False,
        "source": "Microsoft-Windows-Security-Auditing",
        "title": "Failed logon attempt",
        "detail": "An account failed to log on. Multiple occurrences may indicate a brute-force attack (repeated automated login attempts by malicious software) or a misconfigured service trying to authenticate.",
        "action": "Check the account name and source IP in the event details. "
        "If from external IP, review firewall and RDP settings.",
    },
    4648: {
        "noise": False,
        "source": "Microsoft-Windows-Security-Auditing",
        "title": "Explicit credentials logon",
        "detail": "A process attempted to log on with explicit credentials (runas). Can be legitimate or suspicious.",
        "action": "Review the account and process in the event message.",
    },
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

_bsod_cache_lock = threading.Lock()
_bsod_cache: dict = {}
_bsod_queue: queue.Queue = queue.Queue()
_bsod_in_flight: set = set()

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

_event_cache_lock = threading.Lock()
_event_cache: dict = {}  # in-memory; mirrors the JSON file
_lookup_queue: queue.Queue = queue.Queue()
_lookup_in_flight: set = set()  # IDs currently being looked up


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
    safe_source = re.sub(r"[^\w \-]", "", source)
    ps = f"""
try {{
    # Try exact source name first
    $providers = @(Get-WinEvent -ListProvider "*" -EA SilentlyContinue |
        Where-Object {{ $_.Name -like "*{safe_source}*" }})
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
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=20
        )
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc = (data.get("Description") or "").strip()
        if not desc:
            return None
        # Truncate very long provider descriptions — they can be huge template strings
        desc = re.sub(r"%\d+", "[value]", desc)  # replace %1 %2 placeholders
        desc = desc[:400] + ("…" if len(desc) > 400 else "")
        return {
            "source": "windows_provider",
            "title": f"Event {event_id} from {data.get('Provider', source)}",
            "detail": desc,
            "noise": False,
            "action": "See event message details for specific context.",
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
        query = urllib.parse.quote(f"event id {event_id} {source} windows")
        url = f"https://learn.microsoft.com/api/search?search={query}&locale=en-us&%24top=3&facet=products"
        req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
        if not results:
            return None
        top = results[0]
        title = top.get("title", f"Event ID {event_id}")
        summary = top.get("summary", "")[:300]
        url_ref = top.get("url", "https://learn.microsoft.com")
        return {
            "source": "microsoft_learn",
            "title": title,
            "detail": summary or f"See Microsoft documentation for Event ID {event_id}.",
            "noise": False,
            "action": f"Full details: {url_ref}",
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
        got_item = False
        try:
            event_id, source = _lookup_queue.get(timeout=5)
            got_item = True
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
                    "source": "unknown",
                    "title": f"Event ID {event_id}",
                    "detail": "No description found in Windows provider registry or Microsoft Learn.",
                    "noise": False,
                    "action": f"Search: https://learn.microsoft.com/search/?terms=event+id+{event_id}",
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
                if got_item:
                    with _event_cache_lock:
                        _lookup_in_flight.discard(event_id)
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
    with _event_cache_lock:
        if event_id not in _lookup_in_flight:
            _lookup_in_flight.add(event_id)
            _lookup_queue.put((event_id, source))

    return None  # Not ready yet — caller will show "looking up…" state


def get_cache_status() -> dict:
    """Return cache stats for the admin endpoint."""
    with _event_cache_lock:
        cached = dict(_event_cache)
    return {
        "total_cached": len(cached),
        "queue_pending": _lookup_queue.qsize(),
        "in_flight": len(_lookup_in_flight),
        "cache_file": EVENT_CACHE_FILE,
        "entries": [
            {"id": k, "title": v.get("title", "?"), "source": v.get("source", "?"), "fetched": v.get("fetched", "")}
            for k, v in list(cached.items())[:50]
        ],
    }


def summarize_events(events: list) -> dict:
    if not events:
        return {
            "status": "ok",
            "headline": "No events to summarise — run a query first.",
            "insights": [],
            "actions": [],
        }

    errors = [e for e in events if e.get("Level") in ("Error", "Critical")]
    warnings = [e for e in events if e.get("Level") == "Warning"]
    insights = []
    actions = []

    # Separate real errors from known noise
    real_errors = [
        e
        for e in errors
        if e.get("Source") not in NOISE_SOURCES and not EVENT_KB.get(e.get("Id"), {}).get("noise", False)
    ]
    noise_errors = [e for e in errors if e not in real_errors]

    # ── Per-ID lookup (static KB + learned cache) ────────────────────────
    id_counts = Counter(e.get("Id") for e in events)
    id_source = {e.get("Id"): e.get("Source", "") for e in events}
    explained = set()
    pending = []  # IDs queued for background lookup

    for eid, cnt in id_counts.most_common(15):
        info = get_event_info(eid, id_source.get(eid, ""))
        if info is None:
            pending.append((eid, cnt))
            continue
        explained.add(eid)
        is_noise = info.get("noise", False)
        src_label = info.get("source", "")
        src_tag = "" if src_label in ("", "static") else f" [{src_label}]"
        level = "info" if is_noise else ("critical" if cnt >= 10 else "warning")
        noise_tag = " *(known noise — safe to ignore)*" if is_noise else ""
        insights.append(
            _insight(
                level,
                f"Event ID {eid}{src_tag} — {info.get('title', '')} — {cnt}x{noise_tag}. {info.get('detail', '')}",
                info.get("action", ""),
            )
        )
        if not is_noise and info.get("action"):
            actions.append(info["action"][:80])

    if pending:
        ids_str = ", ".join(str(e) for e, _ in pending[:5])
        more = f" (+{len(pending) - 5} more)" if len(pending) > 5 else ""
        insights.append(
            _insight(
                "info",
                f"Looking up {len(pending)} unknown Event ID(s) in background "
                f"({ids_str}{more}). Refresh in a few seconds to see details.",
                "",
            )
        )

    # ── Unexplained real errors ───────────────────────────────────────────
    unexplained_errors = [e for e in real_errors if e.get("Id") not in explained]
    if unexplained_errors:
        sources = Counter(e.get("Source", "?") for e in unexplained_errors)
        top_src, top_n = sources.most_common(1)[0]
        insights.append(
            _insight(
                "warning",
                f"{len(unexplained_errors)} unrecognised error(s). Top source: {top_src} ({top_n}x).",
                f"Filter by source '{top_src}' and search Microsoft support for specific event IDs.",
            )
        )

    # ── Noise summary (collapsed) ─────────────────────────────────────────
    if noise_errors:
        noise_ids = Counter(e.get("Id") for e in noise_errors)
        top_noise = ", ".join(f"ID {k} ({v}x)" for k, v in noise_ids.most_common(3))
        insights.append(
            _insight(
                "info",
                f"{len(noise_errors)} known-noise event(s) in results ({top_noise}) — "
                "these are normal Windows background activity and do not require action.",
            )
        )

    # ── Warnings summary ─────────────────────────────────────────────────
    if warnings:
        warn_sources = Counter(e.get("Source", "?") for e in warnings)
        top_ws, top_wn = warn_sources.most_common(1)[0]
        insights.append(_insight("info", f"{len(warnings)} warning(s). Top source: {top_ws} ({top_wn}x)."))

    if not errors:
        insights.append(_insight("ok", f"No errors in current results. {len(events)} total events shown."))

    # ── Status ────────────────────────────────────────────────────────────
    real_count = len(real_errors)
    status = "critical" if real_count > 10 else "warning" if real_count > 0 else "ok"
    headline = (
        f"{real_count} real error(s) need attention"
        + (f" ({len(noise_errors)} noise events filtered)" if noise_errors else "")
        if real_count
        else f"{len(events)} events retrieved — no actionable errors"
    )
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
    "system": {
        "plain": "Windows Kernel",
        "publisher": "Microsoft",
        "what": "The Windows NT kernel process. Always running — cannot and should not be killed.",
        "safe_kill": False,
    },
    "registry": {
        "plain": "Windows Registry",
        "publisher": "Microsoft",
        "what": "Manages the Windows registry in memory. Core system process.",
        "safe_kill": False,
    },
    "smss": {
        "plain": "Session Manager Subsystem",
        "publisher": "Microsoft",
        "what": "Starts user sessions during Windows boot. Core system process.",
        "safe_kill": False,
    },
    "csrss": {
        "plain": "Client Server Runtime Process",
        "publisher": "Microsoft",
        "what": "Manages Windows console and GUI shutdown. Killing it causes a BSOD.",
        "safe_kill": False,
    },
    "wininit": {
        "plain": "Windows Initialisation",
        "publisher": "Microsoft",
        "what": "Launches core Windows services at startup. Critical process.",
        "safe_kill": False,
    },
    "winlogon": {
        "plain": "Windows Logon",
        "publisher": "Microsoft",
        "what": "Handles user login/logout and locking the screen.",
        "safe_kill": False,
    },
    "services": {
        "plain": "Service Control Manager",
        "publisher": "Microsoft",
        "what": "Manages all Windows services — starting, stopping, and monitoring them.",
        "safe_kill": False,
    },
    "lsass": {
        "plain": "Local Security Authority",
        "publisher": "Microsoft",
        "what": "Handles user authentication and security policy enforcement. Killing causes immediate logout.",
        "safe_kill": False,
    },
    "svchost": {
        "plain": "Service Host",
        "publisher": "Microsoft",
        "what": "A shared hosting process for Windows services. Multiple instances are normal — each hosts one or more services.",
        "safe_kill": False,
    },
    "explorer": {
        "plain": "Windows Explorer",
        "publisher": "Microsoft",
        "what": "The Windows desktop shell — taskbar, Start menu, and File Explorer. Restarting it refreshes the desktop.",
        "safe_kill": True,
    },
    "dwm": {
        "plain": "Desktop Window Manager",
        "publisher": "Microsoft",
        "what": "Renders all windows and visual effects on screen. Terminating it causes a brief black screen and restart.",
        "safe_kill": False,
    },
    "taskhostw": {
        "plain": "Task Host Window",
        "publisher": "Microsoft",
        "what": "Hosts Windows tasks that run at logon and logoff. Background system process.",
        "safe_kill": False,
    },
    "runtimebroker": {
        "plain": "Runtime Broker",
        "publisher": "Microsoft",
        "what": "Manages permissions for Windows Store apps. Multiple instances are normal.",
        "safe_kill": True,
    },
    "sihost": {
        "plain": "Shell Infrastructure Host",
        "publisher": "Microsoft",
        "what": "Supports the Windows shell — notification area, action centre, and background slideshow.",
        "safe_kill": False,
    },
    "fontdrvhost": {
        "plain": "Font Driver Host",
        "publisher": "Microsoft",
        "what": "Hosts the Windows font driver in an isolated process for security.",
        "safe_kill": False,
    },
    "searchhost": {
        "plain": "Windows Search",
        "publisher": "Microsoft",
        "what": "Powers the Start menu search and Windows Search indexing.",
        "safe_kill": True,
    },
    "searchindexer": {
        "plain": "Search Indexer",
        "publisher": "Microsoft",
        "what": "Indexes your files in the background for fast search. High disk use is normal when indexing.",
        "safe_kill": True,
    },
    "msmpeng": {
        "plain": "Windows Defender Antivirus",
        "publisher": "Microsoft",
        "what": "Real-time antivirus and malware protection. High CPU during scans is normal.",
        "safe_kill": False,
    },
    "nissrv": {
        "plain": "Windows Defender Network Inspection",
        "publisher": "Microsoft",
        "what": "Network-level intrusion detection component of Windows Defender.",
        "safe_kill": False,
    },
    "securityhealthservice": {
        "plain": "Windows Security Health Service",
        "publisher": "Microsoft",
        "what": "Reports security status to Windows Security centre.",
        "safe_kill": False,
    },
    "audiodg": {
        "plain": "Windows Audio Device Graph",
        "publisher": "Microsoft",
        "what": "Runs audio processing in an isolated process. High CPU here means heavy audio workload or audio driver issue.",
        "safe_kill": False,
    },
    "spoolsv": {
        "plain": "Print Spooler",
        "publisher": "Microsoft",
        "what": "Manages print jobs. Safe to kill if not printing — it will restart.",
        "safe_kill": True,
    },
    "ctfmon": {
        "plain": "CTF Loader",
        "publisher": "Microsoft",
        "what": "Supports alternative text input — handwriting, speech, on-screen keyboard.",
        "safe_kill": True,
    },
    "dllhost": {
        "plain": "COM Surrogate",
        "publisher": "Microsoft",
        "what": "Hosts COM objects out-of-process for safety. Multiple instances are normal — Explorer uses them for thumbnail generation.",
        "safe_kill": True,
    },
    "conhost": {
        "plain": "Console Window Host",
        "publisher": "Microsoft",
        "what": "Hosts each command prompt / PowerShell window. One instance per terminal.",
        "safe_kill": True,
    },
    "applicationframehost": {
        "plain": "Application Frame Host",
        "publisher": "Microsoft",
        "what": "Hosts the frames/windows for Windows Store apps.",
        "safe_kill": True,
    },
    "shellexperiencehost": {
        "plain": "Windows Shell Experience Host",
        "publisher": "Microsoft",
        "what": "Powers the Start menu, taskbar clock, and notification area.",
        "safe_kill": False,
    },
    "startmenuexperiencehost": {
        "plain": "Start Menu",
        "publisher": "Microsoft",
        "what": "Hosts the Windows 11 Start menu. Restarting Explorer also restarts this.",
        "safe_kill": True,
    },
    "textinputhost": {
        "plain": "Text Input Application",
        "publisher": "Microsoft",
        "what": "Hosts the on-screen touch keyboard and handwriting panel.",
        "safe_kill": True,
    },
    "wuauclt": {
        "plain": "Windows Update",
        "publisher": "Microsoft",
        "what": "Windows Update client — checks for and downloads updates. High activity is normal during update scans.",
        "safe_kill": False,
    },
    "msdtc": {
        "plain": "Distributed Transaction Coordinator",
        "publisher": "Microsoft",
        "what": "Manages distributed database transactions. Usually idle unless you run SQL Server or BizTalk.",
        "safe_kill": True,
    },
    "dashost": {
        "plain": "Device Association Framework",
        "publisher": "Microsoft",
        "what": "Manages pairing of Bluetooth and Wi-Fi Direct devices.",
        "safe_kill": True,
    },
    "wlanext": {
        "plain": "WLAN Extensibility Module",
        "publisher": "Microsoft",
        "what": "Extends Wi-Fi driver functionality. Required for Wi-Fi adapters.",
        "safe_kill": False,
    },
    "mrt": {
        "plain": "Malicious Software Removal Tool",
        "publisher": "Microsoft",
        "what": "Microsoft's periodic malware scan tool. Runs once a month — high CPU use during that scan is normal.",
        "safe_kill": True,
    },
    "compattelrunner": {
        "plain": "Compatibility Telemetry",
        "publisher": "Microsoft",
        "what": "Collects usage and compatibility data for Microsoft. High CPU/disk is normal during its periodic run.",
        "safe_kill": True,
    },
    "wsappx": {
        "plain": "Windows Store App Service",
        "publisher": "Microsoft",
        "what": "Manages Windows Store app installations and updates.",
        "safe_kill": True,
    },
    "wermgr": {
        "plain": "Windows Error Reporting",
        "publisher": "Microsoft",
        "what": "Sends crash reports to Microsoft. Appears briefly after app crashes.",
        "safe_kill": True,
    },
    # ── Dell ─────────────────────────────────────────────────────────────
    "dellsupportassistremediationservice": {
        "plain": "Dell SupportAssist Remediation",
        "publisher": "Dell Inc.",
        "what": "Background component of Dell SupportAssist — scans hardware and fetches driver updates.",
        "safe_kill": True,
    },
    "dellsupportassist": {
        "plain": "Dell SupportAssist",
        "publisher": "Dell Inc.",
        "what": "Dell diagnostic and driver update tool.",
        "safe_kill": True,
    },
    "dellcommandupdate": {
        "plain": "Dell Command Update",
        "publisher": "Dell Inc.",
        "what": "Manages Dell BIOS, driver, and firmware updates.",
        "safe_kill": True,
    },
    "delldigitaldelivery": {
        "plain": "Dell Digital Delivery",
        "publisher": "Dell Inc.",
        "what": "Delivers bundled software for Dell PCs.",
        "safe_kill": True,
    },
    # ── NVIDIA ───────────────────────────────────────────────────────────
    "nvcontainer": {
        "plain": "NVIDIA Container",
        "publisher": "NVIDIA",
        "what": "Hosts NVIDIA background services including GeForce Experience, telemetry, and display driver components.",
        "safe_kill": True,
    },
    "nvdisplay.container": {
        "plain": "NVIDIA Display Container",
        "publisher": "NVIDIA",
        "what": "Hosts the NVIDIA display driver service and control panel backend.",
        "safe_kill": False,
    },
    "nvbackend": {
        "plain": "NVIDIA GeForce Experience Backend",
        "publisher": "NVIDIA",
        "what": "Powers the GeForce Experience overlay, game optimisation, and screenshot capture.",
        "safe_kill": True,
    },
    "nvcplui": {
        "plain": "NVIDIA Control Panel",
        "publisher": "NVIDIA",
        "what": "The NVIDIA Control Panel UI for display and GPU settings.",
        "safe_kill": True,
    },
    "nvidia web helper": {
        "plain": "NVIDIA Web Helper",
        "publisher": "NVIDIA",
        "what": "Communicates with NVIDIA's online services for driver updates and GeForce Now.",
        "safe_kill": True,
    },
    # ── Intel ────────────────────────────────────────────────────────────
    "igfxem": {
        "plain": "Intel Graphics Event Monitor",
        "publisher": "Intel",
        "what": "Monitors hotkey events for Intel integrated graphics (e.g. display mode switching).",
        "safe_kill": True,
    },
    "igfxhk": {
        "plain": "Intel Graphics Hotkey Helper",
        "publisher": "Intel",
        "what": "Enables keyboard shortcuts for Intel graphics settings.",
        "safe_kill": True,
    },
    "lms": {
        "plain": "Intel Management Engine Local Management Service",
        "publisher": "Intel",
        "what": "Provides local access to Intel Management Engine features. Low-level firmware interface.",
        "safe_kill": False,
    },
    # ── Microsoft Office / 365 ───────────────────────────────────────────
    "officeclicktorun": {
        "plain": "Microsoft Office Click-to-Run",
        "publisher": "Microsoft",
        "what": "Manages Office app updates and streaming installation in the background.",
        "safe_kill": True,
    },
    "msoffice": {
        "plain": "Microsoft Office",
        "publisher": "Microsoft",
        "what": "Microsoft Office application.",
        "safe_kill": True,
    },
    "teams": {
        "plain": "Microsoft Teams",
        "publisher": "Microsoft",
        "what": "Microsoft Teams messaging and video call app. High RAM use (1–2 GB) is normal.",
        "safe_kill": True,
    },
    "ms-teams": {
        "plain": "Microsoft Teams",
        "publisher": "Microsoft",
        "what": "Microsoft Teams — the new version. High RAM use (1–2 GB) is normal for modern Electron apps.",
        "safe_kill": True,
    },
    "outlook": {
        "plain": "Microsoft Outlook",
        "publisher": "Microsoft",
        "what": "Microsoft Outlook email client.",
        "safe_kill": True,
    },
    "winword": {
        "plain": "Microsoft Word",
        "publisher": "Microsoft",
        "what": "Microsoft Word word processor.",
        "safe_kill": True,
    },
    "excel": {
        "plain": "Microsoft Excel",
        "publisher": "Microsoft",
        "what": "Microsoft Excel spreadsheet application.",
        "safe_kill": True,
    },
    "powerpnt": {
        "plain": "Microsoft PowerPoint",
        "publisher": "Microsoft",
        "what": "Microsoft PowerPoint presentation app.",
        "safe_kill": True,
    },
    # ── Browsers ─────────────────────────────────────────────────────────
    "chrome": {
        "plain": "Google Chrome",
        "publisher": "Google",
        "what": "Google Chrome browser. Multiple processes are normal — Chrome uses separate processes per tab for stability.",
        "safe_kill": True,
    },
    "msedge": {
        "plain": "Microsoft Edge",
        "publisher": "Microsoft",
        "what": "Microsoft Edge browser. Multiple processes are normal — one per tab.",
        "safe_kill": True,
    },
    "firefox": {
        "plain": "Mozilla Firefox",
        "publisher": "Mozilla",
        "what": "Mozilla Firefox browser.",
        "safe_kill": True,
    },
    "brave": {
        "plain": "Brave Browser",
        "publisher": "Brave Software",
        "what": "Privacy-focused Chromium-based browser.",
        "safe_kill": True,
    },
    # ── Common apps ──────────────────────────────────────────────────────
    "discord": {
        "plain": "Discord",
        "publisher": "Discord Inc.",
        "what": "Discord chat and voice app. High RAM use (300–600 MB) is normal for Electron apps.",
        "safe_kill": True,
    },
    "slack": {
        "plain": "Slack",
        "publisher": "Slack Technologies",
        "what": "Slack messaging app. High RAM is normal for Electron-based apps.",
        "safe_kill": True,
    },
    "zoom": {
        "plain": "Zoom",
        "publisher": "Zoom Video Communications",
        "what": "Zoom video conferencing. High CPU during calls is expected.",
        "safe_kill": True,
    },
    "spotify": {
        "plain": "Spotify",
        "publisher": "Spotify AB",
        "what": "Spotify music streaming app.",
        "safe_kill": True,
    },
    "steam": {
        "plain": "Steam",
        "publisher": "Valve Corporation",
        "what": "Steam gaming platform and store. High RAM when a game is loaded is expected.",
        "safe_kill": True,
    },
    "steamwebhelper": {
        "plain": "Steam Web Browser Helper",
        "publisher": "Valve Corporation",
        "what": "Embedded browser component used by the Steam store and community pages.",
        "safe_kill": True,
    },
    "epicgameslauncher": {
        "plain": "Epic Games Launcher",
        "publisher": "Epic Games",
        "what": "Epic Games store and launcher.",
        "safe_kill": True,
    },
    "onedrive": {
        "plain": "Microsoft OneDrive",
        "publisher": "Microsoft",
        "what": "OneDrive sync client. Your WinDesktopMgr health reports sync through this.",
        "safe_kill": True,
    },
    "dropbox": {
        "plain": "Dropbox",
        "publisher": "Dropbox Inc.",
        "what": "Dropbox cloud sync client.",
        "safe_kill": True,
    },
    "1password": {
        "plain": "1Password",
        "publisher": "AgileBits",
        "what": "1Password password manager.",
        "safe_kill": True,
    },
    "nordvpn": {
        "plain": "NordVPN",
        "publisher": "Nord Security",
        "what": "NordVPN client — managing active VPN connection.",
        "safe_kill": True,
    },
    # ── Security ─────────────────────────────────────────────────────────
    "mbam": {
        "plain": "Malwarebytes",
        "publisher": "Malwarebytes",
        "what": "Malwarebytes Anti-Malware real-time protection.",
        "safe_kill": False,
    },
    "mbamservice": {
        "plain": "Malwarebytes Service",
        "publisher": "Malwarebytes",
        "what": "Malwarebytes background service.",
        "safe_kill": False,
    },
    # ── WinDesktopMgr ────────────────────────────────────────────────────
    "windesktopmgr": {
        "plain": "WinDesktopMgr (this app)",
        "publisher": "Local",
        "what": "Your Windows system management dashboard. This is the Flask process powering the UI you are looking at right now.",
        "safe_kill": False,
    },
    "python": {
        "plain": "Python",
        "publisher": "Python Software Foundation",
        "what": "Python interpreter — likely running WinDesktopMgr or another script.",
        "safe_kill": True,
    },
    # ── MC / McAfee ───────────────────────────────────────────────────────
    "mc-fw-host": {
        "plain": "McAfee Firewall Host",
        "publisher": "McAfee / Trellix",
        "what": "McAfee/Trellix firewall engine. High RAM use (1–2 GB) is common with McAfee security suites.",
        "safe_kill": False,
    },
    "mcafee": {
        "plain": "McAfee Security",
        "publisher": "McAfee / Trellix",
        "what": "McAfee antivirus and security suite.",
        "safe_kill": False,
    },
    "mfemms": {
        "plain": "McAfee Multi-Access Service",
        "publisher": "McAfee / Trellix",
        "what": "McAfee licence and account management service.",
        "safe_kill": False,
    },
    "serviceshell": {
        "plain": "McAfee Service Shell",
        "publisher": "McAfee / Trellix",
        "what": "Hosts McAfee security service components. High RAM use is normal for McAfee. Consider whether a lighter antivirus would suit you better — Windows Defender is built-in and uses far less RAM.",
        "safe_kill": False,
    },
    "mfewch": {
        "plain": "McAfee Web Control Helper",
        "publisher": "McAfee / Trellix",
        "what": "McAfee web content filtering component.",
        "safe_kill": False,
    },
    "mfetp": {
        "plain": "McAfee Threat Prevention",
        "publisher": "McAfee / Trellix",
        "what": "McAfee real-time threat detection engine.",
        "safe_kill": False,
    },
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
    """Read embedded file version info from the exe — offline, always current.

    Uses shutil.which() to locate the exe and win32api.GetFileVersionInfo()
    to read the embedded version resource.  No PowerShell subprocess needed.
    """
    if not path and proc_name:
        safe_name = re.sub(r"[^a-zA-Z0-9\-_. ]", "", proc_name)
        if safe_name:
            path = shutil.which(safe_name + ".exe") or shutil.which(safe_name) or ""
    if not path:
        return None
    try:
        # Get language/codepage pair from the version resource
        lc_pairs = win32api.GetFileVersionInfo(path, "\\VarFileInfo\\Translation")
        if not lc_pairs:
            return None
        lang = "%04x%04x" % (lc_pairs[0][0], lc_pairs[0][1])

        def _str(key: str) -> str:
            try:
                return (
                    win32api.GetFileVersionInfo(
                        path,
                        f"\\StringFileInfo\\{lang}\\{key}",
                    )
                    or ""
                ).strip()
            except Exception:
                return ""

        desc = _str("FileDescription")
        company = _str("CompanyName")
        product = _str("ProductName")
        if not desc and not company:
            return None
        is_system = any(p in path.lower() for p in ("\\windows\\", "\\system32\\", "\\syswow64\\"))
        return {
            "source": "file_version_info",
            "plain": product or desc or proc_name,
            "publisher": company or "Unknown",
            "what": desc or f"Executable from {company}.",
            "safe_kill": not is_system,
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[ProcessLookup] file info failed for {proc_name}: {e}")
        return None


def _lookup_process_via_web(proc_name: str) -> dict | None:
    """Web search fallback via Microsoft Learn."""
    for q_str in [f"{proc_name}.exe process windows what is", f"{proc_name} windows process"]:
        try:
            q = urllib.parse.quote(q_str)
            url = f"https://learn.microsoft.com/api/search?search={q}&locale=en-us&%24top=3"
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top = results[0]
            summary = (top.get("summary") or "").strip()[:250]
            if not summary:
                continue
            return {
                "source": "microsoft_learn",
                "plain": top.get("title", proc_name),
                "publisher": "See details",
                "what": summary,
                "safe_kill": True,
                "url": top.get("url", ""),
                "fetched": datetime.now(timezone.utc).isoformat(),
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
                    "source": "unknown",
                    "plain": proc_name,
                    "publisher": "Unknown",
                    "what": "No description found. Search the process name online to identify it.",
                    "safe_kill": True,
                    "fetched": datetime.now(timezone.utc).isoformat(),
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
                    with _process_cache_lock:
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
    with _process_cache_lock:
        if key not in _process_in_flight:
            _process_in_flight.add(key)
            _process_queue.put((key, proc_name, path))
    return None


SAFE_PROCESSES = {
    "system",
    "system idle process",
    "secure system",  # VBS/HVCI virtual secure mode (backlog #36)
    "registry",
    "memcompression",  # compressed RAM pages -- not a leak (backlog #36)
    "memory compression",  # alt display name for MemCompression
    "vmmem",  # Hyper-V / Docker / WSL VM host process (backlog #36)
    "vmmemwsl",  # WSL 2 VM memory specifically
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "explorer.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "sihost.exe",
    "ctfmon.exe",
    "searchindexer.exe",
    "wuauclt.exe",
    "mrt.exe",
    "dllhost.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "applicationframehost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "searchhost.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "audiodg.exe",
    "dashost.exe",
    "wlanext.exe",
    "msdtc.exe",
    "windesktopmgr.py",
    "python.exe",
    "pythonw.exe",
    "py.exe",
}


# Plain-English explanations for opaque system processes shown in the Memory
# tab (backlog #36). Users commonly see names like "MemCompression" and "vmmem"
# with no idea what they do -- or whether they're safe to kill. This dict
# backs the info-icon tooltips (Memory tab) and is also served by
# /api/processes/glossary so NLQ / future clients share one source of truth.
#
# Keys are LOWERCASED process names WITHOUT the .exe suffix so lookups can
# normalise from psutil's Name (which varies: "MemCompression" on Windows 10+
# vs "Memory Compression" on some builds). Every key present here also
# appears in SAFE_PROCESSES -- the two sets are deliberately kept in sync
# by ``_assert_glossary_in_safe_processes`` at module-load time.
SYSTEM_PROCESSES_GLOSSARY: dict[str, dict] = {
    "memcompression": {
        "title": "Memory Compression (Windows)",
        "explanation": (
            "Windows system process that holds compressed RAM pages. When memory "
            "gets tight, Windows compresses less-used pages in-place rather than "
            "swapping them to disk. High usage here is a perf win, not a leak. "
            "Do not kill -- Windows recreates it immediately and you lose the "
            "compression saving."
        ),
        "protected": True,
    },
    "memory compression": {
        "title": "Memory Compression (Windows)",
        "explanation": (
            "Same as MemCompression -- Windows system process holding compressed "
            "RAM pages. See the MemCompression entry for details."
        ),
        "protected": True,
    },
    "vmmem": {
        "title": "Hyper-V Virtual Machine Memory",
        "explanation": (
            "Hosts a Hyper-V utility VM's memory on the Windows side. On this "
            "machine it's almost certainly Docker Desktop or WSL 2. Free the "
            "memory by shutting the VM down through its own tool "
            "(Docker Desktop quit, or `wsl --shutdown`) -- killing vmmem "
            "force-stops every container / WSL session."
        ),
        "protected": True,
    },
    "vmmemwsl": {
        "title": "WSL 2 VM Memory",
        "explanation": (
            "The Linux VM that hosts your WSL 2 distros. Use `wsl --shutdown` "
            "in a Windows terminal to release this cleanly instead of killing "
            "the process."
        ),
        "protected": True,
    },
    "system": {
        "title": "Windows System (kernel + drivers)",
        "explanation": (
            "The Windows kernel and every loaded driver share this process. "
            "Terminating it bluescreens the machine -- cannot be killed from "
            "user space anyway."
        ),
        "protected": True,
    },
    "secure system": {
        "title": "Secure System (VBS / HVCI)",
        "explanation": (
            "Runs inside Virtual Secure Mode to enforce Hypervisor-protected "
            "Code Integrity. Isolated from the normal kernel by design and "
            "cannot be terminated."
        ),
        "protected": True,
    },
    "registry": {
        "title": "Windows Registry",
        "explanation": (
            "Holds the registry hive in memory. Cannot be safely terminated -- "
            "Windows depends on it for every configuration lookup."
        ),
        "protected": True,
    },
    "dwm": {
        "title": "Desktop Window Manager",
        "explanation": (
            "Composites the Windows desktop: window animations, transparency, "
            "multi-monitor. Killing briefly blanks the screen while Windows "
            "restarts it -- unsaved work in windowed apps can be lost."
        ),
        "protected": True,
    },
    "csrss": {
        "title": "Client / Server Runtime (critical)",
        "explanation": (
            "Handles the Windows console subsystem and window/thread creation. Terminating forces an immediate restart."
        ),
        "protected": True,
    },
    "lsass": {
        "title": "Local Security Authority",
        "explanation": (
            "Handles Windows sign-in, password validation, and security tokens. "
            "Critical -- killing signs you out and usually forces a reboot."
        ),
        "protected": True,
    },
    "services": {
        "title": "Service Control Manager",
        "explanation": ("Starts and stops every Windows service. Critical -- do not terminate."),
        "protected": True,
    },
    "winlogon": {
        "title": "Windows Logon",
        "explanation": (
            "Manages sign-on / sign-off and the secure attention sequence "
            "(Ctrl+Alt+Del). Terminating triggers a reboot."
        ),
        "protected": True,
    },
    "svchost": {
        "title": "Service Host (shared)",
        "explanation": (
            "A container process for multiple Windows services. Many svchost "
            "instances are normal. To see which services a specific svchost "
            "PID hosts, open Task Manager -> Services tab and match the PID."
        ),
        "protected": True,
    },
    "runtimebroker": {
        "title": "UWP Runtime Broker",
        "explanation": (
            "Enforces permissions (camera, location, microphone) for UWP / "
            "Microsoft Store apps. One instance per running UWP app is normal."
        ),
        "protected": True,
    },
    "audiodg": {
        "title": "Windows Audio Device Graph Isolation",
        "explanation": (
            "Runs audio drivers in a sandboxed process. Killing briefly drops sound; Windows restarts it automatically."
        ),
        "protected": True,
    },
    "fontdrvhost": {
        "title": "Font Driver Host",
        "explanation": ("Isolates font rendering from the kernel. Windows restarts it automatically if it misbehaves."),
        "protected": True,
    },
    "smss": {
        "title": "Session Manager Subsystem",
        "explanation": ("First user-mode process Windows starts at boot. Cannot be terminated from user space."),
        "protected": True,
    },
    "wininit": {
        "title": "Windows Initialization",
        "explanation": ("Starts user sessions and critical services during boot. Critical -- do not terminate."),
        "protected": True,
    },
    "conhost": {
        "title": "Console Window Host",
        "explanation": (
            "Renders each classic console window (cmd.exe, PowerShell). One "
            "conhost instance per open console is normal."
        ),
        "protected": False,  # technically OK to kill, just closes a console
    },
    "explorer": {
        "title": "Windows Explorer",
        "explanation": (
            "The taskbar, Start menu, and File Explorer. Killing it hides the "
            "taskbar briefly until Windows auto-restarts it."
        ),
        "protected": True,
    },
    "dllhost": {
        "title": "COM Surrogate",
        "explanation": (
            "Hosts COM components (file-preview thumbnails, some Explorer "
            "extensions) in an isolated process. Normal to see multiple."
        ),
        "protected": False,
    },
}


def _assert_glossary_in_safe_processes() -> None:
    """Runtime invariant: every PROTECTED entry in the glossary must also be
    listed in SAFE_PROCESSES. Otherwise we could show a "don't kill this"
    tooltip to the user while the kill endpoint happily terminated it.
    """
    missing = []
    for name, entry in SYSTEM_PROCESSES_GLOSSARY.items():
        if not entry.get("protected"):
            continue
        if name in SAFE_PROCESSES or f"{name}.exe" in SAFE_PROCESSES:
            continue
        missing.append(name)
    if missing:
        raise RuntimeError(f"SYSTEM_PROCESSES_GLOSSARY/SAFE_PROCESSES drift: {missing}")


_assert_glossary_in_safe_processes()

# High-resource thresholds
CPU_WARN_PCT = 25.0
MEM_WARN_MB = 500
MEM_CRIT_MB = 1500


# CPU-percentage sample cache (Processes tab bug fix, 2026-04-20).
# Keyed by PID -> (cumulative_cpu_seconds, wall_clock_timestamp) recorded on
# the last ``get_process_list()`` call. On the next call we compute
#     delta_sec / delta_time * 100 / num_cores
# to get the real CPU percentage (0-100) used between the two samples.
#
# Why this exists: psutil's ``Process.cpu_percent(interval=None)`` is the
# "right" API for this, but it requires priming (first call always returns
# 0) and needs a baseline per Process instance. Because we rebuild
# Process objects from scratch each call via ``process_iter()``, that
# per-instance state is lost. Keeping the baseline in a module-level dict
# survives across calls and lets a PID accumulate a real rate over time.
_last_cpu_samples: dict[int, tuple[float, float]] = {}
_cpu_samples_lock = threading.Lock()


def _compute_cpu_pct(
    pid: int,
    cpu_sec: float,
    now: float,
    num_cores: int,
    prev_samples: dict[int, tuple[float, float]],
) -> float:
    """Compute current CPU-% (0-100) for one process using a sample delta.

    Returns 0.0 whenever we can't compute a meaningful rate:
      - First ever observation of this PID (no baseline)
      - Zero elapsed time (shouldn't happen, but guard against it)
      - Negative delta (PID reuse -- old PID died, new process got it;
        the new process has smaller cumulative CPU than the old one)

    Values are clamped to [0, 100] to keep the UI sane -- a runaway
    all-cores-pegged process on a 10-core box shows "100%" not "1000%".
    """
    prev = prev_samples.get(pid)
    if not prev:
        return 0.0
    prev_sec, prev_ts = prev
    dt = now - prev_ts
    if dt <= 0:
        return 0.0
    delta = cpu_sec - prev_sec
    if delta < 0:
        # PID reuse, or psutil returned a weird snapshot. Either way we
        # don't have a trustworthy rate; 0% is safer than a negative pct.
        return 0.0
    pct = (delta / dt) * 100.0 / max(1, num_cores)
    return max(0.0, min(pct, 100.0))


def get_process_list() -> dict:
    """Enumerate running processes using psutil (no PowerShell).

    Replaces the older ``Get-WmiObject Win32_Process`` + ``Get-Process``
    PowerShell pipeline (backlog #24 batch A). ``psutil.process_iter`` is
    ~10x faster per call and avoids the ~200–400 ms ``powershell.exe``
    cold start.

    Field semantics:
      - ``CPU``     — cumulative CPU **seconds** (user + system) since the
                      process started. Preserved for backwards compatibility
                      with consumers that expect the old ``Get-Process .CPU``
                      shape, but NOT a percentage.
      - ``CPUTime`` — alias of ``CPU``, named honestly. New code should use
                      this.
      - ``CPUPct``  — actual CPU % (0-100, normalised across cores) used
                      since the previous ``get_process_list()`` call.
                      Always 0 on first call (no baseline yet). This is the
                      field the summarizer's warn threshold compares against.

    Fix for 2026-04-20: the summarizer used to compare ``CPU`` (cumulative
    seconds) against ``CPU_WARN_PCT`` (25.0) and format the value as "%
    CPU", which produced misleading labels like "Edge using 231% CPU" -
    actually 231 cumulative CPU-seconds, which any long-running browser
    accumulates quickly. CPUPct gives the honest current-load number.
    """
    procs: list[dict] = []
    now = time.time()
    num_cores = psutil.cpu_count(logical=True) or 1

    # Snapshot the previous sample map under the lock so the read is
    # consistent even if another caller mutates the dict mid-iteration.
    with _cpu_samples_lock:
        prev_samples = dict(_last_cpu_samples)

    new_samples: dict[int, tuple[float, float]] = {}

    try:
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_times", "memory_info", "num_threads", "num_handles", "exe", "cmdline"],
        ):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                cpu_t = info.get("cpu_times")
                cpu_sec = round((cpu_t.user + cpu_t.system), 1) if cpu_t else 0
                cpu_pct = _compute_cpu_pct(pid, cpu_sec, now, num_cores, prev_samples)
                mem = info.get("memory_info")
                mem_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list).replace('"', "")
                procs.append(
                    {
                        "PID": pid,
                        "Name": info.get("name", "") or "",
                        "CPU": cpu_sec,  # legacy name: cumulative seconds
                        "CPUTime": cpu_sec,  # honest name for the same value
                        "CPUPct": round(cpu_pct, 1),  # real current-load %
                        "MemMB": mem_mb,
                        "Threads": info.get("num_threads") or 0,
                        "Handles": info.get("num_handles") or 0,
                        "Path": info.get("exe") or "",
                        # psutil doesn't expose Win32_Process.Description — mirror it from Name
                        # which matches what WMI usually returned anyway (image-name fallback).
                        "Description": info.get("name", "") or "",
                        "CmdLine": cmdline,
                    }
                )
                new_samples[pid] = (cpu_sec, now)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process exited between iter and read, or we can't see it (protected).
                continue

        procs.sort(key=lambda p: p["MemMB"], reverse=True)
    except Exception as e:
        print(f"[ProcessMonitor] error: {e}")
        return {"processes": [], "total": 0, "total_mem_mb": 0, "flagged": [], "flag_notes": []}

    # Replace the cache with only the PIDs we saw this call -- processes
    # that died drop out naturally, so the dict can't grow unboundedly.
    with _cpu_samples_lock:
        _last_cpu_samples.clear()
        _last_cpu_samples.update(new_samples)

    total_mem = sum(p.get("MemMB", 0) for p in procs)
    flags = []
    for p in procs:
        name_l = (p.get("Name", "") + ".exe").lower()
        mem = p.get("MemMB", 0)
        cpu_pct = p.get("CPUPct", 0)
        # Attach enrichment info
        p["info"] = get_process_info(p.get("Name", ""), p.get("Path", ""))
        # Use safe_kill from KB/cache to refine flagging
        is_safe_system = name_l in SAFE_PROCESSES or (p["info"] and p["info"].get("safe_kill") is False)
        p["flag"] = ""
        if not is_safe_system:
            if mem >= MEM_CRIT_MB:
                plain = (p["info"] or {}).get("plain", p["Name"])
                p["flag"] = "critical"
                flags.append(f"{plain} using {mem:.0f} MB RAM")
            elif mem >= MEM_WARN_MB:
                p["flag"] = "warning"
            elif cpu_pct >= CPU_WARN_PCT:
                plain = (p["info"] or {}).get("plain", p["Name"])
                p["flag"] = "warning"
                flags.append(f"{plain} using {cpu_pct:.0f}% CPU")

    return {
        "processes": procs,
        "total": len(procs),
        "total_mem_mb": round(total_mem, 1),
        "flagged": [p for p in procs if p["flag"]],
        "flag_notes": flags[:5],
    }


def kill_process(pid: int) -> dict:
    """Terminate a process by PID using psutil (no PowerShell).

    Replaces ``Stop-Process -Force`` (backlog #24 batch A). ``int(pid)``
    cast is preserved so callers can pass floats / strings safely; the
    psutil call will only accept a real int.
    """
    try:
        psutil.Process(int(pid)).kill()
        return {"ok": True, "error": ""}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": f"No such process: {int(pid)}"}
    except psutil.AccessDenied:
        return {"ok": False, "error": "Access is denied"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def summarize_processes(data: dict) -> dict:
    procs = data.get("processes", [])
    flagged = data.get("flagged", [])
    insights = []
    actions = []
    if not procs:
        return {"status": "ok", "headline": "No process data.", "insights": [], "actions": []}

    critical = [p for p in flagged if p.get("flag") == "critical"]
    warnings = [p for p in flagged if p.get("flag") == "warning"]

    # ── Critical RAM hogs — with plain-English names and explanation ──────────
    for p in sorted(critical, key=lambda x: x.get("MemMB", 0), reverse=True)[:5]:
        info = p.get("info") or {}
        plain = info.get("plain", p["Name"])
        what = info.get("what", "")
        pub = info.get("publisher", "")
        mem = p.get("MemMB", 0)
        safe = info.get("safe_kill", True)
        pub_str = f" ({pub})" if pub and pub not in ("Unknown", "See details") else ""
        what_str = f" — {what}" if what else ""
        action_str = (
            "This process is safe to kill if not needed right now."
            if safe
            else "This is a system or security process — do not kill it."
        )
        insights.append(_insight("critical", f"{plain}{pub_str} using {mem:.0f} MB RAM.{what_str}", action_str))
    if critical:
        actions.append("Kill high-memory processes if not needed")

    # ── Warning-level resource use ────────────────────────────────────────────
    for p in sorted(warnings, key=lambda x: x.get("MemMB", 0), reverse=True)[:4]:
        info = p.get("info") or {}
        plain = info.get("plain", p["Name"])
        what = info.get("what", "")
        mem = p.get("MemMB", 0)
        # CPUPct = real current-load % (0-100). Falls back to CPU (cumulative
        # seconds) only for legacy callers that never populated CPUPct.
        cpu_pct = p.get("CPUPct", p.get("CPU", 0))
        metric = f"{mem:.0f} MB RAM" if mem >= MEM_WARN_MB else f"{cpu_pct:.0f}% CPU"
        what_str = f" — {what[:80]}…" if len(what) > 80 else (f" — {what}" if what else "")
        insights.append(_insight("warning", f"{plain} using {metric}.{what_str}"))

    # ── Unknown processes (no info yet) ───────────────────────────────────────
    unknown = [p for p in procs if p.get("info") is None and (p.get("Name", "") + ".exe").lower() not in SAFE_PROCESSES]
    if unknown:
        insights.append(
            _insight(
                "info",
                f"{len(unknown)} process(es) still being identified in the background. "
                "Refresh in a few seconds for full details.",
            )
        )

    # ── Top consumers overview ────────────────────────────────────────────────
    top_mem = sorted(procs, key=lambda p: p.get("MemMB", 0), reverse=True)[:3]
    top_str = ", ".join(
        f"{(p.get('info') or {}).get('plain', p['Name'])} ({p.get('MemMB', 0):.0f} MB)" for p in top_mem
    )
    insights.append(
        _insight(
            "info", f"{data['total']} processes, {data['total_mem_mb']:.0f} MB RAM total. Top consumers: {top_str}."
        )
    )

    if not critical and not warnings:
        insights.append(_insight("ok", "All processes within normal resource limits."))

    status = "critical" if critical else "warning" if warnings else "ok"
    headline = (
        f"{len(critical)} process(es) using excessive RAM"
        if critical
        else f"{len(warnings)} process(es) with elevated resource use"
        if warnings
        else f"{data['total']} processes — all normal"
    )
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
        r1 = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_temps], capture_output=True, text=True, timeout=20
        )
        temps_raw = json.loads(r1.stdout.strip() or "[]")
        temps = temps_raw if isinstance(temps_raw, list) else ([temps_raw] if temps_raw else [])

        r2 = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_perf], capture_output=True, text=True, timeout=15
        )
        perf = json.loads(r2.stdout.strip() or "{}")

        r3 = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_fans], capture_output=True, text=True, timeout=10
        )
        fans_raw = json.loads(r3.stdout.strip() or "[]")
        fans = fans_raw if isinstance(fans_raw, list) else ([fans_raw] if fans_raw else [])

        # Annotate temperatures
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
                "Install LibreHardwareMonitor for detailed CPU/GPU per-core temperatures. "
                "Run it once as Administrator to register its WMI provider."
            ),
        }
    except Exception as e:
        print(f"[Thermals] error: {e}")
        return {"temps": [], "perf": {}, "fans": [], "has_rich": False, "note": str(e)}


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
    "wuauserv": {
        "plain": "Windows Update",
        "safe_stop": False,
        "what": "Downloads and installs Windows updates. Required for system security.",
    },
    "windefend": {
        "plain": "Windows Defender Antivirus",
        "safe_stop": False,
        "what": "Real-time malware protection. Never disable.",
    },
    "mpssvc": {"plain": "Windows Firewall", "safe_stop": False, "what": "Network firewall. Never disable."},
    "bits": {
        "plain": "Background Intelligent Transfer",
        "safe_stop": True,
        "what": "Downloads Windows updates in the background using idle bandwidth.",
    },
    "spooler": {
        "plain": "Print Spooler",
        "safe_stop": True,
        "what": "Manages print jobs. Safe to disable if you never print.",
    },
    "themes": {
        "plain": "Windows Themes",
        "safe_stop": True,
        "what": "Applies visual themes to the Windows UI. Disabling reverts to a basic look.",
    },
    "sysmain": {
        "plain": "SysMain (SuperFetch)",
        "safe_stop": True,
        "what": "Pre-loads frequently used apps into RAM. On SSDs it adds little value.",
    },
    "wersvc": {
        "plain": "Windows Error Reporting",
        "safe_stop": True,
        "what": "Sends crash reports to Microsoft. Safe to disable for privacy.",
    },
    "diagtrack": {
        "plain": "Connected User Experiences & Telemetry",
        "safe_stop": True,
        "what": "Sends usage and diagnostic data to Microsoft. Safe to disable for privacy.",
    },
    "fax": {
        "plain": "Fax Service",
        "safe_stop": True,
        "what": "Fax support. Almost certainly unused. Safe to disable.",
    },
    "tabletinputservice": {
        "plain": "Touch Keyboard & Handwriting",
        "safe_stop": True,
        "what": "Supports touchscreen input. Safe to disable on non-touch PCs.",
    },
    "xbgm": {
        "plain": "Xbox Game Monitoring",
        "safe_stop": True,
        "what": "Xbox game capture service. Safe to disable if you don't use Xbox features.",
    },
    "xblgamesave": {
        "plain": "Xbox Live Game Save",
        "safe_stop": True,
        "what": "Syncs Xbox game saves to the cloud. Safe to disable if unused.",
    },
    "xboxnetapisvc": {
        "plain": "Xbox Live Networking",
        "safe_stop": True,
        "what": "Xbox Live multiplayer networking. Safe to disable if unused.",
    },
    "xblauthmanager": {
        "plain": "Xbox Live Auth Manager",
        "safe_stop": True,
        "what": "Xbox Live authentication. Safe to disable if you don't use Xbox.",
    },
    "wsearch": {
        "plain": "Windows Search",
        "safe_stop": True,
        "what": "Indexes files for fast search in Explorer. Disabling saves RAM but slows file search.",
    },
    "lmhosts": {
        "plain": "TCP/IP NetBIOS Helper",
        "safe_stop": True,
        "what": "Supports old NetBIOS network name resolution. Rarely needed on modern networks.",
    },
    "remoteregistry": {
        "plain": "Remote Registry",
        "safe_stop": True,
        "what": "Allows remote editing of registry. Disable for security unless specifically needed.",
    },
    "termservice": {
        "plain": "Remote Desktop Services",
        "safe_stop": True,
        "what": "Enables Remote Desktop connections to this PC. Disable if you don't use RDP.",
    },
    "upnphost": {
        "plain": "UPnP Device Host",
        "safe_stop": True,
        "what": "Hosts UPnP devices. Safe to disable if you don't use UPnP sharing.",
    },
    "ssdpsrv": {
        "plain": "SSDP Discovery",
        "safe_stop": True,
        "what": "Discovers UPnP devices on the network. Safe to disable with UPnP Host.",
    },
    "wmpnetworksvc": {
        "plain": "Windows Media Player Network Sharing",
        "safe_stop": True,
        "what": "Shares media libraries over the network. Safe to disable if unused.",
    },
    "seclogon": {
        "plain": "Secondary Logon",
        "safe_stop": True,
        "what": "Allows running programs as a different user (Run As). Safe to disable if unused.",
    },
    "schedule": {
        "plain": "Task Scheduler",
        "safe_stop": False,
        "what": "Runs scheduled tasks — including WinDesktopMgr at login. Do not disable.",
    },
    "eventlog": {
        "plain": "Windows Event Log",
        "safe_stop": False,
        "what": "Records system events. Required for BSOD Dashboard and Event Log tab. Never disable.",
    },
    "cryptsvc": {
        "plain": "Cryptographic Services",
        "safe_stop": False,
        "what": "Manages certificates and crypto operations. Required for Windows Update and TLS.",
    },
    "rpcss": {
        "plain": "Remote Procedure Call (RPC)",
        "safe_stop": False,
        "what": "Core Windows RPC subsystem. Never disable — system will fail to boot.",
    },
    "dnscache": {
        "plain": "DNS Client",
        "safe_stop": True,
        "what": "Caches DNS lookups to speed up web browsing. Rarely worth disabling.",
    },
    "dhcp": {
        "plain": "DHCP Client",
        "safe_stop": False,
        "what": "Gets your IP address from the router. Disabling breaks network connectivity.",
    },
    "lanmanserver": {
        "plain": "Server (File Sharing)",
        "safe_stop": True,
        "what": "Enables file and printer sharing from this PC. Safe to disable if not sharing.",
    },
    "lanmanworkstation": {
        "plain": "Workstation (Network Files)",
        "safe_stop": False,
        "what": "Allows connecting to shared network files and printers. Disable only if fully isolated.",
    },
    "dellsupportassistremediationservice": {
        "plain": "Dell SupportAssist Remediation",
        "safe_stop": True,
        "what": "Dell hardware diagnostics and driver update component. Safe to disable if managing drivers manually.",
    },
    "dellsupportassist": {
        "plain": "Dell SupportAssist",
        "safe_stop": True,
        "what": "Dell support and diagnostics service. WinDesktopMgr covers the same ground.",
    },
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
            q = urllib.parse.quote(q_str)
            url = f"https://learn.microsoft.com/api/search?search={q}&locale=en-us&%24top=3"
            req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if not results:
                continue
            top = results[0]
            summary = (top.get("summary") or "").strip()[:300]
            if not summary:
                continue
            return {
                "source": "microsoft_learn",
                "plain": top.get("title", display_name),
                "what": summary,
                "safe_stop": True,
                "reason": f"See: {top.get('url', '')}",
                "fetched": datetime.now(timezone.utc).isoformat(),
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
                    "source": "unknown",
                    "plain": display_name,
                    "what": "No description found.",
                    "safe_stop": True,
                    "reason": f'Search "{svc_key} windows service" online.',
                    "fetched": datetime.now(timezone.utc).isoformat(),
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
                    with _services_cache_lock:
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
    with _services_cache_lock:
        if key not in _services_in_flight:
            _services_in_flight.add(key)
            _services_queue.put((key, display_name))
    return None


def get_services_list() -> list:
    """Enumerate Windows services using psutil (no PowerShell).

    Replaces ``Get-WmiObject Win32_Service`` (backlog #24 batch A, site
    #34). ``psutil.win_service_iter`` + ``.as_dict()`` surfaces every
    field we previously read from WMI, but Status + StartMode values need
    light remapping to match the PowerShell title-case the JS renderer
    expects:

    - psutil status: ``running``/``stopped``/``start_pending``/``paused``/…
      → ``Running``/``Stopped``/``StartPending``/``Paused``/…
    - psutil start_type: ``automatic``/``manual``/``disabled`` →
      ``Auto``/``Manual``/``Disabled`` (the exact strings the PS code
      returned and that summarize_services() compares against).
    """
    _status_map = {
        "running": "Running",
        "stopped": "Stopped",
        "start_pending": "StartPending",
        "stop_pending": "StopPending",
        "continue_pending": "ContinuePending",
        "pause_pending": "PausePending",
        "paused": "Paused",
    }
    _start_map = {
        "automatic": "Auto",
        "manual": "Manual",
        "disabled": "Disabled",
    }

    svcs: list[dict] = []
    try:
        for svc in psutil.win_service_iter():
            try:
                d = svc.as_dict()
            except Exception:
                # Some services raise on .as_dict() (e.g. missing description
                # permissions). Skip them — WMI would have skipped them too.
                continue
            svcs.append(
                {
                    "Name": d.get("name") or "",
                    "DisplayName": d.get("display_name") or "",
                    "Status": _status_map.get((d.get("status") or "").lower(), d.get("status") or ""),
                    "StartMode": _start_map.get((d.get("start_type") or "").lower(), d.get("start_type") or ""),
                    "ProcessId": d.get("pid") or 0,
                    "Description": d.get("description") or "",
                    "PathName": d.get("binpath") or "",
                }
            )
        # Match the PS pipeline's Sort-Object DisplayName so UI ordering is stable.
        svcs.sort(key=lambda s: (s.get("DisplayName") or "").lower())
        for s in svcs:
            s["info"] = get_services_item_info(s.get("Name", ""), s.get("DisplayName", ""))
        return svcs
    except Exception as e:
        print(f"[Services] error: {e}")
        return []


def toggle_service(name: str, action: str) -> dict:
    """Start/stop/enable/disable a Windows service via pywin32 (no PowerShell)."""
    safe_name = re.sub(r"[^a-zA-Z0-9\-_]", "", name).strip()
    if not safe_name:
        return {"ok": False, "error": "Invalid service name"}
    if action not in ("stop", "start", "disable", "enable"):
        return {"ok": False, "error": "Invalid action"}
    try:
        if action == "stop":
            win32serviceutil.StopService(safe_name)
        elif action == "start":
            win32serviceutil.StartService(safe_name)
        elif action == "disable":
            hs = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            try:
                hsc = win32service.OpenService(hs, safe_name, win32service.SERVICE_CHANGE_CONFIG)
                try:
                    win32service.ChangeServiceConfig(
                        hsc,
                        win32service.SERVICE_NO_CHANGE,  # serviceType
                        win32service.SERVICE_DISABLED,  # startType
                        win32service.SERVICE_NO_CHANGE,  # errorControl
                        None,
                        None,
                        0,
                        None,
                        None,
                        None,
                        None,
                    )
                finally:
                    win32service.CloseServiceHandle(hsc)
            finally:
                win32service.CloseServiceHandle(hs)
        elif action == "enable":
            hs = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            try:
                hsc = win32service.OpenService(hs, safe_name, win32service.SERVICE_CHANGE_CONFIG)
                try:
                    win32service.ChangeServiceConfig(
                        hsc,
                        win32service.SERVICE_NO_CHANGE,
                        win32service.SERVICE_DEMAND_START,  # Manual
                        win32service.SERVICE_NO_CHANGE,
                        None,
                        None,
                        0,
                        None,
                        None,
                        None,
                        None,
                    )
                finally:
                    win32service.CloseServiceHandle(hsc)
            finally:
                win32service.CloseServiceHandle(hs)
        return {"ok": True, "error": ""}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def summarize_services(svcs: list) -> dict:
    if not svcs:
        return {"status": "ok", "headline": "No service data.", "insights": [], "actions": []}
    running = [s for s in svcs if s.get("Status", "").lower() == "running"]
    stopped = [s for s in svcs if s.get("Status", "").lower() == "stopped"]
    disabled = [s for s in svcs if s.get("StartMode", "").lower() == "disabled"]
    insights = []
    # Flag auto-start services that are stopped (may indicate a problem)
    auto_stopped = [
        s for s in stopped if s.get("StartMode", "").lower() == "auto" and s.get("Name", "").lower() not in ("spooler",)
    ]
    if auto_stopped:
        insights.append(
            _insight(
                "warning",
                f"{len(auto_stopped)} auto-start service(s) are not running: "
                + ", ".join(s.get("DisplayName", s.get("Name", "")) for s in auto_stopped[:3]),
                "Check Event Log for service failure errors.",
            )
        )
    insights.append(
        _insight(
            "info", f"{len(running)} running, {len(stopped)} stopped, {len(disabled)} disabled ({len(svcs)} total)."
        )
    )
    # Highlight privacy/telemetry services that are running
    privacy_svcs = {"diagtrack", "dmwappushservice", "wersvc"}
    privacy_running = [s for s in running if s.get("Name", "").lower() in privacy_svcs]
    if privacy_running:
        insights.append(
            _insight(
                "info",
                f"{len(privacy_running)} telemetry/diagnostic service(s) running: "
                + ", ".join(s.get("DisplayName", "") for s in privacy_running),
                "Safe to disable for privacy if desired.",
            )
        )
    if not auto_stopped:
        insights.append(_insight("ok", "All auto-start services are running normally."))
    status = "warning" if auto_stopped else "ok"
    headline = (
        f"{len(auto_stopped)} auto-start service(s) not running"
        if auto_stopped
        else f"{len(running)} services running — all normal"
    )
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
                ts = datetime.strptime(f"{dm.group(1)}_{dm.group(2)}", "%Y-%m-%d_%H-%M-%S").replace(tzinfo=timezone.utc)

            # Format 2: 20260316_093024 (compact format)
            if not ts:
                dm = re.search(r"(\d{8})_(\d{6})", fname)
                if dm:
                    ts = datetime.strptime(f"{dm.group(1)}_{dm.group(2)}", "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)

            if not ts:
                continue

            with open(path, encoding="utf-8", errors="ignore") as f:
                html = f.read()

            # Extract health score — SystemHealthDiag.py uses <div class="score-num">87</div>
            score = None
            # Primary: score-num div (SystemHealthDiag.py format)
            for pat in [
                r'class=["\']score-num["\'][^>]*>(\d{1,3})<',  # <div class="score-num">87</div>
                r"score-num[^>]*>\s*(\d{1,3})\s*<",  # whitespace variant
                r"Health Score[:\s]+([0-9]{1,3})\s*/\s*100",  # "Health Score: 87/100"
                r"(\d{1,3})\s*/\s*100",  # "87/100" anywhere
                r"[Ss]core[:\s]+([0-9]{1,3})",  # "Score: 87"
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
                    html,
                    re.IGNORECASE,
                )
                bsod_count = len(bsod_codes)  # total occurrences, not unique

            # WHEA errors
            whea = len(re.findall(r"WHEA|hardware error|machine check", html, re.IGNORECASE))

            # Driver errors in this report
            drv_errors = len(re.findall(r"driver error|driver fail|driver crash", html, re.IGNORECASE))

            # Distinct .sys files mentioned (faulty drivers)
            sys_files = list(dict.fromkeys(d.lower() for d in re.findall(r"\b(\w+\.sys)\b", html, re.IGNORECASE)))[:5]

            # Status label from report
            status = "ok"
            if bsod_count > 0 or "critical" in html.lower():
                status = "critical"
            elif "warning" in html.lower() or whea > 0 or drv_errors > 0:
                status = "warning"

            reports.append(
                {
                    "file": fname,
                    "path": path,
                    "timestamp": ts.isoformat(),
                    "date_label": ts.strftime("%b %d"),
                    "score": score,
                    "bsod_count": bsod_count,
                    "whea_count": whea,
                    "drv_errors": drv_errors,
                    "sys_files": sys_files,
                    "status": status,
                }
            )
        except Exception as e:
            print(f"[HealthHistory] error parsing {path}: {e}")
            continue

    # Summary stats
    scores = [r["score"] for r in reports if r["score"] is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else None
    latest = reports[-1] if reports else None

    # Staleness check — flag if no report in the last 48 hours
    stale = False
    stale_days = 0
    if latest and latest.get("timestamp"):
        try:
            ts = latest["timestamp"]
            # Handle ISO format: "2026-04-03T17:01:14+00:00"
            if "T" in ts:
                last_dt = datetime.fromisoformat(ts.replace("+00:00", "").replace("Z", ""))
            else:
                last_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M")
            age = datetime.now() - last_dt
            stale_days = age.days
            stale = age.total_seconds() > 48 * 3600  # >48 hours
        except (ValueError, TypeError):
            pass

    return {
        "reports": reports,
        "total": len(reports),
        "avg_score": avg_score,
        "latest": latest,
        "report_dir": REPORT_DIR,
        "stale": stale,
        "stale_days": stale_days,
    }


def summarize_health_history(data: dict) -> dict:
    reports = data.get("reports", [])
    insights, actions = [], []
    if not reports:
        return {
            "status": "info",
            "headline": "No health reports found — run SystemHealthDiag to generate them.",
            "insights": [],
            "actions": [],
        }
    avg = data.get("avg_score")
    last = data.get("latest", {})
    last_score = last.get("score") if last else None
    # Staleness alert
    if data.get("stale"):
        days = data.get("stale_days", 0)
        insights.append(
            _insight(
                "warning",
                f"Health reports are stale — last report was {days} day(s) ago.",
                "Check that the scheduled task for SystemHealthDiag.py is running and that REPORT_DIR matches.",
            )
        )
    # Score trend
    if avg is not None:
        level = "ok" if avg >= 80 else "warning" if avg >= 60 else "critical"
        insights.append(_insight(level, f"Average health score: {avg}/100 across {len(reports)} reports."))
    if last_score is not None:
        level = "ok" if last_score >= 80 else "warning" if last_score >= 60 else "critical"
        insights.append(_insight(level, f"Latest report score: {last_score}/100 ({last.get('date_label', '')})."))
    # Trend direction — compare first 10% vs last 10%
    if len(reports) >= 10:
        scored = [r for r in reports if r["score"] is not None]
        if len(scored) >= 10:
            n = max(3, len(scored) // 10)
            early_avg = sum(r["score"] for r in scored[:n]) / n
            late_avg = sum(r["score"] for r in scored[-n:]) / n
            diff = round(late_avg - early_avg, 1)
            if diff < -5:
                insights.append(
                    _insight(
                        "warning",
                        f"Health score trending down {abs(diff):.1f} points over the period.",
                        "Review recent BSODs and driver changes in the System Timeline.",
                    )
                )
            elif diff > 5:
                insights.append(_insight("ok", f"Health score trending up {diff:.1f} points — system is improving."))
    # BSOD correlation
    reports_with_bsod = [r for r in reports if r["bsod_count"] > 0]
    if reports_with_bsod:
        insights.append(
            _insight(
                "warning",
                f"{len(reports_with_bsod)} report(s) contained BSOD events. "
                f"Most recent: {reports_with_bsod[-1].get('date_label', '')}.",
                "Cross-reference with BSOD Dashboard for stop code details.",
            )
        )
    status = (
        "critical"
        if any(i["level"] == "critical" for i in insights)
        else "warning"
        if any(i["level"] == "warning" for i in insights)
        else "ok"
    )
    headline = f"Avg score {avg}/100 — {len(reports)} reports" if avg else f"{len(reports)} reports found"
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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_upd], capture_output=True, text=True, timeout=25
        )
        upd_list = json.loads(r.stdout.strip() or "[]")
        if isinstance(upd_list, dict):
            upd_list = [upd_list]
        for u in upd_list:
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


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

# Process → category mapping
MEM_CATEGORIES = {
    "security": [
        "msmpeng",
        "nissrv",
        "securityhealthservice",
        "mbam",
        "mbamservice",
        "mc-fw-host",
        "serviceshell",
        "mfewch",
        "mfetp",
        "mfemms",
        "mcafee",
        "kavtray",
        "avp",
        "avgui",
        "avgsvc",
        "bdagent",
        "bdservicehost",
        "ekrn",
        "ccsvchst",
        "nortonsecurity",
    ],
    "browser": ["chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore", "chromium", "waterfox"],
    "microsoft": [
        "explorer",
        "dwm",
        "sihost",
        "taskhostw",
        "shellexperiencehost",
        "startmenuexperiencehost",
        "runtimebroker",
        "svchost",
        "searchhost",
        "searchindexer",
        "ctfmon",
        "fontdrvhost",
        "spoolsv",
        "dllhost",
        "conhost",
        "applicationframehost",
        "textinputhost",
        "backgroundtaskhost",
        "wuauclt",
        "msdtc",
        "audiodg",
        "dashost",
        "lsass",
        "services",
        "winlogon",
        "csrss",
        "wininit",
        "smss",
        "registry",
        "system",
    ],
    "office": ["winword", "excel", "powerpnt", "outlook", "onenote", "mspub", "visio", "officeclicktorun", "msaccess"],
    "comms": ["teams", "ms-teams", "slack", "zoom", "discord", "skype", "telegram", "signal"],
    "gpu_driver": [
        "nvcontainer",
        "nvdisplay.container",
        "nvbackend",
        "nvcplui",
        "igfxem",
        "igfxhk",
        "amdrsserv",
        "radeon",
    ],
    # Developer tools (backlog #21). Added 2026-04-19 after the user's
    # claude.exe was bucketed as "other". Ordered BEFORE "this_app" because
    # the _categorise_process substring match is bidirectional — e.g.
    # "py" (this_app) would otherwise catch "pycharm64.exe" before we
    # reach dev_tools. Also dropped the bare "py" entry from this_app
    # since it would swallow almost every Python-named developer tool.
    "dev_tools": [
        # Claude Code CLI
        "claude",
        # Popular editors
        "code",  # VS Code / VS Code Insiders renderer+host
        "code-insiders",
        "cursor",  # Cursor.com
        "windsurf",  # Codeium Windsurf
        "warp",  # Warp terminal
        "zed",  # Zed editor
        "sublime_text",
        "atom",
        "notepad++",
        # JetBrains family — IDE names vary per product
        "idea",  # IntelliJ IDEA
        "webstorm",
        "pycharm",
        "goland",
        "clion",
        "phpstorm",
        "rubymine",
        "rider",
        "datagrip",
        "fleet",  # JetBrains Fleet
        # Version control clients
        "github desktop",
        "gitkraken",
        "sourcetree",
        "fork",
        "git",  # git.exe, git-bash
        "bash",  # git-bash
        # Shells / terminals
        "wezterm",
        "alacritty",
        "tabby",
        # Docker / container tools
        "docker desktop",
        "docker",
        "wsl",
        "wslhost",
        # Node runtime (Claude Code's cli.js runs under node.exe)
        "node",
    ],
    "this_app": ["python", "pythonw", "windesktopmgr", "flask"],
    "games": ["steam", "steamwebhelper", "epicgameslauncher", "origin", "battlenet", "geforceexperience"],
    "cloud": ["onedrive", "dropbox", "googledrivefs", "box", "icloudservices"],
    "other": [],
}

# McAfee processes specifically for the comparison
MCAFEE_PROCS = {
    "mc-fw-host",
    "serviceshell",
    "mfewch",
    "mfetp",
    "mfemms",
    "mcafee",
    "mfefire",
    "mfevtps",
    "mfehidk",
    "mfecscan",
}
DEFENDER_PROCS = {"msmpeng", "nissrv", "securityhealthservice", "securityhealthsystray"}


def _categorise_process(name: str) -> str:
    n = name.lower().replace(".exe", "")
    for cat, procs in MEM_CATEGORIES.items():
        if any(p in n or n in p for p in procs):
            return cat
    return "other"


def get_memory_analysis() -> dict:
    """Summarise system memory usage using psutil (no PowerShell).

    Replaces the older ``Get-Process`` + ``Get-WmiObject Win32_OperatingSystem``
    pipeline (backlog #24 batch A, sites #36 + #37). ``psutil.virtual_memory``
    reports MB totals from the Windows global memory status, and
    ``process_iter(['name', 'memory_info'])`` gives the per-process working
    set in bytes — matching what ``WorkingSet64`` returned.
    """
    try:
        procs: list[dict] = []
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                info = proc.info
                name = info.get("name") or ""
                mem = info.get("memory_info")
                mem_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0
                procs.append({"ProcessName": name, "MemMB": mem_mb, "PID": info.get("pid")})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # System memory info — psutil.virtual_memory returns bytes.
        vm = psutil.virtual_memory()
        total_mb = round(vm.total / (1024 * 1024), 0)
        free_mb = round(vm.available / (1024 * 1024), 0)
        used_mb = total_mb - free_mb

        # Categorise. Also keep a per-vendor breakdown list so the UI can
        # reconcile the vendor-rollup number against the per-process table
        # (2026-04-11 bug: user saw McAfee=1730 MB total but mc-fw-host=
        # 1015 MB in the table — the rest of the vendor total came from
        # sibling processes the table happened not to show, e.g. mcshield,
        # mfevtps. This breakdown makes the math auditable).
        #
        # Note on Windows memory accounting: psutil's rss == WorkingSet64,
        # which counts every resident page the process can reference --
        # including DLLs shared across processes. Summing rss across
        # multi-process vendors like McAfee therefore slightly overstates
        # the unique resident footprint (shared pages get counted once per
        # process). This is the same accounting that Task Manager's
        # "Memory (active private working set)" column shows, and is the
        # best we can get without calling QueryWorkingSetEx per-page.
        categories: dict = {c: 0.0 for c in MEM_CATEGORIES}
        mcafee_mb = 0.0
        defender_mb = 0.0
        mcafee_breakdown: list[dict] = []
        defender_breakdown: list[dict] = []
        top_procs = []

        for p in procs:
            name = (p.get("ProcessName") or "").lower()
            mem = p.get("MemMB", 0) or 0
            cat = _categorise_process(name)
            categories[cat] = categories.get(cat, 0) + mem
            if any(mp in name for mp in MCAFEE_PROCS):
                mcafee_mb += mem
                mcafee_breakdown.append({"name": p.get("ProcessName", ""), "mem": mem})
            if any(dp in name for dp in DEFENDER_PROCS):
                defender_mb += mem
                defender_breakdown.append({"name": p.get("ProcessName", ""), "mem": mem})
            top_procs.append({"name": p.get("ProcessName", ""), "mem": mem, "category": cat, "pid": p.get("PID")})

        top_procs.sort(key=lambda x: x["mem"], reverse=True)
        mcafee_breakdown.sort(key=lambda x: x["mem"], reverse=True)
        defender_breakdown.sort(key=lambda x: x["mem"], reverse=True)

        # Defender baseline estimate (from Microsoft specs: ~100–200 MB typical)
        defender_baseline_mb = max(defender_mb, 150)
        mcafee_saving_mb = round(mcafee_mb - defender_baseline_mb, 0)

        # 'Other' bucket audit (backlog #21): when unclassified processes
        # cross 5 % of total RAM, surface the top 3 names so we know what
        # entries to add to MEM_CATEGORIES next time. Small memory footprint
        # processes (< 50 MB) get filtered out -- they're noise, not
        # classification gaps.
        other_total_mb = round(categories.get("other", 0), 0)
        other_pct = round(other_total_mb / total_mb * 100, 1) if total_mb else 0.0
        other_top = [
            {"name": p["name"], "mem": p["mem"]}
            for p in top_procs
            if p.get("category") == "other" and p.get("mem", 0) >= 50
        ][:3]

        return {
            "total_mb": total_mb,
            "used_mb": round(used_mb, 0),
            "free_mb": round(free_mb, 0),
            "categories": {k: round(v, 0) for k, v in categories.items()},
            "top_procs": top_procs[:20],
            "mcafee_mb": round(mcafee_mb, 0),
            "defender_mb": round(defender_mb, 0),
            "mcafee_processes": mcafee_breakdown,
            "defender_processes": defender_breakdown,
            "defender_baseline": defender_baseline_mb,
            "mcafee_saving_mb": max(mcafee_saving_mb, 0),
            "has_mcafee": mcafee_mb > 50,
            "other_pct": other_pct,
            "other_top_unclassified": other_top,
            "other_needs_audit": other_pct > 5.0,
            "accounting_note": (
                "Vendor totals sum per-process RSS (Windows WorkingSet64). "
                "Shared DLL pages are counted once per process, so totals "
                "slightly overstate unique resident memory."
            ),
        }
    except Exception as e:
        print(f"[MemAnalysis] error: {e}")
        return {}


def summarize_memory(data: dict) -> dict:
    if not data:
        return {"status": "ok", "headline": "No memory data.", "insights": [], "actions": []}
    insights, actions = [], []
    total = data.get("total_mb", 32768)
    used = data.get("used_mb", 0)
    free = data.get("free_mb", 0)
    pct = round(used / total * 100, 1) if total else 0
    cats = data.get("categories", {})

    level = "critical" if pct > 90 else "warning" if pct > 75 else "ok"
    insights.append(_insight(level, f"{used:,.0f} MB used of {total:,.0f} MB ({pct}%). {free:,.0f} MB free."))

    browser_mb = cats.get("browser", 0)
    comms_mb = cats.get("comms", 0)
    if browser_mb > 2000:
        insights.append(_insight("warning", f"Browsers are using {browser_mb:,.0f} MB. Consider closing unused tabs."))
    if comms_mb > 1000:
        insights.append(_insight("info", f"Communication apps (Teams, Slack, etc.) are using {comms_mb:,.0f} MB."))
    if pct < 75:
        insights.append(_insight("ok", "Memory usage is within normal limits."))

    status = "critical" if pct > 90 else "warning" if pct > 75 else "ok"
    headline = f"{pct}% RAM used — {used:,.0f}/{total:,.0f} MB"
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY CONCERN SNOOZE (backlog #19)
# ══════════════════════════════════════════════════════════════════════════════
#
# Per-process memory concerns can be dismissed for 24 hours at a time via the
# "⏳ Snooze" action button. A snooze is keyed by the process NAME (not PID,
# because PIDs are ephemeral -- the user snoozing "chrome.exe at 2.5 GB" wants
# that suppressed regardless of which chrome.exe instance).
MEMORY_SNOOZE_FILE = os.path.join(APP_DIR, "memory_snoozes.json")
_memory_snooze_lock = threading.RLock()


def _load_memory_snoozes() -> dict:
    """Return {process_name_lower: expiry_iso}. Expired entries are filtered."""
    with _memory_snooze_lock:
        try:
            if not os.path.exists(MEMORY_SNOOZE_FILE):
                return {}
            with open(MEMORY_SNOOZE_FILE, encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return {}
        except (OSError, json.JSONDecodeError):
            return {}
        now = datetime.now()
        out = {}
        dirty = False
        for key, iso in raw.items():
            try:
                expiry = datetime.fromisoformat(iso)
            except (ValueError, TypeError):
                dirty = True
                continue
            if expiry > now:
                out[key] = iso
            else:
                dirty = True
        if dirty:
            _save_memory_snoozes(out, _already_locked=True)
        return out


def _save_memory_snoozes(snoozes: dict, *, _already_locked: bool = False) -> None:
    """Write the snooze map atomically."""
    body = json.dumps(snoozes, indent=2)
    tmp = MEMORY_SNOOZE_FILE + ".tmp"
    if _already_locked:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(tmp, MEMORY_SNOOZE_FILE)
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
        return
    with _memory_snooze_lock:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(tmp, MEMORY_SNOOZE_FILE)
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass


def add_memory_snooze(process_name: str, hours: int = 24) -> dict:
    """Snooze warnings for ``process_name`` for ``hours`` (default 24)."""
    key = (process_name or "").strip().lower()
    if not key:
        return {"ok": False, "error": "process_name required"}
    if not isinstance(hours, int) or hours <= 0 or hours > 168:
        return {"ok": False, "error": "hours must be 1..168"}
    with _memory_snooze_lock:
        snoozes = _load_memory_snoozes()
        expiry = datetime.now() + timedelta(hours=hours)
        snoozes[key] = expiry.isoformat(timespec="seconds")
        _save_memory_snoozes(snoozes, _already_locked=True)
        return {"ok": True, "key": key, "expires": snoozes[key]}


def remove_memory_snooze(process_name: str) -> dict:
    key = (process_name or "").strip().lower()
    with _memory_snooze_lock:
        snoozes = _load_memory_snoozes()
        existed = snoozes.pop(key, None) is not None
        _save_memory_snoozes(snoozes, _already_locked=True)
        return {"ok": True, "removed": existed}


def is_memory_snoozed(process_name: str) -> bool:
    key = (process_name or "").strip().lower()
    if not key:
        return False
    return key in _load_memory_snoozes()


# ══════════════════════════════════════════════════════════════════════════════
# BIOS & FIRMWARE CHECKER
# ══════════════════════════════════════════════════════════════════════════════

BIOS_CACHE_FILE = os.path.join(APP_DIR, "bios_cache.json")


def get_current_bios() -> dict:
    try:
        c = _wmi_conn()
        bios = c.Win32_BIOS()[0]
        board = c.Win32_BaseBoard()[0]
        raw_date = bios.ReleaseDate or ""
        bios_date = ""
        if raw_date and len(raw_date) >= 8:
            try:
                bios_date = datetime.strptime(raw_date[:8], "%Y%m%d").strftime("%B %d, %Y")
            except Exception:
                bios_date = raw_date[:8]
        return {
            "BIOSVersion": bios.SMBIOSBIOSVersion,
            "ReleaseDate": raw_date,
            "Manufacturer": bios.Manufacturer,
            "BoardProduct": board.Product,
            "BoardMfr": board.Manufacturer,
            "BIOSDateFormatted": bios_date,
        }
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
            age = (datetime.now(timezone.utc) - _parse_ts(cached.get("checked_at", ""))).total_seconds() / 3600
            if age < 24:
                return cached
    except Exception:
        pass

    # Get service tag dynamically from WMI
    service_tag = ""
    try:
        tag = _wmi_conn().Win32_BIOS()[0].SerialNumber
        if tag and len(tag) >= 5:
            service_tag = tag
    except Exception:
        pass

    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "current_version": current_version,
        "latest_version": None,
        "latest_date": None,
        "update_available": False,
        "release_notes": "",
        "service_tag": service_tag,
        "download_url": (
            f"https://www.dell.com/support/home/en-us/product-support/servicetag/{service_tag}/drivers"
            if service_tag
            else "https://www.dell.com/support/home/en-us"
        ),
        "source": "unknown",
        "error": None,
    }

    def _ver_gt(latest: str, current: str) -> bool:
        def _v(s):
            return [int(x) for x in re.split(r"[.\-]", str(s)) if x.isdigit()]

        try:
            return _v(latest) > _v(current)
        except Exception:
            return latest.strip() != current.strip()

    # ── Method 1: Dell Command Update CLI ─────────────────────────────────────
    # DCU is pre-installed on Dell XPS systems at a predictable path
    dcu_paths = [
        r"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
        r"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
        r"C:\Program Files\Dell\Dell Command Update\dcu-cli.exe",
    ]
    dcu_exe = next((p for p in dcu_paths if os.path.exists(p)), None)
    if dcu_exe:
        try:
            import tempfile
            import uuid

            tmp = os.path.join(tempfile.gettempdir(), f"dcu_scan_{uuid.uuid4().hex}.xml")
            subprocess.run(
                [dcu_exe, "/scan", f"-outputLog={tmp}", "-silent"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if os.path.exists(tmp):
                try:
                    with open(tmp, encoding="utf-8", errors="replace") as f:
                        xml_content = f.read()
                    # Find BIOS updates in the output
                    m = re.search(r'type="BIOS"[^/]*/.*?version="([0-9.]+)"', xml_content, re.DOTALL | re.IGNORECASE)
                    if not m:
                        m = re.search(r'BIOS.*?version="([0-9.]+)"', xml_content, re.DOTALL | re.IGNORECASE)
                    if m:
                        ver = m.group(1)
                        result["latest_version"] = ver
                        result["source"] = "dell_command_update"
                        result["update_available"] = _ver_gt(ver, current_version)
                        print(f"[BIOS] DCU found version: {ver}")
                finally:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        except Exception as e:
            result["error"] = f"DCU: {e}"
    else:
        print("[BIOS] DCU not found")

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
                ["powershell", "-NonInteractive", "-Command", ps_catalog], capture_output=True, text=True, timeout=90
            )
            out2 = r2.stdout.strip()
            if out2 and out2.startswith("{"):
                data2 = json.loads(out2)
                ver2 = data2.get("Version", "")
                if ver2:
                    result["latest_version"] = ver2
                    result["latest_date"] = data2.get("ReleaseDate", "")
                    result["release_notes"] = data2.get("Name", "")[:200]
                    result["download_url"] = data2.get("Path", result["download_url"])
                    result["source"] = "dell_catalog"
                    result["update_available"] = _ver_gt(ver2, current_version)
                    result["error"] = None
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
                ["powershell", "-NonInteractive", "-Command", ps_wu], capture_output=True, text=True, timeout=30
            )
            out3 = r3.stdout.strip()
            if out3 and out3.startswith("{"):
                data3 = json.loads(out3)
                ver3 = data3.get("Version", "")
                title = data3.get("Title", "")
                if ver3:
                    result["latest_version"] = ver3
                    result["release_notes"] = title[:200]
                    result["source"] = "windows_update"
                    result["update_available"] = True  # WU only shows pending updates
                    result["error"] = None
                    print(f"[BIOS] Windows Update found BIOS update: {title}")
        except Exception:
            pass

    # ── Method 4: Get service tag for a direct personalised Dell support URL ────
    # If we didn't get it at the top (e.g. timeout), try once more
    if not result.get("service_tag"):
        try:
            tag = _wmi_conn().Win32_BIOS()[0].SerialNumber
            if tag and len(tag) >= 5:
                result["service_tag"] = tag
                result["download_url"] = (
                    f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers"
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

    print(f"[BIOS] Done: current={current_version} latest={result['latest_version']} source={result['source']}")
    return result


def get_bios_status() -> dict:
    current = get_current_bios()
    version = current.get("BIOSVersion", "")
    update = check_dell_bios_update(current.get("BoardProduct", ""), version)
    return {"current": current, "update": update}


def summarize_bios(data: dict) -> dict:
    current = data.get("current", {})
    update = data.get("update", {})
    insights, actions = [], []
    version = current.get("BIOSVersion", "Unknown")
    bios_date = current.get("BIOSDateFormatted", "")
    insights.append(_insight("info", f"Current BIOS: {version} ({bios_date}, {current.get('Manufacturer', '')})."))
    tag = update.get("service_tag", "")
    tag_url = (
        f"https://www.dell.com/support/home/en-us/product-support/servicetag/{tag}/drivers"
        if tag
        else "https://www.dell.com/support/home/en-us?app=drivers"
    )

    if update.get("update_available"):
        latest = update.get("latest_version", "")
        insights.append(
            _insight(
                "critical",
                f"BIOS update available: {latest} (you have {version}). "
                f"Update immediately — this may fix your HYPERVISOR_ERROR crashes.",
                "Update via Dell Command Update or download directly from Dell Support.",
            )
        )
        actions.append("Update BIOS via Dell Command Update")
    elif update.get("latest_version"):
        src = update.get("source", "")
        src_note = " (confirmed by Dell)" if src == "confirmed_current" else f" (source: {src})"
        insights.append(
            _insight(
                "ok",
                f"BIOS {version} is current — no update needed{src_note}. "
                f"Latest: {update['latest_version']} ({update.get('latest_date', '')}).",
            )
        )
        if update.get("release_notes"):
            insights.append(_insight("info", update["release_notes"]))
    else:
        insights.append(
            _insight(
                "info",
                f"Could not auto-detect latest version from Dell. Your current BIOS is {version}.",
                f"Check your personalised Dell page at: {tag_url}",
            )
        )
    # Special note for i9-14900K HYPERVISOR_ERROR
    # Only show the Raptor Lake note — framed correctly given BIOS is current
    insights.append(
        _insight(
            "info",
            "Your i9-14900K is affected by Intel Raptor Lake instability (intelppm.sys / HYPERVISOR_ERROR). "
            "BIOS 2.22.0 includes Intel microcode patches for this issue — your BIOS is current, no update needed. "
            "If HYPERVISOR_ERROR crashes continue, the remaining mitigations are: "
            "disable C-States in BIOS, and disable Memory Integrity in Windows Security > Core Isolation.",
            "To access BIOS settings: restart and press F2 at the Dell splash screen. "
            "Or from PowerShell (Admin): shutdown /r /fw /t 0",
        )
    )
    status = "critical" if update.get("update_available") else "warning" if not update.get("latest_version") else "ok"
    headline = (
        f"BIOS update available: {update.get('latest_version', '')}"
        if update.get("update_available")
        else f"BIOS {version} — {'up to date' if update.get('latest_version') else 'check manually'}"
    )
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
                $portNum   = if ($proto -eq "NFS") { 2049 } else { 445 }
                $dialect   = ""
                $mappedDrives += [PSCustomObject]@{
                    Name        = $pd.Name
                    Root        = $pd.Root
                    DisplayRoot = $disp
                    Reachable   = [bool]$reachable
                    Protocol    = $proto
                    Port        = $portNum
                    Dialect     = $dialect
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

    import concurrent.futures

    list_keys = {"creds", "events", "fw"}

    def _run_ps(name, ps):
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=25
            )
            raw = r.stdout.strip()
            return name, json.loads(raw) if raw and raw not in ("", "[]", "{}") else ([] if name in list_keys else {})
        except Exception as e:
            print(f"[CredNet] {name} error: {e}")
            return name, [] if name in list_keys else {}

    results = {}
    scripts = [
        ("creds", ps_creds),
        ("smb", ps_smb),
        ("onedrive", ps_onedrive),
        ("fast", ps_fast),
        ("events", ps_events),
        ("fw", ps_fw),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run_ps, n, ps): n for n, ps in scripts}
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            try:
                name, data = fut.result()
                results[name] = data
            except Exception as e:
                fallback_name = futures[fut]
                print(f"[CredNet] {fallback_name} error: {e}")
                results[fallback_name] = [] if fallback_name in list_keys else {}

    creds = results.get("creds", [])
    smb = results.get("smb", {})
    onedrive = results.get("onedrive", {})
    fast = results.get("fast", {})
    events = results.get("events", [])
    fw = results.get("fw", [])
    if isinstance(creds, dict):
        creds = [creds]
    if isinstance(events, dict):
        events = [events]
    if isinstance(fw, dict):
        fw = [fw]

    # Categorise credentials
    email_creds = [
        c
        for c in creds
        if any(
            w in str(c.get("Target", "")).lower()
            for w in (
                "outlook",
                "office",
                "microsoft",
                "smtp",
                "imap",
                "exchange",
                "gmail",
                "yahoo",
                "icloud",
                "microsoftonline",
                "live.com",
            )
        )
    ]
    nas_creds = [
        c
        for c in creds
        if any(
            w in str(c.get("Target", "")).lower()
            for w in ("smb", "nas", "share", "synology", "qnap", "wd", "netgear", "cifs", "nfs")
        )
    ]

    # Drives - SMB/CIFS/NFS
    drives = smb.get("MappedDrives", []) if isinstance(smb, dict) else []
    drives_down = [d for d in drives if not d.get("Reachable", True)]
    drives_up = [d for d in drives if d.get("Reachable", True)]
    smb_drives = [d for d in drives if "SMB" in d.get("Protocol", "")]
    nfs_drives = [d for d in drives if "NFS" in d.get("Protocol", "")]
    nfs_mounts = smb.get("NfsMounts", []) if isinstance(smb, dict) else []

    # OneDrive / M365 token status
    od_running = onedrive.get("OneDriveRunning", False) if isinstance(onedrive, dict) else False
    od_connected = onedrive.get("OneDriveConnected", False) if isinstance(onedrive, dict) else False
    od_account = onedrive.get("OneDriveAccount", "") if isinstance(onedrive, dict) else ""
    msal_files = onedrive.get("MsalCacheFiles", 0) if isinstance(onedrive, dict) else 0
    msal_newest = onedrive.get("MsalCacheNewest") if isinstance(onedrive, dict) else None
    msal_size = onedrive.get("MsalCacheSizeKB", 0) if isinstance(onedrive, dict) else 0
    office_creds = onedrive.get("OfficeCreds", []) if isinstance(onedrive, dict) else []
    office_errors = onedrive.get("OfficeErrors", []) if isinstance(onedrive, dict) else []

    # Token age - flag if MSAL token older than 8 hours
    token_stale = False
    token_age_h = None
    if msal_newest:
        try:
            token_dt = _parse_ts(msal_newest)
            token_age_h = round((datetime.now(timezone.utc) - token_dt).total_seconds() / 3600, 1)
            token_stale = token_age_h > 8
        except Exception:
            pass

    # Credential events
    cred_failures = [e for e in events if e.get("Id") in (4625, 4776)]
    cred_explicit = [e for e in events if e.get("Id") == 4648]
    fast_startup = fast.get("FastStartupEnabled")
    fw_blocking = [f for f in fw if f.get("Action", "") == "Block" and f.get("Enabled")]

    return {
        "creds": creds,
        "email_creds": email_creds,
        "nas_creds": nas_creds,
        "drives": drives,
        "drives_down": drives_down,
        "drives_up": drives_up,
        "smb_drives": smb_drives,
        "nfs_drives": nfs_drives,
        "nfs_mounts": nfs_mounts,
        "smb_connections": smb.get("SmbConnections", []) if isinstance(smb, dict) else [],
        "smb_config": smb.get("SmbConfig") if isinstance(smb, dict) else None,
        "fast_startup": fast_startup,
        "cred_failures": cred_failures[:10],
        "cred_explicit": cred_explicit[:5],
        "fw_rules": fw,
        "fw_blocking": fw_blocking,
        "total_creds": len(creds),
        "broker_issues": onedrive.get("BrokerIssues", []) if isinstance(onedrive, dict) else [],
        "ms_account_suspended": onedrive.get("MsAccountSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_running": od_running,
        "onedrive_suspended": onedrive.get("OneDriveSuspended", False) if isinstance(onedrive, dict) else False,
        "onedrive_priority": onedrive.get("OneDrivePriority", "") if isinstance(onedrive, dict) else "",
        "suspended_auth_procs": onedrive.get("SuspendedAuthProcs", []) if isinstance(onedrive, dict) else [],
        "onedrive_connected": od_connected,
        "onedrive_account": od_account,
        "msal_cache_files": msal_files,
        "msal_cache_newest": msal_newest,
        "msal_cache_size_kb": msal_size,
        "msal_token_age_h": token_age_h,
        "msal_token_stale": token_stale,
        "office_creds": office_creds,
        "office_errors": office_errors[:5],
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
        insights.append(
            _insight(
                "warning",
                "Fast Startup is enabled. This is a known cause of SMB share disconnection and "
                "credential loss on reboot. Windows does not fully shut down — network state is "
                "partially preserved in a hibernation file and sometimes restored incorrectly.",
                "Disable Fast Startup: Control Panel > Power Options > Choose what the power "
                "buttons do > Turn on fast startup (uncheck). Then do a full Restart (not Shut Down).",
            )
        )
        actions.append("Disable Fast Startup to fix SMB credential loss on reboot")
    elif fast_startup is False:
        insights.append(_insight("ok", "Fast Startup is disabled. Full shutdown/restart cycle is in effect."))
    else:
        insights.append(_insight("info", "Could not determine Fast Startup state."))

    # Drives down
    if drives_down:
        insights.append(
            _insight(
                "critical",
                f"{len(drives_down)} mapped SMB drive(s) currently unreachable: "
                + ", ".join(f"{d.get('Name', '?')}: ({d.get('DisplayRoot', '')})" for d in drives_down[:3]),
                "Check NAS device is powered on and reachable on the network. Try: net use * /delete then remap.",
            )
        )
        actions.append("Reconnect unreachable SMB drives")
    elif data.get("drives"):
        insights.append(_insight("ok", f"All {len(data['drives'])} mapped SMB drive(s) are reachable."))

    # OneDrive / M365 token status
    token_stale = data.get("msal_token_stale", False)
    token_age = data.get("msal_token_age_h")
    od_running = data.get("onedrive_running", False)
    od_connected = data.get("onedrive_connected", False)
    od_account = data.get("onedrive_account", "")
    office_errs = data.get("office_errors", [])
    # Note: backgroundTaskHost suspensions are typically McAfee's idle UWP RulesEngine —
    # normal Windows behavior, not an auth issue. The real auth issue is OneDrive suspension.
    od_suspended = data.get("onedrive_suspended", False)
    susp_auth = data.get("suspended_auth_procs", [])

    if od_suspended:
        insights.append(
            _insight(
                "critical",
                "OneDrive process is SUSPENDED by Windows memory management. "
                "This is the direct cause of the Sign in Required error in Word and Outlook. "
                "When OneDrive is suspended it cannot refresh Microsoft 365 OAuth tokens.",
                "Fix: run the Resume OneDrive button, or run in PowerShell: "
                "Get-Process OneDrive | ForEach-Object { $_.Threads | ForEach-Object { try { $_.Resume() } catch {} } }. "
                "To prevent recurrence, set OneDrive to AboveNormal priority.",
            )
        )
        actions.append("Resume OneDrive process to fix Office 365 sign-in errors")
    if susp_auth:
        names = ", ".join(p.get("Name", "") for p in susp_auth[:3])
        insights.append(
            _insight(
                "warning",
                f"Other auth-related processes are suspended: {names}. "
                "These may also contribute to Office connectivity issues.",
                "Use the Resume Auth Brokers button to restore them.",
            )
        )

    if token_stale and not od_suspended:
        age_str = f"{token_age:.0f} hours" if token_age else "unknown"
        insights.append(
            _insight(
                "critical",
                f"Microsoft 365 authentication token is {age_str} old. "
                "This is the direct cause of the Sign in Required error in Word and Outlook.",
                "Fix: click the OneDrive cloud icon in the system tray and sign in. "
                "Tokens refresh for all Office apps once signed in.",
            )
        )
        actions.append("Re-sign into OneDrive to fix Office 365 credential expiry")
    elif not od_connected and not od_suspended:
        insights.append(
            _insight(
                "warning",
                "OneDrive is not connected to an account. Office apps will show sign-in prompts.",
                "Click the OneDrive cloud icon in the system tray and sign in.",
            )
        )
    elif not od_running:
        insights.append(
            _insight(
                "warning",
                "OneDrive process is not running. Office credential sync is paused.",
                "Launch OneDrive from the Start menu.",
            )
        )
    else:
        age_str = f" (token refreshed {token_age:.0f}h ago)" if token_age is not None else ""
        acct = f" as {od_account}" if od_account else ""
        insights.append(_insight("ok", f"OneDrive connected{acct}{age_str}."))
    if office_errs:
        insights.append(
            _insight(
                "warning",
                f"{len(office_errs)} recent Office or OneDrive error event(s) in Application log.",
                "Check Event Viewer > Application log for OneDrive and Microsoft Office errors.",
            )
        )

    # NFS/CIFS breakdown
    nfs_drives = data.get("nfs_drives", [])
    if nfs_drives:
        nfs_down = [d for d in nfs_drives if not d.get("Reachable", True)]
        insights.append(
            _insight(
                "critical" if nfs_down else "ok",
                f"{len(nfs_drives)} NFS mount(s): "
                + ", ".join(f"{d.get('Name', '?')} ({d.get('DisplayRoot', '')})" for d in nfs_drives[:3])
                + (f" -- {len(nfs_down)} unreachable" if nfs_down else " -- all reachable"),
            )
        )

    # Email credentials
    if email_creds:
        insights.append(
            _insight(
                "info",
                f"{len(email_creds)} email credential(s) in Credential Manager: "
                + ", ".join(c.get("Target", "")[:40] for c in email_creds[:3]),
                "If Outlook loses these on reboot, check credential Type is Generic not Session.",
            )
        )
    else:
        insights.append(
            _insight(
                "warning",
                "No email credentials in Credential Manager. Outlook uses MSAL token cache only.",
                "Open Credential Manager from Start and check Windows Credentials tab.",
            )
        )

    # Credential failures
    if cred_failures:
        insights.append(
            _insight(
                "warning",
                f"{len(cred_failures)} credential failure event(s) in Security log (Event 4625/4776). "
                "These may correlate with the Outlook and NAS disconnection issues.",
                "Check Security Event Log for the account names and sources involved.",
            )
        )

    # Firewall blocking
    if fw_blocking:
        insights.append(
            _insight(
                "warning",
                "File and Printer Sharing firewall rule(s) set to Block: "
                + ", ".join(f.get("DisplayName", "") for f in fw_blocking[:2]),
                "McAfee may have modified these rules. Check McAfee Firewall settings.",
            )
        )

    # SMB signing
    if smb_config and smb_config.get("RequireSecuritySignature"):
        insights.append(
            _insight(
                "info",
                "SMB security signing is required. If your NAS does not support SMB signing "
                "this can cause intermittent connection failures.",
                "Check NAS SMB settings and ensure SMB2/3 is enabled on the NAS.",
            )
        )

    token_stale = data.get("msal_token_stale", False)
    od_suspended = data.get("onedrive_suspended", False)
    status = (
        "critical"
        if od_suspended or drives_down or token_stale
        else "warning"
        if (fast_startup or cred_failures or fw_blocking or not email_creds)
        else "ok"
    )
    headline = (
        "OneDrive SUSPENDED -- direct cause of Word/Outlook sign-in errors"
        if od_suspended
        else "Office 365 token expired -- re-sign into OneDrive to fix"
        if token_stale
        else f"{len(drives_down)} SMB/CIFS/NFS drive(s) unreachable"
        if drives_down
        else "Fast Startup ON -- likely cause of credential loss on reboot"
        if fast_startup
        else f"{data.get('total_creds', 0)} credentials stored -- connections healthy"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

_flask_log = get_logger("flask")


class _RequestLogFloodSuppressor:
    """Collapse runs of adjacent identical successful requests into one log
    line with a suppressed count.

    The 2026-04-20 UI incident generated thousands of identical
    ``POST /api/summary/drivers status=200`` lines per second, burying
    real signal (a BIOS-audit WARNING became invisible in the Logs tab
    because it fell off the tail-read budget). This suppressor keyed by
    ``(method, path, status)`` skips consecutive duplicates within a
    short window and emits a running count on the next non-duplicate.

    Kept per-key: the last-logged timestamp, and how many duplicates
    were suppressed since. Only consecutive runs are folded -- A/B/A/B
    alternation still logs every line. That matches the real failure
    mode (one runaway client hammering one route) while keeping normal
    traffic fully visible.

    Thread-safe: every access is under ``self._lock``. The after_request
    hook can run on many threads concurrently.
    """

    # If a new occurrence of the same key arrives within this many seconds
    # of the last one we actually logged, it's a dup. Larger windows
    # suppress more aggressively; smaller windows preserve more granularity.
    # 10s chosen so a once-per-poll-tick endpoint at 5s cadence still gets
    # logged every time, but a runaway 100-rps flood is collapsed.
    WINDOW_SECONDS = 10.0

    def __init__(self) -> None:
        # key -> (last_logged_time, suppressed_count_since_last_log)
        self._state: dict[tuple, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def note(self, key: tuple) -> tuple[bool, int]:
        """Record an occurrence of ``key``.

        Returns ``(should_log, suppressed_count)``:

            should_log=True  -> emit the log line. ``suppressed_count``
                                is how many duplicates were skipped since
                                the previous log for this key. Append to
                                the log message when >0.
            should_log=False -> skip. ``suppressed_count`` is always 0 in
                                this branch.
        """
        now = time.time()
        with self._lock:
            last = self._state.get(key)
            if last is not None:
                last_ts, count = last
                if now - last_ts < self.WINDOW_SECONDS:
                    self._state[key] = (last_ts, count + 1)
                    return (False, 0)
                # Window expired — log this one and include the backlog
                self._state[key] = (now, 0)
                return (True, count)
            self._state[key] = (now, 0)
            return (True, 0)


_request_log_suppressor = _RequestLogFloodSuppressor()


@app.before_request
def _log_request_start():
    """Stamp the start time so we can report request duration on completion."""
    request._wdm_start_time = time.time()


@app.after_request
def _log_request_end(response):
    """Log every HTTP request with method, path, status, duration, size,
    client IP, and query string. Skip /api/health to avoid polluting the log.

    Non-success responses (>=400) always log -- those are the signal
    that must never be suppressed. Successful responses flow through
    the flood suppressor so runaway clients can't bury real events.
    """
    try:
        path = request.path or ""
        # Suppress heartbeat polls -- they would dominate the log
        if path == "/api/health":
            return response
        start = getattr(request, "_wdm_start_time", None)
        elapsed_ms = int((time.time() - start) * 1000) if start else 0

        # Client info
        remote = request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip()
        qs = request.query_string.decode("utf-8", errors="replace") if request.query_string else ""
        qs_snip = ("?" + qs[:120]) if qs else ""

        # Response size if known
        try:
            size = response.calculate_content_length()
        except Exception:  # noqa: BLE001
            size = None
        size_str = f"{size}b" if size is not None else "-"

        is_error = response.status_code >= 400

        # Flood-suppress only successful requests -- errors are rare-by-
        # definition AND they're exactly what we need to see in the logs.
        suppressed = 0
        if not is_error:
            key = (request.method, path, response.status_code)
            should_log, suppressed = _request_log_suppressor.note(key)
            if not should_log:
                return response

        suffix = f" (+{suppressed} similar suppressed)" if suppressed else ""
        level = _flask_log.warning if is_error else _flask_log.info
        level(
            "%s %s%s status=%d elapsed=%dms size=%s client=%s%s",
            request.method,
            path,
            qs_snip,
            response.status_code,
            elapsed_ms,
            size_str,
            remote,
            suffix,
        )
    except Exception:  # noqa: BLE001
        pass  # never break a request just because logging failed
    return response


@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/health")
def api_health():
    """Lightweight heartbeat endpoint for server-alive checks."""
    return jsonify({"ok": True, "status": "running"})


def _parse_log_query():
    """Shared query-string parsing for /api/logs and download routes."""
    try:
        n = int(request.args.get("lines", 200))
    except (TypeError, ValueError):
        n = 200
    n = max(1, min(n, 20000))
    level = request.args.get("level") or None
    return n, level


@app.route("/api/logs")
def api_logs():
    """Return recent log entries from the rotating app log file.

    Query params:
        lines (int)   -- how many entries to return, default 200, max 20000
        level (str)   -- minimum severity (DEBUG/INFO/WARNING/ERROR/CRITICAL)
    """
    from applogging import read_recent

    n, level = _parse_log_query()
    # API browser view is capped tighter than downloads
    n = min(n, 2000)
    entries = read_recent(lines=n, min_level=level)
    return jsonify({"ok": True, "count": len(entries), "entries": entries})


@app.route("/api/logs/download")
def api_logs_download():
    """Download recent log entries as JSON or CSV.

    Query params:
        format (str)  -- "json" (default) or "csv"
        lines (int)   -- how many entries to return, default 2000, max 20000
        level (str)   -- minimum severity (DEBUG/INFO/WARNING/ERROR/CRITICAL)
    """
    import csv
    import io

    from applogging import read_recent

    n, level = _parse_log_query()
    fmt = (request.args.get("format") or "json").lower()
    entries = read_recent(lines=n, min_level=level)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["timestamp", "level", "thread", "logger", "source", "message"])
        for e in entries:
            writer.writerow(
                [
                    e.get("timestamp", ""),
                    e.get("level", ""),
                    e.get("thread", ""),
                    e.get("logger", ""),
                    e.get("source", ""),
                    e.get("message", ""),
                ]
            )
        resp = make_response(buf.getvalue())
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="windesktopmgr_logs_{ts}.csv"'
        return resp

    # Default: JSON download
    payload = json.dumps({"count": len(entries), "entries": entries}, indent=2)
    resp = make_response(payload)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="windesktopmgr_logs_{ts}.json"'
    return resp


# ── Self-test smoke check registry ────────────────────────────────────────────
# Each entry: (name, function, timeout_seconds). Functions are resolved lazily
# at request time so tests can monkey-patch them.
SELFTEST_CHECKS: list[tuple[str, str, int]] = [
    ("memory", "get_memory_analysis", 15),
    ("disk", "get_disk_health", 20),
    ("network", "get_network_data", 15),
    ("thermals", "get_thermals", 15),
    ("processes", "get_process_list", 15),
    ("services", "get_services_list", 20),
    ("startup", "get_startup_items", 15),
    ("bsod", "get_bsod_events", 15),
    ("drivers", "get_driver_health", 60),
    ("updates", "get_update_history", 20),
    ("credentials", "get_credentials_network_health", 20),
    ("bios", "get_bios_status", 15),
    ("timeline", "get_system_timeline", 20),
    ("health_history", "get_health_report_history", 10),
]


@app.route("/api/selftest")
def api_selftest():
    """Run every key data-collection function in parallel and report per-check
    ok/duration/error. Used by post-restart smoke checks to verify the app
    came back up cleanly. Real PowerShell calls — slow but authoritative.
    """
    import concurrent.futures

    results: list[dict] = []
    # Overall wall-time budget for all 14 checks running in parallel. Had to
    # bump 90 → 180 on 2026-04-18 because slow checks (bsod/timeline/processes/
    # bios ≈ 45-58 s each) can eat the budget before drivers finishes its WMI
    # + NVIDIA lookups. The per-check timeouts in SELFTEST_CHECKS are only
    # nominal — only this budget actually fires.
    overall_budget = 180  # seconds

    def _run_check(name: str, fn_name: str, _timeout: int) -> dict:
        fn = globals().get(fn_name)
        start = time.time()
        if fn is None:
            return {
                "name": name,
                "ok": False,
                "duration_ms": 0,
                "error": f"function {fn_name} not found",
            }
        try:
            out = fn()
            ok = out is not None
            err = None
            if isinstance(out, dict) and out.get("error"):
                ok = False
                err = str(out.get("error"))
            return {
                "name": name,
                "ok": ok,
                "duration_ms": int((time.time() - start) * 1000),
                "error": err,
            }
        except Exception as e:  # noqa: BLE001 — smoke check must not crash
            return {
                "name": name,
                "ok": False,
                "duration_ms": int((time.time() - start) * 1000),
                "error": f"{type(e).__name__}: {e}",
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_run_check, name, fn_name, t): name for name, fn_name, t in SELFTEST_CHECKS}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=overall_budget):
                results.append(fut.result())
        except concurrent.futures.TimeoutError:
            completed_names = {r["name"] for r in results}
            for name, _fn, _t in SELFTEST_CHECKS:
                if name not in completed_names:
                    results.append(
                        {
                            "name": name,
                            "ok": False,
                            "duration_ms": overall_budget * 1000,
                            "error": "timed out waiting for result",
                        }
                    )

    results.sort(key=lambda r: r["name"])
    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    return jsonify(
        {
            "ok": failed == 0,
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "checks": results,
        }
    )


@app.route("/api/restart", methods=["POST"])
def api_restart():
    """Schedule a full app restart. Spawns a new pythonw process running the
    same entry point, then exits the current one after a short delay. Callers
    should poll /api/health to detect the new instance.

    Localhost-only — refuses any request not from 127.0.0.1/::1.
    """
    remote = request.remote_addr or ""
    if remote not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({"ok": False, "error": "restart is localhost-only"}), 403

    def _do_restart():
        time.sleep(0.3)  # let the HTTP response flush
        try:
            python = sys.executable
            subprocess.Popen(  # noqa: S603
                [python, *sys.argv],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        finally:
            time.sleep(0.3)
            os._exit(0)  # noqa: SLF001 — hard exit kills daemon threads immediately

    threading.Thread(target=_do_restart, daemon=True, name="RestartWorker").start()
    return jsonify({"ok": True, "status": "restart scheduled"}), 202


@app.route("/api/launch/nvidia-app", methods=["POST"])
def launch_nvidia_app():
    """Try to open the NVIDIA App on the local machine.

    Checks common install paths and the Start Menu shortcut.
    Returns {"ok": True, "launched": True} if found and started,
    or {"ok": True, "launched": False, "fallback_url": "..."} if not installed.
    """
    fallback = "https://www.nvidia.com/en-us/software/nvidia-app/"
    ps = r"""
$paths = @(
    "$env:LOCALAPPDATA\NVIDIA Corporation\NVIDIA app\NVIDIAapp\NVIDIA app.exe",
    "$env:ProgramFiles\NVIDIA Corporation\NVIDIA app\NVIDIAapp\NVIDIA app.exe",
    "${env:ProgramFiles(x86)}\NVIDIA Corporation\NVIDIA app\NVIDIAapp\NVIDIA app.exe"
)
foreach ($p in $paths) {
    if (Test-Path $p) { Start-Process $p; Write-Output 'launched'; exit 0 }
}
# Try Start Menu shortcut
$shortcut = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Recurse -Filter "NVIDIA*app*.lnk" -EA SilentlyContinue | Select-Object -First 1
if ($shortcut) { Start-Process $shortcut.FullName; Write-Output 'launched'; exit 0 }
Write-Output 'not_found'
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if "launched" in r.stdout:
            return jsonify({"ok": True, "launched": True})
    except Exception:
        pass
    return jsonify({"ok": True, "launched": False, "fallback_url": fallback})


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
    items = (request.get_json() or {}).get("items", [])
    queued = 0
    for item in items:
        name = item.get("Name", "")
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
                _startup_cache.pop(cache_key, None)  # clear so worker re-fetches
                if cache_key not in _startup_in_flight:
                    _startup_in_flight.add(cache_key)
                    _startup_queue.put((cache_key, command, name))
                queued += 1

    return jsonify({"ok": True, "queued": queued, "queue_depth": _startup_queue.qsize()})


@app.route("/api/startup/lookup-status")
def startup_lookup_status():
    """Poll how many lookups are still pending."""
    return jsonify(
        {
            "queue_pending": _startup_queue.qsize(),
            "in_flight": len(_startup_in_flight),
            "cached": len(_startup_cache),
        }
    )


@app.route("/api/startup/cache")
def startup_cache_status():
    with _startup_cache_lock:
        cached = dict(_startup_cache)
    return jsonify(
        {
            "total_cached": len(cached),
            "queue_pending": _startup_queue.qsize(),
            "in_flight": len(_startup_in_flight),
        }
    )


@app.route("/api/startup/toggle", methods=["POST"])
def startup_toggle():
    data = request.get_json() or {}
    name = data.get("name")
    item_type = data.get("type")
    enable = data.get("enable")
    if not name or not item_type or enable is None:
        return jsonify({"ok": False, "error": "Missing required fields: name, type, enable"}), 400
    return jsonify(toggle_startup_item(name, item_type, enable))


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
        "drivers": lambda: summarize_drivers(data.get("results", [])),
        "bsod": lambda: summarize_bsod(data),
        "startup": lambda: summarize_startup(data.get("items", [])),
        "disk": lambda: summarize_disk(data),
        "network": lambda: summarize_network(data),
        "updates": lambda: summarize_updates(data.get("items", [])),
        "events": lambda: summarize_events(data.get("events", [])),
        "processes": lambda: summarize_processes(data),
        "thermals": lambda: summarize_thermals(data),
        "services": lambda: summarize_services(data.get("services", [])),
        "health-history": lambda: summarize_health_history(data),
        "timeline": lambda: summarize_timeline(data.get("events", [])),
        "memory": lambda: summarize_memory(data),
        "bios": lambda: summarize_bios(data),
        "credentials": lambda: summarize_credentials_network(data),
        "sysinfo": lambda: summarize_sysinfo(data),
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
    procs = (request.get_json() or {}).get("processes", [])
    queued = 0
    for p in procs:
        key = p.get("Name", "").lower().replace(".exe", "")
        if key in PROCESS_KB:
            continue
        with _process_cache_lock:
            existing = _process_cache.get(key, {})
        if existing.get("source", "") not in ("unknown", ""):
            continue
        with _process_cache_lock:
            _process_cache.pop(key, None)
            if key not in _process_in_flight:
                _process_in_flight.add(key)
                _process_queue.put((key, p.get("Name", ""), p.get("Path", "")))
            queued += 1
    return jsonify({"ok": True, "queued": queued})


@app.route("/api/processes/lookup-status")
def process_lookup_status():
    return jsonify({"queue_pending": _process_queue.qsize(), "in_flight": len(_process_in_flight)})


@app.route("/api/processes/kill", methods=["POST"])
def process_kill():
    data = request.get_json() or {}
    try:
        pid = int(data.get("pid", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "pid must be an integer"}), 400
    if pid <= 0:
        return jsonify({"ok": False, "error": "Invalid PID"}), 400

    # SAFE_PROCESSES guard (backlog #35). The memory-tab Kill button
    # hides for protected processes, but that's a UI-side guard only --
    # NLQ, future clients, or a handcrafted curl could still hit this
    # endpoint with a system PID. Look the process up by PID and refuse
    # if its name is in SAFE_PROCESSES. Match both "foo" and "foo.exe"
    # since the set carries entries in both styles.
    try:
        proc_name = psutil.Process(pid).name() or ""
    except psutil.NoSuchProcess:
        return jsonify({"ok": False, "error": f"No such process: {pid}"}), 404
    except psutil.AccessDenied:
        # Can't read the name — be cautious and refuse rather than kill
        # blind. User can retry as admin if they really mean it.
        return jsonify({"ok": False, "error": "Access denied reading process name"}), 403
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"process lookup failed: {e}"}), 500

    name_l = proc_name.lower()
    name_noext = name_l.removesuffix(".exe")
    if name_l in SAFE_PROCESSES or name_noext in SAFE_PROCESSES:
        return jsonify(
            {
                "ok": False,
                "error": f"Refusing to kill protected system process: {proc_name}",
                "protected": True,
            }
        ), 403

    return jsonify(kill_process(pid))


@app.route("/api/processes/glossary")
def processes_glossary_route():
    """Return the curated glossary of opaque system process names (backlog #36).

    Shape:
        {"ok": true, "glossary": {"memcompression": {"title": ..., "explanation": ..., "protected": true}, ...}}

    Keys are lowercased process names without the ``.exe`` suffix so
    client-side lookups can normalise consistently. The frontend fetches
    this once per page load and caches it; NLQ can also call it to
    explain a process name the user asked about.
    """
    return jsonify({"ok": True, "glossary": SYSTEM_PROCESSES_GLOSSARY})


@app.route("/api/thermals/data")
def thermals_data():
    return jsonify(get_thermals())


@app.route("/api/services/list")
def services_list():
    return jsonify(get_services_list())


@app.route("/api/services/toggle", methods=["POST"])
def services_toggle():
    data = request.get_json() or {}
    return jsonify(toggle_service(data.get("name", ""), data.get("action", "")))


@app.route("/api/services/lookup-unknowns", methods=["POST"])
def services_lookup_unknowns():
    svcs = (request.get_json() or {}).get("services", [])
    queued = 0
    for s in svcs:
        key = s.get("Name", "").lower()
        if key in SERVICES_KB:
            continue
        with _services_cache_lock:
            existing = _services_cache.get(key, {})
        if existing.get("source", "") not in ("unknown", ""):
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
    return jsonify(
        {
            "queue_pending": _services_queue.qsize(),
            "in_flight": len(_services_in_flight),
        }
    )


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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=15
        )
        data = json.loads(r.stdout.strip() or "[]")
        if isinstance(data, dict):
            data = [data]
        fixed = [d for d in data if d.get("Status") == "OK"]
        return jsonify(
            {
                "ok": len(fixed) > 0,
                "fixed": len(fixed),
                "results": data,
                "message": "OneDrive resumed and set to AboveNormal priority. Word and Outlook should reconnect."
                if fixed
                else "OneDrive process not found.",
            }
        )
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
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=15
        )
        data = json.loads(r.stdout.strip() or "[]")
        if isinstance(data, dict):
            data = [data]
        fixed = [d for d in data if d.get("Status") == "OK"]
        return jsonify(
            {
                "ok": len(fixed) > 0,
                "fixed": len(fixed),
                "results": data,
                "message": f"Resumed {len(fixed)} broker process(es). Word and Outlook should reconnect."
                if fixed
                else "No broker processes found to resume.",
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "fixed": 0, "results": [], "message": str(e)})


@app.route("/api/credentials/fix-fast-startup", methods=["POST"])
def fix_fast_startup_route():
    """Toggle Fast Startup on or off via registry."""
    data = request.get_json() or {}
    enable = data.get("enable", False)
    return jsonify(fix_fast_startup(enable))


def fix_fast_startup(enable):
    """Execute the Fast Startup registry toggle."""
    value = 1 if enable else 0
    label = "enabled" if enable else "disabled"
    ps = f"""
try {{
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power" `
        -Name "HiberbootEnabled" -Value {value} -Type DWord -Force
    Write-Output "OK:{label}"
}} catch {{ Write-Output "ERROR: $_" }}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=10
        )
        ok = "OK" in r.stdout
        return {"ok": ok, "enabled": enable, "message": f"Fast Startup {label}." if ok else r.stdout.strip()}
    except Exception as e:
        return {"ok": False, "enabled": enable, "message": str(e)}


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


@app.route("/api/bios/audit/history")
def bios_audit_history_route():
    """Return the BIOS audit trail (baselines + change + error events).

    Query params:
        limit             -- trim to last N entries (default: all)
        include_phantoms  -- "1" to keep historical pre-fix null-vs-value
                             flicker entries visible (default: drop them)
    """
    import bios_audit

    limit_arg = request.args.get("limit", type=int)
    include_phantoms = request.args.get("include_phantoms") == "1"

    history = bios_audit.load_history()
    if not include_phantoms:
        history = [e for e in history if not bios_audit.is_phantom_change_entry(e)]
    if limit_arg is not None and limit_arg > 0:
        history = history[-limit_arg:]
    return jsonify({"ok": True, "history": history, "include_phantoms": include_phantoms})


@app.route("/api/bios/audit/snapshot")
def bios_audit_snapshot_route():
    """Return the latest captured snapshot, or take one on demand if empty."""
    import bios_audit

    snap = bios_audit.latest_snapshot()
    if snap is None:
        # No history yet — take a fresh snapshot so the UI has something
        # to show on first load. Does not persist unless caller forces it.
        snap = bios_audit.take_snapshot()
    return jsonify({"ok": True, "snapshot": snap})


# ── Baseline / drift detection (backlog #14) ────────────────────────


@app.route("/api/baseline/drift")
def baseline_drift_route():
    """Return the current drift vs the accepted baseline.

    This is the heavy call (~5 s total: 287 ms services + 3 s schtasks +
    ~2 s startup-via-PS) and is the primary source for the Baseline UI
    tab. Records an entry in the drift history if drift > 0 AND a
    baseline exists, so recent_drift() can power a dashboard concern
    without the user having to open the tab first.
    """
    import baseline

    return jsonify(baseline.record_drift_if_any())


@app.route("/api/baseline/snapshot")
def baseline_snapshot_route():
    """Return a live snapshot of the current state (no diff, no history)."""
    import baseline

    return jsonify({"ok": True, "snapshot": baseline.take_snapshot()})


@app.route("/api/baseline/accept", methods=["POST"])
def baseline_accept_route():
    """Promote the current system state to the accepted baseline.

    Idempotent: re-accepting after legitimate changes (Windows Update
    installed new services, user added a startup item they like) is
    the expected way to clear drift.
    """
    import baseline

    result = baseline.accept_current_as_baseline()
    status = 200 if result.get("ok") else 500
    return jsonify(result), status


@app.route("/api/baseline/history")
def baseline_history_route():
    """Return recent drift-detection history entries (default 24h window)."""
    import baseline

    try:
        hours = int(request.args.get("hours", "24"))
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(hours, 720))  # clamp 1h..30d
    entries = baseline.recent_drift(window=timedelta(hours=hours))
    return jsonify({"ok": True, "hours": hours, "entries": entries})


@app.route("/api/baseline/entry-history")
def baseline_entry_history_route():
    """Return every historical drift event for a specific (category, key) pair.

    Used by the per-entry drill-down modal (2026-04-28) to show whether a
    drifted service / task / startup item has drifted before -- a
    recurring pattern often signals legit churn (Windows Update touching
    the same binary every patch Tuesday).

    Query params:
      - category: services | tasks | startup
      - key:      the entry key (full task path, service name, etc.)
      - hours:    optional cutoff (defaults to all history, capped at 30d)
    """
    import baseline

    category = (request.args.get("category") or "").lower().strip()
    key = (request.args.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category and key required"}), 400

    window: timedelta | None = None
    raw_hours = request.args.get("hours")
    if raw_hours is not None:
        try:
            hours = max(1, min(int(raw_hours), 720))
            window = timedelta(hours=hours)
        except (TypeError, ValueError):
            window = None

    events = baseline.entry_drift_history(category, key, window=window)
    return jsonify({"ok": True, "category": category, "key": key, "events": events})


# Maps a drift category to the Windows console that edits it. No user
# input reaches the command line -- the category is validated against
# this whitelist, so there's no injection surface.
_BASELINE_CONSOLES = {
    "services": "services.msc",
    "tasks": "taskschd.msc",
    # Task Manager's Startup tab is the user-friendly way to toggle
    # startup items; msconfig is the deep-cut alternative.
    "startup": "taskmgr.exe",
}


@app.route("/api/baseline/launch_console", methods=["POST"])
def baseline_launch_console_route():
    """Open the native Windows console for a drift category.

    Called by the "Open Task Scheduler" / "Open services.msc" / "Open
    Task Manager" buttons in the Baseline tab's remediation block. Lets
    the user jump straight from "here's what drifted" to "the place to
    fix it" without hunting through Start menu.
    """
    data = request.get_json(silent=True) or {}
    category = (data.get("category") or "").lower().strip()
    if category not in _BASELINE_CONSOLES:
        return jsonify({"ok": False, "error": f"unknown category: {category}"}), 400

    console = _BASELINE_CONSOLES[category]
    try:
        # os.startfile is the Windows shell-execute equivalent -- the right
        # tool to "open this MMC snap-in as if the user double-clicked it".
        # Services/tasks snap-ins are .msc files (MMC); taskmgr.exe is a
        # direct executable launch. Both work via startfile.
        if not hasattr(os, "startfile"):
            return jsonify({"ok": False, "error": "os.startfile unavailable (non-Windows host)"}), 500
        os.startfile(console)  # noqa: S606  # deliberate: fixed console path, no user input
        return jsonify({"ok": True, "launched": console, "category": category})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e), "launched": console}), 500


@app.route("/api/baseline/accept_entry", methods=["POST"])
def baseline_accept_entry_route():
    """Accept a SINGLE drift entry into the baseline (not the whole snapshot).

    User feedback 2026-04-28: the existing /api/baseline/accept is all-
    or-nothing. This route takes one (category, key) pair and updates
    only that entry in the baseline, so the user can absorb individual
    changes without committing to "everything that's drifted is fine."

    Body shape: ``{"category": "services|tasks|startup", "key": "..."}``
    Returns: ``{"ok": bool, "kind": "added|removed|changed",
                "error": str|None, "baseline_timestamp": str|None}``
    """
    import baseline

    body = request.get_json(silent=True) or {}
    category = (body.get("category") or "").lower().strip()
    key = (body.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category (startup|services|tasks) and key required"}), 400

    # Optional fast-path inputs from the UI: kind ("added"|"removed"|
    # "changed") + current_value (the new dict for added/changed). When
    # provided, baseline.accept_drift_entry skips its expensive
    # take_snapshot() call and applies the change in a few ms instead
    # of the 5-30s a full snapshot takes.
    raw_kind = body.get("kind")
    kind = raw_kind.lower().strip() if isinstance(raw_kind, str) else None
    if kind not in (None, "added", "removed", "changed"):
        kind = None  # fall back to slow path on garbage rather than 400ing
    raw_value = body.get("current_value")
    current_value = raw_value if isinstance(raw_value, dict) else None

    result = baseline.accept_drift_entry(category, key, kind=kind, current_value=current_value)
    if result.get("ok"):
        return jsonify(result), 200
    err = (result.get("error") or "").lower()
    if "not found" in err:
        return jsonify(result), 404
    return jsonify(result), 500


@app.route("/api/baseline/investigate", methods=["POST"])
def baseline_investigate_route():
    """Analyze a single drift entry to help the user decide whether to accept.

    Body shape:
        {"category": "services|tasks|startup",
         "key":      "<entry key from drift.<category>.<kind>[].key>",
         "kind":     "added|removed|changed"  (optional -- inferred from drift state)}

    Returns:
        {"ok": True, "investigation": {path_safety, recent_updates, inferred_cause,
                                       recommendation, explanation, ...}}
    """
    import baseline

    body = request.get_json(silent=True) or {}
    category = (body.get("category") or "").lower().strip()
    key = (body.get("key") or "").strip()
    if category not in ("startup", "services", "tasks") or not key:
        return jsonify({"ok": False, "error": "category (startup|services|tasks) and key required"}), 400

    # Recompute current drift to find the entry by category + key.
    result = baseline.compute_drift()
    drift_cat = (result.get("drift") or {}).get(category) or {}
    entry = None
    for kind in ("changed", "added", "removed"):
        for e in drift_cat.get(kind) or []:
            if e.get("key") == key:
                entry = e
                break
        if entry:
            break

    if not entry:
        return (
            jsonify({"ok": False, "error": f"no current drift entry for category={category} key={key}"}),
            404,
        )

    investigation = baseline.investigate_drift_entry(category, entry)
    return jsonify({"ok": True, "investigation": investigation})


@app.route("/api/tasks/health")
def tasks_health_route():
    """Return health status for every managed scheduled task."""
    import task_watcher

    try:
        tasks = task_watcher.get_all_task_health()
        return jsonify({"ok": True, "tasks": tasks})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e), "tasks": []})


@app.route("/api/alerts/rules", methods=["GET"])
def alerts_rules_list_route():
    """Return the full merged (defaults + user overrides) alert rule list."""
    import alerts

    try:
        return jsonify({"ok": True, "rules": [r.to_dict() for r in alerts.load_rules()]})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e), "rules": []}), 500


@app.route("/api/alerts/rules/<rule_id>", methods=["PATCH"])
def alerts_rule_update_route(rule_id: str):
    """Update threshold / level / enabled for one rule.

    Body: ``{"threshold": 88.0}`` or ``{"enabled": false}`` or both.
    Returns the updated rule on success.
    """
    import alerts

    data = request.get_json() or {}
    # Only allow known fields to pass through
    allowed = {k: v for k, v in data.items() if k in ("threshold", "level", "enabled")}
    if not allowed:
        return jsonify(
            {"ok": False, "error": "no editable fields in payload (allowed: threshold, level, enabled)"}
        ), 400
    result = alerts.update_rule(rule_id, **allowed)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/tasks/open-logs-folder", methods=["POST"])
def tasks_open_logs_folder_route():
    """Open the app's Logs/ directory in Windows Explorer."""
    log_dir = os.path.join(APP_DIR, "Logs")
    if not os.path.isdir(log_dir):
        return jsonify({"ok": False, "error": f"Log directory not found: {log_dir}"}), 404
    try:
        # Fire-and-forget — Popen returns immediately, explorer pops a window
        subprocess.Popen(["explorer.exe", log_dir])
        return jsonify({"ok": True, "path": log_dir})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/memory/snooze", methods=["POST"])
def memory_snooze_route():
    """Snooze memory warnings for a given process name (default 24h)."""
    data = request.get_json() or {}
    name = data.get("process_name") or data.get("name")
    hours = data.get("hours", 24)
    if not name:
        return jsonify({"ok": False, "error": "Missing required field: process_name"}), 400
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "hours must be an integer"}), 400
    result = add_memory_snooze(name, hours=hours)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/api/memory/snooze", methods=["DELETE"])
def memory_snooze_delete_route():
    data = request.get_json() or {}
    name = data.get("process_name") or data.get("name") or request.args.get("process_name")
    if not name:
        return jsonify({"ok": False, "error": "Missing required field: process_name"}), 400
    return jsonify(remove_memory_snooze(name))


@app.route("/api/memory/snoozes", methods=["GET"])
def memory_snoozes_route():
    """List currently-active memory snoozes."""
    return jsonify({"ok": True, "snoozes": _load_memory_snoozes()})


@app.route("/api/warranty/data")
def warranty_data():
    """Collect Intel/Dell warranty readiness data."""
    try:
        # CPU / BIOS / System info via WMI
        try:
            c = _wmi_conn()
            cpu_obj = c.Win32_Processor()[0]
            bios_obj = c.Win32_BIOS()[0]
            cs_obj = c.Win32_ComputerSystem()[0]
            bios_date_raw = bios_obj.ReleaseDate or ""
            bios_date = _wmi_date_to_str(bios_date_raw) if bios_date_raw else "Unknown"
            sys_data = {
                "CPUName": (cpu_obj.Name or "").strip(),
                "ProcessorId": cpu_obj.ProcessorId or "",
                "SerialNumber": cpu_obj.SerialNumber or "N/A",
                "DellServiceTag": bios_obj.SerialNumber or "",
                "BIOSVersion": bios_obj.SMBIOSBIOSVersion or "",
                "BIOSDate": bios_date,
                "Manufacturer": cs_obj.Manufacturer or "",
                "Model": cs_obj.Model or "",
            }
        except Exception:
            sys_data = {}

        cpu_name = sys_data.get("CPUName", "Unknown")
        is_affected = bool(re.search(r"i[579]-1[34]\d{3}", cpu_name))

        # Microcode from registry
        mcu_cmd = """
try {
    $key = Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0'
    $raw = $key.'Update Revision'
    if ($raw -is [byte[]]) { '0x' + [BitConverter]::ToString($raw).Replace('-','') }
    else { [string]$raw }
} catch { 'Unable to read' }
"""
        r2 = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", mcu_cmd], capture_output=True, text=True, timeout=10
        )
        microcode = r2.stdout.strip() if r2.stdout.strip() else "Unable to read"

        # BSOD + WHEA counts (lightweight)
        counts_cmd = """
$bsod30 = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001} -MaxEvents 100 -EA SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-30) }).Count
$whea = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 100 -EA SilentlyContinue).Count
$kp41 = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=41} -MaxEvents 100 -EA SilentlyContinue).Count
@{BSODs30Days=$bsod30;WHEAErrors=$whea;UnexpectedShutdowns=$kp41} | ConvertTo-Json
"""
        r3 = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", counts_cmd], capture_output=True, text=True, timeout=20
        )
        counts = json.loads(r3.stdout.strip()) if r3.stdout.strip() else {}

        service_tag = sys_data.get("DellServiceTag", "N/A")
        if service_tag in ("", "To Be Filled By O.E.M.", "Default string"):
            service_tag = "N/A"

        cpu_serial = sys_data.get("ProcessorId", "Unknown")
        if sys_data.get("SerialNumber", "N/A") not in ("N/A", "", "To Be Filled By O.E.M."):
            cpu_serial = sys_data["SerialNumber"]

        warranty = {
            "IsAffectedCPU": is_affected,
            "CPUModel": cpu_name,
            "CPUSerial": cpu_serial,
            "MicrocodeVersion": microcode,
            "BIOSVersion": sys_data.get("BIOSVersion", "Unknown"),
            "BIOSDate": sys_data.get("BIOSDate", "Unknown"),
            "DellServiceTag": service_tag,
            "Manufacturer": sys_data.get("Manufacturer", "Unknown"),
            "Model": sys_data.get("Model", "Unknown"),
            "BSODs30Days": counts.get("BSODs30Days", 0),
            "WHEAErrors": counts.get("WHEAErrors", 0),
            "UnexpectedShutdowns": counts.get("UnexpectedShutdowns", 0),
            "IntelWarrantyURL": "https://warranty.intel.com",
            "DellSupportURL": f"https://www.dell.com/support/home/en-us/product-support/servicetag/{service_tag}"
            if service_tag != "N/A"
            else "https://www.dell.com/support",
        }

        return jsonify({"status": "ok", "warranty": warranty})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/architecture.html")
def architecture_diagram():
    """Serve the architecture diagram HTML file."""
    return send_from_directory(app.root_path, "architecture.html")


@app.route("/api/sysinfo/data")
def sysinfo_data():
    """Collect comprehensive system information for the System Info tab."""
    from datetime import datetime
    from datetime import timezone as tz

    collected_at = datetime.now(tz.utc).isoformat()
    stale = False
    error_detail = None
    data = {}
    try:
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

    except Exception as e:
        stale = True
        error_detail = str(e)

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

    return jsonify(
        {
            "status": "partial" if stale else "ok",
            "data": data,
            "collected_at": collected_at,
            "stale": stale,
            "error": error_detail,
            "upgrades": upgrades,
        }
    )


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


def summarize_upgrades(data: dict) -> dict:
    """Walk the system-info inventory and surface upgrade opportunities.

    Backlog #43 (hardware upgrade analyser). Three categories today:

    * **memory** -- compares populated DIMMs against board capacity
      (Win32_PhysicalMemoryArray.MaxCapacity + .MemoryDevices). Reports
      free slots, RAM headroom, and -- when only one DIMM is installed --
      a single-channel-mode warning since dual-channel doubles bandwidth
      and is free if you've already got a second matching stick lying
      around.
    * **pcie** -- lists Win32_SystemSlot rows whose CurrentUsage is
      "Available". Each free slot is a candidate for a GPU / NIC /
      capture card / NVMe carrier; the slot description usually carries
      the link width (x1 / x4 / x16) so users can match expansion cards
      to slot capability.
    * **storage** -- counts physical disks by interface type. Doesn't
      attempt to enumerate empty SATA/M.2 ports (Win32 has no clean
      surface for that), but DOES surface "you have N spinning-rust
      drives" as a candidate for SSD migration.

    Each opportunity has a stable shape so the UI can render them
    uniformly:
        category   -- "memory" | "pcie" | "storage"
        severity   -- "ok" | "info" | "warning"
        headline   -- one-line summary (shown bold on the card)
        detail     -- multi-line context
        action     -- imperative next step (shown as the card's CTA)

    The function is pure -- no I/O, no globals -- so it's trivially
    testable. Empty/missing data returns ``{"opportunities": []}`` rather
    than raising, so a partial sysinfo collection (WMI flake) still
    renders a clean panel instead of a JS error.
    """
    opportunities = []

    # ── Memory ────────────────────────────────────────────────────────
    mem_sticks = data.get("Memory", []) or []
    mem_arrays = data.get("MemoryArray", []) or []
    # Sum capacities across populated DIMMs. Capacity from WMI is in
    # bytes, so /1024**3 → GB.
    installed_bytes = sum(int(m.get("Capacity") or 0) for m in mem_sticks)
    installed_gb = round(installed_bytes / (1024**3), 1) if installed_bytes else 0
    populated_slots = len([m for m in mem_sticks if int(m.get("Capacity") or 0) > 0])
    # Aggregate across all memory arrays on the board (servers may have
    # multiple). Most desktops have exactly one.
    total_slots = sum(int(a.get("MemoryDevices") or 0) for a in mem_arrays)
    max_capacity_gb = sum(float(a.get("MaxCapacityGB") or 0) for a in mem_arrays)
    free_slots = max(0, total_slots - populated_slots) if total_slots else 0
    headroom_gb = round(max_capacity_gb - installed_gb, 1) if max_capacity_gb else 0

    # Memory-type / speed -- needed for the "buy matching" recommendation.
    mem_types = sorted({m.get("MemoryType", "") for m in mem_sticks if m.get("MemoryType")})
    mem_type_str = "/".join(mem_types) if mem_types else "Unknown type"
    speeds = [int(m.get("ConfiguredClockSpeed") or 0) for m in mem_sticks if m.get("ConfiguredClockSpeed")]
    speed_str = f"-{max(speeds)}" if speeds else ""
    form_factors = sorted({m.get("FormFactor", "") for m in mem_sticks if m.get("FormFactor")})
    form_str = "/".join(form_factors) if form_factors else ""

    # Largest installed stick -- best heuristic for "what size to buy
    # next" since most boards expect matched capacities per channel.
    largest_stick_gb = 0
    if mem_sticks:
        biggest = max((int(m.get("Capacity") or 0) for m in mem_sticks), default=0)
        largest_stick_gb = round(biggest / (1024**3), 1) if biggest else 0

    if total_slots and free_slots > 0 and headroom_gb > 0:
        # The headline upgrade case: empty slots AND board capacity to spare.
        # Concrete recommendation calls out the exact spec to buy so the
        # user doesn't have to translate "DDR5 @ 5600 MHz SODIMM" themselves.
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
                    f"(suggested: {free_slots} × {suggest_size}). "
                    "Verify the board's chipset max in your motherboard manual -- "
                    "OEM firmware sometimes reports the originally-shipped config "
                    "rather than the chipset's true ceiling."
                ),
                "action": f"Buy {free_slots} × {suggest_size} {spec} matching your existing PartNumber",
            }
        )
    elif total_slots and free_slots == 0 and headroom_gb > 0:
        # All slots full but board would accept higher capacities -- the
        # only path is to *replace* existing sticks with bigger ones.
        opportunities.append(
            {
                "category": "memory",
                "severity": "info",
                "headline": f"Up to {headroom_gb:g} GB more RAM possible (requires replacing existing sticks)",
                "detail": (
                    f"All {total_slots} DIMM slots are populated with {installed_gb:g} GB. "
                    f"The board reports max capacity {max_capacity_gb:g} GB, so further "
                    "expansion means swapping existing sticks for higher-density modules. "
                    "Check current resale value of your existing sticks before buying replacements."
                ),
                "action": f"Replace existing sticks with higher-density {mem_type_str} modules",
            }
        )
    elif total_slots and populated_slots == total_slots:
        # All slots full and at max capacity -- nothing to do, but worth
        # surfacing so the user knows it's not a missed opportunity.
        opportunities.append(
            {
                "category": "memory",
                "severity": "ok",
                "headline": "Memory fully populated",
                "detail": f"All {total_slots} DIMM slots populated; {installed_gb:g} GB at the board's reported max.",
                "action": "",
            }
        )

    # Single-channel-mode warning. Running 1 DIMM in a multi-slot board
    # halves memory bandwidth vs dual-channel -- a free perf win if you
    # add a second matching stick. Only fire when the board has at least
    # 2 slots (otherwise dual-channel isn't possible anyway).
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
            }
        )

    # ── PCIe ──────────────────────────────────────────────────────────
    pcie_slots = data.get("PCIeSlots", []) or []
    free_pcie = [s for s in pcie_slots if (s.get("CurrentUsage") or "").lower() == "available"]
    if pcie_slots and free_pcie:
        # Build a slot-by-slot description so users can match the right
        # card form-factor (x1 vs x16) to the right slot.
        slot_lines = []
        for s in free_pcie:
            desg = s.get("SlotDesignation", "?")
            desc = s.get("Description", "")
            slot_lines.append(f"  • {desg} ({desc})" if desc else f"  • {desg}")
        opportunities.append(
            {
                "category": "pcie",
                "severity": "info",
                "headline": f"{len(free_pcie)} of {len(pcie_slots)} PCIe slot{'s' if len(pcie_slots) != 1 else ''} free",
                "detail": (
                    "Available slots:\n" + "\n".join(slot_lines) + "\n\n"
                    "Capacity for: discrete GPU, 10 GbE NIC, capture card, NVMe carrier card, "
                    "or HBA / RAID controller. Match the card's lane requirement (x1 / x4 / x16) "
                    "to a slot of equal or greater width."
                ),
                "action": "Identify which expansion card the workload needs, then match to slot width",
            }
        )

    # ── Storage ───────────────────────────────────────────────────────
    disks = data.get("Disks", []) or []
    if disks:
        # MediaType in WMI is one of "Fixed hard disk media", "External
        # hard disk media", or "" / None. SSD vs HDD has to come from
        # InterfaceType + Model heuristics since WMI doesn't expose
        # rotation rate uniformly. NVMe drives report InterfaceType=SCSI
        # on most Windows builds (a long-standing WMI quirk) but their
        # model string usually contains "NVMe" or "SSD".
        spinning = []
        for d in disks:
            model = (d.get("Model") or "").upper()
            iface = (d.get("InterfaceType") or "").upper()
            # Best-effort: anything that doesn't say SSD/NVMe and is on
            # IDE/SATA *might* be spinning rust. We're conservative
            # because a false-positive here recommends spending money.
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
                }
            )

    return {"opportunities": opportunities}


# ── Dashboard summary cache ────────────────────────────────────────
#
# The full fan-out to get_thermals / get_memory_analysis / get_bios_status /
# get_credentials_network_health / get_disk_health / get_driver_health is
# slow (observed 37-47 s under load on 2026-04-20, normal 1-3 s). The UI
# polls this endpoint frequently, and rapid-fire requests used to each
# pay full fan-out cost plus pile up server-side.
#
# The cache serves the last-known-good payload instantly and kicks a
# single background refresh when the cache goes stale. TTL is deliberately
# short (30 s) -- long enough that a dashboard refresh click, a tray
# status poll, and a Playwright smoke pass during the same window all
# share one computation; short enough that truly new state (e.g. a
# remediation action that just ran) is visible on the next refresh.
_dashboard_state: dict = {"data": None, "ts": None}
_dashboard_cache_lock = threading.Lock()
_dashboard_refresh_lock = threading.Lock()
_DASHBOARD_CACHE_TTL = timedelta(seconds=30)


def _compute_dashboard_summary() -> dict:
    """Synchronous fan-out over every dashboard collector.

    Returns the full response dict (not a Flask Response) so the route
    handler and the background refresher can share one implementation.
    """
    import concurrent.futures

    results = {}

    def run(name, fn):
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = {"error": str(e)}

    checks = {
        "thermals": get_thermals,
        "memory": get_memory_analysis,
        "bios": get_bios_status,
        "credentials": get_credentials_network_health,
        "disk": get_disk_health,
        "drivers": get_driver_health,
        "gpu": get_gpu_metrics,
        "network": get_network_metrics,
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
        snoozes = _load_memory_snoozes()
    except Exception:  # noqa: BLE001
        snoozes = {}
    for p in mem.get("top_procs", [])[:8]:
        name = p.get("name") or ""
        mb = p.get("mem") or 0
        pid = p.get("pid")
        if not name or mb < MEM_CRIT_MB:
            continue
        if name.lower() in snoozes:
            continue
        # Skip well-known system-critical processes that have no business
        # being killed from the dashboard (kernel-adjacent, AV, etc.)
        if (name + ".exe").lower() in SAFE_PROCESSES:
            continue
        concerns.append(
            {
                "level": "critical" if mb >= 2 * MEM_CRIT_MB else "warning",
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

        drift_entries = baseline.recent_drift()
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
    except Exception:  # noqa: BLE001 -- baseline is best-effort
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


@app.route("/api/dashboard/summary")
def dashboard_summary():
    """Dashboard concerns summary. Cached — see ``_compute_dashboard_summary``.

    First call ever: compute synchronously, populate cache. Subsequent
    calls: serve the cached payload instantly; if older than
    ``_DASHBOARD_CACHE_TTL`` trigger a background refresh. The response
    includes a ``cache`` field so the UI can tell fresh vs. cached.
    """
    # Snapshot cache state under the lock, then decide what to do outside
    # the lock so we don't hold it across a multi-second fan-out.
    with _dashboard_cache_lock:
        cached = _dashboard_state["data"]
        ts = _dashboard_state["ts"]

    if cached is None:
        # Cold start: nothing to serve yet, so we have to compute.
        data = _compute_dashboard_summary()
        with _dashboard_cache_lock:
            _dashboard_state["data"] = data
            _dashboard_state["ts"] = datetime.now()
        return jsonify({**data, "cache": "miss"})

    age_s = (datetime.now() - ts).total_seconds() if ts else None
    is_stale = age_s is not None and age_s > _DASHBOARD_CACHE_TTL.total_seconds()
    if is_stale:
        _trigger_dashboard_refresh_async()
    return jsonify(
        {
            **cached,
            "cache": "stale" if is_stale else "fresh",
            "cache_age_s": round(age_s, 1) if age_s is not None else None,
        }
    )


@app.route("/api/metrics/history")
def metrics_history_route():
    """Return time-series samples for the dashboard Trends card (backlog #4).

    Query params:
        window_h:  hours of history to return (default 168 = 7 days, max 720)
        metric:    optional metric key to drill into a single series
    """
    import metrics_history as mh

    try:
        window_h = int(request.args.get("window_h", "168"))
    except (TypeError, ValueError):
        window_h = 168
    window_h = max(1, min(window_h, 720))
    window = timedelta(hours=window_h)

    metric = request.args.get("metric")
    if metric:
        return jsonify(
            {
                "window_h": window_h,
                "metric": metric,
                "series": mh.get_series(metric, window=window),
            }
        )

    return jsonify(
        {
            "window_h": window_h,
            "metrics": mh.get_all_series(window=window),
            "available": mh.list_metrics(),
        }
    )


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


# ==============================================================================
# AUTOMATED REMEDIATION ENGINE -- moved to remediation.py (backlog #22 blueprint extraction)
# ==============================================================================
# The 10 action handlers, REMEDIATION_REGISTRY metadata, history store, NLQ
# bridges (_nlq_get_remediation_history / _nlq_run_remediation), and the three
# /api/remediation/* routes all live in remediation.py and are re-imported at
# the top of this file so that NLQ dispatch (_NLQ_TOOL_DISPATCH) still resolves
# through the windesktopmgr namespace.


# ══════════════════════════════════════════════════════════════════════════════
#   HOME NETWORK MANAGEMENT — extracted to homenet.py
# ══════════════════════════════════════════════════════════════════════════════
app.register_blueprint(disk_bp)
app.register_blueprint(homenet_bp)
app.register_blueprint(remediation_bp)


# ==============================================================================
# NATURAL LANGUAGE QUERY (NLQ) -- moved to nlq.py (backlog #22 blueprint extraction)
# ==============================================================================
# The Claude tool definitions, agentic loop, _truncate_for_context helper, and
# the /api/nlq/ask route all live in nlq.py. The two pieces that stay here are
# the _nlq_dashboard_summary aggregator (it calls get_thermals / summarize_* /
# etc. from this module) and the _NLQ_DISPATCH dict literal — the lambdas
# inside it resolve get_thermals / query_event_log / build_bsod_analysis / etc.
# through this module's globals at call time, which keeps existing
# @patch("windesktopmgr.get_thermals") test patterns working unchanged.
# The dispatch dict is handed to nlq.py via nlq.register_tool_dispatch().


def _nlq_dashboard_summary() -> dict:
    """Collect dashboard summary without jsonify for NLQ consumption."""
    import concurrent.futures

    results = {}
    checks = {
        "thermals": get_thermals,
        "memory": get_memory_analysis,
        "bios": get_bios_status,
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

    # Summarize each area
    summaries = {}
    sum_map = {
        "thermals": summarize_thermals,
        "memory": summarize_memory,
        "bios": summarize_bios,
        "credentials": summarize_credentials_network,
    }
    for name, fn in sum_map.items():
        try:
            summaries[name] = fn(results.get(name, {}))
        except Exception:
            summaries[name] = {"status": "error"}

    return {"raw_data": results, "summaries": summaries}


# Map tool names -> Python callables. Lambdas resolve through this module's
# globals at call time so existing test patches keep working unchanged.
_NLQ_DISPATCH = {
    "get_dashboard_summary": lambda params: _nlq_dashboard_summary(),
    "query_event_log": lambda params: query_event_log(params),
    "get_bsod_analysis": lambda params: build_bsod_analysis(),
    "get_disk_health": lambda params: get_disk_health(),
    "get_network_data": lambda params: get_network_data(),
    "get_update_history": lambda params: get_update_history(),
    "get_startup_items": lambda params: get_startup_items(),
    "get_process_list": lambda params: get_process_list(),
    "get_thermals": lambda params: get_thermals(),
    "get_services_list": lambda params: get_services_list(),
    "get_health_report_history": lambda params: get_health_report_history(),
    "get_system_timeline": lambda params: get_system_timeline(params.get("days", 30)),
    "get_memory_analysis": lambda params: get_memory_analysis(),
    "get_bios_status": lambda params: get_bios_status(),
    "get_credentials_network_health": lambda params: get_credentials_network_health(),
    "navigate_to_tab": lambda params: {"navigated": True, "tab": params.get("tab", "dashboard")},
    "get_remediation_history": lambda params: _nlq_get_remediation_history(),
    "run_remediation_action": lambda params: _nlq_run_remediation(params),
    "get_homenet_inventory": lambda params: homenet_get_inventory(),
}

# Wire the dispatch into nlq.py and register its blueprint.
_nlq_register_tool_dispatch(_NLQ_DISPATCH)
app.register_blueprint(nlq_bp)


# ==============================================================================


def _requeue_stale_cache(
    cache: dict,
    queue_obj: queue.Queue,
    in_flight: set,
    label: str,
    id_field: str = "id",
    source_field: str = "source",
    max_age_days: int = 90,
) -> int:
    """
    At startup, re-queue two kinds of cache entries for a fresh lookup:
      1. source == "unknown"  — previous lookup failed; try again now
      2. age > max_age_days   — may have better docs available since last fetch
    Returns the number of entries re-queued.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    requeued = 0
    _lock_map = {
        "Event": _event_cache_lock,
        "BSOD": _bsod_cache_lock,
        "Startup": _startup_cache_lock,
        "Services": _services_cache_lock,
        "Process": _process_cache_lock,
    }
    with _lock_map[label]:
        for key, entry in list(cache.items()):
            source = entry.get("source", "")
            fetched_str = entry.get("fetched", "")

            stale = False
            if source == "unknown":
                stale = True
            elif fetched_str:
                try:
                    fetched_dt = datetime.fromisoformat(fetched_str.replace("Z", "+00:00"))
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


def start_server(open_browser: bool = True):  # pragma: no cover
    """
    Initialize caches, start background workers, and run the Flask server.
    Called by __main__ (direct run) and by tray.py (system tray mode).
    """
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
    ev_requeued = _requeue_stale_cache(_event_cache, _lookup_queue, _lookup_in_flight, "Event")
    bsod_requeued = _requeue_stale_cache(_bsod_cache, _bsod_queue, _bsod_in_flight, "BSOD")
    startup_requeued = _requeue_stale_cache(_startup_cache, _startup_queue, _startup_in_flight, "Startup")
    services_requeued = _requeue_stale_cache(_services_cache, _services_queue, _services_in_flight, "Services")
    process_requeued = _requeue_stale_cache(_process_cache, _process_queue, _process_in_flight, "Process")

    print(f"[EventCache] Worker started. {len(_event_cache)} cached, {ev_requeued} re-queued.")
    print(f"[BSODCache]    Worker started. {len(_bsod_cache)} cached, {bsod_requeued} re-queued.")
    print(f"[StartupCache]  Worker started. {len(_startup_cache)} cached, {startup_requeued} re-queued.")
    print(f"[ServicesCache] Worker started. {len(_services_cache)} cached, {services_requeued} re-queued.")
    print(f"[ProcessCache]  Worker started. {len(_process_cache)} cached, {process_requeued} re-queued.")

    print("\n  WinDesktopMgr running at http://localhost:5000\n")
    app.run(debug=False, port=5000, use_reloader=False, threaded=True)


if __name__ == "__main__":
    start_server()
