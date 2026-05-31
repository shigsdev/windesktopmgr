"""
WinDesktopMgr
Flask backend — driver update checker + BSOD trend dashboard.
Reads from Windows Event Log and existing SystemHealthDiag HTML reports.
"""

import glob
import hashlib
import json
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
import win32com.client
import win32evtlog
import win32service
import win32serviceutil
import wmi
from flask import Flask, jsonify, make_response, render_template, request, send_from_directory

import bsod  # noqa: E402 -- import order intentional
import codehealth  # noqa: E402 -- import order intentional
import events  # noqa: E402 -- import order intentional
import processes  # noqa: E402 -- import order intentional
import sysinfo  # noqa: E402 -- import order intentional
from applogging import get_logger
from bsod import (
    REPORT_DIR,
    build_bsod_analysis,
    get_bsod_cache_status,
    get_bsod_events,  # noqa: F401 -- re-exported; resolved by-name via globals() in SELFTEST_CHECKS
    parse_event,
    summarize_bsod,
)
from credentials import get_credentials_network_health, summarize_credentials_network
from dashboard import (
    _DASHBOARD_CACHE_TTL,  # noqa: F401 -- re-exported; used by the dashboard_summary route
    _compute_dashboard_summary,  # noqa: F401 -- re-exported; called by route + patched in tests
    _dashboard_cache_clear,  # noqa: F401 -- re-exported; conftest reset hook + tests
    _dashboard_cache_lock,  # noqa: F401 -- re-exported; route + tests mutate under this lock
    _dashboard_refresh_lock,  # noqa: F401 -- re-exported; single-flight lock used by tests
    _dashboard_state,  # noqa: F401 -- re-exported; route reads/writes, tests mutate
    _trigger_dashboard_refresh_async,  # noqa: F401 -- re-exported; route calls it, tests patch it
)
from disk import disk_bp, get_disk_health, summarize_disk
from events import (
    get_cache_status,
    query_event_log,  # noqa: F401 -- re-exported; resolved by-name via globals() in NLQ tool dispatch
    summarize_events,
)
from homenet import homenet_bp, homenet_get_inventory
from nlq import nlq_bp
from nlq import register_tool_dispatch as _nlq_register_tool_dispatch
from processes import (
    SAFE_PROCESSES,
    SYSTEM_PROCESSES_GLOSSARY,
    add_memory_snooze,
    get_memory_analysis,  # noqa: F401 -- re-exported; resolved by-name via globals() in SELFTEST_CHECKS
    get_process_list,  # noqa: F401 -- re-exported; resolved by-name via globals() in SELFTEST_CHECKS
    kill_process,
    remove_memory_snooze,
    summarize_memory,
    summarize_processes,
)
from remediation import (
    _nlq_get_remediation_history,
    _nlq_run_remediation,
    remediation_bp,
)
from sysinfo import (
    summarize_sysinfo,
)
from thermals import get_thermals, summarize_thermals

_ps_log = get_logger("ps")

# ─── Headless mode: suppress console windows for subprocess calls ─────────────
# When running via tray.py (pythonw.exe), PowerShell subprocess calls would
# flash console windows. This flag is set by tray.py before start_server().
HEADLESS_MODE = False

_original_subprocess_run = subprocess.run


def _summarize_cmd(args) -> str:
    """Return a short string describing the subprocess command for logging."""
    try:
        text = " ".join(str(a) for a in args) if isinstance(args, list | tuple) else str(args)
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
# EVENT_CACHE_FILE now lives in events.py (#54 PR B).
# BSOD_CACHE_FILE / REPORT_DIR / BUGCHECK_CODES / RECOMMENDATIONS_DB /
# DRIVER_CONTEXT now live in bsod.py and are re-imported at the top of this file.

# ─── Driver checker state ─────────────────────────────────────────────────────
_wu_driver_cache = None
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


# ─── BSOD constants (BUGCHECK_CODES, REPORT_DIR) moved to bsod.py ─────────────

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


# RECOMMENDATIONS_DB moved to bsod.py


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
# WMI decode maps (_ff_map/_mem_type_map/_arch_map/_slot_usage_map/
# _mem_ec_map/_mem_loc_map) moved to sysinfo.py (#54 PR D)


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

    The conversion is only defined for the canonical NVIDIA form, where
    parts[2]+parts[3] is exactly 6 digits ("15" + "9174" → "159174"). Any
    other shape — a non-NVIDIA driver version, a malformed string — is
    returned unchanged rather than run through the formula, which would
    otherwise emit a garbage version (e.g. "32.0.1.23" → ".23") that could
    misfire update detection.
    """
    parts = win_ver.split(".")
    if len(parts) < 4:
        return win_ver
    raw = parts[2] + parts[3]  # e.g. "159174"
    if not raw.isdigit() or len(raw) != 6:
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
# Series 129 = GeForce RTX 50 Series (Desktop)
# Series 120 = GeForce RTX 30 Series (Desktop)
# Series 116 = GeForce RTX 20 Series (Desktop)
# Series 112 = GeForce GTX 16 Series (Desktop)
_NVIDIA_PFID_MAP: dict[str, int] = {
    # RTX 50 series
    "NVIDIA GeForce RTX 5090": 1054,
    "NVIDIA GeForce RTX 5080": 1055,
    "NVIDIA GeForce RTX 5070 Ti": 1056,
    "NVIDIA GeForce RTX 5070": 1057,
    # RTX 40 series
    "NVIDIA GeForce RTX 4090": 995,
    "NVIDIA GeForce RTX 4080 SUPER": 1041,
    "NVIDIA GeForce RTX 4080": 996,
    "NVIDIA GeForce RTX 4070 Ti SUPER": 1040,
    "NVIDIA GeForce RTX 4070 Ti": 1001,
    "NVIDIA GeForce RTX 4070 SUPER": 1039,
    "NVIDIA GeForce RTX 4070": 1015,
    "NVIDIA GeForce RTX 4060 Ti": 1022,
    "NVIDIA GeForce RTX 4060": 1023,
    # RTX 30 series
    "NVIDIA GeForce RTX 3090 Ti": 948,
    "NVIDIA GeForce RTX 3090": 890,
    "NVIDIA GeForce RTX 3080 Ti": 892,
    "NVIDIA GeForce RTX 3080": 889,
    "NVIDIA GeForce RTX 3070 Ti": 900,
    "NVIDIA GeForce RTX 3070": 891,
    "NVIDIA GeForce RTX 3060 Ti": 899,
    "NVIDIA GeForce RTX 3060": 904,
    "NVIDIA GeForce RTX 3050": 978,
    # RTX 20 series
    "NVIDIA GeForce RTX 2080 Ti": 838,
    "NVIDIA GeForce RTX 2080 SUPER": 856,
    "NVIDIA GeForce RTX 2080": 815,
    "NVIDIA GeForce RTX 2070 SUPER": 855,
    "NVIDIA GeForce RTX 2070": 824,
    "NVIDIA GeForce RTX 2060 SUPER": 854,
    "NVIDIA GeForce RTX 2060": 843,
    # GTX 16 series
    "NVIDIA GeForce GTX 1660 Ti": 846,
    "NVIDIA GeForce GTX 1660 SUPER": 858,
    "NVIDIA GeForce GTX 1660": 845,
    "NVIDIA GeForce GTX 1650 SUPER": 857,
    "NVIDIA GeForce GTX 1650": 847,
}


def _lookup_nvidia_pfid(gpu_name: str) -> int | None:
    """Fuzzy lookup of GPU product family ID from the PFID map.

    Handles common variations in GPU name strings from nvidia-smi and WMI:
    - Missing "NVIDIA" prefix (WMI sometimes drops it)
    - Extra suffixes like "8GB", "16GB", "Laptop GPU"
    - Case differences

    Returns the pfid int or None if no match.
    """
    # 1. Exact match (fastest path)
    pfid = _NVIDIA_PFID_MAP.get(gpu_name)
    if pfid is not None:
        return pfid

    # 2. Normalise: strip, ensure "NVIDIA " prefix, collapse whitespace
    name = " ".join(gpu_name.strip().split())  # collapse whitespace
    if not name.upper().startswith("NVIDIA "):
        name = "NVIDIA " + name

    pfid = _NVIDIA_PFID_MAP.get(name)
    if pfid is not None:
        return pfid

    # 3. Case-insensitive exact match
    name_lower = name.lower()
    for key, val in _NVIDIA_PFID_MAP.items():
        if key.lower() == name_lower:
            return val

    # 4. Substring match — GPU name contains a known model (longest match wins)
    # Handles "NVIDIA GeForce RTX 4060 Ti 16GB" → "NVIDIA GeForce RTX 4060 Ti"
    best_key, best_len = None, 0
    for key in _NVIDIA_PFID_MAP:
        if key.lower() in name_lower and len(key) > best_len:
            best_key = key
            best_len = len(key)
    if best_key:
        return _NVIDIA_PFID_MAP[best_key]

    return None


# NVIDIA AjaxDriverService API endpoint
_NVIDIA_DRIVER_API = "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php"


def _detect_nvidia_driver_branch() -> bool:
    """Detect whether the user is on Studio/CRD or Game Ready driver branch.

    Checks NVIDIA App's SHIM.json for IsCRD flag.  The flag lives INSIDE
    the ``NVDriver`` sub-object (not at top level), e.g.::

        {"NVDriver": {"IsCRD": false, "Version": 59595, ...}}

    Falls back to False (Game Ready) since that's the most common consumer
    configuration and returning True (Studio) when the user has Game Ready
    causes the API to return nothing (the exact bug from 2026-05-18).

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
            # IsCRD is nested inside NVDriver, not at top level
            nv_driver = data.get("NVDriver") or {}
            is_crd = nv_driver.get("IsCRD")
            if is_crd is not None:
                return bool(is_crd)
            # Legacy fallback: some older SHIM.json versions had it at top level
            top_level = data.get("IsCRD")
            if top_level is not None:
                return bool(top_level)
    except Exception:
        pass
    # Default to Game Ready — most common consumer configuration.
    # Defaulting to Studio when user has Game Ready causes the API to
    # return nothing (no Studio driver for many consumer GPUs).
    return False


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
        # Cap the read so a hijacked endpoint, compromised DNS, or a broken
        # proxy can't OOM the process with an unbounded response body.
        # NVIDIA's single-driver payload is ~2 KB; 1 MiB is a generous
        # ceiling. A truncated body fails json.loads and falls through to
        # the except handler → None (same as any other API failure).
        max_body = 1_048_576
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read(max_body).decode())
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


# ── NVIDIA update info cache ──────────────────────────────────────────────
# The NVIDIA API is queried via get_driver_health() inside the dashboard
# fan-out, which runs every 30s.  Hammering the API every 30s is wasteful
# and risks rate-limiting.  Cache the result for 10 minutes — driver
# releases don't happen more than once a week, and the Installer2 / WU
# fallbacks are even slower to change.
_nvidia_update_cache: dict = {"data": None, "ts": None}
_NVIDIA_UPDATE_CACHE_TTL = timedelta(minutes=10)
# get_nvidia_update_info() is called concurrently from the dashboard
# fan-out's ThreadPoolExecutor, run_scan()'s daemon thread, and the
# /api/nvidia/status route. The lock makes the (data, ts) pair read and
# written atomically so a reader never sees fresh data paired with a stale
# timestamp (or None), which would otherwise misfire the TTL check.
_nvidia_update_cache_lock = threading.Lock()


def _reset_nvidia_update_cache() -> None:
    """Test helper — clear the NVIDIA update cache between tests."""
    with _nvidia_update_cache_lock:
        _nvidia_update_cache["data"] = None
        _nvidia_update_cache["ts"] = None


def get_nvidia_update_info() -> dict | None:
    """Check for NVIDIA GPU and pending driver updates.

    Detection priority:
    1. NVIDIA public API (real-time, works even if update not downloaded)
    2. Installer2 Cache registry (downloaded-but-not-installed)
    3. Windows Update pending driver list (catches updates the API missed)

    Results are cached for 10 minutes to avoid hammering the NVIDIA API
    on every 30-second dashboard refresh.

    Returns dict with InstalledVersion, LatestVersion, UpdateAvailable, Name
    or None if no NVIDIA GPU found.
    """
    # Always read the current installed driver version first. It's cheap
    # (nvidia-smi + WMI, ~300 ms) compared to the expensive API + Windows
    # Update fan-out the cache is protecting (~5 s+).
    #
    # We need this BEFORE consulting the cache so we can detect the
    # "user just installed the new driver" case. Without this check the
    # cache would keep serving ``UpdateAvailable: True`` (with the OLD
    # InstalledVersion) for up to 10 minutes after the install, leaving
    # the dashboard concern and Driver Manager NVIDIA card stuck on
    # "Update Available" until the TTL expired. The cache key is now
    # tied to the installed version, so a version bump invalidates
    # immediately.
    gpu = _get_nvidia_gpu_info()
    if not gpu:
        return None

    installed = gpu["installed"]
    name = gpu["name"]

    # No usable installed-version string. _get_nvidia_gpu_info() can return a
    # GPU dict with installed="" when nvidia-smi is absent AND WMI yields no
    # DriverVersion. Without a version we can't tell update-vs-current, and
    # caching a result keyed on "" would either falsely cache-hit forever or
    # — if the version flickers back on a later WMI read — force the full
    # ~5 s API + Windows Update recompute on every call. Bail out instead;
    # the /api/nvidia/status route treats None as "no NVIDIA card to show".
    if not installed:
        return None

    # Cache hit — only when the installed version still matches what was
    # cached. A mismatch means the user updated the driver since the last
    # check; recompute so the UI clears immediately on the next refresh.
    # Read the (data, ts) pair under the lock so a concurrent writer can't
    # hand us fresh data with a stale timestamp.
    with _nvidia_update_cache_lock:
        cached = _nvidia_update_cache["data"]
        cached_ts = _nvidia_update_cache["ts"]
    if cached is not None and cached_ts is not None and cached.get("InstalledVersion") == installed:
        age = datetime.now() - cached_ts
        if age < _NVIDIA_UPDATE_CACHE_TTL:
            return cached
    latest = ""
    source = "none"

    # Detect driver branch (Studio/CRD vs Game Ready) from NVIDIA App data
    is_studio = _detect_nvidia_driver_branch()

    # Method 1: NVIDIA public API — real-time latest version check
    pfid = _lookup_nvidia_pfid(name)
    if pfid:
        api_result = _query_nvidia_api(pfid, studio=is_studio)
        if api_result and api_result.get("version"):
            latest = api_result["version"]
            source = "nvidia_api"
        else:
            # Primary branch returned nothing — try the other branch.
            # This catches SHIM.json misdetection (2026-05-18 bug: IsCRD was
            # nested inside NVDriver, not at top level, so branch detection
            # defaulted wrong) and GPUs that only have one branch available.
            alt_result = _query_nvidia_api(pfid, studio=not is_studio)
            if alt_result and alt_result.get("version"):
                latest = alt_result["version"]
                source = "nvidia_api"
                # The alt branch succeeding where the primary failed is a
                # strong signal that _detect_nvidia_driver_branch() guessed
                # wrong. Log it so a branch-detection regression is visible
                # instead of being silently papered over by the retry.
                primary = "Studio" if is_studio else "Game Ready"
                alt = "Game Ready" if is_studio else "Studio"
                print(
                    f"[NVIDIA] branch detection picked {primary} but only the "
                    f"{alt} API returned a driver — branch detection may be wrong"
                )
    else:
        # GPU not in _NVIDIA_PFID_MAP — the API can't be queried at all, so
        # detection silently falls back to the offline-only Methods 2/3.
        # Log it so an unlisted GPU is diagnosable from the console instead
        # of looking like "no update available".
        print(
            f"[NVIDIA] no PFID mapping for GPU {name!r} — skipping API, "
            f"using offline fallbacks (Installer2 cache / Windows Update) only"
        )

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

    # Method 3: Windows Update pending driver list — catches NVIDIA updates
    # that the public API hasn't published yet (e.g., NVIDIA App notified the
    # user before the AjaxDriverService API was updated).  Uses the existing
    # _wu_driver_cache if a scan has run, otherwise makes a fresh WU query.
    if not latest:
        try:
            wu = get_windows_update_drivers()
            if wu:
                for title, info in wu.items():
                    if "nvidia" in title.lower():
                        wu_ver = info.get("DriverVersion", "")
                        if wu_ver and wu_ver != installed:
                            # WU returns Windows 4-part version — convert
                            nv_ver = _win_to_nvidia_version(wu_ver)
                            if nv_ver != installed:
                                latest = nv_ver
                                source = "windows_update"
                                break
        except Exception:
            pass

    update_available = bool(latest and latest != installed)
    result = {
        "Name": name,
        "InstalledVersion": installed,
        "WindowsVersion": gpu["win_ver"],
        "LatestVersion": latest,
        "UpdateAvailable": update_available,
        "UpdateSource": source,
    }

    # Cache the result for 10 minutes. Write the (data, ts) pair under the
    # lock so concurrent readers always see a consistent snapshot.
    with _nvidia_update_cache_lock:
        _nvidia_update_cache["data"] = result
        _nvidia_update_cache["ts"] = datetime.now()

    return result


# ── Windows Update COM helpers ─────────────────────────────────────────────
# The Windows Update API is reached via the Microsoft.Update.Session COM
# object, driven in-process with win32com — no PowerShell subprocess (backlog
# #28 Batch G). A prototype spike (2026-05-22) proved synchronous Search() /
# QueryHistory() work cleanly from Python; the per-call win is the ~200-500 ms
# PowerShell process spawn that COM eliminates.


def _wu_prop(obj, name):
    """Read a COM property that may not exist on this update/history type.

    Driver-update objects expose ``DriverVersion`` etc., but a generic update
    does not — accessing a missing COM property raises, so swallow it.
    """
    try:
        return getattr(obj, name)
    except Exception:  # noqa: BLE001 — missing COM property → treat as absent
        return None


def _wu_iso(dt) -> str:
    """COM date → ISO-8601 string (mirrors the PowerShell ``.ToString('o')``)."""
    if dt is None:
        return ""
    try:
        return dt.isoformat()
    except Exception:  # noqa: BLE001
        return str(dt)


def _wu_searcher():
    """Create a Windows Update ``IUpdateSearcher`` with COM initialised for
    the current thread — same pattern as ``_wmi_conn()``. WU collectors run
    in Flask worker threads, the dashboard fan-out, and run_scan's daemon
    thread, none of which have COM set up by default.
    """
    pythoncom.CoInitialize()
    session = win32com.client.Dispatch("Microsoft.Update.Session")
    return session.CreateUpdateSearcher()


def _wu_run(work, timeout_s: float, label: str):
    """Run a COM-using callable bounded by a wall-clock timeout.

    WU COM calls (``Search`` / ``QueryHistory``) block and cannot be
    interrupted, and a cold Windows Update Agent can take tens of seconds to
    initialise on the first call after a restart. So ``work`` runs in a
    daemon worker thread we join with a timeout — mirroring the subprocess
    timeouts the PowerShell versions had. Raises ``TimeoutError`` on timeout
    (the orphaned daemon worker finishes on its own); re-raises any error
    from ``work``.
    """
    box: dict = {}

    def _runner():
        try:
            box["data"] = work()
        except Exception as e:  # noqa: BLE001 — surfaced to the caller below
            box["error"] = e

    t = threading.Thread(target=_runner, name=f"WU-{label}", daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise TimeoutError(f"{label} exceeded {timeout_s:.0f}s")
    if "error" in box:
        raise box["error"]
    return box.get("data")


def _wu_search_drivers(timeout_s: float = 120.0) -> list:
    """Run the WU 'available driver updates' search via in-process COM,
    bounded by ``timeout_s`` (the blocking COM ``Search()`` cannot be
    cancelled — see ``_wu_run``). Raises ``TimeoutError`` on timeout."""

    def _search():
        searcher = _wu_searcher()
        updates = searcher.Search("IsInstalled=0 AND Type='Driver'").Updates
        rows = []
        for i in range(updates.Count):
            u = updates.Item(i)
            rows.append(
                {
                    "Title": _wu_prop(u, "Title") or "",
                    "Description": _wu_prop(u, "Description") or "",
                    "DriverModel": _wu_prop(u, "DriverModel") or "",
                    "DriverVersion": _wu_prop(u, "DriverVersion") or "",
                    "DriverManufacturer": _wu_prop(u, "DriverManufacturer") or "",
                }
            )
        return rows

    return _wu_run(_search, timeout_s, "Windows Update driver search") or []


def get_windows_update_drivers() -> dict | None:
    """Find available driver updates via the Windows Update COM API
    (in-process win32com — no PowerShell subprocess).

    Returns a dict keyed by lowercase driver title -> update info, or None on
    failure. Returns None (never {}) on timeout/error so a transient failure
    is not cached — see the cache-poisoning note below.
    """
    global _wu_driver_cache
    if _wu_driver_cache is not None:
        return _wu_driver_cache

    try:
        updates = _wu_search_drivers(timeout_s=120)
        lookup = {(u["Title"] or "").lower(): u for u in updates}
        _wu_driver_cache = lookup
        print(f"[WU] Found {len(lookup)} driver update(s) via Windows Update")
        return lookup
    except TimeoutError as e:
        # A timeout is transient — do NOT cache it. Caching {} here would
        # poison the cache: every later call hits the `_wu_driver_cache is not
        # None` short-circuit at the top and returns {} forever, permanently
        # disabling Windows Update driver detection (and the NVIDIA Method 3
        # fallback) until the process restarts. Leave the cache unpopulated so
        # the next call retries, and return None — the "failure" signal that
        # makes run_scan() mark drivers "unknown" rather than "up to date".
        print(f"[WU error] {e}")
        _wu_driver_cache = None
        return None
    except Exception as e:  # noqa: BLE001
        print(f"[WU error] {e}")
        _wu_driver_cache = None
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
    global _scan_results, _scan_status, _wu_driver_cache
    _wu_driver_cache = None
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


# ─── BSOD analysis helpers moved to bsod.py (get_bsod_events, parse_event,
#     parse_report_crashes, build_recommendations, build_bsod_analysis) ──────────


def _parse_ts(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


# _is_this_month + build_bsod_analysis moved to bsod.py


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


def _exe_version_info(path: str) -> dict:
    """Read an executable's version resource — FileDescription, CompanyName,
    ProductName, FileVersion — via ``win32api``, replacing a PowerShell
    ``Get-Item .VersionInfo`` call. Returns ``{}`` if the file has no version
    resource or cannot be read.
    """
    try:
        # String fields live under a language/codepage block; the translation
        # table lists the (lang, codepage) pairs the resource provides.
        langs = win32api.GetFileVersionInfo(path, r"\VarFileInfo\Translation")
        lang, codepage = langs[0] if langs else (0x0409, 1200)
    except Exception:  # noqa: BLE001 — no version resource / unreadable
        return {}
    info: dict = {}
    for field in ("FileDescription", "CompanyName", "ProductName", "FileVersion"):
        try:
            info[field] = (
                win32api.GetFileVersionInfo(path, f"\\StringFileInfo\\{lang:04X}{codepage:04X}\\{field}") or ""
            )
        except Exception:  # noqa: BLE001 — this field absent from the resource
            info[field] = ""
    return info


def _lookup_startup_via_fileinfo(command: str, name: str) -> dict | None:
    """
    Read Windows file version info for the executable — publisher, description,
    version — in-process via win32api. Completely offline, no PowerShell.
    """
    # Extract exe path from command
    cmd = command.strip()
    # Handle quoted paths
    if cmd.startswith('"'):
        exe_path = cmd.split('"')[1] if '"' in cmd[1:] else cmd[1:]
    else:
        exe_path = cmd.split()[0] if cmd else ""

    if not exe_path or not exe_path.lower().endswith(".exe"):
        # Resolve the exe on PATH — shutil.which replaces a Get-Command call.
        base = _extract_exe_from_command(command)
        if base:
            try:
                found = shutil.which(base + ".exe") or shutil.which(base)
                if found:
                    exe_path = found
            except Exception:  # noqa: BLE001
                pass

    if not exe_path:
        return None

    data = _exe_version_info(exe_path)
    if not data:
        return None
    try:
        desc = (data.get("FileDescription") or "").strip()
        company = (data.get("CompanyName") or "").strip()
        product = (data.get("ProductName") or "").strip()
        version = (data.get("FileVersion") or "").strip()
        fname = (os.path.basename(exe_path) or name).strip()

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


# Task Scheduler COM trigger-type constants (TASK_TRIGGER_TYPE2 — MSDN).
_TASK_TRIGGER_BOOT = 8
_TASK_TRIGGER_LOGON = 9


def _walk_tasks_with_logon_or_boot(folder, out: list) -> None:
    """Recursively collect Schedule.Service tasks whose triggers include a
    Logon or Boot trigger (the PowerShell `CimClassName -match
    "LogonTrigger|BootTrigger"` equivalent). Each emitted entry has the same
    shape `get_startup_items` produced from PS: Name / Command / Location /
    Type / Enabled.
    """
    try:
        for task in folder.GetTasks(1):  # 1 = TASK_ENUM_HIDDEN: include hidden
            try:
                definition = task.Definition
                triggers = definition.Triggers
                has_match = False
                for j in range(1, triggers.Count + 1):  # COM collections are 1-indexed
                    if triggers.Item(j).Type in (_TASK_TRIGGER_LOGON, _TASK_TRIGGER_BOOT):
                        has_match = True
                        break
                if not has_match:
                    continue
                cmd = task.Name
                actions = definition.Actions
                if actions.Count > 0:
                    a = actions.Item(1)
                    path = getattr(a, "Path", "") or ""
                    if path:
                        args = getattr(a, "Arguments", "") or ""
                        cmd = f"{path} {args}".strip()
                out.append(
                    {
                        "Name": task.Name,
                        "Command": cmd,
                        "Location": "Task Scheduler",
                        "Type": "task",
                        "Enabled": bool(task.Enabled),
                    }
                )
            except Exception:  # noqa: BLE001 — skip individual broken tasks
                continue
    except Exception:  # noqa: BLE001 — GetTasks can refuse on a restricted folder
        pass
    try:
        for sub in folder.GetFolders(0):
            _walk_tasks_with_logon_or_boot(sub, out)
    except Exception:  # noqa: BLE001
        pass


def _find_scheduled_task(folder, name: str):
    """Recursively locate a Task Scheduler task by name (used by
    ``toggle_startup_item``)."""
    try:
        for task in folder.GetTasks(1):
            if task.Name == name:
                return task
    except Exception:  # noqa: BLE001
        pass
    try:
        for sub in folder.GetFolders(0):
            found = _find_scheduled_task(sub, name)
            if found is not None:
                return found
    except Exception:  # noqa: BLE001
        pass
    return None


def get_startup_items() -> list:
    """Enumerate startup items from every source — all in-process (backlog
    #28 close-out): HKLM/HKCU ``Run`` + ``Run-Disabled`` via ``winreg``,
    Startup folder via ``pathlib``, and scheduled tasks with Logon/Boot
    triggers via the ``Schedule.Service`` COM object. No PowerShell."""
    items: list = []

    # ── Registry Run keys (HKLM/HKCU × Run + Run-Disabled) ───────────────
    _RUN_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    _DISABLED_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run-Disabled"
    for hive_const, hive_label, item_type in (
        (winreg.HKEY_LOCAL_MACHINE, "HKLM Run", "registry_hklm"),
        (winreg.HKEY_CURRENT_USER, "HKCU Run", "registry_hkcu"),
    ):
        for subkey, enabled in ((_RUN_SUBKEY, True), (_DISABLED_SUBKEY, False)):
            try:
                key = winreg.OpenKey(hive_const, subkey)
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _typ = winreg.EnumValue(key, i)
                            items.append(
                                {
                                    "Name": name,
                                    "Command": str(value),
                                    "Location": hive_label,
                                    "Type": item_type,
                                    "Enabled": enabled,
                                }
                            )
                            i += 1
                        except OSError:
                            break  # no more values
                finally:
                    winreg.CloseKey(key)
            except FileNotFoundError:
                pass  # Run-Disabled often doesn't exist until first toggle
            except Exception:  # noqa: BLE001
                pass

    # ── Startup folders (All Users + Current User) ───────────────────────
    from pathlib import Path

    for env_var, label in (
        ("ALLUSERSPROFILE", "Startup Folder (All Users)"),
        ("APPDATA", "Startup Folder (User)"),
    ):
        root = os.environ.get(env_var, "")
        if not root:
            continue
        folder_path = Path(root) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        try:
            for entry in folder_path.iterdir():
                if entry.is_file():
                    items.append(
                        {
                            "Name": entry.stem,
                            "Command": str(entry),
                            "Location": label,
                            "Type": "folder",
                            "Enabled": True,
                        }
                    )
        except (FileNotFoundError, NotADirectoryError):
            pass
        except Exception:  # noqa: BLE001
            pass

    # ── Scheduled tasks with Logon/Boot triggers (Schedule.Service COM) ──
    try:
        pythoncom.CoInitialize()
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        _walk_tasks_with_logon_or_boot(scheduler.GetFolder("\\"), items)
    except Exception as e:  # noqa: BLE001
        print(f"[Startup tasks] {e}")

    # ── Enrich + sort (unchanged) ────────────────────────────────────────
    for item in items:
        cmd = (item.get("Command") or "").lower()
        item["suspicious"] = any(re.search(p, cmd) for p in SUSPICIOUS_PATTERNS)
        info = get_startup_item_info(item.get("Name", ""), item.get("Command", ""))
        item["info"] = info

    rec_order = {"disable": 0, "optional": 1, "keep": 2, None: 3}
    items.sort(
        key=lambda x: (
            not x.get("suspicious", False),
            rec_order.get((x.get("info") or {}).get("recommendation"), 3),
            x.get("Name", "").lower(),
        )
    )
    return items


def toggle_startup_item(name: str, item_type: str, enable: bool) -> dict:
    """Toggle a startup item between Run and Run-Disabled (registry) or
    enable/disable a scheduled task — pure-Python via ``winreg`` and the
    ``Schedule.Service`` COM object. No PowerShell (backlog #28 close-out).
    """
    safe_name = re.sub(r"[^a-zA-Z0-9\-_. ]", "", name).strip()
    if not safe_name:
        return {"ok": False, "error": "Invalid name"}

    if item_type in ("registry_hklm", "registry_hkcu"):
        hive = winreg.HKEY_LOCAL_MACHINE if item_type == "registry_hklm" else winreg.HKEY_CURRENT_USER
        run_subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        disabled_subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run-Disabled"
        # Enabling means moving the value from Run-Disabled → Run; disabling
        # is the reverse. The value's REG_TYPE is preserved (Run entries are
        # commonly REG_SZ but occasionally REG_EXPAND_SZ).
        src, dst = (disabled_subkey, run_subkey) if enable else (run_subkey, disabled_subkey)
        try:
            sk = winreg.OpenKey(hive, src, 0, winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(sk, safe_name)
            finally:
                winreg.CloseKey(sk)
            # CreateKey opens-or-creates — Run-Disabled often doesn't exist yet.
            dk = winreg.CreateKey(hive, dst)
            try:
                winreg.SetValueEx(dk, safe_name, 0, regtype, value)
            finally:
                winreg.CloseKey(dk)
            sk = winreg.OpenKey(hive, src, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(sk, safe_name)
            finally:
                winreg.CloseKey(sk)
            return {"ok": True, "error": ""}
        except FileNotFoundError:
            return {"ok": False, "error": f"Startup entry not found: {safe_name}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    if item_type == "task":
        try:
            pythoncom.CoInitialize()
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            task = _find_scheduled_task(scheduler.GetFolder("\\"), safe_name)
            if task is None:
                return {"ok": False, "error": f"Task not found: {safe_name}"}
            task.Enabled = bool(enable)
            return {"ok": True, "error": ""}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": "Cannot toggle this item type"}


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
    """Windows Update install history via the in-process Update COM API
    (``IUpdateSearcher.QueryHistory`` — no PowerShell subprocess).

    QueryHistory itself is a fast local call, but creating the COM session
    cold-starts the Windows Update Agent, which can take tens of seconds on
    the first call after a restart. Bounded by a 60 s worker-thread timeout
    so a cold WUA can't hang the Updates tab — this restores the cap the old
    PowerShell ``subprocess(..., timeout=30)`` provided.
    """

    def _query():
        searcher = _wu_searcher()
        total = searcher.GetTotalHistoryCount()
        hist = searcher.QueryHistory(0, min(total, 150))
        items = []
        for i in range(hist.Count):
            entry = hist.Item(i)
            title = _wu_prop(entry, "Title") or ""
            code = int(_wu_prop(entry, "ResultCode") or 0)
            # Categories is an ICategoryCollection — join the category names.
            cats = _wu_prop(entry, "Categories")
            cat_names = []
            if cats is not None:
                for j in range(cats.Count):
                    name = _wu_prop(cats.Item(j), "Name")
                    if name:
                        cat_names.append(name)
            kb_m = re.search(r"KB(\d+)", title)
            items.append(
                {
                    "Title": title,
                    "Date": _wu_iso(_wu_prop(entry, "Date")),
                    "ResultCode": code,
                    "Categories": ", ".join(cat_names),
                    "KB": f"KB{kb_m.group(1)}" if kb_m else "",
                    "result": RESULT_CODES.get(code, "Unknown"),
                }
            )
        return items

    try:
        return _wu_run(_query, 60, "Windows Update history query") or []
    except Exception as e:  # noqa: BLE001
        print(f"[Update history error] {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# EVENT LOG VIEWER
# ══════════════════════════════════════════════════════════════════════════════

# LEVEL_MAP / _LEVEL_DISPLAY / query_event_log moved to events.py (#54 PR B)


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
    # Split important updates from low-priority ones. Low-priority updates
    # are Monitor / printer-class INF metadata: Windows exposes these only
    # as *optional* driver updates (Settings > Windows Update > Advanced
    # options > Optional updates), never on the main Windows Update page.
    # Telling the user to "Open Windows Update" for one sends them
    # somewhere the update isn't shown — and these are "almost never worth
    # installing" anyway. So they must not raise a warning or drive the
    # main-Windows-Update advice; they're surfaced as an info note instead.
    important = [r for r in updates if not r.get("low_priority")]
    low_prio = [r for r in updates if r.get("low_priority")]
    insights = []
    actions = []
    if important:
        cats = Counter(r["category"] for r in important)
        top = cats.most_common(1)[0][0]
        nvidia_updates = [r for r in important if r.get("download_url", "").startswith("nvidia-app:")]
        wu_updates_list = [r for r in important if not r.get("download_url", "").startswith("nvidia-app:")]
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
                f"{len(important)} driver update(s) available — most in {top}.",
                advice,
            )
        )
        critical = [r for r in important if r["category"] in ("Display", "Network", "Chipset")]
        if critical:
            insights.append(
                _insight(
                    "critical",
                    f"{len(critical)} critical driver(s) need updating: "
                    + ", ".join(r["name"][:40] for r in critical[:3]),
                    "Prioritise display, network and chipset drivers for system stability.",
                )
            )
    if low_prio:
        lp_top = Counter(r["category"] for r in low_prio).most_common(1)[0][0]
        insights.append(
            _insight(
                "info",
                f"{len(low_prio)} optional {lp_top.lower()}-class driver update(s) detected.",
                "These are optional updates under Windows Update > Advanced options > "
                "Optional updates — rarely worth installing, and not shown on the main "
                "Windows Update page.",
            )
        )
    if unknown and not important:
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
    if important:
        headline = f"{len(important)} update(s) need attention"
    elif low_prio:
        headline = f"{len(low_prio)} optional driver update(s) — no action needed"
    elif unknown and not ok:
        headline = f"{len(unknown)} driver(s) could not be verified"
    elif unknown:
        headline = f"{len(ok)} driver(s) verified, {len(unknown)} unknown"
    else:
        headline = f"All {len(results)} drivers up to date"
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# summarize_bsod moved to bsod.py (re-imported at top)


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
# EVENT_KB moved to events.py (#54 PR B)
# NOISE_SOURCES + self-learning event-ID lookup subsystem moved to events.py
# (_event_cache state, _lookup_worker, _lookup_via_*, get_event_info,
#  get_cache_status, EVENT_CACHE_FILE) — re-imported at top (#54 PR B)
# summarize_events moved to events.py (re-imported at top) (#54 PR B)


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS MONITOR
# ══════════════════════════════════════════════════════════════════════════════

# Known system processes — flagged as safe, no action needed

# PROCESS knowledge base + enrichment + SAFE_PROCESSES + glossary +
# get_process_list/kill_process/summarize_processes moved to processes.py
# (re-imported at top; selftest globals() lookups resolve there) (#54 PR C)


# ══════════════════════════════════════════════════════════════════════════════
# TEMPERATURE & POWER
# ══════════════════════════════════════════════════════════════════════════════
# get_thermals + summarize_thermals + TEMP_WARN_C/TEMP_CRIT_C moved to
# thermals.py (#54 PR G). Re-imported at top so the route, /api/selftest
# globals() lookup, get_summary dispatch, NLQ dispatch, and dashboard fan-out
# keep their windesktopmgr-namespace bindings.


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


# MEMORY ANALYSIS + memory-snooze subsystem moved to processes.py (#54 PR C)


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
    # Pure-Python: urllib downloads the catalog, expand.exe (a Windows OS tool
    # — not PowerShell) extracts the .cab, ElementTree parses the XML. The
    # PowerShell heredoc this replaces was the last `subprocess powershell`
    # call in check_dell_bios_update (backlog #28 close-out).
    if not result["latest_version"]:
        import tempfile
        import urllib.request
        import xml.etree.ElementTree as ET

        cab_path = os.path.join(tempfile.gettempdir(), "DellCatalog.cab")
        xml_dir = os.path.join(tempfile.gettempdir(), "DellCatalog")
        xml_path = os.path.join(xml_dir, "CatalogPC.xml")
        try:
            # Fetch the catalog (~2 MB). Cap the read at 16 MB so a hostile
            # endpoint can't OOM us.
            req = urllib.request.Request(
                "https://downloads.dell.com/catalog/CatalogPC.cab",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                cab_bytes = resp.read(16_777_216)
            if not cab_bytes:
                raise RuntimeError("empty catalog download")
            with open(cab_path, "wb") as f:
                f.write(cab_bytes)
            os.makedirs(xml_dir, exist_ok=True)
            # No CAB extractor in the Python stdlib — use the OS's expand.exe
            # (not PowerShell). One light subprocess call, no PS process spawn.
            subprocess.run(
                ["expand.exe", cab_path, xml_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # XML element matching is case-INSENSITIVE here because the old
            # PowerShell relied on PS's case-insensitive property access
            # (`$_.componentType.value` vs the actual `ComponentType` element);
            # ElementTree is case-sensitive by default. The `{*}` namespace
            # wildcard handles the catalog's default xmlns.
            def _findall_ci(parent, name):
                t = name.lower()
                return [c for c in parent.iter() if c.tag.rsplit("}", 1)[-1].lower() == t]

            def _find_child_ci(parent, name):
                t = name.lower()
                for c in parent:
                    if c.tag.rsplit("}", 1)[-1].lower() == t:
                        return c
                return None

            # ruff S314: the XML source is the trusted Dell catalog over HTTPS
            # (fixed URL, 16 MB read cap above), and the catalog schema has no
            # external entities — adding a `defusedxml` dep for one parse is
            # disproportionate.
            tree = ET.parse(xml_path)  # noqa: S314
            root = tree.getroot()
            best = None
            best_date = ""
            for sc in _findall_ci(root, "SoftwareComponent"):
                ct = _find_child_ci(sc, "ComponentType")
                if ct is None or (ct.get("value") or "").upper() != "BIOS":
                    continue
                # Match on Model name *8960* OR systemID *0BC0* (XPS 8960).
                matched = False
                for m in _findall_ci(sc, "Model"):
                    mname = (m.get("name") or "").lower()
                    sysid = (m.get("systemID") or "").lower()
                    if "8960" in mname or "0bc0" in sysid:
                        matched = True
                        break
                if not matched:
                    continue
                rdate = sc.get("releaseDate", "")
                if best is None or rdate > best_date:
                    best = sc
                    best_date = rdate

            if best is not None:
                ver2 = best.get("dellVersion") or best.get("vendorVersion") or ""
                if ver2:
                    # Name/Display CDATA → element.text on the Display child.
                    name_text = ""
                    name_el = _find_child_ci(best, "Name")
                    if name_el is not None:
                        disp = _find_child_ci(name_el, "Display")
                        if disp is not None and disp.text:
                            name_text = disp.text.strip()
                    rel_path = best.get("path", "")
                    result["latest_version"] = ver2
                    result["latest_date"] = best_date
                    result["release_notes"] = name_text[:200]
                    if rel_path:
                        result["download_url"] = f"https://downloads.dell.com/{rel_path}"
                    result["source"] = "dell_catalog"
                    result["update_available"] = _ver_gt(ver2, current_version)
                    result["error"] = None
                    print(f"[BIOS] Catalog found version: {ver2}")
        except Exception as e2:  # noqa: BLE001
            if result["error"]:
                result["error"] += f" | Catalog: {e2}"
            else:
                result["error"] = f"Catalog: {e2}"
        finally:
            # Best-effort cleanup.
            try:
                if os.path.exists(cab_path):
                    os.remove(cab_path)
                if os.path.exists(xml_dir):
                    shutil.rmtree(xml_dir, ignore_errors=True)
            except Exception:  # noqa: BLE001
                pass

    # ── Method 3: Windows Update pending BIOS check ────────────────────────────
    # Reuses get_windows_update_drivers() — the WU "available drivers" search
    # already surfaces BIOS/Firmware updates, so there is no need for a second
    # COM search here. This also shares the _wu_driver_cache if a driver scan
    # has already run.
    if not result["latest_version"]:
        try:
            wu = get_windows_update_drivers()
            bios_u = None
            if wu:
                bios_u = next(
                    (u for u in wu.values() if re.search(r"BIOS|Firmware", u.get("Title", ""), re.IGNORECASE)),
                    None,
                )
            if bios_u:
                title = bios_u.get("Title", "")
                m = re.search(r"(\d+\.\d+[.\d]*)", title)
                ver3 = m.group(1) if m else ""
                if ver3:
                    result["latest_version"] = ver3
                    result["release_notes"] = title[:200]
                    result["source"] = "windows_update"
                    result["update_available"] = True  # WU only shows pending updates
                    result["error"] = None
                    print(f"[BIOS] Windows Update found BIOS update: {title}")
        except Exception:  # noqa: BLE001
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
# get_credentials_network_health + summarize_credentials_network moved to
# credentials.py (#54 PR F). Re-imported at top so the route, /api/selftest
# globals() lookup, get_summary dispatch, and NLQ tool dispatch keep their
# windesktopmgr-namespace bindings.


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


@app.route("/api/nvidia/status")
def api_nvidia_status():
    """Lightweight NVIDIA GPU + update status for the Driver Manager tab.

    Returns the cached NVIDIA update info without requiring a full driver scan.
    The driver tab calls this on load so the user sees GPU status immediately
    instead of the old "No scan results yet — click Run Scan" empty state.
    """
    info = get_nvidia_update_info()
    if info is None:
        return jsonify({"ok": True, "has_nvidia": False})
    return jsonify({"ok": True, "has_nvidia": True, **info})


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
    """Compute the per-tab summary.

    Backlog #29: defensive ETag / If-None-Match support against the
    2026-04-20 flood pattern (an old browser tab fires the same payload
    ~100×/sec). Server still computes the response (so cache stays
    fresh against backend state changes) but on a hit we return ``304
    Not Modified`` with zero body bytes — saves the per-call payload
    (~500-5000 B per tab × N redundant calls).
    """
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
    result = fn()
    # Strong ETag from the canonical JSON of (tab, result). Strong is
    # safe here: ``json.dumps(sort_keys=True)`` is fully deterministic,
    # and the summarizers are pure functions of their inputs + module
    # state, so equal ETag → equivalent response bytes. 16 hex chars
    # (64 bits of SHA-256) is plenty to avoid collisions between any
    # two adjacent responses on the same tab.
    canon = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
    etag = '"' + hashlib.sha256(f"{tab}:{canon}".encode()).hexdigest()[:16] + '"'
    inm = request.headers.get("If-None-Match", "")
    if inm and inm == etag:
        # RFC 7232: 304 must include any header that would have been
        # sent on a 200 response and is relevant to caching — that's
        # ETag here. Body MUST be empty.
        resp = make_response("", 304)
        resp.headers["ETag"] = etag
        return resp
    resp = jsonify(result)
    resp.headers["ETag"] = etag
    return resp


@app.route("/api/processes/list")
def process_list():
    return jsonify(get_process_list())


@app.route("/api/processes/lookup-unknowns", methods=["POST"])
def process_lookup_unknowns():
    procs = (request.get_json() or {}).get("processes", [])
    return jsonify({"ok": True, "queued": processes.requeue_unknowns(procs)})


@app.route("/api/processes/lookup-status")
def process_lookup_status():
    return jsonify(processes.lookup_status())


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
    """Toggle Fast Startup via the ``HiberbootEnabled`` registry value
    (``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power``).

    Pure-Python via ``winreg`` — no PowerShell subprocess. Requires admin
    (the key is under HKLM); a non-elevated process gets PermissionError,
    surfaced in the message.
    """
    value = 1 if enable else 0
    label = "enabled" if enable else "disabled"
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(key, "HiberbootEnabled", 0, winreg.REG_DWORD, value)
        finally:
            winreg.CloseKey(key)
        return {"ok": True, "enabled": enable, "message": f"Fast Startup {label}."}
    except Exception as e:  # noqa: BLE001
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


@app.route("/api/bios/audit/poll", methods=["POST"])
def bios_audit_poll_route():
    """Force a BIOS audit poll cycle right now.

    Useful for verifying that a fix actually worked on the live system
    without waiting up to 15 min for the next scheduled poll. The user
    can click 'Force Poll Now' in the UI and immediately see whether
    new errors appear in the audit history (or whether everything
    succeeded clean).

    Bug context 2026-05-14: PR #36 added caching for bios_serial / vbs
    that eliminated chronic timeouts. Without this endpoint the only
    way to verify the fix was to wait for the next 15-min cycle, which
    left the user staring at 8 historical error entries thinking the
    fix didn't work.
    """
    import bios_audit

    try:
        result = bios_audit.check_and_log_bios_changes(force=True, context="user")
        return jsonify(
            {
                "ok": True,
                "context": result.get("context"),
                "changes_count": len(result.get("changes") or []),
                "errors_count": len(result.get("errors") or []),
                "snapshot_timestamp": (result.get("snapshot") or {}).get("timestamp"),
            }
        )
    except Exception as e:  # noqa: BLE001 -- never crash this convenience route
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


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


# ── Backup tab (backlog #47) ─────────────────────────────────────────


@app.route("/api/backup/windows-backups")
def backup_windows_backups_route():
    """Section 1: WindowsImageBackup inventory.

    Returns the cached catalog from `backup_cache.json` (populated by
    the elevated helper in PR-2) or a `has_cache=False` placeholder if
    no scan has been run yet. PR-1 is read-only -- the cache is either
    pre-seeded manually or via the future Scan-with-UAC endpoint.
    """
    import backup

    return jsonify(backup.load_windows_backup_cache())


@app.route("/api/backup/file-history")
def backup_file_history_route():
    """Section 2: File History live state.

    Reads Config1.xml under %LOCALAPPDATA% (no elevation needed) and
    probes the configured target drive + backup-store folder + catalog
    freshness + staging area for health signals. The most common silent
    failure is "configured + enabled but the target backup-store folder
    on the target drive is missing" -- bubbles up as a critical health
    verdict.
    """
    import backup

    return jsonify(backup.get_file_history_state())


@app.route("/api/backup/summary")
def backup_summary_route():
    """Combined health summary across Sections 1 + 2.

    Used by the Backup tab's status header AND by the dashboard
    concern fan-out (so the dashboard doesn't have to parse two
    separate endpoints).
    """
    import backup

    return jsonify(backup.summarize_backup())


# ── Backup tab — elevated actions (PR-2 of #47) ─────────────────────


@app.route("/api/backup/scan", methods=["POST"])
def backup_scan_route():
    """Launch the elevated catalog scan via ShellExecuteW("runas").

    Returns ``{ok: True, session_id: "<hex>"}`` once the UAC prompt has
    been accepted and the helper is running; the UI then polls
    ``/api/backup/scan-status`` until the helper writes a result file.

    Refuses cleanly when the UAC prompt is declined or the helper can't
    be located.
    """
    import backup

    result = backup.request_elevated_action("scan_catalog", {})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@app.route("/api/backup/scan-status")
def backup_scan_status_route():
    """Poll endpoint -- returns ``{state: pending|done|missing}``."""
    import backup

    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"state": "missing", "error": "session_id required"}), 400
    return jsonify(backup.get_scan_status(session_id))


@app.route("/api/backup/scan-cleanup", methods=["POST"])
def backup_scan_cleanup_route():
    """Tray housekeeping: drop the request/result files for a finished
    session. The UI calls this after rendering the result so a future
    poll doesn't pick up stale state."""
    import backup

    data = request.get_json() or {}
    session_id = (data.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"ok": False, "error": "session_id required"}), 400
    backup.cleanup_session_files(session_id)
    return jsonify({"ok": True})


@app.route("/api/backup/delete-version", methods=["POST"])
def backup_delete_version_route():
    """Delete a specific WindowsImageBackup version via the elevated
    helper. Requires a TYPE-TO-CONFIRM body field that exactly matches
    the version_id -- mirrors the PR #22 router-reboot guard so a stray
    POST can't trigger an irreversible delete.

    Body::
        {"version_id": "05/24/2026-04:00", "confirm_token": "05/24/2026-04:00"}
    """
    import backup

    data = request.get_json() or {}
    version_id = (data.get("version_id") or "").strip()
    confirm = (data.get("confirm_token") or "").strip()
    if not version_id:
        return jsonify({"ok": False, "error": "version_id required"}), 400
    if confirm != version_id:
        return jsonify({"ok": False, "error": "confirm_token must equal version_id (defense-in-depth)"}), 400

    # Validate against the current cached catalog BEFORE we even spawn
    # the UAC prompt -- saves the user a click if the request is bad.
    cache = backup.load_windows_backup_cache()
    ok, err = backup.validate_delete_version_request(version_id, cache.get("versions") or [])
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    result = backup.request_elevated_action("delete_version", {"version_id": version_id})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@app.route("/api/backup/file-history-cleanup", methods=["POST"])
def backup_fh_cleanup_route():
    """Run ``fhmanagew.exe -cleanup <days>`` via the elevated helper.

    Body::
        {"days": 90, "confirm_token": "CLEANUP 90"}

    The confirm_token convention is the literal string "CLEANUP <days>"
    so a stray POST with default ``days=0`` (which would WIPE all but
    the newest version) can't fire without an explicit match.
    """
    import backup

    data = request.get_json() or {}
    days = data.get("days")
    try:
        days = int(days)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "days must be an integer"}), 400
    confirm = (data.get("confirm_token") or "").strip()
    expected = f"CLEANUP {days}"
    if confirm != expected:
        return jsonify({"ok": False, "error": f"confirm_token must equal {expected!r}"}), 400

    ok, err = backup.validate_fh_cleanup_request(days)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    result = backup.request_elevated_action("fh_cleanup", {"days": days})
    status = 200 if result.get("ok") else 502
    return jsonify(result), status


@app.route("/api/backup/actions-history")
def backup_actions_history_route():
    """Return the append-only audit log of elevated actions."""
    import backup

    return jsonify({"ok": True, "entries": backup.load_actions_history()})


# ── Backup tab Section 3 — OneDrive -> iCloud replicator (PR-1 of #46) ──


@app.route("/api/cloudcopy/rules", methods=["GET"])
def cloudcopy_get_rules_route():
    """Return the user-configured exclusion rules, or DEFAULT_RULES if
    none have been saved yet. Always shape-complete so the UI never has
    to null-check."""
    import cloudcopy

    return jsonify({"ok": True, "rules": cloudcopy.load_rules()})


@app.route("/api/cloudcopy/rules", methods=["PUT"])
def cloudcopy_put_rules_route():
    """Persist a user-edited rule set.

    Body: ``{"rules": {...}}`` -- shape must match DEFAULT_RULES.
    Returns ``{ok, error}`` -- 400 on validation failure, 500 on disk error.
    """
    import cloudcopy

    data = request.get_json() or {}
    incoming = data.get("rules")
    if not isinstance(incoming, dict):
        return jsonify({"ok": False, "error": "body must be {rules: {...}}"}), 400
    ok, err = cloudcopy.validate_rules(incoming)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    ok, err = cloudcopy.save_rules(incoming)
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


@app.route("/api/cloudcopy/preview", methods=["GET"])
def cloudcopy_preview_route():
    """Walk the OneDrive source root with the current rules and return
    counts + samples of what would be copied. Read-only -- no files
    are touched.

    Optional query params:
      sample_size: default 50, capped at 200
    """
    import cloudcopy

    try:
        sample = int(request.args.get("sample_size", "50"))
    except (TypeError, ValueError):
        sample = 50
    sample = max(1, min(sample, 200))
    return jsonify(cloudcopy.preview(sample_size=sample))


@app.route("/api/cloudcopy/history", methods=["GET"])
def cloudcopy_history_route():
    """Return past copy-session history. Empty in PR-1; PR-2's copy
    engine starts recording entries."""
    import cloudcopy

    return jsonify({"ok": True, "entries": cloudcopy.load_history()})


@app.route("/api/cloudcopy/resume-state", methods=["GET"])
def cloudcopy_resume_state_route():
    """Return the in-progress session state if a crashed session is
    detected, else ``{has_crashed: False}``. PR-2 wires this to the
    per-file commit log -- the user sees a "Resume previous run?"
    banner after a tray restart."""
    import cloudcopy

    state = cloudcopy.load_resume_state()
    active = cloudcopy.get_active_session_id()
    # If a session is currently active, the state file belongs to it
    # (not to a crashed run). Distinguish so the UI doesn't show a
    # spurious "Resume" banner during a normal in-progress copy.
    if not state or (active and active == state.get("session_id")):
        return jsonify({"ok": True, "has_crashed": False, "active_session_id": active})
    return jsonify({"ok": True, "has_crashed": True, "state": state, "active_session_id": active})


# PR-2: actual copy engine routes.


@app.route("/api/cloudcopy/run", methods=["POST"])
def cloudcopy_run_route():
    """Start a new copy session.

    Body::
        {"confirm_token": "START CLOUD COPY"}

    Type-to-confirm gate (mirrors PR #22 router-reboot pattern). The
    literal string "START CLOUD COPY" must match exactly so a stray
    POST can't trigger a long-running write operation.

    Returns ``{ok: true, session_id: "<hex>"}`` on launch, or 400/409
    with an error string on validation / concurrency failure.
    """
    import cloudcopy

    data = request.get_json() or {}
    confirm = (data.get("confirm_token") or "").strip()
    if confirm != "START CLOUD COPY":
        return jsonify({"ok": False, "error": "confirm_token must equal 'START CLOUD COPY'"}), 400
    result = cloudcopy.start_copy_session()
    if not result.get("ok"):
        # 409 Conflict for "another session is active"; 400 for everything else.
        status = 409 if "active" in (result.get("error") or "") else 400
        return jsonify(result), status
    return jsonify(result)


@app.route("/api/cloudcopy/status", methods=["GET"])
def cloudcopy_status_route():
    """Live progress for the active session (or its history row if it
    just finished)."""
    import cloudcopy

    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"state": "missing", "error": "session_id required"}), 400
    return jsonify(cloudcopy.get_status(session_id))


@app.route("/api/cloudcopy/cancel", methods=["POST"])
def cloudcopy_cancel_route():
    """Co-operative cancel of the active session. Worker drains its
    in-progress file then exits cleanly with a 'cancelled' history
    entry."""
    import cloudcopy

    data = request.get_json() or {}
    session_id = (data.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"ok": False, "error": "session_id required"}), 400
    accepted = cloudcopy.request_cancel(session_id)
    if not accepted:
        return jsonify({"ok": False, "error": "session id does not match active session"}), 404
    return jsonify({"ok": True})


@app.route("/api/cloudcopy/resume", methods=["POST"])
def cloudcopy_resume_route():
    """Continue a crashed session from its last-committed cursor. Re-
    validates source + destination + rules-hash before resuming so the
    rest of the session honours the same rule snapshot the original
    used."""
    import cloudcopy

    result = cloudcopy.resume_crashed_session()
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/cloudcopy/discard-crashed", methods=["POST"])
def cloudcopy_discard_route():
    """Write a 'discarded' history entry + clear the orphan state
    file. User chose Discard on the crashed-session banner."""
    import cloudcopy

    result = cloudcopy.discard_crashed_session()
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


# ── Baseline cluster examine + accept-all (backlog #50) ──────────────


@app.route("/api/baseline/cluster-context", methods=["GET"])
def baseline_cluster_context_route():
    """Gather contextual signals (Windows Updates + BIOS audit) inside
    a cluster's time window. Powers the Examine modal on the cross-
    surface timeline (#44).

    Query params:
      - started_at: ISO timestamp of the cluster's first event
      - ended_at:   ISO timestamp of the cluster's last event
      - window:     seconds to expand the window on each side
                    (default 300 = 5min)
    """
    import baseline

    started_at = (request.args.get("started_at") or "").strip()
    ended_at = (request.args.get("ended_at") or "").strip()
    if not started_at or not ended_at:
        return jsonify({"ok": False, "error": "started_at and ended_at required"}), 400
    try:
        window = int(request.args.get("window", "300"))
    except (TypeError, ValueError):
        window = 300
    window = max(0, min(window, 86400))  # 0..24h
    result = baseline.gather_cluster_context(started_at, ended_at, window_seconds=window)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@app.route("/api/baseline/accept-cluster", methods=["POST"])
def baseline_accept_cluster_route():
    """Bulk-accept every change in a cluster.

    Body::
        {
          "events": [
            {"category": "startup|services|tasks",
             "key": "...",
             "kind": "added|removed|changed",
             "current_value": {...} | null},
            ...
          ],
          "confirm_token": "ACCEPT N CHANGES"
        }

    The confirm_token must equal the literal string ``"ACCEPT <N>
    CHANGES"`` where N matches ``len(events)`` exactly. Mirrors the
    PR #22 router-reboot type-to-confirm guard so a stray POST can't
    flip a baseline by mistake.
    """
    import baseline

    data = request.get_json() or {}
    events = data.get("events")
    confirm = (data.get("confirm_token") or "").strip()
    if not isinstance(events, list):
        return jsonify({"ok": False, "error": "events list required"}), 400
    expected = f"ACCEPT {len(events)} CHANGES"
    if confirm != expected:
        return jsonify({"ok": False, "error": f"confirm_token must equal {expected!r}"}), 400
    result = baseline.accept_cluster_events(events)
    status = 200 if result.get("ok") else 207  # 207 Multi-Status when partial-success
    return jsonify(result), status


@app.route("/api/codehealth/status")
def codehealth_status_route():
    """Return the last persisted codehealth scan + freshness signals.

    Response::

        {"ok": true,
         "state": {<scan result> or {}},
         "is_stale": <bool>,                          # last_run > STALE_DAYS ago, or never run
         "is_running": <bool>,                        # background scan currently in flight
         "running_scanner": <str|None>,               # name of the single scanner re-running, or None
         "scanner_names": [<str>, ...],               # registered scanners, in card order
         "is_refreshing_coverage": <bool>,            # pytest --cov refresh in flight (PR-2 of #51)
         "coverage_refresh_last_result": <dict|None>, # last refresh outcome (stdout/stderr tail)
         "stale_days_threshold": <int>}

    Empty ``state`` ({}) means no scan has ever completed -- the UI
    should render placeholder cards + a primary "Scan now" CTA.
    """
    state = codehealth.load_state()
    return jsonify(
        {
            "ok": True,
            "state": state,
            "is_stale": codehealth.is_stale(state),
            "is_running": codehealth.is_running(),
            "running_scanner": codehealth.running_scanner(),
            "scanner_names": codehealth.scanner_names(),
            "is_refreshing_coverage": codehealth.is_refreshing_coverage(),
            "coverage_refresh_last_result": codehealth.get_coverage_refresh_last_result(),
            "stale_days_threshold": codehealth.STALE_DAYS,
        }
    )


@app.route("/api/codehealth/run", methods=["POST"])
def codehealth_run_route():
    """Kick off a fresh codehealth scan in the background.

    Returns immediately with 202 + ``{"ok": true, "started": true}``.
    If a scan is already running, returns 409 + ``{"ok": false,
    "started": false, "error": "already running"}``. UI polls
    ``/api/codehealth/status`` until ``is_running`` flips back to false.
    """
    started = codehealth.run_in_background()
    if not started:
        return jsonify({"ok": False, "started": False, "error": "scan already running"}), 409
    return jsonify({"ok": True, "started": True}), 202


@app.route("/api/codehealth/run/<scanner>", methods=["POST"])
def codehealth_run_one_route(scanner):
    """Re-run a SINGLE scanner (coverage / ruff / secrets / tech_debt)
    in the background, leaving the other cards untouched. Backs the
    per-card "↻ Run" buttons.

    Returns 202 + ``{"ok": true, "started": true}`` on success.
    404 + ``{"ok": false, "error": "unknown scanner"}`` for an
    unregistered name. 409 + ``{"ok": false, "started": false}`` if any
    scan (global or single) is already in flight. UI polls
    ``/api/codehealth/status`` until ``is_running`` flips back to false.

    Note: the coverage card's expensive pytest path stays on
    ``/api/codehealth/refresh-coverage``; ``run/coverage`` here just
    re-reads the existing .coverage file (cheap), same as the run-all
    sweep does.
    """
    if scanner not in codehealth.scanner_names():
        return jsonify({"ok": False, "error": f"unknown scanner: {scanner}"}), 404
    started = codehealth.run_one_in_background(scanner)
    if not started:
        return jsonify({"ok": False, "started": False, "error": "scan already running"}), 409
    return jsonify({"ok": True, "started": True}), 202


@app.route("/api/codehealth/reset-emitted", methods=["POST"])
def codehealth_reset_emitted_route():
    """Clear the set of scan-finding fingerprints we've already pushed
    to the backlog. Next scan will re-emit findings that were previously
    deduped. Useful when the user has manually cleaned up old auto-
    generated rows and wants the scanner to repopulate.

    PR-2 of #51 (sub-task B, 2026-05-27): backlog auto-population.
    """
    ok = codehealth.reset_emitted_fingerprints()
    return jsonify({"ok": ok}), (200 if ok else 500)


@app.route("/api/codehealth/refresh-coverage", methods=["POST"])
def codehealth_refresh_coverage_route():
    """Run pytest --cov in the background so the .coverage file gets a
    fresh write, then auto-trigger a scan_all to re-read everything.

    Returns 202 immediately with ``{"ok": true, "started": true}``.
    If a refresh is already running, returns 409. UI should poll
    ``/api/codehealth/status`` and wait for ``is_refreshing_coverage``
    to flip back to false; the new coverage % will then be in ``state``.

    PR-2 of #51: ships the user-facing "Refresh coverage" button so
    the stale .coverage file issue (caught 2026-05-27) is fixable
    from inside the UI rather than requiring the user to drop to a
    shell and run pytest manually.
    """
    started = codehealth.refresh_coverage_in_background()
    if not started:
        return jsonify({"ok": False, "started": False, "error": "coverage refresh already running"}), 409
    return jsonify({"ok": True, "started": True}), 202


@app.route("/api/baseline/timeline")
def baseline_timeline_route():
    """Unified cross-surface change timeline (backlog #44).

    Flattens the per-category drift history into one chronologically-sorted
    stream of change events and clusters multi-category bursts within the
    requested window. Lone events and same-category bursts stay
    ungrouped. Cluster severity scales with the number of categories
    touched — a single burst that hits startup + services + tasks is the
    canonical install / malware fingerprint.

    Query params:
      - window: seconds, default 300 (5 min). Clamped to [10, 86400].

    Response::

        {"ok": true, "window_seconds": <int>, "timeline": [<items>, ...]}

    Items are either ``{"type": "event", ...}`` or
    ``{"type": "cluster", "events": [...], "categories": [...], ...}``.
    Newest first. See ``baseline.correlate_drift_events`` for the
    exact item shape.
    """
    import baseline

    try:
        window = int(request.args.get("window", "300"))
    except (TypeError, ValueError):
        window = 300
    # Clamp: <10 s is finer than the timestamp resolution (`isoformat`
    # rounded to seconds), >24 h is pointless — anything that far apart
    # isn't correlated.
    window = max(10, min(window, 86400))
    history = baseline.load_history()
    timeline = baseline.correlate_drift_events(history, window_seconds=window)
    return jsonify({"ok": True, "window_seconds": window, "timeline": timeline})


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
    return jsonify({"ok": True, "snoozes": processes._load_memory_snoozes()})


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

        # Microcode revision from the registry — winreg, no PowerShell.
        # HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 'Update Revision'
        # is a REG_BINARY blob; format it as 0x<uppercase-hex>, matching what
        # [BitConverter]::ToString().Replace('-','') produced.
        microcode = "Unable to read"
        try:
            mc_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            )
            try:
                raw, _typ = winreg.QueryValueEx(mc_key, "Update Revision")
            finally:
                winreg.CloseKey(mc_key)
            microcode = "0x" + raw.hex().upper() if isinstance(raw, bytes | bytearray) else str(raw)
        except Exception:  # noqa: BLE001
            microcode = "Unable to read"

        # BSOD / WHEA / Kernel-Power-41 counts via the event-log API
        # (win32evtlog), replacing three Get-WinEvent -FilterHashtable calls.
        counts: dict = {}
        try:
            bsod_rows = _query_event_log_xpath(
                "System",
                _build_evt_xpath(ids=[1001], providers=["Microsoft-Windows-WER-SystemErrorReporting"]),
                max_events=100,
            )
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            bsod30 = sum(1 for e in bsod_rows if _parse_ts(e.get("TimeCreated", "")) >= cutoff)
            whea = len(
                _query_event_log_xpath(
                    "System",
                    _build_evt_xpath(providers=["Microsoft-Windows-WHEA-Logger"]),
                    max_events=100,
                )
            )
            kp41 = len(
                _query_event_log_xpath(
                    "System",
                    _build_evt_xpath(ids=[41], providers=["Microsoft-Windows-Kernel-Power"]),
                    max_events=100,
                )
            )
            counts = {"BSODs30Days": bsod30, "WHEAErrors": whea, "UnexpectedShutdowns": kp41}
        except Exception:  # noqa: BLE001
            counts = {}

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
    """Collect comprehensive system information for the System Info tab.

    Body moved to sysinfo.collect_sysinfo() (#54 PR D); this stays a thin
    route wrapper that jsonify()s the same payload dict.
    """
    return jsonify(sysinfo.collect_sysinfo())


# summarize_sysinfo + hardware-upgrade analyser (#43) + summarize_upgrades
# moved to sysinfo.py (#54 PR D). summarize_sysinfo re-imported at top.


# Dashboard summary cache + fan-out (_compute_dashboard_summary,
# _trigger_dashboard_refresh_async, _dashboard_cache_clear, cache state +
# locks) moved to dashboard.py (#54 PR E). Symbols re-imported at top so the
# route below and the test suite keep their windesktopmgr-namespace bindings.


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
    return jsonify(bsod.delete_cached_code(code))


@app.route("/api/bsod/cache/clear", methods=["POST"])
def bsod_cache_clear():
    return jsonify(bsod.clear_cache())


@app.route("/api/events/cache")
def events_cache():
    """Return the current event ID cache status — useful for debugging."""
    return jsonify(get_cache_status())


@app.route("/api/events/cache/delete/<int:event_id>", methods=["DELETE"])
def events_cache_delete(event_id: int):
    """Remove a specific event ID from the cache so it gets re-looked up."""
    return jsonify(events.delete_cached_id(event_id))


@app.route("/api/events/cache/clear", methods=["POST"])
def events_cache_clear():
    """Wipe the entire learned cache (keeps static EVENT_KB)."""
    return jsonify(events.clear_cache())


@app.route("/api/report/export")
def report_export():
    """On-demand system health report (backlog #15).

    Query parameters:
      scope       -- "full" | "dashboard" | "bsod" | "hardware" | "network"
                     (default "full")
      format      -- "markdown" | "html" | "json" (default "markdown")
      redact_pii  -- "1" / "true" / "yes" enable; anything else disable.
                     Default: enabled. The cost of leaking a service tag
                     in a public support post is real -- explicit opt-out.
      attachment  -- "1" to force Content-Disposition: attachment (browser
                     downloads instead of rendering inline). Useful for
                     the "Save to file" button. Default: inline so the
                     browser can preview HTML / Markdown.

    Returns the rendered report with the correct Content-Type. Errors
    are 400 (bad params) or 500 (collector blew up); both surface a
    JSON error body.
    """
    from report import generate_report

    scope = (request.args.get("scope") or "full").strip().lower()
    fmt = (request.args.get("format") or "markdown").strip().lower()
    # Default redact ON; only OFF when the user explicitly opts out.
    redact_raw = (request.args.get("redact_pii") or "1").strip().lower()
    redact = redact_raw in ("1", "true", "yes", "on")
    as_attachment = (request.args.get("attachment") or "0").strip().lower() in ("1", "true", "yes", "on")

    try:
        content, mime = generate_report(scope=scope, fmt=fmt, redact_pii=redact)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:  # noqa: BLE001 -- we want the route to NEVER 500 silently
        return jsonify({"ok": False, "error": f"Report generation failed: {e}"}), 500

    headers = {"Content-Type": mime}
    if as_attachment:
        ext = {"markdown": "md", "html": "html", "json": "json"}[fmt]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        headers["Content-Disposition"] = f'attachment; filename="windesktopmgr_report_{ts}.{ext}"'
    return content, 200, headers


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
        "Event": events._event_cache_lock,
        "BSOD": bsod._bsod_cache_lock,
        "Startup": _startup_cache_lock,
        "Services": _services_cache_lock,
        "Process": processes._process_cache_lock,
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
    events._load_event_cache()
    bsod._load_bsod_cache()
    _load_startup_cache()

    # Start background lookup worker threads first so the queues are draining
    _worker_thread = threading.Thread(target=events._lookup_worker, daemon=True, name="EventLookupWorker")
    _worker_thread.start()
    _bsod_worker_thread = threading.Thread(target=bsod._bsod_lookup_worker, daemon=True, name="BSODLookupWorker")
    _bsod_worker_thread.start()
    _startup_worker_thread = threading.Thread(target=_startup_lookup_worker, daemon=True, name="StartupLookupWorker")
    _startup_worker_thread.start()
    _load_services_cache()
    processes._load_process_cache()
    _services_worker_thread = threading.Thread(target=_services_lookup_worker, daemon=True, name="ServicesLookupWorker")
    _services_worker_thread.start()
    _process_worker_thread = threading.Thread(
        target=processes._process_lookup_worker, daemon=True, name="ProcessLookupWorker"
    )
    _process_worker_thread.start()

    # Re-queue unknown or aged entries — workers will pick them up immediately
    ev_requeued = _requeue_stale_cache(events._event_cache, events._lookup_queue, events._lookup_in_flight, "Event")
    bsod_requeued = _requeue_stale_cache(bsod._bsod_cache, bsod._bsod_queue, bsod._bsod_in_flight, "BSOD")
    startup_requeued = _requeue_stale_cache(_startup_cache, _startup_queue, _startup_in_flight, "Startup")
    services_requeued = _requeue_stale_cache(_services_cache, _services_queue, _services_in_flight, "Services")
    process_requeued = _requeue_stale_cache(
        processes._process_cache, processes._process_queue, processes._process_in_flight, "Process"
    )

    print(f"[EventCache] Worker started. {len(events._event_cache)} cached, {ev_requeued} re-queued.")
    print(f"[BSODCache]    Worker started. {len(bsod._bsod_cache)} cached, {bsod_requeued} re-queued.")
    print(f"[StartupCache]  Worker started. {len(_startup_cache)} cached, {startup_requeued} re-queued.")
    print(f"[ServicesCache] Worker started. {len(_services_cache)} cached, {services_requeued} re-queued.")
    print(f"[ProcessCache]  Worker started. {len(processes._process_cache)} cached, {process_requeued} re-queued.")

    # Codehealth scanners (backlog #51): fire a background scan on tray
    # boot if the persisted state is missing OR older than STALE_DAYS.
    # The four scanners (coverage / ruff / secrets / tech-debt) take
    # ~3-5 s total against this repo, so it's a fire-and-forget that
    # the user sees populated on the Utilities tab a few seconds after
    # the tray comes up. PR-2 adds a proper cron + configurable cadence.
    if codehealth.maybe_run_on_boot():
        print("[CodeHealth]    Background scan kicked off (state stale or missing).")
    else:
        print("[CodeHealth]    Skipped boot scan (state fresh).")

    # Router config backups are MANUAL (reverted 2026-05-11). The earlier
    # daemon-thread scheduler fired daily failures because neither vendor
    # supports a working unattended-backup path: Orbi RBRE960 returns
    # HTTP 500 on the documented SOAP endpoint, and Verizon CR1000A's
    # admin SPA requires browser interaction. Backups are now triggered
    # from the UI's Backup buttons (open the device admin Save/Restore
    # page in a new tab) and the dashboard surfaces a concern when the
    # newest file is older than the per-vendor staleness threshold.

    print("\n  WinDesktopMgr running at http://localhost:5000\n")
    app.run(debug=False, port=5000, use_reloader=False, threaded=True)


if __name__ == "__main__":
    start_server()
