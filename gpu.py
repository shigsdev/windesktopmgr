"""gpu.py -- GPU / NVIDIA telemetry + driver-update checking for WinDesktopMgr.

Extracted from windesktopmgr.py (#54, the final extraction that crosses the
<5,000-line target). Owns:
  - get_gpu_metrics()        -- live pynvml GPU telemetry (temp / util / mem / power)
  - get_nvidia_update_info() -- latest NVIDIA driver vs installed (Game-Ready/Studio
                                API + Windows-Update fallback), 10-min cached
  - the NVIDIA API client (_query_nvidia_api, _lookup_nvidia_pfid,
    _detect_nvidia_driver_branch) + _NVIDIA_PFID_MAP product-family table
  - _win_to_nvidia_version, _get_nvidia_gpu_info, _gpu_metrics_blank
  - the update-info cache (_nvidia_update_cache + _nvidia_update_cache_lock)

Mock-target note: GPU-internal helpers call each other via THIS module's
namespace, so tests that stub them to drive get_nvidia_update_info /
get_gpu_metrics must patch ``gpu.<name>`` (e.g. gpu._query_nvidia_api), NOT
windesktopmgr.<name>. The public entry points (get_gpu_metrics,
get_nvidia_update_info, _win_to_nvidia_version, _reset_nvidia_update_cache)
are re-exported back into windesktopmgr so existing windesktopmgr.<name>
callers (dashboard fan-out, run_scan, get_driver_health, /api/nvidia/* routes,
snapshots) keep working.

The two wdm-resident dependencies -- _wmi_conn (WMI video-controller version)
and get_windows_update_drivers (the WU fallback) -- are lazy-imported from
windesktopmgr at call time to break the import cycle.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import winreg
from datetime import datetime, timedelta


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

    # Get Windows driver version from WMI (bounded -- a wedged Winmgmt must not
    # hang the GPU-info path or leak a stuck COM thread).
    def _wmi_work():
        from windesktopmgr import _wmi_conn  # lazy: wdm-resident, breaks import cycle

        c = _wmi_conn()
        for vc in c.Win32_VideoController():
            if vc.Name and "NVIDIA" in vc.Name.upper():
                return {"found": True, "win_ver": vc.DriverVersion or "", "name": vc.Name}
        return {"found": False}

    from windesktopmgr import bounded_wmi_query  # lazy: wdm-resident, breaks import cycle

    vc_info = bounded_wmi_query(_wmi_work, timeout_s=8.0, fallback={"found": False}, label="GPU video controller")
    if vc_info.get("found"):
        win_ver = vc_info["win_ver"]
        if not gpu_name:
            gpu_name = vc_info["name"]

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
            from windesktopmgr import get_windows_update_drivers  # lazy: wdm-resident WU fallback

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
