"""
processes.py — Process & Memory module for WinDesktopMgr.

Owns two cohesive, independent subsystems that both enumerate live
processes via psutil (no PowerShell):

* Processes — the ``PROCESS_KB`` knowledge base, self-learning process
  enrichment (file-version-info -> Microsoft Learn -> cache, drained by a
  background worker), ``SAFE_PROCESSES`` kill-guard + ``SYSTEM_PROCESSES_GLOSSARY``
  (tied by the import-time ``_assert_glossary_in_safe_processes`` invariant),
  CPU-% sampling, ``get_process_list`` / ``kill_process`` / ``summarize_processes``.
* Memory — ``MEM_CATEGORIES`` classification, ``get_memory_analysis`` /
  ``summarize_memory``, and the per-process memory-concern snooze store
  (backlog #19).

Extracted from windesktopmgr.py (backlog #54 PR C, third production-file
extraction after bsod.py and events.py). No behaviour changes: every block
is a verbatim relocation.

``subprocess`` is NOT used here (both subsystems are pure psutil / win32api /
urllib). ``win32api`` is imported for the file-version-info process lookup.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import psutil
import win32api

APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _insight(level: str, text: str, action: str = "") -> dict:
    """Insight dict constructor — local copy of the windesktopmgr helper
    (the disk.py / bsod.py / events.py extraction pattern)."""
    return {"level": level, "text": text, "action": action}


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


def requeue_unknowns(procs: list) -> int:
    """Re-queue processes whose cached enrichment is missing/unknown for a
    fresh background lookup. Backs POST /api/processes/lookup-unknowns.
    Returns the number queued.
    """
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
    return queued


def lookup_status() -> dict:
    """Queue/in-flight counts for the process enrichment worker.
    Backs GET /api/processes/lookup-status.
    """
    return {"queue_pending": _process_queue.qsize(), "in_flight": len(_process_in_flight)}
