"""
disk.py — Disk Health module for WinDesktopMgr.

Logical drive enumeration (psutil + ctypes), physical disk health
(``Get-PhysicalDisk``), disk IO counters, the WinDirStat-style path
analyzer, quick-win bloat locations, DISM-backed WinSxS sizing, and
the whitelisted cleanup tool launcher.

Extracted from windesktopmgr.py as the first of three blueprint
extractions planned for backlog #22 (disk → remediation → nlq).
Reduces the 10k-line main file and lets every disk-related test
target a focused module. No behaviour changes.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import time
from ctypes import wintypes

import psutil
from flask import Blueprint, jsonify, request

disk_bp = Blueprint("disk", __name__)


def _insight(level: str, text: str, action: str = "") -> dict:
    """Insight dict constructor — local copy of the windesktopmgr helper.

    summarize_disk() is the only caller in this module. Duplicated here
    to avoid a circular import back into windesktopmgr.
    """
    return {"level": level, "text": text, "action": action}


# ══════════════════════════════════════════════════════════════════════════════
# DISK HEALTH
# ══════════════════════════════════════════════════════════════════════════════


# psutil.disk_partitions() reports drive type via the opts keyword (uses
# GetDriveType() from the Win32 API). Map those keywords to the canonical
# DriveType enum values used by Win32_LogicalDisk so the summarizer and
# frontend see a consistent shape regardless of how we enumerated the drives.
_PSUTIL_DRIVETYPE_MAP = {
    "fixed": (3, "local"),
    "remote": (4, "network"),
    "removable": (2, "removable"),
    "cdrom": (5, "cdrom"),
    "ramdisk": (6, "ramdisk"),
}

# SetErrorMode flag — suppresses the "There is no disk in the drive" system
# dialog when we probe an empty optical drive or unreachable network share.
_SEM_FAILCRITICALERRORS = 0x0001


def _get_unc_path(letter: str) -> str | None:
    """Return the UNC path for a mapped network drive (e.g. ``\\\\nas\\share``).

    Uses ``WNetGetConnectionW`` from ``mpr.dll`` via ctypes — no PowerShell,
    no pywin32 dependency. Returns None for local drives or on any failure.
    """
    try:
        mpr = ctypes.WinDLL("mpr")
        fn = mpr.WNetGetConnectionW
        fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        fn.restype = wintypes.DWORD
        buf_len = wintypes.DWORD(2048)
        buf = ctypes.create_unicode_buffer(buf_len.value)
        rc = fn(f"{letter}:", buf, ctypes.byref(buf_len))
        if rc == 0:  # NO_ERROR
            return buf.value
    except Exception:
        pass
    return None


def _get_volume_label(letter: str) -> str:
    """Return the volume label for a local drive, or empty string.

    Uses ``GetVolumeInformationW`` via ctypes. Wrapped with SetErrorMode so
    unreachable drives fail silently instead of popping a system dialog.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        old_mode = kernel32.SetErrorMode(_SEM_FAILCRITICALERRORS)
        try:
            buf = ctypes.create_unicode_buffer(256)
            ok = kernel32.GetVolumeInformationW(
                f"{letter}:\\",
                buf,
                256,
                None,
                None,
                None,
                None,
                0,
            )
            return buf.value if ok else ""
        finally:
            kernel32.SetErrorMode(old_mode)
    except Exception:
        return ""


def _enumerate_logical_drives() -> list[dict]:
    """Enumerate mounted logical drives using pure Python (psutil + ctypes).

    Replaces the older ``Get-PSDrive`` / ``Win32_LogicalDisk`` PowerShell
    approaches. Benefits per the "Python first, PowerShell secondary" rule:
    no 200-500 ms PS startup cost, trivially mockable in tests, typed error
    handling. CD/DVD and RAM disks are filtered out — they're irrelevant to
    capacity monitoring. Unreachable network drives are still returned (with
    zeroed totals) so the UI can show them with a clear CIFS badge.
    """
    drives: list[dict] = []
    try:
        parts = psutil.disk_partitions(all=True)
    except Exception as e:
        print(f"[Disk enum error] {e}")
        return []
    for p in parts:
        drive_type, type_name = 3, "local"
        opts = p.opts or ""
        for kw, (dt, name) in _PSUTIL_DRIVETYPE_MAP.items():
            if kw in opts:
                drive_type, type_name = dt, name
                break
        # Filter CD/DVD and RAM disks — no capacity relevance, and they also
        # tend to raise OSError on disk_usage when empty.
        if drive_type in (5, 6):
            continue
        letter = (p.device[:1] if p.device else "").upper()
        try:
            u = psutil.disk_usage(p.mountpoint)
            total_gb = round(u.total / (1024**3), 2)
            free_gb = round(u.free / (1024**3), 2)
            used_gb = round(u.used / (1024**3), 2)
            pct_used = round(u.percent, 1)
        except OSError:
            # Unreachable (e.g. NAS offline) — surface the drive with zeros
            total_gb = free_gb = used_gb = 0.0
            pct_used = 0.0
        unc = _get_unc_path(letter) if drive_type == 4 else None
        label = _get_volume_label(letter) if drive_type == 3 else ""
        drives.append(
            {
                "Letter": letter,
                "Label": label,
                "UsedGB": used_gb,
                "FreeGB": free_gb,
                "TotalGB": total_gb,
                "PctUsed": pct_used,
                "DriveType": drive_type,
                "DriveTypeName": type_name,
                "FileSystem": p.fstype or "",
                "UNCPath": unc,
            }
        )
    return drives


def _sample_disk_io() -> list[dict]:
    """Sample per-disk read/write rate using psutil (no PowerShell).

    Replaces the legacy ``Get-Counter "\\PhysicalDisk(*)\\Disk Read Bytes/sec"``
    pipeline (backlog #24 batch A, site #19). ``psutil.disk_io_counters``
    exposes monotonic byte counters — we sample twice ~1 s apart and
    divide the delta to get bytes/sec, then convert to KB/s to match the
    Value semantics the PS pipeline used.

    Output preserves the legacy ``[{Counter, Value}]`` shape so tests and
    the existing ``io`` field contract keep working. Counter paths follow
    the PerfMon-style ``physicaldisk(<name>)\\disk (read|write) bytes/sec``
    string so anything filtering on substrings still matches.
    """
    try:
        first = psutil.disk_io_counters(perdisk=True) or {}
    except Exception:
        return []
    if not first:
        return []
    time.sleep(1.0)
    try:
        second = psutil.disk_io_counters(perdisk=True) or {}
    except Exception:
        return []

    out: list[dict] = []
    for name, s2 in second.items():
        s1 = first.get(name)
        if not s1:
            continue
        # Bytes per second over the ~1 s interval → KB/s for output.
        read_kbs = round(max(0, s2.read_bytes - s1.read_bytes) / 1024, 1)
        write_kbs = round(max(0, s2.write_bytes - s1.write_bytes) / 1024, 1)
        out.append({"Counter": f"\\physicaldisk({name})\\disk read bytes/sec", "Value": read_kbs})
        out.append({"Counter": f"\\physicaldisk({name})\\disk write bytes/sec", "Value": write_kbs})
    return out


def get_disk_health() -> dict:
    """Return drives + physical disks + disk IO for the dashboard.

    Drives come from ``_enumerate_logical_drives()`` (Python/psutil, no PS).
    Physical disks still use ``Get-PhysicalDisk`` because Health, MediaType,
    and BusType are only surfaced by the Windows Storage Management API
    and psutil doesn't wrap it. IO counters use ``psutil.disk_io_counters``
    sampled twice (backlog #24 batch A).
    """
    ps_physical = r"""
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
$physical | ConvertTo-Json -Depth 3
"""
    drives = _enumerate_logical_drives()
    physical: list[dict] = []
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_physical],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = json.loads(r.stdout.strip() or "[]")
        physical = raw if isinstance(raw, list) else [raw]
    except Exception as e:
        print(f"[Disk physical error] {e}")
        physical = []
    try:
        io_data = _sample_disk_io()
    except Exception as e:
        print(f"[Disk IO error] {e}")
        io_data = []
    return {"drives": drives, "physical": physical, "io": io_data}


# ── Disk space analyzer (WinDirStat-style breadth-first) ─────────────────────

# Characters allowed in a Windows path passed to PowerShell. Paths are embedded
# as SINGLE-quoted PS literals (so $name expansion is disabled), and we strip
# everything outside this whitelist. `$` is allowed because system folders like
# `C:\$Recycle.Bin` legitimately contain it; single-quoting defuses expansion.
# Allowed: letters, digits, space, dash, underscore, dot, colon, backslash,
# parentheses (for "Program Files (x86)"), and `$` (for $Recycle.Bin).
_PATH_SAFE_RE = re.compile(r"[^a-zA-Z0-9\-_. :\\()$]")


def _safe_ps_path(path: str) -> str:
    """Sanitise a filesystem path for safe embedding in a PowerShell string.

    Strips control characters, quotes, semicolons, and anything else that
    could break out of the literal. Returns "" for empty / None input.
    """
    if not path:
        return ""
    cleaned = _PATH_SAFE_RE.sub("", str(path)).strip()
    # Collapse runs of backslashes (defensive — not strictly required)
    cleaned = re.sub(r"\\{3,}", r"\\\\", cleaned)
    return cleaned


def _validate_analyze_path(path: str) -> tuple[bool, str]:
    """Validate that `path` is safe to analyse.

    Rules:
    - must be a non-empty absolute Windows path (drive-letter rooted)
    - no UNC paths (``\\\\server\\share``)
    - no device paths (``\\\\?\\``)
    - must exist on disk after sanitisation
    Returns (True, cleaned_path) or (False, error_message).
    """
    if not path or not isinstance(path, str):
        return False, "Missing required field: path"
    cleaned = _safe_ps_path(path)
    if not cleaned:
        return False, "Invalid path"
    # Reject UNC / device namespace before the slashes get stripped by sanitiser
    if path.startswith(("\\\\", "//")):
        return False, "UNC paths are not supported"
    # Must start with drive letter followed by colon+backslash (e.g. C:\)
    if len(cleaned) < 3 or cleaned[1] != ":" or cleaned[2] != "\\":
        return False, "Path must be an absolute drive-letter path (e.g. C:\\Users)"
    if not os.path.isdir(cleaned):
        return False, f"Path does not exist or is not a directory: {cleaned}"
    return True, cleaned


def _human_bytes(n: int | float) -> str:
    """Human-readable byte size (binary units)."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} EB"


def _walk_dir_size(dir_path: str) -> dict:
    """Recursively sum local + cloud bytes for a directory using os.scandir().

    Uses the same Win32 API (FindFirstFileW) as robocopy but with zero
    subprocess overhead.

    Cloud placeholder detection uses three Windows file attribute flags:
      - ``FILE_ATTRIBUTE_OFFLINE``             (0x1000) — classic offline flag
      - ``FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`` (0x400000) — modern cloud
        placeholder (iCloud, OneDrive Files On-Demand, Dropbox Smart Sync)
      - ``FILE_ATTRIBUTE_RECALL_ON_OPEN``      (0x100000) — content fetched on open

    Any file matching these is counted as cloud-only; its st_size (the
    *logical* size visible in Explorer) goes into cloud_bytes, not local.

    Returns ``{"local": int, "cloud": int, "count": int}``.
    """
    import stat as _stat  # noqa: I001

    _OFFLINE = _stat.FILE_ATTRIBUTE_OFFLINE  # 0x1000
    _RECALL_DATA = 0x00400000  # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    _RECALL_OPEN = 0x00100000  # FILE_ATTRIBUTE_RECALL_ON_OPEN
    _CLOUD_MASK = _OFFLINE | _RECALL_DATA | _RECALL_OPEN
    local = 0
    cloud = 0
    count = 0
    stack = [dir_path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            # Skip junction points (like robocopy /XJ)
                            if not entry.is_junction():
                                stack.append(entry.path)
                        else:
                            st = entry.stat(follow_symlinks=False)
                            count += 1
                            if hasattr(st, "st_file_attributes") and st.st_file_attributes & _CLOUD_MASK:
                                cloud += st.st_size
                            else:
                                local += st.st_size
                    except OSError:
                        pass  # permission denied, etc — skip silently
        except OSError:
            pass  # can't open dir — skip
    return {"local": local, "cloud": cloud, "count": count}


def analyze_disk_path(path: str, top_n: int = 25) -> dict:
    """Return the top `top_n` largest immediate children of `path` by total size.

    Pure Python implementation using ``os.scandir()`` for recursive sizing
    with ``concurrent.futures.ThreadPoolExecutor`` for parallelism across
    subdirectories.  No subprocess, no PowerShell, no robocopy.

    Cloud detection: checks ``FILE_ATTRIBUTE_OFFLINE`` (0x1000),
    ``RECALL_ON_DATA_ACCESS`` (0x400000), and ``RECALL_ON_OPEN`` (0x100000).
    iCloud, OneDrive Files On-Demand, and Dropbox Smart Sync use these
    attributes on cloud-only placeholders.  Downloaded files are counted
    as local; cloud-only stubs as cloud.

    Returns a dict like::

        {
            "ok": True,
            "path": "C:\\\\",
            "parent": None,              # or parent dir string
            "total_bytes": 123456789,
            "entries": [
                {"name": "Users", "path": "C:\\\\Users", "type": "dir",
                 "size_bytes": 40000000000, "size_human": "37.3 GB", "pct": 45.2,
                 "item_count": 12345, "error": False},
                ...
            ],
        }

    On any failure, returns ``{"ok": False, "error": str, "path": path, "entries": []}``.
    """
    import stat as _stat  # noqa: I001
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ok, cleaned = _validate_analyze_path(path)
    if not ok:
        return {"ok": False, "error": cleaned, "path": path, "entries": []}

    _OFFLINE = _stat.FILE_ATTRIBUTE_OFFLINE  # 0x1000
    _RECALL_DATA = 0x00400000  # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    _RECALL_OPEN = 0x00100000  # FILE_ATTRIBUTE_RECALL_ON_OPEN
    _CLOUD_MASK = _OFFLINE | _RECALL_DATA | _RECALL_OPEN

    # ── List immediate children ──────────────────────────────────────────
    try:
        children = list(os.scandir(cleaned))
    except OSError as exc:
        return {"ok": False, "error": str(exc), "path": cleaned, "entries": []}

    raw_entries: list[dict] = []
    dir_entries: list[tuple[int, os.DirEntry]] = []  # (index, entry) for dirs

    for child in children:
        try:
            if child.is_dir(follow_symlinks=False):
                if child.is_junction():
                    continue  # skip junctions (like robocopy /XJ)
                idx = len(raw_entries)
                raw_entries.append(
                    {
                        "name": child.name,
                        "path": child.path,
                        "type": "dir",
                        "local": 0,
                        "cloud": 0,
                        "count": 0,
                    }
                )
                dir_entries.append((idx, child))
            else:
                st = child.stat(follow_symlinks=False)
                is_offline = hasattr(st, "st_file_attributes") and st.st_file_attributes & _CLOUD_MASK
                raw_entries.append(
                    {
                        "name": child.name,
                        "path": child.path,
                        "type": "file",
                        "local": 0 if is_offline else st.st_size,
                        "cloud": st.st_size if is_offline else 0,
                        "count": 1,
                    }
                )
        except OSError:
            pass  # skip inaccessible entries

    # ── Parallel recursive sizing of subdirectories ──────────────────────
    if dir_entries:
        max_workers = min(8, len(dir_entries))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_idx = {pool.submit(_walk_dir_size, entry.path): idx for idx, entry in dir_entries}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result = future.result(timeout=600)
                    raw_entries[idx]["local"] = result["local"]
                    raw_entries[idx]["cloud"] = result["cloud"]
                    raw_entries[idx]["count"] = result["count"]
                except Exception:  # noqa: BLE001
                    pass  # leave zeros — graceful fallback

    # ── Sort by local bytes descending, take top_n ───────────────────────
    raw_entries.sort(key=lambda e: e["local"], reverse=True)
    raw_entries = raw_entries[:top_n]

    # ── Build response ───────────────────────────────────────────────────
    entries: list[dict] = []
    total = 0
    total_cloud = 0
    for row in raw_entries:
        size = row["local"]
        cloud_val = row["cloud"]
        total += size
        total_cloud += cloud_val
        entries.append(
            {
                "name": row["name"],
                "path": row["path"],
                "type": row["type"],
                "size_bytes": size,
                "size_human": _human_bytes(size),
                "cloud_bytes": cloud_val,
                "cloud_human": _human_bytes(cloud_val) if cloud_val > 0 else "",
                "item_count": row["count"],
            }
        )

    for e in entries:
        e["pct"] = round(e["size_bytes"] / total * 100, 1) if total > 0 else 0.0

    # Parent = one dir up, unless we're at a drive root like C:\
    cleaned_rstrip = cleaned.rstrip("\\")
    parent: str | None
    if len(cleaned_rstrip) <= 2:  # "C:" — already at drive root
        parent = None
    else:
        parent = os.path.dirname(cleaned_rstrip) or None
        if parent and len(parent) == 2 and parent[1] == ":":
            parent = parent + "\\"

    return {
        "ok": True,
        "path": cleaned,
        "parent": parent,
        "total_bytes": total,
        "total_cloud_bytes": total_cloud,
        "total_cloud_human": _human_bytes(total_cloud) if total_cloud > 0 else "",
        "entries": entries,
    }


# ── Cleanup tool allowlist ────────────────────────────────────────────────
# Maps a short key to a concrete argv. Only keys in this dict can be launched
# via /api/disk/run-tool — prevents arbitrary-command execution from the
# frontend. Paths are absolute where possible and use only well-known
# Windows system binaries.
#
# For third-party tools (PatchCleaner), the argv may contain placeholders
# that get resolved at launch time against a list of candidate install paths.
# If none exist, the launch returns an error with a download URL so the
# frontend can show the user how to install it.
_CLEANUP_TOOLS: dict[str, dict] = {
    "cleanmgr": {
        "label": "Disk Cleanup",
        "argv": ["cleanmgr.exe", "/d", "C"],
        "description": "Launches Windows Disk Cleanup on the system drive.",
    },
    "cleanmgr_sageset": {
        "label": "Disk Cleanup (extended)",
        "argv": ["cleanmgr.exe", "/sageset:99"],
        "description": "Configures extended Disk Cleanup categories.",
    },
    "sysdm_advanced": {
        "label": "System Properties → Advanced",
        "argv": ["SystemPropertiesAdvanced.exe"],
        "description": "Opens Advanced System Properties (for pagefile config).",
    },
    "storage_settings": {
        "label": "Storage Settings",
        "argv": ["explorer.exe", "ms-settings:storagesense"],
        "description": "Opens Windows Storage Settings / Storage Sense.",
    },
    "patchcleaner": {
        "label": "PatchCleaner",
        # Third-party — resolved at launch against known install paths.
        "candidate_paths": [
            r"C:\Program Files\homedev\PatchCleaner\PatchCleaner.exe",
            r"C:\Program Files (x86)\homedev\PatchCleaner\PatchCleaner.exe",
        ],
        "install_url": "https://www.homedev.com.au/Free/PatchCleaner",
        "description": (
            "Scans C:\\Windows\\Installer for orphaned MSI/MSP patches "
            "(programs already uninstalled) that are safe to remove."
        ),
    },
}


# Fixed set of well-known bloat locations, relative to a drive letter.
# Each entry is a dict with:
#   key, label, rel_path, description,
#   action_kind: "open_folder" | "run_tool" | "info_only"
#   tool:  (run_tool only) key into _CLEANUP_TOOLS
#   cli:   (info_only only) exact command to display/copy
_QUICKWIN_LOCATIONS: list[dict] = [
    {
        "key": "recycle_bin",
        "label": "Recycle Bin",
        "rel": r"$Recycle.Bin",
        "description": "Deleted files still consuming space. Empty from the desktop Recycle Bin.",
        "action_kind": "open_folder",
    },
    {
        "key": "windows_old",
        "label": "Windows.old",
        "rel": r"Windows.old",
        "description": "Previous Windows install left after an upgrade. Remove via Disk Cleanup → Previous Windows installation(s).",
        "action_kind": "run_tool",
        "tool": "cleanmgr",
    },
    {
        "key": "windows_temp",
        "label": "Windows Temp",
        "rel": r"Windows\Temp",
        "description": "System temporary files. Launch Disk Cleanup to remove safely.",
        "action_kind": "run_tool",
        "tool": "cleanmgr",
    },
    {
        "key": "windows_update_cache",
        "label": "Windows Update cache",
        "rel": r"Windows\SoftwareDistribution\Download",
        "description": "Downloaded Windows Update payloads. Disk Cleanup clears these safely.",
        "action_kind": "run_tool",
        "tool": "cleanmgr",
    },
    {
        "key": "windows_installer",
        "label": "Windows Installer cache",
        "rel": r"Windows\Installer",
        "description": (
            "MSI patch cache. Regular Disk Cleanup does NOT touch this folder — "
            "use PatchCleaner to find orphaned patches."
        ),
        "action_kind": "run_tool",
        "tool": "patchcleaner",
        "extra_tools": ["cleanmgr"],
    },
    {
        "key": "winsxs",
        "label": "WinSxS (component store)",
        "rel": r"Windows\WinSxS",
        "description": "Windows component store. Do NOT delete. Run the DISM cleanup command as Administrator.",
        "action_kind": "info_only",
        "cli": "Dism.exe /Online /Cleanup-Image /StartComponentCleanup",
    },
    {
        "key": "hiberfil",
        "label": "Hibernation file (hiberfil.sys)",
        "rel": r"hiberfil.sys",
        "description": "Hibernation image, sized ~40% of RAM. Disable hibernation to reclaim.",
        "action_kind": "info_only",
        "cli": "powercfg /hibernate off",
    },
    {
        "key": "pagefile",
        "label": "Page file (pagefile.sys)",
        "rel": r"pagefile.sys",
        "description": "Virtual memory swap file. Configure via System Properties → Advanced → Performance → Virtual memory.",
        "action_kind": "run_tool",
        "tool": "sysdm_advanced",
    },
]


def get_disk_quickwins(drive: str) -> dict:
    """Find well-known bloat locations on a given drive and report their sizes.

    `drive` should be a single letter ('C') or 'C:' or 'C:\\'. Returns::

        {
            "ok": True,
            "drive": "C:\\\\",
            "locations": [
                {"key": "recycle_bin", "label": "Recycle Bin",
                 "path": "C:\\\\$Recycle.Bin", "exists": True,
                 "size_bytes": 1234567, "size_human": "1.2 MB",
                 "description": "...", "action": "open_recycle_bin"},
                ...
            ],
            "user_locations": [
                {"key": "downloads", "label": "Downloads", ...},
                ...
            ],
        }
    """
    if not drive or not isinstance(drive, str):
        return {"ok": False, "error": "Missing required field: drive", "locations": []}
    letter = drive.strip().rstrip(":\\").upper()
    if len(letter) != 1 or not letter.isalpha():
        return {"ok": False, "error": "Drive must be a single letter (A–Z)", "locations": []}
    drive_root = f"{letter}:\\"
    if not os.path.isdir(drive_root):
        return {"ok": False, "error": f"Drive {drive_root} not found", "locations": []}

    # Build the candidate path list (with full path joined in)
    candidates: list[dict] = []
    for entry in _QUICKWIN_LOCATIONS:
        c = dict(entry)
        c["path"] = os.path.join(drive_root, entry["rel"])
        candidates.append(c)

    # User-profile locations (Downloads, AppData caches) only make sense on the
    # OS drive, so we only add them if `drive` matches the profile drive.
    user_candidates: list[dict] = []
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile and userprofile[0].upper() == letter:
        user_candidates = [
            {
                "key": "downloads",
                "label": "Downloads folder",
                "path": os.path.join(userprofile, "Downloads"),
                "description": "Personal downloads. Review and delete old installers / archives.",
                "action_kind": "open_folder",
            },
            {
                "key": "user_temp",
                "label": "User Temp (%TEMP%)",
                "path": os.path.join(userprofile, "AppData", "Local", "Temp"),
                "description": "Per-user temp files. Disk Cleanup removes these safely.",
                "action_kind": "run_tool",
                "tool": "cleanmgr",
            },
            {
                "key": "chrome_cache",
                "label": "Chrome cache",
                "path": os.path.join(
                    userprofile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"
                ),
                "description": "Chrome browser cache. Clearable via Chrome settings.",
                "action_kind": "open_folder",
            },
            {
                "key": "edge_cache",
                "label": "Edge cache",
                "path": os.path.join(
                    userprofile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"
                ),
                "description": "Edge browser cache. Clearable via Edge settings.",
                "action_kind": "open_folder",
            },
        ]

    all_rows = candidates + user_candidates
    # Build one PS script that sizes every candidate in parallel-ish (foreach).
    # Paths are embedded as SINGLE-quoted literals so that `$Recycle.Bin` and
    # similar dollar-containing names aren't interpreted as variable expansions.
    ps_paths = "\n".join(f"'{_safe_ps_path(c['path'])}'" for c in all_rows)
    ps = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
{ps_paths}
)
$out = @()
foreach ($p in $paths) {{
    if (Test-Path -LiteralPath $p) {{
        $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if ($item -and $item.PSIsContainer) {{
            # Fast native walk via robocopy /L /BYTES /XA:O — ~10x faster than
            # Get-ChildItem -Recurse for large trees like WinSxS.
            # /XA:O excludes cloud placeholders; real local bytes =
            # Total - Skipped (see analyze_disk_path for full explanation).
            $bytes = [int64]0
            $rc = robocopy $p NULL /L /E /NFL /NDL /NJH /NC /BYTES /XA:O /XJ /R:0 /W:0 2>$null
            foreach ($line in $rc) {{
                if ($line -match '^\s*Bytes\s*:\s*(\d+)\s+(\d+)\s+(\d+)') {{
                    $total   = [int64]$matches[1]
                    $skipped = [int64]$matches[3]
                    $bytes = $total - $skipped
                    if ($bytes -lt 0) {{ $bytes = [int64]0 }}
                }}
            }}
        }} elseif ($item) {{
            # Skip Offline (cloud-only) files in quickwins too
            $isOffline = ($item.Attributes -band [IO.FileAttributes]::Offline) -ne 0
            if ($isOffline) {{ $bytes = [int64]0 }} else {{ $bytes = [int64]$item.Length }}
        }} else {{
            $bytes = [int64]0
        }}
        $exists = $true
    }} else {{
        $bytes = [int64]0
        $exists = $false
    }}
    $out += [PSCustomObject]@{{ Path = $p; Exists = $exists; Bytes = $bytes }}
}}
$out | ConvertTo-Json -Depth 2
exit 0
"""
    size_by_path: dict[str, tuple[bool, int]] = {}
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw = (r.stdout or "").strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for row in parsed:
                if not isinstance(row, dict):
                    continue
                p = row.get("Path") or ""
                size_by_path[p] = (
                    bool(row.get("Exists")),
                    int(row.get("Bytes") or 0),
                )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Quick-wins scan timed out", "locations": []}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Failed to parse quick-wins output", "locations": []}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "locations": []}

    def _row(c: dict) -> dict:
        path = c["path"]
        exists, size = size_by_path.get(path, (False, 0))
        action_kind = c.get("action_kind", "open_folder")
        row = {
            "key": c["key"],
            "label": c["label"],
            "path": path,
            "exists": exists,
            "size_bytes": size,
            "size_human": _human_bytes(size),
            "description": c["description"],
            "action_kind": action_kind,
        }
        if action_kind == "run_tool":
            tool_key = c.get("tool", "")
            row["tool"] = tool_key
            tool_spec = _CLEANUP_TOOLS.get(tool_key)
            if tool_spec:
                row["tool_label"] = tool_spec["label"]
        elif action_kind == "info_only":
            row["cli"] = c.get("cli", "")
        # Optional secondary tool buttons (e.g. Windows Installer offers both
        # PatchCleaner (primary) and Disk Cleanup (secondary))
        extras = c.get("extra_tools") or []
        if extras:
            row["extra_tools"] = [
                {"tool": k, "label": _CLEANUP_TOOLS[k]["label"]} for k in extras if k in _CLEANUP_TOOLS
            ]
        return row

    locations = [_row(c) for c in candidates]
    user_locations = [_row(c) for c in user_candidates]

    # WinSxS is a special case: it is mostly hardlinks to files in
    # C:\Windows, so robocopy reports 2-4x the real on-disk footprint.
    # Microsoft provides the authoritative number via
    # `Dism /Online /Cleanup-Image /AnalyzeComponentStore`.
    # Override the winsxs row with the DISM numbers if it's on the OS drive.
    if userprofile and userprofile[0].upper() == letter:
        dism_info = _get_winsxs_actual_size()
        if dism_info:
            for loc in locations:
                if loc["key"] == "winsxs":
                    loc["size_bytes"] = dism_info["actual_bytes"]
                    loc["size_human"] = _human_bytes(dism_info["actual_bytes"])
                    loc["reported_bytes"] = dism_info["reported_bytes"]
                    loc["reported_human"] = _human_bytes(dism_info["reported_bytes"])
                    loc["cleanup_recommended"] = dism_info["cleanup_recommended"]
                    note_extra = (
                        " Cleanup recommended by DISM."
                        if dism_info["cleanup_recommended"]
                        else " DISM reports no cleanup needed."
                    )
                    loc["description"] = (
                        f"Windows component store. Mostly hardlinks to C:\\Windows — "
                        f"real footprint {loc['size_human']} (explorer reports "
                        f"{loc['reported_human']}).{note_extra}"
                    )
                    break

    # Sort each list by size descending so biggest hits float to the top
    locations.sort(key=lambda x: x["size_bytes"], reverse=True)
    user_locations.sort(key=lambda x: x["size_bytes"], reverse=True)
    return {
        "ok": True,
        "drive": drive_root,
        "locations": locations,
        "user_locations": user_locations,
    }


# Cache the last DISM result — analyzing the component store takes 15-60s
# and the number barely changes. Refresh at most once per hour.
_winsxs_cache: dict = {"ts": 0.0, "data": None}
_WINSXS_CACHE_TTL_SEC = 3600


def _get_winsxs_actual_size() -> dict | None:
    """Run DISM /AnalyzeComponentStore and return actual WinSxS footprint.

    Returns a dict like::

        {
            "actual_bytes":        5_234_567_890,   # real on-disk footprint
            "reported_bytes":     10_600_000_000,   # what explorer shows
            "shared_bytes":        4_100_000_000,   # hardlinked to Windows
            "cleanup_recommended": False,
        }

    or ``None`` if DISM isn't available, times out, or output can't be parsed.
    Cached in-process for one hour (`_WINSXS_CACHE_TTL_SEC`) because DISM
    /AnalyzeComponentStore is slow (15-60s) and the real number changes only
    after Windows Update events.
    """
    now = time.time()
    if _winsxs_cache["data"] and (now - _winsxs_cache["ts"]) < _WINSXS_CACHE_TTL_SEC:
        return _winsxs_cache["data"]
    try:
        r = subprocess.run(
            ["Dism.exe", "/Online", "/Cleanup-Image", "/AnalyzeComponentStore", "/English"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    raw = r.stdout or ""
    if not raw:
        return None

    # DISM prints sizes as "5.23 GB" / "812.45 MB" / "123 KB".
    # Parse all three size lines and the "Cleanup Recommended" flag.
    def _parse_size(label: str) -> int | None:
        import re as _re

        m = _re.search(rf"{label}\s*:\s*([\d.]+)\s*(KB|MB|GB|TB)\b", raw, _re.IGNORECASE)
        if not m:
            return None
        n = float(m.group(1))
        unit = m.group(2).upper()
        mult = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}[unit]
        return int(n * mult)

    reported = _parse_size(r"Windows Explorer Reported Size of Component Store")
    actual = _parse_size(r"Actual Size of Component Store")
    shared = _parse_size(r"Shared with Windows") or 0
    if actual is None or reported is None:
        return None
    cleanup_rec = False
    import re as _re

    m = _re.search(r"Component Store Cleanup Recommended\s*:\s*(\w+)", raw, _re.IGNORECASE)
    if m:
        cleanup_rec = m.group(1).strip().lower() == "yes"

    data = {
        "actual_bytes": actual,
        "reported_bytes": reported,
        "shared_bytes": shared,
        "cleanup_recommended": cleanup_rec,
    }
    _winsxs_cache["ts"] = now
    _winsxs_cache["data"] = data
    return data


def open_folder_in_explorer(path: str) -> dict:
    """Launch explorer.exe pointing at `path`. Path must exist.

    Returns {"ok": True, "path": path} or {"ok": False, "error": ...}.
    """
    ok, cleaned = _validate_analyze_path(path)
    if not ok:
        # Also allow files (not just directories) — re-check as a file
        if path and isinstance(path, str):
            tentative = _safe_ps_path(path)
            if tentative and os.path.isfile(tentative):
                cleaned = tentative
                ok = True
        if not ok:
            return {"ok": False, "error": cleaned}
    try:
        subprocess.Popen(["explorer.exe", cleaned])  # noqa: S603
        return {"ok": True, "path": cleaned}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def launch_cleanup_tool(tool_key: str) -> dict:
    """Launch a whitelisted cleanup tool by key.

    Only keys present in ``_CLEANUP_TOOLS`` are allowed — this prevents the
    frontend from invoking arbitrary commands.

    Tools with a ``candidate_paths`` list (e.g. third-party PatchCleaner) are
    resolved by checking each path in order; the first one that exists wins.
    If none exist, the result includes ``install_url`` so the frontend can
    prompt the user to install the tool.

    Returns::

        {"ok": True, "tool": "cleanmgr", "label": "Disk Cleanup"}

    or::

        {"ok": False, "error": "...", "install_url": "..." (optional)}
    """
    if not tool_key or not isinstance(tool_key, str):
        return {"ok": False, "error": "Missing required field: tool"}
    spec = _CLEANUP_TOOLS.get(tool_key)
    if not spec:
        return {"ok": False, "error": f"Unknown cleanup tool: {tool_key}"}

    # Resolve argv — either a fixed `argv` list (system tools) or
    # a `candidate_paths` search (third-party tools).
    argv: list[str]
    if "candidate_paths" in spec:
        resolved = None
        for candidate in spec["candidate_paths"]:
            if os.path.isfile(candidate):
                resolved = candidate
                break
        if not resolved:
            return {
                "ok": False,
                "error": f"{spec['label']} is not installed",
                "install_url": spec.get("install_url", ""),
                "tool": tool_key,
            }
        argv = [resolved]
    else:
        argv = list(spec["argv"])

    try:
        subprocess.Popen(argv)  # noqa: S603
        return {
            "ok": True,
            "tool": tool_key,
            "label": spec["label"],
            "argv": argv,
        }
    except FileNotFoundError:
        return {"ok": False, "error": f"Tool not found on PATH: {argv[0]}"}
    except OSError as e:
        # WinError 740 = ERROR_ELEVATION_REQUIRED. The target executable has
        # `requireAdministrator` in its manifest (PatchCleaner does). Retry
        # via os.startfile(), which uses ShellExecute under the hood and
        # correctly triggers the Windows UAC prompt.
        if getattr(e, "winerror", None) == 740 and len(argv) == 1:
            try:
                os.startfile(argv[0])  # noqa: S606
                return {
                    "ok": True,
                    "tool": tool_key,
                    "label": spec["label"],
                    "argv": argv,
                    "elevated": True,
                }
            except Exception as e2:  # noqa: BLE001
                return {"ok": False, "error": f"Elevation failed: {e2}"}
        return {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARIZER
# ══════════════════════════════════════════════════════════════════════════════


def summarize_disk(data: dict) -> dict:
    drives = data.get("drives", [])
    physical = data.get("physical", [])
    insights = []
    actions = []
    # Split drives by type so network shares can't trigger a false "local disk
    # full" critical. Default missing DriveType to 3 (local) for backward
    # compat with any cached payloads written before this field was added.
    local_drives = [d for d in drives if int(d.get("DriveType") or 3) == 3]
    network_drives = [d for d in drives if int(d.get("DriveType") or 3) == 4]
    # Local drives: critical >=90%, warning 75-89% (unchanged)
    local_critical = [d for d in local_drives if (d.get("PctUsed") or 0) >= 90]
    local_warning = [d for d in local_drives if 75 <= (d.get("PctUsed") or 0) < 90]
    # Network drives: warning at both thresholds — never critical. A NAS being
    # full is a real problem we want to surface, but it won't crash this
    # machine, so it shouldn't push the overall dashboard into "critical".
    net_full = [d for d in network_drives if (d.get("PctUsed") or 0) >= 90]
    net_warn = [d for d in network_drives if 75 <= (d.get("PctUsed") or 0) < 90]
    unhealthy = [p for p in physical if p.get("Health", "").lower() not in ("healthy", "")]
    if unhealthy:
        insights.append(
            _insight(
                "critical",
                f"{len(unhealthy)} physical disk(s) reporting unhealthy status: "
                + ", ".join(p.get("Name", "?") for p in unhealthy),
                "Back up data immediately and investigate disk health. Consider replacement.",
            )
        )
        actions.append("Back up data immediately")
    if local_critical:
        for d in local_critical:
            insights.append(
                _insight(
                    "critical",
                    f"Drive {d.get('Letter', '?')}: is {d.get('PctUsed', 0)}% full ({d.get('FreeGB', 0)} GB free).",
                    "Free up space or expand storage to avoid system instability.",
                )
            )
        actions.append("Free up disk space")
    if local_warning:
        for d in local_warning:
            insights.append(
                _insight(
                    "warning", f"Drive {d.get('Letter', '?')}: is {d.get('PctUsed', 0)}% full — approaching capacity."
                )
            )

    def _net_suffix(drive: dict) -> str:
        unc = drive.get("UNCPath") or ""
        return f" ({unc})" if unc else ""

    if net_full:
        for d in net_full:
            insights.append(
                _insight(
                    "warning",
                    f"Network share {d.get('Letter', '?')}:{_net_suffix(d)} is {d.get('PctUsed', 0)}% full — "
                    "remote NAS storage, not this machine's local disk.",
                    "Free up space on the remote share or expand NAS capacity.",
                )
            )
    if net_warn:
        for d in net_warn:
            insights.append(
                _insight(
                    "warning",
                    f"Network share {d.get('Letter', '?')}:{_net_suffix(d)} is {d.get('PctUsed', 0)}% full — "
                    "approaching capacity.",
                )
            )
    if not unhealthy and not local_critical and not local_warning and not net_full and not net_warn:
        insights.append(
            _insight(
                "ok",
                f"All {len(local_drives)} local disk(s) healthy"
                + (f" · {len(network_drives)} network share(s) mapped" if network_drives else "")
                + ". "
                + (
                    f"Largest drive is {max((p.get('SizeGB', 0) for p in physical), default=0)} GB." if physical else ""
                ),
            )
        )
    for p in physical:
        if p.get("MediaType", "").lower() == "hdd":
            insights.append(
                _insight(
                    "info",
                    f"{p.get('Name', 'HDD')} is a spinning hard drive — consider upgrading to SSD for better performance.",
                )
            )
    status = (
        "critical" if unhealthy or local_critical else "warning" if (local_warning or net_full or net_warn) else "ok"
    )
    headline = (
        f"{len(unhealthy)} unhealthy disk(s) — action required"
        if unhealthy
        else f"{len(local_critical)} drive(s) critically full"
        if local_critical
        else "All drives healthy"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════


@disk_bp.route("/api/disk/data")
def disk_data_route():
    return jsonify(get_disk_health())


@disk_bp.route("/api/disk/analyze", methods=["POST"])
def disk_analyze_route():
    """Analyze a path on disk — returns top N largest immediate children."""
    data = request.get_json() or {}
    path = data.get("path")
    if not path:
        return jsonify({"ok": False, "error": "Missing required field: path"}), 400
    try:
        top_n = int(data.get("top_n") or 25)
    except (TypeError, ValueError):
        top_n = 25
    top_n = max(5, min(top_n, 200))  # clamp
    result = analyze_disk_path(path, top_n=top_n)
    status = 200 if result.get("ok") else 422
    return jsonify(result), status


@disk_bp.route("/api/disk/quickwins")
def disk_quickwins_route():
    """Return well-known bloat locations (Recycle Bin, Temp, Downloads, ...)."""
    drive = request.args.get("drive", "C")
    result = get_disk_quickwins(drive)
    status = 200 if result.get("ok") else 422
    return jsonify(result), status


@disk_bp.route("/api/disk/open", methods=["POST"])
def disk_open_route():
    """Open a folder or file in Windows Explorer."""
    data = request.get_json() or {}
    path = data.get("path")
    if not path:
        return jsonify({"ok": False, "error": "Missing required field: path"}), 400
    result = open_folder_in_explorer(path)
    status = 200 if result.get("ok") else 422
    return jsonify(result), status


@disk_bp.route("/api/disk/run-tool", methods=["POST"])
def disk_run_tool_route():
    """Launch a whitelisted cleanup tool (e.g., cleanmgr, sysdm_advanced)."""
    data = request.get_json() or {}
    tool = data.get("tool")
    if not tool:
        return jsonify({"ok": False, "error": "Missing required field: tool"}), 400
    result = launch_cleanup_tool(tool)
    status = 200 if result.get("ok") else 422
    return jsonify(result), status
