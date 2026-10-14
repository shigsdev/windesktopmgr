"""Storage & drives evidence for the Diagnose engine (spec 2026-10-13).

Read-only probes over this PC's drives, Storage Spaces pool, disk-error logs,
free space, live IO and the NAS, registered into ``diagnose_probes.PROBES``
alongside the network and crash bundles. Python first (CLAUDE.md): WMI,
ctypes and psutil in-process; the only PowerShell is the existing, tested
``disk.get_storage_spaces()`` reader and the ``disk.get_disk_health()``
fallback.

Privacy (spec §7): drives carry only the last 4 characters of their label
serial, never a full serial, and the NAS never appears by name or address.
Nothing here writes to a disk.
"""

from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timezone

import psutil

import diagnose_crash_probes as dcp
import diagnose_probes as dp
import disk
import lhm
import nas

_REDACT = ("username", "serial", "mac", "self_host", "nas_name")
MAX_DRIVES = 12
_CACHE_S = 30.0

REGISTERED: dict[str, dp.Probe] = {}


def _storage_probe(key: str, label: str, fn, timeout_s: float = 10.0, **kw) -> dp.Probe:
    probe = dp.register(dp.Probe(key, label, "storage", fn, redact=_REDACT, timeout_s=timeout_s, **kw))
    REGISTERED[key] = probe
    return probe


_DRIVE_RE = re.compile(r"^\s*([A-Za-z])\s*(?::\\?|\s+drive)?\s*$", re.IGNORECASE)


def norm_drive(raw: object) -> str | None:
    """``"e"``, ``"E:"``, ``"e:\\"``, ``"E drive"`` -> ``"E:"``; anything else None."""
    if not isinstance(raw, str):
        return None
    match = _DRIVE_RE.match(raw)
    return f"{match.group(1).upper()}:" if match else None


# ── physical disks ────────────────────────────────────────────────────────

_HEALTH = {0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
_OPERATIONAL = {
    2: "OK",
    3: "Degraded",
    5: "Predictive Failure",
    6: "Error",
    7: "Non-Recoverable Error",
    12: "No Contact",
    13: "Lost Communication",
}
_BUS = {7: "USB", 8: "RAID", 10: "SAS", 11: "SATA", 17: "NVMe"}
_MEDIA = {3: "HDD", 4: "SSD", 5: "SCM"}
_WMI_FIELDS = (
    "DeviceId",
    "FriendlyName",
    "MediaType",
    "BusType",
    "HealthStatus",
    "OperationalStatus",
    "SerialNumber",
    "AdapterSerialNumber",
    "PhysicalLocation",
    "Size",
)

_cache: tuple[float, dict] | None = None


def _reset_cache() -> None:
    global _cache
    _cache = None


def _code(table: dict[int, str], value: object) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value or "")
    return table.get(number, f"Code {number}")


def _int(value: object, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _slot(location: str, bus: str) -> str:
    info = disk.describe_disk_location(location or "", bus or "")
    return info.get("slot") or info.get("raw") or ""


def _query_msft_physical_disk() -> list[dict]:
    # Its own frame, so every COM object is released on return -- before the
    # caller's CoUninitialize (releasing after it logs "Win32 exception").
    import wmi

    conn = wmi.WMI(namespace=r"root\Microsoft\Windows\Storage")
    return [{f: getattr(d, f, None) for f in _WMI_FIELDS} for d in conn.MSFT_PhysicalDisk()]


def _wmi_physical_disks() -> list[dict]:
    """MSFT_PhysicalDisk rows as plain dicts. COM is initialised on the calling
    (probe worker) thread and released only if this call initialised it (#181)."""
    pythoncom = None
    coinit_ok = False
    try:
        import pythoncom

        pythoncom.CoInitialize()
        coinit_ok = True
    except Exception:  # noqa: BLE001 -- pywin32 absent / CoInitialize faulted; the query may still work
        pass
    try:
        return _query_msft_physical_disk()
    finally:
        if coinit_ok and pythoncom is not None:
            pythoncom.CoUninitialize()


def _label_tail(adapter_serial: object) -> str:
    """Last 4 of the serial PRINTED ON THE LABEL, or "" when there is none.
    Never the NVMe SerialNumber: that EUI-64 appears nowhere on the drive and
    is how the wrong drive got pulled on 2026-10-08."""
    return disk._short_serial(disk._label_serial(str(adapter_serial or "")))


def _from_wmi(row: dict) -> dict:
    bus = _code(_BUS, row.get("BusType"))
    return {
        "disk_number": _int(row.get("DeviceId")),
        "model": str(row.get("FriendlyName") or "").strip(),
        "media": _code(_MEDIA, row.get("MediaType")),
        "bus": bus,
        "size_gb": round((_int(row.get("Size"), 0)) / 1024**3, 1),
        "health": _code(_HEALTH, row.get("HealthStatus")),
        "operational": [_code(_OPERATIONAL, c) for c in (row.get("OperationalStatus") or [])],
        "label_serial_tail": _label_tail(row.get("AdapterSerialNumber")),
        "slot": _slot(str(row.get("PhysicalLocation") or ""), bus),
    }


def _from_powershell(row: dict) -> dict:
    bus = str(row.get("BusType") or "")
    status = str(row.get("Status") or "")
    return {
        "disk_number": _int(row.get("DeviceId")),
        "model": str(row.get("Name") or "").strip(),
        "media": str(row.get("MediaType") or ""),
        "bus": bus,
        "size_gb": float(row.get("SizeGB") or 0),
        "health": str(row.get("Health") or ""),
        "operational": [s.strip() for s in status.split(",") if s.strip()],
        "label_serial_tail": _label_tail(row.get("LabelSerial")),
        "slot": _slot(str(row.get("Location") or ""), bus),
    }


def collect_physical_disks() -> dict:
    """``{"source", "drives", "unavailable"}``: every physical drive, from WMI
    with the PowerShell reader as fallback. Cached for 30 s so the wear probe
    can match against it without a second query. Never raises."""
    global _cache
    if _cache is not None and time.monotonic() - _cache[0] <= _CACHE_S:
        return _cache[1]
    unavailable: list[str] = []
    source, drives = "wmi", []
    try:
        drives = [_from_wmi(r) for r in _wmi_physical_disks()]
    except Exception:  # noqa: BLE001 -- WMI/COM unavailable -> PowerShell fallback
        unavailable.append("wmi")
        source = "powershell"
        try:
            drives = [_from_powershell(r) for r in disk.get_disk_health().get("physical", [])]
        except Exception:  # noqa: BLE001 -- both readers failed -> no drives, still a result
            unavailable.append("powershell")
    result = {"source": source, "drives": drives[:MAX_DRIVES], "unavailable": unavailable}
    _cache = (time.monotonic(), result)
    return result


_IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
_MAX_EXTENTS = 8


def volume_disk_numbers(letter: str) -> list[int]:
    """Disk numbers a drive letter's volume lives on (a Storage Spaces volume
    gives its virtual disk's number). ``[]`` on any failure. Unelevated."""
    drive = norm_drive(letter)
    if drive is None or sys.platform != "win32":
        return []
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        share = 0x1 | 0x2  # FILE_SHARE_READ | FILE_SHARE_WRITE
        handle = kernel32.CreateFileW(rf"\\.\{drive}", 0, share, None, 3, 0, None)  # OPEN_EXISTING
        if not handle or handle == wintypes.HANDLE(-1).value:
            return []
        try:
            # VOLUME_DISK_EXTENTS: DWORD count + 4 bytes padding, then 24-byte
            # DISK_EXTENT records (DWORD DiskNumber, pad, two LARGE_INTEGERs).
            buf = ctypes.create_string_buffer(8 + 24 * _MAX_EXTENTS)
            returned = wintypes.DWORD()
            ok = kernel32.DeviceIoControl(
                handle,
                _IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                buf,
                len(buf),
                ctypes.byref(returned),
                None,
            )
            if not ok:
                return []
            count = min(int.from_bytes(buf.raw[0:4], "little"), _MAX_EXTENTS)
            numbers = [int.from_bytes(buf.raw[8 + 24 * i : 12 + 24 * i], "little") for i in range(count)]
            return sorted(set(numbers))
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 -- ctypes/IOCTL unavailable -> no mapping
        return []


def _fixed_letters() -> list[str]:
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:  # noqa: BLE001 -- no partitions readable -> no letters
        return []
    letters = []
    for p in parts:
        drive = norm_drive((p.device or "")[:2])
        if drive and "fixed" in (p.opts or "") and drive not in letters:
            letters.append(drive)
    return letters


def _p_physical_disks(slots: dict) -> dict:
    data = dict(collect_physical_disks())
    data["letters"] = {letter: volume_disk_numbers(letter) for letter in _fixed_letters()}
    data["focus"] = norm_drive(slots.get("drive"))
    return data


_storage_probe(
    "storage.physical_disks",
    "Drives and their health",
    _p_physical_disks,
    timeout_s=12.0,
    needs_optional=("drive",),
)


# ── drive wear & temperature (LibreHardwareMonitor) ───────────────────────
# Unelevated, Get-StorageReliabilityCounter returns null for every drive here
# (checked 2026-10-13); LHM runs elevated and publishes the NVMe SMART log.

_WEAR_MARKERS = frozenset({"Percentage Used", "Available Spare"})
_LEVELS = {
    "Percentage Used": "pct_used",
    "Available Spare": "spare_pct",
    "Available Spare Threshold": "spare_threshold_pct",
}
_TEMP_LIMITS = {"Warning Temperature": "warn_c", "Critical Temperature": "crit_c"}


def _sensors(node: dict) -> list[dict]:
    """Every leaf sensor under a hardware node (one level of grouping deep)."""
    out = []
    for group in node.get("Children") or []:
        if isinstance(group, dict):
            out.extend(c for c in group.get("Children") or [] if isinstance(c, dict) and c.get("Type"))
    return out


def _pct(value: object) -> float | None:
    """A percentage, or None for LHM's invalid readings (255 % sentinels)."""
    number = lhm._parse_temp_value(str(value or ""))
    return number if number is not None and 0 <= number <= 100 else None


def _lhm_row(node: dict) -> dict | None:
    sensors = _sensors(node)
    if not _WEAR_MARKERS & {s.get("Text") for s in sensors}:
        return None
    # A phantom node (live 2026-10-13: named by 40 NUL bytes, 0 °C, 0 % spare)
    # is no drive at all.
    model = "".join(ch for ch in str(node.get("Text") or "") if ch.isprintable()).strip()
    if not model:
        return None
    row = {"model": model, "temp_c": None, "warn_c": None, "crit_c": None}
    row.update(dict.fromkeys(_LEVELS.values()))
    for s in sensors:
        text = s.get("Text")
        if text in _LEVELS:
            row[_LEVELS[text]] = _pct(s.get("Value"))
        elif s.get("Type") == "Temperature":
            celsius = lhm._parse_temp_value(str(s.get("Value") or ""))
            if not celsius or celsius < 0 or celsius > 150:  # 0 °C is LHM's "no reading"
                celsius = None
            if text in _TEMP_LIMITS:
                row[_TEMP_LIMITS[text]] = celsius
            elif row["temp_c"] is None or text == "Composite Temperature":
                row["temp_c"] = celsius
    return row


def parse_lhm_storage(tree: object) -> list[dict]:
    """Storage rows from LHM's data.json: hardware nodes carrying NVMe wear
    levels (RAM DIMMs and other sensors have none). Never raises."""
    rows: list[dict] = []

    def walk(node: object, depth: int) -> None:
        if not isinstance(node, dict) or depth > 4:
            return
        row = _lhm_row(node)
        if row is not None:
            rows.append(row)
            return
        children = node.get("Children")
        for child in children if isinstance(children, list) else []:
            walk(child, depth + 1)

    walk(tree, 0)
    return rows[:MAX_DRIVES]


def _same_model(a: str, b: str) -> bool:
    def norm(x: str) -> str:
        x = x.strip().lower()
        return x[5:] if x.startswith("nvme ") else x

    return norm(a) == norm(b)


def _p_drive_wear(slots: dict) -> dict:
    try:
        tree = lhm._fetch_data_json()
    except Exception:  # noqa: BLE001 -- LHM feed unreadable -> treated as not running
        tree = None
    if not tree:
        return {
            "available": False,
            "reason": "LibreHardwareMonitor isn't running, so drive wear and temperature couldn't be read.",
            "drives": [],
        }
    drives = collect_physical_disks().get("drives", [])
    rows = parse_lhm_storage(tree)
    for row in rows:
        row["match"] = sorted(d["disk_number"] for d in drives if _same_model(d.get("model", ""), row["model"]))
        row["ambiguous"] = len(row["match"]) > 1
    return {"available": True, "reason": "", "drives": rows}


_storage_probe("storage.drive_wear", "Drive wear and temperature", _p_drive_wear, timeout_s=10.0)


# ── Storage Spaces pool ──────────────────────────────────────────────────


def _s(value: object) -> str:
    return str(value or "").strip()


def _p_pool(slots: dict) -> dict:
    try:
        raw = disk.get_storage_spaces() or {}
    except Exception:  # noqa: BLE001 -- the reader already degrades; belt and braces
        raw = {}
    return {
        "has_spaces": bool(raw.get("has_spaces")),
        "pools": [
            {"name": _s(p.get("Name")), "health": _s(p.get("Health")), "operational": _s(p.get("Operational"))}
            for p in raw.get("pools") or []
        ],
        "virtual_disks": [
            {
                "name": _s(v.get("Name")),
                "health": _s(v.get("Health")),
                "operational": _s(v.get("Operational")),
                "resiliency": _s(v.get("Resiliency")),
            }
            for v in raw.get("virtual_disks") or []
        ],
        # Full serials stay behind: only the label tail leaves this probe.
        "members": [
            {
                "pool": _s(m.get("Pool")),
                "model": _s(m.get("Name")),
                "health": _s(m.get("Health")),
                "operational": _s(m.get("Operational")),
                "usage": _s(m.get("Usage")),
                "label_serial_tail": _label_tail(m.get("LabelSerial")),
                "slot": _slot(_s(m.get("Location")), ""),
            }
            for m in (raw.get("members") or [])[:MAX_DRIVES]
        ],
        "repair_jobs": [
            {"name": _s(j.get("Name")), "state": _s(j.get("State")), "pct": max(0, _int(j.get("Pct"), 0))}
            for j in raw.get("repair_jobs") or []
        ],
    }


# ── disk errors in the event log ─────────────────────────────────────────

WINDOW_DAYS = 7
ESCALATION_DAYS = 30
_DISK_IDS = frozenset({7, 11, 51, 153, 157})
_NTFS_IDS = frozenset({50, 55, 98})
_NTFS_CORRUPTION_IDS = frozenset({55, 98})
# Older NTFS events log as "Ntfs", newer ones as "Microsoft-Windows-Ntfs".
_ERROR_PROVIDERS = ("disk", "stornvme", "storahci", "Ntfs", "Microsoft-Windows-Ntfs")
_HARDDISK_RE = re.compile(r"\\Device\\Harddisk(\d+)", re.IGNORECASE)


def _provider_key(provider: str) -> str:
    return "Ntfs" if provider in ("Ntfs", "Microsoft-Windows-Ntfs") else provider


def _counted(provider: str, eid: int) -> bool:
    if provider == "disk":
        return eid in _DISK_IDS
    if provider == "Ntfs":
        return eid in _NTFS_IDS
    return provider in ("stornvme", "storahci")


def _bump(slot: dict, when: str) -> None:
    slot["count"] += 1
    slot["first"] = min(slot["first"], when) if slot["first"] else when
    slot["last"] = max(slot["last"], when)


def _boot_iso() -> str | None:
    try:
        return datetime.fromtimestamp(psutil.boot_time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001 -- boot time unreadable -> nothing counts as "since boot"
        return None


def _disk_errors(days: int) -> dict:
    unavailable: list[str] = []
    boot = _boot_iso()
    by_provider: dict[str, dict] = {}
    by_disk: dict[str, dict] = {}
    corruption = 0
    xpath = dcp.window_xpath(providers=list(_ERROR_PROVIDERS), levels=[1, 2, 3], days=days)
    for ev in dcp._query("System", xpath, unavailable, max_events=500):
        provider = _provider_key(ev.get("provider", ""))
        eid = _int(ev.get("id"))
        if not _counted(provider, eid):
            continue
        when = ev.get("time", "")
        _bump(by_provider.setdefault(provider, {"count": 0, "first": "", "last": ""}), when)
        if provider == "Ntfs" and eid in _NTFS_CORRUPTION_IDS:
            corruption += 1
        values = [*(ev.get("data_list") or []), *(ev.get("data") or {}).values()]
        number = next((m.group(1) for v in values if (m := _HARDDISK_RE.search(str(v)))), None)
        if number is not None:
            slot = by_disk.setdefault(number, {"count": 0, "since_boot": 0, "first": "", "last": ""})
            _bump(slot, when)
            if boot and when >= boot:
                slot["since_boot"] += 1
    pool_events = dcp._query(
        dcp.STORAGE_SPACES_CHANNEL, dcp.window_xpath(levels=[1, 2, 3], days=days), unavailable, max_events=200
    )
    return {
        "window_days": days,
        "boot": boot,
        "by_provider": by_provider,
        "by_disk": by_disk,
        "ntfs_corruption": corruption,
        "pool_events": len(pool_events),
        "unavailable": unavailable,
    }


# ── free space ───────────────────────────────────────────────────────────

MAX_VOLUMES = 26


def _p_volumes(slots: dict) -> dict:
    volumes = []
    try:
        drives = disk._enumerate_logical_drives()
    except Exception:  # noqa: BLE001 -- psutil unavailable -> no volumes
        drives = []
    for d in drives:
        total = float(d.get("TotalGB") or 0)
        if d.get("DriveType") == 4 or total <= 0:  # network drives are the NAS probe's job
            continue
        free = float(d.get("FreeGB") or 0)
        volumes.append(
            {
                "letter": f"{_s(d.get('Letter')).upper()}:",
                "label": _s(d.get("Label")),
                "fs": _s(d.get("FileSystem")),
                "total_gb": total,
                "free_gb": free,
                "free_pct": round(free / total * 100, 1),
                "fixed": d.get("DriveType") == 3,
            }
        )
    return {"volumes": volumes[:MAX_VOLUMES]}


# ── live IO sample ───────────────────────────────────────────────────────

SAMPLE_S = 3
LONG_SAMPLE_S = 10
MIN_OPS = 20
_PHYSICAL_DRIVE_RE = re.compile(r"PhysicalDrive(\d+)$", re.IGNORECASE)


def _counters() -> dict | None:
    try:
        return psutil.disk_io_counters(perdisk=True)
    except Exception:  # noqa: BLE001 -- counters disabled / unreadable
        return None


def _io_sample(seconds: int) -> dict:
    before = _counters()
    time.sleep(seconds)
    after = _counters()
    disks = []
    for name, now in (after or {}).items():
        match = _PHYSICAL_DRIVE_RE.search(name)
        then = (before or {}).get(name)
        if not match or then is None:
            continue
        reads = now.read_count - then.read_count
        writes = now.write_count - then.write_count
        read_ms = now.read_time - then.read_time
        write_ms = now.write_time - then.write_time
        moved = (now.read_bytes - then.read_bytes) + (now.write_bytes - then.write_bytes)
        disks.append(
            {
                "disk_number": int(match.group(1)),
                "reads_s": round(reads / seconds, 1),
                "writes_s": round(writes / seconds, 1),
                "mb_s": round(moved / 1024**2 / seconds, 1),
                "busy_pct": min(100, round((read_ms + write_ms) / (seconds * 1000) * 100)),
                "avg_read_ms": round(read_ms / reads, 1) if reads >= MIN_OPS else None,
                "avg_write_ms": round(write_ms / writes, 1) if writes >= MIN_OPS else None,
            }
        )
    disks.sort(key=lambda d: d["disk_number"])
    return {"seconds": seconds, "disks": disks}


# ── NAS (the app's saved reading; never waits on SNMP) ─────────────────────


def _p_nas(slots: dict) -> dict:
    try:
        data = nas.get_nas_storage(wait=False) or {}
        concerns = nas.nas_storage_concerns(data)
    except Exception:  # noqa: BLE001 -- NAS cache unreadable -> nothing to report
        return {"configured": 0, "pending": False, "nas": [], "concerns": []}
    stamp = getattr(nas, "_nas_cache_ts", 0) or 0
    age_s = round(time.time() - stamp) if stamp else None
    entries = []
    for i, n in enumerate(data.get("nas") or [], 1):
        volumes = []
        for v in n.get("volumes") or []:
            used = v.get("pct_used")
            free_pct = round(100 - used, 1) if isinstance(used, (int, float)) else None
            volumes.append({"status": _s(v.get("status")), "free_pct": free_pct})
        entries.append(
            {
                # Never the configured name or address: the probe numbers them.
                "label": f"NAS {i}",
                "reachable": bool(n.get("reachable")),
                "age_s": age_s,
                "disks": [
                    {"bay": _s(d.get("bay")), "health": _s(d.get("health")), "temp_c": d.get("temp_c")}
                    for d in n.get("disks") or []
                ],
                "volumes": volumes,
            }
        )
    return {
        "configured": _int(data.get("configured"), len(entries)),
        "pending": bool(data.get("pending")),
        "nas": entries,
        "concerns": [
            {"level": _s(c.get("level")), "title": _s(c.get("title")), "detail": _s(c.get("detail"))}
            for c in concerns or []
        ],
    }


# ── escalation: what's using the space ─────────────────────────────────────

MAX_LOCATIONS = 10


def _p_space_breakdown(slots: dict) -> dict:
    drive = norm_drive(slots.get("drive"))
    if drive is None:
        fixed = [v for v in _p_volumes({})["volumes"] if v["fixed"]]
        drive = min(fixed, key=lambda v: v["free_pct"])["letter"] if fixed else None
    if drive is None:
        return {"drive": None, "locations": []}
    try:
        result = disk.get_disk_quickwins(drive) or {}
    except Exception:  # noqa: BLE001 -- analysis failed -> no breakdown
        result = {}
    found = [loc for loc in result.get("locations") or [] if loc.get("exists", True)]
    found.sort(key=lambda loc: -(loc.get("size_bytes") or 0))
    return {
        "drive": drive,
        "locations": [
            {
                "label": _s(loc.get("label")),
                "path": _s(loc.get("path")),
                "size_gb": round((loc.get("size_bytes") or 0) / 1024**3, 1),
            }
            for loc in found[:MAX_LOCATIONS]
        ],
    }


_storage_probe("storage.pool", "Storage Spaces pool", _p_pool, timeout_s=20.0)
_storage_probe(
    "storage.disk_errors", "Disk errors in the event log", lambda s: _disk_errors(WINDOW_DAYS), timeout_s=12.0
)
_storage_probe("storage.volumes", "Free space", _p_volumes, timeout_s=8.0)
_storage_probe("storage.io_sample", "Live drive activity", lambda s: _io_sample(SAMPLE_S), timeout_s=8.0)
_storage_probe("storage.nas", "NAS (saved reading)", _p_nas, timeout_s=8.0)
_storage_probe(
    "storage.space_breakdown",
    "What's using the space",
    _p_space_breakdown,
    timeout_s=20.0,
    needs_optional=("drive",),
)
_storage_probe(
    "storage.errors_30d", "Disk errors, last 30 days", lambda s: _disk_errors(ESCALATION_DAYS), timeout_s=15.0
)
_storage_probe(
    "storage.io_sample_long", "Live drive activity (10 s)", lambda s: _io_sample(LONG_SAMPLE_S), timeout_s=15.0
)
