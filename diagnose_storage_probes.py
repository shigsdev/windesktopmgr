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

import psutil

import diagnose_probes as dp
import disk

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
