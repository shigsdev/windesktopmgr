"""QNAP NAS storage over SNMP for the Storage tab.

Reads ``nas_config.json`` (gitignored; see ``nas_config.example.json``) for the
NAS list + read-only community, then queries each enabled NAS via SNMP v2c for
disks, volumes/pools, fans, and system info — so NAS storage shows alongside
local storage in one place, and an unhealthy NAS disk/volume can raise a
dashboard concern.

OIDs are the QNAP NAS-MIB (enterprise ``.1.3.6.1.4.1.24681.1.2``), verified live
against a TS-X72 on QTS 5.2.9. ``pysnmp`` is the SAME dependency homenet.py
already uses.

Design for testability: the SNMP I/O (``_snmp_collect``) is isolated and
mocked in tests; the parsing (``_parse_temp_c`` / ``_parse_size_gb`` /
``_parse_volume_name``), assembly (``_build_nas_result``), config loading, and
concern logic (``nas_storage_concerns``) are pure and fully unit-tested.
"""

import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

_NAS_CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nas_config.json")
_NAS_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nas_cache.json")

# A full SNMP poll costs ~12s per NAS, and the dashboard fan-out waits on its
# slowest collector -- so polling inline made a cold dashboard block ~25s after
# every reboot (looked like the app had hung). Reads are now cache-first and
# never block; refreshes run on a background thread. Snapshot is persisted so a
# freshly-restarted tray serves last-known NAS state immediately.
NAS_CACHE_TTL_S = 300

_nas_cache: dict | None = None
_nas_cache_ts: float = 0.0
_nas_lock = threading.RLock()
_nas_refreshing = False

# QNAP NAS-MIB columns (index by the trailing .N). Verified on TS-X72 / QTS 5.2.9.
_QNAP = "1.3.6.1.4.1.24681.1.2"
_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"  # "Linux TS-X72 5.2.9.3499"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_OID_CPU = _QNAP + ".1.0"  # "4.8 %"
# Scalar system OIDs (verified live on TVS-672N / TS-X51, QTS 5.2.9). The model
# NAME here (.12.0 -> "TVS-672N") is friendlier than sysDescr's kernel string.
_OID_MODEL = _QNAP + ".12.0"  # "TVS-672N"
_OID_SYS_TEMP = _QNAP + ".6.0"  # "30 C/86 F"
_OID_CPU_TEMP = _QNAP + ".5.0"  # "43 C/109 F"
_OID_TOTAL_MEM = _QNAP + ".2.0"  # "32007.9 MB"
_OID_FREE_MEM = _QNAP + ".3.0"  # "27874.1 MB"
_OID_DISK = {
    "descr": _QNAP + ".11.1.2",  # HDD1..
    "temp": _QNAP + ".11.1.3",  # "37 C/98 F"
    "model": _QNAP + ".11.1.5",  # "ST24000NT002-3N1101"
    "capacity": _QNAP + ".11.1.6",  # "21.83 TB"
    "health": _QNAP + ".11.1.7",  # "GOOD"
}
_OID_VOL = {
    "descr": _QNAP + ".17.1.2",  # "[Volume name, Pool N]"
    "fs": _QNAP + ".17.1.3",  # "EXT4"
    "total": _QNAP + ".17.1.4",  # "108.14 TB"
    "free": _QNAP + ".17.1.5",  # "32.29 TB"
    "status": _QNAP + ".17.1.6",  # "Ready"
}
_OID_FAN = {
    "descr": _QNAP + ".15.1.2",  # "System FAN 1"
    "speed": _QNAP + ".15.1.3",  # "761 RPM"
}

# Health/status values QNAP reports for a good drive / volume.
_DISK_HEALTHY = {"good", "normal", "ok"}
_VOL_HEALTHY = {"ready"}
_SIZE_UNITS = {"kb": 1 / (1024 * 1024), "mb": 1 / 1024, "gb": 1, "tb": 1024, "pb": 1024 * 1024}


def _parse_temp_c(raw: str) -> int | None:
    """'37 C/98 F' -> 37. None if unparseable."""
    m = re.search(r"(-?\d+)\s*C", str(raw or ""), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _parse_size_gb(raw: str) -> float | None:
    """'21.83 TB' / '931.51 GB' -> size in MB-based GB. None if unparseable."""
    m = re.search(r"([\d.]+)\s*([KMGTP]B)", str(raw or ""), re.IGNORECASE)
    if not m:
        return None
    try:
        return round(float(m.group(1)) * _SIZE_UNITS[m.group(2).lower()], 1)
    except (ValueError, KeyError):
        return None


def _parse_volume_name(raw: str) -> tuple[str, str]:
    """'[Volume shigs78nas2-hdd, Pool 1]' -> ('shigs78nas2-hdd', 'Pool 1').

    Falls back to (stripped-raw, '') for any other shape.
    """
    s = str(raw or "").strip()
    m = re.match(r"\[Volume\s+(.*?),\s*(Pool\s*\d+)\]", s, re.IGNORECASE)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return s.strip("[]"), ""


def _under_pytest() -> bool:
    """True inside the test suite -- gates real SNMP I/O and background threads."""
    return "pytest" in sys.modules


def _load_nas_config(path: str = _NAS_CONFIG_FILE) -> dict:
    """Load nas_config.json. Missing / malformed -> empty (feature simply off)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"nas": []}
        data.setdefault("nas", [])
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"nas": []}


def _configured_nas(cfg: dict) -> list[dict]:
    """Enabled NAS entries that have a host + a real community (not the
    placeholder), so a half-filled scaffold never gets polled."""
    out = []
    for n in cfg.get("nas", []):
        if not isinstance(n, dict) or not n.get("enabled"):
            continue
        host = (n.get("host") or "").strip()
        comm = (n.get("community") or "").strip()
        if not host or not comm or comm.upper().startswith("REPLACE_"):
            continue
        out.append(n)
    return out


def _build_nas_result(nas: dict, sys_info: dict, disk_cols: dict, vol_cols: dict, fan_cols: dict) -> dict:
    """Assemble one NAS's result dict from raw SNMP column maps (pure).

    ``*_cols`` are ``{field: {index: value}}`` as returned by the walk. Aligns
    rows by index and normalises. No I/O — this is where all the parsing logic
    lives so it can be tested without a live NAS.
    """
    descr = str(sys_info.get("sys_descr") or "")
    model_m = re.search(r"Linux\s+(\S+)\s+([\d.]+)", descr)
    # Prefer the friendly model name (.12.0 -> "TVS-672N") over sysDescr's
    # kernel token ("TS-X72"); fall back to the kernel token, then "".
    model = str(sys_info.get("model") or "").strip() or (model_m.group(1) if model_m else "")
    firmware = model_m.group(2) if model_m else ""

    sys_temp_c = _parse_temp_c(sys_info.get("sys_temp"))
    cpu_temp_c = _parse_temp_c(sys_info.get("cpu_temp"))
    mem_total_gb = _parse_size_gb(sys_info.get("total_mem"))
    mem_free_gb = _parse_size_gb(sys_info.get("free_mem"))
    mem_used_pct = None
    if mem_total_gb and mem_free_gb is not None and mem_total_gb > 0:
        mem_used_pct = round((mem_total_gb - mem_free_gb) / mem_total_gb * 100, 1)

    disks = []
    for idx in sorted((disk_cols.get("descr") or {}).keys()):
        model_s = str(disk_cols.get("model", {}).get(idx, "")).strip()
        if not model_s:
            continue  # empty bay
        health = str(disk_cols.get("health", {}).get(idx, "")).strip()
        disks.append(
            {
                "bay": str(disk_cols.get("descr", {}).get(idx, f"HDD{idx}")).strip(),
                "model": model_s,
                "capacity": str(disk_cols.get("capacity", {}).get(idx, "")).strip(),
                "capacity_gb": _parse_size_gb(disk_cols.get("capacity", {}).get(idx, "")),
                "temp_c": _parse_temp_c(disk_cols.get("temp", {}).get(idx, "")),
                "health": health,
                "healthy": health.lower() in _DISK_HEALTHY,
            }
        )

    volumes = []
    for idx in sorted((vol_cols.get("descr") or {}).keys()):
        name, pool = _parse_volume_name(vol_cols.get("descr", {}).get(idx, ""))
        total_gb = _parse_size_gb(vol_cols.get("total", {}).get(idx, ""))
        free_gb = _parse_size_gb(vol_cols.get("free", {}).get(idx, ""))
        pct_used = None
        if total_gb and free_gb is not None and total_gb > 0:
            pct_used = round((total_gb - free_gb) / total_gb * 100, 1)
        status = str(vol_cols.get("status", {}).get(idx, "")).strip()
        volumes.append(
            {
                "name": name,
                "pool": pool,
                "fs": str(vol_cols.get("fs", {}).get(idx, "")).strip(),
                "total": str(vol_cols.get("total", {}).get(idx, "")).strip(),
                "free": str(vol_cols.get("free", {}).get(idx, "")).strip(),
                "total_gb": total_gb,
                "free_gb": free_gb,
                "pct_used": pct_used,
                "status": status,
                "healthy": status.lower() in _VOL_HEALTHY,
            }
        )

    fans = []
    for idx in sorted((fan_cols.get("descr") or {}).keys()):
        fans.append(
            {
                "name": str(fan_cols.get("descr", {}).get(idx, "")).strip(),
                "speed": str(fan_cols.get("speed", {}).get(idx, "")).strip(),
            }
        )

    return {
        "name": nas.get("name") or nas.get("host"),
        "host": nas.get("host"),
        "reachable": True,
        "model": model,
        "firmware": firmware,
        "cpu": str(sys_info.get("cpu") or "").strip(),
        "sys_temp_c": sys_temp_c,
        "cpu_temp_c": cpu_temp_c,
        "mem_total_gb": mem_total_gb,
        "mem_used_pct": mem_used_pct,
        "disks": disks,
        "volumes": volumes,
        "fans": fans,
        "error": None,
    }


def _snmp_collect(nas: dict, timeout: float) -> dict | None:  # pragma: no cover — needs a live NAS
    """Query one NAS over SNMP. Returns raw ``{sys_info, disk_cols, vol_cols,
    fan_cols}`` or None on any failure/timeout (caller marks unreachable).

    Isolated so tests mock this boundary; the async pysnmp calls only run
    against a real device.
    """
    # Safety net: NEVER do a real SNMP/network call under pytest, even if a
    # dashboard-summary test forgot to mock get_nas_storage. Returns None
    # (NAS reads as unreachable) with zero network I/O.
    if _under_pytest():
        return None

    try:
        import asyncio

        from pysnmp.hlapi.v1arch.asyncio import (
            CommunityData,
            ObjectIdentity,
            ObjectType,
            SnmpDispatcher,
            UdpTransportTarget,
            get_cmd,
            walk_cmd,
        )
    except ImportError:
        return None

    host = nas.get("host")
    community = nas.get("community")

    async def _run():
        disp = SnmpDispatcher()
        target = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
        creds = CommunityData(community, mpModel=1)

        async def _get(oid):
            errI, errS, _, vbs = await get_cmd(disp, creds, target, ObjectType(ObjectIdentity(oid)))
            if errI or errS:
                return None
            for _, v in vbs:
                return str(v)
            return None

        async def _walk_col(base):
            col = {}
            async for errI, errS, _, vbs in walk_cmd(
                disp, creds, target, ObjectType(ObjectIdentity(base)), lexicographicMode=False
            ):
                if errI or errS:
                    break
                for oid, val in vbs:
                    tail = str(oid).rsplit(".", 1)[-1]
                    try:
                        col[int(tail)] = str(val)
                    except ValueError:
                        continue
            return col

        sys_info = {
            "sys_descr": await _get(_OID_SYS_DESCR),
            "sys_name": await _get(_OID_SYS_NAME),
            "cpu": await _get(_OID_CPU),
            "model": await _get(_OID_MODEL),
            "sys_temp": await _get(_OID_SYS_TEMP),
            "cpu_temp": await _get(_OID_CPU_TEMP),
            "total_mem": await _get(_OID_TOTAL_MEM),
            "free_mem": await _get(_OID_FREE_MEM),
        }
        if sys_info["sys_descr"] is None and sys_info["sys_name"] is None:
            return None  # no SNMP response at all
        disk_cols = {f: await _walk_col(o) for f, o in _OID_DISK.items()}
        vol_cols = {f: await _walk_col(o) for f, o in _OID_VOL.items()}
        fan_cols = {f: await _walk_col(o) for f, o in _OID_FAN.items()}
        return {"sys_info": sys_info, "disk_cols": disk_cols, "vol_cols": vol_cols, "fan_cols": fan_cols}

    try:
        return asyncio.run(_run())
    except Exception as e:  # noqa: BLE001 -- any SNMP/network error -> unreachable
        print(f"[NAS SNMP error] {host}: {e}")
        return None


def _collect_one(nas: dict, timeout: float) -> dict:
    """Poll a single NAS. Never raises -- an unreachable / mis-communitied NAS
    becomes a ``reachable: False`` entry."""
    raw = _snmp_collect(nas, timeout)
    if raw is None:
        return {
            "name": nas.get("name") or nas.get("host"),
            "host": nas.get("host"),
            "reachable": False,
            "disks": [],
            "volumes": [],
            "fans": [],
            "error": "No SNMP response (NAS off, SNMP disabled, or wrong community).",
        }
    return _build_nas_result(nas, raw["sys_info"], raw["disk_cols"], raw["vol_cols"], raw["fan_cols"])


def _collect_all_nas() -> dict:
    """Poll every configured NAS in PARALLEL. They're independent hosts, so the
    old serial loop just summed their latencies (~12s each)."""
    cfg = _load_nas_config()
    nas_list = _configured_nas(cfg)
    if not nas_list:
        return {"nas": [], "configured": 0}
    timeout = cfg.get("poll_timeout_s", 3)
    with ThreadPoolExecutor(max_workers=min(4, len(nas_list))) as ex:
        results = list(ex.map(lambda n: _collect_one(n, timeout), nas_list))
    return {"nas": results, "configured": len(nas_list)}


def _load_nas_cache(path: str | None = None) -> tuple[dict | None, float]:
    """Restore the last snapshot from disk. Missing / malformed -> (None, 0.0).

    Path resolves at CALL time (not as a default arg) so it stays patchable.
    """
    path = path or _NAS_CACHE_FILE
    try:
        with open(path, encoding="utf-8") as f:
            blob = json.load(f)
        data = blob.get("data")
        if not isinstance(data, dict):
            return None, 0.0
        return data, float(blob.get("ts") or 0.0)
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError, ValueError, AttributeError):
        return None, 0.0


def _save_nas_cache(data: dict, ts: float, path: str | None = None) -> None:
    """Persist atomically. A cache-write failure must never break a poll.

    The temp name is per-writer: a Storage-tab ``wait=True`` poll can run
    concurrently with the background refresh (single-flight only guards the
    latter), and a shared ``.tmp`` would let the two interleave into a corrupt
    file. Catches TypeError/ValueError too -- json.dump raises those, not
    OSError, and letting one escape would 500 the route it was called from.
    """
    path = path or _NAS_CACHE_FILE
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"data": data, "ts": ts}, f)
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError) as e:
        print(f"[NASCache] Save error: {e}")
        try:
            os.remove(tmp)  # don't leave a partial temp behind
        except OSError:
            pass


def _refresh_nas_cache() -> dict:
    """Do a real poll and update both the in-memory and on-disk snapshot."""
    global _nas_cache, _nas_cache_ts
    data = _collect_all_nas()
    ts = time.time()
    with _nas_lock:
        _nas_cache = data
        _nas_cache_ts = ts
    _save_nas_cache(data, ts)
    return data


def _start_nas_refresh() -> None:
    """Kick a background refresh unless one is already in flight (single-flight,
    so a burst of dashboard polls can't stack up N concurrent SNMP sweeps)."""
    global _nas_refreshing
    with _nas_lock:
        if _nas_refreshing:
            return
        _nas_refreshing = True

    def _run() -> None:
        global _nas_refreshing
        try:
            _refresh_nas_cache()
        except Exception as e:  # noqa: BLE001 -- background thread must not die loudly
            print(f"[NASCache] Refresh error: {e}")
        finally:
            with _nas_lock:
                _nas_refreshing = False

    threading.Thread(target=_run, name="nas-refresh", daemon=True).start()


def _reset_nas_cache() -> None:
    """Test hook -- drop the in-memory snapshot."""
    global _nas_cache, _nas_cache_ts, _nas_refreshing
    with _nas_lock:
        _nas_cache = None
        _nas_cache_ts = 0.0
        _nas_refreshing = False


def get_nas_storage(wait: bool = False) -> dict:
    """All configured NAS storage for the Storage tab, served from cache.

    Cache-first and NON-BLOCKING by default: returns the last snapshot straight
    away and refreshes in the background, so a slow NAS can never stall the
    dashboard fan-out. ``wait=True`` (the Storage tab route) blocks for a real
    poll only when nothing has ever been cached, so the tab isn't empty on a
    first-ever visit.

    ``configured`` is 0 when nas_config.json is missing or still holds the
    placeholder (feature simply dormant).
    """
    global _nas_cache, _nas_cache_ts
    with _nas_lock:
        cached, ts = _nas_cache, _nas_cache_ts

    # Cold process: try the snapshot left by the previous run before polling.
    if cached is None:
        cached, ts = _load_nas_cache()
        if cached is not None:
            with _nas_lock:
                if _nas_cache is None:
                    _nas_cache, _nas_cache_ts = cached, ts

    if cached is not None and (time.time() - ts) < NAS_CACHE_TTL_S:
        return cached

    if cached is None and wait:
        return _refresh_nas_cache()

    if not _under_pytest():
        _start_nas_refresh()
    if cached is not None:
        return cached  # stale, but instant -- refresh lands on the next poll

    # Never collected yet: report pending so the dashboard renders immediately
    # and raises NO false "unreachable" concerns for a NAS we simply haven't
    # reached yet.
    return {"nas": [], "configured": len(_configured_nas(_load_nas_config())), "pending": True}


def nas_storage_concerns(data: dict) -> list[dict]:
    """Dashboard concerns from get_nas_storage(): an unhealthy NAS disk or a
    not-Ready volume is critical; a configured-but-unreachable NAS is a warning
    (SNMP down / NAS off). Returns [] when everything is fine or nothing is
    configured."""
    concerns: list[dict] = []
    for nas in (data or {}).get("nas", []):
        label = nas.get("name") or nas.get("host") or "NAS"
        if not nas.get("reachable"):
            concerns.append(
                _nas_concern(
                    "warning",
                    f"NAS '{label}' is unreachable over SNMP",
                    nas.get("error")
                    or "Could not reach the NAS. It may be off, SNMP disabled, or the community changed.",
                )
            )
            continue
        bad_disks = [d for d in nas.get("disks", []) if not d.get("healthy")]
        if bad_disks:
            names = ", ".join(f"{d.get('bay')} ({d.get('health')})" for d in bad_disks[:4])
            concerns.append(
                _nas_concern(
                    "critical",
                    f"NAS '{label}': {len(bad_disks)} disk(s) not healthy",
                    f"{names}. Check the NAS's storage manager and back up / replace the drive.",
                )
            )
        bad_vols = [v for v in nas.get("volumes", []) if not v.get("healthy")]
        if bad_vols:
            names = ", ".join(f"{v.get('name')} ({v.get('status')})" for v in bad_vols[:4])
            concerns.append(
                _nas_concern(
                    "critical",
                    f"NAS '{label}': {len(bad_vols)} volume(s) not Ready",
                    f"{names}. A pool may be degraded/rebuilding — check the NAS.",
                )
            )
    return concerns


def _nas_concern(level: str, title: str, detail: str) -> dict:
    return {
        "level": level,
        "tab": "disk",
        "icon": "🗄",
        "title": title,
        "detail": detail,
        "action": "View Storage",
        "action_fn": "switchTab('disk')",
    }
