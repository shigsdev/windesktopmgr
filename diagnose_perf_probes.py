"""Speed & heat evidence for the Diagnose engine (spec 2026-10-17).

Read-only probes over this PC's CPU and memory use per program, temperatures,
graphics card, the stuck-driver detector, drive activity, history since the
last restart, startup timing, power plan and hardware-error reports,
registered into ``diagnose_probes.PROBES`` alongside the network, crash and
storage bundles. Python first (CLAUDE.md): psutil, winreg and the app's own
readers in-process; no PowerShell. LibreHardwareMonitor is only read, never
started.

Privacy (spec §7): programs appear by program name only (``chrome.exe``),
never by window title, command line, path or user name; same-name processes
are summed so "chrome.exe" means every Chrome process.
"""

from __future__ import annotations

import os
import re
import statistics
import struct
import time
import winreg
from datetime import datetime, timedelta, timezone

import psutil

import diagnose_crash_probes as dcp
import diagnose_probes as dp
import diagnose_storage_probes as dsp
import gpu
import kernel_cpu
import lhm
import metrics_history
import thermals

_REDACT = ("username", "serial", "mac", "self_host")
CPU_SAMPLE_S = 3
TOP_N = 5
# The only process fields a perf probe may ask psutil for: nothing that names
# a window, a file, a command line or a user.
ALLOWED_PROC_ATTRS = frozenset({"pid", "name", "cpu_times", "memory_info", "create_time", "num_threads"})
_IDLE_NAMES = frozenset({"system idle process", "idle"})

REGISTERED: dict[str, dp.Probe] = {}


def _perf_probe(key: str, label: str, fn, timeout_s: float = 10.0, **kw) -> dp.Probe:
    probe = dp.register(dp.Probe(key, label, "perf", fn, redact=_REDACT, timeout_s=timeout_s, **kw))
    REGISTERED[key] = probe
    return probe


# ── app names ─────────────────────────────────────────────────────────────

_VENDOR_WORDS = frozenset({"microsoft", "google", "the"})


def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def app_matches(app_name: str | None, exe: str) -> bool:
    """Whether the program ``exe`` is (part of) the app the user named:
    "Chrome" ~ chrome.exe, "Microsoft Teams" ~ ms-teams.exe."""
    if not isinstance(app_name, str) or not app_name.strip() or not isinstance(exe, str):
        return False
    stem = _alnum(re.sub(r"\.exe$", "", exe.strip(), flags=re.IGNORECASE))
    if not stem:
        return False
    words = [_alnum(w) for w in app_name.split()]
    if any(len(w) >= 3 and w not in _VENDOR_WORDS and w in stem for w in words):
        return True
    return stem in "".join(words)


def _focus_slot(slots: dict) -> str | None:
    app = (slots or {}).get("app_name")
    return (app.strip() or None) if isinstance(app, str) else None


# ── CPU ───────────────────────────────────────────────────────────────────


# x64 SYSTEM_PROCESS_INFORMATION fields (verified live against psutil on
# Windows 11 25H2, 2026-10-17): CreateTime 0x20, UserTime 0x28, KernelTime
# 0x30 (100-ns ticks), ImageName UNICODE_STRING (Length 0x38, Buffer 0x40),
# UniqueProcessId 0x50, WorkingSetSize 0x90.
_SPI_HEADER = 0x100
_FILETIME_UNIX_S = 11_644_473_600
_MAX_ENTRIES = 100_000


def parse_process_table(raw: bytes, base: int) -> dict[int, dict]:
    """``{pid: {"name", "cpu_s", "rss", "create_time"}}`` for every process in
    a raw SystemProcessInformation buffer read at address ``base``.
    Bounds-checked: an entry or name that runs past ``raw`` is dropped, never
    read. Image names only -- no paths, command lines or users."""
    out: dict[int, dict] = {}
    off, size = 0, len(raw)
    for _ in range(_MAX_ENTRIES):
        if off + _SPI_HEADER > size:
            break
        nxt = struct.unpack_from("<I", raw, off)[0]
        created, user, kernel = struct.unpack_from("<qqq", raw, off + 0x20)
        length = struct.unpack_from("<H", raw, off + 0x38)[0]
        ptr = struct.unpack_from("<Q", raw, off + 0x40)[0]
        pid = struct.unpack_from("<Q", raw, off + 0x50)[0]
        rss = struct.unpack_from("<Q", raw, off + 0x90)[0]
        name = ""
        start = ptr - base
        if ptr and start >= 0 and start + length <= size:
            name = raw[start : start + length].decode("utf-16-le", errors="replace")
        out[pid] = {
            "name": name,
            "cpu_s": (user + kernel) / 1e7,
            "rss": rss,
            "create_time": created / 1e7 - _FILETIME_UNIX_S if created else None,
        }
        if nxt == 0:
            break
        off += nxt
    return out


def _nt_processes() -> dict[int, dict] | None:
    """Every process from ONE NtQuerySystemInformation snapshot (~5 ms for
    500 processes, protected ones included), or None to fall back to psutil,
    whose per-process reads take ~1.6 s here and pushed perf.cpu past its
    timeout when ten probes ran at once."""
    try:
        result = kernel_cpu.query_process_buffer()
    except Exception:  # noqa: BLE001 -- ctypes/OS failure -> psutil fallback
        return None
    table = parse_process_table(*result) if result else {}
    return table or None


def _proc_fields(attrs: list[str]):
    """psutil fallback: each live process's ``attrs`` read on THIS thread.
    Never ``process_iter(attrs=...)``: it writes ``proc.info`` on Process
    objects psutil shares between threads, and two probes run at once."""
    for proc in psutil.process_iter():
        try:
            yield proc.as_dict(attrs=attrs, ad_value=None)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue  # exited while being read


def _cpu_snapshot() -> dict[int, tuple[str, float]]:
    """``{pid: (name, user+system seconds)}`` for every readable process,
    leaving out the idle pseudo-process and this app's own process."""
    me = os.getpid()
    out: dict[int, tuple[str, float]] = {}
    table = _nt_processes()
    if table is not None:
        for pid, proc in table.items():
            name = proc["name"]
            if name and pid not in (0, me) and name.lower() not in _IDLE_NAMES:
                out[pid] = (name, proc["cpu_s"])
        return out
    for info in _proc_fields(["pid", "name", "cpu_times"]):
        pid, name, times = info.get("pid"), info.get("name"), info.get("cpu_times")
        if times is None or not name or pid in (0, me) or name.lower() in _IDLE_NAMES:
            continue
        out[pid] = (name, times.user + times.system)
    return out


def cpu_sample(seconds: float) -> dict:
    """CPU use over ``seconds``: overall, busiest core, and the top programs by
    share of the WHOLE CPU (0-100), same-name processes summed."""
    psutil.cpu_percent(percpu=True)
    psutil.cpu_percent()
    before = _cpu_snapshot()
    time.sleep(seconds)
    after = _cpu_snapshot()
    per_core = psutil.cpu_percent(percpu=True) or [0.0]
    total = psutil.cpu_percent()
    cores = psutil.cpu_count() or len(per_core) or 1
    groups: dict[str, dict] = {}
    for pid, (name, now) in after.items():
        then = before.get(pid)
        if then is None or then[0] != name or now < then[1]:
            continue
        share = (now - then[1]) / (seconds * cores) * 100
        row = groups.setdefault(name, {"name": name, "pid": pid, "count": 0, "cpu_pct": 0.0, "_best": -1.0})
        row["count"] += 1
        row["cpu_pct"] += share
        if share > row["_best"]:
            row["_best"], row["pid"] = share, pid
    rows = []
    for row in groups.values():
        row.pop("_best")
        row["cpu_pct"] = round(row["cpu_pct"], 1)
        rows.append(row)
    rows.sort(key=lambda r: -r["cpu_pct"])
    return {
        "seconds": seconds,
        "total_pct": round(float(total), 1),
        "busiest_core_pct": round(float(max(per_core)), 1),
        "cores": cores,
        "top": rows[:TOP_N],
        "_all": rows,
    }


def _p_cpu(slots: dict) -> dict:
    data = cpu_sample(CPU_SAMPLE_S)
    rows = data.pop("_all")
    app = _focus_slot(slots)
    matched = [r for r in rows if app_matches(app, r["name"])]
    focus = None
    if matched:
        focus = {
            "name": matched[0]["name"],
            "cpu_pct": round(sum(r["cpu_pct"] for r in matched), 1),
            "count": sum(r["count"] for r in matched),
        }
    return {**data, "focus_app": app, "focus": focus}


_perf_probe("perf.cpu", "What's using the CPU", _p_cpu, needs_optional=("app_name",))


# ── memory ────────────────────────────────────────────────────────────────


def _gb(n: float) -> float:
    return round(n / 1024**3, 1)


def _memory_rows():
    """``{"pid", "name", "rss", "create_time"}`` per process: one system
    snapshot, else psutil."""
    table = _nt_processes()
    if table is not None:
        for pid, proc in table.items():
            if pid:
                yield {"pid": pid, "name": proc["name"], "rss": proc["rss"], "create_time": proc["create_time"]}
        return
    for info in _proc_fields(["pid", "name", "memory_info", "create_time"]):
        mem = info.get("memory_info")
        yield {
            "pid": info.get("pid"),
            "name": info.get("name"),
            "rss": mem.rss if mem is not None else None,
            "create_time": info.get("create_time"),
        }


def _memory_groups() -> list[dict]:
    """Programs by resident memory, same-name processes summed; ``running_h``
    is the oldest instance's age, ``max_proc_gb`` / ``max_proc_h`` the biggest
    single process and its own age (a leak is one process growing, not many
    small ones adding up)."""
    now = time.time()
    groups: dict[str, dict] = {}
    for info in _memory_rows():
        name, rss = info["name"], info["rss"]
        if not name or rss is None or name.lower() in _IDLE_NAMES:
            continue
        row = groups.setdefault(
            name, {"name": name, "pid": info["pid"], "count": 0, "rss": 0, "_big": -1, "_t": None, "_big_t": None}
        )
        row["count"] += 1
        row["rss"] += rss
        created = info["create_time"]
        if rss > row["_big"]:
            row["_big"], row["pid"] = rss, info["pid"]
            row["_big_t"] = created if isinstance(created, (int, float)) else None
        if isinstance(created, (int, float)) and (row["_t"] is None or created < row["_t"]):
            row["_t"] = created
    rows = []
    for row in groups.values():
        started = row["_t"]
        rows.append(
            {
                "name": row["name"],
                "pid": row["pid"],
                "count": row["count"],
                "rss_gb": _gb(row["rss"]),
                "running_h": round((now - started) / 3600, 1) if started else None,
                "max_proc_gb": _gb(row["_big"]),
                "max_proc_h": round((now - row["_big_t"]) / 3600, 1) if row["_big_t"] else None,
                "_rss": row["rss"],
            }
        )
    rows.sort(key=lambda r: -r["_rss"])
    return rows


def _p_memory(slots: dict) -> dict:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    rows = _memory_groups()
    app = _focus_slot(slots)
    matched = [r for r in rows if app_matches(app, r["name"])]
    focus = None
    if matched:
        ages = [r["running_h"] for r in matched if r["running_h"] is not None]
        biggest = max(matched, key=lambda r: r["max_proc_gb"])
        focus = {
            "name": matched[0]["name"],
            "rss_gb": _gb(sum(r["_rss"] for r in matched)),
            "count": sum(r["count"] for r in matched),
            "running_h": max(ages) if ages else None,
            "max_proc_gb": biggest["max_proc_gb"],
            "max_proc_h": biggest["max_proc_h"],
        }
    for row in rows:
        row.pop("_rss")
    return {
        "used_pct": round(float(vm.percent), 1),
        "available_gb": _gb(vm.available),
        "total_gb": _gb(vm.total),
        "swap_used_pct": round(float(swap.percent), 1),
        "top": rows[:TOP_N],
        "focus": focus,
    }


_perf_probe("perf.memory", "Memory use", _p_memory, needs_optional=("app_name",))


# ── temperatures and fans ─────────────────────────────────────────────────

_CPU_SENSOR_PREFIXES = ("/intelcpu/", "/amdcpu/")
_DISTANCE_SUFFIX = " Distance to TjMax"
_PACKAGE_NAMES = ("CPU Package", "Core (Tctl/Tdie)")
_MAX_DEPTH = 64


def _blank_thermals() -> dict:
    return {
        "package_c": None,
        "core_max_c": None,
        "min_tjmax_distance_c": None,
        "tjmax_c": None,
        "package_w": None,
        "p_core_mhz": None,
        "fans": [],
        "gpu_temp_c": None,
    }


def _leaves(tree: object):
    """Every sensor leaf of an LHM tree, depth-capped (the tree comes over
    HTTP from a process this app does not control)."""
    stack = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict) or depth > _MAX_DEPTH:
            continue
        children = node.get("Children")
        if isinstance(children, list) and children:
            stack.extend((child, depth + 1) for child in children)
        elif isinstance(node.get("SensorId"), str):
            yield node


def parse_lhm_cpu(tree: object) -> dict:
    """CPU temperatures, headroom to TjMax, power, clock, fans and the GPU
    temperature from an LHM ``data.json`` tree. Only sensor values are read:
    no node names above the hardware level (the PC's name) are kept."""
    out = _blank_thermals()
    cores: dict[str, float] = {}
    distances: dict[str, float] = {}
    p_clocks: list[float] = []
    clocks: list[float] = []
    try:
        for leaf in _leaves(tree):
            sid, kind, text = leaf["SensorId"], leaf.get("Type"), str(leaf.get("Text") or "")
            value = lhm._parse_temp_value(leaf.get("Value", ""))
            if value is None:
                continue
            is_cpu = sid.startswith(_CPU_SENSOR_PREFIXES)
            if kind == "Fan":
                out["fans"].append({"name": text, "rpm": value})
            elif is_cpu and kind == "Temperature":
                if text.endswith(_DISTANCE_SUFFIX):
                    distances[text[: -len(_DISTANCE_SUFFIX)]] = value
                elif text in _PACKAGE_NAMES:
                    out["package_c"] = value
                elif text == "Core Max":
                    out["core_max_c"] = value
                else:
                    cores[text] = value
            elif is_cpu and kind == "Power" and text == "CPU Package":
                out["package_w"] = value
            elif is_cpu and kind == "Clock":
                (p_clocks if text.startswith("P-Core") else clocks).append(value)
            elif sid.startswith("/gpu-") and kind == "Temperature" and text == "GPU Core":
                out["gpu_temp_c"] = value
    except Exception:  # noqa: BLE001 -- a malformed tree reads as "no sensors", never an error
        return _blank_thermals()
    if out["core_max_c"] is None and cores:
        out["core_max_c"] = max(cores.values())
    if distances:
        out["min_tjmax_distance_c"] = min(distances.values())
        limits = [cores[name] + gap for name, gap in distances.items() if name in cores]
        out["tjmax_c"] = max(limits) if limits else None
    if p_clocks or clocks:
        out["p_core_mhz"] = max(p_clocks or clocks)
    return out


def _windows_thermals() -> dict | None:
    """Windows' own (rougher) sensors, used when LibreHardwareMonitor is not running."""
    try:
        data = thermals.get_thermals() or {}
    except Exception:  # noqa: BLE001 -- WMI wedged or missing -> no reading
        return None
    temps = [t.get("TempC") for t in data.get("temps") or [] if isinstance(t, dict)]
    temps = [float(t) for t in temps if isinstance(t, (int, float))]
    fans = []
    for fan in data.get("fans") or []:
        if isinstance(fan, dict):
            speed = fan.get("DesiredSpeed")
            fans.append(
                {
                    "name": str(fan.get("Name") or "Fan"),
                    "rpm": float(speed) if isinstance(speed, (int, float)) else None,
                }
            )
    if not temps and not fans:
        return None
    out = _blank_thermals()
    out["core_max_c"] = max(temps) if temps else None
    out["fans"] = fans
    return out


def _p_thermals(slots: dict) -> dict:
    tree = lhm._fetch_data_json()
    if tree:
        return {"source": "lhm", **parse_lhm_cpu(tree)}
    windows = _windows_thermals()
    if windows is not None:
        return {"source": "windows", **windows}
    return {"source": "none", **_blank_thermals()}


_perf_probe("perf.thermals", "Temperatures and fans", _p_thermals)


# ── graphics card ─────────────────────────────────────────────────────────


def _p_gpu(slots: dict) -> dict:
    try:
        data = gpu.get_gpu_metrics() or {}
    except Exception:  # noqa: BLE001 -- no GPU reader -> not available
        data = {}
    return {
        "available": bool(data.get("available")),
        "name": data.get("name") or "",
        "util_pct": data.get("utilization_pct"),
        "temp_c": data.get("temp_c"),
        "vram_pct": data.get("vram_pct"),
    }


_perf_probe("perf.gpu", "Graphics card", _p_gpu)


# ── stuck driver (#75 detector) ───────────────────────────────────────────


def _p_kernel(slots: dict) -> dict:
    # The same call the Temps & Power tab makes every 10 s; its minimum-interval
    # guard means an extra call never disturbs the stuck streaks.
    state = kernel_cpu.sample() or {}
    return {
        "available": bool(state.get("available")),
        "warming_up": bool(state.get("warming_up")),
        "busiest": state.get("busiest"),
        "stuck": list(state.get("stuck") or []),
    }


_perf_probe("perf.kernel", "Stuck driver check", _p_kernel)


# ── drive activity ────────────────────────────────────────────────────────


def _p_disk_busy(slots: dict) -> dict:
    import diagnose_storage_rules as dsr  # noqa: PLC0415 -- dsr imports diagnose, which imports this module

    data = dsp._io_sample(CPU_SAMPLE_S)
    try:
        drives = {d.get("disk_number"): d for d in dsp.collect_physical_disks().get("drives") or []}
    except Exception:  # noqa: BLE001 -- no drive list -> numbers only
        drives = {}
    for row in data.get("disks") or []:
        drive = drives.get(row.get("disk_number"))
        row["name"] = dsr._name(drive) if drive else f"Disk {row.get('disk_number')}"
    return data


_perf_probe("perf.disk_busy", "Drive activity", _p_disk_busy)


# ── hardware errors (crash bundle's WHEA reader) ──────────────────────────

WHEA_DAYS = 7


def _p_hw_errors(slots: dict) -> dict:
    whea = dcp._p_whea({}, days=WHEA_DAYS)
    parts = whea.get("by_component") or {}
    return {
        "processor": int(parts.get("processor") or 0),
        "memory": int(parts.get("memory") or 0),
        "pcie": int(parts.get("pcie") or 0),
        "fatal": int(whea.get("fatal") or 0),
        "corrected": int(whea.get("corrected") or 0),
        "last": whea.get("last"),
    }


_perf_probe("perf.hw_errors", "Hardware error reports", _p_hw_errors)


# ── since the last restart ────────────────────────────────────────────────

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def _values(series: list) -> list[float]:
    return [float(p["value"]) for p in series or [] if isinstance(p, dict) and isinstance(p.get("value"), (int, float))]


def _p_since_boot(slots: dict) -> dict:
    boot = psutil.boot_time()
    up_s = max(0.0, time.time() - boot)
    window = timedelta(seconds=up_s)
    memory = _values(metrics_history.get_series("memory_percent", window=window))
    temps = _values(metrics_history.get_series("cpu_temp_c", window=window))
    return {
        "uptime_h": round(up_s / 3600, 1),
        "boot": datetime.fromtimestamp(boot, tz=timezone.utc).strftime(_ISO),
        "memory_first_pct": memory[0] if memory else None,
        "memory_now_pct": memory[-1] if memory else None,
        "temp_max_c": max(temps) if temps else None,
        "samples": len(memory),
    }


_perf_probe("perf.since_boot", "Since the last restart", _p_since_boot)


# ── startup time ──────────────────────────────────────────────────────────

STARTUP_DAYS = 14
MAX_STARTUPS = 5
MAX_PROGRAM_NAMES = 30


def _utc(stamp: str) -> datetime:
    return datetime.strptime(stamp, _ISO).replace(tzinfo=timezone.utc)


def pair_startups(boots: list[str], signins: list[str]) -> list[dict]:
    """Each start (newest first, at most 5) with the first sign-in after it
    and before the next start. A start nobody signed in after is skipped
    rather than paired with a later start's sign-in."""
    starts = sorted({b for b in boots if isinstance(b, str)})
    logons = sorted({s for s in signins if isinstance(s, str)})
    rows = []
    for i, boot in enumerate(starts):
        nxt = starts[i + 1] if i + 1 < len(starts) else None
        signin = next((s for s in logons if s > boot and (nxt is None or s < nxt)), None)
        if signin is None:
            continue
        rows.append({"boot": boot, "signin": signin, "gap_s": round((_utc(signin) - _utc(boot)).total_seconds())})
    return list(reversed(rows))[:MAX_STARTUPS]


def _event_times(provider: str, event_id: int, unavailable: list[str]) -> list[str]:
    xpath = dcp.window_xpath(ids=[event_id], providers=[provider], days=STARTUP_DAYS)
    return [e.get("time") for e in dcp._query("System", xpath, unavailable, max_events=50) if isinstance(e, dict)]


# Per-user scheduled tasks end in the account's SID ("...Task-S-1-5-21-..."),
# which identifies the account; the redaction classes do not know it.
_SID_RE = re.compile(r"-?\bS-1-\d+(?:-\d+)+")


def _startup_programs() -> tuple[int | None, list[str]]:
    """Enabled startup programs by NAME only; their command lines carry user paths."""
    import windesktopmgr  # noqa: PLC0415 -- windesktopmgr imports diagnose, which imports this module

    try:
        items = windesktopmgr.get_startup_items() or []
    except Exception:  # noqa: BLE001 -- unreadable startup list -> unknown, not zero
        return None, []
    names = [
        _SID_RE.sub("", str(i.get("Name"))).strip()
        for i in items
        if isinstance(i, dict) and i.get("Enabled") and i.get("Name")
    ]
    return len(names), names[:MAX_PROGRAM_NAMES]


def _p_startup(slots: dict) -> dict:
    unavailable: list[str] = []
    boots = _event_times("Microsoft-Windows-Kernel-General", 12, unavailable)
    signins = _event_times("Microsoft-Windows-Winlogon", 7001, unavailable)
    rows = pair_startups(boots, signins)
    gaps = [r["gap_s"] for r in rows]
    count, names = _startup_programs()
    return {
        "boots": rows,
        "fastest_gap_s": min(gaps) if gaps else None,
        "median_gap_s": round(statistics.median(gaps)) if gaps else None,
        "last_gap_s": gaps[0] if gaps else None,
        "startup_programs": count,
        "program_names": names,
        "unavailable": list(dict.fromkeys(unavailable)),
    }


_perf_probe("perf.startup", "Startup time", _p_startup)


# ── power plan ────────────────────────────────────────────────────────────

_POWER_SCHEMES_KEY = r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
POWER_PLANS = {
    "381b4222-f694-41f0-9685-ff5bb260df2e": "Balanced",
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": "High performance",
    "a1841308-3541-4fab-bc81-f71556f20b4a": "Power saver",
    "e9a42b02-d5df-448d-aa00-03f14749eb61": "Ultimate performance",
}


def _p_power_plan(slots: dict) -> dict:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _POWER_SCHEMES_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, "ActivePowerScheme")
    except OSError:
        return {"scheme_guid": None, "name": "Unknown"}
    guid = str(value).strip().lower()
    return {"scheme_guid": guid, "name": POWER_PLANS.get(guid, "Custom")}


_perf_probe("perf.power_plan", "Power plan", _p_power_plan)


# ── escalation probes ─────────────────────────────────────────────────────

CPU_LONG_S = 15
APP_DETAIL_S = 10
TREND_DAYS = 7


def _p_cpu_long(slots: dict) -> dict:
    data = cpu_sample(CPU_LONG_S)
    data.pop("_all", None)
    return data


_perf_probe("perf.cpu_long", "What's using the CPU (15 s)", _p_cpu_long, timeout_s=20.0)


def _p_app_detail(slots: dict) -> dict:
    app = _focus_slot(slots)
    if app is None:
        top = cpu_sample(1).get("top") or []
        app = top[0]["name"] if top else None
    cpu_rows = [r for r in cpu_sample(APP_DETAIL_S).get("_all") or [] if app_matches(app, r["name"])]
    mem_rows = [r for r in _memory_groups() if app_matches(app, r["name"])]
    matched = sum(r["count"] for r in mem_rows) or sum(r["count"] for r in cpu_rows)
    ages = [r["running_h"] for r in mem_rows if r.get("running_h") is not None]
    return {
        "app": app,
        "matched": matched,
        "cpu_pct": round(sum(r["cpu_pct"] for r in cpu_rows), 1) if cpu_rows else None,
        "rss_gb": _gb(sum(r["_rss"] for r in mem_rows)) if mem_rows else None,
        "running_h": max(ages) if ages else None,
        # Helper processes beyond the first: Chrome's tabs, Teams' renderers.
        "children": max(0, matched - 1),
    }


_perf_probe("perf.app_detail", "App detail", _p_app_detail, timeout_s=15.0, needs_optional=("app_name",))


def _daily(series: list) -> list[dict]:
    days: dict[str, list[float]] = {}
    for point in series or []:
        if isinstance(point, dict) and isinstance(point.get("value"), (int, float)):
            days.setdefault(str(point.get("ts", ""))[:10], []).append(float(point["value"]))
    return [
        {"day": day, "max": max(vals), "median": round(statistics.median(vals), 1)}
        for day, vals in sorted(days.items())
        if day
    ][-TREND_DAYS:]


def _p_trend_7d(slots: dict) -> dict:
    window = timedelta(days=TREND_DAYS)
    return {
        m: _daily(metrics_history.get_series(m, window=window)) for m in ("memory_percent", "cpu_percent", "cpu_temp_c")
    }


_perf_probe("perf.trend_7d", "Last 7 days", _p_trend_7d)
