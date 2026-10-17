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
import time

import psutil

import diagnose_crash_probes as dcp
import diagnose_probes as dp
import diagnose_storage_probes as dsp
import gpu
import kernel_cpu
import lhm
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


def _cpu_snapshot() -> dict[int, tuple[str, float]]:
    """``{pid: (name, user+system seconds)}`` for every readable process,
    leaving out the idle pseudo-process and this app's own process."""
    me = os.getpid()
    out: dict[int, tuple[str, float]] = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "cpu_times"], ad_value=None):
        info = proc.info
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


def _memory_groups() -> list[dict]:
    """Programs by resident memory, same-name processes summed; ``running_h``
    is the oldest instance's age."""
    now = time.time()
    groups: dict[str, dict] = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "memory_info", "create_time"], ad_value=None):
        info = proc.info
        name, mem = info.get("name"), info.get("memory_info")
        if not name or mem is None or name.lower() in _IDLE_NAMES:
            continue
        row = groups.setdefault(
            name, {"name": name, "pid": info.get("pid"), "count": 0, "rss": 0, "_big": -1, "_t": None}
        )
        row["count"] += 1
        row["rss"] += mem.rss
        if mem.rss > row["_big"]:
            row["_big"], row["pid"] = mem.rss, info.get("pid")
        created = info.get("create_time")
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
        focus = {
            "name": matched[0]["name"],
            "rss_gb": _gb(sum(r["_rss"] for r in matched)),
            "count": sum(r["count"] for r in matched),
            "running_h": max(ages) if ages else None,
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
