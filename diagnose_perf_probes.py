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

import diagnose_probes as dp

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
