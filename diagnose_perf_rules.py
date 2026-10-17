"""Evidence-only verdicts for the Diagnose speed & heat class (spec 2026-10-17 §6).

``evaluate_perf_rules`` reads the perf probes' evidence and returns a full
verdict in ``diagnose._verdict``'s shape. Rules run in a fixed order --
hardware risk (heat, a stuck driver) first, then what is slowing the PC,
then housekeeping -- and the first that fires leads. When the user named an
app, the CPU and memory rules first look only at that app; a heat risk found
elsewhere is still said. Context annotations then add reasoning lines to
whichever rule won.

Import cycle: ``diagnose`` reaches this module only through a wrapper it calls
at run time, and this module touches ``diagnose`` attributes only inside
functions, so either module can be imported first.
"""

from __future__ import annotations

import diagnose as dg

THROTTLE_DISTANCE_C = 2
HOT_CPU_C = 90
HOT_GPU_C = 87
HOG_PCT = 50
HOG_TOTAL_PCT = 90
HOG_TOP_PCT = 25
MEM_USED_PCT = 90
MEM_AVAIL_GB = 2
SWAP_PCT = 80
CREEP_UPTIME_H = 48
CREEP_POINTS = 25
CREEP_APP_GB = 4
CREEP_APP_H = 24
DISK_BUSY_PCT = 90
GPU_BUSY_PCT = 95
SLOW_START_S = 120
LONG_UPTIME_H = 168
SINCE_BOOT_NOTE_POINTS = 10
_HEAT_RISKS = ("thermal_throttling", "running_hot")
_REBOOT_RULES = ("memory_creep", "long_uptime")


# ── evidence helpers ──────────────────────────────────────────────────────


def _d(ev: dict, key: str) -> dict:
    """A probe's data, or ``{}`` when it is missing or did not run cleanly."""
    result = ev.get(key)
    if isinstance(result, dict) and result.get("ok") is True and isinstance(result.get("data"), dict):
        return result["data"]
    return {}


def _num(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _rows(data: dict, focus: bool) -> list[dict]:
    """The rows a CPU/memory rule considers: the named app's, or the top programs."""
    if focus:
        row = data.get("focus")
        return [row] if isinstance(row, dict) else []
    return [r for r in data.get("top") or [] if isinstance(r, dict)]


def _whole(value: float) -> str:
    return f"{value:.0f}"


def _gb(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def _duration(seconds: float) -> str:
    minutes, secs = divmod(round(seconds), 60)
    if not minutes:
        return f"{secs} s"
    return f"{minutes} min {secs} s" if secs else f"{minutes} min"


def _cpu_temp(t: dict) -> float | None:
    temps = [v for v in (_num(t.get("core_max_c")), _num(t.get("package_c"))) if v is not None]
    return max(temps) if temps else None


def _gpu_temp(ev: dict) -> float | None:
    temps = [
        v
        for v in (_num(_d(ev, "perf.gpu").get("temp_c")), _num(_d(ev, "perf.thermals").get("gpu_temp_c")))
        if v is not None
    ]
    return max(temps) if temps else None


# ── rules: each (evidence, focus) -> (key, verdict, evidence_refs, app) | None ──


def _rule_thermal_throttling(ev: dict, focus: bool):
    t = _d(ev, "perf.thermals")
    distance = _num(t.get("min_tjmax_distance_c"))
    if focus or distance is None or distance > THROTTLE_DISTANCE_C:
        return None
    temp = _cpu_temp(t) or _num(t.get("tjmax_c"))
    headline = (
        f"Your CPU hit {_whole(temp)} °C and is slowing itself down to cool off"
        if temp is not None
        else "Your CPU is at its temperature limit and is slowing itself down to cool off"
    )
    reasoning = (
        f"During the check a CPU core was {_whole(distance)} °C from its limit (TjMax), the point where the "
        "processor cuts its own speed to protect itself. A hot CPU is a slow CPU."
    )
    return "thermal_throttling", dg._verdict("confident", "local", headline, reasoning), ["perf.thermals"], None


def _rule_running_hot(ev: dict, focus: bool):
    if focus:
        return None
    cpu = _cpu_temp(_d(ev, "perf.thermals"))
    if cpu is not None and cpu >= HOT_CPU_C:
        headline = f"Your CPU is running hot ({_whole(cpu)} °C)"
        reasoning = f"The CPU reached {_whole(cpu)} °C during the check; above {HOT_CPU_C} °C it is close to slowing itself down."
        return "running_hot", dg._verdict("likely", "local", headline, reasoning), ["perf.thermals"], None
    gpu = _gpu_temp(ev)
    if gpu is not None and gpu >= HOT_GPU_C:
        headline = f"Your graphics card is running hot ({_whole(gpu)} °C)"
        reasoning = f"The graphics card reached {_whole(gpu)} °C during the check, above the {HOT_GPU_C} °C where it starts to slow down."
        return "running_hot", dg._verdict("likely", "local", headline, reasoning), ["perf.gpu", "perf.thermals"], None
    return None


def _rule_stuck_driver(ev: dict, focus: bool):
    stuck = [s for s in _d(ev, "perf.kernel").get("stuck") or [] if isinstance(s, dict)]
    if focus or not stuck:
        return None
    worst = stuck[0]
    reasoning = (
        f"A thread inside Windows' own System process has kept about {_whole(_num(worst.get('pct')) or 0)}% of one "
        f"CPU core busy for {_whole(_num(worst.get('minutes')) or 0)} minutes. That is a driver, not an app."
    )
    verdict = dg._verdict("confident", "local", "A Windows driver is pinning a CPU core", reasoning)
    return "stuck_driver", verdict, ["perf.kernel"], None


def _rule_cpu_hog(ev: dict, focus: bool):
    c = _d(ev, "perf.cpu")
    rows = _rows(c, focus)
    if not rows:
        return None
    top = max(rows, key=lambda r: _num(r.get("cpu_pct")) or 0)
    pct = _num(top.get("cpu_pct")) or 0
    total = _num(c.get("total_pct")) or 0
    if not (pct >= HOG_PCT or (total >= HOG_TOTAL_PCT and pct >= HOG_TOP_PCT)):
        return None
    app = str(top.get("name") or "One app")
    count = int(top.get("count") or 1)
    copies = f" across {count} processes" if count > 1 else ""
    reasoning = f"During a {_whole(_num(c.get('seconds')) or 3)}-second sample {app} used {_whole(pct)}% of the whole CPU{copies}; the PC as a whole was {_whole(total)}% busy."
    verdict = dg._verdict("likely", "local", f"{app} is using {_whole(pct)}% of the CPU", reasoning)
    return "cpu_hog", verdict, ["perf.cpu"], app


def _rule_memory_low(ev: dict, focus: bool):
    m = _d(ev, "perf.memory")
    used, avail, swap = _num(m.get("used_pct")), _num(m.get("available_gb")), _num(m.get("swap_used_pct"))
    low = (
        (used is not None and used >= MEM_USED_PCT)
        or (avail is not None and avail < MEM_AVAIL_GB)
        or (swap is not None and swap >= SWAP_PCT)
    )
    rows = _rows(m, focus)
    if not low or (focus and not rows):
        return None
    biggest = max(rows, key=lambda r: _num(r.get("rss_gb")) or 0) if rows else None
    headline = f"Memory is nearly full ({_whole(used or 0)}%)"
    app = None
    if biggest is not None and _num(biggest.get("rss_gb")):
        app = str(biggest.get("name"))
        headline += f"; {app} is using {_gb(_num(biggest['rss_gb']))} GB"
    reasoning = (
        f"{_whole(used or 0)}% of memory was in use with {_gb(avail or 0)} GB free"
        + (f" and the page file {_whole(swap)}% full" if swap is not None else "")
        + ". When memory runs out Windows moves work to the much slower drive."
    )
    return "memory_low", dg._verdict("confident", "local", headline, reasoning), ["perf.memory"], app


def _rule_memory_creep(ev: dict, focus: bool):
    for row in _rows(_d(ev, "perf.memory"), focus):
        gb, hours = _num(row.get("rss_gb")), _num(row.get("running_h"))
        if gb is not None and hours is not None and gb >= CREEP_APP_GB and hours >= CREEP_APP_H:
            app = str(row.get("name"))
            headline = f"{app} has grown to {_gb(gb)} GB after {_whole(hours)} hours"
            reasoning = f"{app} has been running for {_whole(hours)} hours and now uses {_gb(gb)} GB of memory; apps that grow like this are leaking memory."
            return "memory_creep", dg._verdict("likely", "local", headline, reasoning), ["perf.memory"], app
    if focus:
        return None
    s = _d(ev, "perf.since_boot")
    up, first, now = _num(s.get("uptime_h")), _num(s.get("memory_first_pct")), _num(s.get("memory_now_pct"))
    if up is None or first is None or now is None or up < CREEP_UPTIME_H or now - first < CREEP_POINTS:
        return None
    days = round(up / 24)
    headline = f"Memory has crept from {_whole(first)}% to {_whole(now)}% over the {days} days since the last restart"
    reasoning = "Memory use has climbed steadily since the last restart without dropping back, so something is holding on to memory."
    return "memory_creep", dg._verdict("likely", "local", headline, reasoning), ["perf.since_boot", "perf.memory"], None


def _rule_disk_busy(ev: dict, focus: bool):
    disks = [d for d in _d(ev, "perf.disk_busy").get("disks") or [] if isinstance(d, dict)]
    busy = [d for d in disks if (_num(d.get("busy_pct")) or 0) >= DISK_BUSY_PCT]
    if focus or not busy:
        return None
    worst = max(busy, key=lambda d: _num(d.get("busy_pct")) or 0)
    name = str(worst.get("name") or f"Disk {worst.get('disk_number')}")
    pct = _whole(_num(worst["busy_pct"]))
    reasoning = f"{name} was {pct}% busy during the check, so anything waiting on that drive waits in line."
    verdict = dg._verdict("likely", "local", f"{name} was {pct}% busy during the check", reasoning)
    return "disk_busy", verdict, ["perf.disk_busy"], None


def _rule_gpu_busy(ev: dict, focus: bool):
    util = _num(_d(ev, "perf.gpu").get("util_pct"))
    if focus or util is None or util < GPU_BUSY_PCT:
        return None
    reasoning = f"The graphics card was {_whole(util)}% busy during the check: something is using all of it."
    verdict = dg._verdict("likely", "local", f"The graphics card is fully loaded ({_whole(util)}%)", reasoning)
    return "gpu_busy", verdict, ["perf.gpu"], None


def _rule_power_saver(ev: dict, focus: bool):
    if focus or _d(ev, "perf.power_plan").get("name") != "Power saver":
        return None
    reasoning = "The active Windows power plan is Power saver, which holds the CPU's speed down to save energy."
    verdict = dg._verdict("confident", "local", "Windows' power-saving mode is limiting the CPU", reasoning)
    return "power_saver", verdict, ["perf.power_plan"], None


def _rule_slow_startup(ev: dict, focus: bool):
    st = _d(ev, "perf.startup")
    fastest, last = _num(st.get("fastest_gap_s")), _num(st.get("last_gap_s"))
    # Only the FASTEST recent gap counts: any single gap includes however long
    # the PC sat at the sign-in screen (a restart after a crash overnight).
    if focus or fastest is None or fastest <= SLOW_START_S:
        return None
    shown = last if last is not None else fastest
    headline = f"The last startup took {_duration(shown)} to reach sign-in"
    programs = st.get("startup_programs")
    if isinstance(programs, int):
        headline += f"; {programs} programs start automatically"
    reasoning = (
        "Times run from Windows starting to you signing in, so they include time spent at the sign-in screen; "
        f"even the quickest recent startup took {_duration(fastest or 0)}."
    )
    return "slow_startup", dg._verdict("likely", "local", headline, reasoning), ["perf.startup"], None


def _rule_long_uptime(ev: dict, focus: bool):
    up = _num(_d(ev, "perf.since_boot").get("uptime_h"))
    if focus or up is None or up < LONG_UPTIME_H:
        return None
    days = int(up // 24)
    reasoning = f"The PC has been running for {days} days. Over time apps and Windows build up memory and leftover work that a restart clears."
    verdict = dg._verdict("likely", "local", f"The PC hasn't been restarted in {days} days", reasoning)
    return "long_uptime", verdict, ["perf.since_boot"], None


_RULES = (
    _rule_thermal_throttling,
    _rule_running_hot,
    _rule_stuck_driver,
    _rule_cpu_hog,
    _rule_memory_low,
    _rule_memory_creep,
    _rule_disk_busy,
    _rule_gpu_busy,
    _rule_power_saver,
    _rule_slow_startup,
    _rule_long_uptime,
)


# ── steps ─────────────────────────────────────────────────────────────────

_HEAT_STEPS = [
    "Check that the fans spin and the vents are clear and not dusty.",
    "If the PC was recently opened or repaired, have the CPU cooler and heat sinks checked.",
    "Avoid long heavy work (games, video exports) until it is fixed.",
    "Watch the temperatures on the Temps & Power tab.",
]
_MEMORY_STEPS = [
    "Restart {app}.",
    "If the same app grows every time, update it: it is leaking memory.",
    "If memory is full every day, consider adding more RAM.",
    "Restarting the PC clears it for now.",
]
_STEPS = {
    "thermal_throttling": _HEAT_STEPS,
    "running_hot": _HEAT_STEPS,
    "stuck_driver": [
        "Open the Temps & Power tab and click Identify driver to name the driver.",
        "Update or roll back that driver (Device Manager, or the maker's website).",
    ],
    "cpu_hog": [
        "Close or restart {app}.",
        "If it's a web browser, close tabs or extensions you don't need.",
        "If it's MsMpEng.exe, that's a Windows Defender scan: it usually finishes on its own.",
        "Check the Processes tab to see what it's doing.",
    ],
    "memory_low": _MEMORY_STEPS,
    "memory_creep": _MEMORY_STEPS,
    "disk_busy": [
        "Check the Processes tab for what's reading or writing to the drive.",
        "For a full drive check, run Diagnose again with 'my drive is slow'.",
    ],
    "gpu_busy": ["A game, video or AI app is using the graphics card; close it if you didn't mean it to run."],
    "power_saver": ["Open Settings › System › Power › Power mode and choose Balanced or Best performance."],
    "slow_startup": ["Turn off programs you don't need on the Startup tab."],
    "long_uptime": ["Restart the PC."],
}


# ── context annotations ───────────────────────────────────────────────────


def _context(ev: dict, key: str) -> tuple[list[str], list[str]]:
    hits: list[str] = []
    lines: list[str] = []
    h = _d(ev, "perf.hw_errors")
    processor, memory = int(_num(h.get("processor")) or 0), int(_num(h.get("memory")) or 0)
    if processor or memory:
        hits.append("hw_errors")
        what = " and ".join(
            p for p in (f"{processor} processor" if processor else "", f"{memory} memory" if memory else "") if p
        )
        lines.append(
            f"Windows also logged {what} hardware errors this week; heat and these errors often go together -- "
            "have the cooling checked."
        )
    source = _d(ev, "perf.thermals").get("source")
    if source in ("windows", "none"):
        hits.append("sensors_fallback")
        lines.append(
            "LibreHardwareMonitor isn't running, so temperatures came from Windows' rougher sensors"
            + (" (none could be read)." if source == "none" else ".")
        )
    s = _d(ev, "perf.since_boot")
    first, now, peak = _num(s.get("memory_first_pct")), _num(s.get("memory_now_pct")), _num(s.get("temp_max_c"))
    notes = []
    if key != "memory_creep" and first is not None and now is not None and now - first >= SINCE_BOOT_NOTE_POINTS:
        notes.append(f"memory use went from {_whole(first)}% to {_whole(now)}%")
    if key not in _HEAT_RISKS and peak is not None and peak >= HOT_CPU_C:
        notes.append(f"the CPU reached {_whole(peak)} °C")
    if notes:
        hits.append("since_boot")
        lines.append("Since the last restart " + " and ".join(notes) + ".")
    return hits, lines


def _unread_sources(ev: dict) -> list[str]:
    out = [
        k
        for k, r in ev.items()
        if isinstance(k, str) and k.startswith("perf.") and isinstance(r, dict) and r.get("ok") is not True
    ]
    out += [str(c) for c in _d(ev, "perf.startup").get("unavailable") or []]
    return list(dict.fromkeys(out))


def _first_hit(ev: dict, focus: bool):
    return next((hit for hit in (rule(ev, focus) for rule in _RULES) if hit is not None), None)


# ── entry point ───────────────────────────────────────────────────────────


def evaluate_perf_rules(evidence: dict[str, dict]) -> dict:
    """Evidence-only verdict for the ``performance`` class; always a full verdict."""
    ev = evidence if isinstance(evidence, dict) else {}
    named = isinstance(_d(ev, "perf.cpu").get("focus_app"), str)
    scoped = _first_hit(ev, True) if named else None
    wide = _first_hit(ev, False)
    hit = scoped or wide
    # The named app leads, but a heat risk elsewhere is still said.
    also = wide if scoped is not None and wide is not None and wide[0] in _HEAT_RISKS else None
    if hit is None:
        verdict = dg._verdict(
            "inconclusive",
            "unknown",
            "Nothing is slowing the PC down right now",
            "The CPU, memory, temperatures, graphics card, drives, stuck-driver check, power plan, startup times "
            "and the time since the last restart show nothing slowing the PC down.",
            rule_hits=["nothing_found"],
            manual_steps=["If the slowness comes and goes, run Diagnose again while it is happening."],
        )
        hits, lines = _context(ev, "nothing_found")
        verdict["rule_hits"] += hits
        unread = _unread_sources(ev)
        if unread:
            lines.append(f"Some checks could not run ({', '.join(unread)}), so a problem there could have been missed.")
        if lines:
            verdict["reasoning"] = " ".join([verdict["reasoning"], *lines])
        return verdict
    key, verdict, refs, app = hit
    hits, lines = _context(ev, key)
    verdict["rule_hits"] = [key, *hits]
    if lines:
        verdict["reasoning"] = " ".join([verdict["reasoning"], *lines])
    verdict["evidence_refs"] = refs
    steps = [s.format(app=app or "the busy app") for s in _STEPS[key]]
    # Restarting is the one vetted action, and it only helps memory that has
    # built up over time; nothing else earns it.
    if key in _REBOOT_RULES:
        verdict["suggested_actions"] = ["reboot_system"]
        steps.append("The Restart button below restarts the PC; save your work first.")
    if also is not None:
        verdict["rule_hits"].append(f"also_{also[0]}")
        verdict["reasoning"] += f" Also: {also[1]['headline']}."
    verdict["manual_steps"] = dg.clean_steps(steps)
    return verdict
