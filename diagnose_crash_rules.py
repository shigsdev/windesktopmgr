"""Evidence-only verdicts for the Diagnose crash & stability class (spec 2026-10-09 §6).

``evaluate_crash_rules`` reads the crash probes' evidence and returns a full
verdict in ``diagnose._verdict``'s shape. Rules are tried in a fixed order and
the first that fires leads; context annotations (a hardware/BIOS change, a
recent install, storage trouble, Fast Startup) then add reasoning lines and
steps to whichever rule won.

Import cycle: ``diagnose`` reaches this module only through a wrapper it calls
at run time, and this module touches ``diagnose`` attributes only inside
functions, so either module can be imported first.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import diagnose as dg

WINDOW_DAYS = 7
CONTEXT_HOURS = 48
STORAGE_WINDOW_S = 3600
BOOT_FAILURE_SPAN_S = 1800
WHEA_CORRECTED_THRESHOLD = 10
APP_REPEAT_THRESHOLD = 3
SYSTEM_MODULE_APPS = 3
_ISO = "%Y-%m-%dT%H:%M:%SZ"
_COMPONENT_TEXT = {"processor": "processor", "memory": "memory", "pcie": "PCIe", "other": "other hardware"}


# ── time helpers ──────────────────────────────────────────────────────────


def _utc(ts: str) -> datetime:
    return datetime.strptime(ts, _ISO).replace(tzinfo=timezone.utc)


def _local(ts: str) -> datetime:
    """A probe's UTC timestamp in this machine's local time (tests pin the zone)."""
    return _utc(ts).astimezone()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _when(ts: str) -> str:
    """'23:37 on 2026-10-08' in local time."""
    loc = _local(ts)
    return f"{loc:%H:%M} on {loc:%Y-%m-%d}"


def _within(ts: str | None, start: datetime, end: datetime) -> bool:
    if not ts:
        return False
    try:
        t = _utc(ts)
    except ValueError:
        return False
    return start <= t <= end


# ── evidence access ───────────────────────────────────────────────────────


def _d(evidence: dict, key: str) -> dict:
    """A probe's data, or {} when it is missing or failed (no evidence)."""
    return dg._data(evidence, key) or {}


def _list(data: dict, key: str) -> list:
    value = data.get(key)
    return value if isinstance(value, list) else []


def _unexpected(evidence: dict) -> list[dict]:
    events = [
        e for e in _list(_d(evidence, "crash.unexpected_shutdowns"), "events") if isinstance(e, dict) and e.get("time")
    ]
    return sorted(events, key=lambda e: e["time"], reverse=True)


# ── rules: each returns (rule_key, verdict, incident_time) or None ────────

_STEPS = {
    "whea_fatal": [
        "Run Dell's built-in hardware test: restart, tap F12 at the Dell logo and choose Diagnostics.",
        "Run Windows Memory Diagnostic (Start, type 'Windows Memory Diagnostic') and let it restart the PC to test the memory.",
        "If the case was opened recently, check that the memory sticks and any add-in cards are fully seated.",
        "If a part was just replaced, contact whoever replaced it (or Dell support) with the time of these errors.",
    ],
    "bugcheck": [
        "Look up the stop code on the Blue Screens tab to see which driver or part it usually points to.",
        "Update or roll back the driver it names, especially one installed or updated just before the first crash.",
        "Check the Blue Screens tab for repeats: the same code every time points to one cause.",
    ],
    "hung_shutdown": [
        "Check that the power cable is firmly seated at the PC and the wall, and try a different outlet.",
        "Next time, try Restart instead of Shut down: if only shutting down hangs, note that.",
        "If it hangs again, write down the time and what was open, and look at the Event Log tab around then.",
    ],
    "power_button": [
        "Was the screen frozen before you held the button? If so, treat it as a freeze: the steps for a hard freeze apply.",
        "If it was not frozen, nothing is wrong: holding the button is simply recorded as an unclean shutdown.",
    ],
    "power_loss_or_freeze": [
        "Check the power cable, the outlet and any power strip or UPS the PC is plugged into.",
        "If it happens again, notice whether the lights and fans stay on (a freeze) or everything goes dark (power loss).",
        "If the PC froze, look at the Event Log tab for errors just before that time.",
    ],
    "boot_failure": [
        "Unplug any USB drives or devices added recently and try starting again.",
        "In BIOS setup (F2 at the Dell logo), check the boot order and that Secure Boot settings were not changed; the Documentation tab has the Secure Boot steps.",
        "If Windows keeps failing to start, let it run Startup Repair.",
    ],
    "app_crash_repeat": [
        "Update the app, or reinstall it if it is already up to date.",
        "If the crashing module belongs to an add-in, overlay or plug-in, disable that add-in and try again.",
        "Note the module and version listed here when you contact the app's support.",
    ],
}


def _rule_whea(evidence: dict):
    w = _d(evidence, "crash.whea")
    comps = w.get("by_component") if isinstance(w.get("by_component"), dict) else {}
    fatal = int(w.get("fatal") or 0)
    worst = max(("processor", "memory", "pcie", "other"), key=lambda c: int(comps.get(c) or 0))
    if not (fatal >= 1 or int(comps.get(worst) or 0) >= WHEA_CORRECTED_THRESHOLD):
        return None
    reasoning = (
        f"crash.whea: Windows' hardware error log recorded {fatal} serious and {int(w.get('corrected') or 0)} corrected "
        f"errors in the last {WINDOW_DAYS} days, mostly from the {_COMPONENT_TEXT[worst]}. Hardware errors can cause "
        "crashes that look like software problems, so they come first."
    )
    verdict = dg._verdict("likely", "local", f"Your hardware is reporting errors ({_COMPONENT_TEXT[worst]})", reasoning)
    return "whea_fatal", verdict, w.get("last"), ["crash.whea"]


def _rule_bugcheck(evidence: dict):
    import bsod

    checks = sorted(
        (b for b in _list(_d(evidence, "crash.bugchecks"), "bugchecks") if isinstance(b, dict) and b.get("time")),
        key=lambda b: b["time"],
        reverse=True,
    )
    coded = [e for e in _unexpected(evidence) if e.get("bugcheck_code")]
    if not checks and not coded:
        return None
    if checks:
        newest, code = checks[0]["time"], checks[0].get("code") or ""
        label = checks[0].get("name") or code
        repeats = sum(1 for b in checks if b.get("code") == code)
    else:
        newest = coded[0]["time"]
        code = f"0x{int(coded[0]['bugcheck_code']):08x}"
        label = bsod.BUGCHECK_CODES.get(code) or code
        repeats = sum(1 for e in coded if e.get("bugcheck_code") == coded[0]["bugcheck_code"])
    reasoning = f"crash.bugchecks / crash.unexpected_shutdowns: Windows stopped with a blue screen ({label}, {code}) at {_when(newest)}."
    if repeats > 1:
        reasoning += (
            f" The same code appears {repeats} times in the last {WINDOW_DAYS} days, which points to one cause."
        )
    verdict = dg._verdict("confident", "local", f"Blue screen: {label}", reasoning)
    return "bugcheck", verdict, newest, ["crash.bugchecks", "crash.unexpected_shutdowns"]


def _rule_hung_shutdown(evidence: dict):
    episodes = [
        ep
        for ep in _list(_d(evidence, "crash.power_timeline"), "episodes")
        if isinstance(ep, dict)
        and ep.get("shutdown_started_at")
        and ep.get("next_boot_unexpected")
        and int(ep.get("activity_after_shutdown_start") or 0) > 0
    ]
    if not episodes:
        return None
    ep = max(episodes, key=lambda e: e["shutdown_started_at"])
    parts = [
        f"crash.power_timeline: Windows began shutting down at {_when(ep['shutdown_started_at'])} but never finished."
    ]
    if ep.get("last_activity"):
        parts.append(f"Background activity carried on until {_when(ep['last_activity'])}.")
    if ep.get("last_alive"):
        parts.append(f"The PC was last alive at {_when(ep['last_alive'])}.")
    if ep.get("next_boot"):
        parts.append(
            f"The next start, at {_when(ep['next_boot'])}, recorded an unexpected shutdown with no blue screen "
            "(crash.unexpected_shutdowns)."
        )
    verdict = dg._verdict("likely", "local", "The PC got stuck shutting down", " ".join(parts))
    return "hung_shutdown", verdict, ep["shutdown_started_at"], ["crash.power_timeline", "crash.unexpected_shutdowns"]


def _rule_power_button(evidence: dict):
    pressed = [e for e in _unexpected(evidence) if e.get("power_button") or e.get("long_press")]
    if not pressed:
        return None
    t = pressed[0]["time"]
    reasoning = (
        f"crash.unexpected_shutdowns: at {_when(t)} Windows recorded that the power button was held to turn the PC off."
    )
    verdict = dg._verdict("confident", "local", "It was turned off by holding the power button", reasoning)
    return "power_button", verdict, t, ["crash.unexpected_shutdowns"]


def _rule_power_loss(evidence: dict):
    plain = [e for e in _unexpected(evidence) if not e.get("bugcheck_code")]
    if not plain:
        return None
    t = plain[0]["time"]
    reasoning = (
        f"crash.unexpected_shutdowns: at {_when(t)} Windows started again without having shut down cleanly, with no "
        "blue screen and no power-button press recorded. That pattern means the power was cut or the PC froze so "
        "hard it could not record anything."
    )
    verdict = dg._verdict("likely", "unknown", "The PC lost power or froze completely", reasoning)
    return "power_loss_or_freeze", verdict, t, ["crash.unexpected_shutdowns", "crash.power_timeline"]


def _rule_boot_failure(evidence: dict):
    b = _d(evidence, "crash.boot_health")
    failures = sorted(t for t in _list(b, "boot_failures") if isinstance(t, str))
    repairs = int(b.get("startup_repair_runs") or 0)
    clustered = any(
        (_utc(later) - _utc(earlier)).total_seconds() <= BOOT_FAILURE_SPAN_S
        for earlier, later in zip(failures, failures[1:], strict=False)
    )
    if not (clustered or repairs > 0):
        return None
    latest = failures[-1] if failures else None
    day = _local(latest).strftime("%Y-%m-%d") if latest else _now_utc().astimezone().strftime("%Y-%m-%d")
    n = max(1, sum(1 for t in failures if _local(t).strftime("%Y-%m-%d") == day))
    reasoning = f"crash.boot_health: {len(failures)} failed start(s) recorded"
    reasoning += f" and Startup Repair ran {repairs} time(s)." if repairs else "."
    verdict = dg._verdict("likely", "local", f"Windows failed to start {n} times on {day}", reasoning)
    return "boot_failure", verdict, latest, ["crash.boot_health"]


def _rule_app_repeat(evidence: dict):
    apps = [a for a in _list(_d(evidence, "crash.app_crashes"), "apps") if isinstance(a, dict)]
    repeat = next(
        (a for a in apps if int(a.get("crashes") or 0) + int(a.get("hangs") or 0) >= APP_REPEAT_THRESHOLD), None
    )
    if repeat is None:
        return None
    modules = repeat.get("modules") if isinstance(repeat.get("modules"), list) else []
    module = modules[0].get("module") if modules and isinstance(modules[0], dict) else ""
    module = module or "an unknown module"
    reasoning = (
        f"crash.app_crashes: {repeat['app']} crashed {int(repeat.get('crashes') or 0)} time(s) and stopped responding "
        f"{int(repeat.get('hangs') or 0)} time(s) in the last {WINDOW_DAYS} days, most often in {module}."
    )
    verdict = dg._verdict("likely", "local", f"{repeat['app']} keeps crashing in {module}", reasoning)
    return "app_crash_repeat", verdict, repeat.get("last"), ["crash.app_crashes"]


_RULES = (
    _rule_whea,
    _rule_bugcheck,
    _rule_hung_shutdown,
    _rule_power_button,
    _rule_power_loss,
    _rule_boot_failure,
    _rule_app_repeat,
)


# ── context annotations ───────────────────────────────────────────────────


def _context(evidence: dict, incident: str | None) -> tuple[list[str], list[str], list[str], list[str]]:
    """(hits, reasoning lines, extra steps, evidence refs) for the incident time."""
    hits: list[str] = []
    lines: list[str] = []
    steps: list[str] = []
    refs: list[str] = []
    if incident:
        try:
            t = _utc(incident)
        except ValueError:
            t = None
        if t is not None:
            before = t - timedelta(hours=CONTEXT_HOURS)
            changes = [
                c
                for c in _list(_d(evidence, "crash.hw_changes"), "changes")
                if isinstance(c, dict) and _within(c.get("time"), before, t)
            ]
            if changes:
                hits.append("hw_changed")
                refs.append("crash.hw_changes")
                for c in changes:
                    if c.get("old") == "<changed>":
                        lines.append(f"At {_when(c['time'])}, {c.get('field')} changed.")
                    else:
                        lines.append(
                            f"At {_when(c['time'])}, {c.get('field')} changed from {c.get('old')} to {c.get('new')}."
                        )
                steps.append(
                    "A hardware or BIOS change was recorded shortly before this. If a part was just replaced, tell "
                    "whoever replaced it what happened and when."
                )
            installs = [
                i
                for i in _list(_d(evidence, "crash.recent_changes"), "installs")
                if isinstance(i, dict) and _within(i.get("time"), before, t)
            ]
            if installs:
                hits.append("recent_install")
                refs.append("crash.recent_changes")
                names = ", ".join(str(i.get("name")) for i in installs[:3])
                lines.append(f"Installed in the {CONTEXT_HOURS} hours before: {names}.")
                steps.append(
                    f"Something was installed shortly before ({names}); if the trouble started then, update or roll it back."
                )
            s = _d(evidence, "crash.storage_errors")
            near = timedelta(seconds=STORAGE_WINDOW_S)
            storage_times = [p.get("last") for p in (s.get("by_provider") or {}).values() if isinstance(p, dict)]
            storage_times += _list(s, "pool_times")
            storage_times += [f.get("time") for f in _list(s, "storage_service_faults") if isinstance(f, dict)]
            if any(_within(x, t - near, t + near) for x in storage_times):
                hits.append("storage_trouble")
                refs.append("crash.storage_errors")
                lines.append("Disk or storage errors were logged within an hour of this (crash.storage_errors).")
                steps.append("Disk or storage errors were logged around the same time: check the Storage tab.")
    if _d(evidence, "crash.power_config").get("fast_startup") is True:
        hits.append("fast_startup")
        refs.append("crash.power_config")
        lines.append("Fast Startup is on, so some 'shutdowns' are really hibernation; shutdown times may read oddly.")
    return hits, lines, steps, refs


def _system_module_apps(evidence: dict) -> int:
    apps = _list(_d(evidence, "crash.app_crashes"), "apps")
    return sum(1 for a in apps if isinstance(a, dict) and int(a.get("system_module_crashes") or 0) > 0)


# ── entry point ───────────────────────────────────────────────────────────


def evaluate_crash_rules(evidence: dict[str, dict]) -> dict:
    """Evidence-only verdict for the ``crashes`` class; always a full verdict."""
    evidence = evidence if isinstance(evidence, dict) else {}
    hit = next((r for r in (rule(evidence) for rule in _RULES) if r is not None), None)
    if hit is None:
        since = (_now_utc() - timedelta(days=WINDOW_DAYS)).astimezone().strftime("%Y-%m-%d")
        verdict = dg._verdict(
            "inconclusive",
            "unknown",
            f"No crashes or unexpected shutdowns recorded since {since}",
            "None of the crash, shutdown, startup, hardware-error or app-crash records in the last "
            f"{WINDOW_DAYS} days point to a cause.",
            rule_hits=["nothing_found"],
        )
        return verdict
    key, verdict, incident, refs = hit
    hits, lines, extra_steps, context_refs = _context(evidence, incident)
    verdict["rule_hits"] = [key, *hits]
    if lines:
        verdict["reasoning"] = " ".join([verdict["reasoning"], *lines])
    verdict["evidence_refs"] = list(dict.fromkeys([*refs, *context_refs]))
    verdict["manual_steps"] = dg.clean_steps([*_STEPS[key], *extra_steps])
    # Damaged system files are the one cause a vetted action can fix, and only
    # when several different apps crash inside Windows' own modules. Never on
    # top of a hardware-error verdict: bad hardware causes those crashes too.
    if key != "whea_fatal" and _system_module_apps(evidence) >= SYSTEM_MODULE_APPS:
        verdict["rule_hits"].append("system_modules")
        verdict["suggested_actions"] = ["repair_image"]
        verdict["reasoning"] += (
            f" {_system_module_apps(evidence)} different apps crashed inside Windows' own system files, which "
            "suggests damaged system files."
        )
    return verdict
