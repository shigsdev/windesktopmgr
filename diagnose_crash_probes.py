"""Crash & stability evidence for the Diagnose engine (spec 2026-10-09).

Read-only probes over the Windows event logs, crash dumps, the BIOS audit and
a few registry values, registered into ``diagnose_probes.PROBES`` alongside
the network bundle. Event logs are read in-process through pywin32
``win32evtlog`` (Python-first per CLAUDE.md), never through PowerShell.

Privacy (spec §7): probes return summaries only -- times, ids, providers,
levels and named EventData fields. The rendered event ``Message`` text is
never read, which also keeps each query fast (no publisher metadata loads).
All times are UTC ISO strings ending in ``Z``.
"""

from __future__ import annotations

import concurrent.futures
import os
import xml.etree.ElementTree as ET  # noqa: S405 -- parses Event Log service XML, not user input
from collections.abc import Iterable
from datetime import datetime, timezone

import diagnose_probes as dp

try:
    import win32evtlog
except ImportError:  # pragma: no cover -- non-Windows dev boxes
    win32evtlog = None

WINDOW_DAYS = 7
_DAY_MS = 86_400_000
_EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EvtUnavailable(Exception):
    """An event-log channel could not be opened (missing, access denied, no pywin32)."""

    def __init__(self, channel: str, reason: str):
        super().__init__(f"{channel}: {reason}")
        self.channel = channel
        self.reason = reason


def _norm_time(raw: str) -> str:
    """'2026-10-09T12:17:51.1234567Z' -> '2026-10-09T12:17:51Z' (second precision, UTC)."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    return raw.split(".", 1)[0].rstrip("Z") + "Z"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_event(xml_str: str) -> dict | None:
    """One event's XML -> the summary dict, or None when it can't be parsed."""
    try:
        root = ET.fromstring(xml_str)  # noqa: S314 -- Event Log service serialisation, no DTDs
    except ET.ParseError:
        return None
    system = root.find(f"{_EVT_NS}System")
    if system is None:
        return None
    eid_el = system.find(f"{_EVT_NS}EventID")
    level_el = system.find(f"{_EVT_NS}Level")
    time_el = system.find(f"{_EVT_NS}TimeCreated")
    prov_el = system.find(f"{_EVT_NS}Provider")
    try:
        eid = int((eid_el.text or "0") if eid_el is not None else "0")
    except ValueError:
        eid = 0
    try:
        level = int(level_el.text) if level_el is not None and level_el.text else 0
    except ValueError:
        level = 0
    data: dict[str, str] = {}
    data_list: list[str] = []
    event_data = root.find(f"{_EVT_NS}EventData")
    if event_data is not None:
        for item in event_data:
            value = (item.text or "").strip()
            data_list.append(value)
            name = item.get("Name")
            if name:
                data[name] = value
    user_data = root.find(f"{_EVT_NS}UserData")
    if user_data is not None:
        for item in user_data.iter():
            if len(item) == 0 and item is not user_data:
                data[_local_name(item.tag)] = (item.text or "").strip()
    return {
        "id": eid,
        "time": _norm_time(time_el.get("SystemTime", "") if time_el is not None else ""),
        "provider": prov_el.get("Name", "") if prov_el is not None else "",
        "level": level,
        "data": data,
        "data_list": data_list,
    }


def evt_query(channel: str, xpath: str, max_events: int = 200, timeout_s: float = 10.0) -> list[dict]:
    """Events from ``channel`` matching ``xpath``, newest first, at most ``max_events``.

    Raises ``EvtUnavailable`` when the channel cannot be opened, so a probe can
    report which source it could not read. A timeout returns ``[]``; an event
    that cannot be rendered or parsed is skipped.
    """
    if win32evtlog is None:
        raise EvtUnavailable(channel, "pywin32 is not installed")
    api = win32evtlog
    try:
        handle = api.EvtQuery(channel, api.EvtQueryReverseDirection | api.EvtQueryChannelPath, xpath)
    except Exception as exc:  # noqa: BLE001 -- pywintypes.error and friends: the channel is unreadable
        raise EvtUnavailable(channel, str(exc)) from exc

    def _drain() -> list[dict]:
        out: list[dict] = []
        while len(out) < max_events:
            try:
                batch = api.EvtNext(handle, min(100, max_events - len(out)))
            except Exception:  # noqa: BLE001 -- end of results or a broken handle
                break
            if not batch:
                break
            for evt in batch:
                try:
                    xml_str = api.EvtFormatMessage(None, evt, api.EvtFormatMessageXml)
                except Exception:  # noqa: BLE001 -- one bad event must not lose the rest
                    continue
                parsed = _parse_event(xml_str)
                if parsed is not None:
                    out.append(parsed)
        return out[:max_events]

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return ex.submit(_drain).result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        return []
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def window_xpath(
    ids: Iterable[int] | None = None,
    providers: Iterable[str] | None = None,
    levels: Iterable[int] | None = None,
    days: int = WINDOW_DAYS,
    start: str | None = None,
    end: str | None = None,
) -> str:
    """An EvtQuery XPath filter. With both ``start`` and ``end`` the window is
    absolute (UTC ISO); otherwise it is the last ``days`` days."""
    parts: list[str] = []
    if ids:
        parts.append("(" + " or ".join(f"EventID={int(i)}" for i in ids) + ")")
    if providers:
        parts.append("Provider[" + " or ".join(f"@Name='{p}'" for p in providers) + "]")
    if levels:
        parts.append("(" + " or ".join(f"Level={int(lv)}" for lv in levels) + ")")
    if start and end:
        parts.append(f"TimeCreated[@SystemTime>='{start}' and @SystemTime<='{end}']")
    else:
        parts.append(f"TimeCreated[timediff(@SystemTime) <= {int(days) * _DAY_MS}]")
    return f"*[System[{' and '.join(parts)}]]"


# How long after a boot the "unexpected shutdown" / "dirty shutdown" records
# can be logged and still describe the shutdown that preceded that boot.
_BOOT_REPORT_WINDOW_S = 600


def _seconds_between(a: str, b: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (datetime.strptime(b, fmt) - datetime.strptime(a, fmt)).total_seconds()


def derive_episodes(events: list[dict]) -> list[dict]:
    """Split a boot/shutdown timeline into episodes, oldest first.

    An episode runs from one ``boot`` to the next (or, for the first, from the
    start of the window). It records when a shutdown was requested and when
    Windows began shutting down, and whether the NEXT boot logged an
    unexpected shutdown (41) -- with the last-alive time (6008) when it did.
    """
    ordered = sorted(events, key=lambda e: e.get("time") or "")
    episodes: list[dict] = []
    current: dict | None = None

    def new(boot: str | None) -> dict:
        return {
            "boot": boot,
            "next_boot": None,
            "shutdown_requested_at": None,
            "shutdown_started_at": None,
            "next_boot_unexpected": False,
            "last_alive": None,
        }

    for ev in ordered:
        kind, when = ev.get("kind"), ev.get("time")
        if kind == "boot":
            if current is not None:
                current["next_boot"] = when
            current = new(when)
            episodes.append(current)
            continue
        if current is None:
            current = new(None)
            episodes.append(current)
        previous = episodes[-2] if len(episodes) > 1 else None
        just_booted = (
            previous is not None
            and current["boot"] is not None
            and _seconds_between(current["boot"], when) <= _BOOT_REPORT_WINDOW_S
        )
        if kind == "unexpected" and just_booted:
            previous["next_boot_unexpected"] = True
        elif kind == "dirty_noted" and just_booted:
            previous["next_boot_unexpected"] = True
            previous["last_alive"] = ev.get("last_alive") or previous["last_alive"]
        elif kind == "shutdown_requested" and current["shutdown_requested_at"] is None:
            current["shutdown_requested_at"] = when
        elif kind == "shutdown_started" and current["shutdown_started_at"] is None:
            current["shutdown_started_at"] = when
    return episodes


def activity_between(start: str, end: str, cap: int = 500) -> tuple[int, str | None]:
    """How many System + Application events fall between ``start`` and ``end``,
    and the latest of their times. An unreadable log counts as none."""
    xpath = window_xpath(start=start, end=end)
    count, last = 0, None
    for channel in ("System", "Application"):
        try:
            events = evt_query(channel, xpath, max_events=cap)
        except EvtUnavailable:
            continue
        count += len(events)
        for ev in events:
            if ev["time"] and (last is None or ev["time"] > last):
                last = ev["time"]
    return count, last


# ---------------------------------------------------------------------------
# Probes. Each queries by id/provider AND re-checks both in Python, so an id
# reused by another provider never leaks in. Spec §5.1 / plan Tasks 5-6.
# ---------------------------------------------------------------------------

_REDACT = ("username", "serial", "mac", "self_host")
REGISTERED: dict[str, dp.Probe] = {}

# The local zone that 6008's "last alive" time is written in. None = this
# machine's zone (tests pin it).
_LOCAL_TZ = None

STARTUP_REPAIR_CHANNEL = "Microsoft-Windows-StartupRepair/Operational"
BOOT_PERF_CHANNEL = "Microsoft-Windows-Diagnostics-Performance/Operational"
MAX_TIMELINE_EVENTS = 50
MAX_MINIDUMPS = 10


def _crash_probe(key: str, label: str, fn, timeout_s: float = 10.0, **kw) -> dp.Probe:
    probe = dp.register(dp.Probe(key, label, "crash", fn, redact=_REDACT, timeout_s=timeout_s, **kw))
    REGISTERED[key] = probe
    return probe


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local_to_utc(time_str: str, date_str: str) -> str | None:
    """6008 writes the last-alive time as local, locale-formatted text
    ("4:45:35 AM", "10/9/2026" wrapped in direction marks). UTC ISO, or None."""
    clean = " ".join(s.replace("\u200e", "").replace("\u200f", "").strip() for s in (time_str, date_str))
    for fmt in ("%I:%M:%S %p %m/%d/%Y", "%H:%M:%S %m/%d/%Y"):
        try:
            naive = datetime.strptime(clean, fmt)
        except ValueError:
            continue
        local = naive.replace(tzinfo=_LOCAL_TZ) if _LOCAL_TZ is not None else naive.astimezone()
        return _iso_utc(local)
    return None


def _query(channel: str, xpath: str, unavailable: list[str] | None = None, **kw) -> list[dict]:
    """evt_query that records an unreadable channel instead of raising."""
    try:
        return evt_query(channel, xpath, **kw)
    except EvtUnavailable:
        if unavailable is not None:
            unavailable.append(channel)
        return []


# (provider, id) -> timeline kind
_TIMELINE_KINDS = {
    ("Microsoft-Windows-Kernel-General", 12): "boot",
    ("Microsoft-Windows-Kernel-General", 13): "shutdown_started",
    ("Microsoft-Windows-Kernel-Power", 109): "shutdown_started",
    ("Microsoft-Windows-Kernel-Power", 41): "unexpected",
    ("User32", 1074): "shutdown_requested",
    ("EventLog", 6005): "eventlog_start",
    ("EventLog", 6006): "eventlog_stop",
    ("EventLog", 6008): "dirty_noted",
}


def _p_power_timeline(slots: dict, days: int = WINDOW_DAYS) -> dict:
    unavailable: list[str] = []
    ids = sorted({eid for _, eid in _TIMELINE_KINDS})
    raw = _query("System", window_xpath(ids=ids, days=days), unavailable, max_events=400)
    events = []
    for ev in raw:
        kind = _TIMELINE_KINDS.get((ev["provider"], ev["id"]))
        if kind is None or not ev["time"]:
            continue
        item = {"time": ev["time"], "kind": kind, "id": ev["id"]}
        if kind == "dirty_noted":
            parts = ev["data_list"]
            item["last_alive"] = _local_to_utc(parts[0], parts[1]) if len(parts) >= 2 else None
        events.append(item)
    events.sort(key=lambda e: e["time"])
    episodes = derive_episodes(events)
    for ep in episodes:
        if ep["next_boot_unexpected"] and ep["shutdown_started_at"] and ep["next_boot"]:
            count, last = activity_between(ep["shutdown_started_at"], ep["next_boot"])
            ep["activity_after_shutdown_start"] = count
            ep["last_activity"] = last
    trimmed = [{k: e[k] for k in ("time", "kind", "id")} for e in events[-MAX_TIMELINE_EVENTS:]]
    return {"window_days": days, "events": trimmed, "episodes": episodes, "unavailable": unavailable}


def _int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return default


def _p_unexpected_shutdowns(slots: dict) -> dict:
    kp = "Microsoft-Windows-Kernel-Power"
    out = []
    for ev in _query("System", window_xpath(ids=[41], providers=[kp])):
        if ev["id"] != 41 or ev["provider"] != kp:
            continue
        d = ev["data"]
        out.append(
            {
                "time": ev["time"],
                "bugcheck_code": _int(d.get("BugcheckCode", "0")),
                "power_button": _int(d.get("PowerButtonTimestamp", "0")) != 0,
                "long_press": str(d.get("LongPowerButtonPressDetected", "")).lower() == "true",
                "sleep_in_progress": _int(d.get("SleepInProgress", "0")) != 0,
            }
        )
    return {"events": out}


def _stop_code(raw: str) -> tuple[str, str | None]:
    """'0x0000009f (0x3, ...)' -> ('0x0000009f', 'DRIVER_POWER_STATE_FAILURE').

    Uses only bsod's static table: get_stop_code_info can queue a web lookup."""
    import bsod

    token = (raw or "").strip().split(" ", 1)[0]
    code = bsod._normalise_stop_code(token)
    return code, bsod.BUGCHECK_CODES.get(code)


def _file_time(mtime: float) -> str:
    return _iso_utc(datetime.fromtimestamp(mtime, timezone.utc))


def _p_bugchecks(slots: dict) -> dict:
    wer = "Microsoft-Windows-WER-SystemErrorReporting"
    bugchecks = []
    for ev in _query("System", window_xpath(ids=[1001], providers=[wer])):
        if ev["id"] != 1001 or ev["provider"] != wer or not ev["data_list"]:
            continue
        code, name = _stop_code(ev["data_list"][0])
        bugchecks.append({"time": ev["time"], "code": code, "name": name})
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    minidumps = []
    try:
        with os.scandir(os.path.join(root, "Minidump")) as it:
            dumps = [(e.name, e.stat()) for e in it if e.is_file() and e.name.lower().endswith(".dmp")]
        dumps.sort(key=lambda d: d[1].st_mtime, reverse=True)
        minidumps = [
            {"name": n, "time": _file_time(st.st_mtime), "size": st.st_size} for n, st in dumps[:MAX_MINIDUMPS]
        ]
    except OSError:
        pass
    memory = None
    try:
        st = os.stat(os.path.join(root, "MEMORY.DMP"))
        memory = {"time": _file_time(st.st_mtime), "size": st.st_size}
    except OSError:
        pass
    return {"bugchecks": bugchecks, "minidumps": minidumps, "memory_dmp": memory}


_WHEA_COMPONENT = {17: "pcie", 20: "pcie", 18: "processor", 19: "processor", 46: "memory", 47: "memory"}


def _p_whea(slots: dict) -> dict:
    provider = "Microsoft-Windows-WHEA-Logger"
    fatal = corrected = 0
    by_component = {"processor": 0, "memory": 0, "pcie": 0, "other": 0}
    times = []
    for ev in _query("System", window_xpath(providers=[provider]), max_events=500):
        if ev["provider"] != provider:
            continue
        if ev["level"] in (1, 2):
            fatal += 1
        else:
            corrected += 1
        by_component[_WHEA_COMPONENT.get(ev["id"], "other")] += 1
        times.append(ev["time"])
    return {
        "fatal": fatal,
        "corrected": corrected,
        "by_component": by_component,
        "first": min(times) if times else None,
        "last": max(times) if times else None,
    }


def _p_boot_health(slots: dict) -> dict:
    unavailable: list[str] = []
    kb = "Microsoft-Windows-Kernel-Boot"
    failures = [
        ev["time"]
        for ev in _query("System", window_xpath(ids=[20], providers=[kb]), unavailable)
        if ev["id"] == 20 and ev["provider"] == kb and str(ev["data"].get("LastBootGood", "")).lower() == "false"
    ]
    repairs = len(_query(STARTUP_REPAIR_CHANNEL, window_xpath(), unavailable))
    durations = [
        _int(ev["data"].get("BootTime", ""), -1)
        for ev in _query(BOOT_PERF_CHANNEL, window_xpath(ids=[100]), unavailable)
        if ev["id"] == 100
    ]
    return {
        "boot_failures": failures,
        "startup_repair_runs": repairs,
        "boot_durations_ms": [d for d in durations if d >= 0],
        "unavailable": unavailable,
    }


_crash_probe("crash.power_timeline", "Startups and shutdowns (7 days)", _p_power_timeline, timeout_s=15.0)
_crash_probe("crash.unexpected_shutdowns", "Unexpected shutdown details", _p_unexpected_shutdowns)
_crash_probe("crash.bugchecks", "Blue screens and crash dumps", _p_bugchecks)
_crash_probe("crash.whea", "Hardware error reports (WHEA)", _p_whea)
_crash_probe("crash.boot_health", "Startup health", _p_boot_health)
