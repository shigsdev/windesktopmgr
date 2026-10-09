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
import xml.etree.ElementTree as ET  # noqa: S405 -- parses Event Log service XML, not user input
from collections.abc import Iterable

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
    from datetime import datetime

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
