"""
events.py — Windows Event Log module for WinDesktopMgr.

Owns the Event Log subsystem:

* ``query_event_log`` — the Event Log tab's query API (level filter, search,
  500-row cap) built on the shared XPath event-log helpers in windesktopmgr.
* Static ``EVENT_KB`` knowledge base + ``NOISE_SOURCES`` noise list.
* Self-learning event-ID lookup — static KB -> on-disk cache -> Windows
  provider registry (PowerShell) -> Microsoft Learn search, drained by a
  background worker.
* ``summarize_events`` — the Event Log tab insight summary.

Extracted from windesktopmgr.py (backlog #54 PR B, second production-file
extraction after bsod.py). No behaviour changes: every block is a verbatim
relocation.

Circular-import note: ``query_event_log`` lazy-imports the shared XPath
helpers (``_build_evt_xpath`` / ``_query_event_log_xpath``) from
windesktopmgr at call time. windesktopmgr imports the public Event symbols
from this module at top level; the lazy import breaks the cycle AND keeps
``mocker.patch("windesktopmgr._query_event_log_xpath")`` effective.

``subprocess.run`` is intentionally referenced unqualified (module-global)
so windesktopmgr's headless console-suppression monkeypatch propagates here,
exactly as it does for the already-extracted disk.py.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

import ai_identify as identify

APP_DIR = os.path.dirname(os.path.abspath(__file__))
EVENT_CACHE_FILE = os.path.join(APP_DIR, "event_id_cache.json")


def _insight(level: str, text: str, action: str = "") -> dict:
    """Insight dict constructor — local copy of the windesktopmgr helper
    (the disk.py / bsod.py extraction pattern; avoids a circular import)."""
    return {"level": level, "text": text, "action": action}


def query_event_log(params: dict) -> list:
    # Lazy import breaks the windesktopmgr <-> events cycle and keeps
    # mocker.patch("windesktopmgr._query_event_log_xpath") effective.
    from windesktopmgr import _build_evt_xpath, _query_event_log_xpath

    log = params.get("log", "System")
    level = params.get("level", "")
    search = params.get("search", "").strip()
    max_ev = min(int(params.get("max", 100)), 500)

    safe_log = re.sub(r"[^\w\s\-/]", "", log)

    levels = [LEVEL_MAP[level]] if level and level in LEVEL_MAP else None
    xpath = _build_evt_xpath(levels=levels)

    try:
        rows = _query_event_log_xpath(safe_log, xpath, max_events=max_ev, timeout_s=30.0)
        events = [
            {
                "Time": e["TimeCreated"],
                "Id": e["Id"],
                "Level": _LEVEL_DISPLAY.get(e["Level"], ""),
                "Source": e["ProviderName"],
                # Preserve the legacy 300-char truncation for UI display parity
                "Message": (e["Message"] or "")[:300],
            }
            for e in rows
        ]
        if search:
            sl = search.lower()
            events = [
                e for e in events if sl in (e.get("Message", "") + e.get("Source", "") + str(e.get("Id", ""))).lower()
            ]
        return events
    except Exception as e:
        print(f"[Event log error] {e}")
        return []


LEVEL_MAP = {"Error": 2, "Warning": 3, "Information": 4, "Critical": 1}


_LEVEL_DISPLAY = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}


EVENT_KB = {
    # ── DistributedCOM / DCOM ─────────────────────────────────────────────
    10010: {
        "noise": True,
        "source": "Microsoft-Windows-DistributedCOM",
        "title": "Windows background component unavailable (Event 10010)",
        "detail": "Windows couldn't start a DCOM server (DCOM is the background communication "
        "framework Windows uses to connect apps and system services) in time. "
        "This is almost always harmless background noise — "
        "typically caused by Microsoft Store apps or system components "
        "that register servers they don't always use.",
        "action": "Safe to ignore unless you see application crashes alongside it. No action needed.",
    },
    10016: {
        "noise": True,
        "source": "Microsoft-Windows-DistributedCOM",
        "title": "Windows background component permission error (Event 10016)",
        "detail": "A process tried to activate a DCOM server (DCOM is the background communication "
        "framework Windows uses to connect apps and services) without the required permissions. "
        "This is extremely common on Windows 11 and almost always benign — "
        "it affects background Microsoft components, not your applications.",
        "action": "Safe to ignore in most cases. No action needed unless a specific app is broken.",
    },
    # ── Disk / Storage ────────────────────────────────────────────────────
    7: {
        "noise": False,
        "source": "disk",
        "title": "Bad block on disk",
        "detail": "The disk driver detected a bad block. This is a hardware-level warning "
        "that your drive may be developing physical errors.",
        "action": "URGENT: back up your data immediately. "
        "Then run chkdsk /r (Windows built-in disk check and repair tool): "
        "search Command Prompt in Start, right-click Run as Administrator, "
        "type: chkdsk C: /r and press Enter (replace C: with the affected drive letter). "
        "Check the Disk Health tab for physical disk status.",
    },
    11: {
        "noise": False,
        "source": "disk",
        "title": "Controller error on disk",
        "detail": "The disk controller reported an error. Can indicate a failing drive, "
        "loose cable, or faulty SATA/NVMe controller.",
        "action": "Check the Disk Health tab in WinDesktopMgr for drive health status. "
        "For deeper analysis, CrystalDiskInfo (free tool at crystalmark.info) reads S.M.A.R.T. data "
        "(drive health statistics built into every modern drive). "
        "If errors are found, back up immediately and consider replacing the drive.",
    },
    51: {
        "noise": False,
        "source": "disk",
        "title": "Disk paging error",
        "detail": "An error occurred during a paging operation. Often appears before drive failure.",
        "action": "Back up data. Run chkdsk /r (Windows built-in disk check tool): search Command Prompt in Start, right-click Run as Administrator, type: chkdsk C: /r. Check the Disk Health tab for drive health status.",
    },
    # ── Kernel / Power ────────────────────────────────────────────────────
    41: {
        "noise": False,
        "source": "Microsoft-Windows-Kernel-Power",
        "title": "Unexpected system shutdown (Kernel-Power)",
        "detail": "The system rebooted without cleanly shutting down first — "
        "this is the primary BSOD/crash/power-loss event. "
        "Directly related to the crashes shown in the BSOD Dashboard.",
        "action": "Check BSOD Dashboard for crash analysis. "
        "Verify PSU is adequate for your hardware. Check system temps.",
    },
    6008: {
        "noise": False,
        "source": "EventLog",
        "title": "Unexpected shutdown logged by Event Log",
        "detail": "The previous system shutdown was unexpected. Logged at startup after a crash or power loss.",
        "action": "Cross-reference with BSOD Dashboard. If frequent, investigate power supply and thermals.",
    },
    1001: {
        "noise": False,
        "source": "BugCheck",
        "title": "Windows Error Reporting — crash recorded",
        "detail": "Windows recorded a crash dump. The stop code is logged here.",
        "action": "Check the BSOD Dashboard tab for full crash analysis and recommendations.",
    },
    # ── Service Control Manager ───────────────────────────────────────────
    7000: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service failed to start",
        "detail": "A Windows service failed to start during boot.",
        "action": "Check which service failed in the event message. "
        "Run: Get-Service | Where-Object {$_.Status -eq 'Stopped'} in PowerShell.",
    },
    7001: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service dependency failed",
        "detail": "A service could not start because a service it depends on failed.",
        "action": "Identify the dependency chain — fix the root service first.",
    },
    7031: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service terminated unexpectedly",
        "detail": "A service crashed and Windows took a recovery action (restart/reboot).",
        "action": "Note the service name in the event message. Check Event Log for related errors around the same time.",
    },
    7034: {
        "noise": False,
        "source": "Service Control Manager",
        "title": "Service terminated unexpectedly (no recovery)",
        "detail": "A service crashed with no configured recovery action.",
        "action": "Identify the service and check its logs or event source for the root cause.",
    },
    # ── Windows Update ────────────────────────────────────────────────────
    20: {
        "noise": False,
        "source": "Microsoft-Windows-WindowsUpdateClient",
        "title": "Windows Update installation failure",
        "detail": "A Windows Update failed to install.",
        "action": "Check Update History tab for details. Run sfc /scannow (Windows system file repair tool): search Command Prompt in Start, right-click Run as Administrator, type: sfc /scannow and press Enter. Then retry Windows Update.",
    },
    # ── Application / .NET ───────────────────────────────────────────────
    1000: {
        "noise": False,
        "source": "Application Error",
        "title": "Application crash",
        "detail": "An application faulted and was terminated by Windows.",
        "action": "Note the faulting application and module in the event message. Update or reinstall the application.",
    },
    1026: {
        "noise": True,
        "source": ".NET Runtime",
        "title": ".NET Runtime error",
        "detail": "A .NET application encountered an unhandled exception.",
        "action": "Usually harmless background app crash. "
        "Note the app name — reinstall if it's something you use actively.",
    },
    # ── Networking ───────────────────────────────────────────────────────
    4201: {
        "noise": True,
        "source": "Tcpip",
        "title": "Network adapter disconnected",
        "detail": "The system detected the network adapter was disconnected.",
        "action": "Normal if you disconnected Wi-Fi or Ethernet intentionally. "
        "Investigate if happening unexpectedly — check Network Monitor tab.",
    },
    # ── Hyper-V / Virtualisation ─────────────────────────────────────────
    18456: {
        "noise": False,
        "source": "Microsoft-Windows-Hyper-V-Worker",
        "title": "Hyper-V worker process error",
        "detail": "Hyper-V encountered an error in a virtual machine worker process.",
        "action": "Related to your HYPERVISOR_ERROR BSODs. "
        "Consider disabling Memory Integrity (Core Isolation) and C-States in BIOS.",
    },
    # ── Security ─────────────────────────────────────────────────────────
    4625: {
        "noise": False,
        "source": "Microsoft-Windows-Security-Auditing",
        "title": "Failed logon attempt",
        "detail": "An account failed to log on. Multiple occurrences may indicate a brute-force attack (repeated automated login attempts by malicious software) or a misconfigured service trying to authenticate.",
        "action": "Check the account name and source IP in the event details. "
        "If from external IP, review firewall and RDP settings.",
    },
    4648: {
        "noise": False,
        "source": "Microsoft-Windows-Security-Auditing",
        "title": "Explicit credentials logon",
        "detail": "A process attempted to log on with explicit credentials (runas). Can be legitimate or suspicious.",
        "action": "Review the account and process in the event message.",
    },
}


# ─── Self-learning BSOD stop-code lookup subsystem moved to bsod.py ───────────
#     (bsod._normalise_stop_code, _load/bsod._save_bsod_cache, _bsod_lookup_worker,
#      get_stop_code_info, get_bsod_cache_status, DRIVER_CONTEXT, cache state)


# Sources that are almost always noise — downgrade severity automatically
NOISE_SOURCES = {
    "Microsoft-Windows-DistributedCOM",
    "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-DeviceSetupManager",
    "Microsoft-Windows-UserPnp",
    "VSS",
}


# ══════════════════════════════════════════════════════════════════════════════
# SELF-LEARNING EVENT ID LOOKUP SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
#
# Lookup priority for any unknown Event ID:
#   1. Static EVENT_KB (hardcoded, instant)
#   2. Local cache file (event_id_cache.json — persists across restarts)
#   3. Windows Event Provider metadata (PowerShell — always up to date,
#      no internet needed, reads directly from Windows' own event registry)
#   4. Microsoft Learn web search (internet fallback)
#   5. Generic placeholder (so UI always gets something)
#
# Each ID is looked up at most once ever. Cache grows automatically.
# ══════════════════════════════════════════════════════════════════════════════

_event_cache_lock = threading.Lock()
_event_cache: dict = {}  # in-memory; mirrors the JSON file
_lookup_queue: queue.Queue = queue.Queue()
_lookup_in_flight: set = set()  # IDs currently being looked up


def _load_event_cache():
    """Load the JSON cache from disk into memory."""
    global _event_cache
    if not os.path.exists(EVENT_CACHE_FILE):
        _event_cache = {}
        return
    try:
        with open(EVENT_CACHE_FILE, encoding="utf-8") as f:
            _event_cache = json.load(f)
        print(f"[EventCache] Loaded {len(_event_cache)} cached event IDs")
    except Exception as e:
        print(f"[EventCache] Load error: {e}")
        _event_cache = {}


def _save_event_cache():
    """Persist in-memory cache to disk."""
    try:
        with _event_cache_lock:
            with open(EVENT_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(_event_cache, f, indent=2)
    except Exception as e:
        print(f"[EventCache] Save error: {e}")


def _lookup_via_windows_provider(event_id: int, source: str) -> dict | None:
    """
    Query Windows' own event provider registry via PowerShell.
    This is always up to date — it reads whatever Windows has installed.
    Works offline. Returns None if the provider/event isn't registered.
    """
    safe_source = re.sub(r"[^\w \-]", "", source)
    ps = f"""
try {{
    # Try exact source name first
    $providers = @(Get-WinEvent -ListProvider "*" -EA SilentlyContinue |
        Where-Object {{ $_.Name -like "*{safe_source}*" }})
    foreach ($p in $providers) {{
        $evt = $p.Events | Where-Object {{ $_.Id -eq {event_id} }} | Select-Object -First 1
        if ($evt) {{
            [PSCustomObject]@{{
                Provider    = $p.Name
                Id          = $evt.Id
                Description = $evt.Description
                Level       = $evt.Level
                Keywords    = ($evt.Keywords -join ", ")
            }} | ConvertTo-Json -Depth 2
            exit
        }}
    }}
    # Broader search — any provider with this event ID
    $all = Get-WinEvent -ListProvider "*" -EA SilentlyContinue
    foreach ($p in $all) {{
        $evt = $p.Events | Where-Object {{ $_.Id -eq {event_id} }} | Select-Object -First 1
        if ($evt) {{
            [PSCustomObject]@{{
                Provider    = $p.Name
                Id          = $evt.Id
                Description = $evt.Description
                Level       = $evt.Level
                Keywords    = ($evt.Keywords -join ", ")
            }} | ConvertTo-Json -Depth 2
            exit
        }}
    }}
}} catch {{ }}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps], capture_output=True, text=True, timeout=20
        )
        raw = r.stdout.strip()
        if not raw:
            return None
        data = json.loads(raw)
        desc = (data.get("Description") or "").strip()
        if not desc:
            return None
        # Truncate very long provider descriptions — they can be huge template strings
        desc = re.sub(r"%\d+", "[value]", desc)  # replace %1 %2 placeholders
        desc = desc[:400] + ("…" if len(desc) > 400 else "")
        return {
            "source": "windows_provider",
            "title": f"Event {event_id} from {data.get('Provider', source)}",
            "detail": desc,
            "noise": False,
            "action": "See event message details for specific context.",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[WinProvider] lookup failed for {event_id}: {e}")
        return None


def _lookup_via_web(event_id: int, source: str) -> dict | None:
    """
    Fallback: search Microsoft Learn for the event ID.
    Uses the Microsoft Learn search API — no scraping, clean JSON.
    """
    try:
        query = urllib.parse.quote(f"event id {event_id} {source} windows")
        url = f"https://learn.microsoft.com/api/search?search={query}&locale=en-us&%24top=3&facet=products"
        req = urllib.request.Request(url, headers={"User-Agent": "WinDesktopMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
        if not results:
            return None
        top = results[0]
        title = top.get("title", f"Event ID {event_id}")
        summary = top.get("summary", "")[:300]
        url_ref = top.get("url", "https://learn.microsoft.com")
        return {
            "source": "microsoft_learn",
            "title": title,
            "detail": summary or f"See Microsoft documentation for Event ID {event_id}.",
            "noise": False,
            "action": f"Full details: {url_ref}",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[WebLookup] failed for {event_id}: {e}")
        return None


def _resolve_event(event_id: int, source: str) -> dict:
    """Resolve one unknown event ID: Windows provider metadata -> Microsoft
    Learn web -> AI identifier -> placeholder. Extracted from the worker loop so
    the chain (incl. the AI fallback) is unit-testable."""
    # 1. Try Windows provider metadata first (offline, always current)
    result = _lookup_via_windows_provider(event_id, source)

    # 2. Web fallback
    if not result:
        result = _lookup_via_web(event_id, source)

    # 3. Global rule (identify rollout PR2): AI identifier before the "no
    # description found" punt -- names third-party / obscure event IDs the
    # provider registry and Microsoft Learn both miss.
    if not result:
        ctx = f"from event log provider '{source}'" if source else "Windows Event Log"
        ai = identify.identify_via_ai("event", str(event_id), context=ctx)
        if ai:
            result = {
                "source": ai["source"],
                "title": ai.get("plain") or f"Event ID {event_id}",
                "detail": ai["what"],
                "noise": False,
                "action": "Identified by AI from the event ID + provider.",
                "fetched": ai["fetched"],
            }

    # 4. Generic placeholder so we don't keep re-trying unknown IDs
    if not result:
        result = {
            "source": "unknown",
            "title": f"Event ID {event_id}",
            "detail": "No description found in Windows provider registry or Microsoft Learn.",
            "noise": False,
            "action": f"Search: https://learn.microsoft.com/search/?terms=event+id+{event_id}",
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    return result


def _lookup_worker():
    """
    Background thread: drains the lookup queue, enriches unknown event IDs,
    updates cache. Runs forever as a daemon thread.
    """
    while True:
        got_item = False
        try:
            event_id, source = _lookup_queue.get(timeout=5)
            got_item = True
            cache_key = str(event_id)

            with _event_cache_lock:
                if cache_key in _event_cache:
                    # Already cached -- the `finally` does the in_flight discard
                    # + task_done (doing them here too double-counted task_done).
                    continue

            print(f"[EventCache] Looking up Event ID {event_id} (source: {source})")
            result = _resolve_event(event_id, source)

            with _event_cache_lock:
                _event_cache[cache_key] = result
            _save_event_cache()
            print(f"[EventCache] Cached Event ID {event_id} (source: {result['source']})")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"[LookupWorker] error: {e}")
        finally:
            try:
                if got_item:
                    with _event_cache_lock:
                        _lookup_in_flight.discard(event_id)
                    _lookup_queue.task_done()
            except Exception:
                pass


def get_event_info(event_id: int, source: str = "") -> dict | None:
    """
    Main entry point. Returns info for an event ID from any available source.
    Queues a background lookup if not cached yet.
    Returns None if not yet available (caller shows generic message).
    """
    # 1. Static KB (instant, highest quality)
    if event_id in EVENT_KB:
        return EVENT_KB[event_id]

    # 2. In-memory / disk cache
    cache_key = str(event_id)
    with _event_cache_lock:
        if cache_key in _event_cache:
            return _event_cache[cache_key]

    # 3. Queue for background lookup if not already in flight
    with _event_cache_lock:
        if event_id not in _lookup_in_flight:
            _lookup_in_flight.add(event_id)
            _lookup_queue.put((event_id, source))

    return None  # Not ready yet — caller will show "looking up…" state


def get_cache_status() -> dict:
    """Return cache stats for the admin endpoint."""
    with _event_cache_lock:
        cached = dict(_event_cache)
    return {
        "total_cached": len(cached),
        "queue_pending": _lookup_queue.qsize(),
        "in_flight": len(_lookup_in_flight),
        "cache_file": EVENT_CACHE_FILE,
        "entries": [
            {"id": k, "title": v.get("title", "?"), "source": v.get("source", "?"), "fetched": v.get("fetched", "")}
            for k, v in list(cached.items())[:50]
        ],
    }


def summarize_events(events: list) -> dict:
    if not events:
        return {
            "status": "ok",
            "headline": "No events to summarise — run a query first.",
            "insights": [],
            "actions": [],
        }

    errors = [e for e in events if e.get("Level") in ("Error", "Critical")]
    warnings = [e for e in events if e.get("Level") == "Warning"]
    insights = []
    actions = []

    # Separate real errors from known noise
    real_errors = [
        e
        for e in errors
        if e.get("Source") not in NOISE_SOURCES and not EVENT_KB.get(e.get("Id"), {}).get("noise", False)
    ]
    noise_errors = [e for e in errors if e not in real_errors]

    # ── Per-ID lookup (static KB + learned cache) ────────────────────────
    id_counts = Counter(e.get("Id") for e in events)
    id_source = {e.get("Id"): e.get("Source", "") for e in events}
    explained = set()
    pending = []  # IDs queued for background lookup

    for eid, cnt in id_counts.most_common(15):
        info = get_event_info(eid, id_source.get(eid, ""))
        if info is None:
            pending.append((eid, cnt))
            continue
        explained.add(eid)
        is_noise = info.get("noise", False)
        src_label = info.get("source", "")
        src_tag = "" if src_label in ("", "static") else f" [{src_label}]"
        level = "info" if is_noise else ("critical" if cnt >= 10 else "warning")
        noise_tag = " *(known noise — safe to ignore)*" if is_noise else ""
        insights.append(
            _insight(
                level,
                f"Event ID {eid}{src_tag} — {info.get('title', '')} — {cnt}x{noise_tag}. {info.get('detail', '')}",
                info.get("action", ""),
            )
        )
        if not is_noise and info.get("action"):
            actions.append(info["action"][:80])

    if pending:
        ids_str = ", ".join(str(e) for e, _ in pending[:5])
        more = f" (+{len(pending) - 5} more)" if len(pending) > 5 else ""
        insights.append(
            _insight(
                "info",
                f"Looking up {len(pending)} unknown Event ID(s) in background "
                f"({ids_str}{more}). Refresh in a few seconds to see details.",
                "",
            )
        )

    # ── Unexplained real errors ───────────────────────────────────────────
    unexplained_errors = [e for e in real_errors if e.get("Id") not in explained]
    if unexplained_errors:
        sources = Counter(e.get("Source", "?") for e in unexplained_errors)
        top_src, top_n = sources.most_common(1)[0]
        insights.append(
            _insight(
                "warning",
                f"{len(unexplained_errors)} unrecognised error(s). Top source: {top_src} ({top_n}x).",
                f"Filter by source '{top_src}' and search Microsoft support for specific event IDs.",
            )
        )

    # ── Noise summary (collapsed) ─────────────────────────────────────────
    if noise_errors:
        noise_ids = Counter(e.get("Id") for e in noise_errors)
        top_noise = ", ".join(f"ID {k} ({v}x)" for k, v in noise_ids.most_common(3))
        insights.append(
            _insight(
                "info",
                f"{len(noise_errors)} known-noise event(s) in results ({top_noise}) — "
                "these are normal Windows background activity and do not require action.",
            )
        )

    # ── Warnings summary ─────────────────────────────────────────────────
    if warnings:
        warn_sources = Counter(e.get("Source", "?") for e in warnings)
        top_ws, top_wn = warn_sources.most_common(1)[0]
        insights.append(_insight("info", f"{len(warnings)} warning(s). Top source: {top_ws} ({top_wn}x)."))

    if not errors:
        insights.append(_insight("ok", f"No errors in current results. {len(events)} total events shown."))

    # ── Status ────────────────────────────────────────────────────────────
    real_count = len(real_errors)
    status = "critical" if real_count > 10 else "warning" if real_count > 0 else "ok"
    headline = (
        f"{real_count} real error(s) need attention"
        + (f" ({len(noise_errors)} noise events filtered)" if noise_errors else "")
        if real_count
        else f"{len(events)} events retrieved — no actionable errors"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": list(dict.fromkeys(actions))[:4]}


def delete_cached_id(event_id: int) -> dict:
    """Remove a single event ID from the cache (backs DELETE /api/events/cache/delete)."""
    key = str(event_id)
    with _event_cache_lock:
        removed = key in _event_cache
        _event_cache.pop(key, None)
    if removed:
        _save_event_cache()
    return {"ok": True, "removed": removed, "id": event_id}


def clear_cache() -> dict:
    """Wipe the entire learned cache (keeps static EVENT_KB). Backs POST /api/events/cache/clear."""
    with _event_cache_lock:
        _event_cache.clear()
    _save_event_cache()
    return {"ok": True}
