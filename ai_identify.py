"""Global "identify an unknown thing" service for WinDesktopMgr.

When the app meets an entity it can't describe from a local knowledge base --
an unrecognised process (``vmmem``), a driver with no DeviceName, an unknown
MAC vendor, an undocumented BIOS string -- it should look it up FOR the user
instead of telling them to "search online" themselves. This module is the
shared engine + cache behind that global rule.

Two entry points:

  * :func:`identify_via_ai` -- the engine. ONE bounded Claude call that returns
    ``{plain, what, safe_kill}`` for the named entity, or ``None`` on any
    failure (SDK missing, no API key, call cap hit, timeout, unparseable
    reply). Existing self-learning subsystems (processes, events, ...) call
    this as a smarter fallback *before* their "no description found"
    placeholder.

  * :func:`identify` -- a non-blocking lookup for entities that DON'T already
    have a self-learning subsystem (drivers, MAC vendors, BIOS). A cache hit
    returns the resolved entry; a miss enqueues a background lookup and returns
    a "pending" placeholder so the caller never blocks. The next render picks
    up the cached result.

Reuses the proven self-learning pattern already used by processes/events/bsod
(background daemon worker + queue + single-flight guard + atomic JSON cache),
and the Anthropic SDK + ``ANTHROPIC_API_KEY`` already configured for NLQ.

Cost / privacy: results are cached forever (keyed by ``entity_type`` + name),
only genuine unknowns are ever sent, only the entity NAME + minimal context
leaves the machine (never system telemetry), and a per-process call cap
(:data:`MAX_AI_LOOKUPS`) bounds spend if something misbehaves.
"""

from __future__ import annotations

import json
import os
import queue
import threading
from datetime import datetime, timezone

try:
    import anthropic
except ImportError:  # pragma: no cover - SDK optional, same guard as nlq.py
    anthropic = None

APP_DIR = os.path.dirname(os.path.abspath(__file__))
IDENTIFY_CACHE_FILE = os.path.join(APP_DIR, "identify_cache.json")
# Small/cheap model by default -- identification is a one-liner, not reasoning.
# Overridable via env so it can track model availability without a code change.
IDENTIFY_MODEL = os.environ.get("IDENTIFY_MODEL", "claude-haiku-4-5-20251001")
IDENTIFY_TIMEOUT_S = 20.0
# Safety ceiling on AI calls per process lifetime. Each unknown is looked up
# once (then cached), so this only bites in a runaway / cache-disabled case.
MAX_AI_LOOKUPS = 500

# Friendly entity-kind phrasing for the prompt.
_KIND = {
    "process": "a Windows process / executable",
    "driver": "a Windows hardware device driver",
    "mac_vendor": "the manufacturer that owns a network MAC address (OUI prefix)",
    "bios": "a PC motherboard BIOS / UEFI firmware version",
    "service": "a Windows service",
    "startup": "a Windows startup program",
    "event": "a Windows Event Log entry",
}

_cache: dict = {}
_cache_lock = threading.Lock()
_queue: queue.Queue = queue.Queue()
_in_flight: set = set()
_ai_calls = 0
_ai_calls_lock = threading.Lock()


def _cache_key(entity_type: str, key: str) -> str:
    return f"{entity_type}:{str(key).strip().lower()}"


def _load_cache() -> None:
    global _cache
    try:
        with open(IDENTIFY_CACHE_FILE, encoding="utf-8") as fh:
            loaded = json.load(fh)
        _cache = loaded if isinstance(loaded, dict) else {}
    except Exception:  # noqa: BLE001 -- missing/corrupt cache -> start empty
        _cache = {}


def _save_cache() -> None:
    tmp = IDENTIFY_CACHE_FILE + ".tmp"
    try:
        with _cache_lock:
            snapshot = dict(_cache)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        os.replace(tmp, IDENTIFY_CACHE_FILE)
    except Exception:  # noqa: BLE001 -- best effort; never break the worker
        try:
            os.remove(tmp)
        except OSError:
            pass


_load_cache()


def _extract_json(text: str) -> dict | None:
    """Tolerantly pull a JSON object out of a model reply.

    Tries the slice from each ``{`` to the last ``}`` so a brief prose preamble
    that itself contains a brace (``Here you go: {...}``) doesn't poison the
    parse and drop an otherwise-valid object.
    """
    if not text:
        return None
    end = text.rfind("}")
    if end == -1:
        return None
    start = text.find("{")
    while start != -1 and start < end:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict):
                return obj
        except (ValueError, TypeError):
            pass
        start = text.find("{", start + 1)
    return None


def identify_via_ai(entity_type: str, key: str, context: str = "") -> dict | None:
    """One bounded Claude call identifying ``key``. Returns a dict or ``None``.

    Never raises. ``None`` when the SDK is absent, no API key is set, the
    per-process call cap is hit, the request fails/times out, or the reply
    can't be parsed -- callers fall through to their own placeholder.
    """
    global _ai_calls
    if anthropic is None:
        return None
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    with _ai_calls_lock:
        if _ai_calls >= MAX_AI_LOOKUPS:
            if _ai_calls == MAX_AI_LOOKUPS:  # log once at the boundary
                print(f"[Identify] AI lookup cap ({MAX_AI_LOOKUPS}) reached -- pausing AI identification until restart")
                _ai_calls += 1
            return None
        _ai_calls += 1  # tentative -- only successful calls should count; decrement on any failure below

    kind = _KIND.get(entity_type, f"a Windows {entity_type}")
    ctx = f" Extra context: {context}." if context else ""
    prompt = (
        f"Identify {kind} named '{key}'.{ctx} "
        "Respond with ONLY a JSON object (no prose, no markdown) with keys: "
        '"plain" (a short friendly name), '
        '"what" (1-2 plain-English sentences a non-expert understands: what it '
        "is and whether it is safe to stop / disable / remove), and "
        '"safe_kill" (true if generally safe to end or disable, false if doing '
        "so could destabilise Windows, null if unsure). "
        "If you do not recognise it, set plain to the name and say so in 'what'."
    )
    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=IDENTIFY_TIMEOUT_S)
        resp = client.messages.create(
            model=IDENTIFY_MODEL,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(getattr(block, "text", "") for block in resp.content)
    except Exception:  # noqa: BLE001 -- any API/network error -> graceful None
        # The call never produced a billable success; hand the cap slot back so a
        # network blip can't permanently exhaust the budget on failed attempts.
        with _ai_calls_lock:
            _ai_calls -= 1
        return None

    parsed = _extract_json(text)
    if not parsed or not parsed.get("what"):
        with _ai_calls_lock:
            _ai_calls -= 1
        return None
    return {
        "source": "claude_ai",
        "plain": str(parsed.get("plain") or key),
        "what": str(parsed["what"]).strip(),
        "safe_kill": parsed.get("safe_kill"),
        "fetched": datetime.now(timezone.utc).isoformat(),
    }


def get_cached(entity_type: str, key: str) -> dict | None:
    """Return the resolved cache entry for an entity, or ``None`` if not cached."""
    with _cache_lock:
        return _cache.get(_cache_key(entity_type, key))


def identify(entity_type: str, key: str, context: str = "", display: str = "") -> dict:
    """Non-blocking identify for entities without their own lookup subsystem.

    Cache hit -> the resolved entry. Miss -> enqueue a background lookup and
    return a ``pending`` placeholder. Safe to call on every render; the
    single-flight guard means repeated calls for the same unknown enqueue once.
    """
    ck = _cache_key(entity_type, key)
    with _cache_lock:
        if ck in _cache:
            return _cache[ck]
        if ck not in _in_flight:
            _in_flight.add(ck)
            _queue.put((entity_type, key, context))
    return {
        "source": "pending",
        "plain": display or str(key),
        "what": "Identifying… check back in a moment.",
        "safe_kill": None,
        "fetched": None,
        "pending": True,
    }


def _resolve_one(entity_type: str, key: str, context: str = "") -> dict:
    """Resolve one entity via AI (or an 'unresolved' placeholder) and cache it.

    Idempotent: a cache hit short-circuits without a new AI call. Returns the
    cached/resolved entry. Extracted from the worker loop so it's unit-testable.
    """
    ck = _cache_key(entity_type, key)
    with _cache_lock:
        if ck in _cache:
            return _cache[ck]
    result = identify_via_ai(entity_type, key, context)
    if not result:
        result = {
            "source": "unresolved",
            "plain": str(key),
            "what": "Could not identify this automatically. It may be an uncommon or custom item.",
            "safe_kill": None,
            "fetched": datetime.now(timezone.utc).isoformat(),
        }
    with _cache_lock:
        _cache[ck] = result
    # Persist ONLY successful identifications. An "unresolved" result usually
    # means a transient miss (no API key yet, network blip, cap reached) -- if
    # we wrote it to disk it would survive restart and the entity would never be
    # retried even after the key is set. Keeping it in-memory only dedupes the
    # current session while letting a restart try again with a clean slate.
    if result.get("source") != "unresolved":
        _save_cache()
    return result


def _identify_worker() -> None:
    """Background daemon -- drains the queue, resolves via AI, caches results."""
    while True:
        item = None
        ck = None
        try:
            item = _queue.get(timeout=5)
            entity_type, key, context = item
            ck = _cache_key(entity_type, key)
            _resolve_one(entity_type, key, context)
        except queue.Empty:
            pass
        except Exception as e:  # noqa: BLE001 -- never let the worker die
            print(f"[IdentifyWorker] error: {e}")
        finally:
            if ck is not None:
                with _cache_lock:
                    _in_flight.discard(ck)
            if item is not None:
                try:
                    _queue.task_done()
                except Exception:  # noqa: BLE001
                    pass
