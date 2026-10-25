"""stallwatch.py -- Stall watchdog: write every thread's stack when the tray freezes.

Backlog #106. On 2026-10-20 13:51:27-13:52:34 every request froze for 67 s
(47 queued) while the rest of the PC kept running, and nothing was logged,
so the cause is unknown. This module catches the next one with evidence.

Two watches, one heartbeat thread (``StallWatchdog``):

1. **Request watch.** ``request_started`` / ``request_finished`` (wired to
   Flask's before/teardown hooks) track every in-flight request. Each tick
   the heartbeat looks for one that has run longer than ``REQUEST_STALL_S``;
   the first time it sees it, it writes all thread stacks (with thread
   names) to ``Logs/stalls.log`` and a WARNING to app.log. At most one dump
   per ``DUMP_COOLDOWN_S`` so a slow morning can't fill the disk.

2. **Process watch.** Each tick re-arms ``faulthandler.dump_traceback_later``.
   If the heartbeat itself can't run for ``PROCESS_STALL_S`` -- e.g. a C
   extension holding the GIL, so NO Python code runs -- CPython's C-level
   watchdog thread (which needs no GIL) writes the stacks instead. When the
   heartbeat wakes up it notes the gap. A gap also shows up if the PC was
   asleep; the note says so.

Only ``start()`` touches faulthandler, files or threads, and only
``windesktopmgr.start_server`` calls it -- tests and imports stay inert.
"""

from __future__ import annotations

import faulthandler
import itertools
import os
import sys
import threading
import time
import traceback
from datetime import datetime

from applogging import LOG_DIR, get_logger

log = get_logger("stall")

STALL_LOG = os.path.join(LOG_DIR, "stalls.log")

TICK_S = 5.0
# Requests that ran past this get a stack dump (the row's "> 20 s").
REQUEST_STALL_S = 20.0
# No heartbeat for this long -> faulthandler's C watchdog dumps instead.
PROCESS_STALL_S = 30.0
DUMP_COOLDOWN_S = 300.0
# stalls.log is rotated to stalls.log.1 at start-up past this size, and
# request dumps stop once the live file reaches it.
MAX_LOG_BYTES = 5 * 1024 * 1024

# Known-slow by design: /api/selftest runs 15 real checks for `dev.py verify`.
EXEMPT_PATHS = frozenset({"/api/selftest"})

_token_counter = itertools.count(1)
_inflight: dict[int, dict] = {}
_inflight_lock = threading.Lock()


def request_started(method: str, path: str) -> int | None:
    """Record a request as in flight. Returns a token for ``request_finished``."""
    if path in EXEMPT_PATHS:
        return None
    token = next(_token_counter)
    with _inflight_lock:
        _inflight[token] = {
            "method": method,
            "path": path,
            "start": time.monotonic(),
            "thread": threading.current_thread().name,
            "dumped": False,
        }
    return token


def request_finished(token: int | None) -> None:
    if token is None:
        return
    with _inflight_lock:
        _inflight.pop(token, None)


def stalled_requests(now: float) -> list[dict]:
    """Requests over ``REQUEST_STALL_S`` not yet dumped; marks them dumped."""
    found = []
    with _inflight_lock:
        for req in _inflight.values():
            if not req["dumped"] and now - req["start"] > REQUEST_STALL_S:
                req["dumped"] = True
                found.append({**req, "elapsed_s": now - req["start"]})
    return found


def inflight_summary(now: float) -> list[str]:
    with _inflight_lock:
        reqs = sorted(_inflight.values(), key=lambda r: r["start"])
        return [f"{r['method']} {r['path']} {now - r['start']:.1f}s [{r['thread']}]" for r in reqs]


def format_all_stacks() -> str:
    """Every live thread's stack, labelled with its name (faulthandler only gives ids)."""
    names = {t.ident: t.name for t in threading.enumerate()}
    parts = []
    for ident, frame in sys._current_frames().items():  # noqa: SLF001 -- the documented way to read other threads' stacks
        parts.append(f'Thread "{names.get(ident, "?")}" (id {ident}):\n')
        parts.extend(traceback.format_stack(frame))
        parts.append("\n")
    return "".join(parts)


def _append(text: str) -> None:
    with open(STALL_LOG, "a", encoding="utf-8") as f:
        f.write(text)


def _stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class StallWatchdog:
    """The heartbeat. ``tick()`` holds all the logic so tests can drive it."""

    def __init__(self) -> None:
        self._last_tick: float | None = None
        self._last_dump: float | None = None
        self._fh_file = None
        self._stop = threading.Event()

    def tick(self, now: float) -> None:
        if self._last_tick is not None and now - self._last_tick > PROCESS_STALL_S:
            gap = now - self._last_tick
            log.warning(
                "Heartbeat gap %.1fs: the whole process stalled (or the PC was asleep). "
                "If stalled, faulthandler wrote the stacks to %s",
                gap,
                STALL_LOG,
            )
            self._write(f"=== {_stamp()} heartbeat resumed after a {gap:.1f}s gap (stacks above, if stalled)\n\n")
        self._last_tick = now
        self._rearm_faulthandler()

        stalled = stalled_requests(now)
        if not stalled:
            return
        for req in stalled:
            log.warning(
                "Request stall: %s %s running %.1fs on %s",
                req["method"],
                req["path"],
                req["elapsed_s"],
                req["thread"],
            )
        if self._last_dump is not None and now - self._last_dump < DUMP_COOLDOWN_S:
            return
        if os.path.exists(STALL_LOG) and os.path.getsize(STALL_LOG) >= MAX_LOG_BYTES:
            return
        self._last_dump = now
        header = (
            f"=== {_stamp()} request stall (> {REQUEST_STALL_S:.0f}s)\n"
            + "".join(f"  in flight: {line}\n" for line in inflight_summary(now))
            + "\n"
        )
        self._write(header + format_all_stacks())
        log.warning("Thread stacks written to %s", STALL_LOG)

    def _write(self, text: str) -> None:
        try:
            _append(text)
        except OSError as e:
            log.warning("Could not write %s: %s", STALL_LOG, e)

    def _rearm_faulthandler(self) -> None:
        if self._fh_file is None:
            return
        try:
            faulthandler.dump_traceback_later(PROCESS_STALL_S, repeat=False, file=self._fh_file, exit=False)
        except (RuntimeError, ValueError, OSError) as e:
            log.warning("faulthandler re-arm failed, process watch off: %s", e)
            self._fh_file = None

    def start(self) -> None:
        """Open stalls.log for faulthandler and start the heartbeat thread."""
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            if os.path.exists(STALL_LOG) and os.path.getsize(STALL_LOG) >= MAX_LOG_BYTES:
                os.replace(STALL_LOG, STALL_LOG + ".1")
            # Kept open for the process lifetime: faulthandler writes to its fd
            # from the C watchdog thread, after Python may already be frozen.
            self._fh_file = open(STALL_LOG, "a", encoding="utf-8")  # noqa: SIM115
        except OSError as e:
            log.warning("Stall watchdog: cannot open %s, process watch off: %s", STALL_LOG, e)
        threading.Thread(target=self._run, daemon=True, name="StallWatchdog").start()
        log.info("Stall watchdog on: requests > %.0fs and process freezes > %.0fs", REQUEST_STALL_S, PROCESS_STALL_S)

    def _run(self) -> None:
        while not self._stop.wait(TICK_S):
            try:
                self.tick(time.monotonic())
            except Exception as e:  # noqa: BLE001 -- the watchdog must never die
                log.warning("Stall watchdog tick failed: %s", e)

    def stop(self) -> None:
        self._stop.set()
        if self._fh_file is not None:
            faulthandler.cancel_dump_traceback_later()


_watchdog: StallWatchdog | None = None


def start() -> StallWatchdog:
    """Start the process-wide watchdog once (idempotent)."""
    global _watchdog
    if _watchdog is None:
        _watchdog = StallWatchdog()
        _watchdog.start()
    return _watchdog
