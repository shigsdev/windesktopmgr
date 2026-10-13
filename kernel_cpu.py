"""kernel_cpu.py -- spot a kernel driver pinning a CPU core (backlog #75).

Found 2026-10-11: Intel Killer Traffic Control (KfeCo11X64.sys) had ONE
thread of the Windows "System" process spinning at ~99% of a core around
the clock. Windows parked it on the favoured P-cores, so the CPU ran 68-83 C
at ~5% load and ~60 W idle. Nothing in the app could see it -- psutil and
Get-Process can't read the System process's per-thread CPU, and the Thermals
tab only showed temperatures.

How it works (read-only, unelevated, pure Python via ctypes):
  NtQuerySystemInformation(SystemProcessInformation) returns every process's
  thread kernel+user times WITHOUT opening any thread -- the same snapshot
  Task Manager reads. We keep the previous snapshot of PID 4 and diff the
  next one. A thread above STUCK_PCT of one core for STUCK_INTERVALS
  consecutive intervals (each >= MIN_INTERVAL_S) is a stuck driver thread,
  distinct from normal ntoskrnl worker churn (a few % to ~20% in bursts).

No background thread: sample() runs from get_thermals(), i.e. on every
dashboard refresh and Thermals tab load. A thread pinned 24/7 shows up over
any interval, so sampling only while the app is being looked at is enough.
Naming the driver needs admin (thread start addresses are hidden
unelevated) -- that's a separate UAC "Identify driver" step (#75 PR 2).
"""

from __future__ import annotations

import struct
import sys
import threading
import time
from datetime import datetime
from typing import Any

SYSTEM_PID = 4
STUCK_PCT = 50.0  # % of ONE core a single thread must exceed
MIN_INTERVAL_S = 20.0  # shorter intervals are too noisy to count
STUCK_INTERVALS = 2  # consecutive over-threshold intervals => stuck

# x64 layouts. SYSTEM_PROCESS_INFORMATION: NextEntryOffset (ULONG) at 0x00,
# NumberOfThreads (ULONG) at 0x04, UniqueProcessId at 0x50, entry header is
# 0x100 bytes, followed by NumberOfThreads SYSTEM_THREAD_INFORMATION records
# of 0x50 bytes each: KernelTime 0x00, UserTime 0x08 (100-ns ticks),
# ClientId.UniqueThread 0x30. Verified live on Windows 11 25H2 (2026-10-12).
_SYSTEM_PROCESS_INFORMATION = 5
_PROC_HEADER = 0x100
_PID_OFF = 0x50
_THREAD_SIZE = 0x50
_TID_OFF = 0x30
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_TICKS_PER_PCT_SECOND = 100_000  # 1e7 ticks per core-second / 100

# Usual suspects, named in the concern so the user knows where to look
# before the elevated "Identify driver" step exists.
COMMON_CAUSES = (
    "Intel Killer Prioritization Engine (turn it off in Killer Intelligence Center)",
    "an anti-virus, VPN or firewall filter driver",
    "a network, storage or RGB/peripheral driver stuck in a loop",
)


def parse_process_threads(raw: bytes, pid: int) -> dict[int, int] | None:
    """``{thread_id: kernel+user ticks}`` for ``pid`` from a raw
    SystemProcessInformation buffer, or None when the pid isn't in it or the
    buffer is malformed. Bounds-checked: never reads past ``raw``."""
    off = 0
    size = len(raw)
    for _ in range(100_000):  # entry-count guard against a looping offset
        if off + _PROC_HEADER > size:
            return None
        nxt, n = struct.unpack_from("<II", raw, off)
        if struct.unpack_from("<Q", raw, off + _PID_OFF)[0] == pid:
            if off + _PROC_HEADER + n * _THREAD_SIZE > size:
                return None
            threads: dict[int, int] = {}
            for i in range(n):
                t = off + _PROC_HEADER + i * _THREAD_SIZE
                kernel, user = struct.unpack_from("<qq", raw, t)
                tid = struct.unpack_from("<Q", raw, t + _TID_OFF)[0]
                threads[tid] = kernel + user
            return threads
        if nxt == 0:
            return None
        off += nxt
    return None


def _query_process_info() -> bytes | None:
    """Raw SystemProcessInformation buffer, or None off-Windows / on error."""
    if sys.platform != "win32":
        return None
    import ctypes

    ntdll = ctypes.WinDLL("ntdll")
    size = 4 << 20
    for _ in range(8):  # grow until it fits (process list changes between calls)
        buf = ctypes.create_string_buffer(size)
        ret = ctypes.c_ulong()
        status = ntdll.NtQuerySystemInformation(_SYSTEM_PROCESS_INFORMATION, buf, size, ctypes.byref(ret))
        status &= 0xFFFFFFFF
        if status == 0:
            return buf.raw[: ret.value or size]
        if status != _STATUS_INFO_LENGTH_MISMATCH:
            return None
        size = max(size * 2, ret.value + 65536)
    return None


def snapshot_system_threads() -> dict[int, int] | None:
    """Per-thread CPU ticks of the System process right now. Never raises."""
    try:
        raw = _query_process_info()
        return parse_process_threads(raw, SYSTEM_PID) if raw else None
    except Exception:  # noqa: BLE001 -- ctypes/OS failure -> unavailable
        return None


# ── Sampler state (module-level; reset_globals clears it between tests) ──
_lock = threading.Lock()
_prev: tuple[float, dict[int, int]] | None = None
_streaks: dict[int, tuple[int, float]] = {}  # tid -> (consecutive intervals, stuck-since monotonic)
_last: dict[str, Any] | None = None


def _reset() -> None:
    global _prev, _last
    with _lock:
        _prev = None
        _last = None
        _streaks.clear()


def _unavailable(reason: str) -> dict:
    return {"available": False, "reason": reason, "busiest": None, "stuck": []}


def sample(now: float | None = None, snap: dict[int, int] | None = None) -> dict:
    """Take a snapshot, diff it against the previous one, update the stuck
    streaks, and return the latest verdict::

        {"available": bool, "interval_s": float, "total_pct": float,
         "busiest": {"tid", "pct"} | None,
         "stuck": [{"tid", "pct", "minutes"}], "sampled_at": iso}

    Intervals shorter than MIN_INTERVAL_S don't count: the previous verdict
    is returned unchanged (Thermals auto-refresh calls this every 10 s).
    ``now`` (monotonic seconds) and ``snap`` are injectable for tests.
    """
    global _prev, _last
    now = time.monotonic() if now is None else now
    snap = snapshot_system_threads() if snap is None else snap
    if not snap:
        return _unavailable("System process thread times could not be read")

    with _lock:
        if _prev is None:
            _prev = (now, snap)
            return _last or {**_unavailable("warming up -- first sample taken"), "warming_up": True}
        prev_t, prev_snap = _prev
        interval = now - prev_t
        if interval < MIN_INTERVAL_S:
            return _last or {**_unavailable("warming up -- waiting for a long enough interval"), "warming_up": True}
        _prev = (now, snap)

        pcts = {
            tid: round((ticks - prev_snap[tid]) / (interval * _TICKS_PER_PCT_SECOND), 1)
            for tid, ticks in snap.items()
            if tid in prev_snap and ticks >= prev_snap[tid]
        }
        stuck = []
        for tid in list(_streaks):
            if pcts.get(tid, 0.0) <= STUCK_PCT:
                del _streaks[tid]
        for tid, pct in pcts.items():
            if pct > STUCK_PCT:
                count, since = _streaks.get(tid, (0, prev_t))
                _streaks[tid] = (count + 1, since)
                if count + 1 >= STUCK_INTERVALS:
                    stuck.append({"tid": tid, "pct": pct, "minutes": round((now - since) / 60, 1)})

        busiest_tid = max(pcts, key=pcts.get, default=None)
        _last = {
            "available": True,
            "interval_s": round(interval, 1),
            "total_pct": round(sum(pcts.values()), 1),
            "busiest": {"tid": busiest_tid, "pct": pcts[busiest_tid]} if busiest_tid is not None else None,
            "stuck": sorted(stuck, key=lambda s: -s["pct"]),
            "sampled_at": datetime.now().isoformat(timespec="seconds"),
        }
        return _last


def stuck_concern(state: dict | None) -> dict | None:
    """Dashboard concern for a stuck kernel thread, or None."""
    stuck = (state or {}).get("stuck") or []
    if not stuck:
        return None
    worst = stuck[0]
    more = f" (+{len(stuck) - 1} more thread(s))" if len(stuck) > 1 else ""
    return {
        "level": "warning",
        "tab": "thermals",
        "icon": "🧵",
        "title": (
            f"A Windows driver is keeping one CPU core busy "
            f"(~{worst['pct']:.0f}% of a core for {worst['minutes']:.0f} min){more}"
        ),
        "detail": (
            "A kernel thread in the System process has stayed above half a core. That heats the fastest "
            "cores and raises idle power. Common causes: " + "; ".join(COMMON_CAUSES) + "."
        ),
        "action": "View Temps & Power",
        "action_fn": "switchTab('thermals')",
    }


def kernel_cpu_selftest() -> dict:
    """/api/selftest probe: the REAL ntdll call must still parse into a
    plausible System-process thread list. Catches a Windows update changing
    the struct layout, which mocked tests can't."""
    snap = snapshot_system_threads()
    if not snap:
        return {"error": "could not read System process threads (NtQuerySystemInformation)"}
    if len(snap) < 10:
        return {"error": f"implausible System thread count {len(snap)} -- struct layout changed?"}
    return {"ok": True, "threads": len(snap)}
