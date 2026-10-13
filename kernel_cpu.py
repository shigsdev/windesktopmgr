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

import json
import os
import re
import secrets
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
# StartAddress 0x20 (0 unless elevated), ClientId.UniqueThread 0x30. Verified live on Windows 11 25H2 (2026-10-12).
_SYSTEM_PROCESS_INFORMATION = 5
_PROC_HEADER = 0x100
_PID_OFF = 0x50
_THREAD_SIZE = 0x50
_START_OFF = 0x20
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


def parse_process_thread_details(raw: bytes, pid: int) -> dict[int, tuple[int, int]] | None:
    """``{thread_id: (kernel+user ticks, start address)}`` for ``pid`` from a
    raw SystemProcessInformation buffer, or None when the pid isn't in it or
    the buffer is malformed. Bounds-checked: never reads past ``raw``. Start
    addresses read as 0 unless the caller is elevated."""
    off = 0
    size = len(raw)
    for _ in range(100_000):  # entry-count guard against a looping offset
        if off + _PROC_HEADER > size:
            return None
        nxt, n = struct.unpack_from("<II", raw, off)
        if struct.unpack_from("<Q", raw, off + _PID_OFF)[0] == pid:
            if off + _PROC_HEADER + n * _THREAD_SIZE > size:
                return None
            threads: dict[int, tuple[int, int]] = {}
            for i in range(n):
                t = off + _PROC_HEADER + i * _THREAD_SIZE
                kernel, user = struct.unpack_from("<qq", raw, t)
                start = struct.unpack_from("<Q", raw, t + _START_OFF)[0]
                tid = struct.unpack_from("<Q", raw, t + _TID_OFF)[0]
                threads[tid] = (kernel + user, start)
            return threads
        if nxt == 0:
            return None
        off += nxt
    return None


def parse_process_threads(raw: bytes, pid: int) -> dict[int, int] | None:
    """``{thread_id: kernel+user ticks}`` for ``pid`` (see
    parse_process_thread_details)."""
    details = parse_process_thread_details(raw, pid)
    return None if details is None else {tid: ticks for tid, (ticks, _start) in details.items()}


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
            "cores and raises idle power. Click 'Identify driver' on Temps & Power to name it. "
            "Common causes: " + "; ".join(COMMON_CAUSES) + "."
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


# ══════════════════════════════════════════════════════════════════════
# "Identify driver" (#75 PR 2) -- elevated, on demand
# ══════════════════════════════════════════════════════════════════════
# Thread start addresses and driver base addresses are hidden from an
# unelevated process, so naming the driver runs in a short-lived helper
# (scripts/kernel_cpu_elevated.py) behind a UAC prompt -- the same
# request-file / ShellExecuteW("runas") / result-file pattern as the Backup
# tab's helper. Read-only: it samples and names, it never changes anything.

APP_DIR = os.path.dirname(os.path.abspath(__file__))
IDENTIFY_SECONDS = 10.0
_IDENTIFY_REQUEST_TPL = "kernel_identify_request_{session}.json"
_IDENTIFY_RESULT_TPL = "kernel_identify_result_{session}.json"
SESSION_RE = re.compile(r"[a-f0-9]{12}")

# Known kernel-module offenders -> what to do. Matched on the lowercased
# driver file name's prefix. First match wins, so specific names go first.
DRIVER_HINTS: tuple[tuple[str, str], ...] = (
    ("kfeco", "Intel Killer Prioritization Engine -- turn it off in Killer Intelligence Center."),
    ("killer", "Intel Killer networking software -- turn off its Prioritization Engine or update it."),
    ("wdfilter", "Microsoft Defender's file filter -- usually a scan; if it stays busy, a folder may need excluding."),
    ("nvlddmkm", "NVIDIA graphics driver -- update or clean-reinstall the GPU driver."),
    ("dxgkrnl", "Windows graphics kernel -- update the GPU driver."),
    ("acpi", "ACPI / firmware -- often an interrupt storm; a BIOS update usually fixes it."),
    ("spaceport", "Storage Spaces -- a pool repair or rebuild keeps this busy; check the Storage tab."),
    ("storport", "Storage stack -- check the Storage tab for a failing or rebuilding drive."),
    ("stornvme", "NVMe storage driver -- check the Storage tab for a failing drive."),
    ("ndis", "Network stack -- a network adapter or filter driver; update the network driver."),
    ("tcpip", "Network stack (TCP/IP) -- heavy traffic or a filter driver; check the Network tab."),
    ("ntoskrnl", "The Windows kernel's own worker threads -- normal unless one stays pinned."),
)


def hint_for_driver(name: str) -> str | None:
    """Plain-English next step for a known driver file name, else None."""
    low = (name or "").lower()
    return next((hint for prefix, hint in DRIVER_HINTS if low.startswith(prefix)), None)


# A fix-it hint on a driver using a sliver of a core reads as "this is the
# problem" when it isn't (a 0.2% NVIDIA row said "reinstall the GPU driver"),
# so rows below this share of a core carry no hint. Reassurance-only hints
# (the kernel's own threads are normal) show at any level.
HINT_MIN_PCT = 20.0
_ALWAYS_HINT_PREFIXES = ("ntoskrnl",)


def _row_hint(name: str, pct: float) -> str | None:
    """Hint for an Identify row: only when the driver is busy enough to matter."""
    if pct >= HINT_MIN_PCT or (name or "").lower().startswith(_ALWAYS_HINT_PREFIXES):
        return hint_for_driver(name)
    return None


def driver_for_address(addr: int, drivers: list[tuple[int, str]]) -> str:
    """Name of the loaded kernel module containing ``addr``: the one with the
    highest base address at or below it. ``drivers`` is sorted by base.
    ``(hidden)`` for a 0 address (unelevated), ``(unknown)`` below every base."""
    if not addr:
        return "(hidden)"
    hit = "(unknown)"
    for base, name in drivers:
        if base > addr:
            break
        hit = name
    return hit


def enum_device_drivers() -> list[tuple[int, str]]:
    """``[(base address, file name)]`` of every loaded kernel module, sorted
    by base. Bases read as 0 unless elevated (filtered out). Never raises."""
    if sys.platform != "win32":
        return []
    try:
        import ctypes

        psapi = ctypes.WinDLL("psapi")
        psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
        arr = (ctypes.c_void_p * 4096)()
        needed = ctypes.c_ulong()
        if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return []
        count = min(needed.value // ctypes.sizeof(ctypes.c_void_p), len(arr))
        out = []
        for i in range(count):
            base = arr[i] or 0
            if not base:
                continue
            name = ctypes.create_unicode_buffer(260)
            psapi.GetDeviceDriverBaseNameW(base, name, 260)
            out.append((base, name.value or "(unnamed)"))
        return sorted(out)
    except Exception:  # noqa: BLE001 -- psapi unavailable -> nothing to map
        return []


def summarize_by_driver(
    before: dict[int, tuple[int, int]],
    after: dict[int, tuple[int, int]],
    interval_s: float,
    drivers: list[tuple[int, str]],
    limit: int = 8,
) -> list[dict]:
    """Group per-thread CPU over ``interval_s`` by owning driver, busiest
    first: ``[{"driver", "pct", "threads", "hint"}]``. Threads that used no
    CPU are dropped; ``hint`` is None below ``HINT_MIN_PCT`` (``_row_hint``)."""
    if interval_s <= 0:
        return []
    totals: dict[str, list] = {}
    for tid, (ticks, start) in after.items():
        if tid not in before:
            continue
        delta = ticks - before[tid][0]
        if delta <= 0:
            continue
        entry = totals.setdefault(driver_for_address(start, drivers), [0.0, 0])
        entry[0] += delta / (interval_s * _TICKS_PER_PCT_SECOND)
        entry[1] += 1
    rows = [
        {"driver": name, "pct": round(pct, 1), "threads": n, "hint": _row_hint(name, pct)}
        for name, (pct, n) in totals.items()
    ]
    rows.sort(key=lambda r: -r["pct"])
    return rows[:limit]


def identify_path(kind: str, session: str) -> str:
    """Request/result file for a session (``kind`` = "request" | "result")."""
    tpl = _IDENTIFY_REQUEST_TPL if kind == "request" else _IDENTIFY_RESULT_TPL
    return os.path.join(APP_DIR, tpl.format(session=session))


def request_identify() -> dict:
    """Write a request file and launch the elevated helper via UAC.
    ``{"ok": True, "session_id"}`` once the user accepts the prompt, else
    ``{"ok": False, "error"}`` (declined, helper missing, not Windows)."""
    helper = os.path.join(APP_DIR, "scripts", "kernel_cpu_elevated.py")
    if not os.path.exists(helper):
        return {"ok": False, "error": f"elevated helper not found at {helper}"}
    session = secrets.token_hex(6)
    request_path = identify_path("request", session)
    try:
        with open(request_path, "w", encoding="utf-8") as f:
            json.dump({"session_id": session, "action": "identify", "seconds": IDENTIFY_SECONDS}, f)
    except OSError as e:
        return {"ok": False, "error": f"failed to write request file: {e}"}
    try:
        import ctypes

        # SW_HIDE (0): no console window for the helper.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{helper}" --request "{request_path}"', None, 0
        )
        error = f"admin prompt declined or launch failed (ShellExecuteW rc={rc})"
    except (ImportError, AttributeError, OSError) as e:
        rc, error = 0, f"cannot launch the elevated helper: {e}"
    if rc <= 32:
        try:
            os.remove(request_path)
        except OSError:
            pass
        return {"ok": False, "error": error}
    return {"ok": True, "session_id": session}


def get_identify_status(session_id: str) -> dict:
    """``{"state": "pending"}`` while the helper runs, ``{"state": "done",
    "result"}`` once it wrote its result (the session files are then
    removed), or ``{"state": "missing", "error"}`` for a malformed id."""
    if not SESSION_RE.fullmatch(session_id or ""):
        return {"state": "missing", "error": "invalid session_id"}
    result_path = identify_path("result", session_id)
    if not os.path.exists(result_path):
        return {"state": "pending", "session_id": session_id}
    try:
        with open(result_path, encoding="utf-8") as f:
            result = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"state": "missing", "error": f"result file unreadable: {e}"}
    for kind in ("request", "result"):
        try:
            os.remove(identify_path(kind, session_id))
        except OSError:
            pass
    return {"state": "done", "session_id": session_id, "result": result}


def is_admin() -> bool:
    """True when this process runs elevated (UAC "Yes"). Never raises."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 -- not Windows / shell32 missing
        return False


def enable_debug_privilege() -> bool:
    """Switch on SeDebugPrivilege for this process; True on success.

    Windows 11 hides kernel addresses (thread StartAddress, EnumDeviceDrivers
    bases) even from an elevated process unless this privilege is ENABLED --
    an admin token holds it but disabled. Verified 2026-10-13: the UAC helper
    ran as admin yet every address came back 0. (PowerShell's process APIs
    enable it implicitly, which is why the 2026-10-11 diagnosis script could
    name KfeCo11X64.sys.) Fails harmlessly when unelevated. Never raises."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUIDAndAttributes(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TokenPrivileges(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUIDAndAttributes * 1)]

        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE,
            wintypes.BOOL,
            ctypes.POINTER(TokenPrivileges),
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        token = wintypes.HANDLE()
        token_adjust_and_query = 0x0020 | 0x0008
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_adjust_and_query, ctypes.byref(token)):
            return False
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                return False
            tp = TokenPrivileges(1, (LUIDAndAttributes * 1)(LUIDAndAttributes(luid, 0x00000002)))  # ENABLED
            ctypes.set_last_error(0)
            if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                return False
            # Succeeds even when the token lacks the privilege; that case sets
            # ERROR_NOT_ALL_ASSIGNED (1300), so the last error decides.
            return ctypes.get_last_error() == 0
        finally:
            kernel32.CloseHandle(token)
    except Exception:  # noqa: BLE001 -- any ctypes/OS failure -> not enabled
        return False


def _hidden_note(admin: bool, debug: bool) -> str:
    if not admin:
        return "driver addresses were hidden -- the helper did not run as Administrator"
    if not debug:
        return "driver addresses were hidden -- running as Administrator, but Windows refused the debug privilege"
    return "driver addresses were hidden even with Administrator + debug privilege"


def run_identify(seconds: float = IDENTIFY_SECONDS, sleep=time.sleep) -> dict:
    """The elevated helper's work: two System-process snapshots WITH start
    addresses ``seconds`` apart, attributed to the loaded drivers. Enables
    SeDebugPrivilege first (see enable_debug_privilege) and reports whether
    it ran elevated / got the privilege, so a hidden result says why."""
    admin = is_admin()
    debug = enable_debug_privilege()
    drivers = enum_device_drivers()
    raw = _query_process_info()
    before = parse_process_thread_details(raw, SYSTEM_PID) if raw else None
    t0 = time.monotonic()
    sleep(seconds)
    raw = _query_process_info()
    after = parse_process_thread_details(raw, SYSTEM_PID) if raw else None
    interval = time.monotonic() - t0
    if not before or not after:
        return {"ok": False, "error": "could not read System process threads"}
    named = bool(drivers) and any(start for _ticks, start in after.values())
    return {
        "ok": True,
        "named": named,
        "admin": admin,
        "debug_privilege": debug,
        "sampled_s": round(interval, 1),
        "drivers_mapped": len(drivers),
        "rows": summarize_by_driver(before, after, interval, drivers),
        "note": "" if named else _hidden_note(admin, debug),
    }
