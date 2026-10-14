"""Evidence-only verdicts for the Diagnose storage class (spec 2026-10-13 §6).

``evaluate_storage_rules`` reads the storage probes' evidence and returns a
full verdict in ``diagnose._verdict``'s shape. Rules run in a fixed order,
data-loss risk before speed, and the first that fires leads. When the user
named a drive, the rules first look only at that drive (E: -> the pool and
its members) and only then at everything. Context annotations then add
reasoning lines to whichever rule won.

Drives are named by label-serial tail, model and slot, never by position.
An LHM-only reading on a model this PC has more than one of names the model
and the count, never a guess at which drive.

Import cycle: ``diagnose`` reaches this module only through a wrapper it calls
at run time, and this module touches ``diagnose`` attributes only inside
functions, so either module can be imported first.
"""

from __future__ import annotations

import os
from typing import NamedTuple

import diagnose as dg

WEAR_FAIL_PCT = 90
DRIVE_ERROR_THRESHOLD = 5
FULL_PCT = 10
FULL_GB = 10
BUSY_PCT = 90
SLOW_MS = 20
NAS_STALE_S = 3600
_OK_STATES = ("", "OK")
_HEALTHY = ("", "Healthy")
_FAILED_JOB_STATES = ("Exception", "Killed")
_COUNT_WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}


class _Scope(NamedTuple):
    """What a focused pass may look at; ``None`` in place of a scope means everything."""

    letters: frozenset[str]
    disks: frozenset[int]
    pool: bool


# ── evidence access ──────────────────────────────────────────────────────


def _d(evidence: dict, key: str) -> dict:
    item = evidence.get(key)
    if not isinstance(item, dict) or not item.get("ok"):
        return {}
    data = item.get("data")
    return data if isinstance(data, dict) else {}


def _list(data: dict, key: str) -> list:
    value = data.get(key)
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _drives(ev: dict) -> list[dict]:
    return _list(_d(ev, "storage.physical_disks"), "drives")


def _letters(ev: dict) -> dict[str, list[int]]:
    raw = _d(ev, "storage.physical_disks").get("letters")
    return {k: [int(n) for n in v] for k, v in raw.items() if isinstance(v, list)} if isinstance(raw, dict) else {}


def _known(ev: dict) -> set[int]:
    return {d.get("disk_number") for d in _drives(ev)}


def _drive_by_number(ev: dict, number: int) -> dict | None:
    return next((d for d in _drives(ev) if d.get("disk_number") == number), None)


def _pool_letter(ev: dict) -> str:
    """The letter on a Storage Spaces virtual disk (a disk number no physical drive has)."""
    known = _known(ev)
    return next((letter for letter, disks in sorted(_letters(ev).items()) if disks and not set(disks) & known), "")


def _member_disks(ev: dict) -> set[int]:
    keys = {(m.get("model"), m.get("label_serial_tail")) for m in _list(_d(ev, "storage.pool"), "members")}
    return {
        d["disk_number"]
        for d in _drives(ev)
        if d.get("label_serial_tail") and (d.get("model"), d.get("label_serial_tail")) in keys
    }


def _scope_for(ev: dict, focus: object) -> _Scope | None:
    if not isinstance(focus, str) or not focus:
        return None
    disks = set(_letters(ev).get(focus, []))
    pool = bool(disks) and not disks & _known(ev) and bool(_d(ev, "storage.pool").get("has_spaces"))
    if pool:
        disks |= _member_disks(ev)
    return _Scope(frozenset({focus}), frozenset(disks), pool)


def _disk_ok(scope: _Scope | None, number: object) -> bool:
    return scope is None or number in scope.disks


# ── wording ──────────────────────────────────────────────────────────────


def _num(value: float) -> str:
    value = round(float(value), 1)
    return str(int(value)) if value.is_integer() else str(value)


def _name(drive: dict, cap: bool = True) -> str:
    tail, model, slot = drive.get("label_serial_tail"), drive.get("model", "drive"), drive.get("slot") or "slot unknown"
    text = f"drive …{tail} ({model}, {slot})" if tail else f"the {model} ({slot})"
    return text[0].upper() + text[1:] if cap else text


def _disk_name(ev: dict, number: int) -> str:
    drive = _drive_by_number(ev, number)
    if drive is not None:
        return _name(drive)
    letter = next((ltr for ltr, disks in _letters(ev).items() if number in disks), "")
    return f"Your {letter} pool" if letter and letter == _pool_letter(ev) else f"Disk {number}"


def _model_count(match: list) -> str:
    return _COUNT_WORDS.get(len(match), str(len(match)))


def _period(days: int) -> str:
    return "this week" if days == 7 else f"in the last {days} days"


# ── rules: each returns (key, verdict, evidence_refs, disks) or None ──────


def _rule_pool_trouble(ev: dict, scope: _Scope | None):
    if scope is not None and not scope.pool:
        return None
    pool = _d(ev, "storage.pool")
    letter = _pool_letter(ev) or "storage"
    member = next(
        (
            m
            for m in _list(pool, "members")
            if m.get("operational") not in _OK_STATES or m.get("health") not in _HEALTHY
        ),
        None,
    )
    bad_pool = next(
        (p for p in [*_list(pool, "pools"), *_list(pool, "virtual_disks")] if p.get("health") not in _HEALTHY), None
    )
    failed = next((j for j in _list(pool, "repair_jobs") if j.get("state") in _FAILED_JOB_STATES), None)
    if member is not None:
        state = member.get("operational") or member.get("health")
        dropped = state in ("Lost Communication", "No Contact", "Missing") or "Lost" in str(state)
        what = "dropped out" if dropped else f"is reporting {state}"
        headline = f"Your {letter} pool is degraded: {_name(member, cap=False)} {what}"
        reasoning = (
            f"Storage Spaces reports {_name(member, cap=False)} as {state}. The pool keeps working on its other "
            "drives but has lost its spare copy of your data until that drive is back or replaced."
        )
        disks = [
            d["disk_number"]
            for d in _drives(ev)
            if d.get("label_serial_tail") and d.get("label_serial_tail") == member.get("label_serial_tail")
        ]
    elif bad_pool is not None:
        headline = f"Your {letter} pool is degraded"
        reasoning = f"Storage Spaces reports '{bad_pool.get('name', 'the pool')}' as {bad_pool.get('health')}."
        disks = []
    elif failed is not None:
        headline = f"A repair of your {letter} pool failed"
        reasoning = f"Storage Spaces' {failed.get('name', 'repair')} job ended as {failed.get('state')}."
        disks = []
    else:
        return None
    return "pool_trouble", dg._verdict("confident", "local", headline, reasoning), ["storage.pool"], disks


def _running_job(ev: dict) -> dict | None:
    return next((j for j in _list(_d(ev, "storage.pool"), "repair_jobs") if j.get("state") == "Running"), None)


def _rule_pool_rebuilding(ev: dict, scope: _Scope | None):
    if scope is not None and not scope.pool:
        return None
    job = _running_job(ev)
    if job is None:
        return None
    letter = _pool_letter(ev) or "storage"
    headline = f"Your {letter} pool is rebuilding ({job.get('pct', 0)}%); it will be slow until that finishes"
    reasoning = (
        "Storage Spaces is copying data to restore the pool's spare copy. Every drive in the pool is busy until "
        "it finishes, so reading and writing to it is slower than normal."
    )
    return "pool_rebuilding", dg._verdict("confident", "local", headline, reasoning), ["storage.pool"], []


def _rule_drive_failing(ev: dict, scope: _Scope | None):
    for drive in _drives(ev):
        if not _disk_ok(scope, drive.get("disk_number")):
            continue
        ops = drive.get("operational") or []
        if drive.get("health") in ("Warning", "Unhealthy") or "Predictive Failure" in ops:
            state = "Predictive Failure" if "Predictive Failure" in ops else drive.get("health")
            reasoning = f"Windows reports this drive as {state}: it expects the drive to fail."
            verdict = dg._verdict("confident", "local", f"{_name(drive)} is failing", reasoning)
            return "drive_failing", verdict, ["storage.physical_disks"], [drive["disk_number"]]
    for row in _list(_d(ev, "storage.drive_wear"), "drives"):
        match = [n for n in row.get("match") or [] if _disk_ok(scope, n)]
        if scope is not None and not match:
            continue
        spare, threshold, used = row.get("spare_pct"), row.get("spare_threshold_pct"), row.get("pct_used")
        low_spare = spare is not None and threshold is not None and spare < threshold
        worn = used is not None and used >= WEAR_FAIL_PCT
        if not (low_spare or worn):
            continue
        why = (
            f"its spare capacity is down to {_num(spare)}% (the drive's own limit is {_num(threshold)}%)"
            if low_spare
            else f"it has used {_num(used)}% of its rated life"
        )
        if row.get("ambiguous"):
            headline = f"One of your {_model_count(match)} {row['model']} drives is wearing out"
            reasoning = f"The drive reports {why}. You have more than one of this model, so it can't say which."
            disks = []
        else:
            drive = _drive_by_number(ev, match[0]) if match else None
            headline = f"{_name(drive) if drive else 'Your ' + row['model']} is wearing out"
            reasoning = f"The drive reports {why}."
            disks = match
        return "drive_failing", dg._verdict("confident", "local", headline, reasoning), ["storage.drive_wear"], disks
    return None


def _rule_drive_errors(ev: dict, scope: _Scope | None):
    errors = _d(ev, "storage.disk_errors")
    days = int(errors.get("window_days") or 7)
    present = _known(ev) | {n for disks in _letters(ev).values() for n in disks}
    by_disk = errors.get("by_disk") if isinstance(errors.get("by_disk"), dict) else {}
    hits = []
    for key, slot in by_disk.items():
        try:
            number, count = int(key), int((slot or {}).get("count") or 0)
        except (TypeError, ValueError):
            continue
        if number in present and _disk_ok(scope, number) and count >= DRIVE_ERROR_THRESHOLD:
            hits.append((count, number))
    if hits:
        count, number = max(hits)
        headline = f"{_disk_name(ev, number)} logged {count} disk errors {_period(days)}"
        reasoning = "Windows logged repeated read, write or controller errors for this drive."
        verdict = dg._verdict("likely", "local", headline, reasoning)
        return "drive_errors", verdict, ["storage.disk_errors"], [number]
    corruption = int(errors.get("ntfs_corruption") or 0)
    if corruption and scope is None:
        times = "once" if corruption == 1 else f"{corruption} times"
        headline = f"Windows logged file system corruption {times} {_period(days)}"
        reasoning = "NTFS reported damage it could not fix on its own; a scan can find which files are affected."
        return "drive_errors", dg._verdict("likely", "local", headline, reasoning), ["storage.disk_errors"], []
    return None


def _rule_drive_hot(ev: dict, scope: _Scope | None):
    hot = []
    for row in _list(_d(ev, "storage.drive_wear"), "drives"):
        temp, warn = row.get("temp_c"), row.get("warn_c")
        match = [n for n in row.get("match") or [] if _disk_ok(scope, n)]
        if temp is None or warn is None or temp < warn or (scope is not None and not match):
            continue
        hot.append((temp, row, match))
    if not hot:
        return None
    temp, row, match = max(hot, key=lambda h: h[0])
    if row.get("ambiguous"):
        headline = f"One of your {_model_count(match)} {row['model']} drives is at {_num(temp)} °C"
        disks = []
    else:
        drive = _drive_by_number(ev, match[0]) if match else None
        headline = f"{_name(drive) if drive else 'Your ' + row['model']} is at {_num(temp)} °C"
        disks = match
    reasoning = f"That is at or above the drive's own warning temperature of {_num(row['warn_c'])} °C."
    return "drive_hot", dg._verdict("likely", "local", headline, reasoning), ["storage.drive_wear"], disks


def _full_volumes(ev: dict, scope: _Scope | None) -> list[dict]:
    return [
        v
        for v in _list(_d(ev, "storage.volumes"), "volumes")
        if v.get("fixed")
        and (scope is None or v.get("letter") in scope.letters)
        and (float(v.get("free_gb") or 0) < FULL_GB or float(v.get("free_pct") or 0) < FULL_PCT)
    ]


def _rule_volume_full(ev: dict, scope: _Scope | None):
    full = _full_volumes(ev, scope)
    if not full:
        return None
    vol = min(full, key=lambda v: float(v.get("free_pct") or 0))
    headline = f"{vol['letter']} has {_num(vol.get('free_gb') or 0)} GB free ({_num(vol.get('free_pct') or 0)}%)"
    reasoning = (
        f"Windows needs free space to work well; under {FULL_PCT}% or {FULL_GB} GB free, updates, copies and "
        "programs start failing or slowing down."
    )
    verdict = dg._verdict("confident", "local", headline, reasoning, full_letter=vol["letter"])
    return "volume_full", verdict, ["storage.volumes"], []


def _rule_slow_now(ev: dict, scope: _Scope | None):
    slow = []
    for disk in _list(_d(ev, "storage.io_sample"), "disks"):
        number = disk.get("disk_number")
        if not _disk_ok(scope, number):
            continue
        busy = int(disk.get("busy_pct") or 0)
        worst_ms = max(float(disk.get("avg_read_ms") or 0), float(disk.get("avg_write_ms") or 0))
        if busy >= BUSY_PCT or worst_ms > SLOW_MS:
            slow.append((busy, worst_ms, disk))
    if not slow:
        return None
    busy, worst_ms, disk = max(slow, key=lambda s: (s[0], s[1]))
    name = _disk_name(ev, disk["disk_number"])
    if busy >= BUSY_PCT:
        headline = f"{name} was {busy}% busy during the check"
    else:
        kind = "read" if float(disk.get("avg_read_ms") or 0) >= float(disk.get("avg_write_ms") or 0) else "write"
        headline = f"{name} averaged {_num(worst_ms)} ms per {kind} during the check"
    reasoning = "In a 3-second sample the drive was saturated, so anything else using it has to wait."
    return "slow_now", dg._verdict("likely", "local", headline, reasoning), ["storage.io_sample"], [disk["disk_number"]]


def _stale_hours(ev: dict) -> int:
    ages = [n.get("age_s") for n in _list(_d(ev, "storage.nas"), "nas") if isinstance(n.get("age_s"), (int, float))]
    oldest = max(ages, default=0)
    return int(oldest // 3600) if oldest > NAS_STALE_S else 0


def _rule_nas_problem(ev: dict, scope: _Scope | None):
    if scope is not None:
        return None
    concern = next(
        (c for c in _list(_d(ev, "storage.nas"), "concerns") if c.get("level") in ("warning", "critical")), None
    )
    if concern is not None:
        headline = f"The NAS reports: {concern.get('title', 'a problem')}"
        reasoning = concern.get("detail") or "The NAS's own health reading shows a problem."
    elif _stale_hours(ev):
        headline = f"The NAS hasn't been read for {_stale_hours(ev)} hours"
        reasoning = "The app's last reading of the NAS is old, so it may be off or unreachable."
    else:
        return None
    return "nas_problem", dg._verdict("likely", "external_cause", headline, reasoning), ["storage.nas"], []


_RULES = (
    _rule_pool_trouble,
    _rule_pool_rebuilding,
    _rule_drive_failing,
    _rule_drive_errors,
    _rule_drive_hot,
    _rule_volume_full,
    _rule_slow_now,
    _rule_nas_problem,
)

_BACKUP_STEP = (
    "Back up anything important from that drive now, and check the Backup tab for when Backup and Restore last "
    "finished."
)
_LABEL_STEP = (
    "Find the drive by the serial printed on its label on the Storage tab before touching anything, so the right "
    "drive is handled."
)
_STEPS = {
    "pool_trouble": [
        _BACKUP_STEP,
        _LABEL_STEP,
        "Don't shut down or restart while a pool repair is running.",
        "If the drive shows Lost Communication, shut down and reseat that one drive; if it is failing, replace it "
        "and let the pool repair onto the new one.",
        "If the drive is under warranty, the serial on its label is what the maker will ask for.",
    ],
    "pool_rebuilding": [
        "Leave the PC on until the rebuild finishes; a restart can make it start over.",
        "Large copies to or from the pool will be slow until then.",
        "Run Diagnose again once it reaches 100% to confirm the pool is healthy.",
    ],
    "drive_failing": [
        _BACKUP_STEP,
        _LABEL_STEP,
        "Replace that drive; if it is in the pool, the pool repairs onto the replacement.",
        "If the drive is under warranty, the serial on its label is what the maker will ask for.",
    ],
    "drive_errors": [
        "Run the read-only scan yourself in an admin terminal: chkdsk X: /scan (X is the drive letter). It checks "
        "and changes nothing.",
        "Check for an SSD firmware update (Samsung Magician for Samsung drives).",
        "If the errors keep coming, back up that drive and watch its health on the Storage tab.",
        "If the drive is in the pool, check the pool's state on the Storage tab.",
    ],
    "drive_hot": [
        "Check the airflow around the drive and that its heatsink is fitted.",
        "Note whether a big copy or backup was running; heavy writing heats NVMe drives.",
        "Run Diagnose again once the PC has been idle for a few minutes.",
    ],
    "volume_full": [
        "Open the Cleanup tab to clear junk files safely.",
        "Use the Disk tab's space analysis on that drive to see what is using the space.",
    ],
    "slow_now": [
        "Check the Processes tab to see which app is using the disk.",
        "If the pool is rebuilding, wait for it to finish.",
        "Run Diagnose again while it is slow; it can take a longer 10-second sample.",
    ],
    "nas_problem": [
        "Open the NAS's own admin page and check that disk or volume.",
        "If a NAS disk reports a warning, back up what is on the NAS before replacing the disk.",
        "If the NAS can't be reached, check that it is powered on and connected to the network.",
    ],
}


def _context(ev: dict, key: str, disks: list[int]) -> tuple[list[str], list[str]]:
    hits: list[str] = []
    lines: list[str] = []
    job = _running_job(ev)
    if key == "slow_now" and job is not None:
        hits.append("rebuild_in_progress")
        lines.append(
            f"Your {_pool_letter(ev) or 'storage'} pool is also rebuilding ({job.get('pct', 0)}%), "
            "which keeps its drives busy."
        )
    by_disk = _d(ev, "storage.disk_errors").get("by_disk") or {}
    if key in ("drive_failing", "pool_trouble") and any(
        int((by_disk.get(str(n)) or {}).get("count") or 0) > 0 for n in disks
    ):
        hits.append("errors_on_same_drive")
        lines.append("Windows also logged disk errors for this drive.")
    wear = ev.get("storage.drive_wear") if isinstance(ev.get("storage.drive_wear"), dict) else {}
    if not wear.get("ok") or not _d(ev, "storage.drive_wear").get("available", False):
        hits.append("wear_unavailable")
        reason = _d(ev, "storage.drive_wear").get("reason") or "LibreHardwareMonitor's reading wasn't available."
        lines.append(f"Drive wear and temperature weren't checked: {reason}")
    if key == "nas_problem" and _stale_hours(ev):
        hits.append("nas_stale")
        lines.append(f"The NAS reading is {_stale_hours(ev)} hours old, so it may not show the latest state.")
    return hits, lines


def _unread_sources(ev: dict) -> list[str]:
    out = []
    for key in (
        "storage.physical_disks",
        "storage.pool",
        "storage.disk_errors",
        "storage.volumes",
        "storage.io_sample",
    ):
        item = ev.get(key)
        if isinstance(item, dict) and not item.get("ok"):
            out.append(item.get("label") or key)
    return out


def _absent_disk_errors(ev: dict) -> int:
    present = _known(ev) | {n for disks in _letters(ev).values() for n in disks}
    total = 0
    for key, slot in (_d(ev, "storage.disk_errors").get("by_disk") or {}).items():
        try:
            if int(key) not in present:
                total += int((slot or {}).get("count") or 0)
        except (TypeError, ValueError):
            continue
    return total


def _first_hit(ev: dict, scope: _Scope | None):
    return next((hit for hit in (rule(ev, scope) for rule in _RULES) if hit is not None), None)


def evaluate_storage_rules(evidence: dict[str, dict]) -> dict:
    """Evidence-only verdict for the ``storage`` class; always a full verdict."""
    ev = evidence if isinstance(evidence, dict) else {}
    scope = _scope_for(ev, _d(ev, "storage.physical_disks").get("focus"))
    hit = (_first_hit(ev, scope) if scope is not None else None) or _first_hit(ev, None)
    if hit is None:
        verdict = dg._verdict(
            "inconclusive",
            "unknown",
            "No storage problem found right now",
            "The drives, the pool, the last 7 days of disk-error logs, free space, a 3-second activity sample and "
            "the NAS show no problem.",
            rule_hits=["nothing_found"],
            manual_steps=["If the problem comes and goes, run Diagnose again while it is happening."],
        )
        absent = _absent_disk_errors(ev)
        if absent:
            verdict["reasoning"] += (
                f" {absent} disk errors were logged for a disk that no longer exists, usually a backup image "
                "Windows mounts while it backs up."
            )
        unread = _unread_sources(ev)
        if unread:
            verdict["reasoning"] += (
                f" Some checks could not run ({', '.join(unread)}), so a problem there could have been missed."
            )
        return verdict
    key, verdict, refs, disks = hit
    hits, lines = _context(ev, key, disks)
    verdict["rule_hits"] = [key, *hits]
    if lines:
        verdict["reasoning"] = " ".join([verdict["reasoning"], *lines])
    verdict["evidence_refs"] = refs
    steps = list(_STEPS[key])
    full_letter = verdict.pop("full_letter", None)
    # Clearing temp files is the one vetted action, and it only frees space on the system drive.
    if key == "volume_full" and full_letter == os.environ.get("SYSTEMDRIVE", "C:").upper():
        verdict["suggested_actions"] = ["clear_temp"]
        steps.append("The Clear temp files button below removes Windows' temporary files from this drive.")
    verdict["manual_steps"] = dg.clean_steps(steps)
    return verdict
