"""cloudcopy.py -- OneDrive -> iCloud one-way file replicator (backlog #46).

Section 3 of the unified Backup tab introduced by #47. PR-1 of three:

  PR-1 (THIS PR)
    - Rule schema + load/save (cloudcopy_rules.json)
    - File walker that respects exclusion rules
    - Preview generator (count + bytes + sample paths)
    - Read-only helpers for history + resume state (return empty
      placeholders here; PR-2 fills them in once the copy engine ships)
    - Pure functions only -- NO actual copying yet

  PR-2 (next)
    - Worker-thread copy engine with atomic per-file commit
    - Crash-safe resume from cloudcopy_state.json
    - Cancel via cooperative flag

  PR-3 (later)
    - 4-parallel copies via ThreadPoolExecutor
    - Optional nightly schedule via Windows Task Scheduler
    - Run-history UI panel polish

Design philosophy:
  - SOURCE-WINS conflict mode (locked V1 spec): OneDrive is authoritative,
    iCloud is the downstream mirror. iCloud-side edits are overwritten
    on the next run.
  - FILES ONLY, same directory structure as OneDrive: photo files land
    in the mirrored tree, NOT in the Photos.app library (that needs the
    iCloud Photos API which is explicitly out of scope).
  - EXCLUDE-ONLY rule model: default = mirror everything, user strikes
    out what they don't want. Three exclude dimensions:
        (a) folder paths (e.g. "Work-Confidential", "Backup Data")
        (b) file extensions (e.g. ".tmp", ".bak", ".iso")
        (c) filename glob patterns (e.g. "~$*", "Thumbs.db")
  - PERSONAL VAULT excluded by default; opt-in toggle to override.
    Personal Vault files are encrypted at rest by OneDrive and copying
    them sideways defeats the protection.

Public API (PR-1 surface):
    DEFAULT_RULES         -- baseline excludes that ship with the app
    load_rules()          -- read cloudcopy_rules.json, or DEFAULT_RULES
    save_rules(rules)     -- atomic write of user rules
    is_excluded(rel_path, name, ext, rules) -- pure predicate
    walk_source(source_root, rules, *, sample_only=False)
                          -- generator yielding selected file entries
    preview(rules, source_root=None, sample_size=50)
                          -- {included_count, included_bytes, ...}
    load_history()        -- empty list in PR-1
    load_resume_state()   -- None in PR-1
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import subprocess
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime

try:
    from applogging import get_logger

    _log = get_logger("cloudcopy")
except Exception:  # noqa: BLE001
    import logging

    _log = logging.getLogger("windesktopmgr.cloudcopy")

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Persistence files. PR-1 only writes RULES; the other two are read
# (and return empty placeholders) so the API + UI can be wired without
# the copy engine landing first.
RULES_FILE = os.path.join(APP_DIR, "cloudcopy_rules.json")
STATE_FILE = os.path.join(APP_DIR, "cloudcopy_state.json")
HISTORY_FILE = os.path.join(APP_DIR, "cloudcopy_history.json")

# Source / destination defaults. Honour the OneDrive env var (Microsoft
# sets it during install) and fall back to the well-known location.
# ruff SIM112: the env var is literally named "OneDrive" (mixed case)
# by Microsoft -- not all-caps as the linter expects.
DEFAULT_SOURCE_ROOT = os.environ.get("OneDrive") or os.path.join(  # noqa: SIM112
    os.environ.get("USERPROFILE", ""), "OneDrive"
)
DEFAULT_DESTINATION_ROOT = os.path.join(
    os.environ.get("USERPROFILE", ""),
    "iCloudDrive",
    "OneDrive-Mirror",
)

# Safety caps for the walker. The user's OneDrive can hold 100,000+
# files; a totally-unbounded walk could lock the request thread for
# minutes. Preview mode stops early once we have enough sample paths;
# real copy walks the full tree but reports progress.
_PREVIEW_FILE_CAP = 50_000

# A reasonable default rule-set baked in so a brand-new install gets
# sensible behaviour on day one without forcing the user to configure
# anything. Each list is exclusion-only.
DEFAULT_RULES: dict = {
    "version": 1,
    "exclude_folders": [
        # OneDrive's own metadata / thumbnail cache.
        ".@__thumb",
        # Personal Vault is encrypted at rest by OneDrive; copying it
        # sideways defeats that protection. Opt-in toggle below.
        "Personal Vault",
    ],
    "exclude_extensions": [
        # Office / app temp + lock files.
        ".tmp",
        ".bak",
        ".partial",
        # Browser-in-flight downloads.
        ".crdownload",
        # Hibernation / pagefile shells that occasionally appear.
        ".sys",
    ],
    "exclude_filename_globs": [
        # Office lock files for open documents.
        "~$*",
        # Windows + macOS metadata.
        "Thumbs.db",
        ".DS_Store",
        "desktop.ini",
        # OneDrive sync conflict markers.
        "*-OneDrive-*conflict*",
    ],
    # Override the always-excluded Personal Vault default. False (default)
    # = vault is excluded; True = include it. We never include vault by
    # default because the protection trade-off should be explicit.
    "include_personal_vault": False,
    # Source / destination roots. None = use the module defaults so the
    # user doesn't have to configure them on first run.
    "source_root": None,
    "destination_root": None,
    # Schedule (PR-3). DEFAULT OFF (user-confirmed 2026-05-25): no
    # Windows Task Scheduler entry is created until the user explicitly
    # clicks Enable on the Section 3 toggle. PR-2 ships the schema
    # field but no scheduler wiring -- PR-3 lights it up.
    "schedule_enabled": False,
    "schedule_time": "02:00",  # 24h HH:MM, ignored until schedule_enabled=True
}


# ── Persistence ─────────────────────────────────────────────────────


# RLock (reentrant) -- _append_history acquires the lock then calls
# load_history() which would also want it. Lock would deadlock.
_file_lock = threading.RLock()


def _atomic_write_json(path: str, payload) -> bool:
    """Atomic-rename .tmp -> path. Returns True on success."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def load_rules() -> dict:
    """Read user-configured rules or fall back to DEFAULT_RULES.

    Always returns a dict shaped exactly like DEFAULT_RULES -- missing
    keys are filled in from the defaults so the UI never has to
    null-check. Unknown keys in the file are preserved (forward-compat
    with PR-2 / PR-3 rule additions).
    """
    with _file_lock:
        if not os.path.exists(RULES_FILE):
            return dict(DEFAULT_RULES)
        try:
            with open(RULES_FILE, encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return dict(DEFAULT_RULES)
        except (OSError, json.JSONDecodeError):
            return dict(DEFAULT_RULES)
    merged = dict(DEFAULT_RULES)
    merged.update(raw)
    # Coerce the list fields to lists even if a malformed file had them
    # as strings or None.
    for key in ("exclude_folders", "exclude_extensions", "exclude_filename_globs"):
        v = merged.get(key)
        if not isinstance(v, list):
            merged[key] = list(DEFAULT_RULES[key])
    if not isinstance(merged.get("include_personal_vault"), bool):
        merged["include_personal_vault"] = False
    return merged


def validate_rules(rules: dict) -> tuple[bool, str]:
    """Validate a rules dict before save. Returns ``(ok, error_message)``.

    Errors caught:
      - Not a dict
      - List fields contain non-string entries
      - Folder excludes contain path separators (must be top-level names
        OR rooted-path-relative-to-source -- we keep them simple by
        refusing separators for V1; user can use globs for nested
        patterns)
      - include_personal_vault not bool
      - source_root / destination_root not str / None
    """
    if not isinstance(rules, dict):
        return (False, "rules must be a dict")
    for key in ("exclude_folders", "exclude_extensions", "exclude_filename_globs"):
        v = rules.get(key)
        if v is None:
            continue  # absent is fine; defaults fill in
        if not isinstance(v, list):
            return (False, f"{key} must be a list, got {type(v).__name__}")
        for entry in v:
            if not isinstance(entry, str):
                return (False, f"{key} entries must be strings; got {entry!r}")
        if key == "exclude_extensions":
            for entry in v:
                if entry and not entry.startswith("."):
                    return (False, f"exclude_extensions entries must start with '.', got {entry!r}")
    pv = rules.get("include_personal_vault")
    if pv is not None and not isinstance(pv, bool):
        return (False, "include_personal_vault must be a bool")
    for key in ("source_root", "destination_root"):
        v = rules.get(key)
        if v is not None and not isinstance(v, str):
            return (False, f"{key} must be a string or null")
    se = rules.get("schedule_enabled")
    if se is not None and not isinstance(se, bool):
        return (False, "schedule_enabled must be a bool")
    st = rules.get("schedule_time")
    if st is not None and (not isinstance(st, str) or not _is_valid_hhmm(st)):
        return (False, "schedule_time must be a 24h HH:MM string")
    return (True, "")


def _is_valid_hhmm(s: str) -> bool:
    """Strict HH:MM validation -- 00:00 through 23:59, BOTH zero-padded.

    Rejects "2:00", "23:5", etc to keep the persisted format stable
    (Windows Task Scheduler is picky about time strings and the UI's
    HH:MM input element produces zero-padded output).
    """
    parts = s.split(":")
    if len(parts) != 2 or len(parts[0]) != 2 or len(parts[1]) != 2:
        return False
    try:
        h, m = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return 0 <= h <= 23 and 0 <= m <= 59


def save_rules(rules: dict) -> tuple[bool, str]:
    """Validate + atomically persist rules. Returns ``(ok, error_message)``."""
    ok, err = validate_rules(rules)
    if not ok:
        return (False, err)
    # Merge with defaults so the persisted file is always complete (no
    # downstream code has to null-check).
    persisted = dict(DEFAULT_RULES)
    persisted.update(rules)
    with _file_lock:
        if not _atomic_write_json(RULES_FILE, persisted):
            return (False, "atomic write failed")
    return (True, "")


# ── Exclusion predicate (pure function) ─────────────────────────────


def is_excluded(rel_path: str, name: str, ext: str, rules: dict) -> tuple[bool, str]:
    """Decide whether a single file at relative path ``rel_path``
    (separator = forward slash, no leading slash) should be excluded.

    Returns ``(is_excluded, reason)``. ``reason`` is a short tag so the
    preview can show WHY each excluded sample was excluded.

    ``rel_path`` is the path relative to the source root. ``name`` is
    just the basename. ``ext`` is the lowercased extension including
    the dot (or "" for no extension).

    Match order matters for the reason field: we surface the FIRST
    applicable rule so the user sees the most-specific exclusion.
    """
    # Personal Vault: always excluded unless the toggle says otherwise.
    pv_segments = ("Personal Vault", "personal vault")
    if not rules.get("include_personal_vault", False):
        # Check the path segments for "Personal Vault" -- it lives as
        # a top-level folder under OneDrive.
        parts = rel_path.split("/")
        for seg in parts:
            if seg in pv_segments:
                return (True, "personal_vault")

    # Folder excludes. Match if ANY path segment equals an excluded
    # name (case-insensitive). Folder excludes are intentionally
    # name-level, not path-level, so excluding "Backup Data" hits the
    # folder anywhere it appears (top-level or nested).
    exclude_folders = rules.get("exclude_folders") or []
    parts = rel_path.split("/")
    # Drop the last part (the filename); folders are everything before it.
    folder_parts = parts[:-1] if len(parts) > 1 else []
    folder_excludes_lower = {f.lower() for f in exclude_folders if isinstance(f, str)}
    for seg in folder_parts:
        if seg.lower() in folder_excludes_lower:
            return (True, f"folder:{seg}")

    # Extension excludes. Compare case-insensitive.
    exclude_extensions = rules.get("exclude_extensions") or []
    ext_lower = ext.lower()
    for x in exclude_extensions:
        if isinstance(x, str) and x.lower() == ext_lower:
            return (True, f"extension:{x}")

    # Filename glob excludes. fnmatch handles "*", "?", "[seq]".
    exclude_globs = rules.get("exclude_filename_globs") or []
    for pat in exclude_globs:
        if isinstance(pat, str) and fnmatch.fnmatch(name, pat):
            return (True, f"glob:{pat}")

    return (False, "")


# ── Source walker  ──────────────────────────────────────────────────


def walk_source(
    source_root: str,
    rules: dict,
    *,
    file_cap: int | None = None,
) -> Iterator[dict]:
    """Yield ``{rel_path, name, ext, size, mtime, excluded, reason}`` for
    every file under ``source_root`` (or until ``file_cap`` is hit).

    Pure-ish: only does ``os.scandir`` + ``stat`` calls; never opens a
    file, never materialises a Files-On-Demand placeholder. Safe to run
    against a fully-virtualised OneDrive folder.

    Iterates in deterministic order (sorted per-directory) so the
    preview's "sample paths" are stable across runs with the same rules.
    """
    if not source_root or not os.path.isdir(source_root):
        return
    yielded = 0

    def _walk(dirpath: str, rel_dir: str):
        nonlocal yielded
        if file_cap is not None and yielded >= file_cap:
            return
        try:
            entries = sorted(os.scandir(dirpath), key=lambda e: e.name.lower())
        except OSError:
            return
        for entry in entries:
            if file_cap is not None and yielded >= file_cap:
                return
            rel = entry.name if not rel_dir else rel_dir + "/" + entry.name
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                # Folder-level excludes still let us walk INTO the folder
                # (because nested matches may have different rules
                # someday), but for V1 we prune to save time.
                seg = entry.name
                exclude_folders = rules.get("exclude_folders") or []
                if not rules.get("include_personal_vault", False) and seg in ("Personal Vault", "personal vault"):
                    continue
                if seg.lower() in {f.lower() for f in exclude_folders if isinstance(f, str)}:
                    continue
                yield from _walk(entry.path, rel)
                continue
            # File. Stat + classify.
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            base, dot_ext = os.path.splitext(entry.name)
            excluded, reason = is_excluded(rel, entry.name, dot_ext, rules)
            yielded += 1
            yield {
                "rel_path": rel,
                "name": entry.name,
                "ext": dot_ext,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "excluded": excluded,
                "reason": reason,
            }

    yield from _walk(source_root, "")


# ── Preview ─────────────────────────────────────────────────────────


def preview(
    rules: dict | None = None,
    source_root: str | None = None,
    sample_size: int = 50,
) -> dict:
    """Walk the source root with ``rules`` and report what WOULD be
    copied (without copying anything).

    Returns::

        {
            "ok": True,
            "source_root": "<path>",
            "destination_root": "<path>",
            "included_count": int,
            "included_bytes": int,
            "excluded_count": int,
            "included_sample": [{rel_path, size}, ...]    # up to sample_size
            "excluded_sample": [{rel_path, reason}, ...]  # up to sample_size
            "file_cap_hit": bool,                # True if walker hit the cap
            "walked_at": "<iso>",
        }

    ``file_cap_hit=True`` means the numbers are LOWER BOUNDS -- the
    walker stopped early because the source tree is larger than
    _PREVIEW_FILE_CAP. The UI should display "50,000+ files" in that
    case rather than the literal number.
    """
    rules = rules if rules is not None else load_rules()
    src = source_root or rules.get("source_root") or DEFAULT_SOURCE_ROOT
    dst = rules.get("destination_root") or DEFAULT_DESTINATION_ROOT

    included_count = 0
    included_bytes = 0
    excluded_count = 0
    included_sample: list[dict] = []
    excluded_sample: list[dict] = []

    walked = 0
    cap_hit = False
    for entry in walk_source(src, rules, file_cap=_PREVIEW_FILE_CAP):
        walked += 1
        if entry["excluded"]:
            excluded_count += 1
            if len(excluded_sample) < sample_size:
                excluded_sample.append({"rel_path": entry["rel_path"], "reason": entry["reason"]})
        else:
            included_count += 1
            included_bytes += entry["size"]
            if len(included_sample) < sample_size:
                included_sample.append({"rel_path": entry["rel_path"], "size": entry["size"]})

    if walked >= _PREVIEW_FILE_CAP:
        cap_hit = True

    return {
        "ok": True,
        "source_root": src,
        "destination_root": dst,
        "included_count": included_count,
        "included_bytes": included_bytes,
        "excluded_count": excluded_count,
        "included_sample": included_sample,
        "excluded_sample": excluded_sample,
        "file_cap_hit": cap_hit,
        "walked_at": datetime.now().isoformat(timespec="seconds"),
    }


# ── History + resume state (placeholders for PR-1; populated by PR-2) ──


def load_history() -> list[dict]:
    """PR-1 placeholder. Returns the history list (empty until PR-2's
    copy engine starts recording sessions). Shape is forward-compatible
    so the UI can be written against this signature today."""
    with _file_lock:
        if not os.path.exists(HISTORY_FILE):
            return []
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []


def load_resume_state() -> dict | None:
    """Returns the in-progress state if a crashed session is detected,
    else None. State file is written atomically AFTER each file's
    destination-side atomic-rename completes, so the worst-case after
    a crash is "one file half-copied and skipped"; on resume that
    file's destination hash won't match the source hash and the file
    gets retried automatically."""
    with _file_lock:
        if not os.path.exists(STATE_FILE):
            return None
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None


# ══════════════════════════════════════════════════════════════════════
# Copy engine + crash-safe resume (PR-2 of #46)
# ══════════════════════════════════════════════════════════════════════
#
# Single-threaded. PR-3 will add ThreadPoolExecutor + schedule.
#
# Per-file atomic commit:
#   1. Read source -> hash + size  (skip-check via dest stat first)
#   2. Copy source -> dest.tmp     (in chunks; sized for crash visibility)
#   3. fsync(dest.tmp) + close
#   4. os.replace(dest.tmp, dest)  -- atomic on Windows
#   5. Update state file (atomic .tmp + replace)
#   6. Advance cursor
#
# Worst case after crash:
#   - .tmp file in dest tree  -> resume cleans it before continuing
#   - file half-copied + state cursor still pointing to it -> resume
#     re-runs that file (skip-check fails since hashes differ)
#   - state file half-written -> impossible (atomic-rename)


# Module-level worker-thread state. Only one session at a time.
_active_session_id: str | None = None
_active_session_lock = threading.Lock()
_cancel_flag = threading.Event()

# Soft session bytes cap (default 50 GB). Hard-coded for V1; PR-3 may
# move to rules.
SESSION_BYTES_CAP = 50 * 1024 * 1024 * 1024

# Per-file copy timeout in seconds. Materialising a Files-On-Demand
# placeholder over a slow connection can take a while; cap at 5 min so
# one slow file doesn't stall the whole session.
PER_FILE_TIMEOUT_S = 300

# Chunk size for copies. 1 MB is a reasonable tradeoff between syscall
# overhead and memory footprint; small enough that a hash of the chunk
# can be computed cheaply.
_COPY_CHUNK = 1024 * 1024


def _rules_hash(rules: dict) -> str:
    """Stable SHA-256 of the rules dict (sort_keys for determinism).
    Used at resume time to detect "rules changed while a session was
    running" so we don't silently apply a different rule set to half
    a session."""
    canon = json.dumps(rules, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _hash_file(path: str) -> str:
    """SHA-256 of a file's contents. Returns "" on read error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                buf = f.read(_COPY_CHUNK)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except OSError:
        return ""


def _materialise_placeholder(path: str) -> None:
    """For OneDrive Files-On-Demand: ``attrib +p`` pins the file so it
    is materialised on disk (downloaded if it was a placeholder). Same
    trick used by the SystemHealthDiag.py path-fix in March 2026.

    Best-effort: failures are swallowed because (a) the file may not
    BE a placeholder, (b) attrib may not exist on certain Windows
    flavours, (c) the underlying read in _hash_file will surface a
    "real" error if the file genuinely can't be read.
    """
    try:
        subprocess.run(
            ["attrib", "+p", path],
            capture_output=True,
            timeout=PER_FILE_TIMEOUT_S,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def _atomic_copy(src: str, dst: str) -> tuple[bool, int, str]:
    """Copy ``src`` -> ``dst.tmp`` -> ``dst`` with fsync between.
    Returns ``(ok, bytes_copied, error_message)``.

    Creates parent directories of dst if missing. Caller is responsible
    for any source materialisation (we just open the file).
    """
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".tmp"
    copied = 0
    try:
        with open(src, "rb") as r, open(tmp, "wb") as w:
            while True:
                buf = r.read(_COPY_CHUNK)
                if not buf:
                    break
                w.write(buf)
                copied += len(buf)
            w.flush()
            try:
                os.fsync(w.fileno())
            except OSError:
                # fsync may fail on certain network drives; soldier on
                # since the OS will still flush eventually.
                pass
        os.replace(tmp, dst)
        return (True, copied, "")
    except OSError as e:
        # Clean up the partial .tmp so a future run doesn't see it.
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return (False, copied, str(e))


def _needs_copy(src_stat, dst_path: str) -> tuple[bool, str]:
    """Decide whether to copy this file. Returns ``(copy?, reason)``.

    Skip when size + mtime + content-hash all match. Hash comparison
    is the expensive part (reads both files); we only compute it when
    size + mtime are both equal.
    """
    if not os.path.exists(dst_path):
        return (True, "dest missing")
    try:
        dst_stat = os.stat(dst_path)
    except OSError:
        return (True, "dest stat failed")
    if dst_stat.st_size != src_stat.st_size:
        return (True, "size differs")
    # mtime granularity is 1s on FAT, much finer on NTFS. Use a small
    # tolerance to absorb cross-filesystem mtime drift.
    if abs(dst_stat.st_mtime - src_stat.st_mtime) > 1.0:
        return (True, "mtime differs")
    # Size + mtime match -> probably the same content. Skip without
    # the expensive hash compare; correctness loss is "the user
    # rewrote the file and somehow preserved size + mtime", which is
    # extraordinarily unlikely outside deliberate tampering.
    return (False, "size+mtime match")


def _save_state(state: dict) -> bool:
    """Atomic write of the in-progress state. Stamps last_updated_at
    each time."""
    state["last_updated_at"] = datetime.now().isoformat(timespec="seconds")
    return _atomic_write_json(STATE_FILE, state)


def _clear_state() -> None:
    """Remove the state file on clean session end."""
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
    except OSError:
        pass


def _append_history(entry: dict, cap: int = 200) -> bool:
    """Append one history row, newest-first capped."""
    with _file_lock:
        existing = load_history()
        existing.append(entry)
        if len(existing) > cap:
            existing = existing[-cap:]
        return _atomic_write_json(HISTORY_FILE, existing)


def _build_plan(source_root: str, rules: dict) -> list[dict]:
    """Walk the source and build the full plan -- list of INCLUDED files
    (excluded entries are skipped here so the plan is the work-to-do)."""
    plan: list[dict] = []
    for entry in walk_source(source_root, rules, file_cap=None):
        if entry["excluded"]:
            continue
        plan.append(
            {
                "rel_path": entry["rel_path"],
                "size": entry["size"],
                "mtime": entry["mtime"],
            }
        )
    return plan


def request_cancel(session_id: str) -> bool:
    """Co-operative cancel via flag. Worker checks the flag between
    files. Returns True if the cancel was accepted (session id matched
    the active one)."""
    with _active_session_lock:
        if _active_session_id != session_id:
            return False
        _cancel_flag.set()
        return True


def _run_copy_inner(
    session_id: str,
    rules: dict,
    source_root: str,
    dest_root: str,
    resume_from: dict | None = None,
) -> dict:
    """The actual copy loop. Always writes a history entry on exit
    (success / cancel / error) and clears the state file on clean
    completion. Resume path: takes ``resume_from`` (the loaded state
    dict) and starts at its cursor; build_plan is SKIPPED so we honour
    the snapshot the original session captured (rules may have changed
    in the meantime; we don't care)."""
    global _active_session_id
    started_at = datetime.now().isoformat(timespec="seconds")

    if resume_from:
        state = resume_from
        plan = state.get("plan") or []
        cursor = state.get("cursor", 0)
        bytes_copied = state.get("bytes_copied", 0)
        files_completed = state.get("files_completed", [])
        files_skipped = state.get("files_skipped", [])
        files_failed = state.get("files_failed", [])
        # Resumes carry the original started_at so the history shows the
        # full elapsed time.
        started_at = state.get("started_at", started_at)
    else:
        plan = _build_plan(source_root, rules)
        cursor = 0
        bytes_copied = 0
        files_completed = []
        files_skipped = []
        files_failed = []
        state = {
            "session_id": session_id,
            "started_at": started_at,
            "rules_hash": _rules_hash(rules),
            "source_root": source_root,
            "dest_root": dest_root,
            "plan": plan,
            "cursor": cursor,
            "bytes_copied": bytes_copied,
            "files_completed": files_completed,
            "files_skipped": files_skipped,
            "files_failed": files_failed,
        }
        _save_state(state)

    total_files = len(plan)
    status = "completed"
    cap_hit = False

    while cursor < total_files:
        if _cancel_flag.is_set():
            status = "cancelled"
            break
        if bytes_copied >= SESSION_BYTES_CAP:
            cap_hit = True
            status = "completed_truncated"
            break

        entry = plan[cursor]
        rel = entry["rel_path"]
        # Normalise to OS separator for the actual filesystem calls.
        rel_os = rel.replace("/", os.sep)
        src = os.path.join(source_root, rel_os)
        dst = os.path.join(dest_root, rel_os)

        try:
            # Materialise placeholder (best-effort) + stat source.
            _materialise_placeholder(src)
            src_stat = os.stat(src)
            need, _reason = _needs_copy(src_stat, dst)
            if not need:
                files_skipped.append(cursor)
            else:
                ok, n, err = _atomic_copy(src, dst)
                if ok:
                    # Mirror source mtime onto destination so future
                    # skip-checks succeed.
                    try:
                        os.utime(dst, (src_stat.st_atime, src_stat.st_mtime))
                    except OSError:
                        pass
                    files_completed.append(cursor)
                    bytes_copied += n
                else:
                    files_failed.append({"index": cursor, "rel_path": rel, "error": err})
        except OSError as e:
            files_failed.append({"index": cursor, "rel_path": rel, "error": str(e)})

        cursor += 1
        state["cursor"] = cursor
        state["bytes_copied"] = bytes_copied
        state["files_completed"] = files_completed
        state["files_skipped"] = files_skipped
        state["files_failed"] = files_failed
        _save_state(state)

    ended_at = datetime.now().isoformat(timespec="seconds")
    entry = {
        "session_id": session_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": status,
        "files_planned": total_files,
        "files_completed_count": len(files_completed),
        "files_skipped_count": len(files_skipped),
        "files_failed_count": len(files_failed),
        "bytes_copied": bytes_copied,
        "cap_hit": cap_hit,
        "source_root": source_root,
        "dest_root": dest_root,
        "resumed_from_session_id": (resume_from or {}).get("session_id") if resume_from else None,
        "errors": files_failed[:20],  # only the first 20 errors in history (cap log size)
    }
    _append_history(entry)
    _clear_state()
    return entry


def start_copy_session(rules: dict | None = None) -> dict:
    """Spawn a worker thread to run a new copy session. Returns
    ``{ok, session_id, error}``. Refuses if another session is already
    active (one at a time in V1)."""
    global _active_session_id
    with _active_session_lock:
        if _active_session_id is not None:
            return {"ok": False, "error": f"another session is active: {_active_session_id}"}
        rules = rules if rules is not None else load_rules()
        source = rules.get("source_root") or DEFAULT_SOURCE_ROOT
        dest = rules.get("destination_root") or DEFAULT_DESTINATION_ROOT
        if not source or not os.path.isdir(source):
            return {"ok": False, "error": f"source root does not exist: {source}"}
        try:
            os.makedirs(dest, exist_ok=True)
        except OSError as e:
            return {"ok": False, "error": f"could not create destination root: {e}"}
        session_id = uuid.uuid4().hex[:12]
        _active_session_id = session_id
        _cancel_flag.clear()

    def _worker():
        global _active_session_id
        try:
            _run_copy_inner(session_id, rules, source, dest)
        except Exception as e:  # noqa: BLE001
            _log.error("cloudcopy worker crashed: %s", e)
            _append_history(
                {
                    "session_id": session_id,
                    "started_at": datetime.now().isoformat(timespec="seconds"),
                    "ended_at": datetime.now().isoformat(timespec="seconds"),
                    "status": "errored",
                    "error": str(e),
                }
            )
        finally:
            with _active_session_lock:
                if _active_session_id == session_id:
                    _active_session_id = None
                _cancel_flag.clear()

    t = threading.Thread(target=_worker, daemon=True, name=f"cloudcopy-{session_id}")
    t.start()
    return {"ok": True, "session_id": session_id}


def get_status(session_id: str) -> dict:
    """Return live progress for the active session, or ``{state:
    "missing"}`` if the session id doesn't match the active one."""
    if not session_id or "/" in session_id or "\\" in session_id:
        return {"state": "missing", "error": "invalid session id"}
    with _active_session_lock:
        if _active_session_id == session_id:
            state = load_resume_state()
            if state is None:
                # Edge case: worker started but no state written yet
                return {"state": "starting", "session_id": session_id}
            total = len(state.get("plan", []))
            cursor = state.get("cursor", 0)
            return {
                "state": "running",
                "session_id": session_id,
                "cursor": cursor,
                "total": total,
                "percent": (cursor / total * 100.0) if total else 100.0,
                "bytes_copied": state.get("bytes_copied", 0),
                "files_completed": len(state.get("files_completed", [])),
                "files_skipped": len(state.get("files_skipped", [])),
                "files_failed": len(state.get("files_failed", [])),
            }
    # Not the active session -- look in history.
    for h in load_history():
        if h.get("session_id") == session_id:
            return {"state": "finished", "session_id": session_id, "history": h}
    return {"state": "missing", "session_id": session_id}


def resume_crashed_session() -> dict:
    """Re-validate the orphan state file and continue the copy.

    Validates: source root still exists, dest root still creatable,
    rules-hash hasn't changed (refuse otherwise so half a session
    doesn't run under different rules).
    """
    global _active_session_id
    state = load_resume_state()
    if not state:
        return {"ok": False, "error": "no crashed session to resume"}
    with _active_session_lock:
        if _active_session_id is not None:
            return {"ok": False, "error": f"another session is active: {_active_session_id}"}
        # Validate source / dest are reachable.
        source = state.get("source_root", "")
        dest = state.get("dest_root", "")
        if not source or not os.path.isdir(source):
            return {"ok": False, "error": f"source root missing: {source!r}"}
        try:
            os.makedirs(dest, exist_ok=True)
        except OSError as e:
            return {"ok": False, "error": f"destination not creatable: {e}"}
        # Validate rules-hash still matches what's in the state file.
        current_rules = load_rules()
        current_hash = _rules_hash(current_rules)
        if state.get("rules_hash") != current_hash:
            return {
                "ok": False,
                "error": (
                    "rules changed since the crashed session started -- "
                    "click 'Discard' instead and re-run with the new rules"
                ),
            }
        # All checks pass; spawn the worker.
        session_id = state.get("session_id") or uuid.uuid4().hex[:12]
        _active_session_id = session_id
        _cancel_flag.clear()

    def _worker():
        global _active_session_id
        try:
            _run_copy_inner(session_id, current_rules, source, dest, resume_from=state)
        except Exception as e:  # noqa: BLE001
            _log.error("cloudcopy resume crashed: %s", e)
        finally:
            with _active_session_lock:
                if _active_session_id == session_id:
                    _active_session_id = None
                _cancel_flag.clear()

    t = threading.Thread(target=_worker, daemon=True, name=f"cloudcopy-resume-{session_id}")
    t.start()
    return {"ok": True, "session_id": session_id, "resumed": True}


def discard_crashed_session() -> dict:
    """User chose Discard on the crashed-session banner. Write a
    cancelled history entry + clear the state file."""
    state = load_resume_state()
    if not state:
        return {"ok": False, "error": "no crashed session to discard"}
    _append_history(
        {
            "session_id": state.get("session_id"),
            "started_at": state.get("started_at"),
            "ended_at": datetime.now().isoformat(timespec="seconds"),
            "status": "discarded",
            "files_planned": len(state.get("plan", [])),
            "files_completed_count": len(state.get("files_completed", [])),
            "bytes_copied": state.get("bytes_copied", 0),
            "discarded_by_user": True,
        }
    )
    _clear_state()
    return {"ok": True}


def get_active_session_id() -> str | None:
    """Test-friendly accessor for the module-level active session."""
    with _active_session_lock:
        return _active_session_id


def _reset_module_state_for_tests() -> None:
    """Test-only: clear the module's active-session + cancel state."""
    global _active_session_id
    with _active_session_lock:
        _active_session_id = None
        _cancel_flag.clear()
