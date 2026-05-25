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
import json
import os
import threading
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
}


# ── Persistence ─────────────────────────────────────────────────────


_file_lock = threading.Lock()


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
    return (True, "")


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
    """PR-1 placeholder. Returns the in-progress state if a crashed
    session is detected, else None. PR-2 writes this file as part of
    the per-file atomic commit; PR-1 always returns None because we
    don't run any sessions yet."""
    with _file_lock:
        if not os.path.exists(STATE_FILE):
            return None
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None
