"""LibreHardwareMonitor (LHM) in-app installer for WinDesktopMgr.

The Thermals tab's per-core grid and CPU-temp gauge only populate when LHM
is running elevated and publishing its ``root\\LibreHardwareMonitor`` WMI
namespace. This module lets the Thermals "install LibreHardwareMonitor" CTA
do the work in-app instead of sending the user off to download it by hand:

  * :func:`install_lhm`          download (pinned URL) -> SHA256 verify ->
                                 zip-slip-guarded extract to
                                 ``%LOCALAPPDATA%\\WinDesktopMgr\\LibreHardwareMonitor``
                                 -> seed a start-minimised-to-tray config.
                                 Needs NO admin (per-user folder).
  * :func:`launch_lhm_elevated`  ``ShellExecuteW("runas")`` the installed exe
                                 -> UAC prompt -> LHM runs elevated so it can
                                 read CPU-core temps and publish its WMI ns.
  * :func:`lhm_status`           installed? running? + resolved paths, so the
                                 CTA can show the right button.

Security
--------
* The download is **pinned**: a fixed HTTPS ``github.com`` release-asset URL
  plus an expected SHA256. A hash mismatch aborts BEFORE anything is
  extracted or executed -- we never run a binary we did not expect. Bump
  :data:`LHM_VERSION`/:data:`LHM_SHA256`/:data:`LHM_URL` together to update.
* The URL host/scheme is validated (https + github.com) as defence in depth.
* Extraction is zip-slip guarded: every member must resolve inside the
  install dir or the whole install aborts.
* The elevated launch runs a FIXED path (the verified exe) with no
  user-supplied arguments.

Python-first: download via ``requests`` (already a dependency), hashing via
``hashlib``, extraction via ``zipfile`` -- no PowerShell. The only Windows-
specific call is the ``ShellExecuteW`` UAC launch, which mirrors the existing
elevated-helper pattern in ``backup.py``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import zipfile
from urllib.parse import urlparse

# ── Pinned release ────────────────────────────────────────────────────────
# The .NET Framework 4.8 build ("LibreHardwareMonitor.zip", NOT the .NET 10
# build) -- runs on Windows 10/11 with no extra runtime install. Pinned to an
# explicit tag so the SHA256 below always matches (a moving "latest" URL would
# break verification the day upstream cuts a new release).
LHM_VERSION = "v0.9.6"
LHM_URL = (
    "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases/download/v0.9.6/LibreHardwareMonitor.zip"
)
LHM_SHA256 = "086d9f1b5a99e643edc2cfaaac16051685b551e4c5ac0b32a57c58c0e529c001"
LHM_EXE_NAME = "LibreHardwareMonitor.exe"
# Scheduled-task name for the optional "start LHM elevated at every login"
# feature. Fixed (never user input) -- the only value passed to schtasks.
AUTOSTART_TASK_NAME = "WinDesktopMgr-LibreHardwareMonitor"
# CREATE_NO_WINDOW: keep schtasks' console off-screen when the tray (pythonw)
# queries the task. 0 on non-Windows so tests/other platforms don't choke.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DOWNLOAD_TIMEOUT_S = 60
# The asset is ~6.3 MB; cap well above it so a hijacked/oversized response
# can't exhaust memory before the hash check would have rejected it anyway.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
# Bound on the LHM-running WMI probe (see is_running). Hit on every Thermals
# tab load, so it must never hang a Flask worker when Winmgmt is wedged.
IS_RUNNING_TIMEOUT_S = 5.0

INSTALL_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "WinDesktopMgr",
    "LibreHardwareMonitor",
)

# Seeds LHM to launch straight into the tray (no window in the user's face)
# and stay there on close. Written before first launch; LHM honours it.
_TRAY_CONFIG = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<configuration>\n"
    "  <appSettings>\n"
    '    <add key="startMinMenuItem" value="true" />\n'
    '    <add key="minTrayMenuItem" value="true" />\n'
    '    <add key="minCloseMenuItem" value="true" />\n'
    '    <add key="runMenuItem" value="false" />\n'
    "  </appSettings>\n"
    "</configuration>\n"
)


def exe_path() -> str:
    """Absolute path to the installed LHM executable (may not exist yet)."""
    return os.path.join(INSTALL_DIR, LHM_EXE_NAME)


def is_installed() -> bool:
    """True when the LHM executable is present in the install dir."""
    return os.path.isfile(exe_path())


def is_running() -> bool:
    """True when LHM is publishing its WMI namespace (i.e. actively running).

    We probe the ``root\\LibreHardwareMonitor`` namespace rather than scanning
    the process list because the namespace is the thing the Thermals tab
    actually needs -- if it answers, the gauges will populate. Any failure
    (namespace absent because LHM isn't running, non-Windows host, WMI hiccup)
    is treated as "not running"; this never raises.

    The WMI probe is bounded via ``bounded_wmi_query`` (the same hang-guard
    every other WMI site uses) because this runs on every Thermals tab load --
    an unbounded enum would wedge a Flask worker if Winmgmt is degraded.
    """

    def _probe():
        import pythoncom  # noqa: PLC0415 -- Windows COM, lazy
        import wmi  # noqa: PLC0415 -- lazy: optional, Windows-only

        pythoncom.CoInitialize()
        conn = wmi.WMI(namespace="root\\LibreHardwareMonitor")
        # .Sensor() enumerates published sensors; a live LHM returns >= 1.
        return bool(conn.Sensor())

    try:
        from windesktopmgr import bounded_wmi_query  # noqa: PLC0415 -- lazy: breaks import cycle

        return bool(bounded_wmi_query(_probe, timeout_s=IS_RUNNING_TIMEOUT_S, fallback=False, label="lhm is_running"))
    except Exception:  # noqa: BLE001 -- namespace absent / not Windows / wdm import -> not running
        return False


def lhm_status() -> dict:
    """Snapshot of LHM state for the Thermals CTA.

    Returns ``{installed, running, version, exe, install_dir}``. Never raises.
    """
    return {
        "installed": is_installed(),
        "running": is_running(),
        "version": LHM_VERSION,
        "exe": exe_path(),
        "install_dir": INSTALL_DIR,
    }


def _validate_url(url: str) -> bool:
    """Defence in depth: only ever fetch over https from github.com."""
    try:
        p = urlparse(url)
    except ValueError:
        return False
    host = (p.hostname or "").lower()
    return p.scheme == "https" and (host == "github.com" or host.endswith((".github.com", ".githubusercontent.com")))


def _safe_extract(zip_path: str, dest_dir: str) -> None:
    """Extract ``zip_path`` into ``dest_dir`` with zip-slip protection.

    Every member's resolved destination must stay within ``dest_dir``; a
    member that would escape (``../`` traversal, absolute path, drive letter)
    aborts the whole extraction with ``ValueError`` so we never write outside
    the install dir.
    """
    dest_root = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_root, member))
            if target != dest_root and not target.startswith(dest_root + os.sep):
                raise ValueError(f"unsafe zip member escapes install dir: {member!r}")
        zf.extractall(dest_root)


def install_lhm() -> dict:
    """Download, verify, and extract LHM into the per-user install dir.

    Returns ``{"ok": True, "exe": <path>, "version": ...}`` on success, or
    ``{"ok": False, "error": "..."}`` on any failure (network, hash mismatch,
    bad zip). Never raises -- the Flask route surfaces ``error`` to the UI.
    No elevation required; everything lands under ``%LOCALAPPDATA%``.
    """
    if not _validate_url(LHM_URL):
        return {"ok": False, "error": "refusing to download from a non-github https URL"}

    # ── Download (bounded size + timeout) ──
    try:
        import requests  # noqa: PLC0415 -- already a project dependency

        resp = requests.get(LHM_URL, timeout=DOWNLOAD_TIMEOUT_S, stream=True)
        resp.raise_for_status()
        chunks = bytearray()
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            chunks.extend(chunk)
            if len(chunks) > MAX_DOWNLOAD_BYTES:
                return {"ok": False, "error": "download exceeded size limit -- aborting"}
        data = bytes(chunks)
    except Exception as e:  # noqa: BLE001 -- network/HTTP failure -> graceful error
        return {"ok": False, "error": f"download failed: {type(e).__name__}: {e}"}

    # ── Verify the pinned hash BEFORE writing or extracting anything ──
    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != LHM_SHA256.lower():
        return {
            "ok": False,
            "error": f"SHA256 mismatch (expected {LHM_SHA256[:12]}…, got {actual[:12]}…) -- not extracting",
        }

    # ── Persist the verified zip, then extract with zip-slip protection ──
    zip_path = os.path.join(INSTALL_DIR, "_LibreHardwareMonitor.zip")
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        with open(zip_path, "wb") as fh:
            fh.write(data)
        _safe_extract(zip_path, INSTALL_DIR)
        try:
            os.remove(zip_path)
        except OSError:
            pass
    except Exception as e:  # noqa: BLE001 -- bad zip / fs error -> graceful
        # Don't leave the (verified) zip behind on a failed/aborted extract.
        try:
            os.remove(zip_path)
        except OSError:
            pass
        return {"ok": False, "error": f"extract failed: {type(e).__name__}: {e}"}

    if not is_installed():
        return {"ok": False, "error": "extract completed but executable not found"}

    # ── Seed start-minimised-to-tray config (best effort) ──
    try:
        with open(os.path.join(INSTALL_DIR, "LibreHardwareMonitor.config"), "w", encoding="utf-8") as fh:
            fh.write(_TRAY_CONFIG)
    except OSError:
        pass  # non-fatal: LHM just opens a window the first time

    return {"ok": True, "exe": exe_path(), "version": LHM_VERSION, "install_dir": INSTALL_DIR}


def launch_lhm_elevated() -> dict:
    """Launch the installed LHM elevated via a UAC prompt (``ShellExecuteW``).

    Returns ``{"ok": True}`` once the elevated process starts (user accepted
    UAC), or ``{"ok": False, "error": ...}`` if LHM isn't installed, the host
    isn't Windows, or the prompt was declined. Mirrors the elevated-helper
    launch pattern in ``backup.py``. The launched path is FIXED (the verified
    exe) with no arguments -- no injection surface.
    """
    exe = exe_path()
    if not os.path.isfile(exe):
        return {"ok": False, "error": "LibreHardwareMonitor is not installed yet"}

    try:
        import ctypes  # noqa: PLC0415 -- Windows-only
    except ImportError:
        return {"ok": False, "error": "ctypes unavailable (non-Windows host?)"}

    # SW_SHOWMINNOACTIVE = 7 -> start minimised to the tray (config seeds the
    # rest). "runas" triggers UAC; ShellExecuteW returns > 32 on success.
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, None, INSTALL_DIR, 7)
    except Exception as e:  # noqa: BLE001 -- ShellExecuteW unavailable -> graceful
        return {"ok": False, "error": f"ShellExecuteW failed: {type(e).__name__}: {e}"}

    if rc <= 32:
        rc_map = {
            0: "out of memory",
            2: "FILE_NOT_FOUND",
            3: "PATH_NOT_FOUND",
            5: "ACCESS_DENIED (UAC prompt declined?)",
            8: "OUT_OF_MEMORY",
            31: "NO_ASSOCIATION",
        }
        return {"ok": False, "error": f"elevated launch failed: rc={rc} ({rc_map.get(rc, 'unknown')})"}

    return {"ok": True, "exe": exe}


# ── Optional: launch LHM elevated at every login (auto-start) ──────────────
# Registering an at-logon task that RUNS ELEVATED (RunLevel HIGHEST) itself
# requires elevation, so setup/remove go through a UAC prompt (ShellExecuteW
# "runas" -> schtasks). Querying the task does NOT need elevation. Everything
# passed to schtasks is a fixed constant (task name + the verified exe path) --
# no user input reaches the command.


def autostart_status() -> dict:
    """Whether the at-logon auto-start task is registered. Never raises."""
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", AUTOSTART_TASK_NAME],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_NO_WINDOW,
        )
        return {"enabled": result.returncode == 0, "task": AUTOSTART_TASK_NAME}
    except Exception:  # noqa: BLE001 -- schtasks missing / non-Windows -> not enabled
        return {"enabled": False, "task": AUTOSTART_TASK_NAME}


def _schtasks_elevated(args: str, action: str) -> dict:
    """Run ``schtasks.exe <args>`` elevated via a UAC prompt. ShellExecuteW
    returns > 32 once the elevated process starts (user accepted UAC); it does
    not surface schtasks' own exit code, so callers re-query autostart_status to
    confirm the result."""
    try:
        import ctypes  # noqa: PLC0415 -- Windows-only
    except ImportError:
        return {"ok": False, "error": "ctypes unavailable (non-Windows host?)"}

    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "schtasks.exe", args, None, 0)
    except Exception as e:  # noqa: BLE001 -- ShellExecuteW unavailable -> graceful
        return {"ok": False, "error": f"ShellExecuteW failed: {type(e).__name__}: {e}"}

    if rc <= 32:
        rc_map = {
            0: "out of memory",
            2: "FILE_NOT_FOUND",
            3: "PATH_NOT_FOUND",
            5: "ACCESS_DENIED (UAC prompt declined?)",
            8: "OUT_OF_MEMORY",
            31: "NO_ASSOCIATION",
        }
        return {"ok": False, "error": f"could not {action}: rc={rc} ({rc_map.get(rc, 'unknown')})"}
    return {"ok": True}


def setup_autostart() -> dict:
    """Register an at-logon scheduled task that launches the installed LHM with
    highest privileges (so it can read CPU-core temps + publish its WMI
    namespace every login). UAC prompt. Returns ``{"ok": True}`` once the
    elevated schtasks process starts, else ``{"ok": False, "error": ...}``.

    ACCEPTED SECURITY TRADE-OFF (code-review C1): the task points at the LHM
    exe under ``%LOCALAPPDATA%`` (user-writable, so the install needs no admin).
    A task running ``/RL HIGHEST`` against a user-writable exe is, in the
    general case, a user->admin escalation path -- anything able to write that
    file as the same user could have it run elevated at next login. This is an
    accepted trade-off for a SINGLE-USER personal desktop tool: an attacker who
    can write ``%LOCALAPPDATA%`` as you already has full control of your account
    (per-user Run keys, their own logon tasks, etc.), so the marginal risk is
    low, and the alternative (a %ProgramFiles% install or ACL-locking the dir)
    breaks the no-admin install + one-click update the feature is built around.
    Hardening to a non-user-writable install dir is the upgrade path if the
    threat model ever changes.
    """
    exe = exe_path()
    # Defence in depth at the Python->schtasks boundary: the exe path is derived
    # from constants (LOCALAPPDATA + fixed dir/name), never user input, but a
    # stray double-quote would break /TR parsing -- refuse rather than mangle.
    # (Checked before isfile so it's reachable; NTFS forbids quotes in names so
    # a quoted path could never be a real file anyway.)
    if '"' in exe:
        return {"ok": False, "error": "install path contains an invalid character"}
    if not os.path.isfile(exe):
        return {"ok": False, "error": "LibreHardwareMonitor is not installed yet"}
    # /TR value is quoted so a relocated profile with spaces still parses.
    args = f'/Create /TN "{AUTOSTART_TASK_NAME}" /TR "\\"{exe}\\"" /SC ONLOGON /RL HIGHEST /F'
    return _schtasks_elevated(args, "register the auto-start task")


def remove_autostart() -> dict:
    """Delete the at-logon auto-start task (UAC prompt)."""
    args = f'/Delete /TN "{AUTOSTART_TASK_NAME}" /F'
    return _schtasks_elevated(args, "remove the auto-start task")
