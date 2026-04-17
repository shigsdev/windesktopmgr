"""
remediation.py — Automated Remediation Engine for WinDesktopMgr.

Ten one-click system fixes (flush DNS, reset Winsock, reset TCP/IP, clear
temp, DISM + SFC, clear WU cache, restart spooler, reset network adapters,
clear icon cache, reboot), a JSON-backed history store, and the three
``/api/remediation/*`` routes that the Dashboard Quick Fixes card + the
dedicated Remediation tab talk to. Also exposes two ``_nlq_*`` bridge
helpers so the Natural Language Query agent can list history and trigger
an action from a chat conversation.

Extracted from windesktopmgr.py as the second of three blueprint
extractions planned for backlog #22 (disk → remediation → nlq).
Following the homenet.py / disk.py playbook: zero behaviour changes, all
tests still pass, routes now served by ``remediation_bp``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from datetime import datetime, timezone

import win32serviceutil
from flask import Blueprint, jsonify, request

remediation_bp = Blueprint("remediation", __name__)

# ── Config ────────────────────────────────────────────────────────────────────

APP_DIR = os.path.dirname(os.path.abspath(__file__))
REMEDIATION_HISTORY_FILE = os.path.join(APP_DIR, "remediation_history.json")


# ── Registry: user-facing metadata for every action ──────────────────────────

REMEDIATION_REGISTRY = {
    "flush_dns": {
        "id": "flush_dns",
        "label": "Flush DNS Cache",
        "description": "Clears the Windows DNS resolver cache. Fixes name-resolution failures after network changes.",
        "risk": "low",
        "reboot": False,
        "icon": "\U0001f310",
    },
    "reset_winsock": {
        "id": "reset_winsock",
        "label": "Reset Winsock",
        "description": "Resets the Windows Sockets catalog. Fixes broken internet connectivity. Requires reboot.",
        "risk": "medium",
        "reboot": True,
        "icon": "\U0001f50c",
    },
    "reset_tcpip": {
        "id": "reset_tcpip",
        "label": "Reset TCP/IP Stack",
        "description": "Resets the TCP/IP stack to factory defaults. Fixes persistent network errors. Requires reboot.",
        "risk": "medium",
        "reboot": True,
        "icon": "\U0001f4e1",
    },
    "clear_temp": {
        "id": "clear_temp",
        "label": "Clear Temp Files",
        "description": "Deletes files from %TEMP% and C:\\Windows\\Temp. Frees disk space safely.",
        "risk": "low",
        "reboot": False,
        "icon": "\U0001f5d1",
    },
    "repair_image": {
        "id": "repair_image",
        "label": "Repair Windows Image (DISM + SFC)",
        "description": "Runs DISM RestoreHealth then SFC /scannow. Fixes corrupted system files. Takes 10-30 minutes.",
        "risk": "medium",
        "reboot": False,
        "icon": "\U0001f6e0",
    },
    "clear_wu_cache": {
        "id": "clear_wu_cache",
        "label": "Clear Windows Update Cache",
        "description": "Stops wuauserv, deletes SoftwareDistribution downloads, restarts service. Fixes stuck updates.",
        "risk": "medium",
        "reboot": False,
        "icon": "\U0001f504",
    },
    "restart_spooler": {
        "id": "restart_spooler",
        "label": "Restart Print Spooler",
        "description": "Stops and restarts the Windows Print Spooler service. Fixes stuck print jobs.",
        "risk": "low",
        "reboot": False,
        "icon": "\U0001f5a8",
    },
    "reset_network_adapter": {
        "id": "reset_network_adapter",
        "label": "Reset Network Adapters",
        "description": "Disables then re-enables all physical network adapters. Fixes adapter-level connectivity issues.",
        "risk": "medium",
        "reboot": False,
        "icon": "\U0001f501",
    },
    "clear_icon_cache": {
        "id": "clear_icon_cache",
        "label": "Clear Icon & Thumbnail Cache",
        "description": "Stops Explorer, deletes IconCache.db and thumbcache files, restarts Explorer. Fixes broken icons.",
        "risk": "low",
        "reboot": False,
        "icon": "\U0001f5bc",
    },
    "reboot_system": {
        "id": "reboot_system",
        "label": "Reboot System",
        "description": "Schedules a graceful Windows restart in 10 seconds. Closes all open applications.",
        "risk": "high",
        "reboot": True,
        "icon": "\U0001f503",
    },
}

_remediation_history_lock = threading.Lock()


# ── History store ─────────────────────────────────────────────────────────────


def _log_remediation(action_id: str, ok: bool, message: str, details: str = "") -> None:
    meta = REMEDIATION_REGISTRY.get(action_id, {})
    entry = {
        "id": action_id,
        "label": meta.get("label", action_id),
        "risk": meta.get("risk", "unknown"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "ok": ok,
        "message": message,
        "details": details,
    }
    with _remediation_history_lock:
        try:
            history = []
            if os.path.exists(REMEDIATION_HISTORY_FILE):
                with open(REMEDIATION_HISTORY_FILE, encoding="utf-8") as f:
                    history = json.load(f)
            if not isinstance(history, list):
                history = []
            history.append(entry)
            with open(REMEDIATION_HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass


# ── Action handlers ───────────────────────────────────────────────────────────


def _rem_flush_dns() -> dict:
    ps = "ipconfig /flushdns"
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
        )
        ok = r.returncode == 0
        return {"ok": ok, "message": "DNS cache flushed." if ok else (r.stderr.strip() or r.stdout.strip())}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_reset_winsock() -> dict:
    ps = "netsh winsock reset; netsh int ip reset"
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = r.returncode == 0
        return {"ok": ok, "message": "Winsock and IP stack reset. Reboot required." if ok else r.stderr.strip()}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_reset_tcpip() -> dict:
    ps = "netsh int tcp reset; netsh int ipv4 reset; netsh int ipv6 reset"
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = r.returncode == 0
        return {
            "ok": ok,
            "message": "TCP/IP stack reset. Reboot required." if ok else r.stderr.strip(),
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_clear_temp() -> dict:
    ps = r"""
$removed = 0; $errors = 0
foreach ($dir in @($env:TEMP, "$env:SystemRoot\Temp")) {
    Get-ChildItem $dir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop; $removed++ }
        catch { $errors++ }
    }
}
Write-Output "Removed:$removed Errors:$errors"
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = r.stdout.strip()
        m = re.search(r"Removed:(\d+)", out)
        removed = int(m.group(1)) if m else 0
        ok = r.returncode == 0
        return {
            "ok": ok,
            "message": f"Cleared {removed} temp file(s)." if ok else (r.stderr.strip() or out),
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_repair_image() -> dict:
    ps = r"""
$dismOut = & dism /Online /Cleanup-Image /RestoreHealth 2>&1
$sfcOut  = & sfc /scannow 2>&1
$ok = ($LASTEXITCODE -eq 0)
Write-Output "DISM_DONE SFC_DONE OK:$ok"
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        ok = "OK:True" in r.stdout
        return {
            "ok": ok,
            "message": "Windows image repair completed." if ok else "Repair finished with warnings — check Event Log.",
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_clear_wu_cache() -> dict:
    """Stop wuauserv, clear the SoftwareDistribution/Download folder, restart."""
    try:
        win32serviceutil.StopService("wuauserv")
    except Exception:
        pass  # May already be stopped

    download_path = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"),
        "SoftwareDistribution",
        "Download",
    )
    try:
        if os.path.isdir(download_path):
            for item in os.listdir(download_path):
                item_path = os.path.join(download_path, item)
                try:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path, ignore_errors=True)
                    else:
                        os.remove(item_path)
                except Exception:
                    pass
    except Exception as e:
        return {"ok": False, "message": f"Failed to clear cache: {e}"}

    try:
        win32serviceutil.StartService("wuauserv")
    except Exception:
        pass  # Best-effort restart

    return {"ok": True, "message": "Windows Update cache cleared."}


def _rem_restart_spooler() -> dict:
    """Restart the Print Spooler service via pywin32 (no PowerShell)."""
    try:
        win32serviceutil.RestartService("Spooler")
        return {"ok": True, "message": "Print Spooler restarted."}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_reset_network_adapter() -> dict:
    ps = r"""
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disconnected' }
$count = 0
foreach ($a in $adapters) {
    try { Disable-NetAdapter -Name $a.Name -Confirm:$false; Start-Sleep 1
          Enable-NetAdapter  -Name $a.Name -Confirm:$false; $count++ }
    catch {}
}
Write-Output "RESET:$count"
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=60,
        )
        m = re.search(r"RESET:(\d+)", r.stdout)
        count = int(m.group(1)) if m else 0
        ok = count > 0
        return {"ok": ok, "message": f"Reset {count} network adapter(s)." if ok else "No active adapters found."}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_clear_icon_cache() -> dict:
    ps = r"""
try {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
    $db = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    Remove-Item "$db\IconCache.db"    -Force -ErrorAction SilentlyContinue
    Remove-Item "$db\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    Start-Process explorer
    Write-Output "OK"
} catch { Write-Output "ERROR: $_" }
"""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = "OK" in r.stdout
        return {
            "ok": ok,
            "message": "Icon and thumbnail cache cleared. Explorer restarted." if ok else r.stdout.strip(),
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _rem_reboot_system() -> dict:
    ps = 'shutdown /r /t 10 /c "WinDesktopMgr: Scheduled reboot"'
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ok = r.returncode == 0
        return {"ok": ok, "message": "System will reboot in 10 seconds." if ok else r.stderr.strip()}
    except Exception as e:
        return {"ok": False, "message": str(e)}


_REMEDIATION_DISPATCH = {
    "flush_dns": _rem_flush_dns,
    "reset_winsock": _rem_reset_winsock,
    "reset_tcpip": _rem_reset_tcpip,
    "clear_temp": _rem_clear_temp,
    "repair_image": _rem_repair_image,
    "clear_wu_cache": _rem_clear_wu_cache,
    "restart_spooler": _rem_restart_spooler,
    "reset_network_adapter": _rem_reset_network_adapter,
    "clear_icon_cache": _rem_clear_icon_cache,
    "reboot_system": _rem_reboot_system,
}


# ── NLQ bridges (called from windesktopmgr._NLQ_TOOL_DISPATCH) ────────────────


def _nlq_get_remediation_history() -> list:
    try:
        if os.path.exists(REMEDIATION_HISTORY_FILE):
            with open(REMEDIATION_HISTORY_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def _nlq_run_remediation(params: dict) -> dict:
    action_id = re.sub(r"[^a-z0-9_]", "", params.get("action_id", ""))
    fn = _REMEDIATION_DISPATCH.get(action_id)
    if not fn:
        return {"ok": False, "message": f"Unknown action: {action_id}"}
    result = fn()
    _log_remediation(action_id, result.get("ok", False), result.get("message", ""))
    return result


# ── Routes ────────────────────────────────────────────────────────────────────


@remediation_bp.route("/api/remediation/actions")
def remediation_actions():
    return jsonify(list(REMEDIATION_REGISTRY.values()))


@remediation_bp.route("/api/remediation/history")
def remediation_history():
    try:
        if os.path.exists(REMEDIATION_HISTORY_FILE):
            with open(REMEDIATION_HISTORY_FILE, encoding="utf-8") as f:
                history = json.load(f)
            if isinstance(history, list):
                return jsonify(list(reversed(history)))
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@remediation_bp.route("/api/remediation/run", methods=["POST"])
def remediation_run():
    body = request.get_json() or {}
    action_id = re.sub(r"[^a-z0-9_]", "", str(body.get("action_id", ""))).strip()
    fn = _REMEDIATION_DISPATCH.get(action_id)
    if not fn:
        return jsonify({"ok": False, "message": f"Unknown action: {action_id}"}), 400
    result = fn()
    _log_remediation(action_id, result.get("ok", False), result.get("message", ""))
    return jsonify(result)
