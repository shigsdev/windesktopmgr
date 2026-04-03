"""
Capture real PowerShell and API output as JSON fixtures for snapshot tests.

Run on a live Windows machine:
    python tests/capture_fixtures.py

This calls each get_* function while intercepting subprocess.run to save
both the raw PowerShell stdout and the parsed Python return value.
"""

import datetime
import json
import os
import platform
import subprocess
import sys

# Project root on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
PS_DIR = os.path.join(FIXTURES_DIR, "powershell")
PARSED_DIR = os.path.join(FIXTURES_DIR, "parsed")

os.makedirs(PS_DIR, exist_ok=True)
os.makedirs(PARSED_DIR, exist_ok=True)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  Saved: {os.path.relpath(path, ROOT)}")


def make_meta():
    return {
        "_captured_at": datetime.datetime.now().isoformat(),
        "_hostname": platform.node(),
        "_python": platform.python_version(),
    }


# ── Capture helpers ──────────────────────────────────────────────────────────

_captured_ps_outputs = []


def capturing_run(original_run):
    """Wrap subprocess.run to capture stdout alongside normal execution."""

    def wrapper(*args, **kwargs):
        result = original_run(*args, **kwargs)
        _captured_ps_outputs.append(result.stdout if hasattr(result, "stdout") else "")
        return result

    return wrapper


def capture_function(func_name, func, ps_filenames):
    """Call a function, capture PS stdout(s) and parsed result."""
    global _captured_ps_outputs
    _captured_ps_outputs = []

    import windesktopmgr as wdm

    original = subprocess.run
    subprocess.run = capturing_run(original)
    wdm.subprocess.run = capturing_run(original)

    try:
        print(f"\n  Capturing {func_name}()...")
        result = func()
    except Exception as e:
        print(f"  ERROR in {func_name}: {e}")
        return
    finally:
        subprocess.run = original
        wdm.subprocess.run = original

    # Save raw PS outputs
    for i, fname in enumerate(ps_filenames):
        stdout = _captured_ps_outputs[i] if i < len(_captured_ps_outputs) else ""
        save_json(os.path.join(PS_DIR, fname), {**make_meta(), "data": stdout})

    # Save parsed result
    save_json(os.path.join(PARSED_DIR, f"parsed_{func_name}.json"), {**make_meta(), "data": result})


def main():
    if sys.platform != "win32":
        print("ERROR: This script must run on Windows to capture real PowerShell output.")
        sys.exit(1)

    import windesktopmgr as wdm

    print("=" * 60)
    print("  WinDesktopMgr Fixture Capture")
    print("=" * 60)

    # Each entry: (function_name, callable, [ps_fixture_filenames])
    targets = [
        ("get_installed_drivers", wdm.get_installed_drivers, ["ps_installed_drivers.json"]),
        ("get_driver_health", wdm.get_driver_health, ["ps_driver_health.json"]),
        ("get_disk_health", wdm.get_disk_health, ["ps_disk_health.json", "ps_disk_io.json"]),
        ("get_network_data", wdm.get_network_data, ["ps_network_conns.json", "ps_network_adapters.json"]),
        ("get_update_history", wdm.get_update_history, ["ps_update_history.json"]),
        ("get_startup_items", wdm.get_startup_items, ["ps_startup_items.json"]),
        ("get_process_list", wdm.get_process_list, ["ps_process_list.json"]),
        ("get_thermals", wdm.get_thermals, ["ps_thermals.json"]),
        ("get_services_list", wdm.get_services_list, ["ps_services_list.json"]),
        ("get_memory_analysis", wdm.get_memory_analysis, ["ps_memory_analysis.json", "ps_memory_sysinfo.json"]),
        ("get_current_bios", wdm.get_current_bios, ["ps_bios.json"]),
        ("get_system_timeline", wdm.get_system_timeline, ["ps_timeline.json"]),
        ("get_credentials_network_health", wdm.get_credentials_network_health, ["ps_credentials.json"]),
        ("get_event_log_entries", lambda: wdm.get_event_log_entries(50), ["ps_event_log.json"]),
    ]

    success = 0
    failed = 0
    for func_name, func, ps_files in targets:
        try:
            capture_function(func_name, func, ps_files)
            success += 1
        except Exception as e:
            print(f"  FAILED {func_name}: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"  Done: {success} captured, {failed} failed")
    print(f"  Fixtures saved to: {os.path.relpath(FIXTURES_DIR, ROOT)}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
