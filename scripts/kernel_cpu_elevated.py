"""scripts/kernel_cpu_elevated.py -- elevated "Identify driver" worker (#75 PR 2).

Spawned by the tray via ShellExecuteW("runas") -> Windows UAC prompt -> runs
as Administrator only if the user clicks Yes. Windows hides kernel thread
start addresses and driver base addresses from unelevated processes, so this
short-lived helper is what can say WHICH driver a busy System-process thread
belongs to.

Invocation::

    python scripts/kernel_cpu_elevated.py --request <path-to-request.json>

The request file (written by kernel_cpu.request_identify) carries
``{"session_id": "<12 hex>", "action": "identify", "seconds": 10}``. This
script validates it, samples the System process twice ``seconds`` apart
(kernel_cpu.run_identify), writes kernel_identify_result_<session>.json next
to the app, removes the request file and exits.

READ-ONLY: it reads thread times and the loaded-driver list; it never stops,
changes or unloads anything. It writes only the one result file, and only
for a session id that matches the strict 12-hex pattern (it runs elevated,
so a tampered request must not be able to name an arbitrary path).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

APP_DIR = str(Path(__file__).resolve().parent.parent)
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import kernel_cpu  # noqa: E402

MAX_SECONDS = 30.0


def _write_result(session_id: str, payload: dict) -> None:
    path = kernel_cpu.identify_path("result", session_id)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="Request JSON written by the unelevated tray.")
    args = parser.parse_args(argv)

    try:
        with open(args.request, encoding="utf-8") as f:
            request = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"FATAL: cannot read request file: {e}", file=sys.stderr)
        return 2
    if not isinstance(request, dict):
        print("FATAL: request is not a JSON object", file=sys.stderr)
        return 2

    session_id = str(request.get("session_id") or "")
    if not kernel_cpu.SESSION_RE.fullmatch(session_id):
        # No safe place to write a result for a malformed id -- the tray's
        # poll times out instead.
        print(f"FATAL: invalid session_id {session_id!r}", file=sys.stderr)
        return 2

    try:
        seconds = min(max(float(request.get("seconds", kernel_cpu.IDENTIFY_SECONDS)), 1.0), MAX_SECONDS)
    except (TypeError, ValueError):
        seconds = kernel_cpu.IDENTIFY_SECONDS

    if request.get("action") != "identify":
        result = {"ok": False, "error": f"unknown action {request.get('action')!r}"}
    else:
        try:
            result = kernel_cpu.run_identify(seconds)
        except Exception as e:  # noqa: BLE001 -- the helper must always write a result
            result = {"ok": False, "error": f"identify crashed: {type(e).__name__}: {e}"}
    result["session_id"] = session_id
    _write_result(session_id, result)

    try:
        os.remove(args.request)
    except OSError:
        pass
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
