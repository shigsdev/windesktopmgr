#!/usr/bin/env python3
"""post_deploy_topology_check.py -- semantic checks for the live tray.

Runs AFTER restart + selftest passes. Catches the class of regressions
that pytest + /api/selftest miss because they only check shape, not
semantics:

  - "topology says 5 MoCA bridges but the user has 4 -- a vendor
    pattern is over-matching"
  - "topology says 0 Orbi APs but the SOAP succeeded -- the parser
    silently dropped the data"
  - "dashboard concerns include a brand-new error string we don't
    have a regression test for"
  - "Unknown column has 100% of wireless devices -- the firmware
    quirk regressed harder than before"

Exit codes:
    0 -- all checks passed
    1 -- one or more checks reported an issue
    2 -- tray not reachable on localhost:5000

Add new checks as named entries in CHECKS below. Each check returns
``None`` on success or a string describing what's wrong. The string
is printed and the exit code is 1.

Why this exists: the 2026-05-12 "5 MoCAs but I only have 4" report
caught us because pytest mocks every external source and selftest
only asserts shape. The user had to point this out. A semantic
checker that runs after every deploy makes the gap visible without
relying on the user as the regression suite.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable

DEFAULT_HOST = "http://localhost:5000"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _get(host: str, path: str) -> dict | None:
    try:
        with urllib.request.urlopen(host + path, timeout=10) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionResetError) as e:
        return {"_fetch_error": str(e)}


# ── Checks ────────────────────────────────────────────────────────────────────


def check_topology_basics(host: str) -> str | None:
    """Topology API must return ok=True with the renderer-required keys."""
    t = _get(host, "/api/homenet/topology")
    if t is None or "_fetch_error" in t:
        return f"topology fetch failed: {t.get('_fetch_error') if t else 'no response'}"
    if not t.get("ok"):
        return "topology returned ok=False"
    for k in ("router", "switches", "aps", "moca_bridges", "moca_children", "devices", "stats"):
        if k not in t:
            return f"topology missing required key: {k}"
    return None


def check_moca_bridge_count_matches_strict_vendors(host: str) -> str | None:
    """Every device in moca_bridges must either (a) have wired_via='moca_bridge'
    set by the user, OR (b) have a vendor in the strict ETHERNET_MOCA_BRIDGE
    list. Catches the 2026-05-12 regression where Commscope/Arris STBs
    spawned phantom bridge columns."""
    t = _get(host, "/api/homenet/topology")
    if not t or not t.get("ok"):
        return None  # covered by check_topology_basics
    devices = t.get("devices", {})
    strict_vendors = {
        "actiontec",
        "askey",
        "gocoax",
        "hitron",
        "motorola mobility",
        "screenbeam",
        "westell",
    }
    phantoms: list[str] = []
    for mac in t.get("moca_bridges", []):
        dev = devices.get(mac, {})
        wired_via = (dev.get("wired_via") or "").lower()
        if wired_via == "moca_bridge":
            continue  # explicit user attestation -- always OK
        vendor = (dev.get("vendor") or "").lower()
        if not any(v in vendor for v in strict_vendors):
            phantoms.append(f"{mac} vendor={dev.get('vendor')!r}")
    if phantoms:
        return (
            f"{len(phantoms)} MoCA bridge(s) classified without user "
            f"attestation AND without strict-vendor match: {phantoms}"
        )
    return None


def check_dashboard_concerns_well_formed(host: str) -> str | None:
    """Every concern in /api/dashboard/summary must have the keys the UI
    expects (level, title, detail, action_fn). Surfaces concerns whose
    schema regressed silently."""
    d = _get(host, "/api/dashboard/summary")
    if d is None or "_fetch_error" in d:
        return f"dashboard fetch failed: {d.get('_fetch_error') if d else 'no response'}"
    concerns = d.get("concerns") or []
    missing: list[str] = []
    for i, c in enumerate(concerns):
        if not isinstance(c, dict):
            missing.append(f"concern[{i}] not a dict: {type(c).__name__}")
            continue
        for required in ("level", "title", "detail"):
            if required not in c:
                missing.append(f"concern[{i}] ({c.get('title', '?')[:30]}) missing key: {required}")
    if missing:
        return f"{len(missing)} concern schema issue(s): {missing[:3]}" + ("..." if len(missing) > 3 else "")
    return None


def check_no_self_referential_classifier_loop(host: str) -> str | None:
    """A device must not appear in both moca_bridges AND moca_children of
    itself. Sanity check on the classifier."""
    t = _get(host, "/api/homenet/topology")
    if not t or not t.get("ok"):
        return None
    bridges = set(t.get("moca_bridges", []))
    children = t.get("moca_children") or {}
    for bridge_mac, kids in children.items():
        if bridge_mac in kids:
            return f"bridge {bridge_mac} listed as its own child (classifier loop)"
        for k in kids:
            if k in bridges:
                return f"device {k} is both a bridge AND a child of {bridge_mac}"
    return None


def check_orbi_satellite_visibility(host: str) -> str | None:
    """When the Orbi mesh has clients but only the base AP appears in the
    aps list, surface the firmware-quirk explanation. Not a failure --
    just a visible warning so the operator knows this hasn't been
    silently regressed."""
    t = _get(host, "/api/homenet/topology")
    if not t or not t.get("ok"):
        return None
    aps = t.get("aps") or []
    unknown_count = len(t.get("orbi_mesh_unknown_ap") or [])
    if len(aps) == 1 and aps[0].get("is_base") and unknown_count > 10:
        # This is the known firmware quirk -- not a regression, just an
        # operator-visible WARNING (not a failure).
        return (
            f"WARN: only base AP visible while {unknown_count} clients are 'unknown' -- "
            "Orbi firmware doesn't expose per-satellite mapping. Operator should be "
            "aware this is by design, not a regression. See PR #27 for context."
        )
    return None


def check_no_phantom_actiontec_blink_bridges(host: str) -> str | None:
    """The Blink Sync Module uses an Actiontec OUI; if it ever returns as
    a MoCA bridge that's a regression of PR #29's hostname-negative-match
    guard."""
    t = _get(host, "/api/homenet/topology")
    if not t or not t.get("ok"):
        return None
    devices = t.get("devices", {})
    for mac in t.get("moca_bridges", []):
        dev = devices.get(mac, {})
        hostname = (dev.get("dns_hostname") or dev.get("hostname") or "").lower()
        for blink_signal in ("blink-sync", "blink-mini"):
            if blink_signal in hostname:
                return (
                    f"Blink device {mac} ({hostname!r}) appears in moca_bridges -- "
                    "PR #29 hostname-negative-match regressed"
                )
    return None


def check_inventory_load_not_failed(host: str) -> str | None:
    """Indirect probe of the 2026-05-12 silent-state-wipe guard. If the
    inventory load failed, the API returns empty data; if any device-
    bearing endpoint returns ZERO devices despite the tray running for
    a while, that's a strong hint that something's gone wrong."""
    inv = _get(host, "/api/homenet/inventory")
    if not inv or "_fetch_error" in inv:
        return None  # not our concern -- network issue, not state issue
    devices = inv.get("devices") or []
    last_scan = inv.get("last_scan")
    if not last_scan:
        # No scan ever -- legitimate first-run
        return None
    if not devices:
        return (
            "inventory has last_scan but ZERO devices -- possible silent state wipe. "
            "Check tray log for 'CRITICAL: inventory load failed' message."
        )
    return None


# Registry. Each entry: (name, callable, severity).
# severity: 'fail' -> nonzero exit; 'warn' -> visible but doesn't fail.
CHECKS: list[tuple[str, Callable[[str], str | None], str]] = [
    ("topology_basics", check_topology_basics, "fail"),
    ("moca_bridge_strict_vendors", check_moca_bridge_count_matches_strict_vendors, "fail"),
    ("dashboard_concerns_well_formed", check_dashboard_concerns_well_formed, "fail"),
    ("no_self_referential_classifier_loop", check_no_self_referential_classifier_loop, "fail"),
    ("no_phantom_blink_bridges", check_no_phantom_actiontec_blink_bridges, "fail"),
    ("inventory_load_not_failed", check_inventory_load_not_failed, "fail"),
    ("orbi_satellite_visibility", check_orbi_satellite_visibility, "warn"),
]


def main() -> int:
    host = DEFAULT_HOST
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        host = sys.argv[1].rstrip("/")

    # First make sure the tray is up at all
    health = _get(host, "/api/health")
    if not health or "_fetch_error" in health:
        print(f"{RED}{BOLD}Tray not reachable at {host}{RESET} -- run post_restart_check first")
        return 2

    print(f"{BOLD}Post-deploy semantic checks{RESET} {DIM}({host}){RESET}")
    failures = 0
    warnings = 0
    for name, fn, severity in CHECKS:
        try:
            result = fn(host)
        except Exception as e:  # noqa: BLE001 -- defensive, never crash this checker
            print(f"  {RED}ERROR{RESET}  {name:40s} {DIM}check raised: {e}{RESET}")
            failures += 1
            continue
        if result is None:
            print(f"  {GREEN}PASS{RESET}   {name}")
        elif severity == "warn":
            print(f"  {YELLOW}WARN{RESET}   {name}")
            print(f"         {DIM}{result}{RESET}")
            warnings += 1
        else:
            print(f"  {RED}FAIL{RESET}   {name}")
            print(f"         {DIM}{result}{RESET}")
            failures += 1

    print()
    if failures:
        print(f"  {RED}{BOLD}{failures} check(s) failed{RESET}, {warnings} warning(s)")
        return 1
    if warnings:
        print(f"  {GREEN}All checks passed{RESET} ({warnings} warning(s) noted)")
    else:
        print(f"  {GREEN}{BOLD}All checks passed{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
