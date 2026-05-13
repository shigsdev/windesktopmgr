"""Tests for scripts/post_deploy_topology_check.py.

This script runs AFTER the tray restart + selftest passes; it's the
semantic-correctness gate that catches regressions where pytest is
green but the user-visible product is wrong (e.g., the 2026-05-12
"5 MoCAs but I only have 4" issue that shipped past pytest +
selftest and was caught by the user).

We import the check functions directly and feed them stub responses
via a fake fetcher so we don't need a running tray.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/ importable. We treat the check file as a module to
# exercise the named functions in isolation.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import post_deploy_topology_check as checker  # noqa: E402


class TestCheckMocaBridgeStrictVendors:
    """Phantom-bridge regression guard. Bug 2026-05-12: Commscope/Arris
    STBs spawned a phantom MoCA bridge column because the auto-classifier
    matched the broad vendor pattern. After the fix, only the strict
    bridge-vendor set or explicit user attestation count."""

    def _topology(self, bridges_with_devices):
        """Helper to build a minimal topology payload."""
        return {
            "ok": True,
            "moca_bridges": list(bridges_with_devices.keys()),
            "devices": bridges_with_devices,
        }

    def test_returns_none_when_all_bridges_have_strict_vendor(self, monkeypatch):
        topo = self._topology(
            {
                "88:DE:7C:C2:57:36": {"vendor": "ASKEY COMPUTER CORP"},
                "00:03:7F:11:22:33": {"vendor": "Actiontec Electronics"},
            }
        )
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_moca_bridge_count_matches_strict_vendors("http://x") is None

    def test_returns_none_when_user_attested(self, monkeypatch):
        topo = self._topology(
            {
                # Commscope -- NOT in strict vendors, but user said so
                "B0:5D:D4:76:2A:C0": {"vendor": "Commscope", "wired_via": "moca_bridge"},
            }
        )
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_moca_bridge_count_matches_strict_vendors("http://x") is None

    def test_fails_when_phantom_commscope_appears(self, monkeypatch):
        """The exact bug shape from the 2026-05-12 user report."""
        topo = self._topology(
            {
                "B0:5D:D4:76:2A:C0": {"vendor": "Commscope", "wired_via": ""},
            }
        )
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_moca_bridge_count_matches_strict_vendors("http://x")
        assert result is not None
        assert "Commscope" in result


class TestCheckNoSelfReferentialLoop:
    def test_passes_on_normal_topology(self, monkeypatch):
        topo = {
            "ok": True,
            "moca_bridges": ["AA:AA:AA:AA:AA:AA"],
            "moca_children": {"AA:AA:AA:AA:AA:AA": ["CC:CC:CC:CC:CC:CC"]},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_no_self_referential_classifier_loop("http://x") is None

    def test_fails_when_bridge_is_its_own_child(self, monkeypatch):
        topo = {
            "ok": True,
            "moca_bridges": ["AA:AA:AA:AA:AA:AA"],
            "moca_children": {"AA:AA:AA:AA:AA:AA": ["AA:AA:AA:AA:AA:AA"]},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_no_self_referential_classifier_loop("http://x")
        assert result is not None
        assert "classifier loop" in result

    def test_fails_when_child_is_also_a_bridge(self, monkeypatch):
        """Two devices each in the bridge list while one is a child of
        the other -- structural inconsistency."""
        topo = {
            "ok": True,
            "moca_bridges": ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"],
            "moca_children": {"AA:AA:AA:AA:AA:AA": ["BB:BB:BB:BB:BB:BB"]},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_no_self_referential_classifier_loop("http://x")
        assert result is not None
        assert "both a bridge" in result


class TestCheckNoPhantomBlinkBridges:
    """Regression guard for PR #29's Blink Sync Module false-positive
    hostname-negative-match."""

    def test_returns_none_when_no_blink_in_bridges(self, monkeypatch):
        topo = {
            "ok": True,
            "moca_bridges": ["88:DE:7C:C2:57:36"],
            "devices": {"88:DE:7C:C2:57:36": {"vendor": "ASKEY", "dns_hostname": ""}},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_no_phantom_actiontec_blink_bridges("http://x") is None

    def test_fails_when_blink_appears_as_bridge(self, monkeypatch):
        topo = {
            "ok": True,
            "moca_bridges": ["00:03:7F:B4:A3:0B"],
            "devices": {
                "00:03:7F:B4:A3:0B": {
                    "vendor": "Actiontec",
                    "dns_hostname": "blink-sync-module",
                }
            },
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_no_phantom_actiontec_blink_bridges("http://x")
        assert result is not None
        assert "blink-sync" in result.lower() or "blink" in result.lower()


class TestCheckDashboardConcernsWellFormed:
    def test_passes_on_well_formed_concerns(self, monkeypatch):
        data = {
            "concerns": [
                {"level": "info", "title": "X", "detail": "Y"},
                {"level": "warning", "title": "Z", "detail": "W"},
            ]
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: data)
        assert checker.check_dashboard_concerns_well_formed("http://x") is None

    def test_passes_when_no_concerns(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path: {"concerns": []})
        assert checker.check_dashboard_concerns_well_formed("http://x") is None

    def test_fails_when_concern_missing_required_key(self, monkeypatch):
        data = {
            "concerns": [
                {"level": "info", "title": "X"},  # missing 'detail'
            ]
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: data)
        result = checker.check_dashboard_concerns_well_formed("http://x")
        assert result is not None
        assert "detail" in result


class TestCheckInventoryLoadNotFailed:
    """Indirect probe of the silent-state-wipe guard from PR #30."""

    def test_passes_with_normal_inventory(self, monkeypatch):
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path: {
                "devices": [{"mac": "AA:BB:CC:DD:EE:FF"}],
                "last_scan": "2026-05-13T00:00:00",
            },
        )
        assert checker.check_inventory_load_not_failed("http://x") is None

    def test_passes_on_first_run_no_scan_yet(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path: {"devices": [], "last_scan": None})
        assert checker.check_inventory_load_not_failed("http://x") is None

    def test_fails_when_scan_recorded_but_devices_empty(self, monkeypatch):
        """Smoking gun: a tray that's been running has a last_scan but
        ZERO devices -- almost certainly the silent-state-wipe regression
        from PR #30."""
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path: {"devices": [], "last_scan": "2026-05-13T00:00:00"},
        )
        result = checker.check_inventory_load_not_failed("http://x")
        assert result is not None
        assert "silent state wipe" in result.lower() or "zero devices" in result.lower()


class TestCheckOrbiSatelliteVisibility:
    """Surfaces the firmware quirk as a WARN (not a failure) so the
    operator knows the limitation without it being treated as a
    regression."""

    def test_no_warn_when_satellites_visible(self, monkeypatch):
        topo = {
            "ok": True,
            "aps": [
                {"id": "ap-base", "is_base": True},
                {"id": "ap-sat-1", "is_base": False},
            ],
            "orbi_mesh_unknown_ap": [],
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_orbi_satellite_visibility("http://x") is None

    def test_no_warn_when_unknown_count_is_small(self, monkeypatch):
        topo = {
            "ok": True,
            "aps": [{"id": "ap-base", "is_base": True}],
            "orbi_mesh_unknown_ap": ["MAC1"],  # only 1 -- tolerable
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        assert checker.check_orbi_satellite_visibility("http://x") is None

    def test_warns_when_many_clients_unknown_and_only_base(self, monkeypatch):
        """The user's actual situation: 29 unknown clients, only base AP."""
        topo = {
            "ok": True,
            "aps": [{"id": "ap-base", "is_base": True}],
            "orbi_mesh_unknown_ap": [f"M{i}" for i in range(29)],
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_orbi_satellite_visibility("http://x")
        assert result is not None
        assert "WARN" in result
        assert "firmware" in result.lower()


class TestCheckTopologyBasics:
    def test_fails_when_fetch_errors(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path: {"_fetch_error": "boom"})
        result = checker.check_topology_basics("http://x")
        assert result is not None
        assert "boom" in result

    def test_fails_when_ok_false(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path: {"ok": False})
        result = checker.check_topology_basics("http://x")
        assert result is not None
        assert "ok=False" in result

    def test_fails_when_required_key_missing(self, monkeypatch):
        # Missing "stats"
        topo = {
            "ok": True,
            "router": {},
            "switches": [],
            "aps": [],
            "moca_bridges": [],
            "moca_children": {},
            "devices": {},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path: topo)
        result = checker.check_topology_basics("http://x")
        assert result is not None
        assert "stats" in result
