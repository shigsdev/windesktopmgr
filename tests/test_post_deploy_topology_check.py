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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        assert checker.check_moca_bridge_count_matches_strict_vendors("http://x") is None

    def test_returns_none_when_user_attested(self, monkeypatch):
        topo = self._topology(
            {
                # Commscope -- NOT in strict vendors, but user said so
                "B0:5D:D4:76:2A:C0": {"vendor": "Commscope", "wired_via": "moca_bridge"},
            }
        )
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        assert checker.check_moca_bridge_count_matches_strict_vendors("http://x") is None

    def test_fails_when_phantom_commscope_appears(self, monkeypatch):
        """The exact bug shape from the 2026-05-12 user report."""
        topo = self._topology(
            {
                "B0:5D:D4:76:2A:C0": {"vendor": "Commscope", "wired_via": ""},
            }
        )
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        assert checker.check_no_self_referential_classifier_loop("http://x") is None

    def test_fails_when_bridge_is_its_own_child(self, monkeypatch):
        topo = {
            "ok": True,
            "moca_bridges": ["AA:AA:AA:AA:AA:AA"],
            "moca_children": {"AA:AA:AA:AA:AA:AA": ["AA:AA:AA:AA:AA:AA"]},
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        assert checker.check_dashboard_concerns_well_formed("http://x") is None

    def test_passes_when_no_concerns(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: {"concerns": []})
        assert checker.check_dashboard_concerns_well_formed("http://x") is None

    def test_fails_when_concern_missing_required_key(self, monkeypatch):
        data = {
            "concerns": [
                {"level": "info", "title": "X"},  # missing 'detail'
            ]
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        result = checker.check_dashboard_concerns_well_formed("http://x")
        assert result is not None
        assert "detail" in result


class TestCheckInventoryLoadNotFailed:
    """Indirect probe of the silent-state-wipe guard from PR #30."""

    def test_passes_with_normal_inventory(self, monkeypatch):
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {
                "devices": [{"mac": "AA:BB:CC:DD:EE:FF"}],
                "last_scan": "2026-05-13T00:00:00",
            },
        )
        assert checker.check_inventory_load_not_failed("http://x") is None

    def test_passes_on_first_run_no_scan_yet(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: {"devices": [], "last_scan": None})
        assert checker.check_inventory_load_not_failed("http://x") is None

    def test_fails_when_scan_recorded_but_devices_empty(self, monkeypatch):
        """Smoking gun: a tray that's been running has a last_scan but
        ZERO devices -- almost certainly the silent-state-wipe regression
        from PR #30."""
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {"devices": [], "last_scan": "2026-05-13T00:00:00"},
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        assert checker.check_orbi_satellite_visibility("http://x") is None

    def test_no_warn_when_unknown_count_is_small(self, monkeypatch):
        topo = {
            "ok": True,
            "aps": [{"id": "ap-base", "is_base": True}],
            "orbi_mesh_unknown_ap": ["MAC1"],  # only 1 -- tolerable
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        assert checker.check_orbi_satellite_visibility("http://x") is None

    def test_warns_when_many_clients_unknown_and_only_base(self, monkeypatch):
        """The user's actual situation: 29 unknown clients, only base AP."""
        topo = {
            "ok": True,
            "aps": [{"id": "ap-base", "is_base": True}],
            "orbi_mesh_unknown_ap": [f"M{i}" for i in range(29)],
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        result = checker.check_orbi_satellite_visibility("http://x")
        assert result is not None
        assert "WARN" in result
        assert "firmware" in result.lower()


class TestCheckNoRecentBiosAuditErrors:
    """The semantic gate that would have caught the 2026-05-14 'bios_serial
    timing out for a month' issue. Returns None on healthy or transient
    errors; returns a WARN string when the same field has failed 3+ times
    in the last 7 days."""

    def _now_iso(self):
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    def _hours_ago(self, h):
        from datetime import datetime, timedelta, timezone

        return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()

    def test_passes_with_no_errors(self, monkeypatch):
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {"history": [{"kind": "baseline", "timestamp": self._now_iso()}]},
        )
        assert checker.check_no_recent_bios_audit_errors("http://x") is None

    def test_passes_with_one_transient_error(self, monkeypatch):
        """A single error isn't a pattern -- don't fail the gate."""
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {
                "history": [
                    {
                        "kind": "error",
                        "timestamp": self._hours_ago(2),
                        "errors": [{"field": "bios_serial", "error": "timeout after 10s"}],
                    },
                ]
            },
        )
        assert checker.check_no_recent_bios_audit_errors("http://x") is None

    def test_passes_when_old_errors_outside_window(self, monkeypatch):
        """Errors from 14 days ago are not 'recent' -- ignored."""
        from datetime import datetime, timedelta, timezone

        old_ts = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {
                "history": [
                    {
                        "kind": "error",
                        "timestamp": old_ts,
                        "errors": [{"field": "bios_serial", "error": "timeout after 10s"}],
                    }
                    for _ in range(10)
                ]
            },
        )
        assert checker.check_no_recent_bios_audit_errors("http://x") is None

    def test_warns_when_same_field_fails_3_plus_times_in_7d(self, monkeypatch):
        """The exact pattern from the user's 2026-05-14 report:
        bios_serial failing every poll for many days."""
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {
                "history": [
                    {
                        "kind": "error",
                        "timestamp": self._hours_ago(i),
                        "errors": [{"field": "bios_serial", "error": "timeout after 10s"}],
                    }
                    for i in (1, 12, 24, 36)
                ]
            },
        )
        result = checker.check_no_recent_bios_audit_errors("http://x")
        assert result is not None
        assert "bios_serial" in result
        assert "chronic" in result.lower() or "4x" in result.lower() or "cache" in result.lower()

    def test_aggregates_across_multiple_fields(self, monkeypatch):
        """Both bios_serial AND vbs failing -> both reported in the warning."""
        monkeypatch.setattr(
            checker,
            "_get",
            lambda host, path, timeout=None: {
                "history": [
                    {
                        "kind": "error",
                        "timestamp": self._hours_ago(i),
                        "errors": [{"field": "bios_serial", "error": "x"}],
                    }
                    for i in (1, 2, 3)
                ]
                + [
                    {
                        "kind": "error",
                        "timestamp": self._hours_ago(i),
                        "errors": [{"field": "vbs", "error": "y"}],
                    }
                    for i in (4, 5, 6)
                ]
            },
        )
        result = checker.check_no_recent_bios_audit_errors("http://x")
        assert result is not None
        assert "bios_serial" in result
        assert "vbs" in result


class TestCheckTopologyBasics:
    def test_fails_when_fetch_errors(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: {"_fetch_error": "boom"})
        result = checker.check_topology_basics("http://x")
        assert result is not None
        assert "boom" in result

    def test_fails_when_ok_false(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: {"ok": False})
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
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: topo)
        result = checker.check_topology_basics("http://x")
        assert result is not None
        assert "stats" in result


class TestTopologyFetchTimeout:
    """Regression guard for the false-fail bug: /api/homenet/topology
    triggers a ~12s live network scan on real hardware, but the checker's
    _get() used a flat 10s timeout, so a healthy-but-slow topology fetch
    reported 'topology fetch failed: timed out' and failed the deploy gate.

    Fix: _get() takes a per-call timeout and topology checks request the
    wider TOPOLOGY_TIMEOUT budget.
    """

    def _full_topology(self):
        return {
            "ok": True,
            "router": {},
            "switches": [],
            "aps": [],
            "moca_bridges": [],
            "moca_children": {},
            "devices": {},
            "stats": {},
        }

    def test_topology_timeout_is_wider_than_default(self):
        assert checker.TOPOLOGY_TIMEOUT > checker.DEFAULT_TIMEOUT

    def test_topology_basics_requests_extended_timeout(self, monkeypatch):
        """check_topology_basics must ask _get for the wider budget, not
        the default that false-failed on a ~12s scan."""
        calls: list[tuple[str, float | None]] = []

        def spy(host, path, timeout=checker.DEFAULT_TIMEOUT):
            calls.append((path, timeout))
            return self._full_topology()

        monkeypatch.setattr(checker, "_get", spy)
        assert checker.check_topology_basics("http://x") is None
        assert calls == [("/api/homenet/topology", checker.TOPOLOGY_TIMEOUT)]

    def test_all_topology_checks_use_extended_timeout(self, monkeypatch):
        """Every check that hits /api/homenet/topology must use the wider
        budget -- otherwise the sibling checks silently no-op (return None
        -> PASS) on a slow fetch, turning them into false-passes."""
        seen: list[float | None] = []

        def spy(host, path, timeout=checker.DEFAULT_TIMEOUT):
            if path == "/api/homenet/topology":
                seen.append(timeout)
            return self._full_topology()

        monkeypatch.setattr(checker, "_get", spy)
        for _name, fn, _sev in checker.CHECKS:
            fn("http://x")
        assert seen, "no check fetched the topology endpoint"
        assert all(t == checker.TOPOLOGY_TIMEOUT for t in seen), seen

    @staticmethod
    def _patch_urlopen(monkeypatch, body: bytes):
        """Stub urllib.request.urlopen and return a dict that captures the
        timeout it was called with."""
        captured: dict[str, float] = {}

        class _FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return body

        def fake_urlopen(url, timeout=None):
            captured["timeout"] = timeout
            return _FakeResp()

        monkeypatch.setattr(checker.urllib.request, "urlopen", fake_urlopen)
        return captured

    def test_get_passes_timeout_through_to_urlopen(self, monkeypatch):
        """_get must honor its timeout argument (not the old hardcoded 10)."""
        captured = self._patch_urlopen(monkeypatch, b'{"ok": true}')
        assert checker._get("http://x", "/api/foo", timeout=30) == {"ok": True}
        assert captured["timeout"] == 30

    def test_get_defaults_to_default_timeout(self, monkeypatch):
        captured = self._patch_urlopen(monkeypatch, b"{}")
        checker._get("http://x", "/api/foo")
        assert captured["timeout"] == checker.DEFAULT_TIMEOUT


class TestCheckNvidiaStatusEndpoint:
    """Post-deploy semantic check for /api/nvidia/status. Catches the
    2026-05-18 regression where the NVIDIA update card was invisible."""

    def test_passes_with_nvidia_gpu_and_valid_schema(self, monkeypatch):
        data = {
            "ok": True,
            "has_nvidia": True,
            "Name": "NVIDIA GeForce RTX 4060 Ti",
            "InstalledVersion": "595.79",
            "LatestVersion": "595.79",
            "UpdateAvailable": False,
            "UpdateSource": "nvidia_api",
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        assert checker.check_nvidia_status_endpoint("http://x") is None

    def test_passes_with_no_nvidia_gpu(self, monkeypatch):
        data = {"ok": True, "has_nvidia": False}
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        assert checker.check_nvidia_status_endpoint("http://x") is None

    def test_fails_on_fetch_error(self, monkeypatch):
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: {"_fetch_error": "404"})
        result = checker.check_nvidia_status_endpoint("http://x")
        assert result is not None
        assert "fetch failed" in result

    def test_fails_when_gpu_present_but_installed_version_empty(self, monkeypatch):
        data = {
            "ok": True,
            "has_nvidia": True,
            "Name": "NVIDIA GeForce RTX 4060 Ti",
            "InstalledVersion": "",
            "UpdateAvailable": False,
            "UpdateSource": "none",
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        result = checker.check_nvidia_status_endpoint("http://x")
        assert result is not None
        assert "InstalledVersion" in result

    def test_fails_when_required_key_missing(self, monkeypatch):
        data = {
            "ok": True,
            "has_nvidia": True,
            "Name": "NVIDIA GeForce RTX 4060 Ti",
            # Missing InstalledVersion, UpdateAvailable, UpdateSource
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        result = checker.check_nvidia_status_endpoint("http://x")
        assert result is not None
        assert "missing required key" in result

    def test_update_available_passes_schema_check(self, monkeypatch):
        """When an update IS available, the schema check still passes."""
        data = {
            "ok": True,
            "has_nvidia": True,
            "Name": "NVIDIA GeForce RTX 4060 Ti",
            "InstalledVersion": "591.74",
            "LatestVersion": "595.79",
            "UpdateAvailable": True,
            "UpdateSource": "nvidia_api",
        }
        monkeypatch.setattr(checker, "_get", lambda host, path, timeout=None: data)
        assert checker.check_nvidia_status_endpoint("http://x") is None
