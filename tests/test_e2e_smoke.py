"""
tests/test_e2e_smoke.py — End-to-end smoke tests.

Hit Flask routes with multi-layer mock chains using real captured fixture data.
Validates the full pipeline: HTTP request → Flask route → get_*() → subprocess
mock (with real PS output) → parsing → JSON response → status code.

Catches integration bugs where individual unit tests pass but the route-level
wiring is broken (wrong key names, missing fields, JSON serialisation errors).

Fixtures are captured by running: python tests/capture_fixtures.py
If fixtures are missing, tests are skipped (not failed).
"""

import json

import pytest

import windesktopmgr as wdm
from tests.conftest import MockResult, load_fixture

pytestmark = pytest.mark.e2e


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_single_ps(mocker, ps_fixture):
    """Mock subprocess.run with a single PS fixture's raw output."""
    raw = load_fixture(f"powershell/{ps_fixture}")
    m = mocker.patch("windesktopmgr.subprocess.run")
    m.return_value = MockResult(stdout=raw if isinstance(raw, str) else json.dumps(raw))
    return m


def _mock_multi_ps(mocker, ps_fixtures):
    """Mock subprocess.run with multiple PS fixtures (for multi-call functions)."""
    results = []
    for f in ps_fixtures:
        raw = load_fixture(f"powershell/{f}")
        results.append(MockResult(stdout=raw if isinstance(raw, str) else json.dumps(raw)))
    m = mocker.patch("windesktopmgr.subprocess.run")
    m.side_effect = results
    return m


# ══════════════════════════════════════════════════════════════════════════════
# /api/disk/data
# ══════════════════════════════════════════════════════════════════════════════


class TestDiskDataE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_multi_ps(mocker, ["ps_disk_health.json", "ps_disk_io.json"])
        resp = client.get("/api/disk/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "drives" in data or "physical" in data

    def test_response_drives_have_fields(self, client, mocker):
        _mock_multi_ps(mocker, ["ps_disk_health.json", "ps_disk_io.json"])
        resp = client.get("/api/disk/data")
        data = resp.get_json()
        if data.get("drives"):
            for d in data["drives"]:
                assert "Letter" in d or "Name" in d or "DriveLetter" in d


# ══════════════════════════════════════════════════════════════════════════════
# /api/thermals/data
# ══════════════════════════════════════════════════════════════════════════════


class TestThermalsDataE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_thermals.json")
        resp = client.get("/api/thermals/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_keys_match_expected(self, client, mocker):
        _mock_single_ps(mocker, "ps_thermals.json")
        expected = load_fixture("parsed/parsed_get_thermals.json")
        resp = client.get("/api/thermals/data")
        data = resp.get_json()
        assert set(data.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# /api/services/list
# ══════════════════════════════════════════════════════════════════════════════


class TestServicesListE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_services_list.json")
        resp = client.get("/api/services/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_service_count_matches(self, client, mocker):
        _mock_single_ps(mocker, "ps_services_list.json")
        expected = load_fixture("parsed/parsed_get_services_list.json")
        resp = client.get("/api/services/list")
        data = resp.get_json()
        assert len(data) == len(expected)


# ══════════════════════════════════════════════════════════════════════════════
# /api/startup/list
# ══════════════════════════════════════════════════════════════════════════════


class TestStartupListE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_startup_items.json")
        resp = client.get("/api/startup/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_item_count_matches(self, client, mocker):
        _mock_single_ps(mocker, "ps_startup_items.json")
        expected = load_fixture("parsed/parsed_get_startup_items.json")
        resp = client.get("/api/startup/list")
        data = resp.get_json()
        assert len(data) == len(expected)


# ══════════════════════════════════════════════════════════════════════════════
# /api/processes/list
# ══════════════════════════════════════════════════════════════════════════════


class TestProcessListE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_process_list.json")
        resp = client.get("/api/processes/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "processes" in data

    def test_process_count_matches(self, client, mocker):
        _mock_single_ps(mocker, "ps_process_list.json")
        expected = load_fixture("parsed/parsed_get_process_list.json")
        resp = client.get("/api/processes/list")
        data = resp.get_json()
        if "processes" in expected:
            assert len(data["processes"]) == len(expected["processes"])


# ══════════════════════════════════════════════════════════════════════════════
# /api/updates/history
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdatesHistoryE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_update_history.json")
        resp = client.get("/api/updates/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_update_count_matches(self, client, mocker):
        _mock_single_ps(mocker, "ps_update_history.json")
        expected = load_fixture("parsed/parsed_get_update_history.json")
        resp = client.get("/api/updates/history")
        data = resp.get_json()
        assert len(data) == len(expected)


# ══════════════════════════════════════════════════════════════════════════════
# /api/network/data
# ══════════════════════════════════════════════════════════════════════════════


class TestNetworkDataE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_multi_ps(mocker, ["ps_network_conns.json", "ps_network_adapters.json"])
        resp = client.get("/api/network/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_keys_match_expected(self, client, mocker):
        _mock_multi_ps(mocker, ["ps_network_conns.json", "ps_network_adapters.json"])
        expected = load_fixture("parsed/parsed_get_network_data.json")
        resp = client.get("/api/network/data")
        data = resp.get_json()
        assert set(data.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# /api/memory/data
# ══════════════════════════════════════════════════════════════════════════════


class TestMemoryDataE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        raw_procs = load_fixture("powershell/ps_memory_analysis.json")
        sys_mem = json.dumps({"TotalMB": 32000, "FreeMB": 8000})
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            MockResult(stdout=raw_procs if isinstance(raw_procs, str) else json.dumps(raw_procs)),
            MockResult(stdout=sys_mem),
        ]
        resp = client.get("/api/memory/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_keys_match_expected(self, client, mocker):
        raw_procs = load_fixture("powershell/ps_memory_analysis.json")
        sys_mem = json.dumps({"TotalMB": 32000, "FreeMB": 8000})
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            MockResult(stdout=raw_procs if isinstance(raw_procs, str) else json.dumps(raw_procs)),
            MockResult(stdout=sys_mem),
        ]
        expected = load_fixture("parsed/parsed_get_memory_analysis.json")
        resp = client.get("/api/memory/data")
        data = resp.get_json()
        assert set(data.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# /api/bios/status
# ══════════════════════════════════════════════════════════════════════════════


class TestBiosStatusE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_bios.json")
        # get_bios_status calls check_dell_bios_update internally
        mocker.patch("windesktopmgr.check_dell_bios_update", return_value=None)
        resp = client.get("/api/bios/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "current" in data


# ══════════════════════════════════════════════════════════════════════════════
# /api/credentials/health
# ══════════════════════════════════════════════════════════════════════════════


class TestCredentialsHealthE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_credentials.json")
        resp = client.get("/api/credentials/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_keys_match_expected(self, client, mocker):
        _mock_single_ps(mocker, "ps_credentials.json")
        expected = load_fixture("parsed/parsed_get_credentials_network_health.json")
        resp = client.get("/api/credentials/health")
        data = resp.get_json()
        assert set(data.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# /api/timeline/data
# ══════════════════════════════════════════════════════════════════════════════


class TestTimelineDataE2E:
    def test_returns_200_with_real_fixture(self, client, mocker):
        _mock_single_ps(mocker, "ps_timeline.json")
        resp = client.get("/api/timeline/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "events" in data
        assert "days" in data
        assert "total" in data


# ══════════════════════════════════════════════════════════════════════════════
# /api/health (heartbeat)
# ══════════════════════════════════════════════════════════════════════════════


class TestHealthHeartbeatE2E:
    def test_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["status"] == "running"


# ══════════════════════════════════════════════════════════════════════════════
# Driver health (function-level E2E with real fixture)
# ══════════════════════════════════════════════════════════════════════════════


class TestDriverHealthE2E:
    def test_parses_real_fixture_through_full_chain(self, mocker):
        """Call get_driver_health() with real PS fixture — full parsing chain."""
        _mock_single_ps(mocker, "ps_driver_health.json")
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        result = wdm.get_driver_health()
        assert isinstance(result, dict)
        assert "old_drivers" in result
        assert "problematic_drivers" in result
        assert "nvidia" in result
