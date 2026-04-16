"""
tests/test_snapshots.py — Snapshot regression tests.

Feed captured real PowerShell output through the parsing functions and verify
the result matches the captured parsed output. Catches regressions where
real system output format drifts from what the parser expects.

Fixtures are captured by running: python tests/capture_fixtures.py
If fixtures are missing, tests are skipped (not failed).
"""

import json
import types

import pytest

import windesktopmgr as wdm
from tests.conftest import MockResult, load_fixture

pytestmark = pytest.mark.snapshot


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_single_ps(mocker, ps_fixture):
    """Mock subprocess.run with a single PS fixture's raw output."""
    raw = load_fixture(f"powershell/{ps_fixture}")
    m = mocker.patch("windesktopmgr.subprocess.run")
    m.return_value = MockResult(stdout=raw if isinstance(raw, str) else json.dumps(raw))
    return m


def _fixture_to_wmi_objs(ps_fixture):
    """Load a PS JSON fixture and convert each dict to a SimpleNamespace (WMI-like object)."""
    raw = load_fixture(f"powershell/{ps_fixture}")
    data = json.loads(raw) if isinstance(raw, str) else raw
    if isinstance(data, dict):
        data = [data]
    return [types.SimpleNamespace(**d) for d in data]


def _mock_wmi_snap(mocker, classes):
    """Patch wmi.WMI() for snapshot tests with a dict of class name → list of objects."""
    mock_conn = mocker.MagicMock()
    for name, data in classes.items():
        setattr(mock_conn, name, mocker.MagicMock(return_value=data))
    mocker.patch("windesktopmgr.wmi.WMI", return_value=mock_conn)
    return mock_conn


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
# get_installed_drivers
# ══════════════════════════════════════════════════════════════════════════════


class TestGetInstalledDriversSnapshot:
    def test_parses_real_output(self, mocker):
        wmi_objs = _fixture_to_wmi_objs("ps_installed_drivers.json")
        _mock_wmi_snap(mocker, {"Win32_PnPSignedDriver": wmi_objs})
        expected = load_fixture("parsed/parsed_get_installed_drivers.json")
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)
        assert len(result) == len(expected)

    def test_all_drivers_have_required_keys(self, mocker):
        wmi_objs = _fixture_to_wmi_objs("ps_installed_drivers.json")
        _mock_wmi_snap(mocker, {"Win32_PnPSignedDriver": wmi_objs})
        result = wdm.get_installed_drivers()
        for drv in result:
            assert "DeviceName" in drv
            assert "DriverVersion" in drv


# ══════════════════════════════════════════════════════════════════════════════
# get_driver_health
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDriverHealthSnapshot:
    def _load_fixture_as_wmi(self):
        """Convert driver health fixture to WMI-like objects for the new wmi-based function."""
        raw = load_fixture("powershell/ps_driver_health.json")
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        # Build Win32_PnPSignedDriver objects from OldDrivers
        signed = []
        for d in parsed.get("OldDrivers", []):
            date_str = d.get("Date", "")
            wmi_date = date_str.replace("-", "") + "000000.000000+000" if date_str else ""
            signed.append(
                types.SimpleNamespace(
                    DeviceName=d["DeviceName"],
                    DriverProviderName=d["Provider"],
                    DriverVersion=d["Version"],
                    DriverDate=wmi_date,
                )
            )
        # Build Win32_PnPEntity objects from Problematic
        entities = []
        for p in parsed.get("Problematic", []):
            entities.append(
                types.SimpleNamespace(
                    Name=p["DeviceName"],
                    ConfigManagerErrorCode=p["ErrorCode"],
                    Status=p.get("Status", ""),
                )
            )
        # Add one OK entity so the filter works
        entities.append(types.SimpleNamespace(Name="OK Device", ConfigManagerErrorCode=0, Status="OK"))
        return signed, entities

    def test_parses_real_output(self, mocker):
        signed, entities = self._load_fixture_as_wmi()
        _mock_wmi_snap(
            mocker,
            {
                "Win32_PnPSignedDriver": signed,
                "Win32_PnPEntity": entities,
            },
        )
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        result = wdm.get_driver_health()
        assert "old_drivers" in result
        assert "problematic_drivers" in result
        assert "nvidia" in result
        assert isinstance(result["old_drivers"], list)
        assert isinstance(result["problematic_drivers"], list)

    def test_old_drivers_have_required_keys(self, mocker):
        signed, entities = self._load_fixture_as_wmi()
        _mock_wmi_snap(
            mocker,
            {
                "Win32_PnPSignedDriver": signed,
                "Win32_PnPEntity": entities,
            },
        )
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        result = wdm.get_driver_health()
        for drv in result["old_drivers"]:
            assert "DeviceName" in drv
            assert "Provider" in drv
            assert "Version" in drv
            assert "Date" in drv


# ══════════════════════════════════════════════════════════════════════════════
# get_disk_health
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDiskHealthSnapshot:
    def test_parses_real_output(self, mocker):
        _mock_multi_ps(mocker, ["ps_disk_health.json", "ps_disk_io.json"])
        expected = load_fixture("parsed/parsed_get_disk_health.json")
        result = wdm.get_disk_health()
        assert "drives" in result or "physical" in result
        # Verify same number of drives parsed
        if "drives" in expected and "drives" in result:
            assert len(result["drives"]) == len(expected["drives"])

    def test_drives_have_health_fields(self, mocker):
        _mock_multi_ps(mocker, ["ps_disk_health.json", "ps_disk_io.json"])
        result = wdm.get_disk_health()
        if result.get("drives"):
            for d in result["drives"]:
                assert "Letter" in d or "Name" in d or "DriveLetter" in d or "DeviceID" in d


# ══════════════════════════════════════════════════════════════════════════════
# get_thermals
# ══════════════════════════════════════════════════════════════════════════════


class TestGetThermalsSnapshot:
    def test_parses_real_output(self, mocker):
        _mock_single_ps(mocker, "ps_thermals.json")
        result = wdm.get_thermals()
        assert isinstance(result, dict)
        # Should have some thermal data structure
        assert len(result) > 0

    def test_result_matches_expected_structure(self, mocker):
        _mock_single_ps(mocker, "ps_thermals.json")
        expected = load_fixture("parsed/parsed_get_thermals.json")
        result = wdm.get_thermals()
        # Verify same top-level keys
        assert set(result.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# get_services_list
# ══════════════════════════════════════════════════════════════════════════════


class TestGetServicesListSnapshot:
    """After backlog #24 batch A, get_services_list() uses psutil directly
    — no PowerShell output to snapshot-test. The fixture is kept as a
    format reference, but the test now validates the output *shape* from
    real psutil rather than parser parity against captured JSON."""

    def test_output_shape_matches_fixture(self):
        expected = load_fixture("parsed/parsed_get_services_list.json")
        result = wdm.get_services_list()
        assert isinstance(result, list)
        # Real Windows boxes always have services; empty only happens if
        # win_service_iter fails entirely — we still want a usable result.
        if result and expected:
            assert set(result[0].keys()) >= (set(expected[0].keys()) - {"info"})

    def test_services_have_required_keys(self):
        result = wdm.get_services_list()
        if result:
            svc = result[0]
            assert "Name" in svc or "DisplayName" in svc


# ══════════════════════════════════════════════════════════════════════════════
# get_process_list
# ══════════════════════════════════════════════════════════════════════════════


class TestGetProcessListSnapshot:
    """After backlog #24 batch A, get_process_list() uses psutil directly
    — no PowerShell output to snapshot-test. The parsed fixture is kept
    as a format reference; the test now validates output shape + per-proc
    keys against the historical schema instead of count parity."""

    def test_output_shape_matches_fixture(self):
        expected = load_fixture("parsed/parsed_get_process_list.json")
        result = wdm.get_process_list()
        assert isinstance(result, dict)
        assert "processes" in result
        if result["processes"] and "processes" in expected and expected["processes"]:
            # Every key from the captured fixture must still exist on the
            # psutil result (we may add more, but must not drop any).
            expected_keys = set(expected["processes"][0].keys())
            actual_keys = set(result["processes"][0].keys())
            missing = expected_keys - actual_keys
            assert not missing, f"psutil output dropped keys: {missing}"

    def test_processes_have_required_keys(self):
        result = wdm.get_process_list()
        procs = result.get("processes", [])
        if procs:
            proc = procs[0]
            assert "Name" in proc or "ProcessName" in proc


# ══════════════════════════════════════════════════════════════════════════════
# get_startup_items
# ══════════════════════════════════════════════════════════════════════════════


class TestGetStartupItemsSnapshot:
    def test_parses_real_output(self, mocker):
        _mock_single_ps(mocker, "ps_startup_items.json")
        expected = load_fixture("parsed/parsed_get_startup_items.json")
        result = wdm.get_startup_items()
        assert isinstance(result, list)
        assert len(result) == len(expected)


# ══════════════════════════════════════════════════════════════════════════════
# get_memory_analysis
# ══════════════════════════════════════════════════════════════════════════════


class TestGetMemoryAnalysisSnapshot:
    def test_parses_real_output(self, mocker):
        # get_memory_analysis() makes TWO subprocess calls:
        # 1. Process list  2. System memory info (Win32_OperatingSystem)
        raw_procs = load_fixture("powershell/ps_memory_analysis.json")
        sys_mem = json.dumps({"TotalMB": 32000, "FreeMB": 8000})
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            MockResult(stdout=raw_procs if isinstance(raw_procs, str) else json.dumps(raw_procs)),
            MockResult(stdout=sys_mem),
        ]
        expected = load_fixture("parsed/parsed_get_memory_analysis.json")
        result = wdm.get_memory_analysis()
        assert isinstance(result, dict)
        # Verify same top-level keys
        assert set(result.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# get_update_history
# ══════════════════════════════════════════════════════════════════════════════


class TestGetUpdateHistorySnapshot:
    def test_parses_real_output(self, mocker):
        _mock_single_ps(mocker, "ps_update_history.json")
        expected = load_fixture("parsed/parsed_get_update_history.json")
        result = wdm.get_update_history()
        assert isinstance(result, list)
        assert len(result) == len(expected)


# ══════════════════════════════════════════════════════════════════════════════
# get_current_bios
# ══════════════════════════════════════════════════════════════════════════════


class TestGetCurrentBiosSnapshot:
    def test_parses_real_output(self, mocker):
        raw = load_fixture("powershell/ps_bios.json")
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        bios_obj = types.SimpleNamespace(
            SMBIOSBIOSVersion=parsed.get("BIOSVersion", ""),
            ReleaseDate=parsed.get("ReleaseDate", ""),
            Manufacturer=parsed.get("Manufacturer", ""),
        )
        board_obj = types.SimpleNamespace(
            Product=parsed.get("BoardProduct", ""),
            Manufacturer=parsed.get("BoardMfr", ""),
        )
        _mock_wmi_snap(mocker, {"Win32_BIOS": [bios_obj], "Win32_BaseBoard": [board_obj]})
        expected = load_fixture("parsed/parsed_get_current_bios.json")
        result = wdm.get_current_bios()
        assert isinstance(result, dict)
        assert set(result.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# get_network_data
# ══════════════════════════════════════════════════════════════════════════════


class TestGetNetworkDataSnapshot:
    def test_parses_real_output(self, mocker):
        _mock_multi_ps(mocker, ["ps_network_conns.json", "ps_network_adapters.json"])
        expected = load_fixture("parsed/parsed_get_network_data.json")
        result = wdm.get_network_data()
        assert isinstance(result, dict)
        assert set(result.keys()) == set(expected.keys())


# ══════════════════════════════════════════════════════════════════════════════
# get_credentials_network_health
# ══════════════════════════════════════════════════════════════════════════════


class TestGetCredentialsSnapshot:
    def test_parses_real_output(self, mocker):
        _mock_single_ps(mocker, "ps_credentials.json")
        result = wdm.get_credentials_network_health()
        assert isinstance(result, dict)
        expected = load_fixture("parsed/parsed_get_credentials_network_health.json")
        assert set(result.keys()) == set(expected.keys())
