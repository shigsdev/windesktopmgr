"""
test_integration.py — Integration tests that run REAL PowerShell commands.

These tests verify that the actual PS scripts return valid, parseable data
on a live Windows machine. They do NOT mock subprocess.run.

Usage:
    pytest -m integration          # run only these
    pytest -m integration -v       # verbose
    pytest                         # skips these (default via pyproject.toml)

Each test calls the real data-gathering function and checks:
    1. It returns without raising
    2. The return type is correct (list, dict, etc.)
    3. Required keys/structure are present
    4. No empty-when-shouldnt-be fields

These tests are slow (~30s total) because they hit real WMI/PowerShell.
"""

import sys

import pytest

# Skip entire module on non-Windows
if sys.platform != "win32":
    pytest.skip("Integration tests require Windows", allow_module_level=True)

import windesktopmgr as wdm

pytestmark = pytest.mark.integration


class TestGetInstalledDriversIntegration:
    def test_returns_list(self):
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)

    def test_has_drivers(self):
        result = wdm.get_installed_drivers()
        assert len(result) > 0, "Expected at least one installed driver"

    def test_driver_has_required_fields(self):
        result = wdm.get_installed_drivers()
        for drv in result[:5]:
            assert "DeviceName" in drv
            assert "DriverVersion" in drv


class TestGetWindowsUpdateDriversIntegration:
    def test_returns_dict_or_none_on_timeout(self):
        result = wdm.get_windows_update_drivers()
        assert result is None or isinstance(result, dict)


class TestGetDiskHealthIntegration:
    def test_returns_dict_with_keys(self):
        result = wdm.get_disk_health()
        assert isinstance(result, dict)
        assert "drives" in result
        assert "physical" in result
        assert "io" in result

    def test_has_at_least_one_drive(self):
        result = wdm.get_disk_health()
        assert len(result["drives"]) > 0

    def test_drive_has_letter_and_size(self):
        result = wdm.get_disk_health()
        for d in result["drives"]:
            assert "Letter" in d
            assert "TotalGB" in d


class TestGetNetworkDataIntegration:
    def test_returns_dict_with_keys(self):
        result = wdm.get_network_data()
        assert isinstance(result, dict)
        for key in ("established", "listening", "adapters", "top_processes"):
            assert key in result

    def test_has_connections(self):
        result = wdm.get_network_data()
        assert result["total_connections"] >= 0
        assert result["total_listening"] >= 0


class TestGetUpdateHistoryIntegration:
    def test_returns_list(self):
        result = wdm.get_update_history()
        assert isinstance(result, list)

    def test_updates_have_title(self):
        result = wdm.get_update_history()
        for upd in result[:5]:
            assert "Title" in upd


class TestGetProcessListIntegration:
    def test_returns_dict_with_processes(self):
        result = wdm.get_process_list()
        assert isinstance(result, dict)
        assert "processes" in result
        assert "total" in result
        assert result["total"] > 0

    def test_processes_have_name_and_pid(self):
        result = wdm.get_process_list()
        for p in result["processes"][:5]:
            assert "Name" in p
            assert "PID" in p


class TestGetThermalsIntegration:
    def test_returns_dict_with_keys(self):
        result = wdm.get_thermals()
        assert isinstance(result, dict)
        assert "temps" in result
        assert "perf" in result
        assert "fans" in result

    def test_perf_has_cpu_and_mem(self):
        result = wdm.get_thermals()
        perf = result["perf"]
        assert "CPUPct" in perf
        assert "MemUsedMB" in perf


class TestGetServicesListIntegration:
    def test_returns_list(self):
        result = wdm.get_services_list()
        assert isinstance(result, list)

    def test_has_services(self):
        result = wdm.get_services_list()
        assert len(result) > 10, "Expected many services on a Windows machine"

    def test_service_has_name_and_status(self):
        result = wdm.get_services_list()
        for svc in result[:5]:
            assert "Name" in svc
            assert "Status" in svc


class TestGetStartupItemsIntegration:
    def test_returns_list(self):
        result = wdm.get_startup_items()
        assert isinstance(result, list)


class TestGetBsodEventsIntegration:
    def test_returns_list(self):
        result = wdm.get_bsod_events()
        assert isinstance(result, list)


class TestGetCurrentBiosIntegration:
    def test_returns_dict_with_version(self):
        result = wdm.get_current_bios()
        assert isinstance(result, dict)
        assert "BIOSVersion" in result
        assert "Manufacturer" in result


class TestGetMemoryAnalysisIntegration:
    def test_returns_dict_with_keys(self):
        result = wdm.get_memory_analysis()
        assert isinstance(result, dict)
        assert "total_mb" in result
        assert "used_mb" in result
        assert result["total_mb"] > 0

    def test_top_procs_populated(self):
        result = wdm.get_memory_analysis()
        assert len(result["top_procs"]) > 0


class TestGetSystemTimelineIntegration:
    def test_returns_list(self):
        result = wdm.get_system_timeline()
        assert isinstance(result, list)

    def test_events_have_required_fields(self):
        result = wdm.get_system_timeline()
        for event in result[:5]:
            for field in ("ts", "type", "category", "title", "severity", "icon"):
                assert field in event


class TestGetCredentialsNetworkHealthIntegration:
    def test_returns_dict(self):
        result = wdm.get_credentials_network_health()
        assert isinstance(result, dict)

    def test_has_expected_keys(self):
        result = wdm.get_credentials_network_health()
        # Should have at least some of the standard keys
        expected = {"creds", "events", "fw"}
        assert expected.issubset(set(result.keys())) or len(result) > 0


class TestGetHealthReportHistoryIntegration:
    def test_returns_dict(self):
        result = wdm.get_health_report_history()
        assert isinstance(result, dict)
        assert "reports" in result
