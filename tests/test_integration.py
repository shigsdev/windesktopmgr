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


class TestEnumerateLogicalDrivesIntegration:
    """Snapshot/contract test for the pure-Python disk enumeration path.

    Exercises real psutil + ctypes so we catch drift if psutil changes
    its disk_partitions opts strings, or if WNetGetConnectionW / GetVolumeInformationW
    behavior shifts. No subprocess — runs fast.
    """

    def test_returns_list(self):
        result = wdm._enumerate_logical_drives()
        assert isinstance(result, list)

    def test_has_at_least_one_drive(self):
        result = wdm._enumerate_logical_drives()
        assert len(result) > 0, "Expected at least one logical drive on this machine"

    def test_every_drive_has_contract_keys(self):
        result = wdm._enumerate_logical_drives()
        required = {
            "Letter",
            "Label",
            "UsedGB",
            "FreeGB",
            "TotalGB",
            "PctUsed",
            "DriveType",
            "DriveTypeName",
            "FileSystem",
            "UNCPath",
        }
        for d in result:
            missing = required - set(d.keys())
            assert not missing, f"Drive {d.get('Letter')} missing keys: {missing}"

    def test_field_types_are_correct(self):
        result = wdm._enumerate_logical_drives()
        for d in result:
            assert isinstance(d["Letter"], str)
            assert isinstance(d["Label"], str)
            assert isinstance(d["UsedGB"], int | float)
            assert isinstance(d["FreeGB"], int | float)
            assert isinstance(d["TotalGB"], int | float)
            assert isinstance(d["PctUsed"], int | float)
            assert isinstance(d["DriveType"], int)
            assert isinstance(d["DriveTypeName"], str)
            assert isinstance(d["FileSystem"], str)
            assert d["UNCPath"] is None or isinstance(d["UNCPath"], str)

    def test_drive_types_are_valid_enum_values(self):
        result = wdm._enumerate_logical_drives()
        valid = {2, 3, 4}
        for d in result:
            assert d["DriveType"] in valid, f"Unexpected DriveType {d['DriveType']} on drive {d['Letter']}"

    def test_drive_type_name_matches_drive_type(self):
        result = wdm._enumerate_logical_drives()
        mapping = {2: "removable", 3: "local", 4: "network"}
        for d in result:
            assert d["DriveTypeName"] == mapping[d["DriveType"]]

    def test_no_cdrom_or_ramdisk_present(self):
        result = wdm._enumerate_logical_drives()
        for d in result:
            assert d["DriveType"] not in (5, 6), f"Drive {d['Letter']} should have been filtered"

    def test_system_drive_c_is_local(self):
        result = wdm._enumerate_logical_drives()
        c_drive = next((d for d in result if d["Letter"] == "C"), None)
        assert c_drive is not None, "C: drive should always be present"
        assert c_drive["DriveType"] == 3
        assert c_drive["DriveTypeName"] == "local"
        assert c_drive["TotalGB"] > 0
        assert c_drive["UNCPath"] is None

    def test_network_drives_have_unc_path(self):
        result = wdm._enumerate_logical_drives()
        for d in result:
            if d["DriveType"] == 4:
                assert d["UNCPath"] is not None, f"Network drive {d['Letter']} should have UNCPath"
                assert d["UNCPath"].startswith("\\\\"), f"UNCPath {d['UNCPath']} should start with \\\\"

    def test_pctused_matches_used_total(self):
        result = wdm._enumerate_logical_drives()
        for d in result:
            if d["TotalGB"] > 0:
                computed = (d["UsedGB"] / d["TotalGB"]) * 100
                assert abs(computed - d["PctUsed"]) < 5.0, (
                    f"Drive {d['Letter']}: PctUsed={d['PctUsed']} vs computed={computed:.1f}"
                )
