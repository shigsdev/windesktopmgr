"""
tests/test_powershell.py — PowerShell integration tests for WinDesktopMgr.

Strategy
--------
Every subprocess.run call is mocked so tests run on any OS (no Windows
required).  Each test group covers:

  1. Happy path   — realistic PS JSON output parsed correctly
  2. Single-item  — PS returns a JSON object (not array); must be normalised
  3. Empty output  — empty string / whitespace → safe fallback returned
  4. Malformed JSON — garbage output → safe fallback returned (no 500 / raise)
  5. Non-zero returncode — PS signals failure → error propagated or fallback
  6. Timeout / exception — subprocess raises → safe fallback returned
  7. Command content — the PS command string contains required cmdlets / fields
  8. Input sanitisation — user-supplied values injected into PS commands safely
"""

import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

import windesktopmgr as wdm

# ── helpers ────────────────────────────────────────────────────────────────────


def _mock_run(mocker, stdout="[]", returncode=0, stderr="", side_effect=None):
    """Patch subprocess.run and return the mock."""
    m = mocker.patch("windesktopmgr.subprocess.run")
    if side_effect:
        m.side_effect = side_effect
    else:
        m.return_value.stdout = stdout
        m.return_value.returncode = returncode
        m.return_value.stderr = stderr
    return m


# ══════════════════════════════════════════════════════════════════════════════
# get_installed_drivers
# ══════════════════════════════════════════════════════════════════════════════


class TestGetInstalledDrivers:
    SAMPLE = json.dumps(
        [
            {
                "DeviceName": "Intel Graphics",
                "DriverVersion": "31.0.101.5186",
                "DriverDate": "20240101000000.000000+000",
                "DeviceClass": "Display",
                "Manufacturer": "Intel Corporation",
            },
            {
                "DeviceName": "Realtek Audio",
                "DriverVersion": "6.0.9600.1",
                "DriverDate": "20231001000000.000000+000",
                "DeviceClass": "Media",
                "Manufacturer": "Realtek",
            },
        ]
    )

    def test_happy_path_returns_list(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["DeviceName"] == "Intel Graphics"

    def test_single_object_normalised_to_list(self, mocker):
        single = json.dumps(
            {
                "DeviceName": "USB Controller",
                "DriverVersion": "1.0",
                "DriverDate": "",
                "DeviceClass": "USB",
                "Manufacturer": "MS",
            }
        )
        _mock_run(mocker, stdout=single)
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)
        assert len(result) == 1

    def test_empty_output_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_installed_drivers()
        assert result == []

    def test_whitespace_output_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="   \n\t  ")
        result = wdm.get_installed_drivers()
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="not valid json {{")
        result = wdm.get_installed_drivers()
        assert result == []

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=90))
        result = wdm.get_installed_drivers()
        assert result == []

    def test_command_uses_win32_pnpsigneddriver(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_installed_drivers()
        cmd = m.call_args[0][0][-1]
        assert "Win32_PnPSignedDriver" in cmd

    def test_command_selects_required_fields(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_installed_drivers()
        cmd = m.call_args[0][0][-1]
        for field in ("DeviceName", "DriverVersion", "DeviceClass", "Manufacturer"):
            assert field in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_windows_update_drivers
# ══════════════════════════════════════════════════════════════════════════════


class TestGetWindowsUpdateDrivers:
    SAMPLE = json.dumps(
        [
            {
                "Title": "Intel - Display - 31.0.101.5186",
                "Description": "Intel display driver",
                "DriverModel": "Intel UHD Graphics",
                "DriverVersion": "31.0.101.5186",
                "DriverManufacturer": "Intel Corporation",
            },
        ]
    )

    def setup_method(self):
        wdm._dell_cache = None

    def test_happy_path_returns_dict(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_windows_update_drivers()
        assert isinstance(result, dict)
        assert len(result) == 1

    def test_result_is_cached(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_windows_update_drivers()
        wdm.get_windows_update_drivers()
        assert m.call_count == 1  # second call hits cache

    def test_empty_output_returns_empty_dict(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_windows_update_drivers()
        assert result == {}

    def test_malformed_json_returns_none(self, mocker):
        _mock_run(mocker, stdout="<html>error page</html>")
        result = wdm.get_windows_update_drivers()
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=60))
        result = wdm.get_windows_update_drivers()
        assert result is None

    def test_command_searches_for_drivers(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_windows_update_drivers()
        cmd = m.call_args[0][0][-1]
        assert "Driver" in cmd

    def test_single_object_normalised(self, mocker):
        single = json.dumps(
            {
                "Title": "Dell - BIOS - 2.3.1",
                "Description": "",
                "DriverModel": "",
                "DriverVersion": "2.3.1",
                "DriverManufacturer": "Dell",
            }
        )
        _mock_run(mocker, stdout=single)
        result = wdm.get_windows_update_drivers()
        assert len(result) == 1


# ══════════════════════════════════════════════════════════════════════════════
# get_disk_health
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDiskHealth:
    DRIVES = [
        {"Letter": "C", "Label": "Windows", "UsedGB": 250.5, "FreeGB": 450.2, "TotalGB": 700.7, "PctUsed": 35.8},
    ]
    PHYSICAL = [
        {
            "Name": "Samsung SSD 990 Pro",
            "MediaType": "SSD",
            "SizeGB": 931.5,
            "Health": "Healthy",
            "Status": "OK",
            "BusType": "NVMe",
        },
    ]
    IO = [
        {"Counter": r"\\.\PhysicalDisk(0)\Disk Read Bytes/sec", "Value": 1024.5},
    ]

    def _make_mock(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        main_out = json.dumps({"drives": self.DRIVES, "physical": self.PHYSICAL})
        io_out = json.dumps(self.IO)
        m.side_effect = [
            type("R", (), {"stdout": main_out, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": io_out, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_happy_path_returns_all_keys(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        assert "drives" in result
        assert "physical" in result
        assert "io" in result

    def test_drive_fields_present(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        drive = result["drives"][0]
        assert drive["Letter"] == "C"
        assert drive["PctUsed"] == 35.8

    def test_physical_disk_health_present(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        assert result["physical"][0]["Health"] == "Healthy"

    def test_single_drive_object_normalised(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        main_out = json.dumps({"drives": self.DRIVES[0], "physical": self.PHYSICAL[0]})
        m.side_effect = [
            type("R", (), {"stdout": main_out, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_disk_health()
        assert isinstance(result["drives"], list)
        assert isinstance(result["physical"], list)

    def test_empty_main_output_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_disk_health()
        assert result == {"drives": [], "physical": [], "io": []}

    def test_malformed_json_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "INVALID{", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_disk_health()
        assert result == {"drives": [], "physical": [], "io": []}

    def test_timeout_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=30)
        result = wdm.get_disk_health()
        assert result == {"drives": [], "physical": [], "io": []}

    def test_io_failure_does_not_break_main_result(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        main_out = json.dumps({"drives": self.DRIVES, "physical": self.PHYSICAL})
        m.side_effect = [
            type("R", (), {"stdout": main_out, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "BAD JSON", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_disk_health()
        assert len(result["drives"]) == 1
        assert result["io"] == []

    def test_command_uses_getpsdrive(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-PSDrive" in cmd

    def test_command_uses_get_physicaldisk(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-PhysicalDisk" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_network_data
# ══════════════════════════════════════════════════════════════════════════════


class TestGetNetworkData:
    CONNS = json.dumps(
        [
            {
                "LocalAddress": "192.168.1.100",
                "LocalPort": 54321,
                "RemoteAddress": "142.250.80.46",
                "RemotePort": 443,
                "State": "Established",
                "PID": 1234,
                "Process": "chrome",
            },
            {
                "LocalAddress": "0.0.0.0",
                "LocalPort": 445,
                "RemoteAddress": "0.0.0.0",
                "RemotePort": 0,
                "State": "Listen",
                "PID": 4,
                "Process": "System",
            },
        ]
    )
    ADAPTERS = json.dumps(
        [
            {"Name": "Ethernet", "SentMB": 1024.5, "ReceivedMB": 4096.2, "Status": "Up", "LinkSpeedMb": 1000},
        ]
    )

    def _make_mock(self, mocker, conns=None, adapters=None):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": conns or self.CONNS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": adapters or self.ADAPTERS, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_happy_path_keys(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_network_data()
        for key in ("established", "listening", "adapters", "top_processes", "total_connections", "total_listening"):
            assert key in result

    def test_connection_state_split(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_network_data()
        assert result["total_connections"] == 1
        assert result["total_listening"] == 1

    def test_top_processes_built(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_network_data()
        assert result["top_processes"][0]["process"] == "chrome"
        assert result["top_processes"][0]["connections"] == 1

    def test_empty_connections_returns_zeros(self, mocker):
        self._make_mock(mocker, conns="[]")
        result = wdm.get_network_data()
        assert result["total_connections"] == 0
        assert result["total_listening"] == 0

    def test_single_connection_object_normalised(self, mocker):
        single = json.dumps(
            {
                "LocalAddress": "127.0.0.1",
                "LocalPort": 5000,
                "RemoteAddress": "0.0.0.0",
                "RemotePort": 0,
                "State": "Listen",
                "PID": 99,
                "Process": "flask",
            }
        )
        self._make_mock(mocker, conns=single)
        result = wdm.get_network_data()
        assert result["total_listening"] == 1

    def test_malformed_connections_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "NOT JSON", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_network_data()
        assert result["total_connections"] == 0

    def test_timeout_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=20)
        result = wdm.get_network_data()
        assert result["established"] == []

    def test_conns_command_uses_get_nettcpconnection(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_network_data()
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-NetTCPConnection" in cmd

    def test_adapters_command_uses_get_netadapterstatistics(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_network_data()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Get-NetAdapterStatistics" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_update_history
# ══════════════════════════════════════════════════════════════════════════════


class TestGetUpdateHistory:
    SAMPLE = json.dumps(
        [
            {
                "Title": "2024-12 Cumulative Update for Windows 11 (KB5048667)",
                "Date": "2024-12-10T03:00:00+00:00",
                "ResultCode": 2,
                "Categories": "Security Updates",
                "KB": "KB5048667",
            },
            {
                "Title": "Intel - Display - 31.0.101.5186",
                "Date": "2024-11-20T10:00:00+00:00",
                "ResultCode": 4,
                "Categories": "Drivers",
                "KB": "",
            },
        ]
    )

    def test_happy_path_returns_list(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_update_history()
        assert isinstance(result, list)
        assert len(result) == 2

    def test_failed_updates_flagged(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_update_history()
        failed = [u for u in result if u.get("ResultCode") == 4]
        assert len(failed) == 1

    def test_empty_output_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_update_history()
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="<Error/>")
        result = wdm.get_update_history()
        assert result == []

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=60))
        result = wdm.get_update_history()
        assert result == []

    def test_command_uses_update_session(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_update_history()
        cmd = m.call_args[0][0][-1]
        assert "Microsoft.Update.Session" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_process_list
# ══════════════════════════════════════════════════════════════════════════════


class TestGetProcessList:
    SAMPLE = json.dumps(
        [
            {
                "PID": 1234,
                "Name": "chrome",
                "CPU": 12.5,
                "MemMB": 512.0,
                "Threads": 30,
                "Handles": 400,
                "Path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "Description": "Google Chrome",
                "CmdLine": "chrome.exe --headless",
            },
            {
                "PID": 4,
                "Name": "System",
                "CPU": 0.1,
                "MemMB": 8.0,
                "Threads": 200,
                "Handles": 10000,
                "Path": "",
                "Description": "",
                "CmdLine": "",
            },
        ]
    )

    def test_happy_path_returns_structure(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_process_list()
        assert "processes" in result
        assert "total" in result
        assert "total_mem_mb" in result
        assert result["total"] == 2

    def test_total_mem_summed(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_process_list()
        assert result["total_mem_mb"] == pytest.approx(520.0, abs=1)

    def test_empty_output_returns_fallback(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_process_list()
        assert result["processes"] == []
        assert result["total"] == 0

    def test_malformed_json_returns_fallback(self, mocker):
        _mock_run(mocker, stdout="{bad}")
        result = wdm.get_process_list()
        assert result["processes"] == []

    def test_timeout_returns_fallback(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=45))
        result = wdm.get_process_list()
        assert result["total"] == 0

    def test_command_uses_get_process(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_process_list()
        cmd = m.call_args[0][0][-1]
        assert "Get-Process" in cmd

    def test_command_uses_win32_process_for_paths(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_process_list()
        cmd = m.call_args[0][0][-1]
        assert "Win32_Process" in cmd

    def test_flagged_list_only_contains_flagged(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_process_list()
        for p in result["flagged"]:
            assert p["flag"] in ("warning", "critical")


# ══════════════════════════════════════════════════════════════════════════════
# kill_process — input sanitisation
# ══════════════════════════════════════════════════════════════════════════════


class TestKillProcess:
    def test_success_returns_ok_true(self, mocker):
        _mock_run(mocker, stdout="", returncode=0)
        result = wdm.kill_process(1234)
        assert result["ok"] is True

    def test_failure_returns_ok_false_with_error(self, mocker):
        _mock_run(mocker, stdout="", returncode=1, stderr="Access is denied")
        result = wdm.kill_process(1234)
        assert result["ok"] is False
        assert "Access is denied" in result["error"]

    def test_timeout_returns_ok_false(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10))
        result = wdm.kill_process(1234)
        assert result["ok"] is False

    def test_pid_is_integer_cast_in_command(self, mocker):
        m = _mock_run(mocker, stdout="", returncode=0)
        wdm.kill_process(9999)
        cmd = m.call_args[0][0][-1]
        assert "9999" in cmd
        assert "Stop-Process" in cmd

    def test_non_integer_pid_does_not_inject_arbitrary_code(self, mocker):
        """int() cast must prevent shell injection via PID."""
        m = _mock_run(mocker, stdout="", returncode=0)
        # Passing a float — should be cast cleanly to int
        wdm.kill_process(1234.9)
        cmd = m.call_args[0][0][-1]
        assert "1234" in cmd
        assert "." not in cmd.split("-Id")[1].split()[0]


# ══════════════════════════════════════════════════════════════════════════════
# get_thermals
# ══════════════════════════════════════════════════════════════════════════════


class TestGetThermals:
    TEMPS = json.dumps(
        [
            {"Name": "CPU Package", "TempC": 55.2, "Source": "LibreHardwareMonitor"},
            {"Name": "GPU Core", "TempC": 48.0, "Source": "LibreHardwareMonitor"},
        ]
    )
    PERF = json.dumps({"CPUPct": 12.5, "MemUsedMB": 16384, "MemTotalMB": 32768, "Battery": None})
    FANS = json.dumps([])

    def _make_mock(self, mocker, temps=None, perf=None, fans=None):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": temps or self.TEMPS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": perf or self.PERF, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": fans or self.FANS, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_happy_path_keys(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_thermals()
        for key in ("temps", "perf", "fans", "has_rich"):
            assert key in result

    def test_temp_status_annotated(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_thermals()
        for t in result["temps"]:
            assert "status" in t
            assert t["status"] in ("ok", "warning", "critical")

    def test_critical_temp_flagged(self, mocker):
        hot = json.dumps([{"Name": "CPU Package", "TempC": 95.0, "Source": "LibreHardwareMonitor"}])
        self._make_mock(mocker, temps=hot)
        result = wdm.get_thermals()
        assert result["temps"][0]["status"] == "critical"

    def test_warning_temp_flagged(self, mocker):
        warm = json.dumps([{"Name": "CPU Package", "TempC": 85.0, "Source": "LibreHardwareMonitor"}])
        self._make_mock(mocker, temps=warm)
        result = wdm.get_thermals()
        assert result["temps"][0]["status"] == "warning"

    def test_has_rich_true_when_lhm_source(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_thermals()
        assert result["has_rich"] is True

    def test_has_rich_false_when_only_wmi(self, mocker):
        wmi_temps = json.dumps([{"Name": "ACPI zone", "TempC": 40.0, "Source": "WMI_ThermalZone"}])
        self._make_mock(mocker, temps=wmi_temps)
        result = wdm.get_thermals()
        assert result["has_rich"] is False

    def test_empty_temps_output_returns_fallback(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=20)
        result = wdm.get_thermals()
        assert result["temps"] == []

    def test_temps_command_uses_wmi_thermalzone(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_thermals()
        cmd = m.call_args_list[0][0][0][-1]
        assert "MSAcpi_ThermalZoneTemperature" in cmd

    def test_perf_command_uses_win32_processor(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_thermals()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Win32_Processor" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_services_list
# ══════════════════════════════════════════════════════════════════════════════


class TestGetServicesList:
    SAMPLE = json.dumps(
        [
            {
                "Name": "wuauserv",
                "DisplayName": "Windows Update",
                "Status": "Running",
                "StartMode": "Auto",
                "ProcessId": 1234,
                "Description": "Enables Windows Update",
                "PathName": r"C:\Windows\system32\svchost.exe",
            },
            {
                "Name": "diagtrack",
                "DisplayName": "Connected User Experiences",
                "Status": "Running",
                "StartMode": "Auto",
                "ProcessId": 5678,
                "Description": "Telemetry",
                "PathName": r"C:\Windows\system32\svchost.exe",
            },
        ]
    )

    def test_happy_path_returns_list(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_services_list()
        assert isinstance(result, list)
        assert len(result) == 2

    def test_info_field_attached(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_services_list()
        for s in result:
            assert "info" in s

    def test_empty_output_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_services_list()
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="error text")
        result = wdm.get_services_list()
        assert result == []

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30))
        result = wdm.get_services_list()
        assert result == []

    def test_single_service_object_normalised(self, mocker):
        single = json.dumps(
            {
                "Name": "wuauserv",
                "DisplayName": "Windows Update",
                "Status": "Running",
                "StartMode": "Auto",
                "ProcessId": 1,
                "Description": "",
                "PathName": "",
            }
        )
        _mock_run(mocker, stdout=single)
        result = wdm.get_services_list()
        assert isinstance(result, list)
        assert len(result) == 1

    def test_command_uses_win32_service(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_services_list()
        cmd = m.call_args[0][0][-1]
        assert "Win32_Service" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# toggle_service — input sanitisation
# ══════════════════════════════════════════════════════════════════════════════


class TestToggleService:
    def test_stop_action_calls_stop_service(self, mocker):
        m = _mock_run(mocker, returncode=0)
        result = wdm.toggle_service("wuauserv", "stop")
        assert result["ok"] is True
        cmd = m.call_args[0][0][-1]
        assert "Stop-Service" in cmd

    def test_start_action_calls_start_service(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv", "start")
        cmd = m.call_args[0][0][-1]
        assert "Start-Service" in cmd

    def test_disable_action_calls_set_service_disabled(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv", "disable")
        cmd = m.call_args[0][0][-1]
        assert "Set-Service" in cmd
        assert "Disabled" in cmd

    def test_enable_action_calls_set_service_manual(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv", "enable")
        cmd = m.call_args[0][0][-1]
        assert "Set-Service" in cmd
        assert "Manual" in cmd

    def test_invalid_action_returns_error_no_subprocess(self, mocker):
        m = _mock_run(mocker, returncode=0)
        result = wdm.toggle_service("wuauserv", "explode")
        assert result["ok"] is False
        assert "Invalid" in result["error"]
        m.assert_not_called()

    def test_service_name_sanitised(self, mocker):
        m = _mock_run(mocker, returncode=0)
        # Attempt to inject via semicolons, spaces, and backslashes — those are stripped.
        # re.sub(r"[^\w\-]", "", name) keeps only word chars and hyphens.
        wdm.toggle_service("wuauserv; bad\\path", "stop")
        cmd = m.call_args[0][0][-1]
        # Semicolons, spaces, and backslashes must be stripped from the injected name
        injected_name = cmd.split('"')[1]  # value between the first pair of quotes
        assert ";" not in injected_name
        assert " " not in injected_name
        assert "\\" not in injected_name

    def test_ps_failure_returns_ok_false(self, mocker):
        _mock_run(mocker, returncode=1, stderr="Service not found")
        result = wdm.toggle_service("nosuchsvc", "stop")
        assert result["ok"] is False
        assert "Service not found" in result["error"]

    def test_timeout_returns_ok_false(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=15))
        result = wdm.toggle_service("wuauserv", "stop")
        assert result["ok"] is False

    def test_backtick_stripped_from_service_name(self, mocker):
        """Backtick is PowerShell's escape char — must be stripped."""
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv`Stop-Service -Name windefend", "stop")
        cmd = m.call_args[0][0][-1]
        assert "`" not in cmd.split('"')[1]

    def test_newline_stripped_from_service_name(self, mocker):
        """Newlines are PS statement separators — must be stripped."""
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv\nStop-Service -Name windefend", "stop")
        cmd = m.call_args[0][0][-1]
        assert "\n" not in cmd.split('"')[1]

    def test_dollar_stripped_from_service_name(self, mocker):
        """Dollar sign is PS variable prefix — must be stripped."""
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_service("wuauserv$env:USERNAME", "stop")
        cmd = m.call_args[0][0][-1]
        assert "$" not in cmd.split('"')[1]


# ══════════════════════════════════════════════════════════════════════════════
# toggle_startup_item — input sanitisation
# ══════════════════════════════════════════════════════════════════════════════


class TestToggleStartupItem:
    def test_backtick_stripped(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_startup_item("MyApp`; malicious", "task", True)
        cmd = m.call_args[0][0][-1]
        assert "`" not in cmd
        assert ";" not in cmd

    def test_newline_stripped(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_startup_item("MyApp\nRemove-Item C:\\", "task", False)
        cmd = m.call_args[0][0][-1]
        assert "\n" not in cmd

    def test_spaces_preserved_in_startup_name(self, mocker):
        """Startup items can have spaces in their names."""
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_startup_item("My Cool App", "task", True)
        cmd = m.call_args[0][0][-1]
        assert "My Cool App" in cmd

    def test_registry_toggle_uses_correct_hive(self, mocker):
        m = _mock_run(mocker, returncode=0)
        wdm.toggle_startup_item("TestApp", "registry_hkcu", False)
        cmd = m.call_args[0][0][-1]
        assert "HKCU:" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_memory_analysis
# ══════════════════════════════════════════════════════════════════════════════


class TestGetMemoryAnalysis:
    PROCS = json.dumps(
        [
            {"ProcessName": "chrome", "MemMB": 1024.0},
            {"ProcessName": "msmpeng", "MemMB": 180.0},
            {"ProcessName": "mfemms", "MemMB": 350.0},
        ]
    )
    SYSINFO = json.dumps({"TotalMB": 32768, "FreeMB": 16000})

    def _make_mock(self, mocker, procs=None, sysinfo=None):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": procs or self.PROCS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": sysinfo or self.SYSINFO, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_happy_path_keys(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_memory_analysis()
        for key in (
            "total_mb",
            "used_mb",
            "free_mb",
            "categories",
            "top_procs",
            "mcafee_mb",
            "defender_mb",
            "has_mcafee",
        ):
            assert key in result

    def test_totals_calculated(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_memory_analysis()
        assert result["total_mb"] == 32768
        assert result["free_mb"] == 16000
        assert result["used_mb"] == 32768 - 16000

    def test_mcafee_detected(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_memory_analysis()
        assert result["has_mcafee"] is True
        assert result["mcafee_mb"] > 0

    def test_top_procs_sorted_by_mem_descending(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_memory_analysis()
        mems = [p["mem"] for p in result["top_procs"]]
        assert mems == sorted(mems, reverse=True)

    def test_empty_process_output_returns_empty_dict(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=20)
        result = wdm.get_memory_analysis()
        assert result == {}

    def test_malformed_json_returns_empty_dict(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "NOT JSON", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_memory_analysis()
        assert result == {}

    def test_procs_command_uses_get_process(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_memory_analysis()
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-Process" in cmd

    def test_sysinfo_command_uses_win32_operatingsystem(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_memory_analysis()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Win32_OperatingSystem" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_current_bios
# ══════════════════════════════════════════════════════════════════════════════


class TestGetCurrentBios:
    SAMPLE = json.dumps(
        {
            "BIOSVersion": "2.3.1",
            "ReleaseDate": "20240106000000.000000+000",
            "Manufacturer": "Dell Inc.",
            "BoardProduct": "XPS 8960",
            "BoardMfr": "Dell Inc.",
        }
    )

    def test_happy_path_returns_data(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_current_bios()
        assert result["BIOSVersion"] == "2.3.1"
        assert result["Manufacturer"] == "Dell Inc."

    def test_bios_date_formatted(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_current_bios()
        assert "BIOSDateFormatted" in result
        assert "2024" in result["BIOSDateFormatted"]

    def test_empty_output_returns_empty_dict(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_current_bios()
        # Empty PS output → json.loads("{}") → {} + BIOSDateFormatted added
        # No real BIOS fields should be present
        assert "BIOSVersion" not in result
        assert "Manufacturer" not in result

    def test_malformed_json_returns_empty_dict(self, mocker):
        _mock_run(mocker, stdout="<bios/>")
        result = wdm.get_current_bios()
        assert result == {}

    def test_timeout_returns_empty_dict(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10))
        result = wdm.get_current_bios()
        assert result == {}

    def test_command_uses_win32_bios(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_current_bios()
        cmd = m.call_args[0][0][-1]
        assert "Win32_BIOS" in cmd

    def test_command_includes_baseboard(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm.get_current_bios()
        cmd = m.call_args[0][0][-1]
        assert "Win32_BaseBoard" in cmd

    def test_missing_release_date_handled_gracefully(self, mocker):
        no_date = json.dumps(
            {
                "BIOSVersion": "2.3.1",
                "ReleaseDate": "",
                "Manufacturer": "Dell Inc.",
                "BoardProduct": "XPS 8960",
                "BoardMfr": "Dell Inc.",
            }
        )
        _mock_run(mocker, stdout=no_date)
        result = wdm.get_current_bios()
        assert result["BIOSDateFormatted"] == ""


# ══════════════════════════════════════════════════════════════════════════════
# get_system_timeline
# ══════════════════════════════════════════════════════════════════════════════


class TestGetSystemTimeline:
    # All timestamps within 30-day window — use relative dates so tests don't rot
    _NOW = datetime.now(timezone.utc)
    _BSOD1 = (_NOW - timedelta(days=20)).isoformat()
    _BSOD2 = (_NOW - timedelta(days=15)).isoformat()
    _UPDATE = (_NOW - timedelta(days=18)).isoformat()

    BSOD_EVTS = json.dumps(
        [
            {
                "EventId": 41,
                "TimeCreated": _BSOD1,
                "Message": "The system has rebooted without cleanly shutting down first.",
            },
            {
                "EventId": 1001,
                "TimeCreated": _BSOD2,
                "Message": "Problem signature: stop code 0x0000009F",
            },
        ]
    )
    UPDATE_EVTS = json.dumps(
        [
            {"Title": "2026-03 Cumulative Update (KB5055523)", "Date": _UPDATE, "KB": "KB5055523"},
        ]
    )
    EMPTY = json.dumps([])

    def _make_mock(self, mocker, bsod=None, upd=None, svc=None, boot=None, cred=None):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": bsod or self.BSOD_EVTS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": upd or self.UPDATE_EVTS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": svc or self.EMPTY, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": boot or self.EMPTY, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": cred or self.EMPTY, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_returns_list(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        assert isinstance(result, list)

    def test_bsod_events_included(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        bsods = [e for e in result if e["type"] == "bsod"]
        assert len(bsods) == 2

    def test_update_events_included(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        updates = [e for e in result if e["type"] == "update"]
        assert len(updates) == 1

    def test_bsod_stop_code_extracted(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        bsod_with_code = [e for e in result if e["type"] == "bsod" and "0x" in e.get("detail", "")]
        assert len(bsod_with_code) == 1

    def test_all_events_have_required_fields(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        for event in result:
            for field in ("ts", "type", "category", "title", "severity", "icon"):
                assert field in event, f"Missing field '{field}' in event: {event}"

    def test_events_sorted_most_recent_first(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_system_timeline()
        timestamps = [e["ts"] for e in result]
        # Timeline is sorted reverse=True — most recent event first
        assert timestamps == sorted(timestamps, reverse=True)

    def test_events_outside_window_excluded(self, mocker):
        old_event = json.dumps(
            [
                {"EventId": 41, "TimeCreated": "2025-01-01T00:00:00+00:00", "Message": "Old crash"},
            ]
        )
        self._make_mock(mocker, bsod=old_event)
        result = wdm.get_system_timeline()
        bsods = [e for e in result if e["type"] == "bsod"]
        assert len(bsods) == 0

    def test_all_sources_empty_returns_empty_list(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_system_timeline()
        assert result == []

    def test_ps_error_on_one_source_does_not_crash(self, mocker):
        """If the BSOD query fails, we still get update events."""
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "GARBAGE", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": self.UPDATE_EVTS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_system_timeline()
        updates = [e for e in result if e["type"] == "update"]
        assert len(updates) == 1

    def test_bsod_command_queries_event_ids_41_1001_6008(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[0][0][0][-1]
        assert "41" in cmd
        assert "1001" in cmd
        assert "6008" in cmd

    def test_update_command_uses_update_session(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Microsoft.Update.Session" in cmd

    def test_service_command_queries_event_id_7036(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[2][0][0][-1]
        assert "7036" in cmd

    def test_boot_command_queries_event_id_6013(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[3][0][0][-1]
        assert "6013" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_bsod_events (raw Event Log query)
# ══════════════════════════════════════════════════════════════════════════════


class TestGetBsodEvents:
    SAMPLE = json.dumps(
        [
            {
                "Id": 1001,
                "TimeCreated": "2026-03-10T08:00:00",
                "Message": "Problem signature: stop code HYPERVISOR_ERROR intelppm.sys",
            },
            {
                "Id": 41,
                "TimeCreated": "2026-03-10T07:59:00",
                "Message": "The system has rebooted without cleanly shutting down first.",
            },
        ]
    )

    def test_happy_path_returns_list(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_bsod_events()
        assert isinstance(result, list)

    def test_happy_path_returns_correct_count(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_bsod_events()
        assert len(result) == 2

    def test_happy_path_has_expected_fields(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.get_bsod_events()
        for item in result:
            assert "Id" in item or "EventId" in item
            assert "TimeCreated" in item
            assert "Message" in item

    def test_command_queries_correct_event_ids(self, mocker):
        m = _mock_run(mocker, stdout="[]")
        wdm.get_bsod_events()
        ps_cmd = m.call_args[0][0][-1]
        assert "1001" in ps_cmd
        assert "41" in ps_cmd
        assert "6008" in ps_cmd

    def test_single_object_normalized_to_list(self, mocker):
        single = json.dumps({"Id": 1001, "TimeCreated": "2026-03-10T08:00:00", "Message": "crash"})
        _mock_run(mocker, stdout=single)
        result = wdm.get_bsod_events()
        assert isinstance(result, list)
        assert len(result) == 1

    def test_empty_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.get_bsod_events()
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="<bad/>")
        result = wdm.get_bsod_events()
        assert result == []

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30))
        result = wdm.get_bsod_events()
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# get_startup_items — PowerShell registry + scheduler calls
# ══════════════════════════════════════════════════════════════════════════════


class TestGetStartupItems:
    REG_ITEMS = json.dumps(
        [
            {
                "Name": "OneDrive",
                "Command": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
                "Location": "HKCU\\...\\Run",
                "Type": "registry_run",
            },
        ]
    )
    TASK_ITEMS = json.dumps(
        [
            {
                "Name": "MicrosoftEdgeAutoLaunch",
                "Command": r"C:\Program Files\Edge\msedge.exe --auto-launch",
                "Location": "Task Scheduler",
                "Type": "scheduled_task",
            },
        ]
    )

    def _make_mock(self, mocker, reg=None, tasks=None):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": reg or self.REG_ITEMS, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": tasks or self.TASK_ITEMS, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_returns_list(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_startup_items()
        assert isinstance(result, list)

    def test_items_have_required_fields(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_startup_items()
        # PS outputs PascalCase keys: Name, Command, Location, Type
        for item in result:
            for field in ("Name", "Command", "Location", "Type"):
                assert field in item

    def test_empty_output_returns_empty_list(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_startup_items()
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "bad json", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm.get_startup_items()
        assert isinstance(result, list)

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30))
        result = wdm.get_startup_items()
        assert result == []

    def test_nonzero_returncode_handled(self, mocker):
        _mock_run(mocker, stdout="[]", returncode=1, stderr="error")
        result = wdm.get_startup_items()
        assert isinstance(result, list)

    def test_command_queries_registry_run_keys(self, mocker):
        m = _mock_run(mocker, stdout="[]")
        wdm.get_startup_items()
        ps_cmd = m.call_args[0][0][-1]
        assert "CurrentVersion\\Run" in ps_cmd or "Get-ScheduledTask" in ps_cmd

    def test_single_object_normalized(self, mocker):
        single = json.dumps(
            {"Name": "OneDrive", "Command": "onedrive.exe", "Location": "HKCU Run", "Type": "registry_hkcu"}
        )
        _mock_run(mocker, stdout=single)
        result = wdm.get_startup_items()
        assert isinstance(result, list)
        assert len(result) == 1


# ══════════════════════════════════════════════════════════════════════════════
# query_event_log — PowerShell event log queries
# ══════════════════════════════════════════════════════════════════════════════


class TestQueryEventLog:
    SAMPLE = json.dumps(
        [
            {
                "Time": "2026-03-10T08:00:00",
                "Id": 7036,
                "Level": "Information",
                "Source": "Service Control Manager",
                "Message": "The Windows Update service entered the stopped state.",
            },
            {
                "Time": "2026-03-10T07:55:00",
                "Id": 1001,
                "Level": "Error",
                "Source": "Microsoft-Windows-WER-SystemErrorReporting",
                "Message": "The computer has rebooted from a bugcheck.",
            },
        ]
    )

    def test_happy_path_returns_list(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm.query_event_log({"log": "System"})
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["Id"] == 7036

    def test_empty_output_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm.query_event_log({"log": "System"})
        assert result == []

    def test_malformed_json_returns_empty_list(self, mocker):
        _mock_run(mocker, stdout="not json at all!!!")
        result = wdm.query_event_log({"log": "System"})
        assert result == []

    def test_timeout_returns_empty_list(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30))
        result = wdm.query_event_log({"log": "System"})
        assert result == []

    def test_nonzero_returncode_handled(self, mocker):
        _mock_run(mocker, stdout="[]", returncode=1, stderr="access denied")
        result = wdm.query_event_log({"log": "System"})
        assert isinstance(result, list)

    def test_command_uses_get_winevent(self, mocker):
        m = _mock_run(mocker, stdout="[]")
        wdm.query_event_log({"log": "System"})
        ps_cmd = m.call_args[0][0][-1]
        assert "Get-WinEvent" in ps_cmd

    def test_input_sanitization(self, mocker):
        m = _mock_run(mocker, stdout="[]")
        wdm.query_event_log({"log": '"; rm -rf /'})
        ps_cmd = m.call_args[0][0][-1]
        # Semicolons and quotes should be stripped by re.sub(r"[^\w\s\-/]", "", log)
        assert '";' not in ps_cmd
        assert "rm -rf" in ps_cmd  # letters/spaces survive, but dangerous chars don't

    def test_single_object_normalized(self, mocker):
        single = json.dumps(
            {"Time": "2026-03-10T08:00:00", "Id": 7036, "Level": "Information", "Source": "SCM", "Message": "test"}
        )
        _mock_run(mocker, stdout=single)
        result = wdm.query_event_log({"log": "System"})
        assert isinstance(result, list)
        assert len(result) == 1


# ══════════════════════════════════════════════════════════════════════════════
# get_credentials_network_health — PS command content
# ══════════════════════════════════════════════════════════════════════════════


class TestCredentialsNetworkPSCommands:
    """Verify the PowerShell scripts in get_credentials_network_health."""

    def _capture_ps_commands(self, mocker):
        """Run the function with mocked subprocess and return PS command strings."""
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "{}", "returncode": 0, "stderr": ""})()
        wdm.get_credentials_network_health()
        return [call[0][0][-1] for call in m.call_args_list]

    def _find_smb_script(self, commands):
        """Find the SMB/network shares script (contains PSDrive) regardless of order."""
        for cmd in commands:
            if "PSDrive" in cmd or "$portNum" in cmd:
                return cmd
        return ""

    def test_smb_fallback_defines_portnum(self, mocker):
        """PSDrive fallback block must initialise $portNum (was undefined before fix)."""
        commands = self._capture_ps_commands(mocker)
        ps_smb = self._find_smb_script(commands)
        assert ps_smb, "Could not find SMB script among captured PS commands"
        assert "$portNum   = if" in ps_smb or "$portNum = if" in ps_smb

    def test_smb_fallback_has_no_dialect2_typo(self, mocker):
        """PSDrive fallback block must not reference $dialect2 (was a typo)."""
        commands = self._capture_ps_commands(mocker)
        ps_smb = self._find_smb_script(commands)
        assert ps_smb, "Could not find SMB script among captured PS commands"
        assert "$dialect2" not in ps_smb


# ══════════════════════════════════════════════════════════════════════════════
# Worker task_done safety — must not call task_done after queue.Empty
# ══════════════════════════════════════════════════════════════════════════════


class TestWorkerTaskDoneSafety:
    """Verify workers do NOT call task_done() when queue.Empty is raised."""

    def test_startup_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("windesktopmgr._startup_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            wdm._startup_lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_bsod_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("windesktopmgr._bsod_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            wdm._bsod_lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_event_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("windesktopmgr._lookup_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            wdm._lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_process_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("windesktopmgr._process_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            wdm._process_lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_services_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("windesktopmgr._services_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            wdm._services_lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# check_dell_bios_update
# ══════════════════════════════════════════════════════════════════════════════


class TestCheckDellBiosUpdate:
    """Tests for check_dell_bios_update with all subprocess calls mocked."""

    def _mock_run(self, mocker, side_effects):
        """Mock subprocess.run with a list of (stdout, returncode) tuples."""
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [type("R", (), {"stdout": out, "returncode": rc, "stderr": ""})() for out, rc in side_effects]
        return m

    def test_returns_required_keys(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),  # service tag
                ("DCU_NOT_FOUND", 0),  # method 1
                ("", 0),  # method 2 catalog
                ("NO_BIOS_IN_WU", 0),  # method 3 WU
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        for key in (
            "checked_at",
            "current_version",
            "latest_version",
            "update_available",
            "service_tag",
            "source",
            "error",
        ):
            assert key in result

    def test_dcu_found_sets_version(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        dcu_out = json.dumps({"Version": "2.23.0", "Source": "dcu_cli", "Notes": ""})
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),  # service tag
                (dcu_out, 0),  # method 1 DCU
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["latest_version"] == "2.23.0"
        assert result["source"] == "dell_command_update"
        assert result["update_available"] is True

    def test_dcu_same_version_no_update(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        dcu_out = json.dumps({"Version": "2.22.0", "Source": "dcu_cli", "Notes": ""})
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),
                (dcu_out, 0),
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["update_available"] is False

    def test_catalog_fallback(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        catalog_out = json.dumps(
            {
                "Version": "2.23.0",
                "ReleaseDate": "2026-01-15",
                "Name": "XPS 8960 BIOS Update",
                "Path": "https://downloads.dell.com/bios.exe",
            }
        )
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),  # service tag
                ("DCU_NOT_FOUND", 0),  # method 1 no DCU
                (catalog_out, 0),  # method 2 catalog
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "dell_catalog"
        assert result["latest_version"] == "2.23.0"

    def test_wu_fallback(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        wu_out = json.dumps({"Title": "Dell BIOS Update 2.24.0", "Version": "2.24.0"})
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),  # service tag
                ("DCU_NOT_FOUND", 0),  # no DCU
                ("", 0),  # no catalog
                (wu_out, 0),  # WU found
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "windows_update"
        assert result["update_available"] is True

    def test_all_methods_fail_returns_unknown(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        self._mock_run(
            mocker,
            [
                ("9T46D14", 0),
                ("DCU_NOT_FOUND", 0),
                ("", 0),
                ("NO_BIOS_IN_WU", 0),
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "unknown"
        assert result["latest_version"] is None

    def test_service_tag_populated(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        self._mock_run(
            mocker,
            [
                ("ABC1234", 0),
                ("DCU_NOT_FOUND", 0),
                ("", 0),
                ("NO_BIOS_IN_WU", 0),
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["service_tag"] == "ABC1234"
        assert "ABC1234" in result["download_url"]

    def test_service_tag_empty_fallback_url(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        self._mock_run(
            mocker,
            [
                ("", 0),  # empty service tag
                ("DCU_NOT_FOUND", 0),
                ("", 0),
                ("NO_BIOS_IN_WU", 0),
                ("", 0),  # retry service tag also empty
            ],
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert "dell.com" in result["download_url"]

    def test_cache_returns_without_subprocess(self, mocker, tmp_path):
        cache_file = tmp_path / "bios.json"
        cached = {
            "checked_at": wdm.datetime.now(wdm.timezone.utc).isoformat(),
            "current_version": "2.22.0",
            "latest_version": "2.22.0",
            "update_available": False,
            "source": "dell_catalog",
            "service_tag": "9T46D14",
            "download_url": "",
            "error": None,
            "latest_date": None,
            "release_notes": "",
        }
        cache_file.write_text(json.dumps(cached))
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(cache_file))
        m = mocker.patch("windesktopmgr.subprocess.run")
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        m.assert_not_called()
        assert result["source"] == "dell_catalog"

    def test_subprocess_timeout_handled(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired("powershell", 60)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# PowerShell Command Validation Tests — Phase 1: Static command-content gaps
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDiskHealthIOCommand:
    """Command-content tests for the IO sub-command (2nd subprocess call)."""

    def _make_mock(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        main_out = json.dumps({"drives": [], "physical": []})
        m.side_effect = [
            type("R", (), {"stdout": main_out, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_io_command_uses_get_counter(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Get-Counter" in cmd

    def test_io_command_requests_read_and_write_bytes(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        cmd = m.call_args_list[1][0][0][-1]
        assert "Disk Read Bytes/sec" in cmd
        assert "Disk Write Bytes/sec" in cmd


class TestGetThermsFansCommand:
    """Command-content test for fans sub-command (3rd subprocess call)."""

    def _make_mock(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "{}", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_fans_command_uses_win32_fan(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_thermals()
        cmd = m.call_args_list[2][0][0][-1]
        assert "Win32_Fan" in cmd


class TestGetSystemTimelineCredCommand:
    """Command-content tests for credential events query (5th subprocess call)."""

    EMPTY = json.dumps([])

    def _make_mock(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": self.EMPTY, "returncode": 0, "stderr": ""})(),  # bsod
            type("R", (), {"stdout": self.EMPTY, "returncode": 0, "stderr": ""})(),  # updates
            type("R", (), {"stdout": self.EMPTY, "returncode": 0, "stderr": ""})(),  # services
            type("R", (), {"stdout": self.EMPTY, "returncode": 0, "stderr": ""})(),  # boot
            type("R", (), {"stdout": self.EMPTY, "returncode": 0, "stderr": ""})(),  # cred events
        ]
        return m

    def test_cred_command_queries_event_id_4625(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[4][0][0][-1]
        assert "4625" in cmd

    def test_cred_command_queries_security_log(self, mocker):
        m = self._make_mock(mocker)
        wdm.get_system_timeline()
        cmd = m.call_args_list[4][0][0][-1]
        assert "Security" in cmd


class TestCheckDellBiosCommandContent:
    """Command-content tests for the 4 subprocess calls in check_dell_bios_update."""

    def _mock_run(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "9T46D14", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "DCU_NOT_FOUND", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "NO_BIOS_IN_WU", "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_service_tag_command_uses_win32_bios(self, mocker, tmp_path):
        m = self._mock_run(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[0][0][0][-1]
        assert "Win32_BIOS" in cmd or "SerialNumber" in cmd

    def test_dcu_command_references_command_update(self, mocker, tmp_path):
        m = self._mock_run(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[1][0][0][-1]
        assert "dcu-cli" in cmd.lower() or "CommandUpdate" in cmd

    def test_catalog_command_references_dell_downloads(self, mocker, tmp_path):
        m = self._mock_run(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[2][0][0][-1]
        assert "dell.com" in cmd.lower() or "CatalogPC" in cmd

    def test_wu_command_searches_pending_updates(self, mocker, tmp_path):
        m = self._mock_run(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[3][0][0][-1]
        assert "IsInstalled" in cmd or "BIOS" in cmd or "Firmware" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2: fix_fast_startup
# ══════════════════════════════════════════════════════════════════════════════


class TestFixFastStartup:
    def test_disable_returns_ok_true(self, mocker):
        _mock_run(mocker, stdout="OK:disabled")
        result = wdm.fix_fast_startup(False)
        assert result["ok"] is True
        assert result["enabled"] is False

    def test_enable_returns_ok_true(self, mocker):
        _mock_run(mocker, stdout="OK:enabled")
        result = wdm.fix_fast_startup(True)
        assert result["ok"] is True
        assert result["enabled"] is True

    def test_disable_command_sets_value_zero(self, mocker):
        m = _mock_run(mocker, stdout="OK:disabled")
        wdm.fix_fast_startup(False)
        cmd = m.call_args[0][0][-1]
        assert "HiberbootEnabled" in cmd
        assert "-Value 0" in cmd

    def test_enable_command_sets_value_one(self, mocker):
        m = _mock_run(mocker, stdout="OK:enabled")
        wdm.fix_fast_startup(True)
        cmd = m.call_args[0][0][-1]
        assert "HiberbootEnabled" in cmd
        assert "-Value 1" in cmd

    def test_registry_path_correct(self, mocker):
        m = _mock_run(mocker, stdout="OK:disabled")
        wdm.fix_fast_startup(False)
        cmd = m.call_args[0][0][-1]
        assert "Session Manager\\Power" in cmd

    def test_ps_error_returns_ok_false(self, mocker):
        _mock_run(mocker, stdout="ERROR: Access denied")
        result = wdm.fix_fast_startup(False)
        assert result["ok"] is False

    def test_timeout_returns_ok_false(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 10))
        result = wdm.fix_fast_startup(False)
        assert result["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3: Injection-risk functions
# ══════════════════════════════════════════════════════════════════════════════


class TestLookupViaWindowsProvider:
    SAMPLE = json.dumps(
        {
            "Provider": "Microsoft-Windows-Kernel-Power",
            "Id": 41,
            "Description": "The system has rebooted without cleanly shutting down first.",
            "Level": 2,
            "Keywords": "0x8000000000000002",
        }
    )

    def test_happy_path_returns_dict_with_required_keys(self, mocker):
        _mock_run(mocker, stdout=self.SAMPLE)
        result = wdm._lookup_via_windows_provider(41, "Microsoft-Windows-Kernel-Power")
        assert result is not None
        for key in ("source", "title", "detail", "fetched"):
            assert key in result

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_malformed_json_returns_none(self, mocker):
        _mock_run(mocker, stdout="<error/>")
        result = wdm._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 20))
        result = wdm._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_command_contains_event_id(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        wdm._lookup_via_windows_provider(41, "Kernel-Power")
        cmd = m.call_args[0][0][-1]
        assert "41" in cmd

    def test_command_contains_sanitized_source(self, mocker):
        m = _mock_run(mocker, stdout="")
        wdm._lookup_via_windows_provider(41, "Kernel-Power")
        cmd = m.call_args[0][0][-1]
        assert "Kernel-Power" in cmd

    def test_source_injection_semicolons_stripped(self, mocker):
        """safe_source = re.sub(r"[^\\w \\-]", "", source) strips ; and \\ but keeps words."""
        m = _mock_run(mocker, stdout="")
        wdm._lookup_via_windows_provider(41, "Kernel;Drop-DB")
        cmd = m.call_args[0][0][-1]
        # Semicolons and special chars are stripped
        assert ";" not in cmd
        # Letters survive sanitization
        assert "Kernel" in cmd

    def test_empty_description_returns_none(self, mocker):
        no_desc = json.dumps({"Provider": "SomeProvider", "Id": 41, "Description": "", "Level": 2, "Keywords": ""})
        _mock_run(mocker, stdout=no_desc)
        result = wdm._lookup_via_windows_provider(41, "SomeProvider")
        assert result is None


class TestLookupStartupViaFileinfo:
    FILE_INFO = json.dumps(
        {
            "FileDescription": "Microsoft OneDrive",
            "CompanyName": "Microsoft Corporation",
            "ProductName": "Microsoft OneDrive",
            "FileVersion": "25.001.0112.0001",
            "FileName": "OneDrive.exe",
        }
    )

    def test_happy_path_returns_enrichment(self, mocker):
        _mock_run(mocker, stdout=self.FILE_INFO)
        result = wdm._lookup_startup_via_fileinfo(
            r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', "OneDrive"
        )
        assert result is not None
        assert result["publisher"] == "Microsoft Corporation"

    def test_exe_path_injected_into_get_item(self, mocker):
        m = _mock_run(mocker, stdout=self.FILE_INFO)
        wdm._lookup_startup_via_fileinfo(r'"C:\Windows\system32\notepad.exe"', "Notepad")
        cmd = m.call_args[0][0][-1]
        assert "Get-Item" in cmd
        assert "notepad.exe" in cmd.lower()

    def test_no_exe_path_triggers_get_command(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm._lookup_startup_via_fileinfo("somename", "somename")
        assert result is None
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-Command" in cmd

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm._lookup_startup_via_fileinfo(r'"C:\Program Files\App\app.exe"', "App")
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 10))
        result = wdm._lookup_startup_via_fileinfo(r'"C:\Program Files\App\app.exe"', "App")
        assert result is None

    def test_empty_desc_and_company_returns_none(self, mocker):
        empty = json.dumps(
            {"FileDescription": "", "CompanyName": "", "ProductName": "", "FileVersion": "1.0", "FileName": "x.exe"}
        )
        _mock_run(mocker, stdout=empty)
        result = wdm._lookup_startup_via_fileinfo(r'"C:\app.exe"', "App")
        assert result is None


class TestLookupProcessViaFileinfo:
    FILE_INFO = json.dumps(
        {
            "FileDescription": "Google Chrome",
            "CompanyName": "Google LLC",
            "ProductName": "Google Chrome",
            "FileVersion": "120.0.6099.130",
        }
    )

    def test_happy_path_returns_enrichment(self, mocker):
        _mock_run(mocker, stdout=self.FILE_INFO)
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result is not None
        assert result["publisher"] == "Google LLC"

    def test_no_path_triggers_get_command(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
        ]
        result = wdm._lookup_process_via_fileinfo("unknownapp", "")
        assert result is None
        cmd = m.call_args_list[0][0][0][-1]
        assert "Get-Command" in cmd
        # Must use PS 5.1-compatible syntax -- no ?. null-conditional operator
        assert "?." not in cmd

    def test_empty_proc_name_skips_get_command(self, mocker):
        """Guard against the '.exe' query that produced warnings in prod."""
        m = mocker.patch("windesktopmgr.subprocess.run")
        result = wdm._lookup_process_via_fileinfo("", "")
        assert result is None
        assert m.call_count == 0  # should never hit PS with an empty base name

    def test_get_item_command_contains_path(self, mocker):
        m = _mock_run(mocker, stdout=self.FILE_INFO)
        wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        cmd = m.call_args[0][0][-1]
        assert "Get-Item" in cmd
        assert "chrome.exe" in cmd

    def test_system_path_marks_safe_kill_false(self, mocker):
        sys_info = json.dumps(
            {
                "FileDescription": "Windows Explorer",
                "CompanyName": "Microsoft Corporation",
                "ProductName": "Microsoft Windows",
                "FileVersion": "10.0.26100.1",
            }
        )
        _mock_run(mocker, stdout=sys_info)
        result = wdm._lookup_process_via_fileinfo("explorer", r"C:\Windows\explorer.exe")
        assert result is not None
        assert result["safe_kill"] is False

    def test_non_system_path_marks_safe_kill_true(self, mocker):
        _mock_run(mocker, stdout=self.FILE_INFO)
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result["safe_kill"] is True

    def test_empty_desc_and_company_returns_none(self, mocker):
        empty = json.dumps({"FileDescription": "", "CompanyName": "", "ProductName": "", "FileVersion": "1.0"})
        _mock_run(mocker, stdout=empty)
        result = wdm._lookup_process_via_fileinfo("mystery", r"C:\mystery.exe")
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 8))
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Remediation command-content + fallback tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRemediationCommands:
    """Command-content and fallback tests for all 10 _rem_* functions."""

    # ── flush_dns ─────────────────────────────────────────────────────────────

    def test_flush_dns_command_uses_ipconfig(self, mocker):
        m = _mock_run(mocker, stdout="", returncode=0)
        wdm._rem_flush_dns()
        cmd = m.call_args[0][0][-1]
        assert "ipconfig" in cmd
        assert "flushdns" in cmd

    def test_flush_dns_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="", returncode=0)
        assert wdm._rem_flush_dns()["ok"] is True

    def test_flush_dns_fail_on_nonzero(self, mocker):
        _mock_run(mocker, stdout="", returncode=1, stderr="failed")
        assert wdm._rem_flush_dns()["ok"] is False

    def test_flush_dns_timeout(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 15))
        assert wdm._rem_flush_dns()["ok"] is False

    # ── reset_winsock ─────────────────────────────────────────────────────────

    def test_reset_winsock_command_uses_netsh(self, mocker):
        m = _mock_run(mocker, stdout="", returncode=0)
        wdm._rem_reset_winsock()
        cmd = m.call_args[0][0][-1]
        assert "netsh" in cmd
        assert "winsock" in cmd
        assert "reset" in cmd

    def test_reset_winsock_timeout(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 30))
        assert wdm._rem_reset_winsock()["ok"] is False

    # ── reset_tcpip ───────────────────────────────────────────────────────────

    def test_reset_tcpip_command_uses_netsh_tcp(self, mocker):
        m = _mock_run(mocker, stdout="", returncode=0)
        wdm._rem_reset_tcpip()
        cmd = m.call_args[0][0][-1]
        assert "netsh" in cmd
        assert "tcp" in cmd

    def test_reset_tcpip_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="", returncode=0)
        assert wdm._rem_reset_tcpip()["ok"] is True

    # ── clear_temp ────────────────────────────────────────────────────────────

    def test_clear_temp_command_uses_remove_item(self, mocker):
        m = _mock_run(mocker, stdout="Removed:5 Errors:0", returncode=0)
        wdm._rem_clear_temp()
        cmd = m.call_args[0][0][-1]
        assert "Remove-Item" in cmd

    def test_clear_temp_parses_removed_count(self, mocker):
        _mock_run(mocker, stdout="Removed:42 Errors:3", returncode=0)
        result = wdm._rem_clear_temp()
        assert result["ok"] is True
        assert "42" in result["message"]

    def test_clear_temp_timeout(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 120))
        assert wdm._rem_clear_temp()["ok"] is False

    # ── repair_image ──────────────────────────────────────────────────────────

    def test_repair_image_command_uses_dism_and_sfc(self, mocker):
        m = _mock_run(mocker, stdout="DISM_DONE SFC_DONE OK:True", returncode=0)
        wdm._rem_repair_image()
        cmd = m.call_args[0][0][-1]
        assert "dism" in cmd.lower()
        assert "sfc" in cmd.lower()

    def test_repair_image_ok_true_on_success(self, mocker):
        _mock_run(mocker, stdout="DISM_DONE SFC_DONE OK:True", returncode=0)
        assert wdm._rem_repair_image()["ok"] is True

    def test_repair_image_ok_false_on_failure(self, mocker):
        _mock_run(mocker, stdout="DISM_DONE SFC_DONE OK:False", returncode=0)
        assert wdm._rem_repair_image()["ok"] is False

    # ── clear_wu_cache ────────────────────────────────────────────────────────

    def test_clear_wu_cache_command_stops_wuauserv(self, mocker):
        m = _mock_run(mocker, stdout="OK", returncode=0)
        wdm._rem_clear_wu_cache()
        cmd = m.call_args[0][0][-1]
        assert "Stop-Service" in cmd
        assert "wuauserv" in cmd

    def test_clear_wu_cache_command_clears_softwaredistribution(self, mocker):
        m = _mock_run(mocker, stdout="OK", returncode=0)
        wdm._rem_clear_wu_cache()
        cmd = m.call_args[0][0][-1]
        assert "SoftwareDistribution" in cmd

    def test_clear_wu_cache_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="OK", returncode=0)
        assert wdm._rem_clear_wu_cache()["ok"] is True

    def test_clear_wu_cache_error_string_returns_ok_false(self, mocker):
        _mock_run(mocker, stdout="ERROR: service not found", returncode=0)
        assert wdm._rem_clear_wu_cache()["ok"] is False

    # ── restart_spooler ───────────────────────────────────────────────────────

    def test_restart_spooler_command_stops_and_starts(self, mocker):
        m = _mock_run(mocker, stdout="OK", returncode=0)
        wdm._rem_restart_spooler()
        cmd = m.call_args[0][0][-1]
        assert "Stop-Service" in cmd
        assert "Start-Service" in cmd
        assert "Spooler" in cmd

    def test_restart_spooler_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="OK", returncode=0)
        assert wdm._rem_restart_spooler()["ok"] is True

    # ── reset_network_adapter ─────────────────────────────────────────────────

    def test_reset_adapter_command_uses_netadapter(self, mocker):
        m = _mock_run(mocker, stdout="RESET:2", returncode=0)
        wdm._rem_reset_network_adapter()
        cmd = m.call_args[0][0][-1]
        assert "Get-NetAdapter" in cmd
        assert "Disable-NetAdapter" in cmd
        assert "Enable-NetAdapter" in cmd

    def test_reset_adapter_parses_count(self, mocker):
        _mock_run(mocker, stdout="RESET:3", returncode=0)
        result = wdm._rem_reset_network_adapter()
        assert result["ok"] is True
        assert "3" in result["message"]

    def test_reset_adapter_zero_count_returns_ok_false(self, mocker):
        _mock_run(mocker, stdout="RESET:0", returncode=0)
        assert wdm._rem_reset_network_adapter()["ok"] is False

    # ── clear_icon_cache ──────────────────────────────────────────────────────

    def test_clear_icon_cache_command_stops_explorer(self, mocker):
        m = _mock_run(mocker, stdout="OK", returncode=0)
        wdm._rem_clear_icon_cache()
        cmd = m.call_args[0][0][-1]
        assert "explorer" in cmd.lower()
        assert "IconCache" in cmd

    def test_clear_icon_cache_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="OK", returncode=0)
        assert wdm._rem_clear_icon_cache()["ok"] is True

    # ── reboot_system ─────────────────────────────────────────────────────────

    def test_reboot_command_uses_shutdown(self, mocker):
        m = _mock_run(mocker, stdout="", returncode=0)
        wdm._rem_reboot_system()
        cmd = m.call_args[0][0][-1]
        assert "shutdown" in cmd
        assert "/r" in cmd

    def test_reboot_ok_on_success(self, mocker):
        _mock_run(mocker, stdout="", returncode=0)
        assert wdm._rem_reboot_system()["ok"] is True

    def test_reboot_fail_on_nonzero(self, mocker):
        _mock_run(mocker, stdout="", returncode=1, stderr="permission denied")
        assert wdm._rem_reboot_system()["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: Warranty data command-content tests
# ══════════════════════════════════════════════════════════════════════════════


class TestWarrantyDataCommands:
    CPU_OUT = json.dumps(
        {
            "CPUName": "Intel(R) Core(TM) i9-14900K",
            "ProcessorId": "BFEBFBFF000B0671",
            "SerialNumber": "N/A",
            "DellServiceTag": "9T46D14",
            "BIOSVersion": "2.23.0",
            "BIOSDate": "2024-01-06",
            "Manufacturer": "Dell Inc.",
            "Model": "XPS 8960",
        }
    )
    MCU_OUT = "0x010001B4"
    COUNTS_OUT = json.dumps({"BSODs30Days": 2, "WHEAErrors": 0, "UnexpectedShutdowns": 1})

    def _make_mock(self, mocker):
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": self.CPU_OUT, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": self.MCU_OUT, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": self.COUNTS_OUT, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_cpu_command_uses_win32_processor(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[0][0][0][-1]
        assert "Win32_Processor" in cmd

    def test_cpu_command_collects_bios_info(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[0][0][0][-1]
        assert "Win32_BIOS" in cmd
        assert "Win32_ComputerSystem" in cmd

    def test_microcode_command_reads_registry(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[1][0][0][-1]
        assert "CentralProcessor" in cmd
        assert "Update Revision" in cmd

    def test_counts_command_queries_whea_logger(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[2][0][0][-1]
        assert "WHEA-Logger" in cmd

    def test_counts_command_queries_kernel_power_41(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[2][0][0][-1]
        assert "41" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_driver_health — driver age + NVIDIA update check
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDriverHealth:
    """Tests for get_driver_health() — PS checks old drivers + problematic devices,
    then calls get_nvidia_update_info() from Python for NVIDIA data."""

    SAMPLE = json.dumps(
        {
            "OldDrivers": [
                {"DeviceName": "Realtek Audio", "Provider": "Realtek", "Version": "6.0.1.1", "Date": "2022-03-15"},
            ],
            "Problematic": [
                {"DeviceName": "Unknown Device", "ErrorCode": 28, "Status": "Error"},
            ],
        }
    )

    def _mock_deps(self, mocker, ps_stdout=None, nvidia_result=None):
        """Mock both the PS subprocess and get_nvidia_update_info."""
        m = _mock_run(mocker, stdout=ps_stdout if ps_stdout is not None else self.SAMPLE)
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=nvidia_result)
        return m

    def test_happy_path_returns_all_keys(self, mocker):
        self._mock_deps(mocker)
        result = wdm.get_driver_health()
        assert "old_drivers" in result
        assert "problematic_drivers" in result
        assert "nvidia" in result

    def test_old_drivers_parsed(self, mocker):
        self._mock_deps(mocker)
        result = wdm.get_driver_health()
        assert len(result["old_drivers"]) == 1
        assert result["old_drivers"][0]["DeviceName"] == "Realtek Audio"

    def test_problematic_drivers_parsed(self, mocker):
        self._mock_deps(mocker)
        result = wdm.get_driver_health()
        assert len(result["problematic_drivers"]) == 1
        assert result["problematic_drivers"][0]["ErrorCode"] == 28

    def test_nvidia_update_from_python_call(self, mocker):
        nv = {
            "Name": "NVIDIA GeForce RTX 4060 Ti",
            "InstalledVersion": "591.74",
            "LatestVersion": "595.79",
            "UpdateAvailable": True,
            "UpdateSource": "nvidia_api",
        }
        self._mock_deps(mocker, nvidia_result=nv)
        result = wdm.get_driver_health()
        assert result["nvidia"] is not None
        assert result["nvidia"]["UpdateAvailable"] is True
        assert result["nvidia"]["LatestVersion"] == "595.79"

    def test_no_nvidia_gpu_returns_none(self, mocker):
        self._mock_deps(mocker, nvidia_result=None)
        result = wdm.get_driver_health()
        assert result["nvidia"] is None

    def test_empty_output_returns_safe_defaults(self, mocker):
        self._mock_deps(mocker, ps_stdout="")
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []
        assert result["problematic_drivers"] == []

    def test_timeout_returns_safe_defaults(self, mocker):
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired("powershell", 30),
        )
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []
        assert result["problematic_drivers"] == []

    def test_single_old_driver_normalised_to_list(self, mocker):
        single = json.dumps(
            {
                "OldDrivers": {"DeviceName": "Solo", "Provider": "X", "Version": "1.0", "Date": "2022-01-01"},
                "Problematic": [],
            }
        )
        self._mock_deps(mocker, ps_stdout=single)
        result = wdm.get_driver_health()
        assert isinstance(result["old_drivers"], list)
        assert len(result["old_drivers"]) == 1

    def test_command_queries_driver_date_cutoff(self, mocker):
        m = self._mock_deps(mocker, ps_stdout="{}")
        wdm.get_driver_health()
        cmd = m.call_args[0][0][-1]
        assert "AddYears(-2)" in cmd

    def test_command_queries_configmanager_errors(self, mocker):
        m = self._mock_deps(mocker, ps_stdout="{}")
        wdm.get_driver_health()
        cmd = m.call_args[0][0][-1]
        assert "ConfigManagerErrorCode" in cmd

    def test_command_does_not_contain_nvidia_code(self, mocker):
        """PS script should NOT contain NVIDIA/Installer2/WU code — that's in Python now."""
        m = self._mock_deps(mocker, ps_stdout="{}")
        wdm.get_driver_health()
        cmd = m.call_args[0][0][-1]
        assert "nvidia-smi" not in cmd
        assert "Installer2" not in cmd
        assert "Microsoft.Update.Session" not in cmd


class TestGetNvidiaGpuInfo:
    """Tests for _get_nvidia_gpu_info() — nvidia-smi + WMI fallback for GPU detection."""

    SMI_OUTPUT = json.dumps({"Name": "NVIDIA GeForce RTX 4060 Ti", "Installed": "591.74", "WinVer": "32.0.15.9174"})

    def test_happy_path_returns_gpu_dict(self, mocker):
        _mock_run(mocker, stdout=self.SMI_OUTPUT)
        result = wdm._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"
        assert result["installed"] == "591.74"
        assert result["win_ver"] == "32.0.15.9174"

    def test_no_gpu_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_malformed_json_returns_none(self, mocker):
        _mock_run(mocker, stdout="not json")
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 15))
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_command_uses_nvidia_smi(self, mocker):
        m = _mock_run(mocker, stdout="")
        wdm._get_nvidia_gpu_info()
        cmd = m.call_args[0][0][-1]
        assert "nvidia-smi" in cmd

    def test_command_has_wmi_fallback(self, mocker):
        m = _mock_run(mocker, stdout="")
        wdm._get_nvidia_gpu_info()
        cmd = m.call_args[0][0][-1]
        assert "Win32_VideoController" in cmd


class TestDetectNvidiaDriverBranch:
    """Tests for _detect_nvidia_driver_branch() — detects Studio vs Game Ready."""

    def test_studio_detected_from_shim(self, mocker, tmp_path):
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"IsCRD": True, "NVDriver.Version": 59579}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert wdm._detect_nvidia_driver_branch() is True

    def test_game_ready_detected_from_shim(self, mocker, tmp_path):
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"IsCRD": False}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert wdm._detect_nvidia_driver_branch() is False

    def test_missing_shim_defaults_to_studio(self, mocker):
        mocker.patch("glob.glob", return_value=[])
        assert wdm._detect_nvidia_driver_branch() is True


class TestQueryNvidiaApi:
    """Tests for _query_nvidia_api() — HTTP call to NVIDIA's AjaxDriverService."""

    GOOD_RESPONSE = json.dumps(
        {
            "Success": "1",
            "IDS": [
                {
                    "downloadInfo": {
                        "Success": "1",
                        "Version": "595.79",
                        "DetailsURL": "https%3A%2F%2Fnvidia.com%2Fdl",
                        "ReleaseDateTime": "2026-03-30",
                        "Name": "NVIDIA+Studio+Driver",
                    }
                }
            ],
        }
    ).encode()

    def test_happy_path_returns_version(self, mocker):
        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = self.GOOD_RESPONSE
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("urllib.request.urlopen", return_value=mock_resp)
        result = wdm._query_nvidia_api(1022, studio=True)
        assert result is not None
        assert result["version"] == "595.79"

    def test_api_failure_returns_none(self, mocker):
        mocker.patch("urllib.request.urlopen", side_effect=Exception("timeout"))
        result = wdm._query_nvidia_api(1022, studio=True)
        assert result is None

    def test_bad_success_flag_returns_none(self, mocker):
        bad = json.dumps({"Success": "0", "IDS": []}).encode()
        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = bad
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("urllib.request.urlopen", return_value=mock_resp)
        result = wdm._query_nvidia_api(1022, studio=True)
        assert result is None

    def test_studio_and_game_ready_both_callable(self, mocker):
        """Both studio=True and studio=False should work without errors."""
        mocker.patch("urllib.request.urlopen", side_effect=Exception("skip"))
        # Both calls should handle the exception gracefully and return None
        assert wdm._query_nvidia_api(1022, studio=True) is None
        assert wdm._query_nvidia_api(1022, studio=False) is None


class TestWinToNvidiaVersion:
    """Tests for _win_to_nvidia_version() — Windows→NVIDIA version conversion."""

    def test_standard_conversion(self):
        assert wdm._win_to_nvidia_version("32.0.15.9174") == "591.74"

    def test_another_version(self):
        assert wdm._win_to_nvidia_version("32.0.15.9579") == "595.79"

    def test_older_version(self):
        assert wdm._win_to_nvidia_version("31.0.15.6579") == "565.79"

    def test_short_version_passthrough(self):
        assert wdm._win_to_nvidia_version("1.0") == "1.0"

    def test_three_digit_part3(self):
        # e.g. 32.0.16.5770 → "165770" → drop first → "65770" → "657.70"
        assert wdm._win_to_nvidia_version("32.0.16.5770") == "657.70"


class TestGetNvidiaUpdateInfo:
    """Tests for get_nvidia_update_info() — Python-based 3-tier detection:
    _get_nvidia_gpu_info() → _query_nvidia_api() → Installer2 Cache PS fallback."""

    GPU_INFO = {"name": "NVIDIA GeForce RTX 4060 Ti", "installed": "591.74", "win_ver": "32.0.15.9174"}
    API_RESULT = {
        "version": "595.79",
        "url": "https://nvidia.com/dl/595.79",
        "date": "2026-03-30",
        "name": "Studio Driver",
    }

    def _mock_gpu(self, mocker, gpu=None):
        """Mock _get_nvidia_gpu_info — returns GPU dict or None."""
        if gpu is None:
            gpu = self.GPU_INFO
        mocker.patch("windesktopmgr._detect_nvidia_driver_branch", return_value=True)
        return mocker.patch("windesktopmgr._get_nvidia_gpu_info", return_value=gpu)

    def _mock_api(self, mocker, result=None):
        """Mock _query_nvidia_api — returns API result dict or None."""
        return mocker.patch("windesktopmgr._query_nvidia_api", return_value=result)

    def test_happy_path_api_update_available(self, mocker):
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=self.API_RESULT)
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is True
        assert result["LatestVersion"] == "595.79"
        assert result["InstalledVersion"] == "591.74"
        assert result["UpdateSource"] == "nvidia_api"
        assert "RTX 4060" in result["Name"]

    def test_no_nvidia_gpu_returns_none(self, mocker):
        mocker.patch("windesktopmgr._get_nvidia_gpu_info", return_value=None)
        mocker.patch("windesktopmgr._detect_nvidia_driver_branch", return_value=True)
        result = wdm.get_nvidia_update_info()
        assert result is None

    def test_driver_current_via_api(self, mocker):
        """API returns same version as installed → no update, but source is still nvidia_api."""
        gpu = {"name": "NVIDIA GeForce RTX 4060 Ti", "installed": "595.79", "win_ver": "32.0.15.9579"}
        self._mock_gpu(mocker, gpu=gpu)
        self._mock_api(mocker, result={"version": "595.79", "url": "", "date": "", "name": ""})
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["UpdateSource"] == "nvidia_api"

    def test_api_failure_falls_back_to_installer2_cache(self, mocker):
        """When API fails, check Installer2 Cache via PS."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Mock the Installer2 Cache PS call
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = "595.79\n"
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is True
        assert result["LatestVersion"] == "595.79"
        assert result["UpdateSource"] == "installer2_cache"

    def test_api_failure_no_cache_returns_no_update(self, mocker):
        """When API fails and no Installer2 Cache → no update available."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = ""
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["UpdateSource"] == "none"

    def test_unknown_gpu_skips_api_tries_cache(self, mocker):
        """GPU not in pfid map → skip API, try Installer2 only."""
        gpu = {"name": "NVIDIA GeForce GTX 1660", "installed": "560.00", "win_ver": "31.0.15.6000"}
        self._mock_gpu(mocker, gpu=gpu)
        api_mock = self._mock_api(mocker)
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = ""
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        # API should NOT be called since pfid is not in the map
        api_mock.assert_not_called()

    def test_studio_api_failure_does_not_fall_back_to_game_ready(self, mocker):
        """Studio driver API fails → must NOT fall back to Game Ready.
        Game Ready 595.97 is NOT a valid update for Studio 595.79 user."""
        self._mock_gpu(mocker)
        api_mock = mocker.patch("windesktopmgr._query_nvidia_api", return_value=None)
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value.stdout = ""
        m.return_value.returncode = 0
        m.return_value.stderr = ""
        result = wdm.get_nvidia_update_info()
        # API should be called exactly ONCE (Studio only), not twice
        api_mock.assert_called_once()
        # No update from API — falls through to Installer2 Cache
        assert result["UpdateSource"] == "none"
        assert result["UpdateAvailable"] is False

    def test_installer2_cache_timeout_still_returns_result(self, mocker):
        """Installer2 PS timeout → graceful fallback, still returns GPU info."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=10),
        )
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["InstalledVersion"] == "591.74"

    def test_result_contains_all_expected_keys(self, mocker):
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=self.API_RESULT)
        result = wdm.get_nvidia_update_info()
        for key in ("Name", "InstalledVersion", "WindowsVersion", "LatestVersion", "UpdateAvailable", "UpdateSource"):
            assert key in result
