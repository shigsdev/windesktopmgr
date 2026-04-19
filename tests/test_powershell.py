"""
tests/test_powershell.py — PowerShell + psutil integration tests.

Strategy
--------
Every subprocess.run call is mocked so tests run on any OS (no Windows
required). After backlog #24 batch A, several hot-path functions use
``psutil`` instead of PowerShell — those test classes mock
``windesktopmgr.psutil.<fn>`` returning ``types.SimpleNamespace`` objects
shaped like the psutil named-tuples. Everything else still uses the
subprocess.run mock pattern below.

Each PS test group covers:

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
import os
import subprocess
import types
from datetime import datetime, timedelta, timezone

import pytest

import disk
import remediation
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


def _wmi_obj(**kwargs):
    """Create a simple namespace that mimics a WMI object with attribute access."""
    return types.SimpleNamespace(**kwargs)


def _mock_wmi(mocker, classes=None):
    """Patch windesktopmgr.wmi.WMI() to return a fake WMI connection.

    ``classes`` is a dict mapping WMI class names (e.g. 'Win32_BIOS') to
    lists of _wmi_obj instances.  The returned mock's class-method calls
    (``conn.Win32_BIOS()``) return the corresponding lists.

    Returns the mock connection object so tests can further customise it.
    """
    classes = classes or {}
    mock_conn = mocker.MagicMock()

    for name, data in classes.items():
        setattr(mock_conn, name, mocker.MagicMock(return_value=data))

    mocker.patch("windesktopmgr.wmi.WMI", return_value=mock_conn)
    return mock_conn


def _mock_rem_run(mocker, stdout="", returncode=0, stderr="", side_effect=None):
    """Patch remediation.subprocess.run — used by TestRemediationCommands since the
    remediation action handlers moved to remediation.py (backlog #22)."""
    m = mocker.patch("remediation.subprocess.run")
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
    """Tests for get_installed_drivers() — now uses wmi.WMI().Win32_PnPSignedDriver()."""

    SAMPLE_DRIVERS = [
        _wmi_obj(
            DeviceName="Intel Graphics",
            DriverVersion="31.0.101.5186",
            DriverDate="20240101000000.000000+000",
            DeviceClass="Display",
            Manufacturer="Intel Corporation",
        ),
        _wmi_obj(
            DeviceName="Realtek Audio",
            DriverVersion="6.0.9600.1",
            DriverDate="20231001000000.000000+000",
            DeviceClass="Media",
            Manufacturer="Realtek",
        ),
    ]

    def test_happy_path_returns_list(self, mocker):
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": self.SAMPLE_DRIVERS})
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["DeviceName"] == "Intel Graphics"

    def test_single_driver_returns_list(self, mocker):
        single = [
            _wmi_obj(
                DeviceName="USB Controller",
                DriverVersion="1.0",
                DriverDate="",
                DeviceClass="USB",
                Manufacturer="MS",
            )
        ]
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": single})
        result = wdm.get_installed_drivers()
        assert isinstance(result, list)
        assert len(result) == 1

    def test_empty_wmi_returns_empty_list(self, mocker):
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": []})
        result = wdm.get_installed_drivers()
        assert result == []

    def test_drivers_without_name_filtered(self, mocker):
        drivers = [
            _wmi_obj(
                DeviceName=None,
                DriverVersion="1.0",
                DriverDate="",
                DeviceClass="",
                Manufacturer="",
            )
        ]
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": drivers})
        result = wdm.get_installed_drivers()
        assert result == []

    def test_drivers_without_version_filtered(self, mocker):
        drivers = [
            _wmi_obj(
                DeviceName="Test Device",
                DriverVersion=None,
                DriverDate="",
                DeviceClass="",
                Manufacturer="",
            )
        ]
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": drivers})
        result = wdm.get_installed_drivers()
        assert result == []

    def test_wmi_exception_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("COM error"))
        result = wdm.get_installed_drivers()
        assert result == []

    def test_output_fields_match_contract(self, mocker):
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": self.SAMPLE_DRIVERS})
        result = wdm.get_installed_drivers()
        for field in ("DeviceName", "DriverVersion", "DriverDate", "DeviceClass", "Manufacturer"):
            assert field in result[0]

    def test_none_fields_default_to_empty_string(self, mocker):
        drivers = [
            _wmi_obj(
                DeviceName="Test",
                DriverVersion="1.0",
                DriverDate=None,
                DeviceClass=None,
                Manufacturer=None,
            )
        ]
        _mock_wmi(mocker, {"Win32_PnPSignedDriver": drivers})
        result = wdm.get_installed_drivers()
        assert result[0]["DriverDate"] == ""
        assert result[0]["DeviceClass"] == ""
        assert result[0]["Manufacturer"] == ""


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

    def test_timeout_returns_empty_dict(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=120))
        result = wdm.get_windows_update_drivers()
        assert result == {}

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
    """get_disk_health() orchestrator — drives come from Python, physical+io from PS.

    The drives list is produced by ``_enumerate_logical_drives()`` (psutil +
    ctypes) — that function has its own test class below. Here we only care
    that get_disk_health() stitches the Python and PowerShell halves together
    correctly, and that the PS half (Get-PhysicalDisk + Get-Counter) handles
    the usual failure modes.
    """

    DRIVES = [
        {
            "Letter": "C",
            "Label": "Windows",
            "UsedGB": 250.5,
            "FreeGB": 450.2,
            "TotalGB": 700.7,
            "PctUsed": 35.8,
            "DriveType": 3,
            "DriveTypeName": "local",
            "FileSystem": "NTFS",
            "UNCPath": None,
        },
        {
            "Letter": "Q",
            "Label": "",
            "UsedGB": 1800.0,
            "FreeGB": 200.0,
            "TotalGB": 2000.0,
            "PctUsed": 90.0,
            "DriveType": 4,
            "DriveTypeName": "network",
            "FileSystem": "NTFS",
            "UNCPath": r"\\nas\photos",
        },
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
        """Mock _enumerate_logical_drives + subprocess.run (physical PS)
        + disk.psutil.disk_io_counters (batch A). Returns the subprocess
        mock so tests can inspect call_args if needed."""
        mocker.patch("disk._enumerate_logical_drives", return_value=self.DRIVES)
        m = mocker.patch("windesktopmgr.subprocess.run")
        phys_out = json.dumps(self.PHYSICAL)
        m.return_value = type("R", (), {"stdout": phys_out, "returncode": 0, "stderr": ""})()
        # IO now uses psutil; return empty so the io list is deterministic.
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        mocker.patch("disk.time.sleep", return_value=None)
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

    def test_drive_type_fields_present(self, mocker):
        """Local drives report DriveType=3 / DriveTypeName='local' with no UNCPath."""
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        local = next(d for d in result["drives"] if d["Letter"] == "C")
        assert local["DriveType"] == 3
        assert local["DriveTypeName"] == "local"
        assert local["FileSystem"] == "NTFS"
        assert local["UNCPath"] is None

    def test_network_drive_classified_and_has_unc(self, mocker):
        """CIFS mapped drives report DriveType=4 / DriveTypeName='network' with UNC path."""
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        network = next(d for d in result["drives"] if d["Letter"] == "Q")
        assert network["DriveType"] == 4
        assert network["DriveTypeName"] == "network"
        assert network["UNCPath"] == r"\\nas\photos"

    def test_physical_disk_health_present(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_disk_health()
        assert result["physical"][0]["Health"] == "Healthy"

    def test_single_physical_object_normalised(self, mocker):
        """Single physical disk comes back as a dict from PS — normalise to list."""
        mocker.patch("disk._enumerate_logical_drives", return_value=[])
        m = mocker.patch("windesktopmgr.subprocess.run")
        phys_out = json.dumps(self.PHYSICAL[0])
        m.return_value = type("R", (), {"stdout": phys_out, "returncode": 0, "stderr": ""})()
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        assert isinstance(result["physical"], list)
        assert len(result["physical"]) == 1

    def test_empty_physical_output_returns_fallback(self, mocker):
        mocker.patch("disk._enumerate_logical_drives", return_value=[])
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})()
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        assert result == {"drives": [], "physical": [], "io": []}

    def test_malformed_physical_json_falls_back(self, mocker):
        """Garbage from Get-PhysicalDisk must not take down the whole endpoint."""
        mocker.patch("disk._enumerate_logical_drives", return_value=self.DRIVES)
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "INVALID{", "returncode": 0, "stderr": ""})()
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        # Drives still populated from Python, physical falls back to empty
        assert len(result["drives"]) == len(self.DRIVES)
        assert result["physical"] == []

    def test_physical_timeout_returns_fallback(self, mocker):
        mocker.patch("disk._enumerate_logical_drives", return_value=self.DRIVES)
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=60),
        )
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        assert result["physical"] == []
        assert result["io"] == []
        # Drives still come through — they don't depend on subprocess
        assert len(result["drives"]) == len(self.DRIVES)

    def test_io_failure_does_not_break_main_result(self, mocker):
        mocker.patch("disk._enumerate_logical_drives", return_value=self.DRIVES)
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": json.dumps(self.PHYSICAL), "returncode": 0, "stderr": ""})()
        mocker.patch("disk.psutil.disk_io_counters", side_effect=RuntimeError("boom"))
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        assert len(result["drives"]) == len(self.DRIVES)
        assert len(result["physical"]) == len(self.PHYSICAL)
        assert result["io"] == []

    def test_command_does_not_use_getpsdrive(self, mocker):
        """Regression guard: never fall back to Get-PSDrive for logical drives.

        Get-PSDrive doesn't expose DriveType, so network-mapped drives show up
        indistinguishable from local disks, triggering false "disk full" alerts.
        The logical-drive enumeration now lives in pure Python (psutil+ctypes).
        """
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        for call in m.call_args_list:
            cmd = call[0][0][-1]
            assert "Get-PSDrive" not in cmd
            assert "Win32_LogicalDisk" not in cmd

    def test_command_uses_get_physicaldisk(self, mocker):
        """Physical disks (Health/MediaType/BusType) still need Get-PhysicalDisk —
        psutil doesn't wrap the Windows Storage Management API."""
        m = self._make_mock(mocker)
        wdm.get_disk_health()
        phys_cmd = m.call_args_list[0][0][0][-1]
        assert "Get-PhysicalDisk" in phys_cmd

    def test_io_populated_from_psutil_samples(self, mocker):
        """Two psutil samples ~1 s apart → rate in KB/s per disk, both read + write."""
        import types

        mocker.patch("disk._enumerate_logical_drives", return_value=[])
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})()
        # Two samples: 1 MB read + 512 KB write delta on disk 0.
        first = {"PhysicalDrive0": types.SimpleNamespace(read_bytes=0, write_bytes=0)}
        second = {"PhysicalDrive0": types.SimpleNamespace(read_bytes=1024 * 1024, write_bytes=512 * 1024)}
        io_mock = mocker.patch("disk.psutil.disk_io_counters", side_effect=[first, second])
        sleep_mock = mocker.patch("disk.time.sleep")
        result = wdm.get_disk_health()
        assert io_mock.call_count == 2
        sleep_mock.assert_called_once_with(1.0)
        counters = {entry["Counter"]: entry["Value"] for entry in result["io"]}
        read_key = r"\physicaldisk(PhysicalDrive0)\disk read bytes/sec"
        write_key = r"\physicaldisk(PhysicalDrive0)\disk write bytes/sec"
        assert read_key in counters
        assert write_key in counters
        # 1 MB / 1 KB = 1024 KB/s; 512 KB / 1 KB = 512 KB/s.
        assert counters[read_key] == pytest.approx(1024.0, abs=1)
        assert counters[write_key] == pytest.approx(512.0, abs=1)


# ══════════════════════════════════════════════════════════════════════════════
# _enumerate_logical_drives — pure Python replacement for Get-PSDrive
# ══════════════════════════════════════════════════════════════════════════════


class TestEnumerateLogicalDrives:
    """Mocks psutil.disk_partitions, psutil.disk_usage, and _get_unc_path
    so tests run anywhere (no real disks required)."""

    def _part(self, device, fstype="NTFS", opts="rw,fixed"):
        return type("Part", (), {"device": device, "mountpoint": device, "fstype": fstype, "opts": opts})()

    def _usage(self, total_gb, pct_used):
        total = int(total_gb * (1024**3))
        used = int(total * pct_used / 100)
        free = total - used
        return type("Usage", (), {"total": total, "used": used, "free": free, "percent": pct_used})()

    def test_local_drive_classified(self, mocker):
        mocker.patch("disk.psutil.disk_partitions", return_value=[self._part("C:\\")])
        mocker.patch("disk.psutil.disk_usage", return_value=self._usage(500, 40))
        mocker.patch("disk._get_unc_path", return_value=None)
        mocker.patch("disk._get_volume_label", return_value="Windows")
        drives = disk._enumerate_logical_drives()
        assert len(drives) == 1
        assert drives[0]["Letter"] == "C"
        assert drives[0]["DriveType"] == 3
        assert drives[0]["DriveTypeName"] == "local"
        assert drives[0]["UNCPath"] is None
        assert drives[0]["Label"] == "Windows"

    def test_network_drive_classified_with_unc(self, mocker):
        mocker.patch(
            "disk.psutil.disk_partitions",
            return_value=[self._part("Q:\\", opts="rw,remote")],
        )
        mocker.patch("disk.psutil.disk_usage", return_value=self._usage(2000, 90))
        mocker.patch("disk._get_unc_path", return_value=r"\\nas\photos")
        drives = disk._enumerate_logical_drives()
        assert drives[0]["DriveType"] == 4
        assert drives[0]["DriveTypeName"] == "network"
        assert drives[0]["UNCPath"] == r"\\nas\photos"
        # Network drives don't populate Label (avoids blocking on NAS lookup)
        assert drives[0]["Label"] == ""

    def test_removable_drive_classified(self, mocker):
        mocker.patch(
            "disk.psutil.disk_partitions",
            return_value=[self._part("E:\\", opts="rw,removable")],
        )
        mocker.patch("disk.psutil.disk_usage", return_value=self._usage(32, 20))
        mocker.patch("disk._get_unc_path", return_value=None)
        mocker.patch("disk._get_volume_label", return_value="")
        drives = disk._enumerate_logical_drives()
        assert drives[0]["DriveType"] == 2
        assert drives[0]["DriveTypeName"] == "removable"

    def test_cdrom_drives_filtered_out(self, mocker):
        mocker.patch(
            "disk.psutil.disk_partitions",
            return_value=[
                self._part("C:\\"),
                self._part("D:\\", opts="ro,cdrom"),
            ],
        )
        mocker.patch("disk.psutil.disk_usage", return_value=self._usage(500, 40))
        mocker.patch("disk._get_unc_path", return_value=None)
        mocker.patch("disk._get_volume_label", return_value="")
        drives = disk._enumerate_logical_drives()
        assert len(drives) == 1
        assert drives[0]["Letter"] == "C"

    def test_ramdisk_filtered_out(self, mocker):
        mocker.patch(
            "disk.psutil.disk_partitions",
            return_value=[self._part("R:\\", opts="rw,ramdisk")],
        )
        mocker.patch("disk._get_unc_path", return_value=None)
        mocker.patch("disk._get_volume_label", return_value="")
        drives = disk._enumerate_logical_drives()
        assert drives == []

    def test_unreachable_network_drive_returns_zeros(self, mocker):
        """When a mapped drive's NAS is offline, disk_usage raises OSError.
        We should still surface the drive with zeroed totals so the UI
        can show it as a CIFS share instead of hiding it entirely."""
        mocker.patch(
            "disk.psutil.disk_partitions",
            return_value=[self._part("P:\\", opts="rw,remote")],
        )
        mocker.patch("disk.psutil.disk_usage", side_effect=OSError("not reachable"))
        mocker.patch("disk._get_unc_path", return_value=r"\\nas\offline")
        drives = disk._enumerate_logical_drives()
        assert len(drives) == 1
        assert drives[0]["TotalGB"] == 0.0
        assert drives[0]["UNCPath"] == r"\\nas\offline"

    def test_disk_partitions_failure_returns_empty(self, mocker):
        mocker.patch("disk.psutil.disk_partitions", side_effect=Exception("boom"))
        drives = disk._enumerate_logical_drives()
        assert drives == []

    def test_drive_usage_rounding(self, mocker):
        """UsedGB + FreeGB should approximately equal TotalGB within rounding."""
        mocker.patch("disk.psutil.disk_partitions", return_value=[self._part("C:\\")])
        mocker.patch("disk.psutil.disk_usage", return_value=self._usage(931.5, 35.8))
        mocker.patch("disk._get_unc_path", return_value=None)
        mocker.patch("disk._get_volume_label", return_value="Windows")
        drives = disk._enumerate_logical_drives()
        d = drives[0]
        assert d["TotalGB"] == 931.5
        assert abs((d["UsedGB"] + d["FreeGB"]) - d["TotalGB"]) < 0.1


# ══════════════════════════════════════════════════════════════════════════════
# get_network_data
# ══════════════════════════════════════════════════════════════════════════════


def _fake_sconn(laddr_ip="", laddr_port=0, raddr_ip="", raddr_port=0, status="NONE", pid=0):
    """Build a psutil.sconn-style namedtuple for net_connections mocking."""
    import types

    laddr = types.SimpleNamespace(ip=laddr_ip, port=laddr_port) if laddr_ip or laddr_port else None
    raddr = types.SimpleNamespace(ip=raddr_ip, port=raddr_port) if raddr_ip or raddr_port else None
    return types.SimpleNamespace(laddr=laddr, raddr=raddr, status=status, pid=pid)


def _fake_netio(bytes_sent=0, bytes_recv=0):
    import types

    return types.SimpleNamespace(bytes_sent=bytes_sent, bytes_recv=bytes_recv)


def _fake_ifstats(isup=True, speed=1000):
    import types

    return types.SimpleNamespace(isup=isup, speed=speed)


class TestGetNetworkData:
    """Post-PS→psutil tests (backlog #24 batch A). ``get_network_data``
    now uses ``psutil.net_connections`` + ``net_io_counters`` +
    ``net_if_stats`` instead of PowerShell ``Get-NetTCPConnection`` /
    ``Get-NetAdapterStatistics``. Output contract is unchanged."""

    def _patch(self, mocker, conns=None, io_counters=None, if_stats=None, pid_names=None):
        import types

        import psutil as _psutil

        # Use the real psutil status constants so the state-map works.
        default_conns = [
            _fake_sconn(
                laddr_ip="192.168.1.100",
                laddr_port=54321,
                raddr_ip="142.250.80.46",
                raddr_port=443,
                status=_psutil.CONN_ESTABLISHED,
                pid=1234,
            ),
            _fake_sconn(
                laddr_ip="0.0.0.0",
                laddr_port=445,
                status=_psutil.CONN_LISTEN,
                pid=4,
            ),
        ]
        default_io = {"Ethernet": _fake_netio(bytes_sent=1024 * 1024 * 1024, bytes_recv=4096 * 1024 * 1024)}
        default_stats = {"Ethernet": _fake_ifstats(isup=True, speed=1000)}
        default_names = {1234: "chrome", 4: "System"}

        # Build iter-style mocks for process_iter.
        names = pid_names if pid_names is not None else default_names
        procs = [types.SimpleNamespace(info={"pid": p, "name": n}) for p, n in names.items()]
        mocker.patch("windesktopmgr.psutil.process_iter", return_value=iter(procs))
        mocker.patch(
            "windesktopmgr.psutil.net_connections",
            return_value=conns if conns is not None else default_conns,
        )
        mocker.patch(
            "windesktopmgr.psutil.net_io_counters",
            return_value=io_counters if io_counters is not None else default_io,
        )
        mocker.patch(
            "windesktopmgr.psutil.net_if_stats",
            return_value=if_stats if if_stats is not None else default_stats,
        )

    def test_happy_path_keys(self, mocker):
        self._patch(mocker)
        result = wdm.get_network_data()
        for key in ("established", "listening", "adapters", "top_processes", "total_connections", "total_listening"):
            assert key in result

    def test_connection_state_split(self, mocker):
        self._patch(mocker)
        result = wdm.get_network_data()
        assert result["total_connections"] == 1
        assert result["total_listening"] == 1

    def test_top_processes_built(self, mocker):
        self._patch(mocker)
        result = wdm.get_network_data()
        assert result["top_processes"][0]["process"] == "chrome"
        assert result["top_processes"][0]["connections"] == 1

    def test_process_name_resolved_from_pid_map(self, mocker):
        """Connections with a PID must be tagged with the matching process name."""
        self._patch(mocker)
        result = wdm.get_network_data()
        established = result["established"][0]
        assert established["Process"] == "chrome"
        assert established["PID"] == 1234

    def test_unknown_pid_falls_back_to_unknown(self, mocker):
        """If process_iter doesn't surface a PID, tag the conn as Unknown."""
        self._patch(mocker, pid_names={})  # no pid → name map
        result = wdm.get_network_data()
        assert result["established"][0]["Process"] == "Unknown"

    def test_empty_connections_returns_zeros(self, mocker):
        self._patch(mocker, conns=[])
        result = wdm.get_network_data()
        assert result["total_connections"] == 0
        assert result["total_listening"] == 0

    def test_net_connections_access_denied_falls_back(self, mocker):
        """Non-admin Windows gives AccessDenied — must degrade to empty conns."""
        import psutil as _psutil

        mocker.patch("windesktopmgr.psutil.process_iter", return_value=iter([]))
        mocker.patch("windesktopmgr.psutil.net_connections", side_effect=_psutil.AccessDenied())
        mocker.patch("windesktopmgr.psutil.net_io_counters", return_value={})
        mocker.patch("windesktopmgr.psutil.net_if_stats", return_value={})
        result = wdm.get_network_data()
        assert result["total_connections"] == 0
        assert result["established"] == []

    def test_runtime_error_returns_fallback(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", side_effect=RuntimeError("boom"))
        result = wdm.get_network_data()
        assert result["established"] == []
        assert result["adapters"] == []

    def test_adapter_sentmb_converted_from_bytes(self, mocker):
        """psutil reports bytes; we must round to MB to match the PS output."""
        self._patch(
            mocker,
            io_counters={"Wi-Fi": _fake_netio(bytes_sent=5 * 1024 * 1024, bytes_recv=10 * 1024 * 1024)},
            if_stats={"Wi-Fi": _fake_ifstats(isup=True, speed=867)},
        )
        result = wdm.get_network_data()
        adapter = next(a for a in result["adapters"] if a["Name"] == "Wi-Fi")
        assert adapter["SentMB"] == pytest.approx(5.0, abs=0.01)
        assert adapter["ReceivedMB"] == pytest.approx(10.0, abs=0.01)
        assert adapter["LinkSpeedMb"] == 867
        assert adapter["Status"] == "Up"

    def test_adapter_down_status_reported(self, mocker):
        self._patch(
            mocker,
            io_counters={"Ethernet": _fake_netio()},
            if_stats={"Ethernet": _fake_ifstats(isup=False, speed=0)},
        )
        result = wdm.get_network_data()
        assert result["adapters"][0]["Status"] == "Down"

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no PS calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        wdm.get_network_data()
        assert ps_mock.call_count == 0


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


def _fake_psutil_proc(
    pid=0,
    name="",
    cpu_user=0.0,
    cpu_sys=0.0,
    mem_rss_mb=0.0,
    threads=0,
    handles=0,
    exe="",
    cmdline=None,
):
    """Build a psutil-style proc object for process_iter mocking.

    Matches the attribute shape ``get_process_list`` reads from
    ``proc.info`` after passing the attrs list. ``cpu_times`` and
    ``memory_info`` are namedtuple-ish objects with the same fields
    psutil would populate.
    """
    import types

    return types.SimpleNamespace(
        info={
            "pid": pid,
            "name": name,
            "cpu_times": types.SimpleNamespace(user=cpu_user, system=cpu_sys),
            "memory_info": types.SimpleNamespace(rss=int(mem_rss_mb * 1024 * 1024)),
            "num_threads": threads,
            "num_handles": handles,
            "exe": exe,
            "cmdline": cmdline or [],
        }
    )


class TestGetProcessList:
    """Post-PS→psutil tests (backlog #24 batch A). The old PS fixture was
    JSON mocking subprocess.run; now we mock ``psutil.process_iter`` and
    assert the same output contract."""

    SAMPLE_PROCS = [
        _fake_psutil_proc(
            pid=1234,
            name="chrome",
            cpu_user=8.0,
            cpu_sys=4.5,
            mem_rss_mb=512.0,
            threads=30,
            handles=400,
            exe=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            cmdline=["chrome.exe", "--headless"],
        ),
        _fake_psutil_proc(
            pid=4,
            name="System",
            cpu_user=0.1,
            cpu_sys=0.0,
            mem_rss_mb=8.0,
            threads=200,
            handles=10000,
        ),
    ]

    def _patch(self, mocker, procs=None):
        return mocker.patch(
            "windesktopmgr.psutil.process_iter",
            return_value=iter(procs if procs is not None else self.SAMPLE_PROCS),
        )

    def test_happy_path_returns_structure(self, mocker):
        self._patch(mocker)
        result = wdm.get_process_list()
        assert "processes" in result
        assert "total" in result
        assert "total_mem_mb" in result
        assert result["total"] == 2

    def test_total_mem_summed(self, mocker):
        self._patch(mocker)
        result = wdm.get_process_list()
        assert result["total_mem_mb"] == pytest.approx(520.0, abs=1)

    def test_cpu_is_cumulative_seconds(self, mocker):
        """Regression: CPU must preserve PS ``Get-Process .CPU`` semantics —
        cumulative seconds (user + system), NOT a percentage."""
        self._patch(mocker)
        result = wdm.get_process_list()
        chrome = next(p for p in result["processes"] if p["Name"] == "chrome")
        assert chrome["CPU"] == pytest.approx(12.5, abs=0.1)

    def test_empty_output_returns_fallback(self, mocker):
        self._patch(mocker, procs=[])
        result = wdm.get_process_list()
        assert result["processes"] == []
        assert result["total"] == 0

    def test_iter_exception_returns_fallback(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", side_effect=RuntimeError("oops"))
        result = wdm.get_process_list()
        assert result["processes"] == []
        assert result["total"] == 0
        assert result["flagged"] == []

    def test_dead_process_is_skipped(self, mocker):
        """Processes that exit mid-iteration raise NoSuchProcess — must skip."""
        import psutil as _psutil

        class Dead:
            @property
            def info(self):
                raise _psutil.NoSuchProcess(pid=9999)

        good = self.SAMPLE_PROCS[0]
        mocker.patch("windesktopmgr.psutil.process_iter", return_value=iter([good, Dead()]))
        result = wdm.get_process_list()
        # Only the healthy proc should come through.
        assert result["total"] == 1

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: backlog #24 removed PowerShell from this path."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        wdm.get_process_list()
        assert ps_mock.call_count == 0

    def test_flagged_list_only_contains_flagged(self, mocker):
        self._patch(mocker)
        result = wdm.get_process_list()
        for p in result["flagged"]:
            assert p["flag"] in ("warning", "critical")


# ══════════════════════════════════════════════════════════════════════════════
# kill_process — input sanitisation
# ══════════════════════════════════════════════════════════════════════════════


class TestKillProcess:
    """Post-PS→psutil tests (backlog #24 batch A). ``kill_process`` now
    calls ``psutil.Process(pid).kill()`` — no subprocess at all. Tests
    mock ``psutil.Process`` and assert the same ``{ok, error}`` contract."""

    def _patch(self, mocker, kill_side_effect=None):
        proc = mocker.MagicMock()
        if kill_side_effect:
            proc.kill.side_effect = kill_side_effect
        return mocker.patch("windesktopmgr.psutil.Process", return_value=proc)

    def test_success_returns_ok_true(self, mocker):
        self._patch(mocker)
        result = wdm.kill_process(1234)
        assert result["ok"] is True
        assert result["error"] == ""

    def test_access_denied_returns_ok_false(self, mocker):
        import psutil as _psutil

        self._patch(mocker, kill_side_effect=_psutil.AccessDenied(pid=1234))
        result = wdm.kill_process(1234)
        assert result["ok"] is False
        assert "Access is denied" in result["error"]

    def test_no_such_process_returns_ok_false(self, mocker):
        import psutil as _psutil

        mocker.patch("windesktopmgr.psutil.Process", side_effect=_psutil.NoSuchProcess(pid=9999))
        result = wdm.kill_process(9999)
        assert result["ok"] is False
        assert "No such process" in result["error"]

    def test_generic_exception_returns_ok_false(self, mocker):
        self._patch(mocker, kill_side_effect=RuntimeError("boom"))
        result = wdm.kill_process(1234)
        assert result["ok"] is False
        assert "boom" in result["error"]

    def test_pid_is_integer_cast(self, mocker):
        m = self._patch(mocker)
        wdm.kill_process(9999)
        # The int() cast is what prevents injection — verify psutil.Process
        # was called with a real integer, not whatever the caller passed.
        args, _ = m.call_args
        assert args[0] == 9999
        assert isinstance(args[0], int)

    def test_non_integer_pid_is_cleanly_cast(self, mocker):
        """int() cast must prevent any garbage from reaching psutil."""
        m = self._patch(mocker)
        wdm.kill_process(1234.9)
        args, _ = m.call_args
        assert args[0] == 1234
        assert isinstance(args[0], int)

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no subprocess calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        wdm.kill_process(1234)
        assert ps_mock.call_count == 0


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


def _fake_svc(
    name="",
    display_name="",
    status="running",
    start_type="automatic",
    pid=0,
    description="",
    binpath="",
):
    """Build a psutil.win_service_iter()-style object with as_dict()."""
    svc = type("Svc", (), {})()
    svc.as_dict = lambda: {  # noqa: B023 — intentional closure over vars
        "name": name,
        "display_name": display_name,
        "status": status,
        "start_type": start_type,
        "pid": pid,
        "description": description,
        "binpath": binpath,
    }
    return svc


class TestGetServicesList:
    """Post-PS→psutil tests (backlog #24 batch A). ``get_services_list``
    now uses ``psutil.win_service_iter`` instead of
    ``Get-WmiObject Win32_Service``. Status + StartMode must be
    remapped to the title-case strings the JS renderer expects."""

    SAMPLE_SVCS = [
        _fake_svc(
            name="wuauserv",
            display_name="Windows Update",
            status="running",
            start_type="automatic",
            pid=1234,
            description="Enables Windows Update",
            binpath=r"C:\Windows\system32\svchost.exe",
        ),
        _fake_svc(
            name="diagtrack",
            display_name="Connected User Experiences",
            status="running",
            start_type="automatic",
            pid=5678,
            description="Telemetry",
            binpath=r"C:\Windows\system32\svchost.exe",
        ),
    ]

    def _patch(self, mocker, svcs=None):
        return mocker.patch(
            "windesktopmgr.psutil.win_service_iter",
            return_value=iter(svcs if svcs is not None else self.SAMPLE_SVCS),
        )

    def test_happy_path_returns_list(self, mocker):
        self._patch(mocker)
        result = wdm.get_services_list()
        assert isinstance(result, list)
        assert len(result) == 2

    def test_info_field_attached(self, mocker):
        self._patch(mocker)
        result = wdm.get_services_list()
        for s in result:
            assert "info" in s

    def test_status_remapped_to_title_case(self, mocker):
        """psutil returns 'running'/'stopped' lowercase — must map to title-case."""
        self._patch(mocker)
        result = wdm.get_services_list()
        assert all(s["Status"] == "Running" for s in result)

    def test_start_mode_remapped_to_auto(self, mocker):
        """psutil 'automatic' → PS 'Auto' (for compat with summarize_services)."""
        self._patch(mocker)
        result = wdm.get_services_list()
        assert all(s["StartMode"] == "Auto" for s in result)

    def test_stopped_and_disabled_mapped(self, mocker):
        svcs = [
            _fake_svc(name="foo", display_name="Foo", status="stopped", start_type="disabled"),
            _fake_svc(name="bar", display_name="Bar", status="stopped", start_type="manual"),
        ]
        self._patch(mocker, svcs=svcs)
        result = wdm.get_services_list()
        statuses = {s["Name"]: (s["Status"], s["StartMode"]) for s in result}
        assert statuses["foo"] == ("Stopped", "Disabled")
        assert statuses["bar"] == ("Stopped", "Manual")

    def test_empty_iter_returns_empty_list(self, mocker):
        self._patch(mocker, svcs=[])
        result = wdm.get_services_list()
        assert result == []

    def test_exception_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr.psutil.win_service_iter", side_effect=RuntimeError("boom"))
        result = wdm.get_services_list()
        assert result == []

    def test_as_dict_failure_skips_service(self, mocker):
        bad = type("Bad", (), {"as_dict": lambda self: (_ for _ in ()).throw(RuntimeError("nope"))})()
        good = self.SAMPLE_SVCS[0]
        self._patch(mocker, svcs=[bad, good])
        result = wdm.get_services_list()
        assert len(result) == 1
        assert result[0]["Name"] == "wuauserv"

    def test_services_sorted_by_display_name(self, mocker):
        svcs = [
            _fake_svc(name="zulu", display_name="Zulu"),
            _fake_svc(name="alpha", display_name="Alpha"),
            _fake_svc(name="mike", display_name="Mike"),
        ]
        self._patch(mocker, svcs=svcs)
        result = wdm.get_services_list()
        names = [s["DisplayName"] for s in result]
        assert names == sorted(names)

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no PS calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        wdm.get_services_list()
        assert ps_mock.call_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# toggle_service — input sanitisation
# ══════════════════════════════════════════════════════════════════════════════


class TestToggleService:
    """Tests for toggle_service() — now uses win32serviceutil / win32service
    instead of PowerShell subprocess calls."""

    def test_stop_action_calls_stop_service(self, mocker):
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        result = wdm.toggle_service("wuauserv", "stop")
        assert result["ok"] is True
        m.assert_called_once_with("wuauserv")

    def test_start_action_calls_start_service(self, mocker):
        m = mocker.patch("windesktopmgr.win32serviceutil.StartService")
        result = wdm.toggle_service("wuauserv", "start")
        assert result["ok"] is True
        m.assert_called_once_with("wuauserv")

    def test_disable_action_uses_change_service_config(self, mocker):
        mock_scm = mocker.MagicMock()
        mock_svc = mocker.MagicMock()
        mocker.patch("windesktopmgr.win32service.OpenSCManager", return_value=mock_scm)
        mocker.patch("windesktopmgr.win32service.OpenService", return_value=mock_svc)
        change_mock = mocker.patch("windesktopmgr.win32service.ChangeServiceConfig")
        mocker.patch("windesktopmgr.win32service.CloseServiceHandle")
        mocker.patch("windesktopmgr.win32service.SC_MANAGER_ALL_ACCESS", 0xF003F)
        mocker.patch("windesktopmgr.win32service.SERVICE_CHANGE_CONFIG", 0x0002)
        mocker.patch("windesktopmgr.win32service.SERVICE_NO_CHANGE", 0xFFFFFFFF)
        mocker.patch("windesktopmgr.win32service.SERVICE_DISABLED", 0x00000004)
        result = wdm.toggle_service("wuauserv", "disable")
        assert result["ok"] is True
        # Verify ChangeServiceConfig was called with DISABLED start type
        change_mock.assert_called_once()
        call_args = change_mock.call_args[0]
        assert call_args[2] == 0x00000004  # SERVICE_DISABLED

    def test_enable_action_uses_demand_start(self, mocker):
        mock_scm = mocker.MagicMock()
        mock_svc = mocker.MagicMock()
        mocker.patch("windesktopmgr.win32service.OpenSCManager", return_value=mock_scm)
        mocker.patch("windesktopmgr.win32service.OpenService", return_value=mock_svc)
        change_mock = mocker.patch("windesktopmgr.win32service.ChangeServiceConfig")
        mocker.patch("windesktopmgr.win32service.CloseServiceHandle")
        mocker.patch("windesktopmgr.win32service.SC_MANAGER_ALL_ACCESS", 0xF003F)
        mocker.patch("windesktopmgr.win32service.SERVICE_CHANGE_CONFIG", 0x0002)
        mocker.patch("windesktopmgr.win32service.SERVICE_NO_CHANGE", 0xFFFFFFFF)
        mocker.patch("windesktopmgr.win32service.SERVICE_DEMAND_START", 0x00000003)
        result = wdm.toggle_service("wuauserv", "enable")
        assert result["ok"] is True
        change_mock.assert_called_once()
        call_args = change_mock.call_args[0]
        assert call_args[2] == 0x00000003  # SERVICE_DEMAND_START

    def test_invalid_action_returns_error(self, mocker):
        result = wdm.toggle_service("wuauserv", "explode")
        assert result["ok"] is False
        assert "Invalid" in result["error"]

    def test_service_name_sanitised_for_stop(self, mocker):
        """Injection chars stripped — sanitised name passed to StopService."""
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        wdm.toggle_service("wuauserv; bad\\path", "stop")
        # Semicolons, spaces, and backslashes must be stripped
        called_name = m.call_args[0][0]
        assert ";" not in called_name
        assert " " not in called_name
        assert "\\" not in called_name

    def test_exception_returns_ok_false(self, mocker):
        mocker.patch("windesktopmgr.win32serviceutil.StopService", side_effect=Exception("Service not found"))
        result = wdm.toggle_service("nosuchsvc", "stop")
        assert result["ok"] is False
        assert "Service not found" in result["error"]

    def test_empty_name_returns_error(self, mocker):
        """Empty service name after sanitisation returns error."""
        result = wdm.toggle_service(";;; \\\\", "stop")
        assert result["ok"] is False
        assert "Invalid service name" in result["error"]

    def test_backtick_stripped_from_service_name(self, mocker):
        """Backtick must be stripped from service name."""
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        wdm.toggle_service("wuauserv`Stop-Service", "stop")
        called_name = m.call_args[0][0]
        assert "`" not in called_name

    def test_newline_stripped_from_service_name(self, mocker):
        """Newlines must be stripped from service name."""
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        wdm.toggle_service("wuauserv\nStop-Service", "stop")
        called_name = m.call_args[0][0]
        assert "\n" not in called_name

    def test_dollar_stripped_from_service_name(self, mocker):
        """Dollar sign must be stripped from service name."""
        m = mocker.patch("windesktopmgr.win32serviceutil.StopService")
        wdm.toggle_service("wuauserv$env:USERNAME", "stop")
        called_name = m.call_args[0][0]
        assert "$" not in called_name


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


def _fake_mem_proc(name="", mem_mb=0.0):
    """Build a psutil-style proc object for ``process_iter(['name','memory_info'])``."""
    import types

    return types.SimpleNamespace(
        info={
            "name": name,
            "memory_info": types.SimpleNamespace(rss=int(mem_mb * 1024 * 1024)),
        }
    )


def _fake_vmem(total_mb=32768, available_mb=16000):
    """Build a psutil.virtual_memory()-style namedtuple."""
    import types

    return types.SimpleNamespace(
        total=int(total_mb * 1024 * 1024),
        available=int(available_mb * 1024 * 1024),
    )


class TestGetMemoryAnalysis:
    """Post-PS→psutil tests (backlog #24 batch A). ``get_memory_analysis``
    now uses ``psutil.virtual_memory`` + ``process_iter`` instead of
    ``Get-Process`` + ``Get-WmiObject Win32_OperatingSystem``."""

    SAMPLE_PROCS = [
        _fake_mem_proc(name="chrome", mem_mb=1024.0),
        _fake_mem_proc(name="msmpeng", mem_mb=180.0),
        _fake_mem_proc(name="mfemms", mem_mb=350.0),
    ]

    def _patch(self, mocker, procs=None, vmem=None):
        mocker.patch(
            "windesktopmgr.psutil.process_iter",
            return_value=iter(procs if procs is not None else self.SAMPLE_PROCS),
        )
        mocker.patch(
            "windesktopmgr.psutil.virtual_memory",
            return_value=vmem or _fake_vmem(total_mb=32768, available_mb=16000),
        )

    def test_happy_path_keys(self, mocker):
        self._patch(mocker)
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
        self._patch(mocker)
        result = wdm.get_memory_analysis()
        assert result["total_mb"] == 32768
        assert result["free_mb"] == 16000
        assert result["used_mb"] == 32768 - 16000

    def test_mcafee_detected(self, mocker):
        self._patch(mocker)
        result = wdm.get_memory_analysis()
        assert result["has_mcafee"] is True
        assert result["mcafee_mb"] > 0

    def test_mcafee_breakdown_reconciles_with_total(self, mocker):
        """Regression for 2026-04-11: user saw McAfee total 1730 MB but
        mc-fw-host in the process table was only 1015 MB. The math was
        right — the rollup summed multiple McAfee processes. This test
        locks the invariant: sum(mcafee_processes) == mcafee_mb."""
        procs = [
            _fake_mem_proc(name="mc-fw-host", mem_mb=1015.3),
            _fake_mem_proc(name="mfemms", mem_mb=400.0),
            _fake_mem_proc(name="mfevtps", mem_mb=314.7),
            _fake_mem_proc(name="chrome", mem_mb=500.0),
        ]
        self._patch(mocker, procs=procs)
        result = wdm.get_memory_analysis()
        breakdown = result.get("mcafee_processes", [])
        assert len(breakdown) == 3, f"expected 3 McAfee siblings, got {breakdown}"
        # Reconciliation: the total must equal the sum of the breakdown
        breakdown_sum = round(sum(p["mem"] for p in breakdown), 0)
        assert result["mcafee_mb"] == breakdown_sum, (
            f"rollup {result['mcafee_mb']} != sum of breakdown {breakdown_sum} from {breakdown}"
        )
        # Breakdown must be sorted descending so the UI can show the top
        # contributor first
        mems = [p["mem"] for p in breakdown]
        assert mems == sorted(mems, reverse=True)
        # Non-McAfee processes must NOT appear in the breakdown
        names = {p["name"].lower() for p in breakdown}
        assert "chrome" not in names

    def test_defender_breakdown_reconciles_with_total(self, mocker):
        procs = [
            _fake_mem_proc(name="MsMpEng", mem_mb=180.0),
            _fake_mem_proc(name="NisSrv", mem_mb=30.0),
            _fake_mem_proc(name="chrome", mem_mb=1024.0),
        ]
        self._patch(mocker, procs=procs)
        result = wdm.get_memory_analysis()
        breakdown = result.get("defender_processes", [])
        assert len(breakdown) == 2
        assert round(sum(p["mem"] for p in breakdown), 0) == result["defender_mb"]

    def test_accounting_note_present(self, mocker):
        self._patch(mocker)
        result = wdm.get_memory_analysis()
        note = result.get("accounting_note", "")
        assert "RSS" in note or "WorkingSet" in note, (
            "memory response must include an accounting note explaining that vendor totals sum per-process RSS"
        )

    # ── Vendor classifier (backlog #21) ─────────────────────────────────

    @pytest.mark.parametrize(
        "process_name, expected_category",
        [
            ("claude.exe", "dev_tools"),  # Claude Code CLI
            ("code.exe", "dev_tools"),  # VS Code
            ("cursor.exe", "dev_tools"),
            ("windsurf.exe", "dev_tools"),
            ("warp.exe", "dev_tools"),
            ("idea64.exe", "dev_tools"),  # IntelliJ IDEA
            ("pycharm64.exe", "dev_tools"),
            ("rider64.exe", "dev_tools"),
            ("node.exe", "dev_tools"),  # Node (Claude Code cli.js)
            ("git.exe", "dev_tools"),
            # Sanity: existing categories still classify correctly
            ("chrome.exe", "browser"),
            ("msmpeng.exe", "security"),
            ("MsMpEng.exe", "security"),  # case-insensitive
            ("explorer.exe", "microsoft"),
            # Unknown software still bucketed as "other"
            ("totally-made-up-app.exe", "other"),
        ],
    )
    def test_categorise_process(self, process_name, expected_category):
        assert wdm._categorise_process(process_name) == expected_category

    def test_other_bucket_audit_surfaces_top_unclassified(self, mocker):
        """When 'other' crosses 5% of total RAM, the response should include
        the top 3 unclassified processes so we know what to add next."""
        procs = [
            _fake_mem_proc(name="mystery-app.exe", mem_mb=2500.0),
            _fake_mem_proc(name="unknown-tool.exe", mem_mb=1800.0),
            _fake_mem_proc(name="weirdthing.exe", mem_mb=700.0),
            _fake_mem_proc(name="tiny-other.exe", mem_mb=10.0),  # < 50 MB filter
            _fake_mem_proc(name="chrome.exe", mem_mb=1500.0),  # different cat
        ]
        self._patch(mocker, procs=procs, vmem=_fake_vmem(total_mb=32000, available_mb=20000))
        result = wdm.get_memory_analysis()
        assert result["other_needs_audit"] is True
        top = result["other_top_unclassified"]
        assert len(top) == 3, f"expected 3 unclassified, got {top}"
        assert [p["name"] for p in top] == ["mystery-app.exe", "unknown-tool.exe", "weirdthing.exe"]
        # chrome was classified as browser -- must NOT appear
        assert not any(p["name"] == "chrome.exe" for p in top)
        # tiny-other is too small -- must NOT appear even though unclassified
        assert not any(p["name"] == "tiny-other.exe" for p in top)

    def test_other_bucket_audit_quiet_when_under_threshold(self, mocker):
        """When 'other' is below 5%, no audit alert should fire."""
        procs = [
            _fake_mem_proc(name="chrome.exe", mem_mb=5000.0),  # classified
            _fake_mem_proc(name="mystery.exe", mem_mb=300.0),  # small "other"
        ]
        self._patch(mocker, procs=procs, vmem=_fake_vmem(total_mb=32000, available_mb=10000))
        result = wdm.get_memory_analysis()
        assert result["other_needs_audit"] is False

    def test_top_procs_sorted_by_mem_descending(self, mocker):
        self._patch(mocker)
        result = wdm.get_memory_analysis()
        mems = [p["mem"] for p in result["top_procs"]]
        assert mems == sorted(mems, reverse=True)

    def test_virtual_memory_failure_returns_empty_dict(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", return_value=iter([]))
        mocker.patch("windesktopmgr.psutil.virtual_memory", side_effect=RuntimeError("boom"))
        result = wdm.get_memory_analysis()
        assert result == {}

    def test_process_iter_failure_returns_empty_dict(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", side_effect=RuntimeError("boom"))
        result = wdm.get_memory_analysis()
        assert result == {}

    def test_dead_process_is_skipped(self, mocker):
        import psutil as _psutil

        class Dead:
            @property
            def info(self):
                raise _psutil.NoSuchProcess(pid=1)

        mocker.patch(
            "windesktopmgr.psutil.process_iter",
            return_value=iter([Dead(), self.SAMPLE_PROCS[0]]),
        )
        mocker.patch("windesktopmgr.psutil.virtual_memory", return_value=_fake_vmem())
        result = wdm.get_memory_analysis()
        # Chrome should still come through despite the dead process first.
        assert result["top_procs"][0]["name"] == "chrome"

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no PS calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        wdm.get_memory_analysis()
        assert ps_mock.call_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# get_current_bios
# ══════════════════════════════════════════════════════════════════════════════


class TestGetCurrentBios:
    """Tests for get_current_bios() — now uses wmi.WMI().Win32_BIOS() and Win32_BaseBoard()."""

    BIOS_OBJ = _wmi_obj(
        SMBIOSBIOSVersion="2.3.1",
        ReleaseDate="20240106000000.000000+000",
        Manufacturer="Dell Inc.",
    )
    BOARD_OBJ = _wmi_obj(Product="XPS 8960", Manufacturer="Dell Inc.")

    def test_happy_path_returns_data(self, mocker):
        _mock_wmi(mocker, {"Win32_BIOS": [self.BIOS_OBJ], "Win32_BaseBoard": [self.BOARD_OBJ]})
        result = wdm.get_current_bios()
        assert result["BIOSVersion"] == "2.3.1"
        assert result["Manufacturer"] == "Dell Inc."
        assert result["BoardProduct"] == "XPS 8960"
        assert result["BoardMfr"] == "Dell Inc."

    def test_bios_date_formatted(self, mocker):
        _mock_wmi(mocker, {"Win32_BIOS": [self.BIOS_OBJ], "Win32_BaseBoard": [self.BOARD_OBJ]})
        result = wdm.get_current_bios()
        assert "BIOSDateFormatted" in result
        assert "2024" in result["BIOSDateFormatted"]

    def test_wmi_exception_returns_empty_dict(self, mocker):
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("COM error"))
        result = wdm.get_current_bios()
        assert result == {}

    def test_missing_release_date_handled_gracefully(self, mocker):
        bios_no_date = _wmi_obj(
            SMBIOSBIOSVersion="2.3.1",
            ReleaseDate="",
            Manufacturer="Dell Inc.",
        )
        _mock_wmi(mocker, {"Win32_BIOS": [bios_no_date], "Win32_BaseBoard": [self.BOARD_OBJ]})
        result = wdm.get_current_bios()
        assert result["BIOSDateFormatted"] == ""

    def test_output_has_release_date_raw(self, mocker):
        _mock_wmi(mocker, {"Win32_BIOS": [self.BIOS_OBJ], "Win32_BaseBoard": [self.BOARD_OBJ]})
        result = wdm.get_current_bios()
        assert result["ReleaseDate"] == "20240106000000.000000+000"

    def test_output_fields_match_contract(self, mocker):
        _mock_wmi(mocker, {"Win32_BIOS": [self.BIOS_OBJ], "Win32_BaseBoard": [self.BOARD_OBJ]})
        result = wdm.get_current_bios()
        for key in ("BIOSVersion", "ReleaseDate", "Manufacturer", "BoardProduct", "BoardMfr", "BIOSDateFormatted"):
            assert key in result


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
    """Tests for check_dell_bios_update — DCU method calls exe directly (Batch D),
    catalog and WU methods still use PowerShell."""

    # Sample XML that matches the BIOS version regex in the DCU parser
    DCU_XML_TEMPLATE = '<update type="BIOS" name="BIOS Update" version="{ver}"/>'

    def _mock_deps(self, mocker, tmp_path, *, dcu_xml=None, ps_side_effects=None, service_tag="9T46D14"):
        """Mock WMI, filesystem, and subprocess for check_dell_bios_update.

        Args:
            dcu_xml: XML content for DCU scan output file. None = DCU not installed.
            ps_side_effects: list of (stdout, rc) for catalog/WU PowerShell calls.
        """
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber=service_tag)]})

        _real_exists = os.path.exists
        run_responses = []

        if dcu_xml is not None:
            # Pre-create the scan output file with known content
            scan_file = tmp_path / "dcu_scan_00000000.xml"
            scan_file.write_text(dcu_xml, encoding="utf-8")
            mocker.patch("tempfile.gettempdir", return_value=str(tmp_path))
            mocker.patch("uuid.uuid4", return_value=type("U", (), {"hex": "00000000"})())

            mocker.patch("os.path.exists", side_effect=lambda p: True if "CommandUpdate" in p else _real_exists(p))

            # DCU exe subprocess call (direct, not PS)
            run_responses.append(type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})())
        else:
            mocker.patch("os.path.exists", side_effect=lambda p: False if "CommandUpdate" in p else _real_exists(p))

        for out, rc in ps_side_effects or []:
            run_responses.append(type("R", (), {"stdout": out, "returncode": rc, "stderr": ""})())

        m = mocker.patch("windesktopmgr.subprocess.run")
        if run_responses:
            m.side_effect = run_responses
        return m

    def test_returns_required_keys(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, ps_side_effects=[("", 0), ("NO_BIOS_IN_WU", 0)])
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
        xml = self.DCU_XML_TEMPLATE.format(ver="2.23.0")
        self._mock_deps(mocker, tmp_path, dcu_xml=xml)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["latest_version"] == "2.23.0"
        assert result["source"] == "dell_command_update"
        assert result["update_available"] is True

    def test_dcu_same_version_no_update(self, mocker, tmp_path):
        xml = self.DCU_XML_TEMPLATE.format(ver="2.22.0")
        self._mock_deps(mocker, tmp_path, dcu_xml=xml)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["update_available"] is False

    def test_dcu_no_powershell(self, mocker, tmp_path):
        """Regression: Batch D — DCU method calls exe directly, not via PS."""
        xml = self.DCU_XML_TEMPLATE.format(ver="2.23.0")
        m = self._mock_deps(mocker, tmp_path, dcu_xml=xml)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        # First call should be the direct DCU exe, not powershell
        cmd = m.call_args_list[0][0][0]
        assert cmd[0].endswith("dcu-cli.exe")
        assert "powershell" not in cmd

    def test_catalog_fallback(self, mocker, tmp_path):
        catalog_out = json.dumps(
            {
                "Version": "2.23.0",
                "ReleaseDate": "2026-01-15",
                "Name": "XPS 8960 BIOS Update",
                "Path": "https://downloads.dell.com/bios.exe",
            }
        )
        self._mock_deps(mocker, tmp_path, ps_side_effects=[(catalog_out, 0)])
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "dell_catalog"
        assert result["latest_version"] == "2.23.0"

    def test_wu_fallback(self, mocker, tmp_path):
        wu_out = json.dumps({"Title": "Dell BIOS Update 2.24.0", "Version": "2.24.0"})
        self._mock_deps(mocker, tmp_path, ps_side_effects=[("", 0), (wu_out, 0)])
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "windows_update"
        assert result["update_available"] is True

    def test_all_methods_fail_returns_unknown(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, ps_side_effects=[("", 0), ("NO_BIOS_IN_WU", 0)])
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "unknown"
        assert result["latest_version"] is None

    def test_service_tag_populated(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, ps_side_effects=[("", 0), ("NO_BIOS_IN_WU", 0)], service_tag="ABC1234")
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["service_tag"] == "ABC1234"
        assert "ABC1234" in result["download_url"]

    def test_service_tag_empty_fallback_url(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, ps_side_effects=[("", 0), ("NO_BIOS_IN_WU", 0)], service_tag="")
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
        """All subprocess calls (DCU + catalog + WU) time out — returns unknown."""
        _real_exists = os.path.exists
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber="9T46D14")]})
        mocker.patch("os.path.exists", side_effect=lambda p: False if "CommandUpdate" in p else _real_exists(p))
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = subprocess.TimeoutExpired("powershell", 60)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# PowerShell Command Validation Tests — Phase 1: Static command-content gaps
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDiskHealthIOSampling:
    """Batch A (backlog #24): disk IO now comes from psutil.disk_io_counters,
    sampled twice ~1 s apart — no more PowerShell ``Get-Counter``. These
    tests guard the new sampling path and ensure the PS command is gone."""

    def _patch_physical(self, mocker):
        mocker.patch("disk._enumerate_logical_drives", return_value=[])
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "[]", "returncode": 0, "stderr": ""})()
        return m

    def test_no_getcounter_subprocess_calls(self, mocker):
        """Regression guard: backlog #24 removed PS ``Get-Counter`` from this path.

        Only the physical-disk PS command is allowed; nothing containing
        ``Get-Counter`` should be invoked."""
        import types

        m = self._patch_physical(mocker)
        first = {"d0": types.SimpleNamespace(read_bytes=0, write_bytes=0)}
        second = {"d0": types.SimpleNamespace(read_bytes=0, write_bytes=0)}
        mocker.patch("disk.psutil.disk_io_counters", side_effect=[first, second])
        mocker.patch("disk.time.sleep", return_value=None)
        wdm.get_disk_health()
        for call in m.call_args_list:
            cmd = call[0][0][-1]
            assert "Get-Counter" not in cmd
            assert "Disk Read Bytes/sec" not in cmd
            assert "Disk Write Bytes/sec" not in cmd

    def test_empty_first_sample_returns_empty_io(self, mocker):
        """disk_io_counters returning {} early → no sampling interval, [] io."""
        self._patch_physical(mocker)
        mocker.patch("disk.psutil.disk_io_counters", return_value={})
        sleep_mock = mocker.patch("disk.time.sleep")
        result = wdm.get_disk_health()
        assert result["io"] == []
        sleep_mock.assert_not_called()

    def test_missing_disk_on_second_sample_is_skipped(self, mocker):
        """If a disk disappears between samples, skip it — don't divide on None."""
        import types

        self._patch_physical(mocker)
        first = {
            "d0": types.SimpleNamespace(read_bytes=0, write_bytes=0),
            "d1": types.SimpleNamespace(read_bytes=0, write_bytes=0),
        }
        second = {"d0": types.SimpleNamespace(read_bytes=1024, write_bytes=0)}
        mocker.patch("disk.psutil.disk_io_counters", side_effect=[first, second])
        mocker.patch("disk.time.sleep", return_value=None)
        result = wdm.get_disk_health()
        # Only d0 survives both samples.
        disks = {entry["Counter"].split("(")[1].split(")")[0] for entry in result["io"]}
        assert disks == {"d0"}


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
    """Command-content tests for check_dell_bios_update.
    DCU method now calls exe directly (Batch D); catalog/WU still use PS."""

    def _mock_no_dcu(self, mocker, tmp_path):
        """Mock deps with DCU not installed — only catalog + WU PS calls."""
        _real_exists = os.path.exists
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber="9T46D14")]})
        mocker.patch("os.path.exists", side_effect=lambda p: False if "CommandUpdate" in p else _real_exists(p))
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "NO_BIOS_IN_WU", "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_service_tag_from_wmi(self, mocker, tmp_path):
        """Service tag comes from wmi.WMI().Win32_BIOS(), not subprocess."""
        self._mock_no_dcu(mocker, tmp_path)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["service_tag"] == "9T46D14"

    def test_catalog_command_references_dell_downloads(self, mocker, tmp_path):
        m = self._mock_no_dcu(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[0][0][0][-1]
        assert "dell.com" in cmd.lower() or "CatalogPC" in cmd

    def test_wu_command_searches_pending_updates(self, mocker, tmp_path):
        m = self._mock_no_dcu(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[1][0][0][-1]
        assert "IsInstalled" in cmd or "BIOS" in cmd or "Firmware" in cmd

    def test_dcu_calls_exe_not_powershell(self, mocker, tmp_path):
        """Regression: Batch D — DCU uses direct exe, no PS wrapper."""
        _real_exists = os.path.exists
        mocker.patch("windesktopmgr.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber="9T46D14")]})
        # DCU exe "exists"
        mocker.patch("os.path.exists", side_effect=lambda p: True if "CommandUpdate" in p else _real_exists(p))
        scan_file = tmp_path / "dcu_scan_00000000.xml"
        scan_file.write_text('<update type="BIOS" version="2.23.0"/>', encoding="utf-8")
        mocker.patch("tempfile.gettempdir", return_value=str(tmp_path))
        mocker.patch("uuid.uuid4", return_value=type("U", (), {"hex": "00000000"})())
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.return_value = type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})()
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        cmd = m.call_args_list[0][0][0]
        assert cmd[0].endswith("dcu-cli.exe")
        assert "/scan" in cmd
        assert "powershell" not in cmd


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
    """Tests for _lookup_process_via_fileinfo() — now uses shutil.which() and
    win32api.GetFileVersionInfo() instead of PowerShell subprocess calls."""

    CHROME_LC = [(0x0409, 0x04B0)]  # English / Unicode codepage

    def _mock_fileinfo(
        self, mocker, desc="Google Chrome", company="Google LLC", product="Google Chrome", lc_pairs=None
    ):
        """Mock win32api.GetFileVersionInfo to return version resource data."""
        if lc_pairs is None:
            lc_pairs = self.CHROME_LC

        def _gfvi(path, sub_block):
            if "Translation" in sub_block:
                return lc_pairs
            if "FileDescription" in sub_block:
                return desc
            if "CompanyName" in sub_block:
                return company
            if "ProductName" in sub_block:
                return product
            return ""

        return mocker.patch("windesktopmgr.win32api.GetFileVersionInfo", side_effect=_gfvi)

    def test_happy_path_returns_enrichment(self, mocker):
        self._mock_fileinfo(mocker)
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result is not None
        assert result["publisher"] == "Google LLC"
        assert result["source"] == "file_version_info"
        assert result["plain"] == "Google Chrome"

    def test_no_path_triggers_shutil_which(self, mocker):
        """When no path is given, shutil.which() is used to find the exe."""
        m = mocker.patch("windesktopmgr.shutil.which", return_value=None)
        result = wdm._lookup_process_via_fileinfo("unknownapp", "")
        assert result is None
        # Should have tried both with and without .exe suffix
        assert m.call_count >= 1
        first_call = m.call_args_list[0][0][0]
        assert "unknownapp" in first_call

    def test_empty_proc_name_returns_none(self, mocker):
        """Guard against empty proc_name."""
        m = mocker.patch("windesktopmgr.shutil.which")
        result = wdm._lookup_process_via_fileinfo("", "")
        assert result is None
        assert m.call_count == 0  # should never call which with empty name

    def test_shutil_which_finds_exe_then_reads_version(self, mocker):
        """shutil.which resolves path, then win32api reads version info."""
        mocker.patch(
            "windesktopmgr.shutil.which", return_value=r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )
        self._mock_fileinfo(mocker)
        result = wdm._lookup_process_via_fileinfo("chrome", "")
        assert result is not None
        assert result["publisher"] == "Google LLC"

    def test_system_path_marks_safe_kill_false(self, mocker):
        self._mock_fileinfo(
            mocker, desc="Windows Explorer", company="Microsoft Corporation", product="Microsoft Windows"
        )
        result = wdm._lookup_process_via_fileinfo("explorer", r"C:\Windows\explorer.exe")
        assert result is not None
        assert result["safe_kill"] is False

    def test_non_system_path_marks_safe_kill_true(self, mocker):
        self._mock_fileinfo(mocker)
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result["safe_kill"] is True

    def test_empty_desc_and_company_returns_none(self, mocker):
        self._mock_fileinfo(mocker, desc="", company="", product="")
        result = wdm._lookup_process_via_fileinfo("mystery", r"C:\mystery.exe")
        assert result is None

    def test_exception_returns_none(self, mocker):
        mocker.patch("windesktopmgr.win32api.GetFileVersionInfo", side_effect=Exception("file not found"))
        result = wdm._lookup_process_via_fileinfo("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Remediation command-content + fallback tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRemediationCommands:
    """Command-content and fallback tests for all 10 _rem_* functions."""

    # ── flush_dns (direct exe — no PS wrapper) ─────────────────────────────────

    def test_flush_dns_calls_ipconfig_directly(self, mocker):
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_flush_dns()
        cmd = m.call_args[0][0]
        assert cmd[0] == "ipconfig"
        assert "/flushdns" in cmd

    def test_flush_dns_ok_on_success(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=0)
        assert remediation._rem_flush_dns()["ok"] is True

    def test_flush_dns_fail_on_nonzero(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=1, stderr="failed")
        assert remediation._rem_flush_dns()["ok"] is False

    def test_flush_dns_timeout(self, mocker):
        _mock_rem_run(mocker, side_effect=subprocess.TimeoutExpired("ipconfig", 15))
        assert remediation._rem_flush_dns()["ok"] is False

    def test_flush_dns_no_powershell(self, mocker):
        """Regression: Batch D removed the PS wrapper — ipconfig runs directly."""
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_flush_dns()
        cmd = m.call_args[0][0]
        assert "powershell" not in cmd

    # ── reset_winsock (direct exe — two netsh calls) ─────────────────────────

    def test_reset_winsock_calls_netsh_directly(self, mocker):
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reset_winsock()
        assert m.call_count == 2
        cmd1 = m.call_args_list[0][0][0]
        cmd2 = m.call_args_list[1][0][0]
        assert cmd1[0] == "netsh" and "winsock" in cmd1
        assert cmd2[0] == "netsh" and "ip" in cmd2

    def test_reset_winsock_timeout(self, mocker):
        _mock_rem_run(mocker, side_effect=subprocess.TimeoutExpired("netsh", 30))
        assert remediation._rem_reset_winsock()["ok"] is False

    def test_reset_winsock_no_powershell(self, mocker):
        """Regression: Batch D removed the PS wrapper — netsh runs directly."""
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reset_winsock()
        for call in m.call_args_list:
            assert "powershell" not in call[0][0]

    # ── reset_tcpip (direct exe — three netsh calls) ─────────────────────────

    def test_reset_tcpip_calls_netsh_directly(self, mocker):
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reset_tcpip()
        assert m.call_count == 3
        for call in m.call_args_list:
            assert call[0][0][0] == "netsh"

    def test_reset_tcpip_ok_on_success(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=0)
        assert remediation._rem_reset_tcpip()["ok"] is True

    def test_reset_tcpip_no_powershell(self, mocker):
        """Regression: Batch D removed the PS wrapper."""
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reset_tcpip()
        for call in m.call_args_list:
            assert "powershell" not in call[0][0]

    # ── clear_temp ────────────────────────────────────────────────────────────

    def test_clear_temp_command_uses_remove_item(self, mocker):
        m = _mock_rem_run(mocker, stdout="Removed:5 Errors:0", returncode=0)
        remediation._rem_clear_temp()
        cmd = m.call_args[0][0][-1]
        assert "Remove-Item" in cmd

    def test_clear_temp_parses_removed_count(self, mocker):
        _mock_rem_run(mocker, stdout="Removed:42 Errors:3", returncode=0)
        result = remediation._rem_clear_temp()
        assert result["ok"] is True
        assert "42" in result["message"]

    def test_clear_temp_timeout(self, mocker):
        _mock_rem_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 120))
        assert remediation._rem_clear_temp()["ok"] is False

    # ── repair_image (direct exe — dism.exe + sfc) ─────────────────────────────

    def test_repair_image_calls_dism_and_sfc_directly(self, mocker):
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_repair_image()
        assert m.call_count == 2
        cmd1 = m.call_args_list[0][0][0]
        cmd2 = m.call_args_list[1][0][0]
        assert cmd1[0] == "dism.exe"
        assert "/RestoreHealth" in cmd1
        assert cmd2[0] == "sfc"
        assert "/scannow" in cmd2

    def test_repair_image_ok_true_on_success(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=0)
        assert remediation._rem_repair_image()["ok"] is True

    def test_repair_image_ok_false_on_dism_failure(self, mocker):
        m = _mock_rem_run(mocker)
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 1, "stderr": "DISM failed"})(),
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
        ]
        assert remediation._rem_repair_image()["ok"] is False

    def test_repair_image_ok_false_on_sfc_failure(self, mocker):
        m = _mock_rem_run(mocker)
        m.side_effect = [
            type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": "", "returncode": 1, "stderr": "SFC failed"})(),
        ]
        assert remediation._rem_repair_image()["ok"] is False

    def test_repair_image_no_powershell(self, mocker):
        """Regression: Batch D removed the PS wrapper."""
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_repair_image()
        for call in m.call_args_list:
            assert "powershell" not in call[0][0]

    # ── clear_wu_cache (pywin32 — win32serviceutil + shutil) ─────────────────

    def test_clear_wu_cache_stops_wuauserv(self, mocker):
        stop_mock = mocker.patch("remediation.win32serviceutil.StopService")
        mocker.patch("remediation.win32serviceutil.StartService")
        mocker.patch("remediation.os.path.isdir", return_value=False)
        remediation._rem_clear_wu_cache()
        stop_mock.assert_called_once_with("wuauserv")

    def test_clear_wu_cache_clears_download_dir(self, mocker):
        mocker.patch("remediation.win32serviceutil.StopService")
        mocker.patch("remediation.win32serviceutil.StartService")
        mocker.patch("remediation.os.path.isdir", return_value=True)
        mocker.patch("remediation.os.listdir", return_value=["pkg1", "file1.cab"])
        mocker.patch("remediation.os.path.join", side_effect=lambda *a: "\\".join(a))
        mocker.patch("remediation.shutil.rmtree")
        # First item is a dir, second is a file
        mocker.patch("remediation.os.remove")
        is_dir_calls = [True, False]
        mocker.patch("remediation.os.path.isdir", side_effect=[True] + is_dir_calls)
        result = remediation._rem_clear_wu_cache()
        assert result["ok"] is True
        assert "cleared" in result["message"].lower()

    def test_clear_wu_cache_ok_on_success(self, mocker):
        mocker.patch("remediation.win32serviceutil.StopService")
        mocker.patch("remediation.win32serviceutil.StartService")
        mocker.patch("remediation.os.path.isdir", return_value=False)
        assert remediation._rem_clear_wu_cache()["ok"] is True

    def test_clear_wu_cache_listdir_exception_returns_ok_false(self, mocker):
        mocker.patch("remediation.win32serviceutil.StopService")
        mocker.patch("remediation.os.path.isdir", return_value=True)
        mocker.patch("remediation.os.listdir", side_effect=PermissionError("access denied"))
        result = remediation._rem_clear_wu_cache()
        assert result["ok"] is False
        assert "Failed" in result["message"]

    # ── restart_spooler (pywin32 — win32serviceutil.RestartService) ────────

    def test_restart_spooler_calls_restart_service(self, mocker):
        m = mocker.patch("remediation.win32serviceutil.RestartService")
        remediation._rem_restart_spooler()
        m.assert_called_once_with("Spooler")

    def test_restart_spooler_ok_on_success(self, mocker):
        mocker.patch("remediation.win32serviceutil.RestartService")
        assert remediation._rem_restart_spooler()["ok"] is True

    def test_restart_spooler_exception_returns_ok_false(self, mocker):
        mocker.patch("remediation.win32serviceutil.RestartService", side_effect=Exception("access denied"))
        result = remediation._rem_restart_spooler()
        assert result["ok"] is False
        assert "access denied" in result["message"]

    # ── reset_network_adapter ─────────────────────────────────────────────────

    def test_reset_adapter_command_uses_netadapter(self, mocker):
        m = _mock_rem_run(mocker, stdout="RESET:2", returncode=0)
        remediation._rem_reset_network_adapter()
        cmd = m.call_args[0][0][-1]
        assert "Get-NetAdapter" in cmd
        assert "Disable-NetAdapter" in cmd
        assert "Enable-NetAdapter" in cmd

    def test_reset_adapter_parses_count(self, mocker):
        _mock_rem_run(mocker, stdout="RESET:3", returncode=0)
        result = remediation._rem_reset_network_adapter()
        assert result["ok"] is True
        assert "3" in result["message"]

    def test_reset_adapter_zero_count_returns_ok_false(self, mocker):
        _mock_rem_run(mocker, stdout="RESET:0", returncode=0)
        assert remediation._rem_reset_network_adapter()["ok"] is False

    # ── clear_icon_cache ──────────────────────────────────────────────────────

    def test_clear_icon_cache_command_stops_explorer(self, mocker):
        m = _mock_rem_run(mocker, stdout="OK", returncode=0)
        remediation._rem_clear_icon_cache()
        cmd = m.call_args[0][0][-1]
        assert "explorer" in cmd.lower()
        assert "IconCache" in cmd

    def test_clear_icon_cache_ok_on_success(self, mocker):
        _mock_rem_run(mocker, stdout="OK", returncode=0)
        assert remediation._rem_clear_icon_cache()["ok"] is True

    # ── reboot_system (direct exe — shutdown.exe) ──────────────────────────────

    def test_reboot_calls_shutdown_directly(self, mocker):
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reboot_system()
        cmd = m.call_args[0][0]
        assert cmd[0] == "shutdown"
        assert "/r" in cmd
        assert "/t" in cmd

    def test_reboot_ok_on_success(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=0)
        assert remediation._rem_reboot_system()["ok"] is True

    def test_reboot_fail_on_nonzero(self, mocker):
        _mock_rem_run(mocker, stdout="", returncode=1, stderr="permission denied")
        assert remediation._rem_reboot_system()["ok"] is False

    def test_reboot_no_powershell(self, mocker):
        """Regression: Batch D removed the PS wrapper."""
        m = _mock_rem_run(mocker, stdout="", returncode=0)
        remediation._rem_reboot_system()
        assert "powershell" not in m.call_args[0][0]


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: Warranty data command-content tests
# ══════════════════════════════════════════════════════════════════════════════


class TestWarrantyDataCommands:
    """Tests for warranty_data() — CPU/BIOS/System info now from wmi.WMI(),
    microcode and counts still from subprocess."""

    MCU_OUT = "0x010001B4"
    COUNTS_OUT = json.dumps({"BSODs30Days": 2, "WHEAErrors": 0, "UnexpectedShutdowns": 1})

    CPU_OBJ = _wmi_obj(
        Name="  Intel(R) Core(TM) i9-14900K  ",
        ProcessorId="BFEBFBFF000B0671",
        SerialNumber="N/A",
    )
    BIOS_OBJ = _wmi_obj(
        SerialNumber="9T46D14",
        SMBIOSBIOSVersion="2.23.0",
        ReleaseDate="20240106000000.000000+000",
    )
    CS_OBJ = _wmi_obj(Manufacturer="Dell Inc.", Model="XPS 8960")

    def _make_mock(self, mocker):
        _mock_wmi(
            mocker,
            {
                "Win32_Processor": [self.CPU_OBJ],
                "Win32_BIOS": [self.BIOS_OBJ],
                "Win32_ComputerSystem": [self.CS_OBJ],
            },
        )
        m = mocker.patch("windesktopmgr.subprocess.run")
        m.side_effect = [
            type("R", (), {"stdout": self.MCU_OUT, "returncode": 0, "stderr": ""})(),
            type("R", (), {"stdout": self.COUNTS_OUT, "returncode": 0, "stderr": ""})(),
        ]
        return m

    def test_warranty_returns_cpu_info_from_wmi(self, mocker, client):
        self._make_mock(mocker)
        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["CPUModel"] == "Intel(R) Core(TM) i9-14900K"
        assert d["warranty"]["Manufacturer"] == "Dell Inc."

    def test_warranty_returns_bios_date_from_wmi(self, mocker, client):
        self._make_mock(mocker)
        r = client.get("/api/warranty/data")
        d = r.get_json()
        assert d["warranty"]["BIOSVersion"] == "2.23.0"
        assert d["warranty"]["BIOSDate"] == "2024-01-06"

    def test_microcode_command_reads_registry(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[0][0][0][-1]
        assert "CentralProcessor" in cmd
        assert "Update Revision" in cmd

    def test_counts_command_queries_whea_logger(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[1][0][0][-1]
        assert "WHEA-Logger" in cmd

    def test_counts_command_queries_kernel_power_41(self, mocker, client):
        m = self._make_mock(mocker)
        client.get("/api/warranty/data")
        cmd = m.call_args_list[1][0][0][-1]
        assert "41" in cmd


# ══════════════════════════════════════════════════════════════════════════════
# get_driver_health — driver age + NVIDIA update check
# ══════════════════════════════════════════════════════════════════════════════


class TestGetDriverHealth:
    """Tests for get_driver_health() — uses wmi.WMI() for old drivers + problematic devices,
    then calls get_nvidia_update_info() from Python for NVIDIA data."""

    # Old driver: Realtek, date > 2 years ago
    OLD_DRIVER = _wmi_obj(
        DeviceName="Realtek Audio",
        DriverProviderName="Realtek",
        DriverVersion="6.0.1.1",
        DriverDate="20220315000000.000000+000",
    )
    # Recent MS driver — should be excluded
    MS_DRIVER = _wmi_obj(
        DeviceName="MS Net",
        DriverProviderName="Microsoft",
        DriverVersion="10.0.1",
        DriverDate="20220101000000.000000+000",
    )
    # Problematic PnP entity
    PROB_ENTITY = _wmi_obj(Name="Unknown Device", ConfigManagerErrorCode=28, Status="Error")
    # Normal PnP entity (no error)
    OK_ENTITY = _wmi_obj(Name="Good Device", ConfigManagerErrorCode=0, Status="OK")

    def _mock_deps(self, mocker, signed_drivers=None, pnp_entities=None, nvidia_result=None):
        """Mock WMI classes and get_nvidia_update_info."""
        if signed_drivers is None:
            signed_drivers = [self.OLD_DRIVER]
        if pnp_entities is None:
            pnp_entities = [self.PROB_ENTITY, self.OK_ENTITY]
        _mock_wmi(
            mocker,
            {
                "Win32_PnPSignedDriver": signed_drivers,
                "Win32_PnPEntity": pnp_entities,
            },
        )
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=nvidia_result)

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

    def test_old_driver_fields_match_contract(self, mocker):
        self._mock_deps(mocker)
        result = wdm.get_driver_health()
        drv = result["old_drivers"][0]
        for key in ("DeviceName", "Provider", "Version", "Date"):
            assert key in drv
        assert drv["Date"] == "2022-03-15"

    def test_problematic_drivers_parsed(self, mocker):
        self._mock_deps(mocker)
        result = wdm.get_driver_health()
        assert len(result["problematic_drivers"]) == 1
        assert result["problematic_drivers"][0]["ErrorCode"] == 28

    def test_ms_drivers_excluded(self, mocker):
        self._mock_deps(mocker, signed_drivers=[self.OLD_DRIVER, self.MS_DRIVER])
        result = wdm.get_driver_health()
        assert len(result["old_drivers"]) == 1
        assert result["old_drivers"][0]["DeviceName"] == "Realtek Audio"

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

    def test_empty_wmi_returns_safe_defaults(self, mocker):
        self._mock_deps(mocker, signed_drivers=[], pnp_entities=[])
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []
        assert result["problematic_drivers"] == []

    def test_wmi_exception_returns_safe_defaults(self, mocker):
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("COM error"))
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=None)
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []
        assert result["problematic_drivers"] == []

    def test_recent_driver_not_flagged_as_old(self, mocker):
        recent = _wmi_obj(
            DeviceName="New Driver",
            DriverProviderName="Vendor",
            DriverVersion="2.0",
            DriverDate="20260101000000.000000+000",
        )
        self._mock_deps(mocker, signed_drivers=[recent])
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []

    def test_driver_with_no_provider_excluded(self, mocker):
        no_provider = _wmi_obj(
            DeviceName="Orphan",
            DriverProviderName="",
            DriverVersion="1.0",
            DriverDate="20200101000000.000000+000",
        )
        self._mock_deps(mocker, signed_drivers=[no_provider])
        result = wdm.get_driver_health()
        assert result["old_drivers"] == []


class TestGetNvidiaGpuInfo:
    """Tests for _get_nvidia_gpu_info() — nvidia-smi subprocess + wmi.WMI() for GPU detection."""

    NV_GPU = _wmi_obj(Name="NVIDIA GeForce RTX 4060 Ti", DriverVersion="32.0.15.9174")
    INTEL_GPU = _wmi_obj(Name="Intel UHD Graphics 770", DriverVersion="31.0.101.5186")

    def _mock_smi(self, mocker, stdout="", returncode=0, exists=True, side_effect=None):
        """Mock nvidia-smi subprocess + os.path.exists."""
        mocker.patch("windesktopmgr.os.path.exists", return_value=exists)
        m = mocker.patch("windesktopmgr.subprocess.run")
        if side_effect:
            m.side_effect = side_effect
        else:
            m.return_value.stdout = stdout
            m.return_value.returncode = returncode
            m.return_value.stderr = ""
        return m

    def test_happy_path_with_smi_and_wmi(self, mocker):
        self._mock_smi(mocker, stdout="NVIDIA GeForce RTX 4060 Ti, 591.74\n")
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        result = wdm._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"
        assert result["installed"] == "591.74"
        assert result["win_ver"] == "32.0.15.9174"

    def test_no_smi_falls_back_to_wmi_only(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        result = wdm._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"
        assert result["win_ver"] == "32.0.15.9174"
        # Version derived from win_ver via _win_to_nvidia_version
        assert result["installed"] == "591.74"

    def test_no_nvidia_gpu_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.INTEL_GPU]})
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_empty_wmi_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": []})
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_wmi_exception_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("COM error"))
        result = wdm._get_nvidia_gpu_info()
        assert result is None

    def test_smi_timeout_still_tries_wmi(self, mocker):
        self._mock_smi(mocker, side_effect=subprocess.TimeoutExpired("nvidia-smi", 10))
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        # os.path.exists needs to be True for the smi path to be tried
        mocker.patch("windesktopmgr.os.path.exists", return_value=True)
        result = wdm._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"

    def test_output_contract_fields(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        result = wdm._get_nvidia_gpu_info()
        assert "name" in result
        assert "installed" in result
        assert "win_ver" in result


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

    def _mock_winreg_cache(self, mocker, entries=None):
        """Mock winreg to simulate Installer2 Cache registry keys.

        ``entries`` is a list of (name, value, type) tuples returned by
        EnumValue.  Pass ``None`` for FileNotFoundError (key missing).
        """
        if entries is None:
            mocker.patch(
                "windesktopmgr.winreg.OpenKey",
                side_effect=FileNotFoundError,
            )
            return
        mock_key = mocker.MagicMock()
        mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mock_key)

        # EnumValue returns entries one at a time, then raises OSError
        def _enum(key, idx):
            if idx < len(entries):
                return entries[idx]
            raise OSError("no more items")

        mocker.patch("windesktopmgr.winreg.EnumValue", side_effect=_enum)
        mocker.patch("windesktopmgr.winreg.CloseKey")

    def test_api_failure_falls_back_to_installer2_cache(self, mocker):
        """When API fails, check Installer2 Cache via winreg."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Mock Installer2 Cache with a version newer than installed (591.74)
        self._mock_winreg_cache(
            mocker,
            entries=[
                ("Display.Driver/595.79", "", 1),
                ("SomeOtherKey", "", 1),
            ],
        )
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is True
        assert result["LatestVersion"] == "595.79"
        assert result["UpdateSource"] == "installer2_cache"

    def test_api_failure_no_cache_returns_no_update(self, mocker):
        """When API fails and no Installer2 Cache → no update available."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Registry key exists but has no Display.Driver entries
        self._mock_winreg_cache(mocker, entries=[])
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["UpdateSource"] == "none"

    def test_unknown_gpu_skips_api_tries_cache(self, mocker):
        """GPU not in pfid map → skip API, try Installer2 only."""
        gpu = {"name": "NVIDIA GeForce GTX 1660", "installed": "560.00", "win_ver": "31.0.15.6000"}
        self._mock_gpu(mocker, gpu=gpu)
        api_mock = self._mock_api(mocker)
        self._mock_winreg_cache(mocker, entries=[])
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
        self._mock_winreg_cache(mocker, entries=[])
        result = wdm.get_nvidia_update_info()
        # API should be called exactly ONCE (Studio only), not twice
        api_mock.assert_called_once()
        # No update from API — falls through to Installer2 Cache
        assert result["UpdateSource"] == "none"
        assert result["UpdateAvailable"] is False

    def test_installer2_cache_key_missing_still_returns_result(self, mocker):
        """Installer2 registry key missing → graceful fallback, still returns GPU info."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Simulate key not found
        self._mock_winreg_cache(mocker, entries=None)
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


# ══════════════════════════════════════════════════════════════════════════════
# analyze_disk_path / get_disk_quickwins / open_folder_in_explorer
# ══════════════════════════════════════════════════════════════════════════════


class TestAnalyzeDiskPath:
    """Tests for analyze_disk_path() — pure Python os.scandir() implementation.

    Mocking strategy: mock os.scandir for immediate children listing and
    _walk_dir_size for recursive directory sizing.  No subprocess involved.
    """

    @staticmethod
    def _make_direntry(name, path, is_dir=False, size=0, is_offline=False, is_junction=False, cloud_attrs=0):
        """Create a fake os.DirEntry-like object.

        cloud_attrs: raw attribute bits to OR in (e.g. 0x00400000 for RECALL_ON_DATA_ACCESS).
        is_offline: shorthand that sets FILE_ATTRIBUTE_OFFLINE (0x1000).
        """
        import stat as _stat

        attrs = 0x10 if is_dir else 0  # FILE_ATTRIBUTE_DIRECTORY
        if is_offline:
            attrs |= _stat.FILE_ATTRIBUTE_OFFLINE
        attrs |= cloud_attrs

        stat_result = type(
            "FakeStat",
            (),
            {"st_size": size, "st_file_attributes": attrs},
        )()
        return type(
            "FakeDirEntry",
            (),
            {
                "name": name,
                "path": path,
                "is_dir": lambda self, follow_symlinks=True: is_dir,
                "is_junction": lambda self: is_junction,
                "stat": lambda self, follow_symlinks=True: stat_result,
            },
        )()

    def _mock_scandir(self, mocker, entries):
        """Mock os.scandir to return the given entries (iterable + context manager)."""
        ctx = type(
            "FakeScandir",
            (),
            {
                "__enter__": lambda self: self,
                "__exit__": lambda self, *a: None,
                "__iter__": lambda self: iter(entries),
            },
        )()
        return mocker.patch("windesktopmgr.os.scandir", return_value=ctx)

    def test_happy_path_returns_sorted_entries(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [
            self._make_direntry("Users", "C:\\Users", is_dir=True),
            self._make_direntry("Windows", "C:\\Windows", is_dir=True),
            self._make_direntry("pagefile.sys", "C:\\pagefile.sys", size=10_000_000_000),
        ]
        self._mock_scandir(mocker, entries)
        mocker.patch(
            "disk._walk_dir_size",
            side_effect=[
                {"local": 40_000_000_000, "cloud": 0, "count": 12345},
                {"local": 30_000_000_000, "cloud": 0, "count": 98765},
            ],
        )
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert result["path"] == "C:\\"
        assert result["parent"] is None
        assert len(result["entries"]) == 3
        assert result["total_bytes"] == 80_000_000_000
        assert result["entries"][0]["name"] == "Users"
        assert result["entries"][0]["size_bytes"] == 40_000_000_000
        assert result["entries"][0]["size_human"].endswith("GB")
        assert result["entries"][0]["pct"] == 50.0
        assert result["entries"][0]["type"] == "dir"
        file_entry = [e for e in result["entries"] if e["name"] == "pagefile.sys"][0]
        assert file_entry["type"] == "file"
        assert file_entry["item_count"] == 1

    def test_single_dir_entry(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [self._make_direntry("Users", "C:\\Users", is_dir=True)]
        self._mock_scandir(mocker, entries)
        mocker.patch("disk._walk_dir_size", return_value={"local": 100, "cloud": 0, "count": 2})
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert len(result["entries"]) == 1
        assert result["entries"][0]["name"] == "Users"

    def test_empty_dir_returns_empty_entries(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        self._mock_scandir(mocker, [])
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert result["entries"] == []
        assert result["total_bytes"] == 0

    def test_scandir_oserror_returns_error(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        mocker.patch("windesktopmgr.os.scandir", side_effect=OSError("Access denied"))
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is False
        assert "access denied" in result["error"].lower()
        assert result["entries"] == []

    def test_walk_dir_size_failure_returns_zero(self, mocker):
        """If _walk_dir_size raises, the dir entry gets zero bytes (graceful)."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [self._make_direntry("Broken", "C:\\Broken", is_dir=True)]
        self._mock_scandir(mocker, entries)
        mocker.patch("disk._walk_dir_size", side_effect=RuntimeError("boom"))
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert len(result["entries"]) == 1
        assert result["entries"][0]["size_bytes"] == 0

    def test_missing_path_rejected(self, mocker):
        result = disk.analyze_disk_path("")
        assert result["ok"] is False
        assert "path" in result["error"].lower()

    def test_nonexistent_path_rejected(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        result = disk.analyze_disk_path("C:\\DoesNotExist")
        assert result["ok"] is False
        assert "does not exist" in result["error"].lower()

    def test_unc_path_rejected(self, mocker):
        result = disk.analyze_disk_path("\\\\server\\share")
        assert result["ok"] is False
        assert "unc" in result["error"].lower()

    def test_relative_path_rejected(self, mocker):
        result = disk.analyze_disk_path("Users\\me")
        assert result["ok"] is False
        assert "absolute" in result["error"].lower()

    def test_injection_chars_stripped(self, mocker):
        """Metacharacters are stripped from path before it reaches os.scandir."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        mock_scan = self._mock_scandir(mocker, [])
        disk.analyze_disk_path("C:\\Users'; Remove-Item C:\\ -Recurse; #")
        call_path = mock_scan.call_args[0][0]
        assert ";" not in call_path
        assert "#" not in call_path
        assert "'" not in call_path

    def test_cloud_bytes_surfaced_in_response(self, mocker):
        """Cloud-only files (FILE_ATTRIBUTE_OFFLINE) are counted as cloud_bytes,
        not local bytes, in both dirs (via _walk_dir_size) and files."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [
            self._make_direntry("iCloud Photos", "C:\\Users\\me\\iCloud Photos", is_dir=True),
            self._make_direntry("Windows", "C:\\Windows", is_dir=True),
        ]
        self._mock_scandir(mocker, entries)
        # analyze_disk_path runs _walk_dir_size in a ThreadPoolExecutor, so
        # using ``side_effect=[...]`` (consumed in call-order) was flaky:
        # whichever worker won the race got the first return value. Key the
        # mock by path instead so each directory gets its intended result.
        path_returns = {
            "C:\\Users\\me\\iCloud Photos": {"local": 500_000_000, "cloud": 20_000_000_000, "count": 5000},
            "C:\\Windows": {"local": 30_000_000_000, "cloud": 0, "count": 98765},
        }
        mocker.patch("disk._walk_dir_size", side_effect=lambda p: path_returns[p])
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert result["total_bytes"] == 30_500_000_000
        assert result["total_cloud_bytes"] == 20_000_000_000
        assert result["total_cloud_human"].endswith("GB")
        photos = [e for e in result["entries"] if e["name"] == "iCloud Photos"][0]
        assert photos["size_bytes"] == 500_000_000
        assert photos["cloud_bytes"] == 20_000_000_000
        assert photos["cloud_human"].endswith("GB")
        win = [e for e in result["entries"] if e["name"] == "Windows"][0]
        assert win["cloud_bytes"] == 0
        assert win["cloud_human"] == ""

    def test_offline_file_counted_as_cloud(self, mocker):
        """A file with FILE_ATTRIBUTE_OFFLINE at root level counts as cloud."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [
            self._make_direntry("cloud.txt", "C:\\cloud.txt", size=1_000_000, is_offline=True),
            self._make_direntry("local.txt", "C:\\local.txt", size=2_000_000),
        ]
        self._mock_scandir(mocker, entries)
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        cloud_file = [e for e in result["entries"] if e["name"] == "cloud.txt"][0]
        assert cloud_file["size_bytes"] == 0
        assert cloud_file["cloud_bytes"] == 1_000_000
        local_file = [e for e in result["entries"] if e["name"] == "local.txt"][0]
        assert local_file["size_bytes"] == 2_000_000
        assert local_file["cloud_bytes"] == 0

    def test_recall_on_data_access_counted_as_cloud(self, mocker):
        """FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (iCloud/OneDrive) counts as cloud."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        _RECALL_DATA = 0x00400000
        entries = [
            self._make_direntry("icloud.jpg", "C:\\icloud.jpg", size=5_000_000, cloud_attrs=_RECALL_DATA),
            self._make_direntry("local.txt", "C:\\local.txt", size=2_000_000),
        ]
        self._mock_scandir(mocker, entries)
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        cloud_file = [e for e in result["entries"] if e["name"] == "icloud.jpg"][0]
        assert cloud_file["size_bytes"] == 0
        assert cloud_file["cloud_bytes"] == 5_000_000
        local_file = [e for e in result["entries"] if e["name"] == "local.txt"][0]
        assert local_file["size_bytes"] == 2_000_000
        assert local_file["cloud_bytes"] == 0

    def test_recall_on_open_counted_as_cloud(self, mocker):
        """FILE_ATTRIBUTE_RECALL_ON_OPEN counts as cloud."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        _RECALL_OPEN = 0x00100000
        entries = [
            self._make_direntry("onedrive.docx", "C:\\onedrive.docx", size=3_000_000, cloud_attrs=_RECALL_OPEN),
        ]
        self._mock_scandir(mocker, entries)
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        cloud_file = result["entries"][0]
        assert cloud_file["size_bytes"] == 0
        assert cloud_file["cloud_bytes"] == 3_000_000

    def test_junction_dirs_skipped(self, mocker):
        """Junction points should be skipped (like robocopy /XJ)."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [
            self._make_direntry("RealDir", "C:\\RealDir", is_dir=True),
            self._make_direntry("JunctionDir", "C:\\JunctionDir", is_dir=True, is_junction=True),
        ]
        self._mock_scandir(mocker, entries)
        mocker.patch("disk._walk_dir_size", return_value={"local": 100, "cloud": 0, "count": 1})
        result = disk.analyze_disk_path("C:\\")
        assert result["ok"] is True
        assert len(result["entries"]) == 1
        assert result["entries"][0]["name"] == "RealDir"

    def test_no_subprocess_calls(self, mocker):
        """analyze_disk_path must NOT call subprocess.run — it's pure Python."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        self._mock_scandir(mocker, [])
        m = mocker.patch("windesktopmgr.subprocess.run")
        disk.analyze_disk_path("C:\\")
        m.assert_not_called()

    def test_quickwins_command_excludes_offline(self, mocker):
        """get_disk_quickwins must also pass /XA:O — so cloud-only folders
        (rare in system locations, but possible in user Downloads on OneDrive)
        don't over-report local usage."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        m = _mock_run(mocker, stdout="[]")
        disk.get_disk_quickwins("C")
        # quickwins now makes TWO subprocess calls: the PowerShell sizer and
        # a DISM call for WinSxS. Find the powershell invocation.
        ps_calls = [c for c in m.call_args_list if len(c[0]) > 0 and c[0][0] and c[0][0][0] == "powershell"]
        assert ps_calls, "expected at least one powershell invocation"
        ps_string = " ".join(ps_calls[0][0][0])
        assert "/XA:O" in ps_string
        # The elseif (single file) branch must also skip Offline files
        assert "FileAttributes]::Offline" in ps_string

    def test_parent_set_for_non_root_path(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        self._mock_scandir(mocker, [])
        result = disk.analyze_disk_path("C:\\Users\\me")
        assert result["parent"] == "C:\\Users"

    def test_top_n_limits_results(self, mocker):
        """top_n parameter limits the number of returned entries."""
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        entries = [self._make_direntry(f"dir{i}", f"C:\\dir{i}", is_dir=True) for i in range(10)]
        self._mock_scandir(mocker, entries)
        mocker.patch(
            "disk._walk_dir_size",
            return_value={"local": 100, "cloud": 0, "count": 1},
        )
        result = disk.analyze_disk_path("C:\\", top_n=5)
        assert result["ok"] is True
        assert len(result["entries"]) == 5


class TestGetDiskQuickwins:
    def _stub_paths(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)

    def test_happy_path_returns_known_locations(self, mocker):
        self._stub_paths(mocker)
        # PS returns a size for a subset of candidate paths
        stdout = json.dumps(
            [
                {"Path": "C:\\$Recycle.Bin", "Exists": True, "Bytes": 1_500_000_000},
                {"Path": "C:\\Windows\\Temp", "Exists": True, "Bytes": 200_000_000},
                {"Path": "C:\\Windows.old", "Exists": False, "Bytes": 0},
            ]
        )
        _mock_run(mocker, stdout=stdout)
        result = disk.get_disk_quickwins("C")
        assert result["ok"] is True
        assert result["drive"] == "C:\\"
        # Locations must be sorted by size descending
        sizes = [loc["size_bytes"] for loc in result["locations"]]
        assert sizes == sorted(sizes, reverse=True)
        # Recycle Bin should be the biggest
        assert result["locations"][0]["key"] == "recycle_bin"
        assert result["locations"][0]["exists"] is True
        assert result["locations"][0]["size_bytes"] == 1_500_000_000
        assert result["locations"][0]["size_human"].endswith(("MB", "GB"))

    def test_drive_lowercase_accepted(self, mocker):
        self._stub_paths(mocker)
        _mock_run(mocker, stdout="[]")
        result = disk.get_disk_quickwins("c")
        assert result["ok"] is True
        assert result["drive"] == "C:\\"

    def test_drive_with_colon_accepted(self, mocker):
        self._stub_paths(mocker)
        _mock_run(mocker, stdout="[]")
        result = disk.get_disk_quickwins("D:")
        assert result["ok"] is True
        assert result["drive"] == "D:\\"

    def test_invalid_drive_rejected(self, mocker):
        result = disk.get_disk_quickwins("notadrive")
        assert result["ok"] is False
        assert "drive" in result["error"].lower()

    def test_missing_drive_returns_error(self, mocker):
        result = disk.get_disk_quickwins("")
        assert result["ok"] is False

    def test_nonexistent_drive_rejected(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        result = disk.get_disk_quickwins("Z")
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_empty_ps_output_returns_zeros(self, mocker):
        self._stub_paths(mocker)
        _mock_run(mocker, stdout="")
        result = disk.get_disk_quickwins("C")
        assert result["ok"] is True
        assert all(loc["size_bytes"] == 0 for loc in result["locations"])
        assert all(loc["exists"] is False for loc in result["locations"])

    def test_timeout_returns_safe_fallback(self, mocker):
        self._stub_paths(mocker)
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=180),
        )
        result = disk.get_disk_quickwins("C")
        assert result["ok"] is False
        assert "timed out" in result["error"].lower()

    def test_malformed_json_returns_error(self, mocker):
        self._stub_paths(mocker)
        _mock_run(mocker, stdout="garbage {{{")
        result = disk.get_disk_quickwins("C")
        assert result["ok"] is False

    def test_command_checks_recycle_bin_and_temp(self, mocker):
        self._stub_paths(mocker)
        m = _mock_run(mocker, stdout="[]")
        disk.get_disk_quickwins("C")
        # quickwins now makes TWO subprocess calls: the PowerShell sizer and
        # a DISM call for WinSxS. Find the powershell invocation.
        ps_calls = [c for c in m.call_args_list if len(c[0]) > 0 and c[0][0] and c[0][0][0] == "powershell"]
        assert ps_calls, "expected at least one powershell invocation"
        ps_string = " ".join(ps_calls[0][0][0])
        assert "$Recycle.Bin" in ps_string
        assert "Windows\\Temp" in ps_string
        # Quick-wins sizes directories via robocopy too (/L /BYTES)
        assert "robocopy" in ps_string
        assert "/BYTES" in ps_string
        assert "exit 0" in ps_string

    def test_user_locations_only_for_profile_drive(self, mocker, monkeypatch):
        """Downloads/AppData are per-user — only returned for the profile drive."""
        self._stub_paths(mocker)
        monkeypatch.setenv("USERPROFILE", "C:\\Users\\tester")
        _mock_run(mocker, stdout="[]")
        r_c = disk.get_disk_quickwins("C")
        r_d = disk.get_disk_quickwins("D")
        assert r_c["ok"] and r_d["ok"]
        c_keys = {loc["key"] for loc in r_c["user_locations"]}
        d_keys = {loc["key"] for loc in r_d["user_locations"]}
        assert "downloads" in c_keys
        assert d_keys == set()  # no user locations for non-profile drive


class TestQuickwinsActionDispatch:
    """The quickwins response must include action_kind + tool/cli fields so
    the frontend can render the right button (Open folder vs Launch tool vs
    Show CLI)."""

    def _stub(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        _mock_run(mocker, stdout="[]")

    def test_run_tool_entries_include_tool_key(self, mocker):
        self._stub(mocker)
        result = disk.get_disk_quickwins("C")
        by_key = {loc["key"]: loc for loc in result["locations"]}
        # windows_installer's primary action is PatchCleaner (the only tool
        # that can actually clean C:\Windows\Installer safely). Regular
        # Disk Cleanup does not touch this folder — user-reported confusion.
        wi = by_key["windows_installer"]
        assert wi["action_kind"] == "run_tool"
        assert wi["tool"] == "patchcleaner"
        assert "PatchCleaner" in wi.get("tool_label", "")

    def test_windows_installer_offers_disk_cleanup_as_extra(self, mocker):
        """Windows Installer primary = PatchCleaner; Disk Cleanup is offered
        as a secondary button via `extra_tools` so users still have a way
        to trigger the (limited) Microsoft cleanup path."""
        self._stub(mocker)
        result = disk.get_disk_quickwins("C")
        by_key = {loc["key"]: loc for loc in result["locations"]}
        wi = by_key["windows_installer"]
        extras = wi.get("extra_tools") or []
        extra_keys = [x["tool"] for x in extras]
        assert "cleanmgr" in extra_keys
        # Each extra carries a human label too
        for x in extras:
            assert "label" in x and x["label"]

    def test_info_only_entries_include_cli_string(self, mocker):
        self._stub(mocker)
        result = disk.get_disk_quickwins("C")
        by_key = {loc["key"]: loc for loc in result["locations"]}
        winsxs = by_key["winsxs"]
        assert winsxs["action_kind"] == "info_only"
        assert "Dism.exe" in winsxs["cli"]
        assert "/StartComponentCleanup" in winsxs["cli"]
        hiber = by_key["hiberfil"]
        assert hiber["action_kind"] == "info_only"
        assert "powercfg" in hiber["cli"]
        assert "hibernate off" in hiber["cli"]

    def test_open_folder_entries_have_no_tool_or_cli(self, mocker):
        self._stub(mocker)
        result = disk.get_disk_quickwins("C")
        by_key = {loc["key"]: loc for loc in result["locations"]}
        rb = by_key["recycle_bin"]
        assert rb["action_kind"] == "open_folder"
        assert "tool" not in rb
        assert "cli" not in rb

    def test_run_tool_entries_reference_only_allowlisted_tools(self, mocker, monkeypatch):
        self._stub(mocker)
        monkeypatch.setenv("USERPROFILE", "C:\\Users\\tester")
        result = disk.get_disk_quickwins("C")
        all_rows = result["locations"] + result["user_locations"]
        for row in all_rows:
            if row["action_kind"] == "run_tool":
                assert row["tool"] in disk._CLEANUP_TOOLS, f"Entry {row['key']} references unknown tool {row['tool']!r}"


class TestLaunchCleanupTool:
    def test_known_tool_launches(self, mocker):
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("cleanmgr")
        assert result["ok"] is True
        assert result["tool"] == "cleanmgr"
        assert result["label"] == "Disk Cleanup"
        popen.assert_called_once()
        argv = popen.call_args[0][0]
        assert argv[0] == "cleanmgr.exe"

    def test_sysdm_advanced_launches(self, mocker):
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("sysdm_advanced")
        assert result["ok"] is True
        popen.assert_called_once()
        assert popen.call_args[0][0][0] == "SystemPropertiesAdvanced.exe"

    def test_unknown_tool_rejected(self, mocker):
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("rm_rf_slash")
        assert result["ok"] is False
        assert "unknown" in result["error"].lower()
        popen.assert_not_called()

    def test_missing_tool_rejected(self, mocker):
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("")
        assert result["ok"] is False
        popen.assert_not_called()

    def test_none_tool_rejected(self, mocker):
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool(None)
        assert result["ok"] is False
        popen.assert_not_called()

    def test_tool_not_on_path_returns_error(self, mocker):
        mocker.patch(
            "windesktopmgr.subprocess.Popen",
            side_effect=FileNotFoundError("cleanmgr.exe not found"),
        )
        result = disk.launch_cleanup_tool("cleanmgr")
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_popen_exception_returns_error(self, mocker):
        mocker.patch(
            "windesktopmgr.subprocess.Popen",
            side_effect=OSError("access denied"),
        )
        result = disk.launch_cleanup_tool("cleanmgr")
        assert result["ok"] is False
        assert "access denied" in result["error"].lower()

    def test_patchcleaner_launches_when_installed(self, mocker):
        """PatchCleaner is third-party — its spec uses candidate_paths instead
        of a fixed argv. When the file exists at one of the candidates, we
        launch it with that resolved absolute path."""
        resolved_path = r"C:\Program Files\homedev\PatchCleaner\PatchCleaner.exe"

        def fake_isfile(p):
            return p == resolved_path

        mocker.patch("windesktopmgr.os.path.isfile", side_effect=fake_isfile)
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("patchcleaner")
        assert result["ok"] is True
        assert result["tool"] == "patchcleaner"
        popen.assert_called_once()
        argv = popen.call_args[0][0]
        assert argv[0] == resolved_path

    def test_patchcleaner_not_installed_returns_install_url(self, mocker):
        """When no candidate path exists, the launch must return an error
        AND the install_url so the frontend can offer a download button.
        Popen must NOT be called in this case."""
        mocker.patch("windesktopmgr.os.path.isfile", return_value=False)
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("patchcleaner")
        assert result["ok"] is False
        assert "not installed" in result["error"].lower()
        assert "install_url" in result
        assert result["install_url"].startswith("https://")
        assert "patchcleaner" in result["install_url"].lower()
        popen.assert_not_called()

    def test_patchcleaner_first_matching_candidate_wins(self, mocker):
        """If both Program Files and Program Files (x86) paths exist, the
        first one in the candidate list is used."""
        mocker.patch("windesktopmgr.os.path.isfile", return_value=True)
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.launch_cleanup_tool("patchcleaner")
        assert result["ok"] is True
        argv = popen.call_args[0][0]
        assert "Program Files\\homedev" in argv[0]

    def test_elevation_required_falls_back_to_startfile(self, mocker):
        """PatchCleaner has `requireAdministrator` in its manifest. Plain
        subprocess.Popen fails with WinError 740. The launcher must detect
        this and retry via os.startfile() which uses ShellExecute and
        triggers the Windows UAC prompt."""
        mocker.patch("windesktopmgr.os.path.isfile", return_value=True)
        err = OSError("elevation required")
        err.winerror = 740
        mocker.patch("windesktopmgr.subprocess.Popen", side_effect=err)
        startfile = mocker.patch("windesktopmgr.os.startfile", create=True)
        result = disk.launch_cleanup_tool("patchcleaner")
        assert result["ok"] is True
        assert result.get("elevated") is True
        startfile.assert_called_once()

    def test_elevation_fallback_failure_returns_error(self, mocker):
        """If os.startfile() also fails (user declined UAC, etc.), we must
        surface a clear error — not a silent success."""
        mocker.patch("windesktopmgr.os.path.isfile", return_value=True)
        err = OSError("elevation required")
        err.winerror = 740
        mocker.patch("windesktopmgr.subprocess.Popen", side_effect=err)
        mocker.patch(
            "windesktopmgr.os.startfile",
            side_effect=OSError("UAC declined"),
            create=True,
        )
        result = disk.launch_cleanup_tool("patchcleaner")
        assert result["ok"] is False
        assert "elevation failed" in result["error"].lower()

    def test_allowlist_contains_expected_tools(self):
        """The allowlist must include the tools the frontend expects to launch.
        Each spec must carry a label and either a fixed `argv` (system tools)
        or `candidate_paths` + `install_url` (third-party tools)."""
        assert "cleanmgr" in disk._CLEANUP_TOOLS
        assert "sysdm_advanced" in disk._CLEANUP_TOOLS
        assert "patchcleaner" in disk._CLEANUP_TOOLS
        for spec in disk._CLEANUP_TOOLS.values():
            assert "label" in spec
            has_argv = "argv" in spec
            has_candidates = "candidate_paths" in spec
            assert has_argv or has_candidates, (
                "Each tool must have either `argv` (system tool) or `candidate_paths` (third-party tool)"
            )
            if has_argv:
                assert isinstance(spec["argv"], list) and len(spec["argv"]) >= 1
            if has_candidates:
                assert isinstance(spec["candidate_paths"], list)
                assert len(spec["candidate_paths"]) >= 1
                assert "install_url" in spec, (
                    "Third-party tools must include install_url for the frontend's not-installed fallback"
                )


class TestGetWinsxsActualSize:
    """Tests for the DISM-based WinSxS sizer. WinSxS is mostly hardlinks to
    C:\\Windows, so robocopy reports 2-4x the true on-disk footprint. DISM
    /AnalyzeComponentStore is the only authoritative source."""

    SAMPLE_DISM_OUTPUT = """
Deployment Image Servicing and Management tool
Version: 10.0.26100.5074

Image Version: 10.0.26200.8037

[==========================100.0%==========================]

Component Store (WinSxS) information:

Windows Explorer Reported Size of Component Store : 10.64 GB
Actual Size of Component Store : 5.23 GB

   Shared with Windows : 4.10 GB
   Backups and Disabled Features : 0.81 GB
   Cache and Temporary Data : 0.32 GB

Date of Last Cleanup : 2025-12-09

Number of Reclaimable Packages : 0
Component Store Cleanup Recommended : No

The operation completed successfully.
"""

    def _reset_cache(self):
        disk._winsxs_cache["ts"] = 0.0
        disk._winsxs_cache["data"] = None

    def test_happy_path_parses_all_fields(self, mocker):
        self._reset_cache()
        _mock_run(mocker, stdout=self.SAMPLE_DISM_OUTPUT)
        result = disk._get_winsxs_actual_size()
        assert result is not None
        # 10.64 GB in bytes
        assert 10 * (1024**3) < result["reported_bytes"] < 11 * (1024**3)
        # 5.23 GB in bytes (actual)
        assert 5 * (1024**3) < result["actual_bytes"] < 6 * (1024**3)
        # 4.10 GB shared
        assert 4 * (1024**3) < result["shared_bytes"] < 5 * (1024**3)
        assert result["cleanup_recommended"] is False

    def test_cleanup_recommended_yes(self, mocker):
        self._reset_cache()
        out = self.SAMPLE_DISM_OUTPUT.replace(
            "Component Store Cleanup Recommended : No",
            "Component Store Cleanup Recommended : Yes",
        )
        _mock_run(mocker, stdout=out)
        result = disk._get_winsxs_actual_size()
        assert result["cleanup_recommended"] is True

    def test_command_uses_analyze_component_store(self, mocker):
        self._reset_cache()
        m = _mock_run(mocker, stdout=self.SAMPLE_DISM_OUTPUT)
        disk._get_winsxs_actual_size()
        argv = m.call_args[0][0]
        assert argv[0] == "Dism.exe"
        assert "/Online" in argv
        assert "/Cleanup-Image" in argv
        assert "/AnalyzeComponentStore" in argv

    def test_timeout_returns_none(self, mocker):
        self._reset_cache()
        mocker.patch(
            "windesktopmgr.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="Dism.exe", timeout=120),
        )
        assert disk._get_winsxs_actual_size() is None

    def test_dism_missing_returns_none(self, mocker):
        self._reset_cache()
        mocker.patch("windesktopmgr.subprocess.run", side_effect=FileNotFoundError("Dism.exe"))
        assert disk._get_winsxs_actual_size() is None

    def test_garbage_output_returns_none(self, mocker):
        self._reset_cache()
        _mock_run(mocker, stdout="not DISM output")
        assert disk._get_winsxs_actual_size() is None

    def test_result_is_cached(self, mocker):
        """Second call within TTL must NOT re-run DISM."""
        self._reset_cache()
        m = _mock_run(mocker, stdout=self.SAMPLE_DISM_OUTPUT)
        a = disk._get_winsxs_actual_size()
        b = disk._get_winsxs_actual_size()
        assert a == b
        assert m.call_count == 1  # DISM only invoked once


class TestOpenFolderInExplorer:
    def test_happy_path_launches_explorer(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.open_folder_in_explorer("C:\\Users")
        assert result["ok"] is True
        assert result["path"] == "C:\\Users"
        popen.assert_called_once()
        args = popen.call_args[0][0]
        assert args[0] == "explorer.exe"
        assert args[1] == "C:\\Users"

    def test_file_path_also_accepted(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        mocker.patch("windesktopmgr.os.path.isfile", return_value=True)
        popen = mocker.patch("windesktopmgr.subprocess.Popen")
        result = disk.open_folder_in_explorer("C:\\pagefile.sys")
        assert result["ok"] is True
        popen.assert_called_once()

    def test_missing_path_rejected(self, mocker):
        result = disk.open_folder_in_explorer("")
        assert result["ok"] is False

    def test_nonexistent_path_rejected(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        mocker.patch("windesktopmgr.os.path.isfile", return_value=False)
        result = disk.open_folder_in_explorer("C:\\Ghost")
        assert result["ok"] is False

    def test_popen_failure_returns_error(self, mocker):
        mocker.patch("windesktopmgr.os.path.isdir", return_value=True)
        mocker.patch("windesktopmgr.subprocess.Popen", side_effect=OSError("boom"))
        result = disk.open_folder_in_explorer("C:\\Users")
        assert result["ok"] is False
        assert "boom" in result["error"]
