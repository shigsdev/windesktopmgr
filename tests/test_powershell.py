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
import time
import types
from datetime import datetime, timedelta, timezone

import pytest

import bsod
import disk
import events
import processes
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


# ── Windows Update COM mock helpers ─────────────────────────────────────────
# get_windows_update_drivers / get_update_history / check_dell_bios_update's
# WU method drive the Microsoft.Update.Session COM object in-process via
# win32com (backlog #28 Batch G) — no PowerShell subprocess. These helpers
# build fake COM objects so the tests stay OS-independent.


class _FakeWuColl:
    """Fake COM collection — .Count and .Item(i), like the real
    IUpdateCollection / IUpdateHistoryEntryCollection / ICategoryCollection."""

    def __init__(self, items):
        self._items = list(items)

    @property
    def Count(self):
        return len(self._items)

    def Item(self, i):
        return self._items[i]


def _fake_wu_update(**props):
    """Fake COM IUpdate. Only the supplied properties exist — reading any
    other raises AttributeError, exactly as a real COM update does for a
    property its interface doesn't support (e.g. DriverVersion on a
    non-driver update)."""
    return types.SimpleNamespace(**props)


def _fake_wu_history(title="", date=None, result_code=0, categories=None):
    """Fake COM IUpdateHistoryEntry (Categories is itself a fake collection)."""
    cats = _FakeWuColl([types.SimpleNamespace(Name=c) for c in (categories or [])])
    return types.SimpleNamespace(Title=title, Date=date, ResultCode=result_code, Categories=cats)


def _mock_wu(mocker, driver_updates=None, history=None):
    """Patch the Windows Update COM layer (win32com + pythoncom).

    driver_updates: list of property-dicts → searcher.Search().Updates
    history:        list of _fake_wu_history(...) → searcher.QueryHistory()
    Returns (dispatch_mock, searcher_mock) for call assertions.
    """
    mocker.patch("windesktopmgr.pythoncom.CoInitialize")
    searcher = mocker.MagicMock()
    if driver_updates is not None:
        items = [_fake_wu_update(**d) for d in driver_updates]
        searcher.Search.return_value = types.SimpleNamespace(Updates=_FakeWuColl(items))
    if history is not None:
        searcher.GetTotalHistoryCount.return_value = len(history)
        searcher.QueryHistory.return_value = _FakeWuColl(history)
    session = mocker.MagicMock()
    session.CreateUpdateSearcher.return_value = searcher
    dispatch = mocker.patch("windesktopmgr.win32com.client.Dispatch", return_value=session)
    return dispatch, searcher


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
    """get_windows_update_drivers() — in-process win32com (backlog #28 Batch G)."""

    SAMPLE = [
        {
            "Title": "Intel - Display - 31.0.101.5186",
            "Description": "Intel display driver",
            "DriverModel": "Intel UHD Graphics",
            "DriverVersion": "31.0.101.5186",
            "DriverManufacturer": "Intel Corporation",
        },
    ]

    def setup_method(self):
        wdm._wu_driver_cache = None

    def test_happy_path_returns_dict(self, mocker):
        _mock_wu(mocker, driver_updates=self.SAMPLE)
        result = wdm.get_windows_update_drivers()
        assert isinstance(result, dict)
        assert len(result) == 1
        assert result["intel - display - 31.0.101.5186"]["DriverVersion"] == "31.0.101.5186"

    def test_result_is_cached(self, mocker):
        dispatch, _ = _mock_wu(mocker, driver_updates=self.SAMPLE)
        wdm.get_windows_update_drivers()
        wdm.get_windows_update_drivers()
        assert dispatch.call_count == 1  # second call hits the module cache

    def test_empty_search_returns_empty_dict(self, mocker):
        _mock_wu(mocker, driver_updates=[])
        assert wdm.get_windows_update_drivers() == {}

    def test_search_uses_driver_criteria(self, mocker):
        _, searcher = _mock_wu(mocker, driver_updates=self.SAMPLE)
        wdm.get_windows_update_drivers()
        criteria = searcher.Search.call_args[0][0]
        assert "Type='Driver'" in criteria and "IsInstalled=0" in criteria

    def test_missing_driver_version_handled(self, mocker):
        """A non-driver-class update has no DriverVersion COM property —
        _wu_prop must return '' for it, not raise."""
        _mock_wu(mocker, driver_updates=[{"Title": "Some Monitor INF"}])
        row = wdm.get_windows_update_drivers()["some monitor inf"]
        assert row["DriverVersion"] == "" and row["DriverManufacturer"] == ""

    def test_com_error_returns_none(self, mocker):
        """A COM failure → None (never {}), so a transient failure isn't cached."""
        mocker.patch("windesktopmgr._wu_search_drivers", side_effect=Exception("COM error"))
        assert wdm.get_windows_update_drivers() is None
        assert wdm._wu_driver_cache is None

    def test_timeout_returns_none_and_does_not_poison_cache(self, mocker):
        """A WU search timeout must NOT be cached. Caching {} would make every
        later call short-circuit on the `_wu_driver_cache is not None` guard and
        return {} forever, permanently disabling WU driver detection (and the
        NVIDIA Method 3 fallback) until the process restarts. Regression for
        the 2026-05-21 review finding.
        """
        # First call times out.
        mocker.patch("windesktopmgr._wu_search_drivers", side_effect=TimeoutError("WU search exceeded 120s"))
        result = wdm.get_windows_update_drivers()
        assert result is None, "timeout is a failure — return None, not a misleading empty dict"
        assert wdm._wu_driver_cache is None, "timeout must not poison the module cache"

        # Second call: WU is responsive again — must re-query, not serve a
        # stale poisoned cache entry.
        mocker.patch("windesktopmgr._wu_search_drivers", return_value=self.SAMPLE)
        result2 = wdm.get_windows_update_drivers()
        assert isinstance(result2, dict) and len(result2) == 1

    def test_wu_search_drivers_times_out_on_slow_search(self, mocker):
        """_wu_search_drivers runs the blocking COM Search() in a worker
        thread and raises TimeoutError if it exceeds the budget."""
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        slow_searcher = types.SimpleNamespace(
            Search=lambda criteria: (time.sleep(3), types.SimpleNamespace(Updates=_FakeWuColl([])))[1]
        )
        session = types.SimpleNamespace(CreateUpdateSearcher=lambda: slow_searcher)
        mocker.patch("windesktopmgr.win32com.client.Dispatch", return_value=session)
        with pytest.raises(TimeoutError):
            wdm._wu_search_drivers(timeout_s=0.2)


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
    """get_update_history() — in-process win32com QueryHistory (backlog #28)."""

    def _sample(self):
        return [
            _fake_wu_history(
                title="2024-12 Cumulative Update for Windows 11 (KB5048667)",
                date=datetime(2024, 12, 10, 3, 0, tzinfo=timezone.utc),
                result_code=2,
                categories=["Security Updates"],
            ),
            _fake_wu_history(
                title="Intel - Display - 31.0.101.5186",
                date=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
                result_code=4,
                categories=["Drivers"],
            ),
        ]

    def test_happy_path_returns_list(self, mocker):
        _mock_wu(mocker, history=self._sample())
        result = wdm.get_update_history()
        assert isinstance(result, list)
        assert len(result) == 2

    def test_fields_parsed(self, mocker):
        _mock_wu(mocker, history=self._sample())
        first = wdm.get_update_history()[0]
        assert first["KB"] == "KB5048667"
        assert first["Categories"] == "Security Updates"
        assert first["ResultCode"] == 2
        assert first["result"] == wdm.RESULT_CODES.get(2, "Unknown")
        assert first["Date"].startswith("2024-12-10")

    def test_failed_updates_flagged(self, mocker):
        _mock_wu(mocker, history=self._sample())
        result = wdm.get_update_history()
        assert len([u for u in result if u.get("ResultCode") == 4]) == 1

    def test_empty_history_returns_empty_list(self, mocker):
        _mock_wu(mocker, history=[])
        assert wdm.get_update_history() == []

    def test_com_error_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        mocker.patch("windesktopmgr.win32com.client.Dispatch", side_effect=Exception("COM error"))
        assert wdm.get_update_history() == []

    def test_uses_update_session_com_object(self, mocker):
        dispatch, _ = _mock_wu(mocker, history=[])
        wdm.get_update_history()
        assert dispatch.call_args[0][0] == "Microsoft.Update.Session"

    def test_history_query_capped_at_150(self, mocker):
        _, searcher = _mock_wu(mocker, history=[])
        searcher.GetTotalHistoryCount.return_value = 500
        wdm.get_update_history()
        start, count = searcher.QueryHistory.call_args[0]
        assert start == 0 and count == 150

    def test_timeout_returns_empty_list(self, mocker):
        """A cold Windows Update Agent that exceeds the 60s worker-thread
        budget must degrade to [] (Updates tab shows nothing) rather than
        hang the request — restores the cap the old PS subprocess had."""
        mocker.patch("windesktopmgr._wu_run", side_effect=TimeoutError("WU history query exceeded 60s"))
        assert wdm.get_update_history() == []


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
        result = processes.get_process_list()
        assert "processes" in result
        assert "total" in result
        assert "total_mem_mb" in result
        assert result["total"] == 2

    def test_total_mem_summed(self, mocker):
        self._patch(mocker)
        result = processes.get_process_list()
        assert result["total_mem_mb"] == pytest.approx(520.0, abs=1)

    def test_cpu_is_cumulative_seconds(self, mocker):
        """Regression: CPU must preserve PS ``Get-Process .CPU`` semantics —
        cumulative seconds (user + system), NOT a percentage."""
        self._patch(mocker)
        result = processes.get_process_list()
        chrome = next(p for p in result["processes"] if p["Name"] == "chrome")
        assert chrome["CPU"] == pytest.approx(12.5, abs=0.1)

    def test_empty_output_returns_fallback(self, mocker):
        self._patch(mocker, procs=[])
        result = processes.get_process_list()
        assert result["processes"] == []
        assert result["total"] == 0

    def test_iter_exception_returns_fallback(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", side_effect=RuntimeError("oops"))
        result = processes.get_process_list()
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
        result = processes.get_process_list()
        # Only the healthy proc should come through.
        assert result["total"] == 1

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: backlog #24 removed PowerShell from this path."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        processes.get_process_list()
        assert ps_mock.call_count == 0

    def test_flagged_list_only_contains_flagged(self, mocker):
        self._patch(mocker)
        result = processes.get_process_list()
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
        result = processes.kill_process(1234)
        assert result["ok"] is True
        assert result["error"] == ""

    def test_access_denied_returns_ok_false(self, mocker):
        import psutil as _psutil

        self._patch(mocker, kill_side_effect=_psutil.AccessDenied(pid=1234))
        result = processes.kill_process(1234)
        assert result["ok"] is False
        assert "Access is denied" in result["error"]

    def test_no_such_process_returns_ok_false(self, mocker):
        import psutil as _psutil

        mocker.patch("windesktopmgr.psutil.Process", side_effect=_psutil.NoSuchProcess(pid=9999))
        result = processes.kill_process(9999)
        assert result["ok"] is False
        assert "No such process" in result["error"]

    def test_generic_exception_returns_ok_false(self, mocker):
        self._patch(mocker, kill_side_effect=RuntimeError("boom"))
        result = processes.kill_process(1234)
        assert result["ok"] is False
        assert "boom" in result["error"]

    def test_pid_is_integer_cast(self, mocker):
        m = self._patch(mocker)
        processes.kill_process(9999)
        # The int() cast is what prevents injection — verify psutil.Process
        # was called with a real integer, not whatever the caller passed.
        args, _ = m.call_args
        assert args[0] == 9999
        assert isinstance(args[0], int)

    def test_non_integer_pid_is_cleanly_cast(self, mocker):
        """int() cast must prevent any garbage from reaching psutil."""
        m = self._patch(mocker)
        processes.kill_process(1234.9)
        args, _ = m.call_args
        assert args[0] == 1234
        assert isinstance(args[0], int)

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no subprocess calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        processes.kill_process(1234)
        assert ps_mock.call_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# get_thermals
# ══════════════════════════════════════════════════════════════════════════════


def _mock_wmi_by_namespace(mocker, by_ns=None):
    """Patch windesktopmgr.wmi.WMI() to return a fake connection whose WMI
    class methods depend on the ``namespace`` kwarg the caller passed.

    ``by_ns`` maps a namespace string (or ``""`` for the default root\\cimv2
    connection created via ``wmi.WMI()`` with no args) to a dict of
    {class_name: [_wmi_obj, ...]}. get_thermals() opens three distinct
    namespaces: ``root\\wmi`` for thermal zones, ``root\\OpenHardwareMonitor``
    / ``root\\LibreHardwareMonitor`` for rich sensors, and the default
    namespace for ``Win32_Fan``.

    Returns the mock ``wmi.WMI`` so call assertions (namespace kwarg) work.
    """
    by_ns = by_ns or {}

    def _factory(*args, **kwargs):
        ns = kwargs.get("namespace", "")
        classes = by_ns.get(ns, {})
        conn = mocker.MagicMock()
        for name, data in classes.items():
            setattr(conn, name, mocker.MagicMock(return_value=data))
        return conn

    return mocker.patch("windesktopmgr.wmi.WMI", side_effect=_factory)


class TestGetThermals:
    """get_thermals() is fully in-process (backlog #28): thermal zones +
    OHM/LHM sensors via the ``wmi`` package, CPU/memory/battery via psutil.
    No PowerShell subprocess — tests mock wmi.WMI, psutil and pythoncom."""

    # root\wmi thermal-zone objects: decikelvin (value/10 - 273.15 = C).
    # 55.2 C -> (55.2 + 273.15) * 10 = 3283.5
    ZONE_OBJS = [
        _wmi_obj(InstanceName="ACPI\\ThermalZone\\TZ00_0", CurrentTemperature=3283),
    ]
    # OHM/LHM rich sensors.
    LHM_SENSORS = [
        _wmi_obj(SensorType="Temperature", Name="CPU Package", Value=55.2),
        _wmi_obj(SensorType="Temperature", Name="GPU Core", Value=48.0),
        _wmi_obj(SensorType="Load", Name="CPU Total", Value=12.5),  # filtered out
    ]

    def _make_mock(self, mocker, zones=None, lhm=None, fans=None, cpu_pct=12.5):
        """Mock the WMI namespaces + psutil + pythoncom for get_thermals()."""
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        wmi_mock = _mock_wmi_by_namespace(
            mocker,
            {
                "root\\wmi": {"MSAcpi_ThermalZoneTemperature": zones if zones is not None else []},
                "root\\OpenHardwareMonitor": {"Sensor": []},
                "root\\LibreHardwareMonitor": {"Sensor": lhm if lhm is not None else list(self.LHM_SENSORS)},
                "": {"Win32_Fan": fans if fans is not None else []},
            },
        )
        mocker.patch("windesktopmgr.psutil.cpu_percent", return_value=cpu_pct)
        vm = types.SimpleNamespace(total=32768 * 1024 * 1024, available=16384 * 1024 * 1024)
        mocker.patch("windesktopmgr.psutil.virtual_memory", return_value=vm)
        mocker.patch("windesktopmgr.psutil.sensors_battery", return_value=None)
        return wmi_mock

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
        hot = [_wmi_obj(SensorType="Temperature", Name="CPU Package", Value=95.0)]
        self._make_mock(mocker, lhm=hot)
        result = wdm.get_thermals()
        assert result["temps"][0]["status"] == "critical"

    def test_warning_temp_flagged(self, mocker):
        warm = [_wmi_obj(SensorType="Temperature", Name="CPU Package", Value=85.0)]
        self._make_mock(mocker, lhm=warm)
        result = wdm.get_thermals()
        assert result["temps"][0]["status"] == "warning"

    def test_has_rich_true_when_lhm_source(self, mocker):
        self._make_mock(mocker)
        result = wdm.get_thermals()
        assert result["has_rich"] is True

    def test_has_rich_false_when_only_wmi(self, mocker):
        # Only a root\wmi thermal zone, no OHM/LHM sensors.
        self._make_mock(mocker, zones=list(self.ZONE_OBJS), lhm=[])
        result = wdm.get_thermals()
        assert result["has_rich"] is False
        assert result["temps"][0]["Source"] == "WMI_ThermalZone"

    def test_zone_temp_converted_from_decikelvin(self, mocker):
        self._make_mock(mocker, zones=list(self.ZONE_OBJS), lhm=[])
        result = wdm.get_thermals()
        # 3283 / 10 - 273.15 = 55.15 -> rounded to 55.2 (one decimal place)
        assert result["temps"][0]["TempC"] == 55.2

    def test_wmi_failure_returns_fallback(self, mocker):
        mocker.patch("windesktopmgr.pythoncom.CoInitialize", side_effect=RuntimeError("COM init failed"))
        result = wdm.get_thermals()
        assert result["temps"] == []
        assert result["perf"] == {}
        assert result["has_rich"] is False

    def test_temps_query_uses_root_wmi_namespace(self, mocker):
        wmi_mock = self._make_mock(mocker)
        wdm.get_thermals()
        namespaces = [c.kwargs.get("namespace", "") for c in wmi_mock.call_args_list]
        assert "root\\wmi" in namespaces

    def test_perf_uses_psutil_cpu_percent(self, mocker):
        self._make_mock(mocker)
        cpu = mocker.patch("windesktopmgr.psutil.cpu_percent", return_value=42.0)
        result = wdm.get_thermals()
        assert cpu.called
        assert result["perf"]["CPUPct"] == 42.0


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


def _mock_registry_toggle(mocker, *, found=True):
    """Patch the winreg surface used by ``toggle_startup_item`` for registry
    items. ``found=False`` makes ``OpenKey`` of the source raise
    FileNotFoundError so the not-found branch can be exercised.

    Returns a dict of the mocked winreg functions for call assertions.
    """
    open_key = mocker.patch("windesktopmgr.winreg.OpenKey")
    if not found:
        open_key.side_effect = FileNotFoundError("missing")
    else:
        open_key.return_value = mocker.MagicMock()
    query = mocker.patch(
        "windesktopmgr.winreg.QueryValueEx",
        return_value=("C:\\App\\app.exe", 1),  # 1 == REG_SZ
    )
    create = mocker.patch("windesktopmgr.winreg.CreateKey", return_value=mocker.MagicMock())
    set_val = mocker.patch("windesktopmgr.winreg.SetValueEx")
    del_val = mocker.patch("windesktopmgr.winreg.DeleteValue")
    mocker.patch("windesktopmgr.winreg.CloseKey")
    return {
        "OpenKey": open_key,
        "QueryValueEx": query,
        "CreateKey": create,
        "SetValueEx": set_val,
        "DeleteValue": del_val,
    }


def _mock_scheduler_for_toggle(mocker, *, task_found=True):
    """Patch ``Schedule.Service`` COM + ``_find_scheduled_task`` for the
    ``toggle_startup_item`` task branch. Returns the fake task object so
    callers can assert ``task.Enabled`` was set."""
    mocker.patch("windesktopmgr.pythoncom.CoInitialize")
    scheduler = mocker.MagicMock()
    scheduler.GetFolder.return_value = mocker.MagicMock()
    mocker.patch("windesktopmgr.win32com.client.Dispatch", return_value=scheduler)
    fake_task = mocker.MagicMock()
    fake_task.Enabled = True
    mocker.patch(
        "windesktopmgr._find_scheduled_task",
        return_value=fake_task if task_found else None,
    )
    return fake_task


class TestToggleStartupItem:
    def test_backtick_stripped_from_task_lookup(self, mocker):
        """Input sanitisation: backticks/semicolons must be stripped before
        the name reaches ``_find_scheduled_task``."""
        _mock_scheduler_for_toggle(mocker)
        find = mocker.patch("windesktopmgr._find_scheduled_task", return_value=mocker.MagicMock())
        wdm.toggle_startup_item("MyApp`; malicious", "task", True)
        assert find.called
        looked_up = find.call_args[0][1]
        assert "`" not in looked_up
        assert ";" not in looked_up

    def test_newline_stripped_from_task_lookup(self, mocker):
        _mock_scheduler_for_toggle(mocker)
        find = mocker.patch("windesktopmgr._find_scheduled_task", return_value=mocker.MagicMock())
        wdm.toggle_startup_item("MyApp\nRemove-Item C:\\", "task", False)
        assert find.called
        looked_up = find.call_args[0][1]
        assert "\n" not in looked_up

    def test_spaces_preserved_in_startup_name(self, mocker):
        """Startup items can have spaces in their names — sanitiser must keep them."""
        _mock_scheduler_for_toggle(mocker)
        find = mocker.patch("windesktopmgr._find_scheduled_task", return_value=mocker.MagicMock())
        wdm.toggle_startup_item("My Cool App", "task", True)
        looked_up = find.call_args[0][1]
        assert looked_up == "My Cool App"

    def test_registry_toggle_uses_correct_hive(self, mocker):
        """Disabling an HKCU entry must open HKCU\\...\\Run for read and move
        the value to Run-Disabled."""
        m = _mock_registry_toggle(mocker)
        result = wdm.toggle_startup_item("TestApp", "registry_hkcu", False)
        assert result["ok"] is True
        # First OpenKey call: read the source (Run) under HKCU
        first_call = m["OpenKey"].call_args_list[0]
        assert first_call[0][0] == wdm.winreg.HKEY_CURRENT_USER
        assert "CurrentVersion\\Run" in first_call[0][1]
        # CreateKey opens the destination (Run-Disabled) on the same hive
        create_call = m["CreateKey"].call_args
        assert create_call[0][0] == wdm.winreg.HKEY_CURRENT_USER
        assert "Run-Disabled" in create_call[0][1]

    def test_registry_hklm_enable_moves_from_disabled_to_run(self, mocker):
        """Enabling must read from Run-Disabled and write into Run under HKLM."""
        m = _mock_registry_toggle(mocker)
        result = wdm.toggle_startup_item("TestApp", "registry_hklm", True)
        assert result["ok"] is True
        first_call = m["OpenKey"].call_args_list[0]
        assert first_call[0][0] == wdm.winreg.HKEY_LOCAL_MACHINE
        assert "Run-Disabled" in first_call[0][1]
        create_call = m["CreateKey"].call_args
        assert create_call[0][0] == wdm.winreg.HKEY_LOCAL_MACHINE
        # Destination is plain Run (not Run-Disabled)
        assert create_call[0][1].endswith("\\Run")

    def test_registry_preserves_value_and_regtype(self, mocker):
        """SetValueEx must receive the same (value, type) tuple QueryValueEx returned."""
        m = _mock_registry_toggle(mocker)
        m["QueryValueEx"].return_value = ("D:\\some\\path.exe -arg", 2)  # 2 == REG_EXPAND_SZ
        wdm.toggle_startup_item("TestApp", "registry_hkcu", False)
        set_args = m["SetValueEx"].call_args[0]
        # SetValueEx(key, name, reserved, regtype, value)
        assert set_args[1] == "TestApp"
        assert set_args[3] == 2
        assert set_args[4] == "D:\\some\\path.exe -arg"

    def test_registry_deletes_from_source(self, mocker):
        m = _mock_registry_toggle(mocker)
        wdm.toggle_startup_item("TestApp", "registry_hkcu", False)
        # DeleteValue is invoked with the safe name
        del_args = m["DeleteValue"].call_args[0]
        assert del_args[1] == "TestApp"

    def test_registry_value_not_found_returns_error(self, mocker):
        _mock_registry_toggle(mocker, found=False)
        result = wdm.toggle_startup_item("Missing", "registry_hkcu", True)
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_registry_exception_returns_error(self, mocker):
        """Unexpected winreg errors propagate into {ok:False, error:...}."""
        mocker.patch("windesktopmgr.winreg.OpenKey", side_effect=PermissionError("denied"))
        result = wdm.toggle_startup_item("TestApp", "registry_hklm", False)
        assert result["ok"] is False
        assert result["error"]

    def test_task_enabled_set_to_true(self, mocker):
        fake_task = _mock_scheduler_for_toggle(mocker)
        result = wdm.toggle_startup_item("SomeTask", "task", True)
        assert result == {"ok": True, "error": ""}
        assert fake_task.Enabled is True

    def test_task_enabled_set_to_false(self, mocker):
        fake_task = _mock_scheduler_for_toggle(mocker)
        result = wdm.toggle_startup_item("SomeTask", "task", False)
        assert result == {"ok": True, "error": ""}
        assert fake_task.Enabled is False

    def test_task_not_found_returns_error(self, mocker):
        _mock_scheduler_for_toggle(mocker, task_found=False)
        result = wdm.toggle_startup_item("Ghost", "task", True)
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_task_com_exception_returns_error(self, mocker):
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        mocker.patch(
            "windesktopmgr.win32com.client.Dispatch",
            side_effect=Exception("COM error"),
        )
        result = wdm.toggle_startup_item("SomeTask", "task", True)
        assert result["ok"] is False
        assert result["error"]

    def test_empty_name_returns_error(self):
        """Sanitisation strips everything → empty name → invalid."""
        result = wdm.toggle_startup_item("```", "registry_hkcu", True)
        assert result["ok"] is False
        assert "invalid" in result["error"].lower()

    def test_unknown_type_returns_error(self):
        result = wdm.toggle_startup_item("App", "folder", True)
        assert result["ok"] is False
        assert "cannot toggle" in result["error"].lower()

    def test_no_subprocess_invoked(self, mocker):
        """Regression guard — toggle_startup_item must not shell out to PS."""
        _mock_scheduler_for_toggle(mocker)
        ps = mocker.patch("windesktopmgr.subprocess.run")
        wdm.toggle_startup_item("App", "task", True)
        assert ps.call_count == 0


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
        result = processes.get_memory_analysis()
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
        result = processes.get_memory_analysis()
        assert result["total_mb"] == 32768
        assert result["free_mb"] == 16000
        assert result["used_mb"] == 32768 - 16000

    def test_mcafee_detected(self, mocker):
        self._patch(mocker)
        result = processes.get_memory_analysis()
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
        result = processes.get_memory_analysis()
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
        result = processes.get_memory_analysis()
        breakdown = result.get("defender_processes", [])
        assert len(breakdown) == 2
        assert round(sum(p["mem"] for p in breakdown), 0) == result["defender_mb"]

    def test_accounting_note_present(self, mocker):
        self._patch(mocker)
        result = processes.get_memory_analysis()
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
        assert processes._categorise_process(process_name) == expected_category

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
        result = processes.get_memory_analysis()
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
        result = processes.get_memory_analysis()
        assert result["other_needs_audit"] is False

    def test_top_procs_sorted_by_mem_descending(self, mocker):
        self._patch(mocker)
        result = processes.get_memory_analysis()
        mems = [p["mem"] for p in result["top_procs"]]
        assert mems == sorted(mems, reverse=True)

    def test_virtual_memory_failure_returns_empty_dict(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", return_value=iter([]))
        mocker.patch("windesktopmgr.psutil.virtual_memory", side_effect=RuntimeError("boom"))
        result = processes.get_memory_analysis()
        assert result == {}

    def test_process_iter_failure_returns_empty_dict(self, mocker):
        mocker.patch("windesktopmgr.psutil.process_iter", side_effect=RuntimeError("boom"))
        result = processes.get_memory_analysis()
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
        result = processes.get_memory_analysis()
        # Chrome should still come through despite the dead process first.
        assert result["top_procs"][0]["name"] == "chrome"

    def test_uses_psutil_not_powershell(self, mocker):
        """Regression guard: no PS calls on this path after batch A."""
        ps_mock = mocker.patch("windesktopmgr.subprocess.run")
        self._patch(mocker)
        processes.get_memory_analysis()
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
# _query_event_log_xpath / _build_evt_xpath — win32evtlog helper (Batch F)
# ══════════════════════════════════════════════════════════════════════════════


class TestBuildEvtXpath:
    def test_no_filters_returns_wildcard(self):
        assert wdm._build_evt_xpath() == "*"

    def test_single_id(self):
        x = wdm._build_evt_xpath(ids=[41])
        assert x == "*[System[(EventID=41)]]"

    def test_multiple_ids_joined_by_or(self):
        x = wdm._build_evt_xpath(ids=[41, 1001, 6008])
        assert "EventID=41 or EventID=1001 or EventID=6008" in x

    def test_level_filter(self):
        x = wdm._build_evt_xpath(levels=[2])
        assert "Level=2" in x

    def test_provider_filter(self):
        x = wdm._build_evt_xpath(providers=["Microsoft-Windows-Kernel-Power"])
        assert "Provider[@Name='Microsoft-Windows-Kernel-Power']" in x

    def test_combined_filters_and_together(self):
        x = wdm._build_evt_xpath(ids=[41], levels=[2])
        # Filters are joined with ' and '
        assert " and " in x
        assert "EventID=41" in x
        assert "Level=2" in x

    def test_non_int_id_coerced(self):
        x = wdm._build_evt_xpath(ids=["41"])
        assert "EventID=41" in x


class TestQueryEventLogXpathHelper:
    """
    Tests for the win32evtlog-backed helper itself. Mocks ``win32evtlog.EvtQuery``,
    ``EvtNext``, and ``EvtFormatMessage`` — no real Windows event log access.
    """

    # Minimal EventXML that the helper parses
    _EVT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Kernel-Power" />
    <EventID>41</EventID>
    <Level>1</Level>
    <TimeCreated SystemTime="2026-04-15T12:00:00.0000000Z" />
  </System>
</Event>"""

    def test_returns_parsed_events_list(self, mocker):
        fake_evt = object()  # opaque handle — the helper treats it as pass-through
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        next_mock = mocker.patch(
            "windesktopmgr.win32evtlog.EvtNext",
            side_effect=[[fake_evt], []],  # 1 event, then empty batch
        )
        fmt_mock = mocker.patch(
            "windesktopmgr.win32evtlog.EvtFormatMessage",
            side_effect=[self._EVT_XML, "rendered-body-text"],
        )
        mocker.patch("windesktopmgr.win32evtlog.EvtOpenPublisherMetadata", return_value="PMETA")

        out = wdm._query_event_log_xpath("System", "*", max_events=10, timeout_s=5)
        assert len(out) == 1
        row = out[0]
        assert row["Id"] == 41
        assert row["ProviderName"] == "Microsoft-Windows-Kernel-Power"
        assert row["Level"] == 1
        assert row["TimeCreated"] == "2026-04-15T12:00:00.0000000Z"
        assert row["Message"] == "rendered-body-text"
        # First EvtFormatMessage call is for XML render; second is for message body
        assert fmt_mock.call_count == 2
        assert next_mock.call_count == 2

    def test_evtquery_failure_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", side_effect=Exception("access denied"))
        out = wdm._query_event_log_xpath("Security", "*", max_events=10, timeout_s=5)
        assert out == []

    def test_evtnext_failure_returns_partial(self, mocker):
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        mocker.patch("windesktopmgr.win32evtlog.EvtNext", side_effect=Exception("handle closed"))
        out = wdm._query_event_log_xpath("System", "*", max_events=10, timeout_s=5)
        assert out == []

    def test_empty_event_stream_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        mocker.patch("windesktopmgr.win32evtlog.EvtNext", return_value=[])
        out = wdm._query_event_log_xpath("System", "*", max_events=10, timeout_s=5)
        assert out == []

    def test_malformed_xml_is_skipped(self, mocker):
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        mocker.patch(
            "windesktopmgr.win32evtlog.EvtNext",
            side_effect=[[object(), object()], []],
        )
        # First event returns garbage XML, second returns valid — first should be skipped
        mocker.patch(
            "windesktopmgr.win32evtlog.EvtFormatMessage",
            side_effect=["not xml!!!", self._EVT_XML, "body"],
        )
        mocker.patch("windesktopmgr.win32evtlog.EvtOpenPublisherMetadata", return_value="PMETA")
        out = wdm._query_event_log_xpath("System", "*", max_events=10, timeout_s=5)
        assert len(out) == 1

    def test_publisher_metadata_failure_returns_empty_message(self, mocker):
        """If the provider has no message DLL, Message should be '' not crash."""
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        mocker.patch("windesktopmgr.win32evtlog.EvtNext", side_effect=[[object()], []])
        mocker.patch("windesktopmgr.win32evtlog.EvtFormatMessage", return_value=self._EVT_XML)
        mocker.patch(
            "windesktopmgr.win32evtlog.EvtOpenPublisherMetadata",
            side_effect=Exception("no metadata"),
        )
        out = wdm._query_event_log_xpath("System", "*", max_events=10, timeout_s=5)
        assert len(out) == 1
        assert out[0]["Message"] == ""

    def test_max_events_honoured(self, mocker):
        """Stop fetching once max_events events have been consumed."""
        mocker.patch("windesktopmgr.win32evtlog.EvtQuery", return_value="QHANDLE")
        # Each EvtNext returns 3 events; helper should stop after max_events=5
        batch = [object(), object(), object()]
        next_mock = mocker.patch(
            "windesktopmgr.win32evtlog.EvtNext",
            side_effect=[batch, batch, []],
        )
        # Each event needs 2 EvtFormatMessage calls (XML + body)
        mocker.patch(
            "windesktopmgr.win32evtlog.EvtFormatMessage",
            side_effect=[self._EVT_XML, "b"] * 10,
        )
        mocker.patch("windesktopmgr.win32evtlog.EvtOpenPublisherMetadata", return_value="PMETA")
        out = wdm._query_event_log_xpath("System", "*", max_events=5, timeout_s=5)
        # Helper pulled 2 batches of 3 = 6 events (slightly over-fetches, fine)
        # but must not exceed a reasonable bound
        assert len(out) <= 6
        assert next_mock.call_count >= 2


# ══════════════════════════════════════════════════════════════════════════════
# get_system_timeline
# ══════════════════════════════════════════════════════════════════════════════


class TestGetSystemTimeline:
    """
    Timeline pulls from 5 sources — BSOD, Windows Update history, services, boot, creds.

    After Batch F (win32evtlog migration), 4 of the 5 are routed through
    ``_query_event_log_xpath``. The Windows Update source is now an in-process
    call to ``get_update_history()`` (backlog #28 close-out) — no PowerShell
    subprocess anywhere in this function.

    Tests mock ``_query_event_log_xpath`` for the event-log sources and
    ``get_update_history`` directly for the update source.
    """

    _NOW = datetime.now(timezone.utc)
    _BSOD1 = (_NOW - timedelta(days=20)).isoformat()
    _BSOD2 = (_NOW - timedelta(days=15)).isoformat()
    _UPDATE = (_NOW - timedelta(days=18)).isoformat()

    # Helper-output shape: {Id, TimeCreated, ProviderName, Level, Message}
    BSOD_ROWS = [
        {
            "Id": 41,
            "TimeCreated": _BSOD1,
            "ProviderName": "Microsoft-Windows-Kernel-Power",
            "Level": 1,
            "Message": "The system has rebooted without cleanly shutting down first.",
        },
        {
            "Id": 1001,
            "TimeCreated": _BSOD2,
            "ProviderName": "Microsoft-Windows-WER-SystemErrorReporting",
            "Level": 2,
            "Message": "Problem signature: stop code 0x0000009F",
        },
    ]
    # get_update_history() shape: {Title, Date (ISO8601), ResultCode (int),
    # Categories, KB, result}. ResultCode 2 = succeeded; the timeline keeps
    # only succeeded installs.
    UPDATE_HISTORY = [
        {
            "Title": "2026-03 Cumulative Update (KB5055523)",
            "Date": _UPDATE,
            "ResultCode": 2,
            "Categories": "Security Updates",
            "KB": "KB5055523",
            "result": "Succeeded",
        },
    ]

    def _make_mock(self, mocker, bsod=None, upd=None, svc=None, boot=None, cred=None):
        """Mock the 4 event-log calls + the in-process get_update_history() call."""
        helper = mocker.patch("windesktopmgr._query_event_log_xpath")
        helper.side_effect = [
            bsod if bsod is not None else list(self.BSOD_ROWS),  # 1. BSOD
            svc if svc is not None else [],  # 3. services
            boot if boot is not None else [],  # 4. boot
            cred if cred is not None else [],  # 5. creds
        ]
        upd_hist = mocker.patch(
            "windesktopmgr.get_update_history",
            return_value=upd if upd is not None else list(self.UPDATE_HISTORY),
        )
        return helper, upd_hist

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
        old_event = [
            {
                "Id": 41,
                "TimeCreated": "2025-01-01T00:00:00+00:00",
                "ProviderName": "Microsoft-Windows-Kernel-Power",
                "Level": 1,
                "Message": "Old crash",
            },
        ]
        self._make_mock(mocker, bsod=old_event)
        result = wdm.get_system_timeline()
        bsods = [e for e in result if e["type"] == "bsod"]
        assert len(bsods) == 0

    def test_only_succeeded_updates_included(self, mocker):
        """ResultCode != 2 entries (failed / in-progress) are filtered out."""
        mixed = [
            dict(self.UPDATE_HISTORY[0]),  # ResultCode 2 — kept
            {
                "Title": "Failed Update (KB9999999)",
                "Date": self._UPDATE,
                "ResultCode": 4,  # Failed — dropped
                "Categories": "Security Updates",
                "KB": "KB9999999",
                "result": "Failed",
            },
        ]
        self._make_mock(mocker, upd=mixed)
        result = wdm.get_system_timeline()
        updates = [e for e in result if e["category"] == "update"]
        assert len(updates) == 1
        assert "KB5055523" in updates[0]["detail"]

    def test_all_sources_empty_returns_empty_list(self, mocker):
        helper = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        mocker.patch("windesktopmgr.get_update_history", return_value=[])
        result = wdm.get_system_timeline()
        assert result == []
        # Helper called 4 times: BSOD, services, boot, cred
        assert helper.call_count == 4

    def test_helper_error_on_one_source_does_not_crash(self, mocker):
        """If the BSOD helper call raises, we still get update events."""
        helper = mocker.patch("windesktopmgr._query_event_log_xpath")
        helper.side_effect = [
            RuntimeError("boom"),  # BSOD query fails
            [],  # services
            [],  # boot
            [],  # creds
        ]
        mocker.patch("windesktopmgr.get_update_history", return_value=list(self.UPDATE_HISTORY))
        result = wdm.get_system_timeline()
        updates = [e for e in result if e["type"] == "update"]
        assert len(updates) == 1

    def test_update_history_error_does_not_crash(self, mocker):
        """If get_update_history() raises, BSOD events still come through."""
        helper = mocker.patch("windesktopmgr._query_event_log_xpath")
        helper.side_effect = [list(self.BSOD_ROWS), [], [], []]
        mocker.patch("windesktopmgr.get_update_history", side_effect=RuntimeError("WUA cold"))
        result = wdm.get_system_timeline()
        bsods = [e for e in result if e["type"] == "bsod"]
        assert len(bsods) == 2

    # ── helper-call regression guards ────────────────────────────────────────

    def test_bsod_helper_queries_event_ids_41_1001_6008(self, mocker):
        helper, _ = self._make_mock(mocker)
        wdm.get_system_timeline()
        # 1st helper call is the BSOD query on System log with ids [41, 1001, 6008]
        args, kwargs = helper.call_args_list[0]
        assert args[0] == "System"
        xpath = args[1]
        for eid in ("41", "1001", "6008"):
            assert f"EventID={eid}" in xpath, f"missing EventID={eid} in xpath: {xpath}"

    def test_update_source_calls_get_update_history(self, mocker):
        _, upd_hist = self._make_mock(mocker)
        wdm.get_system_timeline()
        assert upd_hist.called

    def test_service_helper_queries_event_id_7036(self, mocker):
        helper, _ = self._make_mock(mocker)
        wdm.get_system_timeline()
        args, _ = helper.call_args_list[1]
        assert args[0] == "System"
        assert "EventID=7036" in args[1]

    def test_boot_helper_queries_event_id_6013(self, mocker):
        helper, _ = self._make_mock(mocker)
        wdm.get_system_timeline()
        args, _ = helper.call_args_list[2]
        assert args[0] == "System"
        assert "EventID=6013" in args[1]

    def test_no_powershell_anywhere(self, mocker):
        """Regression guard — the timeline must NOT invoke PowerShell at all."""
        self._make_mock(mocker)
        ps = mocker.patch("windesktopmgr.subprocess.run")
        wdm.get_system_timeline()
        assert ps.call_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# get_bsod_events (raw Event Log query)
# ══════════════════════════════════════════════════════════════════════════════


class TestGetBsodEvents:
    """After Batch F, get_bsod_events() goes through ``_query_event_log_xpath``."""

    HELPER_ROWS = [
        {
            "Id": 1001,
            "TimeCreated": "2026-03-10T08:00:00",
            "ProviderName": "Microsoft-Windows-WER-SystemErrorReporting",
            "Level": 2,
            "Message": "Problem signature: stop code HYPERVISOR_ERROR intelppm.sys",
        },
        {
            "Id": 41,
            "TimeCreated": "2026-03-10T07:59:00",
            "ProviderName": "Microsoft-Windows-Kernel-Power",
            "Level": 1,
            "Message": "The system has rebooted without cleanly shutting down first.",
        },
    ]

    def test_happy_path_returns_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=list(self.HELPER_ROWS))
        result = bsod.get_bsod_events()
        assert isinstance(result, list)

    def test_happy_path_returns_correct_count(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=list(self.HELPER_ROWS))
        result = bsod.get_bsod_events()
        assert len(result) == 2

    def test_happy_path_has_expected_fields(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=list(self.HELPER_ROWS))
        result = bsod.get_bsod_events()
        for item in result:
            # Legacy PS shape: EventId / TimeCreated / ProviderName / Message
            assert "EventId" in item
            assert "TimeCreated" in item
            assert "ProviderName" in item
            assert "Message" in item

    def test_helper_queries_correct_event_ids_and_log(self, mocker):
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        bsod.get_bsod_events()
        args, _ = m.call_args
        assert args[0] == "System"
        xpath = args[1]
        for eid in ("1001", "41", "6008"):
            assert f"EventID={eid}" in xpath, f"missing EventID={eid} in xpath: {xpath}"

    def test_empty_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        result = bsod.get_bsod_events()
        assert result == []

    def test_helper_exception_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", side_effect=RuntimeError("boom"))
        result = bsod.get_bsod_events()
        assert result == []

    def test_no_powershell_invoked(self, mocker):
        """Regression guard — get_bsod_events must not shell out to PS."""
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        ps = mocker.patch("windesktopmgr.subprocess.run")
        bsod.get_bsod_events()
        assert ps.call_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# get_startup_items — winreg + pathlib + Schedule.Service COM (no PowerShell)
# ══════════════════════════════════════════════════════════════════════════════


def _registry_enum_side_effect(entries_by_key):
    """Build a winreg.EnumValue side_effect callable.

    ``entries_by_key`` maps the mocked key object returned by ``OpenKey`` to
    a list of ``(name, value, regtype)`` tuples. Once each list is exhausted
    the function raises OSError, which signals "no more values" to the
    production loop.
    """
    state: dict = {id(k): 0 for k in entries_by_key}

    def _side(key, idx):
        entries = entries_by_key.get(key, [])
        i = state.get(id(key), 0)
        if i >= len(entries):
            raise OSError("end of values")
        state[id(key)] = i + 1
        return entries[i]

    return _side


def _build_fake_task(name, *, triggers=("logon",), path="C:\\App\\app.exe", args="", enabled=True):
    """Construct a fake Schedule.Service task COM object — only the
    attributes ``_walk_tasks_with_logon_or_boot`` actually reads."""
    _LOGON, _BOOT = 9, 8

    trig_items = []
    for t in triggers:
        if t == "logon":
            trig_items.append(types.SimpleNamespace(Type=_LOGON))
        elif t == "boot":
            trig_items.append(types.SimpleNamespace(Type=_BOOT))
        else:
            trig_items.append(types.SimpleNamespace(Type=99))  # not a startup trigger

    triggers_coll = types.SimpleNamespace(
        Count=len(trig_items),
        Item=lambda i: trig_items[i - 1],  # COM is 1-indexed
    )
    actions_coll = types.SimpleNamespace(
        Count=1,
        Item=lambda i: types.SimpleNamespace(Path=path, Arguments=args),
    )
    definition = types.SimpleNamespace(Triggers=triggers_coll, Actions=actions_coll)
    return types.SimpleNamespace(Name=name, Enabled=enabled, Definition=definition)


def _build_fake_folder(tasks, subfolders=()):
    """A fake Schedule.Service folder with ``GetTasks(1)``/``GetFolders(0)``."""
    folder = types.SimpleNamespace()
    folder.GetTasks = lambda flag: list(tasks)
    folder.GetFolders = lambda flag: list(subfolders)
    return folder


def _mock_startup_environment(
    mocker,
    *,
    registry_entries=None,
    folder_files=None,
    scheduler_root=None,
    raise_com=False,
):
    """All-in-one mocker for ``get_startup_items``.

    - ``registry_entries`` — dict keyed by (hive_const, subkey) → list of
      (name, value, regtype) tuples. Missing entries default to empty.
    - ``folder_files`` — dict keyed by env var ("ALLUSERSPROFILE" /
      "APPDATA") → list of pathlib.Path-like objects.
    - ``scheduler_root`` — fake folder for ``scheduler.GetFolder("\\")``;
      defaults to a folder with no tasks.
    - ``raise_com`` — make ``win32com.client.Dispatch`` raise.

    Also stubs ``get_startup_item_info`` so enrichment doesn't queue real
    background lookups during tests.
    """
    registry_entries = registry_entries or {}
    folder_files = folder_files or {}

    # ── winreg ───────────────────────────────────────────────────────────
    opened_keys: dict = {}

    def _open_key(hive, subkey, *_args, **_kw):
        entries = registry_entries.get((hive, subkey))
        if entries is None:
            # Run-Disabled keys that don't exist raise FileNotFoundError,
            # which production code swallows.
            raise FileNotFoundError(subkey)
        key_obj = mocker.MagicMock(name=f"key:{subkey}")
        opened_keys[key_obj] = entries
        return key_obj

    mocker.patch("windesktopmgr.winreg.OpenKey", side_effect=_open_key)
    mocker.patch(
        "windesktopmgr.winreg.EnumValue",
        side_effect=_registry_enum_side_effect(opened_keys),
    )
    mocker.patch("windesktopmgr.winreg.CloseKey")

    # ── environment + pathlib for the Startup folder paths ───────────────
    env = {k: f"C:\\fake\\{k}" for k in folder_files}
    mocker.patch.dict("windesktopmgr.os.environ", env, clear=False)

    from pathlib import Path

    def _iterdir(self):
        # Map this Path back to whichever env var its prefix mentions.
        s = str(self)
        for env_var, files in folder_files.items():
            if env_var in s:
                return iter(files)
        raise FileNotFoundError(s)

    mocker.patch.object(Path, "iterdir", _iterdir)

    # ── Schedule.Service COM ─────────────────────────────────────────────
    mocker.patch("windesktopmgr.pythoncom.CoInitialize")
    if raise_com:
        mocker.patch(
            "windesktopmgr.win32com.client.Dispatch",
            side_effect=Exception("COM error"),
        )
    else:
        scheduler = mocker.MagicMock()
        scheduler.GetFolder.return_value = scheduler_root or _build_fake_folder([])
        mocker.patch(
            "windesktopmgr.win32com.client.Dispatch",
            return_value=scheduler,
        )

    # ── enrichment side-effect short-circuit ────────────────────────────
    mocker.patch("windesktopmgr.get_startup_item_info", return_value=None)


_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_DIS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run-Disabled"


def _fake_file(name, full_path):
    """A pathlib.Path-like object good enough for the Startup-folder loop."""
    p = types.SimpleNamespace(
        stem=name,
        is_file=lambda: True,
    )
    p.__str__ = lambda: full_path  # type: ignore[attr-defined]
    # str(entry) is used in the producer
    return _StrPath(name, full_path)


class _StrPath:
    """Minimal pathlib.Path stand-in supporting ``stem``, ``is_file()`` and
    ``str(p)`` — the only surface ``get_startup_items`` touches."""

    def __init__(self, stem, full):
        self.stem = stem
        self._full = full

    def is_file(self):
        return True

    def __str__(self):
        return self._full


class TestGetStartupItems:
    HKLM = None  # filled in lazily in setup so we use the real winreg constants
    HKCU = None

    def _hives(self):
        return wdm.winreg.HKEY_LOCAL_MACHINE, wdm.winreg.HKEY_CURRENT_USER

    def test_returns_list(self, mocker):
        hklm, hkcu = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={
                (hklm, _RUN): [("OneDrive", r"C:\Program Files\OneDrive.exe /bg", 1)],
                (hkcu, _RUN): [],
            },
        )
        result = wdm.get_startup_items()
        assert isinstance(result, list)
        assert any(i["Name"] == "OneDrive" for i in result)

    def test_items_have_required_fields(self, mocker):
        hklm, _ = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hklm, _RUN): [("Foo", "foo.exe", 1)]},
        )
        result = wdm.get_startup_items()
        for item in result:
            for field in ("Name", "Command", "Location", "Type", "Enabled"):
                assert field in item

    def test_empty_everything_returns_empty_list(self, mocker):
        _mock_startup_environment(mocker)
        result = wdm.get_startup_items()
        assert result == []

    def test_registry_hklm_run_emitted(self, mocker):
        hklm, _ = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hklm, _RUN): [("HKLMApp", "hklm.exe", 1)]},
        )
        result = wdm.get_startup_items()
        match = [i for i in result if i["Name"] == "HKLMApp"]
        assert match
        assert match[0]["Type"] == "registry_hklm"
        assert match[0]["Enabled"] is True
        assert match[0]["Command"] == "hklm.exe"

    def test_registry_hkcu_run_emitted(self, mocker):
        _, hkcu = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hkcu, _RUN): [("HKCUApp", "hkcu.exe", 1)]},
        )
        result = wdm.get_startup_items()
        match = [i for i in result if i["Name"] == "HKCUApp"]
        assert match
        assert match[0]["Type"] == "registry_hkcu"

    def test_run_disabled_marked_disabled(self, mocker):
        hklm, _ = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hklm, _DIS): [("DisabledApp", "dis.exe", 1)]},
        )
        result = wdm.get_startup_items()
        match = [i for i in result if i["Name"] == "DisabledApp"]
        assert match
        assert match[0]["Enabled"] is False

    def test_missing_run_disabled_key_does_not_crash(self, mocker):
        """Run-Disabled often doesn't exist on a clean box — FileNotFoundError
        must be swallowed."""
        # No registry entries supplied → every OpenKey raises FileNotFoundError
        _mock_startup_environment(mocker)
        result = wdm.get_startup_items()
        assert result == []

    def test_startup_folder_items_emitted(self, mocker):
        files = [_StrPath("Notepad", r"C:\fake\APPDATA\...\Notepad.lnk")]
        _mock_startup_environment(mocker, folder_files={"APPDATA": files})
        result = wdm.get_startup_items()
        match = [i for i in result if i["Name"] == "Notepad"]
        assert match
        assert match[0]["Type"] == "folder"
        assert match[0]["Enabled"] is True

    def test_scheduled_task_with_logon_trigger_emitted(self, mocker):
        task = _build_fake_task(
            "EdgeAutoLaunch",
            triggers=("logon",),
            path=r"C:\Program Files\Edge\msedge.exe",
            args="--auto-launch",
        )
        root = _build_fake_folder([task])
        _mock_startup_environment(mocker, scheduler_root=root)
        result = wdm.get_startup_items()
        match = [i for i in result if i["Name"] == "EdgeAutoLaunch"]
        assert match
        assert match[0]["Type"] == "task"
        assert match[0]["Location"] == "Task Scheduler"
        assert "msedge.exe" in match[0]["Command"]
        assert "--auto-launch" in match[0]["Command"]

    def test_scheduled_task_with_boot_trigger_emitted(self, mocker):
        task = _build_fake_task("BootSvc", triggers=("boot",))
        _mock_startup_environment(mocker, scheduler_root=_build_fake_folder([task]))
        result = wdm.get_startup_items()
        assert any(i["Name"] == "BootSvc" for i in result)

    def test_scheduled_task_without_logon_or_boot_filtered(self, mocker):
        """Tasks with no Logon/Boot trigger must NOT appear."""
        task = _build_fake_task("HourlyTask", triggers=("other",))
        _mock_startup_environment(mocker, scheduler_root=_build_fake_folder([task]))
        result = wdm.get_startup_items()
        assert not [i for i in result if i["Name"] == "HourlyTask"]

    def test_scheduled_task_recursion_into_subfolders(self, mocker):
        """``_walk_tasks_with_logon_or_boot`` must recurse into sub-folders."""
        nested = _build_fake_task("NestedTask", triggers=("logon",))
        sub = _build_fake_folder([nested])
        root = _build_fake_folder([], subfolders=[sub])
        _mock_startup_environment(mocker, scheduler_root=root)
        result = wdm.get_startup_items()
        assert any(i["Name"] == "NestedTask" for i in result)

    def test_scheduler_exception_swallowed(self, mocker):
        """If Schedule.Service Dispatch raises, the registry/folder items
        still come through and nothing crashes."""
        hklm, _ = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hklm, _RUN): [("Reg1", "r.exe", 1)]},
            raise_com=True,
        )
        result = wdm.get_startup_items()
        assert any(i["Name"] == "Reg1" for i in result)

    def test_no_subprocess_invoked(self, mocker):
        """Regression guard — get_startup_items must not shell out to PS."""
        _mock_startup_environment(mocker)
        ps = mocker.patch("windesktopmgr.subprocess.run")
        wdm.get_startup_items()
        assert ps.call_count == 0

    def test_suspicious_flag_added(self, mocker):
        """The enrichment loop should add a ``suspicious`` bool to every item."""
        hklm, _ = self._hives()
        _mock_startup_environment(
            mocker,
            registry_entries={(hklm, _RUN): [("App", "app.exe", 1)]},
        )
        result = wdm.get_startup_items()
        assert all("suspicious" in i for i in result)
        assert all(isinstance(i["suspicious"], bool) for i in result)


# ══════════════════════════════════════════════════════════════════════════════
# query_event_log — PowerShell event log queries
# ══════════════════════════════════════════════════════════════════════════════


class TestQueryEventLog:
    """After Batch F, query_event_log() goes through ``_query_event_log_xpath``."""

    HELPER_ROWS = [
        {
            "Id": 7036,
            "TimeCreated": "2026-03-10T08:00:00",
            "ProviderName": "Service Control Manager",
            "Level": 4,
            "Message": "The Windows Update service entered the stopped state.",
        },
        {
            "Id": 1001,
            "TimeCreated": "2026-03-10T07:55:00",
            "ProviderName": "Microsoft-Windows-WER-SystemErrorReporting",
            "Level": 2,
            "Message": "The computer has rebooted from a bugcheck.",
        },
    ]

    def test_happy_path_returns_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=list(self.HELPER_ROWS))
        result = events.query_event_log({"log": "System"})
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["Id"] == 7036
        # Legacy output keys preserved: Time / Id / Level / Source / Message
        assert "Time" in result[0]
        assert "Source" in result[0]
        assert result[0]["Level"] == "Information"
        assert result[1]["Level"] == "Error"

    def test_empty_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        result = events.query_event_log({"log": "System"})
        assert result == []

    def test_helper_exception_returns_empty_list(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", side_effect=RuntimeError("boom"))
        result = events.query_event_log({"log": "System"})
        assert result == []

    def test_helper_called_with_log_name(self, mocker):
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": "Application"})
        assert m.call_args[0][0] == "Application"

    def test_level_filter_passed_as_xpath(self, mocker):
        """When caller passes level='Error', helper must receive xpath with Level=2."""
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": "System", "level": "Error"})
        xpath = m.call_args[0][1]
        assert "Level=2" in xpath

    def test_no_level_filter_uses_wildcard_xpath(self, mocker):
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": "System"})
        xpath = m.call_args[0][1]
        assert xpath == "*"

    def test_max_events_honoured(self, mocker):
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": "System", "max": 25})
        assert m.call_args.kwargs.get("max_events") == 25

    def test_max_events_capped_at_500(self, mocker):
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": "System", "max": 9999})
        assert m.call_args.kwargs.get("max_events") == 500

    def test_input_sanitization(self, mocker):
        """Log name is still sanitised with re.sub(r'[^\\w\\s\\-/]', '', log)."""
        m = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        events.query_event_log({"log": '"; rm -rf /'})
        safe = m.call_args[0][0]
        assert '";' not in safe
        assert "rm -rf" in safe  # letters/spaces survive, but dangerous chars don't

    def test_search_filter_applied_to_result(self, mocker):
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=list(self.HELPER_ROWS))
        result = events.query_event_log({"log": "System", "search": "bugcheck"})
        assert len(result) == 1
        assert result[0]["Id"] == 1001

    def test_message_truncated_to_300_chars(self, mocker):
        long_msg = "x" * 500
        mocker.patch(
            "windesktopmgr._query_event_log_xpath",
            return_value=[
                {
                    "Id": 1,
                    "TimeCreated": "t",
                    "ProviderName": "p",
                    "Level": 4,
                    "Message": long_msg,
                }
            ],
        )
        result = events.query_event_log({"log": "System"})
        assert len(result[0]["Message"]) == 300

    def test_no_powershell_invoked(self, mocker):
        """Regression guard — query_event_log must not shell out to PS."""
        mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        ps = mocker.patch("windesktopmgr.subprocess.run")
        events.query_event_log({"log": "System"})
        assert ps.call_count == 0


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

        mock_queue = mocker.patch("bsod._bsod_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            bsod._bsod_lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_event_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("events._lookup_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            events._lookup_worker()
        except KeyboardInterrupt:
            pass
        mock_queue.task_done.assert_not_called()

    def test_process_worker_no_task_done_on_empty(self, mocker):
        import queue as q

        mock_queue = mocker.patch("processes._process_queue")
        mock_queue.get.side_effect = [q.Empty, KeyboardInterrupt]
        try:
            processes._process_lookup_worker()
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
    """Tests for check_dell_bios_update — DCU method calls dcu-cli.exe directly
    (Batch D); the catalog method is pure Python (urllib + expand.exe + ET parse,
    backlog #28 close-out); Method-3 WU reuses get_windows_update_drivers()
    (in-process win32com, Batch G)."""

    # Sample XML that matches the BIOS version regex in the DCU parser
    DCU_XML_TEMPLATE = '<update type="BIOS" name="BIOS Update" version="{ver}"/>'

    # Minimal catalog XML matching the production parser's case-insensitive
    # lookups: SoftwareComponent + ComponentType=BIOS + Model name *8960*.
    CATALOG_XML_8960 = """<Manifest xmlns="openmanage/cm/dm">
  <SoftwareComponent releaseDate="2026-01-15" dellVersion="2.23.0" path="FOLDER01/bios.exe">
    <Name><Display>XPS 8960 BIOS Update</Display></Name>
    <ComponentType value="BIOS" />
    <SupportedSystems>
      <Brand>
        <Model name="XPS 8960" systemID="0BC0" />
      </Brand>
    </SupportedSystems>
  </SoftwareComponent>
</Manifest>"""

    # An empty catalog (no SoftwareComponent matches) — exercises the
    # "catalog ran fine, found nothing" branch.
    CATALOG_XML_EMPTY = '<Manifest xmlns="openmanage/cm/dm"></Manifest>'

    def _mock_deps(
        self,
        mocker,
        tmp_path,
        *,
        dcu_xml=None,
        catalog_xml=None,
        catalog_fail=False,
        wu_drivers=None,
        service_tag="9T46D14",
    ):
        """Mock WMI, filesystem, the catalog HTTP+CAB+ET path, and the WU COM layer.

        Args:
            dcu_xml: XML for the DCU scan output. None = DCU not installed.
            catalog_xml: Catalog XML string to feed the ET.parse mock. If both
                this and ``catalog_fail`` are unset, defaults to CATALOG_XML_EMPTY
                so the catalog runs but matches nothing.
            catalog_fail: If True, make urlopen raise ``URLError`` — exercises the
                "download failed" branch (Catalog never produces a result).
            wu_drivers: dict returned by get_windows_update_drivers() for the
                Method-3 WU check ({} = no WU updates, the default).
            service_tag: Win32_BIOS.SerialNumber returned by the WMI mock.

        Returns:
            The ``subprocess.run`` mock so call_args_list can be inspected for
            DCU/expand.exe arguments.
        """
        import urllib.error
        import xml.etree.ElementTree as ET

        mocker.patch("bios.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber=service_tag)]})
        # Method 3 reuses get_windows_update_drivers() — mock it directly
        # rather than feeding a PowerShell response.
        mocker.patch(
            "windesktopmgr.get_windows_update_drivers",
            return_value=wu_drivers if wu_drivers is not None else {},
        )

        # ── Method 2 mocks: urllib download + ET.parse ─────────────────────
        # The production code does ``import urllib.request`` and ``import xml
        # .etree.ElementTree as ET`` LOCALLY inside check_dell_bios_update. A
        # local import just rebinds to the module already cached in
        # sys.modules, so patching the module's own attribute works fine.
        if catalog_fail:
            mocker.patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("dns"),
            )
        else:
            fake_resp = mocker.MagicMock()
            fake_resp.__enter__ = mocker.MagicMock(return_value=fake_resp)
            fake_resp.__exit__ = mocker.MagicMock(return_value=False)
            fake_resp.read.return_value = b"FAKE_CAB"
            mocker.patch("urllib.request.urlopen", return_value=fake_resp)
            xml_blob = catalog_xml if catalog_xml is not None else self.CATALOG_XML_EMPTY
            tree = ET.ElementTree(ET.fromstring(xml_blob))  # noqa: S314 — test fixture, inline literal
            mocker.patch("xml.etree.ElementTree.parse", return_value=tree)

        _real_exists = os.path.exists
        run_responses = []

        if dcu_xml is not None:
            # Pre-create the scan output file with known content
            scan_file = tmp_path / "dcu_scan_00000000.xml"
            scan_file.write_text(dcu_xml, encoding="utf-8")
            mocker.patch("tempfile.gettempdir", return_value=str(tmp_path))
            mocker.patch("uuid.uuid4", return_value=type("U", (), {"hex": "00000000"})())

            mocker.patch("os.path.exists", side_effect=lambda p: True if "CommandUpdate" in str(p) else _real_exists(p))

            # DCU exe subprocess call (direct, not PS)
            run_responses.append(type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})())
        else:
            mocker.patch(
                "os.path.exists", side_effect=lambda p: False if "CommandUpdate" in str(p) else _real_exists(p)
            )

        # The catalog path still spawns ONE subprocess: expand.exe (Windows OS
        # tool, not PowerShell). Mock it as a no-op success.
        if not catalog_fail:
            run_responses.append(type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})())

        m = mocker.patch("windesktopmgr.subprocess.run")
        if run_responses:
            m.side_effect = run_responses
        else:
            m.return_value = type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})()
        return m

    def test_returns_required_keys(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path)
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
        """Method 1 misses, Method 2 (catalog XML) finds the XPS 8960 BIOS."""
        self._mock_deps(mocker, tmp_path, catalog_xml=self.CATALOG_XML_8960)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "dell_catalog"
        assert result["latest_version"] == "2.23.0"
        assert result["latest_date"] == "2026-01-15"
        assert result["download_url"] == "https://downloads.dell.com/FOLDER01/bios.exe"
        assert "XPS 8960 BIOS Update" in result["release_notes"]

    def test_wu_fallback(self, mocker, tmp_path):
        """Methods 1 & 2 miss; Method 3 reuses get_windows_update_drivers()
        and picks a BIOS/Firmware update out of the WU driver list."""
        self._mock_deps(
            mocker,
            tmp_path,
            wu_drivers={"dell bios update 2.24.0": {"Title": "Dell BIOS Update 2.24.0"}},
        )
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "windows_update"
        assert result["update_available"] is True
        assert result["latest_version"] == "2.24.0"

    def test_all_methods_fail_returns_unknown(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["source"] == "unknown"
        assert result["latest_version"] is None

    def test_service_tag_populated(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, service_tag="ABC1234")
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["service_tag"] == "ABC1234"
        assert "ABC1234" in result["download_url"]

    def test_service_tag_empty_fallback_url(self, mocker, tmp_path):
        self._mock_deps(mocker, tmp_path, service_tag="")
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
        mocker.patch("bios.BIOS_CACHE_FILE", str(cache_file))
        m = mocker.patch("windesktopmgr.subprocess.run")
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        m.assert_not_called()
        assert result["source"] == "dell_catalog"

    def test_subprocess_timeout_handled(self, mocker, tmp_path):
        """The catalog HTTP download fails (URLError) and the WU check finds
        nothing — returns unknown without crashing. After the backlog #28
        migration the catalog path is no longer a PowerShell subprocess, so
        the failure surface that used to be ``TimeoutExpired`` is now a
        urllib error on the urlopen call."""
        self._mock_deps(mocker, tmp_path, catalog_fail=True)
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
    """Fans now come from wmi.WMI().Win32_Fan() — no PowerShell. Asserts the
    Win32_Fan WMI class is queried and its data flows into the result."""

    def test_fans_query_uses_win32_fan(self, mocker):
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        fan = _wmi_obj(Name="System Fan", ActiveCooling=True, DesiredSpeed=2400)
        default_conn = mocker.MagicMock()
        default_conn.Win32_Fan = mocker.MagicMock(return_value=[fan])
        _mock_wmi_by_namespace(
            mocker,
            {
                "root\\wmi": {"MSAcpi_ThermalZoneTemperature": []},
                "root\\OpenHardwareMonitor": {"Sensor": []},
                "root\\LibreHardwareMonitor": {"Sensor": []},
                "": {"Win32_Fan": [fan]},
            },
        )
        mocker.patch("windesktopmgr.psutil.cpu_percent", return_value=5.0)
        vm = types.SimpleNamespace(total=8 * 1024 * 1024 * 1024, available=4 * 1024 * 1024 * 1024)
        mocker.patch("windesktopmgr.psutil.virtual_memory", return_value=vm)
        mocker.patch("windesktopmgr.psutil.sensors_battery", return_value=None)
        result = wdm.get_thermals()
        assert result["fans"] == [{"Name": "System Fan", "ActiveCooling": True, "DesiredSpeed": 2400}]


class TestGetSystemTimelineCredHelperCall:
    """
    Helper-call tests for credential events query (4th ``_query_event_log_xpath``
    call in the timeline). After Batch F this goes through the win32evtlog helper,
    not PowerShell.
    """

    def _make_mock(self, mocker):
        helper = mocker.patch("windesktopmgr._query_event_log_xpath", return_value=[])
        mocker.patch("windesktopmgr.get_update_history", return_value=[])
        return helper

    def test_cred_helper_queries_event_ids_4625_and_4648(self, mocker):
        helper = self._make_mock(mocker)
        wdm.get_system_timeline()
        # helper calls: [0] BSOD [1] services [2] boot [3] creds
        args, _ = helper.call_args_list[3]
        xpath = args[1]
        assert "EventID=4625" in xpath
        assert "EventID=4648" in xpath

    def test_cred_helper_queries_security_log(self, mocker):
        helper = self._make_mock(mocker)
        wdm.get_system_timeline()
        args, _ = helper.call_args_list[3]
        assert args[0] == "Security"


class TestCheckDellBiosCommandContent:
    """Command-content tests for check_dell_bios_update.
    DCU calls dcu-cli.exe directly (Batch D); after backlog #28 the catalog
    path is pure Python (urllib + expand.exe + ET parse) — NOT PowerShell;
    the WU check reuses get_windows_update_drivers() (win32com, Batch G)."""

    EMPTY_CATALOG_XML = '<Manifest xmlns="openmanage/cm/dm"></Manifest>'

    def _mock_no_dcu(self, mocker, tmp_path):
        """Mock deps with DCU not installed.

        After backlog #28 the catalog path is NOT a PS subprocess — it's
        ``urllib.request.urlopen`` (downloads CatalogPC.cab), one ``expand.exe``
        subprocess, and ``xml.etree.ElementTree.parse``. Mock all three so the
        catalog branch runs end-to-end without hitting the network and finds
        no matching SoftwareComponent.

        Returns:
            A dict with ``urlopen``, ``et_parse``, and ``subprocess_run`` mocks
            so call_args_list can be inspected.
        """
        import xml.etree.ElementTree as ET

        _real_exists = os.path.exists
        mocker.patch("bios.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber="9T46D14")]})
        mocker.patch("windesktopmgr.get_windows_update_drivers", return_value={})
        mocker.patch("os.path.exists", side_effect=lambda p: False if "CommandUpdate" in str(p) else _real_exists(p))

        # Fake CAB download — content doesn't need to be a real CAB because
        # expand.exe is also mocked.
        fake_resp = mocker.MagicMock()
        fake_resp.__enter__ = mocker.MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = mocker.MagicMock(return_value=False)
        fake_resp.read.return_value = b"FAKE_CAB"
        urlopen_mock = mocker.patch("urllib.request.urlopen", return_value=fake_resp)

        # ET.parse → minimal in-memory tree with no SoftwareComponents.
        tree = ET.ElementTree(ET.fromstring(self.EMPTY_CATALOG_XML))  # noqa: S314 — test fixture
        et_parse_mock = mocker.patch("xml.etree.ElementTree.parse", return_value=tree)

        # The only subprocess in the catalog path is expand.exe.
        sub_mock = mocker.patch("windesktopmgr.subprocess.run")
        sub_mock.return_value = type("R", (), {"stdout": "", "returncode": 0, "stderr": ""})()
        return {"urlopen": urlopen_mock, "et_parse": et_parse_mock, "subprocess_run": sub_mock}

    def test_service_tag_from_wmi(self, mocker, tmp_path):
        """Service tag comes from wmi.WMI().Win32_BIOS(), not subprocess."""
        self._mock_no_dcu(mocker, tmp_path)
        result = wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert result["service_tag"] == "9T46D14"

    def test_catalog_command_references_dell_downloads(self, mocker, tmp_path):
        """After backlog #28 the catalog download is urllib, not a PS heredoc.
        Assert urlopen was called with a Request whose URL points at the
        canonical Dell catalog endpoint."""
        mocks = self._mock_no_dcu(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        assert mocks["urlopen"].called, "urlopen should be called to fetch CatalogPC.cab"
        # First positional arg may be a string URL or a urllib Request object.
        first_arg = mocks["urlopen"].call_args_list[0][0][0]
        url = first_arg.full_url if hasattr(first_arg, "full_url") else first_arg
        assert "downloads.dell.com/catalog/CatalogPC.cab" in url

    def test_catalog_uses_expand_exe_not_powershell(self, mocker, tmp_path):
        """Regression for backlog #28 close-out: the catalog path's only
        subprocess is expand.exe — no PowerShell process is ever spawned by
        check_dell_bios_update."""
        mocks = self._mock_no_dcu(mocker, tmp_path)
        wdm.check_dell_bios_update("XPS8960", "2.22.0")
        # Exactly one subprocess call (expand.exe). DCU is absent, catalog is
        # the only remaining subprocess in the flow.
        assert mocks["subprocess_run"].call_count >= 1
        for call in mocks["subprocess_run"].call_args_list:
            cmd = call[0][0]
            assert cmd[0].lower().endswith("expand.exe"), f"unexpected subprocess: {cmd!r}"
            # Sanity: no PS anywhere in the arg list.
            for piece in cmd:
                assert "powershell" not in str(piece).lower()

    def test_dcu_calls_exe_not_powershell(self, mocker, tmp_path):
        """Regression: Batch D — DCU uses direct exe, no PS wrapper."""
        _real_exists = os.path.exists
        mocker.patch("bios.BIOS_CACHE_FILE", str(tmp_path / "bios.json"))
        _mock_wmi(mocker, {"Win32_BIOS": [_wmi_obj(SerialNumber="9T46D14")]})
        # DCU exe "exists"
        mocker.patch("os.path.exists", side_effect=lambda p: True if "CommandUpdate" in str(p) else _real_exists(p))
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
    """fix_fast_startup() — winreg HiberbootEnabled toggle, no PowerShell."""

    def _mock_winreg(self, mocker, fail=None):
        """Patch winreg for fix_fast_startup. fail = exception OpenKey raises."""
        mocker.patch("windesktopmgr.winreg.CloseKey")
        if fail is not None:
            mocker.patch("windesktopmgr.winreg.OpenKey", side_effect=fail)
        else:
            mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.winreg.SetValueEx")

    def test_disable_returns_ok_true(self, mocker):
        self._mock_winreg(mocker)
        result = wdm.fix_fast_startup(False)
        assert result["ok"] is True
        assert result["enabled"] is False

    def test_enable_returns_ok_true(self, mocker):
        self._mock_winreg(mocker)
        result = wdm.fix_fast_startup(True)
        assert result["ok"] is True
        assert result["enabled"] is True

    def test_disable_writes_hiberboot_value_zero(self, mocker):
        self._mock_winreg(mocker)
        wdm.fix_fast_startup(False)
        # SetValueEx(key, name, reserved, type, value)
        args = wdm.winreg.SetValueEx.call_args[0]
        assert args[1] == "HiberbootEnabled"
        assert args[4] == 0

    def test_enable_writes_hiberboot_value_one(self, mocker):
        self._mock_winreg(mocker)
        wdm.fix_fast_startup(True)
        args = wdm.winreg.SetValueEx.call_args[0]
        assert args[1] == "HiberbootEnabled"
        assert args[4] == 1

    def test_uses_session_manager_power_key(self, mocker):
        self._mock_winreg(mocker)
        wdm.fix_fast_startup(False)
        subkey = wdm.winreg.OpenKey.call_args[0][1]
        assert subkey.endswith(r"Session Manager\Power")

    def test_permission_error_returns_ok_false(self, mocker):
        """A non-elevated process can't write HKLM — surface it, don't crash."""
        self._mock_winreg(mocker, fail=PermissionError("Access is denied"))
        result = wdm.fix_fast_startup(False)
        assert result["ok"] is False
        assert "denied" in result["message"].lower()

    def test_registry_error_returns_ok_false(self, mocker):
        self._mock_winreg(mocker, fail=OSError("cannot open key"))
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
        result = events._lookup_via_windows_provider(41, "Microsoft-Windows-Kernel-Power")
        assert result is not None
        for key in ("source", "title", "detail", "fetched"):
            assert key in result

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = events._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_malformed_json_returns_none(self, mocker):
        _mock_run(mocker, stdout="<error/>")
        result = events._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 20))
        result = events._lookup_via_windows_provider(41, "Kernel-Power")
        assert result is None

    def test_command_contains_event_id(self, mocker):
        m = _mock_run(mocker, stdout=self.SAMPLE)
        events._lookup_via_windows_provider(41, "Kernel-Power")
        cmd = m.call_args[0][0][-1]
        assert "41" in cmd

    def test_command_contains_sanitized_source(self, mocker):
        m = _mock_run(mocker, stdout="")
        events._lookup_via_windows_provider(41, "Kernel-Power")
        cmd = m.call_args[0][0][-1]
        assert "Kernel-Power" in cmd

    def test_source_injection_semicolons_stripped(self, mocker):
        """safe_source = re.sub(r"[^\\w \\-]", "", source) strips ; and \\ but keeps words."""
        m = _mock_run(mocker, stdout="")
        events._lookup_via_windows_provider(41, "Kernel;Drop-DB")
        cmd = m.call_args[0][0][-1]
        # Semicolons and special chars are stripped
        assert ";" not in cmd
        # Letters survive sanitization
        assert "Kernel" in cmd

    def test_empty_description_returns_none(self, mocker):
        no_desc = json.dumps({"Provider": "SomeProvider", "Id": 41, "Description": "", "Level": 2, "Keywords": ""})
        _mock_run(mocker, stdout=no_desc)
        result = events._lookup_via_windows_provider(41, "SomeProvider")
        assert result is None


class TestLookupStartupViaFileinfo:
    """_lookup_startup_via_fileinfo() is fully in-process (backlog #28):
    exe path resolution via shutil.which, version info via the _exe_version_info
    helper (win32api.GetFileVersionInfo). Tests mock those two — no PowerShell."""

    FILE_INFO = {
        "FileDescription": "Microsoft OneDrive",
        "CompanyName": "Microsoft Corporation",
        "ProductName": "Microsoft OneDrive",
        "FileVersion": "25.001.0112.0001",
    }

    def test_happy_path_returns_enrichment(self, mocker):
        mocker.patch("windesktopmgr._exe_version_info", return_value=dict(self.FILE_INFO))
        result = wdm._lookup_startup_via_fileinfo(
            r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', "OneDrive"
        )
        assert result is not None
        assert result["publisher"] == "Microsoft Corporation"

    def test_exe_path_passed_to_version_info(self, mocker):
        info = mocker.patch("windesktopmgr._exe_version_info", return_value=dict(self.FILE_INFO))
        wdm._lookup_startup_via_fileinfo(r'"C:\Windows\system32\notepad.exe"', "Notepad")
        # The quoted exe path is extracted from the command and read directly.
        path = info.call_args[0][0]
        assert "notepad.exe" in path.lower()

    def test_no_exe_path_resolves_via_shutil_which(self, mocker):
        which = mocker.patch("windesktopmgr.shutil.which", return_value=None)
        result = wdm._lookup_startup_via_fileinfo("somename", "somename")
        assert result is None
        # shutil.which replaces the old Get-Command PS call for bare names.
        assert which.called

    def test_empty_version_info_returns_none(self, mocker):
        mocker.patch("windesktopmgr._exe_version_info", return_value={})
        result = wdm._lookup_startup_via_fileinfo(r'"C:\Program Files\App\app.exe"', "App")
        assert result is None

    def test_which_failure_returns_none(self, mocker):
        mocker.patch("windesktopmgr.shutil.which", side_effect=OSError("PATH error"))
        result = wdm._lookup_startup_via_fileinfo("someapp", "App")
        assert result is None

    def test_empty_desc_and_company_returns_none(self, mocker):
        empty = {"FileDescription": "", "CompanyName": "", "ProductName": "", "FileVersion": "1.0"}
        mocker.patch("windesktopmgr._exe_version_info", return_value=empty)
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
        result = processes._lookup_process_via_fileinfo(
            "chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )
        assert result is not None
        assert result["publisher"] == "Google LLC"
        assert result["source"] == "file_version_info"
        assert result["plain"] == "Google Chrome"

    def test_no_path_triggers_shutil_which(self, mocker):
        """When no path is given, shutil.which() is used to find the exe."""
        m = mocker.patch("windesktopmgr.shutil.which", return_value=None)
        result = processes._lookup_process_via_fileinfo("unknownapp", "")
        assert result is None
        # Should have tried both with and without .exe suffix
        assert m.call_count >= 1
        first_call = m.call_args_list[0][0][0]
        assert "unknownapp" in first_call

    def test_empty_proc_name_returns_none(self, mocker):
        """Guard against empty proc_name."""
        m = mocker.patch("windesktopmgr.shutil.which")
        result = processes._lookup_process_via_fileinfo("", "")
        assert result is None
        assert m.call_count == 0  # should never call which with empty name

    def test_shutil_which_finds_exe_then_reads_version(self, mocker):
        """shutil.which resolves path, then win32api reads version info."""
        mocker.patch(
            "windesktopmgr.shutil.which", return_value=r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )
        self._mock_fileinfo(mocker)
        result = processes._lookup_process_via_fileinfo("chrome", "")
        assert result is not None
        assert result["publisher"] == "Google LLC"

    def test_system_path_marks_safe_kill_false(self, mocker):
        self._mock_fileinfo(
            mocker, desc="Windows Explorer", company="Microsoft Corporation", product="Microsoft Windows"
        )
        result = processes._lookup_process_via_fileinfo("explorer", r"C:\Windows\explorer.exe")
        assert result is not None
        assert result["safe_kill"] is False

    def test_non_system_path_marks_safe_kill_true(self, mocker):
        self._mock_fileinfo(mocker)
        result = processes._lookup_process_via_fileinfo(
            "chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )
        assert result["safe_kill"] is True

    def test_empty_desc_and_company_returns_none(self, mocker):
        self._mock_fileinfo(mocker, desc="", company="", product="")
        result = processes._lookup_process_via_fileinfo("mystery", r"C:\mystery.exe")
        assert result is None

    def test_exception_returns_none(self, mocker):
        mocker.patch("windesktopmgr.win32api.GetFileVersionInfo", side_effect=Exception("file not found"))
        result = processes._lookup_process_via_fileinfo(
            "chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )
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
    """warranty_data() — CPU/BIOS/system from wmi.WMI(), microcode from winreg,
    BSOD/WHEA/KP41 counts from the win32evtlog event-log API (no subprocess)."""

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
        # Microcode — winreg HKLM\...\CentralProcessor\0 'Update Revision'.
        mocker.patch("windesktopmgr.winreg.OpenKey", return_value=mocker.MagicMock())
        mocker.patch("windesktopmgr.winreg.QueryValueEx", return_value=(b"\x01\x00\x01\xb4", 3))
        mocker.patch("windesktopmgr.winreg.CloseKey")
        # Counts — three _query_event_log_xpath calls (bsod 1001 / whea / kp41).
        recent = datetime.now(timezone.utc).isoformat()
        return mocker.patch(
            "windesktopmgr._query_event_log_xpath",
            side_effect=[
                [{"TimeCreated": recent}, {"TimeCreated": recent}],  # bsod → 2
                [],  # whea → 0
                [{"TimeCreated": recent}],  # kp41 → 1
            ],
        )

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

    def test_microcode_read_from_registry(self, mocker, client):
        self._make_mock(mocker)
        client.get("/api/warranty/data")
        subkey = wdm.winreg.OpenKey.call_args[0][1]
        assert "CentralProcessor" in subkey
        assert wdm.winreg.QueryValueEx.call_args[0][1] == "Update Revision"

    def test_microcode_formatted_as_hex(self, mocker, client):
        self._make_mock(mocker)
        d = client.get("/api/warranty/data").get_json()
        assert d["warranty"]["MicrocodeVersion"] == "0x010001B4"

    def test_counts_query_whea_logger(self, mocker, client):
        q = self._make_mock(mocker)
        client.get("/api/warranty/data")
        whea_xpath = q.call_args_list[1][0][1]
        assert "WHEA-Logger" in whea_xpath

    def test_counts_query_kernel_power_41(self, mocker, client):
        q = self._make_mock(mocker)
        client.get("/api/warranty/data")
        kp_xpath = q.call_args_list[2][0][1]
        assert "41" in kp_xpath

    def test_warranty_returns_event_counts(self, mocker, client):
        self._make_mock(mocker)
        w = client.get("/api/warranty/data").get_json()["warranty"]
        assert w["BSODs30Days"] == 2
        assert w["WHEAErrors"] == 0
        assert w["UnexpectedShutdowns"] == 1
