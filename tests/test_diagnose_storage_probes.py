"""Tests for diagnose_storage_probes: the storage & drives bundle's evidence.

Every OS source (WMI, ctypes, psutil, LHM, Storage Spaces, the event log,
the NAS cache) is replaced, so each test states exactly what Windows or the
hardware would have reported.
"""

from __future__ import annotations

import json
import types

import pytest

import diagnose_storage_probes as dsp


@pytest.fixture(autouse=True)
def _fresh_cache():
    dsp._reset_cache()
    yield
    dsp._reset_cache()


def _wmi_row(dev, name, health=0, ops=(2,), bus=17, media=4, serial="0025_38B1_4140_ABCD.", label="S7KHNJ0X90"):
    return {
        "DeviceId": str(dev),
        "FriendlyName": name,
        "MediaType": media,
        "BusType": bus,
        "HealthStatus": health,
        "OperationalStatus": list(ops),
        "SerialNumber": serial,
        "AdapterSerialNumber": label,
        "PhysicalLocation": f"PCI Slot {dev} : Bus 6 : Device 0 : Function 0 : Adapter 1",
        "Size": 2_000_398_934_016,
    }


def _part(letter):
    return types.SimpleNamespace(device=f"{letter}:\\", mountpoint=f"{letter}:\\", fstype="NTFS", opts="rw,fixed")


class TestNormDrive:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("e", "E:"),
            ("E:", "E:"),
            ("e:\\", "E:"),
            ("E drive", "E:"),
            ("", None),
            (None, None),
            ("EE", None),
            ("1:", None),
        ],
    )
    def test_norm_drive(self, raw, expected):
        assert dsp.norm_drive(raw) == expected


class TestPhysicalDisks:
    @pytest.fixture(autouse=True)
    def _no_letters(self, mocker):
        mocker.patch("diagnose_storage_probes.psutil.disk_partitions", return_value=[])

    def test_wmi_happy_path(self, mocker):
        mocker.patch(
            "diagnose_storage_probes._wmi_physical_disks",
            return_value=[
                _wmi_row(0, "Samsung SSD 990 PRO 2TB", label="S7KHNJ0X905B40     _0001"),
                _wmi_row(1, "Samsung SSD 970 EVO Plus 2TB", health=1, ops=(5,)),
            ],
        )
        data = dsp.REGISTERED["storage.physical_disks"].fn({})
        drives = data["drives"]
        assert data["source"] == "wmi"
        assert drives[1]["health"] == "Warning"
        assert "Predictive Failure" in drives[1]["operational"]
        assert drives[0]["bus"] == "NVMe"
        assert drives[0]["media"] == "SSD"
        assert drives[0]["label_serial_tail"] == "5B40"
        assert drives[0]["disk_number"] == 0
        assert drives[0]["slot"]
        assert "S7KHNJ0X905B40" not in json.dumps(data)

    def test_unknown_codes_are_named_not_dropped(self, mocker):
        mocker.patch(
            "diagnose_storage_probes._wmi_physical_disks",
            return_value=[_wmi_row(0, "X", health=9, ops=(13, 53264), bus=99, media=0)],
        )
        drive = dsp.REGISTERED["storage.physical_disks"].fn({})["drives"][0]
        assert drive["operational"] == ["Lost Communication", "Code 53264"]
        assert drive["health"] == "Code 9"

    @pytest.mark.parametrize("label", ["", None, "     _0001"])
    def test_label_tail_never_uses_the_nvme_eui(self, mocker, label):
        """The NVMe SerialNumber is an EUI-64 printed nowhere on the drive (the
        2026-10-08 wrong-drive pull): no label serial means no tail at all."""
        mocker.patch(
            "diagnose_storage_probes._wmi_physical_disks",
            return_value=[_wmi_row(0, "X", serial="0025_384C_3145_20C4.", label=label)],
        )
        assert dsp.REGISTERED["storage.physical_disks"].fn({})["drives"][0]["label_serial_tail"] == ""

    def test_falls_back_to_powershell_when_wmi_fails(self, mocker):
        mocker.patch("diagnose_storage_probes._wmi_physical_disks", side_effect=RuntimeError("COM fault"))
        mocker.patch(
            "diagnose_storage_probes.disk.get_disk_health",
            return_value={
                "physical": [
                    {
                        "Name": "Samsung SSD 990 PRO 2TB",
                        "MediaType": "SSD",
                        "SizeGB": 1863.0,
                        "Health": "Healthy",
                        "Status": "OK",
                        "BusType": "NVMe",
                        "SerialNumber": "0025_38B1.",
                        "LabelSerial": "S7KHNJ0X905B40     _0001",
                        "Location": "PCI Slot 2 : Bus 6 : Device 0 : Function 0 : Adapter 1",
                        "DeviceId": "3",
                    }
                ]
            },
        )
        data = dsp.REGISTERED["storage.physical_disks"].fn({})
        assert data["source"] == "powershell"
        assert data["drives"][0]["disk_number"] == 3
        assert data["drives"][0]["health"] == "Healthy"
        assert data["drives"][0]["operational"] == ["OK"]
        assert data["drives"][0]["label_serial_tail"] == "5B40"
        assert "wmi" in data["unavailable"]

    def test_both_sources_fail_is_empty_not_raise(self, mocker):
        mocker.patch("diagnose_storage_probes._wmi_physical_disks", side_effect=RuntimeError("x"))
        mocker.patch("diagnose_storage_probes.disk.get_disk_health", side_effect=RuntimeError("y"))
        data = dsp.REGISTERED["storage.physical_disks"].fn({})
        assert data["drives"] == []
        assert set(data["unavailable"]) == {"wmi", "powershell"}

    def test_letters_and_focus(self, mocker):
        mocker.patch("diagnose_storage_probes._wmi_physical_disks", return_value=[_wmi_row(0, "X")])
        mocker.patch("diagnose_storage_probes.psutil.disk_partitions", return_value=[_part("C"), _part("E")])
        mocker.patch(
            "diagnose_storage_probes.volume_disk_numbers", side_effect=lambda letter: {"C:": [0], "E:": [6]}[letter]
        )
        data = dsp.REGISTERED["storage.physical_disks"].fn({"drive": "e"})
        assert data["letters"] == {"C:": [0], "E:": [6]}
        assert data["focus"] == "E:"

    def test_no_drive_slot_means_no_focus(self, mocker):
        mocker.patch("diagnose_storage_probes._wmi_physical_disks", return_value=[])
        assert dsp.REGISTERED["storage.physical_disks"].fn({})["focus"] is None

    def test_caps_at_12_drives(self, mocker):
        mocker.patch(
            "diagnose_storage_probes._wmi_physical_disks", return_value=[_wmi_row(i, f"D{i}") for i in range(20)]
        )
        assert len(dsp.REGISTERED["storage.physical_disks"].fn({})["drives"]) == 12

    def test_collector_is_cached(self, mocker):
        wmi = mocker.patch("diagnose_storage_probes._wmi_physical_disks", return_value=[_wmi_row(0, "X")])
        dsp.collect_physical_disks()
        dsp.collect_physical_disks()
        assert wmi.call_count == 1

    def test_volume_disk_numbers_non_windows_returns_empty(self, monkeypatch):
        monkeypatch.setattr(dsp.sys, "platform", "linux")
        assert dsp.volume_disk_numbers("C:") == []

    def test_volume_disk_numbers_rejects_bad_letter(self):
        assert dsp.volume_disk_numbers("CC:") == []


def _sensor(text, value, kind):
    return {"Text": text, "Type": kind, "Value": value, "Children": []}


def _lhm_drive(name, temp="44.0 °C", warn="81.0 °C", crit="84.0 °C", used="5.0 %", spare="100.0 %", thr="10.0 %"):
    return {
        "Text": name,
        "Children": [
            {
                "Text": "Temperatures",
                "Children": [
                    _sensor("Composite Temperature", temp, "Temperature"),
                    _sensor("Warning Temperature", warn, "Temperature"),
                    _sensor("Critical Temperature", crit, "Temperature"),
                ],
            },
            {
                "Text": "Levels",
                "Children": [
                    _sensor("Percentage Used", used, "Level"),
                    _sensor("Available Spare", spare, "Level"),
                    _sensor("Available Spare Threshold", thr, "Level"),
                ],
            },
            {"Text": "Factors", "Children": [_sensor("Power On Hours", "2147.000", "Factor")]},
        ],
    }


_DIMM = {
    "Text": "SK Hynix - HMCG78AGBUA081N (#0)",
    "Children": [{"Text": "Temperatures", "Children": [_sensor("DIMM #0", "42.3 °C", "Temperature")]}],
}


def _lhm_tree(*hardware):
    return {"Text": "Sensor", "Children": [{"Text": "SHIGS78-PC24", "Children": list(hardware)}]}


def _drives(*models):
    return {"source": "wmi", "unavailable": [], "drives": [{"disk_number": n, "model": m} for n, m in models]}


class TestDriveWear:
    def test_parses_temp_limits_wear_spare(self):
        rows = dsp.parse_lhm_storage(_lhm_tree(_lhm_drive("Samsung SSD 990 PRO 2TB")))
        assert rows == [
            {
                "model": "Samsung SSD 990 PRO 2TB",
                "temp_c": 44.0,
                "warn_c": 81.0,
                "crit_c": 84.0,
                "pct_used": 5.0,
                "spare_pct": 100.0,
                "spare_threshold_pct": 10.0,
            }
        ]

    def test_discards_255_sentinels(self):
        """S4: the C: 990 PRO with Heatsink reports 255 % wear / threshold and 0 hours."""
        node = _lhm_drive("Samsung SSD 990 PRO with Heatsink 1TB", temp="37.0 °C", used="255.0 %", thr="255.0 %")
        row = dsp.parse_lhm_storage(_lhm_tree(node))[0]
        assert row["pct_used"] is None
        assert row["spare_threshold_pct"] is None
        assert row["temp_c"] == 37.0

    def test_ram_dimms_are_not_drives(self):
        assert dsp.parse_lhm_storage(_lhm_tree(_DIMM)) == []

    def test_malformed_tree_is_empty(self):
        assert dsp.parse_lhm_storage({"Children": "nope"}) == []
        assert dsp.parse_lhm_storage(None) == []

    def test_match_and_ambiguous(self, mocker):
        mocker.patch(
            "diagnose_storage_probes.lhm._fetch_data_json",
            return_value=_lhm_tree(
                _lhm_drive("Samsung SSD 990 PRO 2TB"), _lhm_drive("Samsung SSD 990 PRO with Heatsink 1TB")
            ),
        )
        mocker.patch(
            "diagnose_storage_probes.collect_physical_disks",
            return_value=_drives(
                (2, "Samsung SSD 990 PRO 2TB"),
                (3, "Samsung SSD 990 PRO 2TB"),
                (1, "NVMe Samsung SSD 990 PRO with Heatsink 1TB"),
            ),
        )
        data = dsp.REGISTERED["storage.drive_wear"].fn({})
        pair, single = data["drives"]
        assert data["available"] is True
        assert (pair["match"], pair["ambiguous"]) == ([2, 3], True)
        assert (single["match"], single["ambiguous"]) == ([1], False)

    def test_lhm_not_running(self, mocker):
        mocker.patch("diagnose_storage_probes.lhm._fetch_data_json", return_value=None)
        data = dsp.REGISTERED["storage.drive_wear"].fn({})
        assert data["available"] is False
        assert "LibreHardwareMonitor" in data["reason"]
        assert data["drives"] == []

    def test_lhm_raising_is_unavailable_not_error(self, mocker):
        mocker.patch("diagnose_storage_probes.lhm._fetch_data_json", side_effect=OSError("refused"))
        assert dsp.REGISTERED["storage.drive_wear"].fn({})["available"] is False

    def test_hostname_never_leaves_the_probe(self, mocker):
        mocker.patch("diagnose_storage_probes.lhm._fetch_data_json", return_value=_lhm_tree(_lhm_drive("X")))
        mocker.patch("diagnose_storage_probes.collect_physical_disks", return_value=_drives())
        assert "SHIGS78" not in json.dumps(dsp.REGISTERED["storage.drive_wear"].fn({}))

    def test_ghost_node_with_nul_name_is_dropped(self):
        """Live 2026-10-13: LHM lists a phantom drive named by 40 NUL bytes, 0 °C, 0 % spare."""
        ghost = _lhm_drive("\x00" * 40, temp="0.0 °C", spare="0.0 %", used="255.0 %", thr="255.0 %")
        assert dsp.parse_lhm_storage(_lhm_tree(ghost, _lhm_drive("Samsung SSD 990 PRO 2TB")))[0]["model"] == (
            "Samsung SSD 990 PRO 2TB"
        )
        assert len(dsp.parse_lhm_storage(_lhm_tree(ghost))) == 0

    def test_zero_celsius_is_no_reading(self):
        row = dsp.parse_lhm_storage(_lhm_tree(_lhm_drive("X", temp="0.0 °C")))[0]
        assert row["temp_c"] is None


# ── Task 4: pool, disk errors, volumes, IO sample, NAS, escalations ──────


def _ev(provider, eid, time="2026-10-12T10:00:00Z", level=2, data_list=None):
    return {"id": eid, "time": time, "provider": provider, "level": level, "data": {}, "data_list": data_list or []}


_SPACES = {
    "pools": [{"Name": "E-Pool", "Health": "Warning", "Operational": "Degraded", "SizeGB": 7451.0}],
    "virtual_disks": [{"Name": "E-Data", "Health": "Warning", "Operational": "Degraded", "Resiliency": "Parity"}],
    "members": [
        {
            "Pool": "E-Pool",
            "Name": "Samsung SSD 970 EVO Plus 2TB",
            "Serial": "0025_384C_3145_20C4.",
            "LabelSerial": "S6S2NS0T5520C4     _0001",
            "Health": "Warning",
            "Operational": "Lost Communication",
            "Usage": "Auto-Select",
            "Location": "PCI Slot 9 : Bus 6 : Device 0 : Function 0 : Adapter 1",
            "SizeGB": 1863.0,
        }
    ],
    "repair_jobs": [{"Name": "Regeneration", "State": "Running", "Pct": 63}],
    "has_spaces": True,
}


class TestPool:
    def test_pool_shape_and_label_tail(self, mocker):
        mocker.patch("diagnose_storage_probes.disk.get_storage_spaces", return_value=_SPACES)
        data = dsp.REGISTERED["storage.pool"].fn({})
        member = data["members"][0]
        assert data["has_spaces"] is True
        assert data["pools"][0] == {"name": "E-Pool", "health": "Warning", "operational": "Degraded"}
        assert data["virtual_disks"][0]["resiliency"] == "Parity"
        assert (member["model"], member["label_serial_tail"], member["operational"]) == (
            "Samsung SSD 970 EVO Plus 2TB",
            "20C4",
            "Lost Communication",
        )
        assert member["slot"] == "PCI Slot 9"
        assert data["repair_jobs"] == [{"name": "Regeneration", "state": "Running", "pct": 63}]

    def test_pool_drops_full_serials(self, mocker):
        mocker.patch("diagnose_storage_probes.disk.get_storage_spaces", return_value=_SPACES)
        dumped = json.dumps(dsp.REGISTERED["storage.pool"].fn({}))
        assert "S6S2NS0T5520C4" not in dumped
        assert "0025_384C" not in dumped

    def test_pool_failure_is_empty_not_raise(self, mocker):
        mocker.patch(
            "diagnose_storage_probes.disk.get_storage_spaces",
            return_value={"pools": [], "virtual_disks": [], "members": [], "repair_jobs": [], "has_spaces": False},
        )
        data = dsp.REGISTERED["storage.pool"].fn({})
        assert data["has_spaces"] is False
        assert data["members"] == []

    def test_pool_timeout_budget(self):
        assert dsp.REGISTERED["storage.pool"].timeout_s == 20.0


class TestDiskErrors:
    def _fake(self, mocker, system=(), spaces=(), spaces_fail=False):
        calls = []

        def query(channel, xpath, unavailable=None, **kw):
            calls.append((channel, xpath))
            if channel == dsp.dcp.STORAGE_SPACES_CHANNEL:
                if spaces_fail:
                    unavailable.append(channel)
                    return []
                return list(spaces)
            return list(system)

        mocker.patch("diagnose_storage_probes.dcp._query", side_effect=query)
        return calls

    def test_groups_by_disk_and_ntfs(self, mocker):
        events = [_ev("disk", 153, data_list=[r"\Device\Harddisk3\DR3"]) for _ in range(6)]
        events += [_ev("Ntfs", 55, data_list=["E:"]), _ev("stornvme", 11, level=3)]
        self._fake(mocker, system=events)
        data = dsp.REGISTERED["storage.disk_errors"].fn({})
        assert data["window_days"] == 7
        assert data["by_disk"]["3"]["count"] == 6
        assert data["by_provider"]["disk"]["count"] == 6
        assert data["by_provider"]["stornvme"]["count"] == 1
        assert data["ntfs_corruption"] == 1

    def test_unlisted_disk_ids_are_ignored(self, mocker):
        self._fake(mocker, system=[_ev("disk", 32, level=3)])
        assert dsp.REGISTERED["storage.disk_errors"].fn({})["by_provider"] == {}

    def test_pool_events_counted(self, mocker):
        self._fake(mocker, spaces=[_ev("Microsoft-Windows-StorageSpaces-Driver", 304)])
        assert dsp.REGISTERED["storage.disk_errors"].fn({})["pool_events"] == 1

    def test_unreadable_channel_listed(self, mocker):
        self._fake(mocker, spaces_fail=True)
        data = dsp.REGISTERED["storage.disk_errors"].fn({})
        assert dsp.dcp.STORAGE_SPACES_CHANNEL in data["unavailable"]

    def test_errors_30d_window(self, mocker):
        calls = self._fake(mocker)
        data = dsp.REGISTERED["storage.errors_30d"].fn({})
        assert data["window_days"] == 30
        assert calls
        assert all(str(30 * 86_400_000) in xpath for _, xpath in calls)


def _vol(letter, free, total, dtype=3, label="Data"):
    return {
        "Letter": letter,
        "Label": label,
        "FreeGB": free,
        "TotalGB": total,
        "PctUsed": round(100 - free / total * 100, 1) if total else 0,
        "DriveType": dtype,
        "FileSystem": "NTFS",
        "UNCPath": None,
    }


class TestVolumes:
    def test_free_space_and_network_drives_excluded(self, mocker):
        mocker.patch(
            "diagnose_storage_probes.disk._enumerate_logical_drives",
            return_value=[_vol("C", 6.0, 200.0, label="OS"), _vol("Z", 10.0, 100.0, dtype=4), _vol("F", 5, 50, 2)],
        )
        vols = dsp.REGISTERED["storage.volumes"].fn({})["volumes"]
        assert [v["letter"] for v in vols] == ["C:", "F:"]
        assert vols[0] == {
            "letter": "C:",
            "label": "OS",
            "fs": "NTFS",
            "total_gb": 200.0,
            "free_gb": 6.0,
            "free_pct": 3.0,
            "fixed": True,
        }
        assert vols[1]["fixed"] is False

    def test_zero_total_is_skipped(self, mocker):
        mocker.patch("diagnose_storage_probes.disk._enumerate_logical_drives", return_value=[_vol("X", 0, 0)])
        assert dsp.REGISTERED["storage.volumes"].fn({})["volumes"] == []


def _io(read_count=0, write_count=0, read_time=0, write_time=0, read_bytes=0, write_bytes=0):
    return types.SimpleNamespace(
        read_count=read_count,
        write_count=write_count,
        read_time=read_time,
        write_time=write_time,
        read_bytes=read_bytes,
        write_bytes=write_bytes,
    )


class TestIoSample:
    def _snapshots(self, mocker, before, after):
        mocker.patch("diagnose_storage_probes.time.sleep")
        mocker.patch("diagnose_storage_probes.psutil.disk_io_counters", side_effect=[before, after])

    def test_busy_and_average(self, mocker):
        self._snapshots(
            mocker,
            {"PhysicalDrive3": _io()},
            {"PhysicalDrive3": _io(read_count=300, read_time=9000, read_bytes=300 * 1024**2)},
        )
        data = dsp.REGISTERED["storage.io_sample"].fn({})
        d = data["disks"][0]
        assert data["seconds"] == 3
        assert d["disk_number"] == 3
        assert d["avg_read_ms"] == 30.0
        assert d["busy_pct"] == 100
        assert d["reads_s"] == 100.0
        assert d["mb_s"] == 100.0

    def test_idle_gives_none_averages(self, mocker):
        """Review Focus 4: under MIN_OPS operations there is no average, never a divide-by-zero."""
        self._snapshots(mocker, {"PhysicalDrive0": _io()}, {"PhysicalDrive0": _io(read_count=5, read_time=10)})
        d = dsp.REGISTERED["storage.io_sample"].fn({})["disks"][0]
        assert d["avg_read_ms"] is None
        assert d["avg_write_ms"] is None

    def test_counters_unavailable_is_empty(self, mocker):
        mocker.patch("diagnose_storage_probes.time.sleep")
        mocker.patch("diagnose_storage_probes.psutil.disk_io_counters", return_value=None)
        assert dsp.REGISTERED["storage.io_sample"].fn({})["disks"] == []

    def test_long_sample_is_ten_seconds(self, mocker):
        self._snapshots(mocker, {}, {})
        assert dsp.REGISTERED["storage.io_sample_long"].fn({})["seconds"] == 10
        assert dsp.REGISTERED["storage.io_sample_long"].timeout_s == 15.0


_NAS_DATA = {
    "configured": 1,
    "nas": [
        {
            "name": "QNAP-Shigs",
            "host": "192.168.1.50",
            "reachable": True,
            "disks": [{"bay": "HDD3", "health": "Warning", "temp_c": 41, "healthy": False}],
            "volumes": [{"name": "DataVol1", "status": "Ready", "pct_used": 93.0, "healthy": True}],
        }
    ],
}


class TestNas:
    def test_never_waits_and_hides_host(self, mocker):
        get = mocker.patch("diagnose_storage_probes.nas.get_nas_storage", return_value=_NAS_DATA)
        mocker.patch(
            "diagnose_storage_probes.nas.nas_storage_concerns",
            return_value=[{"level": "critical", "title": "NAS 'QNAP-Shigs' disk HDD3: Warning", "detail": "x"}],
        )
        mocker.patch.object(dsp.nas, "_nas_cache_ts", dsp.time.time() - 120)
        data = dsp.REGISTERED["storage.nas"].fn({})
        get.assert_called_once_with(wait=False)
        assert "192.168.1.50" not in json.dumps(data)
        entry = data["nas"][0]
        assert entry["label"] == "NAS 1"
        assert 100 <= entry["age_s"] <= 200
        assert entry["disks"] == [{"bay": "HDD3", "health": "Warning", "temp_c": 41}]
        assert entry["volumes"] == [{"status": "Ready", "free_pct": 7.0}]
        assert data["concerns"][0]["level"] == "critical"

    def test_nothing_configured(self, mocker):
        mocker.patch("diagnose_storage_probes.nas.get_nas_storage", return_value={"nas": [], "configured": 0})
        mocker.patch("diagnose_storage_probes.nas.nas_storage_concerns", return_value=[])
        data = dsp.REGISTERED["storage.nas"].fn({})
        assert (data["configured"], data["nas"], data["concerns"]) == (0, [], [])

    def test_reader_failure_is_empty(self, mocker):
        mocker.patch("diagnose_storage_probes.nas.get_nas_storage", side_effect=RuntimeError("snmp"))
        data = dsp.REGISTERED["storage.nas"].fn({})
        assert data["nas"] == []
        assert data["concerns"] == []


class TestSpaceBreakdown:
    def test_named_drive_top_locations(self, mocker):
        q = mocker.patch(
            "diagnose_storage_probes.disk.get_disk_quickwins",
            return_value={
                "ok": True,
                "locations": [
                    {"label": f"L{i}", "path": f"C:\\p{i}", "size_bytes": i * 1024**3, "exists": True}
                    for i in range(14)
                ],
            },
        )
        data = dsp.REGISTERED["storage.space_breakdown"].fn({"drive": "c"})
        q.assert_called_once_with("C:")
        assert data["drive"] == "C:"
        assert len(data["locations"]) == 10
        assert data["locations"][0] == {"label": "L13", "path": "C:\\p13", "size_gb": 13.0}

    def test_defaults_to_fullest_fixed_volume(self, mocker):
        mocker.patch(
            "diagnose_storage_probes.disk._enumerate_logical_drives",
            return_value=[_vol("C", 10.0, 200.0), _vol("E", 1000.0, 5000.0), _vol("Z", 1.0, 100.0, dtype=2)],
        )
        q = mocker.patch("diagnose_storage_probes.disk.get_disk_quickwins", return_value={"ok": True, "locations": []})
        assert dsp.REGISTERED["storage.space_breakdown"].fn({})["drive"] == "C:"
        q.assert_called_once_with("C:")


class TestRegistry:
    KEYS = frozenset(
        {
            "storage.physical_disks",
            "storage.drive_wear",
            "storage.pool",
            "storage.disk_errors",
            "storage.volumes",
            "storage.io_sample",
            "storage.nas",
            "storage.space_breakdown",
            "storage.errors_30d",
            "storage.io_sample_long",
        }
    )

    def test_all_ten_registered_with_storage_rules(self):
        assert set(dsp.REGISTERED) == self.KEYS
        for probe in dsp.REGISTERED.values():
            assert probe.category == "storage"
            assert "nas_name" in probe.redact
            assert "serial" in probe.redact
            assert 8 <= probe.timeout_s <= 20
