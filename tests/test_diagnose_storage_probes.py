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
