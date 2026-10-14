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
