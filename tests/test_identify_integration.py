"""tests/test_identify_integration.py — the global AI identifier wired into the
process / driver / BIOS / MAC-vendor lookup paths. AI is mocked everywhere.
"""

from __future__ import annotations

import bios
import homenet
import processes
import windowsdrivermgr

# ── Process lookup chain (the vmmem fix) ────────────────────────────────────


class TestProcessAiFallback:
    def test_ai_resolves_when_fileinfo_and_web_miss(self, mocker):
        mocker.patch.object(processes, "_lookup_process_via_fileinfo", return_value=None)
        mocker.patch.object(processes, "_lookup_process_via_web", return_value=None)
        mocker.patch.object(
            processes.identify,
            "identify_via_ai",
            return_value={
                "source": "claude_ai",
                "plain": "Virtual Machine Memory",
                "what": "WSL2/Hyper-V VM memory process.",
                "safe_kill": True,
                "fetched": "2026-01-01T00:00:00+00:00",
            },
        )
        result = processes._resolve_process("vmmem", "")
        assert result["source"] == "claude_ai"
        assert result["plain"] == "Virtual Machine Memory"
        assert result["publisher"] == "Identified by AI"
        assert "VM memory" in result["what"]

    def test_placeholder_when_ai_also_misses(self, mocker):
        mocker.patch.object(processes, "_lookup_process_via_fileinfo", return_value=None)
        mocker.patch.object(processes, "_lookup_process_via_web", return_value=None)
        mocker.patch.object(processes.identify, "identify_via_ai", return_value=None)
        result = processes._resolve_process("mystery.exe", "")
        assert result["source"] == "unknown"
        assert "No description found" in result["what"]

    def test_ai_not_called_when_fileinfo_hits(self, mocker):
        mocker.patch.object(
            processes,
            "_lookup_process_via_fileinfo",
            return_value={"source": "fileinfo", "plain": "X", "what": "y", "safe_kill": True},
        )
        ai = mocker.patch.object(processes.identify, "identify_via_ai")
        result = processes._resolve_process("known.exe", "")
        assert result["source"] == "fileinfo"
        ai.assert_not_called()

    def test_ai_null_safe_kill_defaults_true(self, mocker):
        mocker.patch.object(processes, "_lookup_process_via_fileinfo", return_value=None)
        mocker.patch.object(processes, "_lookup_process_via_web", return_value=None)
        mocker.patch.object(
            processes.identify,
            "identify_via_ai",
            return_value={"source": "claude_ai", "plain": "X", "what": "y", "safe_kill": None, "fetched": "t"},
        )
        result = processes._resolve_process("x", "")
        assert result["safe_kill"] is True


# ── Driver scan description (the "Unknown Device" gap) ──────────────────────


class TestDriverIdentification:
    def test_unknown_device_gets_ai_description(self, mocker):
        mocker.patch.object(
            windowsdrivermgr,
            "get_installed_drivers",
            return_value=[{"DeviceName": "Unknown Device", "DriverVersion": "1.0", "Manufacturer": "Acme"}],
        )
        mocker.patch.object(windowsdrivermgr, "get_windows_update_drivers", return_value={})
        mocker.patch.object(
            windowsdrivermgr.identify,
            "identify",
            return_value={"source": "claude_ai", "plain": "Acme Widget Controller", "what": "Controls the widget."},
        )
        windowsdrivermgr.run_scan()
        drv = windowsdrivermgr._scan_results[0]
        assert drv["description"] == "Controls the widget."
        assert drv["name"] == "Acme Widget Controller"

    def test_named_driver_not_sent_to_ai(self, mocker):
        mocker.patch.object(
            windowsdrivermgr,
            "get_installed_drivers",
            return_value=[{"DeviceName": "NVIDIA GeForce RTX 4060 Ti", "DriverVersion": "5", "Manufacturer": "NVIDIA"}],
        )
        mocker.patch.object(windowsdrivermgr, "get_windows_update_drivers", return_value={})
        spy = mocker.patch.object(windowsdrivermgr.identify, "identify")
        windowsdrivermgr.run_scan()
        spy.assert_not_called()
        assert windowsdrivermgr._scan_results[0]["description"] == ""


# ── BIOS firmware note (version-unknown gap) ────────────────────────────────


class TestBiosIdentification:
    def test_missing_version_gets_firmware_note(self, mocker):
        # get_bios_status pulls its siblings from the windesktopmgr namespace.
        mocker.patch(
            "windesktopmgr.get_current_bios",
            return_value={"BIOSVersion": "", "BoardProduct": "XPS 8960", "Manufacturer": "Dell"},
        )
        mocker.patch("windesktopmgr.check_dell_bios_update", return_value={})
        mocker.patch.object(
            bios.identify,
            "identify",
            return_value={"source": "claude_ai", "plain": "XPS 8960 BIOS", "what": "Dell XPS 8960 UEFI firmware."},
        )
        data = bios.get_bios_status()
        assert data["current"]["firmware_note"] == "Dell XPS 8960 UEFI firmware."

    def test_present_version_skips_identify(self, mocker):
        mocker.patch(
            "windesktopmgr.get_current_bios",
            return_value={"BIOSVersion": "2.18.0", "BoardProduct": "XPS 8960"},
        )
        mocker.patch("windesktopmgr.check_dell_bios_update", return_value={})
        spy = mocker.patch.object(bios.identify, "identify")
        data = bios.get_bios_status()
        spy.assert_not_called()
        assert "firmware_note" not in data["current"]


# ── MAC vendor (unknown-OUI gap) ────────────────────────────────────────────


class TestMacVendorIdentification:
    def test_unknown_oui_resolved_by_ai(self, mocker):
        # No curated/IEEE match -> AI path. Force IEEE to miss.
        mocker.patch.object(homenet, "_IEEE_LOOKUP", None)
        homenet._vendor_cache.clear()
        mocker.patch.object(
            homenet.identify,
            "identify",
            return_value={"source": "claude_ai", "plain": "Acme Networks", "what": "x"},
        )
        # A non-locally-administered MAC so randomised-phone detection doesn't fire.
        vendor = homenet._mac_vendor("3C:5A:B4:DD:EE:FF")
        assert vendor == "Acme Networks"

    def test_unknown_oui_stays_unknown_when_ai_pending(self, mocker):
        mocker.patch.object(homenet, "_IEEE_LOOKUP", None)
        homenet._vendor_cache.clear()
        mocker.patch.object(
            homenet.identify,
            "identify",
            return_value={"source": "pending", "plain": "Unknown", "pending": True},
        )
        vendor = homenet._mac_vendor("3C:5A:B4:11:22:33")
        assert vendor == "Unknown"
