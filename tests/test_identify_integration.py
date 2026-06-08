"""tests/test_identify_integration.py — the global AI identifier wired into the
process / driver / BIOS / MAC-vendor lookup paths. AI is mocked everywhere.
"""

from __future__ import annotations

import pytest

import bios
import bsod
import events
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


# ── BSOD stop code (identify rollout PR2) ───────────────────────────────────


class TestBsodAiFallback:
    def test_ai_resolves_when_windows_and_web_miss(self, mocker):
        mocker.patch.object(bsod, "_lookup_stop_code_windows", return_value=None)
        mocker.patch.object(bsod, "_lookup_stop_code_web", return_value=None)
        mocker.patch.object(
            bsod.identify,
            "identify_via_ai",
            return_value={
                "source": "claude_ai",
                "plain": "VIDEO_TDR_FAILURE",
                "what": "GPU driver timed out.",
                "safe_kill": None,
                "fetched": "t",
            },
        )
        result = bsod._resolve_stop_code("0x00000116")
        assert result["source"] == "claude_ai"
        assert result["title"] == "VIDEO_TDR_FAILURE"
        assert "GPU driver" in result["detail"]
        assert result["priority"] == "high"

    def test_placeholder_when_ai_also_misses(self, mocker):
        mocker.patch.object(bsod, "_lookup_stop_code_windows", return_value=None)
        mocker.patch.object(bsod, "_lookup_stop_code_web", return_value=None)
        mocker.patch.object(bsod.identify, "identify_via_ai", return_value=None)
        result = bsod._resolve_stop_code("0xdeadbeef")
        assert result["source"] == "unknown"
        assert "No description found" in result["detail"]

    def test_ai_not_called_when_windows_table_hits(self, mocker):
        mocker.patch.object(
            bsod, "_lookup_stop_code_windows", return_value={"source": "windows", "title": "X", "detail": "y"}
        )
        spy = mocker.patch.object(bsod.identify, "identify_via_ai")
        result = bsod._resolve_stop_code("0x0000000a")
        assert result["source"] == "windows"
        spy.assert_not_called()


# ── Event ID (identify rollout PR2) ─────────────────────────────────────────


class TestEventAiFallback:
    def test_ai_resolves_when_provider_and_web_miss(self, mocker):
        mocker.patch.object(events, "_lookup_via_windows_provider", return_value=None)
        mocker.patch.object(events, "_lookup_via_web", return_value=None)
        mocker.patch.object(
            events.identify,
            "identify_via_ai",
            return_value={
                "source": "claude_ai",
                "plain": "Acme Service Started",
                "what": "The Acme service started.",
                "safe_kill": None,
                "fetched": "t",
            },
        )
        result = events._resolve_event(54321, "Acme-Provider")
        assert result["source"] == "claude_ai"
        assert result["title"] == "Acme Service Started"
        assert result["noise"] is False

    def test_placeholder_when_ai_also_misses(self, mocker):
        mocker.patch.object(events, "_lookup_via_windows_provider", return_value=None)
        mocker.patch.object(events, "_lookup_via_web", return_value=None)
        mocker.patch.object(events.identify, "identify_via_ai", return_value=None)
        result = events._resolve_event(99999, "")
        assert result["source"] == "unknown"
        assert "No description found" in result["detail"]

    def test_ai_not_called_when_provider_hits(self, mocker):
        mocker.patch.object(
            events, "_lookup_via_windows_provider", return_value={"source": "provider", "title": "X", "detail": "y"}
        )
        spy = mocker.patch.object(events.identify, "identify_via_ai")
        result = events._resolve_event(1000, "Application")
        assert result["source"] == "provider"
        spy.assert_not_called()


# ── Worker cache-hit invariant (regression: double task_done) ───────────────


class TestWorkerCacheHitTaskDone:
    """An already-cached item must call task_done() exactly ONCE -- the worker's
    `finally` owns the discard + task_done; the cache-hit early-exit used to do
    them inline too, double-counting task_done (a queue.join() would hang/raise).
    Driven via SystemExit (not caught by the worker's `except Exception`) to
    stop the otherwise-infinite loop after one cache-hit iteration."""

    def test_bsod_cache_hit_single_task_done(self, mocker):
        q = mocker.MagicMock()
        q.get.side_effect = ["0xabc", SystemExit()]
        mocker.patch.object(bsod, "_bsod_queue", q)
        mocker.patch.object(bsod, "_bsod_cache", {"0xabc": {"source": "static_kb"}})
        mocker.patch.object(bsod, "_bsod_in_flight", set())
        with pytest.raises(SystemExit):
            bsod._bsod_lookup_worker()
        assert q.task_done.call_count == 1

    def test_event_cache_hit_single_task_done(self, mocker):
        q = mocker.MagicMock()
        q.get.side_effect = [(4625, "Security"), SystemExit()]
        mocker.patch.object(events, "_lookup_queue", q)
        mocker.patch.object(events, "_event_cache", {"4625": {"source": "static_kb"}})
        mocker.patch.object(events, "_lookup_in_flight", set())
        with pytest.raises(SystemExit):
            events._lookup_worker()
        assert q.task_done.call_count == 1
