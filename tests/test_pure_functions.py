"""
test_pure_functions.py
Tests for pure Python helper functions that require no Windows/subprocess calls.
"""

from datetime import datetime, timezone
import pytest
import windesktopmgr as wdm


# ══════════════════════════════════════════════════════════════════════════════
# categorize(name, device_class)
# ══════════════════════════════════════════════════════════════════════════════

class TestCategorize:
    def test_display_by_name(self):
        assert wdm.categorize("NVIDIA GeForce RTX 4090", "") == "Display"

    def test_display_by_class(self):
        assert wdm.categorize("Unknown Device", "Display") == "Display"

    def test_audio_by_name(self):
        assert wdm.categorize("Realtek High Definition Audio", "") == "Audio"

    def test_audio_by_class(self):
        assert wdm.categorize("Some Speaker", "Audio") == "Audio"

    def test_network_ethernet(self):
        assert wdm.categorize("Intel Ethernet Controller", "") == "Network"

    def test_network_wifi(self):
        assert wdm.categorize("Intel Wi-Fi 6 AX201", "") == "Network"

    def test_network_bluetooth(self):
        assert wdm.categorize("Bluetooth Device", "") == "Network"

    def test_chipset_usb(self):
        assert wdm.categorize("USB 3.0 Root Hub", "") == "Chipset"

    def test_chipset_nvme(self):
        assert wdm.categorize("Samsung NVMe Controller", "") == "Chipset"

    def test_monitor(self):
        assert wdm.categorize("Generic Monitor", "") == "Monitor"

    def test_other_fallback(self):
        assert wdm.categorize("Totally Unknown Gizmo", "") == "Other"

    def test_case_insensitive(self):
        assert wdm.categorize("AUDIO OUTPUT DEVICE", "") == "Audio"

    def test_combined_name_and_class(self):
        # keyword in device_class wins when name has no match
        assert wdm.categorize("Some Device", "Network") == "Network"


# ══════════════════════════════════════════════════════════════════════════════
# find_wu_match(name, wu_updates)
# ══════════════════════════════════════════════════════════════════════════════

class TestFindWuMatch:
    def _wu(self, title):
        """Helper: build a minimal WU update dict."""
        return {title.lower(): {"Title": title, "DriverVersion": "1.0"}}

    def test_two_word_overlap_matches(self):
        wu = self._wu("Intel Ethernet Controller Update")
        result = wdm.find_wu_match("Intel Ethernet Controller", wu)
        assert result is not None
        assert result["Title"] == "Intel Ethernet Controller Update"

    def test_one_word_overlap_no_match(self):
        wu = self._wu("Intel Something Else")
        # Only 1 shared word → score < 2 → no match
        result = wdm.find_wu_match("Intel USB Hub", wu)
        assert result is None

    def test_stop_words_excluded(self):
        # "driver" and "device" are stop words; should not count toward score
        wu = self._wu("Driver Device Update")
        result = wdm.find_wu_match("Driver Device Totally Different", wu)
        assert result is None

    def test_empty_name(self):
        wu = self._wu("Intel Ethernet Controller")
        assert wdm.find_wu_match("", wu) is None

    def test_empty_wu_dict(self):
        assert wdm.find_wu_match("Intel Ethernet Controller", {}) is None

    def test_only_stop_words_in_name(self):
        # After removing stop words, name_words is empty → return None
        assert wdm.find_wu_match("driver device controller adapter", {}) is None

    def test_best_score_wins(self):
        # Use words that are NOT stop words so we get different scores.
        # name_words after stop-word removal for "Intel Realtek Samsung":
        #   {"intel", "realtek", "samsung"}  (none are stop words)
        # Entry A: "intel realtek" → overlap 2
        # Entry B: "intel realtek samsung" → overlap 3 → wins
        wu = {
            "intel realtek":         {"Title": "Intel Realtek",         "DriverVersion": "1.0"},
            "intel realtek samsung": {"Title": "Intel Realtek Samsung", "DriverVersion": "2.0"},
        }
        result = wdm.find_wu_match("Intel Realtek Samsung", wu)
        assert result is not None
        assert result["DriverVersion"] == "2.0"


# ══════════════════════════════════════════════════════════════════════════════
# _normalise_stop_code(code)
# ══════════════════════════════════════════════════════════════════════════════

class TestNormaliseStopCode:
    def test_hypervisor_error(self):
        assert wdm._normalise_stop_code("0x00020001") == "0x00020001"

    def test_short_hex_padded(self):
        assert wdm._normalise_stop_code("0x9f") == "0x0000009f"

    def test_mid_length_hex(self):
        assert wdm._normalise_stop_code("0x139") == "0x00000139"

    def test_uppercase_input(self):
        assert wdm._normalise_stop_code("0X0000009F") == "0x0000009f"

    def test_empty_string(self):
        assert wdm._normalise_stop_code("") == ""

    def test_non_hex_garbage(self):
        # Must not raise; returns lowercased input
        result = wdm._normalise_stop_code("garbage")
        assert isinstance(result, str)

    def test_already_normalised(self):
        assert wdm._normalise_stop_code("0x00000139") == "0x00000139"


# ══════════════════════════════════════════════════════════════════════════════
# _parse_ts(ts_str)
# ══════════════════════════════════════════════════════════════════════════════

class TestParseTs:
    def test_iso_with_utc_offset(self):
        dt = wdm._parse_ts("2026-03-01T10:00:00+00:00")
        assert dt.year == 2026
        assert dt.month == 3
        assert dt.day == 1
        assert dt.tzinfo is not None

    def test_iso_with_z_suffix(self):
        dt = wdm._parse_ts("2026-01-15T08:30:00Z")
        assert dt.year == 2026
        assert dt.tzinfo is not None

    def test_naive_datetime_gets_utc(self):
        dt = wdm._parse_ts("2026-03-01T10:00:00")
        assert dt.tzinfo == timezone.utc

    def test_garbage_returns_datetime_min(self):
        dt = wdm._parse_ts("not-a-timestamp")
        assert dt == datetime.min.replace(tzinfo=timezone.utc)

    def test_empty_string_returns_datetime_min(self):
        dt = wdm._parse_ts("")
        assert dt == datetime.min.replace(tzinfo=timezone.utc)


# ══════════════════════════════════════════════════════════════════════════════
# _insight(level, text, action)
# ══════════════════════════════════════════════════════════════════════════════

class TestInsight:
    def test_returns_dict_with_level(self):
        i = wdm._insight("critical", "Something bad")
        assert i["level"] == "critical"

    def test_returns_dict_with_text(self):
        i = wdm._insight("ok", "All good")
        assert i["text"] == "All good"

    def test_action_defaults_to_empty(self):
        i = wdm._insight("info", "FYI")
        assert i["action"] == ""

    def test_action_set_when_provided(self):
        i = wdm._insight("warning", "Watch out", "Do something")
        assert i["action"] == "Do something"

    def test_returns_exactly_three_keys(self):
        i = wdm._insight("ok", "text", "action")
        assert set(i.keys()) == {"level", "text", "action"}
