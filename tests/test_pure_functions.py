"""
test_pure_functions.py
Tests for pure Python helper functions that require no Windows/subprocess calls.
"""

from datetime import datetime, timezone

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
            "intel realtek": {"Title": "Intel Realtek", "DriverVersion": "1.0"},
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


class TestWmiDateToStr:
    """Tests for _wmi_date_to_str() — WMI datetime parsing helper."""

    def test_standard_wmi_date(self):
        assert wdm._wmi_date_to_str("20260621000000.000000+000") == "2026-06-21"

    def test_custom_format(self):
        assert wdm._wmi_date_to_str("20260621153045.000000+000", "%Y-%m-%d %H:%M:%S") == "2026-06-21 15:30:45"

    def test_empty_string_returns_unknown(self):
        assert wdm._wmi_date_to_str("") == "Unknown"

    def test_none_returns_unknown(self):
        assert wdm._wmi_date_to_str(None) == "Unknown"

    def test_short_string_returns_unknown(self):
        assert wdm._wmi_date_to_str("2026") == "Unknown"

    def test_garbage_falls_back_to_first_8_chars(self):
        result = wdm._wmi_date_to_str("ABCDEFGHIJKLMNOP")
        assert result == "ABCDEFGH"


class TestComputeCpuPct:
    """Regression tests for the Processes-tab CPU-% bug fix (2026-04-20).

    Before the fix, the CPU field was cumulative CPU **seconds** but was
    compared against a % threshold and formatted as "% CPU" -- producing
    labels like "Edge using 231% CPU" that actually meant "Edge has 231
    seconds of accumulated CPU time since it started". _compute_cpu_pct()
    produces the real current-load percentage by sampling the cumulative
    CPU-time delta between two snapshots and dividing by wall-clock delta.
    """

    def test_first_sample_returns_zero(self):
        """No previous baseline -> no rate computable -> report 0%."""
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=10.0, now=1000.0, num_cores=8, prev_samples={})
        assert result == 0.0

    def test_full_core_usage_one_core_box(self):
        """1 second of CPU time over 1 second wall clock on a 1-core box = 100%."""
        prev = {1234: (10.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=11.0, now=1001.0, num_cores=1, prev_samples=prev)
        assert result == 100.0

    def test_normalised_across_cores(self):
        """2.31 cores' worth of CPU on a 10-core box = 23.1% (not 231%).

        This is the exact case from the user's bug report: Edge using
        231% of a single core = 2.31 cores out of 10 = 23.1% of total CPU.
        """
        prev = {9999: (0.0, 1000.0)}
        # 23.1 CPU-seconds in 10 wall-clock seconds = 2.31 cores busy
        result = wdm._compute_cpu_pct(pid=9999, cpu_sec=23.1, now=1010.0, num_cores=10, prev_samples=prev)
        assert result == 23.1

    def test_idle_process_reports_zero(self):
        prev = {1234: (5.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=5.0, now=1005.0, num_cores=4, prev_samples=prev)
        assert result == 0.0

    def test_clamped_to_100_on_runaway(self):
        """A process somehow reporting more CPU-seconds than wall-clock allows
        (spike glitch, clock skew) is clamped to 100% so the UI stays sane."""
        prev = {1234: (0.0, 1000.0)}
        # 20 CPU-seconds in 1 wall-second on a 4-core box = 500% raw. Clamp.
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=20.0, now=1001.0, num_cores=4, prev_samples=prev)
        assert result == 100.0

    def test_pid_reuse_negative_delta_returns_zero(self):
        """Old PID 1234 died with 50s cumulative; new PID 1234 starts at 2s.
        Delta would be -48, which doesn't mean anything; return 0, not a
        negative percentage."""
        prev = {1234: (50.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=2.0, now=1010.0, num_cores=4, prev_samples=prev)
        assert result == 0.0

    def test_zero_time_delta_returns_zero(self):
        """Guard against div-by-zero if two samples land at the same timestamp."""
        prev = {1234: (5.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=6.0, now=1000.0, num_cores=4, prev_samples=prev)
        assert result == 0.0

    def test_negative_time_delta_returns_zero(self):
        """Clock went backwards (NTP adjustment, suspend/resume)."""
        prev = {1234: (5.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=6.0, now=999.0, num_cores=4, prev_samples=prev)
        assert result == 0.0

    def test_zero_core_count_does_not_crash(self):
        """Some environments (containers, psutil edge cases) return 0 for
        num_cores. The helper must treat 0 as 1 rather than div-by-zero."""
        prev = {1234: (0.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=1.0, now=1001.0, num_cores=0, prev_samples=prev)
        # 1 sec / 1 sec / 1 core = 100%
        assert result == 100.0

    def test_returns_float(self):
        prev = {1234: (0.0, 1000.0)}
        result = wdm._compute_cpu_pct(pid=1234, cpu_sec=0.5, now=1001.0, num_cores=4, prev_samples=prev)
        assert isinstance(result, float)
