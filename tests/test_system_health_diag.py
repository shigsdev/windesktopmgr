"""
tests/test_system_health_diag.py — Unit tests for SystemHealthDiag.py

Now that SystemHealthDiag.py is refactored into proper functions with a
`if __name__ == "__main__"` guard, we can directly import and test every function.

All subprocess / PowerShell / winreg / ctypes calls are mocked — no Windows dependency.
"""

import os
import re
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Windows-only modules before importing SystemHealthDiag
# ---------------------------------------------------------------------------
# ctypes — mock the admin check so import doesn't fail on non-Windows
_mock_ctypes = MagicMock()
_mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = True
sys.modules.setdefault("ctypes", _mock_ctypes)

# winreg — mock the Windows registry module
_mock_winreg = MagicMock()
_mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
sys.modules.setdefault("winreg", _mock_winreg)

# Now we can safely import
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import SystemHealthDiag as shd


# ===========================================================================
# TEST CLASS: safe_truncate
# ===========================================================================
class TestSafeTruncate:
    """Test the safe_truncate helper function."""

    def test_none_input(self):
        assert shd.safe_truncate(None) == ""

    def test_empty_string(self):
        assert shd.safe_truncate("") == ""

    def test_short_string_unchanged(self):
        assert shd.safe_truncate("hello") == "hello"

    def test_long_string_truncated(self):
        long_str = "x" * 500
        result = shd.safe_truncate(long_str, max_len=300)
        assert len(result) == 300

    def test_newlines_replaced(self):
        result = shd.safe_truncate("line1\r\nline2\nline3")
        assert "\n" not in result
        assert "\r" not in result
        assert result == "line1 line2 line3"

    def test_custom_max_len(self):
        result = shd.safe_truncate("abcdefghij", max_len=5)
        assert result == "abcde"


# ===========================================================================
# TEST CLASS: normalize_list
# ===========================================================================
class TestNormalizeList:
    """Test the normalize_list helper."""

    def test_list_unchanged(self):
        data = {"items": [1, 2, 3]}
        assert shd.normalize_list(data, "items") == [1, 2, 3]

    def test_dict_wrapped_in_list(self):
        data = {"item": {"name": "test"}}
        result = shd.normalize_list(data, "item")
        assert result == [{"name": "test"}]

    def test_none_becomes_empty_list(self):
        data = {"items": None}
        assert shd.normalize_list(data, "items") == []

    def test_missing_key_becomes_empty_list(self):
        data = {}
        assert shd.normalize_list(data, "missing") == []

    def test_empty_list_unchanged(self):
        data = {"items": []}
        assert shd.normalize_list(data, "items") == []


# ===========================================================================
# TEST CLASS: _count_recent_events
# ===========================================================================
class TestCountRecentEvents:
    """Test the time-weighted event counting helper."""

    def test_all_recent_events_counted(self):
        today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events = [{"Date": today}, {"Date": today}]
        assert shd._count_recent_events(events) == 2

    def test_old_events_excluded(self):
        old_date = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        events = [{"Date": old_date}, {"Date": old_date}]
        assert shd._count_recent_events(events) == 0

    def test_mixed_old_and_recent(self):
        recent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        old = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        events = [{"Date": recent}, {"Date": old}, {"Date": recent}]
        assert shd._count_recent_events(events) == 2

    def test_empty_date_assumed_recent(self):
        events = [{"Date": ""}]
        assert shd._count_recent_events(events) == 1

    def test_missing_date_assumed_recent(self):
        events = [{}]
        assert shd._count_recent_events(events) == 1

    def test_custom_days_parameter(self):
        eight_days_ago = (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S")
        events = [{"Date": eight_days_ago}]
        assert shd._count_recent_events(events, days=7) == 0
        assert shd._count_recent_events(events, days=10) == 1

    def test_empty_list(self):
        assert shd._count_recent_events([]) == 0


# ===========================================================================
# TEST CLASS: calculate_score
# ===========================================================================
class TestCalculateScore:
    """Test the health score calculation."""

    def test_perfect_score(self):
        score, label, color = shd.calculate_score([], [])
        assert score == 100
        assert label == "Good"
        assert color == "#22c55e"

    def test_one_critical(self):
        score, label, _ = shd.calculate_score(["issue"], [])
        assert score == 80
        assert label == "Good"

    def test_five_critical_is_zero(self):
        score, label, color = shd.calculate_score(["a"] * 5, [])
        assert score == 0
        assert label == "Critical"
        assert color == "#ef4444"

    def test_ten_critical_clamped_at_zero(self):
        score, _, _ = shd.calculate_score(["a"] * 10, [])
        assert score == 0

    def test_warnings_only(self):
        score, _, _ = shd.calculate_score([], ["w"] * 4)
        assert score == 80

    def test_mixed(self):
        # 100 - 2*20 - 3*5 = 45
        score, label, _ = shd.calculate_score(["c"] * 2, ["w"] * 3)
        assert score == 45
        assert label == "Poor"

    def test_fair_range(self):
        # 100 - 1*20 - 4*5 = 60
        score, label, color = shd.calculate_score(["c"], ["w"] * 4)
        assert score == 60
        assert label == "Fair"
        assert color == "#eab308"


# ===========================================================================
# TEST CLASS: Intel CPU Check Logic
# ===========================================================================
class TestCheckIntelCPU:
    """Test the check_intel_cpu function."""

    @patch.object(shd, "winreg")
    def test_i9_14900k_detected(self, mock_winreg):
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value = mock_key
        mock_winreg.QueryValueEx.return_value = (b"\x00\x00\x00\x00\x29\x01\x00\x00", 1)
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        sys_info = {"CPUName": "Intel(R) Core(TM) i9-14900K", "BIOSDate": "2025-01-10"}
        intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)

        assert intel_check["IsAffectedCPU"] is True
        assert "14th Gen Core i9" in intel_check["CPUFamily"]
        assert len(crit) == 0  # BIOS is recent

    @patch.object(shd, "winreg")
    def test_old_bios_triggers_critical(self, mock_winreg):
        mock_winreg.OpenKey.return_value = MagicMock()
        mock_winreg.QueryValueEx.return_value = (b"\x00\x00\x00\x00\x00\x00\x00\x00", 1)
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        sys_info = {"CPUName": "Intel(R) Core(TM) i9-14900K", "BIOSDate": "2024-03-15"}
        intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)

        assert len(crit) == 1
        assert "INTEL CPU VULNERABILITY" in crit[0]

    @patch.object(shd, "winreg")
    def test_mid_range_bios_triggers_warning(self, mock_winreg):
        mock_winreg.OpenKey.return_value = MagicMock()
        mock_winreg.QueryValueEx.return_value = (b"\x00\x00\x00\x00\x00\x00\x00\x00", 1)
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        sys_info = {"CPUName": "Intel(R) Core(TM) i7-14700K", "BIOSDate": "2024-09-15"}
        intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)

        assert len(warn) == 1
        assert len(crit) == 0

    def test_amd_not_detected(self):
        sys_info = {"CPUName": "AMD Ryzen 9 7950X", "BIOSDate": "2025-01-01"}
        intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)

        assert intel_check["IsAffectedCPU"] is False
        assert len(crit) == 0
        assert len(info) == 1

    def test_12th_gen_not_detected(self):
        sys_info = {"CPUName": "Intel(R) Core(TM) i9-12900K", "BIOSDate": "2025-01-01"}
        intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)
        assert intel_check["IsAffectedCPU"] is False

    def test_empty_sys_info(self):
        intel_check, crit, warn, info = shd.check_intel_cpu({})
        assert intel_check["IsAffectedCPU"] is False

    def test_malformed_bios_date_fallback(self):
        """Invalid BIOS date falls back to 2020-01-01 (triggers critical)."""
        sys_info = {"CPUName": "Intel(R) Core(TM) i9-14900K", "BIOSDate": "not-a-date"}
        with patch.object(shd, "winreg") as mock_winreg:
            mock_winreg.OpenKey.return_value = MagicMock()
            mock_winreg.QueryValueEx.return_value = (b"\x00", 1)
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            intel_check, crit, warn, info = shd.check_intel_cpu(sys_info)
        assert len(crit) == 1  # 2020-01-01 < 2024-08-01


# ===========================================================================
# TEST CLASS: BUGCHECK_LOOKUP and HW_CODES
# ===========================================================================
class TestBugcheckConstants:
    """Validate the BUGCHECK_LOOKUP and HW_CODES constants."""

    def test_known_codes_present(self):
        assert "0x0000009C" in shd.BUGCHECK_LOOKUP
        assert "0x00000124" in shd.BUGCHECK_LOOKUP
        assert "0x00000101" in shd.BUGCHECK_LOOKUP

    def test_hw_codes_subset_of_lookup(self):
        for code in shd.HW_CODES:
            assert code in shd.BUGCHECK_LOOKUP

    def test_all_codes_have_descriptions(self):
        for code, desc in shd.BUGCHECK_LOOKUP.items():
            assert len(desc) > 10
            assert code.startswith("0x")

    def test_hw_codes_count(self):
        assert len(shd.HW_CODES) == 5


# ===========================================================================
# TEST CLASS: ps() helper
# ===========================================================================
class TestPSHelper:
    """Test the ps() PowerShell wrapper."""

    def _run_ps_with_mock(self, stdout="", as_json=False, side_effect=None):
        """Run shd.ps() with real subprocess module but mocked subprocess.run."""
        import subprocess as real_sp

        original = shd.subprocess
        shd.subprocess = real_sp  # restore real subprocess temporarily
        try:
            with patch.object(real_sp, "run") as mock_run:
                if side_effect:
                    mock_run.side_effect = side_effect
                else:
                    mock_run.return_value.stdout = stdout
                    mock_run.return_value.returncode = 0
                result = shd.ps("test command", as_json=as_json)
                return result, mock_run
        finally:
            shd.subprocess = original

    def test_returns_stdout(self):
        result, _ = self._run_ps_with_mock(stdout="  hello world  ")
        assert result == "hello world"

    def test_json_parsing(self):
        result, _ = self._run_ps_with_mock(stdout='{"key": "value"}', as_json=True)
        assert result == {"key": "value"}

    def test_timeout_returns_empty_string(self):
        import subprocess as real_sp

        result, _ = self._run_ps_with_mock(side_effect=real_sp.TimeoutExpired("cmd", 30))
        assert result == ""

    def test_json_timeout_returns_empty_list(self):
        import subprocess as real_sp

        result, _ = self._run_ps_with_mock(side_effect=real_sp.TimeoutExpired("cmd", 30), as_json=True)
        assert result == []

    def test_bad_json_returns_empty_list(self):
        result, _ = self._run_ps_with_mock(stdout="not valid json {{{", as_json=True)
        assert result == []

    def test_empty_output_no_json_parse(self):
        result, _ = self._run_ps_with_mock(stdout="", as_json=True)
        assert result == ""

    def test_command_construction(self):
        _, mock_run = self._run_ps_with_mock(stdout="")
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "powershell"
        assert "-NoProfile" in call_args
        assert "-NonInteractive" in call_args


# ===========================================================================
# TEST CLASS: ps_events() helper
# ===========================================================================
class TestPSEvents:
    """Test the ps_events() event log query builder."""

    @patch.object(shd, "ps")
    def test_basic_query(self, mock_ps):
        mock_ps.return_value = [{"Date": "2026-03-18", "EventID": 1}]
        result = shd.ps_events("System")
        assert len(result) == 1
        # Verify the command contains the log name
        cmd = mock_ps.call_args[0][0]
        assert "LogName='System'" in cmd

    @patch.object(shd, "ps")
    def test_with_provider_and_id(self, mock_ps):
        mock_ps.return_value = []
        shd.ps_events("System", provider="Kernel-Power", event_id=41)
        cmd = mock_ps.call_args[0][0]
        assert "ProviderName='Kernel-Power'" in cmd
        assert "Id=41" in cmd

    @patch.object(shd, "ps")
    def test_single_dict_wrapped_in_list(self, mock_ps):
        mock_ps.return_value = {"Date": "2026-03-18", "EventID": 41}
        result = shd.ps_events("System")
        assert isinstance(result, list)
        assert len(result) == 1

    @patch.object(shd, "ps")
    def test_empty_result(self, mock_ps):
        mock_ps.return_value = ""
        result = shd.ps_events("System")
        assert result == []

    @patch.object(shd, "ps")
    def test_with_level_filter(self, mock_ps):
        mock_ps.return_value = []
        shd.ps_events("System", level=1, max_events=30)
        cmd = mock_ps.call_args[0][0]
        assert "Level=1" in cmd
        assert "MaxEvents 30" in cmd


# ===========================================================================
# TEST CLASS: collect_system_info
# ===========================================================================
class TestCollectSystemInfo:
    """Test the collect_system_info function."""

    @patch.object(shd, "ps")
    def test_returns_dict(self, mock_ps):
        mock_ps.return_value = {"ComputerName": "TEST-PC", "CPUName": "i9-14900K"}
        result = shd.collect_system_info()
        assert result["ComputerName"] == "TEST-PC"

    @patch.object(shd, "ps")
    def test_empty_output_returns_empty_dict(self, mock_ps):
        mock_ps.return_value = None
        result = shd.collect_system_info()
        assert result == {}


# ===========================================================================
# TEST CLASS: analyze_bsod
# ===========================================================================
class TestAnalyzeBSOD:
    """Test the analyze_bsod function."""

    @patch.object(shd, "ps_events")
    def test_no_minidumps_is_info(self, mock_events):
        mock_events.return_value = []
        with patch("os.path.isdir", return_value=False):
            bsod_data, crit, warn, info = shd.analyze_bsod()
        assert len(info) == 1
        assert "No minidump directory" in info[0]

    @patch.object(shd, "ps_events")
    def test_bugcheck_code_extraction(self, mock_events):
        mock_events.side_effect = [
            # WER events
            [{"Date": "2026-03-18", "Message": "Bug check code: 0x00000139"}],
            # Kernel-Power events
            [],
        ]
        with patch("os.path.isdir", return_value=False):
            bsod_data, crit, warn, info = shd.analyze_bsod()
        assert "0x00000139" in bsod_data["BugCheckCodes"]

    @patch.object(shd, "ps_events")
    def test_unexpected_shutdowns_critical_when_recent(self, mock_events):
        recent_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mock_events.side_effect = [
            [],  # WER events
            [{"Date": recent_date, "Message": "shutdown"} for _ in range(8)],  # Kernel-Power
        ]
        with patch("os.path.isdir", return_value=False):
            bsod_data, crit, warn, info = shd.analyze_bsod()
        assert bsod_data["UnexpectedShutdowns"] == 8
        assert any("unexpected shutdowns" in c for c in crit)

    @patch.object(shd, "ps_events")
    def test_old_shutdowns_become_info(self, mock_events):
        old_date = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        mock_events.side_effect = [
            [],  # WER events
            [{"Date": old_date, "Message": "shutdown"} for _ in range(8)],  # Kernel-Power
        ]
        with patch("os.path.isdir", return_value=False):
            bsod_data, crit, warn, info = shd.analyze_bsod()
        assert bsod_data["UnexpectedShutdowns"] == 8
        assert len(crit) == 0
        assert any("historical" in i for i in info)

    @patch.object(shd, "ps_events")
    def test_few_recent_shutdowns_warning(self, mock_events):
        recent_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mock_events.side_effect = [
            [],  # WER events
            [{"Date": recent_date, "Message": "shutdown"} for _ in range(3)],  # Kernel-Power
        ]
        with patch("os.path.isdir", return_value=False):
            bsod_data, crit, warn, info = shd.analyze_bsod()
        assert len(crit) == 0
        assert any("unexpected shutdown" in w for w in warn)


# ===========================================================================
# TEST CLASS: scan_event_logs
# ===========================================================================
class TestScanEventLogs:
    """Test the scan_event_logs function."""

    @patch.object(shd, "ps_events")
    def test_recent_whea_events_trigger_critical(self, mock_events):
        recent_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mock_events.side_effect = [
            [],  # SystemCritical
            [],  # SystemErrors
            [{"Date": recent_date, "EventID": 18, "Source": "WHEA", "Level": "Error", "Message": "hw error"}],
        ]
        event_data, crit, warn, info = shd.scan_event_logs()
        assert len(event_data["WHEAErrors"]) == 1
        assert len(crit) == 1
        assert "WHEA" in crit[0]

    @patch.object(shd, "ps_events")
    def test_old_whea_events_become_info(self, mock_events):
        old_date = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        mock_events.side_effect = [
            [],  # SystemCritical
            [],  # SystemErrors
            [{"Date": old_date, "EventID": 18, "Source": "WHEA", "Level": "Error", "Message": "hw error"}],
        ]
        event_data, crit, warn, info = shd.scan_event_logs()
        assert len(event_data["WHEAErrors"]) == 1
        assert len(crit) == 0
        assert any("historical WHEA" in i for i in info)

    @patch.object(shd, "ps_events")
    def test_no_events_no_findings(self, mock_events):
        mock_events.return_value = []
        event_data, crit, warn, info = shd.scan_event_logs()
        assert len(crit) == 0
        assert len(warn) == 0


# ===========================================================================
# TEST CLASS: analyze_drivers
# ===========================================================================
class TestAnalyzeDrivers:
    """Test the analyze_drivers function."""

    @patch.object(shd, "ps")
    def test_problematic_drivers_warning(self, mock_ps):
        mock_ps.return_value = {
            "Total": 100,
            "ThirdParty": [],
            "Old": [],
            "Problematic": [{"DeviceName": "Bad Device", "ErrorCode": 22, "Status": "Error"}],
        }
        driver_data, crit, warn, info = shd.analyze_drivers()
        assert len(driver_data["ProblematicDrivers"]) == 1
        assert any("driver errors" in w for w in warn)

    @patch.object(shd, "ps")
    def test_many_old_drivers_warning(self, mock_ps):
        old = [
            {"DeviceName": f"Dev{i}", "Provider": "X", "Version": "1.0", "Date": "2022-01-01", "IsSigned": True}
            for i in range(5)
        ]
        mock_ps.return_value = {"Total": 100, "ThirdParty": old, "Old": old, "Problematic": []}
        driver_data, crit, warn, info = shd.analyze_drivers()
        assert any("over 2 years old" in w for w in warn)

    @patch.object(shd, "ps")
    def test_empty_output(self, mock_ps):
        mock_ps.return_value = None
        driver_data, crit, warn, info = shd.analyze_drivers()
        assert driver_data["TotalDrivers"] == 0
        assert driver_data["ThirdPartyDrivers"] == []


# ===========================================================================
# TEST CLASS: check_disk_health
# ===========================================================================
class TestCheckDiskHealth:
    """Test the check_disk_health function."""

    @patch.object(shd, "ps")
    def test_unhealthy_disk_critical(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [{"FriendlyName": "Bad SSD", "HealthStatus": "Warning", "ReadErrors": 0, "WriteErrors": 0}],
            "Volumes": [],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert len(crit) == 1
        assert "DISK UNHEALTHY" in crit[0]

    @patch.object(shd, "ps")
    def test_disk_errors_warning(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [{"FriendlyName": "SSD", "HealthStatus": "Healthy", "ReadErrors": 5, "WriteErrors": 0}],
            "Volumes": [],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert any("read/write errors" in w for w in warn)

    @patch.object(shd, "ps")
    def test_low_c_drive_space_warning(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [],
            "Volumes": [{"DriveLetter": "C:", "PercentFree": 7.0, "Free_GB": 60}],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert any("low on space" in w for w in warn)

    @patch.object(shd, "ps")
    def test_critically_low_space_is_critical(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [],
            "Volumes": [{"DriveLetter": "E:", "PercentFree": 3.0, "Free_GB": 2.5}],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert any("critically low" in c for c in crit)
        assert "E:" in crit[0]

    @patch.object(shd, "ps")
    def test_non_c_drive_low_space_detected(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [],
            "Volumes": [
                {"DriveLetter": "C:", "PercentFree": 50.0, "Free_GB": 400},
                {"DriveLetter": "E:", "PercentFree": 8.0, "Free_GB": 5},
            ],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert any("E:" in w for w in warn)

    @patch.object(shd, "ps")
    def test_healthy_system(self, mock_ps):
        mock_ps.return_value = {
            "Disks": [{"FriendlyName": "Good SSD", "HealthStatus": "Healthy", "ReadErrors": 0, "WriteErrors": 0}],
            "Volumes": [{"DriveLetter": "C:", "PercentFree": 55.0, "Free_GB": 400}],
        }
        disk_data, crit, warn, info = shd.check_disk_health()
        assert len(crit) == 0
        assert len(warn) == 0


# ===========================================================================
# TEST CLASS: analyze_memory
# ===========================================================================
class TestAnalyzeMemory:
    """Test the analyze_memory function."""

    @patch.object(shd, "ps")
    def test_matched_ram_no_warnings(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [{"DeviceLocator": "DIMM1", "Capacity_GB": 32, "Speed_MHz": 5600}],
            "TotalGB": 64.0,
            "Speeds": [5600, 5600],
            "Sizes": [34359738368, 34359738368],
            "UsageTotalMB": 65536,
            "UsageFreeMB": 32768,
            "UsageUsedMB": 32768,
            "UsagePctUsed": 50.0,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert len(warn) == 0
        assert len(crit) == 0
        assert mem_data["MismatchWarning"] is False
        assert mem_data["XMPWarning"] is False
        assert mem_data["UsagePctUsed"] == 50.0

    @patch.object(shd, "ps")
    def test_mismatched_speeds_warning(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 48.0,
            "Speeds": [5600, 4800],
            "Sizes": [34359738368, 34359738368],
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert mem_data["MismatchWarning"] is True
        assert any("different speeds" in w for w in warn)

    @patch.object(shd, "ps")
    def test_xmp_warning_over_5600(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 32.0,
            "Speeds": [6400],
            "Sizes": [34359738368],
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert mem_data["XMPWarning"] is True
        assert any("XMP" in w for w in warn)

    @patch.object(shd, "ps")
    def test_single_speed_normalization(self, mock_ps):
        """PS returns int for single speed — code wraps in list."""
        mock_ps.return_value = {
            "Sticks": {"DeviceLocator": "DIMM1", "Capacity_GB": 16},
            "TotalGB": 16.0,
            "Speeds": 4800,
            "Sizes": 17179869184,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert isinstance(mem_data["Sticks"], list)

    @patch.object(shd, "ps")
    def test_mismatched_sizes_warning(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 48.0,
            "Speeds": [5600, 5600],
            "Sizes": [34359738368, 17179869184],
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert any("different capacities" in w for w in warn)


# ===========================================================================
# TEST CLASS: check_thermals
# ===========================================================================
class TestCheckThermals:
    """Test the check_thermals function."""

    @patch.object(shd, "ps")
    def test_normal_temps(self, mock_ps):
        mock_ps.return_value = {
            "PowerPlan": "Balanced",
            "CPUPerformancePct": 95.0,
            "CPUThrottling": False,
            "Temperatures": [{"Zone": "TZ00", "TempC": 45.0, "TempF": 113.0}],
        }
        thermal_data, crit, warn, info = shd.check_thermals()
        assert len(crit) == 0
        assert len(warn) == 0

    @patch.object(shd, "ps")
    def test_critical_temp(self, mock_ps):
        mock_ps.return_value = {
            "PowerPlan": "High Performance",
            "CPUPerformancePct": 100.0,
            "CPUThrottling": False,
            "Temperatures": [{"Zone": "TZ00", "TempC": 95.0, "TempF": 203.0}],
        }
        thermal_data, crit, warn, info = shd.check_thermals()
        assert len(crit) == 1
        assert "CRITICALLY HIGH" in crit[0]

    @patch.object(shd, "ps")
    def test_elevated_temp_warning(self, mock_ps):
        mock_ps.return_value = {
            "PowerPlan": "Balanced",
            "CPUPerformancePct": 90.0,
            "CPUThrottling": False,
            "Temperatures": [{"Zone": "TZ00", "TempC": 85.0, "TempF": 185.0}],
        }
        thermal_data, crit, warn, info = shd.check_thermals()
        assert any("elevated" in w for w in warn)

    @patch.object(shd, "ps")
    def test_throttling_warning(self, mock_ps):
        mock_ps.return_value = {
            "PowerPlan": "Balanced",
            "CPUPerformancePct": 72.0,
            "CPUThrottling": True,
            "Temperatures": [],
        }
        thermal_data, crit, warn, info = shd.check_thermals()
        assert any("throttling" in w for w in warn)

    @patch.object(shd, "ps")
    def test_wmi_unavailable(self, mock_ps):
        mock_ps.return_value = {
            "PowerPlan": "Unknown",
            "CPUPerformancePct": "N/A",
            "CPUThrottling": False,
            "Temperatures": [{"Zone": "N/A", "TempC": "WMI unavailable", "TempF": "Install HWiNFO64"}],
        }
        thermal_data, crit, warn, info = shd.check_thermals()
        # Non-numeric temp should not crash
        assert len(crit) == 0


# ===========================================================================
# TEST CLASS: check_updates
# ===========================================================================
class TestCheckUpdates:
    """Test the check_updates function."""

    @patch.object(shd, "ps")
    def test_failed_updates_warning(self, mock_ps):
        mock_ps.return_value = [
            {"Title": "Good Update", "Date": "2025-12-01", "Result": "Succeeded"},
            {"Title": "Bad Update", "Date": "2025-11-15", "Result": "Failed"},
        ]
        updates, crit, warn, info = shd.check_updates()
        assert len(updates) == 2
        assert any("failed" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_all_succeeded(self, mock_ps):
        mock_ps.return_value = [
            {"Title": "Update 1", "Date": "2025-12-01", "Result": "Succeeded"},
        ]
        updates, crit, warn, info = shd.check_updates()
        assert len(warn) == 0

    @patch.object(shd, "ps")
    def test_single_update_normalization(self, mock_ps):
        mock_ps.return_value = {"Title": "Lone Update", "Date": "2025-12-01", "Result": "Succeeded"}
        updates, crit, warn, info = shd.check_updates()
        assert isinstance(updates, list)
        assert len(updates) == 1

    @patch.object(shd, "ps")
    def test_empty_history(self, mock_ps):
        mock_ps.return_value = None
        updates, crit, warn, info = shd.check_updates()
        assert updates == []


# ===========================================================================
# TEST CLASS: collect_reliability
# ===========================================================================
class TestCollectReliability:
    """Test the collect_reliability function."""

    @patch.object(shd, "ps_events")
    def test_returns_crashes_and_hangs(self, mock_events):
        mock_events.side_effect = [
            [{"Date": "2026-03-18", "Message": "crash"}],
            [{"Date": "2026-03-17", "Message": "hang"}],
        ]
        crashes, hangs = shd.collect_reliability()
        assert len(crashes) == 1
        assert len(hangs) == 1

    @patch.object(shd, "ps_events")
    def test_empty_results(self, mock_events):
        mock_events.return_value = []
        crashes, hangs = shd.collect_reliability()
        assert crashes == []
        assert hangs == []


# ===========================================================================
# TEST CLASS: HTML Builder Functions
# ===========================================================================
class TestHTMLBuilders:
    """Test HTML generation helper functions."""

    def test_build_table_basic(self):
        result = shd.build_table(["Name", "Value"], [["CPU", "i9-14900K"]])
        assert "<th>Name</th>" in result
        assert "<td>CPU</td>" in result

    def test_build_table_empty(self):
        result = shd.build_table(["A"], [])
        assert "<th>A</th>" in result
        assert "<td>" not in result

    def test_build_table_escapes_html(self):
        result = shd.build_table(["Test"], [["<script>xss</script>"]])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_build_findings_all_categories(self):
        result = shd.build_findings(["Critical!"], ["Warning!"], ["Info"])
        assert "findings-critical" in result
        assert "findings-warning" in result
        assert "findings-info" in result

    def test_build_findings_empty(self):
        result = shd.build_findings([], [], [])
        assert result == ""

    def test_build_bugcheck_section_with_codes(self):
        bsod_data = {"BugCheckCodes": ["0x00000139", "0x00000124"]}
        result = shd.build_bugcheck_section(bsod_data)
        assert "0x00000139" in result
        assert "0x00000124" in result
        assert "HARDWARE" in result  # 0x00000124 is in HW_CODES

    def test_build_bugcheck_section_empty(self):
        bsod_data = {"BugCheckCodes": []}
        result = shd.build_bugcheck_section(bsod_data)
        assert result == ""

    def test_build_event_table(self):
        events = [{"Date": "2026-03-18", "Source": "WER", "EventID": 1001, "Message": "test"}]
        result = shd.build_event_table(events)
        assert "2026-03-18" in result
        assert "WER" in result

    def test_build_event_table_empty(self):
        result = shd.build_event_table([])
        assert result == ""

    def test_sys_grid(self):
        result = shd.sys_grid([("CPU", "i9-14900K"), ("RAM", "64 GB")])
        assert "sys-grid" in result
        assert "i9-14900K" in result
        assert "64 GB" in result

    def test_build_intel_section_not_affected(self):
        intel_check = {"IsAffectedCPU": False}
        result = shd.build_intel_section(intel_check, [])
        assert result == ""

    def test_build_disk_cards(self):
        disk_data = {
            "Disks": [
                {
                    "FriendlyName": "SSD",
                    "HealthStatus": "Healthy",
                    "MediaType": "SSD",
                    "Size_GB": 1000,
                    "BusType": "NVMe",
                    "Wear": "2%",
                    "Temperature": "38C",
                    "PowerOnHours": 4500,
                    "ReadErrors": 0,
                    "WriteErrors": 0,
                }
            ]
        }
        result = shd.build_disk_cards(disk_data)
        assert "SSD" in result
        assert "status-ok" in result

    def test_svg_dash_calculation(self):
        for score in [0, 50, 75, 100]:
            dash = round(326.7 * score / 100, 1)
            assert 0 <= dash <= 326.7


# ===========================================================================
# TEST CLASS: email_list_html
# ===========================================================================
class TestEmailListHtml:
    """Test the email_list_html helper."""

    def test_with_items(self):
        result = shd.email_list_html(["Issue 1", "Issue 2"], "#d32f2f")
        assert "Issue 1" in result
        assert "Issue 2" in result
        assert "#d32f2f" in result

    def test_empty_list(self):
        result = shd.email_list_html([], "#d32f2f")
        assert "None found" in result

    def test_escapes_html(self):
        result = shd.email_list_html(["<script>bad</script>"], "#d32f2f")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result


# ===========================================================================
# TEST CLASS: convert_to_pdf
# ===========================================================================
class TestConvertToPDF:
    """Test the convert_to_pdf function."""

    def test_no_edge_returns_none(self):
        with patch("os.path.isfile", return_value=False):
            result = shd.convert_to_pdf("/fake/report.html")
        assert result is None

    def test_file_uri_encoding(self):
        from urllib.parse import quote

        path = r"C:\shigsapps\windesktopmgr\System Health Reports\report.html"
        file_uri = "file:///" + quote(path.replace("\\", "/"), safe=":/")
        assert "System%20Health%20Reports" in file_uri

    @patch.object(shd, "subprocess")
    @patch("os.path.isfile")
    @patch("os.path.getsize")
    def test_successful_conversion(self, mock_size, mock_isfile, mock_sp):
        # First call: edge exists, second+: PDF exists
        mock_isfile.side_effect = lambda p: True
        mock_size.return_value = 50000
        mock_sp.run.return_value.stderr = ""

        with patch.object(shd, "time"):
            result = shd.convert_to_pdf(r"C:\test\report.html")
        assert result is not None
        assert result.endswith(".pdf")


# ===========================================================================
# TEST CLASS: send_email_report
# ===========================================================================
class TestSendEmailReport:
    """Test the send_email_report function."""

    def test_no_cred_file_returns_false(self):
        with patch("os.path.isfile", return_value=False):
            result = shd.send_email_report(
                "/fake/report.html",
                None,
                {},
                {"BugCheckCodes": [], "RecentCrashes": 0, "UnexpectedShutdowns": 0},
                {"WHEAErrors": []},
                {"ProblematicDrivers": []},
                [],
                [],
                100,
                "Good",
                "2026-03-19",
            )
        assert result is False

    def test_score_tag_mapping(self):
        for score, expected in [(85, "[OK]"), (65, "[WARN]"), (45, "[POOR]"), (20, "[CRITICAL]")]:
            tag = "[OK]" if score >= 80 else "[WARN]" if score >= 60 else "[POOR]" if score >= 40 else "[CRITICAL]"
            assert tag == expected


# ===========================================================================
# TEST CLASS: build_html_report
# ===========================================================================
class TestBuildHTMLReport:
    """Test the full HTML report assembly."""

    def _minimal_args(self):
        return dict(
            sys_info={
                "ComputerName": "TEST",
                "Manufacturer": "Dell",
                "Model": "XPS",
                "CPUName": "i9-14900K",
                "TotalRAM_GB": 64,
                "OSName": "Windows 11",
                "OSVersion": "10.0",
                "OSBuild": "22631",
                "CPUCores": 24,
                "CPULogical": 32,
                "CPUMaxClock": "6000",
                "BIOSVersion": "2.18",
                "BIOSDate": "2025-01",
                "Baseboard": "Dell",
                "LastBoot": "2026-03-18",
                "Uptime": "1.00:00:00",
            },
            intel_check={
                "IsAffectedCPU": False,
                "CPUFamily": "",
                "MicrocodeVersion": "",
                "Recommendation": "",
                "Details": "",
                "BIOSDate": "",
            },
            bsod_data={
                "MinidumpFiles": [],
                "BugCheckCodes": [],
                "RecentCrashes": 0,
                "CrashSummary": [],
                "UnexpectedShutdowns": 0,
                "UnexpectedShutdownDetails": [],
            },
            event_data={"SystemCritical": [], "SystemErrors": [], "WHEAErrors": []},
            driver_data={"TotalDrivers": 0, "ThirdPartyDrivers": [], "OldDrivers": [], "ProblematicDrivers": []},
            disk_data={"Disks": [], "Volumes": []},
            mem_data={
                "Sticks": [],
                "TotalGB": 64,
                "XMPWarning": False,
                "MismatchWarning": False,
                "UsageTotalMB": 65536,
                "UsageFreeMB": 32768,
                "UsageUsedMB": 32768,
                "UsagePctUsed": 50.0,
            },
            thermal_data={"PowerPlan": "Balanced", "CPUPerformancePct": 95, "Temperatures": []},
            update_history=[],
            app_crashes=[],
            app_hangs=[],
            critical=[],
            warnings=[],
            info=[],
            score=100,
            score_label="Good",
            score_color="#22c55e",
            network_data={
                "Adapters": [
                    {"Name": "Ethernet", "InterfaceDescription": "Intel I225-V", "Status": "Up", "LinkSpeed": "1 Gbps"}
                ],
                "DNSWorking": True,
                "DNSLatencyMs": 10,
                "InternetReachable": True,
                "PingLatencyMs": 8,
            },
            cpu_data={
                "AvgCpuPct": 15.0,
                "Samples": [15.0],
                "TopProcesses": [{"ProcessName": "chrome", "CPU_Seconds": 100, "MemMB": 500}],
                "ProcessorQueueLength": 1,
            },
        )

    def test_report_contains_required_sections(self):
        html = shd.build_html_report(**self._minimal_args())
        required = [
            "System Health Diagnostic Report",
            "Key Findings",
            "BSOD / Crash Analysis",
            "Event Log Analysis",
            "Driver Analysis",
            "Disk Health",
            "Memory - RAM",
            "Thermal and Power",
            "Network Health",
            "CPU Utilization",
            "System Information",
            "Windows Updates and Integrity",
            "Application Reliability",
            "Recommended Actions",
        ]
        for section in required:
            assert section in html, f"Missing section: {section}"

    def test_report_is_valid_html(self):
        html = shd.build_html_report(**self._minimal_args())
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_score_displayed(self):
        html = shd.build_html_report(**self._minimal_args())
        assert "100" in html
        assert "Good" in html

    def test_xss_prevention(self):
        args = self._minimal_args()
        args["sys_info"]["ComputerName"] = "<script>alert(1)</script>"
        html = shd.build_html_report(**args)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


# ===========================================================================
# TEST CLASS: Edge Cases
# ===========================================================================
class TestEdgeCases:
    """Test edge cases across the module."""

    def test_is_admin_function_exists(self):
        assert callable(shd.is_admin)

    def test_cprint_doesnt_crash(self, capsys):
        shd.cprint("test message", "cyan")
        captured = capsys.readouterr()
        assert "test message" in captured.out

    def test_cprint_unknown_color(self, capsys):
        shd.cprint("test", "nonexistent")
        captured = capsys.readouterr()
        assert "test" in captured.out

    def test_constants_exist(self):
        assert hasattr(shd, "REPORT_FOLDER")
        assert hasattr(shd, "SCRIPT_DIR")
        assert hasattr(shd, "CRED_FILE")
        assert hasattr(shd, "BUGCHECK_LOOKUP")
        assert hasattr(shd, "HW_CODES")
        assert hasattr(shd, "CSS")

    def test_main_function_exists(self):
        assert callable(shd.main)


# ===========================================================================
# TEST CLASS: collect_warranty_data
# ===========================================================================
class TestCollectWarrantyData:
    """Test the collect_warranty_data function."""

    def _make_inputs(
        self, cpu_name="Intel(R) Core(TM) i9-14900K", bsod_count=3, whea_count=5, shutdowns=2, bugcheck_codes=None
    ):
        sys_info = {
            "CPUName": cpu_name,
            "BIOSVersion": "2.18.0",
            "BIOSDate": "2025-01-10",
            "Manufacturer": "Dell Inc.",
            "Model": "XPS 8960",
        }
        intel_check = {
            "IsAffectedCPU": bool(re.search(r"i[579]-1[34]\d{3}", cpu_name)),
            "CPUFamily": "Intel 14th Gen Core i9",
            "MicrocodeVersion": "0x0129",
        }
        bsod_data = {
            "RecentCrashes": bsod_count,
            "UnexpectedShutdowns": shutdowns,
            "BugCheckCodes": bugcheck_codes if bugcheck_codes is not None else ["0x00000139"],
        }
        event_data = {
            "WHEAErrors": [{"EventID": 18}] * whea_count,
        }
        return sys_info, intel_check, bsod_data, event_data

    @patch.object(shd, "ps")
    def test_returns_all_required_fields(self, mock_ps):
        mock_ps.side_effect = [
            {"ProcessorId": "BFEBFBFF000B0671", "UniqueId": "N/A", "SerialNumber": "N/A"},
            "ABC1234",
        ]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        required = [
            "CPUModel",
            "CPUSerial",
            "IsAffectedCPU",
            "MicrocodeVersion",
            "BIOSVersion",
            "BIOSDate",
            "DellServiceTag",
            "BSODCount30Days",
            "WHEAErrorCount",
            "BugCheckCodes",
            "IntelWarrantyURL",
            "DellSupportURL",
            "EvidenceSummary",
        ]
        for field in required:
            assert field in warranty, f"Missing field: {field}"

    @patch.object(shd, "ps")
    def test_affected_cpu_flag(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "TAG123"]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        assert warranty["IsAffectedCPU"] is True

    @patch.object(shd, "ps")
    def test_non_affected_cpu(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "TAG"]
        warranty = shd.collect_warranty_data(*self._make_inputs(cpu_name="AMD Ryzen 9 7950X"))
        assert warranty["IsAffectedCPU"] is False

    @patch.object(shd, "ps")
    def test_dell_service_tag_in_url(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "XYZ7890"]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        assert "XYZ7890" in warranty["DellSupportURL"]
        assert warranty["DellServiceTag"] == "XYZ7890"

    @patch.object(shd, "ps")
    def test_oem_service_tag_ignored(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "To Be Filled By O.E.M."]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        assert warranty["DellServiceTag"] == "N/A"

    @patch.object(shd, "ps")
    def test_evidence_summary_contains_key_data(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "BFEBFBFF", "SerialNumber": "N/A"}, "SVC123"]
        warranty = shd.collect_warranty_data(*self._make_inputs(bsod_count=5, whea_count=10))
        evidence = warranty["EvidenceSummary"]
        assert "i9-14900K" in evidence
        assert "BSODs in last 30 days: 5" in evidence
        assert "WHEA hardware errors: 10" in evidence
        assert "0x00000139" in evidence

    @patch.object(shd, "ps")
    def test_hw_codes_highlighted_in_evidence(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "TAG"]
        warranty = shd.collect_warranty_data(*self._make_inputs(bugcheck_codes=["0x00000124", "0x0000003B"]))
        evidence = warranty["EvidenceSummary"]
        assert "Hardware-related codes: 0x00000124" in evidence

    @patch.object(shd, "ps")
    def test_empty_bugcheck_codes(self, mock_ps):
        mock_ps.side_effect = [{"ProcessorId": "TEST", "SerialNumber": "N/A"}, "TAG"]
        sys_info, intel_check, bsod_data, event_data = self._make_inputs(bugcheck_codes=[])
        # Verify we actually passed empty codes
        assert bsod_data["BugCheckCodes"] == []
        warranty = shd.collect_warranty_data(sys_info, intel_check, bsod_data, event_data)
        assert warranty["BugCheckCodes"] == []
        assert "Bug check codes" not in warranty["EvidenceSummary"]

    @patch.object(shd, "ps")
    def test_cpu_serial_prefers_serial_number(self, mock_ps):
        mock_ps.side_effect = [
            {"ProcessorId": "BFEBFBFF", "SerialNumber": "REAL_SERIAL_123", "UniqueId": "N/A"},
            "TAG",
        ]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        assert warranty["CPUSerial"] == "REAL_SERIAL_123"

    @patch.object(shd, "ps")
    def test_cpu_serial_falls_back_to_processor_id(self, mock_ps):
        mock_ps.side_effect = [
            {"ProcessorId": "BFEBFBFF000B0671", "SerialNumber": "N/A", "UniqueId": "N/A"},
            "TAG",
        ]
        warranty = shd.collect_warranty_data(*self._make_inputs())
        assert warranty["CPUSerial"] == "BFEBFBFF000B0671"


# ===========================================================================
# TEST CLASS: build_warranty_section
# ===========================================================================
class TestBuildWarrantySection:
    """Test the build_warranty_section HTML builder."""

    def _make_warranty(self, affected=True, bsod=3, whea=5, shutdowns=2, codes=None, tag="SVC123"):
        return {
            "IsAffectedCPU": affected,
            "CPUModel": "Intel(R) Core(TM) i9-14900K",
            "CPUSerial": "BFEBFBFF000B0671",
            "MicrocodeVersion": "0x0129",
            "BIOSVersion": "2.18.0",
            "BIOSDate": "2025-01-10",
            "DellServiceTag": tag,
            "BSODCount30Days": bsod,
            "WHEAErrorCount": whea,
            "UnexpectedShutdowns": shutdowns,
            "BugCheckCodes": codes or ["0x00000139"],
            "IntelWarrantyURL": "https://warranty.intel.com",
            "DellSupportURL": f"https://dell.com/support/{tag}",
            "EvidenceSummary": "Test evidence summary",
        }

    def test_not_affected_returns_empty(self):
        warranty = self._make_warranty(affected=False)
        assert shd.build_warranty_section(warranty) == ""

    def test_affected_returns_html(self):
        html = shd.build_warranty_section(self._make_warranty())
        assert "Warranty Claim" in html
        assert "i9-14900K" in html

    def test_evidence_summary_present(self):
        html = shd.build_warranty_section(self._make_warranty())
        assert "Evidence Summary" in html
        assert "Test evidence summary" in html

    def test_intel_link_present(self):
        html = shd.build_warranty_section(self._make_warranty())
        assert "warranty.intel.com" in html

    def test_dell_link_present(self):
        html = shd.build_warranty_section(self._make_warranty())
        assert "dell.com/support" in html

    def test_bugcheck_codes_displayed(self):
        html = shd.build_warranty_section(self._make_warranty(codes=["0x00000124"]))
        assert "0x00000124" in html
        assert "badge-crit" in html  # 0x00000124 is in HW_CODES

    def test_software_code_badge(self):
        html = shd.build_warranty_section(self._make_warranty(codes=["0x0000003B"]))
        assert "badge-warn" in html  # software code

    def test_no_issues_uses_warn_border(self):
        html = shd.build_warranty_section(self._make_warranty(bsod=0, whea=0, shutdowns=0))
        assert "intel-warn" in html
        assert "intel-critical" not in html

    def test_with_issues_uses_critical_border(self):
        html = shd.build_warranty_section(self._make_warranty(bsod=5))
        assert "intel-critical" in html

    def test_xss_prevention(self):
        warranty = self._make_warranty()
        warranty["CPUModel"] = "<script>alert(1)</script>"
        html = shd.build_warranty_section(warranty)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ===========================================================================
# TEST CLASS: analyze_memory — usage checks
# ===========================================================================
class TestAnalyzeMemoryUsage:
    """Test memory usage warnings/criticals in analyze_memory."""

    @patch.object(shd, "ps")
    def test_high_usage_warning_at_92(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 64.0,
            "Speeds": [5600],
            "Sizes": [34359738368],
            "UsageTotalMB": 65536,
            "UsageFreeMB": 5243,
            "UsageUsedMB": 60293,
            "UsagePctUsed": 92.0,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert any("92.0%" in w for w in warn)
        assert len(crit) == 0

    @patch.object(shd, "ps")
    def test_85_pct_usage_is_info_not_warning(self, mock_ps):
        """85% should be info, not warning — diagnostic tool inflates usage."""
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 64.0,
            "Speeds": [5600],
            "Sizes": [34359738368],
            "UsageTotalMB": 65536,
            "UsageFreeMB": 9830,
            "UsageUsedMB": 55706,
            "UsagePctUsed": 85.0,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert len(crit) == 0
        assert len(warn) == 0
        assert any("85.0%" in i for i in info)

    @patch.object(shd, "ps")
    def test_critical_usage(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 64.0,
            "Speeds": [5600],
            "Sizes": [34359738368],
            "UsageTotalMB": 65536,
            "UsageFreeMB": 1638,
            "UsageUsedMB": 63898,
            "UsagePctUsed": 97.5,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert any("critically high" in c for c in crit)

    @patch.object(shd, "ps")
    def test_normal_usage_info(self, mock_ps):
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 64.0,
            "Speeds": [5600],
            "Sizes": [34359738368],
            "UsageTotalMB": 65536,
            "UsageFreeMB": 39322,
            "UsageUsedMB": 26214,
            "UsagePctUsed": 40.0,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert len(crit) == 0
        assert len(warn) == 0
        assert any("40.0%" in i for i in info)

    @patch.object(shd, "ps")
    def test_zero_usage_no_info(self, mock_ps):
        """When PS returns no usage data (all zeros), skip the info message."""
        mock_ps.return_value = {
            "Sticks": [],
            "TotalGB": 0,
            "Speeds": [],
            "Sizes": [],
            "UsageTotalMB": 0,
            "UsageFreeMB": 0,
            "UsageUsedMB": 0,
            "UsagePctUsed": 0,
        }
        mem_data, crit, warn, info = shd.analyze_memory()
        assert len(crit) == 0
        assert len(warn) == 0
        assert not any("usage" in i.lower() for i in info)


# ===========================================================================
# TEST CLASS: check_network_health
# ===========================================================================
class TestCheckNetworkHealth:
    """Test the check_network_health function."""

    @patch.object(shd, "ps")
    def test_healthy_network(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [
                {
                    "Name": "Ethernet",
                    "InterfaceDescription": "Intel I225-V",
                    "Status": "Up",
                    "LinkSpeed": "1 Gbps",
                    "MacAddress": "AA-BB-CC-DD-EE-FF",
                }
            ],
            "DNSWorking": True,
            "DNSLatencyMs": 15,
            "InternetReachable": True,
            "PingLatencyMs": 12,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert len(crit) == 0
        assert len(warn) == 0
        assert any("healthy" in i.lower() for i in info)
        assert net_data["InternetReachable"] is True

    @patch.object(shd, "ps")
    def test_no_internet(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [{"Name": "Ethernet", "Status": "Up"}],
            "DNSWorking": True,
            "DNSLatencyMs": 20,
            "InternetReachable": False,
            "PingLatencyMs": 0,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("unreachable" in c.lower() for c in crit)

    @patch.object(shd, "ps")
    def test_dns_failing(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [{"Name": "Ethernet", "Status": "Up"}],
            "DNSWorking": False,
            "DNSLatencyMs": 0,
            "InternetReachable": True,
            "PingLatencyMs": 10,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("dns" in c.lower() for c in crit)

    @patch.object(shd, "ps")
    def test_high_latency_warning(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [{"Name": "Wi-Fi", "Status": "Up"}],
            "DNSWorking": True,
            "DNSLatencyMs": 30,
            "InternetReachable": True,
            "PingLatencyMs": 350,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("latency" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_slow_dns_warning(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [{"Name": "Ethernet", "Status": "Up"}],
            "DNSWorking": True,
            "DNSLatencyMs": 800,
            "InternetReachable": True,
            "PingLatencyMs": 20,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("dns" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_no_active_adapters(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [{"Name": "Wi-Fi", "Status": "Disabled"}],
            "DNSWorking": False,
            "DNSLatencyMs": 0,
            "InternetReachable": False,
            "PingLatencyMs": 0,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("no active" in c.lower() for c in crit)

    @patch.object(shd, "ps")
    def test_disconnected_physical_adapter_warning(self, mock_ps):
        mock_ps.return_value = {
            "Adapters": [
                {"Name": "Ethernet", "InterfaceDescription": "Intel I225-V", "Status": "Up"},
                {"Name": "Wi-Fi", "InterfaceDescription": "Intel AX211", "Status": "Disconnected"},
            ],
            "DNSWorking": True,
            "DNSLatencyMs": 10,
            "InternetReachable": True,
            "PingLatencyMs": 10,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert any("wi-fi" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_virtual_adapters_not_warned(self, mock_ps):
        """Bluetooth, virtual NICs, and VPN adapters should not trigger warnings."""
        mock_ps.return_value = {
            "Adapters": [
                {"Name": "Ethernet", "InterfaceDescription": "Intel I225-V", "Status": "Up"},
                {
                    "Name": "Bluetooth Network Connection",
                    "InterfaceDescription": "Bluetooth Device (Personal Area Network)",
                    "Status": "Disconnected",
                },
                {
                    "Name": "Ethernet 2",
                    "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter",
                    "Status": "Disconnected",
                },
                {
                    "Name": "Local Area Connection",
                    "InterfaceDescription": "VMware Virtual Ethernet Adapter",
                    "Status": "Disconnected",
                },
            ],
            "DNSWorking": True,
            "DNSLatencyMs": 10,
            "InternetReachable": True,
            "PingLatencyMs": 10,
        }
        net_data, crit, warn, info = shd.check_network_health()
        assert len(warn) == 0

    @patch.object(shd, "ps")
    def test_empty_ps_response(self, mock_ps):
        mock_ps.return_value = None
        net_data, crit, warn, info = shd.check_network_health()
        assert net_data["InternetReachable"] is False
        assert len(crit) > 0


# ===========================================================================
# TEST CLASS: check_cpu_utilization
# ===========================================================================
class TestCheckCpuUtilization:
    """Test the check_cpu_utilization function."""

    @patch.object(shd, "ps")
    def test_normal_cpu(self, mock_ps):
        mock_ps.return_value = {
            "AvgCpuPct": 25.3,
            "Samples": [20.1, 28.5, 27.3],
            "TopProcesses": [
                {"ProcessName": "chrome", "CPU_Seconds": 120.5, "MemMB": 800},
                {"ProcessName": "python", "CPU_Seconds": 45.2, "MemMB": 200},
            ],
            "ProcessorQueueLength": 2,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert len(crit) == 0
        assert len(warn) == 0
        assert any("25.3%" in i for i in info)

    @patch.object(shd, "ps")
    def test_high_cpu_warning(self, mock_ps):
        mock_ps.return_value = {
            "AvgCpuPct": 85.0,
            "Samples": [82.0, 86.0, 87.0],
            "TopProcesses": [],
            "ProcessorQueueLength": 5,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert any("85.0%" in w for w in warn)

    @patch.object(shd, "ps")
    def test_critical_cpu(self, mock_ps):
        mock_ps.return_value = {
            "AvgCpuPct": 98.5,
            "Samples": [97.0, 99.0, 99.5],
            "TopProcesses": [],
            "ProcessorQueueLength": 15,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert any("critically high" in c for c in crit)
        assert any("queue" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_high_queue_length(self, mock_ps):
        mock_ps.return_value = {
            "AvgCpuPct": 50.0,
            "Samples": [50.0],
            "TopProcesses": [],
            "ProcessorQueueLength": 15,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert any("queue" in w.lower() for w in warn)

    @patch.object(shd, "ps")
    def test_top_processes_as_string(self, mock_ps):
        """PS sometimes returns JSON string for nested objects."""
        import json

        mock_ps.return_value = {
            "AvgCpuPct": 30.0,
            "Samples": [30.0],
            "TopProcesses": json.dumps([{"ProcessName": "svchost", "CPU_Seconds": 50, "MemMB": 100}]),
            "ProcessorQueueLength": 1,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert len(cpu_data["TopProcesses"]) == 1
        assert cpu_data["TopProcesses"][0]["ProcessName"] == "svchost"

    @patch.object(shd, "ps")
    def test_top_processes_single_dict(self, mock_ps):
        """PS returns single dict instead of list for one process."""
        mock_ps.return_value = {
            "AvgCpuPct": 10.0,
            "Samples": [10.0],
            "TopProcesses": {"ProcessName": "idle", "CPU_Seconds": 5000, "MemMB": 0},
            "ProcessorQueueLength": 0,
        }
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert isinstance(cpu_data["TopProcesses"], list)
        assert len(cpu_data["TopProcesses"]) == 1

    @patch.object(shd, "ps")
    def test_empty_ps_response(self, mock_ps):
        mock_ps.return_value = None
        cpu_data, crit, warn, info = shd.check_cpu_utilization()
        assert cpu_data["AvgCpuPct"] == 0
        assert cpu_data["TopProcesses"] == []
