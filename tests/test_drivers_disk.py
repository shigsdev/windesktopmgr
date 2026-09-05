"""Driver-health, NVIDIA, and disk-analyzer/quickwins subprocess tests.

Split out of tests/test_powershell.py (backlog #56 tech-debt: keep both
test files under the 5,000-line threshold). This module holds three
contiguous test groups that previously lived at the tail of
test_powershell.py:

  * driver-health  -- get_driver_health
  * NVIDIA         -- GPU info, driver-branch detection, update lookups, PFID
  * disk analyzer  -- analyze-path, quickwins, cleanup tools, WinSxS sizing

Nothing about the test logic changed in the move: every class, method,
decorator, and assertion is verbatim. The shared module-level test helpers
(_mock_run, _mock_wmi, _wmi_obj) stay defined in test_powershell.py and are
imported here by name -- the same cross-test-module import pattern used by
tests/test_bios_audit.py and tests/test_e2e_smoke.py.
"""

import json
import subprocess

import pytest

import disk
import gpu
import windesktopmgr as wdm
from tests.test_powershell import _mock_run, _mock_wmi, _wmi_obj

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
        result = gpu._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"
        assert result["installed"] == "591.74"
        assert result["win_ver"] == "32.0.15.9174"

    def test_no_smi_falls_back_to_wmi_only(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        result = gpu._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"
        assert result["win_ver"] == "32.0.15.9174"
        # Version derived from win_ver via _win_to_nvidia_version
        assert result["installed"] == "591.74"

    def test_no_nvidia_gpu_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.INTEL_GPU]})
        result = gpu._get_nvidia_gpu_info()
        assert result is None

    def test_wmi_error_returns_none(self, mocker):
        """With no nvidia-smi AND a WMI video-controller fault (or hang), the
        WMI lookup is bounded via bounded_wmi_query and degrades to no-info, so
        _get_nvidia_gpu_info returns None rather than raising or hanging."""
        self._mock_smi(mocker, exists=False)
        mocker.patch("windesktopmgr.pythoncom.CoInitialize")
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("WMI down"))
        assert gpu._get_nvidia_gpu_info() is None

    def test_empty_wmi_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": []})
        result = gpu._get_nvidia_gpu_info()
        assert result is None

    def test_wmi_exception_returns_none(self, mocker):
        self._mock_smi(mocker, exists=False)
        mocker.patch("windesktopmgr.wmi.WMI", side_effect=Exception("COM error"))
        result = gpu._get_nvidia_gpu_info()
        assert result is None

    def test_smi_timeout_still_tries_wmi(self, mocker):
        self._mock_smi(mocker, side_effect=subprocess.TimeoutExpired("nvidia-smi", 10))
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        # os.path.exists needs to be True for the smi path to be tried
        mocker.patch("windesktopmgr.os.path.exists", return_value=True)
        result = gpu._get_nvidia_gpu_info()
        assert result is not None
        assert result["name"] == "NVIDIA GeForce RTX 4060 Ti"

    def test_output_contract_fields(self, mocker):
        self._mock_smi(mocker, exists=False)
        _mock_wmi(mocker, {"Win32_VideoController": [self.NV_GPU]})
        result = gpu._get_nvidia_gpu_info()
        assert "name" in result
        assert "installed" in result
        assert "win_ver" in result


class TestDetectNvidiaDriverBranch:
    """Tests for _detect_nvidia_driver_branch() — detects Studio vs Game Ready.

    The IsCRD flag lives inside the NVDriver sub-object of SHIM.json,
    not at top level.  Bug 2026-05-18: reading from top level caused
    Game Ready users to be misdetected as Studio, making the API return
    nothing for their GPU.
    """

    def test_studio_detected_from_nvdriver(self, mocker, tmp_path):
        """IsCRD=True inside NVDriver → Studio."""
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"NVDriver": {"IsCRD": True, "Version": 59579}}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert gpu._detect_nvidia_driver_branch() is True

    def test_game_ready_detected_from_nvdriver(self, mocker, tmp_path):
        """IsCRD=False inside NVDriver → Game Ready."""
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"NVDriver": {"IsCRD": False, "Version": 59595}}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert gpu._detect_nvidia_driver_branch() is False

    def test_legacy_top_level_iscrd_still_works(self, mocker, tmp_path):
        """Older SHIM.json format with IsCRD at top level."""
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"IsCRD": True}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert gpu._detect_nvidia_driver_branch() is True

    def test_missing_shim_defaults_to_game_ready(self, mocker):
        """No SHIM.json → default to Game Ready (most common consumer config)."""
        mocker.patch("glob.glob", return_value=[])
        assert gpu._detect_nvidia_driver_branch() is False

    def test_nvdriver_takes_precedence_over_top_level(self, mocker, tmp_path):
        """If both exist, NVDriver.IsCRD wins."""
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"IsCRD": True, "NVDriver": {"IsCRD": False}}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        assert gpu._detect_nvidia_driver_branch() is False

    def test_null_iscrd_in_nvdriver_falls_through(self, mocker, tmp_path):
        """NVDriver.IsCRD = null → falls through to top-level or default."""
        shim = tmp_path / "SHIM.json"
        shim.write_text(json.dumps({"NVDriver": {"IsCRD": None}}))
        mocker.patch("glob.glob", return_value=[str(shim)])
        # No top-level IsCRD either → defaults to Game Ready
        assert gpu._detect_nvidia_driver_branch() is False


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
        result = gpu._query_nvidia_api(1022, studio=True)
        assert result is not None
        assert result["version"] == "595.79"

    def test_api_failure_returns_none(self, mocker):
        mocker.patch("urllib.request.urlopen", side_effect=Exception("timeout"))
        result = gpu._query_nvidia_api(1022, studio=True)
        assert result is None

    def test_bad_success_flag_returns_none(self, mocker):
        bad = json.dumps({"Success": "0", "IDS": []}).encode()
        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = bad
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("urllib.request.urlopen", return_value=mock_resp)
        result = gpu._query_nvidia_api(1022, studio=True)
        assert result is None

    def test_studio_and_game_ready_both_callable(self, mocker):
        """Both studio=True and studio=False should work without errors."""
        mocker.patch("urllib.request.urlopen", side_effect=Exception("skip"))
        # Both calls should handle the exception gracefully and return None
        assert gpu._query_nvidia_api(1022, studio=True) is None
        assert gpu._query_nvidia_api(1022, studio=False) is None

    def test_response_read_is_size_capped(self, mocker):
        """The response body read must be bounded so a hijacked endpoint or
        broken proxy can't OOM the process. Regression for the 2026-05-21
        review finding — resp.read() was previously unbounded.
        """
        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = self.GOOD_RESPONSE
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("urllib.request.urlopen", return_value=mock_resp)
        gpu._query_nvidia_api(1022, studio=True)
        # read() must be called with an explicit positive byte limit.
        mock_resp.read.assert_called_once()
        args, _kwargs = mock_resp.read.call_args
        assert args, "resp.read() called with no size limit — body is unbounded"
        assert isinstance(args[0], int) and args[0] > 0

    def test_oversized_body_fails_gracefully(self, mocker):
        """A body that survives the cap but is not valid JSON (e.g. a
        truncated multi-MB response) must fall through to None, not raise.
        """
        mock_resp = mocker.MagicMock()
        mock_resp.read.return_value = b'{"Success":"1","IDS":[{"downloadInfo"'  # truncated
        mock_resp.__enter__ = mocker.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("urllib.request.urlopen", return_value=mock_resp)
        assert gpu._query_nvidia_api(1022, studio=True) is None


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

    def test_too_few_digits_passthrough(self):
        """raw shorter than the canonical 6 digits → returned unchanged.
        Regression for the 2026-05-21 review: the old `len(raw) < 3` guard
        let "32.0.1.23" (raw "123") through and emitted the garbage ".23".
        """
        assert wdm._win_to_nvidia_version("32.0.1.23") == "32.0.1.23"

    def test_too_many_digits_passthrough(self):
        """raw longer than 6 digits → returned unchanged, no garbage."""
        assert wdm._win_to_nvidia_version("32.0.150.96490") == "32.0.150.96490"

    def test_non_numeric_segments_passthrough(self):
        """Non-digit version segments → returned unchanged."""
        assert wdm._win_to_nvidia_version("32.0.1a.bcde") == "32.0.1a.bcde"


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
        mocker.patch("gpu._detect_nvidia_driver_branch", return_value=True)
        return mocker.patch("gpu._get_nvidia_gpu_info", return_value=gpu)

    def _mock_api(self, mocker, result=None):
        """Mock _query_nvidia_api — returns API result dict or None."""
        return mocker.patch("gpu._query_nvidia_api", return_value=result)

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
        mocker.patch("gpu._get_nvidia_gpu_info", return_value=None)
        mocker.patch("gpu._detect_nvidia_driver_branch", return_value=True)
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
        """When API fails and no Installer2 Cache and no WU → no update available."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Registry key exists but has no Display.Driver entries
        self._mock_winreg_cache(mocker, entries=[])
        mocker.patch("windesktopmgr.get_windows_update_drivers", return_value=None)
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["UpdateSource"] == "none"

    def test_unknown_gpu_skips_api_tries_cache(self, mocker, capsys):
        """GPU not in pfid map → skip API, try Installer2 only, and log a
        diagnostic so an unlisted GPU is visible in the console rather than
        silently looking like 'no update available' (2026-05-21 review)."""
        gpu = {"name": "NVIDIA Quadro P2000", "installed": "560.00", "win_ver": "31.0.15.6000"}
        self._mock_gpu(mocker, gpu=gpu)
        api_mock = self._mock_api(mocker)
        self._mock_winreg_cache(mocker, entries=[])
        mocker.patch("windesktopmgr.get_windows_update_drivers", return_value=None)
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        # API should NOT be called since pfid is not in the map
        api_mock.assert_not_called()
        # The unlisted GPU must be logged with its name.
        out = capsys.readouterr().out
        assert "no PFID mapping" in out
        assert "Quadro P2000" in out

    def test_alt_branch_success_logs_branch_misdetection(self, mocker, capsys):
        """When the alt branch succeeds where the primary failed, a warning
        must be logged — branch misdetection should be visible, not silently
        papered over by the retry (2026-05-21 review)."""
        self._mock_gpu(mocker)  # _detect_nvidia_driver_branch → True (Studio)

        def _side_effect(pfid, *, studio=True):
            if studio:
                return None
            return {"version": "596.49", "url": "", "date": "", "name": "Game Ready"}

        mocker.patch("gpu._query_nvidia_api", side_effect=_side_effect)
        wdm.get_nvidia_update_info()
        out = capsys.readouterr().out
        assert "branch detection" in out
        assert "Studio" in out and "Game Ready" in out

    def test_primary_branch_fails_falls_back_to_alt_branch(self, mocker):
        """Primary branch API returns None → tries the other branch.
        Bug 2026-05-18: SHIM.json IsCRD was nested inside NVDriver,
        causing Studio misdetection on a Game Ready user. Alt-branch
        fallback ensures we still find the update."""
        self._mock_gpu(mocker)

        # Primary branch (Studio) returns None, alt (Game Ready) has an update
        def _side_effect(pfid, *, studio=True):
            if studio:
                return None  # Studio has nothing for this GPU
            return {"version": "596.49", "url": "", "date": "", "name": "Game Ready"}

        api_mock = mocker.patch("gpu._query_nvidia_api", side_effect=_side_effect)
        result = wdm.get_nvidia_update_info()
        # API should be called TWICE (primary + alt branch)
        assert api_mock.call_count == 2
        assert result["UpdateAvailable"] is True
        assert result["LatestVersion"] == "596.49"
        assert result["UpdateSource"] == "nvidia_api"

    def test_both_branches_fail_returns_no_update(self, mocker):
        """Both Studio and Game Ready APIs return None → no update found."""
        self._mock_gpu(mocker)
        api_mock = mocker.patch("gpu._query_nvidia_api", return_value=None)
        self._mock_winreg_cache(mocker, entries=[])
        mocker.patch("windesktopmgr.get_windows_update_drivers", return_value=None)
        result = wdm.get_nvidia_update_info()
        # API should be called TWICE (primary + alt)
        assert api_mock.call_count == 2
        assert result["UpdateSource"] == "none"
        assert result["UpdateAvailable"] is False

    def test_installer2_cache_key_missing_still_returns_result(self, mocker):
        """Installer2 registry key missing → graceful fallback, still returns GPU info."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        # Simulate key not found
        self._mock_winreg_cache(mocker, entries=None)
        mocker.patch("windesktopmgr.get_windows_update_drivers", return_value=None)
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

    def test_wu_fallback_catches_pending_nvidia_update(self, mocker):
        """Method 3: When API + Installer2 both miss, WU pending list catches
        the update. This is the exact failure mode from the 2026-05-18 user
        report — NVIDIA App notified the user but the public API hadn't
        published the new driver yet."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        self._mock_winreg_cache(mocker, entries=[])
        # WU has a pending NVIDIA driver update
        mocker.patch(
            "windesktopmgr.get_windows_update_drivers",
            return_value={
                "nvidia geforce rtx 4060 ti - display - 32.0.15.9579": {
                    "Title": "NVIDIA GeForce RTX 4060 Ti - Display - 32.0.15.9579",
                    "DriverVersion": "32.0.15.9579",
                    "DriverModel": "NVIDIA GeForce RTX 4060 Ti",
                }
            },
        )
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is True
        assert result["LatestVersion"] == "595.79"  # converted from 32.0.15.9579
        assert result["UpdateSource"] == "windows_update"

    def test_wu_fallback_skipped_when_api_found_update(self, mocker):
        """WU is not queried when the API already found an update."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=self.API_RESULT)
        wu_mock = mocker.patch("windesktopmgr.get_windows_update_drivers")
        result = wdm.get_nvidia_update_info()
        assert result["UpdateAvailable"] is True
        assert result["UpdateSource"] == "nvidia_api"
        wu_mock.assert_not_called()

    def test_wu_fallback_handles_wu_failure_gracefully(self, mocker):
        """WU query failure → no crash, just no update detected."""
        self._mock_gpu(mocker)
        self._mock_api(mocker, result=None)
        self._mock_winreg_cache(mocker, entries=[])
        mocker.patch("windesktopmgr.get_windows_update_drivers", side_effect=Exception("COM error"))
        result = wdm.get_nvidia_update_info()
        assert result is not None
        assert result["UpdateAvailable"] is False
        assert result["UpdateSource"] == "none"

    def test_cache_returns_same_result_on_second_call(self, mocker):
        """Second call within 10 min returns cached result without re-querying."""
        self._mock_gpu(mocker)
        api_mock = self._mock_api(mocker, result=self.API_RESULT)
        r1 = wdm.get_nvidia_update_info()
        r2 = wdm.get_nvidia_update_info()
        assert r1 == r2
        # API should only be called once — second call served from cache
        api_mock.assert_called_once()

    def test_cache_cleared_by_reset_helper(self, mocker):
        """_reset_nvidia_update_cache() forces a fresh query next time."""
        self._mock_gpu(mocker)
        api_mock = self._mock_api(mocker, result=self.API_RESULT)
        wdm.get_nvidia_update_info()
        wdm._reset_nvidia_update_cache()
        wdm.get_nvidia_update_info()
        assert api_mock.call_count == 2

    def test_cache_invalidates_when_installed_version_changes(self, mocker):
        """Regression for 2026-05-20 "NVIDIA driver stuck on Update Available"
        bug. When the user installs the new driver, the cached
        InstalledVersion no longer matches the actual installed version.
        The cache must invalidate and recompute so the UI clears
        immediately on the next dashboard refresh -- not 10 minutes later
        when the TTL happens to expire.
        """
        # First call: cache populated with InstalledVersion=591.74 and an
        # update from 595.79. (Update Available state.)
        self._mock_gpu(mocker)
        api_mock = self._mock_api(mocker, result=self.API_RESULT)
        r1 = wdm.get_nvidia_update_info()
        assert r1["InstalledVersion"] == "591.74"
        assert r1["UpdateAvailable"] is True
        assert api_mock.call_count == 1

        # User installs 595.79. Same nvidia-smi/WMI now reports the newer
        # version. The cache still has the stale 591.74 entry but its TTL
        # has not elapsed.
        updated_gpu = {
            "name": "NVIDIA GeForce RTX 4060 Ti",
            "installed": "595.79",
            "win_ver": "32.0.15.9579",
        }
        mocker.patch("gpu._get_nvidia_gpu_info", return_value=updated_gpu)

        # Second call: must NOT serve the stale "Update Available" cache.
        # The API now returns 595.79 as latest (matches installed) -> no
        # update available.
        api_mock2 = mocker.patch(
            "gpu._query_nvidia_api",
            return_value={"version": "595.79", "url": "", "date": "", "name": "Studio"},
        )
        r2 = wdm.get_nvidia_update_info()
        assert r2["InstalledVersion"] == "595.79"
        assert r2["UpdateAvailable"] is False, (
            "Cache must invalidate when installed version changes — "
            "otherwise the dashboard stays stuck on Update Available "
            "after the user runs the install."
        )
        # API was called fresh (cache was invalidated, not served).
        assert api_mock2.call_count == 1

    def test_cache_still_hit_when_installed_version_unchanged(self, mocker):
        """The version-aware cache must not over-invalidate. When the
        installed version is the same as cached, the second call must
        still skip the expensive API/WU calls and serve from cache.

        Counterpart to test_cache_invalidates_when_installed_version_changes:
        that test proves a version *change* recomputes; this proves a
        version *match* does not. The ``is`` assertion verifies the exact
        cached object is handed back — not a recomputed-but-equal dict —
        so a regression that always recomputed would fail here.
        """
        self._mock_gpu(mocker)
        api_mock = self._mock_api(mocker, result=self.API_RESULT)
        r1 = wdm.get_nvidia_update_info()
        r2 = wdm.get_nvidia_update_info()
        # Same object identity -> genuinely served from cache, not recomputed.
        assert r1 is r2
        # API only called once -- second call hit the cache despite the
        # new pre-cache GPU read.
        assert api_mock.call_count == 1

    def test_empty_installed_version_returns_none(self, mocker):
        """Regression for the 2026-05-21 review finding. When
        _get_nvidia_gpu_info() yields a GPU dict with no usable installed
        version (nvidia-smi absent + WMI returned no DriverVersion),
        get_nvidia_update_info() must bail out with None rather than run —
        and cache — a result keyed on an empty string. A cached "" entry
        caused a full ~5s API+WU recompute on every call whenever a later
        WMI read flickered the real version back.
        """
        blank_gpu = {"name": "NVIDIA GeForce RTX 4060 Ti", "installed": "", "win_ver": ""}
        self._mock_gpu(mocker, gpu=blank_gpu)
        api_mock = self._mock_api(mocker, result=self.API_RESULT)
        result = wdm.get_nvidia_update_info()
        assert result is None
        # The expensive API path must be skipped entirely.
        api_mock.assert_not_called()
        # Nothing cached -- a later call with a real version recomputes clean.
        assert gpu._nvidia_update_cache["data"] is None

    def test_concurrent_calls_are_thread_safe(self, mocker):
        """get_nvidia_update_info() is called concurrently by the dashboard
        fan-out, run_scan(), and /api/nvidia/status. The cache lock must
        keep the (data, ts) pair consistent — 12 parallel callers must all
        get a valid, identical result and none may raise.
        """
        import concurrent.futures

        self._mock_gpu(mocker)
        self._mock_api(mocker, result=self.API_RESULT)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            results = list(ex.map(lambda _: wdm.get_nvidia_update_info(), range(12)))
        assert all(r is not None for r in results)
        assert all(r["InstalledVersion"] == "591.74" for r in results)
        assert all(r["UpdateAvailable"] is True for r in results)


class TestLookupNvidiaPfid:
    """Tests for _lookup_nvidia_pfid() — fuzzy GPU name → product family ID.

    Covers:
    - Exact match (canonical name)
    - Missing "NVIDIA" prefix (WMI output)
    - Extra suffixes ("8GB", "16GB", "Laptop GPU")
    - Case insensitivity
    - Unknown GPU returns None
    """

    def test_exact_match(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 4060 Ti") == 1022

    def test_rtx_30_series_in_map(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 3080") == 889

    def test_rtx_20_series_in_map(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 2070 SUPER") == 855

    def test_gtx_16_series_in_map(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce GTX 1660") == 845

    def test_missing_nvidia_prefix(self):
        """WMI sometimes returns 'GeForce RTX 4060 Ti' without NVIDIA prefix."""
        assert gpu._lookup_nvidia_pfid("GeForce RTX 4060 Ti") == 1022

    def test_extra_suffix_8gb(self):
        """nvidia-smi on some systems appends VRAM size."""
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 4060 Ti 8GB") == 1022

    def test_extra_suffix_16gb(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 4060 Ti 16GB") == 1022

    def test_case_insensitive(self):
        assert gpu._lookup_nvidia_pfid("nvidia geforce rtx 4060 ti") == 1022

    def test_unknown_gpu_returns_none(self):
        assert gpu._lookup_nvidia_pfid("NVIDIA Quadro P2000") is None

    def test_empty_string_returns_none(self):
        assert gpu._lookup_nvidia_pfid("") is None

    def test_extra_whitespace(self):
        assert gpu._lookup_nvidia_pfid("  NVIDIA  GeForce  RTX  4060  Ti  ") == 1022

    def test_super_suffix_not_confused_with_base(self):
        """RTX 4080 SUPER (pfid 1041) must not match RTX 4080 (pfid 996)."""
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 4080 SUPER") == 1041
        assert gpu._lookup_nvidia_pfid("NVIDIA GeForce RTX 4080") == 996


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


class TestDescribeDiskLocation:
    """Parse MSFT_PhysicalDisk.PhysicalLocation into slot/bus + a find-it hint."""

    def test_add_in_card_slot(self):
        info = disk.describe_disk_location("PCI Slot 1 : Bus 6 : Device 0 : Function 0 : Adapter 1", "NVMe")
        assert info["slot"] == "PCI Slot 1"
        assert info["bus"] == 6
        assert info["integrated"] is False
        assert "add-in" in info["hint"].lower()
        assert "serial" in info["hint"].lower()

    def test_integrated_slot(self):
        info = disk.describe_disk_location("Integrated : Bus 0 : Device 14 : Function 0 : Adapter 0", "NVMe")
        assert info["integrated"] is True
        assert "motherboard" in info["hint"].lower()

    def test_empty_location(self):
        info = disk.describe_disk_location("", "NVMe")
        assert info["slot"] == ""
        assert info["bus"] is None
        assert "not reported" in info["hint"].lower()

    def test_unparseable_location_has_no_bus(self):
        info = disk.describe_disk_location("some weird string", "")
        assert info["slot"] == ""
        assert info["bus"] is None
        assert info["hint"]  # non-empty, doesn't guess a slot


class TestBuildPcieCardTopology:
    """Group disks into add-in-card sockets vs onboard M.2 + flag the failed one.
    Modelled on this machine: 2 onboard M.2 + a 4x M.2 switch card whose ...20C4
    drive is pool-Retired while SMART still reads Healthy."""

    def _phys(self, name, serial, health, location):
        return {
            "Name": name,
            "SerialNumber": serial,
            "Health": health,
            "SizeGB": 1863.0,
            "LocationInfo": disk.describe_disk_location(location, "NVMe"),
        }

    def _machine(self):
        physical = [
            self._phys("Samsung 990 PRO 1TB", "AAAA.", "Healthy", "Integrated : Bus 0 : Device 14 : Function 0"),
            self._phys("SK hynix PC811 1TB", "BBBB.", "Healthy", "Integrated : Bus 0 : Device 14 : Function 0"),
            # card drives, deliberately out of bus order to prove sorting
            self._phys("Samsung 970 EVO Plus 2TB", "9E72.", "Healthy", "PCI Slot 13 : Bus 15 : Device 0 : Adapter 4"),
            self._phys("Samsung 990 PRO 2TB", "20C4.", "Healthy", "PCI Slot 1 : Bus 6 : Device 0 : Adapter 1"),
            self._phys("Samsung 990 PRO 2TB", "29B7.", "Healthy", "PCI Slot 5 : Bus 9 : Device 0 : Adapter 2"),
            self._phys("Samsung 970 EVO Plus 2TB", "18B5.", "Healthy", "PCI Slot 9 : Bus 12 : Device 0 : Adapter 3"),
        ]
        members = [
            {"Serial": "20C4.", "Usage": "Retired", "Health": "Healthy"},
            {"Serial": "29B7.", "Usage": "Auto-Select", "Health": "Healthy"},
            {"Serial": "18B5.", "Usage": "Auto-Select", "Health": "Healthy"},
            {"Serial": "9E72.", "Usage": "Auto-Select", "Health": "Healthy"},
        ]
        return physical, members

    def test_onboard_split_from_card(self):
        physical, members = self._machine()
        topo = disk.build_pcie_card_topology(physical, members)
        assert topo["has_card"] is True
        assert len(topo["onboard"]) == 2
        assert len(topo["card_drives"]) == 4

    def test_sockets_ordered_by_bus(self):
        physical, members = self._machine()
        topo = disk.build_pcie_card_topology(physical, members)
        sockets = [(d["socket"], d["bus"], d["serial_short"]) for d in topo["card_drives"]]
        assert sockets == [(1, 6, "20C4"), (2, 9, "29B7"), (3, 12, "18B5"), (4, 15, "9E72")]

    def test_retired_flag_wins_over_healthy_smart(self):
        """The definitive case: ...20C4 reads Healthy but is pool-Retired -> failed."""
        physical, members = self._machine()
        topo = disk.build_pcie_card_topology(physical, members)
        failed = topo["card_drives"][0]
        assert failed["serial_short"] == "20C4"
        assert failed["retired"] is True
        assert failed["flag"] == "retired"
        assert topo["failed_serial_short"] == "20C4"
        # the healthy siblings are not flagged
        assert all(d["flag"] == "ok" for d in topo["card_drives"][1:])

    def test_unhealthy_flag_without_pool(self):
        physical = [self._phys("Some NVMe 2TB", "DEAD.", "Unhealthy", "PCI Slot 1 : Bus 6 : Device 0 : Adapter 1")]
        topo = disk.build_pcie_card_topology(physical, members=[])
        assert topo["card_drives"][0]["flag"] == "unhealthy"
        assert topo["failed_serial_short"] == "DEAD"

    def test_no_card_all_onboard(self):
        physical = [self._phys("Boot 1TB", "AAAA.", "Healthy", "Integrated : Bus 0 : Device 14")]
        topo = disk.build_pcie_card_topology(physical, members=[])
        assert topo["has_card"] is False
        assert topo["card_drives"] == []
        assert len(topo["onboard"]) == 1

    def test_empty_input_safe(self):
        topo = disk.build_pcie_card_topology([], [])
        assert topo["has_card"] is False
        assert topo["failed_serial"] == ""
        assert topo["note"]

    def test_note_says_verify_by_serial(self):
        physical, members = self._machine()
        topo = disk.build_pcie_card_topology(physical, members)
        assert "serial" in topo["note"].lower()


class TestGetStorageSpaces:
    def _mock(self, mocker, payload, returncode=0):
        m = mocker.patch("disk.subprocess.run")
        m.return_value.stdout = payload if isinstance(payload, str) else json.dumps(payload)
        m.return_value.returncode = returncode
        m.return_value.stderr = ""
        return m

    def test_degraded_pool_parsed(self, mocker):
        self._mock(
            mocker,
            {
                "pools": [{"Name": "Storage pool", "Health": "Warning", "Operational": "Degraded", "FreeGB": 708}],
                "virtual_disks": [
                    {
                        "Name": "Storage space",
                        "Health": "Warning",
                        "Operational": "Degraded",
                        "Resiliency": "Parity",
                        "Redundancy": 1,
                    }
                ],
                "members": [
                    {
                        "Pool": "Storage pool",
                        "Name": "Samsung SSD 990 PRO 2TB",
                        "Serial": "...20C4",
                        "Health": "Warning",
                        "Operational": "IO Error, OK",
                        "Usage": "Auto-Select",
                        "Location": "PCI Slot 1 : Bus 6",
                        "SizeGB": 1863,
                    }
                ],
                "repair_jobs": [{"Name": "Storage space-Repair", "State": "Suspended", "Pct": 0}],
            },
        )
        ss = disk.get_storage_spaces()
        assert ss["has_spaces"] is True
        assert ss["virtual_disks"][0]["Operational"] == "Degraded"
        assert ss["repair_jobs"][0]["State"] == "Suspended"
        # member location enriched
        assert ss["members"][0]["LocationInfo"]["bus"] == 6

    def test_no_spaces_returns_has_spaces_false(self, mocker):
        self._mock(mocker, {})
        ss = disk.get_storage_spaces()
        assert ss["has_spaces"] is False
        assert ss["pools"] == []

    def test_single_object_normalized_to_list(self, mocker):
        self._mock(
            mocker,
            {
                "pools": {"Name": "P", "Health": "Healthy", "Operational": "OK"},
                "virtual_disks": {"Name": "V", "Health": "Healthy", "Operational": "OK"},
                "members": {"Pool": "P", "Name": "D", "Location": ""},
                "repair_jobs": {"Name": "J", "State": "Running"},
            },
        )
        ss = disk.get_storage_spaces()
        assert isinstance(ss["pools"], list) and len(ss["pools"]) == 1
        assert isinstance(ss["virtual_disks"], list) and len(ss["virtual_disks"]) == 1
        assert ss["has_spaces"] is True

    def test_malformed_json_falls_back(self, mocker):
        self._mock(mocker, "not json at all")
        ss = disk.get_storage_spaces()
        assert ss["has_spaces"] is False
        assert ss["pools"] == []

    def test_timeout_falls_back(self, mocker):
        mocker.patch("disk.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=60))
        ss = disk.get_storage_spaces()
        assert ss == {"pools": [], "virtual_disks": [], "members": [], "repair_jobs": [], "has_spaces": False}

    def test_command_queries_the_right_cmdlets(self, mocker):
        m = self._mock(mocker, {})
        disk.get_storage_spaces()
        joined = " ".join(m.call_args[0][0])
        assert "Get-StoragePool" in joined
        assert "Get-VirtualDisk" in joined
        assert "Get-StorageJob" in joined


class TestDiskSnooze:
    """Drive-health snooze store: pause alerts for one drive by serial."""

    @pytest.fixture(autouse=True)
    def _tmp_snooze(self, tmp_path, monkeypatch):
        monkeypatch.setattr(disk, "DISK_SNOOZE_FILE", str(tmp_path / "disk_snoozes.json"))

    def test_normalize_serial(self):
        assert disk._normalize_serial("0025_384C_3145_20C4.") == "0025384c314520c4"
        assert disk._normalize_serial("") == ""
        assert disk._normalize_serial(None) == ""

    def test_add_then_snoozed_by_normalized_serial(self):
        disk.add_disk_snooze("ABC-123.", 24)
        assert disk.is_disk_snoozed("abc123")  # normalized match
        assert disk.is_disk_snoozed("ABC-123.")
        assert not disk.is_disk_snoozed("OTHER")

    def test_add_rejects_bad_hours(self):
        assert disk.add_disk_snooze("x", 0)["ok"] is False
        assert disk.add_disk_snooze("x", 999)["ok"] is False
        assert disk.add_disk_snooze("x", -5)["ok"] is False

    def test_add_rejects_empty_serial(self):
        assert disk.add_disk_snooze("", 24)["ok"] is False
        assert disk.add_disk_snooze("...", 24)["ok"] is False  # normalizes to empty

    def test_remove(self):
        disk.add_disk_snooze("s1", 24)
        assert disk.remove_disk_snooze("s1")["removed"] is True
        assert not disk.is_disk_snoozed("s1")
        assert disk.remove_disk_snooze("neverthere")["removed"] is False

    def test_expired_dropped_on_load(self):
        import datetime as _dt

        past = (_dt.datetime.now() - _dt.timedelta(hours=1)).isoformat()
        future = (_dt.datetime.now() + _dt.timedelta(hours=1)).isoformat()
        with open(disk.DISK_SNOOZE_FILE, "w", encoding="utf-8") as f:
            json.dump({"old": past, "new": future}, f)
        snz = disk._load_disk_snoozes()
        assert "old" not in snz
        assert "new" in snz

    def test_malformed_file_safe(self):
        with open(disk.DISK_SNOOZE_FILE, "w", encoding="utf-8") as f:
            f.write("not json at all")
        assert disk._load_disk_snoozes() == {}

    def test_missing_file_empty(self):
        assert disk._load_disk_snoozes() == {}
