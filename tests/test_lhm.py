"""tests/test_lhm.py — LibreHardwareMonitor in-app installer (lhm.py).

Covers the download/verify/extract pipeline, the HTTP web-server sensor read
(LHM has NO WMI provider), the "is running" probe, the zip-slip guard, the URL
allow-list, the elevated UAC launch, and the auto-start task. Everything is
mocked — no real network, no real subprocess.
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile

import pytest

import lhm


def _make_lhm_zip(*, include_exe: bool = True, extra_member: str | None = None) -> bytes:
    """Build an in-memory zip resembling the LHM release archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if include_exe:
            zf.writestr("LibreHardwareMonitor.exe", b"MZ fake-exe-bytes")
            zf.writestr("LibreHardwareMonitorLib.dll", b"dll-bytes")
        if extra_member:
            zf.writestr(extra_member, b"evil-payload")
    return buf.getvalue()


class _FakeResp:
    def __init__(self, data: bytes, ok: bool = True):
        self._data = data
        self._ok = ok

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError("HTTP 404")

    def iter_content(self, chunk_size: int = 65536):
        for i in range(0, len(self._data), chunk_size):
            yield self._data[i : i + chunk_size]


# ── URL allow-list ─────────────────────────────────────────────────────────


class TestValidateUrl:
    def test_pinned_release_url_is_allowed(self):
        assert lhm._validate_url(lhm.LHM_URL) is True

    def test_githubusercontent_allowed(self):
        assert lhm._validate_url("https://objects.githubusercontent.com/x.zip") is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/x.zip",  # not https
            "https://evil.com/LibreHardwareMonitor.zip",  # wrong host
            "https://github.com.evil.com/x.zip",  # suffix trick
            "ftp://github.com/x.zip",
            "not a url",
        ],
    )
    def test_rejected_urls(self, url):
        assert lhm._validate_url(url) is False


# ── zip-slip guard ─────────────────────────────────────────────────────────


class TestSafeExtract:
    def test_normal_zip_extracts(self, tmp_path):
        zpath = tmp_path / "ok.zip"
        zpath.write_bytes(_make_lhm_zip())
        dest = tmp_path / "out"
        dest.mkdir()
        lhm._safe_extract(str(zpath), str(dest))
        assert (dest / "LibreHardwareMonitor.exe").is_file()

    def test_zip_slip_member_aborts(self, tmp_path):
        zpath = tmp_path / "evil.zip"
        zpath.write_bytes(_make_lhm_zip(extra_member="../escape.txt"))
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ValueError, match="escapes install dir"):
            lhm._safe_extract(str(zpath), str(dest))
        # The traversal target must NOT have been written.
        assert not (tmp_path / "escape.txt").exists()


# ── is_installed / is_running / lhm_status ─────────────────────────────────


class TestStatus:
    def test_is_installed_true_when_exe_present(self, mocker):
        mocker.patch("lhm.os.path.isfile", return_value=True)
        assert lhm.is_installed() is True

    def test_is_installed_false_when_absent(self, mocker):
        mocker.patch("lhm.os.path.isfile", return_value=False)
        assert lhm.is_installed() is False

    def test_is_running_true_when_web_server_has_temps(self, mocker):
        mocker.patch.object(lhm, "get_lhm_temps", return_value=[{"Name": "Core Max", "TempC": 38.0}])
        assert lhm.is_running() is True

    def test_is_running_false_when_no_temps(self, mocker):
        mocker.patch.object(lhm, "get_lhm_temps", return_value=[])
        assert lhm.is_running() is False

    def test_lhm_status_shape(self, mocker):
        mocker.patch("lhm.is_installed", return_value=True)
        mocker.patch("lhm.is_running", return_value=False)
        st = lhm.lhm_status()
        assert st["installed"] is True
        assert st["running"] is False
        assert st["version"] == lhm.LHM_VERSION
        assert st["exe"].endswith("LibreHardwareMonitor.exe")
        assert "install_dir" in st


# ── LHM web server read (the real data path; LHM has no WMI provider) ──────


_LHM_TREE = {
    "Text": "Sensor",
    "Children": [
        {
            "Text": "Intel Core i9-14900K",
            "Children": [
                {
                    "Text": "Temperatures",
                    "Children": [
                        {
                            "Text": "Core Max",
                            "Value": "38.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/intelcpu/0/temperature/0",
                        },
                        {
                            "Text": "P-Core #1",
                            "Value": "34.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/intelcpu/0/temperature/2",
                        },
                        # Distance-to-TjMax is typed Temperature but is HEADROOM, not a temp -> excluded.
                        {
                            "Text": "Core #1 Distance to TjMax",
                            "Value": "66.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/intelcpu/0/temperature/9",
                        },
                        # Non-temperature sensor -> ignored.
                        {"Text": "Bus Speed", "Value": "100.0 MHz", "Type": "Clock", "SensorId": "/intelcpu/0/clock/0"},
                    ],
                }
            ],
        },
        {
            "Text": "NVIDIA RTX 4060 Ti",
            "Children": [
                {
                    "Text": "GPU Core",
                    "Value": "47.0 °C",
                    "Type": "Temperature",
                    "SensorId": "/gpu-nvidia/0/temperature/0",
                },
            ],
        },
    ],
}


def _resp(payload, ok=True):
    r = type("R", (), {})()
    r.json = lambda: payload
    r.raise_for_status = (lambda: None) if ok else (lambda: (_ for _ in ()).throw(RuntimeError("404")))
    return r


class TestParseTempValue:
    def test_celsius_string(self):
        assert lhm._parse_temp_value("38.0 °C") == 38.0

    def test_comma_decimal(self):
        assert lhm._parse_temp_value("38,5 °C") == 38.5

    def test_negative(self):
        assert lhm._parse_temp_value("-5.0 °C") == -5.0

    def test_garbage_returns_none(self):
        assert lhm._parse_temp_value("n/a") is None

    def test_empty_returns_none(self):
        assert lhm._parse_temp_value("") is None


class TestIsReadingTemp:
    """Threshold / headroom / metadata pseudo-sensors LHM mistypes as
    Temperature must be rejected (2026-06-17 false elevated-temp alert)."""

    def test_real_readings_accepted(self):
        for name in ("Core Max", "P-Core #1", "GPU Core", "Composite Temperature", "Temperature #1", "DIMM #0"):
            assert lhm._is_reading_temp(name), name

    def test_bare_limit_word_is_kept(self):
        # Only the "high limit"/"low limit" threshold suffixes are excluded --
        # a real reading that merely contains the word "limit" must survive
        # (code-review 2026-06-17: bare "limit" substring was too broad).
        assert lhm._is_reading_temp("Power Limit Temperature")
        assert lhm._is_reading_temp("CPU Temp Limit Zone")

    def test_threshold_and_metadata_rejected(self):
        for name in (
            "Core #1 Distance to TjMax",
            "Thermal Sensor Low Limit",
            "Thermal Sensor High Limit",
            "Thermal Sensor Critical Low Limit",
            "Thermal Sensor Critical High Limit",
            "Temperature Sensor Resolution",
            "Warning Temperature",
            "Critical Temperature",
        ):
            assert not lhm._is_reading_temp(name), name

    def test_case_insensitive(self):
        assert not lhm._is_reading_temp("CRITICAL TEMPERATURE")
        assert not lhm._is_reading_temp("thermal sensor critical high LIMIT")

    def test_none_safe(self):
        assert lhm._is_reading_temp(None) is True  # missing name -> treat as a reading (parse_value still guards)


class TestGetLhmTemps:
    def test_parses_tree_excludes_distance_and_nontemp(self, mocker):
        mocker.patch("requests.get", return_value=_resp(_LHM_TREE))
        temps = lhm.get_lhm_temps()
        names = {t["Name"] for t in temps}
        assert names == {"Core Max", "P-Core #1", "GPU Core"}  # distance + Clock excluded
        assert all(t["Source"] == "LibreHardwareMonitor" for t in temps)
        core = next(t for t in temps if t["Name"] == "P-Core #1")
        assert core["TempC"] == 34.0
        assert core["SensorId"] == "/intelcpu/0/temperature/2"

    def test_excludes_ssd_dimm_threshold_pseudo_sensors(self, mocker):
        # The 2026-06-17 false-alarm tree: an NVMe drive + a DIMM exposing
        # their static threshold registers as Temperature sensors. Only the
        # real Composite Temperature reading should survive.
        tree = {
            "Text": "Sensor",
            "Children": [
                {
                    "Text": "Samsung SSD 990",
                    "Children": [
                        {
                            "Text": "Composite Temperature",
                            "Value": "41.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/nvme/0/temperature/0",
                        },
                        {
                            "Text": "Warning Temperature",
                            "Value": "81.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/nvme/0/temperature/1",
                        },
                        {
                            "Text": "Critical Temperature",
                            "Value": "84.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/nvme/0/temperature/2",
                        },
                    ],
                },
                {
                    "Text": "DIMM #0",
                    "Children": [
                        {
                            "Text": "Temperature Sensor Resolution",
                            "Value": "0.3 °C",
                            "Type": "Temperature",
                            "SensorId": "/ram/0/temperature/0",
                        },
                        {
                            "Text": "Thermal Sensor High Limit",
                            "Value": "55.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/ram/0/temperature/1",
                        },
                        {
                            "Text": "Thermal Sensor Critical High Limit",
                            "Value": "85.0 °C",
                            "Type": "Temperature",
                            "SensorId": "/ram/0/temperature/2",
                        },
                    ],
                },
            ],
        }
        mocker.patch("requests.get", return_value=_resp(tree))
        temps = lhm.get_lhm_temps()
        names = {t["Name"] for t in temps}
        assert names == {"Composite Temperature"}, f"only the real reading should survive; got {names}"
        assert next(t for t in temps if t["Name"] == "Composite Temperature")["TempC"] == 41.0

    def test_empty_when_server_down(self, mocker):
        mocker.patch("requests.get", side_effect=OSError("connection refused"))
        assert lhm.get_lhm_temps() == []

    def test_empty_on_timeout(self, mocker):
        import requests

        mocker.patch("requests.get", side_effect=requests.exceptions.Timeout())
        assert lhm.get_lhm_temps() == []

    def test_deeply_nested_payload_does_not_crash(self, mocker):
        # A pathological deep Children chain must not RecursionError into the
        # /api/thermals/lhm/status route -- the depth cap returns what it has.
        node = {"Text": "leaf", "Value": "40.0 °C", "Type": "Temperature"}
        for _ in range(5000):
            node = {"Text": "n", "Children": [node]}
        mocker.patch("requests.get", return_value=_resp(node))
        assert lhm.get_lhm_temps() == []  # leaf is past the depth cap -> ignored, no crash

    def test_ensure_config_preserves_already_configured_file(self, mocker, tmp_path):
        """_ensure_config must NOT clobber a config that already enables the web
        server (it would destroy settings the user changed in LHM's own UI)."""
        mocker.patch.object(lhm, "INSTALL_DIR", str(tmp_path))
        cfg = tmp_path / "LibreHardwareMonitor.config"
        custom = (
            '<?xml version="1.0"?><configuration><appSettings>'
            '<add key="runWebServerMenuItem" value="true" />'
            f'<add key="ListenerPort" value="{lhm.LHM_WEB_PORT}" />'
            '<add key="userColorTheme" value="dark" /></appSettings></configuration>'
        )
        cfg.write_text(custom, encoding="utf-8")
        lhm._ensure_config()
        assert cfg.read_text(encoding="utf-8") == custom  # untouched

    def test_ensure_config_migrates_old_install(self, mocker, tmp_path):
        mocker.patch.object(lhm, "INSTALL_DIR", str(tmp_path))
        cfg = tmp_path / "LibreHardwareMonitor.config"
        cfg.write_text("<configuration><appSettings></appSettings></configuration>", encoding="utf-8")
        lhm._ensure_config()
        written = cfg.read_text(encoding="utf-8")
        assert 'key="runWebServerMenuItem" value="true"' in written

    def test_empty_on_http_error(self, mocker):
        mocker.patch("requests.get", return_value=_resp({}, ok=False))
        assert lhm.get_lhm_temps() == []

    def test_empty_on_nonlist_json(self, mocker):
        mocker.patch("requests.get", return_value=_resp([1, 2, 3]))  # not a dict tree
        assert lhm.get_lhm_temps() == []


# ── install_lhm ────────────────────────────────────────────────────────────


class TestInstall:
    def test_happy_path_downloads_verifies_extracts(self, mocker, tmp_path):
        zip_bytes = _make_lhm_zip()
        install_dir = tmp_path / "lhm"
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        mocker.patch.object(lhm, "LHM_SHA256", hashlib.sha256(zip_bytes).hexdigest())
        mocker.patch("requests.get", return_value=_FakeResp(zip_bytes))

        result = lhm.install_lhm()

        assert result["ok"] is True
        assert os.path.isfile(os.path.join(str(install_dir), "LibreHardwareMonitor.exe"))
        # Tray config seeded.
        assert os.path.isfile(os.path.join(str(install_dir), "LibreHardwareMonitor.config"))
        # The temp zip was cleaned up.
        assert not os.path.exists(os.path.join(str(install_dir), "_LibreHardwareMonitor.zip"))

    def test_hash_mismatch_does_not_extract(self, mocker, tmp_path):
        zip_bytes = _make_lhm_zip()
        install_dir = tmp_path / "lhm"
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        # Leave LHM_SHA256 at its real (mismatching) value.
        mocker.patch("requests.get", return_value=_FakeResp(zip_bytes))

        result = lhm.install_lhm()

        assert result["ok"] is False
        assert "mismatch" in result["error"].lower()
        assert not os.path.exists(os.path.join(str(install_dir), "LibreHardwareMonitor.exe"))

    def test_download_failure_is_graceful(self, mocker):
        mocker.patch("requests.get", side_effect=Exception("connection reset"))
        result = lhm.install_lhm()
        assert result["ok"] is False
        assert "download failed" in result["error"]

    def test_oversize_download_aborts(self, mocker, tmp_path):
        zip_bytes = _make_lhm_zip()
        mocker.patch.object(lhm, "INSTALL_DIR", str(tmp_path / "lhm"))
        mocker.patch.object(lhm, "MAX_DOWNLOAD_BYTES", 4)  # smaller than the zip
        mocker.patch("requests.get", return_value=_FakeResp(zip_bytes))
        result = lhm.install_lhm()
        assert result["ok"] is False
        assert "size limit" in result["error"]

    def test_bad_url_refused_before_download(self, mocker):
        get = mocker.patch("requests.get")
        mocker.patch.object(lhm, "LHM_URL", "http://evil.example/x.zip")
        result = lhm.install_lhm()
        assert result["ok"] is False
        assert "non-github" in result["error"]
        get.assert_not_called()

    def test_zip_without_exe_reports_missing(self, mocker, tmp_path):
        zip_bytes = _make_lhm_zip(include_exe=False)
        install_dir = tmp_path / "lhm"
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        mocker.patch.object(lhm, "LHM_SHA256", hashlib.sha256(zip_bytes).hexdigest())
        mocker.patch("requests.get", return_value=_FakeResp(zip_bytes))
        result = lhm.install_lhm()
        assert result["ok"] is False
        assert "executable not found" in result["error"]


# ── launch_lhm_elevated ────────────────────────────────────────────────────


class TestLaunch:
    def test_not_installed_returns_error(self, mocker, tmp_path):
        mocker.patch.object(lhm, "INSTALL_DIR", str(tmp_path / "nope"))
        result = lhm.launch_lhm_elevated()
        assert result["ok"] is False
        assert "not installed" in result["error"]

    def test_successful_elevated_launch(self, mocker, tmp_path):
        import ctypes

        install_dir = tmp_path / "lhm"
        install_dir.mkdir()
        (install_dir / "LibreHardwareMonitor.exe").write_bytes(b"MZ")
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=42)

        result = lhm.launch_lhm_elevated()
        assert result["ok"] is True

    def test_uac_declined_maps_error(self, mocker, tmp_path):
        import ctypes

        install_dir = tmp_path / "lhm"
        install_dir.mkdir()
        (install_dir / "LibreHardwareMonitor.exe").write_bytes(b"MZ")
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=5)

        result = lhm.launch_lhm_elevated()
        assert result["ok"] is False
        assert "ACCESS_DENIED" in result["error"]


class TestAutostart:
    def test_status_enabled_when_task_present(self, mocker):
        fake = mocker.MagicMock(returncode=0)
        mocker.patch.object(lhm.subprocess, "run", return_value=fake)
        st = lhm.autostart_status()
        assert st["enabled"] is True
        assert st["task"] == lhm.AUTOSTART_TASK_NAME

    def test_status_disabled_when_task_absent(self, mocker):
        fake = mocker.MagicMock(returncode=1)
        mocker.patch.object(lhm.subprocess, "run", return_value=fake)
        assert lhm.autostart_status()["enabled"] is False

    def test_status_graceful_on_exception(self, mocker):
        mocker.patch.object(lhm.subprocess, "run", side_effect=OSError("schtasks missing"))
        assert lhm.autostart_status()["enabled"] is False

    def test_setup_requires_install(self, mocker, tmp_path):
        mocker.patch.object(lhm, "INSTALL_DIR", str(tmp_path / "nope"))
        result = lhm.setup_autostart()
        assert result["ok"] is False
        assert "not installed" in result["error"]

    def test_setup_registers_via_elevated_schtasks(self, mocker, tmp_path):
        import ctypes

        install_dir = tmp_path / "lhm"
        install_dir.mkdir()
        (install_dir / "LibreHardwareMonitor.exe").write_bytes(b"MZ")
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        shell = mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=42)
        result = lhm.setup_autostart()
        assert result["ok"] is True
        # schtasks invoked elevated with the fixed task name + verified exe path.
        args = shell.call_args[0]
        assert args[1] == "runas"
        assert args[2] == "schtasks.exe"
        assert lhm.AUTOSTART_TASK_NAME in args[3]
        assert "ONLOGON" in args[3] and "HIGHEST" in args[3]

    def test_setup_refuses_path_with_quote(self, mocker):
        """Defence in depth: a double-quote in the exe path would break /TR
        parsing, so setup refuses rather than building a mangled schtasks arg.
        (NTFS forbids quotes in real names, so exe_path is mocked to simulate.)"""
        import ctypes

        mocker.patch.object(lhm, "exe_path", return_value='C:\\evil"\\LibreHardwareMonitor.exe')
        shell = mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=42)
        result = lhm.setup_autostart()
        assert result["ok"] is False
        assert "invalid character" in result["error"]
        shell.assert_not_called()  # never reached schtasks

    def test_setup_uac_declined_maps_error(self, mocker, tmp_path):
        import ctypes

        install_dir = tmp_path / "lhm"
        install_dir.mkdir()
        (install_dir / "LibreHardwareMonitor.exe").write_bytes(b"MZ")
        mocker.patch.object(lhm, "INSTALL_DIR", str(install_dir))
        mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=5)
        result = lhm.setup_autostart()
        assert result["ok"] is False
        assert "ACCESS_DENIED" in result["error"]

    def test_remove_deletes_via_elevated_schtasks(self, mocker):
        import ctypes

        shell = mocker.patch.object(ctypes.windll.shell32, "ShellExecuteW", return_value=42)
        result = lhm.remove_autostart()
        assert result["ok"] is True
        args = shell.call_args[0]
        assert "/Delete" in args[3] and lhm.AUTOSTART_TASK_NAME in args[3]
