"""tests/test_lhm.py — LibreHardwareMonitor in-app installer (lhm.py).

Covers the download/verify/extract pipeline, the WMI-namespace "is running"
probe, the zip-slip guard, the URL allow-list, and the elevated UAC launch.
Everything is mocked — no real network, no real subprocess, no real WMI.
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

    def test_is_running_true_when_namespace_has_sensors(self, mocker):
        fake_conn = mocker.Mock()
        fake_conn.Sensor.return_value = [object(), object()]
        mocker.patch("wmi.WMI", return_value=fake_conn)
        assert lhm.is_running() is True

    def test_is_running_false_when_namespace_absent(self, mocker):
        mocker.patch("wmi.WMI", side_effect=Exception("namespace not found"))
        assert lhm.is_running() is False

    def test_is_running_false_when_no_sensors(self, mocker):
        fake_conn = mocker.Mock()
        fake_conn.Sensor.return_value = []
        mocker.patch("wmi.WMI", return_value=fake_conn)
        assert lhm.is_running() is False

    def test_is_running_bounded_returns_false_on_timeout(self, mocker):
        """A wedged Winmgmt must NOT hang the Thermals status route -- the probe
        is bounded via bounded_wmi_query and degrades to False on timeout."""
        import time

        # Tiny bound + a WMI call that sleeps past it -> the bounded helper
        # abandons the probe and returns the False fallback, fast.
        mocker.patch.object(lhm, "IS_RUNNING_TIMEOUT_S", 0.2)
        mocker.patch("pythoncom.CoInitialize", return_value=None)
        mocker.patch("wmi.WMI", side_effect=lambda *a, **k: time.sleep(3))
        start = time.monotonic()
        assert lhm.is_running() is False
        assert time.monotonic() - start < 2.0, "is_running did not honour its timeout bound"

    def test_lhm_status_shape(self, mocker):
        mocker.patch("lhm.is_installed", return_value=True)
        mocker.patch("lhm.is_running", return_value=False)
        st = lhm.lhm_status()
        assert st["installed"] is True
        assert st["running"] is False
        assert st["version"] == lhm.LHM_VERSION
        assert st["exe"].endswith("LibreHardwareMonitor.exe")
        assert "install_dir" in st


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
