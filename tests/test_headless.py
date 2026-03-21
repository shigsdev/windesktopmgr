"""
Tests for the HEADLESS_MODE subprocess wrapper in windesktopmgr.py.

Tests cover:
- Monkey-patch installation (subprocess.run is wrapped)
- CREATE_NO_WINDOW flag added when HEADLESS_MODE is True + Windows
- No flags added when HEADLESS_MODE is False
- No flags added on non-Windows platforms
- Existing creationflags are not overwritten
"""

import os
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import windesktopmgr as wdm


class TestHeadlessSubprocessWrapper(unittest.TestCase):
    """Test the _headless_subprocess_run monkey-patch."""

    def test_monkey_patch_installed(self):
        """subprocess.run should be the wrapped version, not the original."""
        assert subprocess.run is wdm._headless_subprocess_run
        assert subprocess.run is not wdm._original_subprocess_run

    def test_original_preserved(self):
        """The original subprocess.run should be preserved as _original_subprocess_run."""
        assert wdm._original_subprocess_run is not None
        assert callable(wdm._original_subprocess_run)

    @patch.object(wdm, "_original_subprocess_run")
    def test_headless_on_windows_adds_create_no_window(self, mock_original):
        """When HEADLESS_MODE=True and os.name='nt', CREATE_NO_WINDOW should be added."""
        mock_original.return_value = MagicMock(returncode=0)
        wdm.HEADLESS_MODE = True
        try:
            with patch("os.name", "nt"):
                wdm._headless_subprocess_run(["echo", "test"], capture_output=True)
                call_kwargs = mock_original.call_args[1]
                assert call_kwargs.get("creationflags") == subprocess.CREATE_NO_WINDOW
        finally:
            wdm.HEADLESS_MODE = False

    @patch.object(wdm, "_original_subprocess_run")
    def test_headless_off_no_flags(self, mock_original):
        """When HEADLESS_MODE=False, no creationflags should be added."""
        mock_original.return_value = MagicMock(returncode=0)
        wdm.HEADLESS_MODE = False
        wdm._headless_subprocess_run(["echo", "test"], capture_output=True)
        call_kwargs = mock_original.call_args[1]
        assert "creationflags" not in call_kwargs

    @patch.object(wdm, "_original_subprocess_run")
    def test_headless_non_windows_no_flags(self, mock_original):
        """On non-Windows (os.name != 'nt'), no creationflags should be added even in headless mode."""
        mock_original.return_value = MagicMock(returncode=0)
        wdm.HEADLESS_MODE = True
        try:
            with patch("os.name", "posix"):
                wdm._headless_subprocess_run(["echo", "test"], capture_output=True)
                call_kwargs = mock_original.call_args[1]
                assert "creationflags" not in call_kwargs
        finally:
            wdm.HEADLESS_MODE = False

    @patch.object(wdm, "_original_subprocess_run")
    def test_headless_does_not_overwrite_existing_creationflags(self, mock_original):
        """If creationflags is already set, the wrapper should not overwrite it."""
        mock_original.return_value = MagicMock(returncode=0)
        wdm.HEADLESS_MODE = True
        custom_flags = 0x00000010  # some custom flag
        try:
            with patch("os.name", "nt"):
                wdm._headless_subprocess_run(["echo", "test"], creationflags=custom_flags)
                call_kwargs = mock_original.call_args[1]
                assert call_kwargs["creationflags"] == custom_flags
        finally:
            wdm.HEADLESS_MODE = False


if __name__ == "__main__":
    unittest.main()
