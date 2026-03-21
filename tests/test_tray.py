"""
Tests for the System Tray mode (tray.py).

Tests cover:
- Icon generation for all status colors
- HealthMonitor state tracking and notifications
- Tooltip generation
- Concern change detection (new alerts, resolved alerts)
- Truncation helper for large data
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import tray


class TestCreateIcon(unittest.TestCase):
    """Test tray icon generation."""

    def test_creates_rgba_image(self):
        img = tray.create_icon("ok")
        assert img.mode == "RGBA"
        assert img.size == (64, 64)

    def test_custom_size(self):
        img = tray.create_icon("ok", size=32)
        assert img.size == (32, 32)

    def test_all_status_colors(self):
        for status in ("ok", "warning", "critical", "unknown"):
            img = tray.create_icon(status)
            assert img is not None
            # Verify the icon isn't fully transparent
            get_pixels = getattr(img, "get_flattened_data", img.getdata)
            pixels = list(get_pixels())
            non_transparent = [p for p in pixels if p[3] > 0]
            assert len(non_transparent) > 0, f"Icon for '{status}' is fully transparent"

    def test_unknown_status_uses_fallback(self):
        img = tray.create_icon("nonexistent_status")
        assert img is not None  # Should use "unknown" fallback color


class TestHealthMonitor(unittest.TestCase):
    """Test the HealthMonitor class."""

    def setUp(self):
        self.monitor = tray.HealthMonitor()

    def test_initial_state(self):
        assert self.monitor.current_status == "unknown"
        assert self.monitor.current_concerns == []
        assert self.monitor.last_check is None

    @patch("tray.urllib.request.urlopen")
    def test_poll_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"overall":"ok","concerns":[]}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = self.monitor.poll()
        assert result == {"overall": "ok", "concerns": []}

    @patch("tray.urllib.request.urlopen")
    def test_poll_failure_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Connection refused")
        result = self.monitor.poll()
        assert result is None

    @patch("tray.send_notification")
    @patch("tray.urllib.request.urlopen")
    def test_update_changes_status(self, mock_urlopen, mock_notify):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"overall":"warning","concerns":[{"title":"test","level":"warning","icon":"!","detail":"d","tab":"thermals"}]}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        mock_icon = MagicMock()
        self.monitor.icon_ref = mock_icon

        self.monitor.update()

        assert self.monitor.current_status == "warning"
        assert len(self.monitor.current_concerns) == 1
        assert self.monitor.last_check is not None

    @patch("tray.send_notification")
    @patch("tray.urllib.request.urlopen")
    def test_notification_on_new_concern(self, mock_urlopen, mock_notify):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"overall":"critical","concerns":[{"title":"OneDrive suspended","level":"critical","icon":"C","detail":"Fix it","tab":"credentials"}]}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.monitor.icon_ref = MagicMock()
        self.monitor.update()

        mock_notify.assert_called_once()
        # send_notification(title=..., message=..., tab=...)
        call_kwargs = mock_notify.call_args[1] if mock_notify.call_args[1] else {}
        call_positional = mock_notify.call_args[0] if mock_notify.call_args[0] else ()
        title = call_kwargs.get("title", call_positional[0] if call_positional else "")
        assert "OneDrive" in title

    @patch("tray.send_notification")
    @patch("tray.urllib.request.urlopen")
    def test_no_duplicate_notification(self, mock_urlopen, mock_notify):
        """Same concern on second poll should not re-notify."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"overall":"warning","concerns":[{"title":"High temp","level":"warning","icon":"T","detail":"d","tab":"thermals"}]}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.monitor.icon_ref = MagicMock()
        self.monitor.update()
        self.monitor.update()

        # Should only notify once
        assert mock_notify.call_count == 1

    @patch("tray.send_notification")
    @patch("tray.urllib.request.urlopen")
    def test_resolved_concern_cleared(self, mock_urlopen, mock_notify):
        """When a concern resolves, it should be cleared so it can re-notify if it comes back."""
        mock_resp1 = MagicMock()
        mock_resp1.read.return_value = b'{"overall":"warning","concerns":[{"title":"High temp","level":"warning","icon":"T","detail":"d","tab":"thermals"}]}'
        mock_resp1.__enter__ = lambda s: mock_resp1
        mock_resp1.__exit__ = MagicMock(return_value=False)

        mock_resp2 = MagicMock()
        mock_resp2.read.return_value = b'{"overall":"ok","concerns":[]}'
        mock_resp2.__enter__ = lambda s: mock_resp2
        mock_resp2.__exit__ = MagicMock(return_value=False)

        mock_resp3 = MagicMock()
        mock_resp3.read.return_value = b'{"overall":"warning","concerns":[{"title":"High temp","level":"warning","icon":"T","detail":"d","tab":"thermals"}]}'
        mock_resp3.__enter__ = lambda s: mock_resp3
        mock_resp3.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [mock_resp1, mock_resp2, mock_resp3]

        self.monitor.icon_ref = MagicMock()
        self.monitor.update()  # first time: notify
        self.monitor.update()  # resolved: clear tracked
        self.monitor.update()  # comes back: notify again

        assert mock_notify.call_count == 2

    @patch("tray.send_notification")
    @patch("tray.urllib.request.urlopen")
    def test_info_level_not_notified(self, mock_urlopen, mock_notify):
        """Info/ok level concerns should not trigger notifications."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"overall":"ok","concerns":[{"title":"Info item","level":"info","icon":"i","detail":"d","tab":"dashboard"}]}'
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.monitor.icon_ref = MagicMock()
        self.monitor.update()

        mock_notify.assert_not_called()

    @patch("tray.urllib.request.urlopen")
    def test_poll_failure_keeps_state(self, mock_urlopen):
        """If poll fails, status should remain unchanged."""
        self.monitor.current_status = "ok"
        mock_urlopen.side_effect = Exception("timeout")

        self.monitor.update()
        assert self.monitor.current_status == "ok"


class TestTooltip(unittest.TestCase):
    """Test tooltip string generation."""

    def test_starting_tooltip(self):
        monitor = tray.HealthMonitor()
        tooltip = monitor.get_tooltip()
        assert "Starting" in tooltip

    def test_ok_tooltip(self):
        monitor = tray.HealthMonitor()
        monitor.last_check = "14:30"
        monitor.current_concerns = []
        tooltip = monitor.get_tooltip()
        assert "All OK" in tooltip
        assert "14:30" in tooltip

    def test_concerns_tooltip(self):
        monitor = tray.HealthMonitor()
        monitor.last_check = "14:30"
        monitor.current_concerns = [
            {"icon": "T", "title": "High temperature"},
            {"icon": "D", "title": "Disk space low"},
        ]
        tooltip = monitor.get_tooltip()
        assert "2 issue" in tooltip
        assert "High temperature" in tooltip
        assert "Disk space low" in tooltip

    def test_tooltip_truncation(self):
        monitor = tray.HealthMonitor()
        monitor.last_check = "14:30"
        monitor.current_concerns = [{"icon": str(i), "title": f"Issue {i}"} for i in range(5)]
        tooltip = monitor.get_tooltip()
        assert "... and 2 more" in tooltip


class TestMenuActions(unittest.TestCase):
    """Test tray menu action functions."""

    @patch("tray.webbrowser.open")
    def test_open_dashboard(self, mock_open):
        tray.open_dashboard(None, None)
        mock_open.assert_called_once_with(tray.DASHBOARD_URL)

    @patch("tray.webbrowser.open")
    def test_open_tab(self, mock_open):
        action = tray.open_tab("bsod")
        action(None, None)
        mock_open.assert_called_once_with(f"{tray.DASHBOARD_URL}#tab=bsod")


class TestConstants(unittest.TestCase):
    """Test configuration constants."""

    def test_poll_interval_reasonable(self):
        assert 60 <= tray.POLL_INTERVAL <= 600  # 1-10 minutes

    def test_all_status_colors_defined(self):
        for status in ("ok", "warning", "critical", "unknown"):
            assert status in tray.COLORS

    def test_dashboard_url_format(self):
        assert tray.DASHBOARD_URL.startswith("http")
        assert "5000" in tray.DASHBOARD_URL


if __name__ == "__main__":
    unittest.main()
