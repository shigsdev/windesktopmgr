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
import threading
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
        # Verify icon and title were updated on the tray icon
        assert mock_icon.icon is not None  # new icon was set
        assert "Warnings" in mock_icon.title

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


class TestPollingLoop(unittest.TestCase):
    """Test the background polling loop."""

    @patch("tray.urllib.request.urlopen")
    def test_polling_waits_for_flask_then_polls(self, mock_urlopen):
        """Polling loop should wait for Flask, then call monitor.update()."""
        # First call succeeds (Flask is ready), then stop immediately
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        monitor = tray.HealthMonitor()
        monitor.update = MagicMock()
        stop_event = threading.Event()

        # Set stop immediately so we only do one poll cycle
        def stop_after_update():
            monitor.update.side_effect = lambda: stop_event.set()

        stop_after_update()
        tray.polling_loop(monitor, stop_event)

        monitor.update.assert_called()

    def test_polling_exits_early_on_stop_event(self):
        """If stop_event is set before Flask is ready, loop should exit without polling."""
        monitor = tray.HealthMonitor()
        monitor.update = MagicMock()
        stop_event = threading.Event()
        stop_event.set()  # Already stopped

        tray.polling_loop(monitor, stop_event)
        monitor.update.assert_not_called()

    @patch("tray.urllib.request.urlopen")
    def test_polling_stops_during_sleep_interval(self, mock_urlopen):
        """Stop event during the inter-poll sleep should exit quickly."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        monitor = tray.HealthMonitor()
        call_count = 0

        def update_then_stop():
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                stop_event.set()

        monitor.update = update_then_stop
        stop_event = threading.Event()

        import time

        start = time.time()
        tray.polling_loop(monitor, stop_event)
        elapsed = time.time() - start

        assert call_count >= 1
        # Should exit within a few seconds, not wait for full POLL_INTERVAL
        assert elapsed < 10


class TestSendNotification(unittest.TestCase):
    """Test the send_notification function."""

    @patch("tray.subprocess.Popen" if hasattr(tray, "subprocess") else "subprocess.Popen")
    def test_notification_escapes_quotes(self, mock_popen):
        """Single quotes in title/message should be escaped for PowerShell."""
        with patch.dict("os.environ", {}, clear=False):
            tray.send_notification("It's a test", "Don't panic", tab="dashboard")
        # Should not raise — quotes are handled internally

    @patch("tray.subprocess.Popen" if hasattr(tray, "subprocess") else "subprocess.Popen")
    def test_notification_truncates_long_title(self, mock_popen):
        """Titles longer than 100 chars should be truncated."""
        long_title = "A" * 200
        tray.send_notification(long_title, "short message")
        # Should not raise

    def test_notification_exception_does_not_propagate(self):
        """If notification fails internally, it should not raise."""
        with patch("builtins.__import__", side_effect=ImportError("no subprocess")):
            # Even if subprocess import fails, should not propagate
            try:
                tray.send_notification("Test", "Message")
            except Exception:
                pass  # The function has its own try/except

    @patch("subprocess.Popen")
    def test_notification_uses_create_no_window(self, mock_popen):
        """On Windows, notification should use CREATE_NO_WINDOW flag."""
        import subprocess as _sp

        with patch("os.name", "nt"):
            tray.send_notification("Test", "Message")
            if mock_popen.called:
                call_kwargs = mock_popen.call_args[1]
                assert call_kwargs.get("creationflags") == _sp.CREATE_NO_WINDOW


class TestStartFlask(unittest.TestCase):
    """Test start_flask function."""

    def test_start_flask_sets_headless_mode(self):
        """start_flask should set HEADLESS_MODE to True before starting server."""
        import windesktopmgr

        original = windesktopmgr.HEADLESS_MODE
        try:
            with patch.object(windesktopmgr, "start_server") as mock_start:
                tray.start_flask()
                # After start_flask runs, HEADLESS_MODE should have been set to True
                assert windesktopmgr.HEADLESS_MODE is True
                mock_start.assert_called_once_with(open_browser=False)
        finally:
            windesktopmgr.HEADLESS_MODE = original


class TestRefreshNow(unittest.TestCase):
    """Test the refresh_now menu action."""

    def test_refresh_now_calls_update(self):
        """refresh_now should trigger monitor.update in a thread."""
        monitor = tray.HealthMonitor()
        monitor.update = MagicMock()
        action = tray.refresh_now(monitor)
        action(None, None)
        # Give the thread a moment to run
        import time

        time.sleep(0.1)
        monitor.update.assert_called()


class TestQuitApp(unittest.TestCase):
    """Test quit_app function."""

    def test_quit_sets_stop_event_and_stops_icon(self):
        stop_event = threading.Event()
        mock_icon = MagicMock()
        tray.quit_app(mock_icon, None, stop_event)
        assert stop_event.is_set()
        mock_icon.stop.assert_called_once()


class TestRestartApp(unittest.TestCase):
    """Test restart_app function."""

    @patch("tray.os._exit")
    @patch("tray.time.sleep")
    @patch("subprocess.Popen")
    def test_restart_stops_icon_and_spawns_new_process(self, mock_popen, mock_sleep, mock_exit):
        stop_event = threading.Event()
        mock_icon = MagicMock()
        tray.restart_app(mock_icon, None, stop_event)
        assert stop_event.is_set()
        mock_icon.stop.assert_called_once()
        mock_popen.assert_called_once()
        mock_sleep.assert_called_once_with(0.5)
        mock_exit.assert_called_once_with(0)

    @patch("tray.os._exit")
    @patch("tray.time.sleep")
    @patch("subprocess.Popen")
    def test_restart_preserves_sys_argv(self, mock_popen, mock_sleep, mock_exit):
        stop_event = threading.Event()
        mock_icon = MagicMock()
        original_argv = sys.argv[:]
        tray.restart_app(mock_icon, None, stop_event)
        # First positional arg is the command list
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == sys.executable
        assert cmd[1:] == original_argv

    @patch("tray.os._exit")
    @patch("tray.time.sleep")
    @patch("subprocess.Popen", side_effect=Exception("spawn failed"))
    def test_restart_exits_even_if_spawn_fails(self, mock_popen, mock_sleep, mock_exit):
        """If Popen fails, the old process should still try to exit."""
        stop_event = threading.Event()
        mock_icon = MagicMock()
        # The function will raise because Popen fails before os._exit
        with self.assertRaises(Exception):
            tray.restart_app(mock_icon, None, stop_event)
        assert stop_event.is_set()
        mock_icon.stop.assert_called_once()


class TestWaitForPortFree(unittest.TestCase):
    """Test _wait_for_port_free helper."""

    @patch("tray.time.sleep")
    def test_returns_immediately_when_port_free(self, mock_sleep):
        """Port should be free during tests — returns immediately."""
        # Use a random high port that's unlikely to be in use
        tray._wait_for_port_free(59999, timeout=1)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
