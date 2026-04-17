"""
WinDesktopMgr — System Tray Mode

Runs the Flask server in the background with a system tray icon that shows
health status at a glance. Right-click for menu, click notification to open
the relevant dashboard tab.

Usage:
    python tray.py          # start in tray mode (no terminal, no browser)
    pythonw tray.py         # same, but hides the console window entirely

The tray icon color reflects system health:
    Green  = all OK
    Yellow = warnings (elevated temps, disk space, etc.)
    Red    = critical issues (BSOD, NAS down, OneDrive suspended)
"""

import json
import os
import sys
import threading
import time
import urllib.request
import webbrowser

from PIL import Image, ImageDraw

# ── Configuration ─────────────────────────────────────────────────────────────

POLL_INTERVAL = 300  # seconds between health checks (5 minutes)
DASHBOARD_URL = "http://localhost:5000"
API_URL = f"{DASHBOARD_URL}/api/dashboard/summary"
APP_NAME = "WinDesktopMgr"

# ── Icon generation ───────────────────────────────────────────────────────────

COLORS = {
    "ok": "#00e5a0",
    "warning": "#ffd740",
    "critical": "#ff4757",
    "unknown": "#4a5568",
}


def create_icon(status: str = "unknown", size: int = 64) -> Image.Image:
    """Generate a solid circle icon in the status color."""
    color = COLORS.get(status, COLORS["unknown"])
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Outer ring (slightly darker)
    draw.ellipse([2, 2, size - 3, size - 3], fill=color)
    # Inner highlight
    highlight_size = size // 3
    draw.ellipse(
        [size // 4, size // 5, size // 4 + highlight_size, size // 5 + highlight_size],
        fill="#ffffff40",
    )
    return img


# ── Toast notifications ───────────────────────────────────────────────────────


def send_notification(title: str, message: str, tab: str | None = None):
    """Send a Windows toast notification without opening console windows."""
    try:
        # Use ctypes to call Windows notification API directly — no subprocess needed
        import subprocess as _sp

        # Build a PowerShell one-liner for toast notification, but run it hidden
        # Escape single quotes in title/message for PowerShell
        safe_title = str(title).replace("'", "''")[:100]
        safe_msg = str(message).replace("'", "''")[:200]

        ps_script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType = WindowsRuntime] | Out-Null; "
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null; "
            f'$xml = \'<toast><visual><binding template="ToastText02">'
            f'<text id="1">{safe_title}</text>'
            f'<text id="2">{safe_msg}</text>'
            f"</binding></visual></toast>'; "
            "$xdoc = [Windows.Data.Xml.Dom.XmlDocument]::new(); "
            "$xdoc.LoadXml($xml); "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($xdoc); "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{APP_NAME}').Show($toast)"
        )

        _sp.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
            creationflags=_sp.CREATE_NO_WINDOW if os.name == "nt" else 0,
            stdout=_sp.DEVNULL,
            stderr=_sp.DEVNULL,
        )
    except Exception as e:
        print(f"[Tray] Notification failed: {e}")


# ── Health polling ────────────────────────────────────────────────────────────


class HealthMonitor:
    """Polls the dashboard summary API and tracks state changes."""

    def __init__(self):
        self.current_status = "unknown"
        self.current_concerns = []
        self.last_check = None
        self.icon_ref = None  # set by the tray setup
        self._notified_concerns = set()  # track what we've already notified about

    def poll(self) -> dict | None:
        """Fetch dashboard summary from the Flask API."""
        try:
            req = urllib.request.Request(API_URL, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            print(f"[Tray] Poll failed: {e}")
            return None

    def update(self):
        """Poll the API, update icon color, and fire notifications for new concerns."""
        data = self.poll()
        if not data:
            return

        new_status = data.get("overall", "ok")
        concerns = data.get("concerns", [])
        self.last_check = time.strftime("%H:%M")

        # Update icon color if status changed
        if new_status != self.current_status:
            self.current_status = new_status
            if self.icon_ref:
                self.icon_ref.icon = create_icon(new_status)
                status_label = {"ok": "Healthy", "warning": "Warnings", "critical": "Critical"}
                self.icon_ref.title = f"{APP_NAME} — {status_label.get(new_status, new_status)}"

        # Check for new concerns to notify about
        for concern in concerns:
            concern_key = concern.get("title", "")
            level = concern.get("level", "info")

            if concern_key not in self._notified_concerns and level in ("critical", "warning"):
                self._notified_concerns.add(concern_key)
                icon_char = concern.get("icon", "")
                tab = concern.get("tab", "dashboard")
                send_notification(
                    title=f"{icon_char} {concern.get('title', 'Issue detected')}",
                    message=concern.get("detail", ""),
                    tab=tab,
                )

        # Clear notifications for concerns that are resolved
        current_keys = {c.get("title", "") for c in concerns}
        self._notified_concerns = self._notified_concerns & current_keys

        self.current_concerns = concerns

    def get_tooltip(self) -> str:
        """Build a tooltip string showing current status."""
        if not self.last_check:
            return f"{APP_NAME} — Starting..."

        if not self.current_concerns:
            return f"{APP_NAME} — All OK (checked {self.last_check})"

        lines = [f"{APP_NAME} — {len(self.current_concerns)} issue(s)"]
        for c in self.current_concerns[:3]:
            lines.append(f"  {c.get('icon', '')} {c.get('title', '')}")
        if len(self.current_concerns) > 3:
            lines.append(f"  ... and {len(self.current_concerns) - 3} more")
        return "\n".join(lines)


# ── Background polling thread ─────────────────────────────────────────────────


def polling_loop(monitor: HealthMonitor, stop_event: threading.Event):
    """Continuously poll the health API in the background."""
    # Wait for Flask to start — retry connection up to 30 seconds
    for attempt in range(30):
        if stop_event.is_set():
            return
        try:
            urllib.request.urlopen(f"{DASHBOARD_URL}/", timeout=2)
            print(f"[Tray] Flask server ready (attempt {attempt + 1})")
            break
        except Exception:
            time.sleep(1)

    # First poll: retry up to 3 times with short delay if it fails,
    # so the tray icon doesn't stay grey/unknown for a full POLL_INTERVAL.
    for retry in range(3):
        if stop_event.is_set():
            return
        monitor.update()
        if monitor.current_status != "unknown":
            print(f"[Tray] Initial health: {monitor.current_status}")
            break
        print(f"[Tray] Initial poll attempt {retry + 1} returned no data, retrying in 10s...")
        for _ in range(10):
            if stop_event.is_set():
                return
            time.sleep(1)

    while not stop_event.is_set():
        # Sleep in small increments so we can stop quickly
        for _ in range(POLL_INTERVAL):
            if stop_event.is_set():
                break
            time.sleep(1)
        if not stop_event.is_set():
            monitor.update()


# ── Flask server thread ──────────────────────────────────────────────────────


def _wait_for_port_free(port: int, timeout: int = 10):
    """Wait until the given TCP port is free (previous instance released it)."""
    import socket

    for _ in range(timeout * 4):  # check every 250ms
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return  # port is free
            except OSError:
                time.sleep(0.25)
    print(f"[Tray] Warning: port {port} still in use after {timeout}s")


def start_flask():
    """Start the Flask server in a background thread."""
    # Add project root to path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Wait for port 5000 to be free (handles restart race condition)
    _wait_for_port_free(5000)

    import windesktopmgr

    # Enable headless mode — suppresses console windows for all subprocess calls
    windesktopmgr.HEADLESS_MODE = True
    windesktopmgr.start_server(open_browser=False)


# ── Tray menu actions ─────────────────────────────────────────────────────────


def open_dashboard(icon, item):
    webbrowser.open(DASHBOARD_URL)


def open_tab(tab_name):
    def _open(icon, item):
        webbrowser.open(f"{DASHBOARD_URL}#tab={tab_name}")

    return _open


def refresh_now(monitor):
    def _refresh(icon, item):
        threading.Thread(target=monitor.update, daemon=True).start()

    return _refresh


def restart_app(icon, item, stop_event):
    """Restart the entire tray application to pick up code changes."""
    import subprocess as _sp

    stop_event.set()
    icon.stop()

    # Spawn the new process BEFORE exiting so the tray comes back reliably.
    # On Windows os.execv is unreliable with pythonw.exe — it spawns a child
    # and terminates the parent, but the child may fail silently.
    # Using subprocess.Popen + sys.exit is the safe Windows pattern.
    python = sys.executable
    _sp.Popen(  # noqa: S603
        [python] + sys.argv,
        creationflags=_sp.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )

    # Give the new process a moment to start, then exit the old one.
    # The old Flask server (daemon thread) dies with this process,
    # freeing port 5000 for the new instance.
    time.sleep(0.5)
    os._exit(0)  # noqa: SLF001  — hard exit kills daemon threads immediately


def quit_app(icon, item, stop_event):
    stop_event.set()
    icon.stop()


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    import pystray

    monitor = HealthMonitor()
    stop_event = threading.Event()

    # Start Flask in a background thread
    flask_thread = threading.Thread(target=start_flask, daemon=True, name="FlaskServer")
    flask_thread.start()

    # Build the tray menu
    menu = pystray.Menu(
        pystray.MenuItem("Open Dashboard", open_dashboard, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Quick Status",
            pystray.Menu(
                pystray.MenuItem("Dashboard", open_tab("dashboard")),
                pystray.MenuItem("BSOD", open_tab("bsod")),
                pystray.MenuItem("Thermals", open_tab("thermals")),
                pystray.MenuItem("Memory", open_tab("memory")),
                pystray.MenuItem("Credentials", open_tab("credentials")),
                pystray.MenuItem("Disk", open_tab("disk")),
                pystray.MenuItem("Processes", open_tab("processes")),
            ),
        ),
        pystray.MenuItem("Refresh Now", refresh_now(monitor)),
        pystray.MenuItem("Restart App", lambda icon, item: restart_app(icon, item, stop_event)),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            lambda item: f"Last check: {monitor.last_check or 'never'}",
            lambda icon, item: None,
            enabled=False,
        ),
        pystray.MenuItem(
            lambda item: f"Status: {monitor.current_status}",
            lambda icon, item: None,
            enabled=False,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", lambda icon, item: quit_app(icon, item, stop_event)),
    )

    # Create the tray icon
    icon = pystray.Icon(
        APP_NAME,
        icon=create_icon("unknown"),
        title=f"{APP_NAME} — Starting...",
        menu=menu,
    )
    monitor.icon_ref = icon

    # Start the health polling thread
    poll_thread = threading.Thread(target=polling_loop, args=(monitor, stop_event), daemon=True, name="HealthPoller")
    poll_thread.start()

    print(f"[Tray] {APP_NAME} system tray mode started")
    print(f"[Tray] Dashboard: {DASHBOARD_URL}")
    print(f"[Tray] Polling every {POLL_INTERVAL}s")

    # Run the tray icon (blocks until quit)
    icon.run()


if __name__ == "__main__":
    main()
