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


def slugify_concern(title: str) -> str:
    """Slugify a concern title for use as a stable URL fragment.

    Backlog #40 needs a deterministic round-trip from the concern's
    title -> URL fragment -> back to a CSS attribute selector on the
    rendered concern card. The same slug logic lives in JS (in
    ``index.html``: ``slugifyConcern``) -- if you change one, change the
    other or the toast deep-link silently won't find its target.

    Lowercase, strip non-alphanumeric, collapse whitespace to single
    hyphens. ASCII-only output so it survives URL encoding without
    surprises.
    """
    import re as _re

    s = (title or "").lower()
    # Replace any run of non-alphanumeric chars with a single hyphen,
    # then trim leading/trailing hyphens.
    s = _re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s


def build_concern_url(tab: str | None, concern_title: str | None) -> str:
    """Build the deep-link URL Windows opens when the toast is clicked.

    Example: ``http://localhost:5000/#tab=thermals&concern=gpu-temp-critical``

    The frontend's ``hashchange`` listener parses these on page load +
    on hash change, calls ``switchTab(tab)``, then scrolls to the
    matching ``[data-concern-slug]`` card on the dashboard. Both args
    are optional -- empty hash falls back to dashboard root, which is
    the legacy behaviour for toasts that don't carry a tab hint.
    """
    parts = []
    if tab:
        parts.append(f"tab={tab}")
    if concern_title:
        parts.append(f"concern={slugify_concern(concern_title)}")
    if not parts:
        return DASHBOARD_URL
    return f"{DASHBOARD_URL}/#{'&'.join(parts)}"


def send_notification(title: str, message: str, tab: str | None = None, concern_title: str | None = None):
    """Send a Windows toast notification without opening console windows.

    Backlog #40: when ``tab`` (and optionally ``concern_title``) are
    supplied, the toast XML carries a ``launch=`` attribute with
    ``activationType="protocol"`` so a click on the toast opens the
    deep-link URL via the system default browser. Without those args
    the toast is non-interactive (legacy behaviour for tray-status
    notifications that don't map to a single concern).
    """
    try:
        import subprocess as _sp

        safe_title = str(title).replace("'", "''")[:100]
        safe_msg = str(message).replace("'", "''")[:200]

        # Build the launch URL when we have a tab hint. Even if
        # concern_title is empty we still get a useful tab-switch.
        launch_attrs = ""
        if tab:
            launch_url = build_concern_url(tab, concern_title)
            # Single-quoted PS string -> escape ' as ''. URLs shouldn't
            # contain ' in practice but be defensive.
            safe_launch = launch_url.replace("'", "''")
            # activationType="protocol" tells Windows to hand the launch
            # string to the OS's URL handler (default browser). The
            # alternative is "foreground" which requires a registered
            # app and a COM activation handler -- way more setup for
            # the same end result.
            launch_attrs = f' launch="{safe_launch}" activationType="protocol"'

        ps_script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType = WindowsRuntime] | Out-Null; "
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null; "
            f'$xml = \'<toast{launch_attrs}><visual><binding template="ToastText02">'
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
            # 60 s (was 30) — /api/dashboard/summary fans out to 14 slow data
            # collectors in parallel; 30 s was too tight on a loaded machine,
            # leaving the tray stuck in "Starting..." forever when the first
            # poll timed out. Raised on 2026-04-18 after observing 36 s
            # response times in the wild.
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except Exception as e:
            print(f"[Tray] Poll failed: {e}")
            return None

    def update(self):
        """Poll the API, update icon color, and fire notifications for new concerns."""
        data = self.poll()
        # Record the poll attempt regardless of outcome so the tooltip exits
        # the "Starting..." state on the first failed cycle instead of
        # pretending we've never tried. The tooltip helper can still
        # distinguish "never polled" (last_check is None) from "poll failed"
        # (last_check set but current_status == 'unknown').
        self.last_check = time.strftime("%H:%M")
        if not data:
            return

        new_status = data.get("overall", "ok")
        concerns = data.get("concerns", [])

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
                    # Backlog #40: pass the concern title so the toast's
                    # launch URL carries a stable concern slug that the
                    # frontend can scroll-to + flash-highlight after the
                    # tab switch.
                    concern_title=concern.get("title", ""),
                )

        # Clear notifications for concerns that are resolved
        current_keys = {c.get("title", "") for c in concerns}
        self._notified_concerns = self._notified_concerns & current_keys

        self.current_concerns = concerns

    def get_tooltip(self) -> str:
        """Build a tooltip string showing current status."""
        if not self.last_check:
            # Truly never polled yet — tray just came up
            return f"{APP_NAME} — Starting..."

        if self.current_status == "unknown":
            # We tried but the dashboard summary never came back. Surface the
            # failure in the tooltip so the user doesn't see "Starting..."
            # forever — that was the 2026-04-18 bug where a 36s summary
            # response blew past the 30s urlopen timeout on every poll.
            return f"{APP_NAME} — Last poll failed ({self.last_check})"

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
            # BIOS audit snapshot — throttled internally to one run per
            # SNAPSHOT_INTERVAL (15 min), so this is cheap on most polls.
            try:
                import bios_audit

                bios_audit.check_and_log_bios_changes()
            except Exception as e:  # noqa: BLE001
                print(f"[Tray] BIOS audit check failed: {e}")


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

    # ── Post-Windows-Update regression check (backlog #25) ────────────────────
    # Opt-in via env: set WDM_POST_UPDATE_CHECK=1 to enable the automatic
    # "did a Windows Update land since last boot? if so, run the full regression
    # suite + verify + email the user" flow. Runs in a daemon thread so it
    # can't block the tray.
    if os.environ.get("WDM_POST_UPDATE_CHECK") == "1":

        def _post_update_worker():
            # Wait for Flask to come up — the regression suite relies on
            # /api/selftest being reachable.
            time.sleep(15)
            try:
                from post_update_check import run_post_update_check

                run_post_update_check()
            except Exception as e:
                print(f"[Tray] post-update-check failed: {e}")

        threading.Thread(target=_post_update_worker, daemon=True, name="PostUpdateCheck").start()

    # Run the tray icon (blocks until quit)
    icon.run()


if __name__ == "__main__":
    main()
