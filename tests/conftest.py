"""
conftest.py — shared pytest fixtures for WinDesktopMgr tests.

Key design decisions:
- Caches (bsod, event, startup, process, services) are only loaded from disk
  inside `if __name__ == "__main__":`, so importing the module gives us clean
  empty dicts — no file-system dependency during tests.
- Background worker threads are also only started in that same block, so the
  test run is entirely single-threaded.
- The autouse `reset_globals` fixture wipes all mutable module-level state
  between every test, preventing bleed-through.
"""

import json
import os
import sys
from dataclasses import dataclass

# Make sure the project root is on sys.path so `import windesktopmgr` works
# regardless of where pytest is invoked from.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

import disk
import windesktopmgr as wdm

# ── Fixture loading helpers ───────────────────────────────────────────────────

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(relative_path: str):
    """Load a JSON fixture file and return the 'data' field.

    Args:
        relative_path: path relative to tests/fixtures/ (e.g. "powershell/ps_disk_health.json")

    Returns the 'data' field from the fixture, or the full contents if no 'data' key.
    Raises pytest.skip if the fixture file doesn't exist.
    """
    path = os.path.join(FIXTURES_DIR, relative_path)
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {relative_path} — run capture_fixtures.py")
    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    return obj.get("data", obj)


@dataclass
class MockResult:
    """Simulate subprocess.CompletedProcess for snapshot/E2E tests."""

    stdout: str = ""
    returncode: int = 0
    stderr: str = ""


# ── App / client fixtures ──────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def app():
    wdm.app.config["TESTING"] = True
    wdm.app.config["WTF_CSRF_ENABLED"] = False
    return wdm.app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


# ── Global state reset (autouse — runs before every test) ─────────────────────


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset every mutable module-level global before each test."""
    # Headless mode (set by tray.py — must be off during tests)
    wdm.HEADLESS_MODE = False

    # Driver scan state
    wdm._dell_cache = None
    wdm._scan_results = None
    wdm._scan_status = {"status": "idle", "progress": 0, "message": "Ready to scan"}

    # Knowledge caches (normally loaded from JSON on startup)
    wdm._bsod_cache.clear()
    wdm._event_cache.clear()
    wdm._startup_cache.clear()
    wdm._process_cache.clear()
    wdm._services_cache.clear()

    # In-flight sets / queues — drain without blocking
    wdm._bsod_in_flight.clear()
    wdm._lookup_in_flight.clear()
    wdm._startup_in_flight.clear()
    wdm._process_in_flight.clear()
    wdm._services_in_flight.clear()

    # Disk analyzer caches (_winsxs_cache persists DISM results for 1h).
    # Lives in the `disk` blueprint module after the backlog-#22 extraction.
    disk._winsxs_cache["ts"] = 0.0
    disk._winsxs_cache["data"] = None

    # Dashboard summary cache (serves last-known-good for 30 s). Stale
    # cache between tests would cause later tests to "see" an earlier
    # test's mocked collectors and silently skip their own mocks.
    wdm._dashboard_cache_clear()

    # Request-log flood suppressor state -- a prior test's requests must
    # not cause a later test's first request to be silently suppressed
    # as a duplicate.
    wdm._request_log_suppressor._state.clear()

    yield  # run the test

    # Post-test cleanup (same as pre-test for symmetry)
    wdm._bsod_cache.clear()
    wdm._event_cache.clear()
    wdm._startup_cache.clear()
    wdm._process_cache.clear()
    wdm._services_cache.clear()


# ── Reusable data fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def sample_crashes():
    return [
        {
            "timestamp": "2026-03-01T10:00:00+00:00",
            "error_code": "HYPERVISOR_ERROR",
            "stop_code": "0x00020001",
            "faulty_driver": "intelppm.sys",
            "source": "event_log",
            "event_id": 1001,
        },
        {
            "timestamp": "2026-03-05T14:30:00+00:00",
            "error_code": "KERNEL_SECURITY_CHECK_FAILURE",
            "stop_code": "0x00000139",
            "faulty_driver": "ntoskrnl.exe",
            "source": "event_log",
            "event_id": 1001,
        },
    ]


@pytest.fixture
def mock_subprocess_ok(mocker):
    """Mock subprocess.run to return an empty JSON array."""
    mock = mocker.patch("windesktopmgr.subprocess.run")
    mock.return_value.stdout = "[]"
    mock.return_value.returncode = 0
    mock.return_value.stderr = ""
    return mock
