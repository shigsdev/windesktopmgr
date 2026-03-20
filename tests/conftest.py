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

import os
import sys

# Make sure the project root is on sys.path so `import windesktopmgr` works
# regardless of where pytest is invoked from.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

import windesktopmgr as wdm

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
    # Driver scan state
    wdm._dell_cache   = None
    wdm._scan_results = None
    wdm._scan_status  = {"status": "idle", "progress": 0, "message": "Ready to scan"}

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
