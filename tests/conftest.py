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

import bsod
import disk
import events
import homenet
import processes
import windesktopmgr as wdm

# ── Production-file isolation (autouse, session-scoped) ───────────────────────
#
# RCA for the 2026-05-08 "MoCA names disappeared" incident pinned the wipe to
# the 10:55 window when pytest ran pre-commit hooks for commit e640534. The
# inventory dropped from ~32 KB to ~9 KB in a single scan/light cycle while
# the live tray was running. The suspect path: a test in the suite imported
# homenet, exercised a route that called _save_homenet_inventory without
# mocking the save path, and the call wrote into the REAL inventory file
# (C:\shigsapps\windesktopmgr\homenet_inventory.json -- the same one the
# tray was reading) because nothing redirected HOMENET_INVENTORY_FILE.
#
# This session-scoped autouse fixture closes that gap structurally: every
# test in the suite gets a fresh tmp_path-backed homenet_inventory.json by
# default. Tests that need to test the inventory load/save itself
# (TestInventoryLoadFailSafeAgainstStateWipe etc.) override locally via
# monkeypatch -- their override wins because they run AFTER this fixture.
#
# Without this fixture, any future test that accidentally hits an unmocked
# _save_homenet_inventory would clobber the user's production state again.


@pytest.fixture(autouse=True, scope="session")
def _isolate_homenet_inventory_file(tmp_path_factory):
    """Redirect homenet.HOMENET_INVENTORY_FILE to a per-session tmp path
    so no test can write to the user's real inventory file.

    Returns the test path so tests that want to read what was written
    can resolve it without hardcoding."""
    test_inv = tmp_path_factory.mktemp("homenet_inventory_isolated") / "homenet_inventory.json"
    real = homenet.HOMENET_INVENTORY_FILE
    homenet.HOMENET_INVENTORY_FILE = str(test_inv)
    try:
        yield str(test_inv)
    finally:
        homenet.HOMENET_INVENTORY_FILE = real


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
    wdm._wu_driver_cache = None
    wdm._scan_results = None
    wdm._scan_status = {"status": "idle", "progress": 0, "message": "Ready to scan"}

    # Knowledge caches (normally loaded from JSON on startup)
    bsod._bsod_cache.clear()
    events._event_cache.clear()
    wdm._startup_cache.clear()
    processes._process_cache.clear()
    wdm._services_cache.clear()

    # In-flight sets / queues — drain without blocking
    bsod._bsod_in_flight.clear()
    events._lookup_in_flight.clear()
    wdm._startup_in_flight.clear()
    processes._process_in_flight.clear()
    wdm._services_in_flight.clear()

    # Disk analyzer caches (_winsxs_cache persists DISM results for 1h).
    # Lives in the `disk` blueprint module after the backlog-#22 extraction.
    disk._winsxs_cache["ts"] = 0.0
    disk._winsxs_cache["data"] = None

    # Dashboard summary cache (serves last-known-good for 30 s). Stale
    # cache between tests would cause later tests to "see" an earlier
    # test's mocked collectors and silently skip their own mocks.
    wdm._dashboard_cache_clear()

    # NVIDIA update info cache (10-min TTL). Must reset between tests so
    # a prior test's cached result doesn't bleed into the next test.
    wdm._reset_nvidia_update_cache()

    # Request-log flood suppressor state -- a prior test's requests must
    # not cause a later test's first request to be silently suppressed
    # as a duplicate.
    wdm._request_log_suppressor._state.clear()

    # Inventory load-failure flag (homenet.py, added 2026-05-12 to fix the
    # silent state-wipe regression). Must reset between tests so a prior
    # test that deliberately triggered a load failure doesn't make later
    # tests' _save_homenet_inventory calls a no-op.
    import homenet

    homenet._inventory_load_failed = False
    homenet._inventory_load_failure_reason = ""

    yield  # run the test

    # Post-test cleanup (same as pre-test for symmetry)
    bsod._bsod_cache.clear()
    events._event_cache.clear()
    wdm._startup_cache.clear()
    processes._process_cache.clear()
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
