"""Tests for scripts/post_restart_check.py.

Focus: wait_for_background_queues(), added 2026-05-21 so the CPU-budget
check samples a genuinely idle tray instead of the post-selftest queue
drain. Before the fix, post_restart_check ran its 2 s CPU sample
immediately after the full /api/selftest — which floods the BSOD /
event-ID / startup / process / service lookup queues — so verify
reported a false 70-90 % CPU failure on every run.

The check functions are imported directly and fed stub responses via a
patched _get_json, so no running tray is required.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# Make scripts/ importable (same pattern as test_post_deploy_topology_check).
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import post_restart_check as prc  # noqa: E402


def _status(pending=0, in_flight=0):
    """Build a lookup-status payload like /api/bsod/cache etc. return."""
    return {"queue_pending": pending, "in_flight": in_flight}


class TestWaitForBackgroundQueues:
    """wait_for_background_queues() — drains before the CPU sample."""

    def test_returns_true_immediately_when_all_queues_empty(self, mocker):
        """Every status endpoint reports 0 pending / 0 in-flight → drained
        on the first poll, no waiting."""
        mocker.patch.object(prc, "_get_json", return_value=_status(0, 0))
        sleep = mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=10) is True
        # Drained on the first poll — the sleep/retry path is never taken.
        sleep.assert_not_called()

    def test_returns_true_after_queues_drain(self, mocker):
        """Queues start busy, then drain → True once outstanding hits 0."""
        # Round 1: the bsod endpoint still has 3 pending. Round 2: all empty.
        # Two full rounds over every endpoint in QUEUE_STATUS_ENDPOINTS.
        n = len(prc.QUEUE_STATUS_ENDPOINTS)
        responses = [_status(3, 0)] + [_status(0, 0)] * (n - 1) + [_status(0, 0)] * n
        mocker.patch.object(prc, "_get_json", side_effect=responses)
        mocker.patch.object(prc.time, "sleep")  # no real 3 s waits in tests
        assert prc.wait_for_background_queues("http://x", timeout_s=30) is True

    def test_in_flight_lookups_also_block(self, mocker):
        """A drained queue with a worker still in-flight must keep us
        waiting — that lookup thread is exactly the CPU we'd misread."""
        n = len(prc.QUEUE_STATUS_ENDPOINTS)
        responses = [_status(0, 2)] + [_status(0, 0)] * (n - 1) + [_status(0, 0)] * n
        mocker.patch.object(prc, "_get_json", side_effect=responses)
        mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=30) is True

    def test_returns_false_on_timeout_when_queues_never_drain(self, mocker):
        """A queue that never empties → False once the budget expires. The
        caller still samples — a permanently stuck queue is a real signal,
        not something to hide by skipping the check."""
        mocker.patch.object(prc, "_get_json", return_value=_status(5, 1))
        mocker.patch.object(prc.time, "sleep")  # no-op so the test is fast
        # Tiny budget — the loop spins briefly then times out.
        assert prc.wait_for_background_queues("http://x", timeout_s=0.05) is False

    def test_returns_false_when_endpoints_unreachable(self, mocker):
        """If no status endpoint answers, bail out immediately instead of
        blocking the whole budget — verify must still finish."""
        mocker.patch.object(prc, "_get_json", return_value=None)
        sleep = mocker.patch.object(prc.time, "sleep")
        assert prc.wait_for_background_queues("http://x", timeout_s=120) is False
        sleep.assert_not_called()

    def test_polls_every_queue_status_endpoint(self, mocker):
        """All five background-lookup endpoints must be polled — missing one
        would let its queue drain unobserved and reintroduce the false
        positive."""
        get = mocker.patch.object(prc, "_get_json", return_value=_status(0, 0))
        prc.wait_for_background_queues("http://host", timeout_s=10)
        polled = {call.args[0] for call in get.call_args_list}
        for endpoint in prc.QUEUE_STATUS_ENDPOINTS:
            assert f"http://host{endpoint}" in polled


class TestCheckTrayResourceBudget:
    """check_tray_resource_budget() — must drain queues before sampling."""

    def _patch_tray(self, mocker, cpu_values, threads=14):
        """Wire a fake tray process returning the given CPU samples in order."""
        order = []
        fake_conn = types.SimpleNamespace(laddr=types.SimpleNamespace(port=5000), status="LISTEN", pid=999)
        fake_proc = mocker.MagicMock()
        it = iter(cpu_values)
        last = [cpu_values[-1]]

        def _cpu(*_a, **_k):
            order.append("sample")
            try:
                last[0] = next(it)
            except StopIteration:
                pass  # exhausted -> keep returning the last value (sustained case)
            return last[0]

        fake_proc.cpu_percent.side_effect = _cpu
        fake_proc.num_threads.return_value = threads
        psutil_mock = mocker.MagicMock()
        psutil_mock.net_connections.return_value = [fake_conn]
        psutil_mock.Process.return_value = fake_proc
        psutil_mock.NoSuchProcess = Exception
        mocker.patch.dict(sys.modules, {"psutil": psutil_mock})
        mocker.patch.object(prc, "wait_for_background_queues", side_effect=lambda *a, **k: order.append("wait"))
        return order

    def test_drains_queues_before_sampling_cpu(self, mocker):
        """Regression for the false-positive verify failure: the queue
        drain must happen BEFORE the CPU sample, not after."""
        order = self._patch_tray(mocker, [3.0])
        result = prc.check_tray_resource_budget("http://localhost:5000")
        assert result is True  # within budget on the first idle sample
        assert order[0] == "wait", "queues must drain before the CPU sample"
        assert "sample" in order

    def test_transient_spike_then_idle_passes(self, mocker):
        """A high burst that settles to idle (cold dashboard fan-out / AI drain)
        must PASS -- we keep sampling until the tray reaches idle."""
        self._patch_tray(mocker, [98.0, 90.0, 40.0, 2.0])
        assert prc.check_tray_resource_budget("http://localhost:5000") is True

    def test_sustained_high_cpu_times_out_and_fails(self, mocker):
        """A genuine poll/refresh leak never idles -> the wait-for-idle loop
        hits its deadline with CPU still over budget -> FAIL."""
        # Tiny idle-confirm window so the loop times out quickly in the test.
        mocker.patch.object(prc, "IDLE_CONFIRM_TIMEOUT_S", 0.01)
        self._patch_tray(mocker, [97.0, 98.0, 96.0, 99.0, 97.0])
        assert prc.check_tray_resource_budget("http://localhost:5000") is False
