"""
tests/test_network_metrics.py — Network metrics collector (backlog #38).

get_network_metrics() is Python-first per CLAUDE.md: it uses psutil
(net_io_counters, net_connections) + stdlib socket (TCP-connect latency
probe). No subprocess, no PowerShell. Every test mocks the psutil
functions and socket.create_connection, so tests run on any OS.

Coverage:
  1. First call    — no baseline, throughput reports 0
  2. Delta math    — real Mbps after two samples
  3. Loopback filter — "Loopback Pseudo-Interface 1" excluded
  4. Latency OK    — TCP connect succeeds, ms reported
  5. Latency fail  — timeout / refused → None (not 0)
  6. Conns happy   — count ESTABLISHED only
  7. Conns Access denied → fallback to inet4
  8. Conns both fail → None (field absent from trend)
  9. Counter rollover / NIC reset — negative delta → 0 Mbps, not negative
 10. Zero dt (rapid successive calls) → 0 Mbps, not division by zero
 11. net_io_counters exception → error field populated, probe still runs
 12. latency probe runs even when counters fail (independent paths)
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import windesktopmgr as wdm


@pytest.fixture(autouse=True)
def _reset_net_samples():
    """Wipe the throughput-baseline dict between tests so order doesn't matter."""
    with wdm._net_samples_lock:
        wdm._last_net_samples.clear()
    yield
    with wdm._net_samples_lock:
        wdm._last_net_samples.clear()


def _fake_counters(nic_bytes: dict) -> dict:
    """Build the shape psutil.net_io_counters(pernic=True) returns."""
    return {
        name: SimpleNamespace(
            bytes_sent=sent, bytes_recv=recv, packets_sent=0, packets_recv=0, errin=0, errout=0, dropin=0, dropout=0
        )
        for name, (sent, recv) in nic_bytes.items()
    }


def _fake_conn(status: str):
    """Minimal shape for psutil.net_connections() items."""
    return SimpleNamespace(status=status)


class TestMeasureTcpLatency:
    def test_success_returns_rounded_ms(self, mocker):
        import socket

        mocker.patch.object(socket, "create_connection", return_value=MagicMock())
        # perf_counter advances exactly 0.0425 s -> 42.5 ms
        times = iter([1000.0000, 1000.0425])
        mocker.patch("windesktopmgr.time.perf_counter", side_effect=lambda: next(times))
        result = wdm._measure_tcp_latency(("1.1.1.1", 53))
        assert result == 42.5

    def test_timeout_returns_none(self, mocker):
        import socket

        # socket.timeout is a TimeoutError alias in Py 3.10+; use the builtin.
        mocker.patch.object(socket, "create_connection", side_effect=TimeoutError("timed out"))
        assert wdm._measure_tcp_latency(("1.1.1.1", 53)) is None

    def test_oserror_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "create_connection", side_effect=OSError("connection refused"))
        assert wdm._measure_tcp_latency(("1.1.1.1", 53)) is None

    def test_gaierror_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "create_connection", side_effect=socket.gaierror("DNS fail"))
        assert wdm._measure_tcp_latency(("nonexistent.invalid", 53)) is None


class TestLoopbackDetector:
    def test_windows_loopback_name(self):
        assert wdm._is_loopback_adapter("Loopback Pseudo-Interface 1") is True

    def test_linux_loopback_short_name(self):
        assert wdm._is_loopback_adapter("lo") is True

    def test_real_nic_names_false(self):
        assert wdm._is_loopback_adapter("Ethernet") is False
        assert wdm._is_loopback_adapter("Wi-Fi") is False
        assert wdm._is_loopback_adapter("eth0") is False
        # Adapter whose name contains "loop" but NOT "loopback" must not be filtered.
        # Real-world case: Hyper-V creates "vEthernet (Default Switch)"-style names.
        assert wdm._is_loopback_adapter("vEthernet (Loop)") is False


class TestGetNetworkMetrics:
    def _mock_all(
        self,
        mocker,
        *,
        counters=None,
        established=5,
        lat_ms=12.3,
        access_denied=False,
        inet4_also_fails=False,
        io_exc=None,
    ):
        """Full mock setup for a get_network_metrics() call. All calls that
        could escape to the real system are patched."""
        if counters is None:
            counters = _fake_counters({"Ethernet": (100, 200)})

        if io_exc is not None:
            mocker.patch("windesktopmgr.psutil.net_io_counters", side_effect=io_exc)
        else:
            mocker.patch("windesktopmgr.psutil.net_io_counters", return_value=counters)

        if access_denied:
            # First call (kind='tcp') raises AccessDenied, second (kind='inet4') either works or fails
            import psutil as _psutil

            if inet4_also_fails:
                side = [_psutil.AccessDenied(), OSError("still denied")]
            else:
                side = [_psutil.AccessDenied(), [_fake_conn("ESTABLISHED")] * established]
            mocker.patch("windesktopmgr.psutil.net_connections", side_effect=side)
        else:
            conns = [_fake_conn("ESTABLISHED")] * established + [_fake_conn("LISTEN"), _fake_conn("TIME_WAIT")]
            mocker.patch("windesktopmgr.psutil.net_connections", return_value=conns)

        # Latency: patch _measure_tcp_latency directly for determinism
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=lat_ms)

    def test_first_call_throughput_is_zero(self, mocker):
        """No baseline -> rate uncomputable -> 0 Mbps, not None."""
        self._mock_all(mocker)
        result = wdm.get_network_metrics()
        assert result["available"] is True
        assert result["throughput_in_mbps"] == 0.0
        assert result["throughput_out_mbps"] == 0.0

    def test_latency_populated_from_probe(self, mocker):
        self._mock_all(mocker, lat_ms=4.0)
        result = wdm.get_network_metrics()
        assert result["latency_ms"] == 4.0
        assert result["latency_target"] == "1.1.1.1:53"

    def test_latency_none_when_probe_fails(self, mocker):
        self._mock_all(mocker, lat_ms=None)
        result = wdm.get_network_metrics()
        assert result["latency_ms"] is None

    def test_connections_counts_established_only(self, mocker):
        """LISTEN / TIME_WAIT etc. must NOT count."""
        self._mock_all(mocker, established=7)
        result = wdm.get_network_metrics()
        assert result["connections_established"] == 7

    def test_access_denied_falls_back_to_inet4(self, mocker):
        self._mock_all(mocker, access_denied=True, established=3)
        result = wdm.get_network_metrics()
        # AccessDenied on first call → falls back to inet4 → still gets 3
        assert result["connections_established"] == 3

    def test_both_paths_fail_leaves_connections_none(self, mocker):
        self._mock_all(mocker, access_denied=True, inet4_also_fails=True)
        result = wdm.get_network_metrics()
        assert result["connections_established"] is None
        # Other fields still valid -- connection enumeration failure is
        # NOT a full-collector failure
        assert result["available"] is True

    def test_throughput_delta_becomes_mbps(self, mocker):
        """Two samples 1 second apart with 1_000_000 byte delta -> 8.0 Mbps."""
        # First call: counters = {"Ethernet": (0, 0)} at time T
        # Second call: counters = {"Ethernet": (1_000_000, 500_000)} at T+1
        # Expected: out=8 Mbps, in=4 Mbps
        counters1 = _fake_counters({"Ethernet": (0, 0)})
        counters2 = _fake_counters({"Ethernet": (1_000_000, 500_000)})
        mocker.patch("windesktopmgr.psutil.net_io_counters", side_effect=[counters1, counters2])
        mocker.patch("windesktopmgr.psutil.net_connections", return_value=[])
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=1.0)
        # Freeze time: T=1000.0, T+1=1001.0
        mocker.patch("windesktopmgr.time.time", side_effect=[1000.0, 1001.0])

        wdm.get_network_metrics()  # establishes baseline
        result = wdm.get_network_metrics()
        assert result["throughput_out_mbps"] == 8.0
        assert result["throughput_in_mbps"] == 4.0

    def test_loopback_bytes_excluded_from_total(self, mocker):
        """Aggregate throughput must ignore loopback traffic."""
        counters1 = _fake_counters(
            {
                "Ethernet": (0, 0),
                "Loopback Pseudo-Interface 1": (0, 0),
            }
        )
        counters2 = _fake_counters(
            {
                "Ethernet": (500_000, 0),
                "Loopback Pseudo-Interface 1": (999_000_000, 0),  # enormous loopback — must be ignored
            }
        )
        mocker.patch("windesktopmgr.psutil.net_io_counters", side_effect=[counters1, counters2])
        mocker.patch("windesktopmgr.psutil.net_connections", return_value=[])
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=1.0)
        mocker.patch("windesktopmgr.time.time", side_effect=[1000.0, 1001.0])

        wdm.get_network_metrics()
        result = wdm.get_network_metrics()
        # Only Ethernet (500_000 bytes in 1s = 4 Mbps out)
        assert result["throughput_out_mbps"] == 4.0

    def test_counter_rollover_becomes_zero_not_negative(self, mocker):
        """NIC reset / counter rollover: second sample LOWER than first.
        Must clamp to 0 Mbps -- a negative Mbps value is nonsense."""
        counters1 = _fake_counters({"Ethernet": (5_000_000, 10_000_000)})
        counters2 = _fake_counters({"Ethernet": (1_000, 2_000)})  # reset
        mocker.patch("windesktopmgr.psutil.net_io_counters", side_effect=[counters1, counters2])
        mocker.patch("windesktopmgr.psutil.net_connections", return_value=[])
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=1.0)
        mocker.patch("windesktopmgr.time.time", side_effect=[1000.0, 1001.0])

        wdm.get_network_metrics()
        result = wdm.get_network_metrics()
        assert result["throughput_in_mbps"] == 0.0
        assert result["throughput_out_mbps"] == 0.0

    def test_zero_dt_does_not_divide_by_zero(self, mocker):
        """Two samples with the same timestamp (clock skew / very fast
        back-to-back) must not crash; rate reports as 0."""
        counters = _fake_counters({"Ethernet": (0, 0)})
        counters2 = _fake_counters({"Ethernet": (1000, 1000)})
        mocker.patch("windesktopmgr.psutil.net_io_counters", side_effect=[counters, counters2])
        mocker.patch("windesktopmgr.psutil.net_connections", return_value=[])
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=1.0)
        mocker.patch("windesktopmgr.time.time", side_effect=[1000.0, 1000.0])  # same ts!

        wdm.get_network_metrics()
        result = wdm.get_network_metrics()
        assert result["throughput_in_mbps"] == 0.0
        assert result["throughput_out_mbps"] == 0.0

    def test_counter_exception_sets_error_and_returns_early(self, mocker):
        self._mock_all(mocker, io_exc=OSError("adapter enumeration failed"))
        result = wdm.get_network_metrics()
        # Collector short-circuits -- can't compute throughput without counters
        assert result["error"] and "net_io_counters failed" in result["error"]
        # Other fields stay at defaults
        assert result["throughput_in_mbps"] == 0.0
        assert result["latency_ms"] is None  # never ran the probe after early return

    def test_latency_probe_independent_of_conn_enumeration(self, mocker):
        """Even when net_connections totally fails, latency still measures.
        Trend chart must still show "network is reachable" vs "network is down"
        separately from admin-permission issues."""
        counters = _fake_counters({"Ethernet": (0, 0)})
        mocker.patch("windesktopmgr.psutil.net_io_counters", return_value=counters)
        mocker.patch("windesktopmgr.psutil.net_connections", side_effect=RuntimeError("broken"))
        mocker.patch("windesktopmgr._measure_tcp_latency", return_value=15.0)

        result = wdm.get_network_metrics()
        assert result["latency_ms"] == 15.0
        assert result["connections_established"] is None

    def test_shape_always_includes_every_key(self, mocker):
        """Regression pin: future edits must not silently drop a key from
        the returned dict. The extract_metrics() function depends on the
        full shape being present."""
        self._mock_all(mocker)
        result = wdm.get_network_metrics()
        for key in (
            "available",
            "source",
            "throughput_in_mbps",
            "throughput_out_mbps",
            "latency_ms",
            "latency_target",
            "connections_established",
            "error",
        ):
            assert key in result, f"missing key {key!r}"
