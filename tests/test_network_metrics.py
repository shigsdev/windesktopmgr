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

import network as net
import windesktopmgr as wdm  # noqa: F401 -- public network funcs resolve via wdm re-export in other tests


@pytest.fixture(autouse=True)
def _reset_net_samples():
    """Wipe the throughput-baseline dict between tests so order doesn't matter."""
    with net._net_samples_lock:
        net._last_net_samples.clear()
    yield
    with net._net_samples_lock:
        net._last_net_samples.clear()


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
        result = net._measure_tcp_latency(("1.1.1.1", 53))
        assert result == 42.5

    def test_timeout_returns_none(self, mocker):
        import socket

        # socket.timeout is a TimeoutError alias in Py 3.10+; use the builtin.
        mocker.patch.object(socket, "create_connection", side_effect=TimeoutError("timed out"))
        assert net._measure_tcp_latency(("1.1.1.1", 53)) is None

    def test_oserror_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "create_connection", side_effect=OSError("connection refused"))
        assert net._measure_tcp_latency(("1.1.1.1", 53)) is None

    def test_gaierror_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "create_connection", side_effect=socket.gaierror("DNS fail"))
        assert net._measure_tcp_latency(("nonexistent.invalid", 53)) is None


class TestLoopbackDetector:
    def test_windows_loopback_name(self):
        assert net._is_loopback_adapter("Loopback Pseudo-Interface 1") is True

    def test_linux_loopback_short_name(self):
        assert net._is_loopback_adapter("lo") is True

    def test_real_nic_names_false(self):
        assert net._is_loopback_adapter("Ethernet") is False
        assert net._is_loopback_adapter("Wi-Fi") is False
        assert net._is_loopback_adapter("eth0") is False
        # Adapter whose name contains "loop" but NOT "loopback" must not be filtered.
        # Real-world case: Hyper-V creates "vEthernet (Default Switch)"-style names.
        assert net._is_loopback_adapter("vEthernet (Loop)") is False


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
        mocker.patch("network._measure_tcp_latency", return_value=lat_ms)

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
        mocker.patch("network._measure_tcp_latency", return_value=1.0)
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
        mocker.patch("network._measure_tcp_latency", return_value=1.0)
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
        mocker.patch("network._measure_tcp_latency", return_value=1.0)
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
        mocker.patch("network._measure_tcp_latency", return_value=1.0)
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
        mocker.patch("network._measure_tcp_latency", return_value=15.0)

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


class TestMeasureDnsLatency:
    """DNS resolution timing — None on any resolver failure, ms on success."""

    def test_success_returns_rounded_ms(self, mocker):
        import socket

        mocker.patch.object(socket, "getaddrinfo", return_value=[("fam", "type", 0, "", ("8.8.8.8", 0))])
        times = iter([2000.0000, 2000.0330])  # 33.0 ms
        mocker.patch("windesktopmgr.time.perf_counter", side_effect=lambda: next(times))
        assert net._measure_dns_latency("dns.google") == 33.0

    def test_gaierror_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("SERVFAIL"))
        assert net._measure_dns_latency("dns.google") is None

    def test_timeout_returns_none(self, mocker):
        import socket

        mocker.patch.object(socket, "getaddrinfo", side_effect=TimeoutError("resolver timed out"))
        assert net._measure_dns_latency("dns.google") is None

    def test_slow_resolution_times_out_to_none(self, mocker):
        import socket
        import time as _t

        def _slow(*_a, **_k):
            _t.sleep(0.3)
            return []

        mocker.patch.object(socket, "getaddrinfo", side_effect=_slow)
        # Bounded worker gives up well before the resolver returns.
        assert net._measure_dns_latency("dns.google", timeout=0.05) is None

    def test_does_not_mutate_global_socket_timeout(self, mocker):
        import socket

        mocker.patch.object(socket, "getaddrinfo", return_value=[("f", "t", 0, "", ("8.8.8.8", 0))])
        sentinel = socket.getdefaulttimeout()
        net._measure_dns_latency("dns.google")
        assert socket.getdefaulttimeout() == sentinel, "must not touch process-global socket timeout"


class TestMeasureReachability:
    """Reachable if ANY raw-IP target connects; None only when all fail."""

    def test_first_target_wins(self, mocker):
        mocker.patch.object(net, "_measure_tcp_latency", side_effect=[12.3])
        assert net._measure_reachability((("8.8.8.8", 53),)) == 12.3

    def test_falls_through_to_second_target(self, mocker):
        # First target blocked (None), second succeeds — no false "down".
        mocker.patch.object(net, "_measure_tcp_latency", side_effect=[None, 44.0])
        assert net._measure_reachability((("8.8.8.8", 53), ("1.1.1.1", 443))) == 44.0

    def test_all_fail_returns_none(self, mocker):
        mocker.patch.object(net, "_measure_tcp_latency", side_effect=[None, None])
        assert net._measure_reachability((("8.8.8.8", 53), ("1.1.1.1", 443))) is None


class TestGetNetworkHealth:
    def test_healthy_shape(self, mocker):
        mocker.patch.object(net, "_measure_reachability", return_value=25.0)
        mocker.patch.object(net, "_measure_dns_latency", return_value=30.0)
        mocker.patch("windesktopmgr.psutil.net_if_stats", return_value={"Ethernet": SimpleNamespace(isup=True)})
        h = net.get_network_health()
        assert h["internet_reachable"] is True
        assert h["ping_latency_ms"] == 25.0
        assert h["dns_working"] is True
        assert h["dns_latency_ms"] == 30.0
        assert h["adapters"] == [{"name": "Ethernet", "up": True}]

    def test_down_shape(self, mocker):
        mocker.patch.object(net, "_measure_reachability", return_value=None)
        mocker.patch.object(net, "_measure_dns_latency", return_value=None)
        mocker.patch("windesktopmgr.psutil.net_if_stats", return_value={"Ethernet": SimpleNamespace(isup=False)})
        h = net.get_network_health()
        assert h["internet_reachable"] is False
        assert h["dns_working"] is False

    def test_loopback_excluded(self, mocker):
        mocker.patch.object(net, "_measure_reachability", return_value=10.0)
        mocker.patch.object(net, "_measure_dns_latency", return_value=10.0)
        mocker.patch(
            "windesktopmgr.psutil.net_if_stats",
            return_value={
                "Loopback Pseudo-Interface 1": SimpleNamespace(isup=True),
                "Ethernet": SimpleNamespace(isup=True),
            },
        )
        names = [a["name"] for a in net.get_network_health()["adapters"]]
        assert names == ["Ethernet"]

    def test_net_if_stats_exception_is_safe(self, mocker):
        mocker.patch.object(net, "_measure_reachability", return_value=10.0)
        mocker.patch.object(net, "_measure_dns_latency", return_value=10.0)
        mocker.patch("windesktopmgr.psutil.net_if_stats", side_effect=OSError("wmi down"))
        h = net.get_network_health()
        assert h["adapters"] == []
        assert h["internet_reachable"] is True  # probe path independent of adapters


class TestNetworkHealthConcerns:
    def _base(self, **over):
        d = {
            "available": True,
            "internet_reachable": True,
            "ping_latency_ms": 20.0,
            "dns_working": True,
            "dns_latency_ms": 20.0,
            "adapters": [{"name": "Ethernet", "up": True}],
        }
        d.update(over)
        return d

    def test_healthy_no_concerns(self):
        assert net.network_health_concerns(self._base()) == []

    def test_internet_unreachable_is_critical(self):
        cs = net.network_health_concerns(self._base(internet_reachable=False, ping_latency_ms=None))
        assert len(cs) == 1
        assert cs[0]["level"] == "critical"
        assert cs[0]["tab"] == "network"
        assert "unreachable" in cs[0]["title"].lower()

    def test_dns_failing_is_critical(self):
        cs = net.network_health_concerns(self._base(dns_working=False, dns_latency_ms=None))
        assert [c["level"] for c in cs] == ["critical"]
        assert "dns" in cs[0]["title"].lower()

    def test_no_active_adapter_is_critical(self):
        cs = net.network_health_concerns(
            self._base(adapters=[{"name": "Ethernet", "up": False}, {"name": "Wi-Fi", "up": False}])
        )
        assert any("No active network adapter" in c["title"] for c in cs)
        assert all(c["level"] == "critical" for c in cs)

    def test_high_ping_is_warning_not_critical(self):
        cs = net.network_health_concerns(self._base(ping_latency_ms=350.0))
        assert [c["level"] for c in cs] == ["warning"]
        assert "latency" in cs[0]["title"].lower()

    def test_slow_dns_is_warning(self):
        cs = net.network_health_concerns(self._base(dns_latency_ms=900.0))
        assert [c["level"] for c in cs] == ["warning"]

    def test_fully_down_three_criticals(self):
        cs = net.network_health_concerns(
            self._base(
                internet_reachable=False,
                ping_latency_ms=None,
                dns_working=False,
                dns_latency_ms=None,
                adapters=[{"name": "Ethernet", "up": False}],
            )
        )
        assert len(cs) == 3
        assert all(c["level"] == "critical" for c in cs)

    def test_empty_adapters_no_false_adapter_critical(self):
        # No adapters enumerated at all (psutil failed) must NOT fire the
        # "no active adapter" critical — absence of data != everything down.
        cs = net.network_health_concerns(self._base(adapters=[]))
        assert not any("No active network adapter" in c["title"] for c in cs)
