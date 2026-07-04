"""Network monitor + metrics for WinDesktopMgr (#54 PR H).

get_network_data() powers the full Network Monitor tab (adapters,
connections, listeners) and get_network_metrics() feeds the dashboard
Trends card with aggregate throughput (delta-tracked via the in-place
_last_net_samples dict under _net_samples_lock) + a TCP-connect latency
probe to Cloudflare DNS. summarize_network() folds a reading into the
dashboard insight/action shape. All in-process via psutil + socket -- no
PowerShell subprocess.

psutil/socket are imported here but are the SAME module objects the test
suite patches as windesktopmgr.psutil.net_io_counters /
windesktopmgr.psutil.net_connections (module-attribute patches shared
across importers), so those mocks keep intercepting after the move. The
Flask route, /api/selftest globals() lookup, get_summary dispatch, NLQ
dispatch, and the dashboard fan-out call the re-exported bindings.

_insight is duplicated locally (disk.py / bsod.py precedent).
"""

import concurrent.futures
import socket
import threading
import time
from collections import Counter

import psutil


def _insight(level: str, text: str, action: str = "") -> dict:
    return {"level": level, "text": text, "action": action}


def get_network_data() -> dict:
    """Enumerate TCP connections + adapter stats using psutil (no PowerShell).

    Replaces ``Get-NetTCPConnection`` + ``Get-NetAdapterStatistics`` +
    ``Get-NetAdapter`` (backlog #24 batch A, sites #22 + #23). The output
    shape is preserved exactly so the /api/network route and JS renderer
    don't change:

    - ``State`` values are mapped from psutil's ``ESTABLISHED``/``LISTEN``
      constants back to PowerShell's ``Established``/``Listen`` title-case
      so existing filters keep working.
    - ``LinkSpeedMb`` comes from ``net_if_stats().speed`` (already Mbps).
    - ``SentMB`` / ``ReceivedMB`` come from ``net_io_counters(pernic=True)``.
    - Process names are resolved per-PID via ``Process(pid).name()``.
    """
    try:
        # Build pid -> name map once to avoid per-conn Process() lookups.
        pid_names: dict[int, str] = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[proc.info["pid"]] = proc.info.get("name") or "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Map psutil status constants → the title-case strings the UI expects.
        _state_map = {
            psutil.CONN_ESTABLISHED: "Established",
            psutil.CONN_LISTEN: "Listen",
            psutil.CONN_SYN_SENT: "SynSent",
            psutil.CONN_SYN_RECV: "SynReceived",
            psutil.CONN_FIN_WAIT1: "FinWait1",
            psutil.CONN_FIN_WAIT2: "FinWait2",
            psutil.CONN_TIME_WAIT: "TimeWait",
            psutil.CONN_CLOSE: "Closed",
            psutil.CONN_CLOSE_WAIT: "CloseWait",
            psutil.CONN_LAST_ACK: "LastAck",
            psutil.CONN_CLOSING: "Closing",
            psutil.CONN_NONE: "None",
        }

        conns: list[dict] = []
        try:
            raw_conns = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            # net_connections needs admin on Windows for system-wide visibility.
            # Fall back to empty list (same as PS pipeline when RPC is denied).
            raw_conns = []
        for c in raw_conns:
            laddr = c.laddr
            raddr = c.raddr
            pid = c.pid or 0
            conns.append(
                {
                    "LocalAddress": laddr.ip if laddr else "",
                    "LocalPort": laddr.port if laddr else 0,
                    "RemoteAddress": raddr.ip if raddr else "",
                    "RemotePort": raddr.port if raddr else 0,
                    "State": _state_map.get(c.status, c.status),
                    "PID": pid,
                    "Process": pid_names.get(pid, "Unknown"),
                }
            )

        # Adapters: combine net_io_counters (bytes) + net_if_stats (speed/up).
        try:
            io_counters = psutil.net_io_counters(pernic=True)
        except Exception:
            io_counters = {}
        try:
            if_stats = psutil.net_if_stats()
        except Exception:
            if_stats = {}

        adapters: list[dict] = []
        for name, counters in io_counters.items():
            stats = if_stats.get(name)
            adapters.append(
                {
                    "Name": name,
                    "SentMB": round(counters.bytes_sent / (1024 * 1024), 2),
                    "ReceivedMB": round(counters.bytes_recv / (1024 * 1024), 2),
                    "Status": ("Up" if (stats and stats.isup) else "Down") if stats else "Unknown",
                    # psutil speed is already in Mbps — match the PS output directly.
                    "LinkSpeedMb": int(stats.speed) if stats and stats.speed else 0,
                }
            )

        established = [c for c in conns if c.get("State") == "Established"]
        listening = [c for c in conns if c.get("State") == "Listen"]

        # Group by process for summary
        proc_counts = Counter(c.get("Process", "Unknown") for c in established)
        top_procs = [{"process": p, "connections": n} for p, n in proc_counts.most_common(10)]

        return {
            "established": established,
            "listening": listening,
            "adapters": adapters,
            "top_processes": top_procs,
            "total_connections": len(established),
            "total_listening": len(listening),
        }
    except Exception as e:
        print(f"[Network error] {e}")
        return {
            "established": [],
            "listening": [],
            "adapters": [],
            "top_processes": [],
            "total_connections": 0,
            "total_listening": 0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK METRICS — Trends dashboard (backlog #38)
#
# Lightweight time-series metrics for the Trends sparklines, separate from
# get_network_data() which powers the full Network Monitor tab (connection
# table + per-adapter detail). Four numbers per sample:
#
#   throughput_in_mbps       — sum of all non-loopback adapters
#   throughput_out_mbps      — same
#   latency_ms               — single TCP-connect probe to Cloudflare DNS
#   connections_established  — count of ESTABLISHED TCP connections
#
# Python-first: psutil + stdlib socket. No subprocess anywhere.
# ══════════════════════════════════════════════════════════════════════════════

# Throughput needs a baseline to compute Mbps (same pattern as the Processes
# tab CPU % fix -- see _last_cpu_samples). Dict layout:
#   {"total": (bytes_sent_cumulative, bytes_recv_cumulative, wall_clock_ts)}
# Only one key ("total") because the Trends card shows aggregate throughput
# across every non-loopback NIC, not per-adapter. Per-NIC breakdown would
# add N sparklines for marginal value on a home rig.
_last_net_samples: dict[str, tuple[float, float, float]] = {}
_net_samples_lock = threading.Lock()

# External target for the TCP-connect latency probe. Cloudflare DNS: 1.1.1.1
# on port 53 is widely open (not firewalled the way ICMP often is), has
# predictable sub-50 ms RTT from most places, and doesn't require admin
# privileges for a raw-socket ping. Changing this target would shift every
# recorded historic latency sample upward/downward, so pin it here.
_LATENCY_PROBE_TARGET: tuple[str, int] = ("1.1.1.1", 53)
_LATENCY_PROBE_TIMEOUT_S: float = 2.0


def _measure_tcp_latency(
    target: tuple[str, int] = _LATENCY_PROBE_TARGET, timeout: float = _LATENCY_PROBE_TIMEOUT_S
) -> float | None:
    """Return round-trip milliseconds of a TCP connect to ``target``.

    Returns ``None`` on any failure (DNS fail, connection refused, timeout,
    no route to host, firewall drop). Callers treat None as "no signal"
    rather than "zero latency" -- recording 0 ms for a failed probe would
    lie to the trend chart.

    Uses ``socket.create_connection`` which does DNS + TCP handshake in one
    call. Measured in ``time.perf_counter()`` for monotonic accuracy even
    across NTP adjustments.
    """

    try:
        t0 = time.perf_counter()
        with socket.create_connection(target, timeout=timeout):
            return round((time.perf_counter() - t0) * 1000.0, 1)
    except (OSError, TimeoutError, socket.gaierror):
        # socket.timeout is an alias for TimeoutError in Py 3.10+; listed
        # explicitly via TimeoutError to satisfy ruff UP041. socket.gaierror
        # is a distinct subclass of OSError for DNS-resolution failures.
        return None


def _is_loopback_adapter(name: str) -> bool:
    """True for Windows / Linux loopback NIC names.

    Windows usually calls it "Loopback Pseudo-Interface 1" but can vary by
    locale / virtualisation stack. Matching the substring ``loopback`` is
    generous enough to catch every variant I've seen and strict enough to
    avoid false positives -- real user-facing NICs don't include the word.
    """
    n = name.lower()
    return "loopback" in n or n == "lo"


# ── Network HEALTH (reachability / DNS / adapter) for the dashboard ──────────
# Distinct from get_network_metrics (throughput/latency for the Trends card):
# this answers "is the internet actually usable right now?" so the dashboard
# concerns feed matches the daily health report (SystemHealthDiag.
# check_network_health), which flags internet-down / DNS-fail / adapter-down as
# critical. Before this the dashboard collected only throughput and could not
# surface those conditions at all.

# Raw-IP targets (no DNS needed) so reachability is measured INDEPENDENTLY of
# DNS — that lets us tell "internet down" apart from "DNS broken". Multiple
# host:port pairs so a firewall that blocks one port (e.g. outbound :53) can't
# produce a false "internet unreachable" critical: reachable if ANY connects.
_REACHABILITY_TARGETS: tuple[tuple[str, int], ...] = (("8.8.8.8", 53), ("1.1.1.1", 443))
_NET_HEALTH_TIMEOUT_S: float = 1.5
_DNS_RESOLVE_HOST: str = "dns.google"
_PING_WARN_MS: float = 200.0  # matches SystemHealthDiag.check_network_health
_DNS_WARN_MS: float = 500.0  # matches SystemHealthDiag.check_network_health


def _measure_dns_latency(host: str = _DNS_RESOLVE_HOST, timeout: float = _NET_HEALTH_TIMEOUT_S) -> float | None:
    """Return DNS resolution time in ms for ``host``, or None if it fails.

    None means "DNS is broken" (SERVFAIL, no resolver) or "too slow to matter"
    (resolution exceeded ``timeout``) — NOT zero. ``getaddrinfo`` has no timeout
    parameter and ``socket.setdefaulttimeout`` is process-global (unsafe to
    mutate from one of the dashboard's parallel collector threads), so we bound
    it by resolving in a throwaway worker and giving up after ``timeout``. A
    hung resolver leaks that one daemon-ish worker until the OS call returns —
    acceptable and far better than stalling the whole fan-out.
    """

    def _resolve() -> float:
        t0 = time.perf_counter()
        socket.getaddrinfo(host, None)
        return round((time.perf_counter() - t0) * 1000.0, 1)

    # NOT a `with` block: the context manager's __exit__ calls
    # shutdown(wait=True), which would block on a hung resolver and defeat the
    # timeout. shutdown(wait=False) returns immediately and lets the worker
    # finish (and be reaped) on its own once getaddrinfo returns.
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return ex.submit(_resolve).result(timeout=timeout)
    except (concurrent.futures.TimeoutError, OSError, socket.gaierror):
        return None
    finally:
        ex.shutdown(wait=False)


def _measure_reachability(
    targets: tuple[tuple[str, int], ...] = _REACHABILITY_TARGETS,
    timeout: float = _NET_HEALTH_TIMEOUT_S,
) -> float | None:
    """RTT in ms of the first reachable raw-IP target, or None if none respond.

    Tries each target in turn; the first successful TCP connect wins. None
    only when EVERY target failed — a strong "internet is down" signal that a
    single-target probe (blocked port, one-off drop) would over-report.
    """
    for tgt in targets:
        ms = _measure_tcp_latency(tgt, timeout=timeout)
        if ms is not None:
            return ms
    return None


def get_network_health() -> dict:
    """Reachability + DNS + adapter status for the dashboard concerns feed.

    All in-process (socket + psutil), no PowerShell. Bounded worst-case time:
    reachability probes (2 × 1.5 s) + DNS (1.5 s) ≈ 4.5 s only when the network
    is fully down; a healthy network returns in tens of ms.
    """
    ping_ms = _measure_reachability()
    dns_ms = _measure_dns_latency()
    adapters: list[dict] = []
    try:
        stats = psutil.net_if_stats()
    except Exception:  # noqa: BLE001 -- psutil can surface OS-specific surprises
        stats = {}
    for name, st in (stats or {}).items():
        if _is_loopback_adapter(name):
            continue
        adapters.append({"name": name, "up": bool(getattr(st, "isup", False))})
    return {
        "available": True,
        "internet_reachable": ping_ms is not None,
        "ping_latency_ms": ping_ms,
        "dns_working": dns_ms is not None,
        "dns_latency_ms": dns_ms,
        "adapters": adapters,
    }


def _net_concern(level: str, title: str, detail: str) -> dict:
    """Dashboard-concern dict for a network-health finding (network tab)."""
    return {
        "level": level,
        "tab": "network",
        "icon": "🌐",
        "title": title,
        "detail": detail,
        "action": "View Network Monitor",
        "action_fn": "switchTab('network')",
    }


def network_health_concerns(data: dict) -> list[dict]:
    """Map a get_network_health() reading into dashboard concern dicts.

    Mirrors SystemHealthDiag.check_network_health so the dashboard and the
    daily health report agree: internet-unreachable / DNS-failing / no-active-
    adapter are critical; high ping (>200 ms) and slow DNS (>500 ms) are
    warnings. Returns [] on a clean network.

    NOTE: the daily report also warns on a *specific* physical adapter being
    disconnected, using Get-NetAdapter's InterfaceDescription to skip virtual
    NICs. psutil only exposes interface NAMES (Windows lists many normally-down
    pseudo-adapters like "Local Area Connection* 11"), so a name-only filter
    false-alarms on a healthy box. We therefore surface only the unambiguous
    "every adapter is down" critical here and leave per-adapter disconnection
    to the Network tab, which has the richer data.
    """
    concerns: list[dict] = []
    adapters = data.get("adapters", [])
    up_adapters = [a for a in adapters if a.get("up")]

    if adapters and not up_adapters:
        concerns.append(
            _net_concern(
                "critical",
                "No active network adapter",
                "Every network adapter is down — this machine has no connectivity.",
            )
        )

    if not data.get("internet_reachable"):
        concerns.append(
            _net_concern(
                "critical",
                "Internet is unreachable",
                "Could not reach the internet (TCP probes to public hosts all failed). "
                "Check your router/modem — most apps will appear offline.",
            )
        )
    elif (data.get("ping_latency_ms") or 0) > _PING_WARN_MS:
        concerns.append(
            _net_concern(
                "warning",
                f"Internet latency is high ({data['ping_latency_ms']:.0f} ms)",
                "Connectivity is up but slow — video calls and downloads may suffer.",
            )
        )

    if not data.get("dns_working"):
        concerns.append(
            _net_concern(
                "critical",
                "DNS resolution is failing",
                "The internet may be reachable but hostnames can't resolve — most apps will appear offline.",
            )
        )
    elif (data.get("dns_latency_ms") or 0) > _DNS_WARN_MS:
        concerns.append(
            _net_concern(
                "warning",
                f"DNS resolution is slow ({data['dns_latency_ms']:.0f} ms)",
                "Name lookups are sluggish — pages may take a moment to start loading.",
            )
        )

    return concerns


def get_network_metrics() -> dict:
    """Sample lightweight network metrics for the Trends card (backlog #38).

    Fields:
        available                — always True (collector never errors
                                    fatally; individual fields degrade to
                                    None / 0 as noted)
        source                   — "psutil+socket"
        throughput_in_mbps       — Mbps averaged across all non-loopback
                                    NICs between the previous call and now.
                                    0 on the very first call (no baseline).
        throughput_out_mbps      — same, upload direction.
        latency_ms               — TCP-connect RTT to Cloudflare DNS; None
                                    on probe failure.
        connections_established  — count of ESTABLISHED TCP connections;
                                    None when psutil can't enumerate
                                    (AccessDenied without admin on some
                                    setups).
        latency_target           — "host:port" the probe hit, for display.
        error                    — None in the happy path; populated only
                                    if the counter read itself blew up.

    Thread safety: ``_net_samples_lock`` is held for the minimum window
    (copy prev, write new) so parallel dashboard_summary calls don't race
    on the rate calculation.
    """
    result = {
        "available": True,
        "source": "psutil+socket",
        "throughput_in_mbps": 0.0,
        "throughput_out_mbps": 0.0,
        "latency_ms": None,
        "latency_target": f"{_LATENCY_PROBE_TARGET[0]}:{_LATENCY_PROBE_TARGET[1]}",
        "connections_established": None,
        "error": None,
    }

    now = time.time()

    # ── Aggregate counters across all non-loopback NICs ──────────────
    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception as e:  # noqa: BLE001 -- psutil can surface OS-specific surprises
        result["error"] = f"net_io_counters failed: {type(e).__name__}: {e}"
        return result

    total_sent = 0
    total_recv = 0
    for name, c in (counters or {}).items():
        if _is_loopback_adapter(name):
            continue
        total_sent += c.bytes_sent
        total_recv += c.bytes_recv

    with _net_samples_lock:
        prev = _last_net_samples.get("total")
        _last_net_samples["total"] = (float(total_sent), float(total_recv), now)

    if prev is not None:
        prev_sent, prev_recv, prev_ts = prev
        dt = now - prev_ts
        # Guard dt>0 against clock skew / zero-interval rapid calls; guard
        # delta>=0 against counter rollover or NIC reset (which would
        # produce a negative delta -- treat as "no reliable rate" not a
        # negative Mbps).
        if dt > 0:
            d_sent = max(0.0, float(total_sent) - prev_sent)
            d_recv = max(0.0, float(total_recv) - prev_recv)
            # Mbps = bytes/s * 8 bits/byte / 1_000_000 bits/Mb
            result["throughput_out_mbps"] = round(d_sent * 8.0 / 1_000_000.0 / dt, 3)
            result["throughput_in_mbps"] = round(d_recv * 8.0 / 1_000_000.0 / dt, 3)

    # ── Latency probe (TCP connect to Cloudflare DNS) ─────────────────
    result["latency_ms"] = _measure_tcp_latency()

    # ── Active connection count ───────────────────────────────────────
    # psutil.net_connections(kind='tcp') can raise AccessDenied on some
    # configurations (non-admin user enumerating other users' sockets).
    # Fall back to kind='inet4' which is often more permissive; if that
    # also fails, leave the field None so the extractor skips it.
    try:
        conns = psutil.net_connections(kind="tcp")
        result["connections_established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
    except (psutil.AccessDenied, PermissionError):
        try:
            conns = psutil.net_connections(kind="inet4")
            result["connections_established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
        except Exception:  # noqa: BLE001
            result["connections_established"] = None
    except Exception:  # noqa: BLE001
        result["connections_established"] = None

    return result


def summarize_network(data: dict) -> dict:
    established = data.get("established", [])
    adapters = data.get("adapters", [])
    top_procs = data.get("top_processes", [])
    insights = []
    actions = []
    down_adapters = [a for a in adapters if a.get("Status", "").lower() not in ("up", "")]
    if down_adapters:
        insights.append(
            _insight(
                "warning",
                f"{len(down_adapters)} network adapter(s) are not active: "
                + ", ".join(a.get("Name", "?") for a in down_adapters),
            )
        )
    unusual_ports = [c for c in established if c.get("RemotePort") in (4444, 1337, 31337, 9001, 8888)]
    if unusual_ports:
        insights.append(
            _insight(
                "warning",
                f"{len(unusual_ports)} connection(s) on unusual ports — worth reviewing.",
                "Check the Active Connections table below. These may be legitimate (VPN, games, apps) or unexpected. Look at the remote address and process name to decide.",
            )
        )
        actions.append("Investigate flagged connections")
    if top_procs:
        top = top_procs[0]
        if top["connections"] > 20:
            insights.append(
                _insight(
                    "warning",
                    f"{top['process']} has {top['connections']} open connections — unusually high.",
                    "Check if this process is behaving normally.",
                )
            )
        else:
            insights.append(
                _insight("info", f"Top process by connections: {top['process']} ({top['connections']} connections).")
            )
    active_adapters = [a for a in adapters if a.get("Status", "").lower() == "up"]
    if active_adapters:
        insights.append(
            _insight(
                "ok",
                f"{len(active_adapters)} adapter(s) active. "
                f"{data.get('total_connections', 0)} established connection(s).",
            )
        )
    if not unusual_ports and not down_adapters:
        insights.append(_insight("ok", "No suspicious connections or adapter issues detected."))
    status = (
        "critical"
        if unusual_ports
        else "warning"
        if down_adapters or (top_procs and top_procs[0]["connections"] > 20)
        else "ok"
    )
    headline = (
        f"{len(unusual_ports)} suspicious connection(s) detected"
        if unusual_ports
        else f"{data.get('total_connections', 0)} active connections — nothing flagged"
    )
    return {"status": status, "headline": headline, "insights": insights, "actions": actions}
