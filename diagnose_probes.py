"""
diagnose_probes.py — Read-only probe registry + bounded parallel runner for
the Diagnose tab.

A probe is a small function that takes the diagnosis "slots" (e.g. the
target host the user typed) and returns a plain dict of evidence. Every
probe is registered here, in the module-level ``PROBES`` dict, and
``run_probes`` can only run keys found there.

Why a closed registry (spec §4): the diagnostic engine lets a model *ask*
for more evidence by key, so the set of things it can trigger must be a
fixed, reviewable list rather than anything it can name. An unknown key is
reported as an error, never resolved dynamically. Probes are read-only by
contract and none of them may appear in ``remediation._REMEDIATION_DISPATCH``.

``run_probes`` never raises: a probe that crashes, times out, returns the
wrong type or lacks a required slot becomes an ``ok: False`` result, so one
bad probe cannot sink the whole diagnosis.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import socket
import struct
import time
import winreg
from collections.abc import Callable, Sequence
from dataclasses import dataclass

# dnspython is a hard requirement (requirements.txt) but import-guarded so a
# broken install degrades the DNS probes to a clear error instead of taking
# the whole app down at import time.
try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver

    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover -- exercised by patching HAVE_DNSPYTHON
    dns = None  # type: ignore[assignment]
    HAVE_DNSPYTHON = False

_MAX_WORKERS = 8

# Public recursive resolvers used to cross-check the system resolver (name, ip).
PUBLIC_RESOLVERS = (("cloudflare", "1.1.1.1"), ("google", "8.8.8.8"))

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_BRACKETED_V6_RE = re.compile(r"^\[([^\]]+)\](?::\d+)?$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)


@dataclass(frozen=True)
class Probe:
    """One read-only evidence collector.

    ``fn`` receives the slots dict and returns only its ``data`` dict.
    ``needs`` names slots that must be non-empty or the probe is refused
    without being called. ``redact`` lists the PII classes ("mac",
    "serial", ...) the engine must scrub from this probe's data before it
    is sent anywhere. ``timeout_s`` bounds the probe's wall-clock time.
    """

    key: str
    label: str
    category: str
    fn: Callable[[dict], dict]
    needs: tuple[str, ...] = ()
    redact: tuple[str, ...] = ()
    timeout_s: float = 8.0


PROBES: dict[str, Probe] = {}


def register(probe: Probe) -> Probe:
    """Add ``probe`` to the registry and return it; duplicate keys are a bug."""
    if probe.key in PROBES:
        raise ValueError(f"probe already registered: {probe.key}")
    PROBES[probe.key] = probe
    return probe


def _elapsed_ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000.0, 1)


def _failure(key: str, label: str, error: str, elapsed_ms: float = 0.0) -> dict:
    return {"key": key, "label": label, "ok": False, "error": error, "elapsed_ms": elapsed_ms}


def _run_one(probe: Probe, slots: dict) -> dict:
    """Run a single probe in a worker thread and wrap its outcome."""
    t0 = time.perf_counter()
    try:
        data = probe.fn(slots)
    except Exception as exc:  # noqa: BLE001 -- a probe must never take the run down
        return _failure(probe.key, probe.label, f"{type(exc).__name__}: {exc}", _elapsed_ms(t0))
    if not isinstance(data, dict):
        return _failure(probe.key, probe.label, f"probe returned {type(data).__name__}, expected dict", _elapsed_ms(t0))
    return {"key": probe.key, "label": probe.label, "ok": True, "data": data, "elapsed_ms": _elapsed_ms(t0)}


def run_probes(keys: Sequence[str], slots: dict) -> list[dict]:
    """Run the named probes in parallel and return one result per key, in order.

    Result shape: ``{"key", "label", "ok": True, "data", "elapsed_ms"}`` on
    success, ``{"key", "label", "ok": False, "error", "elapsed_ms"}`` when the
    probe itself could not run (unknown key, missing slot, crash, timeout).
    """
    results: list[dict | None] = [None] * len(keys)
    runnable: list[tuple[int, Probe]] = []
    for i, key in enumerate(keys):
        probe = PROBES.get(key)
        if probe is None:
            results[i] = _failure(key, key, "unknown probe")
            continue
        missing = next((name for name in probe.needs if not slots.get(name)), None)
        if missing is not None:
            results[i] = _failure(key, probe.label, f"missing required slot: {missing}")
            continue
        runnable.append((i, probe))

    if runnable:
        # NOT a `with` block, for the same reason as network._measure_dns_latency:
        # __exit__ would shutdown(wait=True) and block on a hung resolver,
        # defeating the per-probe timeout. shutdown(wait=False) returns at once
        # and a stuck worker is reaped when its OS call eventually returns.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(runnable)))
        try:
            t0 = time.perf_counter()
            futures = [(i, probe, ex.submit(_run_one, probe, slots)) for i, probe in runnable]
            for i, probe, fut in futures:
                remaining = max(0.0, probe.timeout_s - (time.perf_counter() - t0))
                try:
                    results[i] = fut.result(timeout=remaining)
                except concurrent.futures.TimeoutError:
                    results[i] = _failure(
                        probe.key, probe.label, f"timed out after {probe.timeout_s}s", _elapsed_ms(t0)
                    )
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    return [r for r in results if r is not None]


def normalize_host(raw: str) -> str | None:
    """Reduce what the user typed to a bare lowercase ASCII hostname or IP literal.

    Accepts a URL, ``host:port``, a trailing dot, a trailing possessive
    ("hynote.ai's") and IDN names (returned as punycode). Returns ``None``
    for anything that is not a plausible FQDN or IP, which also keeps shell
    metacharacters and spaces away from the ``ping``/``tracert`` probes.
    """
    if not isinstance(raw, str):
        return None
    h = _SCHEME_RE.sub("", raw.strip())
    for sep in "/?#":
        h = h.split(sep, 1)[0]
    bracketed = _BRACKETED_V6_RE.match(h)
    if bracketed:
        h = bracketed.group(1)
    elif h.count(":") == 1:  # host:port; two or more colons is a bare IPv6 literal
        h = h.split(":", 1)[0]
    for possessive in ("’s", "'s"):
        if h.endswith(possessive):
            h = h[: -len(possessive)]
    h = h.rstrip(".")
    if not h:
        return None
    if "%" in h:  # IPv6 scope id ("fe80::1%eth0") is link-local and not a valid target
        return None
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    # fullmatch, not match + "$": "$" also matches before a trailing newline.
    return h if _HOSTNAME_RE.fullmatch(h) else None


def _dns_result(server: str, rcode: str, *, answers: list[str] | None = None, aa=False, ad=False, error=None) -> dict:
    answers = answers or []
    return {
        "server": server,
        "rcode": rcode,
        "nodata": rcode == "NOERROR" and not answers,
        "answers": answers,
        "aa": aa,
        "ad": ad,
        "error": error,
    }


def _dns_query(
    server: str,
    name: str,
    rdtype: str,
    *,
    timeout: float = 3.0,
    want_dnssec: bool = False,
    cd: bool = False,
) -> dict:
    """Ask ``server`` directly for ``name``/``rdtype`` and summarise the reply.

    Returns ``{server, rcode, nodata, answers, aa, ad, error}``. ``rcode`` is
    the response code text, or ``"TIMEOUT"`` / ``"ERROR"`` when no usable
    reply arrived. Never raises: any failure becomes an ``ERROR`` result.
    """
    if not HAVE_DNSPYTHON:
        return _dns_result(server, "ERROR", error="dnspython not installed")
    try:
        q = dns.message.make_query(name, rdtype, want_dnssec=want_dnssec)
        if cd:
            q.flags |= dns.flags.CD
        r = dns.query.udp(q, server, timeout=timeout)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, server, timeout=timeout)
        want = dns.rdatatype.from_text(rdtype)
        answers = [rd.to_text() for rrset in r.answer if rrset.rdtype == want for rd in rrset]
        return _dns_result(
            server,
            dns.rcode.to_text(r.rcode()),
            answers=answers,
            aa=bool(r.flags & dns.flags.AA),
            ad=bool(r.flags & dns.flags.AD),
        )
    except dns.exception.Timeout:
        return _dns_result(server, "TIMEOUT")
    except Exception as exc:  # noqa: BLE001 -- a probe helper must never raise
        return _dns_result(server, "ERROR", error=str(exc))


def _system_nameservers() -> list[str]:
    """The nameservers the OS is configured with, or ``[]`` if unavailable."""
    if not HAVE_DNSPYTHON:
        return []
    try:
        return list(dns.resolver.Resolver().nameservers)
    except Exception:  # noqa: BLE001 -- no resolver config is a normal condition
        return []


# ── Wave-one resolution probes ───────────────────────────────────────────────
# Each returns only its ``data`` dict (see the evidence-shapes contract). A
# failed lookup is a normal ``ok`` result describing the failure; the runner
# reserves ``ok: False`` for a probe that could not run at all.

_SWEEP_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SOA", "NS")


def _first_system_or_cloudflare() -> str:
    """The first configured system nameserver, else Cloudflare."""
    ns = _system_nameservers()
    return ns[0] if ns else PUBLIC_RESOLVERS[0][1]


def _p_resolve_cached(slots: dict) -> dict:
    """Resolve through the Windows resolver, so the OS DNS cache is in play."""
    host = slots["target_host"]
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:  # socket.gaierror is an OSError
        return {"resolved": False, "addresses": [], "error": str(exc)}
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return {"resolved": False, "addresses": [], "error": "no addresses returned"}
    return {"resolved": True, "addresses": addresses, "error": None}


def _p_resolve_direct(slots: dict) -> dict:
    """Ask the system, Cloudflare and Google resolvers for A records directly."""
    if not HAVE_DNSPYTHON:
        return {"dnspython": False, "resolvers": []}
    host = slots["target_host"]
    targets: list[tuple[str, str]] = []
    system = _system_nameservers()
    if system:
        targets.append(("system", system[0]))
    targets.extend(PUBLIC_RESOLVERS)
    resolvers = []
    for name, server in targets:
        r = _dns_query(server, host, "A")
        resolvers.append(
            {
                "name": name,
                "server": r["server"],
                "rcode": r["rcode"],
                "nodata": r["nodata"],
                "answers": r["answers"],
            }
        )
    return {"dnspython": True, "resolvers": resolvers}


def _p_authoritative(slots: dict) -> dict:
    """Ask up to two of the domain's own nameservers for the A record."""
    if not HAVE_DNSPYTHON:
        return {"zone": None, "nameservers": []}
    host = slots["target_host"]
    try:
        zone = dns.resolver.zone_for_name(host).to_text().rstrip(".")
    except Exception:  # noqa: BLE001 -- no resolvable zone is a normal outcome
        return {"zone": None, "nameservers": []}
    via = _first_system_or_cloudflare()
    ns_names = [a.rstrip(".") for a in _dns_query(via, zone, "NS")["answers"]][:2]
    nameservers = []
    for ns_name in ns_names:
        ip_answers = _dns_query(via, ns_name, "A")["answers"]
        if not ip_answers:
            continue
        ns_ip = ip_answers[0]
        r = _dns_query(ns_ip, host, "A")
        nameservers.append(
            {
                "name": ns_name,
                "ip": ns_ip,
                "rcode": r["rcode"],
                "nodata": r["nodata"],
                "aa": r["aa"],
                "answers": r["answers"],
            }
        )
    return {"zone": zone, "nameservers": nameservers}


def _p_record_sweep(slots: dict) -> dict:
    """Fetch A/AAAA/CNAME/MX/TXT/SOA/NS so a missing record type stands out."""
    if not HAVE_DNSPYTHON:
        return {"records": {t: [] for t in _SWEEP_TYPES}, "rcode": "ERROR"}
    host = slots["target_host"]
    via = _first_system_or_cloudflare()
    records: dict[str, list[str]] = {}
    rcode = "ERROR"
    for rdtype in _SWEEP_TYPES:
        r = _dns_query(via, host, rdtype)
        records[rdtype] = r["answers"]
        if rdtype == "A":
            rcode = r["rcode"]
    return {"records": records, "rcode": rcode}


# ── Local configuration probes (hosts file, DNS client, proxy) ───────────────
# These read Windows configuration directly (no PowerShell). All registry
# access goes through _reg_values / _reg_subkeys so tests can patch them.

HOSTS_PATH = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "drivers", "etc", "hosts")

_TCPIP_PARAMS = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
_TCPIP_IFACES = _TCPIP_PARAMS + r"\Interfaces"
_DNSCACHE_PARAMS = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
_INET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INET_CONNECTIONS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"

_WINHTTP_PROXY_FLAG = 0x2  # flags bit set when a named proxy is configured


def _reg_values(hive: int, path: str) -> dict[str, object]:
    """All values of one registry key as ``{name: data}``; ``{}`` if the key is missing."""
    values: dict[str, object] = {}
    try:
        with winreg.OpenKey(hive, path) as key:
            index = 0
            while True:
                try:
                    name, data, _type = winreg.EnumValue(key, index)
                except OSError:  # ERROR_NO_MORE_ITEMS ends the enumeration
                    break
                values[name] = data
                index += 1
    except OSError:
        return {}
    return values


def _reg_subkeys(hive: int, path: str) -> list[str]:
    """Names of a registry key's subkeys; ``[]`` if the key is missing."""
    names: list[str] = []
    try:
        with winreg.OpenKey(hive, path) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:  # ERROR_NO_MORE_ITEMS ends the enumeration
                    break
                index += 1
    except OSError:
        return []
    return names


def _split_list(value: object) -> list[str]:
    """Split a registry list value (REG_SZ "a,b c" or REG_MULTI_SZ list) into items."""
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    if not isinstance(value, str):
        return []
    return [item for item in re.split(r"[,\s]+", value) if item]


def _p_hosts_file(slots: dict) -> dict:
    """Report hosts-file lines that name the target host (a classic silent override)."""
    target = slots["target_host"].lower().rstrip(".")
    matches: list[dict] = []
    try:
        with open(HOSTS_PATH, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {"path": HOSTS_PATH, "readable": False, "matches": []}
    for line_no, line in enumerate(lines, start=1):
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        names = [n.lower() for n in fields[1:]]
        if target in (n.rstrip(".") for n in names):
            matches.append({"line_no": line_no, "ip": fields[0], "names": names})
    return {"path": HOSTS_PATH, "readable": True, "matches": matches}


def _p_client_config(slots: dict) -> dict:
    """Per-adapter DNS servers, the DNS suffix search list and the DoH policy."""
    hklm = winreg.HKEY_LOCAL_MACHINE
    adapters = []
    for guid in _reg_subkeys(hklm, _TCPIP_IFACES):
        vals = _reg_values(hklm, f"{_TCPIP_IFACES}\\{guid}")
        # A statically configured server list overrides the DHCP-assigned one.
        servers = _split_list(vals.get("NameServer")) or _split_list(vals.get("DhcpNameServer"))
        if servers:
            adapters.append({"guid": guid, "dns_servers": servers})
    return {
        "adapters": adapters,
        "search_list": _split_list(_reg_values(hklm, _TCPIP_PARAMS).get("SearchList")),
        "enable_auto_doh": _reg_values(hklm, _DNSCACHE_PARAMS).get("EnableAutoDoh"),
    }


def _parse_winhttp_blob(blob: bytes) -> dict:
    """Decode the ``WinHttpSettings`` registry blob (little-endian uint32 header).

    Layout: size/version, counter, flags, proxy length N, N proxy bytes, bypass
    length M, M bypass bytes. Flag bit 0x2 means a named proxy is in use.
    Returns ``{direct, proxy_server, bypass}`` or ``{parse_error}``.
    """
    try:
        if len(blob) < 16:
            raise ValueError("blob shorter than the 16-byte header")
        _size, _counter, flags, proxy_len = struct.unpack_from("<IIII", blob, 0)
        pos = 16
        if len(blob) < pos + proxy_len + 4:
            raise ValueError("blob truncated in the proxy field")
        proxy = blob[pos : pos + proxy_len].decode("ascii")
        pos += proxy_len
        (bypass_len,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        if len(blob) < pos + bypass_len:
            raise ValueError("blob truncated in the bypass field")
        bypass = blob[pos : pos + bypass_len].decode("ascii")
    except (ValueError, struct.error) as exc:  # UnicodeDecodeError is a ValueError
        return {"parse_error": str(exc)}
    return {"direct": not (flags & _WINHTTP_PROXY_FLAG), "proxy_server": proxy, "bypass": bypass}


def _env_proxy(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value is not None else os.environ.get(name.lower())


def _p_proxy_config(slots: dict) -> dict:
    """WinINET (per-user), WinHTTP (machine) and environment proxy settings."""
    inet = _reg_values(winreg.HKEY_CURRENT_USER, _INET_SETTINGS)
    blob = _reg_values(winreg.HKEY_LOCAL_MACHINE, _INET_CONNECTIONS).get("WinHttpSettings")
    return {
        "wininet": {
            "proxy_enable": inet.get("ProxyEnable"),
            "proxy_server": inet.get("ProxyServer"),
            "proxy_override": inet.get("ProxyOverride"),
            "auto_config_url": inet.get("AutoConfigURL"),
            "auto_detect": inet.get("AutoDetect"),
        },
        "winhttp": _parse_winhttp_blob(blob) if isinstance(blob, bytes) else {},
        "env": {name: _env_proxy(name) for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")},
    }


for _key, _label, _fn, _timeout in (
    ("dns.resolve_cached", "Resolve through Windows (uses the DNS cache)", _p_resolve_cached, 8),
    ("dns.resolve_direct", "Ask DNS servers directly (bypasses the cache)", _p_resolve_direct, 8),
    ("dns.authoritative", "Ask the domain's own nameservers", _p_authoritative, 12),
    ("dns.record_sweep", "List every DNS record type for the name", _p_record_sweep, 10),
):
    register(
        Probe(
            key=_key,
            label=_label,
            category="network",
            fn=_fn,
            needs=("target_host",),
            redact=("username",),
            timeout_s=_timeout,
        )
    )

register(
    Probe(
        key="dns.hosts_file",
        label="Check the hosts file",
        category="network",
        fn=_p_hosts_file,
        needs=("target_host",),
        redact=("username",),
    )
)
register(
    Probe(
        key="dns.client_config",
        label="This PC's DNS settings",
        category="network",
        fn=_p_client_config,
        redact=("username", "mac"),
    )
)
register(
    Probe(
        key="net.proxy_config",
        label="Proxy settings",
        category="network",
        fn=_p_proxy_config,
        redact=("username",),
    )
)
