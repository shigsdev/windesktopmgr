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
import re
import time
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
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return h if _HOSTNAME_RE.match(h) else None


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
