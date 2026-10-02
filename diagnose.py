"""
diagnose.py — Diagnostic engine for the Diagnose tab.

The user describes a problem in plain words ("hynote.ai won't load") or pastes
a browser error. The engine turns that into a short, evidence-backed
explanation of where the fault lies, and points at existing remediation
actions without ever running one itself.

The flow (spec §3): a deterministic classifier picks a symptom class and pulls
out the slots its probes need (e.g. the target host); the read-only probes
registered in ``diagnose_probes`` collect evidence in parallel; the evidence
is redacted and shown to the user before anything is sent off-machine; and the
engine reads it back into a verdict. A missing required slot is reported as a
question for the user, never filled with a guess.

Probes are called through ``import diagnose_probes as dp`` (``dp.run_probes``,
``dp.PROBES``, ``dp.normalize_host``) so tests can patch them in one place.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
from collections.abc import Iterable
from typing import Any

import diagnose_probes as dp
import remediation

# Extra evidence-gathering rounds the engine may run after the first wave.
MAX_ROUNDS = 2

# What the engine can diagnose. ``wave1`` runs for every diagnosis of the
# class; ``escalate`` holds the deeper probes a follow-up round may request.
# Every key must exist in ``dp.PROBES`` and every probe's ``needs`` must be one
# of the class's ``slots`` (both enforced by the registry invariant tests).
SYMPTOM_CLASSES = {
    "network_dns": {
        "label": "Website or network unreachable",
        "slots": ("target_host",),
        "wave1": (
            "dns.resolve_cached",
            "dns.resolve_direct",
            "dns.authoritative",
            "dns.record_sweep",
            "dns.hosts_file",
            "dns.client_config",
            "net.control_domain",
            "net.gateway",
            "net.proxy_config",
        ),
        "escalate": (
            "dns.trace_delegation",
            "dns.dnssec_check",
            "net.tcp_connect",
            "net.tls_handshake",
            "net.traceroute",
        ),
    },
}

# Matched case-insensitively as substrings of the raw symptom text.
_NETWORK_KEYWORDS = (
    "err_name_not_resolved",
    "dns_probe_finished_",
    "err_connection_",
    "err_timed_out",
    "err_address_unreachable",
    "err_internet_disconnected",
    "can't be reached",
    "can’t be reached",
    "won't load",
    "not loading",
    "dns",
    "website",
    "site",
    "internet",
    "network",
    "unreachable",
)

# Last labels that look like TLDs but are far more likely file names in a
# pasted error ("error in app.js"). A real site on one of these is not lost:
# the user is asked for the host instead of the engine guessing.
_FILE_EXTENSIONS = frozenset(
    {
        "js",
        "json",
        "py",
        "exe",
        "dll",
        "txt",
        "log",
        "html",
        "css",
        "png",
        "jpg",
        "md",
        "ps1",
        "bat",
        "cfg",
        "ini",
        "xml",
    }
)

_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
# IPv4 literal, or a dotted name ending in a 2-63 letter label; each may carry a possessive.
_BARE_RE = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3}(?![\w-])|[\w.-]+\.[A-Za-z]{2,63})(?:’s|'s)?")
_URL_TRAILING_PUNCT = ".,;:!?)]}>\"'"


def _extract_candidates(symptom: str) -> list[str]:
    """Hosts and IPs mentioned in ``symptom``: URLs first, then bare tokens.

    Deduplicated in first-seen order, so a URL's host and the same host
    written bare count once. File-name lookalikes are dropped.
    """
    found: list[str | None] = [dp.normalize_host(u.rstrip(_URL_TRAILING_PUNCT)) for u in _URL_RE.findall(symptom)]
    # URLs are blanked out first so a path like /index.php is not read as a host.
    found += [dp.normalize_host(t) for t in _BARE_RE.findall(_URL_RE.sub(" ", symptom))]
    candidates: list[str] = []
    for host in found:
        if host is None or host in candidates:
            continue
        if host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        candidates.append(host)
    return candidates


def classify(symptom: str) -> dict:
    """Pick a symptom class and extract its slots from the user's text.

    Returns ``{"symptom_class", "slots", "candidates", "missing"}``.
    ``symptom_class`` is ``None`` when nothing matched. ``slots`` is filled
    only when the text names exactly one host; with none or several the
    required slot is listed in ``missing`` so the UI asks the user rather than
    the engine guessing.
    """
    text = symptom if isinstance(symptom, str) else ""
    candidates = _extract_candidates(text)
    lowered = text.lower()
    if not (candidates or any(k in lowered for k in _NETWORK_KEYWORDS)):
        return {"symptom_class": None, "slots": {}, "candidates": [], "missing": []}
    if len(candidates) == 1:
        return {
            "symptom_class": "network_dns",
            "slots": {"target_host": candidates[0]},
            "candidates": candidates,
            "missing": [],
        }
    return {"symptom_class": "network_dns", "slots": {}, "candidates": candidates, "missing": ["target_host"]}


# ---------------------------------------------------------------------------
# Deterministic rules (spec §9). Evidence-only answers the model can build on
# and, when confident, cannot override. A probe that is missing from the
# evidence or came back ``ok: False`` is "no evidence": rules reading it do
# not fire, and nothing here raises on absent keys or fields.
# ---------------------------------------------------------------------------

_NO_LOCAL_FIX_NODATA = (
    "The domain's own nameservers answer for it but have no A/AAAA/CNAME record. "
    "Only whoever manages the domain's DNS can fix that; nothing on this PC can."
)
_NO_LOCAL_FIX_NXDOMAIN = "The domain's own nameservers say this name does not exist."
_SWEEP_TYPES = ("MX", "TXT", "SOA", "NS")
_ADDRESS_TYPES = ("A", "AAAA", "CNAME")


def _data(evidence: dict, key: str) -> dict | None:
    """The ``data`` dict of probe ``key``, or None when it is absent or failed."""
    result = evidence.get(key) if isinstance(evidence, dict) else None
    if not isinstance(result, dict) or result.get("ok") is not True:
        return None
    data = result.get("data")
    return data if isinstance(data, dict) else None


def _resolvers(evidence: dict) -> list[dict]:
    direct = _data(evidence, "dns.resolve_direct") or {}
    return [r for r in direct.get("resolvers") or [] if isinstance(r, dict)]


def _direct_view(evidence: dict) -> tuple[bool, set[str]]:
    """``(definitive, addresses)`` from the direct resolvers (R13).

    NOERROR with answers contributes its addresses; NXDOMAIN, or NOERROR with
    ``nodata``, is a definitive "no address". TIMEOUT/ERROR/SERVFAIL/REFUSED
    are ignored. ``definitive`` is False when no resolver gave a usable answer.
    """
    addresses: set[str] = set()
    definitive = False
    for r in _resolvers(evidence):
        answers = r.get("answers") or []
        rcode = r.get("rcode")
        if rcode == "NOERROR" and answers:
            definitive = True
            addresses.update(answers)
        elif rcode == "NXDOMAIN" or (rcode == "NOERROR" and r.get("nodata") is True):
            definitive = True
    return definitive, addresses


def _authoritative_view(evidence: dict) -> tuple[list[dict], bool]:
    """``(no_address_servers, any_answers)`` over the authoritative (aa) servers.

    ``no_address_servers`` are aa nameservers saying NXDOMAIN or nodata;
    ``any_answers`` is True when some aa nameserver returned an address.
    """
    authoritative = _data(evidence, "dns.authoritative") or {}
    aa = [ns for ns in authoritative.get("nameservers") or [] if isinstance(ns, dict) and ns.get("aa") is True]
    none = [ns for ns in aa if not ns.get("answers") and (ns.get("rcode") == "NXDOMAIN" or ns.get("nodata") is True)]
    return none, any(ns.get("answers") for ns in aa)


def cache_agrees(evidence: dict[str, dict]) -> bool | None:
    """Whether the Windows resolver cache and the live resolvers agree.

    Only definitive direct answers count (R13): NOERROR with answers means
    resolved; NXDOMAIN, or NOERROR with ``nodata``, means not resolved.
    TIMEOUT/ERROR/SERVFAIL/REFUSED are ignored, so a blocked UDP/53 cannot
    make a working cache look stale. None when the cached probe is
    missing/failed or no resolver gave a definitive answer. Otherwise True iff
    both sides agree on resolved-ness and, when both resolved, their address
    sets intersect.
    """
    cached = _data(evidence, "dns.resolve_cached")
    definitive, direct_addrs = _direct_view(evidence)
    if cached is None or not definitive:
        return None
    cached_resolved = cached.get("resolved") is True
    if cached_resolved != bool(direct_addrs):
        return False
    if not cached_resolved:
        return True
    return bool(direct_addrs & set(cached.get("addresses") or []))


def _verdict(status: str, locus: str, headline: str, reasoning: str, **extra) -> dict:
    verdict = {
        "status": status,
        "locus": locus,
        "headline": headline,
        "reasoning": reasoning,
        "evidence_refs": [],
        "suggested_actions": [],
        "no_local_fix_reason": "",
        "source": "rules",
        "rule_hits": [],
    }
    verdict.update(extra)
    return verdict


def _rule_hosts_override(evidence: dict, host: str) -> dict | None:
    hosts = _data(evidence, "dns.hosts_file") or {}
    matches = [m for m in hosts.get("matches") or [] if isinstance(m, dict)]
    if not matches:
        return None
    first = matches[0]
    line, ip = first.get("line_no"), first.get("ip")
    return _verdict(
        "confident",
        "local",
        f"hosts file line {line} sends {host} to {ip}",
        f"The hosts file on this PC (line {line}) maps {host} to {ip}, which overrides DNS. "
        "Remove or fix that line to restore normal lookups.",
        evidence_refs=["dns.hosts_file"],
        rule_hits=["hosts_override"],
    )


def _rule_external_no_address(evidence: dict, host: str) -> dict | None:
    cached = _data(evidence, "dns.resolve_cached")
    if cached is None or cached.get("resolved") is not False:
        return None
    resolvers = _resolvers(evidence)
    if len(resolvers) < 2 or not all(r.get("rcode") == "NXDOMAIN" or r.get("nodata") is True for r in resolvers):
        return None
    answering, any_answers = _authoritative_view(evidence)
    if not answering or any_answers:
        return None
    sweep = _data(evidence, "dns.record_sweep")
    records = (sweep or {}).get("records") or {}
    # external_cause hides every fix, so any contrary address evidence vetoes it.
    if any(records.get(t) for t in _ADDRESS_TYPES):
        return None
    refs = ["dns.resolve_cached", "dns.resolve_direct", "dns.authoritative"]
    if any(ns.get("rcode") == "NXDOMAIN" for ns in answering):
        return _verdict(
            "confident",
            "external_cause",
            f"{host} does not exist",
            f"This PC's lookup fails, public resolvers agree, and the domain's own nameservers say {host} "
            "does not exist.",
            evidence_refs=refs,
            no_local_fix_reason=_NO_LOCAL_FIX_NXDOMAIN,
            rule_hits=["external_no_address"],
        )
    if sweep is not None:
        refs.append("dns.record_sweep")
    if any(records.get(t) for t in _SWEEP_TYPES):
        return _verdict(
            "confident",
            "external_cause",
            f"{host} exists but publishes no web address",
            f"This PC's lookup fails, public resolvers agree, and the domain's own nameservers answer for {host} "
            "with no address record, although it publishes other records such as mail or text records.",
            evidence_refs=refs,
            no_local_fix_reason=_NO_LOCAL_FIX_NODATA,
            rule_hits=["external_no_address"],
        )
    return _verdict(
        "confident",
        "external_cause",
        f"{host} has no web address record",
        f"This PC's lookup fails, public resolvers agree, and the domain's own nameservers have no address "
        f"record for {host}.",
        evidence_refs=refs,
        no_local_fix_reason=_NO_LOCAL_FIX_NODATA,
        rule_hits=["external_no_address"],
    )


def _rule_stale_cache(evidence: dict, host: str) -> dict | None:
    """The PC's cache disagrees with live DNS; the wording depends on which side resolves."""
    if cache_agrees(evidence) is not False:
        return None
    cached = _data(evidence, "dns.resolve_cached") or {}
    _, live_addrs = _direct_view(evidence)
    refs = ["dns.resolve_cached", "dns.resolve_direct"]
    if live_addrs and cached.get("resolved") is not True:
        return _verdict(
            "confident",
            "local",
            f"This PC's DNS cache disagrees with live DNS for {host}",
            f"Live resolvers resolve {host} but the Windows DNS cache on this PC does not return a matching "
            "answer, so the cached entry is stale. Flushing the DNS cache should clear it.",
            evidence_refs=refs,
            suggested_actions=["flush_dns"],
            rule_hits=["stale_cache"],
        )
    if live_addrs:
        return _verdict(
            "confident",
            "local",
            f"This PC's DNS cache returns a different address for {host} than live DNS",
            f"The Windows DNS cache on this PC and the live resolvers return different addresses for {host}, "
            "so the cached entry is stale. Flushing the DNS cache should clear it.",
            evidence_refs=refs,
            suggested_actions=["flush_dns"],
            rule_hits=["stale_cache"],
        )
    # The cache resolves but live DNS definitively says there is no address.
    none_answering, any_answers = _authoritative_view(evidence)
    if none_answering and not any_answers:
        return _verdict(
            "likely",
            "external_cause",
            f"{host} no longer has a web address at its DNS provider",
            f"This PC's DNS cache still holds an address for {host}, but live resolvers and the domain's own "
            "nameservers no longer return one.",
            evidence_refs=[*refs, "dns.authoritative"],
            no_local_fix_reason=(
                "The domain's own nameservers no longer publish an address for it; this PC is only "
                "holding an old cached copy. Only whoever manages the domain's DNS can restore it."
            ),
            rule_hits=["stale_cache_external"],
        )
    return _verdict(
        "likely",
        "local",
        f"This PC's DNS cache holds an address for {host} that live DNS no longer returns",
        f"This PC's DNS cache still holds an address for {host} that the live DNS servers no longer return.",
        evidence_refs=refs,
        suggested_actions=["flush_dns"],
        rule_hits=["stale_cache"],
    )


def _rule_dead_gateway(evidence: dict, host: str) -> dict | None:
    gateway = _data(evidence, "net.gateway") or {}
    control = _data(evidence, "net.control_domain") or {}
    if gateway.get("reachable") is not False or control.get("connected") is not False:
        return None
    return _verdict(
        "likely",
        "local",
        "The default gateway is not responding",
        "The router (default gateway) does not answer a ping and a known-good control site cannot be "
        f"reached, so {host} is unreachable because this PC has lost its network path.",
        evidence_refs=["net.gateway", "net.control_domain"],
        suggested_actions=["reset_network_adapter"],
        rule_hits=["dead_gateway"],
    )


# First match wins (spec §9). Each rule names itself in the verdict's rule_hits.
_RULES = (_rule_hosts_override, _rule_external_no_address, _rule_stale_cache, _rule_dead_gateway)


def evaluate_rules(evidence: dict[str, dict], target_host: str) -> dict:
    """Evidence-only verdict for the network_dns class; always a full verdict.

    Runs the rules in order and returns the first that fires. ``rule_hits``
    names that rule, plus ``"cache_agrees"`` whenever the cache and the live
    resolvers agree, whichever rule fired.
    """
    host = target_host or "this host"
    verdict = next((v for v in (rule(evidence, host) for rule in _RULES) if v is not None), None)
    if verdict is None:
        verdict = _verdict(
            "inconclusive",
            "unknown",
            "No rule matched this evidence",
            "None of the built-in checks found a clear cause in the evidence collected.",
        )
    if cache_agrees(evidence) is True:
        verdict["rule_hits"].append("cache_agrees")
    return verdict


# ---------------------------------------------------------------------------
# Redaction and the egress payload (spec §7). ``build_payload`` returns the
# exact string the user previews and the exact string later sent to the model,
# so redaction must be deterministic and must run on everything in it.
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)")
_SERIAL_KEY_RE = re.compile(r"serial", re.IGNORECASE)
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
# Placeholders are matched too so a second pass leaves them alone (a user
# named "mac" must not turn "<mac>" into "<<user>>").
_PLACEHOLDER = r"<(?:user|mac|serial|private-ip)>"


def _redact_private_ip(match: re.Match) -> str:
    """Replace an RFC1918 IPv4 token with ``<private-ip>``; leave any other as is."""
    token = match.group(0)
    octets = [int(part) for part in token.split(".")]
    if any(o > 255 for o in octets):
        return token
    addr = ipaddress.IPv4Address(bytes(octets))
    return "<private-ip>" if any(addr in net for net in _PRIVATE_NETS) else token


def _username_pattern() -> re.Pattern | None:
    """Pattern for the current Windows user name, read at call time (None if unset)."""
    name = os.environ.get("USERNAME", "").strip()
    if not name:
        return None
    return re.compile(rf"({_PLACEHOLDER})|(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.IGNORECASE)


def _redact_string(text: str, classes: frozenset[str], user_re: re.Pattern | None) -> str:
    if user_re is not None:
        text = user_re.sub(lambda m: m.group(1) or "<user>", text)
    if "mac" in classes:
        text = _MAC_RE.sub("<mac>", text)
    if "local_ip" in classes:
        text = _IPV4_RE.sub(_redact_private_ip, text)
    return text


def _redact_walk(obj: Any, classes: frozenset[str], user_re: re.Pattern | None) -> Any:
    if isinstance(obj, str):
        return _redact_string(obj, classes, user_re)
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if "serial" in classes and isinstance(key, str) and _SERIAL_KEY_RE.search(key):
                value = "<serial>"
            else:
                value = _redact_walk(value, classes, user_re)
            out[_redact_string(key, classes, user_re) if isinstance(key, str) else key] = value
        return out
    if isinstance(obj, list):
        return [_redact_walk(v, classes, user_re) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_walk(v, classes, user_re) for v in obj)
    return copy.deepcopy(obj)


def redact(obj: Any, classes: Iterable[str]) -> Any:
    """Deep copy of ``obj`` with the named PII ``classes`` scrubbed from every string.

    ``username``: the Windows user name, whole-word and case-insensitive, so
    "local alpha" survives a user called Al. ``mac``: MAC addresses with ``:``
    or ``-`` separators. ``serial``: the whole value of any dict key containing
    "serial". ``local_ip``: RFC1918 IPv4 addresses. Dict keys are scrubbed
    like values; unknown classes are ignored; non-string scalars pass through.
    The input is never mutated.
    """
    wanted = frozenset(classes)
    user_re = _username_pattern() if "username" in wanted else None
    return _redact_walk(obj, wanted, user_re)


def build_payload(session: dict) -> str:
    """The exact JSON text previewed to the user and then sent to the model.

    Each evidence entry is redacted by its probe's own classes; ``username``
    is then applied to the whole object, symptom included.
    """
    evidence = []
    for item in session.get("evidence") or []:
        probe = dp.PROBES.get(item.get("key")) if isinstance(item, dict) else None
        evidence.append(redact(item, probe.redact if probe else ()))
    seen = {item.get("key") for item in evidence if isinstance(item, dict)}
    escalate = SYMPTOM_CLASSES.get(session.get("symptom_class"), {}).get("escalate", ())
    verdict = session.get("rule_verdict") or {}
    rnd = session.get("round", 0)
    payload = {
        "schema_version": 1,
        "symptom": session.get("symptom", ""),
        "symptom_class": session.get("symptom_class"),
        "slots": dict(session.get("slots") or {}),
        "round": rnd,
        "rounds_remaining": MAX_ROUNDS - rnd,
        "capabilities": {"dnspython": dp.HAVE_DNSPYTHON},
        "evidence": evidence,
        "rule_finding": {
            "status": verdict.get("status"),
            "locus": verdict.get("locus"),
            "headline": verdict.get("headline"),
            "rule_hits": list(verdict.get("rule_hits") or []),
        },
        "available_probes": [{"key": k, "label": dp.PROBES[k].label} for k in escalate if k not in seen],
        "available_actions": [
            {"key": k, "label": v["label"], "description": v["description"]}
            for k, v in sorted(remediation.REMEDIATION_REGISTRY.items())
        ],
    }
    return json.dumps(redact(payload, ["username"]), indent=2, sort_keys=True, ensure_ascii=False)
