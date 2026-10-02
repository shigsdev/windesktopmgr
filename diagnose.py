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

import re

import diagnose_probes as dp

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
    if cached is None:
        return None
    direct_addrs: set[str] = set()
    definitive = False
    for r in _resolvers(evidence):
        answers = r.get("answers") or []
        rcode = r.get("rcode")
        if rcode == "NOERROR" and answers:
            definitive = True
            direct_addrs.update(answers)
        elif rcode == "NXDOMAIN" or (rcode == "NOERROR" and r.get("nodata") is True):
            definitive = True
    if not definitive:
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
    )


def _rule_external_no_address(evidence: dict, host: str) -> dict | None:
    cached = _data(evidence, "dns.resolve_cached")
    if cached is None or cached.get("resolved") is not False:
        return None
    resolvers = _resolvers(evidence)
    if len(resolvers) < 2 or not all(r.get("rcode") == "NXDOMAIN" or r.get("nodata") is True for r in resolvers):
        return None
    authoritative = _data(evidence, "dns.authoritative") or {}
    answering = [
        ns
        for ns in authoritative.get("nameservers") or []
        if isinstance(ns, dict) and ns.get("aa") is True and (ns.get("rcode") == "NXDOMAIN" or ns.get("nodata") is True)
    ]
    if not answering:
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
        )
    sweep = _data(evidence, "dns.record_sweep")
    if sweep is not None:
        refs.append("dns.record_sweep")
    records = (sweep or {}).get("records") or {}
    if any(records.get(t) for t in _SWEEP_TYPES):
        return _verdict(
            "confident",
            "external_cause",
            f"{host} exists but publishes no web address",
            f"This PC's lookup fails, public resolvers agree, and the domain's own nameservers answer for {host} "
            "with no address record, although it publishes other records such as mail or text records.",
            evidence_refs=refs,
            no_local_fix_reason=_NO_LOCAL_FIX_NODATA,
        )
    return _verdict(
        "confident",
        "external_cause",
        f"{host} has no web address record",
        f"This PC's lookup fails, public resolvers agree, and the domain's own nameservers have no address "
        f"record for {host}.",
        evidence_refs=refs,
        no_local_fix_reason=_NO_LOCAL_FIX_NODATA,
    )


def _rule_stale_cache(evidence: dict, host: str) -> dict | None:
    if cache_agrees(evidence) is not False:
        return None
    return _verdict(
        "confident",
        "local",
        f"This PC's DNS cache disagrees with live DNS for {host}",
        f"Live resolvers resolve {host} but the Windows DNS cache on this PC does not return a matching "
        "answer, so the cached entry is stale. Flushing the DNS cache should clear it.",
        evidence_refs=["dns.resolve_cached", "dns.resolve_direct"],
        suggested_actions=["flush_dns"],
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
    )


# First match wins (spec §9).
_RULES = (
    ("hosts_override", _rule_hosts_override),
    ("external_no_address", _rule_external_no_address),
    ("stale_cache", _rule_stale_cache),
    ("dead_gateway", _rule_dead_gateway),
)


def evaluate_rules(evidence: dict[str, dict], target_host: str) -> dict:
    """Evidence-only verdict for the network_dns class; always a full verdict.

    Runs the rules in order and returns the first that fires. ``rule_hits``
    names that rule, plus ``"cache_agrees"`` whenever the cache and the live
    resolvers agree, whichever rule fired.
    """
    host = target_host or "this host"
    verdict = None
    hit = None
    for name, rule in _RULES:
        verdict = rule(evidence, host)
        if verdict is not None:
            hit = name
            break
    if verdict is None:
        verdict = _verdict(
            "inconclusive",
            "unknown",
            "No rule matched this evidence",
            "None of the built-in checks found a clear cause in the evidence collected.",
        )
    verdict["rule_hits"] = ([hit] if hit else []) + (["cache_agrees"] if cache_agrees(evidence) is True else [])
    return verdict
