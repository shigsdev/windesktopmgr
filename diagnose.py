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
