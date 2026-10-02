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
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

_MAX_WORKERS = 8


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
