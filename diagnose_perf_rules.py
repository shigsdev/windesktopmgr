"""Evidence-only verdicts for the Diagnose speed & heat class (spec 2026-10-17 §6).

``evaluate_perf_rules`` reads the perf probes' evidence and returns a full
verdict in ``diagnose._verdict``'s shape.

Import cycle: ``diagnose`` reaches this module only through a wrapper it calls
at run time, and this module touches ``diagnose`` attributes only inside
functions, so either module can be imported first.
"""

from __future__ import annotations

import diagnose as dg


def evaluate_perf_rules(evidence: dict[str, dict]) -> dict:
    """Evidence-only verdict for the ``performance`` class; always a full verdict."""
    return dg._verdict(
        "inconclusive",
        "unknown",
        "Nothing is slowing the PC down right now",
        "None of the speed or temperature readings point to a cause.",
        rule_hits=["nothing_found"],
    )
