"""alerts.py -- Smart alerting with user-configurable thresholds (backlog #5).

Today the dashboard concerns fire at hardcoded thresholds (``cpu >= 80``,
``mem_pct > 90``, etc.) defined inline in ``dashboard_summary``. The
user has no way to adjust them without editing code. That means a
dev-workstation owner sees warning spam at every compile, and someone
who wants *earlier* warnings can't get them.

This module replaces those hardcoded thresholds with a small
rules engine:

* ``DEFAULT_RULES`` -- the seed set (same thresholds the hardcoded
  heuristics used, so behavior is unchanged on a fresh install).
* ``load_rules()`` / ``save_rules()`` / ``update_rule()`` -- persistence
  via ``alert_rules.json`` (lock-guarded, atomic write, same idiom as
  ``memory_snoozes.json`` / ``bios_audit_history.json``).
* ``evaluate_rules(metrics)`` -- takes a metrics dict (cpu_percent,
  memory_percent, per-drive disk_percent, temperature_c) and returns
  a list of dashboard concern dicts for any rules that fired.

Dashboard integration is in ``windesktopmgr.dashboard_summary`` --
the rule-driven concerns get appended alongside the existing
heuristic ones (BIOS update available, NAS offline, etc.) which are
domain-specific and not threshold-shaped.

Design notes
------------
* Rules are keyed by a stable ``id``. That way the UI-driven PATCH
  doesn't need to identify rules by position, and future migrations
  can safely add/remove rules without breaking saved configs.
* We never DELETE a rule from the user config -- when the user
  disables a rule, we flip ``enabled=False`` but keep it in the
  file. This means future defaults additions will merge cleanly
  (default + user override).
* Maximum rate-of-change protection: thresholds must fall within
  sane per-metric bounds (e.g. cpu_percent in 0..100). The validator
  enforces this so the UI can't write 999 and lock itself out.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from typing import Any

_STORE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_RULES_FILE = os.path.join(_STORE_DIR, "alert_rules.json")
_rules_lock = threading.RLock()

# ── Metric contract ────────────────────────────────────────────────
#
# Each metric has a validator returning the allowed threshold range.
# Used by update_rule to reject garbage input.

METRIC_BOUNDS: dict[str, tuple[float, float]] = {
    "cpu_percent": (0.0, 100.0),
    "memory_percent": (0.0, 100.0),
    "disk_percent": (0.0, 100.0),  # per-drive
    "temperature_c": (0.0, 110.0),  # sensor
}

VALID_LEVELS = frozenset({"info", "warning", "critical"})


# ── Rule dataclass ────────────────────────────────────────────────


@dataclass
class Rule:
    id: str
    name: str
    metric: str
    threshold: float
    level: str  # "critical" | "warning" | "info"
    enabled: bool = True
    description: str = ""
    icon: str = "⚠"
    tab: str = "dashboard"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        # Defensive: fill any missing fields from defaults
        known = {f: d[f] for f in cls.__dataclass_fields__ if f in d}
        return cls(**known)


# ── Default rule set ──────────────────────────────────────────────
#
# These mirror the thresholds hardcoded in dashboard_summary before #5
# so behaviour is identical on a fresh install. Users can tune them
# without touching code.

DEFAULT_RULES: list[Rule] = [
    Rule(
        id="cpu_critical",
        name="CPU at critical load",
        metric="cpu_percent",
        threshold=90.0,
        level="critical",
        description="Sustained CPU above this percent surfaces as a critical dashboard concern.",
        icon="💻",
        tab="thermals",
    ),
    Rule(
        id="cpu_warning",
        name="CPU elevated",
        metric="cpu_percent",
        threshold=80.0,
        level="warning",
        description="Warn when CPU runs above this percent. 80% is the default; dev-heavy workstations may prefer 90.",
        icon="💻",
        tab="thermals",
    ),
    Rule(
        id="memory_critical",
        name="RAM exhaustion",
        metric="memory_percent",
        threshold=90.0,
        level="critical",
        description="Critical dashboard concern when used RAM crosses this percent.",
        icon="🧠",
        tab="memory",
    ),
    Rule(
        id="memory_warning",
        name="RAM pressure",
        metric="memory_percent",
        threshold=75.0,
        level="warning",
        description="Early warning at this RAM%. Tune up if you run memory-heavy work as normal.",
        icon="🧠",
        tab="memory",
    ),
    Rule(
        id="disk_critical",
        name="Drive nearly full",
        metric="disk_percent",
        threshold=95.0,
        level="critical",
        description="Per-drive warning when used % crosses the threshold. Applies to every local drive.",
        icon="💾",
        tab="disk",
    ),
    Rule(
        id="disk_warning",
        name="Drive filling up",
        metric="disk_percent",
        threshold=85.0,
        level="warning",
        description="Per-drive early warning. Helps you clear space before a critical alert fires.",
        icon="💾",
        tab="disk",
    ),
    Rule(
        id="temp_critical",
        name="Temperature critical",
        metric="temperature_c",
        threshold=95.0,
        level="critical",
        description="Any sensor above this °C surfaces as a critical dashboard concern.",
        icon="🌡",
        tab="thermals",
    ),
    Rule(
        id="temp_warning",
        name="Temperature elevated",
        metric="temperature_c",
        threshold=80.0,
        level="warning",
        description="Early thermal warning. Under-load i9 / Ryzen systems often sit between 70–85 °C.",
        icon="🌡",
        tab="thermals",
    ),
]


# ── Persistence ───────────────────────────────────────────────────


def _default_rules_by_id() -> dict[str, Rule]:
    return {r.id: Rule(**asdict(r)) for r in DEFAULT_RULES}


def load_rules() -> list[Rule]:
    """Return the merged set of (defaults + user overrides), stable-ordered
    matching DEFAULT_RULES (new defaults appended at the end)."""
    with _rules_lock:
        defaults = _default_rules_by_id()
        user: dict[str, dict] = {}
        try:
            if os.path.exists(ALERT_RULES_FILE):
                with open(ALERT_RULES_FILE, encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    user = {k: v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, json.JSONDecodeError):
            user = {}
        merged: list[Rule] = []
        seen: set[str] = set()
        # Preserve default order first
        for rule_id, rule in defaults.items():
            override = user.get(rule_id) or {}
            # Only allow threshold/level/enabled to be overridden; name /
            # metric / id are structural and stay from defaults.
            rule.threshold = float(override.get("threshold", rule.threshold))
            rule.enabled = bool(override.get("enabled", rule.enabled))
            if override.get("level") in VALID_LEVELS:
                rule.level = override["level"]
            merged.append(rule)
            seen.add(rule_id)
        # Any stale user entries (from a rule we renamed/removed) get
        # dropped on the next save -- no migration gymnastics.
        return merged


def _serialise_user_overrides(rules: list[Rule]) -> dict[str, dict]:
    """Extract only the user-editable fields from each rule so the file
    stays minimal. Default-valued rules DO still get saved so the file
    survives a defaults change cleanly."""
    return {r.id: {"threshold": r.threshold, "level": r.level, "enabled": r.enabled} for r in rules}


def save_rules(rules: list[Rule]) -> bool:
    """Persist user overrides. Returns True on success."""
    body = json.dumps(_serialise_user_overrides(rules), indent=2)
    tmp = ALERT_RULES_FILE + ".tmp"
    with _rules_lock:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(tmp, ALERT_RULES_FILE)
            return True
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False


def update_rule(rule_id: str, **changes: Any) -> dict:
    """Apply a partial update to one rule by id. Validates bounds.

    Returns {ok, rule, error?}.
    """
    rules = load_rules()
    target = next((r for r in rules if r.id == rule_id), None)
    if target is None:
        return {"ok": False, "error": f"Unknown rule id: {rule_id}"}

    if "threshold" in changes:
        try:
            thr = float(changes["threshold"])
        except (TypeError, ValueError):
            return {"ok": False, "error": "threshold must be numeric"}
        lo, hi = METRIC_BOUNDS.get(target.metric, (float("-inf"), float("inf")))
        if not lo <= thr <= hi:
            return {"ok": False, "error": f"threshold for {target.metric} must be in [{lo}, {hi}]"}
        target.threshold = thr

    if "level" in changes:
        lvl = str(changes["level"]).lower()
        if lvl not in VALID_LEVELS:
            return {"ok": False, "error": f"level must be one of {sorted(VALID_LEVELS)}"}
        target.level = lvl

    if "enabled" in changes:
        target.enabled = bool(changes["enabled"])

    if save_rules(rules):
        return {"ok": True, "rule": target.to_dict()}
    return {"ok": False, "error": "failed to persist rule"}


# ── Evaluation ───────────────────────────────────────────────────


@dataclass
class MetricPoint:
    """One scalar observation the evaluator should compare against rules."""

    metric: str
    value: float
    label: str = ""  # human-readable context (e.g. "C:" for disk, "CPU pkg" for temp)
    tab: str | None = None  # optional override, else the rule's tab wins
    extra: dict = field(default_factory=dict)


def evaluate_rules(points: list[MetricPoint], rules: list[Rule] | None = None) -> list[dict]:
    """Produce a list of dashboard concern dicts for each triggered rule.

    Rules are matched to points by ``metric`` name. For each matching
    pair, the concern fires when ``value >= threshold`` and the rule is
    enabled. Multiple points for the same metric (e.g. multiple drives)
    each get their own concern.
    """
    rule_list = rules if rules is not None else load_rules()
    # Group rules by (metric) so each point is checked against every rule
    # for its metric -- multiple levels can coexist (e.g. disk_warning
    # fires at 85, disk_critical at 95).
    by_metric: dict[str, list[Rule]] = {}
    for r in rule_list:
        if not r.enabled:
            continue
        by_metric.setdefault(r.metric, []).append(r)
    # For any given point, pick the HIGHEST-severity rule that trips.
    # critical > warning > info. This avoids flooding the dashboard with
    # both a warning and a critical for the same drive.
    severity_order = {"critical": 3, "warning": 2, "info": 1}
    concerns: list[dict] = []
    for p in points:
        hits = [r for r in by_metric.get(p.metric, []) if p.value >= r.threshold]
        if not hits:
            continue
        hits.sort(key=lambda r: severity_order.get(r.level, 0), reverse=True)
        winner = hits[0]
        label_suffix = f" ({p.label})" if p.label else ""
        value_str = f"{p.value:.1f}" if p.metric != "temperature_c" else f"{p.value:.0f}°C"
        concerns.append(
            {
                "level": winner.level,
                "tab": p.tab or winner.tab,
                "icon": winner.icon,
                "title": f"{winner.name}{label_suffix}: {value_str}",
                "detail": winner.description or f"{p.metric} crossed threshold {winner.threshold}",
                "action": f"View {winner.tab}",
                "action_fn": f"switchTab('{winner.tab}')",
                # Metadata the frontend / tray can use:
                "rule_id": winner.id,
                "metric": p.metric,
                "value": p.value,
                "threshold": winner.threshold,
            }
        )
    return concerns
