"""tests/test_alerts.py -- rule persistence + evaluator + Flask routes.

All file I/O is tmp_path-scoped so nothing touches the real
``alert_rules.json``. Backlog #5.
"""

from __future__ import annotations

import pytest

import alerts


@pytest.fixture
def tmp_rules(tmp_path, monkeypatch):
    """Redirect ALERT_RULES_FILE to a per-test tmp path."""
    target = tmp_path / "alert_rules.json"
    monkeypatch.setattr(alerts, "ALERT_RULES_FILE", str(target))
    return target


# ── Defaults + persistence ────────────────────────────────────────


class TestDefaultRules:
    def test_defaults_cover_expected_metrics(self):
        metrics = {r.metric for r in alerts.DEFAULT_RULES}
        # All 4 core metrics must have at least one default rule
        assert {"cpu_percent", "memory_percent", "disk_percent", "temperature_c"} <= metrics

    def test_default_rules_every_level_is_valid(self):
        for r in alerts.DEFAULT_RULES:
            assert r.level in alerts.VALID_LEVELS
            assert r.metric in alerts.METRIC_BOUNDS

    def test_load_without_override_returns_defaults(self, tmp_rules):
        rules = alerts.load_rules()
        assert len(rules) == len(alerts.DEFAULT_RULES)
        # default thresholds match the seed
        seed = {r.id: r.threshold for r in alerts.DEFAULT_RULES}
        for r in rules:
            assert r.threshold == seed[r.id]


class TestPersistence:
    def test_update_and_reload_roundtrip(self, tmp_rules):
        r = alerts.update_rule("cpu_warning", threshold=88.0)
        assert r["ok"] is True
        assert r["rule"]["threshold"] == 88.0
        # Reload from disk and confirm persisted
        reloaded = {x.id: x for x in alerts.load_rules()}
        assert reloaded["cpu_warning"].threshold == 88.0

    def test_update_enabled_flag(self, tmp_rules):
        r = alerts.update_rule("temp_warning", enabled=False)
        assert r["ok"] is True
        reloaded = {x.id: x for x in alerts.load_rules()}
        assert reloaded["temp_warning"].enabled is False

    def test_update_unknown_rule_is_400_shape(self, tmp_rules):
        r = alerts.update_rule("bogus_rule", threshold=50)
        assert r["ok"] is False
        assert "Unknown rule id" in r["error"]

    def test_update_threshold_bounds_enforced(self, tmp_rules):
        # cpu_percent bounds 0..100 — 150 should be rejected
        r = alerts.update_rule("cpu_warning", threshold=150.0)
        assert r["ok"] is False
        assert "threshold" in r["error"]
        # Original value untouched
        reloaded = {x.id: x for x in alerts.load_rules()}
        assert reloaded["cpu_warning"].threshold == 80.0

    def test_update_threshold_non_numeric_rejected(self, tmp_rules):
        r = alerts.update_rule("cpu_warning", threshold="eighty")
        assert r["ok"] is False

    def test_update_invalid_level_rejected(self, tmp_rules):
        r = alerts.update_rule("cpu_warning", level="catastrophic")
        assert r["ok"] is False
        assert "level must be" in r["error"]

    def test_corrupt_file_falls_back_to_defaults(self, tmp_rules):
        tmp_rules.write_text("not json", encoding="utf-8")
        rules = alerts.load_rules()
        assert len(rules) == len(alerts.DEFAULT_RULES)


# ── Evaluator ─────────────────────────────────────────────────────


class TestEvaluateRules:
    def test_no_metrics_no_concerns(self, tmp_rules):
        assert alerts.evaluate_rules([]) == []

    def test_cpu_below_all_thresholds_no_concerns(self, tmp_rules):
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="cpu_percent", value=40.0)])
        assert concerns == []

    def test_cpu_above_warning_below_critical_fires_warning(self, tmp_rules):
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="cpu_percent", value=85.0)])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "warning"
        assert concerns[0]["metric"] == "cpu_percent"
        assert concerns[0]["value"] == 85.0

    def test_cpu_above_critical_fires_critical_only(self, tmp_rules):
        """When value trips both warning (80) and critical (90), only the
        critical concern fires — no double-ups."""
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="cpu_percent", value=95.0)])
        assert len(concerns) == 1
        assert concerns[0]["level"] == "critical"

    def test_disabled_rule_never_fires(self, tmp_rules):
        alerts.update_rule("cpu_warning", enabled=False)
        alerts.update_rule("cpu_critical", enabled=False)
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="cpu_percent", value=99.0)])
        assert concerns == []

    def test_per_drive_disk_produces_one_concern_each(self, tmp_rules):
        points = [
            alerts.MetricPoint(metric="disk_percent", value=92.0, label="C:"),
            alerts.MetricPoint(metric="disk_percent", value=30.0, label="D:"),  # below threshold
            alerts.MetricPoint(metric="disk_percent", value=98.0, label="E:"),
        ]
        concerns = alerts.evaluate_rules(points)
        assert len(concerns) == 2
        assert any("C:" in c["title"] for c in concerns)
        assert any("E:" in c["title"] for c in concerns)
        # E: should be critical (>=95), C: warning (>=85 <95)
        critical = next(c for c in concerns if "E:" in c["title"])
        warning = next(c for c in concerns if "C:" in c["title"])
        assert critical["level"] == "critical"
        assert warning["level"] == "warning"

    def test_temperature_concern_includes_degree_symbol(self, tmp_rules):
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="temperature_c", value=96.0)])
        assert len(concerns) == 1
        assert "°C" in concerns[0]["title"]

    def test_rule_metadata_in_concern(self, tmp_rules):
        """Every rule-driven concern must include rule_id / metric /
        value / threshold so the frontend can trace it back."""
        concerns = alerts.evaluate_rules([alerts.MetricPoint(metric="cpu_percent", value=95.0)])
        c = concerns[0]
        assert c["rule_id"] == "cpu_critical"
        assert c["metric"] == "cpu_percent"
        assert c["value"] == 95.0
        assert c["threshold"] == 90.0


# ── Flask routes ──────────────────────────────────────────────────


class TestAlertRoutes:
    def test_get_rules_returns_full_list(self, client, tmp_rules):
        resp = client.get("/api/alerts/rules")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert len(body["rules"]) == len(alerts.DEFAULT_RULES)

    def test_patch_rule_updates_threshold(self, client, tmp_rules):
        resp = client.patch("/api/alerts/rules/cpu_warning", json={"threshold": 92.0})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["rule"]["threshold"] == 92.0

    def test_patch_unknown_rule_returns_400(self, client, tmp_rules):
        resp = client.patch("/api/alerts/rules/bogus", json={"threshold": 50})
        assert resp.status_code == 400

    def test_patch_with_no_editable_fields_returns_400(self, client, tmp_rules):
        resp = client.patch("/api/alerts/rules/cpu_warning", json={"name": "Nope"})
        assert resp.status_code == 400

    def test_patch_out_of_range_threshold_returns_400(self, client, tmp_rules):
        resp = client.patch("/api/alerts/rules/cpu_warning", json={"threshold": 500})
        assert resp.status_code == 400
        assert "threshold" in resp.get_json()["error"]


# ── Dashboard integration ────────────────────────────────────────


class TestDashboardRuleIntegration:
    """Verify rule-driven concerns appear on /api/dashboard/summary and
    respect the user's threshold override."""

    def _mock_deps(self, mocker, cpu_pct: int, mem_pct: float):
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={
                "temps": [],
                "perf": {"CPUPct": cpu_pct},
                "fans": [],
                "has_rich": True,
            },
        )
        used = int(32000 * mem_pct / 100)
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={"total_mb": 32000, "used_mb": used, "free_mb": 32000 - used, "top_procs": []},
        )
        mocker.patch("windesktopmgr.get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={"onedrive_suspended": False, "fast_startup_enabled": False, "drives_down": []},
        )
        mocker.patch("windesktopmgr.get_disk_health", return_value={"ok": True, "drives": []})
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value={"old_drivers": [], "problematic_drivers": [], "nvidia": None},
        )
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

    def test_high_cpu_fires_rule_concern(self, client, mocker, tmp_rules):
        self._mock_deps(mocker, cpu_pct=92, mem_pct=40.0)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        cpu_concern = next((c for c in concerns if c.get("metric") == "cpu_percent"), None)
        assert cpu_concern is not None
        assert cpu_concern["level"] == "critical"
        assert cpu_concern["rule_id"] == "cpu_critical"

    def test_lowered_threshold_fires_earlier(self, client, mocker, tmp_rules):
        """User drops cpu_warning threshold from 80 -> 50; a 60 % CPU
        should then fire a warning when it wouldn't before."""
        alerts.update_rule("cpu_warning", threshold=50.0)
        self._mock_deps(mocker, cpu_pct=60, mem_pct=40.0)
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        assert any(c.get("rule_id") == "cpu_warning" for c in concerns), (
            f"expected cpu_warning rule to fire at 60% with threshold 50%, got "
            f"concerns: {[c.get('title') for c in concerns]}"
        )

    def test_disabled_rule_stays_silent_on_dashboard(self, client, mocker, tmp_rules):
        alerts.update_rule("memory_critical", enabled=False)
        alerts.update_rule("memory_warning", enabled=False)
        self._mock_deps(mocker, cpu_pct=10, mem_pct=99.0)  # would normally fire critical
        resp = client.get("/api/dashboard/summary")
        concerns = resp.get_json()["concerns"]
        assert not any(c.get("metric") == "memory_percent" for c in concerns)
