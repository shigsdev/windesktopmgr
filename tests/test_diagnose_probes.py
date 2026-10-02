"""Tests for diagnose_probes.py -- the closed probe registry and bounded runner."""

from __future__ import annotations

import time

import pytest

import diagnose_probes as dp


@pytest.fixture(autouse=True)
def _isolated_registry(mocker):
    """Every test starts with an empty PROBES dict and registers throwaway probes."""
    mocker.patch.dict(dp.PROBES, {}, clear=True)


def _probe(key="t.probe", fn=None, **kw):
    return dp.register(dp.Probe(key=key, label=f"label {key}", category="test", fn=fn or (lambda s: {}), **kw))


class TestRunProbes:
    def test_happy_path_wraps_data(self):
        _probe("t.ok", fn=lambda s: {"x": 1})
        out = dp.run_probes(["t.ok"], {})
        assert len(out) == 1
        r = out[0]
        assert r["key"] == "t.ok"
        assert r["label"] == "label t.ok"
        assert r["ok"] is True
        assert r["data"] == {"x": 1}
        assert r["elapsed_ms"] >= 0

    def test_slots_passed_to_probe(self):
        seen = {}
        _probe("t.slots", fn=lambda s: seen.update(s) or {})
        dp.run_probes(["t.slots"], {"target_host": "example.com"})
        assert seen == {"target_host": "example.com"}

    def test_raising_probe_becomes_error_not_exception(self):
        def boom(slots):
            raise RuntimeError("boom")

        _probe("t.boom", fn=boom)
        r = dp.run_probes(["t.boom"], {})[0]
        assert r["ok"] is False
        assert "boom" in r["error"]
        assert "data" not in r

    def test_missing_slot_refuses_without_calling(self, mocker):
        fn = mocker.Mock(return_value={})
        _probe("t.need", fn=fn, needs=("target_host",))
        r = dp.run_probes(["t.need"], {})[0]
        assert r["ok"] is False
        assert r["error"] == "missing required slot: target_host"
        fn.assert_not_called()

    def test_empty_slot_value_counts_as_missing(self, mocker):
        fn = mocker.Mock(return_value={})
        _probe("t.need", fn=fn, needs=("target_host",))
        r = dp.run_probes(["t.need"], {"target_host": ""})[0]
        assert r["ok"] is False
        fn.assert_not_called()

    def test_unknown_key_reported(self):
        r = dp.run_probes(["nope.nothing"], {})[0]
        assert r["key"] == "nope.nothing"
        assert r["ok"] is False
        assert r["error"] == "unknown probe"

    def test_timeout_is_bounded(self):
        _probe("t.slow", fn=lambda s: time.sleep(2) or {}, timeout_s=0.2)
        t0 = time.perf_counter()
        r = dp.run_probes(["t.slow"], {})[0]
        assert time.perf_counter() - t0 < 1.0
        assert r["ok"] is False
        assert r["error"] == "timed out after 0.2s"

    def test_results_preserve_input_order(self):
        _probe("a", fn=lambda s: {"n": "a"})
        _probe("b", fn=lambda s: {"n": "b"})
        out = dp.run_probes(["b", "a"], {})
        assert [r["key"] for r in out] == ["b", "a"]

    def test_mixed_outcomes_keep_order(self):
        _probe("ok", fn=lambda s: {})
        out = dp.run_probes(["missing", "ok"], {})
        assert [r["key"] for r in out] == ["missing", "ok"]
        assert [r["ok"] for r in out] == [False, True]

    def test_runs_in_parallel(self):
        for k in ("p1", "p2", "p3"):
            _probe(k, fn=lambda s: time.sleep(0.3) or {})
        t0 = time.perf_counter()
        out = dp.run_probes(["p1", "p2", "p3"], {})
        assert time.perf_counter() - t0 < 0.8
        assert all(r["ok"] for r in out)

    def test_register_rejects_duplicate(self):
        _probe("dup")
        with pytest.raises(ValueError, match="dup"):
            _probe("dup")

    def test_non_dict_return_is_error(self):
        _probe("t.str", fn=lambda s: "str")
        r = dp.run_probes(["t.str"], {})[0]
        assert r["ok"] is False
        assert r["error"] == "probe returned str, expected dict"

    def test_empty_key_list_returns_empty(self, mocker):
        ex = mocker.patch("diagnose_probes.concurrent.futures.ThreadPoolExecutor")
        assert dp.run_probes([], {}) == []
        ex.assert_not_called()

    def test_all_refused_keys_skip_executor(self, mocker):
        ex = mocker.patch("diagnose_probes.concurrent.futures.ThreadPoolExecutor")
        out = dp.run_probes(["x", "y"], {})
        assert [r["error"] for r in out] == ["unknown probe", "unknown probe"]
        ex.assert_not_called()

    def test_duplicate_keys_in_request_each_get_a_result(self):
        _probe("t.ok", fn=lambda s: {"x": 1})
        out = dp.run_probes(["t.ok", "t.ok"], {})
        assert [r["ok"] for r in out] == [True, True]
