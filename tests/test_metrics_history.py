"""tests/test_metrics_history.py -- unit tests for the trend sampler (backlog #4).

All tests redirect HISTORY_FILE to a tmp_path-backed file via the
``mh_tmp`` fixture so the real metrics_history.json on disk is never
touched. No subprocess, no I/O outside tmp_path.
"""

import json
from datetime import datetime, timedelta

import pytest

import metrics_history as mh

# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def mh_tmp(tmp_path, monkeypatch):
    """Redirect HISTORY_FILE to a per-test tmp file."""
    target = tmp_path / "metrics_history.json"
    monkeypatch.setattr(mh, "HISTORY_FILE", str(target))
    return target


def _summary(*, cpu=None, mem_used=None, mem_total=None, temps=None, drives=None, concerns=None):
    """Build a minimal /summary-shaped dict for tests."""
    s: dict = {}
    if concerns is not None:
        s["concerns"] = concerns
    if cpu is not None or temps is not None:
        s["thermals"] = {}
        if cpu is not None:
            s["thermals"]["perf"] = {"CPUPct": cpu}
        if temps is not None:
            s["thermals"]["temps"] = temps
    if mem_used is not None or mem_total is not None:
        s["memory"] = {"used_mb": mem_used or 0, "total_mb": mem_total or 0}
    if drives is not None:
        s["disk"] = {"drives": drives}
    return s


# ── extract_metrics ────────────────────────────────────────────────


class TestExtractMetrics:
    def test_empty_summary_returns_empty(self):
        assert mh.extract_metrics({}) == {}

    def test_non_dict_input_returns_empty(self):
        assert mh.extract_metrics(None) == {}
        assert mh.extract_metrics([]) == {}
        assert mh.extract_metrics("not a dict") == {}

    def test_concerns_counted_by_level(self):
        s = _summary(concerns=[{"level": "critical"}, {"level": "warning"}, {"level": "warning"}, {"level": "info"}])
        m = mh.extract_metrics(s)
        assert m["concerns_critical"] == 1
        assert m["concerns_warning"] == 2

    def test_concerns_zero_when_list_empty(self):
        m = mh.extract_metrics(_summary(concerns=[]))
        assert m["concerns_critical"] == 0
        assert m["concerns_warning"] == 0

    def test_concerns_garbage_entries_skipped(self):
        s = _summary(concerns=[{"level": "critical"}, "not-a-dict", None, {"level": "warning"}])
        m = mh.extract_metrics(s)
        assert m["concerns_critical"] == 1
        assert m["concerns_warning"] == 1

    def test_cpu_percent_extracted(self):
        m = mh.extract_metrics(_summary(cpu=42))
        assert m["cpu_percent"] == 42.0

    def test_cpu_percent_missing_when_zero_skipped(self):
        # 0 is a valid CPU pct but our extractor coerces to float regardless
        m = mh.extract_metrics(_summary(cpu=0))
        assert m["cpu_percent"] == 0.0

    def test_max_temp_picked_from_temps_list(self):
        s = _summary(temps=[{"TempC": 45}, {"TempC": 67}, {"TempC": 52}])
        m = mh.extract_metrics(s)
        assert m["cpu_temp_c"] == 67.0

    def test_temp_missing_when_no_numeric_values(self):
        s = _summary(temps=[{"TempC": "n/a"}, {"TempC": None}])
        m = mh.extract_metrics(s)
        assert "cpu_temp_c" not in m

    def test_memory_percent_computed_from_used_total(self):
        m = mh.extract_metrics(_summary(mem_used=8000, mem_total=16000))
        assert m["memory_percent"] == 50.0

    def test_memory_percent_skipped_when_total_zero(self):
        m = mh.extract_metrics(_summary(mem_used=8000, mem_total=0))
        assert "memory_percent" not in m

    def test_disk_drives_flattened_with_letter_keys(self):
        drives = [{"Letter": "C", "PctUsed": 78}, {"Letter": "D", "PctUsed": 45}]
        m = mh.extract_metrics(_summary(drives=drives))
        assert m["disk_percent.C"] == 78.0
        assert m["disk_percent.D"] == 45.0

    def test_disk_drives_lowercase_letter_normalised(self):
        drives = [{"letter": "c", "pct_used": 22}]
        m = mh.extract_metrics(_summary(drives=drives))
        assert m["disk_percent.C"] == 22.0

    def test_disk_drive_without_letter_skipped(self):
        drives = [{"PctUsed": 50}]
        m = mh.extract_metrics(_summary(drives=drives))
        assert not any(k.startswith("disk_percent") for k in m)

    def test_handles_partial_summary_gracefully(self):
        # Only thermals present — should still produce CPU even though
        # memory and disk are missing entirely
        m = mh.extract_metrics(_summary(cpu=15))
        assert m == {"cpu_percent": 15.0}

    # ── GPU extraction (backlog #37) ───────────────────────────────

    def test_gpu_available_populates_three_series(self):
        """get_gpu_metrics returns a dict with available=True on NVIDIA
        machines. extract_metrics should pull utilization_pct, vram_pct,
        and temp_c as flat series keys (gpu_utilization_pct, gpu_vram_pct,
        gpu_temp_c)."""
        gpu = {
            "available": True,
            "source": "pynvml",
            "utilization_pct": 42.0,
            "vram_memctrl_pct": 12.0,
            "vram_used_mb": 1024.0,
            "vram_total_mb": 8192.0,
            "vram_pct": 12.5,
            "temp_c": 55.0,
            "power_w": 80.0,
        }
        m = mh.extract_metrics({"gpu": gpu})
        assert m["gpu_utilization_pct"] == 42.0
        assert m["gpu_vram_pct"] == 12.5
        assert m["gpu_temp_c"] == 55.0

    def test_gpu_unavailable_produces_no_series(self):
        """No NVIDIA driver / no GPU -> collector returns available=False.
        extractor must NOT emit gpu_* keys in that case -- a machine
        without a GPU shouldn't get an empty "GPU 0%" series forever."""
        gpu = {"available": False, "error": "no NVIDIA GPU detected"}
        m = mh.extract_metrics({"gpu": gpu})
        assert not any(k.startswith("gpu_") for k in m)

    def test_gpu_missing_section_produces_no_series(self):
        m = mh.extract_metrics({})  # no "gpu" key at all
        assert not any(k.startswith("gpu_") for k in m)

    def test_gpu_partial_fields_still_extracted(self):
        """If the collector returned available=True but temperature sensor
        wasn't supported (None), we should still record utilization and
        vram_pct, just skip temp."""
        gpu = {
            "available": True,
            "utilization_pct": 10.0,
            "vram_pct": 5.0,
            "temp_c": None,  # sensor not available
        }
        m = mh.extract_metrics({"gpu": gpu})
        assert m["gpu_utilization_pct"] == 10.0
        assert m["gpu_vram_pct"] == 5.0
        assert "gpu_temp_c" not in m

    def test_gpu_idle_zero_kept_not_dropped(self):
        """0% GPU utilization on an idle card is a real signal, not missing."""
        gpu = {"available": True, "utilization_pct": 0.0, "vram_pct": 0.0, "temp_c": 35.0}
        m = mh.extract_metrics({"gpu": gpu})
        assert m["gpu_utilization_pct"] == 0.0
        assert m["gpu_vram_pct"] == 0.0
        assert m["gpu_temp_c"] == 35.0

    # ── Network extraction (backlog #38) ───────────────────────────

    def test_network_available_populates_four_series(self):
        """get_network_metrics returns available=True in the happy path.
        extract_metrics emits four flat keys, one per sparkline."""
        net = {
            "available": True,
            "source": "psutil+socket",
            "throughput_in_mbps": 12.5,
            "throughput_out_mbps": 3.2,
            "latency_ms": 15.0,
            "latency_target": "1.1.1.1:53",
            "connections_established": 42,
            "error": None,
        }
        m = mh.extract_metrics({"network": net})
        assert m["net_throughput_mbps.in"] == 12.5
        assert m["net_throughput_mbps.out"] == 3.2
        assert m["net_latency_ms"] == 15.0
        assert m["net_connections_established"] == 42

    def test_network_missing_section_produces_no_keys(self):
        m = mh.extract_metrics({})
        assert not any(k.startswith("net_") for k in m)

    def test_network_unavailable_produces_no_keys(self):
        """available=False -- should not add any net_* series."""
        net = {"available": False, "error": "net_io_counters failed"}
        m = mh.extract_metrics({"network": net})
        assert not any(k.startswith("net_") for k in m)

    def test_network_latency_none_is_skipped_not_zero(self):
        """Failed latency probe -> None in the payload. extract_metrics
        MUST NOT record that as 0 ms -- zero would hide real outages."""
        net = {
            "available": True,
            "throughput_in_mbps": 1.0,
            "throughput_out_mbps": 0.5,
            "latency_ms": None,  # probe failed
            "connections_established": 10,
        }
        m = mh.extract_metrics({"network": net})
        assert "net_latency_ms" not in m
        # Other fields still recorded
        assert m["net_throughput_mbps.in"] == 1.0
        assert m["net_connections_established"] == 10

    def test_network_connections_none_is_skipped(self):
        """AccessDenied on net_connections -> None. Skip the field, keep others."""
        net = {
            "available": True,
            "throughput_in_mbps": 2.0,
            "throughput_out_mbps": 1.0,
            "latency_ms": 8.0,
            "connections_established": None,
        }
        m = mh.extract_metrics({"network": net})
        assert "net_connections_established" not in m
        assert m["net_latency_ms"] == 8.0

    def test_network_idle_zero_throughput_kept(self):
        """0 Mbps throughput on a quiet network is a real reading, not missing."""
        net = {
            "available": True,
            "throughput_in_mbps": 0.0,
            "throughput_out_mbps": 0.0,
            "latency_ms": 12.0,
            "connections_established": 5,
        }
        m = mh.extract_metrics({"network": net})
        assert m["net_throughput_mbps.in"] == 0.0
        assert m["net_throughput_mbps.out"] == 0.0


# ── load_history ───────────────────────────────────────────────────


class TestLoadHistory:
    def test_missing_file_returns_empty(self, mh_tmp):
        assert mh.load_history() == []

    def test_corrupt_json_returns_empty(self, mh_tmp):
        mh_tmp.write_text("{ this is not json")
        assert mh.load_history() == []

    def test_non_list_root_returns_empty(self, mh_tmp):
        mh_tmp.write_text(json.dumps({"not": "a list"}))
        assert mh.load_history() == []

    def test_valid_history_returned_as_list(self, mh_tmp):
        data = [{"timestamp": "2026-01-01T00:00:00", "metrics": {"cpu_percent": 5}}]
        mh_tmp.write_text(json.dumps(data))
        loaded = mh.load_history()
        assert loaded == data


# ── record_sample ──────────────────────────────────────────────────


class TestRecordSample:
    def test_first_sample_writes_entry(self, mh_tmp):
        result = mh.record_sample(_summary(cpu=20))
        assert result["ok"] is True
        assert result["skipped"] is False
        assert result["metrics"]["cpu_percent"] == 20.0
        history = mh.load_history()
        assert len(history) == 1
        assert history[0]["metrics"]["cpu_percent"] == 20.0
        assert "timestamp" in history[0]

    def test_throttled_within_interval_skips_write(self, mh_tmp):
        mh.record_sample(_summary(cpu=20))
        result = mh.record_sample(_summary(cpu=99))
        assert result["skipped"] is True
        assert mh.load_history()[0]["metrics"]["cpu_percent"] == 20.0  # original kept

    def test_force_bypasses_throttle(self, mh_tmp):
        mh.record_sample(_summary(cpu=20))
        result = mh.record_sample(_summary(cpu=99), force=True)
        assert result["skipped"] is False
        history = mh.load_history()
        assert len(history) == 2

    def test_empty_metrics_skipped_no_write(self, mh_tmp):
        # Summary with all sections missing -> extract_metrics returns {}
        # Should NOT add a hole-in-the-series entry to history.
        result = mh.record_sample({})
        assert result["skipped"] is True
        assert mh.load_history() == []

    def test_history_capped_at_max(self, mh_tmp, monkeypatch):
        monkeypatch.setattr(mh, "MAX_HISTORY", 3)
        for i in range(5):
            mh.record_sample(_summary(cpu=i), force=True)
        history = mh.load_history()
        assert len(history) == 3
        # Oldest two trimmed; remaining are i=2,3,4
        cpus = [e["metrics"]["cpu_percent"] for e in history]
        assert cpus == [2.0, 3.0, 4.0]


# ── Querying ───────────────────────────────────────────────────────


class TestGetSeries:
    def _seed(self, mh_tmp, points: list[tuple[datetime, dict]]):
        """Write a list of (datetime, metrics_dict) directly to history."""
        data = [{"timestamp": ts.isoformat(timespec="seconds"), "metrics": m} for ts, m in points]
        mh_tmp.write_text(json.dumps(data))

    def test_returns_only_requested_metric(self, mh_tmp):
        now = datetime.now()
        self._seed(
            mh_tmp,
            [
                (now - timedelta(hours=1), {"cpu_percent": 10, "memory_percent": 50}),
                (now - timedelta(minutes=30), {"cpu_percent": 20, "memory_percent": 60}),
            ],
        )
        series = mh.get_series("cpu_percent")
        assert [p["value"] for p in series] == [10, 20]

    def test_filters_by_window(self, mh_tmp):
        now = datetime.now()
        self._seed(
            mh_tmp,
            [
                (now - timedelta(days=10), {"cpu_percent": 5}),  # outside default 7d
                (now - timedelta(days=1), {"cpu_percent": 15}),
                (now - timedelta(hours=1), {"cpu_percent": 25}),
            ],
        )
        series = mh.get_series("cpu_percent")
        assert [p["value"] for p in series] == [15, 25]

    def test_unknown_metric_returns_empty(self, mh_tmp):
        now = datetime.now()
        self._seed(mh_tmp, [(now, {"cpu_percent": 10})])
        assert mh.get_series("nope") == []

    def test_skips_entries_missing_the_metric(self, mh_tmp):
        # Per-drive metrics exist only on samples taken when the drive existed
        now = datetime.now()
        self._seed(
            mh_tmp,
            [
                (now - timedelta(hours=2), {"cpu_percent": 10}),  # no disk
                (now - timedelta(hours=1), {"cpu_percent": 12, "disk_percent.C": 78}),
            ],
        )
        series = mh.get_series("disk_percent.C")
        assert [p["value"] for p in series] == [78]


class TestListMetrics:
    def test_empty_history_returns_empty_list(self, mh_tmp):
        assert mh.list_metrics() == []

    def test_returns_unique_sorted_keys(self, mh_tmp):
        now = datetime.now()
        data = [
            {"timestamp": now.isoformat(), "metrics": {"cpu_percent": 1, "memory_percent": 2}},
            {"timestamp": now.isoformat(), "metrics": {"cpu_percent": 3, "disk_percent.C": 4}},
        ]
        mh_tmp.write_text(json.dumps(data))
        assert mh.list_metrics() == ["cpu_percent", "disk_percent.C", "memory_percent"]


class TestGetAllSeries:
    def test_returns_one_series_per_metric_in_one_pass(self, mh_tmp):
        now = datetime.now()
        data = [
            {"timestamp": (now - timedelta(hours=2)).isoformat(), "metrics": {"cpu_percent": 5}},
            {"timestamp": (now - timedelta(hours=1)).isoformat(), "metrics": {"cpu_percent": 10, "memory_percent": 50}},
        ]
        mh_tmp.write_text(json.dumps(data))
        all_series = mh.get_all_series()
        assert [p["value"] for p in all_series["cpu_percent"]] == [5, 10]
        assert [p["value"] for p in all_series["memory_percent"]] == [50]

    def test_outside_window_excluded(self, mh_tmp):
        now = datetime.now()
        data = [
            {"timestamp": (now - timedelta(days=10)).isoformat(), "metrics": {"cpu_percent": 99}},
            {"timestamp": (now - timedelta(hours=1)).isoformat(), "metrics": {"cpu_percent": 11}},
        ]
        mh_tmp.write_text(json.dumps(data))
        all_series = mh.get_all_series()
        assert [p["value"] for p in all_series["cpu_percent"]] == [11]


# ── Atomic write failure ───────────────────────────────────────────


class TestAtomicWrite:
    def test_oserror_during_replace_returns_false(self, mh_tmp, mocker):
        # Simulate disk-full / permission-denied at the os.replace step
        mocker.patch("metrics_history.os.replace", side_effect=OSError("disk full"))
        ok = mh._append_history({"timestamp": datetime.now().isoformat(), "metrics": {"cpu_percent": 1}})
        assert ok is False
        # Original file untouched (didn't exist before -> still doesn't)
        assert mh.load_history() == []
