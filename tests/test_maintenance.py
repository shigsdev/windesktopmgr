"""Tests for maintenance.py — Tier 1 junk cleanup (scan preview + clean)."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote

import pytest

import disk
import maintenance

_CLOCK_EVERY_TEST_FILES = maintenance._CLOCK_EVERY * 3

# ── helpers ───────────────────────────────────────────────────────────────────


def _mkfile(path, size=100, age_days=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"x" * size)
    if age_days:
        old = time.time() - age_days * 86400
        os.utime(path, (old, old))
    return path


class TestScanDir:
    def test_counts_files_and_bytes(self, tmp_path):
        _mkfile(str(tmp_path / "a.tmp"), 100)
        _mkfile(str(tmp_path / "b.tmp"), 250)
        count, nbytes, samples = maintenance._scan_dir(str(tmp_path))
        assert count == 2
        assert nbytes == 350
        assert len(samples) == 2

    def test_missing_dir_is_zero(self, tmp_path):
        assert maintenance._scan_dir(str(tmp_path / "nope")) == (0, 0, [])

    def test_recurse_sums_subdirs(self, tmp_path):
        _mkfile(str(tmp_path / "sub" / "c.tmp"), 500)
        count, nbytes, _ = maintenance._scan_dir(str(tmp_path), recurse=True)
        assert nbytes == 500
        assert count == 2  # the subdir + its file

    def test_no_recurse_skips_subdir_contents(self, tmp_path):
        _mkfile(str(tmp_path / "sub" / "c.tmp"), 500)
        count, nbytes, _ = maintenance._scan_dir(str(tmp_path), recurse=False)
        assert nbytes == 0  # subdir not summed
        assert count == 0

    def test_min_age_skips_recent(self, tmp_path):
        _mkfile(str(tmp_path / "fresh.tmp"), 100, age_days=0)
        _mkfile(str(tmp_path / "old.tmp"), 100, age_days=5)
        count, nbytes, _ = maintenance._scan_dir(str(tmp_path), min_age_days=1)
        assert count == 1
        assert nbytes == 100

    def test_patterns_filter(self, tmp_path):
        _mkfile(str(tmp_path / "thumbcache_1.db"), 100)
        _mkfile(str(tmp_path / "keep.db"), 999)
        count, nbytes, _ = maintenance._scan_dir(str(tmp_path), patterns=("thumbcache_",))
        assert count == 1
        assert nbytes == 100


class TestHuman:
    def test_units(self):
        assert maintenance._human(0) == "0 B"
        assert maintenance._human(1536) == "1.5 KB"
        assert maintenance._human(5 * 1024 * 1024) == "5.0 MB"


class TestSafetyGuards:
    def test_within_profile_accepts_paths_under_profile(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})
        assert maintenance._within_profile(str(tmp_path / "AppData" / "Local" / "Temp")) is True

    def test_within_profile_rejects_drive_root(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})
        assert maintenance._within_profile("C:\\") is False

    def test_within_profile_rejects_outside_profile(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path / "prof")})
        assert maintenance._within_profile("C:\\Windows\\Temp") is False

    def test_within_profile_rejects_relative(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})
        assert maintenance._within_profile("Microsoft\\Windows\\Explorer") is False

    def test_resolved_roots_dedupes_and_confines(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})
        inside = str(tmp_path / "Temp")
        os.makedirs(inside, exist_ok=True)
        cat = {"roots": [inside, inside, "C:\\Windows\\Temp"]}  # dup + outside-profile
        roots = maintenance._resolved_roots(cat)
        assert roots == [inside]  # de-duped, and the drive-scope root dropped

    def test_tree_has_recent(self, tmp_path):
        d = str(tmp_path / "d")
        _mkfile(os.path.join(d, "old.bin"), 10, age_days=10)
        cutoff = time.time() - 86400
        assert maintenance._tree_has_recent(d, cutoff) is False
        _mkfile(os.path.join(d, "sub", "fresh.bin"), 10, age_days=0)
        assert maintenance._tree_has_recent(d, cutoff) is True


class TestScanJunk:
    @pytest.fixture(autouse=True)
    def _profile(self, tmp_path, mocker):
        # Category roots in these tests live under tmp_path, so point the
        # profile there — _resolved_roots confines cleanup to %USERPROFILE%.
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})

    def _cats(self, tmp_path):
        root = str(tmp_path / "temp")
        _mkfile(os.path.join(root, "junk.tmp"), 400, age_days=5)
        return [
            {
                "key": "user_temp",
                "label": "Temp",
                "description": "d",
                "roots": [root],
                "min_age_days": 1,
                "risk": "safe",
            },
            {
                "key": "recycle_bin",
                "label": "Recycle Bin",
                "description": "d",
                "special": "recycle_bin",
                "risk": "safe",
            },
        ]

    def test_scan_reports_totals_and_recycle_bin(self, tmp_path, mocker):
        mocker.patch("maintenance._junk_categories", return_value=self._cats(tmp_path))
        mocker.patch("maintenance._recycle_bin_info", return_value=(3, 5000))
        out = maintenance.scan_junk()
        assert out["ok"] is True
        by = {c["key"]: c for c in out["categories"]}
        assert by["user_temp"]["bytes"] == 400
        assert by["recycle_bin"]["count"] == 3 and by["recycle_bin"]["bytes"] == 5000
        assert out["total_bytes"] == 5400

    def test_recycle_bin_is_default_off(self, mocker):
        # The irreversible Recycle-Bin empty must not be pre-checked by the UI.
        mocker.patch("maintenance._recycle_bin_info", return_value=(0, 0))
        out = maintenance.scan_junk()  # real categories
        rb = next(c for c in out["categories"] if c["key"] == "recycle_bin")
        assert rb["default_off"] is True

    def test_scan_never_deletes(self, tmp_path, mocker):
        cats = self._cats(tmp_path)
        mocker.patch("maintenance._junk_categories", return_value=cats)
        mocker.patch("maintenance._recycle_bin_info", return_value=(0, 0))
        maintenance.scan_junk()
        assert os.path.exists(os.path.join(cats[0]["roots"][0], "junk.tmp"))  # still there


class TestCleanJunk:
    @pytest.fixture(autouse=True)
    def _profile(self, tmp_path, mocker):
        mocker.patch.dict(os.environ, {"USERPROFILE": str(tmp_path)})

    def test_safe_category_deletes_permanently(self, tmp_path, mocker):
        root = str(tmp_path / "t")
        f = _mkfile(os.path.join(root, "a.tmp"), 300, age_days=5)
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[
                {
                    "key": "user_temp",
                    "label": "Temp",
                    "description": "d",
                    "roots": [root],
                    "min_age_days": 1,
                    "risk": "safe",
                }
            ],
        )
        out = maintenance.clean_junk(["user_temp"])
        assert out["total_freed"] == 300
        assert out["cleaned"][0]["removed"] == 1
        assert not os.path.exists(f)

    def test_min_age_protects_recent_files(self, tmp_path, mocker):
        root = str(tmp_path / "t")
        recent = _mkfile(os.path.join(root, "fresh.tmp"), 300, age_days=0)
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[
                {
                    "key": "user_temp",
                    "label": "Temp",
                    "description": "d",
                    "roots": [root],
                    "min_age_days": 1,
                    "risk": "safe",
                }
            ],
        )
        out = maintenance.clean_junk(["user_temp"])
        assert out["total_freed"] == 0
        assert os.path.exists(recent)  # in-use / recent file untouched

    def test_caution_category_goes_to_recycle_bin(self, tmp_path, mocker):
        root = str(tmp_path / "cache")
        f = _mkfile(os.path.join(root, "c.tmp"), 200)
        spy = mocker.patch("maintenance._send_to_recycle_bin", return_value=True)
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[{"key": "bcache", "label": "Cache", "description": "d", "roots": [root], "risk": "caution"}],
        )
        out = maintenance.clean_junk(["bcache"])
        spy.assert_called_once_with(f)  # recycle bin, not permanent
        assert out["cleaned"][0]["removed"] == 1

    def test_unknown_key_is_ignored(self, tmp_path, mocker):
        root = str(tmp_path / "t")
        f = _mkfile(os.path.join(root, "a.tmp"), 100)
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[{"key": "user_temp", "label": "Temp", "description": "d", "roots": [root], "risk": "safe"}],
        )
        out = maintenance.clean_junk(["definitely_not_a_category"])
        assert out["cleaned"] == []
        assert out["total_freed"] == 0
        assert os.path.exists(f)  # nothing touched

    def test_old_dir_with_fresh_file_is_protected(self, tmp_path, mocker):
        # A temp working dir created long ago but holding a fresh (in-use) file
        # must NOT be deleted wholesale by a min-age category.
        root = str(tmp_path / "t")
        d = os.path.join(root, "installer_work")
        _mkfile(os.path.join(d, "payload.bin"), 500, age_days=0)  # fresh file
        old = time.time() - 10 * 86400
        os.utime(d, (old, old))  # dir itself is old
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[
                {
                    "key": "user_temp",
                    "label": "Temp",
                    "description": "d",
                    "roots": [root],
                    "min_age_days": 1,
                    "risk": "safe",
                }
            ],
        )
        out = maintenance.clean_junk(["user_temp"])
        assert out["total_freed"] == 0
        assert os.path.exists(os.path.join(d, "payload.bin"))  # live data untouched

    def test_reparse_dir_is_skipped(self, tmp_path, mocker):
        root = str(tmp_path / "t")
        d = os.path.join(root, "junction")
        _mkfile(os.path.join(d, "x.tmp"), 100, age_days=5)
        mocker.patch("maintenance._is_reparse", return_value=True)  # treat as a junction
        deleter = mocker.patch("maintenance._delete_entry")
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[{"key": "user_temp", "label": "Temp", "description": "d", "roots": [root], "risk": "safe"}],
        )
        out = maintenance.clean_junk(["user_temp"])
        deleter.assert_not_called()  # never delete through a reparse point
        assert out["total_freed"] == 0

    def test_root_outside_profile_is_ignored(self, tmp_path, mocker):
        # A category root not under %USERPROFILE% must be skipped entirely.
        prof = tmp_path / "profile"
        prof.mkdir()
        outside = str(tmp_path / "elsewhere")  # under tmp_path but NOT under the profile
        f = _mkfile(os.path.join(outside, "a.tmp"), 100, age_days=5)
        mocker.patch.dict(os.environ, {"USERPROFILE": str(prof)})
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[
                {"key": "user_temp", "label": "Temp", "description": "d", "roots": [outside], "risk": "safe"}
            ],
        )
        out = maintenance.clean_junk(["user_temp"])
        assert out["total_freed"] == 0
        assert os.path.exists(f)  # confinement held

    def test_recycle_bin_special_uses_empty(self, mocker):
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[
                {
                    "key": "recycle_bin",
                    "label": "Recycle Bin",
                    "description": "d",
                    "special": "recycle_bin",
                    "risk": "safe",
                }
            ],
        )
        empty = mocker.patch("maintenance._empty_recycle_bin", return_value=(4096, True))
        out = maintenance.clean_junk(["recycle_bin"])
        empty.assert_called_once()
        assert out["total_freed"] == 4096

    def test_delete_failure_counts_as_error(self, tmp_path, mocker):
        root = str(tmp_path / "t")
        _mkfile(os.path.join(root, "a.tmp"), 100)
        mocker.patch("maintenance._delete_entry", return_value=False)  # simulate locked file
        mocker.patch(
            "maintenance._junk_categories",
            return_value=[{"key": "user_temp", "label": "Temp", "description": "d", "roots": [root], "risk": "safe"}],
        )
        out = maintenance.clean_junk(["user_temp"])
        assert out["cleaned"][0]["errors"] == 1
        assert out["cleaned"][0]["removed"] == 0


class TestScanAsync:
    """The scan is non-blocking: a background thread does the walk and the route
    reports running/done so a slow %TEMP% never ties up a worker thread."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        # Module-global scan cache — reset around each test.
        maintenance._scan_state.update({"running": False, "result": None, "ts": 0.0})
        yield
        maintenance._scan_state.update({"running": False, "result": None, "ts": 0.0})

    def test_first_call_starts_background_scan(self, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        out = maintenance.start_or_get_scan()
        assert out["status"] == "running"
        thread.assert_called_once()  # spawned a worker, did not block
        assert thread.call_args.kwargs.get("daemon") is True

    def test_running_returns_running_without_respawn(self, mocker):
        maintenance._scan_state["running"] = True
        thread = mocker.patch("maintenance.threading.Thread")
        out = maintenance.start_or_get_scan()
        assert out["status"] == "running"
        thread.assert_not_called()  # single-flight

    def test_fresh_cache_returns_done(self, mocker):
        maintenance._scan_state.update(
            {"running": False, "result": {"ok": True, "categories": [], "total_human": "1 GB"}, "ts": time.time()}
        )
        thread = mocker.patch("maintenance.threading.Thread")
        out = maintenance.start_or_get_scan()
        assert out["status"] == "done" and out["total_human"] == "1 GB"
        thread.assert_not_called()  # served from cache

    def test_force_rescans_even_when_cached(self, mocker):
        maintenance._scan_state.update({"running": False, "result": {"ok": True, "categories": []}, "ts": time.time()})
        thread = mocker.patch("maintenance.threading.Thread")
        out = maintenance.start_or_get_scan(force=True)
        assert out["status"] == "running"
        thread.assert_called_once()

    def test_worker_stores_result_and_clears_running(self, mocker):
        maintenance._scan_state["running"] = True
        mocker.patch("maintenance.scan_junk", return_value={"ok": True, "categories": [], "total_human": "0 B"})
        maintenance._run_scan()
        assert maintenance._scan_state["running"] is False
        assert maintenance._scan_state["result"]["ok"] is True

    def test_worker_scan_exception_clears_running_and_reports_error(self, mocker):
        # A scan failure inside the worker must surface ok:False and never
        # leave the flag stuck True (which would wedge the tab forever).
        maintenance._scan_state["running"] = True
        mocker.patch("maintenance.scan_junk", side_effect=OSError("disk gone"))
        maintenance._run_scan()
        assert maintenance._scan_state["running"] is False
        assert maintenance._scan_state["result"]["ok"] is False
        assert "disk gone" in maintenance._scan_state["result"]["error"]

    def test_thread_start_failure_rolls_back_running(self, mocker):
        # If the OS refuses a new thread, running must roll back so the next
        # (force) call can recover instead of returning running forever.
        mocker.patch("maintenance.threading.Thread", side_effect=RuntimeError("can't start thread"))
        out = maintenance.start_or_get_scan()
        assert out["ok"] is False
        assert out["status"] == "error"
        assert maintenance._scan_state["running"] is False


class TestRoutes:
    @pytest.fixture(autouse=True)
    def _reset(self):
        maintenance._scan_state.update({"running": False, "result": None, "ts": 0.0})

    def test_scan_route_is_nonblocking(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/junk/scan")
        assert r.status_code == 200
        assert r.get_json()["status"] == "running"  # returns immediately, scan runs in a thread
        thread.assert_called_once()

    def test_scan_route_refresh_forces(self, client, mocker):
        maintenance._scan_state.update({"running": False, "result": {"ok": True, "categories": []}, "ts": time.time()})
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/junk/scan?refresh=1")
        assert r.get_json()["status"] == "running"
        thread.assert_called_once()  # forced despite the warm cache

    def test_clean_localhost_only(self, client, mocker):
        clean = mocker.patch("maintenance.clean_junk")
        r = client.post(
            "/api/maintenance/junk/clean", json={"keys": ["user_temp"]}, environ_base={"REMOTE_ADDR": "10.0.0.5"}
        )
        assert r.status_code == 403
        clean.assert_not_called()

    def test_clean_requires_keys(self, client, mocker):
        clean = mocker.patch("maintenance.clean_junk")
        r = client.post("/api/maintenance/junk/clean", json={}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert r.status_code == 400
        clean.assert_not_called()

    def test_clean_rejects_non_list_keys(self, client, mocker):
        clean = mocker.patch("maintenance.clean_junk")
        r = client.post(
            "/api/maintenance/junk/clean", json={"keys": "user_temp"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        assert r.status_code == 400
        clean.assert_not_called()

    def test_clean_invokes_cleaner(self, client, mocker):
        clean = mocker.patch(
            "maintenance.clean_junk", return_value={"ok": True, "cleaned": [], "total_freed": 0, "total_human": "0 B"}
        )
        r = client.post(
            "/api/maintenance/junk/clean", json={"keys": ["user_temp"]}, environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        assert r.status_code == 200
        clean.assert_called_once_with(["user_temp"])


# ── Tier 2: space analysis (read-only) ────────────────────────────────────────


def _mkbin(path, blob):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(blob)
    return path


def _raise(exc):
    raise exc


class TestWalkFiles:
    def test_yields_files_recursively_not_dirs(self, tmp_path):
        _mkfile(str(tmp_path / "a.bin"), 10)
        _mkfile(str(tmp_path / "sub" / "b.bin"), 20)
        budget = maintenance._new_budget()
        got = {os.path.basename(p): s for p, s in maintenance._walk_files(str(tmp_path), budget)}
        assert got == {"a.bin": 10, "b.bin": 20}
        assert budget["files"] == 2
        assert budget["truncated"] is False

    def test_file_cap_truncates(self, tmp_path):
        for i in range(5):
            _mkfile(str(tmp_path / f"f{i}.bin"), 10)
        budget = maintenance._new_budget(max_files=2)
        out = list(maintenance._walk_files(str(tmp_path), budget))
        assert len(out) <= 3  # stops at/just past the cap, never walks all 5
        assert budget["truncated"] is True

    def test_time_budget_truncates(self, tmp_path):
        _mkfile(str(tmp_path / "a.bin"), 10)
        budget = maintenance._new_budget(seconds=-1)  # already expired
        assert list(maintenance._walk_files(str(tmp_path), budget)) == []
        assert budget["truncated"] is True

    def test_unreadable_dir_is_skipped_not_fatal(self, tmp_path, mocker):
        _mkfile(str(tmp_path / "a.bin"), 10)
        mocker.patch("maintenance.os.scandir", side_effect=OSError("denied"))
        budget = maintenance._new_budget()
        assert list(maintenance._walk_files(str(tmp_path), budget)) == []

    def test_reparse_points_are_never_followed(self, tmp_path, mocker):
        _mkfile(str(tmp_path / "a.bin"), 10)
        mocker.patch("maintenance._is_reparse", return_value=True)
        budget = maintenance._new_budget()
        assert list(maintenance._walk_files(str(tmp_path), budget)) == []


class TestScanLargeFiles:
    def test_ranks_biggest_first(self, tmp_path, mocker):
        mocker.patch.object(maintenance, "_BIGFILE_MIN_BYTES", 0)
        for name, size in [("small.bin", 10), ("big.bin", 900), ("mid.bin", 500)]:
            _mkfile(str(tmp_path / name), size)
        out = maintenance.scan_large_files(str(tmp_path), top_n=5)
        assert out["ok"] is True
        assert [f["name"] for f in out["files"]] == ["big.bin", "mid.bin", "small.bin"]
        assert out["total_bytes"] == 1410

    def test_top_n_keeps_only_the_largest(self, tmp_path, mocker):
        mocker.patch.object(maintenance, "_BIGFILE_MIN_BYTES", 0)
        for i in range(10):
            _mkfile(str(tmp_path / f"f{i}.bin"), 100 + i)
        out = maintenance.scan_large_files(str(tmp_path), top_n=5)
        assert len(out["files"]) == 5
        assert out["files"][0]["bytes"] == 109  # biggest survives the min-heap

    def test_files_below_threshold_are_ignored(self, tmp_path):
        _mkfile(str(tmp_path / "tiny.bin"), 100)
        out = maintenance.scan_large_files(str(tmp_path))
        assert out["files"] == []
        assert out["scanned"] == 1  # walked it, just did not report it

    def test_top_n_is_clamped(self, tmp_path):
        assert maintenance.scan_large_files(str(tmp_path), top_n=99999)["ok"] is True
        assert maintenance.scan_large_files(str(tmp_path), top_n=0)["ok"] is True

    def test_invalid_root_returns_error_not_raise(self):
        out = maintenance.scan_large_files(r"\\server\share")
        assert out["ok"] is False
        assert out["files"] == []
        assert "error" in out

    def test_row_carries_path_and_dir(self, tmp_path, mocker):
        mocker.patch.object(maintenance, "_BIGFILE_MIN_BYTES", 0)
        p = _mkfile(str(tmp_path / "sub" / "x.bin"), 50)
        row = maintenance.scan_large_files(str(tmp_path))["files"][0]
        assert row["path"] == p
        assert row["dir"] == os.path.dirname(p)
        assert row["name"] == "x.bin"


class TestHashFile:
    def test_full_hash_matches_for_identical_content(self, tmp_path):
        a = _mkbin(str(tmp_path / "a"), b"hello world" * 100)
        b = _mkbin(str(tmp_path / "b"), b"hello world" * 100)
        assert maintenance._hash_file(a) == maintenance._hash_file(b)

    def test_differing_content_differs(self, tmp_path):
        a = _mkbin(str(tmp_path / "a"), b"A" * 500)
        b = _mkbin(str(tmp_path / "b"), b"B" * 500)
        assert maintenance._hash_file(a) != maintenance._hash_file(b)

    def test_limit_reads_only_the_head(self, tmp_path):
        # Same first 16 bytes, different tails -> equal partial, different full.
        a = _mkbin(str(tmp_path / "a"), b"same-head-1234567" + b"A" * 500)
        b = _mkbin(str(tmp_path / "b"), b"same-head-1234567" + b"B" * 500)
        assert maintenance._hash_file(a, limit=16) == maintenance._hash_file(b, limit=16)
        assert maintenance._hash_file(a) != maintenance._hash_file(b)

    def test_unreadable_returns_empty_string(self, tmp_path):
        assert maintenance._hash_file(str(tmp_path / "nope.bin")) == ""


class TestFindDuplicates:
    def test_finds_identical_files(self, tmp_path):
        blob = b"D" * 5000
        _mkbin(str(tmp_path / "a.bin"), blob)
        _mkbin(str(tmp_path / "sub" / "b.bin"), blob)
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert out["ok"] is True
        assert out["group_count"] == 1
        g = out["groups"][0]
        assert g["count"] == 2
        assert g["wasted_bytes"] == 5000  # one copy is the keeper
        assert sorted(f["name"] for f in g["files"]) == ["a.bin", "b.bin"]

    def test_same_size_different_content_is_not_a_duplicate(self, tmp_path):
        # The bug this guards: grouping by size alone would call these dupes.
        _mkbin(str(tmp_path / "a.bin"), b"A" * 5000)
        _mkbin(str(tmp_path / "b.bin"), b"B" * 5000)
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert out["group_count"] == 0
        assert out["total_wasted_bytes"] == 0

    def test_files_larger_than_partial_window_are_fully_confirmed(self, tmp_path, mocker):
        # Identical heads, different tails, size > partial window: must NOT group.
        mocker.patch.object(maintenance, "_PARTIAL_HASH_BYTES", 16)
        _mkbin(str(tmp_path / "a.bin"), b"same-head-1234567" + b"A" * 5000)
        _mkbin(str(tmp_path / "b.bin"), b"same-head-1234567" + b"B" * 5000)
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert out["group_count"] == 0

    def test_small_files_below_min_bytes_ignored(self, tmp_path):
        blob = b"x" * 100
        _mkbin(str(tmp_path / "a.bin"), blob)
        _mkbin(str(tmp_path / "b.bin"), blob)
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert out["group_count"] == 0

    def test_three_copies_waste_two_copies_worth(self, tmp_path):
        blob = b"T" * 4096
        for n in ("a.bin", "b.bin", "c.bin"):
            _mkbin(str(tmp_path / n), blob)
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert out["groups"][0]["count"] == 3
        assert out["groups"][0]["wasted_bytes"] == 8192

    def test_min_bytes_has_a_floor(self, tmp_path):
        out = maintenance.find_duplicates(str(tmp_path), min_bytes=1)
        assert out["min_bytes"] >= 4096  # never degenerates into hashing everything

    def test_invalid_root_returns_error_not_raise(self):
        out = maintenance.find_duplicates(r"\\server\share")
        assert out["ok"] is False
        assert out["groups"] == []

    def test_reports_only_never_deletes(self, tmp_path):
        blob = b"K" * 5000
        a = _mkbin(str(tmp_path / "a.bin"), blob)
        b = _mkbin(str(tmp_path / "b.bin"), blob)
        maintenance.find_duplicates(str(tmp_path), min_bytes=1024)
        assert os.path.exists(a) and os.path.exists(b)  # analysis is read-only


class TestGenericScanRegistry:
    @pytest.fixture(autouse=True)
    def _reset(self):
        maintenance._scans.pop("unit", None)
        yield
        maintenance._scans.pop("unit", None)

    def test_keys_are_isolated(self, mocker):
        mocker.patch("maintenance.threading.Thread")
        maintenance.start_or_get("unit", lambda: {"ok": True})
        assert maintenance._scans["unit"]["running"] is True
        assert maintenance._scans["junk"]["running"] is False  # untouched

    def test_worker_caches_under_its_own_key(self):
        maintenance._scan_worker("unit", lambda: {"ok": True, "v": 1})
        assert maintenance._scans["unit"]["result"]["v"] == 1
        assert maintenance._scans["unit"]["running"] is False

    def test_worker_exception_is_captured(self):
        maintenance._scan_worker("unit", lambda: _raise(OSError("boom")))
        assert maintenance._scans["unit"]["result"]["ok"] is False
        assert "boom" in maintenance._scans["unit"]["result"]["error"]
        assert maintenance._scans["unit"]["running"] is False

    def test_thread_start_failure_rolls_back(self, mocker):
        mocker.patch("maintenance.threading.Thread", side_effect=RuntimeError("nope"))
        out = maintenance.start_or_get("unit", lambda: {"ok": True})
        assert out["ok"] is False and out["status"] == "error"
        assert maintenance._scans["unit"]["running"] is False

    def test_failed_result_is_not_served_as_fresh(self, mocker):
        maintenance._scans["unit"] = {"running": False, "result": {"ok": False}, "ts": time.time()}
        thread = mocker.patch("maintenance.threading.Thread")
        out = maintenance.start_or_get("unit", lambda: {"ok": True})
        assert out["status"] == "running"
        thread.assert_called_once()  # retried rather than serving the stale error


class TestSpaceRoutes:
    @pytest.fixture(autouse=True)
    def _reset(self):
        for k in [k for k in maintenance._scans if k != "junk"]:
            maintenance._scans.pop(k)
        yield

    def test_large_files_route_is_nonblocking(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/space/large-files")
        assert r.status_code == 200
        assert r.get_json()["status"] == "running"
        thread.assert_called_once()

    def test_duplicates_route_is_nonblocking(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/space/duplicates")
        assert r.status_code == 200
        assert r.get_json()["status"] == "running"
        thread.assert_called_once()

    def test_different_roots_do_not_share_a_cache_entry(self, client, mocker):
        mocker.patch("maintenance.threading.Thread")
        client.get("/api/maintenance/space/large-files?root=C:\\Users")
        client.get("/api/maintenance/space/large-files?root=C:\\Windows")
        keys = [k for k in maintenance._scans if k.startswith("large_files:")]
        assert len(keys) == 2  # a scan of one root is never served for another

    def test_top_n_is_part_of_the_cache_key(self, client, mocker):
        mocker.patch("maintenance.threading.Thread")
        client.get("/api/maintenance/space/large-files?top_n=10")
        client.get("/api/maintenance/space/large-files?top_n=50")
        assert len({k for k in maintenance._scans if k.startswith("large_files:")}) == 2

    def test_default_root_is_the_user_profile(self):
        assert maintenance.default_scan_root() == os.path.expandvars("%USERPROFILE%")

    def test_done_result_is_returned_when_cached(self, client):
        key = f"large_files:{os.path.normcase(maintenance.default_scan_root())}:40"
        maintenance._scans[key] = {"running": False, "result": {"ok": True, "files": []}, "ts": time.time()}
        r = client.get("/api/maintenance/space/large-files")
        assert r.get_json()["status"] == "done"


class TestWalkClockGranularity:
    def test_clock_is_rechecked_inside_one_large_directory(self, tmp_path, mocker):
        """The deadline must be re-checked every _CLOCK_EVERY files, not every
        few thousand. On slow media a single stat() can cost ~100ms, so a coarse
        interval would overshoot the time budget by minutes and outlive the UI's
        poll window."""
        for i in range(_CLOCK_EVERY_TEST_FILES):
            _mkfile(str(tmp_path / f"f{i}.bin"), 1)
        # monotonic: call 1 builds the deadline, call 2 is the outer while check
        # (still inside budget), every later call is far past it — so the walk
        # must stop at the first in-directory clock check.
        seq = iter([0.0, 0.0] + [10_000.0] * 100_000)
        mocker.patch("maintenance.time.monotonic", side_effect=lambda: next(seq))
        budget = maintenance._new_budget(seconds=1)
        out = list(maintenance._walk_files(str(tmp_path), budget))
        assert len(out) == maintenance._CLOCK_EVERY
        assert budget["truncated"] is True


class TestRegistryEviction:
    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        for k in [k for k in maintenance._scans if k != "junk"]:
            maintenance._scans.pop(k)

    def test_registry_is_bounded(self):
        for i in range(maintenance._SCANS_MAX + 20):
            maintenance._scans[f"x{i}"] = {"running": False, "result": {"ok": True}, "ts": float(i)}
        with maintenance._scans_lock:
            maintenance._evict_stale()
        assert len(maintenance._scans) <= maintenance._SCANS_MAX

    def test_oldest_go_first(self):
        for i in range(maintenance._SCANS_MAX + 5):
            maintenance._scans[f"x{i}"] = {"running": False, "result": {"ok": True}, "ts": float(i)}
        with maintenance._scans_lock:
            maintenance._evict_stale()
        assert "x0" not in maintenance._scans  # oldest evicted
        assert f"x{maintenance._SCANS_MAX + 4}" in maintenance._scans  # newest kept

    def test_running_scans_are_never_evicted(self):
        maintenance._scans["busy"] = {"running": True, "result": None, "ts": 0.0}
        for i in range(maintenance._SCANS_MAX + 20):
            maintenance._scans[f"x{i}"] = {"running": False, "result": {"ok": True}, "ts": float(i + 1)}
        with maintenance._scans_lock:
            maintenance._evict_stale()
        assert maintenance._scans["busy"]["running"] is True  # its worker still needs the slot

    def test_junk_slot_survives_and_keeps_its_identity(self):
        junk = maintenance._scans["junk"]
        for i in range(maintenance._SCANS_MAX + 20):
            maintenance._scans[f"x{i}"] = {"running": False, "result": {"ok": True}, "ts": float(i + 1)}
        with maintenance._scans_lock:
            maintenance._evict_stale()
        assert "junk" in maintenance._scans
        # The legacy _scan_state alias must still point at the live slot.
        assert maintenance._scans["junk"] is junk
        assert maintenance._scan_state is maintenance._scans["junk"]


class TestSpaceCacheKeys:
    @pytest.fixture(autouse=True)
    def _reset(self):
        for k in [k for k in maintenance._scans if k != "junk"]:
            maintenance._scans.pop(k)
        yield
        for k in [k for k in maintenance._scans if k != "junk"]:
            maintenance._scans.pop(k)

    def _keys(self, prefix):
        return {k for k in maintenance._scans if k.startswith(prefix)}

    def test_out_of_range_top_n_values_share_one_entry(self, client, mocker):
        # All clamp to 200, so they are the same scan and must share one slot.
        mocker.patch("maintenance.threading.Thread")
        client.get("/api/maintenance/space/large-files?top_n=201")
        client.get("/api/maintenance/space/large-files?top_n=5000")
        client.get("/api/maintenance/space/large-files?top_n=999999")
        assert len(self._keys("large_files:")) == 1

    def test_equivalent_root_spellings_share_one_entry(self, client, mocker):
        mocker.patch("maintenance.threading.Thread")
        prof = maintenance.default_scan_root()
        client.get("/api/maintenance/space/large-files?root=" + prof)
        client.get("/api/maintenance/space/large-files?root=" + prof + "\\")
        client.get("/api/maintenance/space/large-files?root=" + prof.replace("\\", "/"))
        assert len(self._keys("large_files:")) == 1

    def test_out_of_range_min_bytes_share_one_entry(self, client, mocker):
        mocker.patch("maintenance.threading.Thread")
        client.get("/api/maintenance/space/duplicates?min_bytes=1")
        client.get("/api/maintenance/space/duplicates?min_bytes=100")
        assert len(self._keys("duplicates:")) == 1  # both clamp to the 4096 floor

    def test_genuinely_different_roots_still_split(self, client, mocker):
        mocker.patch("maintenance.threading.Thread")
        client.get("/api/maintenance/space/large-files?root=C:\\Users")
        client.get("/api/maintenance/space/large-files?root=C:\\Windows")
        assert len(self._keys("large_files:")) == 2

    def test_invalid_root_is_rejected_without_starting_a_scan(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/space/large-files?root=" + quote(r"\\server\share"))
        assert r.status_code == 422
        assert r.get_json()["ok"] is False
        thread.assert_not_called()  # fails fast rather than spawning a doomed scan
        assert self._keys("large_files:") == set()  # and leaves no registry entry

    def test_invalid_root_rejected_for_duplicates_too(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/space/duplicates?root=" + quote("Z:\\nope\\missing"))
        assert r.status_code == 422
        thread.assert_not_called()


# ── Tier 3: system maintenance (read-only status + hand-offs) ─────────────────

_FSUTIL_MODERN = (
    "NTFS DisableDeleteNotify = 0  (Allows TRIM operations to be sent to the storage device)\r\n"
    "ReFS DisableDeleteNotify = 0  (Allows TRIM operations to be sent to the storage device)\r\n"
)
_FSUTIL_LEGACY = "DisableDeleteNotify = 0\r\n"
_FSUTIL_OFF = (
    "NTFS DisableDeleteNotify = 1  (Disables TRIM operations)\r\n"
    "ReFS DisableDeleteNotify = 1  (Disables TRIM operations)\r\n"
)


def _fsutil(mocker, stdout="", stderr="", rc=0):
    m = mocker.patch("maintenance.subprocess.run")
    m.return_value.stdout = stdout
    m.return_value.stderr = stderr
    m.return_value.returncode = rc
    return m


class TestParseTrim:
    def test_modern_two_filesystem_output(self):
        rows = maintenance._parse_trim(_FSUTIL_MODERN)
        assert [r["filesystem"] for r in rows] == ["NTFS", "ReFS"]
        assert all(r["enabled"] is True for r in rows)

    def test_legacy_unlabelled_output_defaults_to_ntfs(self):
        rows = maintenance._parse_trim(_FSUTIL_LEGACY)
        assert len(rows) == 1
        assert rows[0]["filesystem"] == "NTFS"
        assert rows[0]["enabled"] is True

    def test_value_one_means_disabled(self):
        rows = maintenance._parse_trim(_FSUTIL_OFF)
        assert all(r["enabled"] is False for r in rows)

    def test_unexpected_value_is_unknown_not_guessed(self):
        # 2 is neither on nor off — we must not pretend to know.
        rows = maintenance._parse_trim("NTFS DisableDeleteNotify = 2\r\n")
        assert rows[0]["enabled"] is None

    def test_garbage_yields_no_rows(self):
        assert maintenance._parse_trim("not fsutil output at all") == []

    def test_empty_input_is_safe(self):
        assert maintenance._parse_trim("") == []
        assert maintenance._parse_trim(None) == []


class TestTrimStatus:
    def test_happy_path(self, mocker):
        _fsutil(mocker, stdout=_FSUTIL_MODERN)
        out = maintenance._trim_status()
        assert out["known"] is True
        assert out["enabled"] is True
        assert len(out["filesystems"]) == 2

    def test_disabled_reported(self, mocker):
        _fsutil(mocker, stdout=_FSUTIL_OFF)
        assert maintenance._trim_status()["enabled"] is False

    def test_mixed_is_not_reported_as_enabled(self, mocker):
        _fsutil(mocker, stdout="NTFS DisableDeleteNotify = 0\r\nReFS DisableDeleteNotify = 1\r\n")
        assert maintenance._trim_status()["enabled"] is False

    def test_empty_output_is_unknown_not_crash(self, mocker):
        _fsutil(mocker, stdout="   ")
        out = maintenance._trim_status()
        assert out["known"] is False
        assert "detail" in out

    def test_malformed_output_is_unknown(self, mocker):
        _fsutil(mocker, stdout="???")
        assert maintenance._trim_status()["known"] is False

    def test_nonzero_returncode_with_stderr(self, mocker):
        _fsutil(mocker, stdout="", stderr="Access is denied", rc=1)
        out = maintenance._trim_status()
        assert out["known"] is False
        assert "denied" in out["detail"].lower()

    def test_timeout_returns_unknown(self, mocker):
        mocker.patch(
            "maintenance.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="fsutil", timeout=15),
        )
        assert maintenance._trim_status()["known"] is False

    def test_command_content(self, mocker):
        m = _fsutil(mocker, stdout=_FSUTIL_MODERN)
        maintenance._trim_status()
        argv = m.call_args[0][0]
        assert argv[:4] == ["fsutil", "behavior", "query", "DisableDeleteNotify"]


class TestSummarizeOptimize:
    def _task(self, **kw):
        base = {
            "name": "ScheduledDefrag",
            "enabled": True,
            "last_run": "2026-09-06T21:05:54+00:00",
            "last_run_dt": datetime(2026, 9, 6, 21, 5, 54, tzinfo=timezone.utc),
            "result": 0,
        }
        base.update(kw)
        return base

    def test_no_tasks_is_unknown(self):
        out = maintenance._summarize_optimize([])
        assert out["known"] is False

    def test_recent_success_is_not_stale(self):
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        out = maintenance._summarize_optimize([self._task()], now=now)
        assert out["known"] is True
        assert out["days_ago"] == 3
        assert out["succeeded"] is True
        assert out["stale"] is False

    def test_old_run_is_stale(self):
        now = datetime(2026, 12, 1, tzinfo=timezone.utc)
        out = maintenance._summarize_optimize([self._task()], now=now)
        assert out["stale"] is True
        assert out["days_ago"] > 30

    def test_nonzero_result_is_a_failure(self):
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        out = maintenance._summarize_optimize([self._task(result=1)], now=now)
        assert out["succeeded"] is False
        assert out["result_hex"] == "0x1"

    def test_negative_result_formats_as_unsigned_hex(self):
        # Task Scheduler reports HRESULTs that arrive as negative ints.
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        out = maintenance._summarize_optimize([self._task(result=-2147024894)], now=now)
        assert out["result_hex"] == "0x80070002"
        assert out["succeeded"] is False

    def test_naive_timestamp_is_handled(self):
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        task = self._task(last_run_dt=datetime(2026, 9, 6, 21, 5, 54))
        out = maintenance._summarize_optimize([task], now=now)
        assert out["days_ago"] == 3

    def test_missing_timestamp_does_not_crash(self):
        out = maintenance._summarize_optimize([self._task(last_run_dt=None)])
        assert out["known"] is True
        assert out["days_ago"] is None
        assert out["stale"] is False  # unknown age is not asserted as stale

    def test_disabled_schedule_reported(self):
        now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        out = maintenance._summarize_optimize([self._task(enabled=False)], now=now)
        assert out["enabled"] is False


class _FakeTask:
    def __init__(self, name="ScheduledDefrag", enabled=True, last=None, result=0):
        self.Name = name
        self.Enabled = enabled
        self.LastRunTime = last if last is not None else datetime(2026, 9, 6, 21, 5, 54, tzinfo=timezone.utc)
        self.LastTaskResult = result


class _FakeFolder:
    def __init__(self, tasks):
        self._tasks = tasks

    def GetTasks(self, flags):  # noqa: N802 -- mirrors the COM API
        return self._tasks


class _FakeSvc:
    def __init__(self, tasks, expect_path=r"\Microsoft\Windows\Defrag"):
        self._tasks = tasks
        self._expect = expect_path
        self.connected = False

    def Connect(self):  # noqa: N802 -- mirrors the COM API
        self.connected = True

    def GetFolder(self, path):  # noqa: N802 -- mirrors the COM API
        assert path == self._expect
        return _FakeFolder(self._tasks)


class _FakeClient:
    def __init__(self, tasks):
        self.svc = _FakeSvc(tasks)

    def Dispatch(self, progid):  # noqa: N802 -- mirrors the COM API
        assert progid == "Schedule.Service"
        return self.svc


class TestReadDefragTasks:
    def test_parses_task_fields(self):
        client = _FakeClient([_FakeTask()])
        rows = maintenance._read_defrag_tasks(client)
        assert len(rows) == 1
        row = rows[0]
        assert row["name"] == "ScheduledDefrag"
        assert row["enabled"] is True
        assert row["result"] == 0
        assert row["last_run"] == "2026-09-06T21:05:54+00:00"
        assert row["last_run_dt"].year == 2026
        assert client.svc.connected is True  # Connect() is required before use

    def test_missing_last_run_becomes_none(self):
        rows = maintenance._read_defrag_tasks(_FakeClient([_FakeTask(last=False)]))
        assert rows[0]["last_run"] is None

    def test_multiple_tasks_all_returned(self):
        rows = maintenance._read_defrag_tasks(_FakeClient([_FakeTask(), _FakeTask(name="Other", result=1)]))
        assert [r["name"] for r in rows] == ["ScheduledDefrag", "Other"]
        assert rows[1]["result"] == 1


class TestDefragThreadContext:
    def test_works_from_a_worker_thread_not_just_main(self):
        """Regression: COM Dispatch() raises 'CoInitialize has not been called'
        on a fresh thread, so without pythoncom.CoInitialize() this reported
        Unknown on EVERY real Flask request while still passing a main-thread
        hand check. The invariant is that thread context must not change the
        answer — machine-independent, since both sides are empty on a box with
        no Defrag task."""
        main = maintenance._defrag_tasks()
        box = {}

        def worker():
            box["result"] = maintenance._defrag_tasks()

        th = threading.Thread(target=worker)
        th.start()
        th.join(timeout=30)
        assert "result" in box, "worker thread did not finish"
        assert bool(box["result"]) == bool(main), (
            "drive-optimization read differs between main and worker thread — COM apartment not initialised"
        )

    def test_status_is_known_on_a_worker_thread(self):
        # Only assert the verdict when this machine actually exposes the task,
        # so the test stays honest on a box that has none.
        if not maintenance._defrag_tasks():
            pytest.skip("no scheduled Defrag task on this machine")
        box = {}
        th = threading.Thread(target=lambda: box.update(s=maintenance._summarize_optimize(maintenance._defrag_tasks())))
        th.start()
        th.join(timeout=30)
        assert box["s"]["known"] is True


class TestDefragTasks:
    def test_missing_pywin32_returns_empty(self, mocker):
        import builtins

        real = builtins.__import__

        def fake(name, *a, **kw):
            if name == "win32com.client":
                raise ImportError("no pywin32")
            return real(name, *a, **kw)

        mocker.patch.object(builtins, "__import__", side_effect=fake)
        assert maintenance._defrag_tasks() == []

    def test_com_failure_degrades_quietly(self, mocker):
        mocker.patch("win32com.client.Dispatch", side_effect=OSError("COM down"))
        assert maintenance._defrag_tasks() == []


class TestPendingReboot:
    def test_no_signals_means_no_reboot(self, mocker):
        mocker.patch("maintenance._reboot_signal_set", return_value=False)
        out = maintenance._pending_reboot()
        assert out["required"] is False
        assert out["soft_only"] is False
        assert len(out["signals"]) == 3

    def test_strong_signal_requires_reboot(self, mocker):
        mocker.patch(
            "maintenance._reboot_signal_set",
            side_effect=lambda sig: sig["key"] == "component_servicing",
        )
        out = maintenance._pending_reboot()
        assert out["required"] is True
        assert out["soft_only"] is False

    def test_soft_signal_alone_does_not_require_reboot(self, mocker):
        # PendingFileRenameOperations is set on plenty of healthy machines —
        # letting it claim "restart needed" would cry wolf.
        mocker.patch(
            "maintenance._reboot_signal_set",
            side_effect=lambda sig: sig["key"] == "pending_file_rename",
        )
        out = maintenance._pending_reboot()
        assert out["required"] is False
        assert out["soft_only"] is True

    def test_missing_key_is_not_set(self, mocker):
        mocker.patch("maintenance.winreg.OpenKey", side_effect=FileNotFoundError)
        assert maintenance._reboot_signal_set(maintenance._REBOOT_SIGNALS[0]) is False

    def test_permission_error_is_not_set(self, mocker):
        mocker.patch("maintenance.winreg.OpenKey", side_effect=OSError("denied"))
        assert maintenance._reboot_signal_set(maintenance._REBOOT_SIGNALS[0]) is False

    def test_key_presence_alone_is_the_signal(self, mocker):
        mocker.patch("maintenance.winreg.OpenKey", mocker.MagicMock())
        sig = {"path": "x", "value": None}
        assert maintenance._reboot_signal_set(sig) is True

    def test_empty_pending_rename_array_is_not_a_signal(self, mocker):
        mocker.patch("maintenance.winreg.OpenKey", mocker.MagicMock())
        mocker.patch("maintenance.winreg.QueryValueEx", return_value=(["", "  "], 7))
        sig = {"path": "x", "value": "PendingFileRenameOperations"}
        assert maintenance._reboot_signal_set(sig) is False

    def test_populated_pending_rename_is_a_signal(self, mocker):
        mocker.patch("maintenance.winreg.OpenKey", mocker.MagicMock())
        mocker.patch("maintenance.winreg.QueryValueEx", return_value=([r"\??\C:\x.dll"], 7))
        sig = {"path": "x", "value": "PendingFileRenameOperations"}
        assert maintenance._reboot_signal_set(sig) is True


class TestSystemStatus:
    def test_shape(self, mocker):
        mocker.patch("maintenance._trim_status", return_value={"known": True, "enabled": True})
        mocker.patch("maintenance._defrag_tasks", return_value=[])
        mocker.patch("maintenance._reboot_signal_set", return_value=False)
        out = maintenance.system_status()
        assert out["ok"] is True
        for key in ("trim", "optimize", "reboot", "tools"):
            assert key in out

    def test_tools_are_handoffs_only(self, mocker):
        mocker.patch("maintenance._trim_status", return_value={"known": False})
        mocker.patch("maintenance._defrag_tasks", return_value=[])
        mocker.patch("maintenance._reboot_signal_set", return_value=False)
        tools = maintenance.system_status()["tools"]
        keys = {t["key"] for t in tools}
        assert keys == {"optimize_drives", "sfc", "dism"}
        # Every tool either launches a Windows tool or shows a command to paste.
        # Nothing here executes a repair from the app.
        for t in tools:
            assert t["kind"] in ("launch", "command")
            if t["kind"] == "launch":
                assert t["tool"] in disk._CLEANUP_TOOLS  # allowlisted
            else:
                assert t["cli"]

    def test_returned_tools_are_copies(self, mocker):
        mocker.patch("maintenance._trim_status", return_value={"known": False})
        mocker.patch("maintenance._defrag_tasks", return_value=[])
        mocker.patch("maintenance._reboot_signal_set", return_value=False)
        maintenance.system_status()["tools"][0]["label"] = "MUTATED"
        assert maintenance._SYSTEM_TOOLS[0]["label"] == "Optimize Drives"


class TestSystemStatusRoute:
    def test_returns_200_and_shape(self, client, mocker):
        mocker.patch(
            "maintenance.system_status",
            return_value={"ok": True, "trim": {}, "optimize": {}, "reboot": {}, "tools": []},
        )
        r = client.get("/api/maintenance/system/status")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_live_call_does_not_raise(self, client):
        # No mocks: the real reads must degrade rather than 500 on any machine.
        r = client.get("/api/maintenance/system/status")
        assert r.status_code == 200
        d = r.get_json()
        assert d["ok"] is True
        assert {"trim", "optimize", "reboot", "tools"} <= set(d)
        # This assertion is the point: the original version of this test only
        # checked ok/keys, so it passed while the drive-optimization read was
        # dead on arrival (COM apartment) and reported Unknown forever. fsutil
        # is present on every Windows box, so requiring a real TRIM verdict is
        # portable and would have caught an equivalent regression.
        assert d["trim"]["known"] is True
        assert d["reboot"]["required"] in (True, False)


class TestDfrguiAllowlisted:
    def test_dfrgui_is_in_the_tool_allowlist(self):
        # The Optimize Drives hand-off reuses /api/disk/run-tool rather than
        # adding a second launcher route.
        assert "dfrgui" in disk._CLEANUP_TOOLS
        assert disk._CLEANUP_TOOLS["dfrgui"]["argv"] == ["dfrgui.exe"]


# ── Tier 4: registry report (read-only) ───────────────────────────────────────


class TestResolveCommandTarget:
    def test_quoted_path_with_args(self):
        path, status = maintenance._resolve_command_target('"C:\\Program Files\\App\\app.exe" -show')
        assert status == "ok"
        assert path == "C:\\Program Files\\App\\app.exe"

    def test_unquoted_path_with_spaces_and_args(self):
        path, status = maintenance._resolve_command_target(r"C:\Program Files\Foo Bar\thing.exe /AutoRun")
        assert status == "ok"
        assert path == r"C:\Program Files\Foo Bar\thing.exe"

    def test_quoted_empty_value_is_broken(self):
        # The real finding on this machine: a Run value of literally "".
        path, status = maintenance._resolve_command_target('""')
        assert status == "empty"
        assert path == ""

    def test_blank_value_is_broken(self):
        assert maintenance._resolve_command_target("")[1] == "empty"
        assert maintenance._resolve_command_target("   ")[1] == "empty"
        assert maintenance._resolve_command_target(None)[1] == "empty"

    def test_unbalanced_quote_is_unverified_not_guessed(self):
        assert maintenance._resolve_command_target('"C:\\nope\\app.exe')[1] == "unverified"

    def test_bare_host_process_is_unverified(self):
        assert maintenance._resolve_command_target("rundll32.exe foo.dll,Entry")[1] == "unverified"

    def test_fully_qualified_host_process_is_also_unverified(self):
        # The bug this guards: a startswith() check misses the qualified form,
        # so the entry resolves to rundll32.exe, which exists, and a broken
        # entry gets reported as healthy.
        path, status = maintenance._resolve_command_target(
            r"C:\Windows\system32\rundll32.exe C:\Windows\System32\LogiLDA.dll,LogiFetch"
        )
        assert status == "unverified"
        assert path == ""

    def test_quoted_host_process_is_unverified(self):
        assert maintenance._resolve_command_target('"C:\\Windows\\System32\\msiexec.exe" /X{GUID}')[1] == "unverified"

    def test_env_vars_are_expanded(self, monkeypatch):
        monkeypatch.setenv("MYAPPDIR", r"C:\Apps")
        path, status = maintenance._resolve_command_target(r"%MYAPPDIR%\run.exe")
        assert status == "ok"
        assert path == r"C:\Apps\run.exe"

    def test_unparseable_is_unverified(self):
        assert maintenance._resolve_command_target("some nonsense with no path")[1] == "unverified"


class TestHostGuard:
    def test_normal_exe_passes_through(self):
        assert maintenance._host_guard(r"C:\Apps\thing.exe") == (r"C:\Apps\thing.exe", "ok")

    def test_host_matched_case_insensitively(self):
        assert maintenance._host_guard(r"C:\Windows\System32\RUNDLL32.EXE")[1] == "unverified"

    def test_every_listed_host_is_caught(self):
        for stem in maintenance._HOST_PROCESS_STEMS:
            assert maintenance._host_guard(f"C:\\Windows\\{stem}.exe")[1] == "unverified"


class TestRegistryReaders:
    def test_missing_key_returns_empty_not_raise(self):
        assert maintenance._reg_subkeys(maintenance.winreg.HKEY_CURRENT_USER, r"Software\NoSuchKey_WDM") == []
        assert maintenance._reg_values(maintenance.winreg.HKEY_CURRENT_USER, r"Software\NoSuchKey_WDM") == []
        assert maintenance._reg_value(maintenance.winreg.HKEY_CURRENT_USER, r"Software\NoSuchKey_WDM", "x") == ""

    def test_readers_survive_enumeration_errors(self, mocker):
        mocker.patch("maintenance.winreg.QueryInfoKey", return_value=(2, 2, 0))
        mocker.patch("maintenance.winreg.EnumKey", side_effect=OSError("denied"))
        mocker.patch("maintenance.winreg.EnumValue", side_effect=OSError("denied"))
        assert maintenance._reg_subkeys(maintenance.winreg.HKEY_CURRENT_USER, "Software") == []
        assert maintenance._reg_values(maintenance.winreg.HKEY_CURRENT_USER, "Software") == []


class TestScanStartupEntries:
    def test_missing_target_is_reported(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("Ghost", r"C:\gone\ghost.exe")])
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, checked, unverified = maintenance.scan_startup_entries()
        assert len(findings) == len(maintenance._STARTUP_KEYS)
        assert findings[0]["issue"] == "missing"
        assert findings[0]["category"] == "startup"

    def test_present_target_is_not_reported(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("Real", r"C:\here\real.exe")])
        mocker.patch("maintenance.os.path.exists", return_value=True)
        findings, checked, _ = maintenance.scan_startup_entries()
        assert findings == []
        assert checked == len(maintenance._STARTUP_KEYS)

    def test_empty_value_reported_as_empty(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("Dead", '""')])
        findings, _, _ = maintenance.scan_startup_entries()
        assert findings[0]["issue"] == "empty"

    def test_unverified_never_becomes_a_finding(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("Host", "rundll32.exe x.dll,Y")])
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, _, unverified = maintenance.scan_startup_entries()
        assert findings == []
        assert unverified == len(maintenance._STARTUP_KEYS)


class TestScanUninstallEntries:
    def test_missing_install_location_reported(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["SomeApp"])
        mocker.patch(
            "maintenance._reg_value",
            side_effect=lambda r, k, n="": {
                "InstallLocation": r"C:\Program Files\Gone",
                "DisplayName": "Gone App",
            }.get(n, ""),
        )
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, checked, _ = maintenance.scan_uninstall_entries()
        assert findings[0]["name"] == "Gone App"
        assert findings[0]["issue"] == "missing"

    def test_entry_without_install_location_is_unverified_not_flagged(self, mocker):
        # 125 of 209 real entries have no InstallLocation. Flagging those would
        # be pure noise.
        mocker.patch("maintenance._reg_subkeys", return_value=["NoLoc"])
        mocker.patch("maintenance._reg_value", return_value="")
        findings, _, unverified = maintenance.scan_uninstall_entries()
        assert findings == []
        assert unverified == len(maintenance._UNINSTALL_KEYS)

    def test_drive_root_location_is_not_flagged(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["Weird"])
        mocker.patch("maintenance._reg_value", side_effect=lambda r, k, n="": "C:\\" if n == "InstallLocation" else "")
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, _, unverified = maintenance.scan_uninstall_entries()
        assert findings == []  # a bare drive root is mis-recorded, not missing

    def test_present_location_not_flagged(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["Fine"])
        mocker.patch(
            "maintenance._reg_value",
            side_effect=lambda r, k, n="": r"C:\Apps\Fine" if n == "InstallLocation" else "Fine",
        )
        mocker.patch("maintenance.os.path.exists", return_value=True)
        findings, _, _ = maintenance.scan_uninstall_entries()
        assert findings == []


class TestScanSharedDllsAndAppPaths:
    def test_shared_dll_missing_reported(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[(r"C:\Windows\System32\gone.dll", 1)])
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, checked, _ = maintenance.scan_shared_dlls()
        # One per registry view (native + WOW6432Node).
        views = len(maintenance._SHARED_DLLS_KEYS)
        assert len(findings) == views
        assert findings[0]["category"] == "shared_dlls"
        assert checked == views

    def test_shared_dll_present_not_reported(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[(r"C:\Windows\System32\here.dll", 1)])
        mocker.patch("maintenance.os.path.exists", return_value=True)
        assert maintenance.scan_shared_dlls()[0] == []

    def test_app_path_missing_reported(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["thing.exe"])
        mocker.patch("maintenance._reg_value", return_value=r"C:\gone\thing.exe")
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, _, _ = maintenance.scan_app_paths()
        assert findings[0]["category"] == "app_paths"

    def test_app_path_without_default_is_unverified(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["thing.exe"])
        mocker.patch("maintenance._reg_value", return_value="")
        findings, _, unverified = maintenance.scan_app_paths()
        assert findings == []
        assert unverified == len(maintenance._APP_PATHS_KEYS)


class TestScanRegistry:
    def test_shape_and_totals(self, mocker):
        mocker.patch("maintenance.scan_startup_entries", return_value=([{"category": "startup"}], 10, 2))
        mocker.patch("maintenance.scan_uninstall_entries", return_value=([], 20, 5))
        mocker.patch("maintenance.scan_app_paths", return_value=([], 5, 1))
        mocker.patch("maintenance.scan_shared_dlls", return_value=([], 100, 0))
        out = maintenance.scan_registry()
        assert out["ok"] is True
        assert out["total"] == 1
        assert out["checked"] == 135
        assert len(out["categories"]) == 4

    def test_one_failing_category_does_not_sink_the_report(self, mocker):
        mocker.patch("maintenance.scan_startup_entries", side_effect=OSError("hive gone"))
        out = maintenance.scan_registry()
        assert out["ok"] is True
        startup = next(c for c in out["categories"] if c["key"] == "startup")
        assert "error" in startup and startup["count"] == 0

    def test_note_states_the_honest_truth(self):
        note = maintenance.scan_registry()["note"].lower()
        assert "does not make windows faster" in note

    def test_findings_are_capped_for_transport(self, mocker):
        many = [{"category": "shared_dlls", "n": i} for i in range(300)]
        mocker.patch("maintenance.scan_shared_dlls", return_value=(many, 300, 0))
        out = maintenance.scan_registry()
        cat = next(c for c in out["categories"] if c["key"] == "shared_dlls")
        assert cat["count"] == 300  # exact count preserved
        assert len(cat["findings"]) == 50  # payload capped

    def test_live_scan_is_read_only_and_returns(self):
        # No mocks. Must not raise on a real machine, and reports a real total.
        out = maintenance.scan_registry()
        assert out["ok"] is True
        assert out["checked"] > 0
        assert isinstance(out["total"], int)


class TestExportRegistryBackup:
    def test_unknown_key_is_refused(self):
        out = maintenance.export_registry_backup([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"])
        assert out["ok"] is False
        assert "known" in out["error"].lower()

    def test_caller_paths_cannot_escape_the_allowlist(self):
        # The whole point: keys come from the report, never free-form input.
        for evil in [r"SOFTWARE\..\..\Secret", "HKLM", "", r"SAM\SAM"]:
            assert maintenance.export_registry_backup([evil])["ok"] is False

    def test_export_writes_reg_files(self, mocker, tmp_path):
        mocker.patch.object(maintenance, "_REG_BACKUP_DIR", str(tmp_path))
        run = mocker.patch("maintenance.subprocess.run")
        run.return_value.returncode = 0
        run.return_value.stderr = ""

        def fake_export(argv, **kw):
            with open(argv[3], "w", encoding="utf-16") as fh:
                fh.write("Windows Registry Editor Version 5.00")
            m = mocker.MagicMock()
            m.returncode = 0
            m.stderr = ""
            return m

        run.side_effect = fake_export
        out = maintenance.export_registry_backup([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"])
        assert out["ok"] is True
        assert out["count"] >= 1
        assert os.path.isdir(out["dir"])

    def test_export_failure_is_reported(self, mocker, tmp_path):
        mocker.patch.object(maintenance, "_REG_BACKUP_DIR", str(tmp_path))
        run = mocker.patch("maintenance.subprocess.run")
        run.return_value.returncode = 1
        run.return_value.stderr = "ERROR: Access is denied."
        out = maintenance.export_registry_backup([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"])
        assert out["ok"] is False

    def test_export_never_writes_to_the_registry(self, mocker, tmp_path):
        # Tier 4 has no registry-write path at all; this pins that contract.
        mocker.patch.object(maintenance, "_REG_BACKUP_DIR", str(tmp_path))
        set_value = mocker.patch("maintenance.winreg.SetValueEx", create=True)
        delete_value = mocker.patch("maintenance.winreg.DeleteValue", create=True)
        delete_key = mocker.patch("maintenance.winreg.DeleteKey", create=True)
        run = mocker.patch("maintenance.subprocess.run")
        run.return_value.returncode = 1
        run.return_value.stderr = ""
        maintenance.export_registry_backup([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"])
        maintenance.scan_registry()
        set_value.assert_not_called()
        delete_value.assert_not_called()
        delete_key.assert_not_called()
        # And reg.exe is only ever invoked with "export".
        for call in run.call_args_list:
            assert call[0][0][:2] == ["reg", "export"]


class TestRegistryRoutes:
    @pytest.fixture(autouse=True)
    def _reset(self):
        maintenance._scans.pop("registry", None)
        yield
        maintenance._scans.pop("registry", None)

    def test_scan_route_is_nonblocking(self, client, mocker):
        thread = mocker.patch("maintenance.threading.Thread")
        r = client.get("/api/maintenance/registry/scan")
        assert r.status_code == 200
        assert r.get_json()["status"] == "running"
        thread.assert_called_once()

    def test_scan_route_returns_cached_result(self, client):
        maintenance._scans["registry"] = {
            "running": False,
            "result": {"ok": True, "total": 0, "categories": [], "checked": 5},
            "ts": time.time(),
        }
        r = client.get("/api/maintenance/registry/scan")
        assert r.get_json()["status"] == "done"

    def test_backup_route_is_localhost_only(self, client, mocker):
        export = mocker.patch("maintenance.export_registry_backup")
        r = client.post("/api/maintenance/registry/backup", json={"keys": []}, environ_base={"REMOTE_ADDR": "10.0.0.5"})
        assert r.status_code == 403
        export.assert_not_called()

    def test_backup_route_from_localhost(self, client, mocker):
        export = mocker.patch("maintenance.export_registry_backup", return_value={"ok": True})
        r = client.post(
            "/api/maintenance/registry/backup",
            json={"keys": ["a"]},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert r.status_code == 200
        export.assert_called_once_with(["a"])

    def test_backup_route_without_keys_uses_default(self, client, mocker):
        export = mocker.patch("maintenance.export_registry_backup", return_value={"ok": True})
        client.post("/api/maintenance/registry/backup", json={}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
        export.assert_called_once_with(None)

    def test_no_route_can_modify_the_registry(self, client):
        # Contract: Tier 4 exposes exactly two registry routes, neither writing.
        rules = [str(r) for r in client.application.url_map.iter_rules() if "/registry/" in str(r)]
        assert sorted(rules) == [
            "/api/maintenance/registry/backup",
            "/api/maintenance/registry/scan",
        ]


class TestFalsePositiveGuards:
    """A false 'this entry is broken' is the dangerous failure here — it is how
    someone gets talked into deleting a working registry entry. These pin the
    cases where a HEALTHY entry could have been accused."""

    def test_unc_target_is_never_called_broken(self):
        # os.path.exists() on an unreachable share returns False, so a working
        # network-launched entry would read as missing whenever the server is
        # off — and an unreachable UNC can block on SMB timeouts for seconds.
        for unc in ["\\\\server\\share\\app.exe", "//server/share/app.exe"]:
            path, status = maintenance._resolve_command_target(unc)
            assert status == "unverified", unc
            assert path == ""

    def test_unc_startup_entry_produces_no_finding(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("Net", "\\\\nas\\tools\\run.exe")])
        mocker.patch("maintenance.os.path.exists", return_value=False)
        findings, _, unverified = maintenance.scan_startup_entries()
        assert findings == []
        assert unverified == len(maintenance._STARTUP_KEYS)

    def test_x86_sibling_counts_as_existing(self, mocker):
        # A 32-bit entry recording %ProgramFiles% means the (x86) folder, but a
        # 64-bit process expands it to the native one.
        native = os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Vendor", "app.exe")
        x86 = os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"), "Vendor", "app.exe")
        mocker.patch("maintenance.os.path.exists", side_effect=lambda p: p == x86)
        assert maintenance._target_exists(native) is True

    def test_native_sibling_counts_as_existing(self, mocker):
        native = os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Vendor", "app.exe")
        x86 = os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"), "Vendor", "app.exe")
        mocker.patch("maintenance.os.path.exists", side_effect=lambda p: p == native)
        assert maintenance._target_exists(x86) is True

    def test_syswow64_sibling_counts_as_existing(self, mocker):
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        sys32 = os.path.join(root, "System32", "thing.exe")
        wow = os.path.join(root, "SysWOW64", "thing.exe")
        mocker.patch("maintenance.os.path.exists", side_effect=lambda p: p == wow)
        assert maintenance._target_exists(sys32) is True

    def test_genuinely_missing_is_still_missing(self, mocker):
        mocker.patch("maintenance.os.path.exists", return_value=False)
        assert maintenance._target_exists(r"C:\Nowhere\gone.exe") is False

    def test_target_exists_survives_oserror(self, mocker):
        mocker.patch("maintenance.os.path.exists", side_effect=OSError("bad path"))
        assert maintenance._target_exists(r"C:\x\y.exe") is False

    def test_empty_target_is_not_existing(self):
        assert maintenance._target_exists("") is False

    def test_no_infinite_sibling_recursion_on_nested_names(self):
        # ProgramFiles is a prefix of "Program Files (x86)" as a string; the
        # generator must not yield a path that maps back onto itself.
        x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        alts = list(maintenance._alt_bitness_paths(os.path.join(x86, "a.exe")))
        assert all(a != os.path.join(x86, "a.exe") for a in alts)

    def test_non_string_registry_values_never_produce_findings(self, mocker):
        # REG_DWORD / REG_BINARY / REG_MULTI_SZ arriving where a command string
        # is expected must not be parsed into a bogus "missing" path.
        for odd in [1, 0, b"\x00\x01", ["a", "b"]]:
            mocker.patch("maintenance._reg_values", return_value=[("Odd", odd)])
            findings, _, _ = maintenance.scan_startup_entries()
            assert findings == [], odd

    def test_trailing_arg_containing_exe_does_not_shadow_the_real_target(self):
        path, status = maintenance._resolve_command_target(r"C:\a.exe -log C:\b.exe")
        assert status == "ok"
        assert path == r"C:\a.exe"


class TestUncGuardCoversEveryScanner:
    """The UNC guard originally lived only in _host_guard, which is reached from
    scan_startup_entries alone. The other three scanners call _target_exists
    directly, so a UNC InstallLocation / App Paths target / SharedDLL on a
    temporarily-unreachable share was reported as BROKEN — the exact false
    positive this feature exists to avoid — and could block on SMB timeouts."""

    def test_is_unc_recognises_both_slash_styles(self):
        assert maintenance._is_unc("\\\\server\\share\\x.dll") is True
        assert maintenance._is_unc("//server/share/x.dll") is True

    def test_is_unc_ignores_local_paths(self):
        assert maintenance._is_unc(r"C:\Windows\x.dll") is False
        assert maintenance._is_unc("") is False

    def test_uninstall_unc_location_is_unverified_not_missing(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["NetApp"])
        mocker.patch(
            "maintenance._reg_value",
            side_effect=lambda r, k, n="": "\\\\nas\\apps\\NetApp" if n == "InstallLocation" else "NetApp",
        )
        mocker.patch("maintenance._target_exists", return_value=False)
        findings, _, unverified = maintenance.scan_uninstall_entries()
        assert findings == []
        assert unverified == len(maintenance._UNINSTALL_KEYS)

    def test_app_path_unc_target_is_unverified_not_missing(self, mocker):
        mocker.patch("maintenance._reg_subkeys", return_value=["net.exe"])
        mocker.patch("maintenance._reg_value", return_value="\\\\nas\\tools\\net.exe")
        mocker.patch("maintenance._target_exists", return_value=False)
        findings, _, unverified = maintenance.scan_app_paths()
        assert findings == []
        assert unverified >= 1

    def test_shared_dll_unc_target_is_unverified_not_missing(self, mocker):
        mocker.patch("maintenance._reg_values", return_value=[("\\\\nas\\lib\\shared.dll", 1)])
        mocker.patch("maintenance._target_exists", return_value=False)
        findings, _, unverified = maintenance.scan_shared_dlls()
        assert findings == []
        assert unverified >= 1

    def test_unc_entries_never_reach_the_filesystem_check(self, mocker):
        # Also a latency guard: an unreachable UNC can hang os.path.exists for
        # seconds, which would wreck a scan that otherwise runs in ~60ms.
        mocker.patch("maintenance._reg_values", return_value=[("\\\\dead\\share\\a.dll", 1)])
        target = mocker.patch("maintenance._target_exists", return_value=False)
        maintenance.scan_shared_dlls()
        target.assert_not_called()


class TestThirtyTwoBitViewsAreScanned:
    """A broken 32-bit registration lives only in the WOW6432Node view; reading
    the native view alone silently never checks it."""

    def test_startup_covers_the_32bit_runonce(self):
        paths = [p for _, _, p in maintenance._STARTUP_KEYS]
        assert any("WOW6432Node" in p and p.endswith("RunOnce") for p in paths)
        assert any("WOW6432Node" in p and p.endswith("Run") for p in paths)

    def test_app_paths_covers_both_views(self):
        assert len(maintenance._APP_PATHS_KEYS) == 2
        assert any("WOW6432Node" in k for k in maintenance._APP_PATHS_KEYS)

    def test_shared_dlls_covers_both_views(self):
        assert len(maintenance._SHARED_DLLS_KEYS) == 2
        assert any("WOW6432Node" in k for k in maintenance._SHARED_DLLS_KEYS)

    def test_app_paths_scans_every_listed_view(self, mocker):
        subkeys = mocker.patch("maintenance._reg_subkeys", return_value=[])
        maintenance.scan_app_paths()
        scanned = [c[0][1] for c in subkeys.call_args_list]
        assert set(scanned) == set(maintenance._APP_PATHS_KEYS)

    def test_shared_dlls_scans_every_listed_view(self, mocker):
        values = mocker.patch("maintenance._reg_values", return_value=[])
        maintenance.scan_shared_dlls()
        scanned = [c[0][1] for c in values.call_args_list]
        assert set(scanned) == set(maintenance._SHARED_DLLS_KEYS)

    def test_shared_dll_finding_records_the_view_it_came_from(self, mocker):
        wow = next(k for k in maintenance._SHARED_DLLS_KEYS if "WOW6432Node" in k)
        mocker.patch(
            "maintenance._reg_values",
            side_effect=lambda root, base: [(r"C:\gone\x.dll", 1)] if base == wow else [],
        )
        mocker.patch("maintenance._target_exists", return_value=False)
        findings, _, _ = maintenance.scan_shared_dlls()
        assert len(findings) == 1
        assert findings[0]["key"] == wow  # not hardcoded to the native view

    def test_export_allowlist_knows_the_new_keys(self, mocker, tmp_path):
        # The allowlist is what stops a caller-supplied path being exported; it
        # has to track the key constants or valid backups get refused.
        # Backup dir redirected and reg.exe stubbed: this test is about the
        # allowlist, and must not write real files or spawn real subprocesses.
        mocker.patch.object(maintenance, "_REG_BACKUP_DIR", str(tmp_path))
        run = mocker.patch("maintenance.subprocess.run")
        run.return_value.returncode = 1
        run.return_value.stderr = ""
        for key in list(maintenance._APP_PATHS_KEYS) + list(maintenance._SHARED_DLLS_KEYS):
            out = maintenance.export_registry_backup([key])
            assert "No known registry keys" not in out.get("error", ""), key
