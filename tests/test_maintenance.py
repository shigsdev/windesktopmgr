"""Tests for maintenance.py — Tier 1 junk cleanup (scan preview + clean)."""

from __future__ import annotations

import os
import time
from urllib.parse import quote

import pytest

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
