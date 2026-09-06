"""Tests for maintenance.py — Tier 1 junk cleanup (scan preview + clean)."""

from __future__ import annotations

import os
import time

import maintenance

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


class TestScanJunk:
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

    def test_scan_never_deletes(self, tmp_path, mocker):
        cats = self._cats(tmp_path)
        mocker.patch("maintenance._junk_categories", return_value=cats)
        mocker.patch("maintenance._recycle_bin_info", return_value=(0, 0))
        maintenance.scan_junk()
        assert os.path.exists(os.path.join(cats[0]["roots"][0], "junk.tmp"))  # still there


class TestCleanJunk:
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


class TestRoutes:
    def test_scan_route(self, client, mocker):
        mocker.patch(
            "maintenance.scan_junk", return_value={"ok": True, "categories": [], "total_bytes": 0, "total_human": "0 B"}
        )
        r = client.get("/api/maintenance/junk/scan")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

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
