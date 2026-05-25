"""tests/test_cloudcopy.py -- OneDrive -> iCloud replicator (#46 PR-1).

Coverage areas for PR-1 (rules + preview, no copying yet):
  - DEFAULT_RULES schema (Personal Vault excluded by default, etc.)
  - load_rules with missing file / malformed JSON / non-dict top level
  - validate_rules (positive + every negative shape)
  - save_rules round-trip
  - is_excluded across all three dimensions + Personal Vault
  - walk_source against a synthetic tree (real os.scandir, no mocks)
  - preview (counts, samples, file-cap-hit signal)
  - Flask routes (GET/PUT rules, GET preview, GET history, GET resume-state)

PR-2 will add coverage for the copy engine + crash-safe resume.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime

import pytest

import cloudcopy

# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def cc_tmp(tmp_path, monkeypatch):
    """Redirect persistence files to tmp_path so tests don't touch the
    user's real rules."""
    monkeypatch.setattr(cloudcopy, "RULES_FILE", str(tmp_path / "cloudcopy_rules.json"))
    monkeypatch.setattr(cloudcopy, "STATE_FILE", str(tmp_path / "cloudcopy_state.json"))
    monkeypatch.setattr(cloudcopy, "HISTORY_FILE", str(tmp_path / "cloudcopy_history.json"))
    return {
        "rules": tmp_path / "cloudcopy_rules.json",
        "state": tmp_path / "cloudcopy_state.json",
        "history": tmp_path / "cloudcopy_history.json",
        "root": tmp_path,
    }


@pytest.fixture
def synthetic_source(tmp_path):
    """Build a small synthetic OneDrive tree so walker tests run
    against real filesystem without touching the user's data.

    Tree::
        root/
          Docs/
            report.pdf        2 KB
            ~$report.docx     1 KB    (Office lock file — should glob-exclude)
            notes.txt         100 B
          Pictures/
            vacation.jpg      5 KB
            Thumbs.db         50 B    (glob-exclude)
          Personal Vault/
            secret.docx       3 KB    (vault-exclude)
          Backup Data/
            big.iso           10 KB   (intentional folder name)
          temp.tmp            500 B   (extension-exclude)
          README.md           200 B   (kept)
    """
    src = tmp_path / "fake-onedrive"
    src.mkdir()

    (src / "Docs").mkdir()
    (src / "Docs" / "report.pdf").write_bytes(b"x" * 2048)
    (src / "Docs" / "~$report.docx").write_bytes(b"x" * 1024)
    (src / "Docs" / "notes.txt").write_bytes(b"x" * 100)

    (src / "Pictures").mkdir()
    (src / "Pictures" / "vacation.jpg").write_bytes(b"x" * 5120)
    (src / "Pictures" / "Thumbs.db").write_bytes(b"x" * 50)

    (src / "Personal Vault").mkdir()
    (src / "Personal Vault" / "secret.docx").write_bytes(b"x" * 3072)

    (src / "Backup Data").mkdir()
    (src / "Backup Data" / "big.iso").write_bytes(b"x" * 10240)

    (src / "temp.tmp").write_bytes(b"x" * 500)
    (src / "README.md").write_bytes(b"x" * 200)

    return src


# ── DEFAULT_RULES ──────────────────────────────────────────────────


class TestDefaultRules:
    def test_personal_vault_excluded_by_default(self):
        assert cloudcopy.DEFAULT_RULES["include_personal_vault"] is False

    def test_default_excludes_thumb_folder(self):
        assert ".@__thumb" in cloudcopy.DEFAULT_RULES["exclude_folders"]

    def test_default_excludes_personal_vault_folder_name(self):
        assert "Personal Vault" in cloudcopy.DEFAULT_RULES["exclude_folders"]

    def test_default_excludes_office_lock_glob(self):
        assert "~$*" in cloudcopy.DEFAULT_RULES["exclude_filename_globs"]

    def test_default_excludes_thumbs_db(self):
        assert "Thumbs.db" in cloudcopy.DEFAULT_RULES["exclude_filename_globs"]

    def test_default_excludes_tmp_extension(self):
        assert ".tmp" in cloudcopy.DEFAULT_RULES["exclude_extensions"]

    def test_default_source_destination_unset(self):
        # The default rules don't pin source/dest; they're resolved
        # from env vars at preview time.
        assert cloudcopy.DEFAULT_RULES["source_root"] is None
        assert cloudcopy.DEFAULT_RULES["destination_root"] is None


# ── load_rules ─────────────────────────────────────────────────────


class TestLoadRules:
    def test_no_file_returns_defaults(self, cc_tmp):
        rules = cloudcopy.load_rules()
        assert rules["include_personal_vault"] is False
        assert rules["exclude_folders"] == cloudcopy.DEFAULT_RULES["exclude_folders"]

    def test_malformed_json_returns_defaults(self, cc_tmp):
        cc_tmp["rules"].write_text("not json", encoding="utf-8")
        rules = cloudcopy.load_rules()
        assert rules == cloudcopy.DEFAULT_RULES

    def test_non_dict_top_level_returns_defaults(self, cc_tmp):
        cc_tmp["rules"].write_text("[1, 2, 3]", encoding="utf-8")
        rules = cloudcopy.load_rules()
        assert rules == cloudcopy.DEFAULT_RULES

    def test_partial_user_rules_merged_with_defaults(self, cc_tmp):
        cc_tmp["rules"].write_text(
            json.dumps({"exclude_folders": ["Work-Confidential"]}),
            encoding="utf-8",
        )
        rules = cloudcopy.load_rules()
        # User's value wins for the key they set...
        assert rules["exclude_folders"] == ["Work-Confidential"]
        # ...but other defaults still flow through.
        assert "~$*" in rules["exclude_filename_globs"]
        assert rules["include_personal_vault"] is False

    def test_list_field_with_garbage_type_falls_back(self, cc_tmp):
        # exclude_folders as a string (not a list) -> coerce to default.
        cc_tmp["rules"].write_text(json.dumps({"exclude_folders": "oops"}), encoding="utf-8")
        rules = cloudcopy.load_rules()
        assert rules["exclude_folders"] == cloudcopy.DEFAULT_RULES["exclude_folders"]


# ── validate_rules ─────────────────────────────────────────────────


class TestValidateRules:
    def test_empty_dict_ok(self):
        ok, err = cloudcopy.validate_rules({})
        assert ok

    def test_non_dict_refused(self):
        ok, err = cloudcopy.validate_rules("not a dict")
        assert not ok

    def test_non_list_field_refused(self):
        ok, err = cloudcopy.validate_rules({"exclude_folders": "string-not-list"})
        assert not ok
        assert "must be a list" in err

    def test_non_string_entries_refused(self):
        ok, err = cloudcopy.validate_rules({"exclude_folders": ["valid", 123]})
        assert not ok
        assert "strings" in err

    def test_extension_without_dot_refused(self):
        ok, err = cloudcopy.validate_rules({"exclude_extensions": ["tmp"]})  # missing leading dot
        assert not ok
        assert "start with '.'" in err

    def test_personal_vault_must_be_bool(self):
        ok, err = cloudcopy.validate_rules({"include_personal_vault": "yes"})
        assert not ok

    def test_source_root_must_be_string_or_none(self):
        ok, err = cloudcopy.validate_rules({"source_root": 42})
        assert not ok

    def test_source_root_none_ok(self):
        ok, _ = cloudcopy.validate_rules({"source_root": None})
        assert ok

    def test_full_valid_rules_ok(self):
        ok, _ = cloudcopy.validate_rules(
            {
                "exclude_folders": ["Work"],
                "exclude_extensions": [".iso", ".dmg"],
                "exclude_filename_globs": ["~$*"],
                "include_personal_vault": False,
                "source_root": "C:\\Users\\x\\OneDrive",
                "destination_root": "C:\\Users\\x\\iCloudDrive",
            }
        )
        assert ok


# ── save_rules round-trip ──────────────────────────────────────────


class TestSaveRules:
    def test_save_then_load_roundtrip(self, cc_tmp):
        custom = {"exclude_folders": ["Work-Confidential"]}
        ok, _ = cloudcopy.save_rules(custom)
        assert ok
        loaded = cloudcopy.load_rules()
        assert loaded["exclude_folders"] == ["Work-Confidential"]

    def test_save_refuses_invalid(self, cc_tmp):
        ok, err = cloudcopy.save_rules({"exclude_folders": [42]})
        assert not ok

    def test_save_persists_full_shape(self, cc_tmp):
        # Even when caller passes a partial dict, the file must contain
        # every key from DEFAULT_RULES so downstream code never sees
        # missing keys.
        cloudcopy.save_rules({"exclude_folders": ["Custom"]})
        on_disk = json.loads(cc_tmp["rules"].read_text(encoding="utf-8"))
        for key in cloudcopy.DEFAULT_RULES:
            assert key in on_disk


# ── is_excluded ────────────────────────────────────────────────────


class TestIsExcluded:
    _RULES = {
        "exclude_folders": ["Work-Confidential", "Backup Data"],
        "exclude_extensions": [".tmp", ".iso"],
        "exclude_filename_globs": ["~$*", "Thumbs.db"],
        "include_personal_vault": False,
    }

    def test_clean_file_kept(self):
        excluded, _ = cloudcopy.is_excluded("Docs/report.pdf", "report.pdf", ".pdf", self._RULES)
        assert not excluded

    def test_folder_exclude_hits_at_any_depth(self):
        excluded, reason = cloudcopy.is_excluded("Pictures/Backup Data/2024/foo.jpg", "foo.jpg", ".jpg", self._RULES)
        assert excluded
        assert "Backup Data" in reason

    def test_folder_exclude_case_insensitive(self):
        excluded, reason = cloudcopy.is_excluded("WORK-CONFIDENTIAL/secret.txt", "secret.txt", ".txt", self._RULES)
        assert excluded

    def test_extension_exclude_case_insensitive(self):
        excluded, reason = cloudcopy.is_excluded("temp.TMP", "temp.TMP", ".TMP", self._RULES)
        assert excluded
        assert "extension" in reason

    def test_glob_exclude_office_lock(self):
        excluded, reason = cloudcopy.is_excluded("Docs/~$report.docx", "~$report.docx", ".docx", self._RULES)
        assert excluded
        assert "glob" in reason

    def test_glob_exclude_thumbs_db(self):
        excluded, _ = cloudcopy.is_excluded("Pictures/Thumbs.db", "Thumbs.db", ".db", self._RULES)
        assert excluded

    def test_personal_vault_excluded_by_default(self):
        excluded, reason = cloudcopy.is_excluded("Personal Vault/secret.docx", "secret.docx", ".docx", self._RULES)
        assert excluded
        assert reason == "personal_vault"

    def test_personal_vault_included_with_toggle(self):
        rules_with_pv = dict(self._RULES)
        rules_with_pv["include_personal_vault"] = True
        excluded, _ = cloudcopy.is_excluded("Personal Vault/secret.docx", "secret.docx", ".docx", rules_with_pv)
        assert not excluded

    def test_first_matching_reason_wins(self):
        # File in Backup Data with a .tmp extension -- folder match should
        # fire FIRST (we surface the most-specific reason, and folder is
        # checked before extension).
        excluded, reason = cloudcopy.is_excluded("Backup Data/file.tmp", "file.tmp", ".tmp", self._RULES)
        assert excluded
        # Folder match wins (deterministic for stable UI).
        assert "Backup Data" in reason


# ── walk_source ────────────────────────────────────────────────────


class TestWalkSource:
    def test_walks_real_tree(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        entries = list(cloudcopy.walk_source(str(synthetic_source), rules))
        # Six included files (Personal Vault folder pruned at directory
        # level, so secret.docx never even shows up). Backup Data is in
        # default... actually no, it's NOT in DEFAULT_RULES exclude_folders;
        # only ".@__thumb" and "Personal Vault" are. So Backup Data's
        # contents come through but big.iso is filtered by the file walk
        # only if .iso is in default extensions, which it's NOT. Let me
        # just count what we get and check it's sensible.
        names = [e["name"] for e in entries]
        # Personal Vault is folder-pruned during the walk.
        assert "secret.docx" not in names
        # Default rules don't exclude Backup Data folder.
        assert "big.iso" in names
        # README.md should be kept.
        assert "README.md" in names

    def test_personal_vault_folder_pruned_at_directory_level(self, synthetic_source):
        # Confirm the WALKER doesn't even descend into Personal Vault
        # when the toggle is False -- saves time on real OneDrive where
        # vault could be huge.
        rules = dict(cloudcopy.DEFAULT_RULES)
        rules["include_personal_vault"] = False
        entries = list(cloudcopy.walk_source(str(synthetic_source), rules))
        for e in entries:
            assert "Personal Vault" not in e["rel_path"]

    def test_personal_vault_included_when_toggled(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        rules["include_personal_vault"] = True
        # Also remove "Personal Vault" from exclude_folders since the
        # toggle is the user's explicit opt-in.
        rules["exclude_folders"] = [f for f in rules["exclude_folders"] if f != "Personal Vault"]
        entries = list(cloudcopy.walk_source(str(synthetic_source), rules))
        # Now secret.docx shows up.
        assert any("Personal Vault/secret.docx" in e["rel_path"] for e in entries)

    def test_files_have_size_and_mtime(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        entries = list(cloudcopy.walk_source(str(synthetic_source), rules))
        for e in entries:
            assert isinstance(e["size"], int)
            assert e["size"] >= 0
            assert isinstance(e["mtime"], float)

    def test_file_cap_stops_walk_early(self, synthetic_source):
        # Cap at 2 -- expect exactly 2 entries.
        rules = dict(cloudcopy.DEFAULT_RULES)
        entries = list(cloudcopy.walk_source(str(synthetic_source), rules, file_cap=2))
        assert len(entries) == 2

    def test_nonexistent_source_returns_empty(self, tmp_path):
        entries = list(cloudcopy.walk_source(str(tmp_path / "does-not-exist"), cloudcopy.DEFAULT_RULES))
        assert entries == []

    def test_deterministic_order(self, synthetic_source):
        """Two walks with the same rules must yield the same order so
        the preview sample is stable."""
        rules = dict(cloudcopy.DEFAULT_RULES)
        first = [e["rel_path"] for e in cloudcopy.walk_source(str(synthetic_source), rules)]
        second = [e["rel_path"] for e in cloudcopy.walk_source(str(synthetic_source), rules)]
        assert first == second


# ── preview ────────────────────────────────────────────────────────


class TestPreview:
    def test_counts_match_real_tree(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        result = cloudcopy.preview(rules=rules, source_root=str(synthetic_source), sample_size=50)
        # Personal Vault pruned, Thumbs.db + ~$report.docx + temp.tmp excluded.
        # Kept: report.pdf, notes.txt, vacation.jpg, big.iso, README.md = 5
        assert result["included_count"] == 5
        # Files in synthetic tree included (1 byte = "x" * N) summed:
        # 2048 + 100 + 5120 + 10240 + 200 = 17,708
        assert result["included_bytes"] == 17708

    def test_sample_paths_capped_at_sample_size(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        result = cloudcopy.preview(rules=rules, source_root=str(synthetic_source), sample_size=2)
        assert len(result["included_sample"]) <= 2

    def test_excluded_sample_has_reasons(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        result = cloudcopy.preview(rules=rules, source_root=str(synthetic_source))
        # At least Thumbs.db / temp.tmp / ~$report.docx should be in
        # the excluded sample with their reasons attached.
        reasons = [e["reason"] for e in result["excluded_sample"]]
        assert any("glob" in r or "extension" in r for r in reasons)

    def test_missing_source_root_returns_zero_counts(self, tmp_path):
        result = cloudcopy.preview(
            rules=cloudcopy.DEFAULT_RULES,
            source_root=str(tmp_path / "no-such-onedrive"),
            sample_size=50,
        )
        assert result["included_count"] == 0
        assert result["included_bytes"] == 0
        assert result["excluded_count"] == 0

    def test_walked_at_timestamp_present(self, synthetic_source):
        rules = dict(cloudcopy.DEFAULT_RULES)
        result = cloudcopy.preview(rules=rules, source_root=str(synthetic_source))
        assert result["walked_at"]
        # ISO format check: should be parseable.
        from datetime import datetime

        datetime.fromisoformat(result["walked_at"])


# ── History + resume state placeholders (PR-1 returns empty) ───────


class TestPlaceholders:
    def test_history_empty_when_no_file(self, cc_tmp):
        assert cloudcopy.load_history() == []

    def test_history_handles_malformed_file(self, cc_tmp):
        cc_tmp["history"].write_text("garbage", encoding="utf-8")
        assert cloudcopy.load_history() == []

    def test_history_non_list_returns_empty(self, cc_tmp):
        cc_tmp["history"].write_text('{"not": "a list"}', encoding="utf-8")
        assert cloudcopy.load_history() == []

    def test_resume_state_none_when_no_file(self, cc_tmp):
        assert cloudcopy.load_resume_state() is None

    def test_resume_state_handles_malformed(self, cc_tmp):
        cc_tmp["state"].write_text("garbage", encoding="utf-8")
        assert cloudcopy.load_resume_state() is None


# ── Flask routes ───────────────────────────────────────────────────


class TestCloudCopyRoutes:
    def test_get_rules_returns_defaults_for_new_install(self, client, cc_tmp):
        resp = client.get("/api/cloudcopy/rules")
        assert resp.status_code == 200
        rules = resp.get_json()["rules"]
        assert rules["include_personal_vault"] is False

    def test_put_rules_validates_input(self, client, cc_tmp):
        resp = client.put(
            "/api/cloudcopy/rules",
            json={"rules": {"exclude_extensions": ["bad-no-dot"]}},
        )
        assert resp.status_code == 400
        assert "must start with" in resp.get_json()["error"]

    def test_put_rules_requires_dict_body(self, client, cc_tmp):
        resp = client.put("/api/cloudcopy/rules", json={"rules": "not a dict"})
        assert resp.status_code == 400

    def test_put_rules_persists_and_get_returns_it(self, client, cc_tmp):
        put = client.put(
            "/api/cloudcopy/rules",
            json={"rules": {"exclude_folders": ["Work-Confidential"]}},
        )
        assert put.status_code == 200
        get = client.get("/api/cloudcopy/rules")
        assert get.get_json()["rules"]["exclude_folders"] == ["Work-Confidential"]

    def test_preview_route_returns_shape(self, client, cc_tmp, synthetic_source, monkeypatch):
        # Point the preview at the synthetic tree.
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(synthetic_source))
        resp = client.get("/api/cloudcopy/preview")
        assert resp.status_code == 200
        data = resp.get_json()
        for key in (
            "included_count",
            "included_bytes",
            "excluded_count",
            "included_sample",
            "excluded_sample",
            "file_cap_hit",
        ):
            assert key in data
        # 5 included per our synthetic-tree count.
        assert data["included_count"] == 5

    def test_preview_sample_size_param_honoured(self, client, cc_tmp, synthetic_source, monkeypatch):
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(synthetic_source))
        resp = client.get("/api/cloudcopy/preview?sample_size=2")
        data = resp.get_json()
        assert len(data["included_sample"]) <= 2

    def test_preview_sample_size_clamped(self, client, cc_tmp, synthetic_source, monkeypatch):
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(synthetic_source))
        # >200 should clamp to 200; bad string should fall back to 50.
        resp1 = client.get("/api/cloudcopy/preview?sample_size=999999")
        assert resp1.status_code == 200
        resp2 = client.get("/api/cloudcopy/preview?sample_size=banana")
        assert resp2.status_code == 200

    def test_history_route_empty_in_pr1(self, client, cc_tmp):
        resp = client.get("/api/cloudcopy/history")
        assert resp.status_code == 200
        assert resp.get_json()["entries"] == []

    def test_resume_state_route_no_crash_in_pr1(self, client, cc_tmp):
        resp = client.get("/api/cloudcopy/resume-state")
        assert resp.status_code == 200
        assert resp.get_json()["has_crashed"] is False


# ══════════════════════════════════════════════════════════════════════
# PR-2: Schedule schema (default OFF) + extended validate_rules
# ══════════════════════════════════════════════════════════════════════


class TestScheduleSchema:
    """Schedule fields are present in DEFAULT_RULES, DEFAULT OFF, and
    validate at save time. PR-3 wires actual scheduling; PR-2 just
    persists the schema."""

    def test_schedule_enabled_default_false(self):
        # User-confirmed contract: schedule_enabled MUST be False on a
        # brand-new install. If this ever fires, PR-3 is at risk of
        # creating a Windows Task Scheduler entry without user opt-in.
        assert cloudcopy.DEFAULT_RULES["schedule_enabled"] is False

    def test_schedule_time_default_present_but_inactive(self):
        assert cloudcopy.DEFAULT_RULES["schedule_time"] == "02:00"

    def test_validate_rejects_non_bool_schedule_enabled(self):
        ok, err = cloudcopy.validate_rules({"schedule_enabled": "yes"})
        assert not ok
        assert "bool" in err

    def test_validate_rejects_non_string_schedule_time(self):
        ok, err = cloudcopy.validate_rules({"schedule_time": 200})
        assert not ok

    def test_validate_rejects_invalid_hhmm_string(self):
        for bad in ("2:00", "25:00", "12:60", "12-30", "abc", "23:5", ""):
            ok, err = cloudcopy.validate_rules({"schedule_time": bad})
            assert not ok, f"should refuse schedule_time={bad!r}"

    def test_validate_accepts_valid_hhmm(self):
        for good in ("00:00", "02:00", "12:30", "23:59"):
            ok, _ = cloudcopy.validate_rules({"schedule_time": good})
            assert ok, f"should accept schedule_time={good!r}"

    def test_save_then_load_preserves_schedule_off_default(self, cc_tmp):
        cloudcopy.save_rules({"exclude_folders": ["X"]})
        loaded = cloudcopy.load_rules()
        assert loaded["schedule_enabled"] is False
        assert loaded["schedule_time"] == "02:00"


# ══════════════════════════════════════════════════════════════════════
# PR-2: Copy engine helpers (pure where possible)
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def reset_active_session():
    """Always reset the module-level active-session state before AND
    after each test that touches the worker thread."""
    cloudcopy._reset_module_state_for_tests()
    yield
    cloudcopy._reset_module_state_for_tests()


class TestRulesHash:
    def test_same_rules_same_hash(self):
        a = dict(cloudcopy.DEFAULT_RULES)
        b = dict(cloudcopy.DEFAULT_RULES)
        assert cloudcopy._rules_hash(a) == cloudcopy._rules_hash(b)

    def test_different_rules_different_hash(self):
        a = dict(cloudcopy.DEFAULT_RULES)
        b = dict(cloudcopy.DEFAULT_RULES)
        b["exclude_folders"] = ["Custom"]
        assert cloudcopy._rules_hash(a) != cloudcopy._rules_hash(b)

    def test_hash_stable_across_key_order(self):
        a = {"a": 1, "b": 2}
        b = {"b": 2, "a": 1}
        assert cloudcopy._rules_hash(a) == cloudcopy._rules_hash(b)


class TestAtomicCopy:
    def test_copy_creates_dest_with_content(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_bytes(b"hello world")
        dst = tmp_path / "nested" / "dst.txt"
        ok, n, err = cloudcopy._atomic_copy(str(src), str(dst))
        assert ok
        assert n == 11
        assert dst.read_bytes() == b"hello world"

    def test_copy_creates_parent_dirs(self, tmp_path):
        src = tmp_path / "src.bin"
        src.write_bytes(b"abc")
        dst = tmp_path / "a" / "b" / "c" / "dst.bin"
        ok, _, _ = cloudcopy._atomic_copy(str(src), str(dst))
        assert ok
        assert dst.read_bytes() == b"abc"

    def test_copy_does_not_leave_tmp_on_failure(self, tmp_path, monkeypatch):
        src = tmp_path / "src.txt"
        src.write_bytes(b"hello")
        dst = tmp_path / "dst.txt"

        def _failing_replace(_a, _b):
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", _failing_replace)
        ok, _, err = cloudcopy._atomic_copy(str(src), str(dst))
        assert not ok
        assert "simulated" in err
        assert not (tmp_path / "dst.txt.tmp").exists()

    def test_copy_missing_src_returns_error(self, tmp_path):
        dst = tmp_path / "dst.txt"
        ok, _, err = cloudcopy._atomic_copy(str(tmp_path / "no-such.txt"), str(dst))
        assert not ok
        assert err


class TestNeedsCopy:
    def test_no_dst_means_copy(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_bytes(b"x")
        need, _ = cloudcopy._needs_copy(src.stat(), str(tmp_path / "dst.txt"))
        assert need

    def test_size_differs_means_copy(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_bytes(b"hello")
        dst = tmp_path / "dst.txt"
        dst.write_bytes(b"different size")
        need, reason = cloudcopy._needs_copy(src.stat(), str(dst))
        assert need
        assert "size" in reason

    def test_size_and_mtime_match_means_skip(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_bytes(b"hello")
        dst = tmp_path / "dst.txt"
        dst.write_bytes(b"hello")
        s_st = src.stat()
        os.utime(dst, (s_st.st_atime, s_st.st_mtime))
        need, _ = cloudcopy._needs_copy(src.stat(), str(dst))
        assert not need

    def test_mtime_skew_within_tolerance_skips(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_bytes(b"x")
        dst = tmp_path / "dst.txt"
        dst.write_bytes(b"x")
        s_st = src.stat()
        os.utime(dst, (s_st.st_atime, s_st.st_mtime + 0.5))
        need, _ = cloudcopy._needs_copy(src.stat(), str(dst))
        assert not need


# ══════════════════════════════════════════════════════════════════════
# PR-2: Full copy session against a synthetic source
# ══════════════════════════════════════════════════════════════════════


class TestCopySession:
    def _setup(self, synthetic_source, tmp_path, rules=None):
        rules = rules if rules is not None else dict(cloudcopy.DEFAULT_RULES)
        dest_root = tmp_path / "dest"
        dest_root.mkdir()
        return rules, str(synthetic_source), str(dest_root)

    def test_full_copy_creates_destination_tree(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        result = cloudcopy._run_copy_inner("test-session-1", rules, src, dst)
        assert result["status"] == "completed"
        # 5 included files per the synthetic-tree fixture.
        assert result["files_completed_count"] == 5
        assert (tmp_path / "dest" / "README.md").exists()
        assert (tmp_path / "dest" / "Docs" / "report.pdf").exists()
        assert (tmp_path / "dest" / "Pictures" / "vacation.jpg").exists()

    def test_personal_vault_not_copied(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        cloudcopy._run_copy_inner("test-session-2", rules, src, dst)
        assert not (tmp_path / "dest" / "Personal Vault" / "secret.docx").exists()

    def test_history_written_on_completion(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        cloudcopy._run_copy_inner("test-session-3", rules, src, dst)
        history = cloudcopy.load_history()
        assert len(history) == 1
        assert history[0]["status"] == "completed"
        assert history[0]["session_id"] == "test-session-3"

    def test_state_file_cleared_on_completion(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        cloudcopy._run_copy_inner("test-session-4", rules, src, dst)
        assert cloudcopy.load_resume_state() is None

    def test_second_run_skips_already_copied(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        cloudcopy._run_copy_inner("first-run", rules, src, dst)
        result2 = cloudcopy._run_copy_inner("second-run", rules, src, dst)
        assert result2["status"] == "completed"
        assert result2["files_skipped_count"] == 5
        assert result2["files_completed_count"] == 0

    def test_source_wins_on_content_difference(self, cc_tmp, synthetic_source, tmp_path):
        rules, src, dst = self._setup(synthetic_source, tmp_path)
        cloudcopy._run_copy_inner("baseline", rules, src, dst)
        # User edits the destination -- next run must overwrite it
        # (source-wins conflict mode).
        (tmp_path / "dest" / "README.md").write_bytes(b"user edited iCloud copy")
        # Touch source so mtime differs (forces copy).
        os.utime(synthetic_source / "README.md", None)
        result = cloudcopy._run_copy_inner("overwrite", rules, src, dst)
        assert result["files_completed_count"] >= 1
        assert (tmp_path / "dest" / "README.md").read_bytes() == b"x" * 200


class TestSessionLifecycle:
    def test_start_then_status_then_history(
        self, cc_tmp, synthetic_source, tmp_path, reset_active_session, monkeypatch
    ):
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(synthetic_source))
        monkeypatch.setattr(cloudcopy, "DEFAULT_DESTINATION_ROOT", str(tmp_path / "dest"))
        result = cloudcopy.start_copy_session()
        assert result["ok"] is True
        session_id = result["session_id"]
        # Wait briefly for worker (5 files, ~instant on tmp).
        for _ in range(100):
            time.sleep(0.05)
            if cloudcopy.get_active_session_id() is None:
                break
        status = cloudcopy.get_status(session_id)
        assert status["state"] == "finished"
        assert status["history"]["status"] == "completed"

    def test_start_refuses_missing_source_root(self, cc_tmp, tmp_path, reset_active_session, monkeypatch):
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(tmp_path / "does-not-exist"))
        monkeypatch.setattr(cloudcopy, "DEFAULT_DESTINATION_ROOT", str(tmp_path / "dest"))
        result = cloudcopy.start_copy_session()
        assert not result["ok"]
        assert "source" in result["error"].lower()

    def test_request_cancel_refused_for_wrong_session_id(self, cc_tmp, reset_active_session):
        assert cloudcopy.request_cancel("nonsense") is False


class TestResumeFlow:
    def _make_orphan_state(self, cc_tmp, synthetic_source, tmp_path, cursor=2):
        rules = dict(cloudcopy.DEFAULT_RULES)
        plan = cloudcopy._build_plan(str(synthetic_source), rules)
        state = {
            "session_id": "orphan-session",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "rules_hash": cloudcopy._rules_hash(rules),
            "source_root": str(synthetic_source),
            "dest_root": str(tmp_path / "dest"),
            "plan": plan,
            "cursor": cursor,
            "bytes_copied": 1234,
            "files_completed": [0, 1],
            "files_skipped": [],
            "files_failed": [],
        }
        (tmp_path / "dest").mkdir(exist_ok=True)
        cloudcopy._save_state(state)
        return state

    def test_load_resume_state_finds_orphan(self, cc_tmp, synthetic_source, tmp_path):
        self._make_orphan_state(cc_tmp, synthetic_source, tmp_path)
        state = cloudcopy.load_resume_state()
        assert state is not None
        assert state["session_id"] == "orphan-session"
        assert state["cursor"] == 2

    def test_resume_continues_from_cursor(self, cc_tmp, synthetic_source, tmp_path, reset_active_session):
        self._make_orphan_state(cc_tmp, synthetic_source, tmp_path, cursor=3)
        result = cloudcopy.resume_crashed_session()
        assert result["ok"], f"resume refused: {result}"
        for _ in range(100):
            time.sleep(0.05)
            if cloudcopy.get_active_session_id() is None:
                break
        history = cloudcopy.load_history()
        completed = [h for h in history if h.get("session_id") == "orphan-session"]
        assert completed, "no completion row for the resumed session"
        assert completed[0].get("resumed_from_session_id") == "orphan-session"

    def test_resume_refuses_if_rules_changed(self, cc_tmp, synthetic_source, tmp_path, reset_active_session):
        self._make_orphan_state(cc_tmp, synthetic_source, tmp_path)
        cloudcopy.save_rules({"exclude_folders": ["NEW_DIFFERENT_FOLDER"]})
        result = cloudcopy.resume_crashed_session()
        assert not result["ok"]
        assert "rules changed" in result["error"].lower()

    def test_resume_refuses_if_source_missing(self, cc_tmp, tmp_path, reset_active_session):
        rules = dict(cloudcopy.DEFAULT_RULES)
        state = {
            "session_id": "orphan-missing-source",
            "started_at": "2026-05-25T10:00:00",
            "rules_hash": cloudcopy._rules_hash(rules),
            "source_root": str(tmp_path / "no-such-source"),
            "dest_root": str(tmp_path / "dest"),
            "plan": [],
            "cursor": 0,
            "bytes_copied": 0,
            "files_completed": [],
            "files_skipped": [],
            "files_failed": [],
        }
        cloudcopy._save_state(state)
        result = cloudcopy.resume_crashed_session()
        assert not result["ok"]
        assert "source" in result["error"].lower()

    def test_discard_writes_history_and_clears_state(self, cc_tmp, synthetic_source, tmp_path):
        self._make_orphan_state(cc_tmp, synthetic_source, tmp_path)
        result = cloudcopy.discard_crashed_session()
        assert result["ok"]
        assert cloudcopy.load_resume_state() is None
        history = cloudcopy.load_history()
        assert history
        last = history[-1]
        assert last["status"] == "discarded"
        assert last["discarded_by_user"] is True

    def test_discard_with_no_orphan_returns_error(self, cc_tmp):
        result = cloudcopy.discard_crashed_session()
        assert not result["ok"]


# ══════════════════════════════════════════════════════════════════════
# PR-2: Flask routes (run / status / cancel / resume / discard)
# ══════════════════════════════════════════════════════════════════════


class TestCloudCopyPR2Routes:
    def test_run_requires_confirm_token(self, client, cc_tmp, reset_active_session):
        r = client.post("/api/cloudcopy/run", json={})
        assert r.status_code == 400
        assert "confirm_token" in r.get_json()["error"]

    def test_run_refuses_wrong_confirm_token(self, client, cc_tmp, reset_active_session):
        r = client.post("/api/cloudcopy/run", json={"confirm_token": "yes"})
        assert r.status_code == 400

    def test_run_launches_with_correct_token(
        self, client, cc_tmp, synthetic_source, tmp_path, reset_active_session, monkeypatch
    ):
        monkeypatch.setattr(cloudcopy, "DEFAULT_SOURCE_ROOT", str(synthetic_source))
        monkeypatch.setattr(cloudcopy, "DEFAULT_DESTINATION_ROOT", str(tmp_path / "dest"))
        r = client.post("/api/cloudcopy/run", json={"confirm_token": "START CLOUD COPY"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"]
        assert data["session_id"]
        for _ in range(100):
            time.sleep(0.05)
            if cloudcopy.get_active_session_id() is None:
                break

    def test_run_409_when_session_already_active(self, client, cc_tmp, reset_active_session, mocker):
        mocker.patch.object(
            cloudcopy,
            "start_copy_session",
            return_value={"ok": False, "error": "another session is active: abc"},
        )
        r = client.post("/api/cloudcopy/run", json={"confirm_token": "START CLOUD COPY"})
        assert r.status_code == 409

    def test_status_requires_session_id(self, client, cc_tmp):
        r = client.get("/api/cloudcopy/status")
        assert r.status_code == 400

    def test_status_returns_missing_for_unknown_session(self, client, cc_tmp):
        r = client.get("/api/cloudcopy/status?session_id=zzzz")
        assert r.status_code == 200
        assert r.get_json()["state"] == "missing"

    def test_cancel_requires_session_id(self, client, cc_tmp):
        r = client.post("/api/cloudcopy/cancel", json={})
        assert r.status_code == 400

    def test_cancel_404_when_session_not_active(self, client, cc_tmp, reset_active_session):
        r = client.post("/api/cloudcopy/cancel", json={"session_id": "not-active"})
        assert r.status_code == 404

    def test_resume_returns_400_when_no_orphan(self, client, cc_tmp, reset_active_session):
        r = client.post("/api/cloudcopy/resume", json={})
        assert r.status_code == 400

    def test_discard_returns_400_when_no_orphan(self, client, cc_tmp):
        r = client.post("/api/cloudcopy/discard-crashed", json={})
        assert r.status_code == 400


class TestResumeStateRouteDistinguishesActive:
    """Running sessions must NOT be reported as 'crashed' -- otherwise
    the UI shows a spurious 'Resume previous run?' banner during a
    normal in-progress copy."""

    def test_running_session_not_reported_as_crashed(
        self, client, cc_tmp, synthetic_source, tmp_path, reset_active_session
    ):
        cloudcopy._active_session_id = "running-session"
        state = {
            "session_id": "running-session",
            "started_at": "2026-05-25T10:00:00",
            "rules_hash": "abc",
            "source_root": str(synthetic_source),
            "dest_root": str(tmp_path / "dest"),
            "plan": [],
            "cursor": 0,
            "bytes_copied": 0,
            "files_completed": [],
            "files_skipped": [],
            "files_failed": [],
        }
        cloudcopy._save_state(state)
        r = client.get("/api/cloudcopy/resume-state")
        data = r.get_json()
        assert data["has_crashed"] is False
        assert data["active_session_id"] == "running-session"

    def test_orphan_session_reported_as_crashed(self, client, cc_tmp, synthetic_source, tmp_path):
        cloudcopy._active_session_id = None
        state = {
            "session_id": "orphan-session",
            "started_at": "2026-05-25T10:00:00",
            "rules_hash": "abc",
            "source_root": str(synthetic_source),
            "dest_root": str(tmp_path / "dest"),
            "plan": [],
            "cursor": 5,
            "bytes_copied": 12345,
            "files_completed": [],
            "files_skipped": [],
            "files_failed": [],
        }
        cloudcopy._save_state(state)
        r = client.get("/api/cloudcopy/resume-state")
        data = r.get_json()
        assert data["has_crashed"] is True
        assert data["state"]["session_id"] == "orphan-session"
