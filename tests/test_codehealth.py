"""tests/test_codehealth.py -- Utilities tab code-health scanners (backlog #51).

Coverage:
  - Each of the four scanners (coverage / ruff / secrets / tech_debt)
    with happy + failure paths
  - _worst_level rollup
  - State persistence (load/save/is_stale)
  - run_in_background guard (no double-runs)
  - Routes /api/codehealth/status + /api/codehealth/run + 409 conflict

All subprocess calls are mocked so the suite stays fast (~100ms) and
deterministic regardless of what's on disk. The two routes are tested
with the Flask client. tmp_path redirects STATE_FILE per-test so the
on-disk state file is never touched.
"""

from __future__ import annotations

import json
import subprocess

import pytest

import codehealth


@pytest.fixture
def ch_tmp(tmp_path, monkeypatch):
    """Redirect STATE_FILE + EMITTED_FILE + BACKLOG_PATH to tmp_path so
    tests don't touch the real codehealth_state.json / emitted.json /
    project backlog markdown next to the running tray."""
    state_path = tmp_path / "codehealth_state.json"
    emitted_path = tmp_path / "codehealth_emitted.json"
    backlog_path = tmp_path / "project_backlog.md"
    monkeypatch.setattr(codehealth, "STATE_FILE", str(state_path))
    monkeypatch.setattr(codehealth, "EMITTED_FILE", str(emitted_path))
    monkeypatch.setattr(codehealth, "BACKLOG_PATH", str(backlog_path))
    yield {
        "state": state_path,
        "emitted": emitted_path,
        "backlog": backlog_path,
        "tmp": tmp_path,
    }


# ─── load_state / save_state / is_stale ─────────────────────────────


class TestStatePersistence:
    def test_load_missing_returns_empty_dict(self, ch_tmp):
        assert codehealth.load_state() == {}

    def test_save_and_load_round_trip(self, ch_tmp):
        payload = {"finished_at": "2026-05-26T10:00:00", "scanners": {}}
        assert codehealth.save_state(payload)
        assert codehealth.load_state() == payload

    def test_load_malformed_json_returns_empty(self, ch_tmp):
        ch_tmp["state"].write_text("{ not json")
        assert codehealth.load_state() == {}

    def test_is_stale_no_timestamp(self, ch_tmp):
        assert codehealth.is_stale({}) is True

    def test_is_stale_fresh_returns_false(self, ch_tmp):
        from datetime import datetime

        now = datetime.now().isoformat(timespec="seconds")
        assert codehealth.is_stale({"finished_at": now}) is False

    def test_is_stale_old_returns_true(self, ch_tmp):
        # 30 days ago -- well past the 7-day threshold.
        assert codehealth.is_stale({"finished_at": "2026-04-01T00:00:00"}) is True

    def test_is_stale_unparseable_timestamp_returns_true(self, ch_tmp):
        assert codehealth.is_stale({"finished_at": "not-a-date"}) is True


# ─── scan_coverage ──────────────────────────────────────────────────


class TestScanCoverage:
    def test_missing_coverage_file(self, ch_tmp, monkeypatch):
        # Point _REPO_ROOT at an empty tmp dir so there is no .coverage file.
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_coverage()
        assert result["ok"] is False
        assert ".coverage file not found" in result["error"]

    def test_happy_path_parses_total(self, ch_tmp, mocker, monkeypatch):
        # Pretend .coverage exists so we hit the subprocess path.
        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(
            {
                "totals": {"percent_covered": 87.2},
                "files": {
                    "a.py": {"summary": {"percent_covered": 50}},
                    "b.py": {"summary": {"percent_covered": 95}},
                },
            }
        )
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_coverage()
        assert result["ok"] is True
        assert result["level"] == "ok"
        assert "87.2%" in result["summary"]
        assert result["details"][0]["file"] == "a.py"  # worst file first

    def test_below_50_is_critical(self, ch_tmp, mocker, monkeypatch):
        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"totals": {"percent_covered": 30.0}, "files": {}})
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        assert codehealth.scan_coverage()["level"] == "critical"

    def test_between_50_and_80_is_warning(self, ch_tmp, mocker, monkeypatch):
        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"totals": {"percent_covered": 70.0}, "files": {}})
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        assert codehealth.scan_coverage()["level"] == "warning"

    def test_timeout_returns_error_dict(self, ch_tmp, mocker, monkeypatch):
        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mocker.patch(
            "codehealth.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=60),
        )
        result = codehealth.scan_coverage()
        assert result["ok"] is False

    def test_stale_coverage_demotes_severity_and_tags_summary(self, ch_tmp, mocker, monkeypatch):
        """User report 2026-05-27: card showed '57.1% (warning)' against a
        16-day-old .coverage file. Stale data must not drive severity --
        downgrade to info and tag the summary as stale so the user knows
        not to trust the number."""
        import os
        import time

        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")
        # Set the file's mtime to 10 days ago.
        ten_days_ago = time.time() - (10 * 86400)
        os.utime(cov_path, (ten_days_ago, ten_days_ago))
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        # Would normally be 'warning' at 57.1% -- but staleness demotes to info.
        mock_proc.stdout = json.dumps({"totals": {"percent_covered": 57.1}, "files": {}})
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_coverage()
        assert result["is_stale"] is True
        assert result["level"] == "info", f"stale .coverage must NOT drive warning/critical; got {result['level']}"
        assert "stale" in result["summary"].lower()
        assert "57.1%" in result["summary"]  # number still shown
        assert result["coverage_age_days"] is not None and result["coverage_age_days"] >= 9.5

    def test_fresh_coverage_uses_real_severity(self, ch_tmp, mocker, monkeypatch):
        """The inverse: a fresh .coverage file with the same 57.1% MUST
        fire warning. Staleness is the override -- when data is fresh,
        the threshold ladder applies normally."""
        cov_path = ch_tmp["tmp"] / ".coverage"
        cov_path.write_bytes(b"")  # mtime = now -> NOT stale
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"totals": {"percent_covered": 57.1}, "files": {}})
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_coverage()
        assert result["is_stale"] is False
        assert result["level"] == "warning"
        assert "stale" not in result["summary"].lower()


# ─── scan_ruff ──────────────────────────────────────────────────────


class TestScanRuff:
    def test_clean_returns_ok(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "[]"
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_ruff()
        assert result["ok"] is True
        assert result["level"] == "ok"
        assert result["count"] == 0

    def test_security_finding_promotes_to_critical(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(
            [
                {
                    "code": "S105",
                    "message": "hardcoded password",
                    "filename": "x.py",
                    "location": {"row": 10},
                }
            ]
        )
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_ruff()
        assert result["level"] == "critical"
        assert result["count"] == 1

    def test_correctness_finding_is_warning(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(
            [
                {
                    "code": "F401",
                    "message": "unused import",
                    "filename": "x.py",
                    "location": {"row": 1},
                }
            ]
        )
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        assert codehealth.scan_ruff()["level"] == "warning"

    def test_modernisation_only_is_info(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(
            [
                {"code": "UP038", "message": "x", "filename": "x.py", "location": {"row": 1}},
                {"code": "UP038", "message": "y", "filename": "y.py", "location": {"row": 2}},
            ]
        )
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_ruff()
        assert result["level"] == "info"
        assert result["count"] == 2

    def test_unexpected_returncode_returns_error_dict(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "ruff blew up"
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        assert codehealth.scan_ruff()["ok"] is False

    def test_malformed_json_returns_error_dict(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "not json"
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        assert codehealth.scan_ruff()["ok"] is False


# ─── scan_secrets ───────────────────────────────────────────────────


class TestScanSecrets:
    def test_clean_returns_ok(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_secrets()
        assert result["ok"] is True
        assert result["level"] == "ok"
        assert result["count"] == 0

    def test_leak_promotes_to_critical(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "Finding: <REDACTED>\nFinding: <REDACTED>\n"
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_secrets()
        assert result["level"] == "critical"
        assert result["count"] == 2
        # Detail bodies redacted -- we must never echo the actual secret.
        assert result["details"] == []

    def test_secrets_finding_count_falls_back_to_one_when_unparseable(self, mocker):
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "leaks found but no 'Finding:' marker"
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        result = codehealth.scan_secrets()
        assert result["level"] == "critical"
        assert result["count"] == 1


# ─── scan_tech_debt ─────────────────────────────────────────────────


class TestScanTechDebt:
    def test_empty_repo_is_ok(self, ch_tmp, monkeypatch):
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_tech_debt()
        assert result["ok"] is True
        assert result["level"] == "ok"
        assert result["count"] == 0

    def test_counts_todo_markers(self, ch_tmp, monkeypatch):
        (ch_tmp["tmp"] / "a.py").write_text("# TODO: fix this\nx = 1\n# FIXME later\n")
        (ch_tmp["tmp"] / "b.py").write_text("# XXX hack\n# HACK\n")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_tech_debt()
        # 2 in a.py + 2 in b.py = 4 markers
        assert result["details"]["todos"]  # samples populated
        # count = markers + large_files; no large files here.
        assert result["count"] == 4

    def test_flags_large_files(self, ch_tmp, monkeypatch):
        big = "\n".join("x = 1" for _ in range(5500))
        (ch_tmp["tmp"] / "huge.py").write_text(big)
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_tech_debt()
        large = result["details"]["large_files"]
        assert len(large) == 1
        assert large[0]["file"] == "huge.py"
        assert large[0]["lines"] >= 5500

    def test_skips_generated_dirs(self, ch_tmp, monkeypatch):
        (ch_tmp["tmp"] / "__pycache__").mkdir()
        (ch_tmp["tmp"] / "__pycache__" / "junk.py").write_text("# TODO ignore me")
        (ch_tmp["tmp"] / ".git").mkdir()
        (ch_tmp["tmp"] / ".git" / "config").write_text("# TODO never")
        (ch_tmp["tmp"] / "real.py").write_text("# TODO real\n")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_tech_debt()
        # Only the real.py TODO should count.
        assert result["count"] == 1

    def test_html_files_scanned(self, ch_tmp, monkeypatch):
        (ch_tmp["tmp"] / "templates").mkdir()
        (ch_tmp["tmp"] / "templates" / "x.html").write_text("<!-- FIXME ui -->\n")
        monkeypatch.setattr(codehealth, "_REPO_ROOT", str(ch_tmp["tmp"]))
        result = codehealth.scan_tech_debt()
        assert result["count"] == 1


# ─── _worst_level ───────────────────────────────────────────────────


class TestWorstLevel:
    def test_all_ok(self):
        scanners = {
            "a": {"level": "ok"},
            "b": {"level": "ok"},
        }
        assert codehealth._worst_level(scanners) == "ok"

    def test_critical_wins(self):
        scanners = {
            "a": {"level": "ok"},
            "b": {"level": "critical"},
            "c": {"level": "warning"},
        }
        assert codehealth._worst_level(scanners) == "critical"

    def test_info_beats_ok(self):
        scanners = {
            "a": {"level": "ok"},
            "b": {"level": "info"},
        }
        assert codehealth._worst_level(scanners) == "info"

    def test_handles_malformed_entries(self):
        scanners = {
            "a": "not a dict",  # type: ignore
            "b": {"level": "warning"},
        }
        assert codehealth._worst_level(scanners) == "warning"


# ─── run_in_background guard ────────────────────────────────────────


class TestBackgroundRunGuard:
    def test_skips_when_already_running(self, ch_tmp, monkeypatch):
        # Manually set the running flag and confirm a second call is a no-op.
        monkeypatch.setattr(codehealth, "_running", True)
        assert codehealth.run_in_background() is False

    def test_maybe_run_on_boot_skips_fresh(self, ch_tmp, mocker):
        from datetime import datetime

        codehealth.save_state(
            {
                "finished_at": datetime.now().isoformat(timespec="seconds"),
                "scanners": {},
            }
        )
        spy = mocker.spy(codehealth, "run_in_background")
        assert codehealth.maybe_run_on_boot() is False
        assert spy.call_count == 0

    def test_maybe_run_on_boot_fires_when_stale(self, ch_tmp, mocker):
        codehealth.save_state({"finished_at": "2026-01-01T00:00:00", "scanners": {}})
        mock_thread = mocker.patch("codehealth.threading.Thread")
        result = codehealth.maybe_run_on_boot()
        assert result is True
        assert mock_thread.return_value.start.call_count == 1


# ─── Routes ─────────────────────────────────────────────────────────


class TestCodeHealthRoutes:
    def test_status_returns_empty_state_first_run(self, client, ch_tmp):
        r = client.get("/api/codehealth/status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["state"] == {}
        assert data["is_stale"] is True
        assert data["is_running"] is False
        assert data["is_refreshing_coverage"] is False
        assert data["stale_days_threshold"] == codehealth.STALE_DAYS

    def test_status_returns_persisted_state(self, client, ch_tmp):
        payload = {
            "finished_at": "2026-05-26T10:00:00",
            "scanners": {"ruff": {"level": "ok", "count": 0}},
            "worst_level": "ok",
        }
        codehealth.save_state(payload)
        r = client.get("/api/codehealth/status")
        data = r.get_json()
        assert data["state"]["worst_level"] == "ok"

    def test_run_kicks_off_scan(self, client, ch_tmp, mocker):
        # Patch run_in_background so it returns True without actually
        # spawning a thread.
        mocker.patch("codehealth.run_in_background", return_value=True)
        r = client.post("/api/codehealth/run")
        assert r.status_code == 202
        data = r.get_json()
        assert data["ok"] is True
        assert data["started"] is True

    def test_run_conflict_when_already_running(self, client, ch_tmp, mocker):
        mocker.patch("codehealth.run_in_background", return_value=False)
        r = client.post("/api/codehealth/run")
        assert r.status_code == 409
        data = r.get_json()
        assert data["ok"] is False
        assert "already running" in data["error"]


# ─── Coverage refresh (PR-2 of #51) ─────────────────────────────────


class TestRefreshCoverage:
    def test_refresh_kicks_off_pytest_subprocess(self, ch_tmp, mocker):
        """The thread body should call pytest --cov against the repo."""
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "all green"
        mock_proc.stderr = ""
        run_spy = mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        # Patch out the post-refresh scan_all so the test stays fast.
        mocker.patch("codehealth.run_in_background")
        codehealth._refresh_coverage_and_rescan()
        # Subprocess should have been invoked with pytest + --cov.
        assert run_spy.call_count == 1
        cmd = run_spy.call_args[0][0]
        assert "pytest" in " ".join(cmd)
        assert "--cov" in cmd
        # is_refreshing_coverage flag should be cleared after the body runs.
        assert codehealth.is_refreshing_coverage() is False
        last = codehealth.get_coverage_refresh_last_result()
        assert last is not None
        assert last["ok"] is True
        assert last["returncode"] == 0

    def test_refresh_pytest_failure_still_reports_ok(self, ch_tmp, mocker):
        """pytest exit 1 means tests failed but .coverage was still
        written -- the refresh achieved its goal. ok should still be True."""
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "1 failed"
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        mocker.patch("codehealth.run_in_background")
        codehealth._refresh_coverage_and_rescan()
        last = codehealth.get_coverage_refresh_last_result()
        assert last["ok"] is True
        assert last["returncode"] == 1

    def test_refresh_internal_error_returns_failure(self, ch_tmp, mocker):
        """Exit codes other than 0/1/5 are real failures (e.g. 2 =
        interrupted, 3 = internal error). Report ok=False."""
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 3
        mock_proc.stdout = ""
        mock_proc.stderr = "internal error"
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        mocker.patch("codehealth.run_in_background")
        codehealth._refresh_coverage_and_rescan()
        last = codehealth.get_coverage_refresh_last_result()
        assert last["ok"] is False
        assert "pytest returned 3" in last["error"]
        assert "internal error" in last["stderr_tail"]

    def test_refresh_timeout_reports_failure(self, ch_tmp, mocker):
        mocker.patch(
            "codehealth.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pytest", timeout=600),
        )
        mocker.patch("codehealth.run_in_background")
        codehealth._refresh_coverage_and_rescan()
        last = codehealth.get_coverage_refresh_last_result()
        assert last["ok"] is False
        assert "timeout" in last["error"].lower()

    def test_refresh_triggers_followup_scan_all(self, ch_tmp, mocker):
        """After pytest exits, the refresh worker fires a scan_all so
        all 4 cards re-render with the fresh data in one shot."""
        mock_proc = mocker.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mocker.patch("codehealth.subprocess.run", return_value=mock_proc)
        run_spy = mocker.patch("codehealth.run_in_background")
        codehealth._refresh_coverage_and_rescan()
        assert run_spy.call_count == 1, "scan_all must fire after pytest completes"

    def test_refresh_in_background_skips_when_already_running(self, ch_tmp, monkeypatch):
        monkeypatch.setattr(codehealth, "_coverage_refresh_running", True)
        assert codehealth.refresh_coverage_in_background() is False

    def test_refresh_route_returns_202(self, client, ch_tmp, mocker):
        mocker.patch("codehealth.refresh_coverage_in_background", return_value=True)
        r = client.post("/api/codehealth/refresh-coverage")
        assert r.status_code == 202
        data = r.get_json()
        assert data["ok"] is True
        assert data["started"] is True

    def test_refresh_route_returns_409_when_in_flight(self, client, ch_tmp, mocker):
        mocker.patch("codehealth.refresh_coverage_in_background", return_value=False)
        r = client.post("/api/codehealth/refresh-coverage")
        assert r.status_code == 409
        data = r.get_json()
        assert data["ok"] is False
        assert "already running" in data["error"]

    def test_status_exposes_refresh_flag(self, client, ch_tmp, mocker):
        mocker.patch("codehealth.is_refreshing_coverage", return_value=True)
        r = client.get("/api/codehealth/status")
        data = r.get_json()
        assert data["is_refreshing_coverage"] is True


# ─── Backlog auto-append (PR-2 sub-task B, 2026-05-27) ──────────────


# Minimal real-shape backlog skeleton -- the appender inserts before
# the "**Priority key:**" anchor so we mimic that section verbatim.
_BACKLOG_SKELETON = """# Project Backlog

### Backlog

| # | Feature | Effort | Priority |
|---|---------|--------|----------|
| 50 | **Existing feature row** | Medium | P1 |
| 51 | **Another existing row** | Small | P2 |

**Priority key:** P0 = do next, P1 = high value, P2 = nice to have
"""


class TestFindingsToBacklogEntries:
    def test_coverage_warning_emits_entry(self):
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok", "count": 0},
                "tech_debt": {"details": {"large_files": []}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert len(entries) == 1
        assert entries[0]["category"] == "Code Health"
        assert entries[0]["priority"] == "P1"
        assert "70%" in entries[0]["title"]

    def test_coverage_critical_emits_p0(self):
        scan = {
            "scanners": {
                "coverage": {"level": "critical", "count": 30, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok", "count": 0},
                "tech_debt": {"details": {"large_files": []}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert entries[0]["priority"] == "P0"
        assert entries[0]["severity"] == "critical"

    def test_stale_coverage_does_not_emit(self):
        """Don't add backlog rows from a historical/stale coverage
        reading -- the user's already-shipped fix might have moved
        the % since."""
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 57, "is_stale": True},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert entries == []

    def test_ruff_security_emits_critical_p0(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {
                    "details": [
                        {
                            "code": "S105",
                            "message": "hardcoded password",
                            "file": "auth.py",
                            "line": 42,
                        }
                    ]
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert len(entries) == 1
        assert entries[0]["category"] == "Security"
        assert entries[0]["priority"] == "P0"
        assert "S105" in entries[0]["title"]

    def test_ruff_correctness_emits_warning_p1(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {
                    "details": [
                        {
                            "code": "F401",
                            "message": "unused import 'foo'",
                            "file": "x.py",
                            "line": 1,
                        }
                    ]
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert len(entries) == 1
        assert entries[0]["category"] == "Code Bug"
        assert entries[0]["priority"] == "P1"

    def test_ruff_modernisation_no_individual_rows(self):
        """UP/PIE/SIM-class findings must NOT emit per-finding rows --
        they're style fixes, not bugs (they get rolled up separately)."""
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {
                    "details": [
                        {"code": "UP038", "message": "...", "file": "x.py", "line": 1},
                        {"code": "PIE810", "message": "...", "file": "y.py", "line": 2},
                    ],
                    "by_prefix": {"UP": 1, "PIE": 1},
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert [e for e in entries if e.get("source") == "ruff"] == []

    def test_ruff_style_findings_emit_single_rollup(self):
        """User feedback 2026-05-27: card showed 10 UP findings but
        zero in the backlog because the per-finding filter skipped
        them. Fix: ONE consolidated rollup row covers the batch."""
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {
                    "details": [{"code": "UP038", "message": "...", "file": "x.py", "line": 1}],
                    "by_prefix": {"UP": 10},
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        rollups = [e for e in entries if e.get("source") == "ruff_style"]
        assert len(rollups) == 1
        r = rollups[0]
        assert r["priority"] == "P2"
        assert r["severity"] == "info"
        assert "10" in r["title"]
        assert "UP=10" in r["title"]
        assert "ruff check --fix --unsafe-fixes" in r["body"]

    def test_ruff_style_rollup_fingerprint_changes_with_count(self):
        """When the count changes (user fixed some), a NEW rollup row
        gets emitted so the user sees progress in the backlog rather
        than the old row that's now wrong."""
        scan_10 = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": [], "by_prefix": {"UP": 10}},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        scan_5 = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": [], "by_prefix": {"UP": 5}},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        e10 = next(e for e in codehealth.findings_to_backlog_entries(scan_10) if e.get("source") == "ruff_style")
        e5 = next(e for e in codehealth.findings_to_backlog_entries(scan_5) if e.get("source") == "ruff_style")
        assert e10["fingerprint"] != e5["fingerprint"]

    def test_ruff_no_style_findings_no_rollup(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": [], "by_prefix": {}},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert [e for e in entries if e.get("source") == "ruff_style"] == []

    def test_ruff_mixed_per_finding_and_rollup_coexist(self):
        """An F-class bug + a batch of UP findings -> both surface:
        one per-finding row + one rollup row."""
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {
                    "details": [{"code": "F401", "message": "unused", "file": "a.py", "line": 1}],
                    "by_prefix": {"F": 1, "UP": 10},
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        sources = [e["source"] for e in entries]
        assert sources.count("ruff") == 1
        assert sources.count("ruff_style") == 1

    def test_secrets_critical_emits_p0(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": []},
                "secrets": {"level": "critical", "count": 3},
                "tech_debt": {"details": {}},
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert len(entries) == 1
        assert entries[0]["category"] == "Security"
        assert entries[0]["priority"] == "P0"
        assert "3" in entries[0]["title"]

    def test_secrets_clean_emits_nothing(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": []},
                "secrets": {"level": "ok", "count": 0},
                "tech_debt": {"details": {}},
            }
        }
        assert codehealth.findings_to_backlog_entries(scan) == []

    def test_large_files_emit_info_p2(self):
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {
                    "details": {
                        "large_files": [
                            {"file": "huge.py", "lines": 12000},
                            {"file": "big.html", "lines": 5500},
                        ]
                    }
                },
            }
        }
        entries = codehealth.findings_to_backlog_entries(scan)
        assert len(entries) == 2
        assert all(e["priority"] == "P2" for e in entries)
        assert all(e["category"] == "Tech Debt" for e in entries)
        assert "huge.py" in entries[0]["title"]
        assert "12,000" in entries[0]["title"]

    def test_fingerprint_is_stable_across_calls(self):
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        e1 = codehealth.findings_to_backlog_entries(scan)
        e2 = codehealth.findings_to_backlog_entries(scan)
        assert e1[0]["fingerprint"] == e2[0]["fingerprint"]
        # Different inputs -> different fingerprints.
        scan2 = dict(scan)
        scan2["scanners"] = dict(scan["scanners"])
        scan2["scanners"]["coverage"] = {"level": "critical", "count": 30, "is_stale": False}
        e3 = codehealth.findings_to_backlog_entries(scan2)
        assert e1[0]["fingerprint"] != e3[0]["fingerprint"]


class TestAppendFindingsToBacklog:
    def _setup_backlog(self, ch_tmp):
        ch_tmp["backlog"].write_text(_BACKLOG_SKELETON, encoding="utf-8")

    def test_appends_new_rows_before_priority_key(self, ch_tmp):
        self._setup_backlog(ch_tmp)
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        result = codehealth.append_findings_to_backlog(scan)
        assert result["ok"] is True
        assert result["appended"] == 1
        text = ch_tmp["backlog"].read_text(encoding="utf-8")
        # New row should appear BEFORE the priority key line.
        new_row_idx = text.find("Scan finding")
        priority_idx = text.find("**Priority key:**")
        assert new_row_idx != -1
        assert priority_idx != -1
        assert new_row_idx < priority_idx
        # Next number should be 52 (max existing was 51).
        assert "| 52 |" in text

    def test_dedup_skips_already_emitted_findings(self, ch_tmp):
        self._setup_backlog(ch_tmp)
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        r1 = codehealth.append_findings_to_backlog(scan)
        r2 = codehealth.append_findings_to_backlog(scan)
        assert r1["appended"] == 1
        assert r2["appended"] == 0
        assert r2["skipped"] == 1
        # Backlog should have exactly ONE auto-row, not two.
        text = ch_tmp["backlog"].read_text(encoding="utf-8")
        assert text.count("Scan finding") == 1

    def test_missing_backlog_file_returns_error_no_crash(self, ch_tmp):
        # No backlog file created.
        scan = {
            "scanners": {
                "coverage": {"level": "critical", "count": 20, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        result = codehealth.append_findings_to_backlog(scan)
        assert result["ok"] is False
        assert "not found" in result["error"]
        assert result["appended"] == 0

    def test_no_findings_returns_ok_with_zero_appended(self, ch_tmp):
        self._setup_backlog(ch_tmp)
        scan = {
            "scanners": {
                "coverage": {"level": "ok"},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        result = codehealth.append_findings_to_backlog(scan)
        assert result["ok"] is True
        assert result["appended"] == 0

    def test_multiple_findings_get_sequential_numbers(self, ch_tmp):
        self._setup_backlog(ch_tmp)
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {
                    "details": [
                        {"code": "S105", "message": "hp", "file": "a.py", "line": 1},
                        {"code": "F401", "message": "ui", "file": "b.py", "line": 2},
                    ]
                },
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        result = codehealth.append_findings_to_backlog(scan)
        assert result["appended"] == 3
        text = ch_tmp["backlog"].read_text(encoding="utf-8")
        # Existing rows 50, 51 -- new ones should be 52, 53, 54.
        assert "| 52 |" in text
        assert "| 53 |" in text
        assert "| 54 |" in text

    def test_reset_emitted_allows_re_append(self, ch_tmp):
        self._setup_backlog(ch_tmp)
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        codehealth.append_findings_to_backlog(scan)
        codehealth.reset_emitted_fingerprints()
        # After reset, same scan should re-emit.
        result = codehealth.append_findings_to_backlog(scan)
        assert result["appended"] == 1

    def test_backlog_no_priority_key_anchor_falls_back_to_append(self, ch_tmp):
        """If the user has moved/removed the **Priority key:** anchor,
        the function should still succeed -- append at the end of the file."""
        ch_tmp["backlog"].write_text("| 1 | foo | Small | P0 |\n", encoding="utf-8")
        scan = {
            "scanners": {
                "coverage": {"level": "warning", "count": 70, "is_stale": False},
                "ruff": {"details": []},
                "secrets": {"level": "ok"},
                "tech_debt": {"details": {}},
            }
        }
        result = codehealth.append_findings_to_backlog(scan)
        assert result["ok"] is True
        assert result["appended"] == 1
        text = ch_tmp["backlog"].read_text(encoding="utf-8")
        assert "Scan finding" in text


class TestEmittedFingerprintPersistence:
    def test_load_missing_returns_empty_set(self, ch_tmp):
        assert codehealth.load_emitted_fingerprints() == set()

    def test_save_and_load_round_trip(self, ch_tmp):
        fps = {"aaa111", "bbb222", "ccc333"}
        codehealth.save_emitted_fingerprints(fps)
        assert codehealth.load_emitted_fingerprints() == fps

    def test_load_malformed_returns_empty_set(self, ch_tmp):
        ch_tmp["emitted"].write_text("{not json", encoding="utf-8")
        assert codehealth.load_emitted_fingerprints() == set()

    def test_reset_wipes_state(self, ch_tmp):
        codehealth.save_emitted_fingerprints({"aaa"})
        codehealth.reset_emitted_fingerprints()
        assert codehealth.load_emitted_fingerprints() == set()


class TestResetEmittedRoute:
    def test_post_returns_200_and_clears(self, client, ch_tmp):
        codehealth.save_emitted_fingerprints({"abc"})
        r = client.post("/api/codehealth/reset-emitted")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True
        assert codehealth.load_emitted_fingerprints() == set()


class TestRunAndSaveAppendsToBacklog:
    """Integration test: scan_all() -> save_state() -> append_findings_
    to_backlog() should chain through _run_and_save without raising."""

    def test_run_and_save_appends_findings(self, ch_tmp, mocker):
        # Mock scan_all to return a single warning finding.
        mocker.patch(
            "codehealth.scan_all",
            return_value={
                "started_at": "2026-05-27T20:00:00",
                "finished_at": "2026-05-27T20:00:05",
                "worst_level": "warning",
                "scanners": {
                    "coverage": {"level": "ok"},
                    "ruff": {"details": [{"code": "F401", "message": "x", "file": "a.py", "line": 1}]},
                    "secrets": {"level": "ok"},
                    "tech_debt": {"details": {}},
                },
            },
        )
        ch_tmp["backlog"].write_text(_BACKLOG_SKELETON, encoding="utf-8")
        codehealth._run_and_save()
        text = ch_tmp["backlog"].read_text(encoding="utf-8")
        assert "Scan finding" in text
        assert "F401" in text

    def test_run_and_save_survives_missing_backlog(self, ch_tmp, mocker):
        """If the backlog file is missing (different machine, etc.),
        the scan must still complete + persist state -- append failure
        is non-fatal."""
        mocker.patch(
            "codehealth.scan_all",
            return_value={
                "scanners": {
                    "coverage": {"level": "warning", "count": 70, "is_stale": False},
                    "ruff": {"details": []},
                    "secrets": {"level": "ok"},
                    "tech_debt": {"details": {}},
                },
            },
        )
        # No backlog file created -- function should swallow the error.
        codehealth._run_and_save()
        # State got persisted despite backlog miss.
        state = codehealth.load_state()
        assert state.get("scanners", {}).get("coverage", {}).get("level") == "warning"
