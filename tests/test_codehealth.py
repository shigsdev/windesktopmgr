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
    """Redirect STATE_FILE to tmp_path so tests don't touch the real
    codehealth_state.json next to the running tray."""
    state_path = tmp_path / "codehealth_state.json"
    monkeypatch.setattr(codehealth, "STATE_FILE", str(state_path))
    yield {"state": state_path, "tmp": tmp_path}


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
