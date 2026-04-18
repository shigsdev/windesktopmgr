"""
Tests for ``post_update_check.py`` — backlog #25.

Covers the five layers of the post-Windows-Update regression runner:
  1. Update detection via WMI (``get_latest_hotfix``, ``detect_new_update``)
  2. State file read/write (``load_state`` / ``save_state``)
  3. Subprocess runners (``run_pytest``, ``run_verify``)
  4. Gmail SMTP email (``send_email``) using the same
     ``diag_email_config.xml`` DPAPI-encrypted credentials as the daily
     SystemHealthDiag.py report.
  5. Backlog auto-entry prepender + full orchestrator (``run_post_update_check``)

All external side effects are mocked — no real WMI calls, subprocess spawns,
SMTP connections, or filesystem writes outside ``tmp_path``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import post_update_check as puc

# ══════════════════════════════════════════════════════════════════════════════
# _normalize_installed_date — pure
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeInstalledDate:
    def test_us_format(self):
        assert puc._normalize_installed_date("04/10/2026") == "2026-04-10T00:00:00"

    def test_iso_date(self):
        assert puc._normalize_installed_date("2026-04-10") == "2026-04-10T00:00:00"

    def test_iso_datetime(self):
        assert puc._normalize_installed_date("2026-04-10T12:30:45") == "2026-04-10T12:30:45"

    def test_empty(self):
        assert puc._normalize_installed_date("") == ""

    def test_whitespace(self):
        assert puc._normalize_installed_date("  04/10/2026  ") == "2026-04-10T00:00:00"

    def test_unknown_format_passes_through(self):
        """Unknown formats are not dropped — downstream sort falls back on KB #."""
        out = puc._normalize_installed_date("Apr 10 2026")
        assert out == "Apr 10 2026"


# ══════════════════════════════════════════════════════════════════════════════
# _parse_pytest_counts — pure
# ══════════════════════════════════════════════════════════════════════════════


class TestParsePytestCounts:
    def test_all_passed(self):
        out = "============== 1343 passed in 174.83s =============="
        passed, failed = puc._parse_pytest_counts(out)
        assert passed == 1343 and failed == 0

    def test_some_failed(self):
        out = "============== 1340 passed, 3 failed in 175s =============="
        passed, failed = puc._parse_pytest_counts(out)
        assert passed == 1340 and failed == 3

    def test_no_match(self):
        assert puc._parse_pytest_counts("unrelated output") == (0, 0)

    def test_parses_summary_after_long_coverage_report(self):
        """Regression: the pass/fail counts must be found even when a 180-line
        coverage report sits between the dots and the summary line."""
        coverage = "\n".join(f"file{i}.py 100 10 90%" for i in range(200))
        out = f"........................\n{coverage}\n1415 passed, 38 deselected in 147.94s (0:02:27)\n"
        passed, failed = puc._parse_pytest_counts(out)
        assert passed == 1415 and failed == 0


class TestExtractPytestExcerpt:
    def test_includes_summary_line_even_with_long_coverage(self):
        """Tail-40 alone would miss the summary when coverage is 200 lines."""
        coverage = "\n".join(f"module_{i}.py 100 10 90%" for i in range(60))
        out = f"...dots...\n{coverage}\n============= 1415 passed, 38 deselected in 147.94s =============\n"
        excerpt = puc._extract_pytest_excerpt(out, max_lines=40)
        assert "1415 passed" in excerpt

    def test_small_output_passes_through(self):
        out = "line1\nline2\n=== 5 passed in 1s ==="
        assert "5 passed" in puc._extract_pytest_excerpt(out, max_lines=40)


# ══════════════════════════════════════════════════════════════════════════════
# get_latest_hotfix — mock wmi
# ══════════════════════════════════════════════════════════════════════════════


class _FakeHotfix:
    def __init__(self, hfid, installed_on):
        self.HotFixID = hfid
        self.InstalledOn = installed_on


class TestGetLatestHotfix:
    def _mock_wmi(self, mocker, hotfixes):
        fake_wmi = mocker.Mock()
        fake_wmi.Win32_QuickFixEngineering = mocker.Mock(return_value=hotfixes)
        mocker.patch.dict("sys.modules", {"wmi": mocker.Mock(WMI=lambda: fake_wmi)})
        return fake_wmi

    def test_returns_newest_by_installed_on(self, mocker):
        self._mock_wmi(
            mocker,
            [
                _FakeHotfix("KB5001", "04/01/2026"),
                _FakeHotfix("KB5002", "04/10/2026"),
                _FakeHotfix("KB5003", "03/15/2026"),
            ],
        )
        result = puc.get_latest_hotfix()
        assert result["HotFixID"] == "KB5002"
        assert result["InstalledOn"] == "2026-04-10T00:00:00"

    def test_ties_broken_by_kb_id_desc(self, mocker):
        """When two hotfixes share an install date, the higher KB wins."""
        self._mock_wmi(
            mocker,
            [
                _FakeHotfix("KB5001", "04/10/2026"),
                _FakeHotfix("KB5099", "04/10/2026"),
            ],
        )
        assert puc.get_latest_hotfix()["HotFixID"] == "KB5099"

    def test_no_hotfixes_returns_none(self, mocker):
        self._mock_wmi(mocker, [])
        assert puc.get_latest_hotfix() is None

    def test_wmi_missing_returns_none(self, mocker):
        """wmi import failure must not crash the caller."""
        # Force the `import wmi` inside the function to raise.
        mocker.patch.dict("sys.modules", {"wmi": None})
        assert puc.get_latest_hotfix() is None

    def test_hotfix_without_id_is_skipped(self, mocker):
        self._mock_wmi(
            mocker,
            [
                _FakeHotfix("", "04/10/2026"),
                _FakeHotfix("KB5002", "04/10/2026"),
            ],
        )
        assert puc.get_latest_hotfix()["HotFixID"] == "KB5002"


# ══════════════════════════════════════════════════════════════════════════════
# State file — tmp_path isolation
# ══════════════════════════════════════════════════════════════════════════════


class TestStateFile:
    def _redirect_state(self, mocker, tmp_path) -> Path:
        state_file = tmp_path / "state.json"
        mocker.patch.object(puc, "STATE_FILE", state_file)
        mocker.patch.object(puc, "STATE_DIR", tmp_path)
        return state_file

    def test_load_state_missing_returns_empty(self, mocker, tmp_path):
        self._redirect_state(mocker, tmp_path)
        assert puc.load_state() == {}

    def test_save_then_load_roundtrip(self, mocker, tmp_path):
        self._redirect_state(mocker, tmp_path)
        puc.save_state({"last_hotfix_id": "KB5001"})
        assert puc.load_state() == {"last_hotfix_id": "KB5001"}

    def test_load_state_corrupt_returns_empty(self, mocker, tmp_path):
        state_file = self._redirect_state(mocker, tmp_path)
        state_file.write_text("not json at all", encoding="utf-8")
        assert puc.load_state() == {}

    def test_save_state_creates_parent_dir(self, mocker, tmp_path):
        new_dir = tmp_path / "nested" / "deep"
        state_file = new_dir / "state.json"
        mocker.patch.object(puc, "STATE_FILE", state_file)
        mocker.patch.object(puc, "STATE_DIR", new_dir)
        puc.save_state({"key": "value"})
        assert state_file.exists()


# ══════════════════════════════════════════════════════════════════════════════
# detect_new_update
# ══════════════════════════════════════════════════════════════════════════════


class TestDetectNewUpdate:
    def test_returns_none_when_no_hotfixes(self, mocker):
        mocker.patch.object(puc, "get_latest_hotfix", return_value=None)
        assert puc.detect_new_update({}) is None

    def test_returns_hotfix_when_new(self, mocker):
        mocker.patch.object(
            puc,
            "get_latest_hotfix",
            return_value={"HotFixID": "KB5002", "InstalledOn": "2026-04-10T00:00:00"},
        )
        state = {"last_hotfix_id": "KB5001"}
        result = puc.detect_new_update(state)
        assert result is not None and result["HotFixID"] == "KB5002"

    def test_returns_none_when_same_as_last(self, mocker):
        mocker.patch.object(
            puc,
            "get_latest_hotfix",
            return_value={"HotFixID": "KB5001", "InstalledOn": "2026-04-10T00:00:00"},
        )
        assert puc.detect_new_update({"last_hotfix_id": "KB5001"}) is None


# ══════════════════════════════════════════════════════════════════════════════
# run_pytest + run_verify — mock subprocess
# ══════════════════════════════════════════════════════════════════════════════


class TestRunPytest:
    def test_happy_path(self, mocker):
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type(
            "R",
            (),
            {"stdout": "1343 passed in 174.83s\n", "stderr": "", "returncode": 0},
        )()
        result = puc.run_pytest()
        assert result["ok"] is True
        assert result["passed"] == 1343
        assert result["failed"] == 0
        assert "1343 passed" in result["excerpt"]

    def test_failures(self, mocker):
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type(
            "R",
            (),
            {
                "stdout": "FAILED tests/test_foo.py::test_bar\n1340 passed, 3 failed\n",
                "stderr": "",
                "returncode": 1,
            },
        )()
        result = puc.run_pytest()
        assert result["ok"] is False
        assert result["failed"] == 3

    def test_timeout(self, mocker):
        mocker.patch(
            "post_update_check.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pytest", timeout=600),
        )
        result = puc.run_pytest()
        assert result["ok"] is False
        assert result["failed"] == -1
        assert "timeout" in result["excerpt"].lower()

    def test_generic_exception(self, mocker):
        mocker.patch("post_update_check.subprocess.run", side_effect=OSError("boom"))
        result = puc.run_pytest()
        assert result["ok"] is False

    def test_command_does_not_pass_quiet_flag(self, mocker):
        """
        Regression guard for the 2026-04-17 live-run bug: ``pyproject.toml``
        addopts already includes ``-q``. Passing it again promotes pytest
        to extra-quiet and suppresses the pass/fail summary line that
        ``_parse_pytest_counts`` needs to read. Never pass ``-q`` here.
        """
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type("R", (), {"stdout": "1 passed in 1s", "stderr": "", "returncode": 0})()
        puc.run_pytest()
        cmd = m.call_args[0][0]
        assert "-q" not in cmd, f"run_pytest must not pass -q (already in addopts): {cmd}"
        assert "--quiet" not in cmd


class TestRunVerify:
    def test_happy_path(self, mocker):
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type("R", (), {"stdout": "All checks passed\n", "stderr": "", "returncode": 0})()
        result = puc.run_verify()
        assert result["ok"] is True

    def test_failure(self, mocker):
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type(
            "R",
            (),
            {"stdout": "", "stderr": "selftest failed\n", "returncode": 1},
        )()
        result = puc.run_verify()
        assert result["ok"] is False
        assert "selftest failed" in result["excerpt"]

    def test_timeout(self, mocker):
        mocker.patch(
            "post_update_check.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="dev.py", timeout=300),
        )
        result = puc.run_verify()
        assert result["ok"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Email — mock keyring + smtplib
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadEmailConfig:
    """Covers the diag_email_config.xml decrypt path (shared with SystemHealthDiag)."""

    _VALID_CFG = {
        "FromEmail": "daily-report@gmail.com",
        "ToEmail": "higs78@yahoo.com",
        "Password": "app-pw-1234",
    }

    def test_missing_file_returns_none(self, mocker, tmp_path):
        mocker.patch.object(puc, "CRED_FILE", tmp_path / "nope.xml")
        assert puc._load_email_config() is None

    def test_happy_path_parses_json(self, mocker, tmp_path):
        cred = tmp_path / "diag_email_config.xml"
        cred.write_text("<Objs/>", encoding="utf-8")
        mocker.patch.object(puc, "CRED_FILE", cred)
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type(
            "R",
            (),
            {"stdout": json.dumps(self._VALID_CFG), "stderr": "", "returncode": 0},
        )()
        cfg = puc._load_email_config()
        assert cfg == self._VALID_CFG
        # Command must actually be a PowerShell Import-Clixml read
        ps_cmd = m.call_args[0][0][-1]
        assert "Import-Clixml" in ps_cmd
        assert "GetNetworkCredential" in ps_cmd

    def test_nonzero_returncode_returns_none(self, mocker, tmp_path):
        cred = tmp_path / "diag_email_config.xml"
        cred.write_text("<Objs/>", encoding="utf-8")
        mocker.patch.object(puc, "CRED_FILE", cred)
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type("R", (), {"stdout": "", "stderr": "access denied", "returncode": 1})()
        assert puc._load_email_config() is None

    def test_malformed_json_returns_none(self, mocker, tmp_path):
        cred = tmp_path / "diag_email_config.xml"
        cred.write_text("<Objs/>", encoding="utf-8")
        mocker.patch.object(puc, "CRED_FILE", cred)
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type("R", (), {"stdout": "not json!", "stderr": "", "returncode": 0})()
        assert puc._load_email_config() is None

    def test_missing_password_field_returns_none(self, mocker, tmp_path):
        cred = tmp_path / "diag_email_config.xml"
        cred.write_text("<Objs/>", encoding="utf-8")
        mocker.patch.object(puc, "CRED_FILE", cred)
        m = mocker.patch("post_update_check.subprocess.run")
        m.return_value = type(
            "R",
            (),
            {
                "stdout": json.dumps({"FromEmail": "x@y", "ToEmail": "a@b"}),
                "stderr": "",
                "returncode": 0,
            },
        )()
        assert puc._load_email_config() is None

    def test_ps_timeout_returns_none(self, mocker, tmp_path):
        cred = tmp_path / "diag_email_config.xml"
        cred.write_text("<Objs/>", encoding="utf-8")
        mocker.patch.object(puc, "CRED_FILE", cred)
        mocker.patch(
            "post_update_check.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=15),
        )
        assert puc._load_email_config() is None


class TestSendEmail:
    _CFG = {
        "FromEmail": "daily-report@gmail.com",
        "ToEmail": "higs78@yahoo.com",
        "Password": "app-pw-1234",
    }

    def test_skipped_when_no_config(self, mocker):
        """No config file → email silently skipped, SMTP never touched."""
        mocker.patch("post_update_check._load_email_config", return_value=None)
        smtp_mock = mocker.patch("post_update_check.smtplib.SMTP")
        ok = puc.send_email("subject", "body")
        assert ok is False
        smtp_mock.assert_not_called()

    def test_happy_path_sends_via_gmail_smtp(self, mocker):
        mocker.patch("post_update_check._load_email_config", return_value=self._CFG)
        smtp = mocker.Mock()
        smtp_ctx = mocker.patch("post_update_check.smtplib.SMTP")
        smtp_ctx.return_value.__enter__ = lambda self: smtp
        smtp_ctx.return_value.__exit__ = lambda self, *a: None
        ok = puc.send_email("subject", "body")
        assert ok is True
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("daily-report@gmail.com", "app-pw-1234")
        smtp.send_message.assert_called_once()
        # Must use Gmail SMTP (same as SystemHealthDiag.py)
        assert smtp_ctx.call_args[0][0] == "smtp.gmail.com"
        assert smtp_ctx.call_args[0][1] == 587

    def test_to_email_falls_back_to_from(self, mocker):
        cfg = {"FromEmail": "me@gmail.com", "Password": "pw"}
        mocker.patch("post_update_check._load_email_config", return_value=cfg)
        smtp = mocker.Mock()
        smtp_ctx = mocker.patch("post_update_check.smtplib.SMTP")
        smtp_ctx.return_value.__enter__ = lambda self: smtp
        smtp_ctx.return_value.__exit__ = lambda self, *a: None
        assert puc.send_email("subject", "body") is True
        sent = smtp.send_message.call_args[0][0]
        assert sent["To"] == "me@gmail.com"

    def test_smtp_exception_returns_false(self, mocker):
        import smtplib as _smtplib

        mocker.patch("post_update_check._load_email_config", return_value=self._CFG)
        mocker.patch(
            "post_update_check.smtplib.SMTP",
            side_effect=_smtplib.SMTPException("server down"),
        )
        assert puc.send_email("subject", "body") is False


# ══════════════════════════════════════════════════════════════════════════════
# Backlog prepender
# ══════════════════════════════════════════════════════════════════════════════


class TestPrependBacklogEntry:
    @pytest.fixture
    def fake_backlog(self, tmp_path, mocker):
        bl = tmp_path / "project_backlog.md"
        bl.write_text(
            "# Project Backlog\n"
            "\n"
            "| # | Item | Effort | Priority |\n"
            "|---|---|---|---|\n"
            "| 25 | **Post-Windows-Update regression testing** | Medium | P1 |\n",
            encoding="utf-8",
        )
        mocker.patch.object(puc, "BACKLOG_FILE", bl)
        return bl

    def test_prepends_entry_after_header(self, fake_backlog):
        ok = puc.prepend_backlog_entry(
            {"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
            {"passed": 1340, "failed": 3, "elapsed_s": 170.0, "ok": False},
            {"ok": True, "elapsed_s": 140.0},
        )
        assert ok is True
        content = fake_backlog.read_text(encoding="utf-8")
        # Header + new entry + pre-existing backlog rows, in that order
        assert content.startswith("# Project Backlog")
        assert "[POST-UPDATE REGRESSION]" in content
        assert "KB5050" in content
        # Existing row preserved
        assert "| 25 |" in content

    def test_entry_mentions_pass_fail_counts(self, fake_backlog):
        puc.prepend_backlog_entry(
            {"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
            {"passed": 1340, "failed": 3, "elapsed_s": 170.0, "ok": False},
            {"ok": False, "elapsed_s": 140.0},
        )
        content = fake_backlog.read_text(encoding="utf-8")
        assert "1340 passed, 3 failed" in content
        assert "FAILED" in content  # verify line says FAILED

    def test_missing_backlog_returns_false(self, tmp_path, mocker):
        mocker.patch.object(puc, "BACKLOG_FILE", tmp_path / "does-not-exist.md")
        ok = puc.prepend_backlog_entry(
            {"HotFixID": "KB1", "InstalledOn": ""},
            {"passed": 0, "failed": 1, "elapsed_s": 1.0, "ok": False},
            {"ok": False, "elapsed_s": 1.0},
        )
        assert ok is False


# ══════════════════════════════════════════════════════════════════════════════
# Report formatting
# ══════════════════════════════════════════════════════════════════════════════


class TestFormatReport:
    def test_no_hotfix(self):
        subject, body = puc.format_report(None, None, None)
        assert "no new updates" in subject
        assert "No Windows Update" in body

    def test_all_green_verdict(self):
        subject, body = puc.format_report(
            {"HotFixID": "KB5050", "InstalledOn": "2026-04-15"},
            {"ok": True, "passed": 1343, "failed": 0, "elapsed_s": 170.0},
            {"ok": True, "elapsed_s": 140.0},
        )
        assert "ALL GREEN" in subject
        assert "KB5050" in body
        assert "1343 passed" in body

    def test_regressions_verdict(self):
        subject, body = puc.format_report(
            {"HotFixID": "KB5050", "InstalledOn": "2026-04-15"},
            {
                "ok": False,
                "passed": 1340,
                "failed": 3,
                "elapsed_s": 170.0,
                "excerpt": "FAILED tests/test_foo.py",
            },
            {"ok": False, "elapsed_s": 140.0, "excerpt": "selftest failed"},
        )
        assert "REGRESSIONS DETECTED" in subject
        assert "[POST-UPDATE REGRESSION] entry" in body
        assert "FAILED tests/test_foo.py" in body

    def test_body_is_cp1252_encodable(self):
        """
        Regression guard for the 2026-04-17 cp1252-crash bug: a Windows
        console with default codec (``cp1252``) must be able to print the
        entire report body. No box-drawing U+2500 chars.
        """
        _, body = puc.format_report(
            {"HotFixID": "KB5050", "InstalledOn": "2026-04-15"},
            {"ok": True, "passed": 1343, "failed": 0, "elapsed_s": 170.0},
            {"ok": True, "elapsed_s": 140.0},
        )
        # Will raise UnicodeEncodeError if the body contains anything cp1252
        # can't render — that's exactly the live failure we're guarding.
        body.encode("cp1252")


class TestSafePrint:
    def test_plain_ascii_passes_through(self, capsys):
        puc._safe_print("hello world")
        assert capsys.readouterr().out.strip() == "hello world"

    def test_unicode_encode_error_falls_back_to_ascii(self, mocker, capsys):
        """
        When stdout's codec can't render the text, _safe_print must emit an
        ASCII-best-effort version rather than raising.
        """
        real_print = __builtins__["print"] if isinstance(__builtins__, dict) else print
        call_count = {"n": 0}

        def fake_print(msg):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise UnicodeEncodeError("cp1252", msg, 0, 1, "reason")
            real_print(msg)

        mocker.patch("builtins.print", side_effect=fake_print)
        puc._safe_print("box drawing ─ char")
        # Two calls: first raised, second ASCII fallback succeeded
        assert call_count["n"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator — run_post_update_check
# ══════════════════════════════════════════════════════════════════════════════


class TestRunPostUpdateCheck:
    def _patch_all(self, mocker, tmp_path, *, hotfix=None, py_ok=True, vf_ok=True):
        """Wire all side-effect-y deps to in-memory fakes. Returns a dict of mocks."""
        state_file = tmp_path / "state.json"
        mocker.patch.object(puc, "STATE_FILE", state_file)
        mocker.patch.object(puc, "STATE_DIR", tmp_path)

        mocker.patch.object(puc, "detect_new_update", return_value=hotfix)
        mocker.patch.object(
            puc,
            "get_latest_hotfix",
            return_value=hotfix or {"HotFixID": "KB1", "InstalledOn": ""},
        )

        pytest_mock = mocker.patch.object(
            puc,
            "run_pytest",
            return_value={
                "ok": py_ok,
                "passed": 1343 if py_ok else 1340,
                "failed": 0 if py_ok else 3,
                "elapsed_s": 170.0,
                "excerpt": "" if py_ok else "FAILED tests/test_foo",
                "returncode": 0 if py_ok else 1,
            },
        )
        verify_mock = mocker.patch.object(
            puc,
            "run_verify",
            return_value={
                "ok": vf_ok,
                "elapsed_s": 140.0,
                "excerpt": "" if vf_ok else "selftest failed",
                "returncode": 0 if vf_ok else 1,
            },
        )
        email_mock = mocker.patch.object(puc, "send_email", return_value=True)
        backlog_mock = mocker.patch.object(puc, "prepend_backlog_entry", return_value=True)
        return {
            "state_file": state_file,
            "pytest": pytest_mock,
            "verify": verify_mock,
            "email": email_mock,
            "backlog": backlog_mock,
        }

    def test_no_new_update_skips_entire_flow(self, mocker, tmp_path):
        mocks = self._patch_all(mocker, tmp_path, hotfix=None)
        result = puc.run_post_update_check()
        assert result["ran"] is False
        mocks["pytest"].assert_not_called()
        mocks["verify"].assert_not_called()
        mocks["email"].assert_not_called()

    def test_all_green_happy_path(self, mocker, tmp_path):
        mocks = self._patch_all(
            mocker,
            tmp_path,
            hotfix={"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
        )
        result = puc.run_post_update_check()
        assert result["ran"] is True
        assert result["overall_ok"] is True
        mocks["pytest"].assert_called_once()
        mocks["verify"].assert_called_once()
        mocks["email"].assert_called_once()
        # No backlog entry on all-green
        mocks["backlog"].assert_not_called()

    def test_regressions_write_backlog_entry(self, mocker, tmp_path):
        mocks = self._patch_all(
            mocker,
            tmp_path,
            hotfix={"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
            py_ok=False,
            vf_ok=False,
        )
        result = puc.run_post_update_check()
        assert result["overall_ok"] is False
        mocks["backlog"].assert_called_once()
        mocks["email"].assert_called_once()  # still email on failure

    def test_state_saved_after_run(self, mocker, tmp_path):
        mocks = self._patch_all(
            mocker,
            tmp_path,
            hotfix={"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
        )
        puc.run_post_update_check()
        state_file = mocks["state_file"]
        state = json.loads(state_file.read_text(encoding="utf-8"))
        assert state["last_hotfix_id"] == "KB5050"
        assert state["last_result"] == "all_passed"

    def test_force_flag_runs_even_without_new_update(self, mocker, tmp_path):
        mocks = self._patch_all(mocker, tmp_path, hotfix=None)
        # With force=True, use get_latest_hotfix not detect_new_update
        mocker.patch.object(
            puc,
            "get_latest_hotfix",
            return_value={"HotFixID": "KBforced", "InstalledOn": ""},
        )
        result = puc.run_post_update_check(force=True)
        assert result["ran"] is True
        mocks["pytest"].assert_called_once()

    def test_state_and_email_happen_before_print(self, mocker, tmp_path):
        """
        Regression guard for the 2026-04-17 live-run bug: if ``print(body)``
        crashes (cp1252), the state must still have been saved and the email
        must still have been sent. Order enforced by putting them before the
        fragile print in run_post_update_check.
        """
        mocks = self._patch_all(
            mocker,
            tmp_path,
            hotfix={"HotFixID": "KB5050", "InstalledOn": "2026-04-15T00:00:00"},
        )
        # Force the stdout print to raise — the exception must not reach
        # run_post_update_check's caller.
        mocker.patch.object(puc, "_safe_print", side_effect=UnicodeEncodeError("x", "y", 0, 1, "z"))
        with pytest.raises(UnicodeEncodeError):
            # The crash propagates (we only wrap inside _safe_print normally,
            # but forcibly-raising _safe_print proves ordering). Before the
            # crash, both side effects must have fired.
            puc.run_post_update_check()
        mocks["email"].assert_called_once()
        state = json.loads(mocks["state_file"].read_text(encoding="utf-8"))
        assert state["last_hotfix_id"] == "KB5050"


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════


class TestMainCLI:
    def test_check_only_prints_state_and_exits(self, mocker, tmp_path, capsys):
        mocker.patch.object(puc, "STATE_FILE", tmp_path / "state.json")
        mocker.patch.object(puc, "load_state", return_value={"last_hotfix_id": "KB1"})
        mocker.patch.object(
            puc,
            "get_latest_hotfix",
            return_value={"HotFixID": "KB2", "InstalledOn": ""},
        )
        mocker.patch.object(
            puc,
            "detect_new_update",
            return_value={"HotFixID": "KB2", "InstalledOn": ""},
        )
        rc = puc.main(["--check-only"])
        assert rc == 0
        captured = capsys.readouterr().out
        assert "Last recorded:    KB1" in captured
        assert "Latest installed: KB2" in captured

    def test_full_run_returncode_reflects_overall_ok(self, mocker):
        mocker.patch.object(
            puc,
            "run_post_update_check",
            return_value={"ran": True, "overall_ok": True},
        )
        assert puc.main([]) == 0

    def test_regressions_return_nonzero(self, mocker):
        mocker.patch.object(
            puc,
            "run_post_update_check",
            return_value={"ran": True, "overall_ok": False},
        )
        assert puc.main([]) == 1

    def test_no_update_returns_zero(self, mocker):
        mocker.patch.object(puc, "run_post_update_check", return_value={"ran": False})
        assert puc.main([]) == 0

    def test_fatal_error_returns_two(self, mocker):
        mocker.patch.object(puc, "run_post_update_check", side_effect=RuntimeError("boom"))
        assert puc.main([]) == 2
