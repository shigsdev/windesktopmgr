"""tests/test_recurring_audits.py -- the scheduled GitHub Actions audits.

Covers scripts/audit_common.py (Finding, repo helpers, email body, Brevo
send, job summary, the run_audit driver) and each audit script's checks:
check_advisories, check_bug_patterns, check_tech_debt, check_test_coverage
and check_security_posture. Every subprocess (git, pip-audit, ruff, pytest,
npx) and every network call (Brevo, PyPI) is mocked.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import subprocess
import sys
import urllib.error
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import audit_common as ac  # noqa: E402
import check_advisories as cadv  # noqa: E402
import check_bug_patterns as cbp  # noqa: E402
import check_security_posture as csp  # noqa: E402
import check_tech_debt as ctd  # noqa: E402
import check_test_coverage as ctc  # noqa: E402

F = ac.Finding


def _done(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _args(no_email=True, report_only=False):
    return argparse.Namespace(no_email=no_email, report_only=report_only)


def _fake_repo(mocker, module, files: dict[str, str]):
    """Point a check module's tracked_files/read_text at an in-memory repo."""

    def tracked(suffixes=()):
        return [p for p in files if not suffixes or p.endswith(tuple(suffixes))]

    mocker.patch.object(module, "tracked_files", side_effect=tracked)
    mocker.patch.object(module, "read_text", side_effect=files.get)


# ── audit_common ─────────────────────────────────────────────────────────────


class TestFinding:
    def test_location_with_line(self):
        assert F("x", "d", path="a.py", line=3).location == "a.py:3"

    def test_location_file_only(self):
        assert F("x", "d", path="a.py").location == "a.py"

    def test_location_repo_wide(self):
        assert F("x", "d").location == ""


class TestRepoHelpers:
    def test_tracked_files_filters_suffix_and_missing(self, mocker, tmp_path):
        mocker.patch.object(ac, "PROJECT_ROOT", tmp_path)
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.js").write_text("x")
        mocker.patch.object(ac.subprocess, "run", return_value=_done("a.py\nb.js\ngone.py\n"))
        assert ac.tracked_files() == ["a.py", "b.js"]
        assert ac.tracked_files((".py",)) == ["a.py"]

    def test_tracked_files_git_failure_is_empty(self, mocker):
        mocker.patch.object(ac.subprocess, "run", return_value=_done("", returncode=128))
        assert ac.tracked_files() == []

    def test_tracked_files_git_missing_is_empty(self, mocker):
        mocker.patch.object(ac.subprocess, "run", side_effect=OSError("no git"))
        assert ac.tracked_files() == []

    def test_read_text_missing_is_none(self, mocker, tmp_path):
        mocker.patch.object(ac, "PROJECT_ROOT", tmp_path)
        assert ac.read_text("nope.py") is None

    def test_read_text_binary_is_none(self, mocker, tmp_path):
        mocker.patch.object(ac, "PROJECT_ROOT", tmp_path)
        (tmp_path / "b.bin").write_bytes(b"\xff\xfe\x00")
        assert ac.read_text("b.bin") is None

    def test_last_commit_date_parses(self, mocker):
        mocker.patch.object(ac.subprocess, "run", return_value=_done("2026-03-20T10:00:00-04:00\n"))
        assert ac.last_commit_date("a.py") == datetime.date(2026, 3, 20)

    @pytest.mark.parametrize("result", [_done("", 0), _done("x", 128), _done("garbage", 0)])
    def test_last_commit_date_unknown(self, mocker, result):
        mocker.patch.object(ac.subprocess, "run", return_value=result)
        assert ac.last_commit_date("a.py") is None

    def test_last_commit_date_timeout(self, mocker):
        mocker.patch.object(ac.subprocess, "run", side_effect=subprocess.TimeoutExpired("git", 60))
        assert ac.last_commit_date("a.py") is None


class TestRender:
    def _render(self, findings, counts):
        return ac.render(
            today="2026-10-11",
            tag="bug-pattern",
            title="Weekly scan",
            cadence="weekly",
            scope_blurb="things",
            per_check_counts=counts,
            findings=findings,
            descriptions={"a": "Check A.", "b": "Check B."},
            todo_steps=["Fix it.", "Re-run."],
        )

    def test_clean_subject_and_body(self):
        subject, body = self._render([], [("a", 0), ("b", 0)])
        assert subject == "[WinDesktopMgr bug-pattern] ✓ all clear (2 checks) — 2026-10-11"
        assert "0 findings across 2 checks" in body
        assert "✓ a — Check A." in body
        assert "every week" in body.lower()

    def test_findings_grouped_by_check(self):
        findings = [F("a", "first", path="x.py", line=2), F("a", "repo-wide")]
        subject, body = self._render(findings, [("a", 2), ("b", 0)])
        assert subject == "[WinDesktopMgr bug-pattern] 2 issues to review — 2026-10-11"
        assert "a — 2 findings" in body
        assert "  x.py:2\n      first" in body
        assert "  • repo-wide" in body
        assert "Clean this run: b" in body
        assert "  1. Fix it." in body and "  2. Re-run." in body

    def test_single_issue_and_monthly_wording(self):
        subject, body = ac.render(
            today="d",
            tag="security",
            title="t",
            cadence="monthly",
            scope_blurb="s",
            per_check_counts=[("a", 1)],
            findings=[F("a", "one")],
            descriptions={},
            todo_steps=[],
            subject_extra=" (x)",
            header_extra=["HEADER"],
        )
        assert subject == "[WinDesktopMgr security] 1 issue to review (x) — d"
        assert "every month" in body.lower()
        assert "HEADER" in body


class TestSendEmail:
    def test_not_configured_skips(self, monkeypatch, mocker):
        for name in ("BREVO_API_KEY", "DIGEST_FROM_EMAIL", "DIGEST_TO_EMAIL"):
            monkeypatch.delenv(name, raising=False)
        urlopen = mocker.patch.object(ac.urllib.request, "urlopen")
        assert ac.send_email("s", "b", log_tag="t") is False
        urlopen.assert_not_called()

    def _configure(self, monkeypatch):
        monkeypatch.setenv("BREVO_API_KEY", "test-key")
        monkeypatch.setenv("DIGEST_FROM_EMAIL", "from@example.test")
        monkeypatch.setenv("DIGEST_TO_EMAIL", "to@example.test")

    def test_sends_payload(self, monkeypatch, mocker):
        self._configure(monkeypatch)
        resp = MagicMock(status=201)
        resp.__enter__.return_value = resp
        urlopen = mocker.patch.object(ac.urllib.request, "urlopen", return_value=resp)
        assert ac.send_email("Subj", "Body", log_tag="t") is True
        req = urlopen.call_args.args[0]
        assert req.full_url == ac.BREVO_URL
        assert req.get_header("Api-key") == "test-key"
        payload = json.loads(req.data)
        assert payload["subject"] == "Subj"
        assert payload["textContent"] == "Body"
        assert payload["to"] == [{"email": "to@example.test"}]
        assert payload["sender"]["name"] == "WinDesktopMgr CI"

    def test_send_failure_is_swallowed(self, monkeypatch, mocker):
        self._configure(monkeypatch)
        mocker.patch.object(ac.urllib.request, "urlopen", side_effect=urllib.error.URLError("down"))
        assert ac.send_email("s", "b", log_tag="t") is False


class TestStepSummary:
    def test_appends_when_in_actions(self, monkeypatch, tmp_path):
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        ac.write_step_summary("Subj", "Body")
        text = summary.read_text(encoding="utf-8")
        assert "### Subj" in text and "Body" in text

    def test_noop_outside_actions(self, monkeypatch):
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        ac.write_step_summary("Subj", "Body")  # must not raise


class TestRunAudit:
    def _run(self, checks, args, mocker):
        send = mocker.patch.object(ac, "send_email", return_value=True)
        mocker.patch.object(ac, "write_step_summary")
        rc = ac.run_audit(
            tag="t",
            title="T",
            cadence="weekly",
            scope_blurb="s",
            checks=checks,
            descriptions={},
            todo_steps=[],
            args=args,
        )
        return rc, send

    def test_clean_exits_0_and_emails(self, mocker):
        rc, send = self._run([("a", list)], _args(no_email=False), mocker)
        assert rc == 0
        send.assert_called_once()

    def test_findings_exit_1(self, mocker):
        rc, _ = self._run([("a", lambda: [F("a", "d")])], _args(), mocker)
        assert rc == 1

    def test_report_only_exits_0_with_findings(self, mocker):
        rc, _ = self._run([("a", lambda: [F("a", "d")])], _args(report_only=True), mocker)
        assert rc == 0

    def test_no_email_does_not_send(self, mocker):
        _, send = self._run([("a", list)], _args(no_email=True), mocker)
        send.assert_not_called()

    def test_crashing_check_exits_2_without_email(self, mocker):
        def boom():
            raise RuntimeError("tool missing")

        rc, send = self._run([("a", boom)], _args(no_email=False), mocker)
        assert rc == 2
        send.assert_not_called()

    def test_cp1252_stdout_does_not_crash_on_subject(self, mocker, monkeypatch):
        # A piped Windows stdout is cp1252; the clean subject contains "✓".
        buf = io.BytesIO()
        monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buf, encoding="cp1252"))
        rc, _ = self._run([("a", list)], _args(no_email=True), mocker)
        sys.stdout.flush()
        assert rc == 0
        assert b"all clear" in buf.getvalue()

    def test_build_parser_flags(self):
        args = ac.build_parser("x").parse_args(["--no-email", "--report-only"])
        assert args.no_email and args.report_only


# ── check_advisories ─────────────────────────────────────────────────────────


class TestAdvisories:
    def test_command_audits_lock_without_installing(self, mocker):
        mocker.patch.dict(cadv.IGNORED_VULNS, {"PYSEC-1": "reason"})
        cmd = cadv._pip_audit_cmd()
        assert cmd[cmd.index("-r") + 1] == "requirements.lock"
        assert "--no-deps" in cmd and "--disable-pip" in cmd
        assert cmd[cmd.index("--ignore-vuln") + 1] == "PYSEC-1"

    def test_one_finding_per_package_with_upgrade_target(self, mocker):
        report = {
            "dependencies": [
                {"name": "clean", "version": "1.0", "vulns": []},
                {
                    "name": "pillow",
                    "version": "12.1.1",
                    "vulns": [
                        {"id": "A", "fix_versions": ["12.2.0"]},
                        {"id": "B", "fix_versions": ["12.10.0", "13.0.0"]},
                        {"id": "C", "fix_versions": []},
                    ],
                },
            ]
        }
        mocker.patch.object(cadv.subprocess, "run", return_value=_done(json.dumps(report), returncode=1))
        findings = cadv.check_pip_advisories()
        assert len(findings) == 1
        detail = findings[0].detail
        assert "pillow 12.1.1 — 3 advisory(ies): A, B, C" in detail
        assert ">= 12.10.0" in detail  # numeric, not string, comparison
        assert "1 advisory(ies) not fixed" in detail

    def test_no_fix_available(self, mocker):
        report = {"dependencies": [{"name": "x", "version": "1", "vulns": [{"id": "A"}]}]}
        mocker.patch.object(cadv.subprocess, "run", return_value=_done(json.dumps(report)))
        assert "no fixed version yet" in cadv.check_pip_advisories()[0].detail

    def test_clean_report(self, mocker):
        mocker.patch.object(cadv.subprocess, "run", return_value=_done('{"dependencies": []}'))
        assert cadv.check_pip_advisories() == []

    @pytest.mark.parametrize("stdout", ["", "Traceback ...", "[]"])
    def test_unusable_output_raises(self, mocker, stdout):
        mocker.patch.object(cadv.subprocess, "run", return_value=_done(stdout, returncode=1))
        with pytest.raises(RuntimeError):
            cadv.check_pip_advisories()

    def test_main_wires_run_audit(self, mocker):
        run = mocker.patch.object(cadv, "run_audit", return_value=1)
        assert cadv.main(["--no-email"]) == 1
        assert run.call_args.kwargs["tag"] == "advisory"


# ── check_bug_patterns ───────────────────────────────────────────────────────


class TestBugPatterns:
    def test_url_credentials_masked(self, mocker):
        _fake_repo(mocker, cbp, {"cfg.py": 'URL = "https://bob:hunter2@github.com/o/r.git"\n'})
        [finding] = cbp.check_embedded_url_credentials()
        assert finding.location == "cfg.py:1"
        assert "hunter2" not in finding.detail
        assert "bob:****@github.com" in finding.detail

    def test_url_credentials_allowlist_and_plain_urls(self, mocker):
        _fake_repo(
            mocker,
            cbp,
            {
                "docs/security/git-credentials.md": "https://user:token@github.com/",
                "app.py": 'u = "https://github.com/o/r"\nv = "git@github.com:o/r.git"\n',
                "binary.png": None,
            },
        )
        assert cbp.check_embedded_url_credentials() == []

    @pytest.mark.parametrize(
        "decorator,flagged",
        [
            ('@app.route("/api/x", methods=["GET", "POST"])', True),
            ("@bp.route('/api/x', methods=('DELETE', 'GET'))", True),
            ('@app.route("/api/x", methods=["POST"])', False),
            ('@app.route("/api/x")', False),
        ],
    )
    def test_state_mutating_get_routes(self, mocker, decorator, flagged):
        _fake_repo(mocker, cbp, {"routes.py": f"{decorator}\ndef x():\n    pass\n"})
        assert bool(cbp.check_state_mutating_get_routes()) is flagged

    def test_subprocess_without_timeout(self, mocker):
        src = (
            "import subprocess\n"
            "subprocess.run(['a'])\n"
            "subprocess.check_output(['b'], timeout=5)\n"
            "subprocess.run(['c'], **opts)\n"
            "subprocess.Popen(['d'])\n"
        )
        _fake_repo(mocker, cbp, {"app.py": src, "dev.py": src, "scripts/x.py": src, "tests/test_x.py": src})
        findings = cbp.check_subprocess_without_timeout()
        assert [f.location for f in findings] == ["app.py:2"]

    def test_subprocess_check_unparseable_file_raises(self, mocker):
        _fake_repo(mocker, cbp, {"broken.py": "def (:\n"})
        with pytest.raises(RuntimeError, match="broken.py"):
            cbp.check_subprocess_without_timeout()

    def test_relaunch_from_live_argv(self, mocker):
        src = (
            "subprocess.Popen([sys.executable, *sys.argv])\n"
            "# subprocess.Popen([sys.executable, *sys.argv]) -- explained in a comment\n"
            "subprocess.Popen([sys.executable, *_ORIGINAL_ARGV])\n"
        )
        _fake_repo(mocker, cbp, {"tray.py": src, "tests/test_tray.py": src})
        assert [f.location for f in cbp.check_relaunch_from_live_argv()] == ["tray.py:1"]

    def test_setinterval_clean(self, mocker):
        mocker.patch.object(cbp.subprocess, "run", return_value=_done("", 0))
        assert cbp.check_unguarded_setinterval() == []

    def test_setinterval_findings(self, mocker):
        mocker.patch.object(cbp.subprocess, "run", return_value=_done("app.js:12 pollTimer", 1))
        [finding] = cbp.check_unguarded_setinterval()
        assert "pollTimer" in finding.detail

    def test_setinterval_lint_crash_raises(self, mocker):
        mocker.patch.object(cbp.subprocess, "run", return_value=_done("", 2, "Traceback"))
        with pytest.raises(RuntimeError):
            cbp.check_unguarded_setinterval()

    def test_every_check_has_a_description(self):
        assert {label for label, _ in cbp.CHECKS} == set(cbp.CHECK_DESCRIPTIONS)

    def test_main_wires_run_audit(self, mocker):
        run = mocker.patch.object(cbp, "run_audit", return_value=0)
        assert cbp.main([]) == 0
        assert run.call_args.kwargs["tag"] == "bug-pattern"


# ── check_tech_debt ──────────────────────────────────────────────────────────


class TestTechDebt:
    def test_large_file_threshold_matches_utilities_tab(self):
        import codehealth

        assert ctd.LARGE_FILE_LINE_THRESHOLD == codehealth.LARGE_FILE_LINE_THRESHOLD

    def test_todo_hotspot_and_total(self, mocker):
        files = {
            "hot.py": "# TODO\n" * 6,
            "a.js": "// FIXME\n" * 5,
            "b.css": "/* HACK */\n" * 5,
            "c.html": "<!-- XXX -->\n" * 5,
            "d.py": "# TODO\n" * 5,
            "tests/test_x.py": "# TODO\n" * 50,
            "codehealth.py": "# TODO\n" * 50,
            "vendor.min.js": "// TODO\n" * 50,
        }
        _fake_repo(mocker, ctd, files)
        findings = ctd.check_todo_fixme_accumulation()
        assert [f.path for f in findings] == ["hot.py", ""]
        assert "26 TODO/FIXME markers across the tree" in findings[1].detail

    def test_todo_under_thresholds_is_clean(self, mocker):
        _fake_repo(mocker, ctd, {"a.py": "# TODO\n", "b.py": None})
        assert ctd.check_todo_fixme_accumulation() == []

    def test_large_files(self, mocker):
        big = "x\n" * ctd.LARGE_FILE_LINE_THRESHOLD
        _fake_repo(mocker, ctd, {"big.js": big, "small.py": "x\n", "tests/test_big.py": big, "big.min.js": big})
        [finding] = ctd.check_large_files()
        assert finding.path == "big.js"
        assert "5,000 lines" in finding.detail

    def test_complex_functions_sorted_and_tests_skipped(self, mocker):
        root = ctd.PROJECT_ROOT
        results = [
            {"filename": str(root / "bios.py"), "location": {"row": 5}, "message": "`f` is too complex (43 > 30)"},
            {"filename": str(root / "dash.py"), "location": {"row": 9}, "message": "`g` is too complex (65 > 30)"},
            {
                "filename": str(root / "tests" / "t.py"),
                "location": {"row": 1},
                "message": "`h` is too complex (99 > 30)",
            },
        ]
        run = mocker.patch.object(ctd.subprocess, "run", return_value=_done(json.dumps(results)))
        findings = ctd.check_complex_functions()
        assert [f.location for f in findings] == ["dash.py:9", "bios.py:5"]
        assert "g() has complexity 65" in findings[0].detail
        assert "lint.mccabe.max-complexity=30" in run.call_args.args[0]

    def test_complex_functions_bad_output_raises(self, mocker):
        mocker.patch.object(ctd.subprocess, "run", return_value=_done("error", 2))
        with pytest.raises(RuntimeError):
            ctd.check_complex_functions()

    def test_dependency_drift(self, mocker):
        files = {
            "requirements.txt": "# comment\nFlask>=3.0\npywin32>=311\npsutil>=5.9,<8\n-r other.txt\nnotlocked>=1\n",
            "requirements.lock": "flask==3.1.3\npywin32==311\npsutil==7.2.2\n",
        }
        mocker.patch.object(ctd, "read_text", side_effect=files.get)
        latest = {"flask": "4.0.1", "pywin32": "312", "psutil": "7.3.0"}
        mocker.patch.object(ctd, "_pypi_latest", side_effect=latest.get)
        [finding] = ctd.check_dependency_drift()
        assert "flask locked at 3.1.3, latest is 4.0.1 (1 major version(s) behind)" in finding.detail

    def test_dependency_drift_pypi_failure_raises(self, mocker):
        files = {"requirements.txt": "flask>=3\n", "requirements.lock": "flask==3.1.3\n"}
        mocker.patch.object(ctd, "read_text", side_effect=files.get)
        mocker.patch.object(ctd, "_pypi_latest", side_effect=urllib.error.URLError("offline"))
        with pytest.raises(RuntimeError, match="flask"):
            ctd.check_dependency_drift()

    def test_pypi_latest_reads_info_version(self, mocker):
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.read.return_value = b'{"info": {"version": "9.9.9"}}'
        urlopen = mocker.patch.object(ctd.urllib.request, "urlopen", return_value=resp)
        assert ctd._pypi_latest("flask") == "9.9.9"
        assert urlopen.call_args.args[0] == "https://pypi.org/pypi/flask/json"

    @pytest.mark.parametrize("version,major", [("3.1.3", 3), ("v2.0", 2), ("311", None), ("dev", None)])
    def test_major(self, version, major):
        assert ctd._major(version) == major

    def test_stale_tests(self, mocker):
        _fake_repo(mocker, ctd, {"tests/test_old.py": "", "tests/test_new.py": "", "tests/x/test_n.py": "", "a.py": ""})
        today = datetime.date.today()
        dates = {
            "tests/test_old.py": today - datetime.timedelta(days=200),
            "tests/test_new.py": today - datetime.timedelta(days=3),
        }
        mocker.patch.object(ctd, "last_commit_date", side_effect=dates.get)
        [finding] = ctd.check_stale_tests()
        assert finding.path == "tests/test_old.py"
        assert "200 days ago" in finding.detail

    def test_duplication_skipped_locally_without_node(self, mocker, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        mocker.patch.object(ctd, "_npx", return_value=None)
        assert ctd.check_code_duplication() == []

    def test_duplication_missing_node_in_ci_raises(self, mocker, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        mocker.patch.object(ctd, "_npx", return_value=None)
        with pytest.raises(RuntimeError, match="npx"):
            ctd.check_code_duplication()

    def test_duplication_parses_report(self, mocker):
        mocker.patch.object(ctd, "_npx", return_value="npx")
        report = {
            "duplicates": [
                {
                    "lines": 40,
                    "firstFile": {"name": "a.py", "start": 10},
                    "secondFile": {"name": "sub\\b.py", "start": 20},
                },
                {"lines": 12, "firstFile": {"name": "c.py"}, "secondFile": {"name": "d.py"}},
                {"lines": 50, "firstFile": {"name": "README.md"}, "secondFile": {"name": "e.py"}},
            ]
        }

        def fake_run(cmd, **_kwargs):
            out_dir = Path(cmd[cmd.index("--output") + 1])
            (out_dir / "jscpd-report.json").write_text(json.dumps(report), encoding="utf-8")
            return _done()

        mocker.patch.object(ctd.subprocess, "run", side_effect=fake_run)
        [finding] = ctd.check_code_duplication()
        assert finding.location == "a.py:10"
        assert "40-line block duplicated at sub/b.py:20" in finding.detail

    def test_duplication_no_report_raises(self, mocker):
        mocker.patch.object(ctd, "_npx", return_value="npx")
        mocker.patch.object(ctd.subprocess, "run", return_value=_done("", 1, "boom"))
        with pytest.raises(RuntimeError, match="jscpd"):
            ctd.check_code_duplication()

    def test_every_check_has_a_description(self):
        assert {label for label, _ in ctd.CHECKS} == set(ctd.CHECK_DESCRIPTIONS)

    def test_main_wires_run_audit(self, mocker):
        run = mocker.patch.object(ctd, "run_audit", return_value=0)
        assert ctd.main([]) == 0
        assert run.call_args.kwargs["tag"] == "tech-debt"


# ── check_test_coverage ──────────────────────────────────────────────────────


class TestCoverage:
    COV = {
        "files": {"remediation.py": {"summary": {"percent_covered": 90.0}}, "scripts\\x.py": {"summary": {}}},
        "totals": {"percent_covered": 88.5},
    }

    def test_per_file_and_total_normalises_paths(self):
        cov = {
            "files": {"scripts\\a.py": {"summary": {"percent_covered": 50}}, "b.py": {"summary": {}}},
            "totals": {"percent_covered": 70.25},
        }
        assert ctc.per_file_and_total(cov) == ({"scripts/a.py": 50.0}, 70.25)

    def test_overall_drift(self):
        assert ctc.check_overall_drift(88.0, {"overall": 89.0}) == []
        [finding] = ctc.check_overall_drift(87.0, {"overall": 89.0})
        assert "2.0 points below" in finding.detail
        assert ctc.check_overall_drift(50.0, {}) == []

    def test_per_file_drift(self):
        baseline = {"per_file": {"a.py": 90.0, "b.py": 90.0, "gone.py": 90.0}}
        findings = ctc.check_per_file_drift({"a.py": 86.0, "b.py": 80.0}, baseline)
        assert [f.path for f in findings] == ["b.py"]

    def test_critical_path_floors(self, mocker):
        mocker.patch.dict(ctc.CRITICAL_PATH_FLOORS, {"ok.py": 80.0, "low.py": 80.0, "missing.py": 80.0}, clear=True)
        findings = ctc.check_critical_path_floors({"ok.py": 81.0, "low.py": 79.0})
        assert [f.path for f in findings] == ["low.py", "missing.py"]
        assert "79.0% covered" in findings[0].detail
        assert "missing from the coverage report" in findings[1].detail

    def test_baseline_round_trip(self, mocker, tmp_path):
        mocker.patch.object(ctc, "BASELINE_PATH", tmp_path / "audit" / "baseline.json")
        assert ctc.read_baseline() is None
        ctc.write_baseline(88.456, {"b.py": 70.0, "a.py": 90.123})
        data = ctc.read_baseline()
        assert data["overall"] == 88.46
        assert list(data["per_file"]) == ["a.py", "b.py"]

    def test_run_pytest_reads_report(self, mocker):
        def fake_run(cmd, **_kwargs):
            report = Path(next(a for a in cmd if a.startswith("--cov-report=json:")).split(":", 1)[1])
            report.write_text(json.dumps(self.COV), encoding="utf-8")
            return _done("1 failed, 10 passed\n", returncode=1)

        mocker.patch.object(ctc.subprocess, "run", side_effect=fake_run)
        assert ctc.run_pytest_with_coverage()["totals"]["percent_covered"] == 88.5

    def test_run_pytest_without_report_raises(self, mocker):
        mocker.patch.object(ctc.subprocess, "run", return_value=_done("", 4, "ImportError"))
        with pytest.raises(RuntimeError, match="no coverage report"):
            ctc.run_pytest_with_coverage()

    def test_main_write_baseline(self, mocker):
        mocker.patch.object(ctc, "run_pytest_with_coverage", return_value=self.COV)
        write = mocker.patch.object(ctc, "write_baseline")
        assert ctc.main(["--write-baseline"]) == 0
        write.assert_called_once_with(88.5, {"remediation.py": 90.0})

    def test_main_measurement_failure_exits_2(self, mocker):
        mocker.patch.object(ctc, "run_pytest_with_coverage", side_effect=RuntimeError("crash"))
        assert ctc.main(["--no-email"]) == 2

    def test_main_missing_baseline_exits_2(self, mocker):
        mocker.patch.object(ctc, "run_pytest_with_coverage", return_value=self.COV)
        mocker.patch.object(ctc, "read_baseline", return_value=None)
        assert ctc.main(["--no-email"]) == 2

    def test_main_runs_checks(self, mocker):
        mocker.patch.object(ctc, "run_pytest_with_coverage", return_value=self.COV)
        mocker.patch.object(ctc, "read_baseline", return_value={"overall": 95.0, "per_file": {}})
        mocker.patch.dict(ctc.CRITICAL_PATH_FLOORS, {"remediation.py": 85.0}, clear=True)
        run = mocker.patch.object(ctc, "run_audit", return_value=1)
        assert ctc.main(["--no-email"]) == 1
        kwargs = run.call_args.kwargs
        results = {label: fn() for label, fn in kwargs["checks"]}
        assert len(results["overall-coverage-drift"]) == 1
        assert results["critical-path-floor"] == []
        assert kwargs["subject_extra"] == " (88.5%)"

    def test_committed_baseline_covers_every_floor(self):
        baseline = ctc.read_baseline()
        assert baseline is not None, "docs/audit/coverage-baseline.json must be committed"
        assert set(ctc.CRITICAL_PATH_FLOORS) <= set(baseline["per_file"])


# ── check_security_posture ───────────────────────────────────────────────────


class TestSecurityPosture:
    def test_secrets_sweep_parses_redacted_leaks(self, mocker):
        out = "LEAK: a.py -- github_pat -- ...x <REDACTED> y...\ncheck_repo_secrets: 1 finding(s).\n"
        mocker.patch.object(csp.subprocess, "run", return_value=_done(out, 1))
        [finding] = csp.check_secrets_sweep()
        assert finding.detail.startswith("a.py -- github_pat")

    def test_secrets_sweep_clean(self, mocker):
        mocker.patch.object(csp.subprocess, "run", return_value=_done("check_repo_secrets: OK", 0))
        assert csp.check_secrets_sweep() == []

    def test_secrets_sweep_crash_raises(self, mocker):
        mocker.patch.object(csp.subprocess, "run", return_value=_done("", 2, "Traceback"))
        with pytest.raises(RuntimeError):
            csp.check_secrets_sweep()

    @pytest.mark.parametrize(
        "call,problem",
        [
            ("app.run(debug=False, port=5000)", None),
            ('app.run(host="127.0.0.1", port=5000)', None),
            ("app.run(debug=True, port=5000)", "debug"),
            ("app.run(debug=DEBUG, port=5000)", "debug"),
            ('app.run(host="0.0.0.0", port=5000)', "0.0.0.0"),
            ("app.run(host=HOST)", "HOST"),
            ("subprocess.run(['x'], timeout=5)", None),
        ],
    )
    def test_flask_exposure(self, mocker, call, problem):
        _fake_repo(mocker, csp, {"app.py": call + "\n", "tests/test_app.py": "app.run(debug=True, port=1)\n"})
        findings = csp.check_flask_exposure()
        if problem is None:
            assert findings == []
        else:
            [finding] = findings
            assert problem in finding.detail

    def test_flask_exposure_unparseable_raises(self, mocker):
        _fake_repo(mocker, csp, {"app.py": "def (:\n"})
        with pytest.raises(RuntimeError, match="app.py"):
            csp.check_flask_exposure()

    def test_ruff_security_keeps_only_s_rules(self, mocker):
        root = csp.PROJECT_ROOT
        results = [
            {"filename": str(root / "nas.py"), "code": "S508", "message": "SNMPv2", "location": {"row": 266}},
            {"filename": str(root / "x.py"), "code": "F401", "message": "unused", "location": {"row": 1}},
            {"filename": str(root / "y.py"), "code": "SIM102", "message": "nested if", "location": {"row": 1}},
        ]
        run = mocker.patch.object(csp.subprocess, "run", return_value=_done(json.dumps(results)))
        [finding] = csp.check_ruff_security_rules()
        assert finding.location == "nas.py:266"
        assert finding.detail == "S508: SNMPv2"
        assert "--select" not in run.call_args.args[0]  # keeps pyproject's reviewed ignores

    def test_ruff_security_bad_output_raises(self, mocker):
        mocker.patch.object(csp.subprocess, "run", return_value=_done("oops", 2))
        with pytest.raises(RuntimeError):
            csp.check_ruff_security_rules()

    def test_current_suppressions(self, mocker):
        files = {
            "a.py": "x = 1  # noqa: S310\ny = 2  # noqa: S603, S607\nz = 3  # noqa: E501\n",
            "tests/test_a.py": "x = 1  # noqa: S105\n",
        }
        _fake_repo(mocker, csp, files)
        assert csp.current_suppressions() == Counter({"a.py S310": 1, "a.py S603": 1, "a.py S607": 1})

    def test_new_suppressions_against_register(self, mocker, tmp_path):
        register = tmp_path / "reg.json"
        mocker.patch.object(csp, "SUPPRESSIONS_PATH", register)
        csp.write_suppressions_baseline(Counter({"a.py S310": 1}))
        mocker.patch.object(csp, "current_suppressions", return_value=Counter({"a.py S310": 2, "b.py S603": 1}))
        findings = csp.check_new_security_suppressions()
        assert [f.path for f in findings] == ["a.py", "b.py"]
        assert "1 unreviewed '# noqa: S310'" in findings[0].detail

    def test_missing_register_raises(self, mocker, tmp_path):
        mocker.patch.object(csp, "SUPPRESSIONS_PATH", tmp_path / "missing.json")
        with pytest.raises(RuntimeError, match="write-baseline"):
            csp.check_new_security_suppressions()

    def test_main_write_baseline(self, mocker):
        mocker.patch.object(csp, "current_suppressions", return_value=Counter({"a.py S310": 1}))
        write = mocker.patch.object(csp, "write_suppressions_baseline")
        assert csp.main(["--write-baseline"]) == 0
        write.assert_called_once()

    def test_main_wires_run_audit(self, mocker):
        run = mocker.patch.object(csp, "run_audit", return_value=0)
        assert csp.main([]) == 0
        assert run.call_args.kwargs["cadence"] == "monthly"

    def test_committed_register_is_readable(self):
        """The monthly run crashes (exit 2) without a readable register."""
        register = json.loads(csp.SUPPRESSIONS_PATH.read_text(encoding="utf-8"))["suppressions"]
        assert register and all(isinstance(n, int) for n in register.values())
