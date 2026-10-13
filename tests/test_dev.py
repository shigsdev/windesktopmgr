"""Tests for dev.py -- the quality-gate runner behind `python dev.py verify`.

dev.py is the entry point for every deploy check, so a silent regression
here (e.g. verify stops running the semantic checker, or a failed test
run no longer exits non-zero) would let a broken deploy report green.
subprocess.run is mocked throughout -- nothing here launches ruff,
pytest or a real verify.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import dev

REPO_ROOT = Path(__file__).resolve().parent.parent


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestRun:
    def test_success_returns_true_and_prints_passed(self, mocker, capsys):
        mocker.patch("dev.subprocess.run", return_value=_proc(0, "ignored"))
        assert dev.run("lint", ["x"]) is True
        out = capsys.readouterr().out
        assert "lint" in out
        assert "passed" in out
        assert "ignored" not in out  # output only shown on failure

    def test_failure_returns_false_and_shows_output(self, mocker, capsys):
        mocker.patch("dev.subprocess.run", return_value=_proc(1, "E501 too long", "boom"))
        assert dev.run("lint", ["x"]) is False
        out = capsys.readouterr().out
        assert "FAILED" in out
        assert "E501 too long" in out
        assert "boom" in out

    def test_failure_output_capped_at_20_lines(self, mocker, capsys):
        many = "\n".join(f"line{i}" for i in range(50))
        mocker.patch("dev.subprocess.run", return_value=_proc(1, many))
        dev.run("t", ["x"])
        out = capsys.readouterr().out
        assert "line19" in out
        assert "line20" not in out


class TestCommands:
    def test_targets_exist_on_disk(self):
        """A renamed/removed file in TARGETS would make ruff error out and
        `dev.py check` fail for a reason unrelated to the change."""
        for t in dev.TARGETS:
            assert (REPO_ROOT / t).exists(), t

    def test_check_runs_ruff_check_and_format_check(self, mocker):
        run = mocker.patch("dev.run", return_value=True)
        assert dev.cmd_check() is True
        cmds = [c.args[1] for c in run.call_args_list]
        assert cmds[0][1:4] == ["-m", "ruff", "check"]
        assert "--check" in cmds[1] and "format" in cmds[1]
        assert all(set(dev.TARGETS) <= set(c) for c in cmds)

    def test_check_fails_if_either_step_fails(self, mocker):
        mocker.patch("dev.run", side_effect=[True, False])
        assert dev.cmd_check() is False

    def test_fix_uses_fix_flag_and_real_format(self, mocker):
        run = mocker.patch("dev.run", return_value=True)
        assert dev.cmd_fix() is True
        cmds = [c.args[1] for c in run.call_args_list]
        assert "--fix" in cmds[0]
        assert "format" in cmds[1] and "--check" not in cmds[1]

    def test_test_runs_pytest_in_parallel(self, mocker):
        run = mocker.patch("dev.run", return_value=True)
        assert dev.cmd_test() is True
        cmd = run.call_args.args[1]
        assert cmd[:3] == [sys.executable, "-m", "pytest"]
        assert cmd[-2:] == ["-n", "auto"]

    def test_all_reports_test_failure(self, mocker):
        mocker.patch("dev.cmd_fix", return_value=True)
        mocker.patch("dev.cmd_test", return_value=False)
        assert dev.cmd_all() is False


class TestVerify:
    def test_runs_both_checkers(self, mocker):
        run = mocker.patch("dev.run", return_value=True)
        assert dev.cmd_verify() is True
        scripts = [c.args[1][1] for c in run.call_args_list]
        assert scripts == ["scripts/post_restart_check.py", "scripts/post_deploy_topology_check.py"]

    def test_semantic_check_still_runs_when_restart_check_fails(self, mocker):
        """The topology checker must run even after a restart-check
        failure -- and the overall verify must still report the failure."""
        run = mocker.patch("dev.run", side_effect=[False, True])
        assert dev.cmd_verify() is False
        assert run.call_count == 2

    def test_semantic_failure_fails_verify(self, mocker):
        mocker.patch("dev.run", side_effect=[True, False])
        assert dev.cmd_verify() is False

    def test_verify_scripts_exist(self):
        assert (REPO_ROOT / "scripts" / "post_restart_check.py").exists()
        assert (REPO_ROOT / "scripts" / "post_deploy_topology_check.py").exists()


class TestDeploy:
    """`python dev.py deploy` (#59): pull main into the primary checkout,
    then verify. Must refuse -- touching nothing -- from a worktree, off
    main, or with uncommitted tracked changes."""

    PRIMARY = Path("C:/shigsapps/windesktopmgr")

    def _git(self, mocker, branch="main", dirty="", shas=("aaa", "bbb")):
        sha_iter = iter(shas)

        def git_out(*args):
            if args[0] == "rev-parse" and "--abbrev-ref" in args:
                return branch
            if args[0] == "status":
                return dirty
            if args[0] == "rev-parse":
                return next(sha_iter)
            return ""

        return mocker.patch.object(dev, "_git_out", side_effect=git_out)

    def test_refuses_from_a_worktree(self, mocker, capsys):
        mocker.patch.object(dev, "_HERE", self.PRIMARY / ".claude" / "worktrees" / "wt")
        run = mocker.patch.object(dev, "run")
        assert dev.cmd_deploy() is False
        run.assert_not_called()
        assert "not a worktree" in capsys.readouterr().out

    def test_refuses_off_main(self, mocker, capsys):
        mocker.patch.object(dev, "_HERE", self.PRIMARY)
        self._git(mocker, branch="feat/x")
        run = mocker.patch.object(dev, "run")
        assert dev.cmd_deploy() is False
        run.assert_not_called()
        assert "not 'main'" in capsys.readouterr().out

    @pytest.mark.parametrize("dirty", [" M dev.py", None])
    def test_refuses_dirty_tree_or_git_failure(self, mocker, capsys, dirty):
        mocker.patch.object(dev, "_HERE", self.PRIMARY)
        self._git(mocker, dirty=dirty)
        run = mocker.patch.object(dev, "run")
        assert dev.cmd_deploy() is False
        run.assert_not_called()
        assert "uncommitted changes" in capsys.readouterr().out

    def test_pulls_then_verifies(self, mocker, capsys):
        mocker.patch.object(dev, "_HERE", self.PRIMARY)
        self._git(mocker)
        run = mocker.patch.object(dev, "run", return_value=True)
        verify = mocker.patch.object(dev, "cmd_verify", return_value=True)
        assert dev.cmd_deploy() is True
        cmds = [c.args[1] for c in run.call_args_list]
        assert cmds[0][-2:] == ["fetch", "origin"]
        assert cmds[1][-3:] == ["merge", "--ff-only", "origin/main"]
        verify.assert_called_once()
        assert "aaa -> bbb" in capsys.readouterr().out

    def test_already_up_to_date_still_verifies(self, mocker, capsys):
        mocker.patch.object(dev, "_HERE", self.PRIMARY)
        self._git(mocker, shas=("aaa", "aaa"))
        mocker.patch.object(dev, "run", return_value=True)
        verify = mocker.patch.object(dev, "cmd_verify", return_value=True)
        assert dev.cmd_deploy() is True
        verify.assert_called_once()
        assert "already at aaa" in capsys.readouterr().out

    @pytest.mark.parametrize("fail_at", [0, 1])
    def test_git_failure_stops_before_verify(self, mocker, fail_at):
        mocker.patch.object(dev, "_HERE", self.PRIMARY)
        self._git(mocker)
        results = [True, True]
        results[fail_at] = False
        mocker.patch.object(dev, "run", side_effect=results)
        verify = mocker.patch.object(dev, "cmd_verify")
        assert dev.cmd_deploy() is False
        verify.assert_not_called()

    def test_git_out_returns_none_on_failure(self, mocker):
        mocker.patch("dev.subprocess.run", return_value=_proc(1, "x"))
        assert dev._git_out("status") is None
        mocker.patch("dev.subprocess.run", return_value=_proc(0, " main \n"))
        assert dev._git_out("rev-parse") == "main"

    def test_deploy_is_a_registered_command(self, mocker, monkeypatch):
        deploy = mocker.patch.object(dev, "cmd_deploy", return_value=True)
        monkeypatch.setattr(sys, "argv", ["dev.py", "deploy"])
        dev.main()  # success returns normally; failure would sys.exit(1)
        deploy.assert_called_once()

    def test_failed_deploy_exits_nonzero(self, mocker, monkeypatch):
        mocker.patch.object(dev, "cmd_deploy", return_value=False)
        monkeypatch.setattr(sys, "argv", ["dev.py", "deploy"])
        with pytest.raises(SystemExit) as exc:
            dev.main()
        assert exc.value.code == 1


class TestShip:
    def test_skips_verify_when_tests_fail(self, mocker):
        mocker.patch("dev.cmd_fix", return_value=True)
        mocker.patch("dev.cmd_test", return_value=False)
        verify = mocker.patch("dev.cmd_verify")
        assert dev.cmd_ship() is False
        verify.assert_not_called()

    def test_runs_verify_when_tests_pass(self, mocker):
        mocker.patch("dev.cmd_fix", return_value=True)
        mocker.patch("dev.cmd_test", return_value=True)
        verify = mocker.patch("dev.cmd_verify", return_value=False)
        assert dev.cmd_ship() is False
        verify.assert_called_once()


class TestPostUpdateCheck:
    def test_passes_extra_args_and_runs_from_repo_dir(self, mocker, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["dev.py", "post-update-check", "--force"])
        run = mocker.patch("dev.subprocess.run", return_value=_proc(0))
        assert dev.cmd_post_update_check() is True
        cmd = run.call_args.args[0]
        assert cmd == [sys.executable, "-m", "post_update_check", "--force"]
        assert Path(run.call_args.kwargs["cwd"]) == REPO_ROOT

    def test_nonzero_exit_fails(self, mocker, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["dev.py", "post-update-check"])
        mocker.patch("dev.subprocess.run", return_value=_proc(3))
        assert dev.cmd_post_update_check() is False


class TestMain:
    def test_unknown_command_exits_1(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["dev.py", "bogus"])
        with pytest.raises(SystemExit) as exc:
            dev.main()
        assert exc.value.code == 1
        assert "Unknown command: bogus" in capsys.readouterr().out

    def test_no_args_runs_all(self, mocker, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["dev.py"])
        all_ = mocker.patch("dev.cmd_all", return_value=True)
        dev.main()
        all_.assert_called_once()
        assert "All checks passed" in capsys.readouterr().out

    def test_failed_command_exits_1(self, mocker, monkeypatch):
        """`dev.py verify` must exit non-zero on failure -- callers (and the
        SOP) treat exit code 0 as a green deploy."""
        monkeypatch.setattr(sys, "argv", ["dev.py", "verify"])
        mocker.patch("dev.cmd_verify", return_value=False)
        with pytest.raises(SystemExit) as exc:
            dev.main()
        assert exc.value.code == 1

    def test_dispatches_named_command(self, mocker, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["dev.py", "check"])
        check = mocker.patch("dev.cmd_check", return_value=True)
        dev.main()
        check.assert_called_once()
