"""tests/test_claude_automation.py -- Claude Code automation for this repo (#59).

Covers scripts/claude_hooks.py (the PreToolUse Edit|Write hook: worktree
guard + architecture-trigger reminder) and scripts/sop_report.py (the
pre-filled SOP Compliance Report). Both are loaded from their file paths --
scripts/ isn't a package. git is mocked for the report; the hook works on
plain paths under tmp_path.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hooks = _load("claude_hooks")
sop = _load("sop_report")


@pytest.fixture
def repo(tmp_path):
    """A primary checkout with one worktree under .claude/worktrees/wt."""
    primary = tmp_path / "windesktopmgr"
    wt = primary / ".claude" / "worktrees" / "wt"
    (wt / "scripts").mkdir(parents=True)
    (wt / "tests").mkdir()
    (wt / "dev.py").write_text("x", encoding="utf-8")
    (primary / "scripts").mkdir()
    (primary / "dev.py").write_text("x", encoding="utf-8")
    return types.SimpleNamespace(primary=primary, wt=wt)


def _edit(path, old="a", new="b"):
    return {"tool_name": "Edit", "tool_input": {"file_path": str(path), "old_string": old, "new_string": new}}


def _write(path, content="x"):
    return {"tool_name": "Write", "tool_input": {"file_path": str(path), "content": content}}


def _context(out):
    return out["hookSpecificOutput"]["additionalContext"] if out else ""


# ══════════════════════════════════════════════════════════════════════
# claude_hooks.py
# ══════════════════════════════════════════════════════════════════════


class TestRoots:
    def test_primary_root_of_primary_is_itself(self, repo):
        assert hooks.primary_root(str(repo.primary)) == os.path.normpath(str(repo.primary))

    def test_primary_root_of_worktree(self, repo):
        assert hooks.primary_root(str(repo.wt)) == os.path.normpath(str(repo.primary))

    def test_checkout_root_for_worktree_file(self, repo):
        root = hooks.checkout_root(str(repo.wt / "dev.py"), str(repo.primary))
        assert os.path.normcase(root) == os.path.normcase(os.path.normpath(str(repo.wt)))

    def test_checkout_root_for_primary_file(self, repo):
        root = hooks.checkout_root(str(repo.primary / "dev.py"), str(repo.wt))
        assert os.path.normcase(root) == os.path.normcase(os.path.normpath(str(repo.primary)))


class TestWorktreeGuard:
    @pytest.mark.parametrize("project", ["primary", "wt"])
    def test_primary_edit_warns_whatever_the_session_dir(self, repo, project):
        out = hooks.pre_edit(_edit(repo.primary / "dev.py"), str(getattr(repo, project)))
        assert "WORKTREE WARNING" in _context(out)
        assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    def test_worktree_edit_is_quiet(self, repo):
        assert hooks.pre_edit(_edit(repo.wt / "dev.py"), str(repo.primary)) is None

    def test_primary_dot_claude_config_is_quiet(self, repo):
        assert hooks.worktree_warning(str(repo.primary / ".claude" / "settings.json"), str(repo.primary)) is None

    def test_file_outside_repo_is_quiet(self, repo, tmp_path):
        assert hooks.pre_edit(_edit(tmp_path / "memory" / "notes.md"), str(repo.primary)) is None


class TestArchitectureTrigger:
    @pytest.mark.parametrize("rel", ["newmod.py", "scripts/new_tool.py", "tests/test_new.py"])
    def test_new_trigger_file(self, repo, rel):
        out = hooks.pre_edit(_write(repo.wt / rel), str(repo.primary))
        assert "ARCHITECTURE TRIGGER" in _context(out)
        assert "new file" in _context(out)

    @pytest.mark.parametrize("rel", ["static/js/new.js", "scripts/sub/deep.py", "docs/notes.md"])
    def test_new_non_trigger_file_is_quiet(self, repo, rel):
        assert hooks.pre_edit(_write(repo.wt / rel), str(repo.primary)) is None

    def test_overwriting_existing_file_is_not_new(self, repo):
        assert hooks.pre_edit(_write(repo.wt / "dev.py"), str(repo.primary)) is None

    def test_added_route_triggers(self, repo):
        payload = _edit(repo.wt / "dev.py", "x = 1", '@app.route("/api/new")\ndef new():\n    pass')
        assert "new Flask route" in _context(hooks.pre_edit(payload, str(repo.primary)))

    def test_blueprint_route_in_new_write_triggers(self, repo):
        payload = _write(repo.wt / "dev.py", '@backup_bp.route("/api/x")\ndef x(): ...')
        assert "new Flask route" in _context(hooks.pre_edit(payload, str(repo.primary)))

    def test_editing_an_existing_route_is_quiet(self, repo):
        payload = _edit(repo.wt / "dev.py", '@app.route("/api/a")', '@app.route("/api/b")')
        assert hooks.pre_edit(payload, str(repo.primary)) is None

    def test_route_text_in_non_python_is_quiet(self, repo):
        payload = _edit(repo.wt / "notes.md", "", "@app.route(")
        assert hooks.architecture_trigger("Edit", payload["tool_input"], str(repo.primary)) is None

    def test_architecture_html_itself_is_quiet(self, repo):
        assert hooks.pre_edit(_write(repo.wt / "architecture.html"), str(repo.primary)) is None

    def test_both_messages_combine(self, repo):
        out = hooks.pre_edit(_write(repo.primary / "brand_new.py"), str(repo.primary))
        assert "WORKTREE WARNING" in _context(out) and "ARCHITECTURE TRIGGER" in _context(out)


class TestHookMain:
    def _run(self, monkeypatch, stdin_text, argv=("pre-edit",), project=None):
        if project is not None:
            monkeypatch.setenv("CLAUDE_PROJECT_DIR", project)
        else:
            monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
        out = io.StringIO()
        rc = hooks.main(list(argv), stdin=io.StringIO(stdin_text), stdout=out)
        return rc, out.getvalue()

    def test_emits_json_for_primary_edit(self, repo, monkeypatch):
        rc, out = self._run(monkeypatch, json.dumps(_edit(repo.primary / "dev.py")), project=str(repo.wt))
        assert rc == 0 and "WORKTREE WARNING" in json.loads(out)["hookSpecificOutput"]["additionalContext"]

    def test_falls_back_to_payload_cwd(self, repo, monkeypatch):
        payload = {**_edit(repo.primary / "dev.py"), "cwd": str(repo.primary)}
        rc, out = self._run(monkeypatch, json.dumps(payload))
        assert rc == 0 and "WORKTREE WARNING" in out

    @pytest.mark.parametrize("stdin_text", ["not json", "[1, 2]", "{}", '{"tool_input": {}}'])
    def test_bad_or_empty_input_is_silent_and_never_blocks(self, monkeypatch, stdin_text, repo):
        rc, out = self._run(monkeypatch, stdin_text, project=str(repo.primary))
        assert rc == 0 and out == ""

    def test_unknown_subcommand_never_blocks(self, monkeypatch):
        rc, out = self._run(monkeypatch, "{}", argv=("nope",))
        assert rc == 0 and out == ""

    def test_settings_json_wires_this_hook_safely(self):
        settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
        entry = settings["hooks"]["PreToolUse"][0]
        assert entry["matcher"] == "Edit|Write"
        cmd = entry["hooks"][0]["command"]
        assert "scripts/claude_hooks.py" in cmd and "pre-edit" in cmd
        assert cmd.rstrip().endswith("|| true"), "a missing script must never exit 2 (= block the edit)"
        assert "jq" not in cmd, "jq isn't installed on this machine -- the old hook never ran"
        assert "PostToolUse" not in settings["hooks"]


# ══════════════════════════════════════════════════════════════════════
# sop_report.py
# ══════════════════════════════════════════════════════════════════════


class TestClassifiers:
    @pytest.mark.parametrize(
        ("path", "docs"),
        [
            ("CLAUDE.md", True),
            ("architecture.html", True),
            ("README.md", True),
            ("docs/x/y.md", True),
            ("tests/notes.md", False),
            ("dev.py", False),
            ("templates/index.html", False),
        ],
    )
    def test_docs_only(self, path, docs):
        assert sop.is_docs_only(path) is docs

    @pytest.mark.parametrize(
        ("path", "code"),
        [("dev.py", True), ("static/js/app.js", True), ("templates/index.html", True), ("CLAUDE.md", False)],
    )
    def test_is_code(self, path, code):
        assert sop.is_code(path) is code

    def test_arch_triggers(self):
        added = ["newmod.py", "scripts/a.py", "tests/test_b.py", "scripts/x/y.py", "static/js/z.js"]
        assert sop.arch_triggers(added) == ["newmod.py", "scripts/a.py", "tests/test_b.py"]


def _facts(**kw):
    base = {
        "sha": "abc1234",
        "subject": "feat: thing (#300)",
        "pr": "300",
        "files": ["kernel_cpu.py", "tests/test_kernel_cpu.py", "architecture.html"],
        "added": [],
        "merged": True,
        "backlog_hit": True,
    }
    return {**base, **kw}


class TestRender:
    def test_code_change_with_everything_in_place(self):
        out = sop.render("Thing", _facts(), test_count=4734)
        assert out.startswith("SOP Compliance Report — Thing")
        assert "✅ Pushed to remote (merged to origin/main)" in out
        assert "✅ New/modified code has test coverage" in out
        assert "✅ Backlog updated — mentions PR #300" in out
        assert "✅ architecture.html updated" in out
        assert "4,734 tests collected" in out
        assert "[ ] ruff check + format" in out
        assert out.rstrip().endswith("Commit(s): abc1234")

    def test_summary_counts_marks(self):
        out = sop.render("Thing", _facts())
        assert "Summary: 5 done, 0 skipped, 0 not done, 15 to fill in" in out

    def test_docs_only_skips_gates(self):
        out = sop.render("Docs", _facts(files=["CLAUDE.md", "architecture.html"]))
        assert out.count("⏭️ Skipped (docs-only") == 5  # ruff, pytest, review, deploy + tests

    def test_code_without_tests_is_flagged(self):
        out = sop.render("X", _facts(files=["kernel_cpu.py", "architecture.html"]))
        assert "❌ Code changed but no tests/ file changed" in out

    def test_missed_architecture_trigger_is_flagged(self):
        facts = _facts(files=["scripts/new.py", "tests/test_new.py"], added=["scripts/new.py", "tests/test_new.py"])
        out = sop.render("X", facts)
        assert "❌ architecture.html NOT updated but Step-4 trigger(s): scripts/new.py, tests/test_new.py" in out

    def test_no_trigger_leaves_arch_to_author(self):
        out = sop.render("X", _facts(files=["dev.py", "tests/test_dev.py"]))
        assert "[ ] architecture.html — no trigger detected" in out

    def test_missing_backlog_row_is_flagged(self):
        assert "❌ Backlog has no row mentioning PR #300" in sop.render("X", _facts(backlog_hit=False))

    def test_unknown_backlog_and_unmerged_left_to_author(self):
        out = sop.render("X", _facts(pr=None, backlog_hit=None, merged=False))
        assert "[ ] Backlog updated" in out and "[ ] Pushed to remote" in out

    def test_no_files_at_all(self):
        out = sop.render("X", _facts(files=[]))
        assert "[ ] New/modified code has test coverage" in out and "⏭️" not in out

    def test_no_trigger_text_does_not_inflate_skipped_count(self):
        # The instruction text must not contain a mark the Summary counts.
        out = sop.render("X", _facts(files=["dev.py", "tests/test_dev.py"]))
        assert "0 skipped" in out


class TestCollect:
    def _fake_run(self, mocker, outputs, ancestor_rc=0):
        def run(cmd, **_kw):
            if cmd[:2] == ["git", "merge-base"]:
                return types.SimpleNamespace(returncode=ancestor_rc, stdout="", stderr="")
            key = cmd[1]
            return types.SimpleNamespace(returncode=0, stdout=outputs.get(key, ""), stderr="")

        return mocker.patch.object(sop.subprocess, "run", side_effect=run)

    def test_collects_files_pr_and_backlog(self, mocker, tmp_path):
        backlog = tmp_path / "backlog.md"
        backlog.write_text("| 75 | ✅ SHIPPED (PR #207) |", encoding="utf-8")
        self._fake_run(
            mocker,
            {
                "log": 'feat(thermals): "Identify driver" (#207)\n',
                "diff": "M\tkernel_cpu.py\nA\tscripts/kernel_cpu_elevated.py\nR100\told.py\tnew.py\n",
                "rev-parse": "cb1d75d\n",
            },
        )
        facts = sop.collect("cb1d75d", str(backlog))
        assert facts["pr"] == "207" and facts["backlog_hit"] is True and facts["merged"] is True
        assert facts["files"] == ["kernel_cpu.py", "scripts/kernel_cpu_elevated.py", "new.py"]
        assert facts["added"] == ["scripts/kernel_cpu_elevated.py"]
        assert facts["sha"] == "cb1d75d"

    def test_unreadable_backlog_and_unmerged(self, mocker, tmp_path):
        self._fake_run(mocker, {"log": "fix: x (#9)"}, ancestor_rc=1)
        facts = sop.collect("HEAD", str(tmp_path / "missing.md"))
        assert facts["backlog_hit"] is None and facts["merged"] is False and facts["sha"] == "HEAD"

    def test_git_failure_is_empty(self, mocker):
        mocker.patch.object(
            sop.subprocess, "run", return_value=types.SimpleNamespace(returncode=128, stdout="x", stderr="")
        )
        facts = sop.collect("nope", "nowhere")
        assert facts["files"] == [] and facts["pr"] is None

    def test_count_tests_sums_per_file_lines(self, mocker):
        mocker.patch.object(
            sop.subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=0, stdout="tests/test_a.py: 3\ntests/test_b.py: 4\n"),
        )
        assert sop.count_tests() == 7

    def test_count_tests_none_when_nothing_parsed(self, mocker):
        mocker.patch.object(sop.subprocess, "run", return_value=types.SimpleNamespace(returncode=1, stdout=""))
        assert sop.count_tests() is None


class TestSopMain:
    def test_main_prints_report(self, mocker, capsysbinary):
        mocker.patch.object(sop, "collect", return_value=_facts())
        count = mocker.patch.object(sop, "count_tests", return_value=10)
        assert sop.main(["--title", "T", "--count-tests"]) == 0
        assert "SOP Compliance Report — T" in capsysbinary.readouterr().out.decode("utf-8")
        count.assert_called_once()

    def test_runs_against_this_repo_head(self):
        # Real git, read-only: the report must render for the actual HEAD.
        out = subprocess.run(
            [os.sys.executable, str(REPO_ROOT / "scripts" / "sop_report.py"), "--title", "smoke"],
            capture_output=True,
            cwd=REPO_ROOT,
        )
        assert out.returncode == 0
        assert "SOP Compliance Report — smoke" in out.stdout.decode("utf-8")
