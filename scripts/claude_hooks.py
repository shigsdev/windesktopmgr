"""scripts/claude_hooks.py -- Claude Code PreToolUse hook for this repo (#59).

Wired in .claude/settings.json as a PreToolUse hook on Edit|Write::

    python "$CLAUDE_PROJECT_DIR/scripts/claude_hooks.py" pre-edit

Claude Code pipes the tool call as JSON on stdin; this prints a JSON
``additionalContext`` reminder (or nothing) and always exits 0 -- it warns,
it never blocks. Two checks:

  worktree guard -- the edit targets the PRIMARY checkout (the running tray's
      source, C:\\shigsapps\\windesktopmgr) instead of a .claude\\worktrees\\
      copy. The SOP is worktree -> PR -> merge -> pull; a direct primary edit
      skips review and is live on the next tray restart.
  architecture trigger -- the edit hits a CLAUDE.md Step-4 trigger: a NEW
      file in the repo root, scripts/ or tests/, or a NEW Flask route
      decorator. (Test/line-count drift is already enforced by
      tests/test_architecture_html.py, so it is not re-checked here.)

Replaces the jq-based PostToolUse reminder, which never ran on this machine
(jq isn't installed) and would have fired on every edit if it had.
Pure Python, stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import sys

_WORKTREES = os.path.join(".claude", "worktrees")
_ROUTE_RE = re.compile(r"@\w+\.route\(")
_TRIGGER_DIRS = ("scripts", "tests")


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def primary_root(project_dir: str) -> str:
    """The primary checkout for ``project_dir``: itself, or -- when it is a
    ``<primary>/.claude/worktrees/<name>`` worktree -- the primary above it."""
    norm = os.path.normpath(project_dir)
    marker = os.sep + _WORKTREES + os.sep
    idx = os.path.normcase(norm + os.sep).find(os.path.normcase(marker))
    return norm[:idx] if idx >= 0 else norm


def checkout_root(file_path: str, project_dir: str) -> str:
    """The checkout ``file_path`` belongs to: the ``.claude/worktrees/<name>``
    worktree it sits in, else the primary checkout."""
    primary = primary_root(project_dir)
    rel = _relative(file_path, os.path.join(primary, _WORKTREES))
    if rel is not None and os.sep in rel:
        return os.path.join(primary, _WORKTREES, rel.split(os.sep)[0])
    return primary


def _relative(path: str, root: str) -> str | None:
    """``path`` relative to ``root``, or None when it isn't inside it."""
    p, r = _norm(path), _norm(root)
    if p == r or not p.startswith(r + os.sep):
        return None
    return os.path.relpath(p, r)


def worktree_warning(file_path: str, project_dir: str) -> str | None:
    """Warning when ``file_path`` is in the primary checkout (outside .claude/)."""
    rel = _relative(file_path, primary_root(project_dir))
    if rel is None or rel.split(os.sep)[0] == os.path.normcase(".claude"):
        return None
    return (
        f"WORKTREE WARNING: {file_path} is in the PRIMARY checkout -- the running tray's source. "
        "The SOP is worktree -> PR -> merge -> `python dev.py deploy`; a direct edit here skips "
        "review and goes live on the next restart. Edit the .claude\\worktrees\\<name> copy instead "
        "unless this is a deliberate one-off."
    )


def architecture_trigger(tool_name: str, tool_input: dict, project_dir: str) -> str | None:
    """Reminder when the edit hits a CLAUDE.md Step-4 architecture trigger."""
    file_path = tool_input.get("file_path") or ""
    rel = _relative(file_path, checkout_root(file_path, project_dir))
    if rel is None or os.path.basename(rel).lower() == "architecture.html":
        return None
    parts = rel.split(os.sep)
    reasons = []
    if tool_name == "Write" and not os.path.exists(file_path):
        top = parts[0] if len(parts) > 1 else ""
        if len(parts) == 1 or (top in _TRIGGER_DIRS and len(parts) == 2):
            reasons.append(f"new file {rel.replace(os.sep, '/')}")
    if rel.endswith(".py"):
        new = tool_input.get("new_string") if tool_name == "Edit" else tool_input.get("content")
        old = tool_input.get("old_string") if tool_name == "Edit" else ""
        if len(_ROUTE_RE.findall(new or "")) > len(_ROUTE_RE.findall(old or "")):
            reasons.append("new Flask route")
    if not reasons:
        return None
    return (
        f"ARCHITECTURE TRIGGER ({'; '.join(reasons)}): CLAUDE.md Step 4 requires updating "
        "architecture.html for this -- add/adjust the chip, then run /arch-update for the counts."
    )


def pre_edit(payload: dict, project_dir: str) -> dict | None:
    """Hook output for one Edit/Write tool call, or None for no message."""
    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path") or ""
    if not file_path or not project_dir:
        return None
    messages = [
        m
        for m in (
            worktree_warning(file_path, project_dir),
            architecture_trigger(payload.get("tool_name") or "", tool_input, project_dir),
        )
        if m
    ]
    if not messages:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "\n".join(messages)}}


def main(argv: list[str] | None = None, stdin=None, stdout=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    if argv[:1] != ["pre-edit"]:
        print("usage: claude_hooks.py pre-edit  (reads the hook JSON on stdin)", file=sys.stderr)
        return 0
    try:
        payload = json.load(stdin)
    except (ValueError, OSError):
        return 0  # a hook must never break the tool call
    if not isinstance(payload, dict):
        return 0
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or ""
    out = pre_edit(payload, project_dir)
    if out:
        stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
