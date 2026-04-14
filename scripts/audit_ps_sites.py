"""
scripts/audit_ps_sites.py — One-shot inventory of subprocess.run("powershell"|"netsh"|etc)
call sites for the PowerShell-to-Python migration audit (backlog #24).

Walks the AST of each target file, finds every `subprocess.run(...)` call, and for
each one reports:
  - file
  - line
  - enclosing def name
  - the command string or argv head, truncated
  - a best-guess "kind" (powershell, netsh, dism, cmd, other)

Prints one TSV row per site. Not committed as production code — an audit helper only,
safe to delete after the inventory markdown is generated.

Usage:
  python scripts/audit_ps_sites.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGETS = [
    REPO / "windesktopmgr.py",
    REPO / "homenet.py",
    REPO / "SystemHealthDiag.py",
]

MAX_SNIPPET = 110


def _find_enclosing_def(tree: ast.AST, target_lineno: int) -> str:
    """Walk the tree to find the innermost function/method containing target_lineno."""
    best_name = "<module>"
    best_start = -1
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = getattr(node, "end_lineno", node.lineno + 500)
            if node.lineno <= target_lineno <= end and node.lineno > best_start:
                best_name = node.name
                best_start = node.lineno
    return best_name


def _extract_snippet(source_lines: list[str], call_lineno: int) -> str:
    """Grab the subprocess.run(...) block and return a truncated single-line snippet."""
    joined = ""
    depth = 0
    started = False
    for i in range(call_lineno - 1, min(call_lineno + 10, len(source_lines))):
        line = source_lines[i]
        joined += " " + line.strip()
        for ch in line:
            if ch == "(":
                depth += 1
                started = True
            elif ch == ")":
                depth -= 1
        if started and depth <= 0:
            break
    joined = " ".join(joined.split())
    if len(joined) > MAX_SNIPPET:
        joined = joined[:MAX_SNIPPET] + "…"
    return joined


def _guess_kind(snippet: str) -> str:
    s = snippet.lower()
    if '"powershell"' in s or "'powershell'" in s:
        return "powershell"
    if '"netsh"' in s or "'netsh'" in s or "netsh " in s:
        return "netsh"
    if '"dism"' in s or "'dism'" in s or "dism.exe" in s or "dism /" in s:
        return "dism"
    if '"cmd"' in s or "'cmd'" in s or "cmd /c" in s or "cmd.exe" in s:
        return "cmd"
    if '"reg"' in s or "'reg'" in s or "reg query" in s or "reg add" in s:
        return "reg"
    if '"schtasks"' in s or "'schtasks'" in s:
        return "schtasks"
    if '"ping"' in s or "'ping'" in s:
        return "ping"
    if '"wmic"' in s or "'wmic'" in s:
        return "wmic"
    if '"ipconfig"' in s or "'ipconfig'" in s:
        return "ipconfig"
    if '"arp"' in s or "'arp'" in s:
        return "arp"
    if '"tracert"' in s:
        return "tracert"
    return "other"


def main() -> int:
    print("file\tline\tfunction\tkind\tsnippet")
    total = 0
    for path in TARGETS:
        if not path.exists():
            print(f"# missing: {path}", file=sys.stderr)
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            print(f"# syntax error in {path}: {e}", file=sys.stderr)
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                lineno = node.lineno
                fn = _find_enclosing_def(tree, lineno)
                snippet = _extract_snippet(lines, lineno)
                kind = _guess_kind(snippet)
                print(f"{path.name}\t{lineno}\t{fn}\t{kind}\t{snippet}")
                total += 1
    print(f"# total: {total}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
