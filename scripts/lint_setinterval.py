#!/usr/bin/env python3
"""lint_setinterval.py -- Flag unguarded setInterval / setTimeout recurring
call sites in templates/index.html.

The 2026-04-18 incident: ``pollTimer = setInterval(pollStatus, 800);`` had
no preceding ``clearInterval(pollTimer)``. Every user click on "Scan Now"
orphaned the prior poller, stacking 12+ timers at 16 req/s and burning 19%
CPU on the tray pythonw.

Rule
----
For every ``varName = setInterval(...)`` (module-scope timer handle),
require a preceding ``clearInterval(varName)`` within ~5 lines, OR an
``if (varName) return;`` guard at the top of the enclosing function.

Local ``const poll = setInterval(...)`` lines are exempt — they are
function-scoped and cannot leak past the caller.

Exit 1 with findings when violations are found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TARGETS = [Path("templates/index.html")]

# Matches: `ident = setInterval(...)` (not `const/let/var ident`)
ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][\w$]*)\s*=\s*setInterval\s*\(")
# Matches any local declaration: `const|let|var ident = setInterval(...)`
LOCAL_RE = re.compile(r"^\s*(?:const|let|var)\s+[A-Za-z_][\w$]*\s*=\s*setInterval\s*\(")


FUNC_START_RE = re.compile(r"^\s*(?:async\s+)?function\s+[A-Za-z_][\w$]*\s*\(")


def _find_enclosing_function_start(lines: list[str], idx: int) -> int:
    """Walk back from idx until we find a `function foo(...)` declaration.

    Returns the index of the function line, or 0 if none found.
    """
    for i in range(idx - 1, -1, -1):
        if FUNC_START_RE.match(lines[i]):
            return i
    return 0


def scan(path: Path) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if LOCAL_RE.match(line):
            continue  # local scope — cannot leak
        m = ASSIGN_RE.match(line)
        if not m:
            continue
        var = m.group(1)
        # Look back to the top of the enclosing function for a guard:
        #   - `clearInterval(var)`  (explicit cleanup)
        #   - `if (var) return`     (bail if already running)
        #   - `if (var) {`          (toggle-style — inside the cleanup branch)
        #   - `if (flag) return`    (any boolean reentry guard in the same function)
        func_start = _find_enclosing_function_start(lines, idx)
        window = lines[func_start:idx]
        var_guard = any(
            f"clearInterval({var})" in w or re.search(rf"if\s*\(\s*{re.escape(var)}\s*\)\s*(?:return|\{{)", w)
            for w in window
        )
        # Any reentry guard (`if (<bool>) return;`) protects the whole function
        flag_guard = any(re.search(r"if\s*\(\s*[!]?[A-Za-z_][\w$]*\s*\)\s*return\b", w) for w in window)
        if not (var_guard or flag_guard):
            findings.append((idx + 1, var, line.strip()))
    return findings


def main() -> int:
    ok = True
    for target in TARGETS:
        if not target.exists():
            continue
        for lineno, var, snippet in scan(target):
            ok = False
            print(
                f"{target}:{lineno}: unguarded setInterval -> `{var}` "
                f"(add `if ({var}) {{ clearInterval({var}); {var} = null; }}` above this line)",
                file=sys.stderr,
            )
            print(f"    {snippet}", file=sys.stderr)
    if not ok:
        print(
            "\nThe 2026-04-18 poll-accumulator incident was caused by exactly "
            "this pattern. Guard the timer or use a local const.",
            file=sys.stderr,
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
