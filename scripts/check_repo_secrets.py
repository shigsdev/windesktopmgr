#!/usr/bin/env python
"""check_repo_secrets.py -- pre-commit secret scanner (gate-11 equivalent).

Two complementary checks against credential leakage:

  1) File-content scan for known-shape token prefixes (GitHub PAT, AWS
     access key, OpenAI/Stripe-style sk-, Slack tokens, private-key
     headers, npm tokens). Scans the working tree by default, or only
     the files staged for commit when --staged is passed (the pre-
     commit hook mode).

  2) Embedded credentials in git remote URLs. The leak shape is
     ``https://user:token@github.com/...`` -- any non-empty password
     between ``://`` and ``@`` in a remote URL is treated as a leak.

Exit codes:
  0  clean -- nothing matched
  1  one or more findings -- printed to stdout with the actual secret
     redacted (replaced with the literal string '<REDACTED>') and the
     pattern name shown so the user knows which kind of token leaked

False-positive allowlist:
  Specific files can be skipped entirely. Edit ``_ALLOWLIST`` below to
  add paths (relative to repo root). Two existing entries cover the
  Credential Manager metadata fixtures that the file-name regex would
  otherwise flag.

Python-first per CLAUDE.md SOP -- no PowerShell, no shell pipelines
beyond ``git ls-files`` / ``git diff --cached``. Designed to be
runnable from the pre-commit hook AND for ad-hoc audits.

Usage:
    python scripts/check_repo_secrets.py            # scan working tree
    python scripts/check_repo_secrets.py --staged   # scan staged files only (pre-commit)
    python scripts/check_repo_secrets.py --all      # alias for default
    python scripts/check_repo_secrets.py --remote-urls-only  # just remotes
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

# ── Token / secret patterns ─────────────────────────────────────────────
# Each entry: (pattern_name, compiled regex). Names are kept short so
# the printed finding line stays readable.

_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # GitHub PATs (fine-grained, classic, OAuth, server-to-server, user-to-server, refresh).
    # Fine-grained PATs are >=82 chars after the prefix; classic are 36; we keep the lower
    # bound loose at 30+ so future tweaks to GitHub's token length don't make us miss them.
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{30,}")),
    ("github_classic", re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{30,}")),
    ("github_s2s", re.compile(r"ghs_[A-Za-z0-9]{30,}")),
    ("github_u2s", re.compile(r"ghu_[A-Za-z0-9]{30,}")),
    ("github_refresh", re.compile(r"ghr_[A-Za-z0-9]{30,}")),
    # AWS access keys (the secret access key has no fixed prefix, so we
    # only catch the access-key half; that's enough for the alarm).
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    # OpenAI / Stripe-style "sk-" secret keys. Length >=32 to avoid
    # false-positives on harmless "sk-" strings in code (e.g. "skil",
    # "skin", etc. won't have a hyphen after).
    ("openai_stripe_sk", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    # npm tokens (36+ chars after the prefix).
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{30,}")),
    # Slack tokens.
    ("slack_bot", re.compile(r"xoxb-[A-Za-z0-9-]{40,}")),
    ("slack_user", re.compile(r"xoxp-[A-Za-z0-9-]{40,}")),
    # PEM-encoded private keys -- any kind (RSA, EC, OpenSSH, ED25519...).
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
]

# Embedded creds in URLs: scheme://user:pass@host. Match when password
# section is non-empty so we don't false-positive on bare user@host
# patterns (which are also weird but caught by a separate username-only
# rule we may add later).
_URL_CRED_PATTERN = re.compile(r"\b(?P<scheme>https?|git|ssh|ftp)://(?P<user>[^:/@\s]+):(?P<pass>[^@/\s]+)@")

# Files that match the token-NAME pattern but are known false positives.
# Entries are repo-root-relative POSIX paths (forward slashes); we
# normalise the on-disk path to match before comparing.
_ALLOWLIST: set[str] = {
    # Credential Manager metadata fixtures -- captured PS / parsed output
    # listing the user's Windows Credential Manager entries (User /
    # Target / Type only; no password blobs).
    "tests/fixtures/parsed/parsed_get_credentials_network_health.json",
    "tests/fixtures/powershell/ps_credentials.json",
    # Scanner's own test file -- contains SYNTHETIC token-shape strings
    # (literal "ghp_" + 'A'*36 etc.) used to validate detection. The
    # values aren't real tokens but match the shape patterns by design.
    "tests/test_check_repo_secrets.py",
}

# File extensions we never scan -- binaries, large generated assets,
# git's own metadata. Cuts both scan time and false-positive surface.
_SKIP_EXT: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".bmp",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".exe",
    ".dylib",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".eot",
    ".mp3",
    ".mp4",
    ".wav",
    ".ogg",
    ".webm",
}


# ── Utilities ───────────────────────────────────────────────────────────


def _normalise(path: str | os.PathLike[str]) -> str:
    """Repo-root-relative POSIX path for allowlist + display."""
    return str(path).replace("\\", "/").lstrip("./")


def _run_git(args: list[str]) -> str:
    """Run a git command and return stdout. Empty string if git fails
    (so callers in non-git contexts don't crash)."""
    try:
        out = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _staged_files() -> list[str]:
    """Files staged for commit, in repo-root-relative POSIX form."""
    out = _run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    return [_normalise(line) for line in out.splitlines() if line.strip()]


def _tracked_files() -> list[str]:
    """All git-tracked files (working-tree scan)."""
    out = _run_git(["ls-files"])
    return [_normalise(line) for line in out.splitlines() if line.strip()]


def _remote_urls() -> list[tuple[str, str]]:
    """Return [(remote_name, url), ...] from ``git config``."""
    out = _run_git(["config", "--get-regexp", r"^remote\..*\.url$"])
    remotes: list[tuple[str, str]] = []
    for line in out.splitlines():
        # Lines are "remote.<name>.url <url>" separated by a single space.
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        # "remote.foo.url" -> "foo"
        key_parts = parts[0].split(".")
        name = key_parts[1] if len(key_parts) >= 3 else parts[0]
        remotes.append((name, parts[1]))
    return remotes


# ── Core scans ──────────────────────────────────────────────────────────


def scan_content(text: str) -> list[tuple[str, str]]:
    """Scan a chunk of text for known-shape tokens.

    Returns ``[(pattern_name, redacted_excerpt), ...]``. The excerpt
    NEVER contains the raw secret -- we replace the match body with
    "<REDACTED>" and keep ~16 chars of surrounding context so the user
    can locate the offending line without re-leaking on the terminal.
    """
    findings: list[tuple[str, str]] = []
    for name, pat in _TOKEN_PATTERNS:
        for m in pat.finditer(text):
            start = max(0, m.start() - 16)
            end = min(len(text), m.end() + 16)
            context = text[start : m.start()] + "<REDACTED>" + text[m.end() : end]
            context = context.replace("\n", " ").replace("\r", "")
            findings.append((name, context.strip()))
    return findings


def scan_file(path: str | os.PathLike[str]) -> list[tuple[str, str]]:
    """Scan a single file for token shapes. Returns findings list.

    Allowlist + extension filter applied before opening the file. Files
    we can't decode as UTF-8 are silently skipped (almost certainly
    binary content the extension filter missed)."""
    norm = _normalise(path)
    if norm in _ALLOWLIST:
        return []
    ext = Path(norm).suffix.lower()
    if ext in _SKIP_EXT:
        return []
    try:
        with open(path, encoding="utf-8", errors="strict") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    return scan_content(text)


def scan_remote_urls() -> list[tuple[str, str, str]]:
    """Check git remote URLs for embedded user:password@ creds.

    Returns ``[(remote_name, redacted_url, kind), ...]``. ``kind`` is
    one of ``embedded_password`` (the leak shape) or
    ``username_only`` (less risky but still odd).
    """
    findings: list[tuple[str, str, str]] = []
    for name, url in _remote_urls():
        m = _URL_CRED_PATTERN.search(url)
        if m:
            redacted = url[: m.start("pass")] + "<REDACTED>" + url[m.end("pass") :]
            findings.append((name, redacted, "embedded_password"))
            continue
        # Username-only check: scheme://user@host without a colon-and-password.
        # We accept ssh git@github.com:... so we only worry about the
        # http(s) schemes here.
        m2 = re.search(r"\b(https?)://([^:/@\s]+)@", url)
        if m2:
            findings.append((name, url, "username_only"))
    return findings


# ── Orchestrator ────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--staged", action="store_true", help="Scan only files staged for commit (pre-commit mode).")
    group.add_argument("--all", action="store_true", help="Scan all git-tracked files (default).")
    parser.add_argument("--remote-urls-only", action="store_true", help="Skip file scan; only check git remote URLs.")
    parser.add_argument("--no-remotes", action="store_true", help="Skip the git-remote-URL check.")
    args = parser.parse_args(argv)

    findings_count = 0

    # ── File scan ──────────────────────────────────────────────────
    if not args.remote_urls_only:
        files = _staged_files() if args.staged else _tracked_files()
        if not files:
            mode = "staged" if args.staged else "tracked"
            print(f"check_repo_secrets: no {mode} files to scan", file=sys.stderr)
        for f in files:
            findings = scan_file(f)
            for name, excerpt in findings:
                findings_count += 1
                print(f"LEAK: {f} -- {name} -- ...{excerpt}...")

    # ── Remote URL scan ────────────────────────────────────────────
    if not args.no_remotes:
        for name, url, kind in scan_remote_urls():
            findings_count += 1
            print(f"LEAK: git remote '{name}' has {kind}: {url}")

    if findings_count == 0:
        print("check_repo_secrets: OK -- no leaks detected")
        return 0

    print(
        f"\ncheck_repo_secrets: {findings_count} finding(s). See docs/security/git-credentials.md "
        "for the rotation procedure."
    )
    return 1


def _iter_for_tests(paths: Iterable[str | os.PathLike[str]]) -> dict:
    """Test helper -- scan a list of paths and return findings keyed by file.

    Not used by the CLI; tests call it to validate behaviour without
    spawning subprocesses."""
    out: dict[str, list[tuple[str, str]]] = {}
    for p in paths:
        f = scan_file(p)
        if f:
            out[_normalise(p)] = f
    return out


if __name__ == "__main__":
    sys.exit(main())
