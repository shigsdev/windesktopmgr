"""tests/test_check_repo_secrets.py -- pre-commit secret scanner (Phase 4 audit).

Covers:
  - Each token pattern matches a synthetic example
  - Patterns DON'T match clean lookalikes (host:port URLs, short "sk-" words, etc.)
  - File-content scanner redacts the secret in the output
  - URL-cred detection redacts the password portion
  - Allowlist + binary-extension filters short-circuit cleanly
  - Username-only URL form is reported distinctly from embedded-password
  - Orchestrator exit code: 0 on clean / 1 on any finding
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/ importable so we can pull check_repo_secrets in as a module.
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import check_repo_secrets as crs  # noqa: E402

# ── Pattern positives ──────────────────────────────────────────────


class TestTokenPatternsMatch:
    """Each pattern in _TOKEN_PATTERNS must catch a realistic example.

    Examples are SYNTHETIC -- generated character strings of the right
    shape, never real tokens.
    """

    def test_github_pat_fine_grained(self):
        sample = "github_pat_" + "A" * 60 + "_" + "B" * 22  # 82+ chars total
        findings = crs.scan_content(sample)
        names = [n for n, _ in findings]
        assert "github_pat" in names

    def test_github_classic(self):
        sample = "GH_TOKEN=ghp_" + "x" * 36
        findings = crs.scan_content(sample)
        assert "github_classic" in [n for n, _ in findings]

    def test_github_oauth(self):
        sample = "gho_" + "y" * 36
        assert "github_oauth" in [n for n, _ in crs.scan_content(sample)]

    def test_aws_access_key(self):
        sample = "AKIA" + "ABCDEFGHIJKLMNOP"  # 4 + 16 = 20 chars
        assert "aws_access_key" in [n for n, _ in crs.scan_content(sample)]

    def test_openai_stripe_sk(self):
        sample = "OPENAI_API_KEY=sk-" + "Z" * 40
        assert "openai_stripe_sk" in [n for n, _ in crs.scan_content(sample)]

    def test_npm_token(self):
        sample = "npm_" + "q" * 36
        assert "npm_token" in [n for n, _ in crs.scan_content(sample)]

    def test_slack_bot(self):
        sample = "xoxb-" + "1" * 45
        assert "slack_bot" in [n for n, _ in crs.scan_content(sample)]

    def test_pem_private_key_header(self):
        sample = "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----"
        assert "private_key_header" in [n for n, _ in crs.scan_content(sample)]


# ── Pattern negatives (false-positive guards) ───────────────────────


class TestTokenPatternsDoNotMatchLookalikes:
    """Things that LOOK like secrets but aren't must NOT trigger."""

    def test_short_sk_word_not_matched(self):
        # "skin", "skies", "skip" all start with sk and are not tokens.
        for word in ("skin", "skies", "skip", "ski-trip", "sk-bar"):
            findings = crs.scan_content(word)
            assert not any(name == "openai_stripe_sk" for name, _ in findings), (
                f"false positive on innocuous string {word!r}"
            )

    def test_short_github_prefix_not_matched(self):
        # "ghp_" alone, or "ghp_short" with too few chars to be a real PAT.
        for sample in ("ghp_", "ghp_short", "ghp_" + "a" * 10):
            assert not any(name == "github_classic" for name, _ in crs.scan_content(sample))

    def test_host_port_url_not_matched_as_cred(self):
        # "http://localhost:5000" has a colon but no @ -- not a cred URL.
        text = "Server at http://localhost:5000 and http://127.0.0.1:8080"
        # Run the URL detector via its full helper.
        m = crs._URL_CRED_PATTERN.search(text)
        assert m is None, "host:port URL should not match the cred pattern"

    def test_clean_https_remote_not_matched(self):
        # "https://github.com/owner/repo.git" -- no creds, no match.
        text = "https://github.com/shigsdev/windesktopmgr.git"
        assert crs._URL_CRED_PATTERN.search(text) is None


# ── Output redaction ────────────────────────────────────────────────


class TestRedaction:
    """The scanner output MUST NOT replay the raw secret -- the literal
    string '<REDACTED>' replaces the match body. This invariant is what
    lets the pre-commit hook print findings safely to a log."""

    def test_content_scan_redacts_token(self):
        # ghp_ tokens are alphanumeric only (no underscores) -- use an
        # unmistakable alnum marker we can assert against.
        marker = "REALSECRETVALUEDONOTPRINT"  # 25 chars, alnum only
        token = "ghp_" + marker + "x" * 11  # 36 chars after the prefix
        findings = crs.scan_content(f"GH_TOKEN={token}")
        assert findings, "expected at least one finding"
        name, excerpt = findings[0]
        assert marker not in excerpt, "raw secret leaked through redaction"
        assert "<REDACTED>" in excerpt

    def test_excerpt_keeps_surrounding_context(self):
        # User wants enough context to find the line; the redaction must
        # leave the prefix + suffix visible so they can locate it.
        token = "ghp_" + "Z" * 36
        findings = crs.scan_content(f"prefix-text-before {token} after-suffix-text")
        assert findings
        excerpt = findings[0][1]
        assert "prefix-text-before" in excerpt or "before" in excerpt
        assert "after-suffix-text" in excerpt or "after" in excerpt


# ── File-level scanner ─────────────────────────────────────────────


class TestScanFile:
    def test_clean_file_returns_no_findings(self, tmp_path):
        p = tmp_path / "clean.py"
        p.write_text("x = 1\ny = 2\nprint('hello')\n", encoding="utf-8")
        assert crs.scan_file(p) == []

    def test_dirty_file_returns_findings(self, tmp_path):
        p = tmp_path / "dirty.py"
        p.write_text(f"GH_TOKEN = 'ghp_{'A' * 36}'\n", encoding="utf-8")
        f = crs.scan_file(p)
        assert len(f) == 1
        assert f[0][0] == "github_classic"

    def test_binary_extension_skipped(self, tmp_path):
        # Even if a .png "happens" to contain matching bytes, the
        # extension filter must short-circuit -- we never open binaries.
        p = tmp_path / "ignore.png"
        p.write_text("ghp_" + "Z" * 36, encoding="utf-8")
        assert crs.scan_file(p) == []

    def test_unreadable_file_silently_skipped(self, tmp_path):
        # A file with invalid UTF-8 bytes shouldn't crash the scanner.
        p = tmp_path / "bin.txt"
        p.write_bytes(b"\xff\xfe\x00 invalid utf-8 ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        # No exception; returns empty.
        assert crs.scan_file(p) == []

    def test_allowlisted_path_skipped(self, tmp_path, monkeypatch):
        # Put a fake "allowlisted" file in tmp and add its repo-relative
        # path to the allowlist. The scanner must skip it even if it
        # contains a token.
        p = tmp_path / "fake-fixture.json"
        p.write_text(f"token: ghp_{'B' * 36}", encoding="utf-8")
        # The allowlist is keyed on the normalised path passed to scan_file.
        norm = crs._normalise(p)
        monkeypatch.setattr(crs, "_ALLOWLIST", {norm})
        assert crs.scan_file(p) == []


# ── URL-cred scanner ───────────────────────────────────────────────


class TestRemoteUrlScanner:
    """scan_remote_urls() pulls URLs via git config and classifies them."""

    def test_embedded_password_detected_and_redacted(self, monkeypatch):
        # Mock the git config output: one remote with embedded creds.
        monkeypatch.setattr(
            crs,
            "_remote_urls",
            lambda: [("origin", "https://shigsdev:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/owner/repo.git")],
        )
        findings = crs.scan_remote_urls()
        assert len(findings) == 1
        name, url, kind = findings[0]
        assert name == "origin"
        assert kind == "embedded_password"
        # Redaction replaced the password section but kept the user + host.
        assert "shigsdev" in url
        assert "github.com" in url
        assert "ghp_" not in url
        assert "<REDACTED>" in url

    def test_username_only_detected(self, monkeypatch):
        # https://user@github.com/... -- no password, but still odd.
        monkeypatch.setattr(crs, "_remote_urls", lambda: [("origin", "https://shigsdev@github.com/owner/repo.git")])
        findings = crs.scan_remote_urls()
        assert len(findings) == 1
        assert findings[0][2] == "username_only"

    def test_clean_https_remote_no_finding(self, monkeypatch):
        monkeypatch.setattr(crs, "_remote_urls", lambda: [("origin", "https://github.com/owner/repo.git")])
        assert crs.scan_remote_urls() == []

    def test_clean_ssh_remote_no_finding(self, monkeypatch):
        # SSH form "git@github.com:owner/repo" -- ssh authenticates via
        # the user's key, not a password. We tolerate the "git@" prefix.
        monkeypatch.setattr(crs, "_remote_urls", lambda: [("origin", "git@github.com:owner/repo.git")])
        # ssh:// scheme isn't in the URL form so the cred pattern won't
        # match. Username-only is also not flagged for SSH since there's
        # no colon-port syntax matching the host:port-style URL.
        findings = crs.scan_remote_urls()
        assert not findings

    def test_multiple_remotes_independent(self, monkeypatch):
        # Mixed: one clean, one with embedded password.
        monkeypatch.setattr(
            crs,
            "_remote_urls",
            lambda: [
                ("upstream", "https://github.com/upstream/repo.git"),
                ("fork", "https://user:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/fork/repo.git"),
            ],
        )
        findings = crs.scan_remote_urls()
        assert len(findings) == 1
        assert findings[0][0] == "fork"


# ── Orchestrator + exit code ───────────────────────────────────────


class TestMainExitCode:
    """The script must exit 0 on clean and 1 on any finding so pre-commit
    can gate properly."""

    def test_clean_exit_code_zero(self, tmp_path, monkeypatch, capsys):
        # No staged files, no remotes -- a totally clean run.
        monkeypatch.setattr(crs, "_staged_files", list)
        monkeypatch.setattr(crs, "_tracked_files", list)
        monkeypatch.setattr(crs, "_remote_urls", list)
        rc = crs.main(["--staged"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_dirty_file_exit_code_one(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "leaky.py"
        p.write_text(f"TOKEN='ghp_{'C' * 36}'", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(crs, "_staged_files", lambda: [str(p.name)])
        monkeypatch.setattr(crs, "_remote_urls", list)
        rc = crs.main(["--staged"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "LEAK" in captured.out
        # The actual secret bytes must NOT be in stdout.
        assert "CCCCCCCCC" not in captured.out  # raw secret would have these C's

    def test_remote_url_finding_alone_exits_one(self, monkeypatch, capsys):
        monkeypatch.setattr(crs, "_staged_files", list)
        monkeypatch.setattr(crs, "_tracked_files", list)
        monkeypatch.setattr(
            crs,
            "_remote_urls",
            lambda: [("origin", "https://user:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/o/r.git")],
        )
        rc = crs.main(["--staged"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "LEAK" in captured.out
        assert "embedded_password" in captured.out

    def test_no_remotes_flag_skips_url_check(self, monkeypatch, capsys):
        # Even with a dirty remote, --no-remotes skips that check.
        monkeypatch.setattr(crs, "_staged_files", list)
        monkeypatch.setattr(crs, "_tracked_files", list)
        monkeypatch.setattr(
            crs,
            "_remote_urls",
            lambda: [("origin", "https://user:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/o/r.git")],
        )
        rc = crs.main(["--staged", "--no-remotes"])
        assert rc == 0

    def test_remote_urls_only_flag_skips_file_scan(self, tmp_path, monkeypatch, capsys):
        # Even with a dirty file in staging, --remote-urls-only ignores it.
        p = tmp_path / "leaky.py"
        p.write_text(f"TOKEN='ghp_{'D' * 36}'", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(crs, "_staged_files", lambda: [str(p.name)])
        monkeypatch.setattr(crs, "_remote_urls", list)  # clean remotes
        rc = crs.main(["--remote-urls-only"])
        assert rc == 0


# ── Real-world allowlist sanity check ──────────────────────────────


class TestAllowlistedFixturesSkipped:
    """The two real Credential Manager metadata fixtures in this repo
    are in the allowlist. They must continue to be skipped so the pre-
    commit hook stays clean."""

    def test_credentials_parsed_fixture_skipped(self):
        # This file actually exists in the repo (it's the fixture we
        # discussed in the audit). The allowlist must include it.
        target = "tests/fixtures/parsed/parsed_get_credentials_network_health.json"
        assert target in crs._ALLOWLIST

    def test_credentials_ps_fixture_skipped(self):
        target = "tests/fixtures/powershell/ps_credentials.json"
        assert target in crs._ALLOWLIST

    def test_scanner_test_file_self_allowlisted(self):
        # This file -- the one you're reading -- contains synthetic
        # token-shape strings ("ghp_" + 'A'*36, etc) for testing the
        # detector. The detector would correctly flag those as
        # github_classic matches, so the test file itself MUST be in
        # the allowlist to keep the pre-commit hook clean.
        target = "tests/test_check_repo_secrets.py"
        assert target in crs._ALLOWLIST
