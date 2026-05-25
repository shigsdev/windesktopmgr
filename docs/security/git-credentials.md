# Git credentials & secret-rotation playbook

This document covers how WinDesktopMgr handles git credentials, what the
pre-commit secret scanner catches, and exactly what to do when a token
or secret leaks.

## Why this exists

A leaked credential in git history is permanent — deleting the file in
a later commit does not remove it from history, and force-pushing
"clean" history is destructive + breaks every clone. The scanner here
is the first line of defence; rotation is the second.

## What's protected today

Two layers, both running on every commit via `.pre-commit-config.yaml`:

1. **`scripts/check_repo_secrets.py`** — fast Python regex scanner.
   Catches the common token shapes (GitHub PATs, AWS access keys,
   OpenAI/Stripe `sk-`, npm tokens, Slack tokens, PEM private-key
   headers) and embedded credentials in git remote URLs
   (`https://user:token@github.com/...`).
2. **`gitleaks`** — the upstream rule pack with hundreds of additional
   patterns. Runs as a separate pre-commit hook.

Both must pass before a commit lands. Either one flagging a finding
blocks the commit.

## How the Python scanner is configured

`scripts/check_repo_secrets.py` has three operating modes:

- `python scripts/check_repo_secrets.py` — scan every git-tracked file
  in the working tree (default, also `--all`).
- `python scripts/check_repo_secrets.py --staged` — scan only files
  staged for the current commit. This is the **pre-commit hook mode**.
- `python scripts/check_repo_secrets.py --remote-urls-only` — skip
  files; just check `git remote -v` for the `user:pass@host` shape.

Two knobs inside the script you may need to adjust:

- `_TOKEN_PATTERNS` — list of `(name, regex)` tuples for known token
  shapes. Add new ones as cloud providers introduce them.
- `_ALLOWLIST` — set of repo-root-relative paths to skip. Two entries
  cover the Credential Manager metadata fixtures
  (`tests/fixtures/parsed/parsed_get_credentials_network_health.json`
  and `tests/fixtures/powershell/ps_credentials.json`) which match the
  file-name pattern but contain no actual secrets.

When the scanner reports a finding, it always **redacts the secret
itself** with the literal string `<REDACTED>` before printing — so the
terminal output / CI log never replays the leaked value.

## When a finding fires

The scanner prints lines like:

```
LEAK: path/to/file.py -- github_classic -- ...prefix...<REDACTED>...suffix...
LEAK: git remote 'origin' has embedded_password: https://shigsdev:<REDACTED>@github.com/...
```

The pattern name (`github_classic`, `aws_access_key`, ...) tells you
**which kind of token** leaked so you know where to rotate.

## Rotation procedure (do this immediately when a leak is found)

The order matters: **rotate first, scrub history second**. Leaving the
old token live while you scrub history widens the exposure window.

### 1. Identify the affected credential

Look at the `--` middle field on the LEAK line. Translate:

| Pattern name | What to rotate |
|---|---|
| `github_pat` / `github_classic` / `github_oauth` / `github_s2s` / `github_u2s` / `github_refresh` | The matching GitHub Personal Access Token |
| `aws_access_key` | The IAM access key pair (rotate the secret too even if it wasn't matched) |
| `openai_stripe_sk` | The OpenAI / Stripe / similar API key |
| `npm_token` | The npm publish token |
| `slack_bot` / `slack_user` | The Slack app's bot or user OAuth token |
| `private_key_header` | The whole keypair (regenerate both halves) |
| `embedded_password` (URL) | The token used in the remote URL |

### 2. Rotate at the provider

**GitHub PAT** — https://github.com/settings/personal-access-tokens
1. Find the leaked token by name or last-used date.
2. Click **Revoke**.
3. Generate a fresh token with the **minimum scope** the workflow needs
   and a **90-day expiration**.
4. Update Windows Credential Manager (the `manager` git credential
   helper this project uses stores it there) — the next `git push`
   will prompt for the new value, or you can pre-populate via:
   `printf 'host=github.com\nprotocol=https\n' | git credential reject`
   then re-clone or re-push to trigger the prompt.

**AWS access key** — https://console.aws.amazon.com/iam/home#/users
1. Open the user → **Security credentials** tab.
2. **Deactivate** the leaked key first (preserves audit trail).
3. **Create** a new key, update `~/.aws/credentials`.
4. After confirming the new key works, **Delete** the deactivated one.

**OpenAI / Stripe / similar** — provider-specific dashboard. Revoke,
generate, update local `.env` and any production secret-stores.

### 3. Scrub the leaked value from local state

The token is now invalid, but it may still be in places that cache it:

- **Windows Credential Manager** — `control /name Microsoft.CredentialManager`, find any entries that reference the leaked credential, **Remove**.
- **PowerShell PSReadLine history** — `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. Either delete the whole file (it regenerates next session) or edit it to remove the offending lines. The audit doc at `~/.claude/projects/.../memory/feedback_repo_security_audit.md` (or wherever your audit script lives) can pinpoint lines via `Select-String`.
- **Shell history** (bash/zsh) — `~/.bash_history`, `~/.zsh_history` — same treatment.
- **Cloud-synced folders** — if any of the above paths are under OneDrive / iCloud / Dropbox, the old file version is recoverable from the cloud's version-history UI for up to 30 days. Rotation already invalidates the token, but you can also exclude `.git/`, `~/.ssh/`, and shell-history paths from cloud sync to prevent future replication.

### 4. Scrub from git history (only if the token was actually committed)

If `gitleaks detect --source . --no-banner` reports the token in **git history** (not just the working tree), the local files aren't enough — every clone and every fork contains the secret. Two tools:

- **`git filter-repo`** (recommended) — installable via `pip install git-filter-repo`. Run:
  ```bash
  git filter-repo --replace-text <(echo "OLD_TOKEN==><REDACTED>")
  ```
  This rewrites every commit, replacing the token with `<REDACTED>`. **Destructive — coordinate with everyone who has cloned the repo before pushing.**

- **BFG Repo-Cleaner** — alternative, faster on large repos. https://rtyley.github.io/bfg-repo-cleaner/

After rewriting, force-push:
```bash
git push --force-with-lease origin main
```

Everyone else needs to `git fetch && git reset --hard origin/main` (or re-clone).

### 5. Verify

Re-run the scanner:
```bash
python scripts/check_repo_secrets.py
gitleaks detect --source . --no-banner
```

Both must report clean before you call it done.

## Preventing this class of incident

- **Never paste a token into a shell command.** Use the credential
  helper (`git config --global credential.helper manager` on Windows;
  it stores in Windows Credential Manager) so git fetches the token
  from there, not from the URL or your shell history.
- **Always set an expiration date** on PATs — 90 days is a good
  default. An expired token is a soft rotation.
- **Minimum scope.** A token that can only read a specific repo can't
  do as much damage if it leaks as one that can write to the entire
  org.
- **Periodic audit.** Run `python scripts/check_repo_secrets.py` on
  any old clone you haven't touched in a while before pushing. The
  pre-commit hook catches new leaks; the audit catches old ones.

## File / module map

| Where | What |
|---|---|
| `scripts/check_repo_secrets.py` | The Python scanner |
| `.pre-commit-config.yaml` | Wires the scanner + gitleaks into every commit |
| `tests/test_check_repo_secrets.py` | Unit tests for the scanner |
| `docs/security/git-credentials.md` | This document |

## Related backlog

- **#47 Backup tab** — surfaces what Windows already backs up (the
  Credential Manager fixtures the scanner allowlists are part of that
  feature's test inventory).
- Rotating credentials is partially covered by **#12 1Password
  Credential Backend** if/when that ships — 1Password CLI has rotate
  flows that this playbook would defer to.
