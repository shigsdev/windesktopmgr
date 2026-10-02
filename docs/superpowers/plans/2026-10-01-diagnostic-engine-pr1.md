# Diagnostic Engine (PR 1: engine + Network & DNS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the 🔍 Diagnose tab. The user pastes a symptom, the app runs read-only network/DNS probes, shows exactly what would be sent, and (with consent) gets a model verdict. If a fix is warranted, it comes from the vetted remediation registry.

**Architecture:** Two new root modules. `diagnose_probes.py` holds the closed probe registry, the parallel runner, and the 14 network/DNS probes. `diagnose.py` holds the classifier, deterministic rules, redaction, payload/egress gate, model call, session state machine, history, and `diagnose_bp`. A background thread per diagnosis plus polling, the same pattern as `maintenance.start_or_get`. The UI is a new tab with JS prefix `dx`.

**Tech Stack:** Flask blueprint, stdlib `socket`/`ssl`/`winreg`/`ipaddress`, `dnspython>=2.6` (new), optional `anthropic` SDK (already installed, 0.86, supports `output_config` structured outputs), pytest + pytest-mock, pytest-playwright.

**Spec:** `docs/superpowers/specs/2026-10-01-diagnostic-engine-design.md` (approved 2026-10-01). Read it alongside this plan; § references below point into it.

## Global Constraints

- Branch: `feat/diagnose-engine` off current `main` (`9b7831f` or later). One PR for the whole plan (spec §14 "PR 1").
- New dependency: `dnspython>=2.6` in `requirements.txt`. `anthropic` stays optional (import-guarded, as in `ai_identify.py`); do not add it to requirements.
- Python first (CLAUDE.md): no PowerShell anywhere in this feature. Only two subprocesses, `ping.exe` and `tracert.exe`, each with list args and no shell. Their target is validated by `ipaddress` / `normalize_host`.
- Every probe is read-only. No probe function may appear in `remediation._REMEDIATION_DISPATCH`.
- The model returns action **keys only**. Server validates against `remediation.REMEDIATION_REGISTRY`; renders registry metadata only. Nothing auto-executes.
- `locus == "external_cause"` ⇒ `suggested_actions == []`, enforced server-side. `status == "inconclusive"` ⇒ `suggested_actions == []` and never rendered as a diagnosis.
- Escalation: max **2** extra rounds, max **4** probes per round. At most 3 interpretation calls per diagnosis, plus one reformat retry per call (§12).
- Model id: `DIAGNOSE_MODEL = os.environ.get("DIAGNOSE_MODEL", "claude-sonnet-5-5")`. The user chose Sonnet 5.5 over the spec's Sonnet 5 on 2026-10-01: same price, current generation. Do not send `thinking` (Sonnet 5.5 runs adaptive by default; `{"type": "disabled"}` is a 400). Per-process cap `MAX_DIAGNOSE_CALLS = 60`.
- Egress gate on by default. The model client must not be called before consent is recorded for that payload (§7).
- Redaction: `username` always applied to the whole payload; `mac`/`serial` per probe; `local_ip` off for the network class. Hostnames and public IPs are **not** redacted (§7).
- POST routes use non-silent `request.get_json()` (blocks cross-site form posts). `session_id` = `secrets.token_urlsafe(16)`, validated `^[A-Za-z0-9_-]{16,32}$`.
- Symptom text max 4000 chars.
- JS: all tab functions prefixed `dx_`; all interpolated values through the shared `escHtml()` (static/js/app.js:4).
- Tests mock `diagnose_probes.socket` / `diagnose_probes.subprocess.run` / `diagnose_probes._dns_query` / `diagnose_probes._reg_values` / `diagnose._call_model`. **Never** real network, registry, or Anthropic calls in the unit suite.
- Running a single test file: `python -m pytest <file> -q --no-cov` (the repo's `--cov-fail-under=80` addopt fails partial runs). If pytest crashes at teardown with `WinError 5 ... pytest-current`, first `export PYTEST_DEBUG_TEMPROOT="<scratchpad>/pt-$$"; mkdir -p "$PYTEST_DEBUG_TEMPROOT"` (known Windows issue).
- Ruff: use the pinned binary `C:/Users/higs7/.cache/pre-commit/repo9x_k88ol/py_env-python3.14/Scripts/ruff.exe` (fall back to `python -m ruff` only if absent).

## Decisions this plan makes where the spec is open or inconsistent

These were settled while planning (8 added after the user chose Sonnet 5.5). Each is flagged in the PR body.

1. **No `edit_hosts` action exists.** The registry has ten keys and none edits the hosts file. The spec's `hosts_file_override.json` fixture therefore expects `locus: "local"`, **no** actions, and `flush_dns` excluded; the headline names the hosts line. Adding a hosts-writing remediation is out of scope.
2. **Fixtures test the deterministic rule layer.** §9 mentions "deterministic rule hits". This plan makes that concrete as `evaluate_rules(evidence) -> verdict`. It is what the §13 fixture directory asserts against, because a unit test cannot call the real model. The rule verdict is (a) the evidence-only answer, (b) sent to the model as context, and (c) a guard: a *confident* rule `external_cause` overrides the model's locus. S1 is therefore pinned twice: the fixture (rules), and an engine test where a mocked model says `local` + `flush_dns` and the final verdict is still `external_cause` with no actions.
3. **No model-based classifier in PR 1.** With one symptom class, a model classifier can only answer "network_dns". Sending the symptom before the preview gate would also break S2. Low-confidence input returns `awaiting_slots` with a class picker and a host field. Revisit in PR 2 when a second class exists, and route it through the egress gate.
4. **Structured outputs instead of free-text JSON.** `output_config.format` with a json_schema whose `suggested_actions` / `need_probes` are `enum`s of the legal keys. Server-side validation still runs (defence in depth, §8). The §12 "one reformat retry" covers refusal / `max_tokens` truncation.
5. **Two modules, not one** (`diagnose.py` + `diagnose_probes.py`). The probe file is what PRs 2–4 grow; the engine file stays frozen.
6. **Rules for proxy misconfig and captive portal are deferred.** No PR 1 probe connects *through* the proxy or fetches HTTP, so neither condition is observable. Dead gateway **is** observable and ships, as `locus: "local"`, `status: "likely"`, action `reset_network_adapter`.
8. **Model is Sonnet 5.5 with server-side refusal fallback.** Calls go through `client.beta.messages.create(..., betas=["server-side-fallback-2026-07-01"], extra_body={"fallbacks": "default"})`. If Sonnet 5.5's safety classifier declines a request, Anthropic re-runs it on a fallback model instead of returning nothing. `extra_body` is needed because SDK 0.86 has no typed `fallbacks` argument. A final `stop_reason == "refusal"` still degrades to evidence-only.
7. **"Don't ask again"** is per browser session (`sessionStorage`). The server still records an explicit consent for every send: the UI auto-POSTs it, and `auto_followups: true` approves escalation rounds of the same diagnosis.

## Review Focus

Five input classes the spec implies but never states, most likely first. Each has a pinning test in the task named.

1. **A host pasted in an odd form.** Expected: `https://WWW.Hynote.ai:443/login?x=1#y`, `hynote.ai.`, Chrome's possessive `hynote.ai’s` (curly and straight apostrophes), IDN `münchen.de` → `xn--mnchen-3ya.de`, and IPv4 literals all normalise. Garbage such as `foo`, `..`, `a b.com`, and 254+ chars → `None`. *Task 2 (`normalize_host`) and Task 7 (classifier).*
2. **A symptom naming more than one host** ("google.com works but hynote.ai doesn't"). Expected: the engine does not guess. It returns `awaiting_slots` with both hosts as `candidates` and the UI asks which one to test. *Task 7.*
3. **Username redaction edge cases.** Expected: a short username such as `al` is not stripped from `local` or `alpha` (word/path boundaries only); case variants in paths (`C:\USERS\Al\`) are caught; an unset/empty `USERNAME` env redacts nothing and does not crash. *Task 9.*
4. **A machine that is fully offline or has a hung resolver.** Expected: wave one still finishes inside its bound (no probe holds the runner past its `timeout_s`). Every timed-out probe is `{ok: False, error: "timed out after Ns"}`, and the session ends `evidence_only`/inconclusive rather than hanging. *Task 1 (runner bound) and Task 11 (model unreachable).*
5. **The user abandons or repeats consent.** Expected: closing the tab means consent never arrives, and after `_CONSENT_TIMEOUT_S` the session ends `evidence_only` (`reason: "consent_timeout"`). A double-clicked Send is idempotent (second POST → 409, model called once). Consent for an unknown or expired session → 404. *Task 11 and Task 12.*

---

## File Map

| File | Responsibility |
|---|---|
| `diagnose_probes.py` (new) | `Probe`, `PROBES`, `register`, `run_probes`, `normalize_host`, `_dns_query`, registry helpers, all 14 probe functions |
| `diagnose.py` (new) | `SYMPTOM_CLASSES`, `classify`, `evaluate_rules`, `cache_agrees`, `redact`, `build_payload`, model call + `parse_reply` + `apply_guards`, session engine, history, `diagnose_bp` routes |
| `tests/test_diagnose_probes.py` (new) | Runner, registry invariants, every probe (happy/empty/malformed/timeout), command-content + sanitisation for the two subprocess probes |
| `tests/test_diagnose.py` (new) | Classifier, rules fixture test, redaction, payload, model call, guards, engine, history, routes |
| `tests/fixtures/diagnose/*.json` (new) | One scenario per file (§13) |
| `tests/test_playwright_smoke.py` | `"diagnose"` in `TAB_IDS`; `TestDiagnoseTab` |
| `tests/conftest.py` | Reset `diagnose` globals in `reset_globals` |
| `windesktopmgr.py` | Import + `app.register_blueprint(diagnose_bp)` next to `maintenance_bp` (~line 5213) |
| `templates/index.html` | Tab button + `#page-diagnose` |
| `static/js/app.js` | Tab-switch branch + `dx_*` functions |
| `static/css/app.css` | `.dx-*` styles |
| `requirements.txt`, `pyproject.toml` | `dnspython>=2.6`; `--cov=diagnose --cov=diagnose_probes` |
| `architecture.html`, `CLAUDE.md` | New module chips/routes/tab/tests; `dx` prefix in the JS naming list |

## Evidence shapes (shared contract)

Each probe function returns only its `data` dict. `run_probes` wraps it as
`{"key", "label", "ok": True, "data": {...}, "elapsed_ms"}` or
`{"key", "label", "ok": False, "error": str, "elapsed_ms"}`. A *failed lookup* is
`ok: True` with data saying so; `ok: False` means the probe itself could not run.
Throughout, an `rcode` is one of `"NOERROR"|"NXDOMAIN"|"SERVFAIL"|"REFUSED"|"TIMEOUT"|"ERROR"`.

| Key | Wave | `data` |
|---|---|---|
| `dns.resolve_cached` | 1 | `{resolved: bool, addresses: [str] (sorted, unique), error: str\|None}` |
| `dns.resolve_direct` | 1 | `{dnspython: bool, resolvers: [{name: "system"\|"cloudflare"\|"google", server, rcode, nodata, answers: [str]}]}` (A records) |
| `dns.authoritative` | 1 | `{zone: str\|None, nameservers: [{name, ip, rcode, nodata, aa, answers}]}` (≤2 NS queried) |
| `dns.record_sweep` | 1 | `{records: {"A"\|"AAAA"\|"CNAME"\|"MX"\|"TXT"\|"SOA"\|"NS": [str]}, rcode}` (rcode of the A query) |
| `dns.hosts_file` | 1 | `{path, readable: bool, matches: [{line_no, ip, names: [str]}]}` |
| `dns.client_config` | 1 | `{adapters: [{guid, dns_servers: [str]}], search_list: [str], enable_auto_doh: int\|None}` |
| `net.control_domain` | 1 | `{host: CONTROL_DOMAIN, resolved: bool, connected: bool, connect_ms: float\|None, error: str\|None}` |
| `net.gateway` | 1 | `{gateways: [str], reachable: bool\|None, rtt_ms: float\|None}` (`reachable: None` when no gateway configured) |
| `net.proxy_config` | 1 | `{wininet: {proxy_enable, proxy_server, proxy_override, auto_config_url, auto_detect}, winhttp: {...}\|{parse_error}, env: {HTTP_PROXY, HTTPS_PROXY, NO_PROXY}}` |
| `dns.trace_delegation` | esc | `{chain: [{zone, rcode, ns: [str]}]}` (TLD down to the target, via 1.1.1.1) |
| `dns.dnssec_check` | esc | `{rcode_validating, rcode_cd, ad: bool, validation_failure: bool}` |
| `net.tcp_connect` | esc | `{results: [{port: 443\|80, connected, ms, error}]}` |
| `net.tls_handshake` | esc | `{handshake: bool, protocol: str\|None, cert_cn: str\|None, not_after: str\|None, error: str\|None}` |
| `net.traceroute` | esc | `{hops: [{hop: int, ip: str\|None, timeout: bool}], reached: bool}` |

Verdict shape (§6.1 plus server fields): `{status, locus, headline, reasoning, evidence_refs: [str], suggested_actions: [str], no_local_fix_reason: str, source: "rules"|"model", rule_hits: [str]}`.

---

### Task 1: Probe registry and parallel runner

**Files:**
- Create: `diagnose_probes.py`
- Create: `tests/test_diagnose_probes.py`
- Modify: `requirements.txt` (append `dnspython>=2.6` with a two-line comment in the file's existing style: why stdlib `socket` is not enough, see §4.1), `pyproject.toml` addopts (add `"--cov=diagnose"`, `"--cov=diagnose_probes"`)

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class Probe: key: str; label: str; category: str; fn: Callable[[dict], dict]; needs: tuple[str, ...] = (); redact: tuple[str, ...] = (); timeout_s: float = 8.0`
  - `PROBES: dict[str, Probe]`
  - `register(probe: Probe) -> Probe`: raises `ValueError` on a duplicate key.
  - `run_probes(keys: Sequence[str], slots: dict) -> list[dict]`: results in input-key order, shape per "Evidence shapes".

- [ ] **Step 1: Create the branch and install the dependency**

```bash
git checkout -b feat/diagnose-engine main && python -m pip install "dnspython>=2.6"
```

- [ ] **Step 2: Write the failing tests** (`TestRunProbes`). Each test registers throwaway probes into a monkeypatched `PROBES` dict (`mocker.patch.dict(dp.PROBES, {}, clear=True)`).

```python
def test_happy_path_wraps_data(self): ...           # fn returns {"x": 1} -> {"key","label","ok": True,"data": {"x": 1}} and elapsed_ms >= 0
def test_raising_probe_becomes_error_not_exception(self): ...  # fn raises RuntimeError("boom") -> ok False, "boom" in error
def test_missing_slot_refuses_without_calling(self): ...        # needs=("target_host",), slots={} -> ok False, error == "missing required slot: target_host", fn not called
def test_unknown_key_reported(self): ...             # key not in PROBES -> ok False, error == "unknown probe"
def test_timeout_is_bounded(self): ...               # fn sleeps 2s, timeout_s=0.2 -> ok False, error == "timed out after 0.2s"; whole call < 1.0s
def test_results_preserve_input_order(self): ...     # keys ["b","a"] -> [r["key"] for r in out] == ["b","a"]
def test_runs_in_parallel(self): ...                 # 3 probes each sleeping 0.3s -> total < 0.8s
def test_register_rejects_duplicate(self): ...       # second register(same key) raises ValueError
def test_non_dict_return_is_error(self): ...         # fn returns "str" -> ok False, error == "probe returned str, expected dict"
def test_empty_key_list_returns_empty(self): ...     # run_probes([], {}) == [] (no executor created)
```

- [ ] **Step 3: Run them and confirm they fail**

Run: `python -m pytest tests/test_diagnose_probes.py -q --no-cov`
Expected: FAIL / ImportError `No module named 'diagnose_probes'`

- [ ] **Step 4: Implement `Probe`, `PROBES`, `register`, `run_probes`**

Run probes with `concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(keys)))`, created **without** a `with` block and released with `shutdown(wait=False)`. This is the same reason given in the `network._measure_dns_latency` docstring: a hung resolver must not block the return. Record `t0` once at submit. Each future's timeout is `max(0.0, probe.timeout_s - (now - t0))`. Module docstring follows `remediation.py`'s style: what it is, why it is a closed registry (§4).

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_diagnose_probes.py -q --no-cov`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add diagnose_probes.py tests/test_diagnose_probes.py requirements.txt pyproject.toml
git commit -m "feat(diagnose): closed probe registry and bounded parallel runner"
```

---

### Task 2: Host normalisation and the dnspython query wrapper

**Files:**
- Modify: `diagnose_probes.py`
- Test: `tests/test_diagnose_probes.py`

**Interfaces:**
- Produces:
  - `normalize_host(raw: str) -> str | None`: lowercase ASCII (IDNA) hostname or IP literal, or `None`.
  - `HAVE_DNSPYTHON: bool` (import guard: `try: import dns.flags, dns.message, dns.query, dns.rcode, dns.rdatatype, dns.resolver, dns.exception`).
  - `_dns_query(server: str, name: str, rdtype: str, *, timeout: float = 3.0, want_dnssec: bool = False, cd: bool = False) -> dict` returning `{server, rcode, nodata: bool, answers: [str], aa: bool, ad: bool, error: str|None}`.
  - `_system_nameservers() -> list[str]`: `dns.resolver.Resolver().nameservers`, `[]` on any error or without dnspython.
  - `PUBLIC_RESOLVERS = (("cloudflare", "1.1.1.1"), ("google", "8.8.8.8"))`

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.parametrize("raw,expected", [
    ("hynote.ai", "hynote.ai"),
    ("https://WWW.Hynote.ai:443/login?x=1#y", "www.hynote.ai"),
    ("hynote.ai.", "hynote.ai"),
    ("hynote.ai’s", "hynote.ai"), ("hynote.ai's", "hynote.ai"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("8.8.8.8", "8.8.8.8"),
    ("foo", None), ("..", None), ("a b.com", None), ("", None),
    ("a" * 250 + ".com", None),
    ("hynote.ai;rm -rf", None),
])
def test_normalize_host(raw, expected): assert dp.normalize_host(raw) == expected
```

`TestDnsQuery`: patch `dp.dns.query.udp` / `dp.dns.query.tcp` with fake responses (build real ones with `dns.message.make_response(dns.message.make_query(...))` and set `.set_rcode(...)` / `.flags`).
- NOERROR with an A answer → `rcode == "NOERROR"`, `answers == ["93.184.216.34"]`, `nodata is False`
- NOERROR, empty answer → `nodata is True`
- NXDOMAIN → `rcode == "NXDOMAIN"`, `answers == []`
- AA flag set → `aa is True`; AD set → `ad is True`
- `dns.exception.Timeout` → `rcode == "TIMEOUT"`
- `OSError("unreachable")` → `rcode == "ERROR"` and `"unreachable" in error`
- TC flag on the UDP reply → falls back to `dns.query.tcp` (assert it was called)
- `cd=True` → the query passed to `udp` has `dns.flags.CD` set
- `HAVE_DNSPYTHON` patched False → `rcode == "ERROR"`, `error == "dnspython not installed"`

- [ ] **Step 2: Run them and confirm they fail**

Run: `python -m pytest tests/test_diagnose_probes.py -q --no-cov -k "normalize or DnsQuery"`
Expected: FAIL (AttributeError)

- [ ] **Step 3: Implement**

`normalize_host` steps:
1. Strip; drop a leading scheme (`^[a-z][a-z0-9+.-]*://`).
2. Cut at the first of `/?#`. Drop a `:port` suffix (but not inside an IPv6 literal).
3. Strip a trailing `’s` / `'s`, then a trailing `.`.
4. Accept `ipaddress.ip_address(...)` as is.
5. Otherwise `encode("idna").decode()`, lowercase, and match `^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`.

`_dns_query`:
- `dns.message.make_query(name, rdtype, want_dnssec=want_dnssec)`, OR in `dns.flags.CD` when `cd`, then `dns.query.udp(q, server, timeout=timeout)`. If the reply has `dns.flags.TC`, retry with `dns.query.tcp`.
- `answers` = `rd.to_text()` for every rrset in `r.answer` whose `rdtype` matches the request.
- `nodata = rcode == "NOERROR" and not answers`.

- [ ] **Step 4: Run them and confirm they pass**

Run: `python -m pytest tests/test_diagnose_probes.py -q --no-cov`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add diagnose_probes.py tests/test_diagnose_probes.py
git commit -m "feat(diagnose): host normaliser and dnspython query wrapper"
```

---

### Task 3: Wave-one resolution probes

**Files:**
- Modify: `diagnose_probes.py`
- Test: `tests/test_diagnose_probes.py`

**Interfaces:**
- Consumes: `register`, `Probe`, `_dns_query`, `_system_nameservers`, `PUBLIC_RESOLVERS` (Tasks 1–2).
- Produces registered probes (all `category="network"`, `needs=("target_host",)`, `redact=("username",)`):
  - `dns.resolve_cached`, label "Resolve through Windows (uses the DNS cache)", timeout 8
  - `dns.resolve_direct`, label "Ask DNS servers directly (bypasses the cache)", timeout 8
  - `dns.authoritative`, label "Ask the domain's own nameservers", timeout 12
  - `dns.record_sweep`, label "List every DNS record type for the name", timeout 10

- [ ] **Step 1: Write the failing tests.** One class per probe; call `dp.PROBES[key].fn({"target_host": "hynote.ai"})` directly.
  - `resolve_cached`: `socket.getaddrinfo` patched on `dp.socket`. Happy (two tuples with the same IP → `addresses` deduped and sorted, `resolved True`); `socket.gaierror(11001, "getaddrinfo failed")` → `resolved False`, `"11001" in error`; empty list → `resolved False`.
  - `resolve_direct`: patch `dp._dns_query` and `dp._system_nameservers` (→ `["192.168.1.1"]`). Three resolvers in order `system, cloudflare, google`, each with `server`/`rcode`/`nodata`/`answers`. `_system_nameservers` → `[]` means `system` is omitted (2 entries). `HAVE_DNSPYTHON False` → `{"dnspython": False, "resolvers": []}`.
  - `authoritative`: patch `dp.dns.resolver.zone_for_name` → `dns.name.from_text("hynote.ai.")`; `_dns_query` side-effect keyed on `(name, rdtype)`: NS → two names, each NS's A → an IP, target A at each NS IP → NOERROR/nodata/aa. Asserts `zone == "hynote.ai"` and two nameserver entries with `aa True`. Only the first 2 NS are queried (give 4, assert 2). `zone_for_name` raises → `zone None`, `nameservers []`.
  - `record_sweep`: `_dns_query` called once per type in `("A","AAAA","CNAME","MX","TXT","SOA","NS")` against the first system nameserver, or `1.1.1.1` if there is none. `records` has all 7 keys. `rcode` comes from the A query.
  - Command-content style check: `resolve_direct` queries `"A"` and passes `server` values `"1.1.1.1"` and `"8.8.8.8"`.

- [ ] **Step 2: Run them and confirm they fail.** `python -m pytest tests/test_diagnose_probes.py -q --no-cov -k "Resolve or Authoritative or Sweep"` → FAIL (KeyError on `PROBES[...]`).

- [ ] **Step 3: Implement the four probe functions** (`_p_resolve_cached`, `_p_resolve_direct`, `_p_authoritative`, `_p_record_sweep`) and register them at module level. `_p_authoritative` strips the trailing dot from the zone name, and resolves NS → IP through `_dns_query(system_or_1.1.1.1, ns, "A")`.

- [ ] **Step 4: Run them and confirm they pass.** Same command → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(diagnose): wave-one DNS resolution probes"`

---

### Task 4: Local configuration probes (hosts, DNS client, proxy)

**Files:**
- Modify: `diagnose_probes.py`
- Test: `tests/test_diagnose_probes.py`

**Interfaces:**
- Produces:
  - `_reg_values(hive: int, path: str) -> dict[str, object]`: all values of one key, `{}` if the key is missing.
  - `_reg_subkeys(hive: int, path: str) -> list[str]`
  - `_parse_winhttp_blob(blob: bytes) -> dict` → `{direct: bool, proxy_server: str, bypass: str}` or `{parse_error: str}`
  - `HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")`
  - Probes: `dns.hosts_file` (needs target_host, label "Check the hosts file"), `dns.client_config` (needs none, redact `("username","mac")`, label "This PC's DNS settings"), `net.proxy_config` (needs none, label "Proxy settings")

- [ ] **Step 1: Write the failing tests.**
  - hosts: use a `tmp_path` hosts file via `mocker.patch.object(dp, "HOSTS_PATH", ...)`.
    - Comment lines and blank lines are ignored.
    - `0.0.0.0 hynote.ai www.hynote.ai  # block` matches with `line_no` 1-based and `names` lowercased.
    - The match is case-insensitive.
    - `myhynote.ai` does **not** match `hynote.ai` (exact name equality only).
    - Missing file → `readable False, matches []`.
    - A non-UTF-8 byte does not raise (`errors="replace"`).
  - client_config: patch `_reg_subkeys` → `["{G1}", "{G2}"]`. Patch `_reg_values` per path:
    - `{G1}` has `NameServer "1.1.1.1,8.8.8.8"`. `{G2}` has `DhcpNameServer "192.168.1.1 192.168.1.2"`. A `{G3}` with neither is omitted.
    - `Tcpip\Parameters` has `SearchList "corp.local,example.com"`. `Dnscache\Parameters` has `EnableAutoDoh 2`.
    - Assert both separators are split, and assert `enable_auto_doh == 2`.
    - Missing keys → empty lists and `None`.
  - proxy: `_reg_values` for HKCU `Software\Microsoft\Windows\CurrentVersion\Internet Settings` (ProxyEnable/ProxyServer/ProxyOverride/AutoConfigURL/AutoDetect) and HKLM `...\Internet Settings\Connections` (`WinHttpSettings` bytes).
    - `_parse_winhttp_blob`: a hand-built blob of 4-byte LE fields `[0x28, 0, flags, len(proxy)] + proxy + [len(bypass)] + bypass`. flags `1` → `direct True`; flags `3` with `"proxy:8080"` → `proxy_server == "proxy:8080"`. A truncated blob → `parse_error`.
    - env: `HTTP_PROXY` via `mocker.patch.dict(os.environ, ...)`.

- [ ] **Step 2: Run them and confirm they fail.** `-k "Hosts or ClientConfig or Proxy"` → FAIL.

- [ ] **Step 3: Implement.** Registry paths:
  - `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<guid>`
  - `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
  - `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
  - the two Internet Settings keys above

  `_reg_values` uses `winreg.OpenKey` + `EnumValue` until `OSError`. It catches `OSError` → `{}`.

- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): hosts-file, DNS-client and proxy configuration probes"`

---

### Task 5: Connectivity probes (control domain, gateway, TCP, TLS, traceroute)

**Files:**
- Modify: `diagnose_probes.py`
- Test: `tests/test_diagnose_probes.py`

**Interfaces:**
- Produces: `CONTROL_DOMAIN = "www.microsoft.com"`.
- Probes:
  - `net.control_domain` (needs none, wave 1)
  - `net.gateway` (needs none, redact `("mac",)`, wave 1)
  - `net.tcp_connect` (needs target_host)
  - `net.tls_handshake` (needs target_host)
  - `net.traceroute` (needs target_host, `timeout_s=50`)

- [ ] **Step 1: Write the failing tests** (CLAUDE.md's subprocess table applies to `net.gateway` and `net.traceroute`).
  - control_domain: patch `dp.socket.getaddrinfo` and `dp.socket.create_connection`. Resolved + connected → `connected True, connect_ms` is a float. Resolve fails → `connected False` and `create_connection` not called. Connect raises `TimeoutError` → `connected False, error` set.
  - gateway: `_reg_subkeys`/`_reg_values` give `DefaultGateway ["192.168.1.1"]` on one interface and `DhcpDefaultGateway ["192.168.1.1"]` on another → deduped to `gateways == ["192.168.1.1"]`. Patch `dp.subprocess.run`:
    - happy: stdout contains `TTL=64`, returncode 0 → `reachable True` and `rtt_ms` parsed from `time=3ms` / `time<1ms` (→ `0.5`)
    - returncode 1 → `reachable False`
    - `TimeoutExpired` → `reachable False`
    - no gateway → `reachable None` and `run` not called
    - **command content**: `run.call_args.args[0] == ["ping", "-n", "1", "-w", "1000", "192.168.1.1"]` and `shell` not passed
    - **sanitisation**: a registry value `"192.168.1.1 & calc"` is dropped (not a valid `ipaddress`) and never reaches `run`
  - tcp_connect: ports `[443, 80]` attempted with `timeout=3`; per-port results.
  - tls_handshake: patch `dp.ssl.create_default_context` → a fake whose `wrap_socket` returns an object with `version()` → `"TLSv1.3"` and `getpeercert()` → `{"subject": ((("commonName","hynote.ai"),),), "notAfter": "Jan  1 00:00:00 2027 GMT"}`. Happy → `handshake True, cert_cn "hynote.ai"`. `ssl.SSLCertVerificationError` → `handshake False`, error contains the reason.
  - traceroute: stdout fixture of three hop lines (`  1    <1 ms    <1 ms    <1 ms  192.168.1.1`, `  2     *        *        *     Request timed out.`, `  3    12 ms ... 104.16.0.1`) plus `Trace complete.` → three hops, hop 2 `timeout True ip None`, `reached True`.
    - **command content**: args `["tracert", "-d", "-h", "15", "-w", "500", "hynote.ai"]`.
    - `TimeoutExpired` → `{hops: [], reached: False}` plus an `error` key.
    - Empty stdout → `hops []`.
    - **sanitisation**: `slots={"target_host": "x;calc"}` → the probe returns `{"error": "invalid target"}` without calling `run` (re-validate with `normalize_host` inside the probe; this is defence in depth, not trust in the caller).

- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.** Use `subprocess.run(args, capture_output=True, text=True, timeout=...)`: ping timeout 5, tracert timeout 45. Add `creationflags=subprocess.CREATE_NO_WINDOW` only if the codebase already uses it elsewhere (grep first; match the convention).
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): connectivity probes (control domain, gateway, tcp, tls, traceroute)"`

---

### Task 6: DNS escalation probes (delegation trace, DNSSEC)

**Files:**
- Modify: `diagnose_probes.py`
- Test: `tests/test_diagnose_probes.py`

**Interfaces:**
- Produces: `dns.trace_delegation` (label "Follow the delegation chain from the TLD"), `dns.dnssec_check` (label "Check DNSSEC validation"). Both need target_host.

- [ ] **Step 1: Write the failing tests.**
  - trace: for `www.hynote.ai`, the zones queried for NS via `1.1.1.1` are `["ai.", "hynote.ai.", "www.hynote.ai."]` in that order (assert the `_dns_query` call list). The chain carries each rcode/ns. It stops after the first NXDOMAIN (assert no further calls).
  - dnssec: two `_dns_query` calls with `want_dnssec=True`, the second with `cd=True`. A validating `SERVFAIL` plus a cd `NOERROR` → `validation_failure True`. Both `NOERROR` with `ad True` → `validation_failure False`.
- [ ] **Step 2: Fail → Step 3: Implement → Step 4: Pass** (same `-k` pattern).
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): delegation-trace and DNSSEC escalation probes"`

---

### Task 7: Symptom classes, classifier, registry invariants

**Files:**
- Create: `diagnose.py` (module docstring, imports, `SYMPTOM_CLASSES`, `classify`)
- Create: `tests/test_diagnose.py`
- Test: `tests/test_diagnose_probes.py` (invariants)

**Interfaces:**
- Consumes: `diagnose_probes.PROBES`, `normalize_host`.
- Produces:

```python
SYMPTOM_CLASSES = {
    "network_dns": {
        "label": "Website or network unreachable",
        "slots": ("target_host",),
        "wave1": ("dns.resolve_cached", "dns.resolve_direct", "dns.authoritative", "dns.record_sweep",
                  "dns.hosts_file", "dns.client_config", "net.control_domain", "net.gateway", "net.proxy_config"),
        "escalate": ("dns.trace_delegation", "dns.dnssec_check", "net.tcp_connect", "net.tls_handshake", "net.traceroute"),
    },
}
```

  - `classify(symptom: str) -> dict` → `{"symptom_class": str|None, "slots": {"target_host": str} | {}, "candidates": [str], "missing": [str]}`

- [ ] **Step 1: Write the failing tests.**
  - Registry invariants (`tests/test_diagnose_probes.py::TestRegistryInvariants`, importing `diagnose` to get the classes):
    - every key in every `wave1`/`escalate` exists in `PROBES`
    - `{p.fn for p in PROBES.values()}.isdisjoint(set(remediation._REMEDIATION_DISPATCH.values()))`
    - `{p.fn.__name__ ...}` is disjoint from the dispatch function names
    - every `needs` entry of every probe a class references is one of that class's `slots`
    - every `category` is in `{"network","crash","storage","perf"}`
    - no probe source contains `subprocess.run(` except the two allow-listed functions: `inspect.getsource` scan, allow-list `{"_p_gateway", "_p_traceroute"}`
  - Classifier (`TestClassify`):
    - The standard Chrome text below → `network_dns`, `slots == {"target_host": "hynote.ai"}`, `missing == []`. (The user no longer has the original paste, so Chrome's standard wording for this error is the S1 input.) The text: `"This site can’t be reached\nhynote.ai’s server IP address could not be found.\nTry:\nChecking the connection\nChecking the proxy, firewall, and DNS configuration\nRunning Windows Network Diagnostics\nERR_NAME_NOT_RESOLVED"`
    - `"DNS_PROBE_FINISHED_NXDOMAIN https://foo.example.com/x"` → `foo.example.com`.
    - `"the internet is broken"` → `network_dns`, `missing == ["target_host"]`, no slots.
    - `"google.com works but hynote.ai doesn't load"` → `candidates == ["google.com", "hynote.ai"]`, `missing == ["target_host"]` (Review Focus 2).
    - `"my printer jams"` → `symptom_class None`.
    - File-like tokens are not hosts: `"error in app.js and config.json"` → `candidates == []`. Use a denylist of TLD-looking file extensions: `js, json, py, exe, dll, txt, log, html, css, png, jpg, md, ps1, bat, cfg, ini, xml`.
    - `"Windows Network Diagnostics."` produces no candidate.

- [ ] **Step 2: Run them and confirm they fail.** `python -m pytest tests/test_diagnose.py tests/test_diagnose_probes.py -q --no-cov -k "Classify or Invariants"` → FAIL.
- [ ] **Step 3: Implement `classify`.** Network keywords (case-insensitive): `ERR_NAME_NOT_RESOLVED, DNS_PROBE_FINISHED_, ERR_CONNECTION_, ERR_TIMED_OUT, ERR_ADDRESS_UNREACHABLE, ERR_INTERNET_DISCONNECTED, can't be reached, can’t be reached, won't load, not loading, dns, website, site, internet, network, unreachable`. Candidates are URLs first, then bare tokens matching `[\w.-]+\.[a-z]{2,63}` plus an optional possessive. Each runs through `normalize_host`, is deduped, keeps first-seen order, and has the denylist removed. Class = `network_dns` if any keyword **or** any candidate. Exactly one candidate fills the slot.
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit**: `git add diagnose.py tests/ && git commit -m "feat(diagnose): symptom classes, deterministic classifier, registry invariants"`

---

### Task 8: Deterministic rules and the fixture directory (S1)

**Files:**
- Modify: `diagnose.py`
- Create: `tests/fixtures/diagnose/{hynote_zone_missing_a,nxdomain_nonexistent_domain,stale_cache_direct_resolves,hosts_file_override,dead_gateway,healthy_name_resolves}.json`
- Test: `tests/test_diagnose.py::TestRuleFixtures` (the single parametrized test)

**Interfaces:**
- Consumes: the evidence shapes table.
- Produces:
  - `cache_agrees(evidence: dict[str, dict]) -> bool | None`: `None` if either `dns.resolve_cached` or `dns.resolve_direct` is missing or `ok False`. Otherwise `True` iff both sides agree on resolved-ness, and (when both resolved) their address sets intersect. "Direct resolved" = any resolver with non-empty `answers`.
  - `evaluate_rules(evidence: dict[str, dict], target_host: str) -> dict`: always a full verdict with `source: "rules"` and `rule_hits: [str]`.

Rules, first match wins:

| # | Rule | Condition | Verdict |
|---|---|---|---|
| 1 | `hosts_override` | `dns.hosts_file.matches` non-empty | `confident`, `local`, `[]`. Headline names the line number and IP. `no_local_fix_reason` = "" |
| 2 | `external_no_address` | cached `resolved False`; ≥2 direct resolvers, all `NXDOMAIN` or `nodata`; ≥1 authoritative NS with `aa True` and (`NXDOMAIN` or `nodata`) | `confident`, `external_cause`, `[]`. If NODATA and the sweep has any of MX/TXT/SOA/NS: headline "`{host}` exists but publishes no web address", reason "The domain's own nameservers answer for it but have no A/AAAA/CNAME record. Only whoever manages the domain's DNS can fix that; nothing on this PC can." If NXDOMAIN: headline "`{host}` does not exist", reason "The domain's own nameservers say this name does not exist." |
| 3 | `stale_cache` | `cache_agrees(...) is False` | `confident`, `local`, `["flush_dns"]` |
| 4 | `dead_gateway` | `net.gateway.reachable is False` and `net.control_domain.connected is False` | `likely`, `local`, `["reset_network_adapter"]` |
| — | (none) | otherwise | `inconclusive`, `unknown`, `[]`, headline "No rule matched this evidence" |

`evidence_refs` lists the probe keys each rule read. `cache_agrees is True` is added to `rule_hits` as `"cache_agrees"` whenever it holds, whatever rule fires.

- [ ] **Step 1: Write the fixtures.** The golden one in full. NODATA, not NXDOMAIN, because the apex has MX, so resolvers answer NOERROR with no A record:

```json
{
  "symptom": "This site can’t be reached\nhynote.ai’s server IP address could not be found.\nTry:\nChecking the connection\nChecking the proxy, firewall, and DNS configuration\nRunning Windows Network Diagnostics\nERR_NAME_NOT_RESOLVED",
  "evidence": {
    "dns.resolve_cached": {"ok": true, "data": {"resolved": false, "addresses": [], "error": "[Errno 11001] getaddrinfo failed"}},
    "dns.resolve_direct": {"ok": true, "data": {"dnspython": true, "resolvers": [
      {"name": "system", "server": "192.168.1.1", "rcode": "NOERROR", "nodata": true, "answers": []},
      {"name": "cloudflare", "server": "1.1.1.1", "rcode": "NOERROR", "nodata": true, "answers": []},
      {"name": "google", "server": "8.8.8.8", "rcode": "NOERROR", "nodata": true, "answers": []}]}},
    "dns.authoritative": {"ok": true, "data": {"zone": "hynote.ai", "nameservers": [
      {"name": "ns1.example-dns.net", "ip": "198.51.100.53", "rcode": "NOERROR", "nodata": true, "aa": true, "answers": []}]}},
    "dns.record_sweep": {"ok": true, "data": {"rcode": "NOERROR", "records": {
      "A": [], "AAAA": [], "CNAME": [], "MX": ["1 smtp.google.com."],
      "TXT": ["\"v=spf1 include:_spf.google.com include:sendgrid.net ~all\"", "\"google-site-verification=aaa\"", "\"google-site-verification=bbb\""],
      "SOA": ["ns1.example-dns.net. hostmaster.hynote.ai. 2026100101 7200 3600 1209600 3600"], "NS": ["ns1.example-dns.net."]}}},
    "dns.hosts_file": {"ok": true, "data": {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "readable": true, "matches": []}},
    "net.control_domain": {"ok": true, "data": {"host": "www.microsoft.com", "resolved": true, "connected": true, "connect_ms": 18.2, "error": null}},
    "net.gateway": {"ok": true, "data": {"gateways": ["192.168.1.1"], "reachable": true, "rtt_ms": 0.5}}
  },
  "expect": {"target_host": "hynote.ai", "locus": "external_cause", "must_include": [], "must_exclude": ["flush_dns"]}
}
```

The other five fixtures differ from that template as follows:
- `nxdomain_nonexistent_domain`: host `no-such-name-zq7.ai`; all `rcode NXDOMAIN`; sweep all empty with rcode NXDOMAIN; zone `ai`; locus `external_cause`; exclude `flush_dns`.
- `stale_cache_direct_resolves`: cached `resolved false`; direct resolvers return `["104.21.0.1"]`; locus `local`; include `flush_dns`.
- `hosts_file_override`: hosts match `{"line_no": 22, "ip": "0.0.0.0", "names": ["hynote.ai"]}`; cached resolves to `0.0.0.0`; direct resolves to `104.21.0.1`; locus `local`; include `[]`; exclude `flush_dns`.
- `dead_gateway`: symptom `"no website will load, ERR_INTERNET_DISCONNECTED on example.com"`; gateway `reachable false`; control `connected false, resolved false`; all resolvers `TIMEOUT`; locus `local`; include `reset_network_adapter`; exclude `flush_dns`.
- `healthy_name_resolves`: everything resolves to the same address; locus `unknown`; exclude `flush_dns`.

- [ ] **Step 2: Write the single parametrized test**

```python
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "diagnose"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))

def test_fixture_dir_is_populated():
    assert len(FIXTURES) >= 6

@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_rule_fixture(path):
    fx = json.loads(path.read_text(encoding="utf-8"))
    cls = dx.classify(fx["symptom"])
    host = fx["expect"].get("target_host") or cls["slots"].get("target_host")
    if "target_host" in fx["expect"]:
        assert cls["slots"].get("target_host") == fx["expect"]["target_host"]
    verdict = dx.evaluate_rules(fx["evidence"], host)
    assert verdict["locus"] == fx["expect"]["locus"]
    for key in fx["expect"]["must_include"]:
        assert key in verdict["suggested_actions"]
    for key in fx["expect"]["must_exclude"]:
        assert key not in verdict["suggested_actions"]
    if verdict["locus"] == "external_cause":
        assert verdict["suggested_actions"] == []
```

Plus a few `cache_agrees` unit tests: `None` on a failed probe; `False` on disjoint addresses; `True` when both fail.

- [ ] **Step 3: Run them and confirm they fail.** `python -m pytest tests/test_diagnose.py -q --no-cov -k "fixture or cache_agrees"` → FAIL.
- [ ] **Step 4: Implement `cache_agrees`, `evaluate_rules`** (one small private function per rule, called in order).
- [ ] **Step 5: Run them and confirm they pass.**
- [ ] **Step 6: Commit**: `git add tests/fixtures/diagnose diagnose.py tests/test_diagnose.py && git commit -m "feat(diagnose): deterministic rules + fixture-per-scenario test directory (S1 golden case)"`

---

### Task 9: Redaction and the egress payload

**Files:**
- Modify: `diagnose.py`
- Test: `tests/test_diagnose.py`

**Interfaces:**
- Produces:
  - `redact(obj: Any, classes: Iterable[str]) -> Any`: a deep copy; strings rewritten; for `serial`, any dict key matching `/serial/i` has its value replaced.
  - `build_payload(session: dict) -> str`: `json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)`. This exact string is both the preview and the user message.
- The payload object: `{schema_version: 1, symptom, symptom_class, slots, round, rounds_remaining, capabilities: {dnspython}, evidence: [probe results, each redacted by its probe's redact classes], rule_finding: {status, locus, headline, rule_hits}, available_probes: [{key, label}] (escalation keys not yet run), available_actions: [{key, label, description}] (whole registry)}`. Afterwards, `username` redaction is applied to the entire object, symptom included.

- [ ] **Step 1: Write the failing tests** (`TestRedact`, `TestBuildPayload`).
  - username: `USERNAME=Al` (patch env) — `r"C:\Users\Al\x"` → `r"C:\Users\<user>\x"`; `r"C:\USERS\al\x"` is caught; `"local alpha"` is unchanged (Review Focus 3); a plain-word `"Al reported"` → `"<user> reported"`. With `USERNAME` unset or empty, the input is unchanged.
  - mac: `"aa:bb:cc:dd:ee:ff"` and `"AA-BB-CC-DD-EE-FF"` → `<mac>`.
  - serial: `{"SerialNumber": "S3Z9NX0K"}` → `"<serial>"`.
  - local_ip: `"192.168.1.1 and 8.8.8.8"` → `"<private-ip> and 8.8.8.8"` when the class is on. A network-class payload keeps `192.168.1.1` (off by default, §7).
  - Planted-secrets payload test: a session whose evidence and symptom contain the username, a MAC in `dns.client_config`, and a serial key → none of the three appear in `build_payload(...)`; `hynote.ai` and `198.51.100.53` **do** appear.
  - `available_probes` excludes escalation keys already present in the evidence.
  - Deterministic: two calls on the same session return identical strings.

- [ ] **Step 2: Fail → Step 3: Implement** (username via `re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.I)`) **→ Step 4: Pass.**
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): redaction classes and deterministic egress payload"`

---

### Task 10: Model call, reply validation, guards

**Files:**
- Modify: `diagnose.py`
- Test: `tests/test_diagnose.py`

**Interfaces:**
- Produces:
  - `DIAGNOSE_MODEL`, `DIAGNOSE_TIMEOUT_S = 90.0`, `MAX_DIAGNOSE_CALLS = 60`, `_model_calls: int`, `_client` / `_get_client(api_key)` (the same lazy, locked pattern as `ai_identify._get_client`).
  - `model_unavailable_reason() -> str | None` → `"sdk_missing" | "no_api_key" | "call_cap" | None`
  - `reply_schema(class_key: str) -> dict`: one flat object; `additionalProperties: false`; all of these fields required: `kind` enum `["verdict","need_probes"]`; `need_probes` array of enum(class `escalate`); `status` enum `["confident","likely","inconclusive"]`; `locus` enum `["local","external_cause","unknown"]`; `headline`, `reasoning`, `no_local_fix_reason` strings; `evidence_refs` array of string; `suggested_actions` array of enum(`REMEDIATION_REGISTRY` keys).
  - `_call_model(payload_text: str, class_key: str) -> dict | None`: `client.beta.messages.create(model=DIAGNOSE_MODEL, max_tokens=16000, system=_SYSTEM_PROMPT, messages=[{"role": "user", "content": payload_text}], output_config={"format": {"type": "json_schema", "schema": reply_schema(class_key)}}, betas=["server-side-fallback-2026-07-01"], extra_body={"fallbacks": "default"})`. Read the text from the first `block.type == "text"` block, skipping thinking/fallback blocks. Returns the parsed dict, or `None` when `stop_reason in ("refusal", "max_tokens")`, on JSON error, or on any `anthropic` exception. Like `ai_identify`, a failed call refunds its cap slot.
  - `parse_reply(obj: dict, class_key: str) -> tuple[str, Any] | None` → `("need_probes", [keys])` or `("verdict", verdict_dict)`, or `None` if types are wrong. Unknown action/probe keys are dropped and logged with `print("[Diagnose] ...")` (the module's logging style).
  - `apply_guards(verdict: dict, evidence: dict, rule_verdict: dict) -> dict`, applied in this order:
    1. drop unknown action keys
    2. drop `flush_dns` when `cache_agrees(evidence) is True`
    3. if `rule_verdict` is `confident` + `external_cause`, force `locus = "external_cause"` and copy `no_local_fix_reason` if the model's is empty
    4. `external_cause` or `inconclusive` → `suggested_actions = []`
    5. set `source = "model"` and `rule_hits = rule_verdict["rule_hits"]`
- `_SYSTEM_PROMPT` (exact intent; wording may be tightened):
  - You are diagnosing a problem on the user's Windows PC from probe evidence in the user message.
  - Cite probe keys in `evidence_refs` and in your reasoning.
  - Use `locus "external_cause"` when the evidence shows the fault is outside this PC; then suggest no actions and explain in `no_local_fix_reason`.
  - Suggest actions only from `available_actions`, only when the evidence shows they would help. A DNS cache flush cannot help when `dns.resolve_cached` and `dns.resolve_direct` agree.
  - Use `kind "need_probes"` to request up to 4 keys from `available_probes` when the evidence cannot yet distinguish the causes. When `rounds_remaining` is 0 you must return a verdict.
  - Say `inconclusive` rather than guess.

- [ ] **Step 1: Write the failing tests.**
  - `model_unavailable_reason`: `diagnose.anthropic` patched `None` → `"sdk_missing"`; no `ANTHROPIC_API_KEY` → `"no_api_key"`; `_model_calls = MAX_DIAGNOSE_CALLS` → `"call_cap"`.
  - `_call_model` with a fake client (`mocker.patch.object(dx, "_get_client", return_value=fake)`):
    - The happy path returns the dict.
    - `beta.messages.create` kwargs: `model == dx.DIAGNOSE_MODEL == "claude-sonnet-5-5"` (with the env var unset), `messages[0]["content"] == payload_text`, `output_config["format"]["type"] == "json_schema"`, `"server-side-fallback-2026-07-01" in betas`, `extra_body == {"fallbacks": "default"}`, and no `thinking` kwarg.
    - A response whose content is `[thinking block, fallback block, text block]` → parsed from the text block.
    - `stop_reason "refusal"` → `None` and the counter is refunded.
    - `anthropic.APIConnectionError` → `None`.
    - Invalid JSON text → `None`.
  - `reply_schema("network_dns")`: the action enum equals `sorted(REMEDIATION_REGISTRY)`; every object has `additionalProperties: False`.
  - `parse_reply`: unknown action dropped; unknown probe dropped; `status "certain"` → `None`.
  - `apply_guards`:
    - **S1 guard**: the hynote fixture's evidence + its rule verdict, and a model verdict `{locus: "local", suggested_actions: ["flush_dns"], status: "likely", ...}` → result `locus "external_cause"`, `suggested_actions == []`.
    - `cache_agrees True` drops `flush_dns` while keeping `reset_winsock`.
    - inconclusive → no actions.
    - a rule verdict that is not confident leaves the model's locus alone.

- [ ] **Step 2: Fail → Step 3: Implement → Step 4: Pass.**
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): schema-constrained model call, reply validation, server-side guards"`

---

### Task 11: Session engine, egress gate, history

**Files:**
- Modify: `diagnose.py`
- Modify: `tests/conftest.py` (`reset_globals`: `diagnose._sessions.clear()`, `diagnose._model_calls = 0`)
- Test: `tests/test_diagnose.py`

**Interfaces:**
- Produces:
  - Constants: `MAX_ROUNDS = 2`, `MAX_PROBES_PER_ROUND = 4`, `_SESSIONS_MAX = 20`, `_SESSION_TTL_S = 1800`, `_MAX_ACTIVE = 2`, `_CONSENT_TIMEOUT_S = 600`, `MAX_SYMPTOM_CHARS = 4000`, `DIAGNOSE_HISTORY_FILE = os.path.join(APP_DIR, "diagnose_history.json")`, `_HISTORY_MAX = 100`.
  - `_sessions: dict[str, dict]`, `_sessions_lock`.
  - `start_diagnosis(symptom: str, slots: dict | None = None, symptom_class: str | None = None) -> dict` returns one of:
    - `{"ok": True, "state": "awaiting_slots", "symptom_class", "need": [...], "candidates": [...]}` (no session created)
    - `{"ok": True, "session_id", "state": "probing_wave1"}`
    - `{"ok": False, "error": "busy"}` when `_MAX_ACTIVE` sessions are non-terminal
  - `get_status(session_id: str) -> dict | None` → `{ok, session_id, state, symptom_class, slots, round, evidence, rule_verdict, preview (only in awaiting_consent), verdict, actions: [registry entries for the final verdict's keys], reason, error}`
  - `submit_consent(session_id: str, approved: bool, auto_followups: bool = False) -> dict | None`: `None` for an unknown id; `{"ok": False, "error": "not awaiting consent"}` in a wrong state; otherwise `{"ok": True}` and the session's consent event is set.
  - `load_history() -> list[dict]`: newest first.
  - Internal seams, patchable in tests: `_spawn_worker(sid)` (starts the thread), `_run_session(sid)` (the state machine body), `_wait_for_consent(session) -> bool | None` (blocks on the event with `_CONSENT_TIMEOUT_S`; `None` = timeout).
- States (§6): `probing_wave1 → awaiting_consent → interpreting → (probing_waveN → awaiting_consent* → interpreting)* → done | evidence_only | error`. `*` = skipped when `auto_followups`. Each terminal state appends one history entry `{ts, session_id, symptom (username-redacted), symptom_class, target_host, state, reason, verdict, sent: [payload strings], model}`, written atomically (tmp + `os.replace`, same as `ai_identify._save_cache`) and capped at `_HISTORY_MAX`.
- The `_run_session` algorithm (the order is the contract):
  1. Run wave 1. Keep the list for the payload and index it as `evidence = {r["key"]: r for r in results}` for `evaluate_rules(evidence, target_host)` / `apply_guards`.
  2. If `model_unavailable_reason()` is set → `evidence_only` with that reason. Nothing is sent.
  3. Loop: `preview = build_payload(...)`. Unless this round is pre-approved, enter `awaiting_consent` and call `_wait_for_consent`. `False` → `evidence_only` (`reason: "declined"`); `None` → `evidence_only` (`reason: "consent_timeout"`).
  4. Enter `interpreting`, append the preview to `sent`, call `_call_model`. If parsing fails, call once more. Still nothing → `evidence_only` (`reason: "model_error"`).
  5. `need_probes` with `round < MAX_ROUNDS`: keep only the class's escalate keys not yet run, at most 4. `round += 1` (the round counts even if the list is empty). Enter `probing_waveN`, run the probes, re-evaluate rules, continue.
  6. `need_probes` at `round == MAX_ROUNDS` → verdict `inconclusive` / `unknown` with headline "Ran out of probe rounds before reaching a conclusion".
  7. A verdict → `apply_guards` → `done`.
  8. Any exception → `error` with `error` = `str(e)`. The worker never raises.

- [ ] **Step 1: Write the failing tests** (autouse fixture patches `DIAGNOSE_HISTORY_FILE` to `tmp_path`, patches `_spawn_worker` to a no-op, and patches `dp.run_probes` to return the hynote fixture evidence as a list). The tests call `_run_session(sid)` synchronously.
  - `start_diagnosis("the internet is broken")` → `awaiting_slots`, `need == ["target_host"]`, `_sessions` empty.
  - Two candidates → `awaiting_slots` with `candidates`.
  - The `slots` argument overrides the classifier, and an invalid host there → `ValueError("invalid host")`.
  - `symptom_class="network_dns"` with `slots` works on a symptom with no keywords.
  - `_MAX_ACTIVE` non-terminal sessions → `{"ok": False, "error": "busy"}`.
  - **Egress gate**: `_wait_for_consent` → `False` ⇒ `_call_model` mock `.assert_not_called()`, state `evidence_only`, reason `declined`, and the history entry has `sent == []`.
  - `_wait_for_consent` → `None` ⇒ `consent_timeout` (Review Focus 5).
  - Consent `True` ⇒ `_call_model` called once with `payload_text == ` the preview that was visible in `get_status` while `awaiting_consent`. To capture it, have the `_wait_for_consent` patch read `get_status(sid)["preview"]` before returning `True`.
  - No API key ⇒ `evidence_only` (`reason "no_api_key"`), `_wait_for_consent` never called, `rule_verdict.locus == "external_cause"` (S3).
  - Escalation capped: the model always returns `need_probes ["dns.trace_delegation"]` → exactly 3 `_call_model` calls, final `status "inconclusive"`, `round == 2`.
  - An unknown escalation key (bypassing the schema via a mock) → dropped, the round still counted, and `run_probes` not called with the unknown key.
  - At most 4 keys per round: the model asks for 5 → `run_probes` receives 4.
  - Parse failure, then success → 2 calls → `done`. Two failures → `evidence_only` `model_error`.
  - **S1 end-to-end**: a model verdict of `local` + `flush_dns` → final `locus "external_cause"`, `actions == []`.
  - A `run_probes` exception → state `error`, with the message.
  - `auto_followups=True` on the first consent → round 2 does not wait (`_wait_for_consent` called once).
  - `submit_consent` on an unknown id → `None`. A second `submit_consent` after the first moved the session on → `{"ok": False, ...}` (Review Focus 5).
  - TTL eviction: a terminal session older than `_SESSION_TTL_S` is removed on the next `start_diagnosis`. A non-terminal one is not.
  - History: the cap is enforced; `load_history()` is newest first; a corrupt file → `[]`.

- [ ] **Step 2: Fail → Step 3: Implement → Step 4: Pass.**
- [ ] **Step 5: Commit**: `git commit -am "feat(diagnose): session engine with egress consent gate, bounded escalation, history"`

---

### Task 12: Routes and blueprint registration

**Files:**
- Modify: `diagnose.py` (`diagnose_bp = Blueprint("diagnose", __name__)` + routes), `windesktopmgr.py` (import next to `from maintenance import maintenance_bp`; register after `app.register_blueprint(maintenance_bp)`)
- Test: `tests/test_diagnose.py::TestRoutes` (uses the `client` fixture)

**Interfaces:**

| Route | Success | Errors |
|---|---|---|
| `GET /api/diagnose/classes` | 200 `[{key, label, slots}]` | — |
| `POST /api/diagnose/start` `{symptom, slots?, symptom_class?}` | 200 `start_diagnosis(...)` result | 400 missing/empty/non-string symptom, symptom > 4000 chars, `slots` not a dict, invalid host, unknown `symptom_class`; 415 non-JSON body; 429 `busy` |
| `GET /api/diagnose/status/<session_id>` | 200 `get_status` | 400 bad id format; 404 unknown |
| `POST /api/diagnose/consent` `{session_id, approved, auto_followups?}` | 200 `{ok: True}` | 400 missing id / `approved` not a bool / bad id format; 404 unknown; 409 wrong state |
| `GET /api/diagnose/history` | 200 list, newest first | — |

- [ ] **Step 1: Write the failing tests.** For each row: 200 plus JSON keys, and every listed error code. `start` posted as `data="symptom=x"` with a form content-type → 415 (proves non-silent `get_json`). The engine is patched so `_spawn_worker` is a no-op.
- [ ] **Step 2: Fail → Step 3: Implement** (the `POST Route Validation Pattern` from CLAUDE.md) **→ Step 4: Pass.**
- [ ] **Step 5: Run the full suite** — `python -m pytest tests/ -n auto` → all pass, coverage ≥ 80%.
- [ ] **Step 6: Commit**: `git commit -am "feat(diagnose): /api/diagnose/* routes and blueprint registration"`

---

### Task 13: The 🔍 Diagnose tab

**Files:**
- Modify: `templates/index.html` (tab button `<button class="page-tab" data-page="diagnose">🔍 Diagnose</button>` next to the Docs button; `<div id="page-diagnose" style="display:none">` section modelled on `#page-docs`)
- Modify: `static/js/app.js` (tab-switch branch `else if (page === "diagnose") { dx_load(); }`, which reloads history on every visit; the `dx_*` block placed after the docs block)
- Modify: `static/css/app.css` (`.dx-*` rules; reuse the existing CSS variables)
- Test: `tests/test_playwright_smoke.py` (`"diagnose"` in `TAB_IDS`; class `TestDiagnoseTab`)

**Interfaces:**
- DOM ids: `dx-symptom` (textarea), `dx-class` (select, hidden until needed), `dx-host-row` / `dx-host` / `dx-candidates`, `dx-run`, `dx-progress`, `dx-preview` / `dx-preview-text` (`<pre>`) / `dx-send` / `dx-nosend` / `dx-noask` (checkbox), `dx-result`, `dx-evidence` (collapsible `<details>`), `dx-history`.
- `#dx-result` carries `data-state`, `data-status`, `data-locus`.
- `.dx-verdict` is rendered **only** for status `confident`/`likely`.
- `.dx-inconclusive` has the heading "Couldn't determine this", with the evidence shown.
- `.dx-evidence-only` banner text by `reason`:
  - `no_api_key`: "No ANTHROPIC_API_KEY is set, so there's no AI verdict. The probe results below are still complete."
  - `sdk_missing`: "The anthropic package isn't installed…"
  - `declined`: "You chose not to send the evidence."
  - `consent_timeout`: "No answer to the send prompt, so nothing was sent."
  - `model_error`: "The model didn't return a usable answer."
  - `call_cap`: "AI call limit reached until the app restarts."
- The rule verdict is shown as "Rule-based finding".
- Action buttons are `button[data-action="<key>"]` showing the registry `icon label` and `risk`. A click → `confirm()` → `POST /api/remediation/run`.
- `external_cause` shows `no_local_fix_reason` under "Nothing to fix on this PC" and **no** action buttons.
- JS functions:
  - `dx_load()`
  - `dx_start()`
  - `dx_poll(sid)`: one `_dxPollTimer` at 1000 ms, cleared before re-arming, stopped in terminal states
  - `dx_renderPreview(text)`
  - `dx_consent(approved)`
  - `dx_renderResult(status)`: pure render from a status object
  - `dx_runAction(key)`
  - `dx_renderHistory(list)`
- "Don't ask again" = `sessionStorage["dx_noask"] === "1"`, wrapped in try/catch. When set, the preview is shown for one poll cycle, then consent is auto-POSTed with `auto_followups: true`. All interpolation goes through `escHtml`.

- [ ] **Step 1: Write the Playwright tests.** They drive the live tray on `localhost:5000`, which serves the primary repo's `main`, so they first *run* in Task 14 Step 7 after the merge and deploy. Before that, check the tab by hand with the `/run` skill or a branch dev server. The tests still land in this commit.

```python
class TestDiagnoseTab:
    def test_tab_renders_input(self, loaded_page): ...
        # click tab; #dx-symptom and #dx-run exist and are visible
    def test_missing_host_asks_instead_of_guessing(self, loaded_page): ...
        # type "the internet is broken", click run -> #dx-host-row visible; no request to /api/diagnose/status
    def test_inconclusive_never_renders_as_verdict(self, loaded_page): ...
        # page.evaluate("dx_renderResult({state:'done', verdict:{status:'inconclusive', locus:'unknown', headline:'h', reasoning:'r', evidence_refs:[], suggested_actions:[], no_local_fix_reason:''}, evidence:[], actions:[]})")
        # assert document.querySelectorAll('#dx-result .dx-verdict').length == 0 and "Couldn't determine this" in #dx-result text
    def test_external_cause_shows_no_action_buttons(self, loaded_page): ...
        # render locus external_cause with no_local_fix_reason "zone has no A record" -> 0 button[data-action]; reason text present
    def test_submit_reaches_preview_or_evidence_only_and_sends_nothing(self, loaded_page): ...
        # symptom "ERR_NAME_NOT_RESOLVED example.com"; wait up to 60s for #dx-preview visible OR #dx-result[data-state=evidence_only]
        # if preview: assert '"target_host": "example.com"' in #dx-preview-text; click #dx-nosend; wait for data-state=evidence_only
        # (never clicks Send: the smoke test must not send data to Anthropic)
    def test_no_console_errors_on_tab(self, loaded_page): ...  # follow the file's existing console-error pattern
```

- [ ] **Step 2: Implement the HTML/JS/CSS.**
- [ ] **Step 3: Unit suite still green** — `python -m pytest tests/ -n auto` → PASS.
- [ ] **Step 4: Commit**: `git commit -am "feat(diagnose): Diagnose tab UI with payload preview, verdict and evidence views"`

---

### Task 14: Docs, quality gates, ship, verify

**Files:**
- Modify: `architecture.html`, `CLAUDE.md` (add `` `dx` = Diagnose (diagnose.py; symptom → probes → verdict).`` to the JS prefix list)
- Memory (outside the repo): `project_backlog.md` row 63 → `✅ SHIPPED <date> (PR #NN)` **for PR 1 only**; the row stays open for PRs 2–4. Also `project_diagnose_engine_2026-10-01.md`.

- [ ] **Step 1: Ruff** — `"$RUFF" check . && "$RUFF" format .` → no findings.
- [ ] **Step 2: Full suite** — `python -m pytest tests/ -n auto` → all pass, ≥ 80%. Record the new test count.
- [ ] **Step 3: `/code-review`** on the branch diff. Resolve or justify every high-priority finding in a commit body.
- [ ] **Step 4: `/code-simplifier`.** Recommended here (>200 LOC of new logic). Accept or reject per finding; document the accepted ones.
- [ ] **Step 5: `architecture.html`.** Run `/arch-update` for counts, then add by hand: `diagnose.py` + `diagnose_probes.py` chips, the 5 routes, the Diagnose tab, the two test files + fixture dir, the `dnspython` dependency, the `diagnose_history.json` data file, and the per-diagnosis worker thread (§15).
- [ ] **Step 6: Commit, push, open PR.** The PR body lists the eight "Decisions" above and the S1 evidence. Merge after review.
- [ ] **Step 7: Deploy + verify.** Pull `main` into `C:\shigsapps\windesktopmgr`, `python -m pip install -r requirements.txt` (dnspython!), then `python dev.py verify`. Then `PLAYWRIGHT_SMOKE=1 python dev.py verify`, or `pytest -m playwright --no-cov -k Diagnose`.
- [ ] **Step 8: Live S1 check** (this is also the first real proof that the `fallbacks` + `output_config` request shape is accepted by the API, so watch for a 400 and treat it as a blocker) (per `feedback_validation_before_shipped`). In the running app, paste the hynote.ai Chrome error. Confirm the rule finding reads `external_cause`, with no Flush DNS button, and, if a key is set and the user approves sending, that the model verdict agrees. Only then mark backlog row 63 PR 1 as shipped.
- [ ] **Step 9: SOP Compliance Report** (CLAUDE.md Phase 11), printed last.
