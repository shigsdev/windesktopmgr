# Diagnose Crashes & Stability Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `crashes` symptom class to Diagnose that reads this PC's crash, shutdown, boot, app-crash and hardware-change records and returns a rule-based verdict with plain-language steps.

**Architecture:** Two small engine changes in `diagnose.py`: optional slots, plus per-class rules and prompt dispatch. Two new modules hold the bundle. `diagnose_crash_probes.py` has 13 read-only probes registered into `diagnose_probes.PROBES`, plus an EventData-aware event-log reader. `diagnose_crash_rules.py` holds the classifier helpers, 7 ordered rules, context annotations and steps. The UI gains an optional app-name row.

**Tech Stack:** Python 3.14, Flask blueprint, pywin32 `win32evtlog` (EvtQuery/XPath), `winreg`, pytest + pytest-mock, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-09-diagnose-crash-bundle-design.md` (parent: `2026-10-01-diagnostic-engine-design.md`)

## Global Constraints

- Class key `crashes`, label `"Crashes, freezes & startup problems"`, `slots: ()`, `optional_slots: ("app_name",)`.
- `WINDOW_DAYS = 7`; escalation look-back 30 days.
- Caps: ≤50 timeline events, ≤10 apps, ≤30 records in `crash.app_detail`, ≤40 in `crash.event_context`.
- Every crash probe: `category="crash"`, `redact=("username", "serial", "mac", "self_host")`, `timeout_s` between 8 and 15.
- No probe returns a raw event `Message` string; only time, id, provider, level, and named EventData fields.
- All probes are read-only. Event logs go through `win32evtlog` (Python-first per CLAUDE.md), never PowerShell.
- Probe timestamps are UTC ISO strings ending in `Z`. Text shown to the user formats them in local time (`HH:MM`, plus the date when it isn't today).
- Rule order: `whea_fatal` > `bugcheck` > `hung_shutdown` > `power_button` > `power_loss_or_freeze` > `boot_failure` > `app_crash_repeat` > `nothing_found`.
- Thresholds: WHEA ≥1 fatal or ≥10 corrected on one component. App ≥3 crashes+hangs. ≥2 failed boots within 30 min. Context window 48 h before the incident. Storage errors within ±1 h. `repair_image` only when ≥3 **different** apps crash in modules under `%SystemRoot%\System32`.
- Only registry action ever suggested by this class: `repair_image`.
- JS functions use the `dx` prefix. New user-visible text is set through `textContent` / DOM nodes, never `innerHTML` with data.

## Review Focus

1. **Unreadable channel** (Startup Repair or Diagnostics-Performance needs admin, or the channel is missing). The probe still returns `ok: True` with that source listed under `"unavailable"`, and the other sources are unaffected. Pinned in Task 5.
2. **Fast Startup or a normal shutdown with no 41 after it** must never produce `hung_shutdown`: `shutdown_started_at` set, the next boot clean, so `next_boot_unexpected` is False and no rule fires. Pinned in Tasks 4 and 7.
3. **UTC vs local time.** Episodes are compared in UTC, while headlines show local `HH:MM`. A 03:37Z shutdown start shows as 23:37 for a UTC-4 user. Pinned in Task 7.
4. **App names in free text.** "My computer keeps crashing" gives no app; "Microsoft Teams keeps crashing" gives `"Microsoft Teams"`; `"Chrome" crashed!` gives `"Chrome"`. Pinned in Task 8.
5. **Huge logs.** 5,000 app-crash events still give ≤10 apps and finish within the probe timeout, because `max_events` is applied at the query. Pinned in Task 6.

---

### Task 1: Engine: optional slots

**Files:**
- Modify: `diagnose_probes.py` (`Probe`, `run_probes`)
- Modify: `diagnose.py` (`start_diagnosis`, `diagnose_classes_route`)
- Test: `tests/test_diagnose_probes.py`, `tests/test_diagnose.py`, `tests/test_routes.py` (or wherever `/api/diagnose/classes` is tested)

**Interfaces:**
- Produces: `Probe.needs_optional: tuple[str, ...] = ()`. Class spec key `"optional_slots": tuple[str, ...]` (default `()`, read with `.get`). The `/api/diagnose/classes` items gain `"optional_slots": list[str]`.

- [ ] **Step 1: Write failing tests**

```python
# test_diagnose.py
def test_optional_slot_never_in_need_and_is_kept(monkeypatch):
    monkeypatch.setitem(diagnose.SYMPTOM_CLASSES, "t_opt", {"label": "T", "slots": (), "optional_slots": ("app_name",), "wave1": (), "escalate": ()})
    monkeypatch.setattr(diagnose, "_spawn_worker", lambda sid: None)
    r = diagnose.start_diagnosis("x", slots={"app_name": "Chrome"}, symptom_class="t_opt")
    assert r["state"] == "probing_wave1"
    assert diagnose._sessions[r["session_id"]]["slots"] == {"app_name": "Chrome"}
    r2 = diagnose.start_diagnosis("x", symptom_class="t_opt")
    assert r2["state"] == "probing_wave1"          # nothing required, nothing asked

# test_diagnose_probes.py
def test_missing_optional_slot_does_not_refuse_probe():
    seen = {}
    dp.register(dp.Probe("t.opt", "T", "crash", lambda s: seen.setdefault("s", dict(s)) or {}, needs_optional=("app_name",)))
    [res] = dp.run_probes(["t.opt"], {})
    assert res["ok"] is True

# classes route
def test_classes_route_lists_optional_slots(client):
    items = client.get("/api/diagnose/classes").get_json()
    assert all("optional_slots" in c for c in items)
```

- [ ] **Step 2: Run them and confirm they fail.** `python -m pytest tests/test_diagnose.py tests/test_diagnose_probes.py -k "optional" --no-cov -q`. Expected: FAIL (`unexpected keyword 'needs_optional'`, KeyError on `optional_slots`).
- [ ] **Step 3: Implement.** Add `needs_optional` to `Probe`; the runner never refuses on it. In `start_diagnosis`, `need` is computed from `slots` only, and `filled` takes non-empty values from `slots + optional_slots`. Add `optional_slots` to the classes route.
- [ ] **Step 4: Run the full diagnose suites.** `python -m pytest tests/test_diagnose.py tests/test_diagnose_probes.py --no-cov -q -n auto`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(diagnose): optional slots for symptom classes`

### Task 2: Engine: per-class rules, prompt and the repair_image gate

**Files:**
- Modify: `diagnose.py` (`SYMPTOM_CLASSES`, `_SYSTEM_PROMPT` → `_BASE_PROMPT` + per-class `"prompt"`, `_call_model`, `_drive`, `apply_guards`)
- Test: `tests/test_diagnose.py`

**Interfaces:**
- Produces: class spec keys `"rules": Callable[[dict[str, dict], str | None], dict]` and `"prompt": str`. Also `_system_prompt(class_key: str) -> str` (= `_BASE_PROMPT + " " + spec["prompt"]`).
- `network_dns` gets `rules=evaluate_rules` and `prompt=` the DNS-specific sentences moved out of today's `_SYSTEM_PROMPT`. The base keeps only class-neutral sentences.
- `apply_guards` drops `"repair_image"` unless `"system_modules"` is in `rule_verdict["rule_hits"]`.

- [ ] **Step 1: Write failing tests**

```python
def test_drive_uses_class_rules(monkeypatch): ...      # a fake class whose "rules" returns a sentinel verdict; after _drive (model unavailable) the session's rule_verdict is that sentinel
def test_system_prompt_is_base_plus_class_hint():
    p = diagnose._system_prompt("network_dns")
    assert "dns.interception" in p and p.startswith(diagnose._BASE_PROMPT)
def test_base_prompt_is_class_neutral():
    assert "dns" not in diagnose._BASE_PROMPT.lower()
def test_repair_image_dropped_without_system_modules_hit():
    v = {"status": "likely", "locus": "local", "suggested_actions": ["repair_image"], "manual_steps": []}
    assert diagnose.apply_guards(v, {}, {"rule_hits": ["app_crash_repeat"]})["suggested_actions"] == []
    assert diagnose.apply_guards(v, {}, {"rule_hits": ["app_crash_repeat", "system_modules"], "status": "likely", "locus": "local"})["suggested_actions"] == ["repair_image"]
```

- [ ] **Step 2: Run and confirm they fail.**
- [ ] **Step 3: Implement.** `_drive` calls `spec["rules"](_by_key(evidence), host)` at both call sites, and `_call_model` passes `system=_system_prompt(class_key)`. Behaviour for `network_dns` is unchanged.
- [ ] **Step 4: Run the full diagnose suites, including `TestRuleFixtures` and the S1 golden test.** Expected: all pass, network behaviour unchanged.
- [ ] **Step 5: Commit** `refactor(diagnose): per-class rules and prompt; gate repair_image`

### Task 3: Redaction: `self_host`

**Files:**
- Modify: `diagnose.py` (`_redact_string`, `_PLACEHOLDER`, `redact` docstring)
- Test: `tests/test_diagnose.py`

**Interfaces:**
- Produces: redaction class `"self_host"`. It replaces `socket.gethostname()` as a whole word, case-insensitively, with `<this-pc>`. An empty hostname is a no-op.

- [ ] **Step 1: Failing tests.** `redact({"m": "SHIGS78-PC24 restarted"}, ["self_host"])` → `{"m": "<this-pc> restarted"}` with `socket.gethostname` patched to `"shigs78-pc24"`. `"myshigs78-pc24x"` is left unchanged (whole word). A planted username + hostname + `"serialNumber": "S6S2..."` + MAC in one evidence item → none of them appear in `build_payload` output for a probe whose `redact` includes all four classes.
- [ ] **Step 2: Run and confirm they fail.**
- [ ] **Step 3: Implement.** Apply `self_host` before `username`, and add `this-pc` to `_PLACEHOLDER`.
- [ ] **Step 4: Run and confirm they pass.**
- [ ] **Step 5: Commit** `feat(diagnose): self_host redaction class`

### Task 4: Event-log reader and episode derivation

**Files:**
- Create: `diagnose_crash_probes.py`
- Test: `tests/test_diagnose_crash_probes.py`

**Interfaces:**
- Produces:
  - `evt_query(channel: str, xpath: str, max_events: int = 200, timeout_s: float = 10.0) -> list[dict]`. Each dict is `{"id": int, "time": str (UTC ISO "…Z"), "provider": str, "level": int, "data": dict[str, str], "data_list": list[str]}`, newest first. `data` holds named `<Data Name=…>` fields, and `data_list` holds every `<Data>` text in order (Application Error 1000 uses unnamed fields). Raises `EvtUnavailable(channel, reason)` when the channel can't be opened, so probes can record it under `"unavailable"`. Any other per-event parse error skips that event.
  - `window_xpath(ids=None, providers=None, levels=None, days: int = 7, start: str | None = None, end: str | None = None) -> str`: an XPath with `TimeCreated[timediff(@SystemTime) <= ms]`, or an absolute `@SystemTime >= start and <= end` when both are given.
  - `derive_episodes(events: list[dict]) -> list[dict]`. The input is timeline events with `kind` ∈ {`boot`, `eventlog_start`, `eventlog_stop`, `shutdown_requested`, `shutdown_started`, `unexpected`, `dirty_noted`}. It returns oldest-first episodes `{"boot", "next_boot", "shutdown_requested_at", "shutdown_started_at", "next_boot_unexpected": bool, "last_alive": str|None}`, where `last_alive` is the 6008 time logged at the next boot.
  - `activity_between(start: str, end: str, cap: int = 500) -> tuple[int, str | None]`: the count and last time of System + Application events in the range.
  - `class EvtUnavailable(Exception)`.

- [ ] **Step 1: Failing tests** (with `win32evtlog` mocked; XML fixtures as strings):
  - `evt_query` parses `EventID`, `SystemTime`, `Provider@Name`, `Level`, named and unnamed `Data`. A malformed event is skipped. An `EvtQuery` exception raises `EvtUnavailable`. A timeout returns `[]`.
  - `window_xpath(ids=[41, 6008], days=7)` contains `EventID=41 or EventID=6008` and `604800000`.
  - `derive_episodes` on the **real 2026-10-08 sequence**: boot 03:36:24Z, requested 03:36:39Z, started 03:37:03Z, next boot 12:17:48Z with unexpected and dirty_noted 08:45:35Z. The result is one episode with `shutdown_started_at="2026-10-09T03:37:03Z"`, `next_boot_unexpected=True` and `last_alive="2026-10-09T08:45:35Z"`.
  - A clean sequence (started, then next boot with no unexpected) → `next_boot_unexpected=False`. (Review Focus 2.)
- [ ] **Step 2: Run and confirm they fail** (`ModuleNotFoundError: diagnose_crash_probes`).
- [ ] **Step 3: Implement.** Reuse the `_EVT_NAMESPACE` parsing approach from `windesktopmgr._query_event_log_xpath`, but never call `EvtOpenPublisherMetadata` (no message rendering), and run the query in a single worker thread bounded by `timeout_s`.
- [ ] **Step 4: Run and confirm they pass.**
- [ ] **Step 5: Commit** `feat(diagnose): EventData-aware event-log reader + episode derivation`

### Task 5: Wave-one probes A: shutdowns, blue screens, hardware, boots

**Files:**
- Modify: `diagnose_crash_probes.py`
- Test: `tests/test_diagnose_crash_probes.py`

**Interfaces:**
- Consumes: Task 4 helpers. `bsod.get_stop_code_info(raw_code: str, faulty_driver: str = "") -> dict | None` (existing).
- Produces registered probes (each `fn(slots) -> dict`):
  - `crash.power_timeline` → `{"window_days": 7, "events": [{"time", "kind", "id"}] (≤50, newest last), "episodes": [...], "unavailable": []}`. For each episode with `next_boot_unexpected` and `shutdown_started_at`, it adds `"activity_after_shutdown_start": n` and `"last_activity": t` from `activity_between(shutdown_started_at, next_boot)`. Event-id mapping: System 12→`boot`, 6005→`eventlog_start`, 6006→`eventlog_stop`, 1074→`shutdown_requested`, 109 and 13→`shutdown_started`, 41→`unexpected`, 6008→`dirty_noted`.
  - `crash.unexpected_shutdowns` → `{"events": [{"time", "bugcheck_code": int, "power_button": bool, "long_press": bool, "sleep_in_progress": bool}]}`, from 41 EventData `BugcheckCode`, `PowerButtonTimestamp` (≠"0"), `LongPowerButtonPressDetected` (=="true"), `SleepInProgress` (≠"0").
  - `crash.bugchecks` → `{"bugchecks": [{"time", "code": "0x…", "name": str|None}], "minidumps": [{"name", "time", "size"}] (≤10 newest), "memory_dmp": {"time", "size"}|None}`. Reads System 1001 from provider `Microsoft-Windows-WER-SystemErrorReporting` (code from `data_list[0]`), `os.scandir(%SystemRoot%\Minidump)` and `%SystemRoot%\MEMORY.DMP` stat.
  - `crash.whea` → `{"fatal": int, "corrected": int, "by_component": {"processor", "memory", "pcie", "other"}, "first", "last"}`. Provider `Microsoft-Windows-WHEA-Logger`; component by id {17,20: pcie; 18,19: processor; 46,47: memory}; fatal when `level in (1, 2)`.
  - `crash.boot_health` → `{"boot_failures": [time], "startup_repair_runs": int, "boot_durations_ms": [int], "unavailable": [channel]}`. Kernel-Boot 20 with `data["LastBootGood"] == "false"`; `Microsoft-Windows-StartupRepair` channel count; `Microsoft-Windows-Diagnostics-Performance/Operational` 100 `BootTime`. An `EvtUnavailable` on either of the last two goes into `unavailable`.

- [ ] **Step 1: Failing tests** per probe: happy path, empty log, malformed EventData (missing field → default, not crash), `EvtUnavailable`, and command content (the XPath passed contains the required ids/provider). Registry tests: the 5 keys are registered with the global-constraint `redact` and `category`.
- [ ] **Step 2: Run and confirm they fail.**
- [ ] **Step 3: Implement the five `_p_*` functions and `register(...)` calls.**
- [ ] **Step 4: Run and confirm they pass.**
- [ ] **Step 5: Commit** `feat(diagnose): crash probes - timeline, shutdowns, bugchecks, WHEA, boot health`

### Task 6: Wave-one probes B and escalation probes

**Files:**
- Modify: `diagnose_crash_probes.py`
- Test: `tests/test_diagnose_crash_probes.py`

**Interfaces:**
- Consumes: Task 4 helpers; `bios_audit.load_history() -> list[dict]` (existing).
- Produces:
  - `crash.app_crashes` (`needs_optional=("app_name",)`) → `{"named": str|None, "apps": [{"app", "crashes", "hangs", "last", "modules": [{"module", "count"}] (≤3), "exception_codes": [str] (≤3), "system_module_crashes": int}] (≤10)}`. Application 1000 reads `data_list[0]` app, `[3]` module, `[6]` exception, `[11]` module path; 1002 reads `data_list[0]` app; 1026 counts as a crash of `data_list[0]` when present. `max_events=1000` at the query. Sorted by crashes+hangs descending; the named app (case-insensitive, substring of the exe name) goes first. A module path is "system" when it starts with `%SystemRoot%\System32\` (case-insensitive).
  - `crash.storage_errors` → `{"by_provider": {name: {"count", "last"}}, "pool_repair_failures": int, "pool_times": [time], "storage_service_faults": [{"app", "time"}]}`. System providers `disk`, `stornvme`, `storahci`, `Ntfs` at Level ≤3; `Microsoft-Windows-StorageSpaces-Driver/Operational` 313; Application 1000 where the app matches `^(RstMwService|IAStor|ia?storage).*\.exe$` (case-insensitive).
  - `crash.recent_changes` → `{"installs": [{"time", "kind": "driver"|"service"|"update", "name"}] (≤30)}`, from UserPnp 20001/20003 (`data_list` driver name), SCM 7045 (`data["ServiceName"]`) and WindowsUpdateClient 19 (`data["updateTitle"]`).
  - `crash.hw_changes` → `{"changes": [{"time", "field", "old", "new"}]}` from `bios_audit.load_history()` change entries in the window. Any field matching `/serial/i` reports `old="<changed>"` and `new="<changed>"`.
  - `crash.power_config` → `{"fast_startup": bool|None, "hibernate": bool|None}`, from `winreg` `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled` and `HKLM\SYSTEM\CurrentControlSet\Control\Power\HibernateEnabled`.
  - Escalation: `crash.window_30d` (`{"power_timeline", "bugchecks", "whea"}` re-run with `days=30`); `crash.app_detail` (`needs=("app_name",)`, ≤30 records `{"time", "kind", "app_version", "module", "module_version", "exception", "offset"}`); `crash.event_context` (≤40 `{"time", "provider", "id", "level"}` with Level ≤3 in System + Application during the 10 minutes before the newest 41).

- [ ] **Step 1: Failing tests** per probe (same five cases as Task 5), plus:
  - **Review Focus 5:** feed 5,000 synthetic 1000 events through a mocked `evt_query` that honours `max_events`. Assert `len(apps) <= 10`, and that `evt_query` was called with `max_events=1000`.
  - Named app first: `slots={"app_name": "chrome"}` puts `chrome.exe` first even when it's not the top crasher.
  - A serial field in a BIOS change gives `<changed>` and never the value.
  - Registry snapshot test updated: the total becomes 28, and wave one still runs in a single batch (`_MAX_WORKERS` 10 ≥ 10).
- [ ] **Step 2: Run and confirm they fail.**
- [ ] **Step 3: Implement and register.**
- [ ] **Step 4: Run and confirm they pass.**
- [ ] **Step 5: Commit** `feat(diagnose): crash probes - app crashes, storage, installs, hw changes, power config, escalations`

### Task 7: Crash rules, context annotations, steps and fixtures

**Files:**
- Create: `diagnose_crash_rules.py`
- Create: `tests/fixtures/diagnose/crash_*.json` (9 files, spec §9)
- Modify: `tests/test_diagnose.py` (`TestRuleFixtures` dispatches on `fx.get("symptom_class", "network_dns")`)
- Test: `tests/test_diagnose_crash_rules.py`

**Interfaces:**
- Produces: `evaluate_crash_rules(evidence: dict[str, dict]) -> dict`, a full verdict in `diagnose._verdict`'s shape. `rule_hits` = [rule key, then any of `hw_changed`, `recent_install`, `storage_trouble`, `fast_startup`, `system_modules`]. `evidence_refs` lists the probe keys used. `manual_steps` comes from the spec §6 step lists, ≤6. `suggested_actions` = `["repair_image"]` only with `system_modules`.
- Implementation note (import cycle): this module does `import diagnose as dg` at top and uses `dg._verdict` / `dg.clean_steps` **only inside functions**. `diagnose.py` reaches this module only through a wrapper defined in `diagnose.py` (`def _crash_rules(evidence, host): return dcr.evaluate_crash_rules(evidence)`), so neither import touches a half-initialised attribute.
- Headline copy (exact): `"Your hardware is reporting errors ({component})"`, `"Blue screen: {name or code}"` (+ `" caused by {driver}"`), `"The PC got stuck shutting down"`, `"It was turned off by holding the power button"`, `"The PC lost power or froze completely"`, `"Windows failed to start {n} times on {date}"`, `"{app} keeps crashing in {module}"`, `"No crashes or unexpected shutdowns recorded since {date}"`.
- `hung_shutdown` reasoning must state, in local time, when shutdown began, when activity stopped (`last_activity`), and `last_alive`. With `hw_changed`, it adds a sentence naming the changed fields, e.g. `"At 11:39 on 2026-10-08, secure_boot changed from enabled to disabled."` (absolute local time, never a relative "the day before")

- [ ] **Step 1: Write the 9 fixtures** in the existing format, plus `"symptom_class": "crashes"` and `"expect": {"rule": <key>, "status": <s>, "locus": <l>, "must_include": [...], "must_exclude": [...], "context": [...]}`. `crash_hung_shutdown_2026_10_08.json` uses the real sequence from Task 4, with `crash.hw_changes` containing `secure_boot enabled→disabled` at `2026-10-08T15:39:21Z`, and expects `rule="hung_shutdown"` and `context=["hw_changed"]`.
- [ ] **Step 2: Extend `TestRuleFixtures`** to call `dcr.evaluate_crash_rules` for crash fixtures and assert `expect["rule"] == verdict["rule_hits"][0]`, the status and locus, and each `context` key ∈ `rule_hits`. Add unit tests:
  - `whea_fatal` beats `bugcheck` (C3).
  - Each threshold boundary: 9 vs 10 corrected; 2 vs 3 app crashes; 2 failed boots 31 min apart doesn't fire.
  - **Review Focus 3:** with `TZ` patched to UTC-4 (`time.tzset` is unavailable on Windows; patch the module's `_local(ts) -> datetime` helper instead), the hung-shutdown reasoning contains `23:37`.
  - **Review Focus 2:** a clean shutdown followed by a normal boot gives `nothing_found`.
  - `nothing_found` is `inconclusive` (C5).
- [ ] **Step 3: Run and confirm they fail.**
- [ ] **Step 4: Implement `diagnose_crash_rules.py`.**
- [ ] **Step 5: Run `tests/test_diagnose.py` and `tests/test_diagnose_crash_rules.py`.** Expected: all pass.
- [ ] **Step 6: Commit** `feat(diagnose): crash rules, context annotations, steps + fixtures`

### Task 8: Classifier and class registration

**Files:**
- Modify: `diagnose_crash_rules.py` (`CRASH_RE`, `extract_app_name`)
- Modify: `diagnose.py` (`classify`, `SYMPTOM_CLASSES["crashes"]`)
- Test: `tests/test_diagnose.py` (classifier table)

**Interfaces:**
- Produces: `CRASH_RE: re.Pattern`, word-boundary, case-insensitive, over the spec §8 keyword list. `extract_app_name(text: str) -> str | None`: 1–3 words directly before `keeps crashing|crashed|crashes|froze|freezes|stopped responding|keeps closing|is not responding`, quotes and trailing punctuation stripped, rejected when the last word is in the spec §8 generic-noun list or `the|my|a`.
- `classify()` returns `symptom_class="crashes"` with `slots={"app_name": …}` when one is found, `missing=[]` when crash words match and no host or network keyword does, and `symptom_class=None` when both match.
- `SYMPTOM_CLASSES["crashes"]` = label and slots per Global Constraints. `wave1` = the 10 keys from Tasks 5–6, `escalate` = the 3 escalation keys, `rules=_crash_rules`, and `prompt` = a short crash hint: cite probe keys, never treat `nothing_found` as a cause, `repair_image` only for system-module crashes, report times in the user's local time.

- [ ] **Step 1: Failing table test** (`pytest.mark.parametrize`):

| Input | Expected class | Expected app |
|---|---|---|
| `"the computer crashed last evening - cna you investigate?"` | `crashes` | None |
| `"Chrome keeps crashing"` | `crashes` | `"Chrome"` |
| `"Microsoft Teams keeps crashing"` | `crashes` | `"Microsoft Teams"` |
| `'"Chrome" crashed!'` | `crashes` | `"Chrome"` |
| `"My computer keeps crashing"` | `crashes` | None |
| `"I need to change my DNS"` | `network_dns` | None (`hang` must not match "change") |
| `"Chrome crashed loading example.com"` | None | n/a |
| `"blue screen this morning"` | `crashes` | None |
| `"PC won't boot sometimes"` | `crashes` | None |

  Also: the network classifier tests still pass unchanged.
- [ ] **Step 2: Run and confirm they fail.**
- [ ] **Step 3: Implement and register the class.**
- [ ] **Step 4: Run the full suite** `python -m pytest tests/ -n auto`. Expected: all pass, coverage ≥80%.
- [ ] **Step 5: Commit** `feat(diagnose): crashes symptom class + classifier`

### Task 9: UI: optional app row

**Files:**
- Modify: `templates/index.html` (new `#dx-app-row` with `#dx-app` input, label "Which app, if any? (optional)", hidden by default)
- Modify: `static/js/app.js` (`dx_loadClasses` change handler; `dx_start` sends `slots.app_name` when the row is visible and non-empty; `dx_clearAsk` clears it)
- Test: `tests/test_playwright_smoke.py` (`TestDiagnoseTab`)

**Interfaces:**
- Consumes: `/api/diagnose/classes` items with `optional_slots` (Task 1).
- Produces: `dx_classHasOptional(key: string, slot: string) -> boolean`.

- [ ] **Step 1: Failing Playwright tests:**
  - C1 sentence → a request to `/api/diagnose/status/…` happens (session started) and `#dx-ask` is never visible.
  - Choosing `crashes` in `#dx-class` (after an unrecognised symptom like `"something is weird"`) shows `#dx-app-row`; choosing `network_dns` hides it and shows `#dx-host-row`.
  - The PR #184 crash pointer is gone: after an unrecognised symptom, `#dx-ask .dx-link` count is 0.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Commit** `feat(diagnose): optional app-name row for the crash class`. Playwright runs after deploy (Task 10), against the live tray.

### Task 10: Ship: review, docs, deploy, live acceptance

**Files:**
- Modify: `architecture.html` (new root files `diagnose_crash_probes.py` and `diagnose_crash_rules.py`, new test files, probe count 15→28, fixture count, test count, line counts; use `/arch-update` then hand-edit the file chips)
- Modify: `docs/superpowers/specs/2026-10-01-diagnostic-engine-design.md` §14 row 2 → link to this spec
- Memory: `project_backlog.md` row #63 (⏳ → PR 2 shipped, after live acceptance only), `project_diagnose_engine_2026-10-01.md`

- [ ] **Step 1:** `ruff check . && ruff format .` → clean. `python -m pytest tests/ -n auto` → all pass, ≥80%.
- [ ] **Step 2:** `/code-review` on the branch diff. Resolve or justify every finding in the commit body.
- [ ] **Step 3:** `/arch-update` plus the manual chips. `python -m pytest tests/test_architecture_html.py --no-cov` → PASS.
- [ ] **Step 4:** Push, open the PR, merge. Pull main into the primary repo. `python dev.py verify` → "All checks passed".
- [ ] **Step 5:** `pytest tests/test_playwright_smoke.py -m playwright --no-cov -k TestDiagnoseTab` against the live tray → all pass.
- [ ] **Step 6, live acceptance (C2, C6):** in the browser pane, submit the C1 sentence and decline the preview (evidence-only). Expected: headline `"The PC got stuck shutting down"`, with reasoning naming 23:37, about 04:11 last activity, 04:45 last alive, and the Secure Boot change. Screenshot it. If it doesn't match, fix before marking anything shipped.
- [ ] **Step 7:** Update the backlog and memory, regenerate `backlog.html`, and print the SOP Compliance Report.
