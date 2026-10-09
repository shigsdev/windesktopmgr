# Diagnose — Crashes & Stability Bundle (PR 2) — Design Spec

**Date:** 2026-10-09
**Status:** Awaiting review
**Parent spec:** [`2026-10-01-diagnostic-engine-design.md`](2026-10-01-diagnostic-engine-design.md) (§14, row 2)
**Backlog:** #63, PR 2 of 4

---

## 1. Problem

On 2026-10-09 the user typed *"the computer crashed last evening - can you
investigate?"* into Diagnose. It could only offer the Network & DNS check
(PR #184 made that honest, but did not make it useful). The investigation was
then done by hand, and it showed what this bundle has to do:

- The "crash" was not a blue screen. A power-off was requested at 23:36:39,
  shutdown began at 23:37:03 and **never finished**. Background tasks kept
  logging until about 04:11, the last sign of life was 04:45:35, and the next
  boot (08:17) logged Kernel-Power 41 with `BugcheckCode 0`, no power-button
  press, and no dump.
- The decisive context came from **elsewhere**: the motherboard had been
  replaced that day, and the app's own BIOS audit had logged
  `secure_boot: enabled → disabled` at 11:39.
- Supporting evidence sat in three more logs: an Intel RST service fault and a
  failed Storage Spaces repair at the 23:36 boot.

A crash rarely announces its own category. The bundle must read every
relevant source in one pass and say which kind of failure it was.

## 2. Intent and success criteria

**Intent:** the user describes a crash, freeze, unexpected restart, startup
problem, or crashing app in plain language and gets a verdict grounded in this
machine's logs, with plain-language steps. Read-only, the same egress gate as
PR 1, and useful without the model (rules first).

| | Criterion |
|---|---|
| C1 | *"the computer crashed last evening - cna you investigate?"* (verbatim, typo included) classifies to `crashes` with no question asked. |
| C2 | Run live against the 2026-10-08 incident, the verdict is **"stuck shutting down"** and the reasoning mentions the motherboard/BIOS change the day before. |
| C3 | Hardware-error evidence (WHEA fatal) outranks a blue screen in the same window. |
| C4 | No usernames, PC name, serials or MACs reach the payload preview. |
| C5 | "Nothing found in 7 days" renders as inconclusive, never as a diagnosis. |
| C6 | With no model, rules still give the C2 verdict (evidence-only mode). |

**Non-goals:** full crash-dump debugging (no WinDbg/`kd`), automatic driver
rollback, fixing a PC that cannot boot (the app is not running then; "won't
start" is diagnosed after the fact), and monitoring or alerting.

## 3. Scope: one class covering three kinds of crash

Approach **A** (chosen 2026-10-09 over three separate classes, or one
model-only class): a single class `crashes`, labelled **"Crashes, freezes &
startup problems"**, whose wave one reads every source. It covers:

1. **Whole-PC failures:** blue screens, sudden restarts or power-offs, hard
   freezes, hung shutdowns.
2. **App crashes:** a named app ("Chrome keeps crashing") or, unnamed, the
   apps that crash most.
3. **Startup problems:** failed or repeated boots, startup repair. Diagnosed
   once Windows is running again.

The class key **must be `crashes`**: PR #184's unclassified prompt hides its
"look at the Blue Screens tab" pointer once a `crashes` class exists.

## 4. Engine change: optional slots

The engine currently treats every slot in `SYMPTOM_CLASSES[k]["slots"]` as
required (`start()` computes `need` from it). This bundle needs an
**optional** `app_name`. The change, the only one to the "frozen" engine:

- A class may declare `"optional_slots": ("app_name",)`.
- `start()` computes `need` from `slots` only. `filled` keeps any non-empty
  value from `slots` **or** `optional_slots`.
- `GET /api/diagnose/classes` returns `optional_slots` alongside `slots`.
- Probes may name an optional slot in `needs_optional`; the runner passes it
  when present and never refuses a probe for a missing optional slot.
  Required `needs` keep today's refuse-if-missing behaviour.
- The registry invariant tests extend to optional slots: every
  `needs_optional` entry is one of its class's `optional_slots`.

`crashes` has `slots: ()` and `optional_slots: ("app_name",)`. With no
required slot the session starts immediately, which is C1.

## 5. Probes

All read-only, with a default 7-day look-back (`WINDOW_DAYS = 7`). Event logs
are read through pywin32 `win32evtlog.EvtQuery` + XPath, reusing the
established pattern in `windesktopmgr._query_event_log_xpath` (Python-first
per CLAUDE.md). A small shared helper in `diagnose_probes.py` additionally
returns the `EventData` name/value pairs, which the existing helper drops and
Kernel-Power 41 needs. Every probe returns **structured summaries** (time, id,
code, count, app/module name), never raw `Message` text.

### 5.1 Wave one (10 probes, within `_MAX_WORKERS = 10`)

| Key | Source | Returns |
|---|---|---|
| `crash.power_timeline` | System: 12, 13, 41, 109, 1074, 6005, 6006, 6008; Kernel-Boot 20, 27 | Ordered boot/shutdown events (≤50), plus derived **episodes**: each boot→next boot span, with flags `clean_shutdown`, `shutdown_started_at`, `activity_after_shutdown_start` (count + last timestamp of any System/Application event after the shutdown began), `last_alive` (from 6008) |
| `crash.unexpected_shutdowns` | System 41 EventData | Per event: `BugcheckCode`, `PowerButtonTimestamp`, `LongPowerButtonPressDetected`, `SleepInProgress`, `ConnectedStandbyInProgress` |
| `crash.bugchecks` | System 1001 (BugCheck), `C:\Windows\Minidump\*.dmp` metadata, `MEMORY.DMP` presence | Stop codes + params, dump file names/times/sizes. Stop-code names via `bsod.get_stop_code_info` (existing cache) |
| `crash.whea` | System, provider `Microsoft-Windows-WHEA-Logger` | Counts by severity (fatal vs corrected) and component (processor / memory / PCIe), first/last time |
| `crash.boot_health` | Kernel-Boot + Startup Repair (`Microsoft-Windows-StartupRepair`) + boot performance (Diagnostics-Performance 100, when readable) | Failed or repeated boots within short spans, startup-repair runs, boot durations |
| `crash.app_crashes` | Application 1000 (Application Error), 1002 (Application Hang), 1026 (.NET Runtime) | Grouped by app: count, last time, top faulting modules, exception codes. When `app_name` is given, that app's groups first; otherwise the top 10 by count |
| `crash.storage_errors` | System: `disk`, `stornvme`, `storahci`, `Ntfs` (Level ≤ 3), StorageSpaces-Driver/Operational 304/313; Application 1000 for storage services (e.g. `RstMwService.exe`) | Counts and times, grouped by provider |
| `crash.recent_changes` | System 7045 (service installed), UserPnp/DriverFrameworks installs, `get_update_history()` (existing) | Driver/service/update installs in the window, with times |
| `crash.hw_changes` | `bios_audit.load_history()` (existing) | BIOS version, Secure Boot, TPM, board/serial **changes** in the window (never raw serial values) |
| `crash.power_config` | `winreg`: `HiberbootEnabled` (Fast Startup), hibernate enabled | Two booleans. Fast Startup changes what "shutdown" means in the timeline |

### 5.2 Escalation probes (the model may request them)

| Key | Returns |
|---|---|
| `crash.window_30d` | `crash.power_timeline` + `crash.bugchecks` + `crash.whea` re-run over 30 days |
| `crash.app_detail` | Every 1000/1002 record for one app (needs `app_name`) with module versions and offsets, ≤30 |
| `crash.event_context` | All System + Application Level ≤ 3 events in the 10 minutes before the most recent unexpected shutdown, ≤40, summarised (provider, id, level, time) |

Each probe declares `category: "crash"`, `timeout_s` 8–15 s, and the
redaction classes in §7.

## 6. Rules and verdicts

Deterministic rules run over the evidence (as in PR 1 §9). The first match
in this order leads; the model may add to a confident rule verdict but cannot
contradict it (the existing guard).

| # | Rule key | Fires when | Headline | Status / locus |
|---|---|---|---|---|
| 1 | `whea_fatal` | Any WHEA fatal error in the window, or ≥10 corrected on one component | "Your hardware is reporting errors (component)" | likely / local |
| 2 | `bugcheck` | 41 with `BugcheckCode ≠ 0`, or a 1001 | "Blue screen: STOP_NAME" (+ "caused by DRIVER" when the same driver repeats) | confident / local |
| 3 | `hung_shutdown` | An episode with `shutdown_started_at` set, `activity_after_shutdown_start > 0`, and the next boot logging 41 with bugcheck 0 | "The PC got stuck shutting down" | likely / local |
| 4 | `power_button` | 41 with `PowerButtonTimestamp ≠ 0` or `LongPowerButtonPressDetected` | "It was turned off by holding the power button" | confident / local |
| 5 | `power_loss_or_freeze` | 41 with bugcheck 0, no button press, no shutdown started | "The PC lost power or froze completely" | likely / unknown |
| 6 | `boot_failure` | ≥2 failed or aborted boots within 30 minutes, or a startup-repair run | "Windows failed to start N times on DATE" | likely / local |
| 7 | `app_crash_repeat` | One app with ≥3 crashes/hangs in the window | "APP keeps crashing in MODULE" | likely / local |
| — | `nothing_found` | None of the above | "No crashes or unexpected shutdowns recorded since DATE" | **inconclusive** / unknown |

**Context annotations** don't win on their own, but attach to whichever
verdict did, as reasoning lines and (where useful) steps:

- `hw_changed`: a BIOS-audit change (board, BIOS, Secure Boot, TPM) within 48 h
  before the incident, e.g. "The motherboard was replaced the day before and
  Secure Boot was turned off."
- `recent_install`: a driver, service, or update installed within 48 h before.
- `storage_trouble`: disk/controller/pool errors within ±1 h of the incident.
- `fast_startup`: Fast Startup is on (a caveat on shutdown readings).

**Built-in manual steps** (≤6, the existing `manual_steps` contract):

- `whea_fatal`: Dell diagnostics (F12 at startup → Diagnostics); Windows Memory
  Diagnostic; reseat RAM / the add-in card if recently handled; contact the
  repairer or Dell if a part was just replaced.
- `bugcheck`: update or roll back the named driver; check the Blue Screens tab
  for repeats; note any recent install from `recent_install`.
- `hung_shutdown`: check the power cable and outlet; if it repeats, note the
  time and mention it to whoever replaced the board (when `hw_changed`); try
  a restart instead of shut down to see if only shutdown hangs; look at
  `storage_trouble` / `recent_install` items.
- `power_button`: was the screen frozen first? If so, treat it as a freeze
  (the steps for `power_loss_or_freeze`).
- `power_loss_or_freeze`: power cable, outlet, UPS; whether the lights or fans
  stayed on (freeze) or went dark (power loss).
- `boot_failure`: disconnect recently added USB devices; check BIOS boot order
  and Secure Boot changes (link the Docs procedure); run Startup Repair if it
  recurs.
- `app_crash_repeat`: update or reinstall the app; if MODULE is a third-party
  add-in/overlay, disable it; the faulting module and version are listed.

**Registry actions:** only `repair_image` (DISM + SFC), and only when ≥3
**different** apps crash in modules under `%SystemRoot%\System32`, the
signature of corrupted system files. Every other verdict suggests no action.
The model can request `repair_image` only through the same guard.

## 7. Privacy

Event-log data is far more personal than DNS answers. In addition to the
parent spec §7:

- **Summaries only.** No probe returns a raw `Message` string.
- **Redaction classes** on every crash probe: `username`, `serial`, `mac`,
  plus a new class **`self_host`**: the PC's own computer name
  (`socket.gethostname()`, case-insensitive, whole word) → `<this-pc>`.
- **`crash.hw_changes` never emits serial values**, only that a serial
  field changed.
- **Caps:** ≤50 timeline events, ≤10 apps, ≤30 records in `crash.app_detail`.
- The egress preview and "nothing leaves until you click Send" are unchanged.

## 8. Classifier

- **Crash keywords** (case-insensitive, matched on **word boundaries**, so
  `hang` does not fire on "change" and `hung` not on "hungry"; `crash` and
  `freez` also match their inflections): `crash`, `blue screen`,
  `bsod`, `froze`, `freez`, `hung`, `hang`, `stopped responding`,
  `not responding`, `restarted by itself`, `rebooted`, `reboot`, `shut down`,
  `shutdown`, `won't boot`, `wont boot`, `won't start`, `wont start`,
  `black screen`, `keeps closing`, `power off`, `turned off`.
- **App name extraction** (optional slot): `<Name> keeps crashing / crashed /
  froze / stopped responding / keeps closing`, where `<Name>` is 1–3 words
  before the verb and not a generic word (`computer`, `pc`, `laptop`,
  `system`, `it`, `windows`, `machine`, `screen`). `"the computer crashed"` →
  no app.
- **Both crash and network signals** (a crash keyword *and* a host candidate
  or network keyword) → `symptom_class: None`, so the user picks. Never guess.
- Table-tested, including C1 verbatim and the mixed case.

**UI:** when `crashes` is picked from the dropdown, an optional **"Which app,
if any? (optional)"** row appears (driven by `optional_slots`). The site row
stays tied to `target_host`.

## 9. Testing

Per CLAUDE.md layers, plus the parent spec's fixture pattern
(`tests/fixtures/diagnose/*.json`, discovered by one parametrized test):

| Fixture | Expect |
|---|---|
| `crash_hung_shutdown_2026_10_08.json`: built from the real logs (redacted) | `hung_shutdown`, `hw_changed` in reasoning (C2, C6) |
| `crash_bugcheck_repeat_driver.json` | `bugcheck`, driver named |
| `crash_whea_beats_bugcheck.json` | `whea_fatal` (C3) |
| `crash_power_button.json` | `power_button` |
| `crash_power_loss.json` | `power_loss_or_freeze` |
| `crash_boot_failure.json` | `boot_failure` |
| `crash_app_repeat_chrome.json` | `app_crash_repeat`, no actions |
| `crash_system_modules_multi_app.json` | `app_crash_repeat` + `repair_image` |
| `crash_nothing_found.json` | inconclusive (C5) |

Also:

- **Probe tests:** happy / empty / malformed EventData / EvtQuery failure /
  timeout per probe, with `win32evtlog` mocked.
- **Episode derivation:** unit tests on the timeline-to-episodes function,
  including the real 2026-10-08 sequence.
- **Classifier table:** C1 verbatim, app extraction, generic-noun rejection,
  the crash+network mix.
- **Engine:** optional slots (absent → session starts; present → passed to
  probes; never in `need`).
- **Redaction:** planted username, PC name, serials, MACs absent from the
  payload (C4).
- **Routes:** `/api/diagnose/classes` includes `optional_slots`.
- **Playwright:** C1 sentence starts a session with no ask; the app row
  appears only for `crashes`; the PR #184 crash pointer is gone.
- **Live acceptance:** after deploy, run the C1 sentence on this machine and
  compare the verdict with the hand investigation (§1). Backlog #63 is not
  marked shipped until that matches.

## 10. Decomposition

One PR (bundle 2), in order: engine optional slots → probes → rules → classifier
+ UI → fixtures/tests → `architecture.html` (new test fixtures, new probes in
the diagnose_probes chip, test count, line counts). If the probe set pushes
`diagnose_probes.py` well past ~2,000 lines, the crash probes move to a new
`diagnose_probes_crash.py` registered into the same `PROBES` dict; that is a
new root file and an `architecture.html` trigger.
