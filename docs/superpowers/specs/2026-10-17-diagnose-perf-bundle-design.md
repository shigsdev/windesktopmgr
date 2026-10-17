# Diagnose — Speed & Heat Bundle (PR 4) — Design Spec

**Date:** 2026-10-17
**Status:** Awaiting review
**Parent spec:** [`2026-10-01-diagnostic-engine-design.md`](2026-10-01-diagnostic-engine-design.md) (§14, row 4)
**Siblings:** [`2026-10-09-diagnose-crash-bundle-design.md`](2026-10-09-diagnose-crash-bundle-design.md) (PR 2), [`2026-10-13-diagnose-storage-bundle-design.md`](2026-10-13-diagnose-storage-bundle-design.md) (PR 3, the pattern this follows most closely)
**Backlog:** #63, PR 4 of 4

---

## 1. Problem

"My PC is slow" and "it's running hot" are the two complaints Diagnose still
can't answer. On this PC they are live problems: since the 2026-10-08
motherboard swap the CPU has reached 100 °C at moderate load, Dell's
pre-boot check reports the VR heat sink not installed (2000-0714), and
Windows has logged 110+ corrected processor errors in four days. The app
already measures temperatures, per-core headroom, power, clocks, fans, CPU
and memory per app, the GPU, the stuck-driver detector (#75) and trend
history, but nothing turns those readings into a plain answer.

## 2. Intent and success criteria

**Intent:** the user describes a speed or heat problem in plain language
and gets a verdict grounded in this PC's live readings and recent history,
with plain-language steps. Read-only, no admin, the same egress gate as PR 1,
useful without the model (rules first). Covers four kinds of problem, chosen
by the user 2026-10-16: **slow right now**, **running hot / loud fans**,
**slow to start up**, **gets slower over time**.

| | Criterion |
|---|---|
| P1 | *"my PC is slow and running hot"* and *"Chrome is slow"* classify to `performance` with no question asked; the second fills `app_name = "Chrome"`. |
| P2 | A core at 0–2 °C from TjMax during the check gives **thermal_throttling**, and processor WHEA errors in the window add the `hw_errors` note. |
| P3 | One app taking ≥ 50 % of total CPU in the sample is named in the headline (`cpu_hog`). |
| P4 | No window title, file path, command line, user name or PC name reaches the payload preview. |
| P5 | Nothing found renders as **inconclusive**, never "all fine". |
| P6 | With no model, rules give the same verdicts (evidence-only mode). |
| P7 | *"the internet is slow"*, *"E: is slow"* and *"the PC froze"* keep their current classes (network, storage, crashes). |

**Non-goals:** changing anything (no killing processes, no power-plan or
startup changes, no BIOS settings); per-program startup cost (needs the
admin-only Diagnostics-Performance log, unreadable here, checked
2026-10-17); load testing or benchmarks; fan control.

## 3. Scope: one class

Approach **A** (chosen 2026-10-16 over separate slow/hot classes or a
dashboard wrapper): a single class `performance`, labelled **"Speed &
heat"**, whose wave one reads every source, because a hot CPU *is* a slow
CPU and the causes overlap.

```python
"performance": {
    "label": "Speed & heat",
    "slots": (),
    "optional_slots": ("app_name",),
    "wave1": (...10 probes, §5.1...),
    "escalate": (...3 probes, §5.2...),
    "rules": lambda evidence, host: dpr.evaluate_perf_rules(evidence),
    "prompt": _PERF_PROMPT,
    "actions": ("reboot_system",),
}
```

`app_name` reuses the crash class's optional slot and UI row ("Which app,
if any? (optional)"). No engine change beyond the action guard in §6.

## 4. Code layout

| File | Contents |
|---|---|
| `diagnose_perf_probes.py` (new) | Probes, registered into `diagnose_probes.PROBES` with `category="perf"` |
| `diagnose_perf_rules.py` (new) | Classifier helpers (`PERF_STRONG_RE`, `PERF_WEAK_RE`, `extract_perf_app`) and `evaluate_perf_rules` |
| `diagnose.py` | `SYMPTOM_CLASSES["performance"]`, `_PERF_PROMPT`, `classify()` branch, `reboot_system` guard, imports |
| `static/js/app.js` | `dx` app row shown for any class whose `optional_slots` has `app_name` (already generic; verify) |
| `tests/test_diagnose_perf_probes.py`, `tests/test_diagnose_perf_rules.py` (new) + `tests/fixtures/diagnose/perf_*.json` | §9 |

## 5. Probes

All read-only, unelevated, Python first (psutil, winreg, the existing
`lhm`, `gpu`, `kernel_cpu`, `metrics_history`, crash and storage readers).
No PowerShell.

### 5.1 Wave one (10 probes)

| Key | Source | Returns |
|---|---|---|
| `perf.cpu` | psutil, two snapshots `CPU_SAMPLE_S = 3` s apart (`cpu_times`, `cpu_percent(percpu=True)`, per-process `cpu_times`) | `total_pct`, `busiest_core_pct`, `cores`, top 5 processes `{name, pid, cpu_pct}` where `cpu_pct` is the share of the **whole** CPU (0–100) |
| `perf.memory` | `psutil.virtual_memory`, `psutil.swap_memory`, per-process `memory_info().rss` + `create_time` | `used_pct`, `available_gb`, `total_gb`, `swap_used_pct`, top 5 processes `{name, pid, rss_gb, running_h}` |
| `perf.thermals` | `lhm._fetch_data_json()` (30 s cache; never starts LHM); fallback `thermals.get_thermals()` | `source` (`lhm` / `windows` / `none`), CPU `package_c`, `core_max_c`, `min_tjmax_distance_c` (smallest "Distance to TjMax"), `tjmax_c` (core temp + distance where both exist), `package_w`, `p_core_mhz` (max), `fans` `[{name, rpm}]`, `gpu_temp_c` |
| `perf.gpu` | `gpu.get_gpu_metrics()` | `available`, `name`, `util_pct`, `temp_c`, `vram_pct` |
| `perf.kernel` | `kernel_cpu.sample()` (the #75 detector's last state) | `available`, `busiest` `{pct, …}`, `stuck` list (thread / pct / seconds) |
| `perf.disk_busy` | reuses `diagnose_storage_probes._io_sample(3)` | per-disk `busy_pct`, `avg_*_ms` (storage probe shape) |
| `perf.since_boot` | `psutil.boot_time()` + `metrics_history.get_series()` for `memory_percent` and `cpu_temp_c` since boot | `uptime_h`, `boot` (UTC ISO), `memory_first_pct` / `memory_now_pct`, `temp_max_c` since boot, `samples` |
| `perf.startup` | System log: `Microsoft-Windows-Kernel-General` 12 (OS start) and `Microsoft-Windows-Winlogon` 7001 (sign-in), last 14 days (crash bundle `_query`); `windesktopmgr.get_startup_items()` | per boot `{boot, signin, gap_s}` (≤ 5), `fastest_gap_s`, `median_gap_s`, `startup_programs` (enabled count) and names (≤ 30) |
| `perf.power_plan` | `winreg` `HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\ActivePowerScheme` | `scheme_guid`, `name` (known GUIDs: Balanced 381b4222…, High performance 8c5e7fda…, Power saver a1841308…, Ultimate e9a42b02…; else "Custom") |
| `perf.hw_errors` | reuses the crash bundle's WHEA reader (7 days) | `processor`, `memory`, `pcie`, `fatal` counts, `last` |

**Startup timing caveat:** sign-in time includes however long the user sat
at the sign-in screen, so a single gap is not "boot time". The rule uses
the **fastest** of the last five gaps: if even the quickest sign-in took
over two minutes, startup itself is slow.

### 5.2 Escalation probes

| Key | Returns |
|---|---|
| `perf.cpu_long` | `perf.cpu` over 15 s, for slowness that comes and goes |
| `perf.app_detail` | For `app_name` (or the top CPU/memory app): every matching process's CPU share over 10 s, memory, running time, child count. Needs `app_name` optional |
| `perf.trend_7d` | `memory_percent`, `cpu_percent`, `cpu_temp_c` series over 7 days, summarised to daily max / median |

Each probe: `category="perf"`, `redact=("username", "serial", "mac", "self_host")`, `timeout_s` 8–20.

## 6. Rules and verdicts

Deterministic, first match leads (hardware risk, then cause of slowness,
then housekeeping); the model may add to a confident rule verdict but not
contradict it. When `app_name` is set, the CPU / memory rules look at that
app first (as a named drive does in PR 3), and a hardware risk elsewhere is
still added as an `also_<rule>` note.

| # | Rule key | Fires when | Headline | Status / locus |
|---|---|---|---|---|
| 1 | `thermal_throttling` | `min_tjmax_distance_c` ≤ 2 | "Your CPU hit N °C and is slowing itself down to cool off" | confident / local |
| 2 | `running_hot` | CPU `core_max_c` or `package_c` ≥ 90, or GPU temp ≥ 87 | "Your CPU is running hot (N °C)" / "Your graphics card is running hot (N °C)" | likely / local |
| 3 | `stuck_driver` | `perf.kernel.stuck` non-empty | "A Windows driver is pinning a CPU core" | confident / local |
| 4 | `cpu_hog` | One process ≥ 50 % of total CPU, or total ≥ 90 % and the top process ≥ 25 % | "APP is using N% of the CPU" | likely / local |
| 5 | `memory_low` | `used_pct` ≥ 90, `available_gb` < 2, or `swap_used_pct` ≥ 80 | "Memory is nearly full (N%); APP is using N GB" | confident / local |
| 6 | `memory_creep` | `uptime_h` ≥ 48 and memory up ≥ 25 points since boot, or a process ≥ 4 GB running ≥ 24 h | "Memory has crept from A% to B% over the N days since the last restart" / "APP has grown to N GB after N hours" | likely / local |
| 7 | `disk_busy` | A disk ≥ 90 % busy in the sample | "Drive … was N% busy during the check" (storage naming) | likely / local |
| 8 | `gpu_busy` | GPU `util_pct` ≥ 95 | "The graphics card is fully loaded (N%)" | likely / local |
| 9 | `power_saver` | Active plan is Power saver | "Windows' power-saving mode is limiting the CPU" | confident / local |
| 10 | `slow_startup` | `fastest_gap_s` > 120, or the last gap ≥ 2× `median_gap_s` and > 120 | "The last startup took N to reach sign-in; M programs start automatically" | likely / local |
| 11 | `long_uptime` | `uptime_h` ≥ 168 | "The PC hasn't been restarted in N days" | likely / local |
| — | `nothing_found` | None of the above | "Nothing is slowing the PC down right now" | **inconclusive** / unknown |

**Context annotations:** `hw_errors` (processor/memory WHEA in the window:
"Windows also logged N processor hardware errors this week; heat and these
errors often go together -- have the cooling checked"), `sensors_fallback`
(LHM not running: temperatures came from Windows' rougher sensors),
`since_boot` (memory/temperature movement since restart, when it adds
something), `also_<rule>` (a hardware-risk rule elsewhere when `app_name`
focused the pass).

**Built-in manual steps** (≤ 6 per verdict, `manual_steps` contract):

- `thermal_throttling` / `running_hot`: check the fans spin and the vents
  are clear and not dusty; if the PC was recently opened or repaired, have
  the CPU cooler and heat sinks checked; avoid long heavy work until it is
  fixed; watch it on the Temps & Power tab.
- `stuck_driver`: use **Identify driver** on Temps & Power, then update or
  roll back that driver.
- `cpu_hog`: close or restart APP; for a browser, close tabs or
  extensions; a Windows scan (Defender / `MsMpEng.exe`) usually finishes on
  its own; check the Processes tab.
- `memory_low` / `memory_creep`: restart APP; if the same app grows every
  time, update it (it is leaking memory); if memory is full every day,
  consider more RAM; restarting the PC clears it for now.
- `disk_busy`: check the Processes tab; run the storage check.
- `gpu_busy`: a game, video or AI app is using the graphics card; close it
  if you didn't mean it to run.
- `power_saver`: Settings › System › Power › Power mode → Balanced or Best
  performance.
- `slow_startup`: turn off programs you don't need on the Startup tab.
- `long_uptime`: restart the PC.

**Registry actions:** only `reboot_system`, only for `memory_creep` and
`long_uptime`. **Engine guard** (same pattern as PR 3's `clear_temp`): for
`class_key == "performance"`, `reboot_system` survives `apply_guards` only
when the rule verdict offered it.

**Model hint (`_PERF_PROMPT`):** evidence is this PC's live CPU, memory,
temperature, GPU, disk and driver readings plus history since the last
restart and recent startups (times UTC: convert with `local_utc_offset`).
Heat and hardware errors outrank slowness. Name apps by program name only.
Never suggest killing system processes, changing BIOS settings or
overclocking. `nothing_found` means inconclusive. Suggest `reboot_system`
only for memory creep or long uptime.

## 7. Privacy

- Processes appear by program name (`chrome.exe`) only: never window
  titles, command lines, paths or user names. Caps: top 5 per list, ≤ 30
  startup program names.
- Startup program names come from the Run keys / Startup folder names, not
  their command lines.
- Redaction classes on every perf probe: `username`, `serial`, `mac`,
  `self_host` (the LHM tree carries the PC name; the probe drops it and the
  class guards it).
- The egress preview and "nothing leaves until you click Send" are unchanged.

## 8. Classifier

- **Strong words** (always this class, whole words): `hot`, `overheat\w*`,
  `temperature`, `temps?`, `fans?` (with loud / noisy / racing / spinning /
  running), `throttl\w*`, `high cpu`, `\d+ ?% cpu`, `cpu usage`, `memory`,
  `ram`, `out of memory`, `slow to (start|boot)`, `slow (startup|boot)`,
  `takes forever to (start|boot)`.
- **Weak words:** `slow\w*`, `sluggish`, `lag\w*`, `stutter\w*`.
- **Order inside `classify()`:** storage (PR 3) → crash (strong crash words;
  "won't start" stays crashes) → **performance** → network.
  - Weak words with a network word or host → leave to the network branch
    (unchanged behaviour: "the internet is slow").
  - Strong words with a network word or host → ask (`symptom_class: None`).
  - "slow to start" is performance; "won't start" is crashes.
- **App name** (`extract_perf_app`): `<App> is slow / laggy / hot / using
  (all) my CPU|memory|RAM / eating my CPU|memory`, 1–3 words before the
  verb, reusing the crash class's generic-word list ("computer", "PC",
  "it", "Windows", …) so "my computer is slow" names no app.
- Table-tested (§9), including P1 and P7 verbatim.

## 9. Testing

Fixtures (`tests/fixtures/diagnose/perf_*.json`, replayed by the existing
fixture test):

| Fixture | Expect |
|---|---|
| `perf_throttling_whea_2026_10.json` (100 °C, distance 0, 110 processor WHEA) | `thermal_throttling` + `hw_errors` (P2) |
| `perf_running_hot.json` (93 °C, distance 7) | `running_hot` |
| `perf_gpu_hot.json` | `running_hot` (GPU wording) |
| `perf_stuck_driver.json` | `stuck_driver` |
| `perf_cpu_hog_chrome.json` | `cpu_hog`, names chrome.exe (P3) |
| `perf_memory_low.json` | `memory_low` |
| `perf_memory_creep.json` (uptime 96 h, 40 → 85 %) | `memory_creep` + `reboot_system` |
| `perf_disk_busy.json` | `disk_busy` |
| `perf_gpu_busy.json` | `gpu_busy` |
| `perf_power_saver.json` | `power_saver` |
| `perf_slow_startup.json` (fastest gap 190 s, 24 programs) | `slow_startup` |
| `perf_long_uptime.json` | `long_uptime` + `reboot_system` |
| `perf_idle_2026_10_17.json` (this PC idle, LHM 70 °C, distance ≥ 31) | `nothing_found` (P5) |

Also:

- **Probe tests** per probe: happy / empty / malformed / source failure /
  timeout; LHM missing → Windows fallback; psutil `AccessDenied` on some
  processes; `metrics_history` empty; unreadable startup events.
- **Rules:** thresholds at their boundaries; app focus leads with
  `also_thermal_throttling` kept; `nothing_found` reasoning lists unread
  sources.
- **Classifier table:** P1 and P7 verbatim, "Teams is eating my RAM"
  (app), "my computer is slow" (no app), "the internet is slow and my PC
  is hot" (ask), "slow to start" vs "won't start".
- **Guards:** `reboot_system` dropped for `performance` unless the rules
  offered it; network/crash/storage behaviour unchanged.
- **Redaction (P4):** planted window title, command line, path, user name
  and PC name absent from the payload.
- **Routes:** `/api/diagnose/classes` lists `performance` with
  `optional_slots: ["app_name"]`.
- **Playwright:** "my PC is slow and running hot" starts a performance
  session with no ask; the app row shows for `performance`.
- **Live acceptance:** after deploy, run *"my PC is slow"* at idle and
  compare with the Temps & Power tab; then a light, short load (one Python
  process busy on one core for ~10 s; no heavy load while the VR heat sink
  is unfixed) must name that process as `cpu_hog` if it crosses the
  threshold, or explain why not. Backlog #63 is not marked shipped until
  both match.

## 10. Decomposition and architecture.html

One PR: probes → rules → class + classifier + guard → fixtures/tests →
`architecture.html` (two new root files, two new test files, fixture count,
test count, line counts, "four symptom classes"). Deferred review findings
become backlog rows before close-out (standing rule, 2026-10-17).
