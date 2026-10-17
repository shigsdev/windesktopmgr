# Diagnose Speed & Heat Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `performance` symptom class ("Speed & heat") to Diagnose that reads this PC's live CPU, memory, temperatures, GPU, stuck-driver detector, disk activity, history since boot, startup timing, power plan and hardware errors, and returns a rule-based verdict with plain-language steps.

**Architecture:** Two new modules mirror the storage bundle. `diagnose_perf_probes.py` registers 10 wave-one + 3 escalation read-only probes into `diagnose_probes.PROBES`. `diagnose_perf_rules.py` holds the classifier helpers, 11 ordered rules + `nothing_found`, context annotations and steps. `diagnose.py` gains the class entry, `_PERF_PROMPT`, a `classify()` branch and the `reboot_system` guard. The UI already shows the app row for any class with `optional_slots: ("app_name",)`.

**Tech Stack:** Python 3.14, Flask blueprint, `psutil`, `winreg`, existing `lhm`, `thermals`, `gpu`, `kernel_cpu`, `metrics_history`, `diagnose_crash_probes` (event reader, WHEA), `diagnose_storage_probes._io_sample`, pytest + pytest-mock, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-17-diagnose-perf-bundle-design.md` (parent: `2026-10-01-diagnostic-engine-design.md`; pattern: `docs/superpowers/plans/2026-10-13-diagnose-storage-bundle.md`)

## Global Constraints

- Class key `performance`, label `"Speed & heat"`, `slots: ()`, `optional_slots: ("app_name",)`, `actions: ("reboot_system",)`.
- Every perf probe: `category="perf"`, `redact=("username", "serial", "mac", "self_host")`, `timeout_s` 8–20 (`perf.cpu_long` 20, `perf.app_detail` 15, others ≤ 12).
- Read-only, unelevated, no PowerShell. No probe kills, changes or starts anything (LHM is read via `lhm._fetch_data_json()` only, never launched).
- Processes are named by program name only (`proc.info["name"]`, e.g. `chrome.exe`). `psutil.process_iter` is called with `attrs` drawn only from `{"pid", "name", "cpu_times", "memory_info", "create_time", "num_threads"}`; never `cmdline`, `exe`, `cwd`, `username`, window titles. Same-name processes are **grouped** (summed) so "chrome.exe" means all Chrome processes; each row keeps `count` and the busiest instance's `pid`.
- Caps: top 5 per process list, ≤ 5 startup gaps, ≤ 30 startup program names. LHM node text above the hardware level (the PC name) is never copied.
- Constants: `CPU_SAMPLE_S = 3`, `CPU_LONG_S = 15`, `APP_DETAIL_S = 10`, `STARTUP_DAYS = 14`, `WHEA_DAYS = 7`, `TREND_DAYS = 7`.
- Thresholds (spec §6): `THROTTLE_DISTANCE_C = 2`; `HOT_CPU_C = 90`; `HOT_GPU_C = 87`; `HOG_PCT = 50`, `HOG_TOTAL_PCT = 90`, `HOG_TOP_PCT = 25`; `MEM_USED_PCT = 90`, `MEM_AVAIL_GB = 2`, `SWAP_PCT = 80`; `CREEP_UPTIME_H = 48`, `CREEP_POINTS = 25`, `CREEP_APP_GB = 4`, `CREEP_APP_H = 24`; `DISK_BUSY_PCT = 90`; `GPU_BUSY_PCT = 95`; `SLOW_START_S = 120`; `LONG_UPTIME_H = 168`.
- Rule order: `thermal_throttling` > `running_hot` > `stuck_driver` > `cpu_hog` > `memory_low` > `memory_creep` > `disk_busy` > `gpu_busy` > `power_saver` > `slow_startup` > `long_uptime` > `nothing_found`. Status/locus per spec §6 table; `nothing_found` is `inconclusive` / `unknown`.
- `reboot_system` offered by the rules only for `memory_creep` and `long_uptime`; the engine drops it for `class_key == "performance"` unless the rule verdict offered it. Every other perf verdict `suggested_actions == []`.
- Power plan GUIDs: Balanced `381b4222-f694-41f0-9685-ff5bb260df2e`, High performance `8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`, Power saver `a1841308-3541-4fab-bc81-f71556f20b4a`, Ultimate `e9a42b02-d5df-448d-aa00-03f14749eb61`; anything else `"Custom"`.
- Event-log times are UTC ISO (`2026-10-17T12:08:53Z`); `metrics_history` timestamps are local naive ISO.
- Commits: `export PATH="/c/Users/higs7/AppData/Local/Python/pythoncore-3.14-64:$PATH"`, `PYTEST_DEBUG_TEMPROOT=<fresh scratchpad dir>`, `< /dev/null`. Ruff via `C:/Users/higs7/.cache/pre-commit/repo9x_k88ol/py_env-python3.14/Scripts/ruff.exe`.

## Review Focus

1. **psutil `AccessDenied` / `NoSuchProcess` mid-sample** (system processes, a process that exits between the two snapshots). Must be skipped, never raise, never count as 0 % of a missing process. Pinned in Task 1 (`test_cpu_skips_denied_and_vanished`).
2. **"System Idle Process" (pid 0) and `Idle`** report the idle CPU as a share; it must never be named a `cpu_hog`. Pinned in Task 1 (`test_cpu_excludes_idle`).
3. **LHM running but with no CPU "Distance to TjMax" sensors** (AMD CPUs, an older LHM): `min_tjmax_distance_c is None` and `thermal_throttling` must not fire; `running_hot` still works off `core_max_c`. Pinned in Task 2 (`test_thermals_no_distance_sensors`) and Task 4 (`test_no_distance_never_throttles`).
4. **The 3 s sample catching a short spike from the app itself** (the tray's own `python.exe` / `pythonw.exe` doing the sampling). The probe excludes its own PID (`os.getpid()`). Pinned in Task 1 (`test_cpu_excludes_own_process`).
5. **A startup gap with no sign-in** (PC booted, nobody signed in, or 7001 missing after a crash). That boot is skipped, not paired with the next boot's sign-in. Pinned in Task 3 (`test_startup_boot_without_signin_is_skipped`).

---

### Task 1: Scaffold, `perf.cpu`, `perf.memory`, class entry

**Files:**
- Create: `diagnose_perf_probes.py`, `diagnose_perf_rules.py`
- Create: `tests/test_diagnose_perf_probes.py`
- Modify: `diagnose.py` (imports `import diagnose_perf_probes  # noqa: F401 -- registers the perf probes into dp.PROBES` and `import diagnose_perf_rules as dpr`; `_PERF_PROMPT`; `SYMPTOM_CLASSES["performance"]`)
- Modify: `tests/test_diagnose.py` (`TestSymptomClassesShape` if it pins the class list)

**Interfaces:**
- Produces:
  - `REGISTERED: dict[str, dp.Probe]`; `_perf_probe(key, label, fn, timeout_s=10.0, **kw) -> dp.Probe` (same shape as `diagnose_storage_probes._storage_probe`, `category="perf"`, `redact=_REDACT`).
  - `app_matches(app_name: str | None, exe: str) -> bool`: lowercase both, strip `.exe`, drop non-alphanumerics; true when the exe stem contains any app-name word of ≥ 3 letters other than `microsoft`/`google`/`the`, or the joined app name contains the exe stem. `("Chrome", "chrome.exe")`, `("Microsoft Teams", "ms-teams.exe")`, `("google chrome", "chrome.exe")` → True; `("Teams", "chrome.exe")`, `(None, "chrome.exe")`, `("", "x.exe")` → False.
  - `cpu_sample(seconds: float) -> dict` (shared by `perf.cpu`, `perf.cpu_long`, `perf.app_detail`): `{"seconds", "total_pct", "busiest_core_pct", "cores", "top": [{"name", "pid", "count", "cpu_pct"}]}` (top 5 by `cpu_pct`, share of the whole CPU 0–100, one decimal).
  - Probe `perf.cpu` (label "What's using the CPU", `needs_optional=("app_name",)`): `cpu_sample(CPU_SAMPLE_S)` plus `"focus_app": str | None` (the slot, stripped) and `"focus": {"name", "cpu_pct", "count"} | None` (the summed matching processes via `app_matches`).
  - Probe `perf.memory` (label "Memory use", `needs_optional=("app_name",)`): `{"used_pct", "available_gb", "total_gb", "swap_used_pct", "top": [{"name", "pid", "count", "rss_gb", "running_h"}], "focus": {...} | None}`; `running_h` from the oldest same-name process's `create_time`.
  - `evaluate_perf_rules(evidence: dict[str, dict]) -> dict` stub in `diagnose_perf_rules.py`: always the `nothing_found` verdict (filled in Task 4).
  - `SYMPTOM_CLASSES["performance"]` per Global Constraints with `wave1 = ("perf.cpu", "perf.memory")`, `escalate = ()`, `"rules": lambda evidence, host: dpr.evaluate_perf_rules(evidence)`, `"prompt": _PERF_PROMPT` (spec §6 model hint text). Later tasks append keys.

- [ ] **Step 1: Write the failing tests** (`TestAppMatches`, `TestCpu`, `TestMemory`, `TestRegistry`), mocking `diagnose_perf_probes.psutil` and `diagnose_perf_probes.time.sleep`:
  - `test_app_matches` parametrized over the cases above.
  - `test_cpu_groups_by_name_and_shares_whole_cpu`: 8 cores, 3 s; three `chrome.exe` processes with Δcpu_times (user+system) 6 s, 3 s, 3 s and one `code.exe` 1.2 s → `top[0] == {"name": "chrome.exe", "pid": <busiest>, "count": 3, "cpu_pct": 50.0}`, `top[1]["cpu_pct"] == 5.0`.
  - `test_cpu_excludes_idle` (RF2): pid 0 `System Idle Process` with Δ 20 s → absent from `top`.
  - `test_cpu_excludes_own_process` (RF4): a process with `pid == os.getpid()` → absent.
  - `test_cpu_skips_denied_and_vanished` (RF1): one process raising `psutil.AccessDenied` on `cpu_times`, one present only in the first snapshot → no raise, neither listed.
  - `test_cpu_focus_app`: slots `{"app_name": " Chrome "}` → `focus_app == "Chrome"`, `focus["cpu_pct"] == 50.0`, `focus["count"] == 3`.
  - `test_cpu_never_asks_for_identifying_attrs`: every `process_iter` call's `attrs` ⊆ the Global Constraints set.
  - `test_memory_happy_path`: `virtual_memory` (total 64 GiB, available 1.5 GiB, percent 97.7), `swap_memory` percent 85 → `used_pct == 97.7`, `available_gb == 1.5`, `swap_used_pct == 85`; two `Teams.exe` 3 GiB + 2 GiB, oldest created 30 h ago → `top[0]` `rss_gb 5.0`, `count 2`, `running_h 30.0`.
  - `test_memory_psutil_failure_is_not_ok`: `virtual_memory` raises → the probe raises (the engine records `ok: False`); per-process `AccessDenied` only skips that process.
  - `test_registry_invariants`: every key in `REGISTERED` is in `dp.PROBES` with `category == "perf"`, `redact == ("username", "serial", "mac", "self_host")`, `8 <= timeout_s <= 20`.
- [ ] **Step 2:** `python -m pytest tests/test_diagnose_perf_probes.py --no-cov` → FAIL (module missing).
- [ ] **Step 3: Implement.** Two snapshots of `{pid: (name, user+system seconds)}` around `time.sleep(seconds)`, `psutil.cpu_percent(percpu=True)` primed before the sleep and read after (gives `busiest_core_pct`, `cores = psutil.cpu_count()`), `total_pct = psutil.cpu_percent()` read the same way. Share = Δ / (seconds × cores) × 100. Skip pid 0, name `Idle`/`System Idle Process`, own pid, and any process missing from either snapshot. Add the class entry, imports and `_PERF_PROMPT` in the same commit (registry invariant: every registered probe must belong to a class).
- [ ] **Step 4:** `python -m pytest tests/test_diagnose_perf_probes.py tests/test_diagnose_probes.py tests/test_diagnose.py -k "perf or Registry or registered or SymptomClasses" --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): perf probe scaffold + CPU and memory (#63 PR 4)`.

### Task 2: Readers of existing monitors: thermals, GPU, kernel, disk, hardware errors

**Files:**
- Modify: `diagnose_perf_probes.py`, `diagnose.py` (append the 5 keys to `wave1`)
- Test: `tests/test_diagnose_perf_probes.py` (`TestThermals`, `TestGpu`, `TestKernel`, `TestDiskBusy`, `TestHwErrors`)

**Interfaces:**
- Consumes: `lhm._fetch_data_json() -> dict | None`, `lhm._parse_temp_value(str) -> float | None`, `thermals.get_thermals() -> {"temps": [{"Name", "TempC", "Source"}], "fans": [...], ...}`, `gpu.get_gpu_metrics() -> {"available", "name", "utilization_pct", "temp_c", "vram_pct", ...}`, `kernel_cpu.sample() -> {"available", "busiest": {"tid", "pct"} | None, "stuck": [{"tid", "pct", "minutes"}], ...}`, `diagnose_storage_probes._io_sample(seconds) -> {"seconds", "disks": [...]}`, `diagnose_storage_probes.collect_physical_disks()`, `diagnose_crash_probes._p_whea(slots, days) -> {"fatal", "corrected", "by_component": {"processor", "memory", "pcie", "other"}, "first", "last"}`.
- Produces:
  - `parse_lhm_cpu(tree: object) -> dict` (pure): `{"package_c", "core_max_c", "min_tjmax_distance_c", "tjmax_c", "package_w", "p_core_mhz", "fans": [{"name", "rpm"}], "gpu_temp_c"}`; each value `None` when its sensor is absent. CPU sensors are leaves whose `SensorId` starts `/intelcpu/` or `/amdcpu/`; GPU leaves `/gpu-`. `package_c` = Temperature "CPU Package" (or "Core (Tctl/Tdie)"); `core_max_c` = "Core Max" else the max non-distance core temp; `min_tjmax_distance_c` = min over Temperature leaves whose `Text` ends "Distance to TjMax"; `tjmax_c` = a core's temp + its own distance when both exist for the same core name; `package_w` = Power "CPU Package"; `p_core_mhz` = max Clock leaf whose Text starts "P-Core" (else "Core"); fans = every `Type == "Fan"` leaf; `gpu_temp_c` = GPU Temperature "GPU Core". Depth cap 64, never raises.
  - Probe `perf.thermals` (label "Temperatures and fans"): `{"source": "lhm" | "windows" | "none", **parse_lhm_cpu(...)}`; with no LHM tree, `source "windows"` with `core_max_c` = max `TempC` from `thermals.get_thermals()["temps"]` and its fans, distances `None`; `"none"` when neither reads.
  - Probe `perf.gpu` (label "Graphics card"): `{"available", "name", "util_pct", "temp_c", "vram_pct"}` (`util_pct` ← `utilization_pct`).
  - Probe `perf.kernel` (label "Stuck driver check"): `{"available", "warming_up": bool, "busiest", "stuck"}` from `kernel_cpu.sample()`.
  - Probe `perf.disk_busy` (label "Drive activity"): `_io_sample(CPU_SAMPLE_S)` with each disk gaining `"name"` = the storage naming (`diagnose_storage_rules._name(drive)` for the matching `disk_number` in `collect_physical_disks()["drives"]`, else `f"Disk {n}"`).
  - Probe `perf.hw_errors` (label "Hardware error reports"): `{"processor", "memory", "pcie", "fatal", "corrected", "last"}` from `_p_whea({}, days=WHEA_DAYS)`.

- [ ] **Step 1: Write the failing tests**, with a trimmed LHM tree built in the test from the live 2026-10-17 shape (root `Text "Sensor"` → `Text "SHIGS78-PC24"` → `Text "Intel Core i9-14900K"` → groups `Temperatures`/`Powers`/`Clocks`/`Fans`; leaves `{"Text", "Type", "Value": "51.0 °C", "SensorId": "/intelcpu/0/temperature/26"}`; plus `NVIDIA GeForce RTX 4060 Ti` with `GPU Core 45.0 °C`):
  - `test_parse_lhm_cpu_live_shape`: package 51.0, core_max 51.0, `min_tjmax_distance_c == 49.0` (P-Core #5), `tjmax_c == 100.0` (P-Core #1 41 + 59), package_w 48.9, p_core_mhz 1394.4, gpu_temp_c 45.0.
  - `test_thermals_never_carries_pc_name`: `"SHIGS78-PC24" not in json.dumps(probe data)`.
  - `test_thermals_no_distance_sensors` (RF3): tree with temps but no distance leaves → `min_tjmax_distance_c is None`, `core_max_c` set.
  - `test_thermals_windows_fallback`: `_fetch_data_json` → `None`, `get_thermals` temps `[{"Name": "TZ00", "TempC": 88.0}]` → `source "windows"`, `core_max_c 88.0`.
  - `test_thermals_none_when_both_fail`: `get_thermals` raises → `source "none"`, still ok.
  - `test_parse_lhm_cpu_malformed` parametrized `None`, `[]`, `{"Children": "x"}`, a 70-deep tree → all-`None` dict, no raise.
  - `test_gpu_maps_utilization`: `utilization_pct 97` → `util_pct 97`; `get_gpu_metrics` raises → `available False`.
  - `test_kernel_stuck_passthrough` and `test_kernel_warming_up`.
  - `test_disk_busy_names_drives`: `_io_sample` mocked with disk 0 busy 100, physical disks mocked with disk 0 `label_serial_tail "5B40"` → `name` contains `"…5B40"`; disk 9 unknown → `"Disk 9"`; asserts `_io_sample` called with `3`.
  - `test_hw_errors_counts`: `_p_whea` mocked `{"fatal": 0, "corrected": 110, "by_component": {"processor": 110, ...}, "last": "2026-10-17T11:00:00Z"}` → `processor 110`; asserts `days=7`.
- [ ] **Step 2:** run the new classes → FAIL.
- [ ] **Step 3: Implement** the five probes and append them to `wave1` in spec §5.1 order.
- [ ] **Step 4:** `python -m pytest tests/test_diagnose_perf_probes.py tests/test_diagnose_probes.py --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): perf thermals, GPU, driver, disk, WHEA probes (#63 PR 4)`.

### Task 3: History, startup, power plan, escalations

**Files:**
- Modify: `diagnose_perf_probes.py`, `diagnose.py` (append 3 keys to `wave1`; `escalate = ("perf.cpu_long", "perf.app_detail", "perf.trend_7d")`)
- Test: `tests/test_diagnose_perf_probes.py` (`TestSinceBoot`, `TestStartup`, `TestPowerPlan`, `TestEscalation`)

**Interfaces:**
- Consumes: `psutil.boot_time()`, `metrics_history.get_series(metric, window: timedelta) -> [{"ts", "value"}]`, `diagnose_crash_probes._query(channel, xpath, unavailable, max_events=...)`, `window_xpath(ids=, providers=, days=)`, `windesktopmgr.get_startup_items() -> [{"Name", "Enabled", ...}]` (imported lazily inside the probe: `windesktopmgr` imports `diagnose`), `winreg`.
- Produces:
  - `perf.since_boot` (label "Since the last restart"): `{"uptime_h", "boot" (UTC ISO), "memory_first_pct", "memory_now_pct", "temp_max_c", "samples"}`; window = now − boot; first/last `memory_percent` sample and max `cpu_temp_c`; `None`s and `samples 0` when history is empty.
  - `pair_startups(boots: list[str], signins: list[str]) -> list[dict]` (pure): for each boot (newest first) the first sign-in after it and before the next later boot → `{"boot", "signin", "gap_s"}`; a boot with none is skipped (RF5); ≤ 5 rows.
  - `perf.startup` (label "Startup time"): `{"boots": [...], "fastest_gap_s", "median_gap_s", "last_gap_s", "startup_programs": int (enabled), "program_names": list[str] (≤ 30, enabled only), "unavailable": list[str]}`. Boots = System `Microsoft-Windows-Kernel-General` 12; sign-ins = System `Microsoft-Windows-Winlogon` 7001; `STARTUP_DAYS`. Gap stats `None` with no pairs. Only `Name` is read from startup items, never `Command`.
  - `perf.power_plan` (label "Power plan"): `{"scheme_guid", "name"}`; `name "Unknown"` when the key is unreadable.
  - `perf.cpu_long` (label "What's using the CPU (15 s)", timeout 20): `cpu_sample(CPU_LONG_S)`.
  - `perf.app_detail` (label "App detail", `needs_optional=("app_name",)`, timeout 15): for `app_name`, else the top CPU process name from a fresh 1 s sample: `{"app", "matched": int, "cpu_pct" (over APP_DETAIL_S), "rss_gb", "running_h", "children": int}`; `matched 0` when nothing matches.
  - `perf.trend_7d` (label "Last 7 days"): per metric in (`memory_percent`, `cpu_percent`, `cpu_temp_c`): `[{"day": "YYYY-MM-DD", "max", "median"}]` (≤ 7 days).

- [ ] **Step 1: Write the failing tests:**
  - `test_since_boot_memory_movement`: boot 96 h ago, series memory 40 → 85, temps max 99 → `uptime_h 96.0`, `memory_first_pct 40`, `memory_now_pct 85`, `temp_max_c 99`; asserts `get_series` window ≈ 96 h.
  - `test_since_boot_empty_history`: `samples 0`, values `None`, ok.
  - `test_pair_startups_live_shape`: the live 2026-10-17 pairs (boots `12:08:53Z`, `2026-10-16T12:24:48Z`; sign-ins `12:25:10Z`, `2026-10-16T12:26:14Z`) → gaps 977 and 86.
  - `test_startup_boot_without_signin_is_skipped` (RF5): boots A < B, one sign-in after B → one row (B), A not paired with B's sign-in.
  - `test_startup_fastest_and_median`: gaps 190, 200, 400 → `fastest_gap_s 190`, `median_gap_s 200`.
  - `test_startup_names_only`: items `{"Name": "OneDrive", "Command": "C:\\Users\\higs7\\...", "Enabled": True}`, one disabled → `startup_programs 1`, `program_names ["OneDrive"]`, `"higs7" not in json.dumps(data)`.
  - `test_startup_unreadable_log`: `_query` records `System` in `unavailable` → stats `None`, ok.
  - `test_power_plan_known_and_custom` parametrized over the four GUIDs + a random one (mock `winreg.OpenKey`/`QueryValueEx`); `OSError` → `"Unknown"`.
  - `test_cpu_long_uses_15s`, `test_app_detail_matches_named_app`, `test_app_detail_no_match`, `test_trend_daily_max_median`.
  - `test_wave1_and_escalate_complete`: `SYMPTOM_CLASSES["performance"]["wave1"]` equals the spec §5.1 10 keys in order; `escalate` equals the 3 §5.2 keys.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** the six probes and the class key lists.
- [ ] **Step 4:** `python -m pytest tests/test_diagnose_perf_probes.py tests/test_diagnose_probes.py --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): perf history, startup, power plan, escalation probes (#63 PR 4)`.

### Task 4: Rules, annotations, steps and fixtures

**Files:**
- Modify: `diagnose_perf_rules.py`
- Create: `tests/test_diagnose_perf_rules.py`
- Create: `tests/fixtures/diagnose/perf_*.json` (13, spec §9 table)
- Modify: `tests/test_diagnose.py` (`test_rule_fixture` dispatches `"performance"` to `_check_perf_fixture`, mirroring `_check_storage_fixture` with allowed actions `{"reboot_system"}`)

**Interfaces:**
- Consumes: probe data shapes from Tasks 1–3; `dg._verdict`, `dg.clean_steps`, `dg.MAX_MANUAL_STEPS`.
- Produces: `evaluate_perf_rules(evidence) -> dict` (full verdict; `rule_hits[0]` the rule key, then context keys). Focus app read from `evidence["perf.cpu"]["data"]["focus_app"]`.

- [ ] **Step 1: Write the fixtures and failing tests.** Fixture format as the storage ones (`symptom`, `symptom_class: "performance"`, `evidence`, `expect: {"rule","status","locus","must_include","must_exclude","context"}`). Expectations per spec §9; additionally `perf_memory_creep` and `perf_long_uptime` `must_include: ["reboot_system"]`, every other fixture `must_exclude: ["reboot_system"]`; `perf_throttling_whea_2026_10` `context: ["hw_errors"]`. Unit tests:
  - Boundaries, each parametrized just-in / just-out: distance 2 / 3; CPU 90 / 89.9; GPU 87 / 86.9; hog 50 / 49.9; total 90 + top 25 / total 89.9; memory 90 % / 89.9 %, avail 1.99 / 2.0 GB, swap 80 / 79.9; creep uptime 48 h + 25 pts / 47.9 h; app 4 GB + 24 h / 23.9 h; disk 90 / 89; GPU busy 95 / 94; startup fastest 121 / 120; last ≥ 2× median and > 120; uptime 168 / 167.9.
  - `test_order_hardware_risk_first`: throttling + cpu_hog evidence → `thermal_throttling` leads.
  - `test_no_distance_never_throttles` (RF3): distance `None`, core 95 → `running_hot`.
  - `test_running_hot_gpu_wording`: headline contains "graphics card".
  - `test_cpu_hog_names_app` (P3): headline `"chrome.exe is using 50% of the CPU"`.
  - `test_focus_app_leads_with_also` : focus Teams at 6 GB / 30 h (creep) plus distance 1 → `memory_creep` leads, `"also_thermal_throttling" in rule_hits`, reasoning says "Also:".
  - `test_hw_errors_annotation`: 110 processor WHEA → `"hw_errors" in rule_hits` and the spec §6 sentence with 110.
  - `test_sensors_fallback_annotation`: `source "windows"` → `"sensors_fallback"`.
  - `test_nothing_found_lists_unread` (P5): a perf probe `ok: False` → inconclusive, reasoning names it.
  - `test_reboot_only_for_creep_and_uptime`: across all fixtures `suggested_actions ⊆ {"reboot_system"}` and non-empty only for those two rules.
  - `test_steps_capped_and_never_kill_system`: every verdict ≤ `MAX_MANUAL_STEPS`; no step matches `r"taskkill|end task.*(system|svchost|csrss|MsMpEng)|bios|overclock"` (case-insensitive) except the `cpu_hog` Defender note, which says it finishes on its own.
- [ ] **Step 2:** `python -m pytest tests/test_diagnose_perf_rules.py tests/test_diagnose.py -k "perf or fixture" --no-cov` → FAIL.
- [ ] **Step 3: Implement** `_RULES` as an ordered tuple of `_rule_*(ev, focus) -> tuple[str, dict, list[str]] | None` (key, verdict, evidence_refs); the CPU/memory rules check `perf.cpu.focus` / `perf.memory.focus` first when a focus app is set. `_context(ev, key) -> (hits, lines)` adds `hw_errors`, `sensors_fallback`, `since_boot`; `also_<rule>` when a focus led and the unfocused pass found `thermal_throttling` or `running_hot`. `_STEPS[key]` holds spec §6 steps with `APP` filled. Headlines are the spec §6 strings; temperatures as whole °C, percentages whole, GB one decimal, days = `uptime_h / 24` rounded. `reboot_system` set in `evaluate_perf_rules` after the winning rule, keyed on `memory_creep` / `long_uptime`.
- [ ] **Step 4:** same command → PASS.
- [ ] **Step 5:** commit `feat(diagnose): perf rules, steps and fixtures (#63 PR 4)`.

### Task 5: `reboot_system` guard and payload redaction

**Files:**
- Modify: `diagnose.py` (`apply_guards`: after the storage `clear_temp` guard, the same pattern for `class_key == "performance"` and `reboot_system`)
- Test: `tests/test_diagnose.py` (`TestApplyGuards`, `TestRedact`)

- [ ] **Step 1: Write the failing tests:**
  - `test_perf_reboot_dropped_unless_rules_offered`: model verdict `suggested_actions ["reboot_system"]`, rule verdict without it → `[]`; with rule `["reboot_system"]` → kept.
  - `test_perf_other_actions_dropped`: model `["clear_temp", "flush_dns"]` for performance → `[]` (class allowlist).
  - `test_reboot_guard_leaves_other_classes`: an unrestricted class keeps `reboot_system` as before.
  - `test_perf_evidence_leaks_nothing_into_the_payload` (P4), mirroring `test_storage_evidence_leaks_nothing_into_the_payload`: perf evidence with a planted user name (`higs7`) in a startup program name, the PC name in a GPU name, and a serial-shaped string → none in `build_payload`; `chrome.exe` and `98` °C survive.
- [ ] **Step 2:** `python -m pytest tests/test_diagnose.py -k "perf or reboot" --no-cov` → FAIL (first test).
- [ ] **Step 3: Implement** the guard (one `if` block and its one-line comment).
- [ ] **Step 4:** same command → PASS.
- [ ] **Step 5:** commit `feat(diagnose): reboot_system guard for performance (#63 PR 4)`.

### Task 6: Classifier

**Files:**
- Modify: `diagnose_perf_rules.py` (`PERF_STRONG_RE`, `PERF_WEAK_RE`, `extract_perf_app`)
- Modify: `diagnose.py` (`classify()`)
- Test: `tests/test_diagnose.py` (`TestClassify`, `TestRoutes`), `tests/test_diagnose_perf_rules.py` (`TestPerfClassifier`)

**Interfaces:**
- Produces: `PERF_STRONG_RE`, `PERF_WEAK_RE` (spec §8 word lists, whole words, case-insensitive; `fans?` only with loud/noisy/racing/spinning/running within 3 words); `extract_perf_app(text: str) -> str | None` (`<1–3 words> (is|are|keeps?|has been)? (slow|laggy|lagging|hot|using (all )?(my|the) (cpu|memory|ram)|eating (my|the|all) (cpu|memory|ram))`, filler/generic words from `diagnose_crash_rules._LEADING_FILLER` / `_GENERIC`); `classify()` returns `{"symptom_class": "performance", "slots": {"app_name": ...} | {}, "candidates": [], "missing": []}`.

- [ ] **Step 1: Write the failing table test** `test_perf_classification` parametrized `(sentence, class, slots)`:
  - `"my PC is slow and running hot"` → `performance`, `{}` (P1)
  - `"Chrome is slow"` → `performance`, `{"app_name": "Chrome"}` (P1)
  - `"Teams is eating my RAM"` → `performance`, `{"app_name": "Teams"}`
  - `"my computer is slow"` → `performance`, `{}`
  - `"fans are really loud"` → `performance`, `{}`
  - `"100% cpu all the time"` → `performance`, `{}`
  - `"slow to start"` → `performance`, `{}`; `"won't start"` → `crashes`
  - `"the internet is slow"` → `network_dns` (P7); `"E: is slow"` → `storage`, `{"drive": "E:"}` (P7); `"the PC froze"` → `crashes` (P7)
  - `"the internet is slow and my PC is hot"` → `None` (ask)
  - `"my PC is slow since I rebooted"` → `performance` (weak crash word yields to perf)
  - `"I love my fans"` → `None` (fan needs a noise word)
  - `"example.com won't load"` → `network_dns`; `"the computer crashed last evening - cna you investigate?"` → `crashes` (regressions)
  
  Plus `test_classes_route_lists_performance`: `GET /api/diagnose/classes` includes `{"key": "performance", "label": "Speed & heat", "optional_slots": ["app_name"]}`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** Branch order in `classify()`: storage (unchanged) → crash branch only when `STRONG_CRASH_RE` matches, or `CRASH_RE` matches with no perf word → **performance** → network. Performance: strong word + (host candidate or network word) → `None`; weak word only + (host or network word) → fall through to network; else `performance` with `extract_perf_app` slot.
- [ ] **Step 4:** `python -m pytest tests/test_diagnose.py tests/test_diagnose_perf_rules.py tests/test_diagnose_storage_rules.py tests/test_diagnose_crash_rules.py --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): Speed & heat classifier (#63 PR 4)`.

### Task 7: UI check and Playwright

**Files:**
- Test: `tests/test_playwright_smoke.py` (`TestDiagnoseTab`)
- Modify (only if Step 2 shows a gap): `static/js/app.js`

- [ ] **Step 1: Write the Playwright tests:** `test_perf_sentence_starts_without_ask` ("my PC is slow and running hot" → session starts, no host prompt, class shown as "Speed & heat"); `test_app_row_shows_for_performance` (`#dx-app-row` visible after picking `performance`, hidden for `storage` and `network_dns`).
- [ ] **Step 2:** serve the branch on port 5055 (scratch launcher, gitignored `.claude/launch.json` entry; check no other session is running Playwright first): `WDM_BASE_URL=http://localhost:5055 pytest tests/test_playwright_smoke.py -m playwright --no-cov -k "perf or app_row"` → PASS expected (the app row is already generic via `dx_classHasOptional`); fix `app.js` only on a FAIL.
- [ ] **Step 3:** whole `TestDiagnoseTab` → PASS. Remove the launcher entry.
- [ ] **Step 4:** commit `test(diagnose): Speed & heat Playwright smoke (#63 PR 4)`.

### Task 8: Ship: review, docs, deploy, live acceptance

**Files:**
- Modify: `architecture.html` (new root files `diagnose_perf_probes.py`, `diagnose_perf_rules.py`; new tests `tests/test_diagnose_perf_probes.py`, `tests/test_diagnose_perf_rules.py` (also in `TEST_FILES` of `tests/test_architecture_html.py`); probe count +13; fixture count +13; test count; line counts; "four symptom classes". `/arch-update` first, then hand-edit file chips)
- Memory: `project_backlog.md` (#63; a row per deferred review finding), `project_diagnose_engine_2026-10-01.md`

- [ ] **Step 1:** ruff check + format → clean; `python -m pytest tests/ -n auto -p no:cacheprovider --color=no` → all pass, ≥ 80 %.
- [ ] **Step 2:** whole-branch review (opus subagent), fix Important findings test-first; `/code-review low`; `/code-simplifier` (> 200 LOC). Resolve or justify each finding in the commit body.
- [ ] **Step 3:** architecture chips; `python -m pytest tests/test_architecture_html.py --no-cov` → PASS.
- [ ] **Step 4:** push, PR (spec + plan commits ride along), `gh pr merge --squash --delete-branch`; from the primary repo `python dev.py deploy` → "All checks passed".
- [ ] **Step 5:** `pytest tests/test_playwright_smoke.py -m playwright --no-cov -k TestDiagnoseTab` against the live tray → PASS.
- [ ] **Step 6, live acceptance:** in the browser pane submit *"my PC is slow"*, decline the preview (evidence-only). Expected: temperatures and top app match the Temps & Power and Processes tabs (today at idle: `nothing_found` or a rule those tabs corroborate). Then run one light load: `python -c "import time; t=time.time()
while time.time()-t<12: pass"` (one core, ~12 s, nothing heavier while the VR heat sink is unfixed) and submit *"my PC is slow"* during it: `cpu_hog` names `python.exe` if it crosses 50 % of the whole CPU, or (expected on 32 threads: ~3 %) the verdict does not name it and the reason is explained. Screenshot both. Mismatch → fix before marking anything shipped.
- [ ] **Step 7:** backlog #63 PR 4 ✅ only after Step 6; rows for every deferred finding; `python scripts/backlog_html.py`; `/sop-report` printed last.
