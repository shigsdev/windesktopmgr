# Diagnose Storage & Drives Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `storage` symptom class to Diagnose that reads this PC's drives, Storage Spaces pool, disk-error logs, free space, live IO and NAS, and returns a rule-based verdict with plain-language steps.

**Architecture:** Two new modules mirror the crash bundle. `diagnose_storage_probes.py` registers 10 read-only probes into `diagnose_probes.PROBES`. `diagnose_storage_rules.py` holds the classifier helpers, 8 ordered rules, context annotations and steps. `diagnose.py` gains the class entry, a `classify()` branch and one new redaction class (`nas_name`). The UI gains an optional "Which drive?" row.

**Tech Stack:** Python 3.14, Flask blueprint, `wmi` + `pythoncom` (MSFT_PhysicalDisk), `ctypes` (volume → disk numbers), `psutil`, pywin32 `win32evtlog` via the crash bundle's reader, pytest + pytest-mock, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-13-diagnose-storage-bundle-design.md` (parent: `2026-10-01-diagnostic-engine-design.md`; pattern: `docs/superpowers/plans/2026-10-09-diagnose-crash-bundle.md`)

## Global Constraints

- Class key `storage`, label `"Storage & drives"`, `slots: ()`, `optional_slots: ("drive",)`, `actions: ("clear_temp",)`.
- Every storage probe: `category="storage"`, `redact=("username", "serial", "mac", "self_host", "nas_name")`, `timeout_s` 8–20 (`storage.pool` 20, `storage.io_sample_long` 15, others ≤ 12).
- Probes never return a full serial: only `label_serial_tail` (last 4 of `AdapterSerialNumber`, else of `SerialNumber`, via `disk._short_serial` semantics), and never a NAS host/IP.
- Read-only. No probe or step runs anything that writes to a disk. Python first; the only PowerShell is the existing `disk.get_storage_spaces()` and the `disk.get_disk_health()` fallback.
- Window `WINDOW_DAYS = 7`; escalation 30 days. Sample `SAMPLE_S = 3`, long sample `LONG_SAMPLE_S = 10`; per-op averages only when ≥ `MIN_OPS = 20` operations.
- Caps: ≤ 12 drives, ≤ 26 volumes, ≤ 10 breakdown locations.
- Rule order: `pool_trouble` > `pool_rebuilding` > `drive_failing` > `drive_errors` > `drive_hot` > `volume_full` > `slow_now` > `nas_problem` > `nothing_found`.
- Thresholds: `WEAR_FAIL_PCT = 90`; `DRIVE_ERROR_THRESHOLD = 5` (per disk, 7 days) or any Ntfs 55/98; temperature ≥ the drive's own warning limit; `FULL_PCT = 10` or `FULL_GB = 10`; `BUSY_PCT = 90` or `SLOW_MS = 20`; `NAS_STALE_S = 3600`.
- Status/locus per spec §6; `nas_problem` uses locus `"external_cause"` (the engine's name for "outside this PC").
- `clear_temp` only for `volume_full` on the system drive (`os.environ.get("SystemDrive", "C:")`); every other verdict `suggested_actions == []`.
- A drive is named only as `…XXXX (<model>, <slot>)`; an LHM-only reading with `ambiguous: true` names the model and count only ("one of your two <model> drives").
- JS functions use the `dx` prefix; user-visible text via `textContent` / DOM nodes.
- Commits use the repo's `PYTEST_DEBUG_TEMPROOT=<fresh scratchpad dir>` and the working interpreter first on PATH (`/c/Users/higs7/AppData/Local/Python/bin`) while the WindowsApps `python` alias is broken.

## Review Focus

1. **LHM sentinel values** (C: 990 PRO reports `Percentage Used = 255 %`, `Available Spare Threshold = 255 %`, `Power On Hours = 0`). Must yield no wear figure and never trip `drive_failing`. Pinned in Task 3 and the `storage_lhm_invalid_255` fixture (Task 5).
2. **Storage Spaces virtual disk as a drive letter.** E: resolves to the pool's virtual disk number, which is not a physical disk; `drive="E:"` must focus the pool (one pool) rather than find "no such drive". Pinned in Task 5.
3. **WMI unavailable or COM fault in a worker thread.** `storage.physical_disks` falls back to `disk.get_disk_health()["physical"]` and still returns `ok: True` with `source: "powershell"`. Pinned in Task 2.
4. **Idle drives in the IO sample.** 0–19 operations give `avg_read_ms: None`, never a divide-by-zero or a false "slow". Pinned in Task 4.
5. **"I drive …" and cloud drives in the sentence.** "I drive to work and my PC is slow" sets no drive slot; "Google Drive won't sync" is not storage. Pinned in Task 6.

---

### Task 1: Redaction class `nas_name`

**Files:**
- Modify: `diagnose.py` (`redact`, `_redact_walk`, `_redact_string`, `build_payload`; new `_nas_name_pattern`)
- Test: `tests/test_diagnose.py` (class `TestRedaction`)

**Interfaces:**
- Produces: PII class `"nas_name"` usable in any `Probe.redact`; `_nas_name_pattern() -> re.Pattern | None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_nas_name_redacts_configured_names_and_hosts(self, mocker):
    mocker.patch("diagnose._nas_name_pattern", return_value=re.compile(r"(?<![\w-])(?:QNAP-Shigs|192\.168\.1\.50)(?![\w-])", re.I))
    out = diagnose.redact({"t": "NAS 'qnap-shigs' at 192.168.1.50 is hot"}, ["nas_name"])
    assert out == {"t": "NAS 'the NAS' at the NAS is hot"}

def test_nas_name_absent_class_leaves_text(self, mocker):
    mocker.patch("diagnose._nas_name_pattern", return_value=re.compile("QNAP-Shigs", re.I))
    assert diagnose.redact("QNAP-Shigs", ["mac"]) == "QNAP-Shigs"

def test_nas_name_pattern_none_without_config(self, mocker):
    mocker.patch("nas._load_nas_config", return_value={"nas": []})
    assert diagnose._nas_name_pattern() is None
```

- [ ] **Step 2:** `python -m pytest tests/test_diagnose.py -k nas_name --no-cov` → FAIL (`_nas_name_pattern` missing).
- [ ] **Step 3: Implement.** `_nas_name_pattern()` reads `nas._load_nas_config()["nas"]` (all entries, enabled or not), collects non-empty `name` and `host`, returns one whole-token, case-insensitive alternation (longest first, `re.escape`d, same `(?<![\w-])…(?![\w-])` guards as `_self_host_pattern`) or `None`; never raises. `redact()` builds `nas_re` when `"nas_name"` is wanted and threads it through `_redact_walk`/`_redact_string` as a keyword `nas_re: re.Pattern | None = None`, applied right after `host_re`, replacement `"the NAS"`. Docstring of `redact` lists the class. In `build_payload`, add `"nas_name"` to `typed` when `_class_redacts(spec, "nas_name")`.
- [ ] **Step 4:** same command → PASS; `python -m pytest tests/test_diagnose.py --no-cov` → all PASS.
- [ ] **Step 5:** commit `feat(diagnose): nas_name redaction class (#63 PR 3)`.

### Task 2: Probe module scaffold + `storage.physical_disks`

**Files:**
- Create: `diagnose_storage_probes.py`
- Create: `tests/test_diagnose_storage_probes.py`
- Modify: `diagnose.py` (add `import diagnose_storage_probes  # noqa: F401 -- registers the storage probes`)

**Interfaces:**
- Produces:
  - `REGISTERED: dict[str, dp.Probe]`; `_storage_probe(key, label, fn, timeout_s=10.0, **kw) -> dp.Probe` (same shape as `diagnose_crash_probes._crash_probe`, `category="storage"`, `redact=_REDACT`).
  - `norm_drive(raw: object) -> str | None`: `"e"`, `"E:"`, `"e:\\"`, `"E drive"` → `"E:"`; anything else → `None`.
  - `volume_disk_numbers(letter: str) -> list[int]`: ctypes `CreateFileW(r"\\.\E:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)` + `DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000)` into a buffer of up to 8 `DISK_EXTENT` records (`DWORD DiskNumber`, 4 bytes padding, `LARGE_INTEGER StartingOffset`, `LARGE_INTEGER ExtentLength`, 24 bytes each, after the 8-byte header); `[]` on any failure, non-Windows, or invalid handle.
  - Probe `storage.physical_disks` (label "Drives and their health", `needs_optional=("drive",)`), data: `{"source": "wmi"|"powershell", "drives": [{"disk_number": int, "model": str, "media": str, "bus": str, "size_gb": float, "health": str, "operational": list[str], "label_serial_tail": str, "slot": str}], "letters": {"C:": [0], ...}, "focus": "E:"|None, "unavailable": list[str]}`.

- [ ] **Step 1: Write the failing tests** (class `TestPhysicalDisks`, `TestNormDrive`):
  - `test_norm_drive` parametrized: `("e", "E:")`, `("E:", "E:")`, `("e:\\", "E:")`, `("E drive", "E:")`, `("", None)`, `(None, None)`, `("EE", None)`, `("1:", None)`.
  - `test_wmi_happy_path`: mock `diagnose_storage_probes._wmi_physical_disks` returning two rows (`HealthStatus` 0 and 1, `OperationalStatus` `[2]` and `[5]`, `BusType` 17, `MediaType` 4, `AdapterSerialNumber "S7KHNJ0X905B40"`); assert `drives[1]["health"] == "Warning"`, `"Predictive Failure" in drives[1]["operational"]`, `drives[0]["bus"] == "NVMe"`, `drives[0]["media"] == "SSD"`, `drives[0]["label_serial_tail"] == "5B40"`, and `"S7KHNJ0X905B40" not in json.dumps(data)`.
  - `test_falls_back_to_powershell_when_wmi_fails`: `_wmi_physical_disks` raises; `disk.get_disk_health` mocked with one `physical` row → `source == "powershell"`, one drive.
  - `test_letters_and_focus`: `psutil.disk_partitions` mocked (C:, E:), `volume_disk_numbers` mocked `{"C:": [0], "E:": [6]}`; slots `{"drive": "e"}` → `letters == {"C:": [0], "E:": [6]}`, `focus == "E:"`.
  - `test_caps_at_12_drives`.
  - `test_volume_disk_numbers_non_windows_returns_empty` (monkeypatch `sys.platform`).
- [ ] **Step 2:** `python -m pytest tests/test_diagnose_storage_probes.py --no-cov` → FAIL (module missing).
- [ ] **Step 3: Implement.** `_wmi_physical_disks() -> list[dict]` runs on the calling (probe) thread: `pythoncom.CoInitialize()` guarded like `baseline.py:245-262` (uninitialise only if it succeeded), `wmi.WMI(namespace=r"root\Microsoft\Windows\Storage").MSFT_PhysicalDisk()`, mapping each to a plain dict of `DeviceId, FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, SerialNumber, AdapterSerialNumber, PhysicalLocation, Size`. Code tables: `HealthStatus {0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}`; `OperationalStatus {2: "OK", 3: "Degraded", 5: "Predictive Failure", 6: "Error", 7: "Non-Recoverable Error", 12: "No Contact", 13: "Lost Communication"}` else `"Code N"`; `BusType {7: "USB", 11: "SATA", 17: "NVMe", 8: "RAID", 10: "SAS"}`; `MediaType {3: "HDD", 4: "SSD", 5: "SCM"}`. The PowerShell fallback maps `get_disk_health()["physical"]` (already strings: `Health`, `Status`, `BusType`, `MediaType`, `DeviceId`, `LabelSerial`, `SerialNumber`, `Location`, `SizeGB`). `slot` = `disk.describe_disk_location(location, bus)["slot"]` when non-empty, else its `"raw"`. `letters` covers fixed drives from `psutil.disk_partitions(all=False)`.
- [ ] **Step 4:** same command → PASS.
- [ ] **Step 5:** commit `feat(diagnose): storage probe scaffold + physical disks (#63 PR 3)`.

### Task 3: `storage.drive_wear` (LHM)

**Files:**
- Modify: `diagnose_storage_probes.py`
- Test: `tests/test_diagnose_storage_probes.py` (class `TestDriveWear`)

**Interfaces:**
- Consumes: `lhm._fetch_data_json() -> dict | None`, `lhm._parse_temp_value(str) -> float | None`; Task 2's drive list for `match`.
- Produces: probe `storage.drive_wear` (label "Drive wear and temperature"), data: `{"available": bool, "reason": str, "drives": [{"model": str, "temp_c": float|None, "warn_c": float|None, "crit_c": float|None, "pct_used": float|None, "spare_pct": float|None, "spare_threshold_pct": float|None, "match": list[int], "ambiguous": bool}]}`. `parse_lhm_storage(tree: dict) -> list[dict]` (pure) returns the rows without `match`.

- [ ] **Step 1: Write the failing tests**, using a trimmed LHM tree fixture built in the test from the live 2026-10-13 shape (`Text`/`Type`/`Value`/`Children`; storage nodes have `Temperatures`, `Levels`, `Factors`, `Data` groups):
  - `test_parses_temp_limits_wear_spare`: a 990 PRO 2TB node (`Composite Temperature 44.0 °C`, `Warning Temperature 81.0 °C`, `Critical Temperature 84.0 °C`, `Percentage Used 5.0 %`, `Available Spare 100.0 %`, `Available Spare Threshold 10.0 %`) → those numbers.
  - `test_discards_255_sentinels`: the C: node (`Percentage Used 255.0 %`, `Available Spare Threshold 255.0 %`, `Power On Hours 0.000`) → `pct_used is None`, `spare_threshold_pct is None`, temperature kept (37.0).
  - `test_ram_dimms_are_not_drives`: a `SK Hynix - HMCG78AGBUA081N (#0)` DIMM node is ignored (storage nodes are those with a `Levels` group containing `Percentage Used` or `Available Spare`).
  - `test_match_and_ambiguous`: two drives with model `"Samsung SSD 990 PRO 2TB"` (disk 2, 3) and one LHM node of that name → `match == [2, 3]`, `ambiguous is True`; a unique model → `ambiguous is False`.
  - `test_lhm_not_running`: `_fetch_data_json` → `None` → `available is False`, `reason` mentions LibreHardwareMonitor, `drives == []`, probe still `ok`.
- [ ] **Step 2:** run the class → FAIL.
- [ ] **Step 3: Implement.** A percentage > 100 or a threshold > 100 is invalid → `None`. Match on case-insensitive equality of the LHM node `Text` with the drive `model`, ignoring a leading `"NVMe "` on either side. Read the drive list by calling Task 2's collector (not the probe) so the probe stays self-contained.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `feat(diagnose): storage drive wear from LHM (#63 PR 3)`.

### Task 4: Remaining probes: pool, disk errors, volumes, IO sample, NAS, escalations

**Files:**
- Modify: `diagnose_storage_probes.py`
- Test: `tests/test_diagnose_storage_probes.py` (classes `TestPool`, `TestDiskErrors`, `TestVolumes`, `TestIoSample`, `TestNas`, `TestEscalation`, `TestRegistry`)

**Interfaces:**
- Consumes: `disk.get_storage_spaces()`, `diagnose_crash_probes._query` / `window_xpath` / `STORAGE_SPACES_CHANNEL`, `disk._enumerate_logical_drives()`, `psutil.disk_io_counters(perdisk=True)`, `nas.get_nas_storage(wait=False)`, `nas.nas_storage_concerns()`, `disk.get_disk_quickwins(drive)`.
- Produces (probe data shapes the rules read):
  - `storage.pool` (timeout 20): `{"has_spaces": bool, "pools": [{"name", "health", "operational"}], "virtual_disks": [{"name", "health", "operational", "resiliency"}], "members": [{"pool", "model", "health", "operational", "usage", "label_serial_tail", "slot"}], "repair_jobs": [{"name", "state", "pct"}]}`. Full serials dropped.
  - `storage.disk_errors` / `storage.errors_30d`: `{"window_days": int, "by_provider": {provider: {"count", "first", "last"}}, "by_disk": {"<n>": {"count", "last"}}, "ntfs_corruption": int, "pool_events": int, "unavailable": list[str]}`. Events: `disk` ids 7, 11, 51, 153, 157; `stornvme`/`storahci` Level ≤ 3; `Ntfs` 50, 55, 98 (55/98 also counted in `ntfs_corruption`); StorageSpaces-Driver/Operational Level ≤ 3 → `pool_events`. `by_disk` from a `\Device\Harddisk(\d+)` match in any EventData value.
  - `storage.volumes`: `{"volumes": [{"letter", "label", "fs", "total_gb", "free_gb", "free_pct", "fixed": bool}]}` (≤ 26; network drives excluded).
  - `storage.io_sample` / `storage.io_sample_long` (timeout 15): `{"seconds": float, "disks": [{"disk_number", "reads_s", "writes_s", "mb_s", "busy_pct", "avg_read_ms", "avg_write_ms"}]}`. `busy_pct = min(100, (Δread_time + Δwrite_time) / (seconds * 1000) * 100)`; averages `None` below `MIN_OPS`.
  - `storage.nas`: `{"configured": int, "nas": [{"label": "NAS 1", "reachable", "age_s", "disks": [{"health", "temp_c"}], "volumes": [{"status", "free_pct"}]}], "concerns": [{"level", "title", "detail"}]}`. No `host`, no IP.
  - `storage.space_breakdown` (`needs_optional=("drive",)`): the named drive or the fullest fixed volume; `{"drive", "locations": [{"label", "path", "size_gb"}]}` top 10 by size from `get_disk_quickwins`.

- [ ] **Step 1: Write the failing tests** (one happy path + one failure/empty case per probe, plus):
  - `test_pool_drops_full_serials`: member with `Serial "Z4A0BC123420C4"` → `label_serial_tail == "20C4"`, full serial absent from `json.dumps`.
  - `test_pool_failure_is_empty_not_raise`: `get_storage_spaces` returns its own empty fallback → `has_spaces is False`.
  - `test_disk_errors_groups_by_disk_and_ntfs`: events for `disk` 153 with `\Device\Harddisk3\DR3` ×6 and `Ntfs` 55 ×1 → `by_disk["3"]["count"] == 6`, `ntfs_corruption == 1`.
  - `test_disk_errors_unreadable_channel_listed`: the Storage Spaces channel query fails → `ok`, channel in `unavailable`.
  - `test_errors_30d_window`: `window_days == 30` and the XPath uses 30 days.
  - `test_io_sample_busy_and_avg`: two mocked counter snapshots, `time.sleep` patched; 300 reads with Δread_time 9000 ms over 3 s → `avg_read_ms == 30.0`, `busy_pct == 100`.
  - `test_io_sample_idle_gives_none_avgs` (Review Focus 4): 5 reads → `avg_read_ms is None`.
  - `test_nas_never_waits_and_hides_host`: `get_nas_storage` asserted called with `wait=False`; configured host `"192.168.1.50"` absent from output.
  - `test_registry_invariants`: all 10 keys present in `dp.PROBES`, `category == "storage"`, `"nas_name" in redact`, timeouts within 8–20.
- [ ] **Step 2:** run the new classes → FAIL.
- [ ] **Step 3: Implement** the six collectors and register the seven probes (`storage.pool` "Storage Spaces pool", `storage.disk_errors` "Disk errors in the event log", `storage.volumes` "Free space", `storage.io_sample` "Live drive activity", `storage.nas` "NAS (saved reading)", `storage.space_breakdown` "What's using the space", `storage.errors_30d` "Disk errors, last 30 days", `storage.io_sample_long` "Live drive activity (10 s)"). The two sample probes share one `_io_sample(seconds: float) -> dict`; the two error probes share `_disk_errors(days: int) -> dict`.
- [ ] **Step 4:** `python -m pytest tests/test_diagnose_storage_probes.py --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): storage pool, errors, volumes, IO, NAS probes (#63 PR 3)`.

### Task 5: Rules, annotations, steps and fixtures

**Files:**
- Create: `diagnose_storage_rules.py`
- Create: `tests/test_diagnose_storage_rules.py`
- Create: `tests/fixtures/diagnose/storage_*.json` (12, list below)
- Modify: `tests/test_diagnose.py` (`test_rule_fixture` dispatches `symptom_class == "storage"` to a `_check_storage_fixture` mirroring `_check_crash_fixture`)

**Interfaces:**
- Consumes: probe data shapes from Tasks 2–4; `dg._verdict`, `dg.clean_steps`, `dg.MAX_MANUAL_STEPS`.
- Produces: `evaluate_storage_rules(evidence: dict[str, dict]) -> dict` (always a full verdict; `rule_hits[0]` is the rule key, then context keys). Focus drive is read from `evidence["storage.physical_disks"]["data"]["focus"]` (the engine passes no slots to rules).

- [ ] **Step 1: Write the fixtures and failing tests.** Fixtures use the existing format (`symptom`, `symptom_class: "storage"`, `evidence` keyed by probe with `{"key","label","ok","data","elapsed_ms"}`, `expect: {"rule","status","locus","must_include","must_exclude","context"}`):

| Fixture | expect.rule | status / locus | context | must_include |
|---|---|---|---|---|
| `storage_pool_degraded_2026_10_08` (member …20C4 `Lost Communication`, pool `Degraded`) | `pool_trouble` | confident / local | `errors_on_same_drive` | — |
| `storage_pool_rebuilding` (job `Running`, 63) | `pool_rebuilding` | confident / local | — | — |
| `storage_drive_failing` (`Predictive Failure`) | `drive_failing` | confident / local | — | — |
| `storage_drive_errors` (disk 3, 14 errors) | `drive_errors` | likely / local | — | — |
| `storage_drive_hot_ambiguous` (two 990 PRO 2TB, 82 °C ≥ warn 81) | `drive_hot` | likely / local | — | — |
| `storage_lhm_invalid_255` (only the sentinel values, nothing else wrong) | `nothing_found` | inconclusive / unknown | — | — |
| `storage_c_full` (C: 6 GB, 3 %) | `volume_full` | confident / local | — | `clear_temp` |
| `storage_e_full` (E: 4 %) | `volume_full` | confident / local | — | — (`must_exclude: clear_temp`) |
| `storage_slow_now` (disk 6 busy 100 %, job running only as context: pool Healthy, job `Running`) | `pool_rebuilding` | confident / local | — | — |
| `storage_slow_now_plain` (busy 100 %, no job) | `slow_now` | likely / local | — | — |
| `storage_nas_problem` (concern `critical`) | `nas_problem` | likely / external_cause | — | — |
| `storage_nothing_found` | `nothing_found` | inconclusive / unknown | — | — |

  Unit tests in `tests/test_diagnose_storage_rules.py`:
  - `test_pool_headline_names_label_model_slot`: headline contains `"…20C4"` and the member's model and slot (S2).
  - `test_hot_ambiguous_never_names_a_drive`: headline contains `"one of your two Samsung SSD 990 PRO 2TB drives"` and no `"…"` serial tail (S3).
  - `test_focus_drive_leads`: evidence with C: full **and** an E: pool `pool_rebuilding`; `focus = "C:"` → `volume_full` leads; `focus = None` → `pool_rebuilding` leads.
  - `test_focus_virtual_disk_maps_to_pool` (Review Focus 2): `letters {"E:": [6]}`, disk 6 not in `drives`, one pool, `focus "E:"`, pool degraded → `pool_trouble`.
  - `test_wear_unavailable_annotation`: `storage.drive_wear.available False` → `"wear_unavailable" in rule_hits` and a reasoning line mentioning LibreHardwareMonitor.
  - `test_slow_with_rebuild_annotation`: `focus "C:"`, C:'s disk 0 busy 100 %, E: pool job `Running` → `slow_now` leads (focus) with `"rebuild_in_progress"` in `rule_hits`. (Unfocused, `pool_rebuilding` outranks `slow_now` and already explains the slowness, so the annotation only appears under a focus.)
  - `test_nas_stale_annotation`: `age_s 7200` → `nas_problem` with `"nas_stale"` in `rule_hits`.
  - `test_steps_never_contain_write_commands`: for every fixture's verdict, no step matches `r"chkdsk\s+\S+\s+/(?:f|r|x)\b|Repair-VirtualDisk|format\s+[a-z]:|Optimize-Volume"` (case-insensitive), and `chkdsk <letter> /scan` appears in `drive_errors` steps.
  - `test_unread_sources_note_on_nothing_found`: a probe with `ok: False` → reasoning names it.
- [ ] **Step 2:** `python -m pytest tests/test_diagnose_storage_rules.py tests/test_diagnose.py -k "storage or fixture" --no-cov` → FAIL.
- [ ] **Step 3: Implement** `_RULES` as an ordered tuple of `_rule_*(evidence, focus) -> tuple[str, dict, list[str]] | None` (key, verdict, evidence_refs), each considering the focus drive's items first; `_context(evidence, key, focus)` adds `rebuild_in_progress`, `errors_on_same_drive`, `wear_unavailable`, `nas_stale`; `_STEPS[key]` holds the spec §6 step text (≤ 6 after `clean_steps`). Headlines/copy are the spec §6 strings with values filled in; `nothing_found` headline `"No storage problem found right now"`. The `clear_temp` gate sits in `evaluate_storage_rules`, after the winning rule, keyed on `volume_full` and the system drive letter.
- [ ] **Step 4:** same command → PASS.
- [ ] **Step 5:** commit `feat(diagnose): storage rules, steps and fixtures (#63 PR 3)`.

### Task 6: Classifier and class registration

**Files:**
- Modify: `diagnose_storage_rules.py` (`STORAGE_RE`, `CLOUD_DRIVE_RE`, `extract_drive`, `is_storage_subject_crash`)
- Modify: `diagnose.py` (`_STORAGE_PROMPT`, `SYMPTOM_CLASSES["storage"]`, `classify()`, `import diagnose_storage_rules as dsr`)
- Test: `tests/test_diagnose.py` (classes `TestClassify`, `TestClassesRoute`), `tests/test_diagnose_storage_rules.py` (`TestStorageClassifier`)

**Interfaces:**
- Produces: `extract_drive(text: str) -> str | None` (returns `"X:"`); `STORAGE_RE: re.Pattern`; `classify()` returns `{"symptom_class": "storage", "slots": {"drive": "E:"} | {}, "candidates": [], "missing": []}`.

- [ ] **Step 1: Write the failing table test** `test_storage_classification` parametrized over `(sentence, expected_class, expected_slots)`:
  - `"C drive is full"` → `storage`, `{"drive": "C:"}` (S1)
  - `"E: is really slow"` → `storage`, `{"drive": "E:"}` (S1)
  - `"is my E: pool OK?"` → `storage`, `{"drive": "E:"}`
  - `"my hard drive crashed"` → `storage`, `{}`
  - `"the disk died"` → `storage`, `{}`
  - `"the PC crashed while copying to E:"` → `None`
  - `"NAS unreachable"` → `storage`, `{}`
  - `"the NAS can't reach example.com"` → `None`
  - `"I drive to work and my PC is slow"` → `None` (not storage, no slot)
  - `"Google Drive won't sync"` → `None`
  - `"out of disk space"` → `storage`, `{}`
  - `"the computer crashed last evening - cna you investigate?"` → `crashes` (regression)
  - `"example.com won't load"` → `network_dns` (regression)
  
  Plus `test_classes_route_lists_storage`: `GET /api/diagnose/classes` includes `{"key": "storage", "label": "Storage & drives", "optional_slots": ["drive"]}` fields.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** `extract_drive`: first match of `\b([A-Z]):(?=\\|\s|$|[?.!,])`, `\b([A-Z])\s+drive\b`, or `\bdrive\s+([A-Z])\b` (case-insensitive), rejecting `I` in the `X drive` form. `STORAGE_RE` per spec §8 (whole words); `full` counts only within 3 words of a storage word or drive letter. Strip `CLOUD_DRIVE_RE` (`google\s+drive|onedrive|icloud\s+drive|dropbox`) from the text before matching. In `classify()`, evaluate storage before the crash branch: storage word + crash word → `storage` when `is_storage_subject_crash(text)` (a storage noun within the 3 words before the crash verb, e.g. "hard drive crashed", "disk died"; `died`/`failed`/`dead` count as crash verbs here only), else `None`; storage word + host candidate → `None`; otherwise `storage`. `_STORAGE_PROMPT` is the spec §6 model hint. Class entry per Global Constraints with `"rules": lambda evidence, host: dsr.evaluate_storage_rules(evidence)`, `wave1` = the 7 spec §5.1 keys, `escalate` = the 3 §5.2 keys.
- [ ] **Step 4:** `python -m pytest tests/test_diagnose.py tests/test_diagnose_storage_rules.py --no-cov` → PASS.
- [ ] **Step 5:** commit `feat(diagnose): storage class + classifier (#63 PR 3)`.

### Task 7: UI: optional drive row

**Files:**
- Modify: `templates/index.html` (new `#dx-drive-row` after `#dx-app-row`: label "Which drive? (optional)", input `#dx-drive`, `maxlength="12"`, placeholder `e.g. E:`)
- Modify: `static/js/app.js` (the three `dx-app-row` sites at ~10465, ~10565, ~10605 gain the drive equivalent via `dx_classHasOptional(sel.value, "drive")`; body sends `slots.drive` only while the row shows)
- Test: `tests/test_playwright_smoke.py` (`TestDiagnoseTab`)

- [ ] **Step 1: Write the failing Playwright tests:** `test_storage_sentence_starts_without_ask` ("C drive is full" → session starts, no host prompt, class shown as "Storage & drives"); `test_drive_row_only_for_storage` (`#dx-drive-row` hidden by default, visible after picking `storage`, hidden again for `crashes` and `network_dns`).
- [ ] **Step 2:** against the dev server/tray with the branch: `pytest tests/test_playwright_smoke.py -m playwright --no-cov -k "storage or drive_row"` → FAIL. (Check no other session is running Playwright against the tray first.)
- [ ] **Step 3: Implement** the row and wiring, mirroring the app row exactly.
- [ ] **Step 4:** same command → PASS; the existing `TestDiagnoseTab` tests still PASS.
- [ ] **Step 5:** commit `feat(diagnose): Which drive? row (#63 PR 3)`.

### Task 8: Ship: review, docs, deploy, live acceptance

**Files:**
- Modify: `architecture.html` (new root files `diagnose_storage_probes.py`, `diagnose_storage_rules.py`; new test files `tests/test_diagnose_storage_probes.py`, `tests/test_diagnose_storage_rules.py` (also add both to `TEST_FILES` in `tests/test_architecture_html.py`); probe count +10; fixture count +12; test count; line counts. `/arch-update` first, then hand-edit the file chips)
- Memory: `project_backlog.md` row #63, `project_diagnose_engine_2026-10-01.md`

- [ ] **Step 1:** ruff (pinned binary) check + format → clean; `python -m pytest tests/ -n auto -p no:cacheprovider --color=no` → all pass, ≥ 80 %.
- [ ] **Step 2:** `/code-review` on the branch diff; resolve or justify each finding in the commit body. `/code-simplifier` (> 200 LOC).
- [ ] **Step 3:** architecture chips; `python -m pytest tests/test_architecture_html.py --no-cov` → PASS.
- [ ] **Step 4:** push, PR (spec + plan commits ride along), merge; from the primary repo `python dev.py deploy` → "All checks passed".
- [ ] **Step 5:** `pytest tests/test_playwright_smoke.py -m playwright --no-cov -k TestDiagnoseTab` against the live tray → PASS.
- [ ] **Step 6, live acceptance:** in the browser pane submit *"is my E: pool OK?"*, decline the preview (evidence-only). Expected: matches the Storage tab (today: pool Healthy, no job → `nothing_found` or another rule the Storage tab corroborates, never a false `pool_trouble`). Also submit *"C drive is full"* and check the C: free figure against Explorer. Screenshot both. Mismatch → fix before marking anything shipped.
- [ ] **Step 7:** backlog row #63 (PR 3 ✅ only after Step 6), memory, `backlog.html`, SOP Compliance Report.
