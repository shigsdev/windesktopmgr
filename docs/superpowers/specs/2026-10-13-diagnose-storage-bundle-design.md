# Diagnose — Storage & Drives Bundle (PR 3) — Design Spec

**Date:** 2026-10-13
**Status:** Awaiting review
**Parent spec:** [`2026-10-01-diagnostic-engine-design.md`](2026-10-01-diagnostic-engine-design.md) (§14, row 3)
**Sibling:** [`2026-10-09-diagnose-crash-bundle-design.md`](2026-10-09-diagnose-crash-bundle-design.md) (PR 2, the pattern this follows)
**Backlog:** #63, PR 3 of 4

---

## 1. Problem

This PC has six NVMe drives, a Storage Spaces pool (E:, rebuilt 2026-10-12
as 3+1 parity after drive …20C4 failed), and a QNAP NAS. The app already
reads all of that on the Storage tab, but when something feels wrong ("E: is
slow", "C: is full", "is my pool OK?") Diagnose can only offer the Network
or Crash checks. The degraded-pool period showed why one read of every
storage source matters: a slow copy, a rebuild, a failing member drive and a
full volume all feel the same from the chair.

## 2. Intent and success criteria

**Intent:** the user describes a storage problem in plain language and gets
a verdict grounded in this machine's drives, pool, logs and NAS, with
plain-language steps. Read-only, the same egress gate as PR 1, useful
without the model (rules first). Covers four kinds of problem, chosen by the
user 2026-10-13: **failing drive**, **pool / E: array**, **drive full**,
**slow drive or slow copies**, plus the **NAS**.

| | Criterion |
|---|---|
| S1 | *"C drive is full"* and *"E: is really slow"* classify to `storage` with no question asked; the second fills `drive = "E:"`. |
| S2 | Replaying the 2026-10-08 degraded pool (member …20C4 Lost Communication) gives **pool_trouble**, naming the drive by label-serial suffix, model and slot. |
| S3 | Two identical drives (same model) with one hot: the verdict says "one of your two <model> drives" and never guesses which. |
| S4 | LHM's invalid readings (255 %, 0 power-on hours, as the C: 990 PRO reports) are discarded, never reported as wear. |
| S5 | No full serial, username, PC name or NAS name reaches the payload preview. |
| S6 | Nothing found renders as **inconclusive**, never "all fine". |
| S7 | With no model, rules give the same verdicts (evidence-only mode). |

**Non-goals:** any write to a disk (no `chkdsk /f`, `Repair-VirtualDisk`,
`Optimize-Volume`, format, delete); SMART counters that need admin (see §5
note); per-process disk attribution (PR 4, performance); monitoring or
alerting (the dashboard already does that).

## 3. Scope: one class

Approach **A** (chosen 2026-10-13 over two classes or a dashboard-concern
wrapper): a single class `storage`, labelled **"Storage & drives"**, whose
wave one reads every source, because the four kinds of problem overlap.

```python
"storage": {
    "label": "Storage & drives",
    "slots": (),
    "optional_slots": ("drive",),
    "wave1": (...7 probes, §5.1...),
    "escalate": (...3 probes, §5.2...),
    "rules": lambda evidence, host: dsr.evaluate_storage_rules(evidence),
    "prompt": _STORAGE_PROMPT,
    "actions": ("clear_temp",),
}
```

No engine change: optional slots, per-class rules/prompt/actions all landed
in PR 2.

## 4. Code layout

| File | Contents |
|---|---|
| `diagnose_storage_probes.py` (new) | The probes, registered into `diagnose_probes.PROBES` with `category="storage"` |
| `diagnose_storage_rules.py` (new) | Classifier helpers (`STORAGE_RE`, `extract_drive`) and `evaluate_storage_rules` |
| `diagnose.py` | `SYMPTOM_CLASSES["storage"]`, `_STORAGE_PROMPT`, `classify()` branch, import of both new modules |
| `static/js/app.js` / `templates/index.html` | "Which drive? (optional)" row driven by `optional_slots` (the crash class's app row is the model) |
| `tests/test_diagnose_storage.py` (new) + `tests/fixtures/diagnose/storage_*.json` | §9 |

## 5. Probes

All read-only. Python first (CLAUDE.md): PowerShell only where no binding
exists, and then by reusing an existing, already-tested reader.

**Note on SMART:** unelevated, `Get-StorageReliabilityCounter` returns null
for temperature, wear and error counts on every drive here (checked live
2026-10-13). LibreHardwareMonitor runs elevated and publishes per-drive
temperature, warning/critical limits, *Percentage Used*, *Available Spare*
and its threshold. The bundle reads LHM's feed through the existing 30 s
last-good cache (`lhm._fetch_data_json`) and never starts LHM.

### 5.1 Wave one (7 probes)

| Key | Source | Returns |
|---|---|---|
| `storage.physical_disks` | `wmi` (`root/Microsoft/Windows/Storage`, `MSFT_PhysicalDisk`) with `pythoncom.CoInitialize`/`CoUninitialize` around the call (COM-thread rule, #181); falls back to `disk.get_disk_health()["physical"]` | Per drive: `disk_number`, model, media/bus type, size GB, `health` (Healthy/Warning/Unhealthy), `operational` (incl. *Predictive Failure*, *Lost Communication*), `label_serial_tail` (last 4 of `AdapterSerialNumber`, else `SerialNumber`), slot via `disk.describe_disk_location`. Plus `letters`: drive letter → disk numbers from `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` (ctypes, unelevated) |
| `storage.drive_wear` | `lhm._fetch_data_json()` | Per LHM storage node: model, temperature °C, warning/critical °C, percentage used, available spare, spare threshold. Values of 255 % (or spare threshold > 100) and all-zero hours/data are dropped as invalid (S4). Each row carries `match`: the disk numbers whose model equals the node's name; `ambiguous: true` when more than one (S3). `available: false` with a reason when LHM is not running |
| `storage.pool` | `disk.get_storage_spaces()` (existing, PowerShell) | Pools, virtual disks, members (health, operational, usage, label-serial tail, slot), repair jobs (state, %) |
| `storage.disk_errors` | System log via the crash bundle's `_query` / `window_xpath` (7 days): `disk` 7, 11, 51, 153, 157; `stornvme` / `storahci` Level ≤ 3; `Ntfs` 50, 55, 98; StorageSpaces-Driver/Operational Level ≤ 3 | Counts and first/last time grouped by provider and, where the event names `\Device\HarddiskN`, by disk number. `ntfs_corruption` count (55/98) separately |
| `storage.volumes` | `psutil.disk_partitions` + `shutil.disk_usage` (`disk._enumerate_logical_drives`) | Per letter: label, filesystem, total / free GB, free % |
| `storage.io_sample` | `psutil.disk_io_counters(perdisk=True)` twice, 3 s apart | Per `PhysicalDriveN`: reads/writes per second, MB/s, `busy_pct` (from read+write time over the interval, capped 100), average ms per read and per write (only when ≥ 20 operations, else null) |
| `storage.nas` | `nas.get_nas_storage(wait=False)` + `nas.nas_storage_concerns()` | Per NAS: reachable, reading age in seconds, disks (health, temp), volumes (status, free %), and the existing concerns. Never waits on SNMP |

### 5.2 Escalation probes (the model may request them)

| Key | Returns |
|---|---|
| `storage.space_breakdown` | `disk.get_disk_quickwins(<drive>)` for the named drive, or the fullest volume when none named: known bloat locations with sizes, top 10 |
| `storage.errors_30d` | `storage.disk_errors` over 30 days |
| `storage.io_sample_long` | `storage.io_sample` over 10 s, for problems that come and go |

Each probe declares `category="storage"`, `timeout_s` 8–20 s
(`storage.pool` 20 s, it shells out), and the redaction classes in §7.

## 6. Rules and verdicts

Deterministic, first match leads (data-loss risk before speed); the model
may add to a confident rule verdict but cannot contradict it (existing
guard). When `drive` is set, each rule checks that drive first (E: → the
pool and its members via `letters`; C: → its physical disk) and only then
the others.

| # | Rule key | Fires when | Headline | Status / locus |
|---|---|---|---|---|
| 1 | `pool_trouble` | A pool or virtual disk not Healthy, a member *Lost Communication* / missing / not Healthy, or a failed repair job | "Your <letter> pool is degraded: drive …XXXX dropped out" | confident / local |
| 1b | `pool_rebuilding` | A repair job running (and rule 1 did not fire) | "Your <letter> pool is rebuilding (N %); it will be slow until that finishes" | confident / local |
| 2 | `drive_failing` | `health` Warning/Unhealthy, `operational` Predictive Failure, available spare below its threshold, or percentage used ≥ 90 | "Drive …XXXX (<model>, <slot>) is failing" | confident / local |
| 3 | `drive_errors` | ≥ 5 disk/stornvme errors on one disk in 7 days, or any Ntfs 55/98 | "Drive …XXXX logged N errors this week" | likely / local |
| 4 | `drive_hot` | Temperature ≥ the drive's own warning limit | "Drive …XXXX is at N °C" or, when ambiguous, "One of your two <model> drives is at N °C" | likely / local |
| 5 | `volume_full` | Free < 10 % or < 10 GB on a fixed volume | "<letter> has N GB free (P %)" | confident / local |
| 6 | `slow_now` | During the sample a disk was ≥ 90 % busy, or averaged > 20 ms per read or write | "Drive N was P % busy during the check" | likely / local |
| 7 | `nas_problem` | Any NAS concern at warning/critical, or reading older than 1 h / unreachable | "The NAS reports: <concern title>" | likely / external |
| — | `nothing_found` | None of the above | "No storage problem found right now" | **inconclusive** / unknown |

A drive is always named by label-serial tail + model + slot, never by an
inferred position (memory: identify hardware by label). An LHM-only reading
on an ambiguous model names the model and count only (S3).

**Context annotations** (attach to the winner as reasoning lines):

- `rebuild_in_progress`: a running repair job, attached to `slow_now`.
- `errors_on_same_drive`: `drive_errors` evidence on the drive a
  `drive_failing` / `pool_trouble` verdict names.
- `wear_unavailable`: LHM not running, so wear/temperature were not checked.
- `nas_stale`: the NAS reading is older than 1 h.

**Built-in manual steps** (≤ 6 per verdict, existing `manual_steps` contract):

- `pool_trouble` / `drive_failing`: back up anything important from that
  drive now, and check the Backup tab's last Backup and Restore run; find the
  drive by its **label serial** on the Storage tab before touching anything;
  do not shut down or restart while a repair runs; reseat (Lost
  Communication) or replace (failing) that one drive; Samsung warranty note
  for failing Samsung drives.
- `pool_rebuilding`: leave the PC on; large copies will be slow until done;
  re-run Diagnose after it finishes.
- `drive_errors`: the read-only scan `chkdsk <letter> /scan` to run yourself
  in an admin terminal (shown, never run); check for an SSD firmware update
  (Samsung Magician); if errors name a pool member, see `pool_trouble` steps.
- `drive_hot`: check airflow and the drive's heatsink; note whether a large
  copy or backup was running; re-check when idle.
- `volume_full`: the Cleanup tab; the Disk tab's space analysis for that
  drive; for C:, the **Clear temp files** action.
- `slow_now`: the Processes tab to see what is using the disk; wait out a
  rebuild (`rebuild_in_progress`); run the longer sample while it is slow.
- `nas_problem`: open the NAS's own admin page and check that disk / volume.

**Registry actions:** only `clear_temp`, only for `volume_full` on the
system drive. Every other verdict suggests no action, and the class
`actions` tuple stops the model offering anything else.

**Model hint (`_STORAGE_PROMPT`):** evidence is this PC's drives, pool,
event logs (7 days, UTC; convert with `local_utc_offset`) and NAS. Data-loss
risks (pool, failing drive) outrank speed. Name drives only by the label
tail given; when `ambiguous` is true, never say which drive. Never suggest a
command that writes to a disk. `nothing_found` means inconclusive.

## 7. Privacy

In addition to parent spec §7 and the crash bundle's rules:

- **Serials:** probes emit only the last 4 characters of the label serial
  (`label_serial_tail`); the `serial` redaction class still runs as a guard.
- **Redaction classes** on every storage probe: `username`, `serial`, `mac`,
  `self_host`, plus a new class **`nas_name`**: configured NAS names and
  hosts (from `nas_config.json`) → `the NAS`. NAS IP addresses are dropped
  by the probe, not redacted.
- **Paths:** only `storage.space_breakdown` returns paths, and only the
  known-location roots `get_disk_quickwins` already reports, with the user
  profile folder replaced by `<user>` (the `username` class). No file names.
- Caps: ≤ 12 drives, ≤ 26 volumes, ≤ 10 breakdown locations.
- The egress preview and "nothing leaves until you click Send" are unchanged.

## 8. Classifier

- **Storage words** (case-insensitive, whole words): `drive`, `disk`,
  `ssd`, `nvme`, `hard drive`, `hdd`, `storage`, `pool`, `storage spaces`,
  `raid`, `nas`, `out of space`, `no space`, `disk space`, `full` (only next
  to a storage word or drive letter), `copying`, `file copy`, and a drive
  letter (`C:`, `E drive`, `drive E`). Cloud-storage names are not
  storage words: `Google Drive`, `OneDrive`, `iCloud Drive`, `Dropbox`.
- **Drive slot** (`extract_drive`): the first drive letter written as
  `X:`, `X drive` or `drive X` (A–Z, excluding `I` as a pronoun:
  "I drive" is not a drive letter) → `"X:"`.
- **Order inside `classify()`:** a storage word **and** a crash word:
  storage when the storage word is the subject of the crash word ("my hard
  drive crashed", "the disk died"); otherwise ask (`symptom_class: None`),
  e.g. "the PC crashed while copying to E:". A storage word and a
  site/host: ask. `nas` with no site named: storage. Storage words alone:
  storage.
- Table-tested (§9), including S1 verbatim.

**UI:** picking "Storage & drives" shows an optional **"Which drive?
(optional)"** row, driven by `optional_slots` like the crash class's app
row.

## 9. Testing

Fixtures (`tests/fixtures/diagnose/storage_*.json`, discovered by the
existing parametrized fixture test):

| Fixture | Expect |
|---|---|
| `storage_pool_degraded_2026_10_08.json` (member …20C4 Lost Communication, redacted) | `pool_trouble`, names …20C4 + model + slot (S2) |
| `storage_pool_rebuilding.json` | `pool_rebuilding` |
| `storage_drive_failing.json` | `drive_failing` |
| `storage_drive_errors.json` | `drive_errors` |
| `storage_drive_hot_ambiguous.json` (two identical models) | `drive_hot`, "one of your two" (S3) |
| `storage_lhm_invalid_255.json` (C: 990 PRO sentinel values) | no wear verdict from the bogus readings (S4) |
| `storage_c_full.json` | `volume_full` + `clear_temp` |
| `storage_e_full.json` | `volume_full`, no action |
| `storage_slow_now.json` + rebuild running | `slow_now` with `rebuild_in_progress` |
| `storage_nas_problem.json` | `nas_problem` |
| `storage_nothing_found.json` | inconclusive (S6) |

Also:

- **Probe tests** per probe: happy / empty / malformed / source failure /
  timeout; WMI unavailable → PowerShell fallback; LHM not running; the
  IOCTL failing for one letter.
- **Drive focus:** `drive="E:"` makes an E: pool problem lead over a C:
  full volume; no drive named → rule order.
- **Classifier table:** S1 sentences, "my hard drive crashed" (storage),
  "the PC crashed while copying to E:" (ask), "NAS unreachable" (storage),
  "C drive is full", "I drive to work and my PC is slow" (not a drive slot),
  "Google Drive won't sync" (not storage).
- **Redaction:** planted full serial, username, PC name, NAS name absent
  from the payload (S5).
- **Routes:** `/api/diagnose/classes` lists `storage` with
  `optional_slots: ["drive"]`.
- **Playwright:** "C drive is full" starts a storage session with no ask;
  the drive row appears only for `storage`.
- **Live acceptance:** after deploy, run *"is my E: pool OK?"* on this PC
  and compare with the Storage tab. Backlog #63 PR 3 is not marked shipped
  until they agree.

## 10. Decomposition and architecture.html

One PR, in order: probes → rules → class + classifier + UI → fixtures/tests
→ `architecture.html` (two new root files, a new test file, fixture count,
test count, line counts: Step-4 triggers).
