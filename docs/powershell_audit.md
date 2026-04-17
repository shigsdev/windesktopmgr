# PowerShell → Python Migration Audit

**Generated:** 2026-04-14 (backlog #24, inventory phase only — no migrations in this pass)
**Scope:** Every `subprocess.run("powershell" | "dism" | "netsh" | …)` call site across the three primary modules.
**Regenerate:** `python scripts/audit_ps_sites.py` dumps the raw TSV the tables below are built from.

## Headline numbers

| File | PS sites | REPLACE | KEEP | MAYBE |
|---|---:|---:|---:|---:|
| `windesktopmgr.py` | 60 | 38 | 12 | 10 |
| `homenet.py` | 11 | 6 | 2 | 3 |
| `SystemHealthDiag.py` | 3 | 1 | 1 | 1 |
| **Total** | **74** | **45** | **15** | **14** |

Legend:
- **REPLACE** — mature standard-library or pypi alternative exists. Migration is mechanical; confidence is high.
- **KEEP** — no realistic Python replacement. Wrap as a direct `.exe` subprocess (e.g. `dism.exe`, `netsh.exe`, `shutdown.exe`) but stay out of PS. Saves ~200–400 ms of `powershell.exe` startup per call.
- **MAYBE** — a Python alternative exists on paper (usually `pywin32` COM or `win32evtlog`) but ergonomics / edge cases / perf need prototyping before committing.

Hot-path legend:
- **HOT** — called from dashboard parallel checks, `/api/selftest`, or a polling loop. Migrations here pay back fastest.
- **WARM** — called from a tab that loads on user click, or an NLQ tool.
- **COLD** — user-triggered one-shot (remediation buttons, BIOS check, setup).

---

## `windesktopmgr.py` — 60 sites

### Drivers & NVIDIA (6 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 1 | 392 | `get_installed_drivers` | `Get-WmiObject Win32_PnPSignedDriver` | Enumerate signed drivers for Driver tab | **REPLACE** | `wmi.WMI().Win32_PnPSignedDriver()` | WARM |
| 2 | 431 | `get_driver_health` | `Get-WmiObject Win32_PnPSignedDriver` + `CIM_LogicalDevice` | Dashboard driver-age + problem-device check | **REPLACE** | `wmi` package | **HOT** |
| 3 | 500 | `_get_nvidia_gpu_info` | `Get-WmiObject Win32_VideoController` | Detect NVIDIA GPU + driver version | **REPLACE** | `wmi` or `platform.win32_ver` | WARM |
| 4 | 664 | `get_nvidia_update_info` | `Get-ItemProperty HKLM\\…\\GeForce App` (registry) | Read GeForce App cache from registry | **REPLACE** | `winreg` (stdlib) | WARM |
| 5 | 718 | `get_windows_update_drivers` | `Microsoft.Update.Session` COM | Query WU API for driver updates | **MAYBE** | `pywin32 win32com.client.Dispatch("Microsoft.Update.Session")` | WARM |
| 6 | 8112 | `launch_nvidia_app` | `Start-Process` nvcontainer | Launch NVIDIA App from tray | **REPLACE** | `subprocess.Popen` direct | COLD |

### BSOD + Events + Timeline (7 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 7 | 908 | `get_bsod_events` | `Get-WinEvent -FilterHashtable` System log | BSOD tab + timeline source | **MAYBE** | `pywin32 win32evtlog.EvtQuery` w/ XPath | WARM |
| 8 | 3165 | `query_event_log` | `Get-WinEvent` with dynamic XPath | Event Log tab ad-hoc queries | **MAYBE** | `pywin32 win32evtlog` | WARM |
| 9 | 6152 | `get_system_timeline` | `Get-WinEvent` BSOD filter | Timeline aggregator — BSOD events | **MAYBE** | `pywin32 win32evtlog` | WARM |
| 10 | 6208 | `get_system_timeline` | `Get-WinEvent` Setup log | Timeline — Windows Update events | **MAYBE** | `pywin32 win32evtlog` | WARM |
| 11 | 6248 | `get_system_timeline` | `Get-WinEvent` System log (service events) | Timeline — service crashes | **MAYBE** | `pywin32 win32evtlog` | WARM |
| 12 | 6293 | `get_system_timeline` | `Get-WinEvent` System log (boot events) | Timeline — boot / shutdown | **MAYBE** | `pywin32 win32evtlog` | WARM |
| 13 | 6335 | `get_system_timeline` | `Get-WinEvent` Security log (credential events) | Timeline — auth failures | **MAYBE** | `pywin32 win32evtlog` (+ admin) | WARM |

> **Pattern:** 7 of the 14 MAYBE sites are `Get-WinEvent`. Migrating this family is a single focused effort (one helper around `win32evtlog.EvtQuery` + XPath) that collapses 7 cold starts into one warm Python loop. High ROI once the helper exists; low ROI if done piecemeal.

### Startup & Services (4 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 14 | 1669 | `_lookup_startup_via_fileinfo` | `Get-Item <path> \| Get-ItemProperty VersionInfo` | Enrich startup row with file metadata | **REPLACE** | `os.stat` + `win32api.GetFileVersionInfo` | COLD |
| 15 | 1698 | `_lookup_startup_via_fileinfo` | `Get-ItemProperty` (secondary) | Backup metadata lookup | **REPLACE** | same as #14 | COLD |
| 16 | 1957 | `get_startup_items` | `Get-CimInstance Win32_StartupCommand` + `Get-ScheduledTask` | Startup tab main loader | **MAYBE** | `wmi` for Win32_StartupCommand; `win32com.Schedule.Service` for scheduled tasks | WARM |
| 17 | 2009 | `toggle_startup_item` | `Set-ItemProperty` registry + `Disable-ScheduledTask` | Enable/disable startup entry | **MAYBE** | `winreg` + `win32com.Schedule.Service` | COLD |

### Disk (3 sites — note: `_enumerate_logical_drives` was migrated 2026-04-14, no PS)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 18 | 2179 | `get_disk_health` | `Get-PhysicalDisk \| Get-StorageReliabilityCounter` | SMART data for dashboard | **KEEP** | Storage Management API has no Python binding | **HOT** |
| 19 | 2192 | `get_disk_health` | `Get-Counter '\\LogicalDisk(*)\\…'` | Per-drive IO counters | **REPLACE** | `psutil.disk_io_counters(perdisk=True)` | **HOT** |
| 20 | 2719 | `get_disk_quickwins` | `Get-ChildItem` + size rollup on known bloat dirs | Disk quick-wins card | **REPLACE** | `os.walk` + `os.stat` | WARM |
| 21 | 2844 | `_get_winsxs_actual_size` | **`DISM /Online /Cleanup-Image /AnalyzeComponentStore`** | WinSxS actual size | **KEEP** | No Python DISM binding — call `dism.exe` directly instead of through PS | COLD |

### Network (3 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 22 | 3047 | `get_network_data` | `Get-NetTCPConnection` | Active TCP connections | **REPLACE** | `psutil.net_connections(kind='tcp')` | **HOT** |
| 23 | 3053 | `get_network_data` | `Get-NetAdapter` + `Get-NetAdapterStatistics` | Adapter stats + link state | **REPLACE** | `psutil.net_if_addrs` + `net_if_stats` + `net_io_counters(pernic=True)` | **HOT** |
| 24 | 7473 | `_run_ps` (helper) | generic wrapper (remediation helper) | Generic fallback dispatcher | **—** | helper itself can stay; callers migrate | — |

### Windows Update History (1 site)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 25 | 3112 | `get_update_history` | `Microsoft.Update.Session` COM via PS | Windows Update installed-history | **MAYBE** | `pywin32 win32com.client.Dispatch("Microsoft.Update.Session")` — same API PS uses | WARM |

### Process monitor (5 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 26 | 4139 | `_lookup_via_windows_provider` | `Get-WmiObject Win32_Process` | Process metadata enrichment (cache fill) | **REPLACE** | `psutil.Process(pid).as_dict(...)` | WARM |
| 27 | 4954 | `_lookup_process_via_fileinfo` | `Get-Item <exe> \| Select FileVersionInfo` | Vendor + product name lookup | **REPLACE** | `win32api.GetFileVersionInfo` | WARM |
| 28 | 4986 | `_lookup_process_via_fileinfo` | same, secondary branch | Fallback path | **REPLACE** | same as #27 | WARM |
| 29 | 5194 | `get_process_list` | `Get-Process \| Select -Property …` | Full process snapshot — Process tab | **REPLACE** | `psutil.process_iter(attrs=[…])` | **HOT** |
| 30 | 5243 | `kill_process` | `Stop-Process -Id {pid} -Force` | Kill-process button | **REPLACE** | `psutil.Process(pid).kill()` | COLD |

### Thermals (3 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 31 | 5407 | `get_thermals` | `Get-WmiObject MSAcpi_ThermalZoneTemperature` | CPU/chipset temps | **KEEP** | Provider is vendor-gated; LibreHardwareMonitor needed — keep PS | WARM |
| 32 | 5413 | `get_thermals` | `Get-Counter '\\Processor Information(*)\\%…'` | CPU utilization counters | **REPLACE** | `psutil.cpu_percent(percpu=True)` | WARM |
| 33 | 5418 | `get_thermals` | `Get-WmiObject Win32_Fan` | Fan RPM | **KEEP** | Same vendor gating as temps | WARM |

### Services (2 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 34 | 5822 | `get_services_list` | `Get-WmiObject Win32_Service` | Services tab main loader | **REPLACE** | `psutil.win_service_iter()` | WARM |
| 35 | 5848 | `toggle_service` | `Start-Service` / `Stop-Service` / `Set-Service -StartupType` | Mutate service state | **REPLACE** | `pywin32 win32serviceutil.{Start,Stop}Service` + `win32service.ChangeServiceConfig` | COLD |

### Memory (2 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 36 | 6707 | `get_memory_analysis` | `Get-Process \| Select WorkingSet64,…` | Per-process memory rollup | **REPLACE** | `psutil.process_iter(['memory_info', 'username'])` | **HOT** |
| 37 | 6721 | `get_memory_analysis` | `Get-CimInstance Win32_OperatingSystem` | Total + free memory | **REPLACE** | `psutil.virtual_memory()` | **HOT** |

### BIOS (5 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 38 | 6817 | `get_current_bios` | `Get-WmiObject Win32_BIOS` | BIOS version + vendor | **REPLACE** | `wmi.WMI().Win32_BIOS()` | WARM |
| 39 | 6860 | `check_dell_bios_update` | `(Get-WmiObject Win32_BIOS).SerialNumber` | Dell service tag | **REPLACE** | `wmi` | COLD |
| 40 | 6931 | `check_dell_bios_update` | `Test-Path` + Dell Command Update `dcu-cli.exe` | DCU presence + query | **KEEP** | Wrap `dcu-cli.exe` directly (no PS) | COLD |
| 41 | 6983 | `check_dell_bios_update` | `Invoke-WebRequest` Dell catalog | Download Dell XML catalog | **REPLACE** | `requests.get(...)` | COLD |
| 42 | 7028 | `check_dell_bios_update` | `Microsoft.Update.Session` COM | WU-surfaced BIOS update | **MAYBE** | `pywin32 win32com` | COLD |
| 43 | 7053 | `check_dell_bios_update` | secondary Win32_BIOS read | Re-read after check | **REPLACE** | `wmi` | COLD |

### Credentials / OneDrive / Fast Startup (3 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 44 | 8458 | `resume_onedrive` | `Start-Process` + `powercfg` Efficiency Mode | Unthrottle OneDrive | **KEEP** | `subprocess.Popen(["powercfg", …])` directly | COLD |
| 45 | 8522 | `resume_broker_processes` | `Get-Process` + efficiency-mode toggle | Unthrottle RuntimeBroker | **REPLACE** | `psutil` + `ctypes.windll.kernel32.SetPriorityClass` | COLD |
| 46 | 8563 | `fix_fast_startup` | `powercfg /h off` + registry tweak | Disable Fast Startup | **KEEP** | `subprocess.Popen(["powercfg", "/h", "off"])` + `winreg` | COLD |

### SysInfo + Warranty (4 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 47 | 8607 | `warranty_data` | `Get-WmiObject Win32_Processor` | CPU model + microcode | **REPLACE** | `wmi` | WARM |
| 48 | 8624 | `warranty_data` | `Get-WmiObject Win32_PhysicalMemory` | DIMM layout | **REPLACE** | `wmi` | WARM |
| 49 | 8637 | `warranty_data` | `Get-WmiObject Win32_OperatingSystem` | OS + install date | **REPLACE** | `wmi` or `platform.win32_ver` | WARM |
| 50 | 8766 | `sysinfo_data` | multi-class `Get-WmiObject` bundle | SysInfo tab bulk fetch | **REPLACE** | `wmi` (single connection, multi-query) | WARM |

### Remediation actions (10 sites)

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 51 | 9400 | `_rem_flush_dns` | `ipconfig /flushdns` | Flush DNS resolver cache | **KEEP** | `subprocess.run(["ipconfig", "/flushdns"])` — drop the PS wrapper | COLD |
| 52 | 9415 | `_rem_reset_winsock` | `netsh winsock reset; netsh int ip reset` | Winsock repair | **KEEP** | `subprocess.run(["netsh", …])` directly | COLD |
| 53 | 9430 | `_rem_reset_tcpip` | `netsh int tcp reset; …ipv4…; …ipv6…` | Full TCP/IP stack reset | **KEEP** | `subprocess.run(["netsh", …])` directly | COLD |
| 54 | 9457 | `_rem_clear_temp` | `Get-ChildItem $env:TEMP \| Remove-Item -Recurse` | Clear temp dirs | **REPLACE** | `shutil.rmtree` + `os.walk` | COLD |
| 55 | 9483 | `_rem_repair_image` | **`dism /Online /Cleanup-Image /RestoreHealth`** + `sfc /scannow` | Image repair | **KEEP** | `subprocess.run(["dism.exe", …])` + `sfc.exe` directly | COLD |
| 56 | 9509 | `_rem_clear_wu_cache` | `Stop-Service wuauserv` + `Remove-Item` | Clear WU download cache | **REPLACE** | `win32serviceutil` + `shutil.rmtree` | COLD |
| 57 | 9530 | `_rem_restart_spooler` | `Stop-Service Spooler; Start-Service Spooler` | Restart print spooler | **REPLACE** | `win32serviceutil.RestartService` | COLD |
| 58 | 9554 | `_rem_reset_network_adapter` | `Disable-NetAdapter` + `Enable-NetAdapter` | Reset physical NICs | **MAYBE** | `wmi.WMI().Win32_NetworkAdapter().Disable()` / `Enable()` | COLD |
| 59 | 9581 | `_rem_clear_icon_cache` | `Stop-Process explorer` + `Remove-Item IconCache.db` | Rebuild icon cache | **REPLACE** | `psutil` + `os.remove` + `subprocess.Popen(["explorer.exe"])` | COLD |
| 60 | 9599 | `_rem_reboot_system` | `shutdown /r /t 10` | Scheduled reboot | **KEEP** | `subprocess.run(["shutdown", "/r", "/t", "10"])` — drop PS | COLD |

> **Pattern:** all 10 remediation sites wrap a one-shot external tool (`ipconfig`, `netsh`, `dism`, `shutdown`, `sfc`) inside a `powershell -Command` call. Every one of these pays a ~200–400 ms PS cold start for zero benefit. Even the ones classified **KEEP** are fast wins — drop the PS wrapper, call the `.exe` directly. **Entire remediation file could become PS-free in one batch with no logic changes.**

---

## `homenet.py` — 11 sites

| # | Line | Function | PS used | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 1 | 666 | `_resolve_names_batch` | `Resolve-DnsName -Type PTR` | Reverse DNS for discovered IPs | **REPLACE** | `socket.gethostbyaddr` or `dnspython` | **HOT** (polling) |
| 2 | 717 | `_resolve_names_batch` | `nbtstat -A <ip>` via PS | NetBIOS name resolution | **REPLACE** | `subprocess.run(["nbtstat", …])` directly — drop PS | **HOT** |
| 3 | 780 | `_resolve_names_batch` | `Get-NetAdapter` WiFi check | Identify WiFi adapter | **REPLACE** | `psutil.net_if_stats` + `psutil.net_if_addrs` | **HOT** |
| 4 | 921 | `_arp_scan` | `Get-NetNeighbor -AddressFamily IPv4` | ARP table walk | **REPLACE** | `psutil` has no ARP; parse `subprocess.run(["arp", "-a"])` or use `scapy` | **HOT** |
| 5 | 1010 | `_wifi_ensure_orbi_connected` | `Get-NetAdapter -Name 'Wi-Fi'` | Check if Wi-Fi adapter is up | **REPLACE** | `psutil.net_if_stats` | COLD |
| 6 | 1050 | `_wifi_ensure_orbi_connected` | `Enable-NetAdapter -Name 'Wi-Fi'` | Enable Wi-Fi adapter | **MAYBE** | `wmi.Win32_NetworkAdapter().Enable()` | COLD |
| 7 | 1069 | `_wifi_ensure_orbi_connected` | **`netsh wlan connect name=<ssid>`** | Connect to Orbi SSID | **KEEP** | `subprocess.run(["netsh", …])` direct (already almost is) | COLD |
| 8 | 1079 | `_wifi_ensure_orbi_connected` | `Get-NetIPAddress -InterfaceAlias 'Wi-Fi'` | Confirm IP acquired | **REPLACE** | `psutil.net_if_addrs()` | COLD |
| 9 | 1100 | `_wifi_ensure_orbi_connected` | same, post-connect verification | Second IP check | **REPLACE** | `psutil.net_if_addrs()` | COLD |
| 10 | 1139 | `_get_orbi_ssid` | `netsh wlan show profiles` via PS | Enumerate saved WiFi profiles | **KEEP** | `subprocess.run(["netsh", …])` direct | COLD |
| 11 | 1168 | `_wifi_restore` | `Disable-NetAdapter -Name 'Wi-Fi'` | Disable Wi-Fi to restore ethernet | **MAYBE** | `wmi.Win32_NetworkAdapter().Disable()` | COLD |

> **Pattern:** 3 of the 4 HOT homenet sites (`_resolve_names_batch` + `_arp_scan`) run every 60 s on the polling loop. Even modest per-call savings compound quickly here. This is the second-best migration target after `windesktopmgr.get_process_list`.

---

## `SystemHealthDiag.py` — 3 sites

| # | Line | Function | Tool | Purpose | Class | Python replacement | Hot |
|---|---:|---|---|---|---|---|---|
| 1 | 85 | `ps` (helper) | `powershell.exe -Command <dynamic>` | Generic PS wrapper used throughout the diagnostic | **—** | helper itself stays; callers (inside the 10+ diag checks) migrate individually | — |
| 2 | 1518 | `convert_to_pdf` | `msedge.exe --headless --print-to-pdf` | HTML → PDF via Edge headless | **MAYBE** | `weasyprint` or `playwright` — larger dependency change | COLD |
| 3 | 1672 | `run_windesktopmgr_tests` | `python -m pytest` | Run the unit test suite from the diag | **REPLACE** | Already Python — no change needed | COLD |

> **Note:** the `ps()` helper at line 85 is a generic wrapper. The ~15 PS cmdlets it invokes (`Get-WmiObject MSAcpi_ThermalZoneTemperature`, `Get-Counter`, `Get-WinEvent`, `Get-HotFix`, etc.) are the actual migration targets. They're distributed across the 13 daily-report check functions. A follow-up audit pass should inventory `SystemHealthDiag.py`'s PS strings specifically.

---

## Top 10 HOT migration candidates (by likely user impact)

Ranked by: hot-path frequency × replacement simplicity × cold-start savings per call.

| Rank | File | Function | Line | Why |
|---:|---|---|---:|---|
| 1 | `windesktopmgr.py` | `get_process_list` | 5194 | Dashboard Process tab + NLQ + selftest. `psutil` is a one-liner. Saves ~300 ms per refresh. |
| 2 | `windesktopmgr.py` | `get_memory_analysis` | 6707/6721 | Called every dashboard render. Two PS calls collapse to one `psutil` pass. |
| 3 | `windesktopmgr.py` | `get_disk_health` (IO counters) | 2192 | Dashboard. `psutil.disk_io_counters(perdisk=True)`. Leaves the SMART PS call alone. |
| 4 | `windesktopmgr.py` | `get_network_data` | 3047/3053 | Dashboard Network tab. `psutil.net_connections` + `net_io_counters`. |
| 5 | `homenet.py` | `_resolve_names_batch` | 666/717/780 | 60 s polling loop. Three PS calls collapse into `socket.gethostbyaddr` + `psutil`. |
| 6 | `homenet.py` | `_arp_scan` | 921 | 60 s polling loop. Parse `arp -a` directly. |
| 7 | `windesktopmgr.py` | `get_driver_health` | 431 | Dashboard parallel check. `wmi` package, one-time dependency add. |
| 8 | `windesktopmgr.py` | `get_services_list` | 5822 | Services tab. `psutil.win_service_iter()` already gives name/status/display_name. |
| 9 | `windesktopmgr.py` | `warranty_data` (3 sites) | 8607/8624/8637 | SysInfo tab. Single `wmi` connection, three queries. |
| 10 | `windesktopmgr.py` | `sysinfo_data` | 8766 | SysInfo tab. Same `wmi` connection reusable with #9. |

Each of these is **≤ 2 hours** of work including tests. Ten items = roughly one focused week.

---

## Recommended migration batches

### Batch A — psutil-only quick wins (7 sites) — ✅ SHIPPED 2026-04-14
All are drop-in `psutil` substitutions with no new pypi dependencies (`psutil` is already pinned to `>=5.9.0,<8.0.0`).

| Site | Function | Replacement | Status |
|---|---|---|---|
| #19 | `get_disk_health` IO counters | `psutil.disk_io_counters(perdisk=True)` sampled twice ~1 s apart | ✅ |
| #22 | `get_network_data` connections | `psutil.net_connections(kind='tcp')` + pid→name map from `process_iter` | ✅ |
| #23 | `get_network_data` adapters | `psutil.net_if_stats` + `net_io_counters(pernic=True)` | ✅ |
| #29 | `get_process_list` | `psutil.process_iter` (CPU preserves cumulative-seconds semantics) | ✅ |
| #30 | `kill_process` | `psutil.Process.kill` | ✅ |
| #34 | `get_services_list` | `psutil.win_service_iter` + title-case Status/StartMode remap | ✅ |
| #36/#37 | `get_memory_analysis` | `psutil.virtual_memory` + `process_iter(['name','memory_info'])` | ✅ |

**Effort actual:** ~1 day (matches estimate). **Risk:** realized low — all 60 rewritten tests passed first-run, full suite 1332/1332 green at 85% coverage. **Test-target rewrite cost:** 6 classes + 1 route test + 2 snapshot tests + 2 e2e smoke tests; each class now mocks `psutil.*` returning `types.SimpleNamespace` objects instead of `subprocess.run` JSON payloads.

### Batch B — `wmi` package wins (9 sites) — ✅ SHIPPED 2026-04-16
Adds `wmi>=1.5.1` to `requirements.txt`. One persistent connection covers multiple queries.

| Sites | Functions | Status |
|---|---|---|
| #1, #2, #3 | driver family (Win32_PnPSignedDriver + Win32_VideoController) | ✅ |
| #38, #39, #43 | BIOS (Win32_BIOS) | ✅ |
| #47, #48, #49 | warranty (Win32_Processor, Win32_PhysicalMemory, Win32_OperatingSystem) | ✅ |
| #50 | sysinfo bulk bundle | ✅ |

**Effort actual:** ~1 day (matches estimate). **Risk:** realized medium — COM threading required `pythoncom.CoInitialize()` wrapper for Flask worker threads, and `dashboard_summary` needed `TimeoutError` handling for `as_completed()`. Full suite 1333/1333 green at 85% coverage. Added `_wmi_conn()` helper, `_wmi_date_to_str()`, plus mapping dicts for FormFactor/MemoryType/Architecture/SlotUsage codes. `sysinfo_data()` was the largest migration (14 WMI queries replacing one massive PS block).

### Batch C — `winreg` + `win32serviceutil` (6 sites) — ✅ SHIPPED 2026-04-16
Stdlib + `pywin32` (already installed from wmi in Batch B). No new deps.

| Sites | Functions | Status |
|---|---|---|
| #4 | `get_nvidia_update_info` registry → `winreg` | ✅ |
| #27, #28 | `_lookup_process_via_fileinfo` → `shutil.which` + `win32api.GetFileVersionInfo` | ✅ |
| #35 | `toggle_service` → `win32serviceutil` + `win32service.ChangeServiceConfig` | ✅ |
| #56, #57 | `_rem_clear_wu_cache` / `_rem_restart_spooler` → `win32serviceutil` + `shutil.rmtree` | ✅ |

**Effort actual:** ~½ day (matches estimate). **Risk:** realized low. Also added dashboard/summary verification to `post_restart_check.py` and tray startup retry (3 attempts with 10s delay) to prevent grey-icon-on-restart issue. Full suite 1334/1334 green at 85% coverage.

### Batch D — drop-the-PS-wrapper remediation actions (6 sites) ✅ SHIPPED 2026-04-17

No Python libs at all — just call the tool directly instead of wrapping it in PS.

| Sites | Migration | Status |
|---|---|---|
| #51 | `_rem_flush_dns` → `subprocess.run(["ipconfig", "/flushdns"])` direct | ✅ |
| #52 | `_rem_reset_winsock` → 2× `subprocess.run(["netsh", ...])` direct | ✅ |
| #53 | `_rem_reset_tcpip` → 3× `subprocess.run(["netsh", ...])` direct | ✅ |
| #55 | `_rem_repair_image` → `subprocess.run(["dism.exe", ...])` + `["sfc", "/scannow"]` | ✅ |
| #60 | `_rem_reboot_system` → `subprocess.run(["shutdown", ...])` direct | ✅ |
| #40 | `check_dell_bios_update` DCU method → `os.path.exists` + direct `[dcu-cli.exe, /scan]` + Python file I/O + regex | ✅ |

**Effort actual:** ~1.5 hours (under estimate). **Risk:** realized zero — output contracts identical, all 1341 tests green at 85% coverage.

### Batch E — HomeNet polling loop (4 sites) ✅ SHIPPED 2026-04-17

Called every 60 s so the migration pays back quickly in aggregate CPU.

| Sites | Migration | Status |
|---|---|---|
| #H1 | `_resolve_names_batch` DNS → `socket.gethostbyaddr` in `ThreadPoolExecutor` | ✅ |
| #H2 | `_resolve_names_batch` NBT → direct `subprocess.run(["nbtstat", "-A", ip])` | ✅ |
| #H3 | `_resolve_names_batch` Wi-Fi check → `socket.create_connection(("10.0.0.1", 443))` + direct nbtstat | ✅ |
| #H4 | `_arp_scan` → direct `subprocess.run(["arp", "-a"])` + Python regex parsing | ✅ |

**Effort actual:** ~1.5 hours (well under the 1-day estimate — test migration was simpler than expected). **Risk:** realized low — `socket.gethostbyaddr` uses the same OS resolver as `[System.Net.Dns]::GetHostEntry`. Added `_dns_resolve_ip` and `_nbt_resolve_ip` helper functions for clean testability. 1343 tests green at 85% coverage.

### Batch F — `Get-WinEvent` cluster (6 sites) ✅ SHIPPED 2026-04-17

One shared helper (`_query_event_log_xpath` built on `win32evtlog.EvtQuery` + XPath), then 6 cold-path migrations that route through it. (Audit originally counted 7; on migration we found the true count was 6 — the Setup-log row in the audit table had already been removed from `get_system_timeline` before the batch started.)

| Sites | Migration | Status |
|---|---|---|
| #7 | `get_bsod_events` → helper with `ids=[1001,41,6008]` on System log | ✅ |
| #8 | `query_event_log` (dynamic XPath for log + level filter, search applied in Python) | ✅ |
| #9 | `get_system_timeline` BSOD events (`ids=[41,1001,6008]` on System) | ✅ |
| #11 | `get_system_timeline` service events (`ids=[7036]` on System) | ✅ |
| #12 | `get_system_timeline` boot events (`ids=[6013]` on System) | ✅ |
| #13 | `get_system_timeline` credential events (`ids=[4625,4648]` on Security) | ✅ |

Helper renders human-readable message bodies via `EvtOpenPublisherMetadata` so the output contract is identical to the old PowerShell `$_.Message` value. Query runs in a `ThreadPoolExecutor` so callers keep the timeout guarantee they had with `subprocess.run(timeout=...)`.

**Skipped (bonus candidates, deferred):** the 2 `Get-WinEvent` calls inside `get_credentials_network_health` (Office/OneDrive error feed and Security log 4625/4648/4776). These are embedded inside larger PS blocks that also use `Get-SmbConnection`, `Get-NfsMappedDrive`, `Get-SmbClientConfiguration`, and `Get-NetFirewallRule` — migrating just the `Get-WinEvent` portion would leave a half-PS / half-Python block. Best addressed as part of a future "credentials/network block unbundle" rather than Batch F.

**Effort actual:** ~2 hours (well under the 2-day estimate — the one-helper-fits-all design meant the 6 call-site migrations each became a ~6-line rewrite). **Risk:** realized low — `win32evtlog.EvtQuery` exposes the exact same Windows Event Log Service that `Get-WinEvent` does, so the output shape, access-denied semantics (Security log without admin), and empty-result behaviour all matched the PS calls on the first run.

### Batch G — `Microsoft.Update.Session` COM (3 sites)
Requires a real prototype first. `pywin32 win32com.client.Dispatch` can talk to the same COM object PS uses, but the async operations (`IUpdateSearcher.BeginSearch`) are harder to drive from Python. **Suggest keeping in PS** unless batches A–F expose a reason to tackle it.

### Batch H — Keep in PowerShell
- #18 `Get-PhysicalDisk \| Get-StorageReliabilityCounter` — Storage Management API has no Python binding. SMART is vendor-specific.
- #31, #33 thermal providers — require LibreHardwareMonitor or vendor WMI namespaces (Dell `root\DCIM`).
- #16 `Get-ScheduledTask` — possible via `win32com.Schedule.Service` but brittle; see Batch G reasoning.

---

## Time savings analysis

Each `powershell.exe` invocation incurs a ~300 ms cold-start overhead (process creation + CLR init) before any actual work runs. Calling `.exe` tools directly or using Python APIs eliminates this overhead entirely.

### Per-batch savings

| Batch | Sites eliminated | HOT | WARM | COLD | Per-refresh saving | Per-call aggregate | Status |
|-------|:---:|:---:|:---:|:---:|---:|---:|---|
| **A** (psutil) | 7 | 2 | 3 | 2 | **~600 ms** | 2.1 s | ✅ Shipped |
| **B** (wmi) | 9 | 1 | 8 | 0 | **~300 ms** | 2.7 s | ✅ Shipped |
| **C** (winreg + pywin32) | 6 | 0 | 1 | 5 | 0 ms | 1.8 s | ✅ Shipped |
| **D** (direct exe) | 6 | 0 | 0 | 6 | 0 ms | 1.8 s | ✅ Shipped |
| **E** (HomeNet) | 4 | 4 | 0 | 0 | **~1.2 s / 60 s** | 1.2 s | ✅ Shipped |
| **F** (Get-WinEvent) | 6 | 0 | 6 | 0 | **~1.8 s / tab load** | 1.8 s | ✅ Shipped |
| **G** (COM WU) | 3 | 0 | 2 | 1 | 0 ms | 0.9 s | Deferred |
| **H** (Keep) | — | — | — | — | — | — | Permanent |

**Hot path** = called on every dashboard refresh / selftest / polling loop.
**Per-refresh saving** = time shaved off every `/api/dashboard/summary` or selftest cycle.
**Per-call aggregate** = total cold-start saved if all functions in the batch fire once.

### Cumulative shipped savings (Batches A–F)

| Metric | Value |
|--------|-------|
| PS subprocess calls eliminated | **38** |
| Hot-path calls eliminated | 7 (2 from A, 1 from B, 4 from E) |
| Warm-path calls eliminated | 24 (3 A, 8 B, 1 C, 6 timeline/events from F, etc.) |
| Dashboard refresh speedup | **~900 ms** (cumulative) |
| Polling loop speedup (60s cycle) | **~1.2 s** (Batch E — 4 HOT homenet calls) |
| Event-log tab / timeline load speedup | **~1.8 s** (Batch F — 6 WARM event-log calls) |
| Remaining PS calls (prod code) | ~31 |
| Original PS calls (baseline) | 74 |
| Migration progress | **51%** of sites, **61%** of REPLACE-class |

### Biggest remaining win

~~**Batch E** (HomeNet polling loop, 4 HOT sites)~~ — **shipped**.
~~**Batch F** (6 `Get-WinEvent` WARM-path sites)~~ — **shipped**.

**Next biggest win:** Batch G (`Microsoft.Update.Session` COM — 3 sites, ~900 ms). This is higher-risk than Batches A–F because COM async events (`IUpdateSearcher.BeginSearch` callbacks) are harder to drive from Python than from PS. Recommended: prototype in a branch, benchmark against current PS call, then decide.

---

## Patterns & observations

- **31 of the 74 sites (42%) use `Get-WmiObject` or `Get-CimInstance`.** Adding the `wmi` package to `requirements.txt` unlocks Batch B in one go. This is the single highest-ROI dependency addition on the list.
- **10 remediation sites wrap one-shot .exe calls in `powershell -Command`.** Every single one is a free cold-start saving. Batch D can land in one commit.
- **7 of the 14 MAYBE sites are `Get-WinEvent`.** Worth one focused migration (Batch F) rather than drip-feeding.
- **No PS call is used for anything that's truly irreplaceable at the platform level.** The "KEEP" classifications are pragmatic choices (vendor gating, cmdlet uniqueness) — not platform blockers. A fully PS-free windesktopmgr is technically achievable.
- **Test targets will move.** Every mocker.patch site on `windesktopmgr.subprocess.run` (hundreds of them in `test_powershell.py`) will need to move to `psutil.<fn>` / `wmi.*` / etc. This is the largest mechanical cost of the migration and should be factored into batch sizing. ~20 mock targets per batch is a reasonable rate.

---

## Next actions

This pass is **inventory only**. Migration batches are NOT scheduled yet. When the user greenlights execution:

1. Start with **Batch A (psutil-only)** — lowest risk, highest hot-path payoff, no new dependencies.
2. Before merging A, add `wmi>=1.5.1` to `requirements.txt` so **Batch B** can start immediately after.
3. **Batches C, D, E** are independent and can run in parallel (different code areas, different tests).
4. **Batches F, G, H** are explicitly deferred pending outcomes from A–E.

Regenerate the raw TSV any time with:

```bash
python scripts/audit_ps_sites.py
```
