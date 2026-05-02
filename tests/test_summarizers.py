"""
test_summarizers.py
Tests for all summarize_* functions — pure Python, no subprocess required.
"""

from datetime import datetime, timedelta, timezone

import windesktopmgr as wdm


def _recent_iso(days_ago: int = 10) -> str:
    """ISO-8601 timestamp ``days_ago`` days before now in UTC.

    Use this in test fixtures whenever the summarizer compares the
    timestamp against ``datetime.now()``. Hard-coded dates drift past
    the summarizer's stale-update threshold (60 days) once the wall
    clock moves far enough; clock-relative fixtures stay valid forever.
    Caught 2026-05-01 when test_all_succeeded_ok started failing because
    its 2026-03-01 fixture aged past the 60-day threshold.
    """
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


# ── Helper builders ────────────────────────────────────────────────────────────


def _driver(name, status, category="Display", low_priority=False, download_url=""):
    return {
        "name": name,
        "status": status,
        "category": category,
        "low_priority": low_priority,
        "version": "1.0",
        "date": "",
        "manufacturer": "",
        "latest_version": None,
        "latest_date": None,
        "download_url": download_url,
        "category_note": "",
    }


def _crash(error_code, timestamp="2026-03-01T10:00:00+00:00", faulty_driver=None):
    return {
        "timestamp": timestamp,
        "error_code": error_code,
        "stop_code": "0x00000000",
        "faulty_driver": faulty_driver,
        "source": "event_log",
        "event_id": 1001,
    }


def _bsod_data(crashes, timeline=None, avg_uptime=0, this_month=0):
    total = len(crashes)
    return {
        "crashes": crashes,
        "summary": {
            "total_crashes": total,
            "this_month": this_month,
            "most_common_error": crashes[0]["error_code"] if crashes else "None",
            "avg_uptime_hours": avg_uptime,
        },
        "timeline": timeline or [],
        "recommendations": [],
        "error_breakdown": [],
        "driver_breakdown": [],
    }


def _drive(letter, pct_used, free_gb=50, drive_type=3, unc_path=None):
    """Build a drive dict. drive_type defaults to 3 (local) to match Win32_LogicalDisk.

    DriveType 3 = local fixed, 4 = network/CIFS, 2 = removable.
    """
    d = {"Letter": letter, "PctUsed": pct_used, "FreeGB": free_gb, "DriveType": drive_type}
    if unc_path:
        d["UNCPath"] = unc_path
    return d


def _physical(name, health="Healthy", media_type="SSD"):
    return {"Name": name, "Health": health, "MediaType": media_type, "SizeGB": 500}


def _startup_item(name, enabled=True, suspicious=False, location="HKLM", item_type="registry_hklm"):
    return {
        "Name": name,
        "Enabled": enabled,
        "suspicious": suspicious,
        "Location": location,
        "Type": item_type,
        "Command": f"C:\\Program Files\\{name}\\{name}.exe",
    }


def _service(name, display_name, status="Running", start_mode="Auto"):
    return {
        "Name": name,
        "DisplayName": display_name,
        "Status": status,
        "StartMode": start_mode,
    }


def _process(name, mem_mb, cpu=0, flag=None, info=None):
    p = {"Name": name, "MemMB": mem_mb, "CPU": cpu}
    if flag:
        p["flag"] = flag
        p["info"] = info or {"plain": name, "what": "A process", "publisher": "", "safe_kill": True}
    else:
        p["info"] = info
    return p


# ══════════════════════════════════════════════════════════════════════════════
# summarize_drivers
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeDrivers:
    def test_empty_list_returns_idle(self):
        result = wdm.summarize_drivers([])
        assert result["status"] == "idle"

    def test_all_up_to_date_returns_ok(self):
        drivers = [_driver("NVIDIA", "up_to_date"), _driver("Intel", "up_to_date", "Network")]
        result = wdm.summarize_drivers(drivers)
        assert result["status"] == "ok"

    def test_update_available_returns_warning(self):
        drivers = [_driver("NVIDIA", "update_available", "Display")]
        result = wdm.summarize_drivers(drivers)
        assert result["status"] in ("warning", "critical")

    def test_critical_category_update_returns_critical(self):
        drivers = [_driver("NVIDIA GPU", "update_available", "Display", low_priority=False)]
        result = wdm.summarize_drivers(drivers)
        assert result["status"] == "critical"

    def test_low_priority_update_not_critical(self):
        drivers = [_driver("Generic Monitor", "update_available", "Monitor", low_priority=True)]
        result = wdm.summarize_drivers(drivers)
        # Monitor is low priority — should not escalate to critical
        assert result["status"] != "critical"

    def test_unknown_drivers_info_insight(self):
        drivers = [_driver("Mystery Device", "unknown")]
        result = wdm.summarize_drivers(drivers)
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_headline_mentions_update_count(self):
        drivers = [_driver("NVIDIA", "update_available", "Display")]
        result = wdm.summarize_drivers(drivers)
        assert "1" in result["headline"]

    def test_network_update_is_critical(self):
        drivers = [_driver("Intel Ethernet", "update_available", "Network")]
        result = wdm.summarize_drivers(drivers)
        assert result["status"] == "critical"

    def test_all_unknown_headline_not_up_to_date(self):
        """When all drivers are unknown (WU failed), headline should NOT say 'up to date'."""
        drivers = [_driver("Device A", "unknown"), _driver("Device B", "unknown")]
        result = wdm.summarize_drivers(drivers)
        assert "up to date" not in result["headline"].lower()
        assert "could not be verified" in result["headline"] or "unknown" in result["headline"]

    def test_mixed_ok_and_unknown_headline(self):
        drivers = [_driver("Intel NIC", "up_to_date"), _driver("Mystery", "unknown")]
        result = wdm.summarize_drivers(drivers)
        assert "1" in result["headline"]  # at least mentions count
        assert "up to date" not in result["headline"].lower() or "unknown" in result["headline"]

    def test_nvidia_only_updates_show_nvidia_action(self):
        drivers = [_driver("NVIDIA RTX 4060 Ti", "update_available", "Display", download_url="nvidia-app:")]
        result = wdm.summarize_drivers(drivers)
        assert "Update via NVIDIA App" in result["actions"]
        assert "Open Windows Update" not in result["actions"]

    def test_wu_only_updates_show_wu_action(self):
        drivers = [_driver("HP Audio", "update_available", "Audio", download_url="ms-settings:windowsupdate")]
        result = wdm.summarize_drivers(drivers)
        assert "Open Windows Update" in result["actions"]
        assert "Update via NVIDIA App" not in result["actions"]

    def test_mixed_nvidia_and_wu_updates_show_both_actions(self):
        drivers = [
            _driver("NVIDIA RTX 4060 Ti", "update_available", "Display", download_url="nvidia-app:"),
            _driver("HP Audio", "update_available", "Audio", download_url="ms-settings:windowsupdate"),
        ]
        result = wdm.summarize_drivers(drivers)
        assert "Update via NVIDIA App" in result["actions"]
        assert "Open Windows Update" in result["actions"]


# ══════════════════════════════════════════════════════════════════════════════
# summarize_bsod
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeBsod:
    def test_zero_crashes_returns_ok(self):
        result = wdm.summarize_bsod(_bsod_data([]))
        assert result["status"] == "ok"
        assert "stable" in result["headline"].lower()

    def test_more_than_3_this_month_critical(self):
        crashes = [_crash("HYPERVISOR_ERROR")] * 5
        data = _bsod_data(crashes, this_month=5)
        result = wdm.summarize_bsod(data)
        levels = [i["level"] for i in result["insights"]]
        assert "critical" in levels

    def test_avg_uptime_below_24h_critical(self):
        crashes = [_crash("HYPERVISOR_ERROR")]
        data = _bsod_data(crashes, avg_uptime=12, this_month=1)
        result = wdm.summarize_bsod(data)
        levels = [i["level"] for i in result["insights"]]
        assert "critical" in levels

    def test_trending_upward_warning(self):
        timeline = [
            {"label": "W1", "count": 0},
            {"label": "W2", "count": 0},
            {"label": "W3", "count": 1},
            {"label": "W4", "count": 3},
        ]
        crashes = [_crash("HYPERVISOR_ERROR")] * 4
        data = _bsod_data(crashes, timeline=timeline, this_month=4)
        result = wdm.summarize_bsod(data)
        texts = " ".join(i["text"] for i in result["insights"])
        assert "trending" in texts.lower() or result["status"] in ("warning", "critical")

    def test_trending_downward_ok_insight(self):
        timeline = [
            {"label": "W1", "count": 3},
            {"label": "W2", "count": 2},
            {"label": "W3", "count": 0},
            {"label": "W4", "count": 0},
        ]
        crashes = [_crash("HYPERVISOR_ERROR")] * 5
        data = _bsod_data(crashes, timeline=timeline, this_month=0)
        result = wdm.summarize_bsod(data)
        texts = " ".join(i["text"] for i in result["insights"])
        assert "trending" in texts.lower() or "downward" in texts.lower()

    def test_result_has_required_keys(self):
        result = wdm.summarize_bsod(_bsod_data([]))
        assert "status" in result
        assert "headline" in result
        assert "insights" in result
        assert "actions" in result


# ══════════════════════════════════════════════════════════════════════════════
# summarize_startup
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeStartup:
    def test_empty_list_ok(self):
        result = wdm.summarize_startup([])
        assert result["status"] == "ok"

    def test_suspicious_item_critical(self):
        items = [_startup_item("evil", suspicious=True)]
        result = wdm.summarize_startup(items)
        assert result["status"] == "critical"

    def test_suspicious_item_in_insights(self):
        items = [_startup_item("malware", suspicious=True)]
        result = wdm.summarize_startup(items)
        levels = [i["level"] for i in result["insights"]]
        assert "critical" in levels

    def test_more_than_20_enabled_warning(self):
        items = [_startup_item(f"App{i}", enabled=True) for i in range(21)]
        result = wdm.summarize_startup(items)
        assert result["status"] == "warning"

    def test_normal_items_ok(self):
        items = [_startup_item("Chrome", enabled=True), _startup_item("Spotify", enabled=True)]
        result = wdm.summarize_startup(items)
        assert result["status"] == "ok"

    def test_no_suspicious_includes_ok_insight(self):
        items = [_startup_item("Chrome")]
        result = wdm.summarize_startup(items)
        levels = [i["level"] for i in result["insights"]]
        assert "ok" in levels


# ══════════════════════════════════════════════════════════════════════════════
# summarize_disk
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeDisk:
    def test_all_healthy_ok(self):
        data = {"drives": [_drive("C", 50)], "physical": [_physical("Samsung SSD")]}
        result = wdm.summarize_disk(data)
        assert result["status"] == "ok"

    def test_drive_over_90_critical(self):
        data = {"drives": [_drive("C", 92, free_gb=5)], "physical": [_physical("Samsung SSD")]}
        result = wdm.summarize_disk(data)
        assert result["status"] == "critical"

    def test_drive_75_to_89_warning(self):
        data = {"drives": [_drive("C", 80)], "physical": [_physical("Samsung SSD")]}
        result = wdm.summarize_disk(data)
        assert result["status"] == "warning"

    def test_unhealthy_physical_critical(self):
        data = {
            "drives": [_drive("C", 50)],
            "physical": [_physical("WD Hard Drive", health="Unhealthy")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "critical"

    def test_hdd_media_type_info_insight(self):
        data = {
            "drives": [_drive("C", 50)],
            "physical": [_physical("WD HDD", media_type="HDD")],
        }
        result = wdm.summarize_disk(data)
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_empty_data_ok(self):
        result = wdm.summarize_disk({"drives": [], "physical": []})
        assert result["status"] == "ok"

    def test_critical_drive_letter_in_insight(self):
        data = {"drives": [_drive("D", 95, free_gb=2)], "physical": [_physical("SSD")]}
        result = wdm.summarize_disk(data)
        texts = " ".join(i["text"] for i in result["insights"])
        assert "D" in texts

    # ── CIFS / network drive classification (bug fix 2026-04) ────────────────
    # Previously all drives were treated uniformly — a NAS share at 95% full
    # would trigger a bogus "critical" alert for the local machine. The fix:
    # - DriveType=3 (local): critical @ 90%+, warning @ 75-89% (unchanged)
    # - DriveType=4 (network): warning at both thresholds, NEVER critical
    #   (a full NAS is worth surfacing but won't crash this machine).

    def test_network_drive_full_is_warning_not_critical(self):
        """A mapped CIFS share at 95% full is a warning, not a local-disk critical."""
        data = {
            "drives": [_drive("Q", 95, free_gb=100, drive_type=4, unc_path=r"\\nas\photos")],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "warning"
        levels = [i["level"] for i in result["insights"]]
        # Warnings allowed, but no criticals
        assert "warning" in levels
        assert "critical" not in levels

    def test_network_drive_full_insight_labels_as_remote(self):
        """A near-full network share is clearly labelled as remote NAS, not a local disk."""
        data = {
            "drives": [_drive("Q", 96, free_gb=80, drive_type=4, unc_path=r"\\nas\photos")],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        texts = " ".join(i["text"] for i in result["insights"])
        assert "Network share" in texts
        assert "Q" in texts
        assert r"\\nas\photos" in texts

    def test_network_drive_75_to_89_warning_approaching(self):
        """Network drives should still get an 'approaching capacity' warning."""
        data = {
            "drives": [_drive("N", 82, drive_type=4, unc_path=r"\\nas\plex")],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "warning"
        texts = " ".join(i["text"] for i in result["insights"])
        assert "approaching capacity" in texts

    def test_network_drive_below_75_no_warning(self):
        """Network drive at 50% should not trigger any warning."""
        data = {
            "drives": [
                _drive("C", 40),
                _drive("Q", 50, drive_type=4, unc_path=r"\\nas\photos"),
            ],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "ok"

    def test_full_network_does_not_escalate_to_critical(self):
        """Multiple full network drives must never push status to critical."""
        data = {
            "drives": [
                _drive("C", 40),
                _drive("N", 95, drive_type=4, unc_path=r"\\nas\plex"),
                _drive("Q", 98, drive_type=4, unc_path=r"\\nas\photos"),
            ],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "warning"

    def test_local_drive_still_critical_when_network_present(self):
        """Mixing drive types: critical local drive is still critical."""
        data = {
            "drives": [
                _drive("C", 95, free_gb=5),
                _drive("Q", 50, drive_type=4, unc_path=r"\\nas\photos"),
            ],
            "physical": [_physical("Samsung SSD")],
        }
        result = wdm.summarize_disk(data)
        assert result["status"] == "critical"

    def test_missing_drivetype_defaults_to_local(self):
        """Backward compat: cached payloads without DriveType still trigger critical."""
        drive_no_type = {"Letter": "C", "PctUsed": 95, "FreeGB": 5}
        data = {"drives": [drive_no_type], "physical": [_physical("SSD")]}
        result = wdm.summarize_disk(data)
        assert result["status"] == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# summarize_network
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeNetwork:
    def _base_data(self, established=None, adapters=None, top_procs=None):
        return {
            "established": established or [],
            "adapters": adapters or [{"Name": "Ethernet", "Status": "Up"}],
            "top_processes": top_procs or [{"process": "chrome.exe", "connections": 5}],
            "total_connections": len(established or []),
        }

    def test_clean_network_ok(self):
        result = wdm.summarize_network(self._base_data())
        assert result["status"] == "ok"

    def test_unusual_port_4444_warning(self):
        conn = {"RemotePort": 4444, "Process": "mystery.exe", "RemoteAddress": "1.2.3.4"}
        result = wdm.summarize_network(self._base_data(established=[conn]))
        assert result["status"] == "critical"

    def test_unusual_port_1337_flagged(self):
        conn = {"RemotePort": 1337, "Process": "hax.exe", "RemoteAddress": "1.2.3.4"}
        result = wdm.summarize_network(self._base_data(established=[conn]))
        levels = [i["level"] for i in result["insights"]]
        assert "warning" in levels

    def test_down_adapter_warning(self):
        adapters = [{"Name": "Wi-Fi", "Status": "Down"}]
        result = wdm.summarize_network(self._base_data(adapters=adapters))
        assert result["status"] == "warning"

    def test_process_over_20_connections_warning(self):
        top_procs = [{"process": "chrome.exe", "connections": 25}]
        result = wdm.summarize_network(self._base_data(top_procs=top_procs))
        assert result["status"] == "warning"

    def test_result_has_required_keys(self):
        result = wdm.summarize_network(self._base_data())
        assert {"status", "headline", "insights", "actions"} <= set(result.keys())


# ══════════════════════════════════════════════════════════════════════════════
# summarize_updates
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeUpdates:
    def test_empty_list_info(self):
        result = wdm.summarize_updates([])
        assert result["status"] == "info"

    def test_failed_update_warning(self):
        items = [
            {"Title": "KB12345", "result": "Failed", "Date": "2026-02-01T00:00:00+00:00"},
            {"Title": "KB00001", "result": "Succeeded", "Date": "2026-02-15T00:00:00+00:00"},
        ]
        result = wdm.summarize_updates(items)
        assert result["status"] == "warning"

    def test_all_succeeded_ok(self):
        # Use a clock-relative date (10 days ago) so this test stays valid
        # forever -- hard-coded "2026-03-01" originally trip-wired the
        # 60-day stale-updates warning once the wall clock moved past
        # 2026-05-01. See _recent_iso() docstring.
        items = [
            {"Title": "KB12345", "result": "Succeeded", "Date": _recent_iso(days_ago=10)},
        ]
        result = wdm.summarize_updates(items)
        assert result["status"] == "ok"

    def test_stale_update_over_60_days_warning(self):
        items = [
            # Only successful update was >60 days ago -- use clock-relative
            # so this test still asserts the 60-day threshold even when
            # the wall clock advances past any hard-coded date.
            {"Title": "KB00001", "result": "Succeeded", "Date": _recent_iso(days_ago=120)},
        ]
        result = wdm.summarize_updates(items)
        assert result["status"] == "warning"

    def test_no_failed_updates_ok_insight(self):
        items = [
            {"Title": "KB12345", "result": "Succeeded", "Date": _recent_iso(days_ago=10)},
        ]
        result = wdm.summarize_updates(items)
        levels = [i["level"] for i in result["insights"]]
        assert "ok" in levels


# ══════════════════════════════════════════════════════════════════════════════
# summarize_services
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeServices:
    def test_empty_list_ok(self):
        result = wdm.summarize_services([])
        assert result["status"] == "ok"

    def test_all_auto_running_ok(self):
        svcs = [
            _service("wuauserv", "Windows Update", status="Running", start_mode="Auto"),
            _service("bits", "BITS", status="Running", start_mode="Auto"),
        ]
        result = wdm.summarize_services(svcs)
        assert result["status"] == "ok"

    def test_auto_start_stopped_warning(self):
        svcs = [
            _service("wuauserv", "Windows Update", status="Stopped", start_mode="Auto"),
        ]
        result = wdm.summarize_services(svcs)
        assert result["status"] == "warning"

    def test_diagtrack_running_info_insight(self):
        svcs = [
            _service("diagtrack", "Connected User Experiences", status="Running", start_mode="Auto"),
        ]
        result = wdm.summarize_services(svcs)
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_result_has_required_keys(self):
        result = wdm.summarize_services([_service("spooler", "Print Spooler")])
        assert {"status", "headline", "insights", "actions"} <= set(result.keys())

    def test_spooler_stopped_not_flagged_as_problem(self):
        # spooler is explicitly excluded from the auto-stopped warning
        svcs = [_service("spooler", "Print Spooler", status="Stopped", start_mode="Auto")]
        result = wdm.summarize_services(svcs)
        assert result["status"] == "ok"


# ══════════════════════════════════════════════════════════════════════════════
# summarize_processes
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeProcesses:
    def _data(self, procs, flagged=None):
        total_mem = sum(p.get("MemMB", 0) for p in procs)
        return {
            "processes": procs,
            "flagged": flagged or [],
            "total": len(procs),
            "total_mem_mb": total_mem,
        }

    def test_empty_processes_ok(self):
        result = wdm.summarize_processes(self._data([]))
        assert result["status"] == "ok"

    def test_critical_memory_hog_critical_status(self):
        hog = _process(
            "memoryhog.exe",
            mem_mb=2000,
            flag="critical",
            info={"plain": "Memory Hog", "what": "Uses lots of RAM", "publisher": "Unknown", "safe_kill": True},
        )
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        assert result["status"] == "critical"

    def test_critical_safe_kill_false_action(self):
        hog = _process(
            "windefend.exe",
            mem_mb=2000,
            flag="critical",
            info={"plain": "Windows Defender", "what": "Security", "publisher": "Microsoft", "safe_kill": False},
        )
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        actions = " ".join(i["action"] for i in result["insights"])
        assert "do not kill" in actions.lower() or "system" in actions.lower()

    def test_critical_safe_kill_true_action(self):
        hog = _process(
            "chrome.exe",
            mem_mb=2000,
            flag="critical",
            info={"plain": "Chrome", "what": "Browser", "publisher": "Google", "safe_kill": True},
        )
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        actions = " ".join(i["action"] for i in result["insights"])
        assert "safe to kill" in actions.lower()

    def test_warning_level_process(self):
        warn = _process(
            "slack.exe",
            mem_mb=600,
            flag="warning",
            info={"plain": "Slack", "what": "Chat app", "publisher": "Slack", "safe_kill": True},
        )
        result = wdm.summarize_processes(self._data([warn], flagged=[warn]))
        assert result["status"] == "warning"

    def test_normal_processes_ok(self):
        p1 = _process("chrome.exe", mem_mb=300)
        p2 = _process("notepad.exe", mem_mb=10)
        result = wdm.summarize_processes(self._data([p1, p2]))
        assert result["status"] == "ok"


# ══════════════════════════════════════════════════════════════════════════════
# summarize_thermals
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeThermals:
    def _data(self, temps=None, cpu_pct=20, mem_used=8000, mem_total=32000, has_rich=False):
        return {
            "temps": temps or [],
            "perf": {"CPUPct": cpu_pct, "MemUsedMB": mem_used, "MemTotalMB": mem_total},
            "fans": [],
            "has_rich": has_rich,
        }

    def test_no_temps_no_rich_info_insight(self):
        result = wdm.summarize_thermals(self._data())
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_critical_temp_critical_status(self):
        temps = [{"Name": "CPU", "TempC": 100, "status": "critical"}]
        result = wdm.summarize_thermals(self._data(temps=temps))
        assert result["status"] == "critical"

    def test_warning_temp_warning_status(self):
        temps = [{"Name": "CPU", "TempC": 85, "status": "warning"}]
        result = wdm.summarize_thermals(self._data(temps=temps))
        assert result["status"] == "warning"

    def test_ok_temp_ok_insight(self):
        temps = [{"Name": "CPU", "TempC": 55, "status": "ok"}]
        result = wdm.summarize_thermals(self._data(temps=temps))
        levels = [i["level"] for i in result["insights"]]
        assert "ok" in levels

    def test_high_cpu_warning(self):
        result = wdm.summarize_thermals(self._data(cpu_pct=95))
        assert result["status"] == "critical"

    def test_moderately_busy_cpu_info(self):
        result = wdm.summarize_thermals(self._data(cpu_pct=65))
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_high_ram_usage_critical(self):
        # 95% RAM usage → critical
        result = wdm.summarize_thermals(self._data(mem_used=30400, mem_total=32000))
        levels = [i["level"] for i in result["insights"]]
        assert "critical" in levels

    def test_result_has_required_keys(self):
        result = wdm.summarize_thermals(self._data())
        assert {"status", "headline", "insights", "actions"} <= set(result.keys())


# ══════════════════════════════════════════════════════════════════════════════
# summarize_sysinfo
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeSysinfo:
    """Tests for the summarize_sysinfo function."""

    @staticmethod
    def _data(
        ram_gb=32,
        uptime="01.05:30:00",
        cpu_name="Intel(R) Core(TM) i9-14900K",
        cores=24,
        logical=32,
        os_name="Microsoft Windows 11 Pro",
        build="22631",
        install_date="2024-01-15",
        manufacturer="Dell Inc.",
        model="XPS 8960",
        memory=None,
        gpu=None,
        sound=None,
        nic_hw=None,
    ):
        d = {
            "Computer": {"Manufacturer": manufacturer, "Model": model, "TotalRAM_GB": ram_gb},
            "OS": {"Name": os_name, "Uptime": uptime, "Build": build, "InstallDate": install_date},
            "CPU": {"Name": cpu_name, "Cores": cores, "LogicalProcs": logical},
        }
        if memory is not None:
            d["Memory"] = memory
        if gpu is not None:
            d["GPU"] = gpu
        if sound is not None:
            d["Sound"] = sound
        if nic_hw is not None:
            d["NetworkHardware"] = nic_hw
        return d

    def test_returns_required_keys(self):
        result = wdm.summarize_sysinfo(self._data())
        assert {"status", "headline", "insights", "actions"} <= set(result.keys())

    def test_ok_status_for_normal_system(self):
        result = wdm.summarize_sysinfo(self._data())
        assert result["status"] == "ok"

    def test_headline_contains_manufacturer_and_cpu(self):
        result = wdm.summarize_sysinfo(self._data())
        assert "Dell" in result["headline"]
        assert "i9-14900K" in result["headline"]

    def test_warning_for_high_uptime(self):
        result = wdm.summarize_sysinfo(self._data(uptime="15.00:00:00"))
        assert result["status"] == "warning"
        levels = [i["level"] for i in result["insights"]]
        assert "warning" in levels

    def test_info_for_moderate_uptime(self):
        result = wdm.summarize_sysinfo(self._data(uptime="08.12:00:00"))
        # Moderate uptime should be info, not warning
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_no_uptime_warning_for_short_uptime(self):
        result = wdm.summarize_sysinfo(self._data(uptime="02.05:30:00"))
        levels = [i["level"] for i in result["insights"]]
        assert "warning" not in levels

    def test_warning_for_low_ram(self):
        result = wdm.summarize_sysinfo(self._data(ram_gb=8))
        assert result["status"] == "warning"
        texts = " ".join(i["text"] for i in result["insights"])
        assert "8" in texts

    def test_ok_for_sufficient_ram(self):
        result = wdm.summarize_sysinfo(self._data(ram_gb=32))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "32" in texts

    def test_cpu_insight_present(self):
        result = wdm.summarize_sysinfo(self._data())
        texts = " ".join(i["text"] for i in result["insights"])
        assert "i9-14900K" in texts

    def test_os_insight_present(self):
        result = wdm.summarize_sysinfo(self._data())
        texts = " ".join(i["text"] for i in result["insights"])
        assert "Windows 11" in texts

    def test_empty_data_returns_warning(self):
        result = wdm.summarize_sysinfo({})
        assert result["status"] == "warning"
        assert "unavailable" in result["headline"].lower()
        assert len(result["insights"]) > 0
        assert result["insights"][0]["level"] == "warning"

    def test_partial_data_does_not_crash(self):
        """Only Computer key present — should not raise."""
        result = wdm.summarize_sysinfo({"Computer": {"Name": "TEST", "TotalRAM_GB": 16}})
        assert "status" in result

    def test_actions_populated_on_high_uptime(self):
        result = wdm.summarize_sysinfo(self._data(uptime="20.00:00:00"))
        assert len(result["actions"]) > 0
        assert "reboot" in result["actions"][0].lower()

    def test_memory_type_insight_ddr5(self):
        mem = [{"MemoryType": "DDR5", "ConfiguredClockSpeed": 5600, "Capacity": 17179869184}]
        result = wdm.summarize_sysinfo(self._data(memory=mem))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "DDR5" in texts

    def test_memory_type_insight_ddr4(self):
        mem = [{"MemoryType": "DDR4", "ConfiguredClockSpeed": 3200, "Capacity": 8589934592}]
        result = wdm.summarize_sysinfo(self._data(memory=mem))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "DDR4" in texts
        # DDR4 should be info level
        mem_insights = [i for i in result["insights"] if "DDR4" in i["text"]]
        assert mem_insights[0]["level"] == "info"

    def test_gpu_manufacturer_in_insight(self):
        gpu = [
            {
                "Name": "GeForce RTX 4060 Ti",
                "AdapterCompatibility": "NVIDIA",
                "DriverVersion": "32.0",
                "AdapterRAM": 8589934592,
            }
        ]
        result = wdm.summarize_sysinfo(self._data(gpu=gpu))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "NVIDIA" in texts
        assert "RTX 4060" in texts

    def test_sound_devices_insight(self):
        snd = [{"Name": "Realtek HD Audio", "Manufacturer": "Realtek", "Status": "OK"}]
        result = wdm.summarize_sysinfo(self._data(sound=snd))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "audio" in texts.lower()

    def test_nic_hardware_insight(self):
        nic = [{"Name": "Killer E3100G", "Manufacturer": "Intel"}]
        result = wdm.summarize_sysinfo(self._data(nic_hw=nic))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "network" in texts.lower()


# ══════════════════════════════════════════════════════════════════════════════
# summarize_credentials_network
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeCredentialsNetwork:
    def _data(self, **overrides):
        base = {
            "drives": [],
            "drives_down": [],
            "email_creds": [{"Target": "MicrosoftOffice16_Data:live:user@example.com"}],
            "fast_startup": False,
            "cred_failures": [],
            "fw_blocking": [],
            "smb_config": None,
            "nfs_drives": [],
            "msal_token_stale": False,
            "msal_token_age_h": None,
            "onedrive_running": True,
            "onedrive_connected": True,
            "onedrive_account": "user@example.com",
            "office_errors": [],
            "onedrive_suspended": False,
            "onedrive_priority": "",
            "suspended_auth_procs": [],
            "total_creds": 5,
        }
        base.update(overrides)
        return base

    def test_healthy_returns_ok(self):
        result = wdm.summarize_credentials_network(self._data())
        assert result["status"] == "ok"

    def test_fast_startup_enabled_warning(self):
        result = wdm.summarize_credentials_network(self._data(fast_startup=True))
        assert result["status"] == "warning"
        assert "Fast Startup" in result["headline"]

    def test_fast_startup_disabled_ok(self):
        result = wdm.summarize_credentials_network(self._data(fast_startup=False))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "disabled" in texts.lower()

    def test_fast_startup_none_info(self):
        result = wdm.summarize_credentials_network(self._data(fast_startup=None))
        levels = [i["level"] for i in result["insights"]]
        assert "info" in levels

    def test_drives_down_critical(self):
        down = [{"Name": "Z:", "DisplayRoot": "\\\\nas\\share"}]
        result = wdm.summarize_credentials_network(self._data(drives_down=down))
        assert result["status"] == "critical"
        assert "unreachable" in result["headline"]

    def test_all_drives_reachable_ok(self):
        drives = [{"Name": "Z:", "DisplayRoot": "\\\\nas\\share"}]
        result = wdm.summarize_credentials_network(self._data(drives=drives))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "reachable" in texts.lower()

    def test_onedrive_suspended_critical(self):
        result = wdm.summarize_credentials_network(self._data(onedrive_suspended=True))
        assert result["status"] == "critical"
        assert "SUSPENDED" in result["headline"]

    def test_suspended_auth_procs_warning(self):
        procs = [{"Name": "AADBrokerPlugin"}]
        result = wdm.summarize_credentials_network(self._data(suspended_auth_procs=procs))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "auth-related" in texts.lower()

    def test_token_stale_critical(self):
        result = wdm.summarize_credentials_network(self._data(msal_token_stale=True, msal_token_age_h=48.0))
        assert result["status"] == "critical"
        assert "token expired" in result["headline"].lower()

    def test_token_stale_not_shown_when_suspended(self):
        """When OneDrive is suspended, the suspension insight takes priority."""
        result = wdm.summarize_credentials_network(
            self._data(onedrive_suspended=True, msal_token_stale=True, msal_token_age_h=48.0)
        )
        assert "SUSPENDED" in result["headline"]

    def test_onedrive_not_connected_warning(self):
        result = wdm.summarize_credentials_network(self._data(onedrive_connected=False))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "not connected" in texts.lower()

    def test_onedrive_not_running_warning(self):
        result = wdm.summarize_credentials_network(self._data(onedrive_running=False, onedrive_connected=True))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "not running" in texts.lower()

    def test_onedrive_connected_ok(self):
        result = wdm.summarize_credentials_network(
            self._data(onedrive_connected=True, onedrive_running=True, msal_token_age_h=2.0)
        )
        texts = " ".join(i["text"] for i in result["insights"])
        assert "connected" in texts.lower()

    def test_office_errors_warning(self):
        result = wdm.summarize_credentials_network(self._data(office_errors=[{"Id": 1}]))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "error event" in texts.lower()

    def test_nfs_drives_all_reachable(self):
        nfs = [{"Name": "Y:", "DisplayRoot": "//nas/nfs", "Reachable": True}]
        result = wdm.summarize_credentials_network(self._data(nfs_drives=nfs))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "NFS" in texts and "reachable" in texts.lower()

    def test_nfs_drives_some_down(self):
        nfs = [{"Name": "Y:", "DisplayRoot": "//nas/nfs", "Reachable": False}]
        result = wdm.summarize_credentials_network(self._data(nfs_drives=nfs))
        levels = [i["level"] for i in result["insights"]]
        assert "critical" in levels

    def test_email_creds_present(self):
        creds = [{"Target": "MicrosoftOffice16_Data:live:user@example.com"}]
        result = wdm.summarize_credentials_network(self._data(email_creds=creds))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "email credential" in texts.lower()

    def test_no_email_creds_warning(self):
        result = wdm.summarize_credentials_network(self._data(email_creds=[]))
        assert result["status"] == "warning"

    def test_cred_failures_warning(self):
        failures = [{"Id": 4625}]
        result = wdm.summarize_credentials_network(self._data(cred_failures=failures))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "credential failure" in texts.lower()

    def test_fw_blocking_warning(self):
        rules = [{"DisplayName": "File and Printer Sharing (SMB-In)"}]
        result = wdm.summarize_credentials_network(self._data(fw_blocking=rules))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "Block" in texts or "firewall" in texts.lower()

    def test_smb_signing_required_info(self):
        result = wdm.summarize_credentials_network(self._data(smb_config={"RequireSecuritySignature": True}))
        texts = " ".join(i["text"] for i in result["insights"])
        assert "SMB" in texts and "signing" in texts.lower()

    def test_empty_data_does_not_crash(self):
        result = wdm.summarize_credentials_network({})
        assert "status" in result
        assert "insights" in result


# ══════════════════════════════════════════════════════════════════════════════
# summarize_events
# ══════════════════════════════════════════════════════════════════════════════


def _event(event_id, level="Information", source="TestSource", message="Test message"):
    return {
        "Time": "2026-03-10T08:00:00",
        "Id": event_id,
        "Level": level,
        "Source": source,
        "Message": message,
    }


class TestSummarizeEvents:
    def test_empty_list_returns_ok(self):
        result = wdm.summarize_events([])
        assert result["status"] == "ok"
        assert result["insights"] == []

    def test_normal_info_events_returns_ok(self):
        events = [_event(7036, "Information"), _event(7040, "Information")]
        result = wdm.summarize_events(events)
        assert result["status"] == "ok"
        assert "headline" in result
        assert "insights" in result

    def test_error_events_return_warning_or_critical(self):
        events = [_event(1001, "Error", "Microsoft-Windows-WER-SystemErrorReporting")]
        result = wdm.summarize_events(events)
        assert result["status"] in ("warning", "critical")

    def test_many_errors_returns_critical(self):
        # More than 10 real errors should trigger critical status
        events = [_event(9999, "Error", f"UnknownSource{i}", f"Error message {i}") for i in range(12)]
        result = wdm.summarize_events(events)
        assert result["status"] == "critical"

    def test_missing_keys_does_not_crash(self):
        # Events with missing keys should not raise
        events = [{"Id": 100}, {}, {"Level": "Error"}]
        result = wdm.summarize_events(events)
        assert "status" in result
        assert "insights" in result

    def test_result_has_expected_structure(self):
        events = [_event(7036, "Warning")]
        result = wdm.summarize_events(events)
        assert "status" in result
        assert "headline" in result
        assert "insights" in result
        assert "actions" in result


# ══════════════════════════════════════════════════════════════════════════════
# summarize_health_history
# ══════════════════════════════════════════════════════════════════════════════


def _hh_report(score=85, bsod_count=0, date_label="Apr 01"):
    return {
        "file": "report.html",
        "timestamp": "2026-04-01T07:00:00+00:00",
        "date_label": date_label,
        "score": score,
        "bsod_count": bsod_count,
        "whea_count": 0,
        "drv_errors": 0,
        "sys_files": [],
        "status": "ok",
    }


class TestSummarizeHealthHistory:
    def test_no_reports_returns_info(self):
        result = wdm.summarize_health_history({"reports": []})
        assert result["status"] == "info"
        assert "No health reports" in result["headline"]

    def test_stale_reports_show_warning(self):
        data = {
            "reports": [_hh_report()],
            "avg_score": 85,
            "latest": _hh_report(),
            "stale": True,
            "stale_days": 5,
        }
        result = wdm.summarize_health_history(data)
        stale_insights = [i for i in result["insights"] if "stale" in i["text"].lower()]
        assert len(stale_insights) == 1
        assert stale_insights[0]["level"] == "warning"
        assert "5 day" in stale_insights[0]["text"]

    def test_fresh_reports_no_stale_warning(self):
        data = {
            "reports": [_hh_report()],
            "avg_score": 85,
            "latest": _hh_report(),
            "stale": False,
            "stale_days": 0,
        }
        result = wdm.summarize_health_history(data)
        stale_insights = [i for i in result["insights"] if "stale" in i["text"].lower()]
        assert len(stale_insights) == 0

    def test_critical_score_returns_critical(self):
        data = {
            "reports": [_hh_report(score=40)],
            "avg_score": 40,
            "latest": _hh_report(score=40),
            "stale": False,
            "stale_days": 0,
        }
        result = wdm.summarize_health_history(data)
        assert result["status"] == "critical"

    def test_bsod_reports_raise_warning(self):
        data = {
            "reports": [_hh_report(bsod_count=3)],
            "avg_score": 85,
            "latest": _hh_report(bsod_count=3),
            "stale": False,
            "stale_days": 0,
        }
        result = wdm.summarize_health_history(data)
        bsod_insights = [i for i in result["insights"] if "BSOD" in i["text"]]
        assert len(bsod_insights) == 1


# ══════════════════════════════════════════════════════════════════════════════
# _correlate_crashes_with_updates  &  summarize_timeline
# ══════════════════════════════════════════════════════════════════════════════


def _tl_crash(ts, stop_code=None, error_name="", faulty_driver=None):
    return {
        "ts": ts,
        "type": "bsod",
        "category": "crash",
        "title": "System Crash",
        "detail": f"Stop code: {stop_code}" if stop_code else "Kernel power loss",
        "severity": "critical",
        "icon": "💀",
        "stop_code": stop_code,
        "error_name": error_name,
        "faulty_driver": faulty_driver,
    }


def _tl_update(ts, title="Windows Update KB1234", update_type="update"):
    return {
        "ts": ts,
        "type": update_type,
        "category": "update",
        "title": title,
        "detail": "",
        "severity": "info",
        "icon": "🔄",
    }


class TestCorrelateUpdatesWithCrashes:
    """Tests for _correlate_crashes_with_updates."""

    def test_crash_after_update_gets_correlated(self):
        events = [
            _tl_update("2026-04-01T10:00:00"),
            _tl_crash("2026-04-01T11:30:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "update"][0]
        assert upd["crash_correlation"]["has_correlation"] is True
        assert upd["crash_correlation"]["confidence"] > 0

    def test_crash_before_update_not_correlated(self):
        events = [
            _tl_crash("2026-04-01T08:00:00", "0x00000116", "VIDEO_TDR_FAILURE"),
            _tl_update("2026-04-01T10:00:00"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "update"][0]
        assert upd["crash_correlation"]["has_correlation"] is False

    def test_domain_match_boosts_confidence(self):
        # NVIDIA driver update → nvlddmkm.sys crash should score higher
        events_matched = [
            _tl_update("2026-04-01T10:00:00", "NVIDIA GeForce Driver Update", "driver_install"),
            _tl_crash("2026-04-01T11:00:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        events_unmatched = [
            _tl_update("2026-04-01T10:00:00", "Windows Security Update KB5555"),
            _tl_crash("2026-04-01T11:00:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        result_matched = wdm._correlate_crashes_with_updates(events_matched)
        result_unmatched = wdm._correlate_crashes_with_updates(events_unmatched)
        conf_matched = [e for e in result_matched if e["type"] == "driver_install"][0]["crash_correlation"][
            "confidence"
        ]
        conf_unmatched = [e for e in result_unmatched if e["type"] == "update"][0]["crash_correlation"]["confidence"]
        assert conf_matched > conf_unmatched

    def test_pre_existing_pattern_reduces_confidence(self):
        # Same stop code existed before the update → confidence drops
        events = [
            _tl_crash("2026-03-25T08:00:00", "0x00000116", "VIDEO_TDR_FAILURE"),
            _tl_update("2026-04-01T10:00:00"),
            _tl_crash("2026-04-01T11:00:00", "0x00000116", "VIDEO_TDR_FAILURE"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "update"][0]
        # Still correlated but lower confidence due to pre-existing
        corr = upd["crash_correlation"]
        assert corr["has_correlation"] is True
        assert any("prior" in r.lower() or "existed before" in r.lower() for r in corr["reasoning"])

    def test_new_crash_pattern_boosts_confidence(self):
        # Stop code first appeared after update → confidence boost
        events = [
            _tl_update("2026-04-01T10:00:00", "NVIDIA Driver Update", "driver_install"),
            _tl_crash("2026-04-01T11:00:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "driver_install"][0]
        corr = upd["crash_correlation"]
        assert any("first time" in r.lower() for r in corr["reasoning"])

    def test_crash_more_than_24h_after_not_correlated(self):
        events = [
            _tl_update("2026-04-01T10:00:00"),
            _tl_crash("2026-04-03T10:00:00"),  # 48h later
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "update"][0]
        assert upd["crash_correlation"]["has_correlation"] is False

    def test_no_crashes_means_no_correlation(self):
        events = [_tl_update("2026-04-01T10:00:00")]
        result = wdm._correlate_crashes_with_updates(events)
        upd = result[0]
        assert upd["crash_correlation"]["has_correlation"] is False

    def test_classification_likely_cause(self):
        # Driver install with domain match + close timing → likely_cause
        events = [
            _tl_update("2026-04-01T10:00:00", "NVIDIA GeForce Driver", "driver_install"),
            _tl_crash("2026-04-01T10:30:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "driver_install"][0]
        assert upd["crash_correlation"]["classification"] == "likely_cause"

    def test_backward_compat_near_crash_field(self):
        events = [
            _tl_update("2026-04-01T10:00:00"),
            _tl_crash("2026-04-01T11:00:00"),
        ]
        result = wdm._correlate_crashes_with_updates(events)
        upd = [e for e in result if e["type"] == "update"][0]
        # near_crash field still set for backward compat
        assert "near_crash" in upd


class TestSummarizeTimeline:
    def test_likely_cause_returns_critical(self):
        events = [
            _tl_update("2026-04-01T10:00:00", "NVIDIA Driver", "driver_install"),
            _tl_crash("2026-04-01T10:30:00", "0x00000116", "VIDEO_TDR_FAILURE", "nvlddmkm.sys"),
        ]
        events = wdm._correlate_crashes_with_updates(events)
        result = wdm.summarize_timeline(events)
        assert result["status"] == "critical"
        assert "likely" in result["headline"].lower()

    def test_no_crashes_returns_ok(self):
        events = [_tl_update("2026-04-01T10:00:00")]
        events = wdm._correlate_crashes_with_updates(events)
        result = wdm.summarize_timeline(events)
        assert result["status"] == "ok"

    def test_crashes_without_correlation_returns_warning(self):
        events = [
            _tl_crash("2026-04-01T08:00:00"),
            _tl_update("2026-04-01T10:00:00"),  # update after crash — no correlation
        ]
        events = wdm._correlate_crashes_with_updates(events)
        result = wdm.summarize_timeline(events)
        assert result["status"] == "warning"

    def test_empty_events_returns_ok(self):
        result = wdm.summarize_timeline([])
        assert result["status"] == "ok"


# ══════════════════════════════════════════════════════════════════════════════
# summarize_upgrades (backlog #43 -- hardware upgrade analyser)
# ══════════════════════════════════════════════════════════════════════════════


class TestSummarizeUpgrades:
    """Tests for the summarize_upgrades function.

    summarize_upgrades is the synthesiser behind the System Info tab's
    "🚀 Upgrade Opportunities" panel. Given the inventory dict that
    /api/sysinfo/data returns, it emits a list of categorised
    recommendations with severity / headline / detail / action.
    """

    @staticmethod
    def _stick(capacity_gb=16, speed=5600, mtype="DDR5", form="SODIMM", part="CT16G56C46S5"):
        """Build one Memory entry mirroring the WMI shape."""
        return {
            "BankLabel": "BANK 0",
            "Capacity": capacity_gb * (1024**3),
            "Speed": speed,
            "ConfiguredClockSpeed": speed,
            "Manufacturer": "Crucial",
            "PartNumber": part,
            "FormFactor": form,
            "MemoryType": mtype,
            "DataWidth": 64,
            "DeviceLocator": "DIMM A1",
        }

    @staticmethod
    def _array(slots=4, max_gb=64):
        return {
            "MaxCapacityGB": max_gb,
            "MemoryDevices": slots,
            "MemoryErrorCorrection": "None",
            "Location": "System Board",
        }

    def test_returns_opportunities_key(self):
        result = wdm.summarize_upgrades({})
        assert "opportunities" in result
        assert isinstance(result["opportunities"], list)

    def test_empty_data_returns_empty_list(self):
        """Defensive: a totally-empty data dict (WMI failed entirely)
        must return an empty list -- never raise. The UI hides the panel
        on empty so the user just sees the inventory tables below."""
        result = wdm.summarize_upgrades({})
        assert result["opportunities"] == []

    def test_partial_slots_filled_recommends_expansion(self):
        """The headline upgrade case: 2 of 4 DIMMs populated, half the
        max board capacity used. Should surface a 'memory' opportunity
        with the right slot/headroom math."""
        data = {
            "Memory": [self._stick(16), self._stick(16)],
            "MemoryArray": [self._array(slots=4, max_gb=64)],
        }
        result = wdm.summarize_upgrades(data)
        mem_ops = [o for o in result["opportunities"] if o["category"] == "memory"]
        assert len(mem_ops) >= 1
        op = mem_ops[0]
        assert op["severity"] == "info"
        assert "32" in op["headline"]  # +32 GB headroom
        assert "2 of 4" in op["headline"] or "2 of 4 DIMM" in op["headline"]
        # Action must mention the form factor + type so user knows what to buy
        assert "DDR5" in op["action"]
        assert "SODIMM" in op["action"]

    def test_all_slots_full_with_headroom_suggests_replace(self):
        """All slots populated but board accepts higher density: only
        path is to swap existing sticks. Should be 'info' severity, not
        a free win."""
        data = {
            "Memory": [self._stick(8), self._stick(8), self._stick(8), self._stick(8)],
            "MemoryArray": [self._array(slots=4, max_gb=64)],
        }
        result = wdm.summarize_upgrades(data)
        mem_ops = [o for o in result["opportunities"] if o["category"] == "memory"]
        assert mem_ops, "expected at least one memory opportunity"
        op = mem_ops[0]
        assert "replac" in op["headline"].lower() or "replac" in op["action"].lower()

    def test_all_slots_at_max_returns_ok_status(self):
        """Fully populated AND at max board capacity -- nothing to
        upgrade. Surface as 'ok' so the user knows we checked, not as
        absence of any memory opportunity."""
        data = {
            "Memory": [self._stick(16), self._stick(16), self._stick(16), self._stick(16)],
            "MemoryArray": [self._array(slots=4, max_gb=64)],
        }
        result = wdm.summarize_upgrades(data)
        mem_ops = [o for o in result["opportunities"] if o["category"] == "memory"]
        assert mem_ops
        assert mem_ops[0]["severity"] == "ok"

    def test_single_dimm_in_multislot_board_warns_single_channel(self):
        """1 stick in a 2+ slot board -> running in single-channel mode,
        which halves bandwidth. Free win to add a matching stick."""
        data = {
            "Memory": [self._stick(16)],
            "MemoryArray": [self._array(slots=4, max_gb=64)],
        }
        result = wdm.summarize_upgrades(data)
        warnings = [o for o in result["opportunities"] if o["severity"] == "warning"]
        assert any("single-channel" in o["headline"].lower() for o in warnings)

    def test_single_dimm_in_one_slot_board_no_channel_warning(self):
        """A board with only 1 slot can't be in single-channel mode --
        don't fire a misleading warning on laptops with soldered RAM
        plus one socket."""
        data = {
            "Memory": [self._stick(16)],
            "MemoryArray": [self._array(slots=1, max_gb=32)],
        }
        result = wdm.summarize_upgrades(data)
        assert not any("single-channel" in o["headline"].lower() for o in result["opportunities"])

    def test_missing_memory_array_skips_memory_opportunities(self):
        """No MemoryArray data (some VMs / locked OEM firmware): we
        can't compute headroom or free slots, so memory opportunities
        are silently skipped rather than guessed at."""
        data = {"Memory": [self._stick(16), self._stick(16)]}
        result = wdm.summarize_upgrades(data)
        # Single-channel doesn't fire here either since total_slots is unknown
        mem_ops = [o for o in result["opportunities"] if o["category"] == "memory"]
        assert mem_ops == []

    def test_free_pcie_slots_surface_opportunity(self):
        """Board has 3 PCIe slots, 2 free -> a 'pcie' opportunity should
        surface with the slot designations listed."""
        data = {
            "PCIeSlots": [
                {"SlotDesignation": "PCIEX16_1", "CurrentUsage": "In Use", "Description": "PCIe 4.0 x16"},
                {"SlotDesignation": "PCIEX16_2", "CurrentUsage": "Available", "Description": "PCIe 4.0 x16"},
                {"SlotDesignation": "PCIEX1_1", "CurrentUsage": "Available", "Description": "PCIe 3.0 x1"},
            ]
        }
        result = wdm.summarize_upgrades(data)
        pcie_ops = [o for o in result["opportunities"] if o["category"] == "pcie"]
        assert len(pcie_ops) == 1
        op = pcie_ops[0]
        assert "2 of 3" in op["headline"]
        # Detail should list the actual free slot designations so user
        # can match the right card form-factor
        assert "PCIEX16_2" in op["detail"]
        assert "PCIEX1_1" in op["detail"]

    def test_all_pcie_slots_in_use_no_opportunity(self):
        data = {
            "PCIeSlots": [
                {"SlotDesignation": "PCIEX16_1", "CurrentUsage": "In Use", "Description": "PCIe 4.0 x16"},
            ]
        }
        result = wdm.summarize_upgrades(data)
        assert not [o for o in result["opportunities"] if o["category"] == "pcie"]

    def test_spinning_disk_surfaces_ssd_migration(self):
        """A drive that looks like an HDD (no SSD/NVMe in the model) on
        IDE/ATAPI interface should surface an SSD-migration opportunity."""
        data = {
            "Disks": [
                {"Model": "WDC WD40EZRZ-00GXCB0", "Size": 4 * (1024**3) * 1000, "InterfaceType": "IDE"},
                {"Model": "Samsung SSD 980 PRO 2TB", "Size": 2 * (1024**3) * 1000, "InterfaceType": "SCSI"},
            ]
        }
        result = wdm.summarize_upgrades(data)
        storage = [o for o in result["opportunities"] if o["category"] == "storage"]
        assert storage, "expected an SSD-migration recommendation"
        # Only the WD drive should count -- not the Samsung NVMe
        assert "1" in storage[0]["headline"]

    def test_all_ssd_no_storage_opportunity(self):
        """All NVMe / SSD drives -- no migration recommendation."""
        data = {
            "Disks": [
                {"Model": "Samsung SSD 980 PRO 2TB", "Size": 2 * (1024**3), "InterfaceType": "SCSI"},
                {"Model": "Crucial MX500 SSD", "Size": 1 * (1024**3), "InterfaceType": "SATA"},
            ]
        }
        result = wdm.summarize_upgrades(data)
        assert not [o for o in result["opportunities"] if o["category"] == "storage"]

    def test_opportunity_shape_is_stable(self):
        """Every opportunity must have category/severity/headline/detail/action --
        the UI renderer relies on the shape being uniform."""
        data = {
            "Memory": [self._stick(16), self._stick(16)],
            "MemoryArray": [self._array(slots=4, max_gb=64)],
            "PCIeSlots": [
                {"SlotDesignation": "PCIEX16_2", "CurrentUsage": "Available", "Description": "x16"},
            ],
        }
        result = wdm.summarize_upgrades(data)
        for op in result["opportunities"]:
            assert {"category", "severity", "headline", "detail", "action"} <= set(op.keys())
            assert op["category"] in ("memory", "pcie", "storage")
            assert op["severity"] in ("ok", "info", "warning")
