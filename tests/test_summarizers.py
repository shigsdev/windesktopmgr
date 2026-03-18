"""
test_summarizers.py
Tests for all summarize_* functions — pure Python, no subprocess required.
"""

import pytest
import windesktopmgr as wdm


# ── Helper builders ────────────────────────────────────────────────────────────

def _driver(name, status, category="Display", low_priority=False):
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
        "download_url": "",
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


def _drive(letter, pct_used, free_gb=50):
    return {"Letter": letter, "PctUsed": pct_used, "FreeGB": free_gb}


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
        items = [
            {"Title": "KB12345", "result": "Succeeded", "Date": "2026-03-01T00:00:00+00:00"},
        ]
        result = wdm.summarize_updates(items)
        assert result["status"] == "ok"

    def test_stale_update_over_60_days_warning(self):
        items = [
            # Only successful update was >60 days ago
            {"Title": "KB00001", "result": "Succeeded", "Date": "2025-01-01T00:00:00+00:00"},
        ]
        result = wdm.summarize_updates(items)
        assert result["status"] == "warning"

    def test_no_failed_updates_ok_insight(self):
        items = [
            {"Title": "KB12345", "result": "Succeeded", "Date": "2026-03-01T00:00:00+00:00"},
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
        hog = _process("memoryhog.exe", mem_mb=2000, flag="critical",
                        info={"plain": "Memory Hog", "what": "Uses lots of RAM",
                              "publisher": "Unknown", "safe_kill": True})
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        assert result["status"] == "critical"

    def test_critical_safe_kill_false_action(self):
        hog = _process("windefend.exe", mem_mb=2000, flag="critical",
                        info={"plain": "Windows Defender", "what": "Security",
                              "publisher": "Microsoft", "safe_kill": False})
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        actions = " ".join(i["action"] for i in result["insights"])
        assert "do not kill" in actions.lower() or "system" in actions.lower()

    def test_critical_safe_kill_true_action(self):
        hog = _process("chrome.exe", mem_mb=2000, flag="critical",
                        info={"plain": "Chrome", "what": "Browser",
                              "publisher": "Google", "safe_kill": True})
        result = wdm.summarize_processes(self._data([hog], flagged=[hog]))
        actions = " ".join(i["action"] for i in result["insights"])
        assert "safe to kill" in actions.lower()

    def test_warning_level_process(self):
        warn = _process("slack.exe", mem_mb=600, flag="warning",
                        info={"plain": "Slack", "what": "Chat app",
                              "publisher": "Slack", "safe_kill": True})
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
