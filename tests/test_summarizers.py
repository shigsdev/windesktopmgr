"""
test_summarizers.py
Tests for all summarize_* functions — pure Python, no subprocess required.
"""

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
