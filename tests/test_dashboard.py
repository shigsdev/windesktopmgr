"""Tests for dashboard.py — the /api/dashboard/summary concern aggregator.

Focus: physical-disk health surfacing (bug fix 2026-07-04). A physical
disk reporting a non-Healthy ``HealthStatus`` was flagged by the daily
health report (SystemHealthDiag.check_disk_health) and the Disk tab
(disk.summarize_disk) but was silently absent from the dashboard
concerns feed, which only inspected logical-volume fullness.
"""

import dashboard


class TestFormatOperationalStatus:
    """OperationalStatus arrives as a scalar, a list, or a wrapped dict
    depending on PowerShell's JSON serialisation — normalise all three."""

    def test_none_returns_empty(self):
        assert dashboard._format_operational_status(None) == ""

    def test_scalar_string_passthrough(self):
        assert dashboard._format_operational_status("OK") == "OK"

    def test_scalar_string_stripped(self):
        assert dashboard._format_operational_status("  OK  ") == "OK"

    def test_list_joined(self):
        assert dashboard._format_operational_status(["IO Error", "OK"]) == "IO Error, OK"

    def test_list_drops_blank_entries(self):
        assert dashboard._format_operational_status(["IO Error", "", "  "]) == "IO Error"

    def test_wrapped_dict_value_joined(self):
        # The shape ConvertTo-Json emits for a multi-value enum at times:
        # {"value": ["IO Error", "OK"], "Count": 2}
        status = {"value": ["IO Error", "OK"], "Count": 2}
        assert dashboard._format_operational_status(status) == "IO Error, OK"

    def test_empty_list_returns_empty(self):
        assert dashboard._format_operational_status([]) == ""


class TestDashboardPhysicalDiskHealth:
    """A non-Healthy physical disk must surface as a critical dashboard
    concern, matching the daily report and the Disk tab."""

    def _mock_deps(self, mocker, disk_health: dict):
        """Mock every collector the dashboard fan-out touches so no real
        PowerShell / WMI / GPU / network probe runs."""
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={"temps": [], "perf": {"CPUPct": 5}, "fans": [], "has_rich": True},
        )
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={"total_mb": 32000, "used_mb": 8000, "free_mb": 24000, "top_procs": []},
        )
        mocker.patch("windesktopmgr.get_bios_status", return_value={"current": {}, "update": {}})
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={"onedrive_suspended": False, "fast_startup_enabled": False, "drives_down": []},
        )
        mocker.patch("windesktopmgr.get_disk_health", return_value=disk_health)
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value={"old_drivers": [], "problematic_drivers": [], "nvidia": None},
        )
        mocker.patch("windesktopmgr.get_gpu_metrics", return_value={"ok": False})
        mocker.patch("windesktopmgr.get_network_metrics", return_value={"ok": False})
        # Default: healthy network so no network concern leaks into disk tests.
        mocker.patch(
            "windesktopmgr.get_network_health",
            return_value={
                "available": True,
                "internet_reachable": True,
                "ping_latency_ms": 20.0,
                "dns_working": True,
                "dns_latency_ms": 20.0,
                "adapters": [{"name": "Ethernet", "up": True}],
            },
        )
        # Default: healthy hardware (not affected, no WHEA) so no advisory
        # concern leaks into disk/network tests.
        mocker.patch(
            "windesktopmgr.get_warranty_data",
            return_value={
                "IsAffectedCPU": False,
                "CPUModel": "AMD Ryzen 9",
                "BIOSDate": "2026-01-01",
                "WHEAErrors30Days": 0,
                "WHEAErrorsRecent7Days": 0,
            },
        )
        # Default: matched at-spec RAM so no config concern leaks in.
        mocker.patch(
            "windesktopmgr.get_memory_config",
            return_value={
                "sticks": [
                    {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                    {"locator": "DIMM2", "capacity_gb": 16.0, "speed_mhz": 5600},
                ]
            },
        )
        # Default: no Storage Spaces so no pool concern leaks in.
        mocker.patch(
            "windesktopmgr.get_storage_spaces",
            return_value={"pools": [], "virtual_disks": [], "members": [], "repair_jobs": [], "has_spaces": False},
        )
        import task_watcher as _tw

        mocker.patch.object(_tw, "get_all_task_health", return_value=[])

    def _disk_concerns(self, resp):
        return [c for c in resp.get_json()["concerns"] if c.get("tab") == "disk"]

    def test_warning_physical_disk_surfaces_critical_concern(self, client, mocker):
        self._mock_deps(
            mocker,
            disk_health={
                "drives": [],
                "physical": [
                    {
                        "Name": "Samsung SSD 990 PRO 2TB",
                        "Health": "Warning",
                        "Status": ["IO Error", "OK"],
                        "MediaType": "SSD",
                        "SizeGB": 1863,
                    }
                ],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        disk_concerns = self._disk_concerns(resp)
        assert len(disk_concerns) == 1
        c = disk_concerns[0]
        assert c["level"] == "critical"
        assert "Samsung SSD 990 PRO 2TB" in c["title"]
        assert "Warning" in c["title"]
        # OperationalStatus IO Error should reach the detail so the user
        # knows *why* it is unhealthy, not just that it is.
        assert "IO Error" in c["detail"]

    def test_unhealthy_physical_disk_surfaces_critical_concern(self, client, mocker):
        self._mock_deps(
            mocker,
            disk_health={
                "drives": [],
                "physical": [{"Name": "Dying Disk", "Health": "Unhealthy", "Status": "OK"}],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        disk_concerns = self._disk_concerns(resp)
        assert len(disk_concerns) == 1
        assert disk_concerns[0]["level"] == "critical"
        assert "Dying Disk" in disk_concerns[0]["title"]

    def test_healthy_physical_disks_produce_no_disk_concern(self, client, mocker):
        self._mock_deps(
            mocker,
            disk_health={
                "drives": [],
                "physical": [
                    {"Name": "Good SSD A", "Health": "Healthy", "Status": "OK"},
                    {"Name": "Good SSD B", "Health": "Healthy", "Status": "OK"},
                ],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        assert self._disk_concerns(resp) == []

    def test_missing_health_field_is_treated_as_healthy(self, client, mocker):
        # A disk whose Health is empty/None must NOT raise a false alarm —
        # absence of data is not evidence of failure.
        self._mock_deps(
            mocker,
            disk_health={
                "drives": [],
                "physical": [{"Name": "No-health disk", "Health": "", "Status": "OK"}],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        assert self._disk_concerns(resp) == []

    def test_only_the_unhealthy_disk_among_many_is_flagged(self, client, mocker):
        # Mirrors the live box: two 990 PROs, one Healthy, one Warning.
        self._mock_deps(
            mocker,
            disk_health={
                "drives": [],
                "physical": [
                    {"Name": "Samsung SSD 990 PRO 2TB", "Health": "Healthy", "Status": "OK"},
                    {"Name": "Samsung SSD 990 PRO 2TB", "Health": "Warning", "Status": ["IO Error", "OK"]},
                    {"Name": "Samsung SSD 970 EVO Plus 2TB", "Health": "Healthy", "Status": "OK"},
                ],
                "io": [],
            },
        )
        resp = client.get("/api/dashboard/summary")
        disk_concerns = self._disk_concerns(resp)
        assert len(disk_concerns) == 1
        assert disk_concerns[0]["level"] == "critical"


class TestDashboardNetworkHealth:
    """Network reachability/DNS problems must surface as dashboard concerns,
    matching the daily report (SystemHealthDiag.check_network_health)."""

    def _healthy_baseline(self, mocker):
        # Reuse the disk class's full collector mock (healthy everything),
        # then individual tests override get_network_health to a bad state.
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )

    def _net_concerns(self, resp):
        return [c for c in resp.get_json()["concerns"] if c.get("tab") == "network"]

    def test_internet_down_surfaces_critical(self, client, mocker):
        self._healthy_baseline(mocker)
        mocker.patch(
            "windesktopmgr.get_network_health",
            return_value={
                "available": True,
                "internet_reachable": False,
                "ping_latency_ms": None,
                "dns_working": False,
                "dns_latency_ms": None,
                "adapters": [{"name": "Ethernet", "up": False}],
            },
        )
        resp = client.get("/api/dashboard/summary")
        net = self._net_concerns(resp)
        assert len(net) == 3  # no-adapter + internet + dns
        assert all(c["level"] == "critical" for c in net)
        assert resp.get_json()["overall"] == "critical"

    def test_healthy_network_no_concern(self, client, mocker):
        self._healthy_baseline(mocker)  # baseline already patches healthy network
        resp = client.get("/api/dashboard/summary")
        assert self._net_concerns(resp) == []

    def test_collector_error_does_not_break_dashboard(self, client, mocker):
        self._healthy_baseline(mocker)
        mocker.patch("windesktopmgr.get_network_health", return_value={"error": "probe blew up"})
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        assert self._net_concerns(resp) == []


class TestHardwareAdvisoryConcerns:
    """Intel 13th/14th-gen microcode/BIOS + WHEA advisories, mirroring the
    daily report (check_intel_cpu / check_events)."""

    def _w(self, **over):
        d = {
            "IsAffectedCPU": True,
            "CPUModel": "Intel(R) Core(TM) i9-14900K",
            "BIOSDate": "2026-01-06",
            "WHEAErrors30Days": 0,
            "WHEAErrorsRecent7Days": 0,
        }
        d.update(over)
        return d

    def test_empty_or_error_returns_nothing(self):
        assert dashboard.hardware_advisory_concerns({}) == []
        assert dashboard.hardware_advisory_concerns({"error": "wmi down"}) == []

    def test_affected_cpu_recent_bios_no_intel_concern(self):
        # Post-fix BIOS -> no Intel concern (the live i9-14900K case).
        cs = dashboard.hardware_advisory_concerns(self._w(BIOSDate="2026-01-06"))
        assert not any(c["tab"] == "bios" for c in cs)

    def test_affected_cpu_old_bios_is_critical(self):
        cs = dashboard.hardware_advisory_concerns(self._w(BIOSDate="2024-03-01"))
        bios = [c for c in cs if c["tab"] == "bios"]
        assert len(bios) == 1
        assert bios[0]["level"] == "critical"
        assert "predates the fix" in bios[0]["title"]

    def test_affected_cpu_midrange_bios_is_warning(self):
        cs = dashboard.hardware_advisory_concerns(self._w(BIOSDate="2024-09-15"))
        bios = [c for c in cs if c["tab"] == "bios"]
        assert len(bios) == 1
        assert bios[0]["level"] == "warning"

    def test_unaffected_cpu_never_flags_intel(self):
        cs = dashboard.hardware_advisory_concerns(self._w(IsAffectedCPU=False, BIOSDate="2020-01-01"))
        assert not any(c["tab"] == "bios" for c in cs)

    def test_unknown_bios_date_raises_no_intel_concern(self):
        # Absence of a parseable date must NOT false-alarm.
        assert not any(c["tab"] == "bios" for c in dashboard.hardware_advisory_concerns(self._w(BIOSDate="Unknown")))
        assert not any(c["tab"] == "bios" for c in dashboard.hardware_advisory_concerns(self._w(BIOSDate="")))

    def test_recent_whea_is_critical(self):
        cs = dashboard.hardware_advisory_concerns(self._w(WHEAErrorsRecent7Days=2, WHEAErrors30Days=3))
        whea = [c for c in cs if c["tab"] == "sysinfo"]
        assert len(whea) == 1
        assert whea[0]["level"] == "critical"
        assert "7 days" in whea[0]["title"]

    def test_older_whea_is_warning(self):
        cs = dashboard.hardware_advisory_concerns(self._w(WHEAErrorsRecent7Days=0, WHEAErrors30Days=1))
        whea = [c for c in cs if c["tab"] == "sysinfo"]
        assert len(whea) == 1
        assert whea[0]["level"] == "warning"
        assert "30 days" in whea[0]["title"]

    def test_no_whea_no_concern(self):
        assert dashboard.hardware_advisory_concerns(self._w()) == []

    def test_recent_whea_takes_precedence_over_older(self):
        # Only one WHEA concern (the critical), not both.
        cs = dashboard.hardware_advisory_concerns(self._w(WHEAErrorsRecent7Days=1, WHEAErrors30Days=5))
        whea = [c for c in cs if c["tab"] == "sysinfo"]
        assert len(whea) == 1
        assert whea[0]["level"] == "critical"


class TestDashboardHardwareAdvisoryIntegration:
    def _baseline(self, mocker):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )

    def test_old_bios_affected_cpu_surfaces_critical(self, client, mocker):
        self._baseline(mocker)
        mocker.patch(
            "windesktopmgr.get_warranty_data",
            return_value={
                "IsAffectedCPU": True,
                "CPUModel": "Intel(R) Core(TM) i9-14900K",
                "BIOSDate": "2024-02-01",
                "WHEAErrors30Days": 0,
                "WHEAErrorsRecent7Days": 0,
            },
        )
        resp = client.get("/api/dashboard/summary")
        bios = [c for c in resp.get_json()["concerns"] if c.get("tab") == "bios" and "microcode" in c.get("title", "")]
        assert len(bios) == 1
        assert bios[0]["level"] == "critical"

    def test_warranty_collector_error_does_not_break_dashboard(self, client, mocker):
        self._baseline(mocker)
        mocker.patch("windesktopmgr.get_warranty_data", return_value={"error": "winmgmt wedged"})
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        assert not any("microcode" in c.get("title", "") for c in resp.get_json()["concerns"])


class TestMemoryConfigConcerns:
    """RAM speed/capacity mismatch + above-spec XMP -> warnings, mirroring the
    daily report (check_memory)."""

    def test_matched_at_spec_no_concern(self):
        cfg = {
            "sticks": [
                {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                {"locator": "DIMM2", "capacity_gb": 16.0, "speed_mhz": 5600},
            ]
        }
        assert dashboard.memory_config_concerns(cfg) == []

    def test_speed_mismatch_is_warning(self):
        cfg = {
            "sticks": [
                {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                {"locator": "DIMM2", "capacity_gb": 16.0, "speed_mhz": 4800},
            ]
        }
        cs = dashboard.memory_config_concerns(cfg)
        assert any("different speeds" in c["title"] for c in cs)
        assert all(c["level"] == "warning" for c in cs)

    def test_capacity_mismatch_is_warning(self):
        cfg = {
            "sticks": [
                {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                {"locator": "DIMM2", "capacity_gb": 8.0, "speed_mhz": 5600},
            ]
        }
        assert any("different capacities" in c["title"] for c in dashboard.memory_config_concerns(cfg))

    def test_above_spec_xmp_is_warning(self):
        cfg = {
            "sticks": [
                {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 6000},
                {"locator": "DIMM2", "capacity_gb": 16.0, "speed_mhz": 6000},
            ]
        }
        cs = dashboard.memory_config_concerns(cfg)
        assert len(cs) == 1
        assert "above Intel spec" in cs[0]["title"]
        assert "6000" in cs[0]["title"]

    def test_at_5600_boundary_no_xmp_concern(self):
        # 5600 is the spec ceiling — must NOT flag (strict >).
        cfg = {"sticks": [{"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600}]}
        assert dashboard.memory_config_concerns(cfg) == []

    def test_empty_or_error_returns_nothing(self):
        assert dashboard.memory_config_concerns({}) == []
        assert dashboard.memory_config_concerns({"error": "wmi failed"}) == []
        assert dashboard.memory_config_concerns({"sticks": []}) == []

    def test_single_stick_never_mismatches(self):
        cfg = {"sticks": [{"locator": "DIMM1", "capacity_gb": 32.0, "speed_mhz": 5200}]}
        assert dashboard.memory_config_concerns(cfg) == []


class TestDashboardMemoryConfigIntegration:
    def _baseline(self, mocker):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )

    def test_mismatched_ram_surfaces_warning(self, client, mocker):
        self._baseline(mocker)
        mocker.patch(
            "windesktopmgr.get_memory_config",
            return_value={
                "sticks": [
                    {"locator": "DIMM1", "capacity_gb": 16.0, "speed_mhz": 5600},
                    {"locator": "DIMM2", "capacity_gb": 8.0, "speed_mhz": 4800},
                ]
            },
        )
        resp = client.get("/api/dashboard/summary")
        cfg_concerns = [c for c in resp.get_json()["concerns"] if "RAM sticks" in c.get("title", "")]
        assert len(cfg_concerns) == 2
        assert all(c["level"] == "warning" for c in cfg_concerns)

    def test_memory_config_error_does_not_break_dashboard(self, client, mocker):
        self._baseline(mocker)
        mocker.patch("windesktopmgr.get_memory_config", return_value={"error": "winmgmt wedged"})
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        assert not any("RAM sticks" in c.get("title", "") for c in resp.get_json()["concerns"])


class TestStoragePoolConcerns:
    """Storage Spaces pool/virtual-disk health -> dashboard concerns. Windows
    never alerts on a degraded pool, so this is the only safety net."""

    def _ss(self, **over):
        d = {
            "has_spaces": True,
            "pools": [{"Name": "Storage pool", "Health": "Healthy", "Operational": "OK"}],
            "virtual_disks": [
                {"Name": "Storage space", "Health": "Healthy", "Operational": "OK", "Resiliency": "Parity"}
            ],
            "members": [],
            "repair_jobs": [],
        }
        d.update(over)
        return d

    def test_no_spaces_no_concern(self):
        assert dashboard.storage_pool_concerns({"has_spaces": False}) == []
        assert dashboard.storage_pool_concerns({}) == []

    def test_healthy_pool_no_concern(self):
        assert dashboard.storage_pool_concerns(self._ss()) == []

    def test_degraded_space_is_critical(self):
        cs = dashboard.storage_pool_concerns(
            self._ss(
                virtual_disks=[
                    {"Name": "Storage space", "Health": "Warning", "Operational": "Degraded", "Resiliency": "Parity"}
                ]
            )
        )
        crit = [c for c in cs if c["level"] == "critical"]
        assert len(crit) == 1
        assert "redundancy lost" in crit[0]["title"]
        assert crit[0]["tab"] == "disk"

    def test_empty_health_but_degraded_operational_still_fires(self):
        # Live Windows returns empty HealthStatus during a repair but keeps
        # OperationalStatus=Degraded — must still flag.
        cs = dashboard.storage_pool_concerns(
            self._ss(virtual_disks=[{"Name": "S", "Health": "", "Operational": "Degraded", "Resiliency": "Parity"}])
        )
        assert any(c["level"] == "critical" for c in cs)

    def test_suspended_repair_adds_warning(self):
        cs = dashboard.storage_pool_concerns(
            self._ss(
                virtual_disks=[{"Name": "S", "Health": "Warning", "Operational": "Degraded", "Resiliency": "Parity"}],
                repair_jobs=[{"Name": "S-Repair", "State": "Suspended"}],
            )
        )
        assert any(c["level"] == "critical" for c in cs)
        assert any(c["level"] == "warning" and "stalled" in c["title"] for c in cs)

    def test_running_repair_no_extra_warning(self):
        cs = dashboard.storage_pool_concerns(
            self._ss(
                virtual_disks=[{"Name": "S", "Health": "Healthy", "Operational": "OK", "Resiliency": "Parity"}],
                repair_jobs=[{"Name": "S-Repair", "State": "Running"}],
            )
        )
        assert cs == []

    def test_degraded_pool_without_vdisk_match(self):
        cs = dashboard.storage_pool_concerns(
            self._ss(pools=[{"Name": "Pool", "Health": "Unhealthy", "Operational": "Degraded"}], virtual_disks=[])
        )
        assert any(c["level"] == "critical" and "pool" in c["title"].lower() for c in cs)

    def test_unhealthy_space_is_critical(self):
        cs = dashboard.storage_pool_concerns(
            self._ss(
                virtual_disks=[{"Name": "S", "Health": "Unhealthy", "Operational": "Detached", "Resiliency": "Mirror"}]
            )
        )
        assert any(c["level"] == "critical" for c in cs)


class TestDashboardStorageSpacesIntegration:
    def _baseline(self, mocker):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )

    def test_degraded_pool_surfaces_critical(self, client, mocker):
        self._baseline(mocker)
        mocker.patch(
            "windesktopmgr.get_storage_spaces",
            return_value={
                "has_spaces": True,
                "pools": [{"Name": "Storage pool", "Health": "Warning", "Operational": "Degraded"}],
                "virtual_disks": [
                    {"Name": "Storage space", "Health": "Warning", "Operational": "Degraded", "Resiliency": "Parity"}
                ],
                "members": [],
                "repair_jobs": [{"Name": "Storage space-Repair", "State": "Suspended"}],
            },
        )
        resp = client.get("/api/dashboard/summary")
        pool = [c for c in resp.get_json()["concerns"] if "redundancy lost" in c.get("title", "")]
        assert len(pool) == 1
        assert pool[0]["level"] == "critical"
        assert resp.get_json()["overall"] == "critical"

    def test_error_does_not_break_dashboard(self, client, mocker):
        self._baseline(mocker)
        mocker.patch(
            "windesktopmgr.get_storage_spaces",
            return_value={"pools": [], "virtual_disks": [], "members": [], "repair_jobs": [], "has_spaces": False},
        )
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
