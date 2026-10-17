"""Tests for dashboard.py — the /api/dashboard/summary concern aggregator.

Focus: physical-disk health surfacing (bug fix 2026-07-04). A physical
disk reporting a non-Healthy ``HealthStatus`` was flagged by the daily
health report (SystemHealthDiag.check_disk_health) and the Disk tab
(disk.summarize_disk) but was silently absent from the dashboard
concerns feed, which only inspected logical-volume fullness.
"""

from datetime import datetime, timedelta

import pytest

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
        # Default: no NAS configured so no NAS concern leaks in.
        mocker.patch("windesktopmgr.get_nas_storage", return_value={"nas": [], "configured": 0})
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


class TestDashboardDiskSnooze:
    """A paused (snoozed) drive is suppressed from the dashboard by serial;
    others still fire and carry disk_serial for the Pause button."""

    def _mock(self, mocker, physical):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": physical, "io": []},
        )

    def _disk(self, resp):
        return [c for c in resp.get_json()["concerns"] if c.get("tab") == "disk"]

    def test_snoozed_drive_is_suppressed(self, client, mocker, tmp_path, monkeypatch):
        import disk

        monkeypatch.setattr(disk, "DISK_SNOOZE_FILE", str(tmp_path / "ds.json"))
        disk.add_disk_snooze("SN-BAD-1.", 24)
        self._mock(mocker, [{"Name": "Bad SSD", "Health": "Warning", "Status": "OK", "SerialNumber": "SN-BAD-1."}])
        resp = client.get("/api/dashboard/summary")
        assert self._disk(resp) == []

    def test_only_the_snoozed_drive_is_suppressed(self, client, mocker, tmp_path, monkeypatch):
        import disk

        monkeypatch.setattr(disk, "DISK_SNOOZE_FILE", str(tmp_path / "ds.json"))
        disk.add_disk_snooze("SN-PAUSED.", 24)
        self._mock(
            mocker,
            [
                {"Name": "Paused SSD", "Health": "Warning", "Status": "OK", "SerialNumber": "SN-PAUSED."},
                {"Name": "Other SSD", "Health": "Warning", "Status": "OK", "SerialNumber": "SN-OTHER."},
            ],
        )
        resp = client.get("/api/dashboard/summary")
        dc = self._disk(resp)
        assert len(dc) == 1
        assert dc[0]["disk_serial"] == "SN-OTHER."

    def test_unsnoozed_concern_carries_serial(self, client, mocker, tmp_path, monkeypatch):
        import disk

        monkeypatch.setattr(disk, "DISK_SNOOZE_FILE", str(tmp_path / "ds.json"))
        self._mock(mocker, [{"Name": "Bad SSD", "Health": "Warning", "Status": "OK", "SerialNumber": "SN-XYZ."}])
        resp = client.get("/api/dashboard/summary")
        dc = self._disk(resp)
        assert len(dc) == 1
        assert dc[0]["disk_serial"] == "SN-XYZ."


class TestDashboardBaselineDriftReconciled:
    """Bug 2026-10-10: the baseline drift concerns ignored everything the
    accepted baseline already holds except a full "accept current" -- so a
    cross-surface cluster accepted one entry at a time on the Baseline tab
    ("Accept all N") kept raising both concerns for up to 24h."""

    @pytest.fixture
    def drift_files(self, tmp_path, monkeypatch, mocker):
        import baseline

        monkeypatch.setattr(baseline, "BASELINE_FILE", str(tmp_path / "baseline_snapshot.json"))
        monkeypatch.setattr(baseline, "HISTORY_FILE", str(tmp_path / "baseline_history.json"))
        monkeypatch.setattr(baseline, "ACCEPT_WATERMARK_FILE", str(tmp_path / "baseline_accept_watermark.json"))
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )
        now = datetime.now().replace(microsecond=0)
        baseline._save_accept_watermark((now - timedelta(hours=2)).isoformat())
        # One three-category burst recorded after the last full accept.
        baseline._append_history(
            {
                "timestamp": (now - timedelta(minutes=30)).isoformat(),
                "total_changes": 3,
                "drift": {
                    "startup": {"added": [{"key": "run_app", "name": "app"}], "removed": [], "changed": []},
                    "services": {"added": [{"key": "AppSvc", "name": "AppSvc"}], "removed": [], "changed": []},
                    "tasks": {"added": [{"key": "AppTask", "name": "AppTask"}], "removed": [], "changed": []},
                    "total_changes": 3,
                },
            }
        )
        return baseline

    @staticmethod
    def _write_baseline(baseline, startup=(), services=(), tasks=()):
        baseline._atomic_write(
            baseline.BASELINE_FILE,
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "startup": {"by_key": {k: {"name": k} for k in startup}},
                "services": {"by_key": {k: {"name": k} for k in services}},
                "tasks": {"by_key": {k: {"name": k} for k in tasks}},
            },
        )

    @staticmethod
    def _baseline_concerns(client):
        return [c for c in client.get("/api/dashboard/summary").get_json()["concerns"] if c.get("tab") == "baseline"]

    def test_open_cluster_raises_both_concerns(self, client, drift_files):
        self._write_baseline(drift_files)
        titles = [c["title"] for c in self._baseline_concerns(client)]
        assert any("drift detected (3 change(s)" in t for t in titles)
        assert any("Cross-surface" in t for t in titles)

    def test_cluster_accepted_entry_by_entry_raises_nothing(self, client, drift_files):
        self._write_baseline(drift_files, startup=["run_app"], services=["AppSvc"], tasks=["AppTask"])
        assert self._baseline_concerns(client) == []

    def test_partly_accepted_cluster_counts_only_open_items(self, client, drift_files):
        self._write_baseline(drift_files, startup=["run_app"], services=["AppSvc"])
        concerns = self._baseline_concerns(client)
        assert [c["title"] for c in concerns] == ["System baseline drift detected (1 change(s) in 24h)"]
        assert concerns[0]["detail"] == "tasks: +1/-0/~0"


class TestDashboardThermalsSampledFirst:
    """CPU temp + load are sampled BEFORE the other collectors start. Sampled
    in parallel they measured the dashboard's own refresh burst (PowerShell /
    WMI collectors pushed an idle 14900K to ~200 W and 86-91 C for seconds),
    and that cached reading then stayed on screen for minutes."""

    COLLECTORS = [
        "get_thermals",
        "get_memory_analysis",
        "get_bios_status",
        "get_credentials_network_health",
        "get_disk_health",
        "get_driver_health",
        "get_gpu_metrics",
        "get_network_metrics",
        "get_network_health",
        "get_warranty_data",
        "get_memory_config",
        "get_storage_spaces",
        "get_nas_storage",
    ]

    def _healthy(self, mocker):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {"drives": [], "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}], "io": []},
        )

    def test_thermals_finish_before_any_other_collector_starts(self, mocker):
        import threading
        import time

        import windesktopmgr as wdm

        self._healthy(mocker)
        events = []
        lock = threading.Lock()

        def recorded(name, fn):
            def wrapper(*args, **kwargs):
                with lock:
                    events.append(f"start:{name}")
                if name == "get_thermals":
                    time.sleep(0.05)  # a parallel fan-out would start others meanwhile
                result = fn(*args, **kwargs)
                with lock:
                    events.append(f"end:{name}")
                return result

            return wrapper

        for name in self.COLLECTORS:
            mocker.patch(f"windesktopmgr.{name}", side_effect=recorded(name, getattr(wdm, name)))

        dashboard._compute_dashboard_summary()

        assert events[:2] == ["start:get_thermals", "end:get_thermals"]
        assert sum(e.startswith("start:") for e in events) == len(self.COLLECTORS)

    def test_thermals_failure_still_runs_the_rest(self, mocker):
        self._healthy(mocker)
        mocker.patch("windesktopmgr.get_thermals", side_effect=RuntimeError("WMI gone"))
        result = dashboard._compute_dashboard_summary()
        gauges = {g["key"]: g for g in result["gauges"]}
        assert gauges["cpu_temp"]["value"] is None
        assert gauges["cpu_temp"]["sub"] == "no sensor"
        assert result["concerns"] is not None  # the other collectors still ran


class TestSummaryCharacterization:
    """Pins _compute_dashboard_summary's exact concern list before it is split
    into helpers (tech-debt audit 2026-10-17, complexity 67): every concern
    branch fires, the alerts-engine fallback runs, and every best-effort
    source can crash without breaking the dashboard."""

    @staticmethod
    def _rows(result):
        return [(c["level"], c["tab"], c["title"]) for c in result["concerns"]]

    def _everything(self, mocker):
        TestDashboardPhysicalDiskHealth._mock_deps(
            TestDashboardPhysicalDiskHealth(),
            mocker,
            {
                "drives": [
                    {"Letter": "C", "PctUsed": 96, "FreeGB": 10.5},
                    {"Letter": "D", "PctUsed": 86, "FreeGB": 100.0},
                ],
                "physical": [{"Name": "SSD", "Health": "Healthy", "Status": "OK"}],
                "io": [],
            },
        )
        mocker.patch(
            "windesktopmgr.get_credentials_network_health",
            return_value={
                "onedrive_suspended": True,
                "msal_token_stale": True,
                "msal_token_age_h": 30,
                "fast_startup": True,
                "drives_down": [{"Name": "Z:", "DisplayRoot": "\\\\nas\\share"}],
            },
        )
        mocker.patch(
            "windesktopmgr.get_thermals",
            return_value={
                "temps": [{"Name": "CPU Package", "TempC": 96, "status": "critical"}],
                "perf": {"CPUPct": 85},
                "fans": [],
                "has_rich": True,
            },
        )
        mocker.patch(
            "windesktopmgr.get_memory_analysis",
            return_value={
                "total_mb": 32000,
                "used_mb": 30000,
                "top_procs": [{"name": "chrome", "mem": 3500, "pid": 42}],
            },
        )
        mocker.patch(
            "windesktopmgr.get_bios_status",
            return_value={"current": {}, "update": {"update_available": True, "latest_version": "2.25.0"}},
        )
        mocker.patch(
            "windesktopmgr.get_driver_health",
            return_value={
                "problematic_drivers": [{"DeviceName": "Bad Device"}],
                "old_drivers": [{}, {}, {}, {}],
                "nvidia": {"UpdateAvailable": True, "InstalledVersion": "1.0", "LatestVersion": "2.0", "Name": "RTX"},
            },
        )
        import task_watcher

        mocker.patch.object(
            task_watcher,
            "concerns_from_health",
            return_value=[{"level": "warning", "tab": "tasks", "title": "Task X failing"}],
        )
        import baseline

        mocker.patch.object(baseline, "load_history", return_value=[])
        mocker.patch.object(
            baseline,
            "recent_drift",
            return_value=[{"total_changes": 3, "drift": {"startup": {"added": [1], "changed": [2, 3]}}}],
        )
        mocker.patch.object(baseline, "drop_reconciled", side_effect=lambda entries, history=None: entries)
        mocker.patch.object(
            baseline,
            "correlation_alert",
            return_value={"categories": ["startup", "services", "tasks"], "span_seconds": 12, "event_count": 5},
        )
        import backup

        mocker.patch.object(
            backup,
            "summarize_backup",
            return_value={
                "overall_health": {"level": "critical", "reason": "r"},
                "file_history": {"health": {"level": "critical", "reason": "off"}},
                "windows_backup_schedule": {"health": {"level": "warning", "reason": "stale"}},
            },
        )
        import bios_audit

        mocker.patch.object(bios_audit, "recent_changes", return_value=[{"changes": [{"field": f} for f in "abcde"]}])
        mocker.patch.object(bios_audit, "recent_errors", return_value=[{"errors": [{"field": f} for f in "pqrstu"]}])
        import homenet

        mocker.patch.object(
            homenet,
            "get_backup_health",
            return_value={"verizon_stale": True, "verizon_age_days": None, "orbi_stale": True, "orbi_age_days": 45},
        )
        mocker.patch("processes._load_memory_snoozes", return_value={})
        import metrics_history

        return mocker.patch.object(metrics_history, "record_sample")

    def test_every_concern_branch_in_order(self, mocker):
        sample = self._everything(mocker)
        import alerts

        points = []

        def rules(metric_points):
            points.extend((p.metric, p.value, p.label) for p in metric_points)
            return [{"level": "warning", "tab": "thermals", "title": "CPU rule"}]

        mocker.patch.object(alerts, "evaluate_rules", side_effect=rules)
        result = dashboard._compute_dashboard_summary()
        assert self._rows(result) == EXPECTED_EVERYTHING
        assert points == [
            ("cpu_percent", 85.0, ""),
            ("memory_percent", 93.8, "30,000 MB used"),
            ("disk_percent", 96.0, "C:"),
            ("disk_percent", 86.0, "D:"),
        ]
        assert (result["total"], result["critical"], result["warnings"], result["overall"]) == EXPECTED_COUNTS
        assert sample.call_args.args[0]["concerns"] == result["concerns"]

    def test_alerts_engine_fallback(self, mocker):
        self._everything(mocker)
        import alerts

        mocker.patch.object(alerts, "evaluate_rules", side_effect=RuntimeError("rules file corrupt"))
        rows = self._rows(dashboard._compute_dashboard_summary())
        assert [r for r in rows if r[1] in ("thermals", "memory", "disk")] == EXPECTED_FALLBACK

    def test_every_best_effort_source_can_crash(self, mocker):
        self._everything(mocker)
        boom = RuntimeError("boom")
        import alerts
        import backup
        import baseline
        import bios_audit
        import disk
        import homenet
        import kernel_cpu
        import metrics_history
        import nas
        import network
        import task_watcher

        for target, name in (
            (alerts, "evaluate_rules"),
            (kernel_cpu, "stuck_concern"),
            (network, "network_health_concerns"),
            (dashboard, "hardware_advisory_concerns"),
            (dashboard, "memory_config_concerns"),
            (dashboard, "storage_pool_concerns"),
            (nas, "nas_storage_concerns"),
            (task_watcher, "get_all_task_health"),
            (baseline, "load_history"),
            (backup, "summarize_backup"),
            (bios_audit, "recent_changes"),
            (homenet, "get_backup_health"),
            (metrics_history, "record_sample"),
            (disk, "_load_disk_snoozes"),
        ):
            mocker.patch.object(target, name, side_effect=boom)
        mocker.patch("processes._load_memory_snoozes", side_effect=boom)
        result = dashboard._compute_dashboard_summary()
        assert self._rows(result) == EXPECTED_ALL_CRASH
        assert result["gauges"]


# Golden values recorded from the code BEFORE the split (2026-10-17).
EXPECTED_EVERYTHING = [
    ("critical", "credentials", "OneDrive is SUSPENDED — confirmed cause of Word/Outlook sign-in errors"),
    ("critical", "credentials", "Microsoft 365 token expired (30h old)"),
    ("critical", "credentials", "1 NAS drive(s) unreachable"),
    ("critical", "thermals", "Critical temperature: 96°C (CPU Package)"),
    ("critical", "processes", "chrome using 3,500 MB RAM"),
    ("critical", "bios", "BIOS update available: 2.25.0"),
    ("critical", "backup", "Backup health: critical -- backups are not being saved or are out of date"),
    ("critical", "drivers", "1 device(s) with driver errors"),
    ("warning", "credentials", "Fast Startup is enabled"),
    ("warning", "thermals", "CPU rule"),
    ("warning", "tasks", "Task X failing"),
    ("warning", "baseline", "Cross-surface baseline drift cluster (5 events, 12 s)"),
    ("warning", "logs", "BIOS audit collection errors (1 cycle(s) in 24h)"),
    ("warning", "drivers", "NVIDIA driver update available: 1.0 → 2.0"),
    ("info", "baseline", "System baseline drift detected (3 change(s) in 24h)"),
    ("info", "bios", "BIOS/firmware setting change detected (1 in 24h)"),
    ("info", "drivers", "4 third-party drivers are over 2 years old"),
    ("info", "homenet", "Verizon CR1000A config backup is stale (never backed up)"),
    ("info", "homenet", "Orbi RBRE960 config backup is stale (45 days old)"),
]
EXPECTED_COUNTS = (19, 8, 6, "critical")
EXPECTED_FALLBACK = [
    ("critical", "thermals", "Critical temperature: 96°C (CPU Package)"),
    ("critical", "memory", "RAM at 93.8% (30,000 MB used)"),
    ("critical", "disk", "Drive C is 96% full (10.5 GB free)"),
    ("warning", "thermals", "CPU at 85% utilisation"),
    ("warning", "disk", "Drive D is 86% full (100.0 GB free)"),
]
EXPECTED_ALL_CRASH = [
    ("critical", "credentials", "OneDrive is SUSPENDED — confirmed cause of Word/Outlook sign-in errors"),
    ("critical", "credentials", "Microsoft 365 token expired (30h old)"),
    ("critical", "credentials", "1 NAS drive(s) unreachable"),
    ("critical", "thermals", "Critical temperature: 96°C (CPU Package)"),
    ("critical", "memory", "RAM at 93.8% (30,000 MB used)"),
    ("critical", "disk", "Drive C is 96% full (10.5 GB free)"),
    ("critical", "processes", "chrome using 3,500 MB RAM"),
    ("critical", "bios", "BIOS update available: 2.25.0"),
    ("critical", "drivers", "1 device(s) with driver errors"),
    ("warning", "credentials", "Fast Startup is enabled"),
    ("warning", "thermals", "CPU at 85% utilisation"),
    ("warning", "disk", "Drive D is 86% full (100.0 GB free)"),
    ("warning", "drivers", "NVIDIA driver update available: 1.0 → 2.0"),
    ("info", "drivers", "4 third-party drivers are over 2 years old"),
]
