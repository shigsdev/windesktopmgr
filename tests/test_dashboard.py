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
