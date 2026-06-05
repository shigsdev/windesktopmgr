"""tests/test_homenet_topology.py -- topology + reboot + router-config-backup
+ backup-health tests.

Split out of tests/test_homenet.py (backlog #57) to keep both files under the
5,000-line codehealth threshold. Pure relocation -- no test logic changed.
Covers the contiguous tail from TestBuildTopology through
TestTopologyDiagramPerBridgeColumns. Mirrors the origin's module header; the
homenet module is imported inside individual tests, and fixtures (client,
mocker, tmp_path, monkeypatch) come from conftest / pytest-mock.
"""

import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest  # noqa: F401 -- used by moved classes via pytest.skip / fixtures


class TestBuildTopology:
    """Topology builder is the heart of #9 -- joins three data sources
    (device inventory, switch MAC table, Orbi per-AP mapping) into one
    nested structure the SVG renderer can walk."""

    def _inventory(self, *device_dicts):
        """Helper: wrap device dicts into the inventory shape build_topology
        expects. Each device dict needs at least mac+ip; missing fields
        fall back to defaults via _merge_device_data semantics."""
        return {
            "devices": {d["mac"]: d for d in device_dicts},
            "last_scan": "2026-04-25T00:00:00",
        }

    def test_router_label_picks_up_inventory_mac(self):
        """When a 192.168.1.1 device is in inventory, build_topology fills
        router.mac so the diagram can use it as the connection anchor."""
        from homenet import build_topology

        inv = self._inventory({"mac": "11:11:11:11:11:11", "ip": "192.168.1.1", "active": True})
        t = build_topology(inv, switch_data={})
        assert t["router"]["ip"] == "192.168.1.1"
        assert t["router"]["mac"] == "11:11:11:11:11:11"
        assert t["router"]["name"] == "Verizon CR1000A"

    def test_user_attested_orbi_satellite_appears_as_ap_column(self):
        """Bug fix 2026-05-13: the RBRE960 firmware quirk corrupts
        ConnAPMAC for satellite-connected clients, so the auto-discovery
        path from `conn_ap_mac` can no longer surface satellites. User
        manually attests via wired_via='orbi_satellite'. The topology
        builder MUST render an AP column for any attested satellite
        even when no client has yet been assigned to it (empty-column
        is the affordance for the user to click + name the satellite)."""
        from homenet import build_topology

        sat_mac = "28:94:01:40:58:F6"
        inv = self._inventory(
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1"},  # base
            {
                "mac": sat_mac,
                "ip": "",
                "vendor": "Netgear",
                "wired_via": "orbi_satellite",
                "friendly_name": "Master Bedroom",
            },
        )
        t = build_topology(inv, switch_data={})
        ap_macs = {ap["mac"] for ap in t["aps"]}
        assert sat_mac in ap_macs, (
            "User-attested Orbi satellite must appear as an AP column even "
            "without any clients assigned to it. Without this, the user can't "
            "rename the satellite via the clickable header (PR #29)."
        )

    def test_via_orbi_satellite_assigns_clients_to_attested_satellite(self):
        """When a wireless device has via_orbi_satellite=<sat_mac>, the
        topology builder buckets it under that satellite's AP column.
        Same pattern as behind_moca_bridge for MoCA bridges."""
        from homenet import build_topology

        sat_mac = "28:94:01:40:58:F6"
        inv = self._inventory(
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1"},  # base
            {
                "mac": sat_mac,
                "ip": "",
                "vendor": "Netgear",
                "wired_via": "orbi_satellite",
                "friendly_name": "Master Bedroom",
            },
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.0.0.50",
                "network": "wireless",
                "via_orbi_satellite": sat_mac,
            },
        )
        t = build_topology(inv, switch_data={})
        sat_col = next((ap for ap in t["aps"] if ap["mac"] == sat_mac), None)
        assert sat_col is not None
        assert "AA:BB:CC:DD:EE:FF" in sat_col["clients"]

    def test_via_orbi_satellite_pointing_at_unattested_mac_is_dropped(self):
        """Dangling pointer: a client points at a sat_mac that's no longer
        tagged as orbi_satellite (user changed their mind / removed the
        satellite). The client must NOT spawn a phantom column -- it
        falls through to whichever other bucket applies (or none)."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1"},
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.0.0.50",
                "network": "wireless",
                "via_orbi_satellite": "FF:FF:FF:FF:FF:FF",  # not in inventory as a sat
            },
        )
        t = build_topology(inv, switch_data={})
        ap_macs = {ap["mac"] for ap in t["aps"]}
        assert "FF:FF:FF:FF:FF:FF" not in ap_macs, "Dangling sat reference must not spawn a column"

    def test_via_orbi_satellite_self_reference_is_ignored(self):
        """A satellite can't be its own parent satellite -- defensive
        guard against UI bugs that might send mac == via_orbi_satellite."""
        from homenet import build_topology

        sat_mac = "28:94:01:40:58:F6"
        inv = self._inventory(
            {
                "mac": sat_mac,
                "ip": "",
                "wired_via": "orbi_satellite",
                "via_orbi_satellite": sat_mac,  # self-reference
            },
        )
        t = build_topology(inv, switch_data={})
        sat_col = next((ap for ap in t["aps"] if ap["mac"] == sat_mac), None)
        assert sat_col is not None
        # The satellite is in its own AP column but NOT as its own client
        assert sat_mac not in sat_col["clients"]

    def test_switch_unavailable_is_reported_not_fatal(self):
        from homenet import build_topology

        inv = self._inventory({"mac": "AA:AA:AA:AA:AA:AA", "ip": "192.168.1.50"})
        t = build_topology(inv, switch_data={"error": "snmp timeout"})
        assert t["ok"] is True
        assert t["switches"][0]["available"] is False
        assert "snmp timeout" in t["switches"][0]["error"]
        # Device with no port mapping ends up unmapped, not lost
        assert "AA:AA:AA:AA:AA:AA" in t["unmapped"]

    def test_switch_mac_table_groups_by_port(self):
        """The wired devices on switch ports must be bucketed by port_index."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "AA:AA:AA:AA:AA:01", "ip": "192.168.1.10"},
            {"mac": "AA:AA:AA:AA:AA:02", "ip": "192.168.1.11"},
            {"mac": "AA:AA:AA:AA:AA:03", "ip": "192.168.1.12"},
        )
        switch_data = {
            "mac_table": [
                {"mac": "AA:AA:AA:AA:AA:01", "port_index": 1},
                {"mac": "AA:AA:AA:AA:AA:02", "port_index": 1},
                {"mac": "AA:AA:AA:AA:AA:03", "port_index": 5},
            ]
        }
        t = build_topology(inv, switch_data=switch_data)
        ports = t["switches"][0]["ports"]
        assert sorted(ports[1]) == ["AA:AA:AA:AA:AA:01", "AA:AA:AA:AA:AA:02"]
        assert ports[5] == ["AA:AA:AA:AA:AA:03"]
        # All three are mapped (none unmapped)
        assert t["stats"]["wired_mapped"] == 3
        assert t["stats"]["unmapped"] == 0

    def test_orbi_clients_grouped_by_satellite(self):
        """conn_ap_mac on wireless devices buckets them under their AP."""
        from homenet import build_topology

        # Use realistic universal Netgear OUI BSSIDs -- the prior
        # fixture used BA:5E... and 5A:71:11:11:11:11 (both locally-admin
        # MACs) which now get correctly rejected by
        # _is_plausible_orbi_ap_mac as phantom client randomization.
        inv = self._inventory(
            # Orbi base (10.0.0.1 in inventory) -- universal Netgear OUI
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1"},
            # Two clients on the base
            {"mac": "CC:CC:CC:00:00:01", "ip": "10.0.0.10", "conn_ap_mac": "28:94:01:3F:73:E1"},
            {"mac": "CC:CC:CC:00:00:02", "ip": "10.0.0.11", "conn_ap_mac": "28:94:01:3F:73:E1"},
            # Two clients on a satellite -- different Netgear MAC, also universal
            {"mac": "CC:CC:CC:00:00:03", "ip": "10.0.0.12", "conn_ap_mac": "28:94:01:40:58:F6"},
            {"mac": "CC:CC:CC:00:00:04", "ip": "10.0.0.13", "conn_ap_mac": "28:94:01:40:58:F6"},
        )
        t = build_topology(inv, switch_data={})
        aps = {ap["mac"]: ap for ap in t["aps"]}
        assert "28:94:01:3F:73:E1" in aps
        assert aps["28:94:01:3F:73:E1"]["is_base"] is True
        assert sorted(aps["28:94:01:3F:73:E1"]["clients"]) == [
            "CC:CC:CC:00:00:01",
            "CC:CC:CC:00:00:02",
        ]
        assert "28:94:01:40:58:F6" in aps
        assert aps["28:94:01:40:58:F6"]["is_base"] is False
        assert "satellite" in aps["28:94:01:40:58:F6"]["name"].lower()
        assert sorted(aps["28:94:01:40:58:F6"]["clients"]) == [
            "CC:CC:CC:00:00:03",
            "CC:CC:CC:00:00:04",
        ]
        assert t["stats"]["wireless_mapped"] == 4

    def test_phantom_locally_admin_conn_ap_mac_does_not_create_satellite(self):
        """User feedback 2026-05-08 ('five orbi's when I only have three'):
        the topology was synthesising 'Orbi satellite (1111)' columns from
        clients reporting locally-admin / repeated-octet ConnAPMAC values
        (e.g. 5A:71:11:11:11:11). Real Orbi BSSIDs are universal Netgear
        OUIs -- locally-admin MACs are ALWAYS client randomization."""
        from homenet import build_topology

        inv = self._inventory(
            # Real Orbi base
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1"},
            # Real client on the base
            {"mac": "CC:CC:CC:00:00:01", "ip": "10.0.0.10", "conn_ap_mac": "28:94:01:3F:73:E1"},
            # Phantom: client reports locally-admin + repeated-octet ConnAPMAC
            {"mac": "DD:DD:DD:00:00:01", "ip": "10.0.0.20", "conn_ap_mac": "5A:71:11:11:11:11"},
        )
        t = build_topology(inv, switch_data={})
        ap_macs = {ap["mac"] for ap in t["aps"]}
        assert "5A:71:11:11:11:11" not in ap_macs, (
            f"Phantom locally-admin ConnAPMAC should NOT spawn an Orbi satellite column. Got APs: {sorted(ap_macs)}"
        )
        assert "28:94:01:3F:73:E1" in ap_macs

    def test_base_detection_prefers_universal_mac_over_locally_admin(self):
        """Multiple inventory entries can share IP 10.0.0.1 (a real Orbi
        BSSID + a transient randomized-MAC client). Base detection must
        prefer the universal MAC, not whichever entry came first.
        Catches the 2026-05-08 'Orbi RBRE960 (Base)' showing as a
        BA:5E:... random MAC instead of the real Netgear MAC."""
        from homenet import build_topology

        # Insertion order: phantom FIRST, real Netgear AP SECOND.
        # Pre-fix code picked whichever came first -> phantom. Post-fix
        # code picks the universal MAC regardless of insertion order.
        inv = self._inventory(
            {"mac": "BA:5E:00:00:00:01", "ip": "10.0.0.1", "vendor": "Random MAC (Phone)"},
            {"mac": "28:94:01:3F:73:E1", "ip": "10.0.0.1", "vendor": "Netgear"},
        )
        t = build_topology(inv, switch_data={})
        # The base may not appear at all if no clients use it -- the
        # topology builder only synthesises a base entry when needed.
        # The important assertion is that BA:5E is NEVER picked as base.
        for ap in t["aps"]:
            if ap.get("is_base"):
                assert ap["mac"] == "28:94:01:3F:73:E1", (
                    f"Base picked locally-admin MAC {ap['mac']!r} -- should be the universal Netgear MAC."
                )

    def test_devices_without_uplink_land_in_unmapped(self):
        """ARP-discovered offline devices with no switch entry and no
        Orbi conn_ap_mac end up in the unmapped bucket -- they don't
        vanish from the topology entirely."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "DE:AD:BE:EF:00:01", "ip": "192.168.1.99", "active": False},
        )
        t = build_topology(inv, switch_data={})
        assert "DE:AD:BE:EF:00:01" in t["unmapped"]

    def test_infrastructure_macs_excluded_from_unmapped(self):
        """The router itself / switch itself / Orbi base shouldn't show
        up as 'unmapped devices' -- they're rendered as their own infra
        nodes elsewhere in the diagram."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "DC:62:79:F3:52:5C", "ip": "192.168.1.5"},  # the switch itself
        )
        t = build_topology(inv, switch_data={})
        assert "DC:62:79:F3:52:5C" not in t["unmapped"]

    def test_moca_bridges_detected_by_vendor(self):
        """Devices made by known MoCA-bridge vendors (Actiontec, GoCoax, etc.)
        get bucketed into ``moca_bridges`` so the diagram can render them as
        their own infrastructure tier."""
        from homenet import build_topology

        inv = self._inventory(
            {
                "mac": "00:0F:B3:11:22:33",
                "ip": "192.168.1.50",
                "vendor": "Actiontec Electronics, Inc.",
                "network": "wired",
            },
            {"mac": "AA:BB:CC:00:00:99", "ip": "192.168.1.51", "vendor": "GoCoax", "network": "wired"},
            # Not a MoCA bridge -- should NOT land in moca_bridges
            {"mac": "11:22:33:44:55:66", "ip": "192.168.1.52", "vendor": "Apple, Inc.", "network": "wired"},
        )
        t = build_topology(inv, switch_data={})
        assert "00:0F:B3:11:22:33" in t["moca_bridges"]
        assert "AA:BB:CC:00:00:99" in t["moca_bridges"]
        assert "11:22:33:44:55:66" not in t["moca_bridges"]
        assert t["stats"]["moca_bridges"] == 2

    def test_via_verizon_or_moca_catches_wired_devices_off_switch(self):
        """A wired device that's NOT on the switch MAC table AND isn't itself
        a MoCA bridge ends up in ``via_verizon_or_moca`` -- the catch-all
        explaining 'wired but not seen by the switch'. This is the bucket that
        shows EVERY wired device when SNMP isn't configured."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "AA:00:00:00:00:01", "ip": "192.168.1.20", "vendor": "Apple, Inc.", "network": "wired"},
            {"mac": "AA:00:00:00:00:02", "ip": "192.168.1.21", "vendor": "QNAP Systems", "network": "wired"},
        )
        # Empty switch MAC table = SNMP not configured / switch unreachable
        t = build_topology(inv, switch_data={})
        assert "AA:00:00:00:00:01" in t["via_verizon_or_moca"]
        assert "AA:00:00:00:00:02" in t["via_verizon_or_moca"]
        # NOT in unmapped -- wired devices shouldn't appear there anymore
        assert "AA:00:00:00:00:01" not in t["unmapped"]
        assert t["stats"]["via_verizon_or_moca"] == 2

    def test_wired_on_switch_not_double_counted_in_via_verizon(self):
        """A wired device that DID land on the switch must NOT also appear
        in via_verizon_or_moca -- it has a precise port, not a fallback."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "AA:00:00:00:00:01", "ip": "192.168.1.20", "vendor": "Apple, Inc.", "network": "wired"},
        )
        switch = {"mac_table": [{"mac": "AA:00:00:00:00:01", "port_index": 3}]}
        t = build_topology(inv, switch_data=switch)
        assert "AA:00:00:00:00:01" not in t["via_verizon_or_moca"]
        assert "AA:00:00:00:00:01" not in t["unmapped"]
        assert t["stats"]["wired_mapped"] == 1
        assert t["stats"]["via_verizon_or_moca"] == 0

    def test_router_mac_excluded_from_via_verizon_or_moca(self):
        """The Verizon router itself (192.168.1.1) must NOT appear in any
        device-tier bucket -- it's the tier-1 router node. Caught live on
        2026-04-25 when the WNC Corporation MAC at 192.168.1.1 was leaking
        into the Verizon-direct/MoCA list."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "78:67:0E:BD:A4:3F", "ip": "192.168.1.1", "vendor": "WNC Corporation", "network": "wired"},
        )
        t = build_topology(inv, switch_data={})
        assert "78:67:0E:BD:A4:3F" not in t["via_verizon_or_moca"]
        assert "78:67:0E:BD:A4:3F" not in t["unmapped"]
        # And the router node itself picked up the MAC
        assert t["router"]["mac"] == "78:67:0E:BD:A4:3F"

    def test_orbi_wan_mac_excluded_via_hostname_pattern(self):
        """An Orbi base has separate WAN-side and LAN-side MACs -- the wired
        ARP scan picks up the WAN-side MAC at a 192.x address with hostname
        like RBRE960.mynetworksettings.com. That MAC must be recognised as
        infrastructure (not a tier-3 device) via the hostname pattern."""
        from homenet import build_topology

        inv = self._inventory(
            {
                "mac": "28:94:01:3F:73:E2",
                "ip": "192.168.1.152",
                "vendor": "Netgear",
                "hostname": "RBRE960.mynetworksettings.com",
                "network": "wired",
            },
        )
        t = build_topology(inv, switch_data={})
        assert "28:94:01:3F:73:E2" not in t["via_verizon_or_moca"]
        assert "28:94:01:3F:73:E2" not in t["unmapped"]

    def test_wired_via_field_splits_into_two_buckets(self, mocker):
        """User feedback 2026-04-25: 'Verizon-direct / MoCA' was conflating
        two physically-distinct paths. New per-device ``wired_via`` field
        splits them into ``verizon_lan`` and ``via_moca`` buckets in the
        topology response. Empty/unknown values default to verizon_lan."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        inv = self._inventory(
            {
                "mac": "AA:00:00:00:00:01",
                "ip": "192.168.1.50",
                "network": "wired",
                "wired_via": "moca",
                "vendor": "Apple",
            },
            {
                "mac": "AA:00:00:00:00:02",
                "ip": "192.168.1.51",
                "network": "wired",
                "wired_via": "verizon_lan",
                "vendor": "Apple",
            },
            {"mac": "AA:00:00:00:00:03", "ip": "192.168.1.52", "network": "wired", "vendor": "Apple"},
        )
        t = build_topology(inv, switch_data={})
        assert "AA:00:00:00:00:01" in t["via_moca"]
        assert "AA:00:00:00:00:02" in t["verizon_lan"]
        # Untagged defaults to verizon_lan
        assert "AA:00:00:00:00:03" in t["verizon_lan"]
        assert t["stats"]["via_moca"] == 1
        assert t["stats"]["verizon_lan"] == 2
        # Backwards-compat alias still includes both
        assert set(t["via_verizon_or_moca"]) == {"AA:00:00:00:00:01", "AA:00:00:00:00:02", "AA:00:00:00:00:03"}

    def test_wired_via_switch_force_excludes_from_leftover_buckets(self, mocker):
        """When the user marks wired_via='switch' on a device, it's a force-
        override that says 'I know this is on the switch even though SNMP
        didn't see it'. Such a device must NOT appear in via_moca or
        verizon_lan -- it would double-count and confuse the diagram."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        inv = self._inventory(
            {
                "mac": "AA:00:00:00:00:01",
                "ip": "192.168.1.50",
                "network": "wired",
                "wired_via": "switch",
                "vendor": "Apple",
            },
        )
        t = build_topology(inv, switch_data={})
        assert "AA:00:00:00:00:01" not in t["via_moca"]
        assert "AA:00:00:00:00:01" not in t["verizon_lan"]
        assert "AA:00:00:00:00:01" not in t["unmapped"]

    def test_device_update_route_accepts_wired_via(self, client, mocker):
        """The /api/homenet/device/update route must persist wired_via with
        a whitelist (only 'moca'/'verizon_lan'/'switch'/'' allowed) so
        garbage values can't leak into the topology classifier."""
        # Set up an inventory with one device
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:00:00:00:00:01": {
                        "mac": "AA:00:00:00:00:01",
                        "ip": "192.168.1.50",
                        "wired_via": "",
                    },
                },
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        # Valid value -> persisted
        resp = client.post("/api/homenet/device/update", json={"mac": "AA:00:00:00:00:01", "wired_via": "moca"})
        assert resp.status_code == 200
        # The save_mock got called with inventory carrying the new field
        saved_inv = save_mock.call_args[0][0]
        assert saved_inv["devices"]["AA:00:00:00:00:01"]["wired_via"] == "moca"

    def test_device_update_route_rejects_invalid_wired_via(self, client, mocker):
        """Whitelist guard: junk values (SQL-injection-style attempts,
        garbage strings) must NOT land in inventory."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:00:00:00:00:01": {"mac": "AA:00:00:00:00:01", "wired_via": "moca"},
                },
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update", json={"mac": "AA:00:00:00:00:01", "wired_via": "DROP TABLE devices"}
        )
        assert resp.status_code == 200  # the call succeeds
        # but the bad value isn't persisted -- the prior 'moca' value stays
        saved_inv = save_mock.call_args[0][0]
        assert saved_inv["devices"]["AA:00:00:00:00:01"]["wired_via"] == "moca"

    def test_base_labelled_as_base_not_satellite(self):
        """Bug 2026-04-25: The Orbi base (10.0.0.1) was being labelled
        'Orbi satellite (73E1)' instead of 'Orbi RBRE960 (Base)' because
        its MAC isn't in _INFRA_LABELS (only the IP is) and the labeller
        couldn't tell base from satellite. Adding an is_base parameter
        fixes the label without losing other resolution paths."""
        from homenet import _label_orbi_node

        base_mac = "28:94:01:3F:73:E1"
        # Without is_base flag => satellite fallback
        assert _label_orbi_node(base_mac) == "Orbi satellite (73E1)"
        # With is_base flag => base label
        assert _label_orbi_node(base_mac, is_base=True) == "Orbi RBRE960 (Base)"
        # friendly_name still wins over is_base label
        inv = {base_mac: {"friendly_name": "Living Room Orbi"}}
        assert _label_orbi_node(base_mac, inv, is_base=True) == "Living Room Orbi"

    def test_orbi_satellite_names_from_soap_used_as_label(self):
        """When the user has already named satellites in the Orbi web UI,
        we pull those names via the GetAllNewSatellites SOAP action and
        use them as the topology label. Falls between hostname/friendly
        (which beat it) and is_base/MAC-suffix (which it beats)."""
        from homenet import _label_orbi_node

        sat_mac = "28:94:01:40:5A:63"
        sat_names = {sat_mac: "Upstairs Orbi"}
        # SOAP-fetched name beats the (XXXX) fallback
        assert _label_orbi_node(sat_mac, sat_names_from_orbi=sat_names) == "Upstairs Orbi"
        # User-set friendly_name in WDM still beats the Orbi-side name
        # (the user explicitly chose to override it locally)
        inv = {sat_mac: {"friendly_name": "My Custom Name"}}
        assert _label_orbi_node(sat_mac, inv, sat_names_from_orbi=sat_names) == "My Custom Name"
        # No SOAP, no friendly, no hostname => MAC-suffix fallback
        assert _label_orbi_node(sat_mac) == "Orbi satellite (5A63)"

    def test_orbi_satellite_soap_failure_does_not_break_topology(self, mocker):
        """If the Orbi GetAllNewSatellites SOAP call fails (auth error,
        firmware doesn't support the action, network drop), the satellite
        labeller must still produce a usable label via the existing
        fallback chain."""
        from homenet import _get_orbi_satellite_names_cached

        # Force a fresh fetch then make the SOAP call blow up.
        mocker.patch("homenet._orbi_sat_cache", {"ts": 0.0, "data": []})
        mocker.patch("homenet._orbi_get_satellites", side_effect=Exception("firmware doesn't support this action"))
        # Should swallow the exception and return an empty mapping
        assert _get_orbi_satellite_names_cached() == {}

    def test_orbi_satellite_soap_parses_devicename(self):
        """Parse a realistic GetAllNewSatellites response into MAC+name pairs."""
        from homenet import _parse_orbi_satellites

        xml = """<?xml version="1.0"?><Response>
        <NewSatellite>
          <DeviceName>Upstairs Orbi</DeviceName>
          <MAC>28:94:01:40:5A:63</MAC>
          <IP>10.0.0.5</IP>
          <ModelName>RBS50Y</ModelName>
        </NewSatellite>
        <NewSatellite>
          <DeviceName>Downstairs Orbi</DeviceName>
          <MAC>28:94:01:40:58:F6</MAC>
          <IP>10.0.0.6</IP>
          <ModelName>RBS50Y</ModelName>
        </NewSatellite>
        </Response>"""
        sats = _parse_orbi_satellites(xml)
        assert len(sats) == 2
        names = {s["mac"]: s["name"] for s in sats}
        assert names["28:94:01:40:5A:63"] == "Upstairs Orbi"
        assert names["28:94:01:40:58:F6"] == "Downstairs Orbi"

    def test_orbi_unknown_ap_bucket_separates_from_unmapped(self, mocker):
        """Wireless devices the Orbi reported (source='orbi') but with empty
        conn_ap_mac get their own ``orbi_mesh_unknown_ap`` bucket -- not
        dumped into ``unmapped`` where they look lost. Truly unmapped (not
        seen by Orbi) stay in ``unmapped``."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        inv = self._inventory(
            # Orbi-reported wireless without conn_ap_mac
            {"mac": "AA:BB:CC:00:00:01", "ip": "10.0.0.50", "network": "wireless", "source": "orbi", "vendor": "Apple"},
            # Stale ARP-only wireless ghost (probably offline)
            {
                "mac": "AA:BB:CC:00:00:02",
                "ip": "10.0.0.99",
                "network": "wireless",
                "source": "arp",
                "vendor": "Unknown",
            },
        )
        t = build_topology(inv, switch_data={})
        assert "AA:BB:CC:00:00:01" in t["orbi_mesh_unknown_ap"]
        assert "AA:BB:CC:00:00:02" in t["unmapped"]
        # The truly unmapped one is NOT in orbi_mesh_unknown_ap
        assert "AA:BB:CC:00:00:02" not in t["orbi_mesh_unknown_ap"]
        assert t["stats"]["orbi_mesh_unknown_ap"] == 1

    def test_satellite_friendly_name_from_inventory(self):
        """Bug 2026-04-25: Orbi satellites were stuck at the 'Orbi satellite
        (XXXX)' fallback forever because they never appeared in
        devices_by_mac (Orbi SOAP returns clients only). Fix: build_topology
        synthesises a placeholder inventory entry per satellite + the labeller
        accepts a devices_by_mac arg and reads friendly_name from it."""
        from homenet import _label_orbi_node

        sat_mac = "28:94:01:40:5A:63"
        # No inventory => MAC-suffix fallback
        assert _label_orbi_node(sat_mac) == "Orbi satellite (5A63)"
        # Inventory with friendly_name => that wins
        inv = {sat_mac: {"friendly_name": "Living Room Orbi"}}
        assert _label_orbi_node(sat_mac, inv) == "Living Room Orbi"
        # Inventory with hostname only => hostname (sans .mynetworksettings.com)
        inv2 = {sat_mac: {"hostname": "Kitchen-Orbi.mynetworksettings.com"}}
        assert _label_orbi_node(sat_mac, inv2) == "Kitchen-Orbi"
        # Inventory entry with NEITHER => still falls back
        inv3 = {sat_mac: {"friendly_name": "", "hostname": ""}}
        assert _label_orbi_node(sat_mac, inv3) == "Orbi satellite (5A63)"

    def test_satellite_synthesised_into_inventory(self, mocker):
        """When a satellite MAC isn't yet in inventory, build_topology
        synthesises a placeholder so the user can name it via the existing
        device-edit modal. Without this the satellite has no inventory row
        to edit, and the friendly_name path is unreachable."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")  # avoid disk write in test
        sat_mac = "28:94:01:40:5A:63"
        inv = self._inventory(
            # Orbi base in inventory
            {"mac": "BA:5E:00:00:00:01", "ip": "10.0.0.1"},
            # One wireless client connected to a satellite that's NOT in inventory
            {"mac": "CC:CC:CC:00:00:01", "ip": "10.0.0.10", "conn_ap_mac": sat_mac, "network": "wireless"},
        )
        t = build_topology(inv, switch_data={})
        # Satellite MAC must now exist in t["devices"] with a synthesised entry
        assert sat_mac in t["devices"]
        sat_entry = t["devices"][sat_mac]
        assert sat_entry["source"] == "topology_synthesised"
        # And it MUST have empty friendly_name initially -- user fills it in via
        # the edit modal. Test that subsequent build_topology runs would pick
        # up the friendly_name if it were set.
        assert sat_entry["friendly_name"] == ""

    def test_commscope_fios_set_top_box_NOT_auto_classified_as_bridge(self):
        """Bug 2026-05-12 reversal of earlier behaviour: the Verizon FiOS
        VMS4100 / VMS1100 Set-Top Boxes (Commscope vendor) are MoCA
        ENDPOINTS, not Ethernet-to-coax bridges. Earlier we auto-
        classified them as bridges (which spawned a phantom column in
        the user's topology); now we keep them out of moca_bridges
        UNLESS the user explicitly attests wired_via=moca_bridge.

        User can still classify a Commscope as a real bridge by
        editing the device and selecting wired_via='moca_bridge'."""
        from homenet import build_topology

        inv = self._inventory(
            {
                "mac": "B0:5D:D4:76:2A:C0",
                "ip": "192.168.1.102",
                "vendor": "Commscope",
                "hostname": "VMS4100ATV.mynetworksettings.com",
                "network": "wired",
            },
        )
        t = build_topology(inv, switch_data={})
        # NO auto-classification as a bridge
        assert "B0:5D:D4:76:2A:C0" not in t["moca_bridges"]

    def test_commscope_explicitly_tagged_as_bridge_DOES_appear(self):
        """Reverse of the above: if the user explicitly tags a Commscope
        device as wired_via='moca_bridge', it MUST appear in the bridge
        list -- their attestation wins."""
        from homenet import build_topology

        inv = self._inventory(
            {
                "mac": "B0:5D:D4:76:2A:C0",
                "ip": "",
                "vendor": "Commscope",
                "hostname": "MyCommscopeBridge",
                "network": "wired",
                "wired_via": "moca_bridge",
            },
        )
        t = build_topology(inv, switch_data={})
        assert "B0:5D:D4:76:2A:C0" in t["moca_bridges"]

    def test_wireless_devices_without_ap_stay_in_unmapped(self):
        """Wireless devices without a conn_ap_mac (e.g. inventory captured
        before the ConnAPMAC field was added) are TRULY unmapped -- not
        Verizon-direct, since they're not wired."""
        from homenet import build_topology

        inv = self._inventory(
            {"mac": "WI:RE:FF:00:00:01", "ip": "10.0.0.50", "network": "wireless", "vendor": "Apple"},
        )
        t = build_topology(inv, switch_data={})
        assert "WI:RE:FF:00:00:01" in t["unmapped"]
        assert "WI:RE:FF:00:00:01" not in t["via_verizon_or_moca"]


class TestMocaVendorDetection:
    """The vendor-name pattern list is the single source of truth for what
    counts as a MoCA bridge. Each test pins one matching pattern and one
    near-miss to guard against accidental over-matching."""

    @pytest.mark.parametrize(
        "vendor, expected",
        [
            # Known Ethernet-to-coax bridge vendors: auto-classified
            ("Actiontec Electronics, Inc.", True),
            ("ACTIONTEC ELECTRONICS", True),  # case-insensitive
            ("Askey Computer Corp", True),  # Verizon Network Extenders
            ("GoCoax", True),
            ("Hitron Technologies", True),
            ("Westell Technologies", True),
            ("Motorola Mobility LLC", True),
            ("ScreenBeam Inc.", True),
            # Bug 2026-05-12: Commscope / Arris are MoCA endpoints (Verizon
            # FiOS STBs), NOT bridges. Must NOT auto-classify -- the user
            # can still tag explicitly via wired_via=moca_bridge.
            ("Commscope", False),
            ("Arris Group", False),
            # Other near-misses
            ("Apple, Inc.", False),
            ("Cisco Systems", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_moca_bridge_pattern_matching(self, vendor, expected):
        from homenet import _is_moca_bridge

        dev = {"vendor": vendor} if vendor is not None else {}
        assert _is_moca_bridge(dev) is expected

    def test_user_wired_via_overrides_vendor_pattern_to_NOT_bridge(self):
        """Bug 2026-04-25 (round 2): VMS4100ATV (Commscope) was being
        auto-detected as a MoCA bridge by vendor pattern, but the user
        clarified it's actually a Verizon Set-Top Box endpoint -- a
        MoCA-CAPABLE device, not a bridge. Setting wired_via to anything
        specific ("moca", "verizon_lan", "switch") must override the
        vendor pattern."""
        from homenet import _is_moca_bridge

        # User says "moca endpoint" -> NOT bridge (overrides any classifier)
        assert _is_moca_bridge({"vendor": "Actiontec", "wired_via": "moca"}) is False
        # Same for verizon_lan
        assert _is_moca_bridge({"vendor": "Askey", "wired_via": "verizon_lan"}) is False
        # And for switch override
        assert _is_moca_bridge({"vendor": "Actiontec", "wired_via": "switch"}) is False
        # Commscope auto-detection no longer fires (bug 2026-05-12 second-
        # round fix: Commscope/Arris dropped from _ETHERNET_MOCA_BRIDGE_VENDORS
        # because they're STBs, not bridges). User can still tag explicitly:
        assert _is_moca_bridge({"vendor": "Commscope"}) is False  # no longer auto-True
        assert _is_moca_bridge({"vendor": "Commscope", "wired_via": "moca_bridge"}) is True
        # Real bridge vendor still auto-classifies
        assert _is_moca_bridge({"vendor": "Actiontec"}) is True

    def test_is_moca_bridge_user_attestation_overrides_vendor(self):
        """Bug 2026-04-25: user reported "I have two MoCA's, only see one"
        because their second bridge had a vendor name not in the auto-
        detection patterns. New ``wired_via='moca_bridge'`` option lets
        them tag any device as a bridge regardless of vendor."""
        from homenet import _is_moca_bridge

        # Vendor doesn't match any pattern, but user attested -> True
        dev = {"vendor": "NoNameBrand", "wired_via": "moca_bridge"}
        assert _is_moca_bridge(dev) is True
        # No vendor at all + user attested -> True
        assert _is_moca_bridge({"wired_via": "moca_bridge"}) is True
        # Pattern matches but user-attested anyway -> still True (idempotent)
        assert _is_moca_bridge({"vendor": "Actiontec", "wired_via": "moca_bridge"}) is True

    def test_is_moca_bridge_blink_sync_module_false_positive(self):
        """Bug 2026-05-12: the Blink Sync Module uses the Actiontec OUI
        (00:03:7F) and was getting auto-classified as a MoCA bridge,
        spawning a phantom 'Actiontec A30B' column in the user's
        topology with no children. dns_hostname='blink-sync-module'
        proves it's not a network bridge."""
        from homenet import _is_moca_bridge

        # Blink discovered via DNS -- vendor matches MoCA pattern, hostname
        # makes it obvious it's not a bridge.
        blink = {
            "mac": "00:03:7F:B4:A3:0B",
            "vendor": "Actiontec",
            "dns_hostname": "blink-sync-module",
            "wired_via": "",
        }
        assert _is_moca_bridge(blink) is False

    def test_is_moca_bridge_hostname_check_case_insensitive(self):
        from homenet import _is_moca_bridge

        # Case-insensitive substring match -- catches "Blink-Sync-Module",
        # "BLINK-SYNC-MODULE", etc.
        for hn in ("blink-sync-module", "Blink-Sync-Module", "BLINK-SYNC-MODULE"):
            assert _is_moca_bridge({"vendor": "Actiontec", "dns_hostname": hn}) is False

    def test_is_moca_bridge_hostname_check_falls_back_to_hostname_field(self):
        """When dns_hostname is empty but hostname is set, we still check it."""
        from homenet import _is_moca_bridge

        assert _is_moca_bridge({"vendor": "Actiontec", "dns_hostname": "", "hostname": "blink-sync-module"}) is False

    def test_is_moca_bridge_user_override_still_wins_over_hostname_check(self):
        """If the user explicitly tags wired_via='moca_bridge', that overrides
        even the Blink hostname check (defensive: they may have a weird
        deployment we haven't seen)."""
        from homenet import _is_moca_bridge

        dev = {
            "vendor": "Actiontec",
            "dns_hostname": "blink-sync-module",
            "wired_via": "moca_bridge",  # user attested
        }
        assert _is_moca_bridge(dev) is True

    def test_is_moca_bridge_real_actiontec_still_passes(self):
        """The fix mustn't break legitimate Actiontec MoCA bridges --
        their hostname is empty (router-discovered) or names them as
        bridges, never as Blink/Echo/Ring."""
        from homenet import _is_moca_bridge

        # Real Actiontec ECB6200 bridge: vendor matches, no hostname
        assert _is_moca_bridge({"vendor": "Actiontec", "dns_hostname": ""}) is True
        # Real Actiontec with router-side label
        assert _is_moca_bridge({"vendor": "Actiontec", "dns_hostname": "MoCA-Living-Room"}) is True


class TestIsPlausibleOrbiApMac:
    """Backlog #42 follow-up #2 (2026-05-08): the topology builder was
    spawning phantom 'Orbi satellite' columns for client-randomized
    locally-admin MACs and repeated-octet sentinels. _is_plausible_orbi_
    ap_mac is the filter that caught both. Conservative -- a false
    positive (rejecting a real BSSID) silently drops a real satellite,
    much worse than tolerating a phantom, so legitimate-looking MACs
    must always pass."""

    def test_real_netgear_orbi_oui_passes(self):
        from homenet import _is_plausible_orbi_ap_mac

        # User's actual Orbi base + satellites (universal Netgear MACs)
        assert _is_plausible_orbi_ap_mac("28:94:01:3F:73:E1") is True
        assert _is_plausible_orbi_ap_mac("28:94:01:40:58:F6") is True
        assert _is_plausible_orbi_ap_mac("28:94:01:40:5A:63") is True
        # Other Netgear OUIs documented in their public IEEE assignments
        assert _is_plausible_orbi_ap_mac("A8:A1:59:00:00:01") is True
        assert _is_plausible_orbi_ap_mac("9C:3D:CF:11:22:33") is True

    def test_locally_admin_first_octet_rejected(self):
        """Any MAC with bit 0x02 set in the first octet is randomized
        (per IEEE 802 universal/local bit). Real APs use universal MACs."""
        from homenet import _is_plausible_orbi_ap_mac

        # 5A = 0101 1010 (bit 0x02 set)
        assert _is_plausible_orbi_ap_mac("5A:71:11:11:11:11") is False
        # BA = 1011 1010 (bit 0x02 set)
        assert _is_plausible_orbi_ap_mac("BA:5E:00:00:00:01") is False
        # 02 = 0000 0010 (just the locally-admin bit)
        assert _is_plausible_orbi_ap_mac("02:00:00:00:00:01") is False

    def test_repeated_last_three_octets_rejected(self):
        """xx:yy:zz:11:11:11 style placeholder pattern -- no real BSSID
        matches that. Catches sentinels like 5A:71:11:11:11:11 even when
        the locally-admin check doesn't (e.g. if a vendor ever shipped
        a universal MAC with this last-3-octets pattern, we'd still want
        to filter it)."""
        from homenet import _is_plausible_orbi_ap_mac

        # First octet 28 is universal, but last 3 are all 11 -- placeholder
        assert _is_plausible_orbi_ap_mac("28:94:01:11:11:11") is False
        # All-zero last 3
        assert _is_plausible_orbi_ap_mac("28:94:01:00:00:00") is False

    def test_all_zero_or_all_ff_sentinel_rejected(self):
        from homenet import _is_plausible_orbi_ap_mac

        assert _is_plausible_orbi_ap_mac("00:00:00:00:00:00") is False
        assert _is_plausible_orbi_ap_mac("FF:FF:FF:FF:FF:FF") is False
        assert _is_plausible_orbi_ap_mac("ff:ff:ff:ff:ff:ff") is False

    def test_empty_or_malformed_rejected(self):
        from homenet import _is_plausible_orbi_ap_mac

        assert _is_plausible_orbi_ap_mac("") is False
        assert _is_plausible_orbi_ap_mac("not-a-mac") is False
        # Wrong length
        assert _is_plausible_orbi_ap_mac("28:94:01:3F:73") is False
        # Non-hex octet
        assert _is_plausible_orbi_ap_mac("28:94:01:3F:73:ZZ") is False

    def test_universal_mac_with_varied_octets_passes(self):
        """Defensive: a vendor MAC whose last 3 octets vary slightly but
        are NOT all the same MUST pass -- this is the common case."""
        from homenet import _is_plausible_orbi_ap_mac

        assert _is_plausible_orbi_ap_mac("28:94:01:3F:73:E1") is True
        assert _is_plausible_orbi_ap_mac("28:94:01:3F:73:E2") is True
        # Even when last 2 octets match, last 3 are not all same -- pass
        assert _is_plausible_orbi_ap_mac("28:94:01:3F:E1:E1") is True


class TestUserTaggedMocaBridge:
    """End-to-end coverage for the manual MoCA-bridge tagging flow added
    when the user reported their 2nd MoCA bridge wasn't auto-detected."""

    def _inventory(self, *device_dicts):
        return {
            "devices": {d["mac"]: d for d in device_dicts},
            "last_scan": "2026-04-25T00:00:00",
        }

    def test_user_tagged_moca_bridge_lands_in_moca_bridges_bucket(self, mocker):
        """A device the user tagged via the edit modal as wired_via=
        moca_bridge must show up in the topology's moca_bridges list,
        not in via_moca/verizon_lan."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        inv = self._inventory(
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "192.168.1.105",
                "network": "wired",
                "vendor": "Generic Networks Inc.",
                "wired_via": "moca_bridge",
            },
        )
        t = build_topology(inv, switch_data={})
        assert "AA:BB:CC:DD:EE:01" in t["moca_bridges"]
        assert "AA:BB:CC:DD:EE:01" not in t["via_moca"]
        assert "AA:BB:CC:DD:EE:01" not in t["verizon_lan"]
        assert t["stats"]["moca_bridges"] >= 1

    def test_askey_vendor_auto_detected_as_moca_bridge(self):
        """OUI 88:DE:7C resolves to Askey Computer Corp -- the Taiwanese
        ODM that builds Verizon-branded transparent MoCA bridges. Added
        2026-04-25 after a user reported their Verizon FiOS Network
        Extender wasn't auto-detected."""
        from homenet import _is_moca_bridge

        assert _is_moca_bridge({"vendor": "ASKEY COMPUTER CORP"}) is True
        assert _is_moca_bridge({"vendor": "Askey Computer Corp"}) is True

    def test_add_manual_route_creates_inventory_entry(self, client, mocker):
        """Transparent MoCA bridges have no IP and never appear in ARP, so
        the normal scan flow can't surface them. The new
        /api/homenet/device/add-manual route lets the user inject an entry
        from MAC alone, so the diagram can render the device."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={"devices": {}, "last_scan": ""},
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        mocker.patch("homenet._mac_vendor", return_value="ASKEY COMPUTER CORP")

        resp = client.post(
            "/api/homenet/device/add-manual",
            json={"mac": "88:DE:7C:C2:57:36", "friendly_name": "Living Room MoCA"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        # Inventory was persisted
        saved = save_mock.call_args[0][0]
        added = saved["devices"]["88:DE:7C:C2:57:36"]
        assert added["mac"] == "88:DE:7C:C2:57:36"
        assert added["friendly_name"] == "Living Room MoCA"
        assert added["wired_via"] == "moca_bridge"  # default for manual-add
        assert added["source"] == "manual"
        assert added["vendor"] == "ASKEY COMPUTER CORP"

    def test_add_manual_route_rejects_invalid_mac(self, client, mocker):
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": ""})
        mocker.patch("homenet._save_homenet_inventory")
        for bad in ("", "not-a-mac", "GG:GG:GG:GG:GG:GG", "11:22:33", "11:22:33:44:55:66:77"):
            resp = client.post("/api/homenet/device/add-manual", json={"mac": bad})
            assert resp.status_code == 400, f"expected 400 for {bad!r}, got {resp.status_code}"

    def test_add_manual_route_409_on_duplicate_mac(self, client, mocker):
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {"88:DE:7C:C2:57:36": {"mac": "88:DE:7C:C2:57:36"}},
                "last_scan": "",
            },
        )
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/device/add-manual", json={"mac": "88:DE:7C:C2:57:36"})
        assert resp.status_code == 409

    def test_behind_moca_bridge_groups_devices_under_parent(self, client, mocker):
        """User feedback 2026-04-25: "i would expect to see what devices are
        connected to what moca." Build_topology now exposes a
        moca_children dict mapping each bridge MAC to the device MACs the
        user has marked as downstream of it. Children are excluded from
        via_moca/verizon_lan to avoid double-rendering."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        bridge_mac = "08:33:ED:7B:34:34"  # the user's TV Room MoCA
        child_mac = "B0:5D:D4:76:2A:C0"  # VMS4100ATV (sits behind it per user)
        inv = {
            "devices": {
                bridge_mac: {
                    "mac": bridge_mac,
                    "vendor": "ASKEY COMPUTER CORP",
                    "wired_via": "moca_bridge",
                    "network": "wired",
                },
                child_mac: {
                    "mac": child_mac,
                    "vendor": "Apple",  # not a bridge itself
                    "behind_moca_bridge": bridge_mac,
                    "network": "wired",
                    "wired_via": "moca",
                },
            },
            "last_scan": "2026-04-25",
        }
        t = build_topology(inv, switch_data={})
        # The bridge appears in moca_bridges
        assert bridge_mac in t["moca_bridges"]
        # The child appears under the bridge in moca_children
        assert child_mac in t["moca_children"][bridge_mac]
        # And NOT in via_moca / verizon_lan (avoids double-render)
        assert child_mac not in t["via_moca"]
        assert child_mac not in t["verizon_lan"]

    def test_behind_moca_bridge_dangling_pointer_drops_child(self, client, mocker):
        """If the user removes a bridge from inventory, children pointing to
        it shouldn't disappear -- they should fall back to via_moca /
        verizon_lan via the existing leftover bucketing."""
        from homenet import build_topology

        mocker.patch("homenet._save_homenet_inventory")
        # Child points to a bridge MAC that doesn't exist
        inv = {
            "devices": {
                "AA:BB:CC:00:00:01": {
                    "mac": "AA:BB:CC:00:00:01",
                    "behind_moca_bridge": "DE:AD:BE:EF:00:00",
                    "wired_via": "moca",
                    "network": "wired",
                    "vendor": "Apple",
                },
            },
            "last_scan": "",
        }
        t = build_topology(inv, switch_data={})
        # Child is NOT in moca_children (no bridge to nest under)
        assert "AA:BB:CC:00:00:01" not in (t["moca_children"].get("DE:AD:BE:EF:00:00") or [])
        # Falls back to via_moca because wired_via=moca
        assert "AA:BB:CC:00:00:01" in t["via_moca"]

    def test_device_update_route_accepts_behind_moca_bridge(self, client, mocker):
        """The route's whitelist must include behind_moca_bridge with a
        format check (or empty to clear)."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:BB:CC:00:00:01": {"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": ""},
                },
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        # Valid MAC -> persisted
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": "08:33:ED:7B:34:34"},
        )
        assert resp.status_code == 200
        saved = save_mock.call_args[0][0]
        assert saved["devices"]["AA:BB:CC:00:00:01"]["behind_moca_bridge"] == "08:33:ED:7B:34:34"

    def test_device_update_route_rejects_bad_behind_moca_bridge(self, client, mocker):
        """Junk values in behind_moca_bridge must NOT land in inventory."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:BB:CC:00:00:01": {"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": "08:33:ED:7B:34:34"}
                },
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": "DROP TABLE devices"},
        )
        assert resp.status_code == 200
        # The previous valid value persists -- garbage was rejected
        saved = save_mock.call_args[0][0]
        assert saved["devices"]["AA:BB:CC:00:00:01"]["behind_moca_bridge"] == "08:33:ED:7B:34:34"

    def test_behind_moca_bridge_clearing_with_empty_string(self, client, mocker):
        """Sending behind_moca_bridge='' should clear the link, not preserve
        the old value -- otherwise the user can't undo a wrong assignment."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:BB:CC:00:00:01": {"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": "08:33:ED:7B:34:34"}
                },
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:00:00:01", "behind_moca_bridge": ""},
        )
        assert resp.status_code == 200
        saved = save_mock.call_args[0][0]
        assert saved["devices"]["AA:BB:CC:00:00:01"]["behind_moca_bridge"] == ""

    def test_device_update_route_accepts_moca_bridge_value(self, client, mocker):
        """The whitelist must include 'moca_bridge'. Otherwise the user
        could pick it in the dropdown but the value would be silently
        dropped by the route handler."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {"AA:BB:CC:DD:EE:01": {"mac": "AA:BB:CC:DD:EE:01", "wired_via": ""}},
                "last_scan": "",
            },
        )
        save_mock = mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:DD:EE:01", "wired_via": "moca_bridge"},
        )
        assert resp.status_code == 200
        saved = save_mock.call_args[0][0]
        assert saved["devices"]["AA:BB:CC:DD:EE:01"]["wired_via"] == "moca_bridge"


class TestRebootRoute:
    """Backlog #16: POST /api/homenet/reboot/<device> with type-to-confirm.

    The route MUST refuse without a matching ``confirm`` field even when
    the device key is valid. Defense-in-depth so a stray POST (curl from
    history, malicious browser tab) can't take down the user's network.
    """

    def test_unknown_device_returns_400(self, client):
        resp = client.post("/api/homenet/reboot/nope", json={"confirm": "nope"})
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["ok"] is False
        assert "Unknown device" in body["error"]

    def test_missing_confirm_field_returns_400(self, client):
        """No body at all -> route MUST refuse."""
        resp = client.post("/api/homenet/reboot/orbi")
        assert resp.status_code == 400
        assert "confirm" in resp.get_json()["error"].lower()

    def test_wrong_confirm_value_returns_400(self, client):
        """Confirm field present but doesn't match device key -> refuse."""
        resp = client.post("/api/homenet/reboot/orbi", json={"confirm": "verizon"})
        assert resp.status_code == 400
        assert "confirm" in resp.get_json()["error"].lower()

    def test_confirm_match_is_case_insensitive(self, client, mocker):
        """User typing 'ORBI' should still work -- the comparison
        normalises both sides to lowercase."""
        mocker.patch("homenet._orbi_reboot_router", return_value={"ok": True, "mode": "reboot-fired"})
        resp = client.post("/api/homenet/reboot/orbi", json={"confirm": "ORBI"})
        assert resp.status_code == 200

    def test_orbi_dispatches_to_soap_helper(self, client, mocker):
        stub = mocker.patch(
            "homenet._orbi_reboot_router",
            return_value={"ok": True, "mode": "reboot-fired", "message": "Sent."},
        )
        resp = client.post("/api/homenet/reboot/orbi", json={"confirm": "orbi"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["mode"] == "reboot-fired"
        stub.assert_called_once()

    def test_verizon_returns_deep_link_url(self, client):
        """Verizon path returns the admin UI's reboot route as a URL --
        no actual reboot fired server-side."""
        resp = client.post("/api/homenet/reboot/verizon", json={"confirm": "verizon"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["mode"] == "deep-link"
        assert "192.168.1.1" in body["url"]
        assert "system/reboot" in body["url"]

    def test_tplink_returns_deep_link_url_when_ip_known(self, client, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("192.168.1.50", "publiccommunity"))
        resp = client.post("/api/homenet/reboot/tplink", json={"confirm": "tplink"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["mode"] == "deep-link"
        assert "192.168.1.50" in body["url"]

    def test_tplink_500_when_ip_undiscoverable(self, client, mocker):
        """Switch IP is 'auto' but ARP doesn't find it -> 500 with a
        useful error message, not a broken URL."""
        mocker.patch("homenet._get_homenet_cred", return_value=("auto", "public"))
        mocker.patch("homenet._resolve_ip_from_mac", return_value="")
        resp = client.post("/api/homenet/reboot/tplink", json={"confirm": "tplink"})
        assert resp.status_code == 500
        assert "switch IP" in resp.get_json()["error"]


class TestOrbiRebootHelper:
    """Direct tests for _orbi_reboot_router() -- network mocked."""

    def test_no_creds_returns_error(self, mocker):
        from homenet import _orbi_reboot_router

        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        result = _orbi_reboot_router()
        assert "error" in result
        assert "credentials" in result["error"].lower()

    def test_happy_path_http_200_returns_ok(self, mocker):
        """SOAP returns 200 -> ok with mode=reboot-fired."""
        from homenet import _orbi_reboot_router

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        mock_session.post.return_value = ok_resp
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_reboot_router()
        assert result["ok"] is True
        assert result["mode"] == "reboot-fired"

    def test_connection_error_during_reboot_treated_as_success(self, mocker):
        """The router killing the response mid-flight is the EXPECTED
        success indicator for reboot. ConnectionError on the Reboot
        SOAP call -> ok=True, not an error."""
        import requests as _req

        from homenet import _orbi_reboot_router

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        # First call (ConfigurationStarted) succeeds; second call (Reboot)
        # raises ConnectionError mid-response.
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        mock_session.post.side_effect = [ok_resp, _req.exceptions.ConnectionError("connection closed")]
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_reboot_router()
        assert result["ok"] is True
        assert result["mode"] == "reboot-fired"
        assert "connection closed mid-response" in result["message"]

    def test_chunked_encoding_error_also_success(self, mocker):
        """Same idea for ChunkedEncodingError -- another way the router
        can drop the response when it actually starts the reboot."""
        import requests as _req

        from homenet import _orbi_reboot_router

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        mock_session.post.side_effect = [ok_resp, _req.exceptions.ChunkedEncodingError("incomplete")]
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_reboot_router()
        assert result["ok"] is True

    def test_connect_timeout_returns_unreachable_error(self, mocker):
        """If the FIRST call (ConfigurationStarted) times out before
        connecting at all, that's a real failure -- the Wi-Fi probably
        isn't on the Orbi network."""
        import requests as _req

        from homenet import _orbi_reboot_router

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        # Both calls fail with ConnectTimeout (not a mid-reboot connection
        # close, an actual unreachable router)
        mock_session.post.side_effect = _req.exceptions.ConnectTimeout()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_reboot_router()
        assert "error" in result
        assert "unreachable" in result["error"].lower()


class TestVerizonAndTpLinkRebootHelpers:
    """The non-SOAP helpers just compute deep-link URLs -- no network."""

    def test_verizon_url_uses_known_admin_path(self):
        from homenet import _verizon_reboot_url

        url = _verizon_reboot_url()
        assert url.startswith("http://192.168.1.1/")
        # The hash route is documented in the SPA's Vue Router table
        assert "system/reboot" in url

    def test_tplink_url_uses_stored_ip(self, mocker):
        from homenet import _tplink_reboot_url

        mocker.patch("homenet._get_homenet_cred", return_value=("192.168.1.42", "secret"))
        url = _tplink_reboot_url()
        assert url == "http://192.168.1.42/"

    def test_tplink_url_auto_resolves_when_user_field_is_auto(self, mocker):
        from homenet import _tplink_reboot_url

        mocker.patch("homenet._get_homenet_cred", return_value=("auto", "secret"))
        mocker.patch("homenet._resolve_ip_from_mac", return_value="192.168.1.99")
        url = _tplink_reboot_url()
        assert "192.168.1.99" in url

    def test_tplink_url_empty_when_unresolvable(self, mocker):
        from homenet import _tplink_reboot_url

        mocker.patch("homenet._get_homenet_cred", return_value=("auto", "secret"))
        mocker.patch("homenet._resolve_ip_from_mac", return_value="")
        url = _tplink_reboot_url()
        assert url == ""


class TestRouterConfigBackup:
    """New feature 2026-05-09: pull + persist router config snapshots so
    a factory-reset / silent config drift / replacement is recoverable.

    Two-track approach: real SOAP-based download for Orbi, deep-link
    Path A for Verizon (write-surface probing was sandbox-blocked).
    """

    @pytest.fixture(autouse=True)
    def _isolate_backups_dir(self, tmp_path, mocker):
        """Each test gets its own backups directory under pytest's
        tmp_path so file writes don't pollute the real backups/ dir."""
        backups_dir = tmp_path / "backups"
        mocker.patch("homenet.BACKUPS_DIR", str(backups_dir))
        return str(backups_dir)

    def test_ensure_backup_dir_creates_per_vendor_subdir(self, _isolate_backups_dir):
        from homenet import _ensure_backup_dir

        path = _ensure_backup_dir("orbi")
        assert path.endswith("orbi")
        assert path.startswith(_isolate_backups_dir)
        path2 = _ensure_backup_dir("orbi")
        assert path == path2

    def test_ensure_backup_dir_rejects_unknown_vendor(self):
        """Defense against path-traversal via crafted vendor strings."""
        from homenet import _ensure_backup_dir

        with pytest.raises(ValueError, match="Unknown backup vendor"):
            _ensure_backup_dir("../etc")
        with pytest.raises(ValueError):
            _ensure_backup_dir("tplink")  # not in whitelist

    def test_prune_old_backups_removes_oldest_first(self, tmp_path):
        from homenet import _prune_old_backups

        vdir = tmp_path / "orbi"
        vdir.mkdir()
        for i in range(5):
            f = vdir / f"orbi_{i}.cfg"
            f.write_bytes(b"x" * 100)
            os.utime(str(f), (1000 + i, 1000 + i))
        removed = _prune_old_backups(str(vdir), keep=3)
        assert removed == 2
        remaining = sorted(e.name for e in os.scandir(str(vdir)))
        assert remaining == ["orbi_2.cfg", "orbi_3.cfg", "orbi_4.cfg"]

    def test_prune_no_op_when_under_cap(self, tmp_path):
        from homenet import _prune_old_backups

        vdir = tmp_path / "orbi"
        vdir.mkdir()
        for i in range(3):
            (vdir / f"orbi_{i}.cfg").write_bytes(b"x")
        assert _prune_old_backups(str(vdir), keep=10) == 0
        assert len(list(os.scandir(str(vdir)))) == 3

    def test_prune_returns_zero_when_dir_missing(self, tmp_path):
        from homenet import _prune_old_backups

        assert _prune_old_backups(str(tmp_path / "ghost")) == 0

    def test_list_backups_returns_empty_when_no_dirs(self):
        from homenet import list_router_backups

        result = list_router_backups()
        assert result["ok"] is True
        assert result["backups"]["orbi"] == []
        assert result["backups"]["verizon"] == []

    def test_list_backups_orders_newest_first(self, _isolate_backups_dir):
        from homenet import _ensure_backup_dir, list_router_backups

        vdir = _ensure_backup_dir("orbi")
        for i, ts in enumerate([1000, 2000, 3000]):
            p = os.path.join(vdir, f"orbi_{i}.cfg")
            with open(p, "wb") as f:
                f.write(b"x" * (100 + i))
            os.utime(p, (ts, ts))
        result = list_router_backups("orbi")
        files = [b["filename"] for b in result["backups"]["orbi"]]
        assert files == ["orbi_2.cfg", "orbi_1.cfg", "orbi_0.cfg"]

    def test_list_backups_filter_by_vendor(self, _isolate_backups_dir):
        from homenet import list_router_backups

        result = list_router_backups("orbi")
        assert "orbi" in result["backups"]
        assert "verizon" not in result["backups"]

    def test_list_response_includes_backup_dir_for_ui_display(self, _isolate_backups_dir):
        """The UI surfaces the resolved BACKUPS_DIR so the user always
        knows where files land (especially important now that the
        default path is OneDrive-synced and overridable via env var).
        """
        from homenet import list_router_backups

        result = list_router_backups()
        assert "backup_dir" in result
        assert result["backup_dir"] == _isolate_backups_dir


class TestBackupsDirResolution:
    """The new feature 2026-05-10: BACKUPS_DIR is no longer the repo
    dir's ``backups/`` subfolder; defaults to ``~/OneDrive/WinDesktopMgr/
    backup`` so backups auto-sync to cloud + survive a machine wipe.
    Overridable via WINDESKTOPMGR_BACKUP_DIR env var.

    These tests reload homenet under different env states. Don't
    monkey-patch the module-level value here -- the point IS to
    exercise the import-time resolution logic.
    """

    def test_default_path_uses_user_onedrive_folder(self, monkeypatch):
        """Default (no env var) should resolve to ~/OneDrive/WinDesktopMgr/backup."""
        import importlib
        import os as _os

        monkeypatch.delenv("WINDESKTOPMGR_BACKUP_DIR", raising=False)
        import homenet

        importlib.reload(homenet)
        try:
            expected = _os.path.join(_os.path.expanduser("~"), "OneDrive", "WinDesktopMgr", "backup")
            assert expected == homenet.BACKUPS_DIR, (
                f"Default BACKUPS_DIR should resolve under user's OneDrive folder. Got: {homenet.BACKUPS_DIR}"
            )
        finally:
            # Restore via reimport so subsequent tests in this session
            # see the real (or env-overridden) value rather than whatever
            # this test left around.
            importlib.reload(homenet)

    def test_env_var_override_wins_over_default(self, monkeypatch, tmp_path):
        """WINDESKTOPMGR_BACKUP_DIR set -> that path wins."""
        import importlib

        custom = str(tmp_path / "custom-backup-location")
        monkeypatch.setenv("WINDESKTOPMGR_BACKUP_DIR", custom)
        import homenet

        importlib.reload(homenet)
        try:
            assert custom == homenet.BACKUPS_DIR
        finally:
            monkeypatch.delenv("WINDESKTOPMGR_BACKUP_DIR", raising=False)
            importlib.reload(homenet)

    def test_ensure_backup_dir_creates_intermediate_parents(self, monkeypatch, tmp_path):
        """The OneDrive default path may have multiple non-existent
        parent directories on first run (e.g. WinDesktopMgr/ then
        backup/). _ensure_backup_dir + the underlying os.makedirs MUST
        create the whole chain, not just the leaf."""
        import importlib

        deep = str(tmp_path / "level1" / "level2" / "level3" / "backup")
        monkeypatch.setenv("WINDESKTOPMGR_BACKUP_DIR", deep)
        import homenet

        importlib.reload(homenet)
        try:
            from homenet import _ensure_backup_dir

            path = _ensure_backup_dir("orbi")
            assert os.path.isdir(path)
            assert path.endswith(os.path.join("backup", "orbi"))
        finally:
            monkeypatch.delenv("WINDESKTOPMGR_BACKUP_DIR", raising=False)
            importlib.reload(homenet)


class TestBackupHealthRoute:
    """GET /api/homenet/backup/health returns the backup-health snapshot.

    Replaces the old /api/homenet/backup/scheduler route after the
    scheduler was reverted on 2026-05-11 (Orbi RBRE960 firmware
    rejects the documented SOAP backup endpoint, Verizon needs
    browser interaction -- daemon thread fired daily failures with
    nothing to show for it)."""

    def test_route_returns_health(self, client):
        resp = client.get("/api/homenet/backup/health")
        assert resp.status_code == 200
        body = resp.get_json()
        for hk in (
            "verizon_stale",
            "orbi_stale",
            "verizon_stale_threshold_days",
            "orbi_stale_threshold_days",
            "verizon_age_days",
            "orbi_age_days",
        ):
            assert hk in body

    def test_old_scheduler_route_is_gone(self, client):
        """Regression guard: the scheduler route was REMOVED on revert.
        If something accidentally re-adds it, this test fires.

        Note: a GET on /api/homenet/backup/scheduler returns 405 (not 404)
        because the path collides with /api/homenet/backup/<vendor> (POST-
        only) -- Flask resolves the URL to the vendor route and rejects
        the method. What we assert is that no GET handler returns the old
        scheduler payload (enabled / interval_h / last_run_at)."""
        resp = client.get("/api/homenet/backup/scheduler")
        assert resp.status_code != 200, "Scheduler route should no longer be served"
        # And there's no scheduler payload structure to be found anywhere.
        body = resp.get_data(as_text=True)
        for forbidden in ("interval_h", "last_run_at", "next_due_at", "thread_alive"):
            assert forbidden not in body, (
                f"Response leaked scheduler key {forbidden!r} -- the scheduler "
                "was reverted on 2026-05-11 and must not come back."
            )


class TestBackupHealth:
    """get_backup_health() summarises the most-recent backup per vendor
    + flags staleness so the dashboard pipeline can surface concerns."""

    @pytest.fixture(autouse=True)
    def _isolate_backups_dir(self, tmp_path, mocker):
        mocker.patch("homenet.BACKUPS_DIR", str(tmp_path / "backups"))

    def test_no_backups_returns_stale_for_both_vendors(self):
        """No backups -> stale=True for both. A never-backed-up router
        is just as stale as a 31-day-old one from the dashboard's POV."""
        from homenet import get_backup_health

        h = get_backup_health()
        assert h["verizon_stale"] is True
        assert h["orbi_stale"] is True
        assert h["verizon_age_days"] is None
        assert h["orbi_age_days"] is None

    def test_recent_backup_marks_not_stale(self, _isolate_backups_dir):
        """Backup file with mtime <1 day old -> not stale."""
        from homenet import _ensure_backup_dir, get_backup_health

        vdir = _ensure_backup_dir("verizon")
        f = os.path.join(vdir, "verizon_recent.cfg")
        with open(f, "wb") as fh:
            fh.write(b"x" * 1024)
        h = get_backup_health()
        assert h["verizon_stale"] is False
        assert h["verizon_age_days"] is not None
        assert h["verizon_age_days"] < 1.0

    def test_old_verizon_backup_marks_stale_at_30d_threshold(self, _isolate_backups_dir):
        from homenet import _ensure_backup_dir, get_backup_health

        vdir = _ensure_backup_dir("verizon")
        f = os.path.join(vdir, "verizon_old.cfg")
        with open(f, "wb") as fh:
            fh.write(b"x" * 1024)
        old_ts = (datetime.now() - timedelta(days=31)).timestamp()
        os.utime(f, (old_ts, old_ts))
        h = get_backup_health()
        assert h["verizon_stale"] is True
        assert h["verizon_age_days"] > 30


class TestSchedulerSymbolsAreGone:
    """Regression guard. The scheduler was reverted on 2026-05-11 after
    user feedback ("if both backups don't work why even do it?"). These
    assertions break the build if someone re-adds the scheduler symbols
    without coming back to first principles."""

    def test_scheduler_module_symbols_absent(self):
        import homenet

        for sym in (
            "start_backup_scheduler",
            "stop_backup_scheduler",
            "get_backup_scheduler_state",
            "_backup_scheduler_loop",
            "_backup_scheduler_state",
            "_backup_scheduler_thread",
            "_backup_scheduler_lock",
            "_BACKUP_SCHEDULER_DEFAULT_INTERVAL_H",
        ):
            assert not hasattr(homenet, sym), (
                f"homenet.{sym} should have been removed during the 2026-05-11 "
                "scheduler revert. Both vendors require manual backups; the "
                "scheduler was firing daily failures with nothing to show for it."
            )


class TestOrbiBackupHelper:
    """_orbi_backup_config tested with the network mocked end-to-end."""

    @pytest.fixture(autouse=True)
    def _isolate_backups_dir(self, tmp_path, mocker):
        mocker.patch("homenet.BACKUPS_DIR", str(tmp_path / "backups"))

    def test_no_creds_returns_error_with_fallback_url(self, mocker):
        from homenet import _orbi_backup_config

        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        result = _orbi_backup_config()
        assert "error" in result
        assert "credentials" in result["error"].lower()
        assert "fallback_url" in result
        assert "10.0.0.1" in result["fallback_url"]

    def test_happy_path_saves_file_and_returns_metadata(self, mocker):
        from homenet import _orbi_backup_config

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        mock_session.post.return_value = ok_resp
        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.content = b"NETGEAR_CFG_BLOB" * 50  # 800 bytes
        mock_session.get.return_value = get_resp
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_backup_config()
        assert result["ok"] is True
        assert result["vendor"] == "orbi"
        assert result["bytes"] == 800
        assert result["filename"].startswith("orbi_") and result["filename"].endswith(".cfg")
        assert os.path.exists(result["path"])

    def test_endpoint_404_returns_fallback_not_crash(self, mocker):
        from homenet import _orbi_backup_config

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.return_value = MagicMock(status_code=200)
        not_found = MagicMock()
        not_found.status_code = 404
        not_found.content = b""
        mock_session.get.return_value = not_found
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_backup_config()
        assert "error" in result
        assert "404" in result["error"]
        assert "fallback_url" in result

    def test_tiny_response_treated_as_error_page_not_real_backup(self, mocker):
        """A real config blob is at least a few KB. 200 OK with <200
        bytes is almost certainly an HTML error page, not a backup."""
        from homenet import _orbi_backup_config

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.return_value = MagicMock(status_code=200)
        suspicious = MagicMock()
        suspicious.status_code = 200
        suspicious.content = b"<html>error</html>"
        mock_session.get.return_value = suspicious
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_backup_config()
        assert "error" in result
        assert "bytes" in result["error"].lower()
        assert "fallback_url" in result

    def test_connect_timeout_returns_unreachable(self, mocker):
        import requests as _req

        from homenet import _orbi_backup_config

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.return_value = MagicMock(status_code=200)
        mock_session.get.side_effect = _req.exceptions.ConnectTimeout()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        result = _orbi_backup_config()
        assert "error" in result
        assert "unreachable" in result["error"].lower()
        assert "fallback_url" in result


class TestVerizonBackupHelper:
    def test_url_uses_admin_save_restore_route(self):
        from homenet import _verizon_backup_url

        url = _verizon_backup_url()
        assert url.startswith("http://192.168.1.1")
        assert "system/saverestore" in url


class TestBackupRoutes:
    """API surface for backup. Type-to-confirm guard NOT used here
    because backup is a read-style action (no destructive side effects
    on the router itself); the only file written is on the local disk
    in a sandboxed directory."""

    @pytest.fixture(autouse=True)
    def _isolate_backups_dir(self, tmp_path, mocker):
        mocker.patch("homenet.BACKUPS_DIR", str(tmp_path / "backups"))

    def test_unknown_vendor_returns_400(self, client):
        resp = client.post("/api/homenet/backup/cisco")
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["ok"] is False
        assert "Unknown vendor" in body["error"]

    def test_orbi_dispatches_to_helper_on_success(self, client, mocker):
        mocker.patch(
            "homenet._orbi_backup_config",
            return_value={
                "ok": True,
                "path": "/tmp/orbi_x.cfg",
                "filename": "orbi_x.cfg",
                "bytes": 1024,
                "vendor": "orbi",
            },
        )
        resp = client.post("/api/homenet/backup/orbi")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["mode"] == "downloaded"
        assert body["filename"] == "orbi_x.cfg"

    def test_orbi_failure_returns_needs_fallback_with_url(self, client, mocker):
        """When the SOAP backup fails, the route surfaces ok=False BUT
        with mode='needs-fallback' + fallback_url so the UI can offer
        the deep-link as recovery instead of just dead-ending."""
        mocker.patch(
            "homenet._orbi_backup_config",
            return_value={"error": "404 from CGI", "fallback_url": "https://10.0.0.1/"},
        )
        resp = client.post("/api/homenet/backup/orbi")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is False
        assert body["mode"] == "needs-fallback"
        assert body["fallback_url"] == "https://10.0.0.1/"

    def test_verizon_returns_deep_link_url(self, client):
        resp = client.post("/api/homenet/backup/verizon")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["mode"] == "deep-link"
        assert "192.168.1.1" in body["url"]
        assert "saverestore" in body["url"]

    def test_list_route_returns_both_vendors(self, client):
        resp = client.get("/api/homenet/backup/list")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert "orbi" in body["backups"]
        assert "verizon" in body["backups"]


class TestTopologyRoute:
    def test_route_returns_topology_shape(self, client, mocker):
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:AA:AA:AA:AA:01": {"mac": "AA:AA:AA:AA:AA:01", "ip": "192.168.1.10"},
                },
                "last_scan": "2026-04-25T00:00:00",
            },
        )
        mocker.patch("homenet._tplink_get_data", return_value={"mac_table": []})
        resp = client.get("/api/homenet/topology")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        for k in ("router", "switches", "aps", "devices", "unmapped", "stats"):
            assert k in data, f"topology payload missing {k}"

    def test_route_handles_inventory_load_failure_gracefully(self, client, mocker):
        """Even if switch query throws, the topology endpoint must still
        return a usable structure -- not a 500."""
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={"devices": {}, "last_scan": ""},
        )
        mocker.patch("homenet._tplink_get_data", side_effect=RuntimeError("boom"))
        resp = client.get("/api/homenet/topology")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True


class TestTopologyDiagramPerBridgeColumns:
    """Backlog #42 follow-up (2026-05-08): user feedback "shows one moca
    bridge" -- the topology diagram was rendering all MoCA bridges in a
    single collapsed column instead of one column per bridge (asymmetric
    with Orbi satellites which each get their own column).

    The fix lives in templates/index.html (hnTopoBuildSvg). These tests
    are source-level contract guards: they don't drive the JS, they
    assert the source contains the right loop structure so a future
    edit can't silently regress to the single-column layout. Same
    pattern as the slugifyConcern JS-Python parity guard from #40.
    """

    @staticmethod
    def _index_html() -> str:
        from pathlib import Path

        # Frontend source = index.html + extracted static/js/app.js (#55 PR 2).
        root = Path(__file__).parent.parent
        html = (root / "templates" / "index.html").read_text(encoding="utf-8")
        js = (root / "static" / "js" / "app.js").read_text(encoding="utf-8")
        return html + "\n" + js

    def test_topology_renderer_loops_over_bridges_for_columns(self):
        """Each bridge MUST get its own column entry. Look for the
        per-bridge column-push, not the old single-column-with-all-bridges
        push. Anchored by the loop variable `bridgeColumns` and the
        per-bridge column id pattern."""
        html = self._index_html()
        # The new code creates a bridgeColumns array, sorts it, and
        # iterates `for (const bc of bridgeColumns)` to push one column
        # per bridge. If someone reverts to the single-collapsed-column
        # layout, this string disappears and the test fails.
        assert "bridgeColumns" in html, (
            "templates/index.html: per-bridge column rendering missing -- "
            "the topology diagram regressed to a single 'MoCA Bridges' "
            "column. Restore the bridgeColumns loop in hnTopoBuildSvg."
        )
        assert "moca-bridge-${" in html or "`moca-bridge-${" in html, (
            "Per-bridge column id pattern (moca-bridge-<MAC>) is missing -- "
            "the column ids are how the SVG distinguishes bridge columns."
        )

    def test_topology_renderer_does_not_use_old_single_column_kind(self):
        """The old layout used `id: 'moca-bridges'` (plural) for the
        single column. Per-bridge layout uses `moca-bridge-<MAC>` ids
        (singular). If the plural form reappears, someone has rolled
        back to the single-column collapse."""
        html = self._index_html()
        # The plural literal lived inside the old `id: "moca-bridges"`
        # string. Per-bridge layout never uses it.
        assert '"moca-bridges"' not in html, (
            "Found old single-column id 'moca-bridges' -- the per-bridge "
            "fix has been rolled back. Each bridge should have its own "
            "column with id moca-bridge-<MAC>."
        )

    def test_topology_renderer_falls_back_to_vendor_plus_macsuffix_naming(self):
        """When a bridge has no friendly_name, the column title falls back
        to '<vendor> <last 4 of MAC>'. Source must contain the slice(-4)
        pattern that produces that suffix."""
        html = self._index_html()
        assert "slice(-4)" in html, (
            "MAC-suffix fallback (slice(-4) on the unhyphenated MAC) is "
            "missing -- bridges without friendly_name will render as "
            "the bare MAC instead of 'Vendor XXXX'."
        )
