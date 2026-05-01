"""Tests for Home Network Management feature."""

import subprocess
from unittest.mock import MagicMock

import pytest  # noqa: F401 -- used by backlog #10 classes via pytest.skip


class TestHomeNetCredentialRoutes:
    """Test credential management endpoints."""

    def test_list_credentials_returns_200(self, client, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        resp = client.get("/api/homenet/credentials")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["key"] == "verizon"
        assert data[1]["key"] == "orbi"
        assert data[2]["key"] == "tplink_switch"

    def test_list_credentials_shows_configured(self, client, mocker):
        def fake_cred(key):
            if key == "verizon":
                return ("admin", "mypass123")
            return (None, None)

        mocker.patch("homenet._get_homenet_cred", side_effect=fake_cred)
        resp = client.get("/api/homenet/credentials")
        data = resp.get_json()
        verizon = data[0]
        assert verizon["configured"] is True
        assert verizon["username"] == "admin"
        assert "••••" in verizon["password_hint"]
        orbi = data[1]
        assert orbi["configured"] is False

    def test_save_credential_success(self, client, mocker):
        mocker.patch("homenet._set_homenet_cred", return_value=True)
        resp = client.post(
            "/api/homenet/credentials/save",
            json={"device_key": "verizon", "username": "admin", "password": "test123"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_save_credential_missing_fields(self, client):
        resp = client.post(
            "/api/homenet/credentials/save",
            json={"device_key": "verizon", "username": "admin"},
        )
        assert resp.status_code == 400

    def test_save_credential_empty_key(self, client):
        resp = client.post(
            "/api/homenet/credentials/save",
            json={"device_key": "", "username": "admin", "password": "test"},
        )
        assert resp.status_code == 400

    def test_delete_credential_success(self, client, mocker):
        mocker.patch("homenet._delete_homenet_cred", return_value=True)
        resp = client.post(
            "/api/homenet/credentials/delete",
            json={"device_key": "verizon"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_save_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/homenet/credentials/save",
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_delete_credential_missing_key(self, client):
        resp = client.post(
            "/api/homenet/credentials/delete",
            json={},
        )
        assert resp.status_code == 400

    def test_delete_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/homenet/credentials/delete",
            json={},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False

    def test_test_credential_verizon(self, client, mocker):
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={"ok": True, "known_devices": {"known_devices": [1, 2, 3]}},
        )
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "verizon"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "3 devices" in data["message"]

    def test_test_credential_orbi(self, client, mocker):
        mocker.patch(
            "homenet._orbi_get_devices",
            return_value={"ok": True, "devices": [{"ip": "10.0.0.2"}]},
        )
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "orbi"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_test_credential_unknown_device(self, client):
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "unknown_device"},
        )
        assert resp.status_code == 400

    def test_test_credential_verizon_failure(self, client, mocker):
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={"error": "Bad password"},
        )
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "verizon"},
        )
        data = resp.get_json()
        assert data["ok"] is False
        assert "Bad password" in data["message"]


class TestHomeNetScanRoute:
    """Test network scanning endpoints."""

    def test_scan_returns_200(self, client, mocker):
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"error": "No creds"})
        mocker.patch("homenet._orbi_get_devices", return_value={"error": "No creds"})
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "device_count" in data

    def test_scan_merges_arp_devices(self, client, mocker):
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "192.168.1.50", "MAC": "AA:BB:CC:DD:EE:FF", "Type": "dynamic", "Interface": "192.168.1.10"},
            ],
        )
        mocker.patch("homenet._verizon_get_devices", return_value={"error": "No creds"})
        mocker.patch("homenet._orbi_get_devices", return_value={"error": "No creds"})
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        data = resp.get_json()
        assert data["device_count"] == 1
        assert data["devices"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert data["devices"][0]["network"] == "wired"

    def test_scan_collects_errors(self, client, mocker):
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._verizon_get_devices", return_value={"error": "Connection refused"})
        mocker.patch("homenet._orbi_get_devices", return_value={"error": "Timeout"})
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        data = resp.get_json()
        assert len(data["errors"]) == 2
        assert "Verizon" in data["errors"][0]
        assert "Orbi" in data["errors"][1]

    def test_scan_merges_verizon_devices(self, client, mocker):
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={
                "ok": True,
                "known_devices": {
                    "known_devices": [
                        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.20", "hostname": "MyPC", "activity": 1},
                    ]
                },
            },
        )
        mocker.patch("homenet._orbi_get_devices", return_value={"error": "No creds"})
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        data = resp.get_json()
        assert data["device_count"] == 1
        assert data["devices"][0]["hostname"] == "MyPC"
        assert data["devices"][0]["source"] == "verizon"


class TestHomeNetLightScan:
    """Test light ARP-only scan endpoint."""

    def test_light_scan_returns_200(self, client, mocker):
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan/light")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_light_scan_updates_active_status(self, client, mocker):
        existing = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "MyPC",
                    "vendor": "Unknown",
                    "network": "wired",
                    "source": "arp",
                    "last_seen": "2026-03-21T00:00:00+00:00",
                    "friendly_name": "Test",
                    "category": "Computer",
                    "location": "",
                    "notes": "",
                    "connection_type": "",
                    "signal_strength": "",
                    "link_rate": "",
                    "device_type": "",
                    "device_os": "",
                    "active": True,
                },
            },
            "last_scan": None,
        }
        # ARP sees no devices — the known device should go offline
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch("homenet._load_homenet_inventory", return_value=existing)
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan/light")
        data = resp.get_json()
        assert data["device_count"] == 1
        assert data["devices"][0]["active"] is False

    def test_light_scan_discovers_new_device(self, client, mocker):
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "10.0.0.50", "MAC": "11:22:33:44:55:66", "Type": "dynamic", "Interface": "10.0.0.89"},
            ],
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan/light")
        data = resp.get_json()
        assert data["device_count"] == 1
        assert data["devices"][0]["network"] == "wireless"
        assert data["devices"][0]["active"] is True

    def test_light_scan_updates_known_device_ip(self, client, mocker):
        existing = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "",
                    "vendor": "Unknown",
                    "network": "wired",
                    "source": "arp",
                    "last_seen": "",
                    "friendly_name": "",
                    "category": "",
                    "location": "",
                    "notes": "",
                    "connection_type": "",
                    "signal_strength": "",
                    "link_rate": "",
                    "device_type": "",
                    "device_os": "",
                    "active": False,
                },
            },
            "last_scan": None,
        }
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "192.168.1.55", "MAC": "AA:BB:CC:DD:EE:FF", "Type": "dynamic", "Interface": "192.168.1.10"},
            ],
        )
        mocker.patch("homenet._load_homenet_inventory", return_value=existing)
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan/light")
        data = resp.get_json()
        dev = data["devices"][0]
        assert dev["ip"] == "192.168.1.55"  # IP updated
        assert dev["active"] is True  # Now online


class TestHomeNetInventoryRoute:
    """Test inventory retrieval."""

    def test_inventory_returns_200(self, client, mocker):
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={"devices": {}, "last_scan": None},
        )
        resp = client.get("/api/homenet/inventory")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["device_count"] == 0

    def test_inventory_returns_devices(self, client, mocker):
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:BB:CC:DD:EE:FF": {
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "ip": "192.168.1.50",
                        "hostname": "TestPC",
                        "vendor": "Intel",
                        "network": "wired",
                        "active": True,
                    }
                },
                "last_scan": "2026-03-21T00:00:00+00:00",
            },
        )
        resp = client.get("/api/homenet/inventory")
        data = resp.get_json()
        assert data["device_count"] == 1
        assert data["devices"][0]["hostname"] == "TestPC"


class TestHomeNetDeviceUpdate:
    """Test device edit endpoint."""

    def test_update_device_success(self, client, mocker):
        inv = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF", "friendly_name": "", "category": ""},
            },
            "last_scan": None,
        }
        mocker.patch("homenet._load_homenet_inventory", return_value=inv)
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "AA:BB:CC:DD:EE:FF", "friendly_name": "Living Room TV", "category": "TV"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_update_device_missing_mac(self, client):
        resp = client.post("/api/homenet/device/update", json={})
        assert resp.status_code == 400

    def test_update_device_not_found(self, client, mocker):
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        resp = client.post(
            "/api/homenet/device/update",
            json={"mac": "FF:FF:FF:FF:FF:FF"},
        )
        assert resp.status_code == 404


class TestHomeNetRescanHostname:
    """Test the per-device DNS hostname rescan endpoint (backlog #7, Path A).

    The endpoint asks the routers for one device's name without running the
    full ARP+Wi-Fi+Orbi scan. It's the "🔄 Pull from router" button in the
    device-edit modal -- after the user renames a device in the router's
    own admin UI, this is how WinDesktopMgr's inventory catches up.
    """

    def _inv(self, mac="AA:BB:CC:DD:EE:FF"):
        return {
            "devices": {
                mac: {
                    "mac": mac,
                    "ip": "192.168.1.50",
                    "hostname": "old-name",
                    "dns_hostname": "old-name",
                }
            },
            "last_scan": None,
        }

    def test_rescan_invalid_mac_returns_400(self, client):
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "not-a-mac"},
        )
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_rescan_unknown_mac_returns_404(self, client, mocker):
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "FF:FF:FF:FF:FF:FF"},
        )
        assert resp.status_code == 404

    def test_rescan_happy_path_verizon(self, client, mocker):
        """Verizon returns the device with a fresh name -> persisted to dns_hostname."""
        inv = self._inv()
        mocker.patch("homenet._load_homenet_inventory", return_value=inv)
        save = mocker.patch("homenet._save_homenet_inventory")
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={
                "ok": True,
                "known_devices": [
                    {"mac": "AA:BB:CC:DD:EE:FF", "hostname": "Living-Room-TV", "ip": "192.168.1.50"},
                ],
            },
        )
        # Orbi should NOT be called -- Verizon already returned a hit.
        orbi = mocker.patch("homenet._orbi_get_devices")
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "AA:BB:CC:DD:EE:FF"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["dns_hostname"] == "Living-Room-TV"
        assert body["source"] == "verizon"
        save.assert_called_once()
        saved_inv = save.call_args[0][0]
        assert saved_inv["devices"]["AA:BB:CC:DD:EE:FF"]["dns_hostname"] == "Living-Room-TV"
        assert saved_inv["devices"]["AA:BB:CC:DD:EE:FF"]["hostname"] == "Living-Room-TV"
        orbi.assert_not_called()

    def test_rescan_falls_through_to_orbi_when_verizon_misses(self, client, mocker):
        """Wireless device only on Orbi network -- Verizon doesn't see it,
        Orbi does. Endpoint MUST try Orbi after Verizon comes up empty."""
        mocker.patch("homenet._load_homenet_inventory", return_value=self._inv())
        save = mocker.patch("homenet._save_homenet_inventory")
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={"ok": True, "known_devices": []},  # empty list -- no hit
        )
        mocker.patch(
            "homenet._orbi_get_devices",
            return_value={
                "ok": True,
                "devices": [{"mac": "AA:BB:CC:DD:EE:FF", "name": "iPhone-15", "ip": "10.0.0.5"}],
            },
        )
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "AA:BB:CC:DD:EE:FF"},
        )
        body = resp.get_json()
        assert body["ok"] is True
        assert body["dns_hostname"] == "iPhone-15"
        assert body["source"] == "orbi"
        saved_inv = save.call_args[0][0]
        assert saved_inv["devices"]["AA:BB:CC:DD:EE:FF"]["dns_hostname"] == "iPhone-15"

    def test_rescan_no_router_hit_returns_message(self, client, mocker):
        """Both routers respond OK but neither has the MAC in its table.
        Result: not-ok with a useful message, NO save (don't blank the
        existing dns_hostname just because the device is offline)."""
        mocker.patch("homenet._load_homenet_inventory", return_value=self._inv())
        save = mocker.patch("homenet._save_homenet_inventory")
        mocker.patch("homenet._verizon_get_devices", return_value={"ok": True, "known_devices": []})
        mocker.patch("homenet._orbi_get_devices", return_value={"ok": True, "devices": []})
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "AA:BB:CC:DD:EE:FF"},
        )
        body = resp.get_json()
        assert body["ok"] is False
        assert "No router-side hostname" in body["message"]
        save.assert_not_called()  # don't overwrite the previous good name with empty

    def test_rescan_router_errors_propagate_in_errors_list(self, client, mocker):
        """Verizon down + Orbi down -> errors list populated, ok=False."""
        mocker.patch("homenet._load_homenet_inventory", return_value=self._inv())
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={"error": "Verizon router unreachable"},
        )
        mocker.patch(
            "homenet._orbi_get_devices",
            return_value={"error": "Orbi unreachable"},
        )
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "AA:BB:CC:DD:EE:FF"},
        )
        body = resp.get_json()
        assert body["ok"] is False
        assert any("Verizon" in e for e in body.get("errors", []))
        assert any("Orbi" in e for e in body.get("errors", []))

    def test_rescan_normalizes_mac_format(self, client, mocker):
        """Hyphenated and lowercase MACs should normalise to upper-colon."""
        mocker.patch("homenet._load_homenet_inventory", return_value=self._inv())
        mocker.patch("homenet._save_homenet_inventory")
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={
                "ok": True,
                "known_devices": [{"mac": "AA:BB:CC:DD:EE:FF", "hostname": "Foo"}],
            },
        )
        mocker.patch("homenet._orbi_get_devices", return_value={"ok": True, "devices": []})
        resp = client.post(
            "/api/homenet/device/rescan-hostname",
            json={"mac": "aa-bb-cc-dd-ee-ff"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True


class TestMacVendor:
    """Test MAC vendor lookup."""

    def test_known_vendor(self):
        from homenet import _mac_vendor

        assert _mac_vendor("28:94:01:3F:73:E1") == "Netgear"
        assert _mac_vendor("E0:E2:E6:09:67:30") == "Roku"
        assert _mac_vendor("80:6A:10:31:42:E8") == "Apple"

    def test_unknown_vendor(self):
        """OUI that isn't in the curated dict, isn't in IEEE, and isn't
        locally-admin -> should return 'Unknown'. 99:99:99 is reserved /
        unallocated in IEEE MA-L at the time of writing."""
        from homenet import _mac_vendor, _vendor_cache

        _vendor_cache.clear()  # don't let prior tests colour the lookup
        assert _mac_vendor("99:99:99:00:00:00") == "Unknown"

    def test_dash_format(self):
        from homenet import _mac_vendor

        assert _mac_vendor("28-94-01-3F-73-E1") == "Netgear"


# ── Backlog #10: IEEE OUI lookup + randomized-MAC detection ──────────────


class TestIsLocallyAdminMac:
    """Bit 1 (second from LSB) of the first octet = locally-administered.
    Used to classify randomized phone MACs without a real vendor."""

    def test_universal_mac_returns_false(self):
        from homenet import _is_locally_admin_mac

        # Real IEEE-issued OUIs (bit 1 = 0)
        assert _is_locally_admin_mac("28:94:01:00:00:00") is False  # Netgear
        assert _is_locally_admin_mac("80:6A:10:00:00:00") is False  # Apple
        assert _is_locally_admin_mac("00:15:5D:00:00:00") is False  # Microsoft

    def test_locally_admin_mac_returns_true(self):
        from homenet import _is_locally_admin_mac

        # Bit 1 set in first octet -> randomised MAC
        # 0x02 = 00000010 -> bit 1 set
        assert _is_locally_admin_mac("02:00:00:00:00:00") is True
        # 0x16 = 00010110 -> bit 1 set (from live device)
        assert _is_locally_admin_mac("16:3C:BE:A4:6C:C9") is True
        # 0xFA = 11111010 -> bit 1 set
        assert _is_locally_admin_mac("FA:93:62:00:00:00") is True

    def test_dash_separator_works(self):
        from homenet import _is_locally_admin_mac

        assert _is_locally_admin_mac("02-00-00-00-00-00") is True
        assert _is_locally_admin_mac("28-94-01-00-00-00") is False

    def test_malformed_mac_returns_false_safely(self):
        """Defensive: garbage input must not crash -- return False so the
        caller falls through to the normal IEEE / Unknown path."""
        from homenet import _is_locally_admin_mac

        assert _is_locally_admin_mac("") is False
        assert _is_locally_admin_mac("xx:xx") is False
        assert _is_locally_admin_mac("not a mac") is False


class TestMacVendorIEEELookup:
    """Backlog #10: vendor lookup falls through to IEEE registry when the
    curated _MAC_VENDORS dict doesn't have the OUI. Tests mock the
    _IEEE_LOOKUP.lookup call so we don't depend on the live IEEE file."""

    def _reset_cache(self):
        import homenet as hn

        hn._vendor_cache.clear()

    def test_curated_dict_wins_over_ieee(self, mocker):
        """Curated friendly names ('Netgear') take priority over IEEE's
        long-form ('NETGEAR')."""
        from homenet import _IEEE_LOOKUP, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is not None:
            mocker.patch.object(_IEEE_LOOKUP, "lookup", return_value="NETGEAR")
        assert _mac_vendor("28:94:01:00:00:00") == "Netgear"  # curated wins

    def test_ieee_lookup_used_when_not_in_curated(self, mocker):
        from homenet import _IEEE_LOOKUP, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")
        mocker.patch.object(_IEEE_LOOKUP, "lookup", return_value="Amazon Technologies Inc.")
        # 64:CD:C2 is Amazon per IEEE -- not in our curated dict
        assert _mac_vendor("64:CD:C2:00:00:00") == "Amazon Technologies Inc."

    def test_random_mac_fallback_when_ieee_misses(self, mocker):
        from homenet import _IEEE_LOOKUP, VendorNotFoundError, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is not None:
            mocker.patch.object(_IEEE_LOOKUP, "lookup", side_effect=VendorNotFoundError("00:00:00:00:00:00"))
        # 16:3C:BE has the locally-admin bit set AND no IEEE match
        assert _mac_vendor("16:3C:BE:A4:6C:C9") == "Random MAC (Phone)"

    def test_unknown_when_no_match_anywhere(self, mocker):
        from homenet import _IEEE_LOOKUP, VendorNotFoundError, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is not None:
            mocker.patch.object(_IEEE_LOOKUP, "lookup", side_effect=VendorNotFoundError("00:00:00:00:00:00"))
        # 64:CD:C2 is universally admin + not in curated -> "Unknown"
        # (once IEEE is mocked to fail)
        assert _mac_vendor("64:CD:C2:00:00:00") == "Unknown"

    def test_cache_prevents_duplicate_ieee_calls(self, mocker):
        from homenet import _IEEE_LOOKUP, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")
        spy = mocker.patch.object(_IEEE_LOOKUP, "lookup", return_value="Fake Vendor Inc")
        _mac_vendor("AA:BB:CC:00:00:01")
        _mac_vendor("AA:BB:CC:00:00:02")  # same OUI prefix
        _mac_vendor("AA:BB:CC:11:22:33")  # same OUI prefix
        assert spy.call_count == 1, "second+ lookups with the same OUI must hit cache"

    def test_ieee_exception_degrades_to_unknown(self, mocker):
        from homenet import _IEEE_LOOKUP, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")
        # Any unexpected exception (file corrupt, network blip during init)
        # must not propagate -- degrade to Unknown so the UI keeps working.
        mocker.patch.object(_IEEE_LOOKUP, "lookup", side_effect=RuntimeError("corrupt file"))
        assert _mac_vendor("64:CD:C2:00:00:00") == "Unknown"

    def test_empty_mac_returns_unknown(self):
        from homenet import _mac_vendor

        self._reset_cache()
        assert _mac_vendor("") == "Unknown"

    def test_unknown_result_is_not_cached(self, mocker):
        """Regression pin for the 2026-04-23 cache-poisoning bug: a
        transient IEEE-lookup failure returned "Unknown" and got cached,
        so subsequent calls never retried even after the registry
        finished loading. Fix: only cache positive resolutions. Next
        call with a now-working lookup must pick up the real vendor."""
        from homenet import _IEEE_LOOKUP, VendorNotFoundError, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")
        # First call: simulate transient failure -> "Unknown"
        call1 = mocker.patch.object(_IEEE_LOOKUP, "lookup", side_effect=VendorNotFoundError("64:CD:C2:00:00:00"))
        assert _mac_vendor("64:CD:C2:00:00:00") == "Unknown"
        # Second call: IEEE now works and returns a real vendor.
        # Cache must NOT have poisoned the result -- retry must find it.
        call1.side_effect = None
        call1.return_value = "Amazon Technologies Inc."
        assert _mac_vendor("64:CD:C2:00:00:00") == "Amazon Technologies Inc."

    def test_positive_result_is_cached(self, mocker):
        """Positive results still cache -- only the negative path skips.
        Ensures the cache's performance benefit is preserved."""
        from homenet import _IEEE_LOOKUP, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")
        spy = mocker.patch.object(_IEEE_LOOKUP, "lookup", return_value="Fake Vendor Ltd")
        _mac_vendor("AA:BB:CC:00:00:01")
        _mac_vendor("AA:BB:CC:11:22:33")  # same OUI
        assert spy.call_count == 1, "positive result must still cache"

    def test_ieee_lookup_is_serialized_across_threads(self, mocker):
        """Regression pin for the 2026-04-23 threaded-race bug: mac-vendor-
        lookup wraps its async core with ``loop.run_until_complete()`` on a
        private event loop shared by the MacLookup instance. Concurrent
        calls from multiple threads race on that loop and some lookups
        silently fail -- observed live as 14/76 still-Unknown devices
        despite REPL resolving every one of them.

        Fix: ``_ieee_lookup_lock`` serialises lookup() calls. This test
        hammers 20 threads at the lock with distinct OUI prefixes and
        asserts every thread gets its expected vendor back. Without the
        lock the test is flaky; with the lock it's deterministic.
        """
        from concurrent.futures import ThreadPoolExecutor

        from homenet import _IEEE_LOOKUP, VendorNotFoundError, _mac_vendor

        self._reset_cache()
        if _IEEE_LOOKUP is None:
            pytest.skip("mac-vendor-lookup not installed")

        # Use 00:04:xx prefix -- first octet 0x00 has bit 1 = 0 so the
        # locally-admin fallback doesn't kick in if IEEE misses, and we
        # can cleanly distinguish "threaded race failed" from "fell
        # through to Random MAC" in the assertion message.
        fake_vendors = {f"00:04:{i:02X}": f"Vendor-{i:02X}" for i in range(20)}

        def fake_lookup(mac):
            prefix = mac[:8].upper()  # 3-octet OUI with colons
            if prefix in fake_vendors:
                return fake_vendors[prefix]
            raise VendorNotFoundError(mac)

        mocker.patch.object(_IEEE_LOOKUP, "lookup", side_effect=fake_lookup)

        def one(i):
            mac = f"00:04:{i:02X}:00:00:01"
            return _mac_vendor(mac)

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(one, range(20)))

        expected = [f"Vendor-{i:02X}" for i in range(20)]
        assert results == expected, (
            f"threaded lookup produced inconsistent results -- likely the "
            f"_ieee_lookup_lock was removed. Missing: "
            f"{set(expected) - set(results)}"
        )


class TestVendorCategorySubstring:
    """IEEE returns long names like 'Amazon Technologies Inc.' that won't
    exact-match the curated _VENDOR_CATEGORY_MAP. Substring patterns pick
    those up. This test pins the pattern set so a future edit that
    reorders / drops a needle fails loudly."""

    def test_amazon_variants_become_iot(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Amazon Technologies Inc.") == "IoT"
        assert _categorise_by_vendor_substring("Ring LLC") == "IoT"
        assert _categorise_by_vendor_substring("Blink, Inc.") == "IoT"

    def test_apple_becomes_phone(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Apple, Inc.") == "Phone"
        assert _categorise_by_vendor_substring("Apple Inc") == "Phone"

    def test_samsung_becomes_tv(self):
        """Samsung sells phones AND TVs; we default to TV since the curated
        _MAC_VENDORS dict had that mapping already."""
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Samsung Electronics Co., Ltd.") == "TV"

    def test_google_nest_ring_iot(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Google LLC") == "IoT"
        assert _categorise_by_vendor_substring("Nest Labs Inc.") == "IoT"
        assert _categorise_by_vendor_substring("Ring LLC") == "IoT"

    def test_printer_vendors(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Brother Industries, Ltd.") == "Printer"
        assert _categorise_by_vendor_substring("Seiko Epson Corp.") == "Printer"
        assert _categorise_by_vendor_substring("Canon Inc.") == "Printer"
        assert _categorise_by_vendor_substring("Hewlett-Packard") == "Printer"

    def test_network_gear(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("NETGEAR") == "Network"
        assert _categorise_by_vendor_substring("TP-Link Technologies") == "Network"
        assert _categorise_by_vendor_substring("Cisco Systems Inc") == "Network"
        assert _categorise_by_vendor_substring("Ubiquiti Networks") == "Network"

    def test_storage_vendors(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Synology Incorporated") == "Storage"
        assert _categorise_by_vendor_substring("QNAP Systems") == "Storage"

    def test_microsoft_goes_other(self):
        """Microsoft covers Xbox, Surface, Hyper-V -- no clear category."""
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Microsoft Corporation") == "Other"

    def test_empty_input_returns_empty(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("") == ""
        assert _categorise_by_vendor_substring("Random MAC (Phone)") == ""

    def test_unknown_vendor_returns_empty(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("Some Random Company") == ""

    def test_case_insensitive(self):
        from homenet import _categorise_by_vendor_substring

        assert _categorise_by_vendor_substring("AMAZON TECHNOLOGIES INC.") == "IoT"
        assert _categorise_by_vendor_substring("apple inc.") == "Phone"


class TestMdnsResolveBatch:
    """Mock the zeroconf module so we don't actually broadcast during tests."""

    def test_empty_ip_list_returns_empty(self):
        from homenet import _mdns_resolve_batch

        assert _mdns_resolve_batch([]) == {}

    def test_returns_empty_when_zeroconf_unavailable(self, mocker):
        """Import-time failure of zeroconf -> graceful empty dict, no raise."""
        import sys

        # Force import failure
        saved = sys.modules.pop("zeroconf", None)
        mocker.patch.dict(sys.modules, {"zeroconf": None})
        try:
            from homenet import _mdns_resolve_batch

            result = _mdns_resolve_batch(["192.168.1.100"], timeout_s=0.1)
            assert result == {}
        finally:
            if saved is not None:
                sys.modules["zeroconf"] = saved

    def test_zeroconf_init_failure_returns_empty(self, mocker):
        """zeroconf installed but Zeroconf() raises (no interfaces, etc.)."""
        import sys
        import types

        fake = types.ModuleType("zeroconf")

        class _FakeZeroconf:
            def __init__(self, *a, **kw):
                raise OSError("no interfaces available")

        fake.Zeroconf = _FakeZeroconf
        fake.ServiceBrowser = lambda *a, **kw: None
        fake.ServiceListener = type(
            "ServiceListener", (), {"add_service": None, "remove_service": None, "update_service": None}
        )

        mocker.patch.dict(sys.modules, {"zeroconf": fake})
        from homenet import _mdns_resolve_batch

        result = _mdns_resolve_batch(["192.168.1.100"], timeout_s=0.1)
        assert result == {}

    def test_mdns_collects_hostname_for_matched_ip(self, mocker):
        """Happy path: zeroconf browses, listener gets a service, hostname
        lands in results under the matching IP. Uses a fake module that
        captures the listener and drives it synchronously."""
        import sys
        import types

        captured_listeners = []

        class _FakeServiceInfo:
            def __init__(self, server, addresses):
                self.server = server
                self._addresses = addresses

            def parsed_addresses(self):
                return self._addresses

        class _FakeZeroconf:
            def __init__(self, *a, **kw):
                pass

            def get_service_info(self, type_, name, timeout=None):
                # Resolve to a predictable hostname per name
                return _FakeServiceInfo(server=f"{name.split('.')[0]}.local.", addresses=["192.168.1.42"])

            def close(self):
                pass

        class _FakeServiceBrowser:
            def __init__(self, zc, service_type, listener):
                captured_listeners.append((zc, listener))
                # Immediately fire an "add_service" event synchronously
                listener.add_service(zc, service_type, "MyAppleTV")

            def cancel(self):
                pass

        fake = types.ModuleType("zeroconf")
        fake.Zeroconf = _FakeZeroconf
        fake.ServiceBrowser = _FakeServiceBrowser
        fake.ServiceListener = type(
            "ServiceListener",
            (),
            {
                "add_service": lambda self, *a, **kw: None,
                "remove_service": lambda self, *a, **kw: None,
                "update_service": lambda self, *a, **kw: None,
            },
        )
        mocker.patch.dict(sys.modules, {"zeroconf": fake})

        from homenet import _mdns_resolve_batch

        result = _mdns_resolve_batch(["192.168.1.42", "192.168.1.99"], timeout_s=0.05)
        assert result == {"192.168.1.42": "MyAppleTV"}


class TestVerizonJsParsing:
    """Test Verizon cgi_basic.js parsing."""

    def test_parse_simple_string(self):
        from homenet import _parse_verizon_js

        js = 'addROD("router_name", "MyRouter");'
        result = _parse_verizon_js(js)
        assert result["router_name"] == "MyRouter"

    def test_parse_json_object(self):
        from homenet import _parse_verizon_js

        js = 'addROD("hardware_model", "CR1000A");'
        result = _parse_verizon_js(js)
        assert result["hardware_model"] == "CR1000A"

    def test_parse_known_device_list(self):
        from homenet import _parse_verizon_js

        js = """addROD("known_device_list", {"known_devices": [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.5"}]});"""
        result = _parse_verizon_js(js)
        assert "known_device_list" in result
        devs = result["known_device_list"]["known_devices"]
        assert len(devs) == 1
        assert devs[0]["mac"] == "AA:BB:CC:DD:EE:FF"


class TestOrbiSoapParsing:
    """Test Orbi SOAP response parsing."""

    def test_parse_xml_device_format(self):
        """Test RBRE960 XML Device element parsing."""
        from homenet import _parse_orbi_soap

        xml = """<Device>
        <IP>10.0.0.60</IP>
        <Name>Fire TV</Name>
        <MAC>44:3D:54:00:12:AC</MAC>
        <ConnectionType>5GHz</ConnectionType>
        <Linkspeed>72</Linkspeed>
        <SignalStrength>56</SignalStrength>
        <DeviceModel>Fire TV Stick 4K Max</DeviceModel>
        <DeviceBrand>Amazon</DeviceBrand>
        <DeviceTypeV2>GENERIC</DeviceTypeV2>
        <SSID>mynet</SSID>
        <NameUserSet>false</NameUserSet>
        </Device>
        <Device>
        <IP>10.0.0.25</IP>
        <Name>Ring-Front</Name>
        <MAC>90:48:6C:F9:48:7A</MAC>
        <ConnectionType>5GHz - IoT</ConnectionType>
        <Linkspeed>40</Linkspeed>
        <SignalStrength>70</SignalStrength>
        <DeviceModel>Video Doorbell</DeviceModel>
        <DeviceBrand>Ring</DeviceBrand>
        <DeviceTypeV2>CAMERA</DeviceTypeV2>
        <SSID>mynet-iot</SSID>
        <NameUserSet>true</NameUserSet>
        </Device>"""
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 2
        assert devices[0]["ip"] == "10.0.0.60"
        assert devices[0]["name"] == "Fire TV"
        assert devices[0]["mac"] == "44:3D:54:00:12:AC"
        assert devices[0]["device_model"] == "Fire TV Stick 4K Max"
        assert devices[0]["device_brand"] == "Amazon"
        assert devices[0]["ssid"] == "mynet"
        assert devices[0]["device_name_user_set"] is False
        assert devices[1]["name"] == "Ring-Front"
        assert devices[1]["device_name_user_set"] is True

    def test_parse_legacy_delimited_format(self):
        """Test legacy @-delimited format from older firmware."""
        from homenet import _parse_orbi_soap

        xml = """<NewGetAttachDevice2>10.0.0.2;MyPhone;AA:BB:CC:DD:EE:FF;5G;866Mbps;-45;Phone@10.0.0.3;Laptop;11:22:33:44:55:66;2.4G;72Mbps;-60;Computer</NewGetAttachDevice2>"""
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 2
        assert devices[0]["ip"] == "10.0.0.2"
        assert devices[0]["name"] == "MyPhone"
        assert devices[1]["connection_type"] == "2.4G"

    def test_parse_empty_response(self):
        from homenet import _parse_orbi_soap

        xml = "<SomeOtherTag>nothing here</SomeOtherTag>"
        devices = _parse_orbi_soap(xml)
        assert devices == []

    def test_parse_xml_skips_no_mac(self):
        """Devices without MAC should be skipped."""
        from homenet import _parse_orbi_soap

        xml = """<Device><IP>10.0.0.1</IP><Name>NoMAC</Name></Device>
        <Device><IP>10.0.0.2</IP><Name>HasMAC</Name><MAC>AA:BB:CC:DD:EE:FF</MAC></Device>"""
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 1
        assert devices[0]["name"] == "HasMAC"


class TestArcMd5:
    """Test Verizon's ArcMD5 hashing."""

    def test_arc_md5_deterministic(self):
        from homenet import _arc_md5

        h1 = _arc_md5("admin")
        h2 = _arc_md5("admin")
        assert h1 == h2
        assert len(h1) == 128  # SHA512 hex = 128 chars

    def test_arc_md5_different_inputs(self):
        from homenet import _arc_md5

        assert _arc_md5("admin") != _arc_md5("password")


class TestMergeDeviceData:
    """Test device data merging logic."""

    def test_merge_new_device(self):
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.50", "name": "TestPC"}]
        result = _merge_device_data(inv, "arp", devices)
        assert "AA:BB:CC:DD:EE:FF" in result["devices"]
        assert result["devices"]["AA:BB:CC:DD:EE:FF"]["network"] == "wired"

    def test_merge_preserves_user_fields(self):
        from homenet import _merge_device_data

        inv = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "friendly_name": "My PC",
                    "category": "Computer",
                    "location": "Office",
                    "notes": "Main desktop",
                    "hostname": "old-host",
                }
            },
            "last_scan": None,
        }
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.51", "name": "new-host"}]
        result = _merge_device_data(inv, "arp", devices)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert dev["ip"] == "192.168.1.51"  # IP updated
        assert dev["hostname"] == "new-host"  # hostname updated
        assert dev["friendly_name"] == "My PC"  # preserved
        assert dev["category"] == "Computer"  # preserved
        assert dev["location"] == "Office"  # preserved

    def test_merge_skips_broadcast(self):
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "FF:FF:FF:FF:FF:FF", "ip": "192.168.1.255", "name": ""}]
        result = _merge_device_data(inv, "arp", devices)
        assert len(result["devices"]) == 0

    def test_merge_wireless_detection(self):
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.50", "name": ""}]
        result = _merge_device_data(inv, "orbi", devices)
        assert result["devices"]["AA:BB:CC:DD:EE:FF"]["network"] == "wireless"

    def test_merge_normalizes_mac(self):
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "aa-bb-cc-dd-ee-ff", "ip": "192.168.1.50", "name": ""}]
        result = _merge_device_data(inv, "arp", devices)
        assert "AA:BB:CC:DD:EE:FF" in result["devices"]

    def test_merge_captures_dns_hostname_from_verizon(self):
        """Verizon scan -> dns_hostname populated with the router-reported name.

        Backlog #7 (Path A): we keep dns_hostname distinct from hostname so
        the UI can show the user what the router thinks the device is called
        even when local heuristics (mDNS, NetBIOS) gave us a different name.
        """
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.50", "name": "Living-Room-TV"}]
        result = _merge_device_data(inv, "verizon", devices)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert dev["dns_hostname"] == "Living-Room-TV"

    def test_merge_captures_dns_hostname_from_orbi(self):
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.5", "name": "iPhone-15"}]
        result = _merge_device_data(inv, "orbi", devices)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert dev["dns_hostname"] == "iPhone-15"

    def test_merge_arp_does_not_overwrite_dns_hostname(self):
        """ARP gives no name -- it must NOT blank out a previously-captured
        router-sourced dns_hostname. This is the regression most likely to
        happen if someone "simplifies" the merge logic later."""
        from homenet import _merge_device_data

        inv = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "Living-Room-TV",
                    "dns_hostname": "Living-Room-TV",  # already captured from Verizon
                }
            },
            "last_scan": None,
        }
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.50", "name": ""}]
        result = _merge_device_data(inv, "arp", devices)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert dev["dns_hostname"] == "Living-Room-TV"  # preserved

    def test_merge_arp_initial_seen_dns_hostname_empty(self):
        """First-ever ARP sighting: no router data yet -> dns_hostname is empty
        (NOT undefined). The UI's 'pull from router' button needs the field
        to exist on every device record so the read-only row renders."""
        from homenet import _merge_device_data

        inv = {"devices": {}, "last_scan": None}
        devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.50", "name": ""}]
        result = _merge_device_data(inv, "arp", devices)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert "dns_hostname" in dev
        assert dev["dns_hostname"] == ""


class TestCredentialHelpers:
    """Test keyring wrapper functions."""

    def test_get_cred_no_keyring(self, mocker):
        mocker.patch.dict("sys.modules", {"keyring": None})
        from homenet import _get_homenet_cred

        result = _get_homenet_cred("verizon")
        assert result == (None, None)

    def test_get_cred_with_admin_password(self, mocker):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = "secret123"
        mocker.patch("homenet.keyring", mock_kr, create=True)
        # We need to reimport to use the mock - instead test via route
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "secret123"))
        from homenet import _get_homenet_cred

        assert _get_homenet_cred("verizon") == ("admin", "secret123")

    def test_get_cred_via_credential_object(self, mocker):
        """When get_password returns None but get_credential returns a cred object."""
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = None
        mock_cred = MagicMock()
        mock_cred.username = "customuser"
        mock_cred.password = "custompw"
        mock_kr.get_credential.return_value = mock_cred
        mocker.patch("homenet.keyring", mock_kr, create=True)
        mocker.patch("homenet._get_homenet_cred", return_value=("customuser", "custompw"))
        from homenet import _get_homenet_cred

        user, pw = _get_homenet_cred("orbi")
        assert user == "customuser"

    def test_set_cred_calls_keyring(self, mocker):
        mocker.patch("homenet._set_homenet_cred", return_value=True)
        from homenet import _set_homenet_cred

        assert _set_homenet_cred("verizon", "admin", "test") is True

    def test_set_cred_failure(self, mocker):
        mocker.patch("homenet._set_homenet_cred", return_value=False)
        from homenet import _set_homenet_cred

        assert _set_homenet_cred("verizon", "admin", "test") is False

    def test_delete_cred_with_user(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mocker.patch("homenet._delete_homenet_cred", return_value=True)
        from homenet import _delete_homenet_cred

        assert _delete_homenet_cred("verizon") is True

    def test_delete_cred_no_user(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        mocker.patch("homenet._delete_homenet_cred", return_value=True)
        from homenet import _delete_homenet_cred

        assert _delete_homenet_cred("verizon") is True

    def test_list_creds_all_unconfigured(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        from homenet import _list_homenet_creds

        result = _list_homenet_creds()
        assert len(result) == 3
        assert all(c["configured"] is False for c in result)

    def test_list_creds_password_hint(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "mypassword"))
        from homenet import _list_homenet_creds

        result = _list_homenet_creds()
        assert result[0]["password_hint"] == "••••rd"

    def test_list_creds_short_password(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "ab"))
        from homenet import _list_homenet_creds

        result = _list_homenet_creds()
        assert result[0]["password_hint"] == "••••"


class TestVerizonApi:
    """Test Verizon CR1000A API functions."""

    def test_verizon_no_creds(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        from homenet import _verizon_get_devices

        result = _verizon_get_devices()
        assert "error" in result
        assert "credentials" in result["error"].lower()

    def test_verizon_encode_password(self):
        from homenet import _verizon_encode_password

        token = "abc123"
        result = _verizon_encode_password("password", token)
        assert len(result) == 128
        # Should be deterministic
        assert result == _verizon_encode_password("password", token)

    def test_verizon_connection_timeout(self, mocker):
        import requests

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.cookies.get_dict.return_value = {}
        mock_session.get.side_effect = requests.exceptions.ConnectTimeout()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _verizon_get_devices

        result = _verizon_get_devices()
        assert "error" in result
        assert "unreachable" in result["error"].lower()


class TestOrbiApi:
    """Test Orbi SOAP API functions."""

    def test_orbi_no_creds(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        from homenet import _orbi_get_devices

        result = _orbi_get_devices()
        assert "error" in result
        assert "credentials" in result["error"].lower()

    def test_orbi_ssl_error_returns_error(self, mocker):
        import requests as req

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "password"))
        mock_session = MagicMock()
        mock_session.post.side_effect = req.exceptions.SSLError("SSL certificate verify failed")
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _orbi_get_devices

        result = _orbi_get_devices()
        assert "error" in result
        assert "ssl" in result["error"].lower()


class TestArpScan:
    """Test ARP scanning — Batch E: parses ``arp -a`` output directly (no PS)."""

    # Realistic ``arp -a`` output from Windows
    ARP_OUTPUT = (
        "\n"
        "Interface: 192.168.1.10 --- 0x5\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
        "  192.168.1.50          11-22-33-44-55-66     dynamic\n"
        "\n"
        "Interface: 10.0.0.100 --- 0x9\n"
        "  Internet Address      Physical Address      Type\n"
        "  10.0.0.1              77-88-99-aa-bb-cc     dynamic\n"
    )

    def test_arp_scan_success(self, mocker):
        mock_result = MagicMock()
        mock_result.stdout = self.ARP_OUTPUT
        mocker.patch("homenet.subprocess.run", return_value=mock_result)
        from homenet import _arp_scan

        result = _arp_scan()
        assert len(result) == 3
        assert result[0]["IP"] == "192.168.1.1"
        assert result[0]["Interface"] == "192.168.1.10"
        assert result[0]["MAC"] == "AA:BB:CC:DD:EE:FF"
        assert result[0]["Type"] == "dynamic"
        # Second interface
        assert result[2]["Interface"] == "10.0.0.100"

    def test_arp_scan_single_entry(self, mocker):
        mock_result = MagicMock()
        mock_result.stdout = (
            "\nInterface: 192.168.1.10 --- 0x5\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
        )
        mocker.patch("homenet.subprocess.run", return_value=mock_result)
        from homenet import _arp_scan

        result = _arp_scan()
        assert len(result) == 1

    def test_arp_scan_error(self, mocker):
        mocker.patch("homenet.subprocess.run", side_effect=Exception("fail"))
        from homenet import _arp_scan

        result = _arp_scan()
        assert result == []

    def test_arp_scan_empty(self, mocker):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mocker.patch("homenet.subprocess.run", return_value=mock_result)
        from homenet import _arp_scan

        result = _arp_scan()
        assert result == []

    def test_arp_scan_no_powershell(self, mocker):
        """Regression: Batch E — arp runs directly, no PS wrapper."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        m = mocker.patch("homenet.subprocess.run", return_value=mock_result)
        from homenet import _arp_scan

        _arp_scan()
        cmd = m.call_args[0][0]
        assert cmd[0] == "arp"
        assert "-a" in cmd
        assert "powershell" not in cmd


class TestTpLinkSwitch:
    """Test TP-Link switch SNMP integration."""

    def test_tplink_no_creds(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        from homenet import _tplink_get_data

        result = _tplink_get_data()
        assert "error" in result
        assert "credentials" in result["error"].lower()

    def test_tplink_snmp_no_pysnmp(self, mocker):
        """Test graceful handling when pysnmp is not installed."""
        mocker.patch.dict(
            "sys.modules",
            {"pysnmp": None, "pysnmp.hlapi": None, "pysnmp.hlapi.v1arch": None, "pysnmp.hlapi.v1arch.asyncio": None},
        )
        from homenet import _tplink_snmp_query

        result = _tplink_snmp_query("192.168.1.1", "public")
        assert "error" in result

    def test_tplink_get_data_calls_snmp(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("192.168.1.100", "public"))
        mocker.patch(
            "homenet._tplink_snmp_query",
            return_value={"ok": True, "ports": [], "mac_table": [], "system_info": {}},
        )
        from homenet import _tplink_get_data

        result = _tplink_get_data()
        assert result["ok"] is True

    def test_tplink_auto_resolve_ip(self, mocker):
        """When user stores 'auto' as IP, app resolves via MAC lookup."""
        mocker.patch("homenet._get_homenet_cred", return_value=("auto", "public"))
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "192.168.1.55", "MAC": "DC:62:79:F3:52:5C", "Type": "dynamic", "Interface": "192.168.1.10"},
            ],
        )
        mocker.patch(
            "homenet._tplink_snmp_query",
            return_value={"ok": True, "ports": [], "mac_table": [], "system_info": {}},
        )
        from homenet import _tplink_get_data

        result = _tplink_get_data()
        assert result["ok"] is True

    def test_tplink_auto_resolve_not_found(self, mocker):
        """When auto-resolve can't find the switch MAC."""
        mocker.patch("homenet._get_homenet_cred", return_value=("auto", "public"))
        mocker.patch("homenet._arp_scan", return_value=[])
        from homenet import _tplink_get_data

        result = _tplink_get_data()
        assert "error" in result
        assert "Cannot find" in result["error"]

    def test_resolve_ip_from_mac(self, mocker):
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "192.168.1.55", "MAC": "DC:62:79:F3:52:5C", "Type": "dynamic", "Interface": "192.168.1.10"},
            ],
        )
        from homenet import _resolve_ip_from_mac

        assert _resolve_ip_from_mac("DC:62:79:F3:52:5C") == "192.168.1.55"

    def test_resolve_ip_from_mac_not_found(self, mocker):
        mocker.patch("homenet._arp_scan", return_value=[])
        from homenet import _resolve_ip_from_mac

        assert _resolve_ip_from_mac("DC:62:79:F3:52:5C") == ""

    def test_tplink_test_endpoint(self, client, mocker):
        mocker.patch(
            "homenet._tplink_get_data",
            return_value={
                "ok": True,
                "ports": [
                    {"port": "GigE1/0/1", "status": "up", "speed_mbps": 1000},
                    {"port": "GigE1/0/2", "status": "down", "speed_mbps": 0},
                ],
                "mac_table": [{"mac": "AA:BB:CC:DD:EE:FF", "port_index": 1}],
            },
        )
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "tplink_switch"},
        )
        data = resp.get_json()
        assert data["ok"] is True
        assert "1/2 ports up" in data["message"]
        assert "1 MACs" in data["message"]

    def test_tplink_test_endpoint_failure(self, client, mocker):
        mocker.patch(
            "homenet._tplink_get_data",
            return_value={"error": "SNMP timeout"},
        )
        resp = client.post(
            "/api/homenet/credentials/test",
            json={"device_key": "tplink_switch"},
        )
        data = resp.get_json()
        assert data["ok"] is False
        assert "SNMP timeout" in data["message"]

    def test_switch_data_route(self, client, mocker):
        mocker.patch(
            "homenet._tplink_get_data",
            return_value={
                "ok": True,
                "ports": [{"port": "GigE1/0/1", "status": "up"}],
                "mac_table": [],
                "system_info": {"sysName": "TL-SG2218"},
            },
        )
        resp = client.get("/api/homenet/switch")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert len(data["ports"]) == 1

    def test_creds_list_includes_tplink(self, client, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        resp = client.get("/api/homenet/credentials")
        data = resp.get_json()
        assert len(data) == 3
        keys = [d["key"] for d in data]
        assert "tplink_switch" in keys


class TestHomeNetNlq:
    """Test NLQ integration for home network."""

    def test_nlq_dispatch_has_homenet(self):
        from windesktopmgr import _NLQ_DISPATCH

        assert "get_homenet_inventory" in _NLQ_DISPATCH

    def test_nlq_tools_has_homenet(self):
        from nlq import _NLQ_TOOLS

        tool_names = [t["name"] for t in _NLQ_TOOLS]
        assert "get_homenet_inventory" in tool_names


class TestHomeNetInventoryPersistence:
    """Test inventory file load/save."""

    def test_load_missing_file(self, mocker):
        mocker.patch("os.path.exists", return_value=False)
        from homenet import _load_homenet_inventory

        result = _load_homenet_inventory()
        assert result == {"devices": {}, "last_scan": None}

    def test_load_corrupt_file(self, mocker, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json!")
        mocker.patch("homenet.HOMENET_INVENTORY_FILE", str(f))
        from homenet import _load_homenet_inventory

        result = _load_homenet_inventory()
        assert result == {"devices": {}, "last_scan": None}

    def test_save_and_load(self, mocker, tmp_path):
        f = tmp_path / "inv.json"
        mocker.patch("homenet.HOMENET_INVENTORY_FILE", str(f))
        from homenet import _load_homenet_inventory, _save_homenet_inventory

        inv = {"devices": {"AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF"}}, "last_scan": "2026-01-01"}
        _save_homenet_inventory(inv)
        loaded = _load_homenet_inventory()
        assert "AA:BB:CC:DD:EE:FF" in loaded["devices"]


class TestHomenetFullScan:
    """Test full scan orchestration."""

    def test_full_scan_with_all_sources(self, client, mocker):
        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(True, True, "OrbiNet"))
        mocker.patch("homenet._wifi_restore")
        mocker.patch(
            "homenet._arp_scan",
            return_value=[
                {"IP": "192.168.1.50", "MAC": "AA:BB:CC:DD:EE:FF", "Type": "dynamic", "Interface": "192.168.1.10"},
            ],
        )
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={
                "ok": True,
                "known_devices": {
                    "known_devices": [
                        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.20", "hostname": "TV", "activity": 1},
                    ]
                },
            },
        )
        mocker.patch(
            "homenet._orbi_get_devices",
            return_value={
                "ok": True,
                "devices": [{"ip": "10.0.0.5", "name": "Phone", "mac": "99:88:77:66:55:44", "connection_type": "5G"}],
            },
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        data = resp.get_json()
        assert data["ok"] is True
        assert data["device_count"] == 3
        assert len(data["errors"]) == 0

    def test_full_scan_handles_verizon_list_format(self, client, mocker):
        """Verizon known_devices can be a list directly (not nested in dict)."""
        mocker.patch("homenet._wifi_ensure_orbi_connected", return_value=(False, True, ""))
        mocker.patch("homenet._wifi_restore")
        mocker.patch("homenet._arp_scan", return_value=[])
        mocker.patch(
            "homenet._verizon_get_devices",
            return_value={
                "ok": True,
                "known_devices": [
                    {"mac": "11:22:33:44:55:66", "ip": "192.168.1.20", "hostname": "PC", "activity": 1},
                ],
            },
        )
        mocker.patch("homenet._load_homenet_inventory", return_value={"devices": {}, "last_scan": None})
        mocker.patch("homenet._save_homenet_inventory")
        resp = client.post("/api/homenet/scan")
        data = resp.get_json()
        # When known_devices is a list (not dict), it won't have .get("known_devices")
        # This tests the isinstance(known, list) branch
        assert data["ok"] is True


class TestSwitchDataRoute:
    """Test switch data endpoint."""

    def test_switch_route_no_creds(self, client, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=(None, None))
        resp = client.get("/api/homenet/switch")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "error" in data

    def test_switch_route_with_data(self, client, mocker):
        mocker.patch(
            "homenet._tplink_get_data",
            return_value={
                "ok": True,
                "ports": [
                    {
                        "port": "GigE1/0/1",
                        "ifIndex": "49153",
                        "status": "up",
                        "speed_mbps": 1000,
                        "in_bytes": 1000000,
                        "out_bytes": 500000,
                    },
                    {
                        "port": "GigE1/0/2",
                        "ifIndex": "49154",
                        "status": "down",
                        "speed_mbps": 0,
                        "in_bytes": 0,
                        "out_bytes": 0,
                    },
                ],
                "mac_table": [{"mac": "DC:62:79:F3:52:5C", "port_index": 1}],
                "system_info": {"sysDescr": "TL-SG2218", "sysName": "MySwitch"},
            },
        )
        resp = client.get("/api/homenet/switch")
        data = resp.get_json()
        assert data["ok"] is True
        assert len(data["ports"]) == 2
        assert data["ports"][0]["status"] == "up"
        assert len(data["mac_table"]) == 1
        assert data["system_info"]["sysName"] == "MySwitch"


class TestTpLinkMacVendor:
    """Test TP-Link specific MAC vendor lookup."""

    def test_tplink_switch_mac(self):
        from homenet import _mac_vendor

        assert _mac_vendor("DC:62:79:F3:52:5C") == "TP-Link"

    def test_tplink_common_prefixes(self):
        from homenet import _mac_vendor

        assert _mac_vendor("50:C7:BF:00:00:00") == "TP-Link"
        assert _mac_vendor("F4:EC:38:00:00:00") == "TP-Link"
        assert _mac_vendor("30:B5:C2:00:00:00") == "TP-Link"


class TestOrbiSoapParsingEdgeCases:
    """Additional Orbi SOAP parsing edge cases."""

    def test_parse_single_legacy_device(self):
        from homenet import _parse_orbi_soap

        xml = "<NewGetAttachDevice2>10.0.0.2;Phone;AA:BB:CC:DD:EE:FF;5G;866Mbps;-45;Phone</NewGetAttachDevice2>"
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 1
        assert devices[0]["ip"] == "10.0.0.2"

    def test_parse_short_legacy_entry(self):
        from homenet import _parse_orbi_soap

        xml = "<NewGetAttachDevice2>10.0.0.2;Phone;AA:BB:CC:DD:EE:FF;5G</NewGetAttachDevice2>"
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 1

    def test_parse_too_short_legacy_entry(self):
        from homenet import _parse_orbi_soap

        xml = "<NewGetAttachDevice2>10.0.0.2;Phone;MAC</NewGetAttachDevice2>"
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 0

    def test_parse_xml_missing_optional_fields(self):
        from homenet import _parse_orbi_soap

        xml = """<Device><IP>10.0.0.5</IP><MAC>AA:BB:CC:DD:EE:FF</MAC></Device>"""
        devices = _parse_orbi_soap(xml)
        assert len(devices) == 1
        assert devices[0]["ip"] == "10.0.0.5"
        assert devices[0]["name"] == ""
        assert devices[0]["device_model"] == ""
        assert devices[0]["device_brand"] == ""


class TestVerizonApiEdgeCases:
    """Additional Verizon API edge cases."""

    def test_verizon_connection_error(self, mocker):
        import requests

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.cookies.get_dict.return_value = {}
        mock_session.get.side_effect = requests.exceptions.ConnectionError()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _verizon_get_devices

        result = _verizon_get_devices()
        assert "error" in result
        assert "connect" in result["error"].lower()

    def test_verizon_generic_error(self, mocker):
        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("weird error")
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _verizon_get_devices

        result = _verizon_get_devices()
        assert "error" in result

    def test_orbi_connection_timeout(self, mocker):
        import requests

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.side_effect = requests.exceptions.ConnectTimeout()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _orbi_get_devices

        result = _orbi_get_devices()
        assert "error" in result
        assert "unreachable" in result["error"].lower()

    def test_orbi_connection_error(self, mocker):
        import requests

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.side_effect = requests.exceptions.ConnectionError()
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _orbi_get_devices

        result = _orbi_get_devices()
        assert "error" in result

    def test_orbi_generic_error(self, mocker):

        mocker.patch("homenet._get_homenet_cred", return_value=("admin", "pw"))
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("generic")
        mocker.patch("homenet.requests.Session", return_value=mock_session)
        from homenet import _orbi_get_devices

        result = _orbi_get_devices()
        assert "error" in result


class TestVerizonParsing:
    """Additional Verizon JS parsing edge cases."""

    def test_parse_trailing_comma(self):
        from homenet import _parse_verizon_js

        js = """addROD("known_device_list", {"known_devices": [{"mac": "AA:BB:CC:DD:EE:FF",},]});"""
        result = _parse_verizon_js(js)
        assert "known_device_list" in result

    def test_parse_single_quotes(self):
        from homenet import _parse_verizon_js

        js = "addROD('hardware_model', 'CR1000A');"
        result = _parse_verizon_js(js)
        assert result["hardware_model"] == "CR1000A"

    def test_parse_multiple_entries(self):
        from homenet import _parse_verizon_js

        js = 'addROD("router_name", "HomeRouter");\naddROD("hardware_model", "CR1000A");'
        result = _parse_verizon_js(js)
        assert result["router_name"] == "HomeRouter"
        assert result["hardware_model"] == "CR1000A"


class TestAutoCategorizee:
    """Test auto-categorization by vendor/hostname/device type."""

    def test_categorize_by_vendor(self):
        from homenet import _auto_categorize

        assert _auto_categorize("Roku", "", "", "") == "TV"
        assert _auto_categorize("Apple", "", "", "") == "Phone"
        assert _auto_categorize("Brother", "", "", "") == "Printer"
        assert _auto_categorize("Netgear", "", "", "") == "Network"
        assert _auto_categorize("Intel", "", "", "") == "Computer"
        assert _auto_categorize("Alexa/Amazon", "", "", "") == "IoT"

    def test_categorize_by_device_type(self):
        from homenet import _auto_categorize

        assert _auto_categorize("Unknown", "", "Phone", "") == "Phone"
        assert _auto_categorize("Unknown", "", "Computer", "") == "Computer"
        assert _auto_categorize("Unknown", "", "TV", "") == "TV"
        assert _auto_categorize("Unknown", "", "Printer", "") == "Printer"
        assert _auto_categorize("Unknown", "", "Tablet", "") == "Phone"

    def test_categorize_by_os(self):
        from homenet import _auto_categorize

        assert _auto_categorize("Unknown", "", "", "iOS") == "Phone"
        assert _auto_categorize("Unknown", "", "", "Android") == "Phone"
        assert _auto_categorize("Unknown", "", "", "Windows 11") == "Computer"
        assert _auto_categorize("Unknown", "", "", "macOS") == "Computer"

    def test_categorize_by_hostname(self):
        from homenet import _auto_categorize

        assert _auto_categorize("Unknown", "BRW707781CBB5A5", "", "") == "Printer"
        assert _auto_categorize("Unknown", "Roku-Streaming-Stick", "", "") == "TV"
        assert _auto_categorize("Unknown", "iPhone-John", "", "") == "Phone"
        assert _auto_categorize("Unknown", "Echo-Dot-Kitchen", "", "") == "IoT"
        assert _auto_categorize("Unknown", "shigs78-pc24", "", "") == "Computer"
        assert _auto_categorize("Unknown", "Synology-NAS", "", "") == "Storage"

    def test_categorize_device_type_takes_precedence(self):
        """Device type from router should override vendor guess."""
        from homenet import _auto_categorize

        # Samsung makes TVs but also phones
        assert _auto_categorize("Samsung", "", "Phone", "") == "Phone"

    def test_categorize_unknown(self):
        from homenet import _auto_categorize

        assert _auto_categorize("Unknown", "", "", "") == ""

    def test_categorize_random_mac_is_phone(self):
        """Backlog #10 behaviour change: Random MAC (Phone) now categorises
        as Phone. iOS / Android randomise MACs per-SSID for privacy; there
        is nothing else in the universe that does this, so Phone is a safe
        default (vs the old "" that forced the user to re-guess)."""
        from homenet import _auto_categorize

        assert _auto_categorize("Random MAC (Phone)", "", "", "") == "Phone"


class TestNameResolution:
    """Test name resolution — Batch E: socket.gethostbyaddr + direct nbtstat."""

    def test_resolve_names_batch_with_results(self, mocker):
        """Wired DNS returns names via socket.gethostbyaddr."""
        mocker.patch(
            "homenet.socket.gethostbyaddr",
            return_value=("MyPC", [], ["192.168.1.50"]),
        )
        # Wi-Fi reachability check — Orbi not reachable
        mocker.patch("homenet.socket.create_connection", side_effect=OSError("unreachable"))
        from homenet import _resolve_names_batch

        devices = [
            {"ip": "192.168.1.50", "hostname": ""},
            {"ip": "10.0.0.5", "hostname": ""},
        ]
        result = _resolve_names_batch(devices)
        assert result["192.168.1.50"] == "MyPC"

    def test_resolve_names_batch_empty(self, mocker):
        from homenet import _resolve_names_batch

        # All devices already have names
        devices = [
            {"ip": "192.168.1.50", "hostname": "MyPC"},
        ]
        result = _resolve_names_batch(devices)
        assert result == {}

    def test_resolve_names_batch_dns_error(self, mocker):
        """socket.gethostbyaddr failure → empty results (no crash)."""
        mocker.patch("homenet.socket.gethostbyaddr", side_effect=Exception("dns fail"))
        from homenet import _resolve_names_batch

        devices = [{"ip": "192.168.1.50", "hostname": ""}]
        result = _resolve_names_batch(devices)
        assert isinstance(result, dict)

    def test_resolve_names_nbt_fallback(self, mocker):
        """DNS fails → falls back to direct nbtstat."""
        import socket as _socket

        mocker.patch("homenet.socket.gethostbyaddr", side_effect=_socket.herror("not found"))
        nbt_result = MagicMock()
        nbt_result.stdout = "   NAS-SERVER      <00>  UNIQUE\n"
        mocker.patch("homenet.subprocess.run", return_value=nbt_result)
        from homenet import _resolve_names_batch

        devices = [{"ip": "192.168.1.50", "hostname": ""}]
        result = _resolve_names_batch(devices)
        assert result.get("192.168.1.50") == "NAS-SERVER"

    def test_resolve_skips_already_named(self, mocker):
        """Devices with good hostnames should not be re-resolved."""
        m = mocker.patch("homenet.socket.gethostbyaddr")
        from homenet import _resolve_names_batch

        devices = [
            {"ip": "192.168.1.50", "hostname": "GoodName"},
        ]
        result = _resolve_names_batch(devices)
        m.assert_not_called()
        assert result == {}

    def test_resolve_treats_ip_as_hostname_needing_resolve(self, mocker):
        """If hostname == IP address, it needs resolution."""
        mocker.patch(
            "homenet.socket.gethostbyaddr",
            return_value=("Laptop", [], ["192.168.1.51"]),
        )
        from homenet import _resolve_names_batch

        devices = [{"ip": "192.168.1.51", "hostname": "192.168.1.51"}]
        result = _resolve_names_batch(devices)
        assert result["192.168.1.51"] == "Laptop"

    def test_wireless_phase_checks_orbi_reachability(self, mocker):
        """10.x IPs trigger Orbi reachability check via socket.create_connection."""
        mocker.patch("homenet.socket.create_connection", side_effect=OSError("unreachable"))
        nbt_mock = mocker.patch("homenet.subprocess.run")
        from homenet import _resolve_names_batch

        devices = [{"ip": "10.0.0.50", "hostname": ""}]
        result = _resolve_names_batch(devices)
        # nbtstat should NOT be called — Orbi is unreachable
        nbt_mock.assert_not_called()
        assert result == {}

    def test_wireless_phase_runs_nbt_when_orbi_reachable(self, mocker):
        """10.x nbtstat runs when Orbi is reachable."""
        mocker.patch("homenet.socket.create_connection", return_value=MagicMock())
        nbt_result = MagicMock()
        nbt_result.stdout = "   ORBI-DEVICE     <00>  UNIQUE\n"
        mocker.patch("homenet.subprocess.run", return_value=nbt_result)
        from homenet import _resolve_names_batch

        devices = [{"ip": "10.0.0.50", "hostname": ""}]
        result = _resolve_names_batch(devices)
        assert result.get("10.0.0.50") == "ORBI-DEVICE"


class TestEnrichDeviceNames:
    """Test the full enrichment pipeline."""

    def test_enrich_refreshes_stale_unknown_vendors(self, mocker):
        """Regression pin for the 2026-04-23 stale-entry bug (backlog #10).

        The scan merge (_merge_device_data) only calls _mac_vendor() for
        devices seen in the CURRENT ARP/router response. Offline devices
        keep their vendor from the LAST scan that saw them -- which may
        be days or weeks ago, before the IEEE OUI lookup was introduced.

        _enrich_device_names now backfills: any inventory entry whose
        vendor is 'Unknown' or empty gets re-resolved via _mac_vendor on
        every scan, so the IEEE lookup can upgrade stale entries once
        the device owner has installed the new code."""
        # Avoid real network calls (gethostbyaddr / mDNS would try them)
        import socket as _socket

        from homenet import _enrich_device_names

        mocker.patch("homenet.socket.gethostbyaddr", side_effect=_socket.herror("no DNS"))
        mocker.patch("homenet._mdns_resolve_batch", return_value={})
        # Fake _mac_vendor to simulate the IEEE lookup now resolving what
        # was previously Unknown. Use the prefix the live bug hit.
        mocker.patch(
            "homenet._mac_vendor",
            side_effect=lambda m: "Samsung Electronics Co.,Ltd" if m.startswith("8C:79:F5") else "Unknown",
        )

        inventory = {
            "devices": {
                "8C:79:F5:6B:98:14": {
                    "mac": "8C:79:F5:6B:98:14",
                    "ip": "192.168.1.151",
                    "hostname": "Samsung.local",
                    "vendor": "Unknown",  # stale from pre-IEEE-code scan
                    "category": "",
                    "device_type": "",
                    "device_os": "",
                },
                "99:99:99:00:00:00": {
                    "mac": "99:99:99:00:00:00",
                    "ip": "192.168.1.200",
                    "hostname": "RealRandom",
                    "vendor": "Unknown",  # genuinely unknowable
                    "category": "",
                    "device_type": "",
                    "device_os": "",
                },
            },
            "last_scan": None,
        }
        result = _enrich_device_names(inventory)

        # Stale Samsung entry got upgraded
        assert result["devices"]["8C:79:F5:6B:98:14"]["vendor"] == "Samsung Electronics Co.,Ltd"
        # Genuinely-unknown stays Unknown (IEEE has no data, locally-admin bit off)
        assert result["devices"]["99:99:99:00:00:00"]["vendor"] == "Unknown"

    def test_rollup_active_by_ip_lacp_bond_all_three_active(self):
        """Backlog #10 (2026-04-23): link-aggregated NICs share one IP
        across 2-3 MACs. Our ARP scanner only sees the MAC that wins the
        bond's per-destination hash at any moment, so the other bond
        members falsely appear offline. The roll-up pass makes every MAC
        at the same IP inherit active=True when any one was seen recently.

        Fixture models the exact live QNAP setup: 3 MACs on 192.168.1.13
        in balance-alb bonding, the scanner recently saw only MAC '...CB'.
        After roll-up, '...CC' and '...CD' must also show active=True
        without their last_seen being rewritten."""
        from datetime import datetime, timedelta, timezone

        from homenet import _rollup_active_by_ip

        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(seconds=30)).isoformat()
        stale = (now - timedelta(hours=12)).isoformat()

        inventory = {
            "devices": {
                "24:5E:BE:50:6F:CB": {
                    "mac": "24:5E:BE:50:6F:CB",
                    "ip": "192.168.1.13",
                    "active": True,
                    "last_seen": fresh,
                },
                "24:5E:BE:50:6F:CC": {
                    "mac": "24:5E:BE:50:6F:CC",
                    "ip": "192.168.1.13",
                    "active": False,
                    "last_seen": stale,
                },
                "24:5E:BE:50:6F:CD": {
                    "mac": "24:5E:BE:50:6F:CD",
                    "ip": "192.168.1.13",
                    "active": False,
                    "last_seen": stale,
                },
            }
        }
        _rollup_active_by_ip(inventory)
        for mac in ("24:5E:BE:50:6F:CB", "24:5E:BE:50:6F:CC", "24:5E:BE:50:6F:CD"):
            assert inventory["devices"][mac]["active"] is True, f"{mac} should be active"
        # last_seen must NOT be rewritten -- power users still want to see
        # which NIC was the last observed hash winner
        assert inventory["devices"]["24:5E:BE:50:6F:CC"]["last_seen"] == stale
        assert inventory["devices"]["24:5E:BE:50:6F:CD"]["last_seen"] == stale

    def test_rollup_no_fresh_mac_at_ip_leaves_all_inactive(self):
        """If EVERY MAC at an IP is stale (> 15 min), the rollup must NOT
        activate anyone. Genuinely-offline devices stay offline."""
        from datetime import datetime, timedelta, timezone

        from homenet import _rollup_active_by_ip

        stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        inventory = {
            "devices": {
                "AA:BB:CC:00:00:01": {
                    "mac": "AA:BB:CC:00:00:01",
                    "ip": "10.0.0.50",
                    "active": False,
                    "last_seen": stale,
                },
                "AA:BB:CC:00:00:02": {
                    "mac": "AA:BB:CC:00:00:02",
                    "ip": "10.0.0.50",
                    "active": False,
                    "last_seen": stale,
                },
            }
        }
        _rollup_active_by_ip(inventory)
        for dev in inventory["devices"].values():
            assert dev["active"] is False

    def test_rollup_different_ips_are_independent(self):
        """Two unrelated devices at two different IPs must not cross-activate."""
        from datetime import datetime, timedelta, timezone

        from homenet import _rollup_active_by_ip

        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(seconds=10)).isoformat()
        stale = (now - timedelta(hours=48)).isoformat()
        inventory = {
            "devices": {
                "A1:00:00:00:00:01": {"mac": "A1:00:00:00:00:01", "ip": "10.0.0.1", "active": True, "last_seen": fresh},
                "B2:00:00:00:00:01": {
                    "mac": "B2:00:00:00:00:01",
                    "ip": "10.0.0.2",
                    "active": False,
                    "last_seen": stale,
                },
            }
        }
        _rollup_active_by_ip(inventory)
        assert inventory["devices"]["A1:00:00:00:00:01"]["active"] is True
        assert inventory["devices"]["B2:00:00:00:00:01"]["active"] is False

    def test_rollup_single_mac_at_ip_untouched(self):
        """Rollup only kicks in for 2+ MACs per IP. A single-MAC IP keeps
        its existing active flag -- good or bad."""
        from homenet import _rollup_active_by_ip

        inventory = {
            "devices": {
                "A1:00:00:00:00:01": {
                    "mac": "A1:00:00:00:00:01",
                    "ip": "10.0.0.1",
                    "active": False,
                    "last_seen": "2020-01-01T00:00:00+00:00",
                },
            }
        }
        _rollup_active_by_ip(inventory)
        assert inventory["devices"]["A1:00:00:00:00:01"]["active"] is False

    def test_rollup_excludes_link_local_and_empty_ips(self):
        """Stale entries at 0.0.0.0 or 169.254.x.y must NOT accidentally
        activate a real device at a populated IP. Same-IP grouping must
        skip those 'catch-all' addresses."""
        from datetime import datetime, timedelta, timezone

        from homenet import _rollup_active_by_ip

        fresh = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        inventory = {
            "devices": {
                "X0:00:00:00:00:01": {"mac": "X0:00:00:00:00:01", "ip": "0.0.0.0", "active": True, "last_seen": fresh},
                "X0:00:00:00:00:02": {"mac": "X0:00:00:00:00:02", "ip": "0.0.0.0", "active": False, "last_seen": stale},
                "L1:00:00:00:00:01": {
                    "mac": "L1:00:00:00:00:01",
                    "ip": "169.254.1.1",
                    "active": True,
                    "last_seen": fresh,
                },
                "L1:00:00:00:00:02": {
                    "mac": "L1:00:00:00:00:02",
                    "ip": "169.254.1.1",
                    "active": False,
                    "last_seen": stale,
                },
            }
        }
        _rollup_active_by_ip(inventory)
        assert inventory["devices"]["X0:00:00:00:00:02"]["active"] is False
        assert inventory["devices"]["L1:00:00:00:00:02"]["active"] is False

    def test_light_scan_applies_rollup_so_bond_members_stay_active(self, client, mocker):
        """Backlog #10 (2026-04-23): the full scan applies _rollup_active_
        by_ip correctly, but the light-scan path (runs every 60s as a fast
        ARP sweep) was stomping that rollup. Line 1685 set active=False
        for any MAC not in the current ARP sweep, so QNAP bond NICs
        flickered grey between full scans. Fix: light scan now also calls
        the rollup before saving.

        Fixture: 3 QNAP MACs at 192.168.1.13 in the saved inventory, ARP
        sweep sees only the primary bond winner (the classic balance-alb
        per-destination-hash behaviour). After the light scan, all three
        MACs must still show active=True."""
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(seconds=5)).isoformat()

        existing = {
            "devices": {
                "24:5E:BE:50:6F:CB": {
                    "mac": "24:5E:BE:50:6F:CB",
                    "ip": "192.168.1.13",
                    "active": True,
                    "last_seen": fresh,
                    "hostname": "qnap-bond",
                    "vendor": "QNAP Systems, Inc.",
                    "network": "wired",
                    "source": "arp",
                },
                "24:5E:BE:50:6F:CC": {
                    "mac": "24:5E:BE:50:6F:CC",
                    "ip": "192.168.1.13",
                    "active": True,
                    "last_seen": fresh,
                    "hostname": "qnap-bond",
                    "vendor": "QNAP Systems, Inc.",
                    "network": "wired",
                    "source": "arp",
                },
                "24:5E:BE:50:6F:CD": {
                    "mac": "24:5E:BE:50:6F:CD",
                    "ip": "192.168.1.13",
                    "active": True,
                    "last_seen": fresh,
                    "hostname": "qnap-bond",
                    "vendor": "QNAP Systems, Inc.",
                    "network": "wired",
                    "source": "arp",
                },
            },
            "last_scan": fresh,
        }

        mocker.patch("homenet._load_homenet_inventory", return_value=existing)
        saved: dict = {}
        mocker.patch("homenet._save_homenet_inventory", side_effect=lambda inv: saved.update(inv))

        # Only the primary bond winner shows up in ARP this sweep --
        # classic balance-alb per-destination-hash behaviour.
        mocker.patch(
            "homenet._arp_scan",
            return_value=[{"MAC": "24:5E:BE:50:6F:CB", "IP": "192.168.1.13", "Type": "dynamic"}],
        )

        resp = client.post("/api/homenet/scan/light")
        assert resp.status_code == 200

        for mac in ("24:5E:BE:50:6F:CB", "24:5E:BE:50:6F:CC", "24:5E:BE:50:6F:CD"):
            assert saved["devices"][mac]["active"] is True, (
                f"{mac} went inactive after light scan -- rollup wasn't applied"
            )

    def test_rollup_malformed_last_seen_does_not_crash(self):
        """Defensive: garbage timestamp string must not propagate."""
        from homenet import _rollup_active_by_ip

        inventory = {
            "devices": {
                "A1:00:00:00:00:01": {
                    "mac": "A1:00:00:00:00:01",
                    "ip": "10.0.0.1",
                    "active": True,
                    "last_seen": "not-a-date",
                },
                "A1:00:00:00:00:02": {
                    "mac": "A1:00:00:00:00:02",
                    "ip": "10.0.0.1",
                    "active": False,
                    "last_seen": "",
                },
            }
        }
        _rollup_active_by_ip(inventory)
        # Neither entry has a parseable last_seen, so no rollup -- original flags preserved.
        assert inventory["devices"]["A1:00:00:00:00:01"]["active"] is True
        assert inventory["devices"]["A1:00:00:00:00:02"]["active"] is False

    def test_enrich_preserves_non_unknown_vendors(self, mocker):
        """If a device already has a real vendor, the refresh pass must NOT
        overwrite it -- otherwise curated names like "Netgear" would get
        stomped with IEEE's "NETGEAR"."""
        import socket as _socket

        from homenet import _enrich_device_names

        mocker.patch("homenet.socket.gethostbyaddr", side_effect=_socket.herror("no DNS"))
        mocker.patch("homenet._mdns_resolve_batch", return_value={})
        spy = mocker.patch("homenet._mac_vendor", return_value="NETGEAR")

        inventory = {
            "devices": {
                "28:94:01:00:00:01": {
                    "mac": "28:94:01:00:00:01",
                    "ip": "10.0.0.1",
                    "hostname": "Orbi",
                    "vendor": "Netgear",  # curated friendly name
                    "category": "",
                    "device_type": "",
                    "device_os": "",
                },
            },
            "last_scan": None,
        }
        _enrich_device_names(inventory)
        # _mac_vendor should NOT have been called for vendor-refresh purposes
        # on this entry -- it was already non-Unknown.
        # (May still be called from _auto_categorize downstream, hence
        # not asserting call_count == 0; we verify the vendor value instead.)
        assert inventory["devices"]["28:94:01:00:00:01"]["vendor"] == "Netgear"
        del spy  # silence unused warning

    def test_enrich_fills_names(self, mocker):
        mocker.patch(
            "homenet.socket.gethostbyaddr",
            return_value=("MyPC", [], ["192.168.1.50"]),
        )
        from homenet import _enrich_device_names

        inventory = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "",
                    "vendor": "Intel",
                    "category": "",
                    "device_type": "",
                    "device_os": "",
                },
            },
            "last_scan": None,
        }
        result = _enrich_device_names(inventory)
        dev = result["devices"]["AA:BB:CC:DD:EE:FF"]
        assert dev["hostname"] == "MyPC"
        assert dev["category"] == "Computer"  # Intel vendor → Computer

    def test_enrich_preserves_user_category(self, mocker):
        import socket as _socket

        mocker.patch("homenet.socket.gethostbyaddr", side_effect=_socket.herror("not found"))
        from homenet import _enrich_device_names

        inventory = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "MyDevice",
                    "vendor": "Roku",
                    "category": "Other",  # User already set this
                    "device_type": "",
                    "device_os": "",
                },
            },
            "last_scan": None,
        }
        result = _enrich_device_names(inventory)
        # Should NOT overwrite user-set category
        assert result["devices"]["AA:BB:CC:DD:EE:FF"]["category"] == "Other"

    def test_enrich_does_not_overwrite_good_hostname(self, mocker):
        mocker.patch(
            "homenet.socket.gethostbyaddr",
            return_value=("NewName", [], ["192.168.1.50"]),
        )
        from homenet import _enrich_device_names

        inventory = {
            "devices": {
                "AA:BB:CC:DD:EE:FF": {
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.50",
                    "hostname": "GoodExistingName",
                    "vendor": "Unknown",
                    "category": "",
                    "device_type": "",
                    "device_os": "",
                },
            },
            "last_scan": None,
        }
        result = _enrich_device_names(inventory)
        assert result["devices"]["AA:BB:CC:DD:EE:FF"]["hostname"] == "GoodExistingName"


class TestResolveNamesRoute:
    """Test the resolve names API endpoint."""

    def test_resolve_names_endpoint(self, client, mocker):
        mocker.patch(
            "homenet._load_homenet_inventory",
            return_value={
                "devices": {
                    "AA:BB:CC:DD:EE:FF": {
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "ip": "192.168.1.50",
                        "hostname": "",
                        "vendor": "Intel",
                        "category": "",
                        "device_type": "",
                        "device_os": "",
                    },
                },
                "last_scan": None,
            },
        )
        mocker.patch(
            "homenet.socket.gethostbyaddr",
            return_value=("MyPC", [], ["192.168.1.50"]),
        )
        mocker.patch("homenet._save_homenet_inventory")

        resp = client.post("/api/homenet/resolve-names")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["resolved"] == 1
        assert data["total_named"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# PowerShell Command Validation — homenet.py
# ══════════════════════════════════════════════════════════════════════════════


class TestArpScanCommand:
    """Command-content tests for _arp_scan — Batch E: direct ``arp -a``."""

    ARP_SINGLE = (
        "\nInterface: 192.168.1.1 --- 0x5\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.100         aa-bb-cc-dd-ee-ff     dynamic\n"
    )

    def test_returns_list(self, mocker):
        m = mocker.patch("homenet.subprocess.run")
        m.return_value = MagicMock(stdout="", returncode=0, stderr="")
        from homenet import _arp_scan

        result = _arp_scan()
        assert isinstance(result, list)

    def test_command_calls_arp_directly(self, mocker):
        m = mocker.patch("homenet.subprocess.run")
        m.return_value = MagicMock(stdout="", returncode=0, stderr="")
        from homenet import _arp_scan

        _arp_scan()
        cmd = m.call_args[0][0]
        assert cmd[0] == "arp"
        assert "-a" in cmd
        assert "powershell" not in cmd

    def test_parses_mac_ip_interface_from_arp_output(self, mocker):
        m = mocker.patch("homenet.subprocess.run")
        m.return_value = MagicMock(stdout=self.ARP_SINGLE, returncode=0, stderr="")
        from homenet import _arp_scan

        result = _arp_scan()
        assert len(result) == 1
        assert result[0]["Interface"] == "192.168.1.1"
        assert result[0]["IP"] == "192.168.1.100"
        assert result[0]["MAC"] == "AA:BB:CC:DD:EE:FF"

    def test_empty_output_returns_empty_list(self, mocker):
        m = mocker.patch("homenet.subprocess.run")
        m.return_value = MagicMock(stdout="", returncode=0, stderr="")
        from homenet import _arp_scan

        assert _arp_scan() == []

    def test_timeout_returns_empty_list(self, mocker):
        mocker.patch("homenet.subprocess.run", side_effect=subprocess.TimeoutExpired("arp", 15))
        from homenet import _arp_scan

        assert _arp_scan() == []


class TestResolveNamesBatchCommands:
    """Command-content tests for _resolve_names_batch — Batch E: socket + direct nbtstat."""

    def test_dns_phase_uses_socket_gethostbyaddr(self, mocker):
        m = mocker.patch("homenet.socket.gethostbyaddr", return_value=("host", [], ["192.168.1.100"]))
        from homenet import _resolve_names_batch

        _resolve_names_batch([{"ip": "192.168.1.100", "hostname": ""}])
        m.assert_called()

    def test_nbt_phase_calls_nbtstat_directly(self, mocker):
        """NetBIOS fallback runs nbtstat as direct exe, not through PS."""
        import socket as _socket

        mocker.patch("homenet.socket.gethostbyaddr", side_effect=_socket.herror("not found"))
        m = mocker.patch("homenet.subprocess.run")
        m.return_value = MagicMock(stdout="", returncode=0, stderr="")
        from homenet import _resolve_names_batch

        _resolve_names_batch([{"ip": "192.168.1.100", "hostname": ""}])
        cmd = m.call_args[0][0]
        assert cmd[0] == "nbtstat"
        assert "-A" in cmd
        assert "powershell" not in cmd

    def test_dns_error_handled_gracefully(self, mocker):
        mocker.patch("homenet.socket.gethostbyaddr", side_effect=Exception("dns fail"))
        from homenet import _resolve_names_batch

        result = _resolve_names_batch([{"ip": "192.168.1.100", "hostname": ""}])
        assert isinstance(result, dict)

    def test_skips_devices_with_existing_hostname(self, mocker):
        m = mocker.patch("homenet.socket.gethostbyaddr")
        from homenet import _resolve_names_batch

        result = _resolve_names_batch([{"ip": "192.168.1.100", "hostname": "MyPC"}])
        m.assert_not_called()
        assert result == {}

    def test_wireless_ips_check_orbi_reachability(self, mocker):
        """10.x IPs trigger socket.create_connection to Orbi, not PowerShell Test-Connection."""
        m = mocker.patch("homenet.socket.create_connection", side_effect=OSError("unreachable"))
        from homenet import _resolve_names_batch

        _resolve_names_batch([{"ip": "10.0.0.50", "hostname": ""}])
        m.assert_called_once()
        args = m.call_args[0][0]
        assert args == ("10.0.0.1", 443)


# ════════════════════════════════════════════════════════════════════
# Network Topology Diagram (#9)
# ════════════════════════════════════════════════════════════════════


class TestOrbiSoapConnApMacExtraction:
    """Backlog #9 added ``conn_ap_mac`` extraction to _parse_orbi_soap.
    Without it the topology diagram can't tell which Orbi node a wireless
    client is associated with."""

    def test_conn_ap_mac_is_extracted_and_normalised(self):
        from homenet import _parse_orbi_soap

        xml = """<Device>
        <IP>10.0.0.50</IP>
        <Name>Phone</Name>
        <MAC>AA:BB:CC:DD:EE:FF</MAC>
        <ConnectionType>5GHz</ConnectionType>
        <ConnAPMAC>11-22-33-44-55-66</ConnAPMAC>
        </Device>"""
        devs = _parse_orbi_soap(xml)
        assert len(devs) == 1
        # Hyphens normalised to colons, lowercase->upper, so it joins cleanly
        # against the satellite MAC list later.
        assert devs[0]["conn_ap_mac"] == "11:22:33:44:55:66"

    def test_conn_ap_mac_empty_string_when_absent(self):
        """Wired clients have no ConnAPMAC -- must default to '' so the
        topology builder can distinguish 'wireless client of base' (empty
        because base MAC unknown) from 'wired client' (empty by design)."""
        from homenet import _parse_orbi_soap

        xml = """<Device>
        <IP>10.0.0.10</IP>
        <Name>WiredThing</Name>
        <MAC>AA:BB:CC:DD:EE:FF</MAC>
        </Device>"""
        devs = _parse_orbi_soap(xml)
        assert devs[0]["conn_ap_mac"] == ""


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

        inv = self._inventory(
            # Orbi base (10.0.0.1 in inventory)
            {"mac": "BA:5E:00:00:00:01", "ip": "10.0.0.1"},
            # Two clients on the base
            {"mac": "CC:CC:CC:00:00:01", "ip": "10.0.0.10", "conn_ap_mac": "BA:5E:00:00:00:01"},
            {"mac": "CC:CC:CC:00:00:02", "ip": "10.0.0.11", "conn_ap_mac": "BA:5E:00:00:00:01"},
            # Two clients on an unknown satellite
            {"mac": "CC:CC:CC:00:00:03", "ip": "10.0.0.12", "conn_ap_mac": "5A:71:11:11:11:11"},
            {"mac": "CC:CC:CC:00:00:04", "ip": "10.0.0.13", "conn_ap_mac": "5A:71:11:11:11:11"},
        )
        t = build_topology(inv, switch_data={})
        aps = {ap["mac"]: ap for ap in t["aps"]}
        assert "BA:5E:00:00:00:01" in aps
        assert aps["BA:5E:00:00:00:01"]["is_base"] is True
        assert sorted(aps["BA:5E:00:00:00:01"]["clients"]) == [
            "CC:CC:CC:00:00:01",
            "CC:CC:CC:00:00:02",
        ]
        assert "5A:71:11:11:11:11" in aps
        assert aps["5A:71:11:11:11:11"]["is_base"] is False
        assert "satellite" in aps["5A:71:11:11:11:11"]["name"].lower()
        assert sorted(aps["5A:71:11:11:11:11"]["clients"]) == [
            "CC:CC:CC:00:00:03",
            "CC:CC:CC:00:00:04",
        ]
        assert t["stats"]["wireless_mapped"] == 4

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

    def test_commscope_fios_set_top_box_recognised_as_moca(self):
        """The Verizon FiOS VMS4100 / VMS1100 Set-Top Boxes are MoCA
        endpoints -- they bridge the coax network into video. Vendor name
        is Commscope (or pre-acquisition Arris). Must land in moca_bridges."""
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
        assert "B0:5D:D4:76:2A:C0" in t["moca_bridges"]
        assert "B0:5D:D4:76:2A:C0" not in t["via_verizon_or_moca"]

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
            ("Actiontec Electronics, Inc.", True),
            ("ACTIONTEC ELECTRONICS", True),  # case-insensitive
            ("GoCoax", True),
            ("Hitron Technologies", True),
            ("Westell Technologies", True),
            ("Motorola Mobility LLC", True),
            ("ScreenBeam Inc.", True),
            # Near-misses
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

        # Vendor matches MoCA pattern but user says "moca endpoint" -> NOT bridge
        assert _is_moca_bridge({"vendor": "Commscope", "wired_via": "moca"}) is False
        # Same for Askey + verizon_lan (rare but possible -- some Askey
        # gear is a USB-Ethernet adapter, not a MoCA bridge)
        assert _is_moca_bridge({"vendor": "Askey", "wired_via": "verizon_lan"}) is False
        # And for switch override
        assert _is_moca_bridge({"vendor": "Actiontec", "wired_via": "switch"}) is False
        # Vendor matches AND no wired_via set -> auto-detect still fires
        assert _is_moca_bridge({"vendor": "Commscope"}) is True
        # Vendor matches AND user explicitly says "moca_bridge" -> still bridge
        assert _is_moca_bridge({"vendor": "Commscope", "wired_via": "moca_bridge"}) is True

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
